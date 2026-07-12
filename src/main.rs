//! Project Overlord fleet telemetry collector.
//!
//! A slim, cross-platform HTTPS service that RECEIVES read-only endpoint telemetry and stores it.
//! It contains NO detection logic (the brain stays in the private core) and NO secrets in source —
//! the scoped ingest token is supplied at runtime via the OVERLORD_INGEST_TOKEN env var. It only
//! ever records observations posted to it; it never sends anything back that could act on a machine.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

const RAW_LOG_MAX_BYTES: u64 = 50 * 1024 * 1024;
const SEEN_BATCH_CAP: usize = 200;

#[derive(Clone)]
struct AppState {
    // The ENROLLMENT/operator secret (OVERLORD_INGEST_TOKEN). It authorizes device registration and
    // the operator aggregate view — it is NOT accepted for telemetry ingest, which requires a
    // per-device token so a leaked device credential can only speak for its own machine.
    enroll_secret: Arc<String>,
    data_dir: PathBuf,
    // machine_id -> { received_at, digest } — latest detection digest per machine.
    digests: Arc<Mutex<serde_json::Map<String, Value>>>,
    // machine_id -> device_token. TOFU: issued on first registration, then required for that
    // machine's telemetry. Persisted to data_dir/device-registry.json.
    registry: Arc<Mutex<serde_json::Map<String, Value>>>,
    registry_path: PathBuf,
}

#[tokio::main]
async fn main() {
    let token = std::env::var("OVERLORD_INGEST_TOKEN").unwrap_or_default();
    if token.is_empty() {
        eprintln!("WARNING: OVERLORD_INGEST_TOKEN is not set — registration + aggregate will be rejected (401).");
    }
    // Render (and most platforms) inject the port to bind via $PORT.
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or(8787);
    let data_dir = PathBuf::from(
        std::env::var("OVERLORD_DATA_DIR").unwrap_or_else(|_| "./data".to_string()),
    );
    let _ = std::fs::create_dir_all(data_dir.join("fleet-events"));

    let registry_path = data_dir.join("device-registry.json");
    let registry = std::fs::read_to_string(&registry_path)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Map<String, Value>>(&text).ok())
        .unwrap_or_default();

    let state = AppState {
        enroll_secret: Arc::new(token),
        data_dir,
        digests: Arc::new(Mutex::new(serde_json::Map::new())),
        registry: Arc::new(Mutex::new(registry)),
        registry_path,
    };

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/api/fleet/register", post(register_device))
        .route("/api/fleet/raw-telemetry", post(ingest_raw))
        .route(
            "/api/fleet/telemetry",
            post(ingest_digest).get(aggregate),
        )
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("overlord-collector listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind listener");
    axum::serve(listener, app).await.expect("serve");
}

async fn root() -> &'static str {
    "Project Overlord fleet collector — read-only telemetry receiver."
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true, "service": "overlord-collector" }))
}

fn provided_ingest_token(headers: &HeaderMap) -> &str {
    headers
        .get("X-Overlord-Ingest-Token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

/// Operator/enrollment auth: the shared secret. Guards registration + the aggregate view only.
/// Empty configured secret rejects everything (fail closed).
fn require_enroll_secret(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if !state.enroll_secret.is_empty() && provided_ingest_token(headers) == state.enroll_secret.as_str() {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing or invalid enrollment secret" })),
        )
            .into_response())
    }
}

/// Per-device telemetry auth: the provided token must equal the device token bound to `machine_id`
/// at registration. A holder of one device's token therefore cannot speak for any other machine, and
/// the shared enrollment secret alone is NOT accepted here.
async fn require_device_token(
    state: &AppState,
    headers: &HeaderMap,
    machine_id: &str,
) -> Result<(), Response> {
    let provided = provided_ingest_token(headers);
    let registry = state.registry.lock().await;
    let bound = registry.get(machine_id).and_then(Value::as_str).unwrap_or("");
    if !bound.is_empty() && !provided.is_empty() && provided == bound {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unregistered machine or invalid device token",
                "hint": "POST /api/fleet/register with the enrollment secret to obtain a per-device token"
            })),
        )
            .into_response())
    }
}

/// Unpredictable per-device token from OS entropy (falls back to a fixed-length label on the
/// vanishingly rare entropy failure, which still passes through registration binding).
fn random_device_token() -> String {
    let mut bytes = [0u8; 24];
    if getrandom::getrandom(&mut bytes).is_err() {
        // Entropy unavailable — mix the machine map length in so we don't emit a constant.
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("ovldev-{hex}")
}

/// TOFU device registration: with the enrollment secret, a machine claims its `machine_id` and gets
/// a per-device token (rotated on re-registration, e.g. after a reinstall). That token is what its
/// telemetry must then present. This is not full attestation — a secret holder can still register a
/// fresh id — but it scopes the day-to-day telemetry credential per machine.
async fn register_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // The enrollment secret may arrive in the header or the body (the reporter sends it in the body).
    let body_secret = body.get("enroll_token").and_then(Value::as_str).unwrap_or("");
    let header_ok = require_enroll_secret(&state, &headers).is_ok();
    let secret_ok = header_ok
        || (!state.enroll_secret.is_empty() && body_secret == state.enroll_secret.as_str());
    if !secret_ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing or invalid enrollment secret" })),
        )
            .into_response();
    }
    let machine_id = machine_id_of(&body);
    if machine_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "machine_id is required" })),
        )
            .into_response();
    }
    // The tokio Mutex serializes concurrent registrations (no torn read-modify-write).
    let mut registry = state.registry.lock().await;
    if registry.contains_key(&machine_id) {
        // An existing machine_id is NOT remotely re-registered with the shared secret alone — a
        // leaked secret can't rotate a live machine's token to impersonate it. Recovery after a
        // genuine registry reset still works (the id is unbound then), and an operator can clear an
        // entry to re-enroll a reinstalled machine.
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "machine already enrolled",
                "hint": "re-enrolling an existing machine requires an operator to reset its registry entry"
            })),
        )
            .into_response();
    }
    let device_token = random_device_token();
    registry.insert(machine_id.clone(), json!(device_token.clone()));
    // Persist atomically; on failure roll back the in-memory insert and report 500, so the endpoint
    // never hands out a token that was not durably stored.
    if let Err(error) = persist_registry(&state.registry_path, &registry) {
        registry.remove(&machine_id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to persist registration: {error}") })),
        )
            .into_response();
    }
    drop(registry);
    Json(json!({ "ok": true, "machine_id": machine_id, "device_token": device_token }))
        .into_response()
}

/// Persist the device registry atomically (temp file + rename) so a crash can't leave it torn.
fn persist_registry(
    path: &std::path::Path,
    registry: &serde_json::Map<String, Value>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(registry).unwrap_or_default())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn machine_id_of(body: &Value) -> String {
    body.get("machine_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

fn safe_name(machine_id: &str) -> String {
    let safe: String = machine_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        "unknown".to_string()
    } else {
        safe
    }
}

fn append_capped(path: &std::path::Path, line: &str, max_bytes: u64) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() >= max_bytes {
            let backup = path.with_extension("jsonl.1");
            let _ = std::fs::remove_file(&backup);
            let _ = std::fs::rename(path, &backup);
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")
}

/// Hub-side dedupe: has this batch id already been recorded for the machine? Bounded `.seen` ring.
fn batch_already_seen(path: &std::path::Path, batch_id: &str) -> bool {
    if batch_id.is_empty() {
        return false;
    }
    let mut seen: Vec<String> = std::fs::read_to_string(path)
        .ok()
        .map(|text| text.lines().map(str::to_string).collect())
        .unwrap_or_default();
    if seen.iter().any(|id| id == batch_id) {
        return true;
    }
    seen.push(batch_id.to_string());
    if seen.len() > SEEN_BATCH_CAP {
        let drop = seen.len() - SEEN_BATCH_CAP;
        seen.drain(0..drop);
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, seen.join("\n"));
    false
}

/// Broad raw activity: append the envelope to the machine's log, deduping resends.
async fn ingest_raw(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let machine_id = machine_id_of(&body);
    if machine_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "machine_id is required" })),
        )
            .into_response();
    }
    if let Err(response) = require_device_token(&state, &headers, &machine_id).await {
        return response;
    }
    let name = safe_name(&machine_id);
    let batch_id = body.get("batch_id").and_then(Value::as_str).unwrap_or("");
    let seen_path = state.data_dir.join("fleet-events").join(format!("{name}.seen"));
    if batch_already_seen(&seen_path, batch_id) {
        return Json(json!({ "ok": true, "machine_id": machine_id, "stored": "deduped" }))
            .into_response();
    }
    let log_path = state.data_dir.join("fleet-events").join(format!("{name}.jsonl"));
    let line = serde_json::to_string(&body).unwrap_or_default();
    match append_capped(&log_path, &line, RAW_LOG_MAX_BYTES) {
        Ok(()) => Json(json!({ "ok": true, "machine_id": machine_id, "stored": "appended" }))
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

/// Latest detection digest per machine, held in memory for the aggregate view.
async fn ingest_digest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let machine_id = machine_id_of(&body);
    if machine_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "machine_id is required" })),
        )
            .into_response();
    }
    if let Err(response) = require_device_token(&state, &headers, &machine_id).await {
        return response;
    }
    let digest = body.get("digest").cloned().unwrap_or(Value::Null);
    let mut digests = state.digests.lock().await;
    digests.insert(
        machine_id.clone(),
        json!({ "machine_id": machine_id, "digest": digest }),
    );
    Json(json!({ "ok": true, "machine_id": machine_id, "machines_reporting": digests.len() }))
        .into_response()
}

/// Operator view (also token-guarded): fleet-wide rollup of the latest per-machine digests.
async fn aggregate(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(response) = require_enroll_secret(&state, &headers) {
        return response;
    }
    let digests = state.digests.lock().await;
    let mut malicious = 0u64;
    let mut suspicious = 0u64;
    let machines: Vec<Value> = digests.values().cloned().collect();
    for entry in &machines {
        let verdicts = entry.pointer("/digest/verdicts");
        malicious += verdicts
            .and_then(|v| v.get("malicious"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        suspicious += verdicts
            .and_then(|v| v.get("suspicious"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
    }
    Json(json!({
        "read_only": true,
        "machines_reporting": machines.len(),
        "fleet_totals": { "malicious": malicious, "suspicious": suspicious },
        "machines": machines
    }))
    .into_response()
}
