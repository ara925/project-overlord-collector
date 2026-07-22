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
    let data_dir =
        PathBuf::from(std::env::var("OVERLORD_DATA_DIR").unwrap_or_else(|_| "./data".to_string()));
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
        // Registration / recovery-bind bodies are tiny — cap them tightly so they can't be abused
        // as a large-body vector, while raw telemetry keeps the generous allowance below.
        .route(
            "/api/fleet/register",
            post(register_device).layer(axum::extract::DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/api/fleet/recovery-bind",
            post(recovery_bind).layer(axum::extract::DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/api/fleet/raw-telemetry", post(ingest_raw))
        .route("/upload", post(ingest_field_bundle))
        .route("/api/field-telemetry", get(field_telemetry_aggregate))
        .route("/api/fleet/telemetry", post(ingest_digest).get(aggregate))
        // Broad raw telemetry envelopes exceed axum's 2MB default; endpoints already cap each
        // envelope well under this, so 16MB is comfortable headroom.
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024))
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

fn provided_field_key(headers: &HeaderMap) -> &str {
    headers
        .get("X-Overlord-Field-Key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

/// Operator/enrollment auth: the shared secret. Guards registration + the aggregate view only.
/// Empty configured secret rejects everything (fail closed).
fn require_enroll_secret(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if !state.enroll_secret.is_empty()
        && provided_ingest_token(headers) == state.enroll_secret.as_str()
    {
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
    let bound = registry
        .get(machine_id)
        .and_then(entry_device_token)
        .unwrap_or_default();
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

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A registry entry is either a legacy raw token string, or `{ token, recovery_hash }`. Extract the
/// device token from either shape so old entries keep working after the format change.
fn entry_device_token(entry: &Value) -> Option<String> {
    entry.as_str().map(str::to_string).or_else(|| {
        entry
            .get("token")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

/// A recovery token bounds a lost-device-token recovery. Only the SHA-256 of the recovery secret is
/// ever stored — never the secret itself. Accepts the `ovlrec-` prefix, length-bounded.
fn recovery_hash_of(recovery_token: Option<&str>) -> Option<String> {
    recovery_token
        .filter(|token| token.starts_with("ovlrec-") && token.len() <= 128)
        .map(|token| sha256_hex(token.as_bytes()))
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
    let body_secret = body
        .get("enroll_token")
        .and_then(Value::as_str)
        .unwrap_or("");
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
    if machine_id.is_empty() || machine_id.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "machine_id is required and must be <= 128 chars" })),
        )
            .into_response();
    }
    let recovery_hash = recovery_hash_of(body.get("recovery_token").and_then(Value::as_str));
    // The tokio Mutex serializes concurrent registrations (no torn read-modify-write).
    let mut registry = state.registry.lock().await;
    if let Some(existing) = registry.get(&machine_id) {
        // Existing machine: return the SAME token ONLY when the caller proves the recovery secret
        // (its hash matches what was stored). A shared-secret holder WITHOUT that proof cannot rotate
        // or read another live machine's token — it gets 409. Recovery after a genuine registry reset
        // still works (the id is unbound then).
        let token = entry_device_token(existing);
        let stored_hash = existing.get("recovery_hash").and_then(Value::as_str);
        if let (Some(token), Some(provided), Some(stored)) =
            (token, recovery_hash.as_deref(), stored_hash)
        {
            if provided == stored {
                return Json(json!({
                    "ok": true,
                    "machine_id": machine_id,
                    "device_token": token,
                    "registration": "recovered"
                }))
                .into_response();
            }
        }
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "machine already enrolled",
                "hint": "re-enrolling an existing machine requires its recovery proof or an operator reset"
            })),
        )
            .into_response();
    }
    let device_token = random_device_token();
    registry.insert(
        machine_id.clone(),
        json!({ "token": device_token, "recovery_hash": recovery_hash }),
    );
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
    Json(json!({
        "ok": true,
        "machine_id": machine_id,
        "device_token": device_token,
        "registration": "new"
    }))
    .into_response()
}

/// Bind (or refresh) a recovery proof for an already-registered machine. Authenticated with the
/// machine's CURRENT device token — the shared enrollment secret alone cannot bind recovery material.
/// Only the SHA-256 of the recovery secret is stored.
async fn recovery_bind(
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
    let recovery_hash = match recovery_hash_of(body.get("recovery_token").and_then(Value::as_str)) {
        Some(hash) => hash,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid recovery token" })),
            )
                .into_response()
        }
    };
    let mut registry = state.registry.lock().await;
    let Some(existing) = registry.get(&machine_id).cloned() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "machine is not registered" })),
        )
            .into_response();
    };
    let Some(token) = entry_device_token(&existing) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "device token missing" })),
        )
            .into_response();
    };
    registry.insert(
        machine_id.clone(),
        json!({ "token": token, "recovery_hash": recovery_hash }),
    );
    if let Err(error) = persist_registry(&state.registry_path, &registry) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to persist recovery binding: {error}") })),
        )
            .into_response();
    }
    drop(registry);
    Json(json!({ "ok": true, "machine_id": machine_id, "recovery": "bound" })).into_response()
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
    std::fs::write(
        &tmp,
        serde_json::to_string_pretty(registry).unwrap_or_default(),
    )?;
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

fn write_json_atomic(path: &std::path::Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(value).unwrap_or_default())?;
    std::fs::rename(tmp, path)
}

fn redact_sensitive_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let lower = key.to_ascii_lowercase();
                let is_status_flag = matches!(
                    lower.as_str(),
                    "raw_secret_returned"
                        | "automatic_upload_configured"
                        | "automatic_upload_performed"
                        | "ingest_key_configured"
                );
                if !is_status_flag
                    && (lower.contains("token")
                        || lower.contains("secret")
                        || lower.contains("password")
                        || lower.contains("api_key")
                        || lower.contains("credential")
                        || lower.contains("private_key")
                        || lower.contains("bearer"))
                {
                    *child = Value::String("[redacted]".to_string());
                } else {
                    redact_sensitive_value(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_sensitive_value(item);
            }
        }
        _ => {}
    }
}

/// Receive the bounded, redacted desktop field bundle. This endpoint exists independently from
/// fleet enrollment so a renderer failure can still report its startup log on first launch.
async fn ingest_field_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> impl IntoResponse {
    if state.enroll_secret.is_empty()
        || provided_field_key(&headers) != state.enroll_secret.as_str()
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing or invalid field key" })),
        )
            .into_response();
    }
    let submission_id = body
        .get("submission_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let header_submission_id = headers
        .get("X-Overlord-Submission-Id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    if submission_id.is_empty()
        || submission_id.len() > 128
        || submission_id != header_submission_id
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid or mismatched submission id" })),
        )
            .into_response();
    }
    let participant = body
        .get("participant_id")
        .and_then(Value::as_str)
        .unwrap_or("unassigned")
        .trim()
        .to_string();
    if participant.is_empty() || participant.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "participant id must be 1..128 characters" })),
        )
            .into_response();
    }
    let name = safe_name(&participant);
    redact_sensitive_value(&mut body);
    let dir = state.data_dir.join("field-events");
    let seen_path = dir.join(format!("{name}.seen"));
    if batch_already_seen(&seen_path, &submission_id) {
        return Json(json!({
            "ok": true,
            "saved": true,
            "deduped": true,
            "submission_id": submission_id,
            "raw_secret_returned": false
        }))
        .into_response();
    }
    let received_at = chrono::Utc::now().to_rfc3339();
    let envelope = json!({
        "participant_id": participant,
        "submission_id": submission_id,
        "received_at": received_at,
        "bundle": body
    });
    let line = serde_json::to_string(&envelope).unwrap_or_default();
    let history_path = dir.join(format!("{name}.jsonl"));
    let latest_path = dir.join(format!("{name}.latest.json"));
    if let Err(error) = append_capped(&history_path, &line, RAW_LOG_MAX_BYTES)
        .and_then(|_| write_json_atomic(&latest_path, &envelope))
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response();
    }
    remember_batch(&seen_path, &submission_id);
    Json(json!({
        "ok": true,
        "saved": true,
        "deduped": false,
        "submission_id": submission_id,
        "received_at": received_at,
        "raw_secret_returned": false
    }))
    .into_response()
}

async fn field_telemetry_aggregate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(response) = require_enroll_secret(&state, &headers) {
        return response;
    }
    let dir = state.data_dir.join("field-events");
    let mut participants = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .ends_with(".latest.json")
            {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                if let Ok(value) = serde_json::from_str::<Value>(&text) {
                    participants.push(value);
                }
            }
        }
    }
    participants.sort_by(|left, right| {
        let left = left
            .get("received_at")
            .and_then(Value::as_str)
            .unwrap_or("");
        let right = right
            .get("received_at")
            .and_then(Value::as_str)
            .unwrap_or("");
        right.cmp(left)
    });
    Json(json!({
        "read_only": true,
        "participants_reporting": participants.len(),
        "participants": participants,
        "raw_secret_returned": false
    }))
    .into_response()
}

fn batch_already_seen(path: &std::path::Path, batch_id: &str) -> bool {
    if batch_id.is_empty() {
        return false;
    }
    std::fs::read_to_string(path)
        .ok()
        .is_some_and(|text| text.lines().any(|id| id == batch_id))
}

/// Record dedupe only after durable storage succeeds. Advancing it before the write would turn a
/// transient disk error into permanent telemetry loss on the sender's retry.
fn remember_batch(path: &std::path::Path, batch_id: &str) {
    if batch_id.is_empty() {
        return;
    }
    let mut seen: Vec<String> = std::fs::read_to_string(path)
        .ok()
        .map(|text| text.lines().map(str::to_string).collect())
        .unwrap_or_default();
    if seen.iter().any(|id| id == batch_id) {
        return;
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
    let seen_path = state
        .data_dir
        .join("fleet-events")
        .join(format!("{name}.seen"));
    if batch_already_seen(&seen_path, batch_id) {
        return Json(json!({ "ok": true, "machine_id": machine_id, "stored": "deduped" }))
            .into_response();
    }
    let log_path = state
        .data_dir
        .join("fleet-events")
        .join(format!("{name}.jsonl"));
    let line = serde_json::to_string(&body).unwrap_or_default();
    match append_capped(&log_path, &line, RAW_LOG_MAX_BYTES) {
        Ok(()) => {
            remember_batch(&seen_path, batch_id);
            Json(json!({ "ok": true, "machine_id": machine_id, "stored": "appended" }))
                .into_response()
        }
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
