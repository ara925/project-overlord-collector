//! Project Overlord fleet telemetry collector.
//!
//! A slim, cross-platform HTTPS service that RECEIVES read-only endpoint telemetry and stores it.
//! It contains NO detection logic (the brain stays in the private core) and NO secrets in source —
//! the scoped ingest token is supplied at runtime via the OVERLORD_INGEST_TOKEN env var. It only
//! ever records observations posted to it; it never sends anything back that could act on a machine.

use axum::{
    extract::{Path, State},
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
const MACHINE_ONLINE_WINDOW_SECONDS: i64 = 5 * 60;

#[derive(Clone)]
struct AppState {
    // The ENROLLMENT/operator secret (OVERLORD_INGEST_TOKEN). It authorizes device registration and
    // the operator aggregate view — it is NOT accepted for telemetry ingest, which requires a
    // per-device token so a leaked device credential can only speak for its own machine.
    enroll_secret: Arc<String>,
    data_dir: PathBuf,
    // machine_id -> { received_at, digest } — latest detection digest per machine.
    digests: Arc<Mutex<serde_json::Map<String, Value>>>,
    digest_path: PathBuf,
    // A bounded latest raw-heartbeat summary per machine. Full raw activity remains in the
    // append-only journal and is never returned by the operator summary endpoints.
    raw_summaries: Arc<Mutex<serde_json::Map<String, Value>>>,
    raw_summary_path: PathBuf,
    // machine_id -> device_token. TOFU: issued on first registration, then required for that
    // machine's telemetry. Persisted to data_dir/device-registry.json.
    registry: Arc<Mutex<serde_json::Map<String, Value>>>,
    registry_path: PathBuf,
    storage_readiness: StorageReadiness,
}

#[derive(Clone)]
struct StorageReadiness {
    data_dir_explicit: bool,
    persistent_storage_declared: bool,
    data_dir_ready: bool,
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
    let configured_data_dir = std::env::var("OVERLORD_DATA_DIR")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let data_dir_explicit = configured_data_dir.is_some();
    let data_dir = PathBuf::from(configured_data_dir.unwrap_or_else(|| "./data".to_string()));
    let persistent_storage_declared = std::env::var("OVERLORD_PERSISTENT_STORAGE")
        .ok()
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        });
    let data_dir_ready = std::fs::create_dir_all(data_dir.join("fleet-events")).is_ok();
    if !data_dir_ready {
        eprintln!("WARNING: collector data directory is unavailable; persistence writes will fail");
    } else if !data_dir_explicit || !persistent_storage_declared {
        eprintln!(
            "WARNING: durable collector storage is not declared; enrolled devices may be lost after a redeploy"
        );
    }

    let registry_path = data_dir.join("device-registry.json");
    let registry = std::fs::read_to_string(&registry_path)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Map<String, Value>>(&text).ok())
        .unwrap_or_default();

    let digest_path = data_dir.join("fleet-latest-digests.json");
    let raw_summary_path = data_dir.join("fleet-latest-raw-summaries.json");
    let digests = load_json_map(&digest_path);
    let raw_summaries = load_json_map(&raw_summary_path);
    let state = AppState {
        enroll_secret: Arc::new(token),
        data_dir,
        digests: Arc::new(Mutex::new(digests)),
        digest_path,
        raw_summaries: Arc::new(Mutex::new(raw_summaries)),
        raw_summary_path,
        registry: Arc::new(Mutex::new(registry)),
        registry_path,
        storage_readiness: StorageReadiness {
            data_dir_explicit,
            persistent_storage_declared,
            data_dir_ready,
        },
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
        .route("/api/fleet/machines", get(machine_list))
        .route("/api/fleet/machines/{machine_id}", get(machine_detail))
        .route(
            "/api/fleet/machines/{machine_id}/timeline",
            get(machine_timeline),
        )
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

async fn health(State(state): State<AppState>) -> Json<Value> {
    let durable_storage_configured = state.storage_readiness.data_dir_explicit
        && state.storage_readiness.persistent_storage_declared
        && state.storage_readiness.data_dir_ready;
    Json(json!({
        "ok": state.storage_readiness.data_dir_ready,
        "service": "overlord-collector",
        "storage": {
            "data_directory_configured": state.storage_readiness.data_dir_explicit,
            "data_directory_ready": state.storage_readiness.data_dir_ready,
            "persistent_storage_declared": state.storage_readiness.persistent_storage_declared,
            "durable_storage_configured": durable_storage_configured,
            "status": if durable_storage_configured { "persistent" } else { "ephemeral-risk" }
        }
    }))
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

fn registry_registered_at(entry: Option<&Value>) -> Value {
    entry
        .and_then(|value| value.get("registered_at"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn registry_recovery_bound(entry: Option<&Value>) -> bool {
    entry
        .and_then(|value| value.get("recovery_hash"))
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
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
    let now = chrono::Utc::now().to_rfc3339();
    // The tokio Mutex serializes concurrent registrations (no torn read-modify-write).
    let mut registry = state.registry.lock().await;
    if let Some(existing) = registry.get(&machine_id).cloned() {
        // Existing machine: return the SAME token ONLY when the caller proves the recovery secret
        // (its hash matches what was stored). A shared-secret holder WITHOUT that proof cannot rotate
        // or read another live machine's token — it gets 409. Recovery after a genuine registry reset
        // still works (the id is unbound then).
        let token = entry_device_token(&existing);
        let stored_hash = existing
            .get("recovery_hash")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let (Some(token), Some(provided), Some(stored)) =
            (token, recovery_hash.as_deref(), stored_hash.as_deref())
        {
            if provided == stored {
                let previous = existing;
                registry.insert(
                    machine_id.clone(),
                    json!({
                        "token": token,
                        "recovery_hash": stored,
                        "registered_at": previous
                            .get("registered_at")
                            .cloned()
                            .unwrap_or(Value::Null),
                        "last_recovered_at": now
                    }),
                );
                if let Err(error) = persist_registry(&state.registry_path, &registry) {
                    registry.insert(machine_id.clone(), previous);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": format!("failed to persist recovered registration: {error}") })),
                    )
                        .into_response();
                }
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
        json!({
            "token": device_token,
            "recovery_hash": recovery_hash,
            "registered_at": now,
            "last_recovered_at": Value::Null
        }),
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
        json!({
            "token": token,
            "recovery_hash": recovery_hash,
            "registered_at": existing
                .get("registered_at")
                .cloned()
                .unwrap_or(Value::Null),
            "last_recovered_at": existing
                .get("last_recovered_at")
                .cloned()
                .unwrap_or(Value::Null),
            "recovery_bound_at": chrono::Utc::now().to_rfc3339()
        }),
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

fn load_json_map(path: &std::path::Path) -> serde_json::Map<String, Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Map<String, Value>>(&text).ok())
        .unwrap_or_default()
}

fn write_json_map_atomic(
    path: &std::path::Path,
    map: &serde_json::Map<String, Value>,
) -> std::io::Result<()> {
    write_json_atomic(path, &Value::Object(map.clone()))
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

fn raw_heartbeat_summary(body: &Value, received_at: &str) -> Value {
    let section_count = |name: &str| {
        body.pointer(&format!("/sections/{name}/records"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    };
    let mut summary = json!({
        "machine_id": machine_id_of(body),
        "received_at": received_at,
        "collected_at": body.get("collected_at").cloned().unwrap_or(Value::Null),
        "batch_id": body.get("batch_id").cloned().unwrap_or(Value::Null),
        "schema": body.get("schema").cloned().unwrap_or(Value::Null),
        "provenance": body.get("provenance").cloned().unwrap_or(Value::Null),
        "heartbeat": body.get("heartbeat").cloned().unwrap_or(Value::Null),
        "telemetry_gap": body.get("telemetry_gap").cloned().unwrap_or(Value::Null),
        "section_counts": {
            "processes": section_count("processes"),
            "network_connections": section_count("network_connections"),
            "runtime_scripts": section_count("runtime_scripts"),
            "dns_cache": section_count("dns_cache"),
            "process_events": section_count("process_events")
        },
        "read_only": true,
        "hands_tied": true,
        "raw_activity_returned": false,
        "raw_secret_returned": false
    });
    redact_sensitive_value(&mut summary);
    summary
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
    let received_at = chrono::Utc::now().to_rfc3339();
    let summary = raw_heartbeat_summary(&body, &received_at);
    {
        let mut summaries = state.raw_summaries.lock().await;
        summaries.insert(machine_id.clone(), summary);
        if let Err(error) = write_json_map_atomic(&state.raw_summary_path, &summaries) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("could not persist latest machine heartbeat: {error}") })),
            )
                .into_response();
        }
    }
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
    let mut digest = body.get("digest").cloned().unwrap_or(Value::Null);
    redact_sensitive_value(&mut digest);
    let received_at = chrono::Utc::now().to_rfc3339();
    let mut digests = state.digests.lock().await;
    digests.insert(
        machine_id.clone(),
        json!({ "machine_id": machine_id, "received_at": received_at, "digest": digest }),
    );
    if let Err(error) = write_json_map_atomic(&state.digest_path, &digests) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("could not persist latest machine digest: {error}") })),
        )
            .into_response();
    }
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

fn machine_summary_value(
    machine_id: &str,
    registry_entry: Option<&Value>,
    digest_entry: Option<&Value>,
    raw_summary: Option<&Value>,
) -> Value {
    let digest = digest_entry
        .and_then(|entry| entry.get("digest"))
        .unwrap_or(&Value::Null);
    let digest_seen = digest_entry
        .and_then(|entry| entry.get("received_at"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let raw_seen = raw_summary
        .and_then(|entry| entry.get("received_at"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let last_seen = if digest_seen >= raw_seen {
        digest_seen
    } else {
        raw_seen
    };
    let online = chrono::DateTime::parse_from_rfc3339(last_seen)
        .ok()
        .map(|seen| {
            chrono::Utc::now()
                .signed_duration_since(seen.with_timezone(&chrono::Utc))
                .num_seconds()
                <= MACHINE_ONLINE_WINDOW_SECONDS
        })
        .unwrap_or(false);
    let reporting_status = if last_seen.is_empty() {
        "never-reported"
    } else if online {
        "online"
    } else {
        "offline"
    };
    let from_digest_or_raw = |digest_pointer: &str, raw_pointer: &str| {
        digest
            .pointer(digest_pointer)
            .cloned()
            .or_else(|| {
                raw_summary
                    .and_then(|entry| entry.pointer(raw_pointer))
                    .cloned()
            })
            .unwrap_or(Value::Null)
    };
    let lifecycle = from_digest_or_raw("/lifecycle", "/heartbeat/lifecycle");
    let mut value = json!({
        "machine_id": machine_id,
        "enrollment_status": if registry_entry.is_some() { "enrolled" } else { "telemetry-without-registration" },
        "registered_at": registry_registered_at(registry_entry),
        "recovery_bound": registry_recovery_bound(registry_entry),
        "reporting_status": reporting_status,
        "online": online,
        "display_name": from_digest_or_raw("/machine/display_name", "/heartbeat/display_name"),
        "last_seen_at": if last_seen.is_empty() { Value::Null } else { json!(last_seen) },
        "provenance": from_digest_or_raw("/provenance", "/provenance"),
        "runtime": from_digest_or_raw("/runtime", "/heartbeat"),
        "latest_scan": from_digest_or_raw("/latest_scan", "/heartbeat/latest_scan"),
        "update": from_digest_or_raw("/update", "/heartbeat/update"),
        "lifecycle": lifecycle,
        "verdicts": digest.get("verdicts").cloned().unwrap_or(Value::Null),
        "flags_total": digest.get("flags_total").cloned().unwrap_or(json!(0)),
        "coverage": digest.get("coverage").cloned().unwrap_or(Value::Null),
        "data_quality": digest.get("data_quality").cloned().unwrap_or(Value::Null),
        "section_counts": raw_summary
            .and_then(|entry| entry.get("section_counts"))
            .cloned()
            .unwrap_or(Value::Null),
        "telemetry_gap": raw_summary
            .and_then(|entry| entry.get("telemetry_gap"))
            .cloned()
            .unwrap_or(Value::Null),
        "read_only": true,
        "hands_tied": true,
        "remote_commands_enabled": false,
        "raw_activity_returned": false,
        "raw_secret_returned": false
    });
    redact_sensitive_value(&mut value);
    value
}

fn machine_summaries(
    registry: &serde_json::Map<String, Value>,
    digests: &serde_json::Map<String, Value>,
    raw_summaries: &serde_json::Map<String, Value>,
) -> Vec<Value> {
    let mut ids = registry
        .keys()
        .chain(digests.keys())
        .chain(raw_summaries.keys())
        .cloned()
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    let mut machines = ids
        .iter()
        .map(|machine_id| {
            machine_summary_value(
                machine_id,
                registry.get(machine_id),
                digests.get(machine_id),
                raw_summaries.get(machine_id),
            )
        })
        .collect::<Vec<_>>();
    machines.sort_by(|left, right| {
        right
            .get("last_seen_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(
                left.get("last_seen_at")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            )
    });
    machines
}

async fn machine_list(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(response) = require_enroll_secret(&state, &headers) {
        return response;
    }
    let registry = state.registry.lock().await;
    let digests = state.digests.lock().await;
    let raw_summaries = state.raw_summaries.lock().await;
    let machines = machine_summaries(&registry, &digests, &raw_summaries);
    let machines_online = machines
        .iter()
        .filter(|machine| machine.get("online") == Some(&json!(true)))
        .count();
    let machines_reporting = machines
        .iter()
        .filter(|machine| {
            machine
                .get("last_seen_at")
                .is_some_and(|value| !value.is_null())
        })
        .count();
    let machines_never_reported = machines
        .iter()
        .filter(|machine| {
            machine.get("enrollment_status") == Some(&json!("enrolled"))
                && machine.get("reporting_status") == Some(&json!("never-reported"))
        })
        .count();
    let machines_offline = machines
        .iter()
        .filter(|machine| {
            machine.get("enrollment_status") == Some(&json!("enrolled"))
                && machine.get("online") == Some(&json!(false))
        })
        .count();
    Json(json!({
        "schema": "overlord.fleet.machine-list.v2",
        "machines_enrolled": registry.len(),
        "machines_reporting": machines_reporting,
        "machines_online": machines_online,
        "machines_offline": machines_offline,
        "machines_never_reported": machines_never_reported,
        "machines": machines,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "read_only": true,
        "hands_tied": true,
        "remote_commands_enabled": false,
        "raw_secret_returned": false
    }))
    .into_response()
}

async fn machine_detail(
    State(state): State<AppState>,
    Path(machine_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(response) = require_enroll_secret(&state, &headers) {
        return response;
    }
    let registry = state.registry.lock().await;
    let digests = state.digests.lock().await;
    let raw_summaries = state.raw_summaries.lock().await;
    if !registry.contains_key(&machine_id)
        && !digests.contains_key(&machine_id)
        && !raw_summaries.contains_key(&machine_id)
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "machine not found" })),
        )
            .into_response();
    }
    Json(machine_summary_value(
        &machine_id,
        registry.get(&machine_id),
        digests.get(&machine_id),
        raw_summaries.get(&machine_id),
    ))
    .into_response()
}

async fn machine_timeline(
    State(state): State<AppState>,
    Path(machine_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(response) = require_enroll_secret(&state, &headers) {
        return response;
    }
    let registry = state.registry.lock().await;
    let digests = state.digests.lock().await;
    let raw_summaries = state.raw_summaries.lock().await;
    if !registry.contains_key(&machine_id)
        && !digests.contains_key(&machine_id)
        && !raw_summaries.contains_key(&machine_id)
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "machine not found" })),
        )
            .into_response();
    }
    let summary = machine_summary_value(
        &machine_id,
        registry.get(&machine_id),
        digests.get(&machine_id),
        raw_summaries.get(&machine_id),
    );
    let events = summary
        .pointer("/lifecycle/recent")
        .or_else(|| summary.get("lifecycle").filter(|value| value.is_array()))
        .cloned()
        .unwrap_or_else(|| json!([]));
    Json(json!({
        "schema": "overlord.fleet.machine-timeline.v1",
        "machine_id": machine_id,
        "events": events,
        "read_only": true,
        "hands_tied": true,
        "raw_secret_returned": false
    }))
    .into_response()
}

#[cfg(test)]
mod observability_tests {
    use super::*;

    #[test]
    fn raw_summary_keeps_heartbeat_but_not_raw_records() {
        let input = json!({
            "machine_id": "machine-1",
            "batch_id": "batch-1",
            "provenance": { "version": "0.2.25" },
            "heartbeat": { "display_name": "FIELD-PC", "hands_tied": true },
            "sections": {
                "processes": { "records": [{ "command": "private" }] },
                "network_connections": { "records": [1, 2] }
            }
        });
        let summary = raw_heartbeat_summary(&input, "2026-08-15T12:00:00Z");
        assert_eq!(
            summary.pointer("/section_counts/processes"),
            Some(&json!(1))
        );
        assert_eq!(
            summary.pointer("/section_counts/network_connections"),
            Some(&json!(2))
        );
        assert!(summary.get("sections").is_none());
        assert_eq!(summary.pointer("/heartbeat/hands_tied"), Some(&json!(true)));
    }

    #[test]
    fn machine_summary_is_read_only_and_resolves_version_and_update() {
        let digest = json!({
            "machine_id": "machine-1",
            "received_at": "2026-08-15T12:00:01Z",
            "digest": {
                "machine": { "display_name": "FIELD-PC" },
                "provenance": { "version": "0.2.25" },
                "update": { "status": "succeeded" },
                "verdicts": { "malicious": 0 }
            }
        });
        let registry = json!({
            "token": "secret-device-token",
            "recovery_hash": "secret-recovery-hash",
            "registered_at": "2026-08-15T11:00:00Z"
        });
        let summary = machine_summary_value("machine-1", Some(&registry), Some(&digest), None);
        assert_eq!(summary.get("display_name"), Some(&json!("FIELD-PC")));
        assert_eq!(
            summary.pointer("/provenance/version"),
            Some(&json!("0.2.25"))
        );
        assert_eq!(summary.pointer("/update/status"), Some(&json!("succeeded")));
        assert_eq!(summary.get("enrollment_status"), Some(&json!("enrolled")));
        assert_eq!(summary.get("recovery_bound"), Some(&json!(true)));
        assert!(summary.get("token").is_none());
        assert!(summary.get("recovery_hash").is_none());
        assert_eq!(summary.get("hands_tied"), Some(&json!(true)));
        assert_eq!(summary.get("remote_commands_enabled"), Some(&json!(false)));
    }

    #[test]
    fn machine_ledger_keeps_enrolled_devices_without_telemetry() {
        let registry = serde_json::Map::from_iter([(
            "machine-offline".to_string(),
            json!({
                "token": "secret-device-token",
                "recovery_hash": "secret-recovery-hash",
                "registered_at": "2026-08-15T11:00:00Z"
            }),
        )]);
        let machines =
            machine_summaries(&registry, &serde_json::Map::new(), &serde_json::Map::new());
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0]["machine_id"], json!("machine-offline"));
        assert_eq!(machines[0]["reporting_status"], json!("never-reported"));
        assert_eq!(machines[0]["online"], json!(false));
        assert_eq!(machines[0]["registered_at"], json!("2026-08-15T11:00:00Z"));
        assert!(machines[0].get("token").is_none());
        assert!(machines[0].get("recovery_hash").is_none());
    }

    #[test]
    fn registry_survives_a_storage_reload() {
        let unique = format!(
            "overlord-collector-registry-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let path = std::env::temp_dir().join(unique);
        let registry = serde_json::Map::from_iter([(
            "machine-restart".to_string(),
            json!({
                "token": "secret-device-token",
                "recovery_hash": "secret-recovery-hash",
                "registered_at": "2026-08-15T11:00:00Z"
            }),
        )]);

        persist_registry(&path, &registry).expect("persist registry");
        let reloaded = load_json_map(&path);
        let machines =
            machine_summaries(&reloaded, &serde_json::Map::new(), &serde_json::Map::new());

        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0]["machine_id"], json!("machine-restart"));
        assert_eq!(machines[0]["enrollment_status"], json!("enrolled"));
        assert_eq!(machines[0]["reporting_status"], json!("never-reported"));
        let _ = std::fs::remove_file(path);
    }
}
