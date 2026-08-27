# Project Overlord — fleet telemetry collector

A slim, cross-platform HTTPS service that **receives** read-only endpoint telemetry from Project
Overlord installs and stores it. It has **no detection logic** (the brain stays in the private core)
and **no secrets in source** — the scoped ingest token is supplied at runtime.

It only records observations posted to it. Nothing it returns can act on any machine.

## Endpoints

The operator-facing machine ledger includes every enrolled device, including devices that are
currently offline or have not uploaded their first heartbeat. It returns only bounded heartbeat
summaries and never returns full raw activity or credential material.

- `GET /api/fleet/machines` - list enrolled machines with online/offline/never-reported state plus build, runtime, scan, update, and delivery state.
- `GET /api/fleet/machines/{machine_id}` - retrieve one machine's latest bounded heartbeat.
- `GET /api/fleet/machines/{machine_id}/timeline` - retrieve its bounded desktop lifecycle timeline.

- `GET /health` — liveness plus storage durability readiness.
- `POST /api/fleet/raw-telemetry` — append the machine's raw activity envelope (deduped by `batch_id`).
- `POST /api/fleet/telemetry` — store the machine's latest detection digest.
- `GET /api/fleet/telemetry` — operator rollup of the latest per-machine digests.

All ingest/read endpoints require header `X-Overlord-Ingest-Token`.

## Configuration (environment)

- `OVERLORD_INGEST_TOKEN` (required) — the scoped ingest credential. If unset, all ingest is rejected.
- `PORT` — port to bind (platforms like Render inject this automatically).
- `OVERLORD_DATA_DIR` — where per-machine logs are written (default `./data`; `/data` in Docker).
- `OVERLORD_PERSISTENT_STORAGE` — set to `true` only when `OVERLORD_DATA_DIR` is backed by a persistent volume.

## Required Render storage setup

The collector must not rely on Render's ephemeral filesystem. On the Render web service:

1. Attach a persistent disk mounted at `/var/data`.
2. Set `OVERLORD_DATA_DIR=/var/data`.
3. Set `OVERLORD_PERSISTENT_STORAGE=true`.
4. Redeploy and verify `/health` reports `storage.status: persistent`.

Without these settings, `/health` reports `ephemeral-risk`. The collector still receives data, but
its device ledger can be lost when the service is redeployed or recreated. After this durable build
is deployed, an existing endpoint only needs to come online once to recover or re-register using
its locally stored recovery proof; it then remains in the ledger while offline.

## Run locally

```
OVERLORD_INGEST_TOKEN=your-token cargo run --release
```
