# Project Overlord — fleet telemetry collector

A slim, cross-platform HTTPS service that **receives** read-only endpoint telemetry from Project
Overlord installs and stores it. It has **no detection logic** (the brain stays in the private core)
and **no secrets in source** — the scoped ingest token is supplied at runtime.

It only records observations posted to it. Nothing it returns can act on any machine.

## Endpoints

- `GET /health` — liveness.
- `POST /api/fleet/raw-telemetry` — append the machine's raw activity envelope (deduped by `batch_id`).
- `POST /api/fleet/telemetry` — store the machine's latest detection digest.
- `GET /api/fleet/telemetry` — operator rollup of the latest per-machine digests.

All ingest/read endpoints require header `X-Overlord-Ingest-Token`.

## Configuration (environment)

- `OVERLORD_INGEST_TOKEN` (required) — the scoped ingest credential. If unset, all ingest is rejected.
- `PORT` — port to bind (platforms like Render inject this automatically).
- `OVERLORD_DATA_DIR` — where per-machine logs are written (default `./data`; `/data` in Docker).

> On free hosting tiers the data directory is ephemeral (resets on redeploy). Mount a persistent
> disk for durable storage when moving past testing.

## Run locally

```
OVERLORD_INGEST_TOKEN=your-token cargo run --release
```
