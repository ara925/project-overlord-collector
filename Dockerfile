# Build a small static-ish Linux binary, then run it on a slim base.
FROM rust:slim-bookworm AS build
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -r -u 10001 overlord
COPY --from=build /app/target/release/overlord-collector /usr/local/bin/overlord-collector
# Data dir for per-machine telemetry logs (ephemeral on free tiers; mount a disk for durability).
ENV OVERLORD_DATA_DIR=/data
RUN mkdir -p /data && chown overlord /data
USER overlord
EXPOSE 8787
CMD ["overlord-collector"]
