# fluxpeer control-server — multi-stage build.
# Build context is the repo root: `docker build -f deploy/Dockerfile .`
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p fluxpeer-control-server

FROM debian:bookworm-slim
RUN useradd -r -u 10001 fluxpeer && mkdir -p /data && chown fluxpeer:fluxpeer /data
COPY --from=build /src/target/release/control-server /usr/local/bin/control-server
USER fluxpeer
# WORKDIR /data so the default embedded SQLite file (`fluxpeer.db`) lands on the
# mounted /data volume and survives restarts. Override with
# DATABASE_URL=postgres://… for the commercial/hosted deployment.
WORKDIR /data
VOLUME ["/data"]
ENV FLUXPEER_CONTROL_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/control-server"]
