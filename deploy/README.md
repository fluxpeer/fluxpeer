# deploy

Self-host deployment for fluxpeer.

```bash
docker compose up -d      # control-server only — embedded SQLite, no DB server
```

The open self-host stack is a **single service**. Storage defaults to an embedded
**SQLite** file on the `fpdata` volume (`/data/fluxpeer.db`) — nothing else to run
or maintain, and plenty for a self-hosted mesh (cf. Headscale). Set
`DATABASE_URL=postgres://…` to use **PostgreSQL** instead; that is opt-in for the
commercial/hosted deployment only (see the commented block in
`docker-compose.yml`).

- `Dockerfile` — multi-stage build of `control-server` (build context = repo root);
  runs as non-root, `WORKDIR /data`, durable `/data` volume.
- `docker-compose.yml` — `control-server` + `fpdata` volume. PostgreSQL is a
  commented commercial-only option.

Status: control-server live with durable storage (SQLite default; PostgreSQL via
`DATABASE_URL` — both validated on a real host). **Pending**: `admin-lite`
(SvelteKit) service, `relay-server`. Helm / systemd / NAS packaging later.

> Validated on a Linux host: `control-server` builds and serves on both the SQLite
> default (file created + survives restart) and PostgreSQL (`DATABASE_URL`). Run
> `docker compose config` then `docker compose up -d` to deploy.
