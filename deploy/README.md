# deploy

Self-host deployment for fluxpeer. Run commands below from the repository root.
Set and export `FLUXPEER_ADMIN_PASSWORD` before starting the stack to use CLI
registration; Compose passes this automation credential to the control server.

```bash
docker compose -f deploy/docker-compose.yml up -d
```

The default stack runs the control server with embedded SQLite on `fpdata`
(`/data/fluxpeer.db`). `DATABASE_URL` selects PostgreSQL for hosted deployments;
see the optional configuration in `docker-compose.yml`. `Dockerfile` builds the
standalone control server. `Containerfile` builds the unified `fluxpeer` binary
for control, relay and node roles, with `FLUXPEER_DATA_DIR=/data`.

## Control request deadlines

HTTP handlers (including authentication and request body reads) have a 30-second
deadline. Set `FLUXPEER_CONTROL_HTTP_TIMEOUT_SECS` in the control process environment
to an integer from 1 to 3600; invalid values warn and fall back to 30. For Compose,
add it to the control service's `environment`. Expiry returns an empty HTTP 503
and logs ERROR with the method, route template and elapsed milliseconds. Upgraded
WebSocket watch connections keep their existing heartbeat/idle lifecycle.

SQLite and PostgreSQL pool acquisition is limited to 5 seconds. Acquisition
timeouts log ERROR, including in login/watch paths; existing error responses are
preserved. Requests taking over 1 second log WARN, while other completed requests
log DEBUG. These request logs omit credentials, query strings and path parameters.
Deadlines cancel asynchronous work; they cannot preempt synchronous code that
blocks runtime threads. A timed-out write may already have committed: clients
must check state before repeating a mutation.

## SQLite contention and traffic reporting

SQLite connections use a 15000 ms busy timeout. Set
`FLUXPEER_SQLITE_BUSY_TIMEOUT_MS` in the control process environment to 1..=60000
milliseconds to override it; invalid values warn and use 15000. Each connection,
including replacements, enables WAL with `wal_autocheckpoint=1000` pages. Normal
commits checkpoint and reuse WAL frames; long-lived external readers can still
delay checkpoint completion. This is not a hard WAL file-size limit.

Control integrity transactions and stats/endpoints writes retry SQLite BUSY or
LOCKED errors at most twice (three total attempts), with jittered backoff and a
fresh transaction each time. The existing HTTP deadline may end the operation
earlier. Exhausted SQLite contention returns 503 with `Retry-After: 1` and WARN
logs; other database errors retain their existing handling. HTTP deadline 503s
also carry `Retry-After: 1`. PostgreSQL's existing transaction retry policy is
unchanged; SQLite PRAGMAs are never sent to PostgreSQL.

Nodes report traffic every 15 seconds by default. Set
`FLUXPEER_STATS_INTERVAL_SECS` in the node process environment to 1..=3600 seconds;
values below 5 are clamped to 5, invalid values fall back to 15. Unchanged
acknowledged samples are skipped (including stable per-peer data). Stats failures
are nonfatal and double the delay up to eight times the interval; success resets
the delay. Reporting sleeps after completion, so slow requests cannot create a
catch-up burst. The stats `updated_at` timestamp is the last changed sample,
not a node liveness heartbeat.

## Relay identity and registration

Enable the optional relay service and its persistent `fprelaydata` volume:

```bash
docker compose -f deploy/docker-compose.yml --profile relay up -d --build
RELAY_PUBLIC_KEY=$(docker compose -f deploy/docker-compose.yml exec -T relay-server fluxpeer relay public-key)
# Set CONTROL_URL, RELAY_ENDPOINT, NETWORK_ID and FLUXPEER_ADMIN_PASSWORD for your deployment.
fp --server "$CONTROL_URL" relay add self-host "$RELAY_ENDPOINT" \
  --network-id "$NETWORK_ID" --node-id fluxpeer-relay --public-key "$RELAY_PUBLIC_KEY"
# The unified binary offers the same management command as `fluxpeer ctl ...`.
```

`RELAY_ENDPOINT` is the address nodes can reach, including the published port
(default 3478). TCP carries relay traffic and UDP serves STUN. The control directory
supplies the pin to enrolled nodes. For a manually configured endpoint, set
`relay_public_key` to the same public key in the node config.

The relay creates `/data/relay.key` (0600), backed by the named volume. Preserve
this volume across container replacement and upgrades; `down -v` deletes it.
Changing the identity requires updating the directory and explicit node pins.
`fluxpeer relay public-key` creates the key if absent, prints only its hex public
key and exits without a listener. `--key-file PATH` selects a specific file;
server startup must use `FLUXPEER_RELAY_KEY_FILE=PATH` to select that same override.
Without an override, both commands use `$FLUXPEER_DATA_DIR/relay.key`, defaulting
to `/var/lib/fluxpeer/relay.key` outside the container image. Missing parent
directories are created with mode 0700; existing permissions are retained.

The Podman driver also retains a named relay identity volume:

```bash
sudo deploy/fluxpeer-podman up relay --port 3478 --data fluxpeer-relay-data
RELAY_PUBLIC_KEY=$(sudo podman exec fluxpeer-relay fluxpeer relay public-key)
fp --server "$CONTROL_URL" relay add self-host "$RELAY_ENDPOINT" \
  --network-id "$NETWORK_ID" --node-id fluxpeer-relay --public-key "$RELAY_PUBLIC_KEY"
```

`fluxpeer-relay-data` is the default when `--data` is omitted. `rm relay` and
subsequent `up relay` preserve the named volume. Run key inspection in the same
container/environment as startup; a host CLI with another state directory would
produce a different identity.

Existing deployments must upgrade the relay, register its public key, then upgrade
nodes; version-1 relay clients are rejected during this transition. The control
server must support the `public_key` field before registration. See
[relay authentication](../docs/relay-auth.md) for protocol boundaries and upgrade
steps. Live container upgrades and cross-host traffic require separate QA; these
configuration changes are covered locally by syntax checks and mocked commands.
