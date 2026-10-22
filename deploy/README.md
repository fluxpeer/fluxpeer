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
