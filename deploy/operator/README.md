# Single-operator deployment

Run a deposits-node operator next to your existing Bitcoin + Lightning
infrastructure. Designed for the audience [PACKAGING_PLAN.md](../../PACKAGING_PLAN.md)
calls out: self-custody Bitcoiners who already run a Lightning node
(Alby Hub, Umbrel + LDK/LND/CLN, Start9, plain Linux) and want to add
the deposits-operator role on top.

No bundled `bitcoind`, no bundled electrs, no bundled Lightning daemon.
The operator declares what's already running via env vars; the deposits
containers slot in next to it.

## What you need first

- **A running Bitcoin full node.** Either `bitcoind` (with `-server=1` and
  `-txindex=1` if you'll use `CHAIN_BACKEND=bitcoind`), or any other
  source exposing one of: esplora HTTP, electrum protocol, bitcoind RPC.
- **A running Lightning daemon.** One of:
  - LDK Server (via `ldk-server-cli`)
  - LND (REST + macaroon — the most common Umbrel/Start9 choice)
  - CLN (Unix socket — needs to be reachable from inside our container,
    typically via bind mount)
- **At least one nostr relay URL** for ledger publishing. The project runs
  `wss://relay.bitcoindeposits.net` on mainnet; you can also self-host
  with `strfry` or `nostr-rs-relay`.
- **`docker compose`** v2.x.
- **Rust toolchain** *only* if you're building the image locally. Pre-built
  images are pulled from `ghcr.io/bitcoin-deposits/deposits-node:latest`
  once that registry path lands.

## Forming a quorum with peers

Once your operator is running, the next step is forming a quorum with
other operators (Q-1 cosigners). See [QUORUM.md](./QUORUM.md) for the
walkthrough — covers `quorum show-identity`, sharing pubkeys + ledger
IDs out of band, and running `quorum form-with --begin` to add members
and rotate reserves in a single command.

## 5-minute quickstart

From this directory (`deploy/operator/`):

```bash
# 1. Build the image locally (until pre-built images ship).
( cd ../../ && docker build -f deposits-node/Dockerfile -t deposits-node:latest . )

# 2. Run the wizard. Walks you through seed + LN backend + chain backend
#    + relays, generates the signer keys, allowlists the daemon.
./init.sh

# 3. If your Lightning backend or chain backend needs files mounted from
#    the host (LND macaroon, CLN socket, bitcoind cookie), create
#    docker-compose.override.yml — see "Bind mounts" below.

# 4. Bring it up.
docker compose up -d

# 5. Watch it sync.
docker compose logs -f deposits-node
```

## What the wizard does

`./init.sh` is interactive but idempotent. It:

1. **Copies** `.env.example` → `.env` (if `.env` doesn't exist yet).
2. **Prompts** for network + operator name + LN backend + chain backend +
   relays. For each field, the current value in `.env` is the default.
3. **Generates or imports** the operator seed (saves to
   `./signer-data/seed`, mode 0600).
4. **Runs** `deposits-signer init` to create the signer's transport keypair.
5. **Runs** `deposits-node transport-pubkey` to derive the daemon's
   transport pubkey.
6. **Runs** `deposits-signer trust add <daemon-pubkey>` so the signer will
   accept the daemon's connection.
7. **Writes** the resulting `SIGNER_PUBKEY` back into `.env` so the daemon
   pins it.

Re-run safely — already-initialized signer dirs are detected and skipped;
already-set `.env` values become the prompt defaults.

## Bind mounts (per backend)

The base `docker-compose.yml` does NOT try to bind-mount LN/bitcoin
credentials. You declare those mounts in a `docker-compose.override.yml`
that compose automatically merges in. Pick the snippet matching your
backend:

### LND macaroon + TLS cert (LIGHTNING_BACKEND=lnd, file-based auth)

```yaml
# docker-compose.override.yml
services:
  deposits-node:
    volumes:
      - /var/lib/lnd/data/chain/bitcoin/mainnet/admin.macaroon:/run/secrets/lnd-admin.macaroon:ro
      - /var/lib/lnd/tls.cert:/run/secrets/lnd-tls.cert:ro
```

Then in `.env`:
```
LND_MACAROON_FILE=/run/secrets/lnd-admin.macaroon
LND_TLS_CERT_FILE=/run/secrets/lnd-tls.cert
```

If your daemon's container can't reach your LND container at
`https://127.0.0.1:8080`, override the URL too:
```
LND_REST_URL=https://lnd-container:8080
```
…and add the LND container's network to the `external` network in the
override.

### CLN socket (LIGHTNING_BACKEND=cln)

```yaml
# docker-compose.override.yml
services:
  deposits-node:
    volumes:
      - /var/lib/cln:/run/cln:ro
```

Then in `.env`:
```
CLN_SOCKET_PATH=/run/cln/bitcoin/lightning-rpc
```

### bitcoind cookie (CHAIN_BACKEND=bitcoind, cookie auth)

```yaml
# docker-compose.override.yml
services:
  deposits-node:
    volumes:
      - /var/lib/bitcoin/.cookie:/run/secrets/bitcoin-cookie:ro
```

Then in `.env`:
```
BITCOIND_COOKIE_FILE=/run/secrets/bitcoin-cookie
BITCOIND_RPC_URL=http://host.docker.internal:8332    # or your bitcoind hostname
```

(`host.docker.internal` works on Docker Desktop; on Linux either use
`extra_hosts` or attach the bitcoind container to a shared network.)

## Operating

```bash
# Status
docker compose ps

# Logs
docker compose logs -f deposits-node     # daemon
docker compose logs -f deposits-signer   # signer

# Restart (config change in .env)
docker compose up -d                     # idempotent; restarts changed services

# Stop everything
docker compose down                       # keeps volumes (= keeps your state)

# Stop AND wipe (DESTRUCTIVE — only when starting over)
docker compose down -v                    # removes signer + daemon volumes
```

The metrics endpoint (Prometheus format) is exposed on
`127.0.0.1:9100/metrics` by default. Change `METRICS_BIND` in `.env` to
`0.0.0.0:9100` if you scrape from a different host.

## Backup checklist

The only non-reconstructible state is the operator seed. Everything else
(ledger history, BDK wallet state, anti-equivocation store) can be
rebuilt from the seed + relay history.

- **Seed**: lives in the `signer_data` named volume at
  `/var/lib/dsigner/seed` (inside the container). Back it up to multiple
  media, multiple physical locations. If you lose this, collateral is
  forfeit.
- **Anti-equivocation store**: in the same `signer_data` volume at
  `anti_equivocation.json`. Losing this lets a compromised daemon
  reset the signer's max-seq view; back it up too, but it's less
  catastrophic than the seed.
- **Daemon state** (`node_data` volume): rebuildable from relay history,
  but slow — back it up if you want fast disaster recovery.

Volume locations on the host depend on your Docker storage driver; for
the default `local` driver:
```
docker volume inspect operator_signer_data
```

## Troubleshooting

### Signer rejected connection (node not in allowlist)

The daemon's transport pubkey doesn't match what's in the signer's
allowlist. Re-run `./init.sh` — step 5 re-allowlists the daemon's
current pubkey (idempotent).

### Daemon says "no connection to LDK / LND / CLN"

Container can't reach your Lightning daemon. Check:
- `docker compose exec deposits-node ping <host>` — is the host reachable?
- For LND: `docker compose exec deposits-node curl -k https://<host>:8080/v1/getinfo` (with macaroon header)
- For CLN: `docker compose exec deposits-node ls /run/cln` — is the socket mounted?

Most often this is a `host.docker.internal` vs `localhost` mixup; the
daemon container can't reach the host's `127.0.0.1`.

### "esplora returned status 502"

Your esplora endpoint is down or behind a load balancer that's
failing. Switch to `CHAIN_BACKEND=bitcoind` if your bitcoin node is
healthy; that's one fewer thing in the chain of dependencies.

### Anti-equivocation refusal during normal operation

`deposits-signer` is refusing to sign because the seq it's being asked
to sign isn't strictly greater than the last one it signed for the same
ledger. If you see this:
- During the first run after a restart: probably the daemon's local state
  drifted from the signer's view. Cleanest fix is to let the daemon
  resync from the relay; restart `deposits-node` only (NOT
  `deposits-signer`).
- Persistently: something is genuinely trying to double-sign. Check
  `anti_equivocation.json` in the signer volume against the daemon's
  current ledger heads.

See [SIGNER.md](../../SIGNER.md) for the full anti-equivocation
machinery.

## What's bundled vs not

| Component | Inside this compose | Comes from |
|---|---|---|
| `deposits-node` daemon | ✓ | This image |
| `deposits-signer` | ✓ | This image (same image, different binary) |
| Bitcoin full node | ✗ | Your existing `bitcoind` |
| Esplora / electrs / electrum | ✗ | Your existing or public infra |
| Lightning daemon | ✗ | Your existing LDK/LND/CLN |
| Nostr relay | ✗ | `wss://relay.bitcoindeposits.net` or your own |
| Prometheus / Grafana | ✗ | Scrape `:9100/metrics` from your own |
| LNURL gateway | ✗ | Separate deployment if needed |

The deliberate minimalism is the point: drop deposits-node into an
already-running self-hosted stack, configure what it talks to, run it.
Bundling more would either fight your existing setup or force a parallel
one. See [PACKAGING_PLAN.md](../../PACKAGING_PLAN.md) for the bigger
picture.
