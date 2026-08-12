# Running the LDK Server fork (hold-invoice holder)

`LIGHTNING_BACKEND=ldk` talks to an **LDK Server** over its REST API. The
deposits-node image already ships the *client* (`ldk-server-cli` + a
wrapper), so nothing extra is needed on the deposits side. What you have to
stand up yourself is the *server* — and it must be **our fork**, not
upstream `ldk-server`.

## Why the fork (upstream won't work)

The deposits protocol receives Lightning payments as **hold invoices**: the
operator issues an invoice for a payment hash whose preimage it does *not*
know, holds the incoming HTLC in the `Accepted` state, and only settles once
the depositor reveals the preimage on-ledger (DEP-10). Upstream ldk-server
has no API for this. Our fork
([`bitcoin-deposits/ldk-server`](https://github.com/bitcoin-deposits/ldk-server),
branch **`deposits-hold-invoices`**) adds:

- `bolt11-receive-for-hash` — issue an invoice for a caller-supplied hash
- `bolt11-claim` / `bolt11-fail` — settle or cancel a held HTLC
- `GetClaimableDetails` — surface held-HTLC state + claim deadline so the
  daemon can decide when to settle vs. let it lapse
- the `rest_service_address` config field (upstream config parsing
  **rejects** it)

Point `LIGHTNING_BACKEND=ldk` at a stock ldk-server and invoice receive
fails at the first `bolt11-receive-for-hash` call.

## 1. Build

Needs a Rust toolchain. The fork's `deposits-hold-invoices` branch is the one
you want — the repo's `main` tracks upstream (which has since moved to gRPC),
so the `-b` flag matters:

```bash
git clone -b deposits-hold-invoices https://github.com/bitcoin-deposits/ldk-server.git
cd ldk-server
cargo build --release -p ldk-server -p ldk-server-cli
# binaries: ./target/release/ldk-server  and  ./target/release/ldk-server-cli
```

## 2. Configure

Create `config.toml`. Mainnet example (adjust paths/ports to your host):

```toml
[node]
network = "bitcoin"                          # bitcoin | testnet | signet | regtest
listening_addresses = ["0.0.0.0:9735"]       # public P2P; forward this port
rest_service_address = "127.0.0.1:3201"      # REST API — FORK-ONLY field
alias = "my-deposits-ln"

[storage.disk]
dir_path = "/var/lib/ldk-server/data"

[log]
level = "Info"
file = "/var/lib/ldk-server/ldk-server.log"

[tls]
hosts = ["localhost"]                        # add the hostname deposits-node uses to reach it

[esplora]
server_url = "https://blockstream.info/api"  # your electrs/esplora; reuse ESPLORA_URL if you have one
```

Chain source is esplora (this is what the fork's integration harness
exercises). Reuse whatever esplora/electrs your `bitcoind`/electrs already
exposes rather than adding a public dependency.

## 3. Run it durably

`ldk-server` takes the config path as its one argument. A systemd unit:

```ini
# /etc/systemd/system/ldk-server.service
[Unit]
Description=LDK Server (deposits hold-invoice holder)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ldk-server /etc/ldk-server/config.toml
Restart=on-failure
RestartSec=5
User=ldk
StateDirectory=ldk-server

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now ldk-server
```

On first start it generates two files under `dir_path`:

- `data/<network>/api_key` — 32 raw bytes (e.g. `data/bitcoin/api_key`)
- `data/tls.crt` — self-signed REST cert

## 4. Extract the credentials deposits-node needs

`LDK_API_KEY` is the **hex** of the api_key file; `LDK_TLS_CERT` is the path
to the cert:

```bash
xxd -p -c64 /var/lib/ldk-server/data/bitcoin/api_key   # -> 64-hex api key
# LDK_TLS_CERT = /var/lib/ldk-server/data/tls.crt
```

Smoke-test the server with the bundled CLI before wiring it in:

```bash
ldk-server-cli -b localhost:3201 \
  -a "$(xxd -p -c64 /var/lib/ldk-server/data/bitcoin/api_key)" \
  -t /var/lib/ldk-server/data/tls.crt \
  get-node-info
```

## 5. Wire into deposits-node

In `deploy/operator/.env`:

```
LIGHTNING_BACKEND=ldk
LDK_HOST=host.docker.internal      # host running ldk-server, reachable from the container
LDK_PORT=3201                      # = rest_service_address port
LDK_API_KEY=<64-hex from step 4>
LDK_TLS_CERT=/run/secrets/ldk-tls.cert
```

The container must be able to **reach the REST address** and **read the TLS
cert**:

- **Reachability.** `rest_service_address = 127.0.0.1:3201` binds host
  loopback, which the container can't reach as `localhost`. Use
  `LDK_HOST=host.docker.internal` (Docker Desktop), or the docker bridge
  gateway on Linux, or bind ldk-server on the docker network and use its
  hostname. Add the cert host to `[tls].hosts` so cert validation passes for
  whatever name you connect by.
- **TLS cert.** Bind-mount it in `docker-compose.override.yml`:

  ```yaml
  services:
    deposits-node:
      volumes:
        - /var/lib/ldk-server/data/tls.crt:/run/secrets/ldk-tls.cert:ro
  ```

`LDK_CLI` does **not** need to be set: the image ships `ldk-server-cli` and
a flag-translating wrapper, so the default resolves inside the container. If
you instead run `deposits-node` on bare metal (systemd, not docker), make
sure `ldk-server-cli` is on its `PATH`, or set `LDK_CLI=/path/to/ldk-server-cli`.

## 6. Fund + open inbound liquidity

To *receive* deposits, the ldk node needs inbound channel capacity. Fund it
on-chain (`ldk-server-cli … onchain-receive`) and have a peer open a channel
in, or open outbound and use a channel with inbound. Note: ldk-node rejects
inbound anchor channels unless it holds an on-chain anchor reserve, so fund
it before requesting inbound.

## 7. Verify end to end

With the LN-backend startup gate (the daemon refuses to boot if its
configured backend is unreachable), a clean start is the smoke test:

```bash
docker compose up -d
docker compose logs -f deposits-node    # expect: Lightning backend reachable (ldk)
```

If it logs a refusal instead, re-check reachability (step 5) — that's the
gate doing its job rather than letting invoice receive fail later.

## Multiple operators sharing one LDK node

The bundled `ldk-cli-wrapper.sh` adds self-pay handling so several operators
on one host can share a single ldk-server. See
`deposits-tools/bin/ldk-cli-wrapper.sh`. Set `LDK_CLI` to the wrapper if you
need this; the single-operator path above does not.

## Related

- `bin/setup-ldk-hold.sh` — the regtest harness this runbook is distilled
  from; run it to see the whole lifecycle locally end to end.
- [README.md](./README.md) — the operator deployment this plugs into.
- DEP-10 — the hold-invoice bridge model these endpoints implement.
