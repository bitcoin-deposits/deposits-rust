# Test Network Operations

## Relay Architecture

Two shared relays handle all traffic:

### Ledgers Relay (durable)

- **Purpose**: Persistent storage of all ledger state. The single source of
  truth for discovery, audit, and historical queries.
- **Port**: 17779 (override via `$RELAY_LEDGERS_PORT` or `$RELAY_LEDGERS`).
- **Retention**: Persists all events indefinitely.

The ledgers relay contains:
- **Kind 9100**: Signed ledger updates (LedgerOpen, QuorumAddMember,
  DepositOpen, TransferLock, etc.)
- **Kind 39100**: Ledger advertisements (replaceable, operator metadata)
- **Kind 9103**: Dispute events

### Messaging Relay (ephemeral)

- **Purpose**: Real-time delivery of ephemeral events (cosign requests,
  balance queries, deposit operations). High throughput, low latency.
- **Port**: 17780 (override via `$RELAY_MESSAGING_PORT` or `$RELAY_MESSAGING`).
- **Retention**: Ephemeral. Events expire after a few minutes.

## Node Architecture

Each operator runs `deposits-node run` as a native process:

```
deposits-node run \
    --seed <hex> --name <name> --network regtest \
    --esplora http://localhost:3201 \
    --relay ws://localhost:17779 --relay ws://localhost:17780 \
    --data-dir ./data/<name>
```

The daemon handles all protocol operations: cosigning, deposit opens,
transfers, withdrawals, quorum management, and dispute detection.

## Wallet Architecture

### Discovery (read-only)

The wallet connects to the **ledgers relay** for discovery:

- Ledger advertisements (Kind 39100) -- operator names, fees, reserves, capacity
- Ledger updates (Kind 9100) -- quorum membership, deposit operations
- Dispute events (Kind 9103) -- dispute state

### Interaction (read-write)

The wallet sends requests (Kind 20101) to the **messaging relay** and receives
responses (Kind 20102) on the same relay. The operator's daemon picks up
requests and responds.

## Setup Flow

```bash
./bin/setup.sh 3    # Q=3: 10 operators, 30 ledgers
./bin/setup.sh 5    # Q=5: 16 operators, 48 ledgers
```

`setup.sh Q` runs:
1. **Reset**: Stop nodes + relays, clear data
2. **Start relays**: Ledgers (17779) + messaging (17780) — defaults; both overridable
3. **Fund**: Create BDK wallets, send regtest BTC to each
4. **Reserves + Ledgers**: Create UTXOs, open 3 ledgers per operator
5. **Start daemons**: One `deposits-node run` per operator
6. **Quorum formation**: Each ledger gets Q members (dispersed assignment)
7. **Activate**: `quorum begin` rotates reserves to Taproot multisig

No collateral deposit phase. Collateral is part of the UTXO (declared
at LedgerOpen, enforced by co-signers).

### Env-gated optional features

| Env var | Effect |
|---|---|
| `DEPOSITS_USE_SIGNER=1` | Provision a co-located `deposits-signer` per operator; daemons sign through it instead of holding the seed in-process (see [SIGNER.md](../SIGNER.md)) |
| `LIGHTNING_BACKEND=lnd` | Use the `lnd` container (profile `lnd`) instead of LDK. Operators get `LND_REST_URL` / `LND_MACAROON_HEX` / `LND_TLS_CERT_FILE` exported automatically; macaroon is extracted from the container on each run. Start the container first: `docker compose --profile lnd up -d lnd`. |
| `LIGHTNING_BACKEND=cln` | Use the `cln` container (profile `cln`). Operators get `CLN_SOCKET_PATH` pointing at the bind-mounted `lightning-rpc` socket. Start the container first: `docker compose --profile cln up -d cln`. |
| `LIGHTNING_BACKEND=ldk` | Explicit form of the default (shared LDK container) |
| `CHAIN_BACKEND=bitcoind` | Operators read chain data via the regtest bitcoind container's JSON-RPC at port 18543 (user:pass) instead of electrs/esplora. Exercises `BitcoindRpcBackend`. |
| `CHAIN_BACKEND=electrum` | Operators read chain data via electrs's electrum protocol on host port 50101. Exercises `ElectrumBackend`. |
| `CHAIN_BACKEND=esplora` | Explicit form of the default (electrs HTTP at port 3102) |

Combinations work: `LIGHTNING_BACKEND=lnd CHAIN_BACKEND=bitcoind DEPOSITS_USE_SIGNER=1 ./bin/setup.sh 3`
exercises LND, bitcoind RPC, AND the remote signer end-to-end. The
existing tier-3 integration tests in `deposits-test/` pass unchanged
with any combination — protocol behaviour doesn't depend on which
runtime sits under the LightningBackend or ChainBackend trait.

## Infrastructure

### Native Processes

- **strfry relays**: 2 instances (ledgers + messaging)
- **deposits-node**: One per operator

Managed by `setup.sh`. Relay data lives under `data/relays/`. Node data
under `data/<name>/`.

### Docker Containers

- **bitcoind**: Regtest Bitcoin Core node (port 18543 RPC)
- **electrs**: Electrum REST API for chain queries (port 3201+)
- **deposits-prometheus**: Metrics collection (port 9190, optional)
- **deposits-grafana**: Metrics visualization (port 3110, optional)

## Useful Commands

```bash
# Source common functions
source bin/_common.sh

# Check operator status
run_node_cmd alice ledger list
run_node_cmd alice info

# Mine blocks
docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass -rpcwallet=faucet -generate 10

# Rebuild and restart (preserves data)
./bin/redeploy.sh
```

## Docker Production

Build the production image:

```bash
docker build -t deposits-node -f deposits-node/Dockerfile .
```

Run with environment:

```bash
docker run -d \
    -e NODE_SEED_FILE=/secrets/seed \
    -e NETWORK=bitcoin \
    -e ELECTRUM_URL=http://electrs:3000 \
    -e LEDGER_RELAY=wss://relay.example.com \
    -v ./seed:/secrets/seed:ro \
    -v ./data:/data \
    -p 7777:7777 -p 9100:9100 \
    deposits-node
```

See `docker/docker-compose.nodes.yml` for a compose template.
