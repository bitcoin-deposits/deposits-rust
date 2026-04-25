# Bitcoin Deposits

Collateral-secured verifiable ledgers for off-chain Bitcoin custody.

Operators maintain append-only hash chains of signed updates tracking deposits, transfers, and fees. Each operator's UTXO is split into reserves (deposit capacity) and collateral (security bond), both held in the same Taproot output controlled by the quorum. If the operator misbehaves, the quorum confiscates the collateral.

See the [DEP specifications](DEP-01.md) for protocol details and [PROPOSAL.md](PROPOSAL.md) for the collateral model rationale.

## Crates

| Crate | Description |
|-------|-------------|
| [deposits-protocol](deposits-protocol/) | Wire format, types, TLV encoding. Pure protocol definitions with no state machine. |
| [deposits-core](deposits-core/) | Ledger state machine, validation, signing, conformance checking. No network or IO. |
| [deposits-node](deposits-node/) | BDK wallet + Nostr transport. The full node daemon, wallet CLI, and utility binaries. |
| [deposits-tools](deposits-tools/) | Test tooling, admin scripts, Docker infrastructure, integration test environment. |
| [tests](tests/) | End-to-end integration tests simulating multi-operator protocol flows. |

## Building

```bash
cargo build --workspace
```

Requires Rust 1.80+ (uses edition 2021).

## Testing

```bash
# Unit and integration tests (no external services needed)
cargo test --workspace

# Lint checks
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Running

### Node daemon

```bash
cargo run --release --bin deposits-node -- run \
    --seed <hex-seed> \
    --network regtest \
    --esplora http://localhost:3000 \
    --relay ws://localhost:7777 \
    --slow-relay ws://localhost:17779 \
    --data-dir ./data
```

### Wallet CLI

```bash
cargo run --release --bin deposits-wallet -- \
    --seed <hex-seed> \
    --relay ws://localhost:7777 \
    discover
```

### Local test network

The test environment uses Docker for infrastructure (bitcoind, electrs) and runs operator nodes as bare processes:

```bash
cd deposits-tools

# Start infrastructure
docker compose up -d

# Build and set up a 10-operator Q=3 network
cargo build --release
./bin/setup.sh 3

# Or a 16-operator Q=5 network
./bin/setup.sh 5
```

`setup.sh Q` creates `3*Q+1` operators, each with 3 ledgers and independent Q-member quorums. No collateral deposits needed -- collateral is part of the UTXO.

### Docker

```bash
# Build the production image
docker build -t deposits-node -f deposits-node/Dockerfile .

# Run with environment variables
docker run -e NODE_SEED=<hex> -e NETWORK=bitcoin \
    -e ELECTRUM_URL=http://electrs:3000 \
    -e LEDGER_RELAY=wss://relay.example.com \
    -v ./data:/data deposits-node
```

See [deposits-tools/docker/docker-compose.nodes.yml](deposits-tools/docker/docker-compose.nodes.yml) for a compose template.

## Architecture

```
deposits-protocol    Pure types, wire format, TLV codec
       |
deposits-core        State machine, validation, signing
       |
deposits-node        BDK wallet, Nostr transport, daemon
       |
deposits-tools       Scripts, Docker, test infrastructure
```

Each operator runs a `deposits-node` daemon that:
- Manages Bitcoin reserves via BDK (on-chain UTXOs)
- Communicates with peers via Nostr relays (NIP-04 DMs, public events)
- Maintains hash-chained ledgers with co-signatures from quorum members
- Detects conformance violations on watched ledgers

See [WHITEPAPER.md](WHITEPAPER.md) for design rationale.

## License

MIT OR Apache-2.0
