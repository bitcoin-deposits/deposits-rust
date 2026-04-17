# Bitcoin Deposits

Collateral-secured verifiable ledgers for off-chain Bitcoin custody.

Operators maintain append-only hash chains of signed updates tracking deposits, transfers, and fees. Quorum members provide collateral backing and co-signatures. Wallets verify the chain, retain evidence, and escalate through the quorum if the operator misbehaves.

See [WHITEPAPER.md](WHITEPAPER.md) for design rationale and [PROTOCOL.md](PROTOCOL.md) for the wire protocol specification.

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
    --slow-relay ws://localhost:7779 \
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

The test environment uses Docker for infrastructure (bitcoind, electrs, strfry relays) and runs operator nodes as bare processes:

```bash
cd deposits-tools

# Start infrastructure
docker compose up -d

# Build and set up 4-operator network
cargo build --release
./bin/reinit.sh

# Run tests
./bin/test-quorum.sh
./bin/test-dispute-4op.sh
```

See [deposits-tools/OPERATIONS.md](deposits-tools/OPERATIONS.md) for detailed operational docs.

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

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system design.

## License

MIT OR Apache-2.0
