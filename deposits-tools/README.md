# deposits-tools

Test tooling, admin scripts, and Docker infrastructure for Bitcoin Deposits.

## Quick Start

```bash
# Start infrastructure (bitcoind, electrs)
docker compose up -d

# Build binaries
cd .. && cargo build --release && cd deposits-tools

# Set up a Q=3 network (10 operators, 30 ledgers)
./bin/setup.sh 3

# Or Q=5 (16 operators, 48 ledgers)
./bin/setup.sh 5
```

`setup.sh Q` creates `3*Q+1` operators with 3 ledgers each, forms Q-member quorums, and activates them. Two relays: one durable (ledgers), one ephemeral (messaging). No collateral deposit phase -- collateral is part of the UTXO.

## Architecture

```
Docker:           bitcoind + electrs (blockchain infrastructure)
Host processes:   deposits-node (one per operator) + strfry (2 relays)
```

Each operator runs a `deposits-node run` daemon that manages BDK wallets, communicates via Nostr relays, and maintains co-signed hash-chain ledgers.

## Scripts

| Script | Description |
|--------|-------------|
| `bin/setup.sh Q` | Set up a Q-quorum network from scratch |
| `bin/redeploy.sh` | Rebuild binaries, restart nodes (preserves data) |
| `bin/setup-attestation.sh` | Set up lightning-address attestation service (lnaddr-attest) |
| `bin/setup-htlc-agent.sh` | Set up HTLC routing agent |
| `bin/setup-lnurl.sh` | Set up LNURL server |

## Docker Infrastructure

| Service | Host Port | Description |
|---------|-----------|-------------|
| bitcoind | 18543 (RPC) | Regtest node |
| electrs | 3201+ | Blockchain indexer (per-group) |
| strfry (ledgers) | 7779 | Durable relay for ledger updates |
| strfry (messaging) | 7780 | Ephemeral relay for request/response |

## Manual Operations

```bash
# Mine blocks
docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass -rpcwallet=faucet -generate 10

# Check an operator's ledgers
source bin/_common.sh && run_node_cmd alice ledger list
```
