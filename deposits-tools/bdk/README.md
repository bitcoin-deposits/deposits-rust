# deposits-bdk Docker Environment

This directory contains Docker configuration for running deposits-bdk test networks.

## Quick Start

```bash
# From this directory
cd deposits-tools/bdk

# Initialize the network (builds images, starts services, funds nodes)
./bin/reinit.sh

# Check status
docker compose ps

# Run tests
./bin/test.sh

# Follow logs
docker compose logs -f

# Stop everything
docker compose down -v
```

## Architecture

Unlike the LDK version which uses Lightning channels, deposits-bdk uses:

- **On-chain UTXOs** for reserves (P2WSH with operator+timelock / partner-multisig)
- **Nostr relays** for peer messaging (NIP-04 encrypted DMs)
- **Electrs** for blockchain indexing (BDK wallet sync)

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Network                        │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   ┌─────────┐    ┌─────────┐    ┌──────────────────┐   │
│   │ Bitcoin │────│ Electrs │────│   deposits-bdk   │   │
│   │  Core   │    │         │    │     nodes        │   │
│   └─────────┘    └─────────┘    └────────┬─────────┘   │
│                                          │              │
│                                    ┌─────┴─────┐        │
│                                    │   Nostr   │        │
│                                    │   Relay   │        │
│                                    └───────────┘        │
└─────────────────────────────────────────────────────────┘
```

## Services

| Service | Container | Host Port | Description |
|---------|-----------|-----------|-------------|
| Bitcoin Core | bdk-bitcoind | 18543 (RPC) | Regtest node |
| Electrs | bdk-electrs | 3102 | Blockchain indexer |
| Nostr Relay | bdk-nostr-relay | 7778 | Strfry relay |
| Alice | bdk-alice | - | Operator node |
| Bob | bdk-bob | - | Operator node |
| Charlie | bdk-charlie | - | Partner node |

## Scripts

### reinit.sh

Reinitializes the entire network:

```bash
./bin/reinit.sh           # Full rebuild and restart
./bin/reinit.sh --quick   # Restart without rebuilding
./bin/reinit.sh --fund    # Just fund nodes (assumes running)
```

### test.sh

Runs health checks and basic tests:

```bash
./bin/test.sh             # Run all tests
./bin/test.sh --health    # Just check service health
./bin/test.sh --verbose   # Show more output
```

## Manual Operations

### Mine blocks

```bash
docker exec bdk-bitcoind bitcoin-cli -regtest \
  -rpcuser=user -rpcpassword=pass \
  -rpcwallet=faucet -generate 1
```

### View node logs

```bash
docker compose logs -f bdk-alice
docker compose logs -f bdk-bob
docker compose logs -f bdk-charlie
```

### Enter dev container

```bash
docker compose --profile dev up -d dev
docker exec -it bdk-dev bash
```

## Port Offsets

Ports are offset from the LDK docker-compose to allow running both networks simultaneously:

| Service | LDK Port | BDK Port |
|---------|----------|----------|
| Bitcoin RPC | 18443 | 18543 |
| Electrs | 3002 | 3102 |
| Nostr | 7777 | 7778 |
