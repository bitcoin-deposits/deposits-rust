# Test Network Operations

## Relay Architecture

Each deposits node has its own dedicated Nostr relay for real-time inter-operator
traffic (cosign requests/responses, ephemeral coordination). There is also a
shared **ledgers relay** that durably persists all non-ephemeral events.

### Node Relays (per-operator)

- **Purpose**: Real-time delivery of ephemeral events (cosign requests, cosign
  responses, balance queries). High throughput, low latency.
- **Retention**: `expireAllEvents = true`. All events are treated as ephemeral
  and expire after `ephemeralEventsLifetimeSeconds` (default 300s). This keeps
  the relay fast and prevents unbounded storage growth.
- **Ports**: alice=7801, bob=7802, charlie=7803, diana=7804
- **Config**: `strfry-performance/strfry.conf`

Node relays do NOT persist ledger updates (Kind 9100), advertisements (Kind
39100), or any other data that needs to survive beyond a few minutes. They are
purely real-time message buses.

### Ledgers Relay (shared, durable)

- **Purpose**: Persistent storage of all ledger state. The single source of
  truth for discovery, audit, and historical queries.
- **Retention**: Persists all events indefinitely. Drops ephemeral kinds
  (20000-29999) via write policy to avoid storing cosign chatter.
- **Port**: 7779
- **Config**: `strfry-performance/strfry-slow.conf`
- **Ingestion**: Streams from all node relays via `strfry stream` to capture
  events that nodes publish to their own relays.

The ledgers relay should contain:
- **Kind 9100**: Signed ledger updates (LedgerOpen, QuorumAddMember,
  CollateralAttestation, DepositOpen, TransferLock, etc.)
- **Kind 39100**: Ledger advertisements (replaceable, operator metadata)
- **Kind 9103**: Dispute events

## Node Architecture (dockerless)

Operator nodes run as native processes on the host. Each node consists of:

1. **Daemon** (`deposits-node run`): Long-running process that handles
   transfer_lock, transfer_complete, auto_complete_deposits, cosign requests,
   and periodic maintenance. Publishes to its own relay as primary; subscribes
   to all relays for reads.

2. **Nostr watchers** (`deposits-node nostr watch <ledger_id>`): One per ledger.
   Handles deposit_open, make_offer, withdraw, collateral_lock, and other
   request types that the daemon doesn't process. Listens on the node's own
   relay.

### Relay Assignment

Each node publishes events to its **own relay** (the first `--relay` argument).
The daemon code uses the first relay as the "primary" for publishing; additional
relays are for subscriptions/reads only.

```
alice:   --relay ws://localhost:7801 --relay ws://localhost:7802 ...
bob:     --relay ws://localhost:7802 --relay ws://localhost:7801 ...
charlie: --relay ws://localhost:7803 --relay ws://localhost:7801 ...
diana:   --relay ws://localhost:7804 --relay ws://localhost:7801 ...
```

The `--slow-relay ws://localhost:7779` argument connects to the ledgers relay
for gap-fill fetches and durable event mirroring.

## Wallet Architecture

The web wallet connects to relays for two purposes:

### Discovery (read-only)

The wallet should only need the **ledgers relay** (ws://localhost:7779) for
discovery. Everything it needs is there:

- Ledger advertisements (Kind 39100) — operator names, fees, reserves, capacity
- Ledger updates (Kind 9100) — quorum membership, collateral attestations,
  deposit operations, transfer history
- Dispute events (Kind 9103) — dispute state

The wallet fetches these events via REQ filters and builds the network graph,
operator cards, and ledger detail views entirely from the ledgers relay.

### Interaction (read-write)

When the wallet needs to interact with a specific operator (open deposit, make
invoice, transfer, withdraw), it sends ephemeral requests to that operator's
node relay:

- alice: ws://localhost:7801
- bob: ws://localhost:7802
- charlie: ws://localhost:7803
- diana: ws://localhost:7804

The operator's daemon or nostr watcher picks up the request and responds on the
same relay. These are ephemeral events (Kind 20101 requests, Kind 20102
responses) that don't need to be persisted.

The wallet discovers which relay to use for each operator from the `relay_url`
field in the operator's advertisement (Kind 39100).

## Infrastructure

### Native Processes (strfry relays)

Nostr relays run as native strfry processes (not Docker containers) on x86_64.
The strfry binary is at `bin/strfry`, built from source in `strfry-performance/`.

- **relay-alice** (port 7801): Fast relay for alice
- **relay-bob** (port 7802): Fast relay for bob
- **relay-charlie** (port 7803): Fast relay for charlie
- **relay-diana** (port 7804): Fast relay for diana
- **relay-ledgers** (port 7779): Durable relay + streams from all fast relays

Each relay's config and LMDB data live under `data/relays/{name}/`.
Managed by `start_all_relays` / `stop_all_relays` in `_common.sh`.

### Docker Containers

- **bitcoind**: Regtest Bitcoin Core node (ports 18543/18544)
- **electrs**: Electrum REST API for chain queries (port 3102)
- **deposits-prometheus**: Metrics collection (port 9190)
- **deposits-grafana**: Metrics visualization (port 3110)
- **wallet**: Static file server for the web wallet

## Lightning Node (optional)

When running with `setup-4op-lightning.sh`, all operators share a single LDK
Lightning node (`lightning` container, API port 3111). Cross-operator payments
on the same node settle internally via `ldk-cli-wrapper.sh` (self-pay /
subwallet approach).

## Setup Flow

1. `bin/reinit-lightning.sh` — Full teardown + rebuild + setup
2. Infrastructure starts (bitcoin, electrs, relays)
3. `bin/setup-4op.sh` runs:
   - Phase 1: Fund operators, get node IDs
   - Phase 2: Create reserves UTXOs
   - Phase 3: Open ledgers
   - Start daemons and nostr watchers
   - Phase 3b: Add quorum members (cross-join all operators)
   - Phase 3c: Open/fund collateral deposits, poll for completion, lock + attest
   - Phase 4: Rotate reserves to quorum Taproot
4. `bin/setup-4op-lightning.sh` continues:
   - Start LDK sidecar containers
   - Restart daemons with LDK environment
   - Fund LDK wallets
   - Open Lightning channels in ring topology

## Useful Commands

```bash
# Discovery
bin/discover.sh                          # Network topology from local data

# Logs
tail -f data/alice/node.log              # Follow alice's daemon log

# Relay inspection
bin/strfry --config data/relays/ledgers/strfry.conf scan '{"kinds":[9100],"limit":5}'

# Node management
source bin/_common.sh
stop_node alice                          # Stops daemon + watchers + cleanup
start_node alice                         # Starts daemon
start_nostr_watch alice <ledger_id>      # Starts watcher

# Bitcoin
bitcoin_cli -rpcwallet=faucet -generate 1   # Mine a block
```
