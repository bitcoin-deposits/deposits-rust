# deposits-wallet

Nostr-based custody wallet CLI for depositors. Discovers operators, opens deposits, manages balances, and moves funds across ledgers.

Binary: `deposits-node/src/bin/deposits-wallet.rs`

## Configuration

All commands accept these global options:

| Option | Description | Default |
|---|---|---|
| `--relay <url>` | Nostr relay URL (required for most commands) | none |
| `--network <net>` | `bitcoin`, `testnet`, `signet`, `regtest` | `regtest` |
| `--seed <hex>` | 32-byte hex seed | auto-generated, stored in `seed.hex` |
| `--data-dir <path>` | Data directory | `~/.deposits-wallet` |

Key derivation uses BIP-84: `m/84'/0'/0'/0/{index}`. Each deposit gets a unique key. The next index is tracked in `deposit_key_index.txt`.

## Data storage

- `~/.deposits-wallet/seed.hex` — wallet seed (auto-generated on first use)
- `~/.deposits-wallet/deposits.json` — array of deposit records (alias, ledger_id, deposit_id, operator pubkey, key index, etc.)
- `~/.deposits-wallet/deposit_key_index.txt` — next available BIP-84 derivation index

## Commands

### Discovery & info

| Command | Description |
|---|---|
| `discover` | Find available ledgers on the network. Supports `--json` for machine-readable output. |
| `info <ledger_id>` | Get details about a specific ledger. |

### Deposit lifecycle

| Command | Description |
|---|---|
| `open <ledger_id> <sats>` | Open a new deposit. Sends `deposit_open` request to operator via Nostr. Returns a funding address. Use `--alias <name>` to name it. |
| `offer <alias> <sats>` | Add funds to an existing deposit. Operator co-signs the offer with quorum members. |
| `balance` | Show balances across all deposits. |
| `sync` | Sync deposit statuses from operators via Nostr. |
| `list` | List all deposits with aliases, ledger IDs, and balances. |
| `history <alias>` | Show transaction history for a deposit. |

### Transfers

| Command | Description |
|---|---|
| `withdraw <alias> <amount>` | Withdraw to an on-chain address (`--to <addr>`). |
| `transfer <alias> <amount>` | Lock funds for a conditional HTLC transfer within the same ledger. |
| `transfer_complete <id>` | Complete a pending transfer by revealing the preimage. |
| `route <from> <to> <amount>` | Cross-ledger transfer via a courier. Source and destination are deposit aliases on different ledgers. |
| `spread <amount> [--count N]` | Open deposits across N discovered operators, splitting the total amount evenly. |

### Lightning

| Command | Description |
|---|---|
| `make_invoice <alias> <amount>` | Create a Lightning invoice receivable on a deposit. |
| `pay_invoice <alias> <bolt11>` | Pay a Lightning invoice from a deposit. |

### Ledger inspection (read-only)

These commands don't require a wallet seed — they read directly from Nostr.

| Command | Description |
|---|---|
| `ledger list` | List all ledgers on the relay with update counts. |
| `ledger show <id>` | Show all updates for a ledger. |
| `ledger validate <id>` | Validate the ledger hash chain. |
| `ledger custody <id>` | Trace custody chain (rotations, disputes, acquisitions). |

### Batch mode

| Command | Description |
|---|---|
| `batch` | Interactive JSON-line mode over stdin/stdout. Maintains a persistent Nostr connection. Outputs `{"ready":true}` when initialized. Supports `transfer_lock` and `transfer_complete` operations. |

## Communication model

The wallet communicates with operators entirely via Nostr:
- Sends requests as encrypted DMs (`send_ledger_request`)
- Waits for operator responses (`wait_for_response`)
- Fetches ledger state by subscribing to `KIND_LEDGER_UPDATE` events, filtered by `#l` (ledger ID) and `#n` (sequence) tags
- Discovery reads ledger advertisement events

## Offer co-signing

When adding funds via `offer`, the wallet verifies quorum member co-signatures on the funding address:
- Builds canonical signing data: `ledger_id || offer_id || operator_xonly || funding_address || deadline_block`
- Uses BIP-340 tagged hash: `deposits/offer_cosign`
- Verifies each co-signer is an actual quorum member by checking ledger history for `QuorumAddMember` operations

## Example usage

```bash
# Discover operators
deposits-wallet discover --relay ws://localhost:8080

# Open a deposit
deposits-wallet open abc123... 100000 --alias savings --relay ws://localhost:8080

# Add more funds
deposits-wallet offer savings 50000 --relay ws://localhost:8080

# Check balance
deposits-wallet balance --relay ws://localhost:8080

# Withdraw on-chain
deposits-wallet withdraw savings 25000 --to bc1q... --relay ws://localhost:8080

# Cross-ledger transfer via courier
deposits-wallet route savings checking 10000 --relay ws://localhost:8080

# Spread across operators
deposits-wallet spread 500000 --count 4 --relay ws://localhost:8080

# Lightning
deposits-wallet make_invoice savings 5000 --relay ws://localhost:8080
deposits-wallet pay_invoice savings lnbc... --relay ws://localhost:8080

# Inspect any ledger
deposits-wallet ledger validate abc123... --relay ws://localhost:8080
```
