# Deposits Explorer TUI Spec

A terminal-based Bitcoin + Deposits protocol explorer for development and debugging, built with Rust and ratatui.

## Overview

Think "midnight commander for the blockchain + deposits" - a two-panel TUI that lets you navigate blocks, transactions, addresses, **and deposits ledgers** with keyboard shortcuts. Designed for regtest/signet debugging, not mainnet scale.

Combines:
- **Blockchain exploration** via electrs REST API
- **Deposits protocol inspection** via deposits-bdk data directory

## Backend

### Blockchain
Uses **electrs REST API** (esplora-compatible):
- Default: `http://localhost:3102`
- Configurable via `--electrs <url>` or `ELECTRS_URL` env var

### Deposits
Reads **deposits-bdk data directory**:
- Default: `~/.deposits-bdk` or `/data` (in container)
- Configurable via `--data-dir <path>` or `DEPOSITS_DATA_DIR` env var
- Parses: `ledger.json`, `taproot_reserves.json`, wallet data

## Layout

```
┌─ Blocks ─────────────────────────┬─ Details ─────────────────────────────┐
│ Height  Hash (short)    Txs Time │                                       │
│ ▶ 328   7f41c1c0...     1   12s  │ Block #328                            │
│   327   2c81faa7...     1   12s  │ Hash: 7f41c1c04e23ba7cde206aa7d4b55...│
│   326   4500d2fe...     1   12s  │ Previous: 2c81faa7152099cc22f5ac51b...│
│   325   1e98ef16...     2   13s  │ Time: 2024-01-15 14:23:45             │
│   324   64625ac5...     1   13s  │ Transactions: 1                       │
│   323   00ae4074...     1   14s  │ Size: 250 bytes                       │
│   322   5a9430fc...     3   14s  │                                       │
│   321   44d0686c...     1   15s  │ ─ Transactions ───────────────────    │
│   320   4f092e20...     1   15s  │ 0162f049... (coinbase)    12.5 BTC    │
│   ...                            │                                       │
├──────────────────────────────────┴───────────────────────────────────────┤
│ [B]locks [T]xn [A]ddress [/]Search [R]efresh [Q]uit      Block 328/328  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Views

### 1. Blocks List (default)
- Left panel: scrollable list of recent blocks
- Right panel: selected block details + transaction list
- Enter on a transaction → Transaction View

### 2. Transaction View
- Full transaction details
- Inputs with prevout info (address, value)
- Outputs with scriptPubKey decoded (address, value)
- For Taproot outputs: show witness program, indicate P2TR
- Navigate to input's previous tx or output's spending tx

```
┌─ Transaction ────────────────────────────────────────────────────────────┐
│ TxID: 43d43b27078e8dcfc1cca33dc578bdbdf34497c75067e3eb214c78a24e8b8255   │
│ Block: #102  Confirmations: 226  Size: 222 vB  Fee: 141 sats (0.63 s/vB)│
├─ Inputs (1) ─────────────────────────────────────────────────────────────┤
│ #0  4f3287a4639c...:0                                                    │
│     bcrt1q5pxeh3ad4udvg2vxjlzp4a0wlhw27jkc  50.00000000 BTC              │
│     P2WPKH  [Enter to view]                                              │
├─ Outputs (2) ────────────────────────────────────────────────────────────┤
│ #0  bcrt1q45zh6t3tdgpz8u67h73dv00dv5ppv0n2  10.00000000 BTC  UNSPENT    │
│     P2WPKH                                                               │
│ #1  bcrt1qquqvld3a7yp4ktrvm4ankuwm3zwgktxw  39.99999859 BTC  SPENT      │
│     P2WPKH  → 8a3f21... [Enter to view]                                  │
├──────────────────────────────────────────────────────────────────────────┤
│ [B]ack [H]ex [C]opy txid                                    Input 0/1   │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3. Address View
- Address summary (total received, balance, tx count)
- UTXO list
- Transaction history

```
┌─ Address ────────────────────────────────────────────────────────────────┐
│ bcrt1q45zh6t3tdgpz8u67h73dv00dv5ppv0n2d9wdup                             │
│ Type: P2WPKH                                                             │
│ Balance: 10.00000000 BTC (1 UTXO)                                        │
├─ UTXOs ──────────────────────────────────────────────────────────────────┤
│ 43d43b27078e...:0   10.00000000 BTC   Block #102                         │
├─ History ────────────────────────────────────────────────────────────────┤
│ #102  43d43b27...  +10.00000000 BTC                                      │
├──────────────────────────────────────────────────────────────────────────┤
│ [B]ack [C]opy address                                                    │
└──────────────────────────────────────────────────────────────────────────┘
```

### 4. Ledgers View (Deposits)
- List of all ledgers (operator + partner ledgers)
- Shows: ledger ID, operator, sequence #, reserves amount, quorum members

```
┌─ Ledgers ────────────────────────┬─ Ledger Details ──────────────────────┐
│ ID             Operator    Seq   │ Ledger: alice-1706123456              │
│ ▶ alice-17...  alice       42    │ Operator: 02a1b2c3d4e5f6...           │
│   bob-1706...  bob         38    │ Partner: 03f6e5d4c3b2a1...            │
│   charlie-...  charlie     15    │ Sequence: 42                          │
│                                  │ Ledger Hash: 8a3f21b5c7d9...          │
│                                  │                                       │
│                                  │ ─ Reserves ───────────────────────    │
│                                  │ Address: bcrt1p7x8w9y...  (P2TR)      │
│                                  │ Amount: 1.50000000 BTC                │
│                                  │ UTXO: 43d43b27...:0 [Enter to view]   │
│                                  │                                       │
│                                  │ ─ Quorum (2/3) ────────────────────   │
│                                  │ 02a1b2c3... (operator) expires: 500   │
│                                  │ 03d4e5f6... bob         expires: 500  │
│                                  │ 02g7h8i9... charlie     expires: 500  │
├──────────────────────────────────┴───────────────────────────────────────┤
│ [B]locks [L]edgers [O]perations [R]eserves [Q]uit        Ledger 1/3     │
└──────────────────────────────────────────────────────────────────────────┘
```

### 5. Operations View (Deposits)
- Scrollable list of ledger operations
- Shows: sequence, operation type, amount/details, hash chain

```
┌─ Operations: alice-1706123456 ───────────────────────────────────────────┐
│ Seq  Type              Amount        Details                   Hash      │
│  42  DepositAdd        +0.10000000   user123                   8a3f21... │
│  41  CollateralLock    -0.05000000   block 450                 7b2e10... │
│  40  QuorumAddMember                 bob (03d4e5f6...)         6c1d09... │
│  39  QuorumAddMember                 charlie (02g7h8i9...)     5d0c08... │
│  38  ReservesIncrease  +1.00000000   43d43b27...:0             4e9b07... │
│  37  ReservesIncrease  +0.50000000   8f2a1b3c...:0             3f8a06... │
│  ...                                                                     │
│   1  LedgerOpen                      partner: 03f6e5d4...      1a2b03... │
├──────────────────────────────────────────────────────────────────────────┤
│ [B]ack [V]erify chain [J]SON                            Operation 42/42 │
└──────────────────────────────────────────────────────────────────────────┘
```

### 6. Reserves View (Deposits)
- Current reserves UTXO details
- Taproot script tree visualization
- Spending conditions decoded

```
┌─ Reserves: alice-1706123456 ─────────────────────────────────────────────┐
│ Address: bcrt1p7x8w9yz...                                                │
│ Type: P2TR (Taproot)                                                     │
│ Amount: 1.50000000 BTC                                                   │
│ UTXO: 43d43b27078e8dcfc1cca33dc578bdbdf34497c7:0                         │
│ Confirmed: Block #328                                                    │
│                                                                          │
│ ─ Script Tree ───────────────────────────────────────────────────────    │
│ Internal Key: 02a1b2c3d4e5f6... (operator)                               │
│                                                                          │
│ Leaf 0: 2-of-3 multisig (immediate)                                      │
│   CHECKSIG 02a1b2c3... (operator)                                        │
│   CHECKSIGADD 03d4e5f6... (bob)                                          │
│   CHECKSIGADD 02g7h8i9... (charlie)                                      │
│   2 NUMEQUAL                                                             │
│                                                                          │
│ Leaf 1: Operator after block 500                                         │
│   500 CHECKLOCKTIMEVERIFY DROP                                           │
│   CHECKSIG 02a1b2c3... (operator)                                        │
│                                                                          │
│ Leaf 2: Emergency recovery (3-of-3) after block 1000                     │
│   1000 CHECKLOCKTIMEVERIFY DROP                                          │
│   CHECKSIG 02a1b2c3... CHECKSIGADD 03d4e5f6... CHECKSIGADD 02g7h8i9...   │
│   3 NUMEQUAL                                                             │
├──────────────────────────────────────────────────────────────────────────┤
│ [B]ack [H]ex scripts [T]x view                          Current: 328    │
└──────────────────────────────────────────────────────────────────────────┘
```

## Keyboard Navigation

### Global
| Key | Action |
|-----|--------|
| `q` | Quit |
| `B` | Go to Blocks view |
| `T` | Prompt for txid, go to Transaction view |
| `A` | Prompt for address, go to Address view |
| `L` | Go to Ledgers view (deposits) |
| `O` | Go to Operations view for current ledger |
| `S` | Go to reServes view for current ledger |
| `/` | Search (txid, address, block hash, or ledger ID) |
| `R` | Refresh current view |
| `?` | Help |

### List Navigation
| Key | Action |
|-----|--------|
| `↑/k` | Move up |
| `↓/j` | Move down |
| `PgUp` | Page up |
| `PgDn` | Page down |
| `g` | Go to top |
| `G` | Go to bottom |
| `Enter` | Select/drill down |

### Detail Views
| Key | Action |
|-----|--------|
| `Esc/b` | Back to previous view |
| `Tab` | Cycle focus between panels |
| `c` | Copy selected item to clipboard |
| `h` | Show hex (for tx: raw hex; for scripts: hex dump) |

## Special Features

### Script Decoding
For debugging Taproot reserves, decode and display:
- P2TR addresses
- Taproot witness programs
- Script-path spend scripts (when visible in witness)
- OP_CHECKSIGADD patterns
- CLTV timelock conditions

### Deposits Integration
- **Cross-reference**: When viewing a transaction, detect if it's a reserves UTXO and offer to jump to the ledger
- **Hash chain verification**: `V` in Operations view verifies the ledger hash chain integrity
- **Quorum visualization**: Show which pubkeys map to which operators/members
- **UTXO tracking**: Link reserves operations to on-chain UTXOs

### Search
`/` opens search prompt. Auto-detects:
- 64 hex chars → txid or block hash
- `bc1`/`bcrt1`/`tb1` prefix → address
- Numeric → block height
- `alice-`/`bob-` prefix → ledger ID
- 66 hex chars (compressed pubkey) → operator/member lookup

### Clipboard
`c` copies the currently focused item:
- Block hash
- Transaction ID
- Address
- Ledger hash
- Raw hex (when in hex view)

Uses OSC 52 escape sequence for terminal clipboard (works in most modern terminals).

### Sync Status
Bottom status bar shows:
- Current block height (from electrs)
- Ledger sync status (if data dir configured)
- Auto-refresh indicator

## Technical Details

### Dependencies
```toml
[dependencies]
ratatui = "0.28"
crossterm = "0.28"
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
bitcoin = "0.32"  # For address/script parsing
clap = { version = "4", features = ["derive"] }

# Deposits protocol
deposits-core = { path = "../deposits-core" }
```

### Structure
```
src/
  main.rs           # Entry point, arg parsing
  app.rs            # App state, event loop
  ui/
    mod.rs
    blocks.rs       # Blocks list view
    transaction.rs  # Transaction detail view
    address.rs      # Address detail view
    ledgers.rs      # Ledgers list view (deposits)
    operations.rs   # Operations list view (deposits)
    reserves.rs     # Reserves detail view (deposits)
    search.rs       # Search modal
    status.rs       # Status bar
  api/
    mod.rs
    electrs.rs      # Electrs API client
    types.rs        # Response types
  deposits/
    mod.rs
    loader.rs       # Load ledger.json, taproot_reserves.json
    types.rs        # Ledger, Operation, etc. (re-use from deposits-core)
    verify.rs       # Hash chain verification
  util/
    clipboard.rs    # OSC 52 clipboard
    format.rs       # BTC formatting, time ago, etc.
    pubkey.rs       # Pubkey display, short names
```

### Binary
Standalone binary in deposits-tools:
```
deposits-explorer --electrs http://localhost:3102 --data-dir ~/.deposits-bdk
```

Or integrate as a subcommand in deposits-bdk:
```
deposits-bdk explorer
```

Docker usage:
```bash
# Run against the bdk docker network
docker run -it --rm --network bdk_network \
  -v bdk_alice_data:/data:ro \
  deposits-explorer --electrs http://electrs:3002 --data-dir /data
```

## Electrs API Endpoints Used

```
GET /blocks                      # Recent blocks
GET /block/:hash                 # Block info
GET /block/:hash/txs/:start     # Block transactions
GET /block-height/:height        # Block hash by height
GET /tx/:txid                    # Transaction
GET /tx/:txid/hex               # Raw transaction hex
GET /tx/:txid/outspends         # Which outputs are spent
GET /address/:addr              # Address info
GET /address/:addr/txs          # Address transactions
GET /address/:addr/utxo         # Address UTXOs
```

## Future Ideas (v2)
- WebSocket subscription for new blocks
- Mempool view (unconfirmed txs)
- Script debugger / execution trace
- Export transaction as PSBT
- **Nostr integration**: View peer messages between operators
- **Multi-node view**: Connect to multiple deposits-bdk data dirs simultaneously
- **Diff view**: Compare ledger states between two operators
- **Simulation mode**: "What if" for proposed operations
- **Alert mode**: Watch for specific conditions (reserves spent, quorum changes)
