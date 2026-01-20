# Migration Status: HTTPS/Protobuf API Migration

## Summary

This document tracks the migration of deposits-tools scripts from HTTP JSON APIs to HTTPS with HMAC authentication and protobuf encoding, required for compatibility with upstream ldk-server.

## Completed Work

### 1. Authentication Infrastructure

- **`_common.sh`**: Added HMAC-SHA256 authentication helpers
  - `ldk_auth_header()` - generates auth header for requests
  - `ldk_curl()` - wrapper for authenticated HTTPS requests
  - `LDK_API_KEY` constant (currently "test_api_key")

### 2. NWC Protobuf Endpoints

Added NWC endpoints to deposits-ldk and ldk-server:

- **`deposits.proto`**: Added messages
  - `GetNwcInfoRequest/Response` - get NWC pubkey and relay URL
  - `GetNwcConnectRequest/Response` - get full connection string with secret

- **`deposits-ldk/src/service/nwc.rs`**: Service handlers
  - Generates deterministic NWC keypair from node pubkey
  - Returns x-only pubkey format for Nostr compatibility

- **`ldk-server/src/service.rs`**: Routes for `deposits/nwc_info` and `deposits/nwc_connect`

### 3. Deposit Invoice Endpoint (NEW)

Added `deposits/CreateInvoice` endpoint to ldk-server that creates BOLT11 invoices registered for deposit credit:

- **`ldk-server-protos/src/api.rs`**: Added `DepositInvoiceRequest/Response` messages
- **`ldk-server-protos/src/endpoints.rs`**: Added `DEPOSIT_INVOICE_PATH`
- **`ldk-server/src/api/deposit_invoice.rs`**: Handler that:
  1. Creates invoice via ldk-node
  2. Registers payment_hash with `deposits_handler.register_deposit_invoice()`
  3. Returns invoice + payment_hash
- **`ldk-server/src/service.rs`**: Route wired up
- **`ldk-server-client/src/client.rs`**: Added `deposit_invoice()` method
- **`ldk-server-cli`**: Added `deposit-invoice` command

### 4. Tool Updates

- **`deposits-admin.rs`**:
  - Uses HTTPS with `danger_accept_invalid_certs(true)`
  - Adds HMAC auth header to all requests

- **`nwc-client.rs`**:
  - `init_node_wallet()` uses protobuf endpoint
  - `get_target_nwc_pubkey()` uses protobuf endpoint
  - Both use HTTPS with auth

### 5. Script Updates

All scripts migrated from `curl http://localhost` to either:
- `ldk_curl` helper (for JSON-compatible endpoints)
- `deposits-admin` CLI (for deposits operations)
- `ldk-server-cli` (for protobuf API - invoices, payments)

| Script | Status | Notes |
|--------|--------|-------|
| `test.sh` | ✅ | Orchestrates other scripts |
| `test-*.sh` (6 files) | ✅ | Use ldk_curl and deposits-admin |
| `make-node-wallets.sh` | ✅ | Uses nwc-client init-node |
| `make-a-wallet.sh` | ✅ | Creates deposit + wallet file |
| `pay-amber-from-charlie.sh` | ✅ | Uses `deposit-invoice` endpoint |
| `pay-blue-from-amber.sh` | ✅ | Uses `deposit-invoice` endpoint |
| `stress-test.sh` | ✅ | Uses ldk_curl and deposits-admin |
| `setup-environment.sh` | ✅ | Uses ldk_curl |
| `reset-environment.sh` | ✅ | Uses ldk_curl |
| `reinit.sh` | ✅ | Skip drop-ledgers for regtest |

### 6. Docker/TLS Integration

- TLS certs copied from containers to `certs/` directory
- Scripts use certs for ldk-server-cli authentication

## Current Test Flow Status

```
./bin/test.sh
├── make-node-wallets.sh     ✅ Creates alice.json, bob.json, charlie.json
├── make-a-wallet.sh amber   ✅ Creates ledgers + amber deposit + wallet
├── make-a-wallet.sh blue    ✅ Creates ledgers + blue deposit + wallet
├── pay-amber-from-charlie   ✅ Creates deposit invoice, Charlie pays, deposit credited
└── pay-blue-from-amber      ✅ Creates deposit invoice, Alice pays, deposit credited
```

## Payment Flow (Fixed)

The payment interception is now hooked up:

1. **Create deposit invoice** via `ldk-server-cli deposit-invoice`:
   - Creates BOLT11 invoice via ldk-node
   - Calls `deposits_handler.register_deposit_invoice(payment_hash, partner_id, deposit_pubkey, ...)`
   - Returns invoice to caller

2. **Payment arrives** at ldk-node:
   - `Event::PaymentClaimable` received
   - `is_deposit_invoice_payment(payment_hash)` → TRUE
   - `credit_deposit_and_move_reserves_async()` → updates ledger
   - `claim_funds()` → payment finalized

3. **Deposit credited**:
   - Ledger state updated
   - Partner notified via protocol message
   - Reserves committed

## Known Issues / TODO

### 1. NWC Relay Integration (Not Implemented)

The NWC protocol over nostr relay is **not wired up**:
- ldk-server doesn't connect to the nostr relay
- ldk-server doesn't listen for NWC request events (kind 23194)
- ldk-server doesn't send NWC response events (kind 23195)

**Current workaround**: Use `ldk-server-cli` directly for invoices/payments instead of NWC protocol.

**To implement**: Would need to add a relay client to ldk-server that:
1. Connects to `ws://nostr-relay:7777`
2. Subscribes to NWC request events for the node's pubkey
3. Processes requests and publishes responses

### 2. ~~Deposit Credit Verification~~ ✅ VERIFIED

Run `./bin/updates.sh` after test to verify deposits are being credited correctly.

**Status**: Working. Tested 2026-01-19 - deposit invoice creates invoice, payment intercepts and credits deposit correctly.

### 3. ~~ldk-server JSON vs Protobuf~~ ✅ FIXED

ldk-server uses **protobuf for all API requests**, not JSON.

**Fixed**: `deposits-admin.rs` now uses protobuf `GetNodeInfo` endpoint instead of JSON `/info`:
- Added `ldk-server-protos` dependency to `deposits-tools/Cargo.toml`
- `resolve_node_id()` and `build_node_name_map()` now use protobuf API

**Note**: `ldk_curl` helper still sends JSON - only use for deposits endpoints (which we control)

### 4. ~~Invalid Deposit Pubkeys~~ ✅ FIXED

The original `make-a-wallet.sh` generated fake pubkeys by prepending "02" to random bytes,
which aren't valid secp256k1 curve points. This caused "INVALID_PUBKEY" errors when adding deposits.

**Fixed**: Script now uses `openssl ecparam -name secp256k1` to generate real EC keypairs.

### 5. ~~Collateral Partner State Sync~~ ✅ FIXED

Collateral partners weren't syncing ledger state when granting consent.

**Fixed**: `handle_collateral_consent_request()` now sends a `SyncRequest` after granting consent
to fetch all ledger updates for the ledger being backed.

Location: `deposits-ldk/src/handler/message_handlers.rs:1337-1354`

### 6. Endpoint Path Differences

| Endpoint Type | Path Format | Example |
|---------------|-------------|---------|
| ldk-server standard | PascalCase | `Bolt11Receive`, `GetNodeInfo` |
| deposits endpoints | snake_case with prefix | `deposits/nwc_info`, `deposits/init_ledger` |
| deposit invoice | Mixed (PascalCase with prefix) | `deposits/CreateInvoice` |

## Files Changed

### deposits-rust
```
deposits-ldk/proto/deposits.proto              # NWC messages
deposits-ldk/src/service/mod.rs                # nwc module + endpoints
deposits-ldk/src/service/nwc.rs                # NEW - NWC handlers
deposits-ldk/src/handler/message_handlers.rs   # Fixed: collateral consent triggers sync
deposits-tools/Cargo.toml                      # Added ldk-server-protos dependency
deposits-tools/bin/_common.sh                  # Auth helpers
deposits-tools/bin/make-a-wallet.sh            # Fixed: generates valid secp256k1 keypairs
deposits-tools/bin/*.sh                        # All scripts updated
deposits-tools/src/bin/deposits-admin.rs       # HTTPS + auth + protobuf GetNodeInfo + 2/2 display
deposits-tools/src/bin/nwc-client.rs           # Protobuf endpoints
```

### ldk-server
```
ldk-server/src/main.rs                   # Enable bitcoin deposits
ldk-server/src/service.rs                # Endpoint routes (NWC + deposit invoice)
ldk-server/src/api/deposit_invoice.rs    # NEW - Deposit invoice handler
ldk-server/src/api/mod.rs                # Module registration
ldk-server-protos/src/api.rs             # DepositInvoiceRequest/Response
ldk-server-protos/src/endpoints.rs       # DEPOSIT_INVOICE_PATH
ldk-server-client/src/client.rs          # deposit_invoice() method
ldk-server-cli/src/main.rs               # deposit-invoice command
```

## Testing

After rebuilding Docker images:

```bash
cd deposits-tools
./bin/reinit.sh          # Full environment reset + setup
./bin/test.sh            # Run test flow
./bin/updates.sh         # Check ledger status
```

## Next Steps

1. ✅ ~~Add deposit invoice endpoint to ldk-server~~ (DONE)
2. ✅ ~~Verify deposit credit flow with `updates.sh` after test run~~ (VERIFIED - working)
3. ✅ ~~Fix deposits-admin JSON vs protobuf issue~~ (FIXED - uses GetNodeInfo protobuf)
4. ✅ ~~Fix make-a-wallet.sh invalid pubkey generation~~ (FIXED - uses openssl secp256k1)
5. ✅ ~~Fix collateral partner state sync~~ (FIXED - sends SyncRequest on consent)
6. Decide on NWC relay integration approach
7. Consider full migration from bash scripts to CLI tools
