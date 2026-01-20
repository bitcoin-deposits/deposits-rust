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

### 3. Tool Updates

- **`deposits-admin.rs`**:
  - Uses HTTPS with `danger_accept_invalid_certs(true)`
  - Adds HMAC auth header to all requests

- **`nwc-client.rs`**:
  - `init_node_wallet()` uses protobuf endpoint
  - `get_target_nwc_pubkey()` uses protobuf endpoint
  - Both use HTTPS with auth

### 4. Script Updates

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
| `pay-amber-from-charlie.sh` | ✅ | Uses ldk-server-cli |
| `pay-blue-from-amber.sh` | ✅ | Uses ldk-server-cli |
| `stress-test.sh` | ✅ | Uses ldk_curl and deposits-admin |
| `setup-environment.sh` | ✅ | Uses ldk_curl |
| `reset-environment.sh` | ✅ | Uses ldk_curl |
| `reinit.sh` | ✅ | Skip drop-ledgers for regtest |

### 5. Docker/TLS Integration

- TLS certs copied from containers to `certs/` directory
- Scripts use certs for ldk-server-cli authentication

## Current Test Flow Status

```
./bin/test.sh
├── make-node-wallets.sh     ✅ Creates alice.json, bob.json, charlie.json
├── make-a-wallet.sh amber   ✅ Creates ledgers + amber deposit + wallet
├── make-a-wallet.sh blue    ✅ Creates ledgers + blue deposit + wallet
├── pay-amber-from-charlie   ✅ Lightning payment succeeds (payment_id returned)
└── pay-blue-from-amber      ? Not yet verified
```

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

### 2. Deposit Credit Verification

Need to verify that Lightning payments are being credited to deposit accounts:
- The payment `Charlie → Alice` succeeded at the Lightning level
- Unknown if deposits protocol intercepted and credited Amber's deposit
- Check via `./bin/updates.sh` or deposits-admin list-deposits

### 3. ldk-server JSON vs Protobuf

ldk-server uses **protobuf for all API requests**, not JSON. The `ldk_curl` helper sends JSON which won't work for standard ldk-server endpoints.

**Solutions**:
- Use `ldk-server-cli` for standard endpoints (invoices, payments, channels)
- Use `ldk_curl` only for deposits endpoints (which we control)
- Or implement protobuf encoding in bash (complex)

### 4. Endpoint Path Differences

| Endpoint Type | Path Format | Example |
|---------------|-------------|---------|
| ldk-server standard | PascalCase | `Bolt11Receive`, `GetNodeInfo` |
| deposits endpoints | snake_case with prefix | `deposits/nwc_info`, `deposits/init_ledger` |

## Files Changed

### deposits-rust
```
deposits-ldk/proto/deposits.proto        # NWC messages
deposits-ldk/src/service/mod.rs          # nwc module + endpoints
deposits-ldk/src/service/nwc.rs          # NEW - NWC handlers
deposits-tools/bin/_common.sh            # Auth helpers
deposits-tools/bin/*.sh                  # All scripts updated
deposits-tools/src/bin/deposits-admin.rs # HTTPS + auth
deposits-tools/src/bin/nwc-client.rs     # Protobuf endpoints
```

### ldk-server
```
ldk-server/src/main.rs    # Enable bitcoin deposits
ldk-server/src/service.rs # NWC endpoint routes
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

1. Verify deposit credit flow with `updates.sh`
2. Decide on NWC relay integration approach
3. Consider adding protobuf encoding to bash helpers or switching fully to CLI tools
