# Integration Plan: Deposits Features into ldk-server

## Architecture

**Goal**: Minimize ldk-server changes by putting everything in deposits-ldk.

```
┌─────────────────────────────────────────────────────────┐
│                      deposits-ldk                        │
├─────────────────────────────────────────────────────────┤
│  proto/                    Protobuf definitions          │
│  src/service/              API handlers (proto → proto)  │
│  src/handler/              Business logic (existing)     │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────┐
│                       ldk-server                         │
├─────────────────────────────────────────────────────────┤
│  Route matching only:                                    │
│  DEPOSITS_* => deposits_ldk::service::handle_*(...)      │
└─────────────────────────────────────────────────────────┘
```

## Phase 1: Protobuf Definitions

**Location**: `deposits-ldk/proto/deposits.proto`

```protobuf
syntax = "proto3";
package deposits;

// Ledger operations
message InitLedgerRequest {
  string partner_node_id = 1;
  string ledger_address = 2;
}
message InitLedgerResponse {
  string ledger_id = 1;
}

message ListLedgersRequest {}
message ListLedgersResponse {
  repeated LedgerInfo ledgers = 1;
}

message GetLedgerRequest {
  string ledger_id = 1;
}
message GetLedgerResponse {
  LedgerInfo ledger = 1;
}

message CloseLedgerRequest {
  string ledger_id = 1;
}
message CloseLedgerResponse {}

// Deposit operations
message AddDepositRequest {
  string partner_node_id = 1;
  string deposit_pubkey = 2;
}
message AddDepositResponse {
  string deposit_pubkey = 1;
}

message ListDepositsRequest {
  optional string ledger_id = 1;
}
message ListDepositsResponse {
  repeated DepositInfo deposits = 1;
}

message RemoveDepositRequest {
  string ledger_id = 1;
  string deposit_pubkey = 2;
}
message RemoveDepositResponse {}

// Reserves operations
message GetReservesStatusRequest {
  string partner_node_id = 1;
}
message GetReservesStatusResponse {
  uint64 current_amount = 1;
  uint64 required_amount = 2;
  uint64 excess_amount = 3;
  uint64 total_deposit_balances = 4;
}

message ReduceReservesRequest {
  string partner_node_id = 1;
  uint64 amount_sat = 2;
}
message ReduceReservesResponse {}

// Quorum member operations
message AddQuorumMemberRequest {
  string partner_node_id = 1;
  string quorum_member_id = 2;
}
message AddQuorumMemberResponse {}

message RemoveQuorumMemberRequest {
  string partner_node_id = 1;
  string quorum_member_id = 2;
}
message RemoveQuorumMemberResponse {}

message GetCollateralInfoRequest {
  string partner_node_id = 1;
}
message GetCollateralInfoResponse {
  repeated QuorumMemberInfo members = 1;
  uint64 total_available_collateral = 2;
}

// Ledger updates
message GetLedgerUpdatesRequest {
  string ledger_id = 1;
  optional uint64 from_sequence = 2;
  optional uint64 limit = 3;
}
message GetLedgerUpdatesResponse {
  repeated LedgerUpdate updates = 1;
}

// Common types
message LedgerInfo {
  string ledger_id = 1;
  string operator_node_id = 2;
  string partner_node_id = 3;
  uint64 operator_balance_sat = 4;
  uint64 partner_balance_sat = 5;
  uint64 reserves_sat = 6;
  uint64 deposit_count = 7;
  uint64 sequence_number = 8;
}

message DepositInfo {
  string deposit_pubkey = 1;
  string ledger_id = 2;
  uint64 balance_sat = 3;
  uint64 locked_balance_sat = 4;
}

message QuorumMemberInfo {
  string pubkey = 1;
  uint64 collateral_amount = 2;
  uint32 block_height = 3;
  bool has_attestation = 4;
}

message LedgerUpdate {
  uint64 sequence_number = 1;
  string operation_type = 2;
  bytes signature = 3;
  uint64 timestamp = 4;
}

message DepositsError {
  string code = 1;
  string message = 2;
}
```

## Phase 2: Service Module

**Location**: `deposits-ldk/src/service/`

```
deposits-ldk/src/service/
├── mod.rs              # Module exports + endpoint constants
├── ledger.rs           # init, list, get, close ledger handlers
├── deposit.rs          # add, list, remove deposit handlers
├── reserves.rs         # get status, reduce reserves handlers
├── collateral.rs       # add/remove partner, get info handlers
└── updates.rs          # get ledger updates handler
```

Each handler follows this pattern:
```rust
pub async fn handle_init_ledger<L>(
    handler: &DepositsHandler<L>,
    request: InitLedgerRequest,
) -> Result<InitLedgerResponse, DepositsError>
where
    L: Deref + Clone,
    L::Target: Logger,
{
    let partner_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError { code: "INVALID_PUBKEY".into(), message: "Invalid partner_node_id".into() })?;

    let address = Address::from_str(&request.ledger_address)
        .map_err(|_| DepositsError { code: "INVALID_ADDRESS".into(), message: "Invalid ledger_address".into() })?;

    handler.initiate_ledger_handshake_async(partner_id, address).await
        .map_err(|e| DepositsError { code: "INIT_FAILED".into(), message: format!("{:?}", e) })?;

    Ok(InitLedgerResponse { ledger_id: partner_id.to_string() })
}
```

## Phase 3: ldk-server Integration

**Location**: `ldk-server/src/service.rs`

Minimal additions:
```rust
// Add imports
use deposits_ldk::service as deposits_service;
use deposits_ldk::service::endpoints::*;

// Add route matching (in handle_request)
DEPOSITS_INIT_LEDGER_PATH => {
    let handler = self.node.deposits_handler()
        .ok_or_else(|| LdkServerError::new(InternalError, "Deposits not enabled"))?;
    let request = InitLedgerRequest::decode(body)?;
    let response = deposits_service::handle_init_ledger(handler, request).await?;
    encode_response(response)
}
// ... repeat for each endpoint
```

## Implementation Order

1. **Add prost dependencies to deposits-ldk** (Cargo.toml)
2. **Create proto/deposits.proto** (protobuf definitions)
3. **Add build.rs** (proto compilation)
4. **Create src/service/mod.rs** (module structure + endpoints)
5. **Implement handlers** (ledger.rs, deposit.rs, reserves.rs, collateral.rs, updates.rs)
6. **Add routes to ldk-server** (service.rs)
7. **Add config option** (util/config.rs)
8. **Test**

## Files to Create/Modify

### deposits-ldk (new files)
- `proto/deposits.proto`
- `build.rs`
- `src/service/mod.rs`
- `src/service/ledger.rs`
- `src/service/deposit.rs`
- `src/service/reserves.rs`
- `src/service/collateral.rs`
- `src/service/updates.rs`

### deposits-ldk (modify)
- `Cargo.toml` - add prost, prost-build

### ldk-server (modify)
- `ldk-server/Cargo.toml` - ensure deposits-ldk dependency
- `ldk-server/src/service.rs` - add route matching (~20 lines)
- `ldk-server/src/util/config.rs` - add deposits_enabled option

## Estimated Effort

- Phase 1 (Proto): 1 hour
- Phase 2 (Service): 2-3 hours
- Phase 3 (ldk-server): 30 minutes
- Testing: 1 hour

**Total**: ~5 hours
