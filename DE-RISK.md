# De-Risking: Moving Code Downstream

This document outlines opportunities to move deposits-related code downstream in the architecture hierarchy:

```
rust-lightning → ldk-node → deposits-ldk → deposits-core
```

Moving code downstream reduces coupling to upstream dependencies, improves testability, and enables reuse with other Lightning implementations.

## Priority 1: High-Value, Low-Risk

### 1.1 Wire Message Definitions → deposits-core

**Current location:** `deposits-ldk/src/wire/messages.rs` (~3,400 lines)

**What to move:**
- Base message structs (data only)
- Message type constants
- TLV encoding primitives

**What stays in deposits-ldk:**
- `Readable`/`Writeable` trait implementations (Lightning-specific codec)

**Why:**
- Message types only use Bitcoin/secp256k1 primitives
- Protocol messages are not inherently Lightning-specific; the codec is
- ~40% of wire module could move out
- Enables protocol testing without Lightning dependencies

**Impact:** ~1,500 lines moved

---

### 1.2 Reserve Proposal Types → deposits-core

**Current location:** `deposits-ldk/src/reserves.rs` (~780 lines)

**What to move:**
```rust
ReservesOutputProposal    // 83 lines
SpendingPolicy            // 15 lines
EmergencyRecovery         // 15 lines
ProposalStatus            // enum
// Plus validation and creation logic (~400 lines)
```

**What stays in deposits-ldk:**
- `ReservesOutputManager` (has logger dependency)
- Commitment transaction integration

**Why:**
- Uses only Bitcoin types (`PublicKey`, `Network`, `Script`)
- Reserve policy is core business logic
- Significant code volume not requiring LDK

**Impact:** ~400 lines moved

---

### 1.3 PaymentTracking Implementation → deposits-core

**Current state:**
- Trait defined in: `deposits-core/src/handler_traits.rs`
- Implementation in: `deposits-ldk/src/handler/payment_tracking.rs` (~100 lines)

**What to move:**
- Default implementation of `PaymentTracking` methods
- `register_deposit_invoice`, `is_deposit_invoice_payment`, etc.

**Why:**
- Only uses `PublicKey` and `Mutex` (standard Rust)
- Core protocol state management, not LDK adaptation
- Trait already in deposits-core; impl should follow

**Impact:** ~50 lines moved

---

## Priority 2: Medium-Value, Medium-Risk

### 2.1 ChannelManagerOps Trait → deposits-core

**Current location:** `deposits-ldk/src/channel_manager_ops.rs` (~240 lines)

**Includes:**
- `ChannelManagerOps` trait
- `ChannelDetails` struct
- `NullChannelManager` implementation

**Blocker:**
- Uses `CommitmentExtraOutput` from `lightning::ln::chan_utils`
- Would need to either:
  - Abstract the type, or
  - Add Lightning as optional dependency to deposits-core

**Why consider:**
- Already designed as adapter trait
- Allows other Lightning implementations to provide adapters
- Clean separation of interface from implementation

**Impact:** ~240 lines moved (after resolving Lightning dependency)

---

### 2.2 Logger Migration Path (COMPLETED)

**Status:** ✅ Infrastructure complete

**What was done:**
1. Added `tracing` crate to deposits-core
2. Created LDK-compatible macros (`log_info!`, `log_debug!`, etc.) backed by tracing
3. Migrated `QuorumProcessor`, `CollateralProcessor`, `RecoveryProcessor` to use tracing

**Migration path for deposits-ldk code:**
```rust
// Before (deposits-ldk with LDK macros):
use lightning::{log_info, log_debug};
log_info!(self.logger, "Processing {}", msg);

// After (in deposits-core with tracing-backed macros):
use deposits_core::{log_info, log_debug};
log_info!(self.logger, "Processing {}", msg);  // Same syntax!
```

**For new code, prefer structured tracing:**
```rust
tracing::info!(peer = %peer_id, seq = n, "Processing message");
```

**Why keep LDK macros in deposits-ldk:**
- LDK macros provide Lightning-specific context (channel_id, peer_id, payment_hash)
- This context is valuable for debugging Lightning operations
- No need to migrate existing deposits-ldk code unless moving to deposits-core
- Cleaner dependency graph

**Impact:** Architectural change across ~30 handler modules

---

## Priority 3: Long-Term Refactoring

### 3.1 Signature Utilities

**Current location:** `deposits-ldk/src/handler/signature_utils.rs`

**Assessment needed:**
- Check if utilities are generic or LDK-specific
- Pure Bitcoin signing logic could move to deposits-core

---

### 3.2 Quorum Processing

**Current state:** Already mostly in `deposits-core/src/message_processor.rs`

**What remains in deposits-ldk:**
- Handler-specific dispatch logic
- Async operation wrappers

**Action:** Verify separation is complete

---

## Not Recommended

### DepositsHandler → deposits-core

**Why not:**
- Tightly bound to `L::Target: LdkLogger`
- 30+ handler modules depend on Lightning macros
- Uses tokio heavily; deposits-core doesn't have async dependency
- Would require massive abstraction layer

### Services → deposits-core

**Why not:**
- Event-driven orchestration is LDK node-specific
- Services coordinate between LDK events and deposits protocol
- Naturally belongs in deposits-ldk

### Commitment Logic → deposits-core

**Why not:**
- `CommitmentTransactionEnhancer` depends on Lightning logger
- `CommitmentExtraOutput` is Lightning-specific type
- Belongs in deposits-ldk as Lightning integration

---

## Expected Benefits

| Metric | Before | Current |
|--------|--------|---------|
| deposits-ldk size | ~27K lines | ~39K lines |
| deposits-core size | ~10K lines | ~23K lines |
| **Core ratio** | ~27% | **37%** |

Note: Total lines increased due to added functionality. The key metric is
that ~13K lines of protocol logic moved from ldk to core.

- **Better reusability** for non-LDK Lightning implementations
- **Cleaner dependency graph** with clear layer separation
- **Easier testing** of core logic without Lightning dependencies
- **Reduced coupling** to upstream changes

---

## Implementation Order

1. ✅ **PaymentTracking impl** (smallest, proves the pattern) - commit 649aab5
2. ✅ **Reserve proposal types** (significant impact, clear boundaries) - commit 99a5f27
3. ✅ **Wire message constants & utilities** (message type constants, utility functions) - commit 3bebb5d
4. ✅ **HashStrategy** (commitment sync strategy based on message type) - commit 1d8e73a
5. ✅ **Signature utilities** (already moved)
6. ✅ **V2 message type name utilities** (type_id_to_const_name, type_id_to_variant_name) - commit ecf582b
7. ✅ **Dead code cleanup** (duplicate is_deposits_message_type, unused serde_arrays modules) - commits a9db34e, 80c857d
8. ✅ **Tracing in deposits-core** (add tracing crate, migrate message processors) - commit 6a5b0ff
9. ✅ **LDK-compatible logging macros** (log_info!, log_debug!, etc. backed by tracing) - commit 12c03d6
10. ✅ **build_taproot_reserves_script** (pure function moved to deposits-core) - commit 8f3feab
11. ✅ **Remove duplicate requires_acknowledgment** (was V2-only, now re-exports from deposits-core) - commit e8d2fc8
12. ✅ **Remove duplicate get_message_category** (was missing V2/quorum/recovery types, now re-exports from deposits-core) - commit 300ce6a
13. ✅ **Logger abstraction in deposits-ldk** (572 log calls across 38 files migrated to deposits-core macros) - commit ac01065
14. ✅ **Wire message structs** (42 message types moved to deposits-core with WireEncode/WireDecode) - commits 189f17e, 30104e1, b4e7236, a6f904f
15. ✅ **ChannelManagerOps** (CommitmentExtraOutput + ChannelId types created in core) - commit 699059c

---

## Phase 2: Handler Logic Extraction

Analysis shows 74% of top handler files is generic protocol logic. Target: ~5,000 lines.

### 2.1 message_validation.rs → deposits-core (Priority: HIGHEST)

**Current location:** `deposits-ldk/src/handler/message_validation.rs` (~1,732 lines)

**Generic:** 88% (~1,532 lines)
**LDK-specific:** 12% (~200 lines) - trait bounds, logger

**What to move:**
- `validate_operation()` function (140 lines)
- All 17 validation method implementations
- Validation is pure computation - no async, no message sending

**Blocker:** Needs `ValidationContext` trait for ledger access

**Impact:** ~1,500 lines moved

---

### 2.2 message_handlers.rs → deposits-core (Priority: HIGH)

**Current location:** `deposits-ldk/src/handler/message_handlers.rs` (~2,483 lines)

**Generic:** 85% (~2,113 lines)
**LDK-specific:** 15% (~370 lines) - LightningError, message queueing

**What to move:**
- 22 protocol handler functions (quorum, recovery, collateral, payment)
- Core business logic for each message type

**Blockers:**
- Need `HandlerContext` trait for ledger/message access
- Need generic `HandlerError` to replace `LightningError`
- `send_message()` needs transport abstraction

**Impact:** ~1,700 lines moved

---

### 2.3 recovery_ops.rs → deposits-core (Priority: HIGH)

**Current location:** `deposits-ldk/src/handler/recovery_ops.rs` (~1,602 lines)

**Generic:** 75% (~1,202 lines)
**LDK-specific:** 25% (~400 lines) - logging, signing, messaging

**What to move:**
- Recovery state machines
- Claim initiation and validation
- Signature collection logic
- Fraud proof (accusation) logic

**Blockers:**
- Heavy logger dependency (40+ calls)
- Message transport abstraction needed
- Signature operations need abstraction

**Impact:** ~1,000 lines moved

---

### 2.4 messages.rs core definitions (Priority: MEDIUM)

**Current location:** `deposits-ldk/src/handler/messages.rs` (~3,502 lines)

**Generic:** 62% (~2,172 lines)
**LDK-specific:** 38% (~1,330 lines) - Readable/Writeable impls

**What to move:**
- `DepositsMessage` enum definition
- Helper methods (message_type, to_operation, descriptive_name)
- V1/V2 conversion logic

**Impact:** ~900 lines moved

---

### Required Abstractions

```rust
// deposits-core/src/traits.rs

pub trait ValidationContext {
    fn get_ledger(&self, operator: PublicKey, partner: PublicKey)
        -> Option<Arc<RwLock<Ledger>>>;
    fn get_our_node_id(&self) -> PublicKey;
}

pub trait HandlerContext: ValidationContext {
    fn send_message(&self, peer: PublicKey, msg: impl Into<Vec<u8>>)
        -> Result<(), HandlerError>;
    fn emit_event(&self, event: DepositEvent);
}

pub trait RecoveryContext: HandlerContext {
    fn get_recovery_manager(&self) -> Arc<Mutex<RecoveryManager>>;
    fn get_claim_manager(&self) -> Arc<Mutex<ClaimManager>>;
}
```

---

### Phase 2 Implementation Order

16. ✅ **ValidationContext trait** - abstraction for ledger access - commit ce3aeba
17. ✅ **message_validation.rs** - move validation logic (~870 lines) - commit ce3aeba
18. ✅ **HandlerError type** - generic error to replace LightningError - commit 8e83769
19. ✅ **HandlerContext trait** - abstraction for message sending - commit 8e83769
20. ✅ **message_handlers.rs** - move handler logic (13 handlers, ~1.8K lines) - commits 8e83769, ae6ca67, 43a42c2
21. **RecoveryContext trait** - abstraction for recovery state
22. **recovery_ops.rs** - move recovery logic (~1,000 lines)
23. **DepositsMessage enum** - move to core (~900 lines)
