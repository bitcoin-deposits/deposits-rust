# Rust-Lightning Reserves Fork: Rebase Analysis

## Executive Summary

The `bitcoin-deposits-reserves` branch of rust-lightning adds reserves output support to Lightning commitment transactions. This branch is based on commit `463e432e9` (LDK 0.1.x era) and needs to be rebased onto commit `5236dba05` (LDK 0.3.x era) to be compatible with upstream ldk-node.

**Key Challenge**: 2,276 upstream commits with 23,819 insertions and 11,121 deletions in the core channel files, resulting in 179 merge conflicts across 6 critical files.

---

## What We Built: Reserves Output Support

### Overview

The reserves feature adds a new output type to Lightning commitment transactions that allows nodes to commit funds to an on-chain address while maintaining channel operation. This enables the Bitcoin Deposits protocol to have cryptographic proof of reserves.

### New Message Types (`lightning/src/ln/msgs.rs`)

```rust
/// Message to propose a reserves update
pub struct UpdateReserves {
    pub channel_id: ChannelId,
    pub reserves_sats: u64,           // Amount to reserve
    pub script_pubkey: ScriptBuf,     // P2TR output for reserves
    pub ledger_hash: [u8; 32],        // Sender's ledger state hash
    pub remote_ledger_hash: [u8; 32], // Expected remote ledger hash
}

/// Message to accept a reserves update
pub struct AcceptReserves {
    pub channel_id: ChannelId,
}
```

**Wire Protocol**: Custom message types for reserves negotiation between peers.

### Channel State Extensions (`lightning/src/ln/channel.rs`)

Key additions:
- `local_reserves: Option<ReservesOutputInfo>` - Our reserves in commitment tx
- `remote_reserves: Option<ReservesOutputInfo>` - Counterparty's reserves
- `pending_local_reserves: Option<ReservesOutputInfo>` - Pending reserves update
- `pending_remote_reserves: Option<ReservesOutputInfo>` - Pending from counterparty

```rust
pub struct ReservesOutputInfo {
    pub amount_sats: u64,
    pub script_pubkey: ScriptBuf,  // P2TR script for reserves output
    pub ledger_hash: [u8; 32],     // Cryptographic commitment to ledger state
}
```

**Holding Cell Pattern**: Uses LDK's holding cell pattern for reserves updates that can't be applied immediately (similar to HTLC handling).

### Commitment Transaction Changes (`lightning/src/ln/chan_utils.rs`)

Modified `build_commitment_transaction` to:
1. Include reserves outputs in commitment transactions
2. Adjust channel balance calculations for reserves amounts
3. Generate proper witness scripts for reserves outputs

### Channel Manager API (`lightning/src/ln/channelmanager.rs`)

New public APIs:
- `send_update_reserves()` - Propose reserves update to peer
- `get_channel_local_reserves_amount()` - Query current local reserves
- `get_channel_remote_reserves_amount()` - Query counterparty reserves
- `get_channel_local_reserves_ledger_hash()` - Get ledger hash
- `has_pending_local_reserves()` - Check for pending updates

### Channel Monitor (`lightning/src/chain/channelmonitor.rs`)

Extended to:
- Track reserves outputs for on-chain enforcement
- Include reserves in justice transaction construction
- Persist reserves state across restarts

---

## Upstream Changes Causing Conflicts

### Scale of Changes

Between our base (`463e432e9`) and target (`5236dba05`):
- **2,276 commits** in upstream
- **channelmanager.rs**: 15,886 insertions, heavy refactoring
- **channel.rs**: 14,981 insertions, major restructuring
- **channelmonitor.rs**: 4,073 insertions

### Major Upstream Refactors

1. **Macro-to-Method Conversions** (channelmanager.rs)
   - `convert_channel_err` macro → multiple methods
   - `send_channel_ready` macro → method
   - Error handling restructured throughout

2. **Splice Support** (channel.rs, channelmanager.rs)
   - New `SplicePending` and `SpliceFailed` events
   - Channel funding transaction handling reworked
   - `ChannelDetails` extended with splice fields

3. **Async Commitment Point Fetching**
   - Channel reestablish handling now supports async
   - Affects commitment transaction generation flow

4. **Quiescence Protocol**
   - New channel state for protocol upgrades
   - Affects state machine in channel.rs

5. **Structured Logging**
   - New `LogRecord` with context fields
   - Logger trait changes

6. **HTLC Forwarding Refactor**
   - Forwarded HTLCs map rebuilt from channels
   - Affects channelmanager serialization

---

## Conflict Breakdown by File

### `channelmanager.rs` (92 conflicts)

**Our changes touch**:
- Channel creation/initialization (reserves fields)
- Message handling (UpdateReserves, AcceptReserves dispatch)
- Channel state queries (reserves getters)
- Commitment transaction triggering

**Upstream changed**:
- Error handling completely restructured
- Macro-to-method conversions everywhere
- HTLC forwarding rebuilt
- Splice support added

**Conflict hotspots**:
- `handle_message()` dispatch
- Channel state accessors
- Error conversion code

### `channelmonitor.rs` (46 conflicts)

**Our changes touch**:
- Commitment transaction parsing (reserves outputs)
- Justice transaction construction
- State persistence

**Upstream changed**:
- Auto-archival of resolved monitors
- Restructured commitment parsing
- New signing flows

### `channel.rs` (26 conflicts)

**Our changes touch**:
- Channel struct fields (reserves state)
- Commitment transaction building
- State transitions for reserves updates

**Upstream changed**:
- Splice support (major)
- Quiescence protocol
- Funding transaction handling
- Async commitment points

### `chan_utils.rs` (10 conflicts)

**Our changes touch**:
- `build_commitment_transaction()` - reserves outputs
- Transaction weight calculations

**Upstream changed**:
- Commitment transaction structure for splices
- Weight calculation updates

### `channel_state.rs` (3 conflicts)

**Our changes**: Added reserves fields to `ChannelDetails`

**Upstream changes**: Added splice-related fields

### `msgs.rs` (2 conflicts)

**Our changes**: Added `UpdateReserves`, `AcceptReserves` messages

**Upstream changes**: Message trait changes, new splice messages

---

## Recommended Rebase Strategy

### Option 1: Incremental Rebase (Recommended)

1. **Phase 1: Message Layer** (Low risk)
   - Rebase `msgs.rs` changes first
   - Pure additions, minimal conflicts

2. **Phase 2: Channel State** (Medium risk)
   - Add reserves fields to channel.rs
   - Integrate with new splice state machine

3. **Phase 3: Commitment Transactions** (Medium risk)
   - Update `chan_utils.rs` for new transaction structure
   - Ensure reserves outputs work with splice

4. **Phase 4: Channel Manager** (High risk)
   - Port message handling to new method-based structure
   - Update APIs for new error handling

5. **Phase 5: Channel Monitor** (High risk)
   - Update for new commitment parsing
   - Test on-chain enforcement

### Option 2: Clean Reimplementation

Given the scale of upstream changes, it may be cleaner to:

1. Start fresh on `5236dba05`
2. Re-implement reserves using upstream patterns
3. Use upstream's quiescence protocol for reserves updates (cleaner state machine)
4. Leverage splice infrastructure for reserves (similar output management)

**Pros**: Cleaner integration, uses upstream patterns
**Cons**: More initial work, risk of missing edge cases from original impl

### Option 3: Wait for Upstream Stabilization

The upstream is actively evolving (splice, quiescence, async signing). Consider:
- Wait for LDK 0.4 stable release
- Implement reserves on stable API
- Reduces repeated rebase effort

---

## Files Changed Summary

| File | Our Lines | Conflicts | Risk |
|------|-----------|-----------|------|
| `channelmanager.rs` | +1,332 | 92 | High |
| `channel.rs` | +973 | 26 | High |
| `channelmonitor.rs` | +721 | 46 | High |
| `msgs.rs` | +189 | 2 | Low |
| `chan_utils.rs` | +163 | 10 | Medium |
| `channel_state.rs` | +12 | 3 | Low |

---

## Testing Considerations

After rebase, need to verify:

1. **Reserves in commitment transactions** - Outputs present and valid
2. **Holding cell behavior** - Reserves updates queued correctly
3. **Persistence** - Reserves state survives restart
4. **On-chain enforcement** - Justice transactions include reserves
5. **Interaction with splice** - Reserves preserved across splices
6. **Interaction with quiescence** - Clean state transitions

---

## Next Steps

1. Decide on rebase strategy (incremental vs. reimplementation)
2. If incremental: Start with msgs.rs (lowest risk)
3. Create test cases that verify reserves behavior
4. Document any API changes from original implementation
5. Consider contributing reserves to upstream LDK (long-term)
