# Reserves Integration Implementation Plan

## Design Decisions

### Protocol Flow
1. **Handshake** → Create reserves (330 sats, zero ledger hash)
2. **OpenLedger** → Update reserves with actual ledger hash
3. **Every ledger update** → Update reserves with new ledger hash

### Key Constraints
- ✅ Reserves output MUST exist before ledger opens
- ✅ Reserves continuously updated to reflect latest ledger state
- ✅ Custodian key = operator's node pubkey
- ✅ Initial reserves amount = 330 sats (anchor output minimum)

---

## Implementation Tasks

### Task 1: Add Node API Passthrough

**File**: `src/lib.rs`

**Add method**:
```rust
pub fn send_update_reserves(
    &self,
    counterparty_node_id: PublicKey,
    channel_id: ChannelId,
    holder_reserves_sats: u64,
    holder_custodian_pubkey: PublicKey,
    holder_ledger_hash: [u8; 32],
    counterparty_reserves_sats: u64,
    counterparty_custodian_pubkey: PublicKey,
    counterparty_ledger_hash: [u8; 32],
) -> Result<(), Error> {
    self.channel_manager.send_update_reserves(
        &counterparty_node_id,
        &channel_id,
        holder_reserves_sats,
        holder_custodian_pubkey,
        holder_ledger_hash,
        counterparty_reserves_sats,
        counterparty_custodian_pubkey,
        counterparty_ledger_hash,
    ).map_err(|e| Error::ChannelConfigFailed)?;
    Ok(())
}
```

**Testing**: Unit test that calls method and verifies no panic

---

### Task 2: Hook Handshake Completion

**File**: `src/bitcoin_deposits/handshake.rs` (or `handler.rs`)

**When**: After handshake succeeds, before returning success

**Action**: Send UpdateReserves with initial parameters

**Code**:
```rust
// After handshake completes successfully
fn on_handshake_complete(
    &self,
    partner_node_id: PublicKey,
    channel_id: ChannelId,
) -> Result<(), DepositsError> {
    // Get node pubkeys to use as custodian keys
    let holder_custodian = self.node_pubkey();
    let counterparty_custodian = partner_node_id;

    // Initial reserves: 330 sats (anchor output minimum)
    let initial_reserves_sats = 330;

    // No ledger exists yet, use zero hash
    let zero_hash = [0u8; 32];

    // Send UpdateReserves to create reserves outputs
    self.channel_manager.send_update_reserves(
        &partner_node_id,
        &channel_id,
        initial_reserves_sats,
        holder_custodian,
        zero_hash,  // holder has no ledger yet
        initial_reserves_sats,
        counterparty_custodian,
        zero_hash,  // counterparty has no ledger yet
    )?;

    log_info!(self.logger,
        "Created reserves outputs (330 sats each) for channel {} with partner {}",
        channel_id, partner_node_id);

    Ok(())
}
```

**Testing**: Test that handshake completion triggers UpdateReserves message

---

### Task 3: Hook OpenLedger

**File**: `src/bitcoin_deposits/handler.rs`

**When**: After OpenLedger message is processed and ledger is initialized

**Action**: Update reserves with actual ledger hash

**Code**:
```rust
// In handle_open_ledger() or similar
fn on_ledger_opened(
    &self,
    partner_node_id: PublicKey,
    channel_id: ChannelId,
) -> Result<(), DepositsError> {
    let protocol = self.protocols.get(&partner_node_id)
        .ok_or(DepositsError::ProtocolNotInitialized)?;

    // Get current ledger hash
    let holder_ledger_hash = protocol.ledger.get_hash();

    // Custodian keys (same as before)
    let holder_custodian = self.node_pubkey();
    let counterparty_custodian = partner_node_id;

    // Keep same reserves amounts (330 sats)
    let reserves_sats = 330;

    // Counterparty still has zero hash (they haven't opened ledger yet)
    let counterparty_hash = [0u8; 32];

    // Update reserves with actual ledger hash
    self.channel_manager.send_update_reserves(
        &partner_node_id,
        &channel_id,
        reserves_sats,
        holder_custodian,
        holder_ledger_hash,  // NOW we have actual ledger state
        reserves_sats,
        counterparty_custodian,
        counterparty_hash,
    )?;

    log_info!(self.logger,
        "Updated reserves with ledger hash {} for channel {}",
        hex::encode(holder_ledger_hash), channel_id);

    Ok(())
}
```

**Testing**: Test that OpenLedger triggers reserves update with non-zero hash

---

### Task 4: Hook Every Ledger Update

**File**: `src/bitcoin_deposits/handler.rs` or `src/bitcoin_deposits/protocol.rs`

**When**: After any ledger update is applied (deposit, withdrawal, payment)

**Action**: Update reserves with new ledger hash

**Code**:
```rust
// Call this after any ledger state change
fn refresh_reserves_commitment(
    &self,
    partner_node_id: PublicKey,
    channel_id: ChannelId,
) -> Result<(), DepositsError> {
    let protocol = self.protocols.get(&partner_node_id)
        .ok_or(DepositsError::ProtocolNotInitialized)?;

    // Get updated ledger hashes
    let holder_ledger_hash = protocol.ledger.get_hash();

    // Get counterparty ledger hash if they have one
    let counterparty_ledger_hash = protocol.counterparty_ledger
        .as_ref()
        .map(|l| l.get_hash())
        .unwrap_or([0u8; 32]);

    // Custodian keys
    let holder_custodian = self.node_pubkey();
    let counterparty_custodian = partner_node_id;

    // Reserves amounts stay constant
    let reserves_sats = 330;

    // Update commitment transaction with new ledger state
    self.channel_manager.send_update_reserves(
        &partner_node_id,
        &channel_id,
        reserves_sats,
        holder_custodian,
        holder_ledger_hash,
        reserves_sats,
        counterparty_custodian,
        counterparty_ledger_hash,
    )?;

    log_trace!(self.logger,
        "Refreshed reserves commitment with updated ledger hash");

    Ok(())
}

// Call this after:
// - apply_deposit()
// - apply_withdrawal()
// - apply_payment()
// - apply_ledger_update() (generic)
```

**Integration points** (add call to `refresh_reserves_commitment()`):
- After `LedgerUpdate::BalanceDeposited` is applied
- After `LedgerUpdate::BalanceWithdrawn` is applied
- After `LedgerUpdate::SendingFulfillPayment` is applied
- After `LedgerUpdate::ReceivingSettlePayment` is applied
- After any other ledger state change

**Testing**:
- Test that deposit updates reserves hash
- Test that withdrawal updates reserves hash
- Test that payment updates reserves hash

---

### Task 5: Handle AcceptReserves Message

**File**: `src/bitcoin_deposits/handler.rs` or message handler

**When**: Receive AcceptReserves from counterparty

**Action**: Log acceptance, update local state

**Code**:
```rust
fn handle_accept_reserves(
    &self,
    partner_node_id: PublicKey,
    msg: AcceptReserves,
) -> Result<(), DepositsError> {
    log_info!(self.logger,
        "Received AcceptReserves for channel {} from {}",
        msg.channel_id, partner_node_id);

    // Optional: Track that reserves were accepted
    // Could update protocol state if needed

    Ok(())
}
```

**Testing**: Test that AcceptReserves message is handled without error

---

## Integration Checklist

- [ ] Task 1: Add `Node::send_update_reserves()` API
- [ ] Task 2: Hook handshake completion
- [ ] Task 3: Hook OpenLedger
- [ ] Task 4: Hook ledger updates
- [ ] Task 5: Handle AcceptReserves
- [ ] Test: Handshake creates reserves
- [ ] Test: OpenLedger updates hash
- [ ] Test: Ledger updates refresh hash
- [ ] Test: End-to-end flow (handshake → open → update → close)

---

## Open Questions

1. **Where is `protocol.ledger.get_hash()` implemented?**
   - Need to verify this exists in `ChannelLedger` or similar
   - If not, need to implement ledger hashing

2. **Do we track counterparty's ledger?**
   - Do we receive and validate their ledger updates?
   - If so, need to store their ledger hash too

3. **What if UpdateReserves fails?**
   - Retry logic?
   - Fail the whole operation?
   - Log and continue?

4. **Should reserves amount ever increase?**
   - Start at 330 sats
   - Could increase based on channel balance?
   - Or always stay at minimum?

---

## Next Steps

1. Start with Task 1 (API passthrough) - simple and testable
2. Then Task 2 (handshake hook) - establishes the flow
3. Then Task 3 (OpenLedger hook) - adds ledger hash
4. Then Task 4 (update hooks) - continuous refresh
5. Finally Task 5 (AcceptReserves) - complete the protocol
