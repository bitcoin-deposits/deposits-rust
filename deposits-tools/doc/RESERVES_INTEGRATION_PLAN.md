# Reserves Output Integration Plan

## Overview

We've completed the low-level reserves implementation in rust-lightning. Now we need to integrate it with ldk-node to enable Bitcoin Deposits protocol to use reserves outputs in commitment transactions.

## What We've Built (rust-lightning)

### Core Functionality ✅
- **Data structures**: `ReservesConfig` with `party_pubkey` + `custodian_pubkey`
- **Messages**: `UpdateReserves` (type 137) and `AcceptReserves` (type 138)
- **Wire protocol**: Full serialization, deserialization, and dispatch
- **Handlers**: Channel-level `update_reserves()` and `accept_reserves()` methods
- **Sending**: Channel-level `send_update_reserves()` and `send_accept_reserves()`
- **Public API**: `ChannelManager::send_update_reserves()`
- **Tests**: 15 tests covering wire protocol and message structures

### Architecture
Two reserves outputs per commitment transaction:
1. **holder_reserves**: Channel party + their custodian (2-of-2 multisig)
2. **counterparty_reserves**: Counterparty + their custodian (2-of-2 multisig)

## What Exists (ldk-node)

### Bitcoin Deposits Infrastructure
- `DepositsHandler`: Main protocol coordinator
- `DepositsProtocol`: Per-partner protocol state
- `ReservesOutputManager`: High-level reserves proposals
- `HandshakeManager`: Initial protocol setup between partners
- `DepositsStore`: Persistent storage for ledgers
- Event system for protocol messages

### Key Integration Points
1. **Node API** (`src/lib.rs`): Public methods like `open_channel()`, `close_channel()`
2. **Message Handler** (`src/message_handler.rs`): Custom message routing
3. **Event Handler** (`src/event.rs`): Event processing loop
4. **Bitcoin Deposits Handler** (`src/bitcoin_deposits/handler.rs`): Protocol logic

## Integration Tasks

### Phase 1: Connect rust-lightning API to Node

**Goal**: Expose `ChannelManager::send_update_reserves()` at the Node level

**Files to modify**:
- `src/lib.rs` - Add public `send_update_reserves()` method

**Implementation**:
```rust
// In src/lib.rs Node impl block
pub fn send_update_reserves(
    &self,
    counterparty_node_id: PublicKey,
    channel_id: ChannelId,
    holder_reserves_sats: u64,
    holder_custodian_pubkey: PublicKey,
    holder_ledger_hash: [u8; 32],  // NEW: Cryptographic commitment to holder's ledger
    counterparty_reserves_sats: u64,
    counterparty_custodian_pubkey: PublicKey,
    counterparty_ledger_hash: [u8; 32],  // NEW: Cryptographic commitment to counterparty's ledger
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

**Testing**:
- Unit test calling the method with valid parameters
- Verify MessageSendEvent is queued

---

### Phase 2: Integrate with DepositsHandler

**Goal**: Connect reserves messages to Bitcoin Deposits protocol lifecycle

**Key Questions to Answer**:
1. When should reserves be proposed? (During handshake? After ledger init?)
2. Who initiates reserves? (Operator? Partner? Both?)
3. How do reserves relate to existing `ReservesOutputProposal`?

**Integration Points**:

#### Option A: Reserves during handshake
- Add reserves negotiation to `HandshakeManager`
- Send `UpdateReserves` after successful handshake
- Store custodian keys in protocol state

#### Option B: Reserves after ledger initialization
- Add `propose_reserves()` method to `DepositsHandler`
- Allow dynamic reserves updates
- Tie to deposit flow

**Files to modify**:
- `src/bitcoin_deposits/handler.rs` - Add reserves coordination
- `src/bitcoin_deposits/handshake.rs` - Integrate with handshake flow
- `src/bitcoin_deposits/protocol.rs` - Add reserves state tracking

**Implementation sketch**:
```rust
// In DepositsHandler
pub fn propose_channel_reserves(
    &self,
    partner_node_id: PublicKey,
    channel_id: ChannelId,
    holder_amount: u64,
    counterparty_amount: u64,
) -> Result<(), DepositsError> {
    // Get custodian keys and ledger hashes from protocol state
    let protocol = self.get_protocol(&partner_node_id)
        .ok_or(DepositsError::ProtocolNotInitialized)?;

    let holder_custodian = protocol.get_holder_custodian_key()?;
    let counterparty_custodian = protocol.get_counterparty_custodian_key()?;

    // Compute ledger hashes from current ledger state
    let holder_ledger_hash = protocol.get_holder_ledger_hash()?;
    let counterparty_ledger_hash = protocol.get_counterparty_ledger_hash()?;

    // Delegate to ChannelManager with ledger commitments
    self.channel_manager.send_update_reserves(
        &partner_node_id,
        &channel_id,
        holder_amount,
        holder_custodian,
        holder_ledger_hash,  // Embed ledger state in reserves output
        counterparty_amount,
        counterparty_custodian,
        counterparty_ledger_hash,  // Embed counterparty ledger state
    )?;

    Ok(())
}
```

**Testing**:
- Test reserves proposal during handshake
- Test reserves update after channel is active
- Test error cases (no protocol, invalid amounts)

---

### Phase 3: Event Handling

**Goal**: React to reserves messages in event processing loop

**Files to modify**:
- `src/event.rs` - Handle reserves-related events
- `src/bitcoin_deposits/events.rs` - Add reserves event types

**New Events**:
```rust
pub enum DepositsEvent {
    // ... existing events ...

    /// Reserves proposal received from counterparty
    ReservesProposalReceived {
        partner_node_id: PublicKey,
        channel_id: ChannelId,
        holder_amount: u64,
        counterparty_amount: u64,
    },

    /// Reserves proposal accepted
    ReservesProposalAccepted {
        partner_node_id: PublicKey,
        channel_id: ChannelId,
    },
}
```

**Event Processing**:
```rust
// In event handler
DepositsEvent::ReservesProposalReceived { partner_node_id, channel_id, .. } => {
    log_info!(logger, "Received reserves proposal for channel {}", channel_id);

    // Auto-accept for now (could add validation logic)
    node.send_accept_reserves(partner_node_id, channel_id)?;
}
```

**Testing**:
- Test event generation when receiving UpdateReserves
- Test event handling and AcceptReserves response
- Test event logging

---

### Phase 4: Message Protocol Integration

**Goal**: Wire reserves messages into existing Bitcoin Deposits message flow

**Current Message Flow**:
1. Handshake messages (protocol initialization)
2. Ledger updates (deposit tracking)
3. Invoice cosigning (payment coordination)

**Reserves Message Flow**:
1. After handshake: Send `UpdateReserves` with custodian keys
2. Counterparty: Validate and send `AcceptReserves`
3. Both parties: Update channel state with reserves config

**Files to modify**:
- `src/bitcoin_deposits/messages.rs` - Add reserves message types
- `src/bitcoin_deposits/handler.rs` - Process reserves messages
- `src/message_handler.rs` - Route reserves messages

**Implementation**:
```rust
// Add to DepositsMessage enum
pub enum DepositsMessage {
    // ... existing variants ...

    UpdateReserves {
        channel_id: ChannelId,
        holder_reserves_sats: u64,
        holder_custodian_pubkey: PublicKey,
        counterparty_reserves_sats: u64,
        counterparty_custodian_pubkey: PublicKey,
    },

    AcceptReserves {
        channel_id: ChannelId,
    },
}
```

**Testing**:
- Test message serialization/deserialization
- Test message routing to DepositsHandler
- Test integration with existing protocol state

---

### Phase 5: CLI/API Exposure

**Goal**: Add user-facing commands for reserves management

**Files to modify**:
- `src/bin/ldk-server.rs` - Add REST API endpoint
- `src/bin/nwc-client.rs` - Add CLI command

**New CLI Command**:
```bash
# Propose reserves for a channel
nwc-client --target <port> propose-reserves \
  --channel-id <channel_id> \
  --holder-amount 10000 \
  --counterparty-amount 10000

# Query reserves status
nwc-client --target <port> get-reserves \
  --channel-id <channel_id>
```

**REST API Endpoint**:
```rust
// POST /api/v1/channels/{channel_id}/reserves
{
  "holder_amount": 10000,
  "counterparty_amount": 10000
}
```

**Testing**:
- Test CLI command parsing and execution
- Test API endpoint with curl
- Test error handling (invalid channel, amounts)

---

### Phase 6: Integration Tests

**Goal**: End-to-end tests covering full reserves lifecycle

**Test Scenarios**:

1. **Happy Path**:
   - Open channel between Alice and Bob
   - Complete handshake
   - Alice proposes reserves
   - Bob accepts reserves
   - Verify commitment transaction includes reserves outputs

2. **Reserves Update**:
   - Existing channel with reserves
   - Propose new reserves amounts
   - Verify updated commitment transaction

3. **Reserves Removal**:
   - Channel with reserves
   - Propose reserves with 0 amounts
   - Verify commitment transaction removes reserves outputs

4. **Error Cases**:
   - Propose reserves before handshake → error
   - Invalid custodian keys → error
   - Amounts exceed channel capacity → error

**Files to create**:
- `tests/reserves_integration_test.rs`

**Testing Infrastructure**:
```rust
#[test]
fn test_full_reserves_lifecycle() {
    // Setup: Create two nodes
    let (alice, bob) = create_test_nodes();

    // Step 1: Open channel
    let channel_id = alice.open_channel_to(bob)?;

    // Step 2: Initialize Bitcoin Deposits protocol
    alice.bitcoin_deposits_handler.initialize_ledger(bob.node_id())?;
    bob.bitcoin_deposits_handler.initialize_ledger(alice.node_id())?;

    // Step 3: Propose reserves
    alice.send_update_reserves(
        bob.node_id(),
        channel_id,
        5000, // holder
        alice_custodian_key,
        5000, // counterparty
        bob_custodian_key,
    )?;

    // Step 4: Process message and accept
    process_pending_messages(alice, bob)?;

    // Step 5: Verify reserves in commitment transaction
    let commitment = alice.get_latest_commitment_transaction(channel_id)?;
    assert!(commitment.has_reserves_outputs());
    assert_eq!(commitment.holder_reserves_amount(), 5000);
    assert_eq!(commitment.counterparty_reserves_amount(), 5000);
}
```

---

## Integration Strategy

### Approach: Incremental Integration

1. **Start simple**: Add Node API passthrough (Phase 1)
2. **Test early**: Verify reserves messages flow end-to-end
3. **Add complexity**: Integrate with DepositsHandler (Phase 2-3)
4. **Expose safely**: Add CLI/API after core is stable (Phase 5)
5. **Test thoroughly**: Comprehensive integration tests (Phase 6)

### Risk Mitigation

1. **Backwards compatibility**: Reserves are optional, existing code unaffected
2. **Feature flag**: Guard Bitcoin Deposits behind `bitcoin-deposits` feature
3. **Graceful degradation**: Handle missing custodian keys gracefully
4. **Extensive testing**: Unit + integration tests at every phase

---

## Open Questions

### Protocol Design Questions

1. **Timing**: When should reserves be proposed?
   - During initial handshake?
   - After ledger initialization?
   - On-demand by operator?

2. **Initiation**: Who can propose reserves?
   - Only operator?
   - Either party?
   - Requires mutual agreement?

3. **Validation**: What validation rules?
   - Minimum/maximum amounts?
   - Ratio to channel capacity?
   - Tie to deposit balances?

4. **Updates**: How to handle reserves changes?
   - Can reserves increase/decrease?
   - Requires both parties' consent?
   - What happens to existing deposits?

5. **Lifecycle**: Reserves relationship to channel lifecycle?
   - What happens on force close?
   - How to recover reserves funds?
   - Emergency timeout mechanisms?

### Technical Questions

1. **Custodian Keys**: How are custodian keys determined?
   - Derived from node keys?
   - Separate key material?
   - Stored where?

2. **State Management**: Where to track reserves state?
   - In `DepositsProtocol`?
   - In channel state?
   - In separate reserves manager?

3. **Persistence**: What needs to be persisted?
   - Reserves proposals?
   - Custodian keys?
   - Reserves history?

4. **Error Handling**: What happens if reserves proposal fails?
   - Retry?
   - Fall back to no reserves?
   - Close channel?

---

## Success Criteria

Integration is complete when:

1. ✅ Node has public `send_update_reserves()` method
2. ✅ Reserves messages flow between nodes
3. ✅ DepositsHandler coordinates reserves
4. ✅ Events notify application of reserves changes
5. ✅ CLI commands allow reserves management
6. ✅ Integration tests verify full lifecycle
7. ✅ Documentation explains reserves usage

---

## Next Steps

1. **Decision Point**: Answer protocol design questions (see "Open Questions")
2. **Phase 1**: Implement Node API passthrough
3. **Smoke Test**: Verify messages flow with manual testing
4. **Phase 2-3**: Integrate with Bitcoin Deposits protocol
5. **Phase 4-6**: Add event handling, CLI, and tests

---

## Notes

- This is a **new feature** - no existing code needs to change
- Integration can be done incrementally
- Feature can remain experimental until fully tested
- Need to coordinate with Bitcoin Deposits protocol design decisions
