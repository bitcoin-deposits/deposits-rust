# Bitcoin Deposits Library Investigation

## Overview

This document captures the analysis of extracting the Bitcoin Deposits protocol into a standalone library that could work with any Lightning implementation.

---

## 1. LDK Integration Points

### Current Dependencies

| Category | Difficulty | Key Dependencies |
|----------|------------|------------------|
| **Peer Messaging** | HARD | `CustomMessageHandler`, `CustomMessageReader`, wire format |
| **Payment Tracking** | MEDIUM | `PaymentId`, `PaymentHash`, `Bolt11Invoice` |
| **Channel Binding** | MEDIUM | `ChannelManager` for peer lookup |
| **Serialization** | MEDIUM | `impl_writeable_tlv_based` macros |
| **Features** | MEDIUM | `InitFeatures`, `NodeFeatures` |
| **Logger** | EASY | `lightning::util::logger::Logger` trait |
| **Persistence** | EASY | Already abstracted via `DynStore` |
| **Events** | EASY | Completely decoupled |
| **Broadcaster** | EASY | `BroadcasterInterface` (minimal) |

### Critical Integration: CustomMessageHandler

The tightest coupling is in `handler/core.rs` (lines 12225-12350):

```rust
impl<L> CustomMessageHandler for DepositsHandler<L> {
    fn handle_custom_message(&self, msg: DepositsMessage, sender: PublicKey)
        -> Result<(), LightningError>
    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, DepositsMessage)>
    fn provided_node_features(&self) -> NodeFeatures
    fn provided_init_features(&self, their_node_id: PublicKey) -> InitFeatures
}
```

This is how deposits messages flow through LDK's peer handler.

### What's Already Well-Isolated

1. **Persistence** - Uses `DynStore` trait, not LDK-specific
2. **Events** - `DepositsEvent` enum is completely independent
3. **Core Logic** - Ledger, validation, recovery are mostly pure business logic
4. **Tapscript** - Bitcoin-only, no LDK dependency

---

## 2. Message Protocol Analysis

### Current State: 46+ Message Types

| Category | Count | Messages |
|----------|-------|----------|
| **Ledger Operations** | 21 | Reserves (5), Deposits (6), Collateral (3), Payments (4), Fees (1), Close (2) |
| **Coordination** | 4 | Handshake (2), ACK (1), CosignInvoice (1) |
| **Audit/Sync** | 3 | SignedUpdate, SyncRequest, SyncResponse |
| **Recovery** | 4 | Vote, ClaimRequest, ClaimSignature, ClaimComplete |
| **Quorum** | 6 | Join*, Vote*, StateSync, MembershipChange |
| **Collateral Mgmt** | 5 | Attestation, Add/Remove Partner, Consent Request/Response |
| **External** | 4 | NWC Relay (3), UncreditedPayment (1) |

### BOLT Message Type Rules

From [BOLT 1](https://github.com/lightning/bolts/blob/master/01-messaging.md):

| Type | Behavior |
|------|----------|
| **Odd** | MAY be ignored if not understood |
| **Even** | MUST close connection if not understood |

Current implementation correctly uses all odd numbers (0x8001, 0x8003, ...) so nodes that don't support the protocol safely ignore messages.

### Consolidation Opportunity

Instead of 46 flat message types, use nested enums with request/response pairs:

```
0x8001 LEDGER_UPDATE           → 0x8003 LEDGER_UPDATE_RESPONSE
0x8005 HANDSHAKE               → 0x8007 HANDSHAKE_RESPONSE
0x8009 SYNC                    → 0x800B SYNC_RESPONSE
0x800D RECOVERY                → 0x800F RECOVERY_RESPONSE
0x8011 COORDINATION            → 0x8013 COORDINATION_RESPONSE
0x8015 RELAY                   → 0x8017 RELAY_RESPONSE
```

All types remain odd for safe ignorability. Correlation via `request_hash` field in responses eliminates need for dedicated ACK message.

---

## 3. Proposed Message Structure

### LEDGER_UPDATE (0x8001) → LEDGER_UPDATE_RESPONSE (0x8003)

```rust
// Request: Operator → Partner
pub struct LedgerUpdateMsg {
    pub operation: LedgerOperation,
    pub sequence_number: u64,
    pub previous_hash: [u8; 32],
    pub current_hash: [u8; 32],
    pub operator_signature: [u8; 64],
}

pub enum LedgerOperation {
    // Reserves
    ReservesAdd { amount: u64, spend_to: PublicKey, collateral_partners: Vec<PublicKey> },
    ReservesRemove,
    ReservesIncrease { new_amount: u64 },
    ReservesDecrease { new_amount: u64 },

    // Deposits
    DepositOpen { pubkey: PublicKey, fees: Option<FeeStructure> },
    DepositClose { pubkey: PublicKey },
    DepositUpdate { pubkey: PublicKey, new_fees: FeeStructure },

    // Transfers (HTLC-like)
    TransferLock { pubkey: PublicKey, amount: u64, transfer_id: [u8; 32] },
    TransferFail { pubkey: PublicKey, transfer_id: [u8; 32] },
    TransferFulfill { pubkey: PublicKey, amount: u64, transfer_id: [u8; 32] },

    // Payments
    PaymentCredit { payment_hash: [u8; 32], deposit_pubkey: PublicKey, amount: u64 },
    PaymentLock { pubkey: PublicKey, amount: u64, payment_id: [u8; 32], sig: [u8; 64] },
    PaymentFail { pubkey: PublicKey, payment_id: [u8; 32] },
    PaymentFulfill { pubkey: PublicKey, amount: u64, payment_id: [u8; 32], preimage: [u8; 32] },

    // Collateral (ledger-modifying)
    CollateralIncrease { new_amount: u64, block_height: u32 },
    CollateralDecrease { new_amount: u64, block_height: u32 },
    CollateralAttestation { operator: PublicKey, amount: u64, block_height: u32, sig: [u8; 64] },
    CollateralAddPartner { partner: PublicKey, sig: [u8; 64] },
    CollateralRemovePartner { partner: PublicKey, sig: [u8; 64] },

    // Lifecycle
    FeeCollect { pubkey: PublicKey, amount: u64, block_height: u32 },
    LedgerClose,
    Tombstone { reason: Option<String> },
}

// Response: Partner → Operator (replaces ACK + porcupine dance)
pub struct LedgerUpdateResponseMsg {
    pub request_hash: [u8; 32],
    pub accepted: bool,
    pub error: Option<String>,
    pub partner_signature: Option<[u8; 64]>,
    pub confirmed_sequence: u64,
    pub confirmed_hash: [u8; 32],
}
```

### HANDSHAKE (0x8005) → HANDSHAKE_RESPONSE (0x8007)

```rust
pub struct HandshakeMsg {
    pub protocol_version: u16,
    pub min_protocol_version: u16,
    pub features: u32,
    pub operator_pubkey: PublicKey,
    pub partner_pubkey: PublicKey,
    pub funding_txid: [u8; 32],
    pub funding_vout: u16,
}

pub struct HandshakeResponseMsg {
    pub request_hash: [u8; 32],
    pub protocol_version: u16,
    pub accepted: bool,
    pub error: Option<String>,
    pub partner_pubkey: PublicKey,
}
```

### SYNC (0x8009) → SYNC_RESPONSE (0x800B)

```rust
pub struct SyncMsg {
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
    pub last_known_sequence: u64,
    pub last_known_hash: [u8; 32],
}

pub struct SyncResponseMsg {
    pub request_hash: [u8; 32],
    pub updates: Vec<LedgerUpdateMsg>,
    pub current_sequence: u64,
    pub current_hash: [u8; 32],
}
```

### RECOVERY (0x800D) → RECOVERY_RESPONSE (0x800F)

```rust
pub enum RecoveryMsg {
    Vote {
        is_conforming: bool,
        validated_hash: [u8; 32],
        validated_sequence: u64,
        signature: [u8; 64],
    },
    ClaimRequest {
        claimant: PublicKey,
        tier_index: u8,
        unsigned_tx: Vec<u8>,
        sighash: [u8; 32],
    },
    ClaimComplete {
        new_operator: PublicKey,
        claim_txid: [u8; 32],
        confirmation_block: u32,
    },
}

pub enum RecoveryResponseMsg {
    VoteAck { request_hash: [u8; 32], recorded: bool },
    ClaimSignature {
        request_hash: [u8; 32],
        sighash: [u8; 32],
        signature: [u8; 64],
    },
    ClaimAck { request_hash: [u8; 32] },
}
```

### COORDINATION (0x8011) → COORDINATION_RESPONSE (0x8013)

```rust
pub enum CoordinationMsg {
    CosignInvoice { pending_invoice: PendingInvoice },
    CollateralConsent { operator_signature: [u8; 64] },
    UncreditedPayment { preimage: [u8; 32], payment_hash: [u8; 32], ... },
}

pub enum CoordinationResponseMsg {
    InvoiceCosigned {
        request_hash: [u8; 32],
        cosignature: [u8; 64],
    },
    ConsentGranted {
        request_hash: [u8; 32],
        granted: bool,
        signature: [u8; 64],
    },
    AccusationAck { request_hash: [u8; 32] },
}
```

### RELAY (0x8015) → RELAY_RESPONSE (0x8017)

```rust
pub enum RelayMsg {
    NwcRequest { encrypted_content: Vec<u8>, relay_urls: Vec<String> },
    NwcDeliveryProof { event_id: [u8; 32], relay_signature: Vec<u8> },
}

pub enum RelayResponseMsg {
    NwcResult { request_hash: [u8; 32], status: RelayStatus, response: Option<Vec<u8>> },
    DeliveryAck { request_hash: [u8; 32] },
}
```

---

## 4. Comparison Summary

| Metric | Before | After |
|--------|--------|-------|
| **Wire message types** | 46 | 12 (6 pairs) |
| **LDK CustomMessageHandler arms** | 46 | 12 |
| **Message type constants** | 46 | 12 |
| **Dedicated ACK message** | Yes | No (responses serve as ACKs) |
| **Codec complexity** | High | Medium |

---

## 5. Extraction Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  deposits-core (new crate)                      │
├─────────────────────────────────────────────────────────────────┤
│  Ledger, Validation, Recovery, Tapscript, Messages              │
│  Events, Types, Codec (abstract wire format)                    │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              Adapter Traits                                     │
├─────────────────────────────────────────────────────────────────┤
│  trait PeerMessageTransport                                     │
│  trait PaymentProcessor                                         │
│  trait ChannelRegistry                                          │
│  trait StorageBackend (already exists as DynStore)              │
└─────────────────────────────────────────────────────────────────┘
                           │
            ┌──────────────┴──────────────┐
            ▼                             ▼
┌─────────────────────────┐   ┌─────────────────────────┐
│  deposits-ldk           │   │  deposits-cln           │
│  (LDK adapter)          │   │  (CLN adapter)          │
└─────────────────────────┘   └─────────────────────────┘
```

### Required Adapter Traits

```rust
/// Send/receive protocol messages to/from peers
pub trait PeerMessageTransport {
    fn send_message(&self, peer: PublicKey, msg: DepositsMessage) -> Result<(), Error>;
    fn register_handler(&self, handler: Arc<dyn MessageHandler>);
}

/// Track Lightning payments for deposit crediting
pub trait PaymentProcessor {
    fn get_payment_status(&self, payment_id: &[u8; 32]) -> Option<PaymentStatus>;
    fn subscribe_payment_events(&self, handler: Arc<dyn PaymentEventHandler>);
}

/// Map channels to partner nodes
pub trait ChannelRegistry {
    fn get_partner_for_channel(&self, channel_id: &[u8; 32]) -> Option<PublicKey>;
    fn list_channels_with_peer(&self, peer: PublicKey) -> Vec<[u8; 32]>;
}

/// Persist protocol state
pub trait StorageBackend {
    fn read(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>, Error>;
    fn write(&self, namespace: &str, key: &str, value: &[u8]) -> Result<(), Error>;
    fn delete(&self, namespace: &str, key: &str) -> Result<(), Error>;
    fn list(&self, namespace: &str, prefix: &str) -> Result<Vec<String>, Error>;
}
```

---

## 6. Effort Estimate

| Scope | Time | Risk |
|-------|------|------|
| **Message consolidation only** | 1-2 weeks | Low |
| **Minimal extraction** (traits + LDK adapter) | 2-3 weeks | Medium |
| **Production-ready** (full abstraction, tests, docs) | 6-8 weeks | Medium |
| **Multi-implementation** (LDK + CLN adapters) | 10-12 weeks | Higher |
