use super::*;

// ============================================================================
// Protocol Version
// ============================================================================

/// Current protocol version (v2 = consolidated messages)
pub const PROTOCOL_VERSION: u16 = 2;

/// Minimum supported protocol version
pub const MIN_PROTOCOL_VERSION: u16 = 1;

// ============================================================================
// Message Type Constants (all odd for safe ignorability per BOLT 1)
// ============================================================================

pub mod consts {
    // Envelope Message Types (used for wire transmission)
    pub const LEDGER_UPDATE: u16 = 0x8001;
    pub const LEDGER_UPDATE_RESPONSE: u16 = 0x8003;
    pub const HANDSHAKE: u16 = 0x8005;
    pub const HANDSHAKE_RESPONSE: u16 = 0x8007;
    pub const SYNC: u16 = 0x8009;
    pub const SYNC_RESPONSE: u16 = 0x800B;
    // Note: 0x800D and 0x800F are reserved (formerly RECOVERY/RECOVERY_RESPONSE
    // for the Lightning-channel-era recovery flow, removed when the protocol
    // moved to collateral-in-UTXO with a tapscript-spending dispute path).
    pub const COORDINATION: u16 = 0x8011;
    pub const COORDINATION_RESPONSE: u16 = 0x8013;

    // Operation Message Types (used in SignedLedgerUpdate.message_type)
    // Reserves operations
    pub const RESERVES_ADD_OUTPUT: u16 = 0x80C1;
    pub const RESERVES_REMOVE_OUTPUT: u16 = 0x80C3;
    pub const QUORUM_BEGIN: u16 = 0x80B5;
    pub const RESERVES_UPDATE_OUTPUT: u16 = 0x80C9;

    // Reserves commitment protocol
    pub const UPDATE_RESERVES: u16 = 0x80E1;
    pub const ACCEPT_RESERVES: u16 = 0x80E3;

    // Collateral operations
    pub const COLLATERAL_INCREASE: u16 = 0x80CB;
    pub const COLLATERAL_DECREASE: u16 = 0x80CD;
    pub const COLLATERAL_STATUS: u16 = 0x80CF;
    // 0x808D was COLLATERAL_ATTESTATION (removed with collateral-in-UTXO migration)
    pub const QUORUM_ADD_MEMBER: u16 = 0x8097;
    pub const QUORUM_REMOVE_MEMBER: u16 = 0x8099;
    pub const COLLATERAL_CONSENT_REQUEST: u16 = 0x809B;
    pub const COLLATERAL_CONSENT_RESPONSE: u16 = 0x809D;
    // 0x809F was COLLATERAL_LOCK (removed with collateral-in-UTXO migration)
    pub const QUORUM_JOIN: u16 = 0x80AB;

    // Deposit operations
    pub const DEPOSIT_OPEN: u16 = 0x80D1;
    pub const DEPOSIT_CLOSE: u16 = 0x80D3;
    pub const FEE_CHANGE: u16 = 0x80D5;
    pub const DEPOSIT_KEY_ROTATE: u16 = 0x80D7;

    // Onchain operations (Bitcoin layer credits/withdrawals)
    pub const ONCHAIN_CREDIT: u16 = 0x80E1;
    pub const ONCHAIN_LOCK: u16 = 0x80E3;
    pub const ONCHAIN_FAIL: u16 = 0x80E5;
    pub const ONCHAIN_FULFILL: u16 = 0x80E7;

    // Transfer operations (conditional transfers between deposits)
    pub const TRANSFER_LOCK: u16 = 0x80F1;
    pub const TRANSFER_COMPLETE: u16 = 0x80F3;
    pub const TRANSFER_FAIL: u16 = 0x80F5;

    // Ledger lifecycle
    pub const LEDGER_CLOSE: u16 = 0x801D;

    // Maintenance
    pub const MAINTENANCE_FEE_COLLECT: u16 = 0x8021;

    // Receiving (incoming payments)
    pub const RECEIVING_COSIGN_INVOICE: u16 = 0x8031;
    pub const RECEIVING_CREDIT_PAYMENT: u16 = 0x8033;
    pub const UNCREDITED_PAYMENT: u16 = 0x8035;

    // Sending (outgoing payments)
    pub const SENDING_LOCK_PAYMENT: u16 = 0x8041;
    pub const SENDING_FAIL_PAYMENT: u16 = 0x8043;
    pub const SENDING_FULFILL_PAYMENT: u16 = 0x8045;

    // Signed updates and sync
    pub const SIGNED_UPDATE: u16 = 0x8057;
    pub const SYNC_REQUEST: u16 = 0x8059;

    // Ledger export and validation
    pub const LEDGER_EXPORT_REQUEST: u16 = 0x805B;
    pub const LEDGER_EXPORT_RESPONSE: u16 = 0x805D;

    // Ledger establishment (aliases for Handshake)
    pub const LEDGER_OPEN_REQUEST: u16 = 0x8061;
    pub const LEDGER_OPEN_RESPONSE: u16 = 0x8063;

    // Acknowledgment
    pub const ACK: u16 = 0x8071;

    // Quorum operations
    pub const QUORUM_JOIN_REQUEST: u16 = 0x8081;
    pub const QUORUM_JOIN_RESPONSE: u16 = 0x8083;
    pub const QUORUM_STATE_SYNC: u16 = 0x8085;
    pub const QUORUM_VOTE_REQUEST: u16 = 0x8087;
    pub const QUORUM_VOTE: u16 = 0x8089;
    pub const QUORUM_MEMBERSHIP_CHANGE: u16 = 0x808B;

    // Recovery operations
    pub const RECOVERY_VOTE: u16 = 0x808F;
    pub const RECOVERY_CLAIM_REQUEST: u16 = 0x8091;
    pub const RECOVERY_CLAIM_SIGNATURE: u16 = 0x8093;
    pub const RECOVERY_CLAIM_COMPLETE: u16 = 0x8095;
}

pub use consts::*;

// ============================================================================
// Message Type Collections
// ============================================================================

/// Envelope message types - the outer wire message types
pub const ALL_ENVELOPE_MESSAGE_TYPES: &[u16] = &[
    LEDGER_UPDATE,
    LEDGER_UPDATE_RESPONSE,
    HANDSHAKE,
    HANDSHAKE_RESPONSE,
    SYNC,
    SYNC_RESPONSE,
    COORDINATION,
    COORDINATION_RESPONSE,
];

/// Operation message types - stored in SignedLedgerUpdate.message_type field
pub const ALL_OPERATION_MESSAGE_TYPES: &[u16] = &[
    RESERVES_ADD_OUTPUT,
    RESERVES_REMOVE_OUTPUT,
    RESERVES_UPDATE_OUTPUT,
    UPDATE_RESERVES,
    ACCEPT_RESERVES,
    COLLATERAL_INCREASE,
    COLLATERAL_DECREASE,
    COLLATERAL_STATUS,
    QUORUM_ADD_MEMBER,
    QUORUM_REMOVE_MEMBER,
    COLLATERAL_CONSENT_REQUEST,
    COLLATERAL_CONSENT_RESPONSE,
    DEPOSIT_OPEN,
    DEPOSIT_CLOSE,
    FEE_CHANGE,
    ONCHAIN_CREDIT,
    ONCHAIN_LOCK,
    ONCHAIN_FAIL,
    ONCHAIN_FULFILL,
    LEDGER_CLOSE,
    MAINTENANCE_FEE_COLLECT,
    RECEIVING_COSIGN_INVOICE,
    RECEIVING_CREDIT_PAYMENT,
    UNCREDITED_PAYMENT,
    SENDING_LOCK_PAYMENT,
    SENDING_FAIL_PAYMENT,
    SENDING_FULFILL_PAYMENT,
    SIGNED_UPDATE,
    SYNC_REQUEST,
    LEDGER_EXPORT_REQUEST,
    LEDGER_EXPORT_RESPONSE,
    LEDGER_OPEN_REQUEST,
    LEDGER_OPEN_RESPONSE,
    ACK,
    QUORUM_JOIN_REQUEST,
    QUORUM_JOIN_RESPONSE,
    QUORUM_STATE_SYNC,
    QUORUM_VOTE_REQUEST,
    QUORUM_VOTE,
    QUORUM_MEMBERSHIP_CHANGE,
    RECOVERY_VOTE,
    RECOVERY_CLAIM_REQUEST,
    RECOVERY_CLAIM_SIGNATURE,
    RECOVERY_CLAIM_COMPLETE,
];

/// Messages that require acknowledgment
pub const MESSAGES_REQUIRING_ACK: &[u16] = &[
    RESERVES_ADD_OUTPUT,
    RESERVES_REMOVE_OUTPUT,
    RESERVES_UPDATE_OUTPUT,
    DEPOSIT_OPEN,
    DEPOSIT_CLOSE,
    FEE_CHANGE,
    ONCHAIN_CREDIT,
    ONCHAIN_LOCK,
    ONCHAIN_FAIL,
    ONCHAIN_FULFILL,
    RECEIVING_CREDIT_PAYMENT,
    RECEIVING_COSIGN_INVOICE,
    SENDING_LOCK_PAYMENT,
    SENDING_FAIL_PAYMENT,
    SENDING_FULFILL_PAYMENT,
    COLLATERAL_INCREASE,
    COLLATERAL_DECREASE,
    QUORUM_ADD_MEMBER,
    QUORUM_REMOVE_MEMBER,
    COLLATERAL_CONSENT_REQUEST,
    COLLATERAL_CONSENT_RESPONSE,
    MAINTENANCE_FEE_COLLECT,
    LEDGER_CLOSE,
    LEDGER_OPEN_REQUEST,
    LEDGER_UPDATE,
    HANDSHAKE,
];

// ============================================================================
// Message Type Utilities
// ============================================================================

/// Check if a message type is a Bitcoin Deposits protocol message
pub fn is_deposits_message_type(message_type: u16) -> bool {
    ALL_ENVELOPE_MESSAGE_TYPES.contains(&message_type)
        || ALL_OPERATION_MESSAGE_TYPES.contains(&message_type)
}

/// Check if a message type requires acknowledgment
pub fn requires_acknowledgment(message_type: u16) -> bool {
    MESSAGES_REQUIRING_ACK.contains(&message_type)
}

/// Get the message category for a message type
pub fn get_message_category(message_type: u16) -> Option<&'static str> {
    match message_type {
        RESERVES_ADD_OUTPUT | RESERVES_REMOVE_OUTPUT | RESERVES_UPDATE_OUTPUT => Some("reserves"),

        COLLATERAL_INCREASE
        | COLLATERAL_DECREASE
        | COLLATERAL_STATUS
        | QUORUM_ADD_MEMBER
        | QUORUM_REMOVE_MEMBER
        | COLLATERAL_CONSENT_REQUEST
        | COLLATERAL_CONSENT_RESPONSE => Some("collateral"),

        DEPOSIT_OPEN | DEPOSIT_CLOSE | FEE_CHANGE => Some("deposit"),

        ONCHAIN_CREDIT | ONCHAIN_LOCK | ONCHAIN_FAIL | ONCHAIN_FULFILL => Some("onchain"),

        LEDGER_CLOSE => Some("lifecycle"),

        MAINTENANCE_FEE_COLLECT => Some("maintenance"),

        RECEIVING_COSIGN_INVOICE | RECEIVING_CREDIT_PAYMENT | UNCREDITED_PAYMENT => {
            Some("receiving")
        }

        SENDING_LOCK_PAYMENT | SENDING_FAIL_PAYMENT | SENDING_FULFILL_PAYMENT => Some("sending"),

        SIGNED_UPDATE
        | SYNC_REQUEST
        | LEDGER_OPEN_REQUEST
        | LEDGER_OPEN_RESPONSE
        | ACK
        | LEDGER_EXPORT_REQUEST
        | LEDGER_EXPORT_RESPONSE => Some("control"),

        QUORUM_JOIN_REQUEST
        | QUORUM_JOIN_RESPONSE
        | QUORUM_STATE_SYNC
        | QUORUM_VOTE_REQUEST
        | QUORUM_VOTE
        | QUORUM_MEMBERSHIP_CHANGE => Some("quorum"),

        RECOVERY_VOTE
        | RECOVERY_CLAIM_REQUEST
        | RECOVERY_CLAIM_SIGNATURE
        | RECOVERY_CLAIM_COMPLETE => Some("recovery"),

        // V2 types
        LEDGER_UPDATE | LEDGER_UPDATE_RESPONSE => Some("ledger"),
        HANDSHAKE | HANDSHAKE_RESPONSE => Some("handshake"),
        SYNC | SYNC_RESPONSE => Some("sync"),
        COORDINATION | COORDINATION_RESPONSE => Some("coordination"),

        _ => None,
    }
}

/// Convert a message type ID to its constant name (V2 messages only)
pub fn type_id_to_const_name(type_id: u16) -> &'static str {
    match type_id {
        LEDGER_UPDATE => "LEDGER_UPDATE",
        LEDGER_UPDATE_RESPONSE => "LEDGER_UPDATE_RESPONSE",
        HANDSHAKE => "HANDSHAKE",
        HANDSHAKE_RESPONSE => "HANDSHAKE_RESPONSE",
        SYNC => "SYNC",
        SYNC_RESPONSE => "SYNC_RESPONSE",
        COORDINATION => "COORDINATION",
        COORDINATION_RESPONSE => "COORDINATION_RESPONSE",
        _ => "UNKNOWN",
    }
}

/// Convert a message type ID to its variant name (V2 messages only)
pub fn type_id_to_variant_name(type_id: u16) -> Option<&'static str> {
    match type_id {
        LEDGER_UPDATE => Some("LedgerUpdate"),
        LEDGER_UPDATE_RESPONSE => Some("LedgerUpdateResponse"),
        HANDSHAKE => Some("Handshake"),
        HANDSHAKE_RESPONSE => Some("HandshakeResponse"),
        SYNC => Some("Sync"),
        SYNC_RESPONSE => Some("SyncResponse"),
        COORDINATION => Some("Coordination"),
        COORDINATION_RESPONSE => Some("CoordinationResponse"),
        _ => None,
    }
}

// ============================================================================
// Hash Strategy
// ============================================================================

/// HashStrategy determines how to calculate the expected consensus hash
/// for message types that require commitment transaction synchronization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashStrategy {
    /// Use the current committed hash (after the operation is applied).
    /// Used for amount-changing operations (ReservesAdd, ReservesToReserves, etc.)
    /// where the reserves amount in the commitment must match ledger state.
    CurrentCommitted,

    /// Predict the hash that will result from the operation being applied.
    /// Used for operations where the commitment must contain the post-op state.
    /// Example: ReceivingCreditPayment - commit predicted hash, then apply credit.
    PredictedAfterOp,

    /// No synchronization needed. The hash will catch up on next sync operation.
    /// Used for operations that don't immediately affect reserves (e.g., LedgerAddDeposit).
    None,
}

impl HashStrategy {
    /// Determine the hash strategy for a given message type.
    /// Returns (needs_reserves_update, strategy)
    pub fn for_message_type(msg_type: u16) -> (bool, HashStrategy) {
        match msg_type {
            // Amount-changing operations - sync after applying
            RESERVES_ADD_OUTPUT | COLLATERAL_INCREASE => (true, HashStrategy::CurrentCommitted),
            // Credit must be in committed hash - predict before applying
            RECEIVING_CREDIT_PAYMENT => (true, HashStrategy::PredictedAfterOp),
            // Everything else - no sync needed (catches up lazily)
            _ => (false, HashStrategy::None),
        }
    }

    /// Check if this strategy requires synchronization
    pub fn requires_sync(&self) -> bool {
        !matches!(self, HashStrategy::None)
    }
}
