use bitcoin::secp256k1::PublicKey;

// ============================================================================
// Handler Result Types
// ============================================================================

/// Result of handling a message
#[derive(Debug)]
pub enum HandlerResult {
    /// Message processed successfully, no further action
    Ok,
    /// Message processed, response should be sent
    /// The caller (LDK layer) should construct and send the appropriate response
    Response(ResponseData),
    /// Message rejected (but not an error)
    Rejected(String),
}

/// Data for constructing a response message
#[derive(Debug, Clone)]
pub enum ResponseData {
    /// Collateral consent response
    CollateralConsent {
        operator_id: PublicKey,
        reserves_id: String,
        consent_granted: bool,
        // Signature is populated by the LDK layer which has access to keys
    },
    /// Quorum join response (simple)
    QuorumJoin {
        accepted: bool,
        rejection_reason: Option<String>,
    },
    /// Quorum join response (full)
    QuorumJoinResponse {
        accepted: bool,
        members: Vec<PublicKey>,
        threshold: u16,
        rejection_reason: Option<String>,
    },
    /// Quorum member added - response with signature data for ACK
    QuorumMemberAdded {
        operator_id: PublicKey,
        reserves_id: String,
        quorum_member: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Quorum member removed - response with signature data for ACK
    QuorumMemberRemoved {
        reserves_id: String,
        quorum_member: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Uncredited payment accusation - emit event for node layer
    UncreditedPaymentAccusation {
        operator: PublicKey,
        reserves_id: String,
        payment_hash: [u8; 32],
        deposit_pubkey: PublicKey,
        amount_msat: u64,
        settlement_sequence: u64,
    },
    /// Credit payment validated - partner should sign and ACK
    CreditPaymentValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_hash: [u8; 32],
        invoice_id: String,
        sequence_number: u64,
    },
    /// Lock payment validated - partner should sign and ACK
    LockPaymentValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
    },
    /// Fulfill payment validated - partner should sign and ACK
    FulfillPaymentValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        preimage: [u8; 32],
        sequence_number: u64,
    },
    /// Fail payment validated - partner should sign and ACK
    FailPaymentValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
    },
    /// Deposit open validated - partner should sign and ACK
    DepositOpenValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Deposit close validated - partner should sign and ACK
    DepositCloseValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Fee change validated - partner should sign and ACK
    FeeChangeValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Reserves add output validated - partner should sign and ACK
    ReservesAddOutputValidated {
        operator: PublicKey,
        reserves_id: String,
        initial_amount: u64,
        spend_to: PublicKey,
        quorum_members: Vec<PublicKey>,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Reserves remove output validated - partner should sign and ACK
    ReservesRemoveOutputValidated {
        operator: PublicKey,
        reserves_id: String,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Fee collection validated - partner should sign and ACK
    FeeCollectValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        block_height: u32,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Ledger close validated - partner should sign and ACK
    LedgerCloseValidated {
        operator: PublicKey,
        reserves_id: String,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Invoice cosign validated - partner should sign the invoice
    CosignInvoiceValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_hash: [u8; 32],
        invoice_id: String,
        bolt11: String,
    },
    /// Quorum state sync processed
    QuorumStateSyncProcessed {
        applied: u32,
        errors: u32,
        total: u32,
    },
    /// Ledger export response - contains the full export for validation
    LedgerExportResponse {
        operator_id: PublicKey,
        reserves_id: String,
        version: u32,
        exported_at: u64,
        block_height: u32,
        update_count: u32,
        updates_data: Vec<u8>,
        success: bool,
        error_message: Option<String>,
    },
}
