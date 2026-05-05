use super::*;

// ============================================================================
// Main Message Enum
// ============================================================================

/// V2 Protocol Messages - 14 types total
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepositsMessage {
    LedgerUpdate(LedgerUpdateMsg),
    LedgerUpdateResponse(LedgerUpdateResponseMsg),
    Handshake(HandshakeMsg),
    HandshakeResponse(HandshakeResponseMsg),
    Sync(SyncMsg),
    SyncResponse(SyncResponseMsg),
    Coordination(CoordinationMsg),
    CoordinationResponse(CoordinationResponseMsg),
    /// Reserves add output - peer message to add reserves to commitment (not a ledger operation)
    ReservesAddOutput(crate::wire_messages::ReservesAddOutputMsg),
    /// Reserves remove output - peer message to remove reserves from commitment (not a ledger operation)
    ReservesRemoveOutput(crate::wire_messages::ReservesRemoveOutputMsg),
}

impl DepositsMessage {
    pub fn message_type(&self) -> u16 {
        match self {
            Self::LedgerUpdate(_) => LEDGER_UPDATE,
            Self::LedgerUpdateResponse(_) => LEDGER_UPDATE_RESPONSE,
            Self::Handshake(_) => HANDSHAKE,
            Self::HandshakeResponse(_) => HANDSHAKE_RESPONSE,
            Self::Sync(_) => SYNC,
            Self::SyncResponse(_) => SYNC_RESPONSE,
            Self::Coordination(_) => COORDINATION,
            Self::CoordinationResponse(_) => COORDINATION_RESPONSE,
            Self::ReservesAddOutput(_) => RESERVES_ADD_OUTPUT,
            Self::ReservesRemoveOutput(_) => RESERVES_REMOVE_OUTPUT,
        }
    }

    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::LedgerUpdate(_) => "LedgerUpdate",
            Self::LedgerUpdateResponse(_) => "LedgerUpdateResponse",
            Self::Handshake(_) => "Handshake",
            Self::HandshakeResponse(_) => "HandshakeResponse",
            Self::Sync(_) => "Sync",
            Self::SyncResponse(_) => "SyncResponse",
            Self::Coordination(_) => "Coordination",
            Self::CoordinationResponse(_) => "CoordinationResponse",
            Self::ReservesAddOutput(_) => "ReservesAddOutput",
            Self::ReservesRemoveOutput(_) => "ReservesRemoveOutput",
        }
    }

    /// Get the reserves_id if present in the message
    pub fn reserves_id(&self) -> Option<String> {
        match self {
            Self::LedgerUpdate(m) => Some(m.reserves_id.clone()),
            Self::LedgerUpdateResponse(m) => Some(m.reserves_id.clone()),
            Self::Handshake(m) => Some(m.reserves_id.clone()),
            Self::HandshakeResponse(m) => Some(m.reserves_id.clone()),
            Self::Sync(_) => None,         // Uses ledger_id now
            Self::SyncResponse(_) => None, // Uses ledger_id now
            Self::Coordination(m) => m.reserves_id(),
            Self::CoordinationResponse(m) => m.reserves_id(),
            Self::ReservesAddOutput(m) => Some(m.reserves_id.clone()),
            Self::ReservesRemoveOutput(m) => Some(m.reserves_id.clone()),
        }
    }

    /// Extract the LedgerOperation from this message, if it contains one.
    /// Returns Some(operation) for LedgerUpdate messages, None otherwise.
    pub fn to_operation(&self) -> Option<LedgerOperation> {
        match self {
            Self::LedgerUpdate(m) => Some(m.operation.clone()),
            _ => None,
        }
    }

    /// Encode message to bytes (type prefix + payload)
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.message_type().to_be_bytes());
        self.write_payload(&mut bytes)
            .expect("encoding to vec should not fail");
        bytes
    }

    /// Decode message from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < 2 {
            return Err(CodecError::TooShort);
        }
        let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let mut reader = &bytes[2..];
        Self::read_payload(message_type, &mut reader)
    }
}

// ============================================================================
// Ledger Update Messages (0x8001 / 0x8003)
// ============================================================================

/// All ledger-modifying operations in a single message type
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerUpdateMsg {
    /// Operator's public key
    pub operator_id: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK)
    pub reserves_id: String,
    /// The operation to perform
    pub operation: LedgerOperation,
    /// Sequence number in the ledger chain
    pub sequence_number: u64,
    /// Hash of the previous ledger state
    pub previous_hash: [u8; 32],
    /// Hash after applying this operation
    pub content_hash: [u8; 32],
    /// Operator's signature over the update
    pub operator_signature: [u8; 64],
}

/// Response to a ledger update (replaces ACK + porcupine dance)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerUpdateResponseMsg {
    /// Operator's public key
    pub operator_id: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK)
    pub reserves_id: String,
    /// Hash of the request being responded to
    pub request_hash: [u8; 32],
    /// Whether the update was accepted
    pub accepted: bool,
    /// Error message if rejected
    pub error: Option<String>,
    /// Co-signer's signature if accepted
    pub cosign_signature: Option<[u8; 64]>,
    /// Confirmed sequence number
    pub confirmed_sequence: u64,
    /// Confirmed ledger hash
    pub confirmed_hash: [u8; 32],
}

/// A single quorum member's identity at the moment of `QuorumBegin`.
///
/// Records both the member's signing pubkey (which appears in
/// `cosignatures` when this member co-signs an update) and the
/// member's own ledger ID — the ledger that holds their collateral
/// and whose tip hash they commit in `member_ledger_hash` when
/// cosigning. Without the ledger_id pairing, fraud-proof verifiers
/// (and the explorer) had to derive it from prior `QuorumAddMember`
/// operations on the operator's history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumMemberRef {
    pub pubkey: PublicKey,
    /// 64-char hex ledger_id of the member's own ledger. Empty when
    /// constructed from older callers that didn't have it on hand —
    /// new construction sites should populate it from the matching
    /// `QuorumAddMember.member_ledger_id`.
    pub member_ledger_id: String,
}

/// A disputant's pledged replacement collateral, declared in `DisputeArmed`.
///
/// At confiscation cosign time, every cosigner verifies the declared UTXO
/// exists and is unspent at their tip, holds at least `amount` sats, and
/// satisfies `amount ≥ obligations × collateral_ratio + claim_fee_estimate`.
/// If the disputant wins the lottery, their claim TX MUST consume this UTXO
/// as Input 1 and route at least `amount` to the new vault output —
/// deviation is a `WinnerCollateralDeviation` fraud proof. See
/// DEP-03 §"Replacement collateral declaration".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplacementCollateral {
    /// Outpoint txid (Bitcoin-internal byte order — same convention as
    /// `QuorumBegin.new_outpoint_txid`).
    pub txid: [u8; 32],
    /// Outpoint vout.
    pub vout: u32,
    /// Sats pledged from this UTXO toward the new reserves vault.
    /// MUST be ≤ the on-chain UTXO value.
    pub amount: u64,
}

impl QuorumMemberRef {
    /// Wrap a pubkey when the caller doesn't have a ledger_id at hand
    /// (recovery flows, tests, etc.). The on-wire encoding still
    /// emits an entry; consumers that depend on the ledger_id should
    /// fall back to QuorumAddMember-history derivation when this is
    /// the empty string.
    pub fn pubkey_only(pubkey: PublicKey) -> Self {
        Self { pubkey, member_ledger_id: String::new() }
    }

    pub fn new(pubkey: PublicKey, member_ledger_id: impl Into<String>) -> Self {
        Self { pubkey, member_ledger_id: member_ledger_id.into() }
    }
}

/// All possible ledger operations (29 variants)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerOperation {
    // ========== Ledger Establishment (1) ==========
    /// Open/establish a new ledger (first operation, sequence 0)
    LedgerOpen {
        /// Operator's node ID
        operator_id: PublicKey,
        /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK)
        reserves_id: String,
        /// Block height when this ledger was opened (used in ledger_id computation)
        genesis_block: u32,
        /// Initial reserves amount in millisatoshis (from on-chain UTXO balance)
        reserves_amount: u64,
        /// Collateral amount in millisatoshis (security bond portion of UTXO)
        collateral_amount: u64,
    },

    // ========== Reserves Operations (1) ==========
    // Note: ReservesAdd/Remove/UpdateSpendTo are peer messages, not ledger operations.
    // The initial reserves state is set via LedgerOpen.
    // Reserves amount is updated at QuorumBegin (formerly ReservesRotate).
    /// Establish/refresh the quorum and rotate reserves UTXO into a new multisig
    ///
    /// Records the rotation of reserves from P2WSH to P2TR with tiered spending:
    /// - Immediate: quorum_threshold-of-quorum_size multisig
    /// - After quorum_expiry: operator can spend alone
    ///
    /// The quorum member pubkeys are derived from QuorumAddMember operations on this ledger.
    QuorumBegin {
        /// New reserves identifier (the new Taproot address)
        reserves_id: String,
        /// Transaction that spent the old reserves UTXO
        spending_txid: [u8; 32],
        /// New reserves UTXO txid
        new_outpoint_txid: [u8; 32],
        /// New reserves UTXO vout
        new_outpoint_vout: u32,
        /// Amount in millisatoshis (should match previous reserves)
        amount: u64,
        /// Block height when the quorum expires (shortest member's membership_until).
        /// A new QuorumBegin MUST be appended before this block (see DEP-11).
        /// The reserves tapscript uses this for tiered spending:
        ///   - Full quorum (k-of-n): no timelock
        ///   - Degraded quorum (k-1 of n): available before quorum_expiry (rotation window)
        ///   - Operator solo: available well after quorum_expiry (last resort)
        quorum_expiry: u32,
        /// Ledger hash committed in the Taproot script
        ledger_hash: [u8; 32],
        /// Quorum members frozen at this rotation. Each entry pairs the
        /// member's signing pubkey with the ledger_id of the member's own
        /// ledger (where their collateral lives). The pubkey is what shows
        /// up in `cosignatures.cosigner_pubkey`; the ledger_id lets
        /// verifiers / explorer pull the ledger that backs the member
        /// without re-deriving from prior `QuorumAddMember` history.
        quorum_members: Vec<QuorumMemberRef>,
        /// Collateral amount in millisatoshis (security bond portion of UTXO).
        collateral_amount: u64,
    },

    // ========== Deposit Operations (6) ==========
    /// Open a new deposit
    DepositOpen {
        /// Unique identifier (hash of descriptor)
        deposit_id: DepositId,
        /// Miniscript descriptor controlling this deposit
        descriptor: String,
        fees: Option<FeeStructure>,
        /// Per-transfer fee schedule (fixed + proportional)
        transfer_fees: Option<TransferFeeSchedule>,
        payment_hash: Option<[u8; 32]>,
        invoice: Option<String>,
        cosigner_guarantee_signature: Option<[u8; 64]>,
        /// If true, incoming funds (transfers, offers, invoices) require a
        /// signature from the deposit key. Prevents unsolicited crediting.
        receive_requires_sig: bool,
        /// Blocks after deposit open before fees can be changed (relative).
        fee_change_after_blocks: Option<u32>,
        /// Blocks of notice required before a fee change takes effect.
        fee_change_notice_blocks: Option<u32>,
        /// Maximum fee change per adjustment in basis points of current fee (default 1000 = 10%).
        fee_change_limit_bps: Option<u16>,
    },
    /// Close a deposit
    DepositClose { deposit_id: DepositId },
    /// Announce a fee change. Takes effect after the notice period.
    /// The new fees must be within fee_change_limit_bps of the current fees.
    FeeChange {
        deposit_id: DepositId,
        new_fees: FeeStructure,
        /// Block height at which this change takes effect.
        /// Must be >= current_block + fee_change_notice_blocks.
        effective_block: u32,
    },
    /// Rotate the deposit's spending key/descriptor
    /// The deposit_id stays the same (derived from original descriptor)
    /// but the current descriptor changes to new_descriptor.
    /// Requires witness proving authorization from the current descriptor.
    DepositKeyRotate {
        deposit_id: DepositId,
        new_descriptor: String,
        /// Witness satisfying the CURRENT descriptor (proves ownership)
        witness: DescriptorWitness,
    },
    // ========== Invoice Operations (4) ==========
    /// Credit a received invoice payment to a deposit
    InvoiceCredit {
        payment_hash: [u8; 32],
        deposit_id: DepositId,
        amount: u64,
        invoice_id: String,
        sequence_number: u64,
    },
    /// Lock funds for an outgoing invoice payment
    InvoiceLock {
        deposit_id: DepositId,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
        /// Witness satisfying the deposit descriptor
        witness: DescriptorWitness,
    },
    /// Fail a pending invoice payment
    InvoiceFail {
        deposit_id: DepositId,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
    },
    /// Fulfill a pending invoice payment
    InvoiceFulfill {
        deposit_id: DepositId,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
        /// Witness satisfying the deposit descriptor
        witness: DescriptorWitness,
        preimage: [u8; 32],
    },

    // ========== Onchain Operations ==========
    /// Credit received on-chain funds to a deposit (incoming, fast)
    OnchainCredit {
        txid: [u8; 32],
        vout: u32,
        deposit_id: DepositId,
        amount: u64,
        funding_address: String,
    },
    /// Lock funds for an on-chain withdrawal (outgoing, debits balance)
    OnchainLock {
        deposit_id: DepositId,
        amount: u64,
        fee_sats: u64,
        destination_address: String,
        withdrawal_id: [u8; 32],
        witness: DescriptorWitness,
    },
    /// Fail a pending on-chain withdrawal (returns funds to deposit)
    OnchainFail {
        deposit_id: DepositId,
        withdrawal_id: [u8; 32],
    },
    /// Fulfill an on-chain withdrawal (confirmed on-chain)
    OnchainFulfill {
        deposit_id: DepositId,
        withdrawal_id: [u8; 32],
        amount: u64,
        txid: [u8; 32],
        destination_address: String,
    },

    // ========== Transfer Operations (3) ==========
    /// Lock funds for a conditional transfer between deposits
    /// The transfer completes if completion_script is satisfied, or times out after timeout_height
    TransferLock {
        nonce: [u8; 32],
        source_deposit_id: DepositId,
        destination_deposit_id: DepositId,
        amount: u64,
        fee: u64,
        completion_script: String,
        timeout_height: u32,
        transfer_id: [u8; 32],
        witness: DescriptorWitness,
    },
    /// Complete a transfer by satisfying the completion_script
    TransferComplete {
        transfer_id: [u8; 32],
        script_witness: DescriptorWitness,
    },
    /// Fail a transfer and return funds to source.
    /// Reason 1 = timeout (deadline reached without completion).
    /// Reason 0 is reserved/invalid.
    TransferFail {
        transfer_id: [u8; 32],
        block_hash: [u8; 32],
        /// Failure reason: 1 = timeout. 0 is reserved.
        reason: u8,
    },

    // ========== Quorum Membership (2) ==========
    /// Add a quorum member to the VoterSet.
    /// Fee limits are the member's terms — minimum fees they require.
    /// DepositOpen fees must meet or exceed the strictest quorum member minimums.
    /// This protects members from inheriting low-fee obligations after custody transfer.
    QuorumAddMember {
        quorum_member: PublicKey,
        quorum_member_signature: [u8; 64],
        /// The ledger ID where this member will lock collateral
        member_ledger_id: String,
        /// Minimum annualized fee rate (basis points) the member requires
        min_fee_bps: Option<u16>,
        /// Minimum annualized fixed fee (msats/year) the member requires
        min_fee_fixed: Option<u64>,
        /// Maximum fee collection period (blocks) the member allows
        max_fee_period: Option<u32>,
        /// Block height until which this member commits to serving.
        membership_until: Option<u32>,
        /// Per-quorum timing: blocks before member must respond to fraud evidence
        dispute_response_blocks: Option<u32>,
        /// Per-quorum timing: blocks after DisputeEnter to arm for lottery
        dispute_arm_blocks: Option<u32>,
        /// Per-quorum timing: blocks before unprocessed request = censorship
        service_response_blocks: Option<u32>,
        /// Per-quorum timing: max timeout_height distance for TransferLock
        max_transfer_timeout_blocks: Option<u32>,
        /// Maximum descriptor size (bytes) member will accept on deposits
        max_descriptor_bytes: Option<u32>,
        /// Basis points of collected fees flowing to this member as
        /// co-signing compensation. `None` means the member waived
        /// compensation. See `DEFAULT_COMPENSATION_BPS` (300 = 3%).
        compensation_bps: Option<u16>,
        /// Deposit on the operator's ledger where compensation is paid.
        /// Must already exist when the operation is appended.
        compensation_deposit_id: Option<DepositId>,
        /// Payout cadence in blocks. See `DEFAULT_COMPENSATION_FREQUENCY_BLOCKS`.
        compensation_frequency_blocks: Option<u32>,
    },
    /// Remove a quorum member from the VoterSet
    QuorumRemoveMember {
        quorum_member: PublicKey,
        operator_signature: [u8; 64],
    },
    /// Record that we have joined another operator's quorum as a monitoring member.
    /// This is appended to the consenting party's own ledger when they grant consent.
    /// Creates a two-sided auditable trail alongside QuorumAddMember on the operator's ledger.
    /// Uses ratchet semantics: can only extend membership duration.
    QuorumJoin {
        /// The operator whose quorum we're joining
        operator_id: PublicKey,
        /// The ledger_id (64-char hex hash) of the ledger we're monitoring
        ledger_id: String,
        /// Block height when our membership commitment expires
        membership_expires: u32,
    },

    // ========== Maintenance (1) ==========
    /// Collect maintenance fees from a deposit
    FeeCollect {
        deposit_id: DepositId,
        amount: u64,
        block_height: u32,
    },

    // ========== Custody Dispute and Recovery (4) ==========
    /// Open a custody dispute. Can ONLY be signed by a quorum member (verified
    /// against the quorum at the fork point).
    ///
    /// Effects:
    /// - Disbands the quorum (all memberships voided)
    /// - Voids all collateral attestations
    /// - The signer becomes the "parent pubkey" for this branch
    /// - Transitions ledger to DISPUTED state
    ///
    /// Signature rule: This is the ONE EXCEPTION to the rule that updates must be
    /// signed by the same pubkey as the previous update. DisputeEnter can be
    /// signed by any pubkey that was a quorum member at the fork point.
    DisputeEnter {
        /// Sequence number of the last valid update before the dispute.
        last_valid_sequence: u64,
        /// Human-readable description of why the dispute was opened.
        reason: String,
    },

    /// Signal readiness for custody competition. This is a PRE-COMMITMENT that
    /// locks in the candidate for entropy-based selection.
    ///
    /// Effects:
    /// - Locks in the current quorum - no more changes allowed
    /// - Registers this candidate for entropy-based selection
    /// - Only candidates with DisputeArmed before the entropy block are eligible
    ///
    /// Validation:
    /// - Must be in DISPUTED state
    /// - Must have at least N quorum members added
    /// - Must have collateral attestations from quorum members
    DisputeArmed {
        /// Block height when this candidate is ready (used for eligibility cutoff).
        armed_block: u32,
        /// HASH160 of secret preimage (32 bytes) for lottery entropy.
        commitment_hash: [u8; 20],
        /// Bitcoin address where winner wants reserves sent.
        target_reserves: String,
        /// Replacement collateral the disputant pledges to commit to the new
        /// vault if they win. `None` on legacy events; new producers MUST
        /// populate it. See DEP-03 §"Replacement collateral declaration".
        replacement_collateral: Option<ReplacementCollateral>,
    },

    /// Acquire custody after winning the on-chain lottery.
    ///
    /// Effects:
    /// - Records the on-chain claim TX that proved control of the
    ///   lottery output
    /// - Transitions ledger back to NORMAL state
    /// - This candidate is now the operator
    ///
    /// Validation:
    /// - Must be in READY state
    /// - The lottery script on-chain enforces that only the
    ///   `(sum mod N)`-th candidate (per revealed preimages) can spend
    ///   the lottery output. The state machine trusts the Bitcoin
    ///   layer to enforce that selection and just records the
    ///   resulting `claim_txid`. A separate component with on-chain
    ///   access (regtest or wallet sync) is responsible for verifying
    ///   that `claim_txid` actually spends the expected lottery output.
    DisputeAcquire {
        /// The new custodian (the lottery winner's pubkey).
        new_custodian: PublicKey,
        /// Transaction ID of the on-chain claim TX. Witnessed-by spend
        /// of the Tapscript lottery leaf, proving the script's
        /// `(sum mod N)`-th-candidate selection.
        claim_txid: [u8; 32],
        /// New reserves address (where the lottery output's value now
        /// resides — the winner's `target_reserves` from `DisputeArmed`).
        new_reserves_address: String,
    },

    /// Yield custody claim after not being selected. Tombstones this branch.
    ///
    /// Effects:
    /// - Terminates this branch permanently
    /// - No further updates allowed on this branch
    ///
    /// Validation:
    /// - Must be in READY state
    /// - Must NOT be the entropy-selected winner
    ///
    /// Note: This is NOT "invalid" - it's simply a terminated branch.
    DisputeYield,

    // ========== Delivery (1) ==========
    /// Embed a wallet's request hash for certified delivery (see DEP-12).
    /// Appended by a quorum member to their own ledger when a wallet escalates
    /// an unprocessed request. Starts the service_response_blocks clock.
    DeliveryEmbed {
        /// SHA256 of the wallet's signed request payload
        request_hash: [u8; 32],
        /// Ledger ID where the request should be processed
        target_ledger_id: [u8; 32],
        /// Operator pubkey of the target ledger
        target_operator: PublicKey,
    },

    // ========== Lifecycle (1) ==========
    /// Close the ledger
    LedgerClose,
}

impl LedgerOperation {
    /// Return the 32-byte hash this operation embeds in its causally-
    /// significant fields, if any. Used by fraud-proof verification to
    /// confirm a `proof_hash` is bound into a specific update.
    ///
    /// Supported sources:
    /// - [`TransferLock::nonce`] — the canonical "wallet-controlled
    ///   embed" path; the wallet picks the nonce and the operator
    ///   cosigns it into the ledger.
    /// - [`DeliveryEmbed::request_hash`] — the operator records a
    ///   wallet's signed request payload by hash; same effect but a
    ///   first-class entanglement op (no transfer required).
    ///
    /// Other op types return `None` and cannot serve as embedding
    /// sources today.
    pub fn embedded_hash(&self) -> Option<&[u8; 32]> {
        match self {
            Self::TransferLock { nonce, .. } => Some(nonce),
            Self::DeliveryEmbed { request_hash, .. } => Some(request_hash),
            _ => None,
        }
    }

    /// Get the operation type as a discriminant byte
    pub fn discriminant(&self) -> u8 {
        match self {
            Self::LedgerOpen { .. } => 1, // First operation
            Self::QuorumBegin { .. } => 12,
            Self::DepositOpen { .. } => 20,
            Self::DepositClose { .. } => 21,
            Self::FeeChange { .. } => 22,
            Self::DepositKeyRotate { .. } => 23,
            Self::InvoiceCredit { .. } => 30,
            Self::InvoiceLock { .. } => 31,
            Self::InvoiceFail { .. } => 32,
            Self::InvoiceFulfill { .. } => 33,
            Self::OnchainCredit { .. } => 35,
            Self::OnchainLock { .. } => 36,
            Self::OnchainFail { .. } => 37,
            Self::OnchainFulfill { .. } => 38,
            Self::TransferLock { .. } => 70,
            Self::TransferComplete { .. } => 71,
            Self::TransferFail { .. } => 72,
            Self::QuorumAddMember { .. } => 43,
            Self::QuorumRemoveMember { .. } => 44,
            Self::QuorumJoin { .. } => 46,
            Self::FeeCollect { .. } => 50,
            // Custody dispute operations
            Self::DisputeEnter { .. } => 54, // Opens dispute, transitions to DISPUTED
            Self::DisputeAcquire { .. } => 55, // Winner acquires custody
            Self::DisputeYield => 56,        // Loser yields, branch tombstoned
            Self::DisputeArmed { .. } => 57, // Pre-commitment, transitions to READY
            Self::DeliveryEmbed { .. } => 80,
            Self::LedgerClose => 60,
        }
    }

    /// Get the wire message type constant for this operation.
    /// Derived from the discriminant — this is the canonical mapping.
    pub fn message_type(&self) -> u16 {
        match self {
            Self::LedgerOpen { .. } => consts::LEDGER_OPEN_REQUEST,
            Self::QuorumBegin { .. } => consts::QUORUM_BEGIN,
            Self::DepositOpen { .. } => consts::DEPOSIT_OPEN,
            Self::DepositClose { .. } => consts::DEPOSIT_CLOSE,
            Self::FeeChange { .. } => consts::FEE_CHANGE,
            Self::DepositKeyRotate { .. } => consts::DEPOSIT_KEY_ROTATE,
            Self::InvoiceCredit { .. } => consts::RECEIVING_CREDIT_PAYMENT,
            Self::InvoiceLock { .. } => consts::SENDING_LOCK_PAYMENT,
            Self::InvoiceFail { .. } => consts::SENDING_FAIL_PAYMENT,
            Self::InvoiceFulfill { .. } => consts::SENDING_FULFILL_PAYMENT,
            Self::OnchainCredit { .. } => consts::ONCHAIN_CREDIT,
            Self::OnchainLock { .. } => consts::ONCHAIN_LOCK,
            Self::OnchainFail { .. } => consts::ONCHAIN_FAIL,
            Self::OnchainFulfill { .. } => consts::ONCHAIN_FULFILL,
            Self::TransferLock { .. } => consts::TRANSFER_LOCK,
            Self::TransferComplete { .. } => consts::TRANSFER_COMPLETE,
            Self::TransferFail { .. } => consts::TRANSFER_FAIL,
            Self::QuorumAddMember { .. } => consts::QUORUM_ADD_MEMBER,
            Self::QuorumRemoveMember { .. } => consts::QUORUM_REMOVE_MEMBER,
            Self::QuorumJoin { .. } => consts::QUORUM_JOIN,
            Self::FeeCollect { .. } => consts::MAINTENANCE_FEE_COLLECT,
            Self::DisputeEnter { .. } => consts::LEDGER_UPDATE,
            Self::DisputeAcquire { .. } => consts::LEDGER_UPDATE,
            Self::DisputeYield => consts::LEDGER_UPDATE,
            Self::DisputeArmed { .. } => consts::LEDGER_UPDATE,
            Self::DeliveryEmbed { .. } => consts::LEDGER_UPDATE,
            Self::LedgerClose => consts::LEDGER_CLOSE,
        }
    }

    /// Derive the message_type u16 from TLV-encoded message bytes
    /// by reading the discriminant from the first TLV field.
    pub fn message_type_from_bytes(message: &[u8]) -> u16 {
        // The discriminant is the first TLV field (tag=0).
        // TLV format: varint(tag) varint(len) bytes...
        // For tag=0: 0x00, then varint(1), then the u8 discriminant
        if message.len() >= 3 && message[0] == 0 && message[1] == 1 {
            Self::message_type_from_discriminant(message[2])
        } else {
            0
        }
    }

    /// Map a discriminant byte to the wire message type constant.
    pub fn message_type_from_discriminant(disc: u8) -> u16 {
        match disc {
            1 => consts::LEDGER_OPEN_REQUEST,
            12 => consts::QUORUM_BEGIN,
            20 => consts::DEPOSIT_OPEN,
            21 => consts::DEPOSIT_CLOSE,
            22 => consts::FEE_CHANGE,
            23 => consts::DEPOSIT_KEY_ROTATE,
            30 => consts::RECEIVING_CREDIT_PAYMENT,
            31 => consts::SENDING_LOCK_PAYMENT,
            32 => consts::SENDING_FAIL_PAYMENT,
            33 => consts::SENDING_FULFILL_PAYMENT,
            35 => consts::ONCHAIN_CREDIT,
            36 => consts::ONCHAIN_LOCK,
            37 => consts::ONCHAIN_FAIL,
            38 => consts::ONCHAIN_FULFILL,
            43 => consts::QUORUM_ADD_MEMBER,
            44 => consts::QUORUM_REMOVE_MEMBER,
            46 => consts::QUORUM_JOIN,
            50 => consts::MAINTENANCE_FEE_COLLECT,
            54 | 55 | 56 | 57 | 80 => consts::LEDGER_UPDATE,
            60 => consts::LEDGER_CLOSE,
            70 => consts::TRANSFER_LOCK,
            71 => consts::TRANSFER_COMPLETE,
            72 => consts::TRANSFER_FAIL,
            _ => 0,
        }
    }

    /// Return deposit IDs affected by this operation (for Nostr event tagging).
    pub fn affected_deposit_ids(&self) -> Vec<&crate::types::DepositId> {
        match self {
            Self::DepositOpen { deposit_id, .. }
            | Self::DepositClose { deposit_id }
            | Self::FeeChange { deposit_id, .. }
            | Self::DepositKeyRotate { deposit_id, .. }
            | Self::InvoiceCredit { deposit_id, .. }
            | Self::InvoiceLock { deposit_id, .. }
            | Self::InvoiceFail { deposit_id, .. }
            | Self::InvoiceFulfill { deposit_id, .. }
            | Self::OnchainCredit { deposit_id, .. }
            | Self::OnchainLock { deposit_id, .. }
            | Self::OnchainFail { deposit_id, .. }
            | Self::OnchainFulfill { deposit_id, .. }
            | Self::FeeCollect { deposit_id, .. } => vec![deposit_id],

            Self::TransferLock {
                source_deposit_id,
                destination_deposit_id,
                ..
            } => {
                vec![source_deposit_id, destination_deposit_id]
            }

            // These don't reference deposits
            _ => vec![],
        }
    }
}

// ============================================================================
// Binary Codec (no LDK dependencies)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    TooShort,
    InvalidMessageType(u16),
    InvalidDiscriminant(u8),
    InvalidData(String),
    Io(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer too short"),
            Self::InvalidMessageType(t) => write!(f, "invalid message type: 0x{:04X}", t),
            Self::InvalidDiscriminant(d) => write!(f, "invalid discriminant: {}", d),
            Self::InvalidData(s) => write!(f, "invalid data: {}", s),
            Self::Io(s) => write!(f, "IO error: {}", s),
        }
    }
}

impl std::error::Error for CodecError {}

impl From<io::Error> for CodecError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Binary codec trait for V2 messages
pub trait BinaryCodec: Sized {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), CodecError>;
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, CodecError>;
}

// Helper functions for binary encoding
pub(super) fn write_u8<W: Write>(w: &mut W, v: u8) -> Result<(), CodecError> {
    w.write_all(&[v])?;
    Ok(())
}

pub(super) fn write_u16<W: Write>(w: &mut W, v: u16) -> Result<(), CodecError> {
    w.write_all(&v.to_be_bytes())?;
    Ok(())
}

pub(super) fn write_u32<W: Write>(w: &mut W, v: u32) -> Result<(), CodecError> {
    w.write_all(&v.to_be_bytes())?;
    Ok(())
}

pub(super) fn write_u64<W: Write>(w: &mut W, v: u64) -> Result<(), CodecError> {
    w.write_all(&v.to_be_bytes())?;
    Ok(())
}

pub(super) fn write_bool<W: Write>(w: &mut W, v: bool) -> Result<(), CodecError> {
    write_u8(w, if v { 1 } else { 0 })
}

pub(super) fn write_bytes<W: Write>(w: &mut W, v: &[u8]) -> Result<(), CodecError> {
    write_u32(w, v.len() as u32)?;
    w.write_all(v)?;
    Ok(())
}

pub(super) fn write_string<W: Write>(w: &mut W, v: &str) -> Result<(), CodecError> {
    write_bytes(w, v.as_bytes())
}

pub(super) fn write_pubkey<W: Write>(w: &mut W, pk: &PublicKey) -> Result<(), CodecError> {
    w.write_all(&pk.serialize())?;
    Ok(())
}

pub(super) fn write_16<W: Write>(w: &mut W, v: &[u8; 16]) -> Result<(), CodecError> {
    w.write_all(v)?;
    Ok(())
}

pub(super) fn write_20<W: Write>(w: &mut W, v: &[u8; 20]) -> Result<(), CodecError> {
    w.write_all(v)?;
    Ok(())
}

pub(super) fn write_32<W: Write>(w: &mut W, v: &[u8; 32]) -> Result<(), CodecError> {
    w.write_all(v)?;
    Ok(())
}

pub(super) fn write_64<W: Write>(w: &mut W, v: &[u8; 64]) -> Result<(), CodecError> {
    w.write_all(v)?;
    Ok(())
}

pub(super) fn write_option<W: Write, T, F>(w: &mut W, v: &Option<T>, f: F) -> Result<(), CodecError>
where
    F: FnOnce(&mut W, &T) -> Result<(), CodecError>,
{
    match v {
        Some(val) => {
            write_bool(w, true)?;
            f(w, val)?;
        }
        None => write_bool(w, false)?,
    }
    Ok(())
}

pub(super) fn write_vec<W: Write, T, F>(w: &mut W, v: &[T], f: F) -> Result<(), CodecError>
where
    F: Fn(&mut W, &T) -> Result<(), CodecError>,
{
    write_u32(w, v.len() as u32)?;
    for item in v {
        f(w, item)?;
    }
    Ok(())
}

pub(super) fn read_u8<R: Read>(r: &mut R) -> Result<u8, CodecError> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

pub(super) fn read_u16<R: Read>(r: &mut R) -> Result<u16, CodecError> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

pub(super) fn read_u32<R: Read>(r: &mut R) -> Result<u32, CodecError> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

pub(super) fn read_u64<R: Read>(r: &mut R) -> Result<u64, CodecError> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

pub(super) fn read_bool<R: Read>(r: &mut R) -> Result<bool, CodecError> {
    Ok(read_u8(r)? != 0)
}

pub(super) fn read_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>, CodecError> {
    let len = read_u32(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub(super) fn read_string<R: Read>(r: &mut R) -> Result<String, CodecError> {
    let bytes = read_bytes(r)?;
    String::from_utf8(bytes).map_err(|e| CodecError::InvalidData(e.to_string()))
}

pub(super) fn read_pubkey<R: Read>(r: &mut R) -> Result<PublicKey, CodecError> {
    let mut buf = [0u8; 33];
    r.read_exact(&mut buf)?;
    PublicKey::from_slice(&buf).map_err(|e| CodecError::InvalidData(e.to_string()))
}

pub(super) fn read_16<R: Read>(r: &mut R) -> Result<[u8; 16], CodecError> {
    let mut buf = [0u8; 16];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub(super) fn read_20<R: Read>(r: &mut R) -> Result<[u8; 20], CodecError> {
    let mut buf = [0u8; 20];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub(super) fn read_32<R: Read>(r: &mut R) -> Result<[u8; 32], CodecError> {
    let mut buf = [0u8; 32];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub(super) fn read_33<R: Read>(r: &mut R) -> Result<[u8; 33], CodecError> {
    let mut buf = [0u8; 33];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub(super) fn read_64<R: Read>(r: &mut R) -> Result<[u8; 64], CodecError> {
    let mut buf = [0u8; 64];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub(super) fn read_option<R: Read, T, F>(r: &mut R, f: F) -> Result<Option<T>, CodecError>
where
    F: FnOnce(&mut R) -> Result<T, CodecError>,
{
    if read_bool(r)? {
        Ok(Some(f(r)?))
    } else {
        Ok(None)
    }
}

pub(super) fn read_vec<R: Read, T, F>(r: &mut R, f: F) -> Result<Vec<T>, CodecError>
where
    F: Fn(&mut R) -> Result<T, CodecError>,
{
    let len = read_u32(r)? as usize;
    let mut result = Vec::with_capacity(len);
    for _ in 0..len {
        result.push(f(r)?);
    }
    Ok(result)
}

// FeeStructure codec
impl BinaryCodec for FeeStructure {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        write_u64(w, self.annualized_msats)?;
        write_u16(w, self.annualized_bps)?;
        write_u32(w, self.frequency_blocks)?;
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            annualized_msats: read_u64(r)?,
            annualized_bps: read_u16(r)?,
            frequency_blocks: read_u32(r)?,
        })
    }
}

// LedgerOperation codec
impl BinaryCodec for LedgerOperation {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        write_u8(w, self.discriminant())?;
        match self {
            Self::LedgerOpen {
                operator_id,
                reserves_id,
                genesis_block,
                reserves_amount,
                collateral_amount,
            } => {
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_u32(w, *genesis_block)?;
                write_u32(w, 0)?; // reserved (was collateral_enforcement_block)
                write_u64(w, *reserves_amount)?;
                write_u64(w, *collateral_amount)?;
            }
            Self::QuorumBegin {
                reserves_id,
                spending_txid,
                new_outpoint_txid,
                new_outpoint_vout,
                amount,
                quorum_expiry,
                ledger_hash,
                quorum_members,
                collateral_amount,
            } => {
                write_string(w, reserves_id)?;
                write_32(w, spending_txid)?;
                write_32(w, new_outpoint_txid)?;
                write_u32(w, *new_outpoint_vout)?;
                write_u64(w, *amount)?;
                write_u8(w, quorum_members.len() as u8)?;
                write_u8(w, quorum_members.len() as u8)?;
                write_u32(w, *quorum_expiry)?;
                write_32(w, ledger_hash)?;
                write_u64(w, *collateral_amount)?;
                // Legacy BinaryEncode for QuorumBegin doesn't actually
                // emit member identities (it only writes the count
                // twice — historical bug). The TLV codec is the real
                // wire format; this branch is only used by old test
                // shims. The ledger_id pairing on each member rides
                // exclusively on the TLV side.
            }
            // Legacy encoding - deposit operations now use deposit_id/descriptor, but we encode
            // the deposit_id bytes as a placeholder for legacy compatibility
            Self::DepositOpen {
                deposit_id,
                fees,
                payment_hash,
                invoice,
                cosigner_guarantee_signature,
                ..
            } => {
                // Write deposit_id padded to 33 bytes (legacy pubkey size)
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02; // Valid compressed pubkey prefix
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_option(w, fees, |w, f| f.write_to(w))?;
                write_option(w, payment_hash, |w, h| write_32(w, h))?;
                write_option(w, invoice, |w, s| write_string(w, s))?;
                write_option(w, cosigner_guarantee_signature, |w, s| write_64(w, s))?;
            }
            Self::DepositClose { deposit_id } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
            }
            Self::FeeChange {
                deposit_id,
                new_fees,
                ..
            } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                new_fees.write_to(w)?;
            }
            Self::DepositKeyRotate {
                deposit_id,
                new_descriptor,
                witness,
            } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_string(w, new_descriptor)?;
                // Write first stack element (signature) as 64 bytes or zeros
                let sig_bytes: [u8; 64] = witness
                    .stack
                    .first()
                    .and_then(|s| {
                        if s.len() >= 64 {
                            s[..64].try_into().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or([0u8; 64]);
                w.write_all(&sig_bytes)?;
            }
            Self::InvoiceCredit {
                payment_hash,
                deposit_id,
                amount,
                invoice_id,
                sequence_number,
            } => {
                write_32(w, payment_hash)?;
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_string(w, invoice_id)?;
                write_u64(w, *sequence_number)?;
            }
            Self::InvoiceLock {
                deposit_id,
                amount,
                payment_id,
                sequence_number,
                witness,
            } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_32(w, payment_id)?;
                write_u64(w, *sequence_number)?;
                // Write first stack element (signature) as 64 bytes or zeros
                let sig_bytes: [u8; 64] = witness
                    .stack
                    .first()
                    .and_then(|s| {
                        if s.len() >= 64 {
                            s[..64].try_into().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or([0u8; 64]);
                w.write_all(&sig_bytes)?;
            }
            Self::InvoiceFail {
                deposit_id,
                amount,
                payment_id,
                sequence_number,
            } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_32(w, payment_id)?;
                write_u64(w, *sequence_number)?;
            }
            Self::InvoiceFulfill {
                deposit_id,
                amount,
                payment_id,
                sequence_number,
                witness,
                preimage,
            } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_32(w, payment_id)?;
                write_u64(w, *sequence_number)?;
                let sig_bytes: [u8; 64] = witness
                    .stack
                    .first()
                    .and_then(|s| {
                        if s.len() >= 64 {
                            s[..64].try_into().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or([0u8; 64]);
                w.write_all(&sig_bytes)?;
                write_32(w, preimage)?;
            }
            Self::OnchainCredit {
                txid,
                vout,
                deposit_id,
                amount,
                funding_address,
            } => {
                write_32(w, txid)?;
                write_u32(w, *vout)?;
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_string(w, funding_address)?;
            }
            Self::OnchainLock {
                deposit_id,
                amount,
                fee_sats,
                destination_address,
                withdrawal_id,
                witness,
            } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_u64(w, *fee_sats)?;
                write_string(w, destination_address)?;
                write_32(w, withdrawal_id)?;
                // Write first stack element (signature) as 64 bytes or zeros
                let sig_bytes: [u8; 64] = witness
                    .stack
                    .first()
                    .and_then(|s| {
                        if s.len() >= 64 {
                            s[..64].try_into().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or([0u8; 64]);
                w.write_all(&sig_bytes)?;
            }
            Self::OnchainFail {
                deposit_id,
                withdrawal_id,
            } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_32(w, withdrawal_id)?;
            }
            Self::OnchainFulfill {
                deposit_id,
                withdrawal_id,
                amount,
                txid,
                destination_address,
            } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_32(w, withdrawal_id)?;
                write_u64(w, *amount)?;
                write_32(w, txid)?;
                write_string(w, destination_address)?;
            }
            Self::TransferLock {
                nonce,
                source_deposit_id,
                destination_deposit_id,
                amount,
                fee,
                completion_script,
                timeout_height,
                transfer_id,
                witness,
            } => {
                write_32(w, nonce)?;
                let mut src_bytes = [0u8; 33];
                src_bytes[0] = 0x02;
                src_bytes[1..17].copy_from_slice(source_deposit_id);
                w.write_all(&src_bytes)?;
                let mut dst_bytes = [0u8; 33];
                dst_bytes[0] = 0x02;
                dst_bytes[1..17].copy_from_slice(destination_deposit_id);
                w.write_all(&dst_bytes)?;
                write_u64(w, *amount)?;
                write_u64(w, *fee)?;
                write_string(w, completion_script)?;
                write_u32(w, *timeout_height)?;
                write_32(w, transfer_id)?;
                let sig_bytes: [u8; 64] = witness
                    .stack
                    .first()
                    .and_then(|s| {
                        if s.len() >= 64 {
                            s[..64].try_into().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or([0u8; 64]);
                w.write_all(&sig_bytes)?;
            }
            Self::TransferComplete {
                transfer_id,
                script_witness,
            } => {
                write_32(w, transfer_id)?;
                // Write witness stack length and elements
                write_u16(w, script_witness.stack.len() as u16)?;
                for element in &script_witness.stack {
                    write_u16(w, element.len() as u16)?;
                    w.write_all(element)?;
                }
            }
            Self::TransferFail {
                transfer_id,
                block_hash,
                reason,
            } => {
                write_32(w, transfer_id)?;
                write_32(w, block_hash)?;
                write_u8(w, *reason)?;
            }
            Self::QuorumAddMember {
                quorum_member,
                quorum_member_signature,
                member_ledger_id,
                ..
            } => {
                write_pubkey(w, quorum_member)?;
                write_64(w, quorum_member_signature)?;
                write_string(w, member_ledger_id)?;
            }
            Self::QuorumRemoveMember {
                quorum_member,
                operator_signature,
            } => {
                write_pubkey(w, quorum_member)?;
                write_64(w, operator_signature)?;
            }
            Self::QuorumJoin {
                operator_id,
                ledger_id,
                membership_expires,
            } => {
                write_pubkey(w, operator_id)?;
                write_string(w, ledger_id)?;
                write_u32(w, *membership_expires)?;
            }
            Self::FeeCollect {
                deposit_id,
                amount,
                block_height,
            } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_u32(w, *block_height)?;
            }
            Self::DisputeEnter {
                last_valid_sequence,
                reason,
            } => {
                write_u64(w, *last_valid_sequence)?;
                write_string(w, reason)?;
            }
            Self::DisputeArmed {
                armed_block,
                commitment_hash,
                target_reserves,
                replacement_collateral,
            } => {
                write_u32(w, *armed_block)?;
                write_20(w, commitment_hash)?;
                write_string(w, target_reserves)?;
                // Replacement collateral: u8 flag (0/1) + (txid|vout|amount)
                // when present. Old readers stop after target_reserves; new
                // readers detect EOF and treat the field as None.
                match replacement_collateral {
                    Some(rc) => {
                        write_u8(w, 1)?;
                        write_32(w, &rc.txid)?;
                        write_u32(w, rc.vout)?;
                        write_u64(w, rc.amount)?;
                    }
                    None => {
                        write_u8(w, 0)?;
                    }
                }
            }
            Self::DisputeAcquire {
                new_custodian,
                claim_txid,
                new_reserves_address,
            } => {
                write_pubkey(w, new_custodian)?;
                write_32(w, claim_txid)?;
                write_string(w, new_reserves_address)?;
            }
            Self::DeliveryEmbed {
                request_hash,
                target_ledger_id,
                target_operator,
            } => {
                write_32(w, request_hash)?;
                write_32(w, target_ledger_id)?;
                write_pubkey(w, target_operator)?;
            }
            Self::DisputeYield => {}
            Self::LedgerClose => {}
        }
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let discriminant = read_u8(r)?;
        match discriminant {
            // LedgerOpen (1)
            1 => {
                let operator_id = read_pubkey(r)?;
                let reserves_id = read_string(r)?;
                let genesis_block = read_u32(r)?;
                let _reserved = read_u32(r)?; // was collateral_enforcement_block
                                              // reserves_amount added later; default to 0 for legacy data
                let reserves_amount = read_u64(r).unwrap_or(0);
                let collateral_amount = read_u64(r).unwrap_or(0);
                Ok(Self::LedgerOpen {
                    operator_id,
                    reserves_id,
                    genesis_block,
                    reserves_amount,
                    collateral_amount,
                })
            }
            // QuorumBegin (12) — formerly ReservesRotate
            12 => {
                let reserves_id = read_string(r)?;
                let spending_txid = read_32(r)?;
                let new_outpoint_txid = read_32(r)?;
                let new_outpoint_vout = read_u32(r)?;
                let amount = read_u64(r)?;
                let _threshold = read_u8(r)?; // legacy: skip
                let _size = read_u8(r)?; // legacy: skip
                let quorum_expiry = read_u32(r)?;
                let ledger_hash = read_32(r)?;
                let collateral_amount = read_u64(r).unwrap_or(0);
                Ok(Self::QuorumBegin {
                    reserves_id,
                    spending_txid,
                    new_outpoint_txid,
                    new_outpoint_vout,
                    amount,
                    quorum_expiry,
                    ledger_hash,
                    quorum_members: Vec::new(),
                    collateral_amount,
                })
            }
            // Deposit operations (20-25) - legacy decoding extracts deposit_id from embedded bytes
            20 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::DepositOpen {
                    deposit_id,
                    descriptor: format!("legacy({})", hex::encode(deposit_id)),
                    fees: read_option(r, FeeStructure::read_from)?,
                    transfer_fees: None,
                    payment_hash: read_option(r, read_32)?,
                    invoice: read_option(r, read_string)?,
                    cosigner_guarantee_signature: read_option(r, read_64)?,
                    receive_requires_sig: false,
                    fee_change_after_blocks: None,
                    fee_change_notice_blocks: None,
                    fee_change_limit_bps: None,
                })
            }
            21 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::DepositClose { deposit_id })
            }
            22 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::FeeChange {
                    deposit_id,
                    new_fees: FeeStructure::read_from(r)?,
                    effective_block: 0,
                })
            }
            23 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                let new_descriptor = read_string(r)?;
                let sig_bytes = read_64(r)?;
                let witness = DescriptorWitness {
                    stack: vec![sig_bytes.to_vec()],
                };
                Ok(Self::DepositKeyRotate {
                    deposit_id,
                    new_descriptor,
                    witness,
                })
            }
            // Invoice operations (30-33)
            30 => {
                let payment_hash = read_32(r)?;
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::InvoiceCredit {
                    payment_hash,
                    deposit_id,
                    amount: read_u64(r)?,
                    invoice_id: read_string(r)?,
                    sequence_number: read_u64(r)?,
                })
            }
            31 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                let amount = read_u64(r)?;
                let payment_id = read_32(r)?;
                let sequence_number = read_u64(r)?;
                let sig = read_64(r)?;
                Ok(Self::InvoiceLock {
                    deposit_id,
                    amount,
                    payment_id,
                    sequence_number,
                    witness: crate::types::DescriptorWitness {
                        stack: vec![sig.to_vec()],
                    },
                })
            }
            32 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::InvoiceFail {
                    deposit_id,
                    amount: read_u64(r)?,
                    payment_id: read_32(r)?,
                    sequence_number: read_u64(r)?,
                })
            }
            33 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                let amount = read_u64(r)?;
                let payment_id = read_32(r)?;
                let sequence_number = read_u64(r)?;
                let sig = read_64(r)?;
                let preimage = read_32(r)?;
                Ok(Self::InvoiceFulfill {
                    deposit_id,
                    amount,
                    payment_id,
                    sequence_number,
                    witness: crate::types::DescriptorWitness {
                        stack: vec![sig.to_vec()],
                    },
                    preimage,
                })
            }
            // Onchain operations (35-38)
            35 => {
                let txid = read_32(r)?;
                let vout = read_u32(r)?;
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::OnchainCredit {
                    txid,
                    vout,
                    deposit_id,
                    amount: read_u64(r)?,
                    funding_address: read_string(r)?,
                })
            }
            36 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                let amount = read_u64(r)?;
                let fee_sats = read_u64(r)?;
                let destination_address = read_string(r)?;
                let withdrawal_id = read_32(r)?;
                let sig_bytes = read_64(r)?;
                Ok(Self::OnchainLock {
                    deposit_id,
                    amount,
                    fee_sats,
                    destination_address,
                    withdrawal_id,
                    witness: DescriptorWitness {
                        stack: vec![sig_bytes.to_vec()],
                    },
                })
            }
            37 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::OnchainFail {
                    deposit_id,
                    withdrawal_id: read_32(r)?,
                })
            }
            38 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::OnchainFulfill {
                    deposit_id,
                    withdrawal_id: read_32(r)?,
                    amount: read_u64(r)?,
                    txid: read_32(r)?,
                    destination_address: read_string(r)?,
                })
            }
            // Transfer operations (70-72)
            70 => {
                let nonce = read_32(r)?;
                let src_bytes = read_33(r)?;
                let mut source_deposit_id = [0u8; 16];
                source_deposit_id.copy_from_slice(&src_bytes[1..17]);
                let dst_bytes = read_33(r)?;
                let mut destination_deposit_id = [0u8; 16];
                destination_deposit_id.copy_from_slice(&dst_bytes[1..17]);
                let amount = read_u64(r)?;
                let fee = read_u64(r)?;
                let completion_script = read_string(r)?;
                let timeout_height = read_u32(r)?;
                let transfer_id = read_32(r)?;
                let sig_bytes = read_64(r)?;
                Ok(Self::TransferLock {
                    nonce,
                    source_deposit_id,
                    destination_deposit_id,
                    amount,
                    fee,
                    completion_script,
                    timeout_height,
                    transfer_id,
                    witness: DescriptorWitness {
                        stack: vec![sig_bytes.to_vec()],
                    },
                })
            }
            71 => {
                let transfer_id = read_32(r)?;
                let stack_len = read_u16(r)? as usize;
                let mut stack = Vec::with_capacity(stack_len);
                for _ in 0..stack_len {
                    let elem_len = read_u16(r)? as usize;
                    let mut elem = vec![0u8; elem_len];
                    r.read_exact(&mut elem)?;
                    stack.push(elem);
                }
                Ok(Self::TransferComplete {
                    transfer_id,
                    script_witness: DescriptorWitness { stack },
                })
            }
            72 => Ok(Self::TransferFail {
                transfer_id: read_32(r)?,
                block_hash: read_32(r)?,
                reason: read_u8(r).unwrap_or(1),
            }),
            43 => Ok(Self::QuorumAddMember {
                quorum_member: read_pubkey(r)?,
                quorum_member_signature: read_64(r)?,
                member_ledger_id: read_string(r)?,
                min_fee_bps: None,
                min_fee_fixed: None,
                max_fee_period: None,
                membership_until: None,
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
                compensation_bps: None,
                compensation_deposit_id: None,
                compensation_frequency_blocks: None,
            }),
            44 => Ok(Self::QuorumRemoveMember {
                quorum_member: read_pubkey(r)?,
                operator_signature: read_64(r)?,
            }),
            46 => Ok(Self::QuorumJoin {
                operator_id: read_pubkey(r)?,
                ledger_id: read_string(r)?,
                membership_expires: read_u32(r)?,
            }),
            // Fee operations (50)
            50 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::FeeCollect {
                    deposit_id,
                    amount: read_u64(r)?,
                    block_height: read_u32(r)?,
                })
            }
            // DisputeEnter (54)
            54 => Ok(Self::DisputeEnter {
                last_valid_sequence: read_u64(r)?,
                reason: read_string(r)?,
            }),
            // DisputeAcquire (55)
            55 => Ok(Self::DisputeAcquire {
                new_custodian: read_pubkey(r)?,
                claim_txid: read_32(r)?,
                new_reserves_address: read_string(r)?,
            }),
            // DisputeYield (56)
            56 => Ok(Self::DisputeYield),
            // DisputeArmed (57)
            57 => {
                let armed_block = read_u32(r)?;
                let commitment_hash = read_20(r)?;
                let target_reserves = read_string(r)?;
                // Replacement collateral: optional. Old events end after
                // target_reserves; if read_u8 returns EOF, treat as None.
                let replacement_collateral = match read_u8(r) {
                    Ok(0) => None,
                    Ok(1) => Some(ReplacementCollateral {
                        txid: read_32(r)?,
                        vout: read_u32(r)?,
                        amount: read_u64(r)?,
                    }),
                    Ok(v) => return Err(CodecError::InvalidData(format!(
                        "invalid replacement_collateral flag: {}",
                        v
                    ))),
                    Err(_) => None,
                };
                Ok(Self::DisputeArmed {
                    armed_block,
                    commitment_hash,
                    target_reserves,
                    replacement_collateral,
                })
            }
            // DeliveryEmbed (80)
            80 => Ok(Self::DeliveryEmbed {
                request_hash: read_32(r)?,
                target_ledger_id: read_32(r)?,
                target_operator: read_pubkey(r)?,
            }),
            // Close operations (60)
            60 => Ok(Self::LedgerClose),
            _ => Err(CodecError::InvalidDiscriminant(discriminant)),
        }
    }
}

// LedgerUpdateMsg codec (for computing message hash in handlers)
impl BinaryCodec for LedgerUpdateMsg {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        write_pubkey(w, &self.operator_id)?;
        write_string(w, &self.reserves_id)?;
        self.operation.write_to(w)?;
        write_u64(w, self.sequence_number)?;
        write_32(w, &self.previous_hash)?;
        write_32(w, &self.content_hash)?;
        write_64(w, &self.operator_signature)?;
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            operator_id: read_pubkey(r)?,
            reserves_id: read_string(r)?,
            operation: LedgerOperation::read_from(r)?,
            sequence_number: read_u64(r)?,
            previous_hash: read_32(r)?,
            content_hash: read_32(r)?,
            operator_signature: read_64(r)?,
        })
    }
}

impl BinaryCodec for SignedLedgerUpdate {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        write_bytes(w, &self.message)?;
        write_u16(w, self.message_type)?;
        write_pubkey(w, &self.operator_id)?;
        write_32(w, &self.ledger_id)?;
        write_u64(w, self.sequence_number)?;
        write_32(w, &self.previous_hash)?;
        write_u32(w, self.block_height)?;
        write_32(w, &self.block_hash)?;
        write_64(w, &self.cosign_signature)?;
        write_64(w, &self.operator_signature)?;
        write_option(w, &self.cosigner_pubkey, |w, pk| write_pubkey(w, pk))?;
        write_option(w, &self.member_ledger_hash, |w, h| write_32(w, h))?;
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let message = read_bytes(r)?;
        let message_type = read_u16(r)?;
        let operator_id = read_pubkey(r)?;
        let ledger_id = read_32(r)?;
        let sequence_number = read_u64(r)?;
        let previous_hash = read_32(r)?;
        let block_height = read_u32(r)?;
        let block_hash = read_32(r)?;
        let cosign_signature = read_64(r)?;
        let operator_signature = read_64(r)?;
        // Optional fields (backward compatible - not present in old format)
        let cosigner_pubkey = read_option(r, read_pubkey).unwrap_or(None);
        let member_ledger_hash = read_option(r, |r| read_32(r)).unwrap_or(None);
        let mut update = Self {
            message,
            message_type,
            operator_id,
            ledger_id,
            sequence_number,
            previous_hash,
            content_hash: [0u8; 32],
            block_height,
            block_hash,
            cosign_signature,
            operator_signature,
            cosigner_pubkey,
            member_ledger_hash,
            cosignatures: Vec::new(),
        };
        update.content_hash = update.compute_hash();
        Ok(update)
    }
}
