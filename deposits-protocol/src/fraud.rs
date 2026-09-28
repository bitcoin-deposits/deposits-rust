//! Fraud proof construction and verification.
//!
//! A fraud proof has two parts:
//!
//! 1. **The proof** (`FraudProof`): evidence of dishonesty. This is hashed
//!    and the hash embedded into a ledger chain as wallet-controlled data
//!    (e.g., a transfer nonce). The proof is constructed before embedding.
//!
//! 2. **The broadcast** (`FraudBroadcast`): the proof plus a causal chain
//!    showing how the hash got entangled into the accused operator's ledger.
//!    Constructed after embedding, once the causal chain has formed.
//!
//! Embedding targets (in order of preference):
//! - Direct: transfer nonce on the operator's own ledger
//! - One hop: on a quorum member's ledger, entangled at next co-signature
//! - Further: any ledger in the web, wait for causal propagation
//!
//! Verification: hash the proof, walk the causal chain from the embedding
//! to the operator's ledger, confirm each link is a signed update.
//!
//! Embedding and causal chain apply only to off-ledger / timing-dependent
//! proof types. A proof that is itself cryptographic evidence of
//! non-conformity is self-evident and verifies on its evidence alone; see
//! [`FraudProofType::requires_embedding`].

use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

// ============================================================================
// The Proof (hashable, constructed before embedding)
// ============================================================================

/// Evidence of operator or quorum member dishonesty.
///
/// This is the hashable part — `proof_hash()` produces the 32-byte value
/// that gets embedded into a ledger chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudProof {
    /// Type of fraud being proven.
    pub proof_type: FraudProofType,
    /// The operator or member being accused (66-char hex pubkey).
    pub accused: String,
    /// The ledger where the fraud occurred (64-char hex).
    pub ledger_id: String,
    /// Evidence specific to the proof type.
    pub evidence: FraudEvidence,
}

/// The five types of fraud from the protocol specification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FraudProofType {
    /// Operator offered to credit a deposit for on-chain funds but didn't,
    /// despite signing updates proving they saw sufficient confirmations.
    UncreditedOnchainPayment,
    /// Operator created a cosigned invoice but didn't credit the deposit
    /// despite the preimage being revealed (provable via causal ordering).
    UncreditedLightningPayment,
    /// A co-signature declares a member_ledger_hash that precedes the
    /// member's own later hash — proving the co-signer backdated.
    StaleCosignature,
    /// A quorum member was active (their ledger has updates) but didn't
    /// initiate a dispute within the required block window.
    DisputeDereliction,
    /// The operator signed a ledger update that violates protocol rules.
    NonConformingUpdate,
    /// The operator failed to rotate the quorum before `quorum_expiry`.
    /// The only respectful fraud-proof type — confiscation tx is
    /// bifurcated (obligations to lottery, change to operator), and
    /// the proof does NOT propagate cross-ledger. Evidence is just an
    /// anchor block hash whose height in the verifier's chain exceeds
    /// the ledger's recorded `quorum_expiry`.
    QuorumExpired,
    /// The lottery winner broadcast a claim TX whose shape deviates
    /// from the `replacement_collateral` they declared in their
    /// `DisputeArmed`. Punitive: attributed to the winner's new
    /// operator pubkey on whatever ledger they're operating after
    /// takeover. Cross-ledger contagion applies as for any other
    /// punitive proof. See DEP-03 §"Claim transaction (multi-input)"
    /// for the canonical claim shape.
    WinnerCollateralDeviation,
    /// Operator double-signed: two distinct `SignedLedgerUpdate`s
    /// at the same `(ledger_id, sequence_number)`, both bearing the
    /// operator's BIP-340 signature, with differing `content_hash`.
    /// Self-contained — verification needs nothing beyond the two
    /// updates themselves; no relay fetch, no block oracle, no
    /// cosigner ledger lookup. Punitive: a chain can have exactly
    /// one canonical update per sequence, so the operator's signature
    /// on two of them at the same seq is proof of misbehavior.
    /// `last_valid_sequence` is the equivocation point minus one —
    /// everything strictly before the double-signed seq is intact
    /// and inherits to the fork branch.
    Equivocation,
    /// Accused operator was party to a non-conforming update on
    /// another (or their own) ledger: their key appears either as
    /// the update's `operator_id` (they issued it) OR in
    /// `cosignatures` (they cosigned it). Either way they're on the
    /// hook.
    ///
    /// Why the framing differs from a naive "operator signed bad
    /// update": with majority-cosign enforced, an operator can't
    /// unilaterally land a non-conforming update — cosigners are
    /// expected to refuse. So the only way a non-conforming update
    /// lives is collusion (or buggy cosigner that ignored its own
    /// conformance check). The fraud is *putting your key on it*,
    /// not *being the operator of the ledger it sits on*.
    ///
    /// The disputed ledger (`FraudProof::ledger_id`) is one of the
    /// accused's *own* ledgers — cross-ledger punitive contagion.
    /// The fault ledger (`fault_ledger_id` inside the evidence) is
    /// where the bad update sits; usually a different ledger from
    /// the disputed one.
    NonConformingCosignature,
}

impl FraudProofType {
    /// Whether this fraud proof is *respectful* (operator wasn't
    /// provably dishonest, just failed to maintain the schedule) or
    /// *punitive* (provably misbehaved).
    ///
    /// Drives:
    /// - the confiscation tx shape (respectful = bifurcated, change to
    ///   operator's pubkey; punitive = full UTXO confiscated and split
    ///   among the Q cosigners).
    /// - cross-ledger propagation (punitive proofs cascade to the
    ///   operator's *other* quorums; respectful do not).
    pub fn is_respectful(&self) -> bool {
        matches!(self, Self::QuorumExpired)
    }

    /// Whether a broadcast of this proof type must carry an embedding and
    /// causal chain (DEP-06), or is *self-evident*.
    ///
    /// The rule: embedding exists for censorship and off-ledger fraud, where
    /// there is no signed, on-ledger evidence of non-conformity and the
    /// causal ordering of the evidence is what proves the fault. **A fraud
    /// proof that is itself cryptographic evidence of non-conformity needs
    /// no embedding and no causal chain**: its verdict does not depend on
    /// when the proof became known, so ordering adds nothing. It is also
    /// often unsatisfiable: a quorum member reporting its own operator after
    /// the fraud cannot get a causal link (the accused chain now holds the
    /// invalid update, and honest members never cosign past it), and a
    /// direct embedding needs the fraudster to sign the reporter's hash.
    ///
    /// Self-evident (embedding optional, ignored when present):
    /// - `NonConformingUpdate`: the operator's own signed update.
    /// - `Equivocation`: two operator-signed updates at one sequence.
    /// - `NonConformingCosignature`: the accused's cosignature on a
    ///   non-conforming update.
    /// - `StaleCosignature`: two signed hashes from the member's own chain.
    /// - `QuorumExpired`: a block anchor past the ledger's signed expiry.
    /// - `WinnerCollateralDeviation`: the claim TX against the winner's
    ///   signed `DisputeArmed`.
    ///
    /// Embedding required (off-ledger or timing-dependent):
    /// - `UncreditedOnchainPayment`, `UncreditedLightningPayment`: the
    ///   payment is off-ledger; the proof must be shown to precede the
    ///   operator's (non-)response.
    /// - `DisputeDereliction` (inactive quorum member): the fault is a
    ///   response window measured from when the member saw the proof.
    ///
    /// The match is exhaustive on purpose: a new proof type must be
    /// classified here.
    pub fn requires_embedding(&self) -> bool {
        match self {
            Self::UncreditedOnchainPayment
            | Self::UncreditedLightningPayment
            | Self::DisputeDereliction => true,
            Self::NonConformingUpdate
            | Self::Equivocation
            | Self::NonConformingCosignature
            | Self::StaleCosignature
            | Self::QuorumExpired
            | Self::WinnerCollateralDeviation => false,
        }
    }

    /// The complement of [`Self::requires_embedding`]: the proof is its own
    /// evidence and verifies without an embedding or causal chain.
    pub fn is_self_evident(&self) -> bool {
        !self.requires_embedding()
    }
}

/// Evidence specific to each proof type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FraudEvidence {
    /// Operator didn't credit an on-chain payment.
    UncreditedOnchain {
        /// The cosigned offer (hex offer_id, funding_address, cosignature).
        offer_id: String,
        funding_address: String,
        /// Operator pubkey that issued the offer (binds the cosigner's
        /// signature to a specific operator).
        accused_operator_pubkey: String,
        /// Block height the offer commits to as its expiration.
        deadline_block: u32,
        cosigner_pubkey: String,
        /// Cosigner's own ledger hash at cosign time. Required to
        /// reconstruct the offer signing message.
        cosigner_ledger_hash: String,
        cosign_signature: String,
        /// On-chain payment.
        txid: String,
        vout: u32,
        amount_sats: u64,
        /// Block hash anchoring when the payment confirmed. Verifier
        /// independently confirms this hash is in its chain — the
        /// height is read out of the verifier's chain, not trusted from
        /// the proof.
        #[serde(with = "crate::types::serde_32")]
        confirmed_at_block_hash: [u8; 32],
        required_confirmations: u32,
        /// Operator signed an update at this sequence — its `block_hash`
        /// (read from the SignedLedgerUpdate, also confirmed via the
        /// oracle) proves the operator saw enough confirmations but
        /// still didn't credit by then.
        proof_sequence: u64,
    },

    /// Operator didn't credit a lightning payment.
    UncreditedLightning {
        /// The cosigned invoice (BOLT11).
        invoice: String,
        payment_hash: String,
        /// Deposit the invoice was minted against.
        #[serde(with = "crate::types::serde_deposit_id")]
        deposit_id: crate::types::DepositId,
        /// Invoice amount in millisatoshis (signed over by the cosigner).
        amount_msat: u64,
        cosigner_pubkey: String,
        /// The cosigner's own ledger hash at cosign time. Required to
        /// reconstruct the BIP-340 signing message; without it the
        /// cosig signature can't be verified.
        cosigner_ledger_hash: String,
        cosign_signature: String,
        /// The preimage proving payment.
        preimage: String,
        /// Operator signed an update after the preimage was known.
        proof_sequence: u64,
    },

    /// Co-signer backdated their ledger hash.
    StaleCosign {
        /// The update with the stale co-signature.
        stale_update_sequence: u64,
        stale_update_hash: String,
        /// The member_ledger_hash declared in the co-signature.
        declared_member_hash: String,
        /// A later update on the member's ledger proving the hash is stale.
        member_later_sequence: u64,
        member_later_hash: String,
        member_ledger_id: String,
    },

    /// Quorum member was active but didn't act on fraud.
    DisputeDereliction {
        /// Hash of the original fraud proof that was ignored.
        original_fraud_hash: String,
        /// Block hash anchoring when the original fraud proof became
        /// knowable (e.g. the block_hash of the update where the
        /// proof_hash was embedded). The verifier confirms this hash is
        /// in its own confirmed chain — the block height alone is not
        /// trusted, only its presence in the chain.
        #[serde(with = "crate::types::serde_32")]
        original_fraud_block_hash: [u8; 32],
        required_response_blocks: u32,
        /// The inactive member's collateral ledger.
        member_ledger_id: String,
        /// Member was active after the window (proving they were online).
        /// The block_hash for this update is read directly off the
        /// referenced SignedLedgerUpdate and confirmed by the verifier.
        member_active_sequence: u64,
        member_pubkey: String,
    },

    /// Operator signed a non-conforming update.
    NonConforming {
        /// The non-conforming update (base64 TLV).
        sequence: u64,
        update_b64: String,
        /// What rule was violated.
        violation: String,
    },

    /// Operator failed to rotate before `quorum_expiry`. The verifier
    /// confirms `anchor_block_hash` is in its own chain, looks up its
    /// height, and checks the height exceeds the ledger's recorded
    /// `quorum_expiry` (also carried here for binding + redundancy).
    /// Block heights are never trusted from the proof — only the hash's
    /// presence in the verifier's chain.
    /// Lottery winner's broadcast claim TX deviates from their declared
    /// replacement collateral. Verifier confirms `claim_block_hash` is
    /// in its chain, fetches/inspects the named claim TX, and compares
    /// against the winner's signed `DisputeArmed` declaration.
    WinnerCollateralDeviation {
        /// The winner's `DisputeArmed` SignedLedgerUpdate (TLV bytes,
        /// lowercase hex). Carries the declared `replacement_collateral`
        /// and the winner's signature, binding the declaration to them.
        winner_armed_update_hex: String,
        /// Hex txid of the claim TX the winner broadcast on-chain.
        claim_txid: String,
        /// Block hash anchoring the claim TX's confirmation. Verifier
        /// confirms this hash is in its chain via `BlockOracle`.
        #[serde(with = "crate::types::serde_32")]
        claim_block_hash: [u8; 32],
    },

    QuorumExpired {
        /// Anchor block whose chain-height proves the deadline has
        /// passed. Verifier looks this up via the BlockOracle.
        #[serde(with = "crate::types::serde_32")]
        anchor_block_hash: [u8; 32],
        /// The expired quorum's `quorum_expiry`, as recorded on the
        /// ledger's most recent `QuorumBegin`. Carried in the evidence
        /// for explicit binding — verifier reads it from ledger state
        /// and checks it matches before consulting the chain.
        quorum_expiry: u32,
    },

    /// Two distinct cosigned updates at the same `(ledger_id, seq)`,
    /// both signed by the operator. Carries both updates inline so
    /// the verifier doesn't need to fetch anything — equivocation is
    /// the only fraud type whose proof is fully self-contained.
    ///
    /// `sequence` is the shared `sequence_number` of both updates;
    /// the daemon uses `sequence - 1` as `last_valid_sequence` when
    /// driving the dispute (every update strictly before the
    /// equivocation point remains canonical and propagates onto the
    /// fork branch).
    Equivocation {
        /// Shared `sequence_number` of both updates. Carried
        /// redundantly with the embedded updates so the daemon can
        /// compute `last_valid_sequence` without decoding the TLV
        /// payloads up front — encoding is bound (verifier still
        /// checks both updates carry the same sequence).
        sequence: u64,
        /// First `SignedLedgerUpdate` (TLV bytes, lowercase hex).
        /// Hex (vs base64) keeps the encoding alphabet identical to
        /// every other on-the-wire blob in this enum and avoids
        /// pulling base64 into deposits-protocol.
        update_a_hex: String,
        /// Second `SignedLedgerUpdate` (TLV bytes, lowercase hex).
        /// Must have the same `operator_id`, `ledger_id`, and
        /// `sequence_number` as `update_a_hex`, with a different
        /// `content_hash` — and both signatures must verify.
        update_b_hex: String,
    },

    /// Accused was party to a non-conforming update on `fault_ledger_id`.
    /// Verifier fetches that ledger's *prior* history (via the
    /// `LedgerProvider`), replays seq 0 → `fault_sequence - 1` to
    /// reconstruct state, then applies the inline `fault_update_hex`
    /// and checks for `ConformanceViolation` or apply failure.
    ///
    /// The fault update is carried inline (not fetched) because
    /// cosigners reject non-conforming updates at the ledger_actor
    /// edge — they never make it to disk, so a from-disk fetch
    /// would always come up empty. The relay carries the broadcast,
    /// but verifier-side gap-fill from the relay is currently
    /// limited to ledger updates that pass apply.
    ///
    /// Conformance is ruleset-dependent; the proof binds explicitly
    /// to the `QuorumBegin` at `governing_quorumbegin_seq` so the
    /// verifier can't be tricked into checking under a later
    /// rotation's rules.
    NonConformingCosignature {
        /// Ledger that holds the bad update. Distinct from the
        /// outer `FraudProof::ledger_id` (which is the accused's
        /// own ledger being slashed).
        fault_ledger_id: String,
        /// Sequence number of the bad update on `fault_ledger_id`.
        /// Used to assert the inline update's sequence_number matches
        /// (redundancy check). The daemon does NOT derive
        /// `last_valid_sequence` from this — the disputed ledger is
        /// the *accused's own* and is slashed at its current tip.
        fault_sequence: u64,
        /// Sequence on `fault_ledger_id` whose `QuorumBegin`
        /// declared the active ruleset under which `fault_sequence`
        /// is non-conforming. Must satisfy
        /// `governing_quorumbegin_seq <= fault_sequence`. Pinning the
        /// QB prevents replaying the conformance check under a
        /// later (more permissive or more restrictive) ruleset and
        /// fishing for an alternate verdict.
        governing_quorumbegin_seq: u64,
        /// The non-conforming `SignedLedgerUpdate` (TLV bytes,
        /// lowercase hex). Verifier checks both signature paths
        /// (operator's BIP-340 and majority-cosig) before treating
        /// the inline update as authentic, then applies it to
        /// replayed state to confirm non-conformance.
        fault_update_hex: String,
    },

    /// The operator BIP-340-signed a ledger update that is structurally
    /// non-conforming on their OWN ledger — it does not chain onto the
    /// canonical tip (wrong `previous_hash`) or its `content_hash` is not
    /// the correct `compute_hash()`. Unlike `NonConformingCosignature`,
    /// no cosignatures are required: an operator-signed update that breaks
    /// the hash chain is unilateral operator fraud (only the operator's key
    /// can produce the signature, and an honest operator never signs an
    /// update that doesn't extend its canonical chain). This is the fault
    /// that `recovery start`'s hash-chain scan detects; the durable bad
    /// update on the relay is self-verifying evidence.
    NonConformingUpdate {
        /// Sequence number of the bad update on the accused's ledger.
        /// Redundancy check against the inline update's `sequence_number`.
        fault_sequence: u64,
        /// The non-conforming `SignedLedgerUpdate` (TLV bytes, lowercase
        /// hex). Verifier checks the operator's BIP-340 signature, then
        /// reconstructs the accused operator's canonical chain from the
        /// supplied history to confirm the update neither chains onto its
        /// predecessor nor carries a valid `content_hash`.
        fault_update_hex: String,
    },
}

impl FraudProof {
    /// Compute the 32-byte hash for embedding into a ledger chain.
    ///
    /// Uses BIP-340 tagged hashing for domain separation.
    pub fn proof_hash(&self) -> [u8; 32] {
        let tag = b"deposits/fraud_proof";
        let tag_hash = sha256::Hash::hash(tag);

        let mut input = Vec::new();
        input.extend_from_slice(tag_hash.as_byte_array());
        input.extend_from_slice(tag_hash.as_byte_array());
        input.push(self.proof_type.discriminant());
        input.extend_from_slice(self.accused.as_bytes());
        input.extend_from_slice(self.ledger_id.as_bytes());
        input.extend_from_slice(&self.evidence.canonical_bytes());

        sha256::Hash::hash(&input).to_byte_array()
    }

    /// Verify that a given 32-byte value matches this proof's hash.
    pub fn verify_embedding(&self, embedded_hash: &[u8; 32]) -> bool {
        &self.proof_hash() == embedded_hash
    }
}

// ============================================================================
// Per-type evidence verifiers (pure)
// ============================================================================
//
// Each verifier consumes a `FraudProof` and the ledger views it needs to
// confirm the claim, returning `Ok(())` if the evidence demonstrates real
// fraud and `Err(...)` describing the first reason it doesn't. The
// verifiers don't perform I/O — block-confirmation and ledger fetching are
// the caller's responsibility, supplied as either slice references or a
// `BlockOracle` callback.

/// Block-confirmation oracle. Daemon implementations look the hash up
/// against bitcoind/esplora and return the height if the hash is part of
/// the validator's confirmed chain. Test implementations use a static
/// `HashMap<[u8; 32], u32>`.
pub trait BlockOracle {
    fn confirms(&self, block_hash: &[u8; 32]) -> Option<u32>;
}

impl<F: Fn(&[u8; 32]) -> Option<u32>> BlockOracle for F {
    fn confirms(&self, block_hash: &[u8; 32]) -> Option<u32> {
        self(block_hash)
    }
}

fn parse_hex32(s: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("{}: {}", label, e))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{}: expected 32 bytes", label))?;
    Ok(arr)
}

/// Verify a `StaleCosignature` claim.
///
/// The accusation: the cosigner declared a `member_ledger_hash` that
/// referred to an already-stale state of their own ledger when they
/// signed. To prove this, evidence must show:
///   1. The accused operator's ledger has a SignedLedgerUpdate at
///      `stale_update_sequence` whose `content_hash` matches.
///   2. That update carries a `CosignEntry` whose `member_ledger_hash`
///      matches `declared_member_hash`.
///   3. The member's ledger has a SignedLedgerUpdate at
///      `member_later_sequence` whose `chain_hash()` matches
///      `member_later_hash`.
///   4. The member's chain reached past `declared_member_hash` BEFORE
///      the accused operator cosigned. Concretely: there exists a
///      sequence S on the member's chain whose `chain_hash()` matches
///      `declared_member_hash` (so the declared hash WAS valid at some
///      point), AND at least one later member update has a block_height
///      no greater than the accused's stale-update block_height (member
///      had advanced before the operator's cosign).
///
/// Cosignature signature validity is intentionally *not* checked here —
/// that's a separate concern (see todo for `verify_cosignatures`). The
/// staleness check is about temporal ordering of ledger states.
pub fn verify_stale_cosignature(
    proof: &FraudProof,
    accused_history: &[crate::types::SignedLedgerUpdate],
    member_history: &[crate::types::SignedLedgerUpdate],
) -> Result<(), String> {
    let FraudEvidence::StaleCosign {
        stale_update_sequence,
        stale_update_hash,
        declared_member_hash,
        member_later_sequence,
        member_later_hash,
        member_ledger_id: _,
    } = &proof.evidence
    else {
        return Err("verify_stale_cosignature: wrong evidence type".into());
    };

    let stale_hash_bytes = parse_hex32(stale_update_hash, "stale_update_hash")?;
    let declared_bytes = parse_hex32(declared_member_hash, "declared_member_hash")?;
    let later_hash_bytes = parse_hex32(member_later_hash, "member_later_hash")?;

    // (1) accused has the stale update at the claimed sequence + content hash.
    let stale_update = accused_history
        .iter()
        .find(|u| u.sequence_number == *stale_update_sequence)
        .ok_or_else(|| {
            format!(
                "stale_update_sequence {} not in accused history",
                stale_update_sequence
            )
        })?;
    if stale_update.content_hash != stale_hash_bytes {
        return Err(format!(
            "stale_update_hash mismatch at seq {}: claimed {}, actual {}",
            stale_update_sequence,
            hex::encode(&stale_hash_bytes[..8]),
            hex::encode(&stale_update.content_hash[..8])
        ));
    }

    // (2) the declared_member_hash appears in one of that update's CosignEntries.
    let cosig_present = stale_update
        .cosignatures
        .iter()
        .any(|c| c.member_ledger_hash == declared_bytes);
    if !cosig_present {
        return Err(format!(
            "declared_member_hash {} not found among CosignEntries on stale update",
            hex::encode(&declared_bytes[..8])
        ));
    }

    // (3) member has the later update at the claimed sequence + chain hash.
    let later_update = member_history
        .iter()
        .find(|u| u.sequence_number == *member_later_sequence)
        .ok_or_else(|| {
            format!(
                "member_later_sequence {} not in member history",
                member_later_sequence
            )
        })?;
    if later_update.chain_hash() != later_hash_bytes {
        return Err(format!(
            "member_later_hash mismatch at seq {}: claimed {}, actual {}",
            member_later_sequence,
            hex::encode(&later_hash_bytes[..8]),
            hex::encode(&later_update.chain_hash()[..8])
        ));
    }

    // (4) prove staleness: declared_member_hash WAS the member's chain_hash
    //     at some sequence S < member_later_sequence, AND the member has
    //     advanced past it at a block_height ≤ the accused's stale-update
    //     block_height (so at the time of cosign, the member was past S).
    let s_match = member_history
        .iter()
        .find(|u| u.chain_hash() == declared_bytes && u.sequence_number < *member_later_sequence);
    let s = s_match.ok_or_else(|| {
        format!(
            "declared_member_hash {} doesn't appear in member history before seq {}",
            hex::encode(&declared_bytes[..8]),
            member_later_sequence
        )
    })?;

    let advance_at_or_before_cosign = member_history.iter().any(|u| {
        u.sequence_number > s.sequence_number
            && u.sequence_number <= *member_later_sequence
            && u.block_height <= stale_update.block_height
    });
    if !advance_at_or_before_cosign {
        return Err(format!(
            "member did not advance past declared_member_hash before cosign at block {}",
            stale_update.block_height
        ));
    }

    Ok(())
}

/// Verify an `UncreditedLightningPayment` claim.
///
/// The accusation: operator cosigned a Lightning invoice, the preimage
/// was revealed (so the payment definitively succeeded), and yet the
/// operator never credited the deposit.
///
/// Checks:
///   1. `sha256(preimage) == payment_hash` — proof of payment.
///   2. The accused's ledger has a SignedLedgerUpdate at `proof_sequence`
///      (operator was alive after the preimage was knowable).
///   3. No `InvoiceCredit` or `InvoiceFulfill` for `payment_hash` in
///      accused history at sequence ≤ `proof_sequence` (operator did
///      not credit).
///
/// Cosignature signature validity is **not** checked here — that would
/// need the canonical "cosigned-invoice" signing message format, which
/// isn't yet centralized. The cosignature anchors the operator's
/// commitment, but for the *uncredited* claim what matters is whether
/// the credit happened, given the preimage. A later patch should add
/// cosig signature checking once the format is locked.
pub fn verify_uncredited_lightning(
    proof: &FraudProof,
    accused_history: &[crate::types::SignedLedgerUpdate],
) -> Result<(), String> {
    use crate::messages::LedgerOperation;
    use crate::tlv::TlvDecode;

    let FraudEvidence::UncreditedLightning {
        invoice: _,
        payment_hash,
        deposit_id,
        amount_msat,
        cosigner_pubkey,
        cosigner_ledger_hash,
        cosign_signature,
        preimage,
        proof_sequence,
    } = &proof.evidence
    else {
        return Err("verify_uncredited_lightning: wrong evidence type".into());
    };

    let payment_hash_bytes = parse_hex32(payment_hash, "payment_hash")?;
    let cosigner_ledger_hash_bytes = parse_hex32(cosigner_ledger_hash, "cosigner_ledger_hash")?;
    let preimage_bytes = parse_hex32(preimage, "preimage")?;

    // (1) hash(preimage) == payment_hash.
    let computed: [u8; 32] = sha256::Hash::hash(&preimage_bytes).to_byte_array();
    if computed != payment_hash_bytes {
        return Err(format!(
            "preimage doesn't hash to payment_hash: computed {} vs claimed {}",
            hex::encode(&computed[..8]),
            hex::encode(&payment_hash_bytes[..8])
        ));
    }

    // (1b) cosignature on the invoice is a valid BIP-340 schnorr sig
    // from cosigner_pubkey over the canonical invoice signing message.
    {
        use bitcoin::secp256k1::{schnorr::Signature, Message, PublicKey, Secp256k1};
        use std::str::FromStr;

        let cosigner_pk = PublicKey::from_str(cosigner_pubkey)
            .map_err(|e| format!("invalid cosigner_pubkey: {}", e))?;
        let sig_bytes = hex::decode(cosign_signature)
            .map_err(|e| format!("cosign_signature hex decode: {}", e))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "cosign_signature: expected 64 bytes".to_string())?;
        let sig = Signature::from_slice(&sig_arr)
            .map_err(|e| format!("cosign_signature parse: {}", e))?;

        let msg_hash = crate::signature_utils::invoice_cosign_signing_message(
            &proof.ledger_id,
            &payment_hash_bytes,
            deposit_id,
            *amount_msat,
            &cosigner_ledger_hash_bytes,
        );
        let msg = Message::from_digest(msg_hash);
        let (xonly, _) = cosigner_pk.x_only_public_key();

        if Secp256k1::verification_only()
            .verify_schnorr(&sig, &msg, &xonly)
            .is_err()
        {
            return Err(format!(
                "invoice cosignature failed BIP-340 verification (cosigner {})",
                hex::encode(&cosigner_pk.serialize()[..8])
            ));
        }
    }

    // (2) accused has an update at proof_sequence (operator was alive).
    let _proof_update = accused_history
        .iter()
        .find(|u| u.sequence_number == *proof_sequence)
        .ok_or_else(|| format!("proof_sequence {} not in accused history", proof_sequence))?;

    // (3) no InvoiceCredit / InvoiceFulfill for this payment_hash
    //     anywhere at seq ≤ proof_sequence. Recurses into Batch contents
    //     so a batched credit isn't hidden from the scanner.
    fn check_op(
        op: &LedgerOperation,
        seq: u64,
        payment_hash_bytes: [u8; 32],
    ) -> Result<(), String> {
        match op {
            LedgerOperation::InvoiceCredit {
                payment_hash: ph, ..
            } if *ph == payment_hash_bytes => Err(format!(
                "InvoiceCredit found at seq {} — operator did credit, not fraud",
                seq
            )),
            LedgerOperation::InvoiceFulfill {
                preimage: ff_preimage,
                ..
            } if sha256::Hash::hash(ff_preimage).to_byte_array() == payment_hash_bytes => {
                Err(format!(
                    "InvoiceFulfill found at seq {} — operator fulfilled, not fraud",
                    seq
                ))
            }
            LedgerOperation::Batch(inner_ops) => {
                for inner in inner_ops {
                    check_op(inner, seq, payment_hash_bytes)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    for u in accused_history
        .iter()
        .filter(|u| u.sequence_number <= *proof_sequence)
    {
        let Ok(op) = LedgerOperation::tlv_decode(&u.message) else {
            continue;
        };
        check_op(&op, u.sequence_number, payment_hash_bytes)?;
    }

    Ok(())
}

/// Verify an `DisputeDereliction` claim.
///
/// The accusation: member was online (their ledger has updates) past
/// the required response window after a fraud proof was knowable, but
/// failed to act on it.
///
/// Checks:
///   1. `original_fraud_block_hash` is in the verifier's confirmed chain.
///      The verifier's `BlockOracle` returns its height — the proof
///      doesn't trust any height claimed by the proof creator.
///   2. The member's ledger has a SignedLedgerUpdate at
///      `member_active_sequence`. Its `block_hash` is also confirmed
///      via the oracle.
///   3. `member_active_height - original_fraud_height >= required_response_blocks`.
///      The member was demonstrably online past the deadline.
///   4. The update at `member_active_sequence` is signed by
///      `member_pubkey` (operator_id of that update). Without this,
///      anyone could plant an update on a third party's ledger and
///      blame the wrong member.
pub fn verify_inactive_quorum_member(
    proof: &FraudProof,
    member_history: &[crate::types::SignedLedgerUpdate],
    block_oracle: &dyn BlockOracle,
) -> Result<(), String> {
    use std::str::FromStr;

    let FraudEvidence::DisputeDereliction {
        original_fraud_hash: _,
        original_fraud_block_hash,
        required_response_blocks,
        member_ledger_id: _,
        member_active_sequence,
        member_pubkey,
    } = &proof.evidence
    else {
        return Err("verify_inactive_quorum_member: wrong evidence type".into());
    };

    // (1) original-fraud block confirmed by the verifier.
    let original_height = block_oracle
        .confirms(original_fraud_block_hash)
        .ok_or_else(|| {
            format!(
                "original_fraud_block_hash {} not in verifier's confirmed chain",
                hex::encode(&original_fraud_block_hash[..8])
            )
        })?;

    // (2) member-active update exists, and its block_hash is confirmed.
    let member_update = member_history
        .iter()
        .find(|u| u.sequence_number == *member_active_sequence)
        .ok_or_else(|| {
            format!(
                "member_active_sequence {} not in member history",
                member_active_sequence
            )
        })?;

    let member_height = block_oracle
        .confirms(&member_update.block_hash)
        .ok_or_else(|| {
            format!(
                "member-active update's block_hash {} not in verifier's confirmed chain",
                hex::encode(&member_update.block_hash[..8])
            )
        })?;

    // (3) member was online past the deadline.
    let elapsed = member_height.saturating_sub(original_height);
    if elapsed < *required_response_blocks {
        return Err(format!(
            "member-active block {} only {} blocks past original-fraud block {}; need {}",
            member_height, elapsed, original_height, required_response_blocks
        ));
    }

    // (4) the member-active update is signed by the accused member.
    let claimed_pk = bitcoin::secp256k1::PublicKey::from_str(member_pubkey)
        .map_err(|e| format!("invalid member_pubkey: {}", e))?;
    if member_update.operator_id != claimed_pk {
        return Err(format!(
            "member-active update at seq {} signed by {} not member_pubkey {}",
            member_active_sequence,
            hex::encode(&member_update.operator_id.serialize()[..8]),
            hex::encode(&claimed_pk.serialize()[..8])
        ));
    }

    Ok(())
}

/// Verify a `QuorumExpired` claim.
///
/// The accusation: the operator failed to rotate before the recorded
/// `quorum_expiry`. Cosigners refuse to cosign past the deadline (see
/// `Ledger::validate_for_cosign`), so a missed rotation is fatal to
/// the current quorum and the lottery — bifurcated, returning
/// collateral to the operator — is the recovery.
///
/// Checks:
///   1. `anchor_block_hash` is in the verifier's confirmed chain. The
///      verifier reads its height directly from the oracle; no height
///      claimed by the proof creator is ever trusted.
///   2. `anchor_height > evidence.quorum_expiry`. The anchor block must
///      be strictly after the deadline — exactly at the deadline is
///      still cosignable per the cosigner-edge rule.
///   3. `evidence.quorum_expiry` matches the ledger's recorded
///      `quorum_expiry`. The verifier reads the ledger state and
///      confirms the binding — without this, a forged proof could cite
///      an arbitrary expiry block to fabricate an "expired" claim.
pub fn verify_quorum_expired(
    proof: &FraudProof,
    accused_history: &[crate::types::SignedLedgerUpdate],
    block_oracle: &dyn BlockOracle,
) -> Result<(), String> {
    use crate::messages::LedgerOperation;
    use crate::tlv::TlvDecode;

    let FraudEvidence::QuorumExpired {
        anchor_block_hash,
        quorum_expiry: claimed_expiry,
    } = &proof.evidence
    else {
        return Err("verify_quorum_expired: wrong evidence type".into());
    };

    // (1) anchor block confirmed.
    let anchor_height = block_oracle.confirms(anchor_block_hash).ok_or_else(|| {
        format!(
            "anchor_block_hash {} not in verifier's confirmed chain",
            hex::encode(&anchor_block_hash[..8])
        )
    })?;

    // (2) anchor strictly after the claimed deadline.
    if anchor_height <= *claimed_expiry {
        return Err(format!(
            "anchor block at height {} is not past quorum_expiry {} \
             (expiry block itself is still cosignable; need anchor > expiry)",
            anchor_height, claimed_expiry
        ));
    }

    // (3) claimed_expiry matches the ledger's most recent QuorumBegin.
    // Walk the accused's history and find the most recent QuorumBegin's
    // declared `quorum_expiry`. The fraud proof is bound to that exact
    // value — it can't fabricate an arbitrary one.
    let mut last_begin_expiry: Option<u32> = None;
    for u in accused_history.iter() {
        if let Ok(LedgerOperation::QuorumBegin { quorum_expiry, .. }) =
            LedgerOperation::tlv_decode(&u.message)
        {
            last_begin_expiry = Some(quorum_expiry);
        }
    }
    let actual_expiry = last_begin_expiry.ok_or_else(|| {
        "accused ledger has no QuorumBegin — quorum was never active, \
         can't be 'expired'"
            .to_string()
    })?;
    if *claimed_expiry != actual_expiry {
        return Err(format!(
            "claimed quorum_expiry {} doesn't match the ledger's most \
             recent QuorumBegin's quorum_expiry {}",
            claimed_expiry, actual_expiry
        ));
    }

    Ok(())
}

/// Verify an `Equivocation` claim.
///
/// The accusation: the operator double-signed — two distinct
/// `SignedLedgerUpdate`s at the same `(ledger_id, sequence_number)`,
/// both bearing the operator's BIP-340 signature. A canonical chain
/// can only have one update per seq, so two operator signatures at
/// the same seq is unrecoverable proof of misbehavior.
///
/// Self-contained: needs nothing beyond the two updates in the
/// evidence. No relay fetch, no block oracle, no cosigner ledger
/// lookup.
///
/// Checks:
///   1. Both updates TLV-decode cleanly.
///   2. Same `operator_id` (proves the operator's key signed both,
///      not two different operators colliding).
///   3. Same `ledger_id` (binds the equivocation to the ledger named
///      in the proof's outer `ledger_id` field — and they match each
///      other).
///   4. Same `sequence_number` (matches the evidence's `sequence`
///      field, redundancy for the daemon's LVS computation).
///   5. Different `content_hash` (proves the updates are actually
///      distinct — re-broadcasts of the same update don't qualify).
///   6. Both `operator_signature`s verify (via
///      `SignedLedgerUpdate::verify_operator_signature`). Without
///      this anyone could fabricate "evidence" by hand.
///   7. The proof's outer `accused` field matches both updates'
///      `operator_id` (no impersonation: the operator named on the
///      proof must be the one whose signature appears on both).
pub fn verify_equivocation(proof: &FraudProof) -> Result<(), String> {
    use crate::tlv::TlvDecode;

    let FraudEvidence::Equivocation {
        sequence,
        update_a_hex,
        update_b_hex,
    } = &proof.evidence
    else {
        return Err("verify_equivocation: wrong evidence type".into());
    };

    // (1) Decode.
    let bytes_a = hex::decode(update_a_hex).map_err(|e| format!("update_a hex decode: {}", e))?;
    let bytes_b = hex::decode(update_b_hex).map_err(|e| format!("update_b hex decode: {}", e))?;
    let update_a = crate::types::SignedLedgerUpdate::tlv_decode(&bytes_a)
        .map_err(|e| format!("update_a TLV decode: {:?}", e))?;
    let update_b = crate::types::SignedLedgerUpdate::tlv_decode(&bytes_b)
        .map_err(|e| format!("update_b TLV decode: {:?}", e))?;

    // (2) Same operator_id.
    if update_a.operator_id != update_b.operator_id {
        return Err(format!(
            "update_a.operator_id {} ≠ update_b.operator_id {} — not the \
             same operator double-signing",
            hex::encode(&update_a.operator_id.serialize()[..8]),
            hex::encode(&update_b.operator_id.serialize()[..8])
        ));
    }

    // (3) Same ledger_id (and binds to the proof's outer ledger_id).
    if update_a.ledger_id != update_b.ledger_id {
        return Err(format!(
            "update_a.ledger_id {} ≠ update_b.ledger_id {} — equivocation \
             requires both updates on the same ledger",
            hex::encode(&update_a.ledger_id[..8]),
            hex::encode(&update_b.ledger_id[..8])
        ));
    }
    let outer_ledger_bytes =
        hex::decode(&proof.ledger_id).map_err(|e| format!("outer ledger_id hex: {}", e))?;
    if outer_ledger_bytes.len() != 32 || outer_ledger_bytes[..] != update_a.ledger_id[..] {
        return Err(format!(
            "outer ledger_id {} ≠ updates' ledger_id {}",
            &proof.ledger_id[..16.min(proof.ledger_id.len())],
            hex::encode(&update_a.ledger_id[..8])
        ));
    }

    // (4) Same sequence_number, and matches evidence.sequence.
    if update_a.sequence_number != update_b.sequence_number {
        return Err(format!(
            "update_a.seq {} ≠ update_b.seq {} — equivocation requires \
             the same sequence number",
            update_a.sequence_number, update_b.sequence_number
        ));
    }
    if update_a.sequence_number != *sequence {
        return Err(format!(
            "evidence.sequence {} ≠ updates' sequence_number {} — \
             redundancy check failed (encoding-corrupted or forged)",
            sequence, update_a.sequence_number
        ));
    }

    // (5) Different content_hash — re-broadcasts of the same update
    //     are NOT equivocation. Tools that splice the same update
    //     into both slots get rejected here.
    if update_a.content_hash == update_b.content_hash {
        return Err("update_a.content_hash == update_b.content_hash — \
                    same update re-broadcast, not an equivocation"
            .into());
    }

    // (6) Both signatures verify. Without this, anyone could
    //     fabricate "evidence" by writing two arbitrary updates and
    //     stuffing in zero bytes for operator_signature.
    update_a
        .verify_operator_signature()
        .map_err(|e| format!("update_a signature verification: {}", e))?;
    update_b
        .verify_operator_signature()
        .map_err(|e| format!("update_b signature verification: {}", e))?;

    // (7) Accused matches the operator that signed.
    let accused_bytes = hex::decode(&proof.accused).map_err(|e| format!("accused hex: {}", e))?;
    if accused_bytes != update_a.operator_id.serialize() {
        return Err(format!(
            "outer accused {} ≠ updates' operator_id {} — impersonation \
             check",
            &proof.accused[..16.min(proof.accused.len())],
            hex::encode(&update_a.operator_id.serialize()[..8])
        ));
    }

    Ok(())
}

/// Verify a `NonConformingCosignature` claim.
///
/// The accusation: the accused operator put their BIP-340 key on
/// (operator-signed OR cosigned) a non-conforming update on
/// `fault_ledger_id`. With majority-cosign in force, the only way a
/// non-conforming update lands is collusion — every party who put a
/// signature on it is on the hook.
///
/// The disputed ledger is the accused's *own* (proof.ledger_id);
/// the fault ledger (`fault_ledger_id` inside the evidence) is
/// where the bad update sits. Cross-ledger contagion is the punitive
/// vehicle.
///
/// Checks:
///   1. Fetch `fault_ledger_id`'s history via `LedgerProvider`.
///      Missing → refuse (the verifier can't conclude either way
///      without it; an honest cosigner is expected to have any
///      ledger they cosigned for).
///   2. Locate the update at `fault_sequence`. Missing → reject.
///   3. The accused's pubkey must appear either as the update's
///      `operator_id` (they issued it) or in `cosignatures[*]
///      .cosigner_pubkey` (they cosigned it).
///   4. The `governing_quorumbegin_seq` must (a) be ≤
///      `fault_sequence` and (b) reference an actual `QuorumBegin`
///      on `fault_ledger_id`. Pinning this prevents replaying the
///      conformance check under a later rotation's rules.
///   5. Replay history seq 0 → `fault_sequence - 1` from the
///      derived genesis state. State carries the active ruleset
///      forward through QuorumBegin so the conformance check at
///      step 6 uses the rules the proof pinned to.
///   6. Apply the fault update via `apply_with_verifier`. Any
///      `ConformanceViolation` confirms the fraud; an empty
///      violations vec means the proof is wrong.
///
/// `authorizer` is the descriptor authorizer used for receive /
/// withdraw / completion-script checks. Daemons pass `Dep16Authorizer`;
/// pure unit tests that don't exercise descriptor-bound ops can pass
/// `DenyAll` (which over-reports — every authorize-gated op trips —
/// fine for ZeroAmount / ExceedsCollateral / InsufficientReserves
/// fault patterns).
pub fn verify_non_conforming_cosignature(
    proof: &FraudProof,
    fault_history: &[crate::types::SignedLedgerUpdate],
    authorizer: &impl crate::types::Authorizer,
) -> Result<(), String> {
    use crate::messages::LedgerOperation;
    use crate::tlv::TlvDecode;

    let FraudEvidence::NonConformingCosignature {
        fault_ledger_id,
        fault_sequence,
        governing_quorumbegin_seq,
        fault_update_hex,
    } = &proof.evidence
    else {
        return Err("verify_non_conforming_cosignature: wrong evidence type".into());
    };

    // (2) Decode the inline fault update + sanity checks.
    let fault_update_bytes =
        hex::decode(fault_update_hex).map_err(|e| format!("fault_update_hex decode: {}", e))?;
    let fault_update = crate::types::SignedLedgerUpdate::tlv_decode(&fault_update_bytes)
        .map_err(|e| format!("fault_update TLV decode: {:?}", e))?;

    if fault_update.sequence_number != *fault_sequence {
        return Err(format!(
            "evidence.fault_sequence {} ≠ inline update.sequence_number {}",
            fault_sequence, fault_update.sequence_number
        ));
    }
    let fault_ledger_bytes =
        hex::decode(fault_ledger_id).map_err(|e| format!("fault_ledger_id hex: {}", e))?;
    if fault_ledger_bytes.len() != 32 || fault_ledger_bytes[..] != fault_update.ledger_id[..] {
        return Err(format!(
            "fault_ledger_id {} ≠ inline update.ledger_id {}",
            &fault_ledger_id[..16.min(fault_ledger_id.len())],
            hex::encode(&fault_update.ledger_id[..8])
        ));
    }

    // (2a) Operator signature on the fault update verifies. Without
    //      this, anyone could fabricate a "non-conforming update"
    //      with random bytes and stuff in the accused's pubkey.
    fault_update
        .verify_operator_signature()
        .map_err(|e| format!("fault update operator_signature: {}", e))?;

    // (3) Accused's key appears as operator_id OR cosigner.
    let accused_bytes = hex::decode(&proof.accused).map_err(|e| format!("accused hex: {}", e))?;
    if accused_bytes.len() != 33 {
        return Err(format!(
            "accused pubkey must be 33-byte compressed: got {} bytes",
            accused_bytes.len()
        ));
    }
    let accused_is_operator = fault_update.operator_id.serialize() == accused_bytes[..];
    let accused_is_cosigner = fault_update
        .cosignatures
        .iter()
        .any(|e| e.cosigner_pubkey.serialize() == accused_bytes[..]);
    if !accused_is_operator && !accused_is_cosigner {
        return Err(format!(
            "accused {} is not operator nor cosigner on fault update at seq {} \
             — proof doesn't tie them to the non-conforming work",
            &proof.accused[..16.min(proof.accused.len())],
            fault_sequence
        ));
    }

    // (4) governing_quorumbegin_seq points to a real QB at-or-before
    //     fault_sequence in the fault ledger's prior history.
    if *governing_quorumbegin_seq > *fault_sequence {
        return Err(format!(
            "governing_quorumbegin_seq {} > fault_sequence {} — \
             a future QB can't govern a past update",
            governing_quorumbegin_seq, fault_sequence
        ));
    }
    let governing_qb_update = fault_history
        .iter()
        .find(|u| u.sequence_number == *governing_quorumbegin_seq)
        .ok_or_else(|| {
            format!(
                "governing_quorumbegin_seq {} not found in fault history",
                governing_quorumbegin_seq
            )
        })?;
    let governing_qb_op = LedgerOperation::tlv_decode(&governing_qb_update.message)
        .map_err(|e| format!("decode QB at seq {}: {}", governing_quorumbegin_seq, e))?;
    if !matches!(governing_qb_op, LedgerOperation::QuorumBegin { .. }) {
        return Err(format!(
            "update at governing_quorumbegin_seq {} is not a QuorumBegin",
            governing_quorumbegin_seq
        ));
    }

    // (5) Replay seq 0 → fault_sequence - 1 from fault_history.
    //     The inline fault update is applied separately in step 6.
    // Build a fresh genesis state from the seq-0 LedgerOpen so the
    // replay starts from the same root the operator did — not from
    // the verifier's possibly-fresher view.
    let seq0 = fault_history
        .iter()
        .find(|u| u.sequence_number == 0)
        .ok_or_else(|| "fault history missing seq 0 LedgerOpen".to_string())?;
    let (initial_operator, initial_reserves_id, initial_genesis_block) =
        match LedgerOperation::tlv_decode(&seq0.message) {
            Ok(LedgerOperation::LedgerOpen {
                operator_id,
                reserves_id,
                genesis_block,
                ..
            }) => (operator_id, reserves_id, genesis_block),
            _ => return Err("seq 0 is not LedgerOpen".into()),
        };
    let mut state = crate::types::LedgerState::new(
        initial_operator,
        initial_reserves_id,
        initial_genesis_block,
    );
    for u in fault_history.iter() {
        if u.sequence_number == 0 || u.sequence_number >= *fault_sequence {
            // seq 0 was already used to seed; replays start at seq 1.
            // Stop at seq == fault_sequence; we apply that one
            // separately to capture violations.
            continue;
        }
        let op = LedgerOperation::tlv_decode(&u.message)
            .map_err(|e| format!("replay decode at seq {}: {}", u.sequence_number, e))?;
        state
            .apply_in_place(&op)
            .map_err(|e| format!("replay apply at seq {}: {:?}", u.sequence_number, e))?;
    }

    // (6) Apply the fault update through the conformance pipeline.
    //     Three outcomes:
    //       - apply Err → state machine outright refuses (e.g.
    //         unknown deposit_id, sequence mismatch); even stronger
    //         evidence of bad cosigning than a conformance flag —
    //         fraud confirmed.
    //       - apply Ok(violations) with violations non-empty →
    //         conformance violation under pinned ruleset — fraud
    //         confirmed.
    //       - apply Ok(violations) empty → proof wrong, reject.
    let fault_op = LedgerOperation::tlv_decode(&fault_update.message)
        .map_err(|e| format!("fault update decode: {}", e))?;
    match state.apply_with_verifier(&fault_op, authorizer, fault_update.block_height) {
        Err(_) => Ok(()),
        Ok((_next_state, violations)) if !violations.is_empty() => Ok(()),
        Ok(_) => Err(format!(
            "fault update at seq {} produced no ConformanceViolation under \
             the pinned ruleset — proof is wrong",
            fault_sequence
        )),
    }
}

/// Verify a `NonConformingUpdate` claim.
///
/// The accusation: the accused operator BIP-340-signed an update on their own
/// ledger that the protocol does not allow. It is self-evident (DEP-06): the
/// signed update is itself the evidence, so the proof verifies on it and the
/// accused ledger's history alone, with no embedding. Two ways to be
/// non-conforming:
///
/// - **It does not chain.** Its `previous_hash` is not the canonical
///   predecessor's `chain_hash` (or its `content_hash` is wrong). An honest
///   daemon always signs onto its own tip, so this alone proves it. This is
///   what `recovery start`'s hash-chain scan surfaces.
/// - **It chains, but breaks a rule.** The canonical history is replayed from
///   genesis to the fault's predecessor and the fault is applied to that
///   state. The proof holds exactly when the state machine refuses it or
///   conformance reports a violation: a credit past reserves
///   (`InsufficientReserves`) or past collateral (`ExceedsCollateral`), a
///   debit past a deposit's balance, a zero-amount lock, a wrong balance
///   commitment, and so on. A fault that applies cleanly is conforming and
///   the proof is refused.
///
/// `history` is the accused ledger's updates, in any order (the caller
/// supplies the relay history, which nothing has authenticated). The history
/// a chaining fault is judged on is the one its own signed `previous_hash`
/// fixes: walked back by hash links to a genesis that opens this ledger, it
/// is authenticated by the fault's signature alone, so only the fault and the
/// candidates at its predecessor's sequence need a signature check. Index,
/// walk and replay are each linear: about 160 ms for a 100,000-update ledger
/// in a release build, where checking every update's signature took 8.7 s.
///
/// Two limits on what counts, both failing closed:
/// - conformance runs with [`crate::types::AllowAll`]: this crate has no
///   descriptor evaluator, and `DenyAll` would report every honest
///   withdrawal as an `InvalidWitness`. A fault whose only defect is its
///   witness is not proved here;
/// - an update's `block_height` is signed by no one, so violations that turn
///   on heights (expiry, nonce window, fee cadence) are not proof; see
///   `proves_non_conformance`.
///
/// Also `Err`: the fault not signed by the accused, no signed predecessor in
/// the history, a missing link back to genesis, a prefix that does not
/// replay, or a fault whose operation does not decode (an honest operator on
/// newer software may sign an operation this verifier does not know).
///
/// A same-sequence sibling that chains and applies cleanly is not this fault:
/// that is `Equivocation`, which has its own verifier.
pub fn verify_non_conforming_update(
    proof: &FraudProof,
    history: &[crate::types::SignedLedgerUpdate],
) -> Result<(), String> {
    use crate::tlv::TlvDecode;

    let FraudEvidence::NonConformingUpdate {
        fault_sequence,
        fault_update_hex,
    } = &proof.evidence
    else {
        return Err("verify_non_conforming_update: wrong evidence type".into());
    };

    // (1) Decode the inline fault update.
    let bytes =
        hex::decode(fault_update_hex).map_err(|e| format!("fault_update hex decode: {}", e))?;
    let fault = crate::types::SignedLedgerUpdate::tlv_decode(&bytes)
        .map_err(|e| format!("fault_update TLV decode: {:?}", e))?;

    // (2) Redundancy: inline seq matches the evidence seq.
    if fault.sequence_number != *fault_sequence {
        return Err(format!(
            "evidence.fault_sequence {} ≠ fault update's sequence_number {} \
             — redundancy check failed (encoding-corrupted or forged)",
            fault_sequence, fault.sequence_number
        ));
    }

    // (3) The fault update is on the proof's ledger.
    let outer_ledger_bytes =
        hex::decode(&proof.ledger_id).map_err(|e| format!("outer ledger_id hex: {}", e))?;
    if outer_ledger_bytes.len() != 32 || outer_ledger_bytes[..] != fault.ledger_id[..] {
        return Err(format!(
            "outer ledger_id {} ≠ fault update's ledger_id {}",
            &proof.ledger_id[..16.min(proof.ledger_id.len())],
            hex::encode(&fault.ledger_id[..8])
        ));
    }

    // (4) The accused is the operator that signed the fault update. Only
    //     the accused's key could have produced the signature verified at
    //     (5), so this binds the fraud to them (no impersonation).
    let accused_bytes = hex::decode(&proof.accused).map_err(|e| format!("accused hex: {}", e))?;
    if accused_bytes != fault.operator_id.serialize() {
        return Err(format!(
            "outer accused {} ≠ fault update's operator_id {} — impersonation check",
            &proof.accused[..16.min(proof.accused.len())],
            hex::encode(&fault.operator_id.serialize()[..8])
        ));
    }

    // (5) The operator actually signed this update. Without it, anyone could
    //     fabricate "evidence" by writing an arbitrary non-conforming update
    //     and stuffing in zero bytes for operator_signature.
    fault
        .verify_operator_signature()
        .map_err(|e| format!("fault update signature verification: {}", e))?;

    // (6) Defensive: content_hash must be the correct compute_hash(). In
    //     practice the TLV wire format does NOT carry content_hash (it is
    //     re-derived on decode — see SignedLedgerUpdate::tlv_decode), so any
    //     update that travelled the relay already has content_hash ==
    //     compute_hash(); this branch only bites an in-memory update with a
    //     hand-corrupted hash. The load-bearing structural signal is the
    //     previous_hash link checked at (8).
    if fault.content_hash != fault.compute_hash() {
        return Ok(());
    }

    // (6a) seq 0 links to the all-zero previous_hash.
    if fault.sequence_number == 0 {
        // A seq-0 open must link to [0; 32]; anything else is non-conforming.
        return if fault.previous_hash == [0u8; 32] {
            Err("fault update at seq 0 chains onto the zero hash and its \
                 content_hash is valid — conforming, proof not demonstrated"
                .into())
        } else {
            Ok(())
        };
    }

    // (7) Index the accused's updates before the fault (one pass).
    let index = OperatorIndex::new(history, &fault.operator_id, fault.sequence_number);
    let pred_seq = fault.sequence_number - 1;

    // The predecessors: updates at pred_seq that the accused signed. Only
    // these need a signature check: everything before one of them is fixed by
    // the hash chain it commits to.
    let preds: Vec<&crate::types::SignedLedgerUpdate> = index
        .at_seq(pred_seq)
        .filter(|u| u.verify_operator_signature().is_ok())
        .collect();
    if preds.is_empty() {
        return Err(format!(
            "no update by the accused at seq {} in the supplied history — the \
             predecessor can't be established, inconclusive (fail closed)",
            pred_seq
        ));
    }

    // (8) Structural verdict: the fault links to none of the accused's signed
    //     updates at pred_seq, one of which reaches the ledger's genesis. An
    //     honest update at this sequence carries previous_hash ==
    //     predecessor.chain_hash(). (Linking to a signed sibling that is not
    //     the one the chain continued from is Equivocation's domain: it is
    //     judged below on the history it does link to.)
    let Some(linked) = preds
        .iter()
        .find(|p| p.chain_hash() == fault.previous_hash)
    else {
        return if preds
            .iter()
            .any(|p| index.chain_to_genesis(p, &fault.ledger_id).is_ok())
        {
            Ok(())
        } else {
            Err(format!(
                "no signed predecessor at seq {} reaches this ledger's genesis \
                 in the supplied history — inconclusive, fail closed",
                pred_seq
            ))
        };
    };

    // (9) It chains, so it must break a rule. The history it chains onto is
    //     fixed by its own signed previous_hash; replay it from genesis and
    //     apply the fault to the predecessor's state.
    let prefix = index.chain_to_genesis(linked, &fault.ledger_id)?;
    let state = replay_canonical(&prefix)?;
    match fault_rejection(&state, &fault)? {
        Some(_reason) => Ok(()),
        None => Err(format!(
            "fault update at seq {} chains onto its predecessor and applies \
             cleanly with no conformance violation — conforming, proof not \
             demonstrated",
            fault.sequence_number
        )),
    }
}

/// An operator's updates below a sequence, indexed by `chain_hash` and by
/// sequence in one pass. Nothing here checks signatures: a chain walked
/// backwards by `previous_hash` from an update whose signature is checked is
/// fixed by that signature, because each `previous_hash` commits to the
/// predecessor's `chain_hash`, which commits to its `content_hash`, which
/// commits to its sequence, `previous_hash`, operation and cosignatures. The
/// walk is O(n) in hashes; checking every update's signature instead cost
/// ~90 µs each (8.7 s for 100,000 updates).
struct OperatorIndex<'a> {
    by_hash: std::collections::HashMap<[u8; 32], &'a crate::types::SignedLedgerUpdate>,
    by_seq: std::collections::HashMap<u64, Vec<&'a crate::types::SignedLedgerUpdate>>,
}

impl<'a> OperatorIndex<'a> {
    /// `operator`'s updates in `history` with sequence below `below_seq` and
    /// a correct `content_hash`. Where two share a `chain_hash` (copies that
    /// differ only in unhashed envelope fields) the first is kept.
    fn new(
        history: &'a [crate::types::SignedLedgerUpdate],
        operator: &bitcoin::secp256k1::PublicKey,
        below_seq: u64,
    ) -> Self {
        let mut by_hash = std::collections::HashMap::new();
        let mut by_seq: std::collections::HashMap<u64, Vec<_>> = std::collections::HashMap::new();
        for u in history {
            if u.sequence_number < below_seq
                && u.operator_id == *operator
                && u.content_hash == u.compute_hash()
            {
                by_hash.entry(u.chain_hash()).or_insert(u);
                by_seq.entry(u.sequence_number).or_default().push(u);
            }
        }
        OperatorIndex { by_hash, by_seq }
    }

    fn at_seq(&self, seq: u64) -> impl Iterator<Item = &'a crate::types::SignedLedgerUpdate> + '_ {
        self.by_seq.get(&seq).into_iter().flatten().copied()
    }

    /// The chain from the genesis to `tip`, oldest first (element `i` at
    /// sequence `i`), following `previous_hash` back to a seq-0 update that
    /// links to the zero hash and opens `ledger_id`. `Err` when a link is
    /// missing from the history or the genesis opens another ledger.
    fn chain_to_genesis(
        &self,
        tip: &'a crate::types::SignedLedgerUpdate,
        ledger_id: &[u8; 32],
    ) -> Result<Vec<&'a crate::types::SignedLedgerUpdate>, String> {
        use crate::messages::LedgerOperation;
        use crate::tlv::TlvDecode;

        let mut chain = vec![tip];
        while let Some(&last) = chain.last().filter(|u| u.sequence_number > 0) {
            match self.by_hash.get(&last.previous_hash) {
                Some(&p) if p.sequence_number + 1 == last.sequence_number => chain.push(p),
                _ => {
                    return Err(format!(
                        "the update at seq {} links to one not in the supplied \
                         history — inconclusive, fail closed",
                        last.sequence_number
                    ))
                }
            }
        }
        chain.reverse();
        let genesis = chain[0];
        let opens_ledger = genesis.previous_hash == [0u8; 32]
            && matches!(
                LedgerOperation::tlv_decode(&genesis.message),
                Ok(LedgerOperation::LedgerOpen { operator_id, ref reserves_id, genesis_block, .. })
                    if operator_id == genesis.operator_id
                        && crate::types::LedgerState::compute_ledger_id(
                            &operator_id, reserves_id, genesis_block,
                        ) == *ledger_id
            );
        if !opens_ledger {
            return Err("the chain's seq 0 is not this ledger's LedgerOpen by the \
                        accused — inconclusive, fail closed"
                .into());
        }
        Ok(chain)
    }
}

/// The ledger state after `chain` (a chain from genesis), replayed from a
/// fresh state at its seq-0 `LedgerOpen` with the same step as every other
/// replay (`LedgerState::apply_update_in_place`). An update that fails to
/// replay is an error: a verdict on the fault needs the exact state before it.
fn replay_canonical(
    chain: &[&crate::types::SignedLedgerUpdate],
) -> Result<crate::types::LedgerState, String> {
    use crate::messages::LedgerOperation;
    use crate::tlv::TlvDecode;

    let genesis = chain.first().ok_or("empty canonical chain")?;
    let (operator_id, reserves_id, genesis_block) =
        match LedgerOperation::tlv_decode(&genesis.message) {
            Ok(LedgerOperation::LedgerOpen {
                operator_id,
                reserves_id,
                genesis_block,
                ..
            }) => (operator_id, reserves_id, genesis_block),
            _ => return Err("canonical seq 0 is not a LedgerOpen".into()),
        };
    let mut state = crate::types::LedgerState::new(operator_id, reserves_id, genesis_block);
    for u in chain {
        state.apply_update_in_place(u).map_err(|e| {
            format!(
                "canonical history does not replay at seq {}: {} — inconclusive, fail closed",
                u.sequence_number, e
            )
        })?;
    }
    Ok(state)
}

/// Whether a conformance violation proves non-conformance on the signed
/// evidence alone. Not the ones that turn on block heights: an update's
/// `block_height` is covered by neither its `content_hash` nor its operator
/// signature, so anyone relaying a copy can change it, and with it the
/// expiry check (`ExpiryPassed`), the nonce window (`NonceReplay`) and the fee
/// cadence, which starts from the DepositOpen's height (`FeeWindowNotElapsed`,
/// `FeeExceedsAssessment`). Counting those would let a relay frame an honest
/// operator by rewriting a height.
fn proves_non_conformance(v: &crate::types::ConformanceViolation) -> bool {
    use crate::types::ConformanceViolation as V;
    !matches!(
        v,
        V::ExpiryPassed { .. }
            | V::NonceReplay { .. }
            | V::FeeWindowNotElapsed { .. }
            | V::FeeExceedsAssessment { .. }
    )
}

/// Why `fault` may not follow `state`: `Some(reason)` when the state machine
/// refuses its operation or conformance reports a violation that
/// [`proves_non_conformance`], `None` when it applies cleanly. `Err` when its
/// operation does not decode (not judged: fail closed). Conformance runs with
/// `AllowAll` (see [`verify_non_conforming_update`]).
fn fault_rejection(
    state: &crate::types::LedgerState,
    fault: &crate::types::SignedLedgerUpdate,
) -> Result<Option<String>, String> {
    use crate::messages::LedgerOperation;
    use crate::tlv::TlvDecode;

    let op = LedgerOperation::tlv_decode(&fault.message).map_err(|e| {
        format!(
            "fault update at seq {} does not decode ({}) — not judged, fail closed",
            fault.sequence_number, e
        )
    })?;
    Ok(
        match state.apply_with_verifier(&op, &crate::types::AllowAll, fault.block_height) {
            Err(e) => Some(format!("state machine refuses it: {}", e)),
            Ok((_, violations)) => {
                let proving: Vec<_> = violations
                    .into_iter()
                    .filter(proves_non_conformance)
                    .collect();
                (!proving.is_empty()).then(|| format!("conformance violations: {:?}", proving))
            }
        },
    )
}

/// Find an update by `operator` in `history` that a `NonConformingUpdate`
/// proof would ground: its sequence and why. For a node looking for a fault
/// itself (the confiscation resolver), where calling
/// [`verify_non_conforming_update`] once per update would replay the whole
/// history per update.
///
/// Linear: one index, a hash-only scan for signed updates that link to none
/// of the signed updates before them, then one forward replay along the chain
/// ending at the newest signed update that reaches genesis, checking each
/// update on it (and any signed sibling linking into it) against the state
/// before it. The replay applies in place and checks conformance without the
/// pre-state (a subset of the full check, so no clone per update); siblings,
/// which are rare, get the full check on a clone. Whatever it finds is
/// confirmed with [`verify_non_conforming_update`] before it is returned.
/// Structural faults are preferred, newest first; otherwise the first rule
/// break in sequence order.
pub fn find_non_conforming_update(
    history: &[crate::types::SignedLedgerUpdate],
    operator: &bitcoin::secp256k1::PublicKey,
) -> Option<(u64, String)> {
    use crate::tlv::TlvEncode;

    let confirm = |u: &crate::types::SignedLedgerUpdate| -> bool {
        let proof = FraudProof {
            proof_type: FraudProofType::NonConformingUpdate,
            accused: hex::encode(operator.serialize()),
            ledger_id: hex::encode(u.ledger_id),
            evidence: FraudEvidence::NonConformingUpdate {
                fault_sequence: u.sequence_number,
                fault_update_hex: hex::encode(u.tlv_encode()),
            },
        };
        verify_non_conforming_update(&proof, history).is_ok()
    };

    let index = OperatorIndex::new(history, operator, u64::MAX);
    let genesis = index.at_seq(0).next()?;
    let ledger_id = genesis.ledger_id;
    let signed = |u: &&crate::types::SignedLedgerUpdate| u.verify_operator_signature().is_ok();

    // Structural: an update whose sequence has predecessors, none of which it
    // links to. Hash-only filter first; signatures only on what's left.
    let mut breaks: Vec<&crate::types::SignedLedgerUpdate> = history
        .iter()
        .filter(|u| {
            u.operator_id == *operator
                && u.sequence_number >= 1
                && index.by_seq.contains_key(&(u.sequence_number - 1))
                && !index
                    .at_seq(u.sequence_number - 1)
                    .any(|p| p.chain_hash() == u.previous_hash)
        })
        .collect();
    breaks.sort_by_key(|u| std::cmp::Reverse(u.sequence_number));
    if let Some(u) = breaks.into_iter().filter(signed).find(|u| confirm(u)) {
        return Some((
            u.sequence_number,
            "does not chain onto its predecessor".into(),
        ));
    }

    // Rule breaks: the chain to the newest signed update that reaches genesis.
    let mut tips: Vec<&crate::types::SignedLedgerUpdate> = index.by_hash.values().copied().collect();
    tips.sort_by_key(|u| std::cmp::Reverse(u.sequence_number));
    let chain = tips
        .into_iter()
        .filter(signed)
        .find_map(|t| index.chain_to_genesis(t, &ledger_id).ok())?;

    let mut state = replay_canonical(&chain[..1]).ok()?;
    for seq in 1..chain.len() {
        let pred_hash = chain[seq - 1].chain_hash();
        for s in index.at_seq(seq as u64).filter(|s| {
            s.previous_hash == pred_hash && s.chain_hash() != chain[seq].chain_hash()
        }) {
            if signed(&s) {
                if let Ok(Some(reason)) = fault_rejection(&state, s) {
                    if confirm(s) {
                        return Some((seq as u64, reason));
                    }
                }
            }
        }
        let u = chain[seq];
        let op = match state.apply_update_in_place(u) {
            Ok(op) => op,
            Err(e) => {
                // Refused by the state machine (nothing was mutated).
                let reason = format!("state machine refuses it: {}", e);
                return confirm(u).then_some((seq as u64, reason));
            }
        };
        let proving: Vec<_> = state
            .check_conformance(&op, None, &crate::types::AllowAll, u.block_height)
            .into_iter()
            .filter(proves_non_conformance)
            .collect();
        if !proving.is_empty() && confirm(u) {
            return Some((seq as u64, format!("conformance violations: {:?}", proving)));
        }
    }
    None
}

/// Verify a `WinnerCollateralDeviation` claim.
///
/// The accusation: the lottery winner broadcast a claim TX whose shape
/// deviates from the `replacement_collateral` they declared in their
/// `DisputeArmed`. Concretely, one of:
///   - claim TX is single-input (lottery only), skipping the declared
///     replacement input
///   - claim TX has a second input but at a different outpoint than
///     declared
///   - claim TX has the right declared input but routes value away from
///     the new vault (output 0 doesn't match `target_reserves`, or the
///     output value is short of `lottery + declared_amount − reasonable_fee`)
///
/// The verifier needs:
///   1. The claim TX (caller fetches via Esplora)
///   2. A `BlockOracle` to confirm the claim TX's anchor block
///
/// Returns `Ok(())` if the claim TX deviates (= fraud is proven), or
/// `Err(...)` describing why no deviation was demonstrated.
pub fn verify_winner_collateral_deviation(
    proof: &FraudProof,
    claim_tx: &bitcoin::Transaction,
    lottery_amount_sats: u64,
    block_oracle: &dyn BlockOracle,
) -> Result<(), String> {
    use crate::messages::LedgerOperation;
    use crate::tlv::TlvDecode;

    let FraudEvidence::WinnerCollateralDeviation {
        winner_armed_update_hex,
        claim_txid,
        claim_block_hash,
    } = &proof.evidence
    else {
        return Err("verify_winner_collateral_deviation: wrong evidence type".into());
    };

    // (1) anchor block confirmed in verifier's chain.
    block_oracle.confirms(claim_block_hash).ok_or_else(|| {
        format!(
            "claim_block_hash {} not in verifier's confirmed chain",
            hex::encode(&claim_block_hash[..8])
        )
    })?;

    // (2) claim_tx's txid matches the claimed value (binds the proof to
    //     the on-chain TX).
    let actual_txid = claim_tx.compute_txid().to_string();
    if actual_txid != *claim_txid {
        return Err(format!(
            "claim TX txid mismatch: proof claims {}, supplied tx is {}",
            claim_txid, actual_txid
        ));
    }

    // (3) decode the winner's signed armed update and extract their
    //     declared replacement_collateral + target_reserves.
    let armed_bytes = hex::decode(winner_armed_update_hex)
        .map_err(|e| format!("winner_armed_update_hex: {}", e))?;
    let armed = crate::types::SignedLedgerUpdate::tlv_decode(&armed_bytes)
        .map_err(|e| format!("winner_armed_update decode: {}", e))?;
    let armed_op = LedgerOperation::tlv_decode(&armed.message)
        .map_err(|e| format!("winner_armed_update operation decode: {}", e))?;
    let (target_reserves, declared) = match armed_op {
        LedgerOperation::DisputeArmed {
            target_reserves,
            replacement_collateral,
            ..
        } => (target_reserves, replacement_collateral),
        _ => {
            return Err("winner_armed_update operation is not DisputeArmed".into());
        }
    };
    let declared = declared.ok_or_else(|| {
        "winner declared no replacement_collateral — there's nothing for \
         the claim TX to deviate from"
            .to_string()
    })?;

    // (4) inspect claim TX inputs. The claim TX must consume the declared
    //     outpoint as one of its inputs. If it doesn't, that's deviation.
    let declared_outpoint_present = claim_tx.input.iter().any(|txin| {
        let prev_txid_bytes: [u8; 32] = *txin.previous_output.txid.as_ref();
        prev_txid_bytes == declared.txid && txin.previous_output.vout == declared.vout
    });
    if !declared_outpoint_present {
        return Ok(()); // deviation: declared input missing
    }

    // (5) inspect claim TX outputs. Output 0 must route to the declared
    //     `target_reserves` address.
    let target_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = target_reserves
        .parse()
        .map_err(|e| format!("target_reserves not a valid address: {}", e))?;
    // Compare scriptPubKey-byte-for-byte against output 0. We compare via
    // assume_checked() to skip network validation — the verifier's chain
    // tells us the network indirectly via BlockOracle, and the same script
    // bytes encode the same output regardless.
    let target_script = target_addr.assume_checked().script_pubkey();
    let output_0 = claim_tx
        .output
        .first()
        .ok_or_else(|| "claim TX has no outputs".to_string())?;
    if output_0.script_pubkey != target_script {
        return Ok(()); // deviation: output 0 routes elsewhere
    }

    // (6) the output value should reflect both the lottery amount and
    //     the declared replacement amount, minus a reasonable fee budget.
    //     If output 0 is materially short, value was siphoned away.
    //
    //     We're generous on the fee budget here (10_000 sats covers any
    //     realistic claim TX vsize) — the goal is to catch *material*
    //     deviation, not nitpick fee surplus.
    let max_fee_budget_sats: u64 = 10_000;
    let expected_min = lottery_amount_sats
        .saturating_add(declared.amount)
        .saturating_sub(max_fee_budget_sats);
    let output_0_sats = output_0.value.to_sat();
    if output_0_sats < expected_min {
        return Ok(()); // deviation: value siphoned
    }

    // No deviation observed.
    Err(
        "claim TX matches the declared replacement_collateral and target_reserves; \
         no deviation found"
            .into(),
    )
}

/// Verify an `UncreditedOnchainPayment` claim.
///
/// The accusation: a cosigned offer was issued, a Bitcoin tx funded the
/// offer's address with sufficient confirmations, and the operator
/// signed at least one further update without crediting the deposit.
///
/// Checks:
///   1. `confirmed_at_block_hash` is in the verifier's confirmed chain.
///   2. The accused has a SignedLedgerUpdate at `proof_sequence`. Its
///      `block_hash` is also confirmed via the oracle.
///   3. The proof-sequence block is at least `required_confirmations`
///      blocks past the funding block (proves operator saw enough confs
///      before signing).
///   4. No `OnchainCredit` for `(txid, vout)` in accused history at
///      sequence ≤ `proof_sequence` (operator did not credit).
///
/// Cosignature signature validity over the offer is intentionally NOT
/// checked here — same caveat as `verify_uncredited_lightning`.
pub fn verify_uncredited_onchain(
    proof: &FraudProof,
    accused_history: &[crate::types::SignedLedgerUpdate],
    block_oracle: &dyn BlockOracle,
) -> Result<(), String> {
    use crate::messages::LedgerOperation;
    use crate::tlv::TlvDecode;

    let FraudEvidence::UncreditedOnchain {
        offer_id,
        funding_address,
        accused_operator_pubkey,
        deadline_block,
        cosigner_pubkey,
        cosigner_ledger_hash,
        cosign_signature,
        txid,
        vout,
        amount_sats: _,
        confirmed_at_block_hash,
        required_confirmations,
        proof_sequence,
    } = &proof.evidence
    else {
        return Err("verify_uncredited_onchain: wrong evidence type".into());
    };

    let txid_bytes = parse_hex32(txid, "txid")?;
    let offer_id_bytes = parse_hex32(offer_id, "offer_id")?;
    let cosigner_ledger_hash_bytes = parse_hex32(cosigner_ledger_hash, "cosigner_ledger_hash")?;

    // (0) cosignature on the offer is a valid BIP-340 schnorr sig from
    //     cosigner_pubkey over the canonical offer signing message.
    {
        use bitcoin::secp256k1::{schnorr::Signature, Message, PublicKey, Secp256k1};
        use std::str::FromStr;

        let accused_op_pk = PublicKey::from_str(accused_operator_pubkey)
            .map_err(|e| format!("invalid accused_operator_pubkey: {}", e))?;
        let cosigner_pk = PublicKey::from_str(cosigner_pubkey)
            .map_err(|e| format!("invalid cosigner_pubkey: {}", e))?;
        let sig_bytes = hex::decode(cosign_signature)
            .map_err(|e| format!("cosign_signature hex decode: {}", e))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "cosign_signature: expected 64 bytes".to_string())?;
        let sig = Signature::from_slice(&sig_arr)
            .map_err(|e| format!("cosign_signature parse: {}", e))?;

        let msg_hash = crate::signature_utils::offer_cosign_signing_message(
            &proof.ledger_id,
            &offer_id_bytes,
            &accused_op_pk,
            funding_address,
            *deadline_block,
            &cosigner_ledger_hash_bytes,
        );
        let msg = Message::from_digest(msg_hash);
        let (xonly, _) = cosigner_pk.x_only_public_key();

        if Secp256k1::verification_only()
            .verify_schnorr(&sig, &msg, &xonly)
            .is_err()
        {
            return Err(format!(
                "offer cosignature failed BIP-340 verification (cosigner {})",
                hex::encode(&cosigner_pk.serialize()[..8])
            ));
        }
    }

    // (1) confirmed-at block in the verifier's chain.
    let confirmed_height = block_oracle
        .confirms(confirmed_at_block_hash)
        .ok_or_else(|| {
            format!(
                "confirmed_at_block_hash {} not in verifier's confirmed chain",
                hex::encode(&confirmed_at_block_hash[..8])
            )
        })?;

    // (2) proof_sequence update exists, and its block_hash is confirmed.
    let proof_update = accused_history
        .iter()
        .find(|u| u.sequence_number == *proof_sequence)
        .ok_or_else(|| format!("proof_sequence {} not in accused history", proof_sequence))?;
    let proof_height = block_oracle
        .confirms(&proof_update.block_hash)
        .ok_or_else(|| {
            format!(
                "proof_sequence update's block_hash {} not in verifier's confirmed chain",
                hex::encode(&proof_update.block_hash[..8])
            )
        })?;

    // (3) operator saw at least required_confirmations confs before signing.
    let elapsed = proof_height.saturating_sub(confirmed_height);
    if elapsed < *required_confirmations {
        return Err(format!(
            "proof_sequence block {} only {} blocks past funding block {}; need {} confs",
            proof_height, elapsed, confirmed_height, required_confirmations
        ));
    }

    // (4) no OnchainCredit for this (txid, vout) at seq ≤ proof_sequence.
    //     Recurses into Batch so a batched credit isn't hidden.
    fn check_op(
        op: &LedgerOperation,
        seq: u64,
        txid_bytes: [u8; 32],
        vout: u32,
    ) -> Result<(), String> {
        match op {
            LedgerOperation::OnchainCredit {
                txid: credit_txid,
                vout: credit_vout,
                ..
            } if *credit_txid == txid_bytes && *credit_vout == vout => Err(format!(
                "OnchainCredit found at seq {} — operator did credit, not fraud",
                seq
            )),
            LedgerOperation::Batch(inner_ops) => {
                for inner in inner_ops {
                    check_op(inner, seq, txid_bytes, vout)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    for u in accused_history
        .iter()
        .filter(|u| u.sequence_number <= *proof_sequence)
    {
        let Ok(op) = LedgerOperation::tlv_decode(&u.message) else {
            continue;
        };
        check_op(&op, u.sequence_number, txid_bytes, *vout)?;
    }

    Ok(())
}

// ============================================================================
// The Broadcast (proof + causal chain, constructed after embedding)
// ============================================================================

/// A fraud proof broadcast containing the proof and the causal chain
/// proving it was embedded before being revealed.
///
/// Broadcast as a Kind 9101 Nostr event. Verifiers walk the chain
/// without needing to search for anything.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudBroadcast {
    /// The fraud proof (hashable evidence).
    pub proof: FraudProof,
    /// Where the proof hash was embedded. Required for proof types that
    /// [`FraudProofType::requires_embedding`]; optional, and ignored by
    /// verification, for self-evident types. Absent (or `null`) on the
    /// wire when `None`; the reference omits the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding: Option<ProofEmbedding>,
    /// Causal chain from the embedding to the accused operator's ledger.
    /// Each link is a co-signed update that entangles one ledger into another.
    /// Empty if embedded directly on the operator's ledger.
    /// One entry if embedded on a quorum member's ledger (the co-signature
    /// on the operator's ledger that includes the member's hash).
    /// Multiple entries for longer paths through the web.
    /// Defaults to empty when absent (self-evident proofs have none).
    #[serde(default)]
    pub causal_chain: Vec<CausalLink>,
}

/// Where the proof hash was embedded in a ledger.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofEmbedding {
    /// The ledger the hash was embedded in.
    pub ledger_id: String,
    /// Sequence number of the update containing the hash.
    pub sequence: u64,
    /// The content_hash of that update.
    pub update_hash: String,
    /// Which field contains the proof hash (e.g., "transfer_nonce").
    pub field: String,
}

impl ProofEmbedding {
    /// Verify the claimed `proof_hash` is bound into the update at this
    /// embedding's `(ledger_id, sequence)`. Returns true iff the update
    /// is present in `history` at the claimed sequence and its operation
    /// embeds the hash in a field supported by
    /// [`LedgerOperation::embedded_hash`].
    ///
    /// `history` is the caller-provided update list for this embedding's
    /// `ledger_id` — extracted by the caller so this remains a pure
    /// function with no dependency on a ledger registry.
    pub fn verify_in_history(
        &self,
        history: &[crate::types::SignedLedgerUpdate],
        proof_hash: &[u8; 32],
    ) -> bool {
        use crate::messages::LedgerOperation;
        use crate::tlv::TlvDecode;
        history.iter().any(|u| {
            if u.sequence_number != self.sequence {
                return false;
            }
            LedgerOperation::tlv_decode(&u.message)
                .ok()
                .and_then(|op| op.embedded_hash().copied())
                .map(|h| h == *proof_hash)
                .unwrap_or(false)
        })
    }
}

/// A single link in the causal chain.
///
/// Each link is a co-signed update on one ledger that includes
/// `member_ledger_hash` from another ledger, proving temporal ordering.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CausalLink {
    /// The ledger this co-signed update is on.
    pub ledger_id: String,
    /// Sequence number.
    pub sequence: u64,
    /// The content_hash of this update.
    pub update_hash: String,
    /// The member_ledger_hash included in the co-signature.
    /// This hash is from the previous link's ledger (or the embedding ledger).
    pub member_ledger_hash: String,
    /// Which ledger the member_ledger_hash came from.
    pub source_ledger_id: String,
}

/// Provider for ledger histories, supplied by the verifying daemon (or
/// a test mock). Lookups return `None` for unknown ledger IDs.
pub trait LedgerProvider {
    fn ledger_history(&self, ledger_id: &str) -> Option<Vec<crate::types::SignedLedgerUpdate>>;
}

impl<F> LedgerProvider for F
where
    F: Fn(&str) -> Option<Vec<crate::types::SignedLedgerUpdate>>,
{
    fn ledger_history(&self, ledger_id: &str) -> Option<Vec<crate::types::SignedLedgerUpdate>> {
        self(ledger_id)
    }
}

/// Top-level fraud-broadcast verifier. Composes:
///   1. Structural sanity (`verify_chain_structure`).
///   2. Embedding presence in the claimed ledger history.
///   3. Causal-link presence at the claimed (ledger, sequence,
///      member_ledger_hash) on each link's ledger.
///   4. Per-type evidence verification (the actual fraud claim).
///
/// Steps 1-3 run only for proof types that
/// [`FraudProofType::requires_embedding`]. A self-evident proof is its own
/// cryptographic evidence of non-conformity, so its embedding (absent, a
/// placeholder, or real) and causal chain are ignored; step 4 always runs.
///
/// Returns `Ok(())` if every applicable layer passes — the broadcast
/// represents real, attributable fraud. Returns the first failure
/// otherwise.
pub fn verify_fraud_broadcast(
    broadcast: &FraudBroadcast,
    ledgers: &dyn LedgerProvider,
    block_oracle: &dyn BlockOracle,
) -> Result<(), String> {
    if broadcast.proof.proof_type.requires_embedding() {
        verify_embedding_and_causal_chain(broadcast, ledgers)?;
    }
    verify_fraud_evidence(&broadcast.proof, ledgers, block_oracle)
}

/// Steps 1-3 of [`verify_fraud_broadcast`]: the broadcast's embedding is
/// present, sits at the claimed sequence of the claimed ledger, and every
/// causal link is present on its ledger.
fn verify_embedding_and_causal_chain(
    broadcast: &FraudBroadcast,
    ledgers: &dyn LedgerProvider,
) -> Result<(), String> {
    // (1) structural (also rejects a missing embedding)
    broadcast.verify_chain_structure()?;
    let embedding = broadcast.embedding.as_ref().ok_or_else(|| {
        format!(
            "{:?} requires an embedding (DEP-06)",
            broadcast.proof.proof_type
        )
    })?;

    let proof_hash = broadcast.proof.proof_hash();

    // (2) embedding in claimed ledger
    let embed_history = ledgers
        .ledger_history(&embedding.ledger_id)
        .ok_or_else(|| {
            format!(
                "embedding ledger {} not available to verifier",
                &embedding.ledger_id[..16.min(embedding.ledger_id.len())]
            )
        })?;
    if !embedding.verify_in_history(&embed_history, &proof_hash) {
        return Err(format!(
            "proof_hash {} not embedded at seq {} on ledger {}",
            hex::encode(&proof_hash[..8]),
            embedding.sequence,
            &embedding.ledger_id[..16.min(embedding.ledger_id.len())]
        ));
    }

    // (3) every causal-chain link is present in its ledger.
    for link in &broadcast.causal_chain {
        let history = ledgers.ledger_history(&link.ledger_id).ok_or_else(|| {
            format!(
                "link ledger {} not available to verifier",
                &link.ledger_id[..16.min(link.ledger_id.len())]
            )
        })?;
        let link_ok = history.iter().any(|u| {
            u.sequence_number == link.sequence
                && u.member_ledger_hash.map(hex::encode) == Some(link.member_ledger_hash.clone())
        });
        if !link_ok {
            return Err(format!(
                "causal link not found at seq {} on ledger {}",
                link.sequence,
                &link.ledger_id[..16.min(link.ledger_id.len())]
            ));
        }
    }
    Ok(())
}

/// Step 4 of [`verify_fraud_broadcast`]: the per-type evidence check, which
/// runs for every proof type, self-evident or not.
pub fn verify_fraud_evidence(
    proof: &FraudProof,
    ledgers: &dyn LedgerProvider,
    block_oracle: &dyn BlockOracle,
) -> Result<(), String> {
    match proof.proof_type {
        FraudProofType::StaleCosignature => {
            let FraudEvidence::StaleCosign {
                member_ledger_id, ..
            } = &proof.evidence
            else {
                return Err("StaleCosignature: wrong evidence type".into());
            };
            let accused_history = ledgers.ledger_history(&proof.ledger_id).ok_or_else(|| {
                format!(
                    "accused ledger {} not available",
                    &proof.ledger_id[..16.min(proof.ledger_id.len())]
                )
            })?;
            let member_history = ledgers.ledger_history(member_ledger_id).ok_or_else(|| {
                format!(
                    "member ledger {} not available",
                    &member_ledger_id[..16.min(member_ledger_id.len())]
                )
            })?;
            verify_stale_cosignature(proof, &accused_history, &member_history)?;
        }
        FraudProofType::UncreditedLightningPayment => {
            let accused_history = ledgers.ledger_history(&proof.ledger_id).ok_or_else(|| {
                format!(
                    "accused ledger {} not available",
                    &proof.ledger_id[..16.min(proof.ledger_id.len())]
                )
            })?;
            verify_uncredited_lightning(proof, &accused_history)?;
        }
        FraudProofType::DisputeDereliction => {
            let FraudEvidence::DisputeDereliction {
                member_ledger_id, ..
            } = &proof.evidence
            else {
                return Err("DisputeDereliction: wrong evidence type".into());
            };
            let member_history = ledgers.ledger_history(member_ledger_id).ok_or_else(|| {
                format!(
                    "member ledger {} not available",
                    &member_ledger_id[..16.min(member_ledger_id.len())]
                )
            })?;
            verify_inactive_quorum_member(proof, &member_history, block_oracle)?;
        }
        FraudProofType::UncreditedOnchainPayment => {
            let accused_history = ledgers.ledger_history(&proof.ledger_id).ok_or_else(|| {
                format!(
                    "accused ledger {} not available",
                    &proof.ledger_id[..16.min(proof.ledger_id.len())]
                )
            })?;
            verify_uncredited_onchain(proof, &accused_history, block_oracle)?;
        }
        FraudProofType::NonConformingUpdate => {
            // The accused operator BIP-340-signed an update on their own ledger
            // that doesn't chain onto the canonical tip, or chains but is
            // refused by the state machine or conformance on the replayed
            // canonical state. Fails closed if the update applies cleanly or
            // the predecessor's state can't be established.
            let accused_history = ledgers.ledger_history(&proof.ledger_id).ok_or_else(|| {
                format!(
                    "accused ledger {} not available",
                    &proof.ledger_id[..16.min(proof.ledger_id.len())]
                )
            })?;
            verify_non_conforming_update(proof, &accused_history)?;
        }
        FraudProofType::QuorumExpired => {
            let accused_history = ledgers.ledger_history(&proof.ledger_id).ok_or_else(|| {
                format!(
                    "accused ledger {} not available",
                    &proof.ledger_id[..16.min(proof.ledger_id.len())]
                )
            })?;
            verify_quorum_expired(proof, &accused_history, block_oracle)?;
        }
        FraudProofType::WinnerCollateralDeviation => {
            // Verifying a deviation requires the on-chain claim TX (not
            // available at this layer). The daemon-side wrapper fetches
            // the TX via Esplora and calls `verify_winner_collateral_deviation`
            // directly. Top-level broadcast verification accepts at this
            // layer, so every caller that acts on a WinnerCollateralDeviation
            // broadcast must run that on-chain step too: the type is
            // self-evident, so no embedding check stands in for it.
        }
        FraudProofType::Equivocation => {
            // Self-contained — both updates are inline in the evidence,
            // no relay/oracle/cosigner-ledger lookup needed.
            verify_equivocation(proof)?;
        }
        FraudProofType::NonConformingCosignature => {
            let FraudEvidence::NonConformingCosignature {
                fault_ledger_id, ..
            } = &proof.evidence
            else {
                return Err("NonConformingCosignature: wrong evidence type".into());
            };
            let fault_history = ledgers.ledger_history(fault_ledger_id).ok_or_else(|| {
                format!(
                    "fault ledger {} not available",
                    &fault_ledger_id[..16.min(fault_ledger_id.len())]
                )
            })?;
            // Top-level entry uses DenyAll. Descriptor-bound conformance
            // checks may over-report, but every NonConforming fault
            // pattern worth disputing (ExceedsCollateral, ZeroAmount,
            // InsufficientReserves, sequence/chain breaks) fires
            // independent of the authorizer — and over-reporting on
            // *honest* updates can't happen here because the cosigners
            // only land updates that pass their own conformance check,
            // so an honest update won't fire any violation regardless
            // of authorizer choice.
            verify_non_conforming_cosignature(proof, &fault_history, &crate::types::DenyAll)?;
        }
    }

    Ok(())
}

impl FraudBroadcast {
    /// Verify the causal chain integrity.
    ///
    /// Checks that each link's `member_ledger_hash` could follow from the
    /// previous link (or embedding). Does NOT verify signatures — that
    /// requires fetching the actual updates from relays.
    ///
    /// A self-evident proof type ([`FraudProofType::is_self_evident`]) needs
    /// no embedding or chain, so it passes whatever they hold. An
    /// embedding-required type without an embedding fails.
    pub fn verify_chain_structure(&self) -> Result<(), String> {
        if self.proof.proof_type.is_self_evident() {
            return Ok(());
        }
        let Some(embedding) = self.embedding.as_ref() else {
            return Err(format!(
                "{:?} requires an embedding (DEP-06)",
                self.proof.proof_type
            ));
        };

        // If direct embedding on the accused ledger, chain should be empty
        if embedding.ledger_id == self.proof.ledger_id {
            if !self.causal_chain.is_empty() {
                return Err("Direct embedding should have empty causal chain".to_string());
            }
            return Ok(());
        }

        // Chain must connect embedding ledger to accused ledger
        if self.causal_chain.is_empty() {
            return Err("Indirect embedding requires at least one causal link".to_string());
        }

        // First link must reference the embedding ledger
        let first = &self.causal_chain[0];
        if first.source_ledger_id != embedding.ledger_id {
            return Err(format!(
                "First causal link source {} doesn't match embedding ledger {}",
                first.source_ledger_id, embedding.ledger_id
            ));
        }

        // Each subsequent link must chain from the previous
        for i in 1..self.causal_chain.len() {
            let prev = &self.causal_chain[i - 1];
            let curr = &self.causal_chain[i];
            if curr.source_ledger_id != prev.ledger_id {
                return Err(format!(
                    "Causal link {} source {} doesn't match previous link ledger {}",
                    i, curr.source_ledger_id, prev.ledger_id
                ));
            }
        }

        // Last link must be on the accused operator's ledger
        let last = &self.causal_chain.last().unwrap();
        if last.ledger_id != self.proof.ledger_id {
            return Err(format!(
                "Last causal link ledger {} doesn't reach accused ledger {}",
                last.ledger_id, self.proof.ledger_id
            ));
        }

        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

impl FraudProofType {
    pub fn discriminant(&self) -> u8 {
        match self {
            Self::UncreditedOnchainPayment => 1,
            Self::UncreditedLightningPayment => 2,
            Self::StaleCosignature => 3,
            Self::DisputeDereliction => 4,
            Self::NonConformingUpdate => 5,
            Self::QuorumExpired => 6,
            Self::WinnerCollateralDeviation => 7,
            Self::Equivocation => 8,
            Self::NonConformingCosignature => 9,
        }
    }
}

impl FraudEvidence {
    /// Canonical bytes for hashing — key fields that uniquely identify this evidence.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::UncreditedOnchain {
                offer_id,
                deadline_block,
                txid,
                vout,
                amount_sats,
                confirmed_at_block_hash,
                ..
            } => {
                out.extend_from_slice(offer_id.as_bytes());
                out.extend_from_slice(&deadline_block.to_le_bytes());
                out.extend_from_slice(txid.as_bytes());
                out.extend_from_slice(&vout.to_le_bytes());
                out.extend_from_slice(&amount_sats.to_le_bytes());
                out.extend_from_slice(confirmed_at_block_hash);
            }
            Self::UncreditedLightning {
                payment_hash,
                deposit_id,
                amount_msat,
                preimage,
                ..
            } => {
                out.extend_from_slice(payment_hash.as_bytes());
                out.extend_from_slice(deposit_id);
                out.extend_from_slice(&amount_msat.to_le_bytes());
                out.extend_from_slice(preimage.as_bytes());
            }
            Self::StaleCosign {
                stale_update_hash,
                declared_member_hash,
                member_later_hash,
                ..
            } => {
                out.extend_from_slice(stale_update_hash.as_bytes());
                out.extend_from_slice(declared_member_hash.as_bytes());
                out.extend_from_slice(member_later_hash.as_bytes());
            }
            Self::DisputeDereliction {
                original_fraud_hash,
                original_fraud_block_hash,
                member_ledger_id,
                member_pubkey,
                ..
            } => {
                out.extend_from_slice(original_fraud_hash.as_bytes());
                out.extend_from_slice(original_fraud_block_hash);
                out.extend_from_slice(member_ledger_id.as_bytes());
                out.extend_from_slice(member_pubkey.as_bytes());
            }
            Self::NonConforming {
                sequence,
                update_b64,
                violation,
                ..
            } => {
                out.extend_from_slice(&sequence.to_le_bytes());
                out.extend_from_slice(update_b64.as_bytes());
                out.extend_from_slice(violation.as_bytes());
            }
            Self::QuorumExpired {
                anchor_block_hash,
                quorum_expiry,
            } => {
                out.extend_from_slice(anchor_block_hash);
                out.extend_from_slice(&quorum_expiry.to_le_bytes());
            }
            Self::WinnerCollateralDeviation {
                winner_armed_update_hex,
                claim_txid,
                claim_block_hash,
            } => {
                out.extend_from_slice(winner_armed_update_hex.as_bytes());
                out.extend_from_slice(claim_txid.as_bytes());
                out.extend_from_slice(claim_block_hash);
            }
            Self::Equivocation {
                sequence,
                update_a_hex,
                update_b_hex,
            } => {
                out.extend_from_slice(&sequence.to_le_bytes());
                // Hash the two updates in sort order so the proof_hash
                // is stable regardless of which update the prover
                // happened to put first.
                let (lo, hi) = if update_a_hex <= update_b_hex {
                    (update_a_hex, update_b_hex)
                } else {
                    (update_b_hex, update_a_hex)
                };
                out.extend_from_slice(lo.as_bytes());
                out.extend_from_slice(hi.as_bytes());
            }
            Self::NonConformingCosignature {
                fault_ledger_id,
                fault_sequence,
                governing_quorumbegin_seq,
                fault_update_hex,
            } => {
                out.extend_from_slice(fault_ledger_id.as_bytes());
                out.extend_from_slice(&fault_sequence.to_le_bytes());
                out.extend_from_slice(&governing_quorumbegin_seq.to_le_bytes());
                out.extend_from_slice(fault_update_hex.as_bytes());
            }
            Self::NonConformingUpdate {
                fault_sequence,
                fault_update_hex,
            } => {
                out.extend_from_slice(&fault_sequence.to_le_bytes());
                out.extend_from_slice(fault_update_hex.as_bytes());
            }
        }
        out
    }
}

/// Nostr event kind for fraud proof broadcasts.
pub const KIND_FRAUD_PROOF: u16 = 9101;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proof() -> FraudProof {
        FraudProof {
            proof_type: FraudProofType::UncreditedOnchainPayment,
            accused: "02".to_string() + &"ab".repeat(32),
            ledger_id: "aa".repeat(32),
            evidence: FraudEvidence::UncreditedOnchain {
                offer_id: "bb".repeat(16),
                funding_address: "bcrt1qtest".to_string(),
                accused_operator_pubkey: "02".to_string() + &"ab".repeat(32),
                deadline_block: 600,
                cosigner_pubkey: "02".to_string() + &"cc".repeat(32),
                cosigner_ledger_hash: "00".repeat(32),
                cosign_signature: "dd".repeat(32),
                txid: "ee".repeat(32),
                vout: 0,
                amount_sats: 100_000,
                confirmed_at_block_hash: [0xAA; 32],
                required_confirmations: 6,
                proof_sequence: 42,
            },
        }
    }

    #[test]
    fn proof_hash_is_deterministic() {
        let proof = make_proof();
        let h1 = proof.proof_hash();
        let h2 = proof.proof_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn different_evidence_different_hash() {
        let mut p1 = make_proof();
        let p2 = make_proof();
        if let FraudEvidence::UncreditedOnchain {
            ref mut amount_sats,
            ..
        } = p1.evidence
        {
            *amount_sats = 200_000;
        }
        assert_ne!(p1.proof_hash(), p2.proof_hash());
    }

    #[test]
    fn direct_embedding_empty_chain_valid() {
        let proof = make_proof();
        let broadcast = FraudBroadcast {
            embedding: Some(ProofEmbedding {
                ledger_id: proof.ledger_id.clone(), // same as accused
                sequence: 50,
                update_hash: "ff".repeat(32),
                field: "transfer_nonce".to_string(),
            }),
            causal_chain: vec![],
            proof,
        };
        assert!(broadcast.verify_chain_structure().is_ok());
    }

    #[test]
    fn one_hop_chain_valid() {
        let proof = make_proof();
        let member_ledger = "11".repeat(32);
        let broadcast = FraudBroadcast {
            embedding: Some(ProofEmbedding {
                ledger_id: member_ledger.clone(), // embedded on member's ledger
                sequence: 10,
                update_hash: "22".repeat(32),
                field: "transfer_nonce".to_string(),
            }),
            causal_chain: vec![CausalLink {
                ledger_id: proof.ledger_id.clone(), // operator's ledger
                sequence: 55,
                update_hash: "33".repeat(32),
                member_ledger_hash: "44".repeat(32),
                source_ledger_id: member_ledger.clone(), // from member's ledger
            }],
            proof,
        };
        assert!(broadcast.verify_chain_structure().is_ok());
    }

    #[test]
    fn indirect_embedding_missing_chain_rejected() {
        let proof = make_proof();
        let broadcast = FraudBroadcast {
            embedding: Some(ProofEmbedding {
                ledger_id: "11".repeat(32), // different from accused
                sequence: 10,
                update_hash: "22".repeat(32),
                field: "transfer_nonce".to_string(),
            }),
            causal_chain: vec![],
            proof,
        };
        assert!(broadcast.verify_chain_structure().is_err());
    }

    #[test]
    fn chain_not_reaching_accused_rejected() {
        let proof = make_proof();
        let broadcast = FraudBroadcast {
            embedding: Some(ProofEmbedding {
                ledger_id: "11".repeat(32),
                sequence: 10,
                update_hash: "22".repeat(32),
                field: "transfer_nonce".to_string(),
            }),
            causal_chain: vec![CausalLink {
                ledger_id: "99".repeat(32), // wrong — doesn't reach accused
                sequence: 55,
                update_hash: "33".repeat(32),
                member_ledger_hash: "44".repeat(32),
                source_ledger_id: "11".repeat(32),
            }],
            proof,
        };
        assert!(broadcast.verify_chain_structure().is_err());
    }

    #[test]
    fn two_hop_chain_valid() {
        let proof = make_proof();
        let ledger_a = "11".repeat(32);
        let ledger_b = "22".repeat(32);
        let broadcast = FraudBroadcast {
            embedding: Some(ProofEmbedding {
                ledger_id: ledger_a.clone(),
                sequence: 10,
                update_hash: "ff".repeat(32),
                field: "transfer_nonce".to_string(),
            }),
            causal_chain: vec![
                // ledger_b co-signed update includes ledger_a's hash
                CausalLink {
                    ledger_id: ledger_b.clone(),
                    sequence: 20,
                    update_hash: "ee".repeat(32),
                    member_ledger_hash: "dd".repeat(32),
                    source_ledger_id: ledger_a.clone(),
                },
                // operator's ledger co-signed update includes ledger_b's hash
                CausalLink {
                    ledger_id: proof.ledger_id.clone(),
                    sequence: 30,
                    update_hash: "cc".repeat(32),
                    member_ledger_hash: "bb".repeat(32),
                    source_ledger_id: ledger_b.clone(),
                },
            ],
            proof,
        };
        assert!(broadcast.verify_chain_structure().is_ok());
    }
}
