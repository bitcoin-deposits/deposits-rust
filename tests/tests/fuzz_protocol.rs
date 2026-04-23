//! Protocol-in-a-box adversarial fuzzer.
//!
//! Simulates N operators running the full protocol flow (propose → co-sign →
//! apply → watch) in-process, with some operators controlled by an adversary.
//! The fuzzer generates random operation sequences and asks: can the adversary
//! ever profit?
//!
//! Profit = funds stolen from operators where the adversary has co-signer
//! majority, minus collateral slashed on adversary operators where honest
//! members catch them.
//!
//! See plan: /home/claude/.claude/plans/recursive-booping-cosmos.md

use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use deposits_core::descriptor::CoreWitnessVerifier;
use deposits_core::ledger::{Ledger, LedgerProtocolState, LedgerRole};
use deposits_core::operation_validation as op_val;
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::signature_utils;
use deposits_protocol::types::*;
use std::collections::{HashMap, HashSet};

// =========================================================================
// PRNG
// =========================================================================

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn range(&mut self, max: u64) -> u64 {
        self.next() % max.max(1)
    }
    #[allow(dead_code)]
    fn chance(&mut self, numerator: u64, denominator: u64) -> bool {
        self.range(denominator) < numerator
    }
}

// =========================================================================
// Keys
// =========================================================================

fn keypair(seed: u16) -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut bytes = [0u8; 32];
    bytes[0] = (seed & 0xff) as u8;
    bytes[1] = (seed >> 8) as u8;
    bytes[31] = 0x42;
    let sk = SecretKey::from_slice(&bytes).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    (sk, pk)
}

// =========================================================================
// Simulation types
// =========================================================================

/// A single operator in the simulation. Each one has their own ledger plus
/// replicas of every ledger where they're a quorum member.
struct SimOperator {
    #[allow(dead_code)]
    idx: usize,
    #[allow(dead_code)]
    secret_key: SecretKey,
    public_key: PublicKey,
    /// Our own ledger — what we authoritatively publish.
    ledger: Ledger,
    /// Replicas of ledgers we co-sign for (keyed by owning operator's idx).
    replicas: HashMap<usize, LedgerState>,
    /// Indices of operators we chose as quorum members.
    quorum_members: Vec<usize>,
    /// Deposits we've opened on our own ledger: (id, descriptor, owning-depositor-idx).
    deposits: Vec<(DepositId, String, u16)>,
    /// Secret keys of the depositors (by deposit id) — used to sign TransferLock
    /// witnesses honestly. Adversary generators can ignore these.
    depositor_keys: HashMap<DepositId, SecretKey>,
    /// Pending transfers we've originated locally, with the preimage the
    /// completion_script commits to — used to generate honest TransferComplete.
    pending_preimages: HashMap<[u8; 32], [u8; 32]>,
    /// Open invoice locks we originated, keyed by payment_id → preimage. Used
    /// to generate honest InvoiceFulfill with the correct preimage.
    open_invoice_preimages: HashMap<[u8; 32], [u8; 32]>,
    /// Open on-chain withdrawals we originated, keyed by withdrawal_id →
    /// (amount, deposit_id, destination_address). Used to generate honest
    /// OnchainFulfill / OnchainFail that reference a real pending withdrawal.
    open_withdrawals: HashMap<[u8; 32], (u64, DepositId, String)>,
    /// For each victim's ledger we're watching, the pubkeys of operators we've
    /// observed publish DisputeArmed. Used to validate the entropy-selected
    /// winner when a DisputeAcquire arrives — matches the real-protocol
    /// `validate_custody_resolution` flow.
    armed_candidates: HashMap<usize, Vec<PublicKey>>,
    /// Total funds deposited into our ledger by external wallets.
    wallet_funds: u64,
}

/// The simulation environment.
struct ProtocolSim {
    operators: Vec<SimOperator>,
    honest: HashSet<usize>,
    adversary: HashSet<usize>,
    block_height: u32,
}

/// Outcome of a proposal.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The operator's own local apply rejected the op (e.g. unknown deposit).
    RejectedLocal,
    /// Honest co-signers refused; majority threshold not reached.
    RejectedCosign,
    /// Majority reached; operation applied to proposer's ledger and to all
    /// co-signing replicas.
    Applied,
}

impl ProtocolSim {
    /// Create a cluster of N operators with the given adversary set and Q=3
    /// round-robin quorums.
    fn new(n: usize, adversary_indices: &[usize]) -> Self {
        let adversary: HashSet<usize> = adversary_indices.iter().copied().collect();
        let honest: HashSet<usize> = (0..n).filter(|i| !adversary.contains(i)).collect();

        // Bootstrap each operator's ledger with LedgerOpen.
        let mut operators: Vec<SimOperator> = (0..n)
            .map(|i| {
                let (sk, pk) = keypair((i + 1) as u16);
                let reserves_id = format!("reserves_{}", i);
                let mut ledger = Ledger::new_as_operator(pk, reserves_id.clone(), 0);

                ledger
                    .append_operation(LedgerOperation::LedgerOpen {
                        operator_id: pk,
                        reserves_id,
                        genesis_block: 0,
                        reserves_amount: 400_000,
                        collateral_amount: 600_000,
                    })
                    .unwrap();

                SimOperator {
                    idx: i,
                    secret_key: sk,
                    public_key: pk,
                    ledger,
                    replicas: HashMap::new(),
                    quorum_members: Vec::new(),
                    deposits: Vec::new(),
                    depositor_keys: HashMap::new(),
                    pending_preimages: HashMap::new(),
                    open_invoice_preimages: HashMap::new(),
                    open_withdrawals: HashMap::new(),
                    armed_candidates: HashMap::new(),
                    wallet_funds: 0,
                }
            })
            .collect();

        // Round-robin quorum assignment: operator i's quorum = [i+1, i+2, i+3] mod n.
        // Each member's replica of this ledger is initialized by replaying history.
        for i in 0..n {
            let members: Vec<usize> = (1..=3).map(|j| (i + j) % n).collect();
            operators[i].quorum_members = members.clone();

            // Add each member via QuorumAddMember, then QuorumBegin to activate.
            for &m in &members {
                let member_pk = operators[m].public_key;
                operators[i]
                    .ledger
                    .append_operation(LedgerOperation::QuorumAddMember {
                        quorum_member: member_pk,
                        quorum_member_signature: [0xAA; 64],
                        member_ledger_id: format!("reserves_{}", m),
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
                    })
                    .unwrap();
            }

            let member_pks: Vec<PublicKey> =
                members.iter().map(|&m| operators[m].public_key).collect();
            operators[i]
                .ledger
                .append_operation(LedgerOperation::QuorumBegin {
                    reserves_id: format!("reserves_{}_rotated", i),
                    spending_txid: [0x11; 32],
                    new_outpoint_txid: [(0x20 + i as u8); 32],
                    new_outpoint_vout: 0,
                    amount: 400_000,
                    quorum_expiry: 999_999,
                    ledger_hash: [0x33; 32],
                    quorum_members: member_pks,
                    collateral_amount: 600_000,
                })
                .unwrap();
        }

        // After all ledgers are bootstrapped, each member initializes their replica
        // by copying the current authoritative state of the ledgers they watch.
        for i in 0..n {
            for j in 0..n {
                if operators[j].quorum_members.contains(&i) {
                    // i is a member of j's quorum; seed i's replica from j's ledger.
                    let state = operators[j].ledger.state.clone();
                    operators[i].replicas.insert(j, state);
                }
            }
        }

        Self {
            operators,
            honest,
            adversary,
            block_height: 100_000,
        }
    }

    /// An honest co-signer's decision: would I sign this update?
    ///
    /// Mirrors what `handle_ledger_update` does in the real protocol:
    /// 1. Per-operation validators (balance checks, fee rate limits, witness
    ///    verification, etc.) via `validate_per_op_as_cosigner`
    /// 2. State-machine apply + conformance check via `apply_with_verifier`
    ///
    /// Either failing means "don't sign". The first layer catches things the
    /// pure state machine doesn't — e.g., FeeCollect rate limits, balance
    /// checks for operations that would silently saturate, witness validity
    /// for ops where conformance is permissive. Block height flows through
    /// to FeeChange validation (timing/limit rules).
    fn honest_would_cosign(
        replica: &LedgerState,
        op: &LedgerOperation,
        block_height: u32,
        armed_candidates: &[PublicKey],
        signer_pubkey: &PublicKey,
    ) -> bool {
        // State-machine gate: the dispute state must permit this operation type.
        // Real cosigners refuse DisputeArmed/Acquire/Yield in Normal state, and
        // refuse almost everything in Disputed/Armed/Tombstoned.
        if !replica.dispute_state.allows_operation(op.discriminant()) {
            return false;
        }
        // Signer identity check. Mirrors validate_update_signer in deposits-core
        // /src/ledger.rs: DisputeEnter in Normal state must be signed by a
        // quorum member; every other op must be signed by the current
        // parent_pubkey (the branch owner).
        match op {
            LedgerOperation::DisputeEnter { .. }
                if replica.dispute_state == DisputeState::Normal =>
            {
                if !replica
                    .quorum_members
                    .iter()
                    .any(|m| &m.pubkey == signer_pubkey)
                {
                    return false;
                }
            }
            _ => {
                if &replica.parent_pubkey != signer_pubkey {
                    return false;
                }
            }
        }
        if !validate_per_op_as_cosigner(replica, op, block_height, armed_candidates) {
            return false;
        }
        let verifier = CoreWitnessVerifier;
        match replica.apply_with_verifier(op, &verifier) {
            Ok((_, violations)) => violations.is_empty(),
            Err(_) => false,
        }
    }

    /// Propose an operation on operator `proposer`'s ledger. Runs the full
    /// propose → local-apply → co-sign → majority-check → apply flow.
    fn propose(&mut self, proposer: usize, op: LedgerOperation) -> Outcome {
        // 1. Local validation: can the proposer apply this to a clone?
        //    Adversary skips this step (happy to publish non-conforming).
        if self.honest.contains(&proposer) {
            let state_clone = self.operators[proposer].ledger.state.clone();
            let verifier = CoreWitnessVerifier;
            if state_clone.check_and_apply(&op, &verifier).is_err() {
                return Outcome::RejectedLocal;
            }
        } else {
            // Adversary still needs the raw apply to succeed, otherwise the
            // data structures won't be consistent. Skip the conformance check.
            let state_clone = self.operators[proposer].ledger.state.clone();
            if state_clone.apply(&op).is_err() {
                return Outcome::RejectedLocal;
            }
        }

        // 2. Co-sign round: each quorum member decides.
        let members = self.operators[proposer].quorum_members.clone();
        let mut signers: Vec<usize> = Vec::new();
        let mut honest_refusers: Vec<usize> = Vec::new();

        for &m in &members {
            let will_sign = if self.honest.contains(&m) {
                let replica = self.operators[m]
                    .replicas
                    .get(&proposer)
                    .expect("replica must exist for quorum member");
                let candidates: &[PublicKey] = self.operators[m]
                    .armed_candidates
                    .get(&proposer)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                let proposer_pk = self.operators[proposer].public_key;
                Self::honest_would_cosign(replica, &op, self.block_height, candidates, &proposer_pk)
            } else {
                true
            };
            if will_sign {
                signers.push(m);
            } else if self.honest.contains(&m) {
                honest_refusers.push(m);
            }
        }

        // 3. Majority check: need floor(n/2) + 1 signatures.
        let threshold = members.len() / 2 + 1;
        if signers.len() < threshold {
            return Outcome::RejectedCosign;
        }

        // 4. Apply to proposer's real ledger. Adversary uses raw apply
        //    (append without conformance check); honest uses checked.
        if self.honest.contains(&proposer) {
            self.operators[proposer]
                .ledger
                .append_operation_with_block(op.clone(), self.block_height, [0u8; 32])
                .expect("honest operator refused to apply after passing local validation");
        } else {
            // Adversary: apply without conformance enforcement. We write
            // directly via apply_state_changes to skip the operator's own
            // conformance gate.
            self.operators[proposer]
                .ledger
                .apply_state_changes(&op)
                .expect("adversary: apply_state_changes failed even though clone succeeded");
            // Append to history so watchers can replay. (We build a minimal
            // update record; signatures are dummy since we don't verify them
            // inside the sim.)
            self.operators[proposer].ledger.state.sequence += 1;
        }

        // 5. Update replicas on every co-signer (honest or adversary).
        //    Honest signers only recorded the update if it conformed; adversary
        //    signers record whatever they were given.
        for &signer in &signers {
            let replica = self.operators[signer]
                .replicas
                .get(&proposer)
                .expect("replica must exist");
            match replica.apply(&op) {
                Ok(new_state) => {
                    self.operators[signer].replicas.insert(proposer, new_state);
                }
                Err(_) => {
                    // Shouldn't happen for honest signers (they validated),
                    // but adversary signers may have applied to inconsistent
                    // replicas. In that case, leave the replica stale.
                }
            }
            // Record armer: if DisputeArmed was applied, the armer (= proposer,
            // since in our sim the proposer is the one "claiming" this branch
            // by virtue of proposing) gets added to this signer's candidate list.
            if matches!(op, LedgerOperation::DisputeArmed { .. }) {
                let proposer_pk = self.operators[proposer].public_key;
                let list = self.operators[signer]
                    .armed_candidates
                    .entry(proposer)
                    .or_default();
                if !list.contains(&proposer_pk) {
                    list.push(proposer_pk);
                }
            }
        }

        // 6. Auto-dispute-and-arm: if adversary-majority pushed through an op
        //    that honest cosigners refused, those honest cosigners trigger
        //    DisputeEnter AND DisputeArmed on their own replicas (both steps
        //    of the real auto_arm_for_dispute in deposits-node/src/node/inbound.rs).
        //    The armers get broadcast to every quorum member's candidate list so
        //    the entropy-winner check in a subsequent DisputeAcquire has
        //    competitive candidates.
        if !honest_refusers.is_empty() {
            let last_valid = self.operators[proposer]
                .ledger
                .state
                .sequence
                .saturating_sub(1);
            let victim_quorum = self.operators[proposer].quorum_members.clone();
            for &refuser in &honest_refusers {
                if self.dispute_enter(proposer, refuser, last_valid) == DisputeStepResult::Applied {
                    let _ = self.dispute_arm(proposer, refuser);
                    let refuser_pk = self.operators[refuser].public_key;
                    for &member in &victim_quorum {
                        let list = self.operators[member]
                            .armed_candidates
                            .entry(proposer)
                            .or_default();
                        if !list.contains(&refuser_pk) {
                            list.push(refuser_pk);
                        }
                    }
                }
            }
        }

        Outcome::Applied
    }

    /// Cross-ledger attack: `attacker` (a quorum member of `victim`) proposes
    /// a dispute operation on the victim's ledger. Goes through the same
    /// cosign flow as `propose()`, but the ledger being modified is the
    /// victim's, not the attacker's — and the signer identity is the attacker,
    /// not the victim.
    ///
    /// If the attacker reaches cosign majority on the victim's quorum (e.g.
    /// because other adversaries are cosigners), the dispute op applies to
    /// the victim's real ledger state. Subsequent DisputeArmed + DisputeAcquire
    /// can ultimately transfer custody to the attacker.
    fn adversary_propose_on_victim(
        &mut self,
        victim: usize,
        attacker: usize,
        op: LedgerOperation,
    ) -> Outcome {
        if !self.operators[victim].quorum_members.contains(&attacker) {
            return Outcome::RejectedLocal;
        }
        let attacker_pk = self.operators[attacker].public_key;

        let members = self.operators[victim].quorum_members.clone();
        let mut signers: Vec<usize> = Vec::new();
        for &m in &members {
            let will_sign = if self.honest.contains(&m) {
                let candidates: Vec<PublicKey> = self.operators[m]
                    .armed_candidates
                    .get(&victim)
                    .cloned()
                    .unwrap_or_default();
                let replica = self.operators[m]
                    .replicas
                    .get(&victim)
                    .expect("replica must exist for quorum member");
                Self::honest_would_cosign(
                    replica,
                    &op,
                    self.block_height,
                    &candidates,
                    &attacker_pk,
                )
            } else {
                true
            };
            if will_sign {
                signers.push(m);
            }
        }
        let threshold = members.len() / 2 + 1;
        if signers.len() < threshold {
            return Outcome::RejectedCosign;
        }

        // Apply to the victim's real ledger state. Use apply_state_changes
        // (skipping conformance) because dispute ops can move state in ways
        // the owner wouldn't sanction.
        if self.operators[victim]
            .ledger
            .apply_state_changes(&op)
            .is_err()
        {
            return Outcome::RejectedLocal;
        }
        self.operators[victim].ledger.state.sequence += 1;

        // Propagate to all cosigners' replicas, and for DisputeArmed record
        // the attacker as an armer in every quorum member's candidate list.
        for &signer in &signers {
            let replica = self.operators[signer]
                .replicas
                .get(&victim)
                .expect("replica must exist");
            if let Ok(new_state) = replica.apply(&op) {
                self.operators[signer].replicas.insert(victim, new_state);
            }
        }
        if matches!(op, LedgerOperation::DisputeArmed { .. }) {
            for &m in &members {
                let list = self.operators[m]
                    .armed_candidates
                    .entry(victim)
                    .or_default();
                if !list.contains(&attacker_pk) {
                    list.push(attacker_pk);
                }
            }
        }

        Outcome::Applied
    }

    /// Give an operator `amount` of "external wallet funds" — these will be
    /// deposited into its ledger via InvoiceCredit. Represents customer
    /// deposits the operator is holding.
    fn wallet_deposit(&mut self, rng: &mut Rng, proposer: usize, amount: u64) -> Option<DepositId> {
        // Generate a depositor keypair and open a deposit.
        let depositor_seed = (proposer * 1000 + self.operators[proposer].deposits.len()) as u16;
        let (dsk, dpk) = keypair(1000 + depositor_seed);
        let descriptor = format!("pk({})", hex::encode(dpk.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);

        let open_op = LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: descriptor.clone(),
            fees: Some(FeeStructure::default()),
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        };

        if self.propose(proposer, open_op) != Outcome::Applied {
            return None;
        }

        // Credit the deposit via InvoiceCredit.
        let mut payment_hash = [0u8; 32];
        payment_hash[0] = rng.range(255) as u8;
        payment_hash[1] = depositor_seed as u8;
        let credit_op = LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id,
            amount,
            invoice_id: format!("wallet_{}_{}", proposer, depositor_seed),
            sequence_number: self.operators[proposer].ledger.state.sequence + 1,
        };

        if self.propose(proposer, credit_op) != Outcome::Applied {
            return None;
        }

        self.operators[proposer]
            .deposits
            .push((deposit_id, descriptor, depositor_seed));
        self.operators[proposer]
            .depositor_keys
            .insert(deposit_id, dsk);
        self.operators[proposer].wallet_funds += amount;
        Some(deposit_id)
    }
}

// =========================================================================
// Dispute simulation
// =========================================================================

/// Records a single dispute branch (one disputer's fork of a victim's ledger).
#[derive(Clone)]
struct DisputeBranch {
    /// Who is driving this branch (a quorum member of the victim).
    disputer: usize,
    /// Did this branch reach Armed state?
    armed: bool,
    /// Final outcome after entropy resolution (set by resolve_dispute).
    outcome: DisputeOutcome,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DisputeOutcome {
    Pending,
    /// This branch won the entropy lottery and acquired custody.
    Acquired,
    /// This branch lost and yielded voluntarily.
    Yielded,
    /// This branch never armed — excluded from lottery.
    NeverArmed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DisputeStepResult {
    /// Op was invalid and correctly rejected by the state machine.
    Rejected,
    /// Op applied successfully to the disputer's fork.
    Applied,
    /// Disputer wasn't in the victim's quorum-at-fork — operation not allowed.
    NotAQuorumMember,
}

/// Human-readable name for a LedgerOperation variant — used by histogram tests.
fn op_name(op: &LedgerOperation) -> &'static str {
    match op {
        LedgerOperation::LedgerOpen { .. } => "LedgerOpen",
        LedgerOperation::DepositOpen { .. } => "DepositOpen",
        LedgerOperation::DepositClose { .. } => "DepositClose",
        LedgerOperation::FeeChange { .. } => "FeeChange",
        LedgerOperation::DepositKeyRotate { .. } => "DepositKeyRotate",
        LedgerOperation::InvoiceCredit { .. } => "InvoiceCredit",
        LedgerOperation::InvoiceLock { .. } => "InvoiceLock",
        LedgerOperation::InvoiceFulfill { .. } => "InvoiceFulfill",
        LedgerOperation::InvoiceFail { .. } => "InvoiceFail",
        LedgerOperation::OnchainCredit { .. } => "OnchainCredit",
        LedgerOperation::OnchainLock { .. } => "OnchainLock",
        LedgerOperation::OnchainFulfill { .. } => "OnchainFulfill",
        LedgerOperation::OnchainFail { .. } => "OnchainFail",
        LedgerOperation::TransferLock { .. } => "TransferLock",
        LedgerOperation::TransferComplete { .. } => "TransferComplete",
        LedgerOperation::TransferFail { .. } => "TransferFail",
        LedgerOperation::FeeCollect { .. } => "FeeCollect",
        LedgerOperation::QuorumAddMember { .. } => "QuorumAddMember",
        LedgerOperation::QuorumRemoveMember { .. } => "QuorumRemoveMember",
        LedgerOperation::QuorumBegin { .. } => "QuorumBegin",
        LedgerOperation::QuorumJoin { .. } => "QuorumJoin",
        LedgerOperation::DisputeEnter { .. } => "DisputeEnter",
        LedgerOperation::DisputeArmed { .. } => "DisputeArmed",
        LedgerOperation::DisputeAcquire { .. } => "DisputeAcquire",
        LedgerOperation::DisputeYield => "DisputeYield",
        LedgerOperation::DeliveryEmbed { .. } => "DeliveryEmbed",
        LedgerOperation::LedgerClose => "LedgerClose",
    }
}

/// Apply an op to a replica, checking the DisputeState gate first. Mirrors
/// what `Ledger::apply_operation` does but operates on a pure LedgerState.
fn apply_with_dispute_gate(state: &LedgerState, op: &LedgerOperation) -> Result<LedgerState, ()> {
    if !state.dispute_state.allows_operation(op.discriminant()) {
        return Err(());
    }
    state.apply(op).map_err(|_| ())
}

/// Build a lightweight `Ledger` shell around a state clone so we can call the
/// existing `validate_*_by_id` functions, which take `&Ledger`. None of those
/// validators touch `history` or `protocol`, so the empty defaults are fine.
fn ledger_shell(state: &LedgerState) -> Ledger {
    Ledger {
        state: state.clone(),
        protocol: LedgerProtocolState::default(),
        role: LedgerRole::Partner,
        history: Vec::new(),
    }
}

/// Per-operation validation an honest cosigner runs *before* applying the
/// state machine. This mirrors the dispatch inside
/// `deposits-core/src/message_handlers/ledger.rs::handle_ledger_update`.
/// Returns true if the op passes validation (cosigner would sign), false if
/// any validator rejects it.
fn validate_per_op_as_cosigner(
    replica: &LedgerState,
    op: &LedgerOperation,
    block_height: u32,
    armed_candidates: &[PublicKey],
) -> bool {
    let ledger = ledger_shell(replica);
    match op {
        LedgerOperation::LedgerOpen { .. } => true,
        LedgerOperation::DepositOpen {
            deposit_id, fees, ..
        } => op_val::validate_deposit_add_by_id(&ledger, deposit_id, fees.as_ref()).is_ok(),
        LedgerOperation::DepositClose { deposit_id } => {
            op_val::validate_deposit_close_by_id(&ledger, deposit_id).is_ok()
        }
        LedgerOperation::FeeChange {
            deposit_id,
            new_fees,
            effective_block,
        } => op_val::validate_deposit_fee_change(
            &ledger,
            deposit_id,
            new_fees,
            *effective_block,
            block_height,
        )
        .is_ok(),
        LedgerOperation::DepositKeyRotate {
            deposit_id,
            new_descriptor,
            witness,
        } => op_val::validate_deposit_key_rotate(&ledger, deposit_id, new_descriptor, witness)
            .is_ok(),
        LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id,
            amount,
            invoice_id,
            ..
        } => op_val::validate_credit_payment_by_id(
            &ledger,
            deposit_id,
            *amount,
            payment_hash,
            invoice_id,
        )
        .is_ok(),
        LedgerOperation::InvoiceLock {
            deposit_id,
            amount,
            payment_id,
            witness,
            ..
        } => op_val::validate_payment_lock_by_id(&ledger, deposit_id, *amount, payment_id, witness)
            .is_ok(),
        LedgerOperation::InvoiceFulfill {
            deposit_id,
            amount,
            payment_id,
            witness,
            preimage,
            ..
        } => op_val::validate_payment_fulfill_by_id(
            deposit_id, *amount, payment_id, witness, preimage,
        )
        .is_ok(),
        LedgerOperation::InvoiceFail { amount, .. } => {
            op_val::validate_payment_fail(*amount).is_ok()
        }
        LedgerOperation::OnchainCredit {
            deposit_id, amount, ..
        } => ledger.state.deposits.contains_key(deposit_id) && *amount > 0,
        LedgerOperation::OnchainLock {
            deposit_id, amount, ..
        } => ledger
            .state
            .deposits
            .get(deposit_id)
            .map(|d| d.available_balance() >= *amount)
            .unwrap_or(false),
        LedgerOperation::OnchainFail { .. } | LedgerOperation::OnchainFulfill { .. } => true,
        LedgerOperation::FeeCollect {
            deposit_id,
            amount,
            block_height,
        } => {
            op_val::validate_fee_collect_by_id(&ledger, deposit_id, *amount, *block_height).is_ok()
        }
        LedgerOperation::LedgerClose => op_val::validate_ledger_close(&ledger).is_ok(),
        LedgerOperation::QuorumJoin {
            operator_id,
            ledger_id,
            membership_expires,
        } => {
            // Ratchet: can only extend membership duration. Mirrors the check
            // in Ledger::validate_operation.
            if let Some(existing) = replica
                .joined_quorums
                .iter()
                .find(|m| &m.operator_id == operator_id && &m.ledger_id == ledger_id)
            {
                *membership_expires >= existing.membership_expires
            } else {
                true
            }
        }
        // Custody resolution — entropy-winner checks. Mirrors Ledger::validate_custody_resolution
        // and Ledger::validate_custody_yield but with the candidate list supplied
        // by the cosigner (who built it from observed DisputeArmed events).
        LedgerOperation::DisputeAcquire {
            new_custodian,
            entropy_block_hash,
            ..
        } => {
            use deposits_protocol::types::is_entropy_winner;
            !armed_candidates.is_empty()
                && is_entropy_winner(entropy_block_hash, new_custodian, armed_candidates)
        }
        LedgerOperation::DisputeYield => {
            // A real cosigner validates DisputeYield against the entropy_block_hash
            // from the winning DisputeAcquire they've already observed. Our sim
            // doesn't track acquires separately, so we only require the yielder
            // (parent_pubkey on the replica's fork) to be an armed candidate.
            armed_candidates.contains(&replica.parent_pubkey)
        }
        // The remaining ops are either governance (cosigners defer to
        // state-machine gates + conformance) or validated during apply.
        _ => true,
    }
}

impl ProtocolSim {
    /// A quorum member `disputer` initiates a dispute against `victim`. Forks
    /// the disputer's replica of victim's ledger into the Disputed state.
    ///
    /// Returns Rejected if the state machine refused (wrong state, unknown
    /// replica), NotAQuorumMember if the disputer isn't in victim's quorum.
    fn dispute_enter(
        &mut self,
        victim: usize,
        disputer: usize,
        last_valid: u64,
    ) -> DisputeStepResult {
        if !self.operators[victim].quorum_members.contains(&disputer) {
            return DisputeStepResult::NotAQuorumMember;
        }
        let op = LedgerOperation::DisputeEnter {
            last_valid_sequence: last_valid,
            reason: format!("op_{}_vs_op_{}", disputer, victim),
        };
        let replica = match self.operators[disputer].replicas.get(&victim) {
            Some(r) => r.clone(),
            None => return DisputeStepResult::Rejected,
        };
        match apply_with_dispute_gate(&replica, &op) {
            Ok(new_state) => {
                self.operators[disputer].replicas.insert(victim, new_state);
                DisputeStepResult::Applied
            }
            Err(_) => DisputeStepResult::Rejected,
        }
    }

    /// Disputer arms their fork of the victim's ledger for the lottery.
    fn dispute_arm(&mut self, victim: usize, disputer: usize) -> DisputeStepResult {
        let op = LedgerOperation::DisputeArmed {
            armed_block: self.block_height,
            // HASH160 of the disputer's idx as the preimage commitment.
            commitment_hash: {
                let mut h = [0u8; 20];
                h[0] = disputer as u8;
                h[1] = victim as u8;
                h
            },
            target_reserves: format!("bcrt1q_op{}_recovers_{}", disputer, victim),
        };
        let replica = match self.operators[disputer].replicas.get(&victim) {
            Some(r) => r.clone(),
            None => return DisputeStepResult::Rejected,
        };
        match apply_with_dispute_gate(&replica, &op) {
            Ok(new_state) => {
                self.operators[disputer].replicas.insert(victim, new_state);
                DisputeStepResult::Applied
            }
            Err(_) => DisputeStepResult::Rejected,
        }
    }

    /// Resolve a dispute: pick the entropy winner from armed candidates, apply
    /// DisputeAcquire on the winner's fork, DisputeYield on the losers' forks.
    ///
    /// Returns (winner_idx, branches).
    fn dispute_resolve(
        &mut self,
        victim: usize,
        candidates: &[usize],
        entropy_block_hash: [u8; 32],
    ) -> (Option<usize>, Vec<DisputeBranch>) {
        let mut branches: Vec<DisputeBranch> = candidates
            .iter()
            .map(|&d| {
                let armed = self.operators[d]
                    .replicas
                    .get(&victim)
                    .map(|s| s.dispute_state == DisputeState::Armed)
                    .unwrap_or(false);
                DisputeBranch {
                    disputer: d,
                    armed,
                    outcome: if armed {
                        DisputeOutcome::Pending
                    } else {
                        DisputeOutcome::NeverArmed
                    },
                }
            })
            .collect();

        let armed_pks: Vec<PublicKey> = branches
            .iter()
            .filter(|b| b.armed)
            .map(|b| self.operators[b.disputer].public_key)
            .collect();

        let winner_pk = select_entropy_winner(&entropy_block_hash, &armed_pks);
        let winner_idx = winner_pk.and_then(|pk| {
            branches
                .iter()
                .find(|b| b.armed && self.operators[b.disputer].public_key == pk)
                .map(|b| b.disputer)
        });

        let entropy_height = self.block_height + 6;
        self.block_height = entropy_height;

        for branch in branches.iter_mut() {
            if !branch.armed {
                continue;
            }
            if Some(branch.disputer) == winner_idx {
                let acquire_op = LedgerOperation::DisputeAcquire {
                    new_custodian: self.operators[branch.disputer].public_key,
                    entropy_block_height: entropy_height,
                    entropy_block_hash,
                    spend_txid: {
                        let mut t = [0u8; 32];
                        t[0] = branch.disputer as u8;
                        t[1] = 0xAC;
                        t
                    },
                    new_reserves_address: format!("bcrt1q_new_{}", branch.disputer),
                };
                let replica = self.operators[branch.disputer].replicas[&victim].clone();
                match apply_with_dispute_gate(&replica, &acquire_op) {
                    Ok(new) => {
                        self.operators[branch.disputer].replicas.insert(victim, new);
                        branch.outcome = DisputeOutcome::Acquired;
                    }
                    Err(_) => {
                        branch.outcome = DisputeOutcome::Pending;
                    }
                }
            } else {
                let yield_op = LedgerOperation::DisputeYield;
                let replica = self.operators[branch.disputer].replicas[&victim].clone();
                match apply_with_dispute_gate(&replica, &yield_op) {
                    Ok(new) => {
                        self.operators[branch.disputer].replicas.insert(victim, new);
                        branch.outcome = DisputeOutcome::Yielded;
                    }
                    Err(_) => {
                        branch.outcome = DisputeOutcome::Pending;
                    }
                }
            }
        }

        (winner_idx, branches)
    }
}

// =========================================================================
// Random operation generators
// =========================================================================

/// Pick a random existing deposit on this operator's ledger. Returns None
/// if the operator has no deposits.
fn pick_deposit(op: &SimOperator, rng: &mut Rng) -> Option<(DepositId, String, u16)> {
    if op.deposits.is_empty() {
        return None;
    }
    let idx = rng.range(op.deposits.len() as u64) as usize;
    Some(op.deposits[idx].clone())
}

/// Sign a message with a depositor key, producing a DescriptorWitness for
/// `pk(<hex>)` descriptors (single Schnorr signature).
fn sign_pk_witness(sk: &SecretKey, msg_hash: &[u8; 32]) -> DescriptorWitness {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, sk);
    let msg = Message::from_digest(*msg_hash);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    DescriptorWitness {
        stack: vec![sig.serialize().to_vec()],
    }
}

/// Build an OnchainLock op signed with `source_sk`. Returns (op, withdrawal_id).
fn build_onchain_lock(
    source: &(DepositId, String, u16),
    amount: u64,
    fee_sats: u64,
    destination_address: String,
    source_sk: &SecretKey,
    withdrawal_id: [u8; 32],
) -> LedgerOperation {
    let msg = signature_utils::withdrawal_signing_message(
        &withdrawal_id,
        &source.0,
        &destination_address,
        amount,
        fee_sats,
    );
    let witness = sign_pk_witness(source_sk, &msg);
    LedgerOperation::OnchainLock {
        deposit_id: source.0,
        amount,
        fee_sats,
        destination_address,
        withdrawal_id,
        witness,
    }
}

/// Build an InvoiceLock op signed with `source_sk`. Returns (op, payment_id,
/// preimage) so the caller can record the preimage for later Fulfill.
fn build_invoice_lock(
    source: &(DepositId, String, u16),
    amount: u64,
    sequence_number: u64,
    source_sk: &SecretKey,
    preimage: [u8; 32],
) -> (LedgerOperation, [u8; 32]) {
    use bitcoin::hashes::{sha256, Hash};
    let payment_id = sha256::Hash::hash(&preimage).to_byte_array();
    let msg = signature_utils::invoice_lock_signing_message(&source.0, &payment_id, amount);
    let witness = sign_pk_witness(source_sk, &msg);
    let op = LedgerOperation::InvoiceLock {
        deposit_id: source.0,
        amount,
        payment_id,
        sequence_number,
        witness,
    };
    (op, payment_id)
}

/// Build a TransferLock for an intra-ledger transfer. Returns (op, transfer_id,
/// preimage) so honest callers can later TransferComplete.
fn build_transfer_lock(
    source: &(DepositId, String, u16),
    dest: &(DepositId, String, u16),
    amount: u64,
    fee: u64,
    timeout_height: u32,
    source_sk: &SecretKey,
    preimage: [u8; 32],
    nonce: [u8; 32],
) -> (LedgerOperation, [u8; 32]) {
    use bitcoin::hashes::{sha256, Hash};
    let hash = sha256::Hash::hash(&preimage).to_byte_array();
    let completion_script = format!("sha256({})", hex::encode(hash));
    let signing_msg = signature_utils::transfer_lock_signing_message(
        &nonce,
        &source.0,
        &dest.0,
        amount,
        fee,
        &completion_script,
        timeout_height,
    );
    let witness = sign_pk_witness(source_sk, &signing_msg);
    let transfer_id = signature_utils::compute_transfer_id(&signing_msg);
    let op = LedgerOperation::TransferLock {
        nonce,
        source_deposit_id: source.0,
        destination_deposit_id: dest.0,
        amount,
        fee,
        completion_script,
        timeout_height,
        transfer_id,
        witness,
    };
    (op, transfer_id)
}

/// Generate a fresh DepositOpen op. The descriptor is derived from a fresh
/// keypair; the caller (propose pipeline) is responsible for tracking it in
/// `operators[proposer].deposits` after a successful Applied outcome.
fn gen_deposit_open(
    proposer: usize,
    deposits_count: usize,
    _rng: &mut Rng,
) -> (LedgerOperation, DepositId, String, u16, SecretKey) {
    let seed = (proposer * 1000 + deposits_count + 5000) as u16;
    let (dsk, dpk) = keypair(seed);
    let descriptor = format!("pk({})", hex::encode(dpk.serialize()));
    let deposit_id = compute_deposit_id(&descriptor);
    // Use a tight frequency (100 blocks) so the fuzzer reaches FeeCollect paths
    // in a reasonable number of steps. Fee-change-limit 10% gives teeth to
    // FeeChange validation without rejecting all honest attempts.
    let fees = FeeStructure::new(0, 100, 100);
    let op = LedgerOperation::DepositOpen {
        deposit_id,
        descriptor: descriptor.clone(),
        fees: Some(fees),
        transfer_fees: None,
        payment_hash: None,
        invoice: None,
        cosigner_guarantee_signature: None,
        receive_requires_sig: false,
        fee_change_after_blocks: Some(50),
        fee_change_notice_blocks: Some(20),
        fee_change_limit_bps: Some(1000), // 10% per change
    };
    (op, deposit_id, descriptor, seed, dsk)
}

/// Build an honest FeeChange: tweak annualized_bps by up to the allowed
/// `fee_change_limit_bps` delta, with effective_block respecting the notice
/// period. Returns None if no deposit qualifies (e.g. not enough blocks since
/// open yet).
fn gen_honest_fee_change(
    op: &SimOperator,
    rng: &mut Rng,
    block_height: u32,
) -> Option<GeneratedOp> {
    let (did, _, _) = pick_deposit(op, rng)?;
    let deposit = op.ledger.state.deposits.get(&did)?;
    let after = deposit.fee_change_after_blocks?;
    let notice = deposit.fee_change_notice_blocks?;
    let limit_bps = deposit.fee_change_limit_bps?;
    // Need at least `after` blocks since open.
    if block_height < deposit.opened_at_block.saturating_add(after) {
        return None;
    }
    let current = deposit.fees.annualized_bps as u64;
    // Max change = current * limit_bps / 10000 (per validator).
    let max_delta = (current.saturating_mul(limit_bps as u64)) / 10000;
    let delta = rng.range(max_delta.saturating_add(1));
    let new_bps = (current + delta).min(10_000) as u16; // cap at MAX_FEE_RATE_BPS
    let new_fees = FeeStructure::new(
        deposit.fees.annualized_msats,
        new_bps,
        deposit.fees.frequency_blocks,
    );
    let effective_block = block_height.saturating_add(notice).saturating_add(1);
    Some(GeneratedOp {
        op: LedgerOperation::FeeChange {
            deposit_id: did,
            new_fees,
            effective_block,
        },
        record_deposit: None,
        record_pending: None,
        record_invoice: None,
        record_key_rotate: None,
        record_withdrawal: None,
    })
}

/// Build an honest FeeCollect: pick a deposit whose fee schedule allows a
/// collection at the current block, with an amount within available balance.
fn gen_honest_fee_collect(
    op: &SimOperator,
    rng: &mut Rng,
    block_height: u32,
) -> Option<LedgerOperation> {
    let (did, _, _) = pick_deposit(op, rng)?;
    let deposit = op.ledger.state.deposits.get(&did)?;
    let earliest = deposit
        .last_fee_assessment
        .saturating_add(deposit.fees.frequency_blocks);
    if block_height < earliest {
        return None;
    }
    let available = deposit.balance.saturating_sub(deposit.locked_balance);
    if available == 0 {
        return None;
    }
    let max_fee = available.min(10_000);
    let amount = 1 + rng.range(max_fee.max(1));
    Some(LedgerOperation::FeeCollect {
        deposit_id: did,
        amount,
        block_height,
    })
}

/// Build an adversarial FeeCollect: ignores rate limits, over-draws, or picks
/// a backdated block_height. Honest validation paths should reject it.
fn gen_adversary_fee_collect(
    op: &SimOperator,
    rng: &mut Rng,
    block_height: u32,
) -> Option<LedgerOperation> {
    let (did, _, _) = pick_deposit(op, rng)?;
    let deposit = op.ledger.state.deposits.get(&did)?;
    let choice = rng.range(4);
    let (amount, block) = match choice {
        0 => (deposit.balance.saturating_mul(2), block_height), // over-draw
        1 => (1000, deposit.last_fee_assessment.saturating_sub(100)), // backdated
        2 => (u64::MAX / 2, block_height),                      // massive amount
        _ => (1, deposit.last_fee_assessment),                  // too early (= last assessment)
    };
    Some(LedgerOperation::FeeCollect {
        deposit_id: did,
        amount,
        block_height: block,
    })
}

/// An honest operator stays within reserves. Generates a mix of:
/// - DepositOpen (always safe)
/// - InvoiceCredit capped at headroom
/// - TransferLock between two existing deposits (intra-ledger, signed)
/// - TransferComplete for a pending transfer we own the preimage for
/// - FeeCollect when the fee schedule permits
fn gen_honest_op(sim: &ProtocolSim, proposer: usize, rng: &mut Rng) -> Option<GeneratedOp> {
    let op = &sim.operators[proposer];
    let total_balance = op.ledger.state.total_deposit_balance();
    let reserves = op.ledger.state.reserves_amount;
    let headroom = reserves.saturating_sub(total_balance);
    let has_pending = !op.ledger.state.pending_transfers.is_empty();

    let choice = rng.range(100);
    if choice < 20 && !op.deposits.is_empty() {
        if let Some(o) = gen_honest_fee_collect(op, rng, sim.block_height) {
            return Some(GeneratedOp {
                op: o,
                record_deposit: None,
                record_pending: None,
                record_invoice: None,
                record_key_rotate: None,
                record_withdrawal: None,
            });
        }
    }
    // 5% each for the less-frequent lifecycle ops. Return None if the state
    // doesn't support them and fall through to the main choice ladder.
    let aux = rng.range(100);
    if aux < 5 {
        // DepositClose on an empty deposit (balance=0, no locks). Newly-opened
        // deposits satisfy this naturally.
        if let Some((did, _, _)) = op.deposits.iter().find_map(|(d, desc, s)| {
            let dep = op.ledger.state.deposits.get(d)?;
            if dep.balance == 0 && dep.locked_balance == 0 {
                Some((*d, desc.clone(), *s))
            } else {
                None
            }
        }) {
            return Some(GeneratedOp {
                op: LedgerOperation::DepositClose { deposit_id: did },
                record_deposit: None,
                record_pending: None,
                record_invoice: None,
                record_key_rotate: None,
                record_withdrawal: None,
            });
        }
    } else if aux < 10 && has_pending {
        // TransferFail: any pending transfer with reason=1 (timeout).
        let pending_ids: Vec<[u8; 32]> =
            op.ledger.state.pending_transfers.keys().copied().collect();
        let tid = pending_ids[rng.range(pending_ids.len() as u64) as usize];
        let mut block_hash = [0u8; 32];
        block_hash[..4].copy_from_slice(&sim.block_height.to_le_bytes());
        return Some(GeneratedOp {
            op: LedgerOperation::TransferFail {
                transfer_id: tid,
                block_hash,
                reason: 1,
            },
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 15 && !op.deposits.is_empty() {
        // FeeChange: bump bps by <= 10% of current, with ≥20-block notice.
        if let Some(gen) = gen_honest_fee_change(op, rng, sim.block_height) {
            return Some(gen);
        }
    } else if aux < 20 && !op.deposits.is_empty() {
        // DepositKeyRotate (honest): fresh keypair; sign hash(new_descriptor)
        // with the OLD depositor key; record the new key so future witness
        // signing (InvoiceLock, TransferLock, etc.) uses it.
        use bitcoin::hashes::{sha256, Hash};
        let (did, _, _) = pick_deposit(op, rng)?;
        let old_sk = op.depositor_keys.get(&did).copied()?;
        let seed = 20_000u16.wrapping_add(rng.range(40_000) as u16);
        let (new_sk, new_pk) = keypair(seed);
        let new_descriptor = format!("pk({})", hex::encode(new_pk.serialize()));
        let msg = sha256::Hash::hash(new_descriptor.as_bytes()).to_byte_array();
        let witness = sign_pk_witness(&old_sk, &msg);
        return Some(GeneratedOp {
            op: LedgerOperation::DepositKeyRotate {
                deposit_id: did,
                new_descriptor,
                witness,
            },
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: Some((did, new_sk)),
            record_withdrawal: None,
        });
    } else if aux < 22 {
        // QuorumJoin (honest): operator declares monitoring commitment for
        // another operator's ledger. Pick a different operator; ratchet the
        // membership_expires forward from whatever's already recorded.
        let n = sim.operators.len();
        let other = (proposer + 1 + rng.range((n - 1) as u64) as usize) % n;
        let target_ledger_id = sim.operators[other].ledger.state.ledger_id;
        let existing_expires = op
            .ledger
            .state
            .joined_quorums
            .iter()
            .find(|m| {
                m.operator_id == sim.operators[other].public_key
                    && m.ledger_id == hex::encode(target_ledger_id)
            })
            .map(|m| m.membership_expires)
            .unwrap_or(0);
        let new_expires = existing_expires
            .max(sim.block_height)
            .saturating_add(rng.range(100_000) as u32 + 1);
        return Some(GeneratedOp {
            op: LedgerOperation::QuorumJoin {
                operator_id: sim.operators[other].public_key,
                ledger_id: hex::encode(target_ledger_id),
                membership_expires: new_expires,
            },
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 23 {
        // DeliveryEmbed: apply is a no-op ("causal ordering only"). We emit
        // it for coverage; honest cosigners sign because it's benign.
        let n = sim.operators.len();
        let other = rng.range(n as u64) as usize;
        let mut request_hash = [0u8; 32];
        request_hash[..8].copy_from_slice(&rng.next().to_le_bytes());
        return Some(GeneratedOp {
            op: LedgerOperation::DeliveryEmbed {
                request_hash,
                target_ledger_id: sim.operators[other].ledger.state.ledger_id,
                target_operator: sim.operators[other].public_key,
            },
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 25 && !op.deposits.is_empty() {
        // OnchainLock (honest): lock funds for a withdrawal, signed by the
        // depositor. Fee goes with it; require available_balance >= amount+fee.
        let (did, _, _) = pick_deposit(op, rng)?;
        let deposit = op.ledger.state.deposits.get(&did)?;
        let available = deposit.balance.saturating_sub(deposit.locked_balance);
        if available < 1000 {
            return None;
        }
        let source = op.deposits.iter().find(|(d, _, _)| *d == did).cloned()?;
        let source_sk = op.depositor_keys.get(&did).copied()?;
        let fee = 500;
        let max_amount = available.saturating_sub(fee).saturating_sub(500).max(1);
        let amount = 500 + rng.range(max_amount);
        let mut wid = [0u8; 32];
        wid[..8].copy_from_slice(&rng.next().to_le_bytes());
        let dest = format!("bcrt1q_wd_{}_{}", proposer, rng.range(1_000_000));
        let o = build_onchain_lock(&source, amount, fee, dest.clone(), &source_sk, wid);
        return Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: Some((wid, amount, did, dest)),
        });
    } else if aux < 27 && !op.open_withdrawals.is_empty() {
        // OnchainFulfill or OnchainFail on an existing pending withdrawal.
        let wids: Vec<[u8; 32]> = op.open_withdrawals.keys().copied().collect();
        let wid = wids[rng.range(wids.len() as u64) as usize];
        let (amount, did, dest) = op.open_withdrawals[&wid].clone();
        let o = if rng.range(100) < 70 {
            let mut txid = [0u8; 32];
            txid[..8].copy_from_slice(&rng.next().to_le_bytes());
            LedgerOperation::OnchainFulfill {
                deposit_id: did,
                withdrawal_id: wid,
                amount,
                txid,
                destination_address: dest,
            }
        } else {
            LedgerOperation::OnchainFail {
                deposit_id: did,
                withdrawal_id: wid,
            }
        };
        return Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 30 && headroom > 1000 && !op.deposits.is_empty() {
        // OnchainCredit: operator claims an on-chain UTXO arrived.
        let (did, _, _) = pick_deposit(op, rng)?;
        let amount = 1000 + rng.range(headroom - 1000);
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&rng.next().to_le_bytes());
        return Some(GeneratedOp {
            op: LedgerOperation::OnchainCredit {
                txid,
                vout: rng.range(4) as u32,
                deposit_id: did,
                amount,
                funding_address: format!("bcrt1q_funding_{}", proposer),
            },
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    }

    let choice = rng.range(100);
    if choice < 25 || op.deposits.is_empty() {
        let (o, did, desc, seed, dsk) = gen_deposit_open(proposer, op.deposits.len(), rng);
        Some(GeneratedOp {
            op: o,
            record_deposit: Some((did, desc, seed, dsk)),
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        })
    } else if choice < 50 && has_pending {
        // TransferComplete: pick a pending transfer. Use a matching preimage
        // if we have it (honest path), otherwise skip.
        let pending_ids: Vec<[u8; 32]> =
            op.ledger.state.pending_transfers.keys().copied().collect();
        let tid = pending_ids[rng.range(pending_ids.len() as u64) as usize];
        let preimage = op.pending_preimages.get(&tid).copied();
        if let Some(pre) = preimage {
            let o = LedgerOperation::TransferComplete {
                transfer_id: tid,
                script_witness: DescriptorWitness {
                    stack: vec![pre.to_vec()],
                },
            };
            Some(GeneratedOp {
                op: o,
                record_deposit: None,
                record_pending: None,
                record_invoice: None,
                record_key_rotate: None,
                record_withdrawal: None,
            })
        } else {
            None
        }
    } else if choice < 75 && op.deposits.len() >= 2 {
        // TransferLock: intra-ledger, pick two distinct deposits, sign correctly.
        let src_idx = rng.range(op.deposits.len() as u64) as usize;
        let dst_idx = {
            let mut d = rng.range(op.deposits.len() as u64) as usize;
            if d == src_idx {
                d = (d + 1) % op.deposits.len();
            }
            d
        };
        let source = op.deposits[src_idx].clone();
        let dest = op.deposits[dst_idx].clone();
        let source_balance = op
            .ledger
            .state
            .deposits
            .get(&source.0)
            .map(|d| d.available_balance())
            .unwrap_or(0);
        if source_balance < 1000 {
            return None;
        }
        let source_sk = op.depositor_keys.get(&source.0).copied()?;
        let max_total = source_balance - 1;
        let amount = 500 + rng.range(max_total.saturating_sub(500).max(1));
        let fee = rng.range(amount / 100).max(1);
        if amount + fee > source_balance {
            return None;
        }
        let mut preimage = [0u8; 32];
        let seed = rng.next();
        preimage[..8].copy_from_slice(&seed.to_le_bytes());
        preimage[8] = proposer as u8;
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&rng.next().to_le_bytes());
        let (o, tid) = build_transfer_lock(
            &source,
            &dest,
            amount,
            fee,
            sim.block_height + 1000,
            &source_sk,
            preimage,
            nonce,
        );
        Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: Some((tid, preimage)),
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        })
    } else if choice < 80 && !op.ledger.state.open_invoice_locks.is_empty() {
        // InvoiceFulfill or InvoiceFail on an existing lock. Honest fulfills
        // with the matching preimage if we have it.
        let payment_ids: Vec<[u8; 32]> =
            op.ledger.state.open_invoice_locks.keys().copied().collect();
        let pid = payment_ids[rng.range(payment_ids.len() as u64) as usize];
        let lock = op.ledger.state.open_invoice_locks.get(&pid)?;
        let did = lock.deposit_id;
        let amount = lock.amount;
        let source = op.deposits.iter().find(|(d, _, _)| *d == did).cloned()?;
        let source_sk = op.depositor_keys.get(&did).copied()?;
        let msg = signature_utils::invoice_lock_signing_message(&did, &pid, amount);
        let witness = sign_pk_witness(&source_sk, &msg);
        let o = if rng.range(100) < 70 {
            // Fulfill path — needs the real preimage.
            let preimage = op.open_invoice_preimages.get(&pid).copied()?;
            LedgerOperation::InvoiceFulfill {
                deposit_id: source.0,
                amount,
                payment_id: pid,
                sequence_number: op.ledger.state.sequence + 1,
                witness,
                preimage,
            }
        } else {
            LedgerOperation::InvoiceFail {
                deposit_id: source.0,
                amount,
                payment_id: pid,
                sequence_number: op.ledger.state.sequence + 1,
            }
        };
        Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        })
    } else if choice < 90 && !op.deposits.is_empty() {
        // InvoiceLock: lock funds on an existing deposit, signing with its
        // depositor key. Amount capped at available_balance minus a safety
        // margin so reserves don't trip.
        let (did, _, _) = pick_deposit(op, rng)?;
        let deposit = op.ledger.state.deposits.get(&did)?;
        let available = deposit.balance.saturating_sub(deposit.locked_balance);
        if available < 1000 {
            return None;
        }
        let source = op.deposits.iter().find(|(d, _, _)| *d == did).cloned()?;
        let source_sk = op.depositor_keys.get(&did).copied()?;
        let amount = 500 + rng.range(available.saturating_sub(500).max(1));
        let mut preimage = [0u8; 32];
        preimage[..8].copy_from_slice(&rng.next().to_le_bytes());
        preimage[8] = proposer as u8;
        preimage[9] = 0x11;
        let (o, pid) = build_invoice_lock(
            &source,
            amount,
            op.ledger.state.sequence + 1,
            &source_sk,
            preimage,
        );
        Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: Some((pid, preimage)),
            record_key_rotate: None,
            record_withdrawal: None,
        })
    } else if headroom > 1000 {
        let (did, _, _) = pick_deposit(op, rng)?;
        let amount = 1000 + rng.range(headroom - 1000);
        let mut payment_hash = [0u8; 32];
        payment_hash[0] = rng.range(256) as u8;
        payment_hash[1] = rng.range(256) as u8;
        payment_hash[2] = (op.ledger.state.sequence & 0xff) as u8;
        let o = LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id: did,
            amount,
            invoice_id: format!("h_{}_{}", proposer, op.ledger.state.sequence),
            sequence_number: op.ledger.state.sequence + 1,
        };
        Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        })
    } else {
        None
    }
}

/// An adversary generates unchecked operations: sometimes valid, sometimes
/// blatantly over-reserve or with bad witnesses. Honest co-signers filter.
fn gen_adversary_op(sim: &ProtocolSim, proposer: usize, rng: &mut Rng) -> Option<GeneratedOp> {
    let op = &sim.operators[proposer];
    // Occasional adversarial variants of the less-common ops. These should
    // be rejected by validate_per_op_as_cosigner or by the state machine.
    let aux = rng.range(100);
    if aux < 3 && !op.deposits.is_empty() {
        // DepositClose on a deposit with non-zero balance → rejected.
        let (did, _, _) = pick_deposit(op, rng)?;
        return Some(GeneratedOp {
            op: LedgerOperation::DepositClose { deposit_id: did },
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 6 && !op.deposits.is_empty() {
        // Adversarial DepositKeyRotate: rotate to attacker-controlled descriptor,
        // signed with the attacker's operator key (not the depositor's).
        use bitcoin::hashes::{sha256, Hash};
        let (did, _, _) = pick_deposit(op, rng)?;
        let new_descriptor = format!("pk({})", hex::encode(op.public_key.serialize()));
        let msg = sha256::Hash::hash(new_descriptor.as_bytes()).to_byte_array();
        let witness = sign_pk_witness(&op.secret_key, &msg);
        return Some(GeneratedOp {
            op: LedgerOperation::DepositKeyRotate {
                deposit_id: did,
                new_descriptor,
                witness,
            },
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 10 && !op.deposits.is_empty() {
        // Adversarial FeeChange: huge rate jump violating fee_change_limit_bps
        // and/or annualized_bps > MAX_FEE_RATE_BPS.
        let (did, _, _) = pick_deposit(op, rng)?;
        let deposit = op.ledger.state.deposits.get(&did)?;
        let new_fees = FeeStructure::new(
            deposit.fees.annualized_msats,
            if rng.range(2) == 0 { 50_000 } else { 9_000 }, // both exceed limits
            deposit.fees.frequency_blocks,
        );
        return Some(GeneratedOp {
            op: LedgerOperation::FeeChange {
                deposit_id: did,
                new_fees,
                effective_block: sim.block_height + 1, // too soon (notice=20)
            },
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 13 && !op.ledger.state.pending_transfers.is_empty() {
        // Adversarial TransferFail: reason=0 is reserved/invalid per the spec.
        let pending_ids: Vec<[u8; 32]> =
            op.ledger.state.pending_transfers.keys().copied().collect();
        let tid = pending_ids[rng.range(pending_ids.len() as u64) as usize];
        return Some(GeneratedOp {
            op: LedgerOperation::TransferFail {
                transfer_id: tid,
                block_hash: [0xBA; 32],
                reason: 0,
            },
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 17 && !op.deposits.is_empty() {
        // Adversarial OnchainCredit: amount=0 (rejected) or non-existent deposit.
        let (did, _, _) = pick_deposit(op, rng)?;
        let amount = if rng.range(2) == 0 { 0 } else { u64::MAX / 2 };
        return Some(GeneratedOp {
            op: LedgerOperation::OnchainCredit {
                txid: [0xBA; 32],
                vout: 0,
                deposit_id: did,
                amount,
                funding_address: String::new(),
            },
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 19 {
        // Adversarial LedgerClose: try to close while deposits have non-zero
        // obligation. validate_ledger_close should reject.
        return Some(GeneratedOp {
            op: LedgerOperation::LedgerClose,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 22 {
        // Adversarial QuorumRemoveMember: try to remove one of our honest
        // cosigners to weaken future majority checks. (In this sim, SimOperator.
        // quorum_members is static from init and doesn't read ledger state, so
        // this exercise only confirms cosigners reject the op — a real impl
        // should reduce the quorum size.)
        let members = &op.quorum_members;
        if !members.is_empty() {
            let m_idx = members[rng.range(members.len() as u64) as usize];
            let m_pk = sim.operators[m_idx].public_key;
            return Some(GeneratedOp {
                op: LedgerOperation::QuorumRemoveMember {
                    quorum_member: m_pk,
                    operator_signature: [0xCC; 64],
                },
                record_deposit: None,
                record_pending: None,
                record_invoice: None,
                record_key_rotate: None,
                record_withdrawal: None,
            });
        }
    } else if aux < 24 && !op.deposits.is_empty() {
        // Adversarial OnchainLock: wrong witness (signed with adversary's
        // operator key) or empty destination. Honest cosigner rejects via
        // validate_onchain_lock_by_id.
        let (did, _, _) = pick_deposit(op, rng)?;
        let deposit = op.ledger.state.deposits.get(&did)?;
        let available = deposit.balance.saturating_sub(deposit.locked_balance);
        let source = op.deposits.iter().find(|(d, _, _)| *d == did).cloned()?;
        let mut wid = [0u8; 32];
        wid[0] = 0xBA;
        wid[1] = rng.range(256) as u8;
        let dest = if rng.range(2) == 0 {
            String::new()
        } else {
            format!("bcrt1q_bogus_{}", proposer)
        };
        let amount = if rng.range(2) == 0 {
            0
        } else {
            available.saturating_add(10_000)
        };
        let o = build_onchain_lock(&source, amount, 100, dest, &op.secret_key, wid);
        return Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 26 {
        // Adversarial OnchainFulfill / OnchainFail: random withdrawal_id. No
        // validator rejects these currently — apply() silently no-ops if the
        // withdrawal doesn't exist. Left in for completeness.
        let (did, _, _) = pick_deposit(op, rng)?;
        let mut wid = [0u8; 32];
        wid[0] = rng.range(256) as u8;
        let o = if rng.range(2) == 0 {
            LedgerOperation::OnchainFail {
                deposit_id: did,
                withdrawal_id: wid,
            }
        } else {
            LedgerOperation::OnchainFulfill {
                deposit_id: did,
                withdrawal_id: wid,
                amount: rng.range(1_000_000),
                txid: [0xBE; 32],
                destination_address: "bcrt1q_bogus_x".to_string(),
            }
        };
        return Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    } else if aux < 28 {
        // Adversarial QuorumJoin: ratchet-violating (expires < existing).
        let n = sim.operators.len();
        let other = (proposer + 1 + rng.range((n - 1) as u64) as usize) % n;
        return Some(GeneratedOp {
            op: LedgerOperation::QuorumJoin {
                operator_id: sim.operators[other].public_key,
                ledger_id: hex::encode(sim.operators[other].ledger.state.ledger_id),
                membership_expires: 0, // already expired
            },
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    }
    // Occasional bogus dispute inputs. Most will be rejected by the state-machine
    // dispute_state gate (e.g., DisputeArmed only valid in Disputed state) or
    // by conformance checks; a few may land but self-sabotage the adversary
    // (DisputeEnter on their own ledger locks it into Disputed state, preventing
    // further adversarial ops). Either way, honest cosigners' per-op validators
    // and the state gate should contain the damage.
    if rng.range(100) < 4 {
        let choice = rng.range(4);
        let o = match choice {
            0 => LedgerOperation::DisputeEnter {
                last_valid_sequence: op.ledger.state.sequence,
                reason: format!("bogus_{}", rng.next()),
            },
            1 => LedgerOperation::DisputeArmed {
                armed_block: sim.block_height,
                commitment_hash: {
                    let mut h = [0u8; 20];
                    h[0] = rng.range(256) as u8;
                    h
                },
                target_reserves: format!("bcrt1q_bogus_{}", proposer),
            },
            2 => LedgerOperation::DisputeAcquire {
                new_custodian: op.public_key,
                entropy_block_height: sim.block_height,
                entropy_block_hash: {
                    let mut h = [0u8; 32];
                    h[0] = rng.range(256) as u8;
                    h
                },
                spend_txid: [0xFF; 32],
                new_reserves_address: format!("bcrt1q_adv_self_{}", proposer),
            },
            _ => LedgerOperation::DisputeYield,
        };
        return Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        });
    }
    if rng.range(100) < 15 && !op.deposits.is_empty() {
        if let Some(o) = gen_adversary_fee_collect(op, rng, sim.block_height) {
            return Some(GeneratedOp {
                op: o,
                record_deposit: None,
                record_pending: None,
                record_invoice: None,
                record_key_rotate: None,
                record_withdrawal: None,
            });
        }
    }
    let choice = rng.range(100);
    let has_pending = !op.ledger.state.pending_transfers.is_empty();

    if choice < 20 || op.deposits.is_empty() {
        let (o, did, desc, seed, dsk) = gen_deposit_open(proposer, op.deposits.len(), rng);
        Some(GeneratedOp {
            op: o,
            record_deposit: Some((did, desc, seed, dsk)),
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        })
    } else if choice < 30 && has_pending {
        // TransferComplete with either the real preimage (works) or a
        // random one (silently applies because apply doesn't check the
        // script_witness — our test is that this doesn't crash anything).
        let pending_ids: Vec<[u8; 32]> =
            op.ledger.state.pending_transfers.keys().copied().collect();
        let tid = pending_ids[rng.range(pending_ids.len() as u64) as usize];
        let mut garbage = [0u8; 32];
        garbage[0] = rng.range(256) as u8;
        let o = LedgerOperation::TransferComplete {
            transfer_id: tid,
            script_witness: DescriptorWitness {
                stack: vec![garbage.to_vec()],
            },
        };
        Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        })
    } else if choice < 35 && !op.deposits.is_empty() {
        // Adversarial InvoiceLock: wrong witness (signed with adversary's
        // operator key, not the depositor's), possibly over-balance.
        let (did, _, _) = pick_deposit(op, rng)?;
        let deposit = op.ledger.state.deposits.get(&did)?;
        let available = deposit.balance.saturating_sub(deposit.locked_balance);
        let source = op.deposits.iter().find(|(d, _, _)| *d == did).cloned()?;
        let amount = if rng.range(100) < 40 {
            available.saturating_add(10_000)
        } else {
            1 + rng.range(available.max(1))
        };
        let mut preimage = [0u8; 32];
        preimage[0] = rng.range(256) as u8;
        let (o, _pid) = build_invoice_lock(
            &source,
            amount,
            op.ledger.state.sequence + 1,
            &op.secret_key, // wrong key
            preimage,
        );
        Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        })
    } else if choice < 45 && !op.ledger.state.open_invoice_locks.is_empty() {
        // Adversarial InvoiceFulfill: correct payment_id but bogus preimage.
        let payment_ids: Vec<[u8; 32]> =
            op.ledger.state.open_invoice_locks.keys().copied().collect();
        let pid = payment_ids[rng.range(payment_ids.len() as u64) as usize];
        let lock = op.ledger.state.open_invoice_locks.get(&pid)?;
        let did = lock.deposit_id;
        let amount = lock.amount;
        let mut bad_preimage = [0u8; 32];
        bad_preimage[0] = rng.range(256) as u8;
        bad_preimage[1] = 0xBA;
        let o = LedgerOperation::InvoiceFulfill {
            deposit_id: did,
            amount,
            payment_id: pid,
            sequence_number: op.ledger.state.sequence + 1,
            witness: DescriptorWitness {
                stack: vec![vec![0u8; 64]],
            }, // garbage sig
            preimage: bad_preimage,
        };
        Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        })
    } else if choice < 50 && op.deposits.len() >= 2 {
        // Adversarial TransferLock: wrong witness, over-balance, or mismatched
        // signing-message. Honest co-signers should flag InvalidWitness.
        let src_idx = rng.range(op.deposits.len() as u64) as usize;
        let dst_idx = (src_idx + 1) % op.deposits.len();
        let source = op.deposits[src_idx].clone();
        let dest = op.deposits[dst_idx].clone();
        let source_balance = op
            .ledger
            .state
            .deposits
            .get(&source.0)
            .map(|d| d.available_balance())
            .unwrap_or(0);
        // Pick an amount that sometimes over-spends and sometimes doesn't,
        // plus a wrong witness (sign with adversary's key instead of depositor's).
        let amount = if rng.range(100) < 40 {
            source_balance.saturating_add(10_000)
        } else {
            source_balance.saturating_sub(1000).max(1000)
        };
        let mut preimage = [0u8; 32];
        preimage[0] = rng.range(256) as u8;
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&rng.next().to_le_bytes());
        // Sign with the adversary operator's own key, not the depositor's.
        let (o, _tid) = build_transfer_lock(
            &source,
            &dest,
            amount,
            10,
            sim.block_height + 1000,
            &op.secret_key,
            preimage,
            nonce,
        );
        Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        })
    } else {
        // Credit — adversary doesn't respect reserves.
        let (did, _, _) = pick_deposit(op, rng)?;
        let reserves = op.ledger.state.reserves_amount;
        let amount = if rng.range(100) < 40 {
            reserves * (2 + rng.range(5))
        } else {
            1_000 + rng.range(reserves.max(1))
        };
        let mut payment_hash = [0u8; 32];
        payment_hash[0] = rng.range(256) as u8;
        payment_hash[1] = rng.range(256) as u8;
        payment_hash[2] = (op.ledger.state.sequence & 0xff) as u8;
        payment_hash[3] = 0xAA;
        let o = LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id: did,
            amount,
            invoice_id: format!("a_{}_{}", proposer, op.ledger.state.sequence),
            sequence_number: op.ledger.state.sequence + 1,
        };
        Some(GeneratedOp {
            op: o,
            record_deposit: None,
            record_pending: None,
            record_invoice: None,
            record_key_rotate: None,
            record_withdrawal: None,
        })
    }
}

/// Bundle of an operation plus bookkeeping the caller should perform on Applied.
struct GeneratedOp {
    op: LedgerOperation,
    /// If set, caller must push to operators[proposer].deposits on Applied.
    record_deposit: Option<(DepositId, String, u16, SecretKey)>,
    /// If set, caller must store (transfer_id, preimage) so we can complete
    /// the transfer later.
    record_pending: Option<([u8; 32], [u8; 32])>,
    /// If set, caller must store (payment_id, preimage) in open_invoice_preimages
    /// so we can Fulfill the lock later with the matching preimage.
    record_invoice: Option<([u8; 32], [u8; 32])>,
    /// If set, caller must replace depositor_keys[deposit_id] with the new key
    /// after an Applied DepositKeyRotate — subsequent witness signing must
    /// use the rotated-to key.
    record_key_rotate: Option<(DepositId, SecretKey)>,
    /// If set, caller must record (withdrawal_id, amount, deposit_id, dest)
    /// in open_withdrawals so OnchainFulfill/Fail can reference it later.
    record_withdrawal: Option<([u8; 32], u64, DepositId, String)>,
}

impl ProtocolSim {
    /// Run one fuzzing step: pick a random operator, generate an op, propose it.
    /// Returns the outcome for inspection. Noop if no op can be generated.
    fn step(&mut self, rng: &mut Rng) -> Option<Outcome> {
        self.step_detailed(rng).map(|(o, _, _)| o)
    }

    /// Same as `step` but also returns the operation type name and whether
    /// the proposer was an adversary. Useful for histogram analysis.
    fn step_detailed(&mut self, rng: &mut Rng) -> Option<(Outcome, &'static str, bool)> {
        // Advance the sim clock. Some operations (FeeCollect rate limit,
        // FeeChange notice period) depend on block height progressing.
        self.block_height = self.block_height.saturating_add(rng.range(30) as u32 + 1);

        let n = self.operators.len();
        let proposer = rng.range(n as u64) as usize;
        let is_adv = self.adversary.contains(&proposer);
        let gen = if is_adv {
            gen_adversary_op(self, proposer, rng)
        } else {
            gen_honest_op(self, proposer, rng)
        }?;

        let name = op_name(&gen.op);
        let outcome = self.propose(proposer, gen.op);
        if outcome == Outcome::Applied {
            if let Some((did, desc, seed, dsk)) = gen.record_deposit {
                self.operators[proposer].deposits.push((did, desc, seed));
                self.operators[proposer].depositor_keys.insert(did, dsk);
            }
            if let Some((tid, preimage)) = gen.record_pending {
                self.operators[proposer]
                    .pending_preimages
                    .insert(tid, preimage);
            }
            if let Some((payment_id, preimage)) = gen.record_invoice {
                self.operators[proposer]
                    .open_invoice_preimages
                    .insert(payment_id, preimage);
            }
            if let Some((did, new_sk)) = gen.record_key_rotate {
                self.operators[proposer].depositor_keys.insert(did, new_sk);
            }
            if let Some((wid, amount, did, dest)) = gen.record_withdrawal {
                self.operators[proposer]
                    .open_withdrawals
                    .insert(wid, (amount, did, dest));
            }
        }
        Some((outcome, name, is_adv))
    }
}

// =========================================================================
// Step 1 sanity test: hand-written sequence exercises the flow.
// =========================================================================

#[test]
fn step1_hand_written_conforming_sequence() {
    // 5 operators, 2 adversary (idx 0, 1), Q=3.
    let mut sim = ProtocolSim::new(5, &[0, 1]);
    let mut rng = Rng::new(0xC0FFEE);

    // Operator 2 (honest) deposits some wallet funds.
    let did = sim.wallet_deposit(&mut rng, 2, 50_000);
    assert!(did.is_some(), "honest deposit should succeed");
    assert_eq!(sim.operators[2].wallet_funds, 50_000);
    assert_eq!(sim.operators[2].ledger.state.deposits.len(), 1);

    // All replicas of op 2's ledger should reflect the deposit.
    for &m in &sim.operators[2].quorum_members.clone() {
        let replica = &sim.operators[m].replicas[&2];
        assert_eq!(
            replica.deposits.len(),
            1,
            "replica for op 2 on member {} should have 1 deposit",
            m
        );
    }
}

#[test]
fn step1_honest_cosigners_block_over_reserve_credit() {
    // Adversary operator 0 tries to credit far more than reserves.
    let mut sim = ProtocolSim::new(5, &[0, 1]);
    let mut _rng = Rng::new(0xFEED);

    // First open a legitimate deposit (small amount).
    let (_sk, dpk) = keypair(5000);
    let descriptor = format!("pk({})", hex::encode(dpk.serialize()));
    let deposit_id = compute_deposit_id(&descriptor);
    let open_op = LedgerOperation::DepositOpen {
        deposit_id,
        descriptor,
        fees: Some(FeeStructure::default()),
        transfer_fees: None,
        payment_hash: None,
        invoice: None,
        cosigner_guarantee_signature: None,
        receive_requires_sig: false,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
    };
    assert_eq!(sim.propose(0, open_op), Outcome::Applied);

    // Now adversary tries to credit 10× the reserves (400k) — honest members
    // should refuse because post-apply conformance would flag InsufficientReserves.
    let over_credit = LedgerOperation::InvoiceCredit {
        payment_hash: [0x99; 32],
        deposit_id,
        amount: 4_000_000, // 10× reserves_amount of 400k
        invoice_id: "over_credit".to_string(),
        sequence_number: sim.operators[0].ledger.state.sequence + 1,
    };

    // Op 0's quorum = [1, 2, 3]. Member 1 is adversary, 2 & 3 are honest.
    // Threshold = 2. Honest 2 & 3 refuse → only adversary 1 signs → below threshold.
    let outcome = sim.propose(0, over_credit);
    assert_eq!(
        outcome,
        Outcome::RejectedCosign,
        "honest majority should refuse over-reserve credit"
    );
}

// =========================================================================
// Step 2: small fuzz — 100 runs × 50 ops, verify invariants on honest ledgers.
// =========================================================================

#[test]
fn step2_fuzz_small_honest_invariants_hold() {
    let mut stats = FuzzStats::default();
    for seed in 0..100u64 {
        let mut sim = ProtocolSim::new(5, &[0, 1]);
        let mut rng = Rng::new(seed * 7919 + 1);
        for _ in 0..50 {
            match sim.step(&mut rng) {
                Some(Outcome::Applied) => stats.applied += 1,
                Some(Outcome::RejectedLocal) => stats.rejected_local += 1,
                Some(Outcome::RejectedCosign) => stats.rejected_cosign += 1,
                None => stats.noop += 1,
            }
        }

        let violations = sim.check_all_invariants();
        assert!(
            violations.is_empty(),
            "seed {} produced invariant violations: {:#?}",
            seed,
            violations
        );
    }

    // Sanity checks on distribution — we should see meaningful activity.
    assert!(
        stats.applied > 500,
        "too few applied operations: {:?}",
        stats
    );
    assert!(
        stats.rejected_cosign > 0,
        "adversary never got rejected — generator may be too tame: {:?}",
        stats
    );
}

#[derive(Default, Debug)]
struct FuzzStats {
    applied: u64,
    rejected_local: u64,
    rejected_cosign: u64,
    noop: u64,
}

/// Observability snapshot of dispute activity across a simulation. Counts
/// how many replicas are in each DisputeState — a proxy for how often honest
/// cosigners auto-triggered disputes.
#[derive(Default, Debug, Clone)]
#[allow(dead_code)]
struct DisputeSnapshot {
    replicas_normal: u64,
    replicas_disputed: u64,
    replicas_armed: u64,
    replicas_tombstoned: u64,
}

impl ProtocolSim {
    fn snapshot_disputes(&self) -> DisputeSnapshot {
        let mut s = DisputeSnapshot::default();
        for op in &self.operators {
            for replica in op.replicas.values() {
                match replica.dispute_state {
                    DisputeState::Normal => s.replicas_normal += 1,
                    DisputeState::Disputed => s.replicas_disputed += 1,
                    DisputeState::Armed => s.replicas_armed += 1,
                    DisputeState::Tombstoned => s.replicas_tombstoned += 1,
                }
            }
        }
        s
    }
}

// =========================================================================
// Cross-ledger adversary attack: adv-majority quorum takes over honest ledger
// =========================================================================

/// 2-adv config, adv = {0, 1}. Op 3 (honest) has quorum [4, 0, 1] — two
/// adversaries in a Q=3 quorum means adv-majority. Adversary 0 publishes
/// DisputeEnter on op 3's ledger, then DisputeArmed, then DisputeAcquire
/// naming themselves as new_custodian. Honest member 4 sees all three
/// operations. With no actual violation observed, honest 4 has nothing to
/// arm against — the attacker ends up as sole armed candidate and wins
/// entropy trivially. Custody transfers.
///
/// This test exercises the path even though operator 4 is honest and did
/// nothing wrong. It's the canonical adv-majority-compromised-quorum attack.
#[test]
fn adv_majority_quorum_can_take_over_honest_ledger() {
    let mut sim = ProtocolSim::new(5, &[0, 1]);
    // Victim: op 3. Attackers: 0 and 1 (both in quorum [4, 0, 1]).
    let victim = 3;
    let attacker = 0;
    let victim_pk_before = sim.operators[victim].ledger.state.operator_key;

    // DisputeEnter signed by attacker. They ARE in victim's quorum.
    let last_valid = sim.operators[victim].ledger.state.sequence;
    let enter = LedgerOperation::DisputeEnter {
        last_valid_sequence: last_valid,
        reason: "fabricated".to_string(),
    };
    assert_eq!(
        sim.adversary_propose_on_victim(victim, attacker, enter),
        Outcome::Applied,
        "adv-majority lets DisputeEnter through"
    );
    assert_eq!(
        sim.operators[victim].ledger.state.dispute_state,
        DisputeState::Disputed
    );

    // DisputeArmed signed by attacker. Adv-majority signs; attacker added
    // to every quorum member's armed_candidates[victim].
    let armed = LedgerOperation::DisputeArmed {
        armed_block: sim.block_height,
        commitment_hash: [0x11; 20],
        target_reserves: format!("bcrt1q_{}", attacker),
    };
    assert_eq!(
        sim.adversary_propose_on_victim(victim, attacker, armed),
        Outcome::Applied
    );
    assert_eq!(
        sim.operators[victim].ledger.state.dispute_state,
        DisputeState::Armed
    );

    // DisputeAcquire naming attacker. Candidate list = [attacker_pk] (sole
    // armer), so attacker trivially wins entropy.
    let attacker_pk = sim.operators[attacker].public_key;
    let acquire = LedgerOperation::DisputeAcquire {
        new_custodian: attacker_pk,
        entropy_block_height: sim.block_height + 6,
        entropy_block_hash: [0x22; 32],
        spend_txid: [0x33; 32],
        new_reserves_address: format!("bcrt1q_attacker_{}", attacker),
    };
    assert_eq!(
        sim.adversary_propose_on_victim(victim, attacker, acquire),
        Outcome::Applied
    );

    // Custody transferred: victim's operator_key is now the attacker.
    assert_eq!(
        sim.operators[victim].ledger.state.operator_key, attacker_pk,
        "attacker is now the operator of op {}'s ledger",
        victim
    );
    assert_ne!(
        sim.operators[victim].ledger.state.operator_key, victim_pk_before,
        "operator_key changed as a result of the attack"
    );
    assert_eq!(
        sim.operators[victim].ledger.state.dispute_state,
        DisputeState::Normal
    );
}

// =========================================================================
// Regression: the exact sequence that surfaced the DEP-05 over-reserve bug.
// =========================================================================

/// Constructs the credit+lock+credit+fail sequence the fuzzer found before
/// the fix in commit 888b0e3. Under the old state machine, step 4 would push
/// total_deposit_balance past reserves_amount. With the fix, balance already
/// represents total obligation, so TransferFail is a no-op on balance and
/// the ledger stays within reserves.
#[test]
fn credit_lock_credit_fail_stays_within_reserves() {
    use deposits_core::ledger::Ledger;
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::types::compute_deposit_id;

    let (_sk0, pk0) = keypair(1);
    let mut ledger = Ledger::new_as_operator(pk0, "reserves".to_string(), 0);
    let reserves_amount: u64 = 400_000;
    ledger
        .append_operation(LedgerOperation::LedgerOpen {
            operator_id: pk0,
            reserves_id: "reserves".to_string(),
            genesis_block: 0,
            reserves_amount,
            collateral_amount: 0,
        })
        .unwrap();

    // D1: `pk(A)`, depositor A. D2: `pk(B)`, depositor B.
    let (sk_a, pk_a) = keypair(1001);
    let (_sk_b, pk_b) = keypair(1002);
    let desc_a = format!("pk({})", hex::encode(pk_a.serialize()));
    let desc_b = format!("pk({})", hex::encode(pk_b.serialize()));
    let did_a = compute_deposit_id(&desc_a);
    let did_b = compute_deposit_id(&desc_b);

    for (did, desc) in [(did_a, desc_a.clone()), (did_b, desc_b.clone())] {
        ledger
            .append_operation(LedgerOperation::DepositOpen {
                deposit_id: did,
                descriptor: desc,
                fees: Some(FeeStructure::default()),
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
            })
            .unwrap();
    }

    // Step 1: credit D1 to 100k.
    ledger
        .append_operation(LedgerOperation::InvoiceCredit {
            payment_hash: [0x11; 32],
            deposit_id: did_a,
            amount: 100_000,
            invoice_id: "c1".to_string(),
            sequence_number: ledger.state.sequence + 1,
        })
        .unwrap();
    assert_eq!(ledger.state.total_deposit_balance(), 100_000);

    // Step 2: TransferLock 90k+500 from D1 to D2.
    let (source, dest) = ((did_a, desc_a.clone(), 0u16), (did_b, desc_b, 0u16));
    let mut preimage = [0u8; 32];
    preimage[0] = 0xAA;
    let (lock_op, _tid) = build_transfer_lock(
        &source, &dest, 90_000, 500, 900_000, &sk_a, preimage, [0xCC; 32],
    );
    ledger.append_operation(lock_op).unwrap();
    // Under the fix, `balance` is unchanged by the lock.
    assert_eq!(ledger.state.deposits[&did_a].balance, 100_000);
    assert_eq!(ledger.state.deposits[&did_a].locked_balance, 90_500);
    assert_eq!(ledger.state.total_deposit_balance(), 100_000);

    // Step 3: credit D2 up to the honest headroom the old generator would
    // have computed from sum(balance). Under the fix, headroom is the true
    // remainder against reserves — so we credit to exactly reserves-100_000.
    ledger
        .append_operation(LedgerOperation::InvoiceCredit {
            payment_hash: [0x22; 32],
            deposit_id: did_b,
            amount: reserves_amount - 100_000,
            invoice_id: "c2".to_string(),
            sequence_number: ledger.state.sequence + 1,
        })
        .unwrap();
    assert_eq!(ledger.state.total_deposit_balance(), reserves_amount);

    // Step 4: the canary — previously TransferFail restored 90_500 into D1's
    // balance and pushed total to 490_500 > 400_000. Under the fix, balance
    // is unchanged, only `locked_balance` drops.
    let transfer_id = ledger
        .state
        .pending_transfers
        .keys()
        .copied()
        .next()
        .unwrap();
    ledger
        .append_operation(LedgerOperation::TransferFail {
            transfer_id,
            block_hash: [0x33; 32],
            reason: 1,
        })
        .unwrap();

    assert_eq!(
        ledger.state.total_deposit_balance(),
        reserves_amount,
        "TransferFail must not push total obligation over reserves"
    );
    assert!(
        ledger.state.total_deposit_balance() <= ledger.state.reserves_amount,
        "post-fail obligation must stay within reserves"
    );
    assert_eq!(ledger.state.deposits[&did_a].locked_balance, 0);
}

// =========================================================================
// Step 3: full invariant set, profit evaluation, scaled fuzz.
// =========================================================================

impl ProtocolSim {
    /// Walk every operator's ledger and every replica. Reports any violated
    /// invariants. Honest ledgers must be strictly conforming; adversary
    /// ledgers are exempt from reserves (that's the attack surface).
    fn check_all_invariants(&self) -> Vec<String> {
        let mut v = Vec::new();

        for (i, op) in self.operators.iter().enumerate() {
            let st = &op.ledger.state;
            let total = st.total_deposit_balance();

            // Honest-only: total obligation must stay within reserves.
            if self.honest.contains(&i) && total > st.reserves_amount {
                v.push(format!(
                    "honest op {}: total_deposits {} > reserves {}",
                    i, total, st.reserves_amount
                ));
            }

            // Universal: per DEP-05, locked_balance is a subset of balance.
            // locked > balance means we've locked more than the deposit owes.
            for (did, d) in &st.deposits {
                if d.locked_balance > d.balance {
                    v.push(format!(
                        "op {} deposit {}: locked_balance {} > balance {}",
                        i,
                        hex::encode(did),
                        d.locked_balance,
                        d.balance
                    ));
                }
            }

            // Universal: sum of pending claims against each deposit must not
            // exceed that deposit's locked_balance. Catches dangling pending
            // entries and accounting drift where claims outlive locks.
            let mut claimed: HashMap<DepositId, u64> = HashMap::new();
            for pending in st.pending_transfers.values() {
                let e = claimed.entry(pending.source_deposit_id).or_insert(0);
                *e = e.saturating_add(pending.amount.saturating_add(pending.fee));
            }
            for w in st.pending_withdrawals.values() {
                let e = claimed.entry(w.deposit_id).or_insert(0);
                *e = e.saturating_add(w.amount.saturating_add(w.fee_sats));
            }
            for lock in st.open_invoice_locks.values() {
                let e = claimed.entry(lock.deposit_id).or_insert(0);
                *e = e.saturating_add(lock.amount);
            }
            for (did, total_claimed) in &claimed {
                match st.deposits.get(did) {
                    Some(d) if d.locked_balance < *total_claimed => {
                        v.push(format!(
                            "op {} deposit {}: pending claims {} > locked_balance {}",
                            i,
                            hex::encode(did),
                            total_claimed,
                            d.locked_balance
                        ));
                    }
                    None => v.push(format!(
                        "op {}: pending op references missing deposit {}",
                        i,
                        hex::encode(did)
                    )),
                    _ => {}
                }
            }

            // History integrity (honest ledgers only — adversary path uses
            // apply_state_changes which skips the history append, so there's
            // nothing well-formed to check).
            if self.honest.contains(&i) {
                v.extend(self.check_history_integrity(i));
                v.extend(self.check_operator_key_transitions(i));
            }

            // Every replica held by this operator should track whatever the
            // owning operator has applied, but can lag. What we check: no
            // replica has state we couldn't have legitimately co-signed.
            for (&owner, replica) in &op.replicas {
                // An honest operator's replica of ANY ledger must itself be
                // conforming — we only co-sign conforming updates.
                if self.honest.contains(&i) {
                    let r_total = replica.total_deposit_balance();
                    if r_total > replica.reserves_amount {
                        v.push(format!(
                            "honest op {} holds non-conforming replica of op {}: \
                             total {} > reserves {}",
                            i, owner, r_total, replica.reserves_amount
                        ));
                    }
                }
            }
        }

        v
    }

    /// Chain continuity + sequence monotonicity on operator i's authoritative
    /// history. Each entry's sequence_number must be one more than the prior
    /// entry's; each entry's previous_hash must equal the prior entry's
    /// `current_hash` (the pre-signing hash, which is what
    /// `Ledger::append_operation_with_block` stores in `chain_tip_hash` and
    /// passes to the next update as `previous_hash`).
    fn check_history_integrity(&self, i: usize) -> Vec<String> {
        let mut v = Vec::new();
        let history = &self.operators[i].ledger.history;
        let mut expected_seq = 0u64;
        let mut prev_current: Option<[u8; 32]> = None;
        for (idx, update) in history.iter().enumerate() {
            if update.sequence_number != expected_seq {
                v.push(format!(
                    "op {} history[{}]: sequence_number {} (expected {})",
                    i, idx, update.sequence_number, expected_seq
                ));
            }
            if let Some(prev) = prev_current {
                if update.previous_hash != prev {
                    v.push(format!(
                        "op {} history[{}]: previous_hash breaks chain",
                        i, idx
                    ));
                }
            }
            prev_current = Some(update.current_hash);
            expected_seq = update.sequence_number.saturating_add(1);
        }
        v
    }

    /// operator_key may only be established by LedgerOpen or changed by
    /// DisputeAcquire. Walk history, track which of those ops set the key,
    /// and verify the final state matches.
    fn check_operator_key_transitions(&self, i: usize) -> Vec<String> {
        use deposits_protocol::TlvDecode;
        let mut v = Vec::new();
        let history = &self.operators[i].ledger.history;
        let mut last_key: Option<PublicKey> = None;
        for update in history {
            if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                match op {
                    LedgerOperation::LedgerOpen { operator_id, .. } => {
                        last_key = Some(operator_id);
                    }
                    LedgerOperation::DisputeAcquire { new_custodian, .. } => {
                        last_key = Some(new_custodian);
                    }
                    _ => {}
                }
            }
        }
        let current = self.operators[i].ledger.state.operator_key;
        if let Some(expected) = last_key {
            if expected != current {
                v.push(format!(
                    "op {}: operator_key {} does not match last LedgerOpen/DisputeAcquire's key {}",
                    i, current, expected
                ));
            }
        }
        v
    }

    /// Evaluate net adversary profit at the end of a run.
    ///
    /// An adversary "steals" from an operator if that operator's quorum has
    /// adversary majority AND the operator's ledger is over-reserved (meaning
    /// the adversary successfully credited more than the reserves backing).
    /// The stolen amount is the over-reserve excess.
    ///
    /// An adversary "loses" collateral when they're on a ledger with honest
    /// majority and still got an over-reserved update through (impossible
    /// under correct co-signing, but we measure for sanity).
    fn evaluate_profit(&self) -> ProfitReport {
        let mut stolen: i64 = 0;
        let mut slashed: i64 = 0;
        let mut profitable_ops: Vec<usize> = Vec::new();

        for (i, op) in self.operators.iter().enumerate() {
            let st = &op.ledger.state;
            let total = st.total_deposit_balance();
            let over = total.saturating_sub(st.reserves_amount);
            if over == 0 {
                continue;
            }

            let members = &op.quorum_members;
            let adv_signers = members
                .iter()
                .filter(|m| self.adversary.contains(m))
                .count();
            let threshold = members.len() / 2 + 1;

            if self.adversary.contains(&i) && adv_signers >= threshold {
                stolen += over as i64;
                profitable_ops.push(i);
            } else if adv_signers >= threshold {
                // Honest operator on an adversary-majority quorum — shouldn't
                // be over-reserved unless they themselves proposed it (they
                // won't). Count as stolen from user funds.
                stolen += over as i64;
                profitable_ops.push(i);
            } else {
                // Honest majority allowed non-conforming state — this should
                // be impossible under correct co-signing.
                slashed += over as i64;
            }
        }

        ProfitReport {
            stolen,
            slashed,
            net: stolen - slashed,
            profitable_ops,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct ProfitReport {
    stolen: i64,
    slashed: i64,
    net: i64,
    profitable_ops: Vec<usize>,
}

/// Full invariants & profit test: 5 operators, 2 adversary, Q=3, 100 runs × 200 ops.
/// With this configuration the adversary provably cannot achieve co-signer majority
/// on their own ledger, so net profit must be exactly 0.
#[test]
fn fuzz_protocol_5node_q3_2adv_no_profit() {
    let mut stats = FuzzStats::default();
    for seed in 0..100u64 {
        let mut sim = ProtocolSim::new(5, &[0, 1]);
        let mut rng = Rng::new(seed * 104729 + 17);

        for _ in 0..200 {
            match sim.step(&mut rng) {
                Some(Outcome::Applied) => stats.applied += 1,
                Some(Outcome::RejectedLocal) => stats.rejected_local += 1,
                Some(Outcome::RejectedCosign) => stats.rejected_cosign += 1,
                None => stats.noop += 1,
            }
        }

        let violations = sim.check_all_invariants();
        assert!(
            violations.is_empty(),
            "seed {} produced invariant violations: {:#?}",
            seed,
            violations
        );

        let profit = sim.evaluate_profit();
        assert_eq!(
            profit.net, 0,
            "seed {} — adversary profited despite provable impossibility: {:?}",
            seed, profit
        );
    }

    eprintln!("fuzz stats: {:?}", stats);
}

/// Sanity: with 3 adversaries in a 5-op Q=3 cluster, operator 0's quorum is
/// [1,2,3] — members 1 and 2 are adversary (majority). The adversary SHOULD
/// be able to push non-conforming updates through on op 0's ledger. This test
/// asserts profit > 0 across the run — if it's zero, the fuzzer isn't actually
/// modeling the attack surface.
#[test]
fn fuzz_protocol_5node_q3_3adv_profit_is_reachable() {
    let mut any_profit = 0i64;
    let mut profitable_seeds = 0u32;

    for seed in 0..100u64 {
        let mut sim = ProtocolSim::new(5, &[0, 1, 2]);
        let mut rng = Rng::new(seed * 104729 + 17);

        for _ in 0..200 {
            sim.step(&mut rng);
        }

        // Honest invariants must still hold — the adversary attacking op 0
        // shouldn't cause op 3 or 4 (honest) to become non-conforming.
        for (i, op) in sim.operators.iter().enumerate() {
            if !sim.honest.contains(&i) {
                continue;
            }
            let total = op.ledger.state.total_deposit_balance();
            assert!(
                total <= op.ledger.state.reserves_amount,
                "seed {} honest op {} over-reserved: {} > {}",
                seed,
                i,
                total,
                op.ledger.state.reserves_amount
            );
        }

        let profit = sim.evaluate_profit();
        if profit.net > 0 {
            profitable_seeds += 1;
            any_profit = any_profit.saturating_add(profit.net);
        }
    }

    assert!(
        profitable_seeds > 0,
        "with 3 adversaries & op 0's adv-majority quorum, adversary should \
         achieve profit in at least one seed. Got zero across 100 seeds — \
         the fuzzer may not be exercising the attack correctly."
    );

    eprintln!(
        "3-adversary run: {} profitable seeds out of 100, total stolen = {} sats",
        profitable_seeds, any_profit
    );
}

// =========================================================================
// Dispute flow tests
// =========================================================================

#[test]
fn dispute_enter_by_non_quorum_member_rejected() {
    let mut sim = ProtocolSim::new(5, &[0]);
    // Op 0's quorum = [1, 2, 3]. Op 4 is NOT a member.
    let result = sim.dispute_enter(0, 4, 1);
    assert_eq!(result, DisputeStepResult::NotAQuorumMember);
}

#[test]
fn dispute_full_flow_produces_single_winner() {
    // Adversary op 0 sits behind quorum [1, 2, 3]. Honest members 2 and 3
    // both initiate dispute and arm. Adversary member 1 also arms (competing).
    // Verify entropy selection picks exactly one winner.
    let mut sim = ProtocolSim::new(5, &[0, 1]);

    // Phase 1: adversary op 0 opens a deposit (a conforming op, just to
    // give the ledger some history).
    let (_sk, dpk) = keypair(9001);
    let descriptor = format!("pk({})", hex::encode(dpk.serialize()));
    let deposit_id = compute_deposit_id(&descriptor);
    let open = LedgerOperation::DepositOpen {
        deposit_id,
        descriptor,
        fees: Some(FeeStructure::default()),
        transfer_fees: None,
        payment_hash: None,
        invoice: None,
        cosigner_guarantee_signature: None,
        receive_requires_sig: false,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
    };
    assert_eq!(sim.propose(0, open), Outcome::Applied);

    // Phase 2: members 1, 2, 3 each initiate their own dispute branch.
    let last_valid = sim.operators[0].ledger.state.sequence;
    for disputer in [1usize, 2, 3] {
        assert_eq!(
            sim.dispute_enter(0, disputer, last_valid),
            DisputeStepResult::Applied,
            "disputer {} should successfully enter dispute",
            disputer
        );
    }

    // Phase 3: each branch arms.
    for disputer in [1usize, 2, 3] {
        assert_eq!(
            sim.dispute_arm(0, disputer),
            DisputeStepResult::Applied,
            "disputer {} should successfully arm",
            disputer
        );
    }

    // Phase 4: resolve with a fixed entropy block hash.
    let entropy_hash = [0x5Au8; 32];
    let (winner, branches) = sim.dispute_resolve(0, &[1, 2, 3], entropy_hash);

    assert!(
        winner.is_some(),
        "should have a winner with 3 armed candidates"
    );
    let winner_idx = winner.unwrap();
    assert!([1, 2, 3].contains(&winner_idx));

    let acquired: Vec<_> = branches
        .iter()
        .filter(|b| b.outcome == DisputeOutcome::Acquired)
        .collect();
    let yielded: Vec<_> = branches
        .iter()
        .filter(|b| b.outcome == DisputeOutcome::Yielded)
        .collect();
    assert_eq!(acquired.len(), 1, "exactly one branch should acquire");
    assert_eq!(yielded.len(), 2, "exactly two branches should yield");
    assert_eq!(acquired[0].disputer, winner_idx);
}

#[test]
fn dispute_unarmed_candidate_is_never_winner() {
    let mut sim = ProtocolSim::new(5, &[0]);
    let last_valid = sim.operators[0].ledger.state.sequence;

    // Only members 1 and 2 arm; member 3 enters but doesn't arm.
    sim.dispute_enter(0, 1, last_valid);
    sim.dispute_enter(0, 2, last_valid);
    sim.dispute_enter(0, 3, last_valid);
    sim.dispute_arm(0, 1);
    sim.dispute_arm(0, 2);
    // Deliberately skip arming member 3.

    let (winner, branches) = sim.dispute_resolve(0, &[1, 2, 3], [0x42; 32]);
    let three_branch = branches.iter().find(|b| b.disputer == 3).unwrap();
    assert_eq!(three_branch.outcome, DisputeOutcome::NeverArmed);
    assert!(winner == Some(1) || winner == Some(2));
}

#[test]
fn dispute_resolution_is_deterministic_for_same_entropy() {
    // Same config, same entropy, same winner — no matter when we run it.
    let mut sim_a = ProtocolSim::new(5, &[0]);
    let mut sim_b = ProtocolSim::new(5, &[0]);
    let entropy = [0xEEu8; 32];

    for sim in [&mut sim_a, &mut sim_b] {
        let lv = sim.operators[0].ledger.state.sequence;
        for d in [1, 2, 3] {
            sim.dispute_enter(0, d, lv);
            sim.dispute_arm(0, d);
        }
    }

    let (winner_a, _) = sim_a.dispute_resolve(0, &[1, 2, 3], entropy);
    let (winner_b, _) = sim_b.dispute_resolve(0, &[1, 2, 3], entropy);
    assert_eq!(winner_a, winner_b);
}

#[test]
fn dispute_enter_is_rejected_in_disputed_state() {
    // After DisputeEnter lands, further DisputeEnters on the same fork should
    // be rejected by the state machine (state is now Disputed, not Normal).
    let mut sim = ProtocolSim::new(5, &[0]);
    let lv = sim.operators[0].ledger.state.sequence;
    assert_eq!(sim.dispute_enter(0, 1, lv), DisputeStepResult::Applied);
    // Second attempt on the SAME disputer's fork should fail.
    assert_eq!(sim.dispute_enter(0, 1, lv), DisputeStepResult::Rejected);
}

/// Exploration: 10 nodes, 4 adversary, Q=3. With round-robin Q=[i+1,i+2,i+3],
/// adversary placement matters — clustered adversaries compromise multiple
/// ledgers, spread adversaries compromise none. Dumps stats, doesn't assert.
#[test]
#[ignore]
fn explore_10node_q3_4adv_placements() {
    let placements: &[(&str, &[usize])] = &[
        ("clustered {0,1,2,3}", &[0, 1, 2, 3]),
        ("spread {0,3,5,7}", &[0, 3, 5, 7]),
        ("pairs {0,1,5,6}", &[0, 1, 5, 6]),
        ("adjacent+one {0,1,2,5}", &[0, 1, 2, 5]),
        ("every-other {0,2,4,6}", &[0, 2, 4, 6]),
    ];

    for (label, adv) in placements {
        // Count how many operators have adversary-majority quorums.
        let mut adv_maj_operators = Vec::new();
        for i in 0..10 {
            let members: Vec<usize> = (1..=3).map(|j| (i + j) % 10).collect();
            let adv_count = members.iter().filter(|m| adv.contains(m)).count();
            if adv_count >= 2 {
                adv_maj_operators.push(i);
            }
        }

        let mut profitable_seeds = 0u32;
        let mut total_stolen = 0i64;
        let mut total_applied = 0u64;
        let mut total_rejected = 0u64;

        for seed in 0..100u64 {
            let mut sim = ProtocolSim::new(10, adv);
            let mut rng = Rng::new(seed * 104729 + 17);

            for _ in 0..500 {
                match sim.step(&mut rng) {
                    Some(Outcome::Applied) => total_applied += 1,
                    Some(Outcome::RejectedCosign) => total_rejected += 1,
                    _ => {}
                }
            }

            // Honest invariants must still hold.
            for (i, op) in sim.operators.iter().enumerate() {
                if !sim.honest.contains(&i) {
                    continue;
                }
                let total = op.ledger.state.total_deposit_balance();
                assert!(
                    total <= op.ledger.state.reserves_amount,
                    "{} seed {} honest op {} over-reserved: {} > {}",
                    label,
                    seed,
                    i,
                    total,
                    op.ledger.state.reserves_amount
                );
            }

            let profit = sim.evaluate_profit();
            if profit.net > 0 {
                profitable_seeds += 1;
                total_stolen += profit.net;
            }
        }

        eprintln!(
            "{:32} adv-maj on ops {:?}: {}/100 profitable, {} sats stolen, {}/{} apply/reject",
            label, adv_maj_operators, profitable_seeds, total_stolen, total_applied, total_rejected
        );
    }
}

/// What's actually accessible? Histogram of (operation type, proposer role,
/// outcome) across a fuzz run. Shows which operation types get generated,
/// who generated them, and whether honest cosigners let them through.
#[test]
#[ignore]
fn explore_op_histogram() {
    for (label, adv) in &[("5op-2adv", &[0usize, 1][..]), ("5op-3adv", &[0, 1, 2][..])] {
        // Accumulate (op_name, proposer_kind, outcome) → count.
        let mut hist: std::collections::BTreeMap<(&'static str, &'static str, &'static str), u64> =
            std::collections::BTreeMap::new();

        for seed in 0..100u64 {
            let mut sim = ProtocolSim::new(5, adv);
            let mut rng = Rng::new(seed * 104729 + 17);
            for _ in 0..500 {
                if let Some((outcome, name, is_adv)) = sim.step_detailed(&mut rng) {
                    let role = if is_adv { "adv" } else { "honest" };
                    let bucket = match outcome {
                        Outcome::Applied => "cosigned",
                        Outcome::RejectedCosign => "cosign_reject",
                        Outcome::RejectedLocal => "local_reject",
                    };
                    *hist.entry((name, role, bucket)).or_insert(0) += 1;
                }
            }
        }

        eprintln!(
            "\n=== {} — op histogram (proposer role × outcome) ===",
            label
        );
        eprintln!(
            "{:<22} {:>8} {:>8} {:>8} | {:>8} {:>8} {:>8}",
            "op_type", "H:cosig", "H:cos✗", "H:loc✗", "A:cosig", "A:cos✗", "A:loc✗"
        );
        // Roll up by op_name.
        let mut by_op: std::collections::BTreeMap<&'static str, [u64; 6]> =
            std::collections::BTreeMap::new();
        for (&(name, role, bucket), &count) in &hist {
            let slot = match (role, bucket) {
                ("honest", "cosigned") => 0,
                ("honest", "cosign_reject") => 1,
                ("honest", "local_reject") => 2,
                ("adv", "cosigned") => 3,
                ("adv", "cosign_reject") => 4,
                ("adv", "local_reject") => 5,
                _ => continue,
            };
            by_op.entry(name).or_insert([0; 6])[slot] += count;
        }
        for (name, counts) in &by_op {
            eprintln!(
                "{:<22} {:>8} {:>8} {:>8} | {:>8} {:>8} {:>8}",
                name, counts[0], counts[1], counts[2], counts[3], counts[4], counts[5]
            );
        }
    }
}

/// Observability: does the fuzzer actually exercise disputes? Reports the
/// distribution of replica DisputeStates for both the safe (2-adv) and
/// vulnerable (3-adv) configurations. In the 2-adv case we expect ~zero
/// disputes (adversary can't push through, so honest never auto-triggers).
/// In the 3-adv case we expect many Disputed replicas (honest refusers of
/// the adv-majority pushes through).
#[test]
#[ignore]
fn explore_dispute_activity() {
    for (label, adv) in &[
        ("2-adv safe", &[0usize, 1][..]),
        ("3-adv attacked", &[0, 1, 2][..]),
    ] {
        let mut total = DisputeSnapshot::default();
        let mut applied = 0u64;
        let mut rejected_cosign = 0u64;
        for seed in 0..100u64 {
            let mut sim = ProtocolSim::new(5, adv);
            let mut rng = Rng::new(seed * 104729 + 17);
            for _ in 0..200 {
                match sim.step(&mut rng) {
                    Some(Outcome::Applied) => applied += 1,
                    Some(Outcome::RejectedCosign) => rejected_cosign += 1,
                    _ => {}
                }
            }
            let s = sim.snapshot_disputes();
            total.replicas_normal += s.replicas_normal;
            total.replicas_disputed += s.replicas_disputed;
            total.replicas_armed += s.replicas_armed;
            total.replicas_tombstoned += s.replicas_tombstoned;
        }
        let total_replicas = total.replicas_normal
            + total.replicas_disputed
            + total.replicas_armed
            + total.replicas_tombstoned;
        eprintln!(
            "{:18} applied={} rejected_cosign={} | replicas: normal={} disputed={} armed={} tombstoned={} ({}% dispute rate)",
            label,
            applied,
            rejected_cosign,
            total.replicas_normal,
            total.replicas_disputed,
            total.replicas_armed,
            total.replicas_tombstoned,
            (total.replicas_disputed + total.replicas_armed + total.replicas_tombstoned) * 100
                / total_replicas.max(1)
        );
    }
}

/// Same config with a heavier load — 1000 runs × 1000 ops = 1M ops. Release-
/// mode benchmark/sanity run. Marked #[ignore] so it doesn't block normal
/// test runs; run with `cargo test --release fuzz_protocol_heavy -- --ignored --nocapture`.
#[test]
#[ignore]
fn fuzz_protocol_heavy() {
    use std::time::Instant;
    let start = Instant::now();
    let mut stats = FuzzStats::default();
    const RUNS: u64 = 1000;
    const OPS: u64 = 1000;

    for seed in 0..RUNS {
        let mut sim = ProtocolSim::new(5, &[0, 1]);
        let mut rng = Rng::new(seed * 104729 + 17);

        for _ in 0..OPS {
            match sim.step(&mut rng) {
                Some(Outcome::Applied) => stats.applied += 1,
                Some(Outcome::RejectedLocal) => stats.rejected_local += 1,
                Some(Outcome::RejectedCosign) => stats.rejected_cosign += 1,
                None => stats.noop += 1,
            }
        }

        let violations = sim.check_all_invariants();
        assert!(
            violations.is_empty(),
            "seed {} violations: {:?}",
            seed,
            violations
        );
        let profit = sim.evaluate_profit();
        assert_eq!(profit.net, 0, "seed {} profit: {:?}", seed, profit);
    }

    let elapsed = start.elapsed();
    eprintln!(
        "heavy fuzz: {} runs × {} ops = {} steps in {:?} ({:.1} μs/step) — stats {:?}",
        RUNS,
        OPS,
        RUNS * OPS,
        elapsed,
        elapsed.as_micros() as f64 / (RUNS * OPS) as f64,
        stats
    );
}
