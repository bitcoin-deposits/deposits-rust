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

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use deposits_core::descriptor::CoreWitnessVerifier;
use deposits_core::ledger::Ledger;
use deposits_protocol::messages::LedgerOperation;
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
    /// Total funds deposited into our ledger by external wallets.
    wallet_funds: u64,
}

/// The simulation environment.
struct ProtocolSim {
    operators: Vec<SimOperator>,
    honest: HashSet<usize>,
    adversary: HashSet<usize>,
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
        }
    }

    /// An honest co-signer's decision: would I sign this update?
    ///
    /// Checks:
    /// - Operation applies cleanly against my replica (not a hard error)
    /// - Post-apply state is conforming (no ConformanceViolations)
    /// - Dispute state is Normal
    fn honest_would_cosign(replica: &LedgerState, op: &LedgerOperation) -> bool {
        if replica.dispute_state != DisputeState::Normal {
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

        for &m in &members {
            let will_sign = if self.honest.contains(&m) {
                let replica = self.operators[m]
                    .replicas
                    .get(&proposer)
                    .expect("replica must exist for quorum member");
                Self::honest_would_cosign(replica, &op)
            } else {
                true
            };
            if will_sign {
                signers.push(m);
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
                .append_operation(op.clone())
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
        }

        Outcome::Applied
    }

    /// Give an operator `amount` of "external wallet funds" — these will be
    /// deposited into its ledger via InvoiceCredit. Represents customer
    /// deposits the operator is holding.
    fn wallet_deposit(&mut self, rng: &mut Rng, proposer: usize, amount: u64) -> Option<DepositId> {
        // Generate a depositor keypair and open a deposit.
        let depositor_seed = (proposer * 1000 + self.operators[proposer].deposits.len()) as u16;
        let (_dsk, dpk) = keypair(1000 + depositor_seed);
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
        self.operators[proposer].wallet_funds += amount;
        Some(deposit_id)
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

/// Generate a fresh DepositOpen op. The descriptor is derived from a fresh
/// keypair; the caller (propose pipeline) is responsible for tracking it in
/// `operators[proposer].deposits` after a successful Applied outcome.
fn gen_deposit_open(
    proposer: usize,
    deposits_count: usize,
    _rng: &mut Rng,
) -> (LedgerOperation, DepositId, String, u16) {
    let seed = (proposer * 1000 + deposits_count + 5000) as u16;
    let (_dsk, dpk) = keypair(seed);
    let descriptor = format!("pk({})", hex::encode(dpk.serialize()));
    let deposit_id = compute_deposit_id(&descriptor);
    let op = LedgerOperation::DepositOpen {
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
    (op, deposit_id, descriptor, seed)
}

/// An honest operator stays within reserves. Generates either a DepositOpen
/// (always safe) or an InvoiceCredit capped at the headroom under reserves.
fn gen_honest_op(sim: &ProtocolSim, proposer: usize, rng: &mut Rng) -> Option<GeneratedOp> {
    let op = &sim.operators[proposer];
    let total_balance: u64 = op.ledger.state.deposits.values().map(|d| d.balance).sum();
    let reserves = op.ledger.state.reserves_amount;
    let headroom = reserves.saturating_sub(total_balance);

    let choice = rng.range(100);
    if choice < 30 || op.deposits.is_empty() {
        let (o, did, desc, seed) = gen_deposit_open(proposer, op.deposits.len(), rng);
        Some(GeneratedOp {
            op: o,
            record_deposit: Some((did, desc, seed)),
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
        })
    } else {
        None
    }
}

/// An adversary generates unchecked operations: sometimes valid, sometimes
/// blatantly over-reserve. Honest co-signers should filter the bad ones.
fn gen_adversary_op(sim: &ProtocolSim, proposer: usize, rng: &mut Rng) -> Option<GeneratedOp> {
    let op = &sim.operators[proposer];
    let choice = rng.range(100);

    if choice < 25 || op.deposits.is_empty() {
        let (o, did, desc, seed) = gen_deposit_open(proposer, op.deposits.len(), rng);
        Some(GeneratedOp {
            op: o,
            record_deposit: Some((did, desc, seed)),
        })
    } else {
        // Credit — adversary doesn't respect reserves.
        let (did, _, _) = pick_deposit(op, rng)?;
        // Pick an amount; sometimes over reserves, sometimes not.
        let reserves = op.ledger.state.reserves_amount;
        let amount = if rng.range(100) < 40 {
            // Blatantly over-reserve.
            reserves * (2 + rng.range(5))
        } else {
            // Plausible amount.
            1_000 + rng.range(reserves.max(1))
        };
        let mut payment_hash = [0u8; 32];
        payment_hash[0] = rng.range(256) as u8;
        payment_hash[1] = rng.range(256) as u8;
        payment_hash[2] = (op.ledger.state.sequence & 0xff) as u8;
        payment_hash[3] = 0xAA; // adversary marker
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
        })
    }
}

/// Bundle of an operation plus bookkeeping the caller should perform on Applied.
struct GeneratedOp {
    op: LedgerOperation,
    /// If set, caller must push to operators[proposer].deposits on Applied.
    record_deposit: Option<(DepositId, String, u16)>,
}

impl ProtocolSim {
    /// Run one fuzzing step: pick a random operator, generate an op, propose it.
    /// Returns the outcome for inspection. Noop if no op can be generated.
    fn step(&mut self, rng: &mut Rng) -> Option<Outcome> {
        let n = self.operators.len();
        let proposer = rng.range(n as u64) as usize;
        let gen = if self.adversary.contains(&proposer) {
            gen_adversary_op(self, proposer, rng)
        } else {
            gen_honest_op(self, proposer, rng)
        }?;

        let outcome = self.propose(proposer, gen.op);
        if outcome == Outcome::Applied {
            if let Some(rec) = gen.record_deposit {
                self.operators[proposer].deposits.push(rec);
            }
        }
        Some(outcome)
    }

    /// An invariant that must hold on every honest operator's ledger: total
    /// deposit balance must never exceed reserves. Violated adversary ledgers
    /// are allowed (that's the attack surface — honest watchers detect it).
    fn check_honest_invariants(&self) -> Vec<String> {
        let mut violations = Vec::new();
        for (i, op) in self.operators.iter().enumerate() {
            if !self.honest.contains(&i) {
                continue;
            }
            let total: u64 = op.ledger.state.deposits.values().map(|d| d.balance).sum();
            if total > op.ledger.state.reserves_amount {
                violations.push(format!(
                    "honest op {} over-reserved: total_deposits={} reserves={}",
                    i, total, op.ledger.state.reserves_amount
                ));
            }
        }
        violations
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

        let violations = sim.check_honest_invariants();
        assert!(
            violations.is_empty(),
            "seed {} produced honest invariant violations: {:?}",
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
            let total: u64 = st.deposits.values().map(|d| d.balance).sum();

            // Honest operator invariants
            if self.honest.contains(&i) {
                if total > st.reserves_amount {
                    v.push(format!(
                        "honest op {}: total_deposits {} > reserves {}",
                        i, total, st.reserves_amount
                    ));
                }
                for (did, d) in &st.deposits {
                    if d.locked_balance > d.balance {
                        v.push(format!(
                            "honest op {}: deposit {:?} locked {} > balance {}",
                            i, did, d.locked_balance, d.balance
                        ));
                    }
                }
            }

            // Every replica held by this operator should track whatever the
            // owning operator has applied, but can lag. What we check: no
            // replica has state we couldn't have legitimately co-signed.
            for (&owner, replica) in &op.replicas {
                // An honest operator's replica of ANY ledger must itself be
                // conforming — we only co-sign conforming updates.
                if self.honest.contains(&i) {
                    let r_total: u64 = replica.deposits.values().map(|d| d.balance).sum();
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
            let total: u64 = st.deposits.values().map(|d| d.balance).sum();
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
            let total: u64 = op.ledger.state.deposits.values().map(|d| d.balance).sum();
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
            any_profit += profit.net;
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
