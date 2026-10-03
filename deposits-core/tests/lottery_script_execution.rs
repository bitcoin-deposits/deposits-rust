//! Lottery-script execution tests.
//!
//! A focused mini-interpreter for the Tapscript opcode subset our
//! lottery scripts use, run against scripts produced by
//! `LotteryScriptBuilder`. The goal is to validate that a witness
//! constructed for a given (N, winner) actually satisfies the script
//! and that the dispatch routes to the right pubkey — catches
//! witness-encoding and stack-state bugs that pure structural tests
//! (ENDIF counts, byte-equality reconstruction) would miss.
//!
//! Stubs:
//! - `OP_CHECKSIG` records the pubkey it was invoked with and pushes 1.
//!   Tests verify `last_checked_pubkey == expected_winner_pubkey`. We
//!   don't actually verify Schnorr signatures here — that's bitcoind's
//!   job and is well-tested elsewhere.
//! - `OP_CHECKSEQUENCEVERIFY` is a no-op verify. Same rationale: we're
//!   testing dispatch, not Bitcoin's CSV semantics.
//! - `OP_CHECKSIGADD` increments the stack counter (treats every sig
//!   as valid).
//!
//! For real on-chain verification, regtest is the right tool. This
//! test catches the "did the script we built actually do what we
//! think it does" class of bugs without needing a node.

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::opcodes::Opcode;
use bitcoin::blockdata::script::{read_scriptbool, read_scriptint, write_scriptint, Instruction};
use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Network, ScriptBuf};
use deposits_core::tapscript_reserves::{
    lottery_subset_indices, LotteryOutput, LotteryParticipant, LotteryScriptBuilder,
    LOTTERY_REVEAL_CSV_BLOCKS, MAX_LOTTERY_PARTICIPANTS,
};

// ============================================================================
// Mini Tapscript interpreter
// ============================================================================

#[derive(Debug)]
struct Interp {
    stack: Vec<Vec<u8>>,
    altstack: Vec<Vec<u8>>,
    cond_stack: Vec<bool>,
    /// Pubkey passed to the last executed OP_CHECKSIG.
    last_checked_pubkey: Option<Vec<u8>>,
}

impl Interp {
    /// Build an interpreter from a witness vector. Witness is given
    /// "spending order" — element 0 is at the bottom of the stack,
    /// element `len-1` is at the top.
    fn new(witness: Vec<Vec<u8>>) -> Self {
        Self {
            stack: witness,
            altstack: Vec::new(),
            cond_stack: Vec::new(),
            last_checked_pubkey: None,
        }
    }

    fn executing(&self) -> bool {
        self.cond_stack.iter().all(|&b| b)
    }

    fn pop(&mut self) -> Result<Vec<u8>, String> {
        self.stack
            .pop()
            .ok_or_else(|| "stack underflow".to_string())
    }

    fn push(&mut self, v: Vec<u8>) {
        self.stack.push(v);
    }

    fn pop_int(&mut self) -> Result<i64, String> {
        let v = self.pop()?;
        // Both `read_scriptint` and our number encoding are
        // little-endian sign-magnitude. read_scriptint requires
        // minimal encoding; since we always go through bitcoin's
        // helpers, that's fine.
        if v.is_empty() {
            return Ok(0);
        }
        read_scriptint(&v).map_err(|e| format!("scriptint decode: {:?}", e))
    }

    fn push_int(&mut self, n: i64) {
        if n == 0 {
            self.stack.push(Vec::new());
            return;
        }
        let mut buf = [0u8; 8];
        let len = write_scriptint(&mut buf, n);
        self.stack.push(buf[..len].to_vec());
    }

    fn run(&mut self, script: &ScriptBuf) -> Result<(), String> {
        for inst in script.instructions() {
            let inst = inst.map_err(|e| format!("script parse error: {:?}", e))?;
            self.step(inst)?;
        }
        if !self.cond_stack.is_empty() {
            return Err(format!(
                "unbalanced IF/ENDIF: cond_stack={:?}",
                self.cond_stack
            ));
        }
        Ok(())
    }

    fn step(&mut self, inst: Instruction) -> Result<(), String> {
        let executing = self.executing();

        // Control flow ops execute even when skipping, to maintain
        // nesting depth. Everything else is gated on `executing`.
        if let Instruction::Op(op) = inst {
            let v = op.to_u8();
            // OP_IF (0x63), OP_NOTIF (0x64), OP_ELSE (0x67), OP_ENDIF (0x68)
            match v {
                0x63 => {
                    let cond = if executing {
                        let val = self.pop()?;
                        read_scriptbool(&val)
                    } else {
                        false
                    };
                    self.cond_stack.push(cond);
                    return Ok(());
                }
                0x64 => {
                    let cond = if executing {
                        let val = self.pop()?;
                        !read_scriptbool(&val)
                    } else {
                        false
                    };
                    self.cond_stack.push(cond);
                    return Ok(());
                }
                0x67 => {
                    let last = self.cond_stack.last_mut().ok_or("OP_ELSE without OP_IF")?;
                    *last = !*last;
                    return Ok(());
                }
                0x68 => {
                    self.cond_stack.pop().ok_or("OP_ENDIF without OP_IF")?;
                    return Ok(());
                }
                _ => {}
            }
        }

        if !executing {
            return Ok(());
        }

        // First, handle script_num pushes: OP_PUSHNUM_NEG1 / OP_PUSHNUM_1..16
        if let Some(n) = inst.script_num() {
            self.push_int(n);
            return Ok(());
        }

        match inst {
            Instruction::PushBytes(b) => {
                self.push(b.as_bytes().to_vec());
                Ok(())
            }
            Instruction::Op(op) => self.exec_op(op),
        }
    }

    fn exec_op(&mut self, op: Opcode) -> Result<(), String> {
        match op.to_u8() {
            // OP_DUP
            0x76 => {
                let top = self.stack.last().ok_or("OP_DUP: stack empty")?.clone();
                self.push(top);
            }
            // OP_DROP
            0x75 => {
                self.pop()?;
            }
            // OP_SWAP
            0x7c => {
                let n = self.stack.len();
                if n < 2 {
                    return Err("OP_SWAP: stack < 2".into());
                }
                self.stack.swap(n - 1, n - 2);
            }
            // OP_TOALTSTACK
            0x6b => {
                let v = self.pop()?;
                self.altstack.push(v);
            }
            // OP_FROMALTSTACK
            0x6c => {
                let v = self
                    .altstack
                    .pop()
                    .ok_or("OP_FROMALTSTACK: altstack empty")?;
                self.push(v);
            }
            // OP_SIZE — pushes len(top) without popping
            0x82 => {
                let len = self.stack.last().ok_or("OP_SIZE: stack empty")?.len() as i64;
                self.push_int(len);
            }
            // OP_HASH160
            0xa9 => {
                let v = self.pop()?;
                let h = hash160::Hash::hash(&v);
                self.push(h.to_byte_array().to_vec());
            }
            // OP_EQUAL
            0x87 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push_int(if a == b { 1 } else { 0 });
            }
            // OP_EQUALVERIFY
            0x88 => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a != b {
                    return Err(format!(
                        "OP_EQUALVERIFY failed: {} != {}",
                        hex::encode(&a),
                        hex::encode(&b)
                    ));
                }
            }
            // OP_VERIFY
            0x69 => {
                let v = self.pop()?;
                if !read_scriptbool(&v) {
                    return Err("OP_VERIFY failed".into());
                }
            }
            // OP_ADD
            0x93 => {
                let b = self.pop_int()?;
                let a = self.pop_int()?;
                self.push_int(a + b);
            }
            // OP_SUB
            0x94 => {
                let b = self.pop_int()?;
                let a = self.pop_int()?;
                self.push_int(a - b);
            }
            // OP_GREATERTHANOREQUAL
            0xa2 => {
                let b = self.pop_int()?;
                let a = self.pop_int()?;
                self.push_int(if a >= b { 1 } else { 0 });
            }
            // OP_LESSTHANOREQUAL
            0xa1 => {
                let b = self.pop_int()?;
                let a = self.pop_int()?;
                self.push_int(if a <= b { 1 } else { 0 });
            }
            // OP_CHECKSIG (stubbed): stack is [..., sig, pubkey] with
            // pubkey on top. An empty sig means "this slot didn't
            // sign" — push 0. A non-empty sig is treated as valid for
            // its paired pubkey — push 1 and record the pubkey.
            0xac => {
                let pubkey = self.pop()?;
                let sig = self.pop()?;
                if sig.is_empty() {
                    self.push_int(0);
                } else {
                    self.last_checked_pubkey = Some(pubkey);
                    self.push_int(1);
                }
            }
            // OP_CHECKSIGADD (stubbed): stack is [..., sig, n, pubkey]
            // with pubkey on top. Empty sig leaves n unchanged; non-
            // empty sig increments n. Models the k-of-n CHECKSIGADD
            // pattern where unused signature slots are pushed empty.
            0xba => {
                let _pubkey = self.pop()?;
                let n = self.pop_int()?;
                let sig = self.pop()?;
                if sig.is_empty() {
                    self.push_int(n);
                } else {
                    self.push_int(n + 1);
                }
            }
            // OP_CHECKSEQUENCEVERIFY (no-op verify in our model)
            0xb2 => {
                // CSV doesn't pop in real Bitcoin script; we just verify
                // top is non-negative and non-empty (well-formed value)
                // and leave the stack unchanged.
                let _ = self.stack.last().ok_or("OP_CSV: stack empty")?;
            }
            // OP_NOP
            0x61 => {}
            other => return Err(format!("unimplemented opcode 0x{:02x}", other)),
        }
        Ok(())
    }
}

// ============================================================================
// Test fixtures
// ============================================================================

/// Deterministic pubkey seeded by `i`. Matches the helper used in the
/// in-tree `tapscript_reserves` tests so we can build the same
/// participants outside that module.
fn pk(i: u8) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let mut bytes = [0u8; 32];
    bytes[31] = i;
    let sk = SecretKey::from_slice(&bytes).expect("valid sk");
    sk.public_key(&secp).x_only_public_key().0
}

/// Build a participant whose preimage will be `[0x00; 16 + contribution]`.
/// The commitment hash is HASH160 of that preimage.
fn participant(i: u8, contribution: usize) -> (LotteryParticipant, Vec<u8>) {
    let preimage = vec![0u8; 16 + contribution];
    let commit = hash160::Hash::hash(&preimage).to_byte_array();
    (
        LotteryParticipant::new(pk(i), commit, "bcrt1p...".to_string()),
        preimage,
    )
}

fn standard_recovery_voters() -> Vec<XOnlyPublicKey> {
    vec![pk(50), pk(51), pk(52), pk(53)]
}

/// Build a lottery script + witness for a known winner, run the
/// interpreter, and return the recorded last-checked pubkey. The
/// expected winner index is `(sum of contributions) mod N`.
fn run_lottery(contributions: &[usize]) -> Result<XOnlyPublicKey, String> {
    let n = contributions.len();
    let mut participants = Vec::with_capacity(n);
    let mut preimages = Vec::with_capacity(n);
    for (i, c) in contributions.iter().enumerate() {
        let (p, pre) = participant((i + 1) as u8, *c);
        participants.push(p);
        preimages.push(pre);
    }

    let builder = LotteryScriptBuilder::new(
        participants.clone(),
        standard_recovery_voters(),
        3,
        Network::Regtest,
    );
    let script = builder
        .build_lottery_script()
        .map_err(|e| format!("build_lottery_script: {:?}", e))?;

    // Witness order (bottom to top): sig, preimage_N, preimage_{N-1},
    // ..., preimage_1. The script consumes preimage_1 first.
    let sig = vec![0xAA; 64]; // dummy schnorr sig
    let mut witness = vec![sig];
    for p in preimages.iter().rev() {
        witness.push(p.clone());
    }

    let mut interp = Interp::new(witness);
    interp.run(&script)?;

    // Final stack should be [TRUE]
    let top = interp.stack.last().ok_or("script left empty stack")?;
    if !read_scriptbool(top) {
        return Err(format!("script returned FALSE: stack={:?}", interp.stack));
    }
    if interp.stack.len() != 1 {
        return Err(format!(
            "script left {} items on stack, expected 1",
            interp.stack.len()
        ));
    }

    let pubkey_bytes = interp
        .last_checked_pubkey
        .ok_or("OP_CHECKSIG was never executed — dispatch must have fallen through")?;
    XOnlyPublicKey::from_slice(&pubkey_bytes).map_err(|e| {
        format!(
            "recorded non-pubkey {}: {:?}",
            hex::encode(&pubkey_bytes),
            e
        )
    })
}

// ============================================================================
// Tests
// ============================================================================

/// Run `leaf` against `witness` (bottom to top, without leaf/control);
/// the pubkey the dispatch checked, or why it failed.
fn run_leaf(leaf: &ScriptBuf, witness: Vec<Vec<u8>>) -> Result<XOnlyPublicKey, String> {
    let mut interp = Interp::new(witness);
    interp.run(leaf)?;
    let top = interp.stack.last().ok_or("script left empty stack")?;
    if !read_scriptbool(top) || interp.stack.len() != 1 {
        return Err(format!(
            "script did not succeed cleanly: {:?}",
            interp.stack
        ));
    }
    let pubkey_bytes = interp
        .last_checked_pubkey
        .ok_or("OP_CHECKSIG never executed")?;
    XOnlyPublicKey::from_slice(&pubkey_bytes).map_err(|e| format!("{:?}", e))
}

fn lottery_with(contributions: &[usize]) -> (LotteryOutput, Vec<Vec<u8>>) {
    let mut participants = Vec::new();
    let mut preimages = Vec::new();
    for (i, c) in contributions.iter().enumerate() {
        let (p, pre) = participant((i + 1) as u8, *c);
        participants.push(p);
        preimages.push(pre);
    }
    let out = LotteryScriptBuilder::new(
        participants,
        standard_recovery_voters(),
        3,
        Network::Regtest,
    )
    .build()
    .unwrap();
    (out, preimages)
}

/// Full set: the dispatch picks `sum mod k` for derived preimages, at every k.
#[test]
fn derived_preimages_spend_the_full_set_leaf_and_agree_with_calculate_winner() {
    use bitcoin::hashes::sha256;
    for k in 2..=MAX_LOTTERY_PARTICIPANTS {
        let mut participants = Vec::new();
        let mut preimages = Vec::new();
        for i in 0..k {
            let seed = sha256::Hash::hash(&[k as u8, i as u8]).to_byte_array();
            let pre = LotteryOutput::derive_lottery_preimage(&seed);
            let commit = hash160::Hash::hash(&pre).to_byte_array();
            participants.push(LotteryParticipant::new(
                pk((i + 1) as u8),
                commit,
                "t".into(),
            ));
            preimages.push(pre);
        }
        let out = LotteryScriptBuilder::new(
            participants.clone(),
            standard_recovery_voters(),
            3,
            Network::Regtest,
        )
        .build()
        .unwrap();
        let mut witness = vec![vec![0xAA; 64]];
        witness.extend(preimages.iter().rev().cloned());
        let won = run_leaf(&out.lottery_script, witness).unwrap();
        let expect = LotteryOutput::calculate_winner(&preimages).unwrap();
        assert_eq!(won, participants[expect].pubkey, "k={}", k);
    }
}

/// Every revealer subset of a 5-participant lottery dispatches to its own
/// draw's winner once three of the four voters attest.
#[test]
fn every_subset_leaf_dispatches_to_its_winner_with_attestation() {
    let (out, preimages) = lottery_with(&[7, 60, 1, 33, 12]);
    for idx in lottery_subset_indices(5) {
        let leaf = out.subset_leaf(&idx).unwrap();
        assert!(leaf
            .as_bytes()
            .starts_with(&[0x01, LOTTERY_REVEAL_CSV_BLOCKS as u8, 0xb2, 0x75]));
        let sub: Vec<Vec<u8>> = idx.iter().map(|&i| preimages[i].clone()).collect();
        let mut witness = vec![vec![0xAA; 64]];
        witness.extend(sub.iter().rev().cloned());
        // voters (sorted) 0, 1, 3 sign; 2 absent; slot 0 ends on top
        for slot in (0..4).rev() {
            witness.push(if slot == 2 { vec![] } else { vec![0xBB; 64] });
        }
        let won = run_leaf(leaf, witness).unwrap();
        let expect = LotteryOutput::subset_winner(&idx, &sub).unwrap();
        assert_eq!(won, out.participants[expect].pubkey, "subset {:?}", idx);
    }
}

#[test]
fn subset_leaf_fails_below_the_attestation_threshold() {
    let (out, preimages) = lottery_with(&[7, 60, 1]);
    let idx = vec![0, 2];
    let mut witness = vec![vec![0xAA; 64], preimages[2].clone(), preimages[0].clone()];
    for slot in (0..4).rev() {
        witness.push(if slot < 2 { vec![0xBB; 64] } else { vec![] });
    }
    let err = run_leaf(out.subset_leaf(&idx).unwrap(), witness).unwrap_err();
    assert!(err.contains("OP_VERIFY"), "{}", err);
}

#[test]
fn subset_leaf_rejects_a_preimage_outside_the_subset() {
    let (out, preimages) = lottery_with(&[7, 60, 1]);
    let idx = vec![0, 2];
    // participant 1's preimage in place of participant 2's
    let mut witness = vec![vec![0xAA; 64], preimages[1].clone(), preimages[0].clone()];
    for _ in 0..4 {
        witness.push(vec![0xBB; 64]);
    }
    assert!(run_leaf(out.subset_leaf(&idx).unwrap(), witness).is_err());
}

/// All-maximum contributions (420 at k = 7) reduce to 0: six conditional
/// subtractions cover sums below 64k.
#[test]
fn maximum_contributions_reduce_correctly() {
    let (out, preimages) = lottery_with(&[60; 7]);
    let mut witness = vec![vec![0xAA; 64]];
    witness.extend(preimages.iter().rev().cloned());
    assert_eq!(
        run_leaf(&out.lottery_script, witness).unwrap(),
        out.participants[0].pubkey
    );
    for k in 2..=7usize {
        let (out, preimages) = lottery_with(&vec![60; k]);
        let mut witness = vec![vec![0xAA; 64]];
        witness.extend(preimages.iter().rev().cloned());
        let expect = (60 * k) % k;
        assert_eq!(
            run_leaf(&out.lottery_script, witness).unwrap(),
            out.participants[expect].pubkey
        );
    }
}

#[test]
fn full_set_rejects_out_of_range_preimages() {
    for bad_len in [16usize, 77] {
        let pre = vec![0u8; bad_len];
        let commit = hash160::Hash::hash(&pre).to_byte_array();
        let (p1, pre1) = participant(1, 5);
        let p0 = LotteryParticipant::new(pk(9), commit, "t".into());
        let out = LotteryScriptBuilder::new(
            vec![p0, p1],
            standard_recovery_voters(),
            3,
            Network::Regtest,
        )
        .build()
        .unwrap();
        let witness = vec![vec![0xAA; 64], pre1, pre];
        let err = run_leaf(&out.lottery_script, witness).unwrap_err();
        assert!(err.contains("OP_VERIFY failed"), "len {}: {}", bad_len, err);
    }
}

#[test]
fn every_participant_wins_some_draw() {
    // Varying one contribution walks the winner through every member.
    for k in 2..=7usize {
        let mut seen = std::collections::BTreeSet::new();
        for c in 1..=k {
            let mut cs = vec![1usize; k];
            cs[0] = c;
            let (out, preimages) = lottery_with(&cs);
            let mut witness = vec![vec![0xAA; 64]];
            witness.extend(preimages.iter().rev().cloned());
            seen.insert(run_leaf(&out.lottery_script, witness).unwrap().serialize());
        }
        assert_eq!(seen.len(), k);
    }
}

#[test]
fn create_subset_claim_witness_layout() {
    let (out, preimages) = lottery_with(&[7, 60, 1]);
    let idx = vec![1, 2];
    let sub = vec![preimages[1].clone(), preimages[2].clone()];
    let sigs = vec![Some([1u8; 64]), None, Some([3u8; 64]), Some([4u8; 64])];
    let w = out
        .create_subset_claim_witness(&idx, &[9u8; 64], &sub, &sigs)
        .unwrap();
    let items: Vec<Vec<u8>> = w.iter().map(|x| x.to_vec()).collect();
    assert_eq!(items.len(), 1 + 2 + 4 + 2);
    assert_eq!(items[0], vec![9u8; 64]);
    assert_eq!(items[1], sub[1]);
    assert_eq!(items[2], sub[0]);
    assert_eq!(items[3], vec![4u8; 64]);
    assert!(items[5].is_empty());
    assert_eq!(items[6], vec![1u8; 64]);
    assert_eq!(&items[7], out.subset_leaf(&idx).unwrap().as_bytes());
    assert!(out
        .create_subset_claim_witness(&[0, 1, 2], &[9u8; 64], &preimages, &sigs)
        .is_err());
    assert!(out
        .create_subset_claim_witness(&idx, &[9u8; 64], &sub, &sigs[..3])
        .is_err());
}

/// Recovery long-tail leaf at CSV 144 with threshold T (=3 in our
/// test setup). Three of the four recovery voters sign; the leaf
/// should accept with the multisig 1+1+1 = 3 ≥ threshold(3).
/// Verifies the CHECKSIG/CHECKSIGADD/GREATERTHANOREQUAL chain.
#[test]
fn high_q_recovery_leaf_csv144_threshold_t() {
    let n = 15usize;
    let mut participants = Vec::new();
    for i in 0..n {
        let (p, _) = participant((i + 1) as u8, 1);
        participants.push(p);
    }
    let recovery_voters = standard_recovery_voters();

    // Build the recovery leaf for CSV 144, threshold T=3.
    let recovery_script =
        LotteryScriptBuilder::new(participants, recovery_voters.clone(), 3, Network::Regtest)
            .build_recovery_script(144)
            .expect("recovery script should build at threshold 3");

    // Build a witness: 4 voter slots, three sigs filled, one empty.
    // Recovery script sorts pubkeys before laying out CHECKSIG/
    // CHECKSIGADD, so the witness slots must align with sorted order.
    // Multisig witness order (top to bottom of stack at CHECKSIG
    // time): the *first* CHECKSIG pops the *top* sig, then later
    // CHECKSIGADDs each pop the next. So the witness vec's last
    // element is consumed first, matching the first sorted pubkey.
    let mut sorted_voters = recovery_voters.clone();
    sorted_voters.sort_by_key(|pk| pk.serialize());
    let dummy_sig = vec![0xAAu8; 64];

    // Sign with voters 0, 2, 3 (skip voter 1 → empty in slot 1).
    // The witness is stack-bottom-to-stack-top, so reverse so
    // sorted_voters[0]'s sig is on top.
    let mut sig_slots: Vec<Vec<u8>> = vec![Vec::new(); 4];
    sig_slots[0] = dummy_sig.clone();
    sig_slots[2] = dummy_sig.clone();
    sig_slots[3] = dummy_sig.clone();
    let stack_inputs: Vec<Vec<u8>> = sig_slots.into_iter().rev().collect();

    let mut interp = Interp::new(stack_inputs);
    interp
        .run(&recovery_script)
        .expect("recovery leaf with 3-of-4 sigs should accept");

    let top = interp.stack.last().expect("recovery left empty stack");
    assert!(
        read_scriptbool(top),
        "recovery leaf returned FALSE: stack={:?}",
        interp.stack
    );
}

/// Recovery long-tail leaf at CSV 144 threshold T, but only TWO
/// signatures provided. Should fail the threshold check
/// (2 < 3 → GREATERTHANOREQUAL pushes 0 → script returns FALSE).
#[test]
fn high_q_recovery_leaf_rejects_below_threshold() {
    let n = 15usize;
    let mut participants = Vec::new();
    for i in 0..n {
        let (p, _) = participant((i + 1) as u8, 1);
        participants.push(p);
    }
    let recovery_voters = standard_recovery_voters();

    let recovery_script =
        LotteryScriptBuilder::new(participants, recovery_voters, 3, Network::Regtest)
            .build_recovery_script(144)
            .unwrap();

    // Only 2 sigs in 4 slots — below threshold 3.
    let dummy_sig = vec![0xAAu8; 64];
    let mut sig_slots: Vec<Vec<u8>> = vec![Vec::new(); 4];
    sig_slots[0] = dummy_sig.clone();
    sig_slots[3] = dummy_sig.clone();
    let stack_inputs: Vec<Vec<u8>> = sig_slots.into_iter().rev().collect();

    let mut interp = Interp::new(stack_inputs);
    interp.run(&recovery_script).unwrap();

    // Script ran but the GREATERTHANOREQUAL pushed 0 because 2 < 3.
    let top = interp.stack.last().unwrap();
    assert!(
        !read_scriptbool(top),
        "recovery leaf with sub-threshold sigs must return FALSE; stack={:?}",
        interp.stack
    );
}

/// Timeout-recovery leaf at CSV 8064 with threshold 1. A single
/// recovery voter's signature suffices. This is the very-final
/// escape hatch for retry-depth exhaustion.
#[test]
fn high_q_timeout_recovery_leaf_csv8064_threshold_one() {
    let n = 15usize;
    let mut participants = Vec::new();
    for i in 0..n {
        let (p, _) = participant((i + 1) as u8, 1);
        participants.push(p);
    }
    let recovery_voters = standard_recovery_voters();

    // Build the timeout-recovery leaf: CSV 8064, threshold 1.
    let timeout_script =
        LotteryScriptBuilder::new(participants, recovery_voters, 1, Network::Regtest)
            .build_recovery_script(deposits_core::TIMEOUT_RECOVERY_CSV_BLOCKS)
            .expect("timeout-recovery script should build at threshold 1");

    // Single-sig case: recovery script emits a bare
    // <pubkey> OP_CHECKSIG. Witness is just the sig.
    let dummy_sig = vec![0xAAu8; 64];
    let stack_inputs = vec![dummy_sig];

    let mut interp = Interp::new(stack_inputs);
    interp
        .run(&timeout_script)
        .expect("timeout-recovery should accept single sig");

    let top = interp.stack.last().expect("script left empty stack");
    assert!(
        read_scriptbool(top),
        "timeout-recovery leaf returned FALSE: stack={:?}",
        interp.stack
    );
}

/// Negative case for the timeout-recovery leaf: empty witness
/// (nobody signed). The bare OP_CHECKSIG sees an empty sig and
/// pushes 0, so the script returns FALSE.
#[test]
fn high_q_timeout_recovery_rejects_empty_signature() {
    let n = 15usize;
    let mut participants = Vec::new();
    for i in 0..n {
        let (p, _) = participant((i + 1) as u8, 1);
        participants.push(p);
    }
    let recovery_voters = standard_recovery_voters();

    let timeout_script =
        LotteryScriptBuilder::new(participants, recovery_voters, 1, Network::Regtest)
            .build_recovery_script(deposits_core::TIMEOUT_RECOVERY_CSV_BLOCKS)
            .unwrap();

    let stack_inputs: Vec<Vec<u8>> = vec![Vec::new()]; // empty sig
    let mut interp = Interp::new(stack_inputs);
    interp.run(&timeout_script).unwrap();

    let top = interp.stack.last().unwrap();
    assert!(
        !read_scriptbool(top),
        "timeout-recovery with empty sig must return FALSE"
    );
}

// ============================================================================
// Armer share output (DEP-06 §"Arm-and-reveal forfeiture")
// ============================================================================

use deposits_core::tapscript_reserves::{
    build_armer_reveal_leaf, build_armer_share_output, build_armer_sweep_leaf,
    ARMER_SHARE_SWEEP_CSV_BLOCKS,
};

/// The reveal-claim leaf accepts a valid `(preimage, signature)`: the
/// preimage's HASH160 matches the commitment, then the armer's CHECKSIG
/// verifies the signature.
#[test]
fn armer_reveal_leaf_accepts_valid_reveal() {
    let preimage = vec![0x42u8; 17];
    let commitment = hash160::Hash::hash(&preimage).to_byte_array();
    let armer_xonly = pk(1);

    let leaf = build_armer_reveal_leaf(&commitment, &armer_xonly);

    // Witness order (bottom→top): sig, preimage. The script consumes
    // preimage first via OP_HASH160, then sig via OP_CHECKSIG.
    let sig = vec![0xAAu8; 64];
    let stack_inputs: Vec<Vec<u8>> = vec![sig, preimage];

    let mut interp = Interp::new(stack_inputs);
    interp
        .run(&leaf)
        .expect("reveal-claim should accept valid reveal");

    let top = interp.stack.last().expect("non-empty stack");
    assert!(
        read_scriptbool(top),
        "reveal-claim should leave TRUE on stack, got: {:?}",
        interp.stack
    );
    let pk_bytes = interp
        .last_checked_pubkey
        .expect("OP_CHECKSIG must execute");
    let recorded = XOnlyPublicKey::from_slice(&pk_bytes).unwrap();
    assert_eq!(recorded, armer_xonly, "recorded pubkey must match armer");
}

/// An attacker who knows the commitment but not the preimage cannot
/// satisfy the reveal-claim leaf — any preimage they provide that
/// differs from the committed one fails HASH160 / EQUALVERIFY.
#[test]
fn armer_reveal_leaf_rejects_wrong_preimage() {
    let real_preimage = vec![0x42u8; 17];
    let commitment = hash160::Hash::hash(&real_preimage).to_byte_array();
    let armer_xonly = pk(1);

    let leaf = build_armer_reveal_leaf(&commitment, &armer_xonly);

    // Witness uses a *different* preimage — same length, different content.
    let wrong_preimage = vec![0xFFu8; 17];
    let sig = vec![0xAAu8; 64];
    let stack_inputs: Vec<Vec<u8>> = vec![sig, wrong_preimage];

    let mut interp = Interp::new(stack_inputs);
    let result = interp.run(&leaf);
    assert!(
        result.is_err() && result.as_ref().unwrap_err().contains("OP_EQUALVERIFY"),
        "wrong preimage must fail EQUALVERIFY, got: {:?}",
        result
    );
}

/// An attacker with the right preimage but the wrong key (or no sig)
/// cannot spend — the CHECKSIG step pushes FALSE, leaving the stack at
/// the bottom of the script as a falsy value (no signature, no spend).
#[test]
fn armer_reveal_leaf_rejects_missing_signature() {
    let preimage = vec![0x42u8; 17];
    let commitment = hash160::Hash::hash(&preimage).to_byte_array();
    let armer_xonly = pk(1);

    let leaf = build_armer_reveal_leaf(&commitment, &armer_xonly);

    // Empty sig — `Interp::CHECKSIG` (stubbed) treats this as "no
    // signature provided" and pushes 0.
    let empty_sig: Vec<u8> = vec![];
    let stack_inputs: Vec<Vec<u8>> = vec![empty_sig, preimage];

    let mut interp = Interp::new(stack_inputs);
    interp
        .run(&leaf)
        .expect("script should execute (HASH160 path passes), even if it pushes FALSE");
    let top = interp.stack.last().expect("non-empty stack");
    assert!(
        !read_scriptbool(top),
        "missing-sig reveal must push FALSE, got: {:?}",
        interp.stack
    );
}

/// The recovery-sweep leaf requires the CSV-checked threshold of
/// recovery-voter signatures. Build the leaf, supply a sufficient sig
/// set, and verify the script accepts.
#[test]
fn armer_sweep_leaf_accepts_threshold_signatures() {
    // 4 voters, threshold 3.
    let voters: Vec<XOnlyPublicKey> = (10..14).map(|i| pk(i as u8)).collect();
    let threshold = 3usize;
    let leaf = build_armer_sweep_leaf(&voters, threshold).unwrap();

    // The script sorts keys before encoding. Sort our local copy the
    // same way so we can put signatures in the matching slots.
    let mut sorted = voters.clone();
    sorted.sort_by_key(|k| k.serialize());

    // 3-of-4 sigs: first three slots non-empty, last empty.
    // Witness layout for CHECKSIG/CHECKSIGADD pattern (bottom→top):
    //   sig_last, sig_..., sig_first  (script consumes sig_first first)
    // i.e., sigs in REVERSE of the key order.
    let nonempty: Vec<u8> = vec![0xAAu8; 64];
    let empty: Vec<u8> = vec![];
    let sigs_in_key_order: Vec<Vec<u8>> = vec![
        nonempty.clone(), // sig for sorted[0]
        nonempty.clone(), // sig for sorted[1]
        nonempty.clone(), // sig for sorted[2]
        empty,            // no sig for sorted[3]
    ];
    let stack_inputs: Vec<Vec<u8>> = sigs_in_key_order.iter().rev().cloned().collect();

    let mut interp = Interp::new(stack_inputs);
    interp
        .run(&leaf)
        .expect("sweep leaf should accept threshold sigs");
    let top = interp.stack.last().expect("non-empty stack");
    assert!(
        read_scriptbool(top),
        "sweep leaf should leave TRUE: {:?}",
        interp.stack
    );
}

/// `build_armer_share_output` produces a Taproot output with two leaves
/// (reveal + sweep), each reachable via its own control block. The
/// internal key is NUMS so the key path is unspendable.
#[test]
fn armer_share_output_exposes_both_leaves() {
    let preimage = vec![0x42u8; 17];
    let commitment = hash160::Hash::hash(&preimage).to_byte_array();
    let armer_xonly = pk(1);
    let voters: Vec<XOnlyPublicKey> = (10..14).map(|i| pk(i as u8)).collect();
    let threshold = 3usize;

    let out = build_armer_share_output(
        &armer_xonly,
        &commitment,
        &voters,
        threshold,
        Network::Regtest,
    )
    .expect("armer-share output should build");

    // Both leaves must be reachable.
    let reveal_cb = out
        .reveal_control_block()
        .expect("reveal leaf must have a control block");
    let sweep_cb = out
        .sweep_control_block()
        .expect("sweep leaf must have a control block");

    // 2-leaf tree → depth 1 for both → control block is 33 + 32 bytes.
    assert_eq!(reveal_cb.serialize().len(), 33 + 32);
    assert_eq!(sweep_cb.serialize().len(), 33 + 32);

    // The sweep leaf's CSV must match the constant.
    let sweep_bytes = out.sweep_script.as_bytes();
    assert!(
        sweep_bytes[0] == bitcoin::opcodes::all::OP_PUSHBYTES_2.to_u8()
            && (sweep_bytes[1] as u32 | ((sweep_bytes[2] as u32) << 8))
                == ARMER_SHARE_SWEEP_CSV_BLOCKS,
        "sweep leaf must start with `OP_PUSH2 <ARMER_SHARE_SWEEP_CSV_BLOCKS>`, got opening bytes {:?}",
        &sweep_bytes[..4.min(sweep_bytes.len())]
    );
}

// ============================================================================
// Forfeit-sweep TX construction (DEP-06 §"Sweep recipients: pro-rata to revealers")
// ============================================================================

use deposits_core::tapscript_reserves::{build_forfeit_sweep_tx, revealers_from_claim_witness};

fn fake_outpoint() -> bitcoin::OutPoint {
    bitcoin::OutPoint {
        txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
        vout: 0,
    }
}

#[test]
fn sweep_tx_pays_pro_rata_to_revealers() {
    let revealers: Vec<XOnlyPublicKey> = (10..13).map(|i| pk(i as u8)).collect(); // 3 revealers
    let tx = build_forfeit_sweep_tx(
        fake_outpoint(),
        100_000, // slice value
        &revealers,
        1_000, // fee
        Network::Regtest,
    )
    .expect("sweep tx must build");

    assert_eq!(
        tx.input.len(),
        1,
        "exactly one input (the armer-share UTXO)"
    );
    assert_eq!(tx.output.len(), 3, "one P2TR per revealer");
    // (100_000 - 1_000) / 3 = 33_000; dust 0 (it divides evenly)
    for o in &tx.output {
        assert_eq!(o.value.to_sat(), 33_000);
    }
}

#[test]
fn sweep_tx_sets_csv_compatible_sequence_and_version() {
    let revealers: Vec<XOnlyPublicKey> = vec![pk(10)];
    let tx = build_forfeit_sweep_tx(fake_outpoint(), 10_000, &revealers, 500, Network::Regtest)
        .expect("sweep tx must build");

    // Version 2 required for BIP-68 relative-locktime semantics.
    assert_eq!(tx.version, bitcoin::transaction::Version::TWO);
    // Sequence must equal the CSV value so OP_CSV passes.
    let seq_val = tx.input[0].sequence.0 & 0xFFFF;
    assert_eq!(seq_val, ARMER_SHARE_SWEEP_CSV_BLOCKS);
}

#[test]
fn sweep_tx_orders_recipients_deterministically() {
    // Pass revealers in random order; the output ordering must be sorted
    // by xonly bytes so every honest sweeper produces the same TX.
    let in_order: Vec<XOnlyPublicKey> = vec![pk(7), pk(1), pk(5), pk(3)];
    let tx = build_forfeit_sweep_tx(fake_outpoint(), 100_000, &in_order, 1_000, Network::Regtest)
        .expect("sweep tx must build");

    let mut expected = in_order.clone();
    expected.sort_by_key(|k| k.serialize());
    for (i, e) in expected.iter().enumerate() {
        let secp = Secp256k1::new();
        let expected_addr = bitcoin::Address::p2tr(&secp, *e, None, Network::Regtest);
        assert_eq!(
            tx.output[i].script_pubkey,
            expected_addr.script_pubkey(),
            "output {} must address sorted revealer #{}",
            i,
            i
        );
    }
}

#[test]
fn sweep_tx_zero_revealers_errors() {
    let result = build_forfeit_sweep_tx(fake_outpoint(), 50_000, &[], 500, Network::Regtest);
    assert!(
        result.is_err(),
        "must refuse to construct a TX with no honest payee"
    );
}

#[test]
fn sweep_tx_uneconomical_fee_errors() {
    let revealers: Vec<XOnlyPublicKey> = vec![pk(10)];
    let result = build_forfeit_sweep_tx(
        fake_outpoint(),
        1_000,
        &revealers,
        2_000, // fee > slice
        Network::Regtest,
    );
    assert!(result.is_err(), "fee >= slice is rejected");
}

#[test]
fn revealers_from_claim_witness_identifies_revealing_armers() {
    // Build (armer_pubkey, commitment_hash) pairs for 4 armers; construct
    // a synthetic witness containing 3 of their preimages (not the 4th).
    let mut armers: Vec<(XOnlyPublicKey, [u8; 20])> = Vec::new();
    let mut preimages: Vec<Vec<u8>> = Vec::new();
    for i in 1..=4u8 {
        let preimage = vec![i; 17 + (i as usize - 1)]; // legal length 17..=20
        let commit = hash160::Hash::hash(&preimage).to_byte_array();
        armers.push((pk(i), commit));
        preimages.push(preimage);
    }

    // Witness includes preimages for armers 1, 2, 4 (not 3), plus some
    // non-preimage clutter the function must skip.
    let mut wit = bitcoin::Witness::new();
    wit.push([0xABu8; 64]); // signature — wrong length, skipped
    wit.push(&preimages[0]); // armer 1 revealed
    wit.push(&preimages[1]); // armer 2 revealed
    wit.push(&preimages[3]); // armer 4 revealed
    wit.push([0xCDu8; 100]); // leaf script — too long, skipped

    let revealers = revealers_from_claim_witness(&wit, &armers);
    let expected: Vec<XOnlyPublicKey> = {
        let mut v = vec![pk(1), pk(2), pk(4)];
        v.sort_by_key(|k| k.serialize());
        v
    };
    assert_eq!(revealers, expected);
}

#[test]
fn revealers_empty_when_no_witness_items_match() {
    let preimage = vec![0x42u8; 17];
    let commit = hash160::Hash::hash(&preimage).to_byte_array();
    let armers = vec![(pk(1), commit)];

    // Witness with a *different* 17-byte item — won't match the commitment.
    let mut wit = bitcoin::Witness::new();
    wit.push(vec![0xFFu8; 17]);

    let revealers = revealers_from_claim_witness(&wit, &armers);
    assert!(revealers.is_empty());
}
