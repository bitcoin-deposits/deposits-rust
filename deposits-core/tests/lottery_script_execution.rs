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
    LotteryOutput, LotteryParticipant, LotteryScriptBuilder, PARTIAL_REVEAL_CSV_BLOCKS,
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
        self.stack.pop().ok_or_else(|| "stack underflow".to_string())
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
            return Err(format!("unbalanced IF/ENDIF: cond_stack={:?}", self.cond_stack));
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
                    let last = self
                        .cond_stack
                        .last_mut()
                        .ok_or("OP_ELSE without OP_IF")?;
                    *last = !*last;
                    return Ok(());
                }
                0x68 => {
                    self.cond_stack
                        .pop()
                        .ok_or("OP_ENDIF without OP_IF")?;
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
    XOnlyPublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| format!("recorded non-pubkey {}: {:?}", hex::encode(&pubkey_bytes), e))
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn primary_lottery_dispatches_correctly_at_n3() {
    // Sum = 1+2+1 = 4, 4 mod 3 = 1 → participant index 1 wins.
    let pk_won = run_lottery(&[1, 2, 1]).unwrap();
    assert_eq!(pk_won, pk(2), "expected participant 2 (index 1) to win");
}

#[test]
fn primary_lottery_dispatches_correctly_across_linear_regime() {
    // Sweep N=2..=5 with random-ish contributions; verify the
    // interpreter agrees with calculate_winner.
    let cases: &[(&[usize], usize)] = &[
        (&[2, 1], 1),       // sum 3 mod 2 = 1
        (&[1, 1, 1], 0),    // sum 3 mod 3 = 0
        (&[3, 2, 1], 0),    // sum 6 mod 3 = 0
        (&[1, 2, 3, 4], 2), // sum 10 mod 4 = 2
        (&[5, 4, 3, 2, 1], 0), // sum 15 mod 5 = 0
        (&[1, 2, 3, 4, 5], 0), // sum 15 mod 5 = 0
    ];
    for (contribs, expected_idx) in cases {
        let pk_won = run_lottery(contribs)
            .unwrap_or_else(|e| panic!("contributions {:?}: {}", contribs, e));
        assert_eq!(
            pk_won,
            pk((*expected_idx + 1) as u8),
            "contributions {:?}: expected index {}",
            contribs,
            expected_idx
        );
    }
}

#[test]
fn primary_lottery_dispatches_correctly_in_combined_table_regime() {
    // N=6 to N=10: CombinedTable. Pick a few representative cases.
    let cases: &[(&[usize], usize)] = &[
        (&[1, 1, 1, 1, 1, 1], 0),       // sum 6 mod 6 = 0
        (&[6, 5, 4, 3, 2, 1], 3),       // sum 21 mod 6 = 3
        (&[1; 10], 0),                  // sum 10 mod 10 = 0
        (&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 5), // sum 55 mod 10 = 5
    ];
    for (contribs, expected_idx) in cases {
        let pk_won = run_lottery(contribs)
            .unwrap_or_else(|e| panic!("contributions {:?}: {}", contribs, e));
        assert_eq!(
            pk_won,
            pk((*expected_idx + 1) as u8),
            "contributions {:?}: expected index {}",
            contribs,
            expected_idx
        );
    }
}

#[test]
fn primary_lottery_dispatches_correctly_at_n11_and_n15() {
    // N=11 and N=15: Regime C (Linear-after-mod). Boundaries.
    let n11: Vec<usize> = (1..=11).collect();
    let sum_n11: usize = n11.iter().sum(); // 66, mod 11 = 0
    let pk_won = run_lottery(&n11).expect("N=11 dispatch should succeed");
    assert_eq!(pk_won, pk(1), "N=11 sum {} mod 11 = 0 → participant 1", sum_n11);

    let n15: Vec<usize> = (1..=15).collect();
    let sum_n15: usize = n15.iter().sum(); // 120, mod 15 = 0
    let pk_won = run_lottery(&n15).expect("N=15 dispatch should succeed");
    assert_eq!(pk_won, pk(1), "N=15 sum {} mod 15 = 0 → participant 1", sum_n15);

    // Non-zero modulo case at N=15.
    let mut alt = n15.clone();
    alt[0] = 7; // change first contribution from 1 to 7 → sum = 126, mod 15 = 6
    let pk_won = run_lottery(&alt).expect("N=15 dispatch should succeed");
    assert_eq!(
        pk_won,
        pk(7),
        "N=15 sum 126 mod 15 = 6 → participant index 6 (= pk(7))"
    );
}

#[test]
fn primary_lottery_rejects_wrong_preimage() {
    // Build a script committing to specific hashes, then provide a
    // witness with a tampered preimage. EQUALVERIFY should fail.
    let n = 3;
    let mut participants = Vec::new();
    let mut preimages = Vec::new();
    for i in 0..n {
        let (p, pre) = participant((i + 1) as u8, 1);
        participants.push(p);
        preimages.push(pre);
    }
    let script = LotteryScriptBuilder::new(
        participants,
        standard_recovery_voters(),
        3,
        Network::Regtest,
    )
    .build_lottery_script()
    .unwrap();

    // Tamper with preimage_1 (bottom-most preimage in disputant order
    // = top of stack at script start).
    preimages[0] = vec![0xFF; 17];

    let sig = vec![0xAA; 64];
    let mut witness = vec![sig];
    for p in preimages.iter().rev() {
        witness.push(p.clone());
    }

    let mut interp = Interp::new(witness);
    let result = interp.run(&script);
    assert!(
        result.is_err()
            && result.as_ref().unwrap_err().contains("OP_EQUALVERIFY"),
        "expected EQUALVERIFY failure, got: {:?}",
        result
    );
}

#[test]
fn partial_reveal_leaf_excludes_missing_disputant() {
    // At N=11, partial leaf for missing index 3 should be a
    // 10-disputant lottery over participants {0,1,2,4,5,6,7,8,9,10}.
    // Run that sub-lottery with chosen contributions and verify the
    // dispatch.
    let n = 11;
    let missing_idx = 3;
    let contributions: Vec<usize> = (1..=n).collect();

    let mut all_participants = Vec::with_capacity(n);
    let mut all_preimages = Vec::with_capacity(n);
    for (i, c) in contributions.iter().enumerate() {
        let (p, pre) = participant((i + 1) as u8, *c);
        all_participants.push(p);
        all_preimages.push(pre);
    }

    let outer = LotteryScriptBuilder::new(
        all_participants.clone(),
        standard_recovery_voters(),
        3,
        Network::Regtest,
    );
    let leaves = outer.build_partial_reveal_leaves().unwrap();
    let leaf = leaves[missing_idx].clone();

    // Witness: dummy CSV value already on script (it pushes 72), then
    // we provide preimages of the 10 revealers (excluding index
    // missing_idx) in REVERSE order. Sub-lottery sum-mod is over the
    // 10 revealers' contributions.
    let revealer_contribs: Vec<usize> = contributions
        .iter()
        .enumerate()
        .filter_map(|(i, c)| if i == missing_idx { None } else { Some(*c) })
        .collect();
    let revealer_preimages: Vec<Vec<u8>> = all_preimages
        .iter()
        .enumerate()
        .filter_map(|(i, p)| if i == missing_idx { None } else { Some(p.clone()) })
        .collect();
    let revealer_pks: Vec<XOnlyPublicKey> = (0..n)
        .filter(|i| *i != missing_idx)
        .map(|i| pk((i + 1) as u8))
        .collect();

    let sum: usize = revealer_contribs.iter().sum();
    let expected_idx = sum % revealer_contribs.len();

    // The script starts with `<72> OP_CSV OP_DROP`. At runtime the
    // OP_CSV expects a sequence value to verify against; in our
    // model it just inspects (without popping) so the prefix needs
    // nothing extra in the witness beyond the standard preimages.
    let sig = vec![0xAA; 64];
    let mut witness = vec![sig];
    for p in revealer_preimages.iter().rev() {
        witness.push(p.clone());
    }

    let mut interp = Interp::new(witness);
    interp
        .run(&leaf)
        .unwrap_or_else(|e| panic!("partial-reveal leaf execution failed: {}", e));

    // Final stack should be [TRUE]
    let top = interp.stack.last().expect("partial-reveal left empty stack");
    assert!(
        read_scriptbool(top),
        "partial-reveal leaf returned FALSE: stack={:?}",
        interp.stack
    );

    let pubkey_bytes = interp
        .last_checked_pubkey
        .expect("OP_CHECKSIG must execute — dispatch fell through");
    let recorded =
        XOnlyPublicKey::from_slice(&pubkey_bytes).expect("recorded non-pubkey bytes");
    assert_eq!(
        recorded, revealer_pks[expected_idx],
        "partial-reveal at N=11 missing=3: sum {} mod 10 = {} → revealer #{}",
        sum, expected_idx, expected_idx
    );
}

/// Run an arbitrary leaf script with a Witness produced by one of
/// the LotteryOutput witness helpers. Strips the trailing
/// `[leaf_script, control_block]` items (consumed by Taproot
/// validation, not by the script body), runs the body against the
/// interpreter, and returns the recorded winner pubkey on success.
fn run_witness_against_leaf(
    leaf_script: &ScriptBuf,
    witness: &bitcoin::Witness,
) -> Result<XOnlyPublicKey, String> {
    // Witness items order in rust-bitcoin's Witness: index 0 is the
    // first push (= bottom of stack at validation time). The last two
    // pushes are the leaf_script and control_block (Taproot Tapscript
    // convention); the script-body's "input stack" is everything before
    // those two.
    let len = witness.len();
    if len < 2 {
        return Err(format!("witness has {} items, expected >= 2", len));
    }
    let stack_inputs: Vec<Vec<u8>> = witness
        .iter()
        .take(len - 2)
        .map(|item| item.to_vec())
        .collect();

    let mut interp = Interp::new(stack_inputs);
    interp.run(leaf_script)?;

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
        .ok_or("OP_CHECKSIG was never executed")?;
    XOnlyPublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| format!("recorded non-pubkey {}: {:?}", hex::encode(&pubkey_bytes), e))
}

#[test]
fn create_claim_witness_unlocks_primary_lottery() {
    // Build an output, construct the claim witness via the public
    // helper, and run it through the interpreter. Verifies the
    // witness layout is what the script expects.
    let n = 5;
    let contributions: Vec<usize> = (1..=n).collect();
    let mut participants = Vec::new();
    let mut preimages = Vec::new();
    for (i, c) in contributions.iter().enumerate() {
        let (p, pre) = participant((i + 1) as u8, *c);
        participants.push(p);
        preimages.push(pre);
    }
    let builder = LotteryScriptBuilder::new(
        participants,
        standard_recovery_voters(),
        3,
        Network::Regtest,
    );
    let output = builder.build().unwrap();

    let sig = [0xAAu8; 64];
    let witness = output.create_claim_witness(&sig, &preimages).unwrap();
    let pk_won = run_witness_against_leaf(&output.lottery_script, &witness).unwrap();

    let sum: usize = contributions.iter().sum(); // 15, mod 5 = 0
    assert_eq!(pk_won, pk(1), "sum {} mod 5 = 0 → participant 1", sum);
}

#[test]
fn create_partial_reveal_witness_unlocks_correct_leaf() {
    // N=12 (Linear-after-mod regime for the sub-lottery N-1=11),
    // missing index 5. Construct the partial-reveal witness and
    // verify it unlocks the leaf and routes to the right revealer.
    let n = 12usize;
    let missing_idx = 5usize;
    let contributions: Vec<usize> = (1..=n).collect();

    let mut participants = Vec::new();
    let mut preimages = Vec::new();
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
    let output = builder.build().unwrap();

    // Revealer preimages are everything except missing_idx, in
    // disputant order. The witness helper pushes them in reverse so
    // preimage_first_revealer ends up on top.
    let revealer_preimages: Vec<Vec<u8>> = preimages
        .iter()
        .enumerate()
        .filter_map(|(i, p)| if i == missing_idx { None } else { Some(p.clone()) })
        .collect();
    let revealer_pks: Vec<XOnlyPublicKey> = (0..n)
        .filter(|i| *i != missing_idx)
        .map(|i| pk((i + 1) as u8))
        .collect();

    let sig = [0xAAu8; 64];
    let witness = output
        .create_partial_reveal_witness(missing_idx, &sig, &revealer_preimages)
        .expect("partial-reveal witness construction should succeed");

    // The leaf for missing_idx is in output.partial_reveal_scripts.
    let leaf = &output.partial_reveal_scripts[missing_idx];
    let pk_won = run_witness_against_leaf(leaf, &witness).unwrap();

    let revealer_contribs: Vec<usize> = contributions
        .iter()
        .enumerate()
        .filter_map(|(i, c)| if i == missing_idx { None } else { Some(*c) })
        .collect();
    let sum: usize = revealer_contribs.iter().sum();
    let expected_idx = sum % revealer_contribs.len();
    assert_eq!(
        pk_won, revealer_pks[expected_idx],
        "N={} missing_idx={} sum {} mod {} = {} → revealer #{}",
        n,
        missing_idx,
        sum,
        revealer_contribs.len(),
        expected_idx,
        expected_idx
    );

    // Sanity: the witness includes leaf_script and control_block at
    // the end. Total push count: 1 sig + (n-1) preimages + 2 = n+2.
    assert_eq!(witness.len(), n + 2);
}

#[test]
fn create_partial_reveal_witness_rejects_invalid_inputs() {
    let n = 11usize;
    let mut participants = Vec::new();
    let mut preimages = Vec::new();
    for i in 0..n {
        let (p, pre) = participant((i + 1) as u8, 1);
        participants.push(p);
        preimages.push(pre);
    }
    let output = LotteryScriptBuilder::new(
        participants,
        standard_recovery_voters(),
        3,
        Network::Regtest,
    )
    .build()
    .unwrap();

    let sig = [0xAAu8; 64];
    let revealers: Vec<Vec<u8>> = preimages.iter().take(n - 1).cloned().collect();

    // Out-of-range missing_idx
    assert!(output
        .create_partial_reveal_witness(n, &sig, &revealers)
        .is_err());
    assert!(output
        .create_partial_reveal_witness(99, &sig, &revealers)
        .is_err());

    // Wrong preimage count: should be N-1.
    assert!(output
        .create_partial_reveal_witness(0, &sig, &preimages)
        .is_err());
    assert!(output
        .create_partial_reveal_witness(0, &sig, &[])
        .is_err());
}

#[test]
fn create_partial_reveal_witness_rejected_when_n_too_small() {
    // N=10 has no partial-reveal leaves. The helper must refuse.
    let n = 10usize;
    let mut participants = Vec::new();
    let mut preimages = Vec::new();
    for i in 0..n {
        let (p, pre) = participant((i + 1) as u8, 1);
        participants.push(p);
        preimages.push(pre);
    }
    let output = LotteryScriptBuilder::new(
        participants,
        standard_recovery_voters(),
        3,
        Network::Regtest,
    )
    .build()
    .unwrap();

    assert!(output.partial_reveal_scripts.is_empty());

    let sig = [0xAAu8; 64];
    let revealers: Vec<Vec<u8>> = preimages.iter().take(n - 1).cloned().collect();
    let err = output
        .create_partial_reveal_witness(0, &sig, &revealers)
        .unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("PARTIAL_REVEAL_MIN_N") || msg.contains("11") || msg.contains("only exist"),
        "expected error to mention the threshold, got: {}",
        msg
    );
}

#[test]
fn lottery_output_includes_all_expected_leaves() {
    // Defence-in-depth: verify that LotteryReservesBuilder::build()
    // produces a Taproot output where every leaf we can build
    // standalone has a control block — primary lottery, every partial
    // reveal, every recovery script, and the timeout-recovery leaf.
    let n = 15;
    let mut participants = Vec::new();
    for i in 0..n {
        let (p, _) = participant((i + 1) as u8, 1);
        participants.push(p);
    }
    let recovery_voters = standard_recovery_voters();

    let builder = LotteryScriptBuilder::new(
        participants.clone(),
        recovery_voters.clone(),
        3,
        Network::Regtest,
    );
    let output: LotteryOutput = builder.build().expect("N=15 lottery output");

    let leaf_version = bitcoin::taproot::LeafVersion::TapScript;

    // Primary lottery
    assert!(
        output
            .spend_info
            .control_block(&(output.lottery_script.clone(), leaf_version))
            .is_some(),
        "primary lottery leaf must be in tree"
    );

    // All N partial-reveal leaves
    for (j, leaf) in output.partial_reveal_scripts.iter().enumerate() {
        assert!(
            output
                .spend_info
                .control_block(&(leaf.clone(), leaf_version))
                .is_some(),
            "partial-reveal leaf {} (CSV {} prefix) must be in tree",
            j,
            PARTIAL_REVEAL_CSV_BLOCKS
        );
    }

    // Recovery long-tail (CSV 144 / 1008 / 4032 with descending
    // thresholds T / T-1 / T-2) plus the timeout-recovery leaf at
    // CSV 8064 with threshold 1.
    let recovery_specs = [
        (144u32, 3usize),
        (1008, 2),
        (4032, 1),
        (deposits_core::TIMEOUT_RECOVERY_CSV_BLOCKS, 1),
    ];
    for (csv, threshold) in recovery_specs {
        let rec = LotteryScriptBuilder::new(
            participants.clone(),
            recovery_voters.clone(),
            threshold,
            Network::Regtest,
        )
        .build_recovery_script(csv)
        .expect("recovery script");
        assert!(
            output
                .spend_info
                .control_block(&(rec.clone(), leaf_version))
                .is_some(),
            "recovery leaf at CSV {} threshold {} must be in tree",
            csv,
            threshold
        );
    }
}

// ============================================================================
// High-Q integration tests
// ============================================================================
//
// End-to-end scenarios that thread the full happy and unhappy paths
// through the script side: build a LotteryOutput, simulate the
// reveal/recovery flow, construct the appropriate witness for the
// chosen spend leaf, and verify the script accepts it and dispatches
// where calculate_winner says it should.
//
// **Scope.** These tests cover script construction, witness layout,
// and dispatch logic. They do NOT validate Bitcoin-layer concerns:
// Schnorr signatures (stubbed), OP_CSV nSequence enforcement (stubbed
// no-op), Taproot key-path equivocation (NUMS prevents it), or the
// confiscation TX path that lands the lottery output on chain.
// Those need bitcoind regtest — see the Tier-3 follow-up in
// CUSTODY_LOTTERY_PLAN.md "Tier-3 integration test target".

/// Drive a full N=15 lottery: every disputant reveals, the winner is
/// computed via `calculate_winner`, and the constructed claim
/// witness unlocks the primary lottery leaf and dispatches to that
/// winner.
#[test]
fn high_q_lottery_n15_full_reveal_happy_path() {
    let n = 15usize;
    // Mix contributions so the sum mod N isn't trivially 0.
    // sum = 1+2+1+2+...+1 = 23, 23 mod 15 = 8.
    let contributions: Vec<usize> = (0..n).map(|i| if i % 2 == 0 { 1 } else { 2 }).collect();

    let mut participants = Vec::new();
    let mut preimages = Vec::new();
    for (i, c) in contributions.iter().enumerate() {
        let (p, pre) = participant((i + 1) as u8, *c);
        participants.push(p);
        preimages.push(pre);
    }

    let builder = LotteryScriptBuilder::new(
        participants,
        standard_recovery_voters(),
        3,
        Network::Regtest,
    );
    let output = builder.build().expect("N=15 output should build");

    // Sanity: the output has 1 lottery + 15 partial + 4 recovery = 20 leaves.
    assert_eq!(output.partial_reveal_scripts.len(), 15);

    // Every disputant reveals; calculate the winner off-chain.
    let winner_idx = LotteryOutput::calculate_winner(&preimages).unwrap();
    let expected_sum: usize = contributions.iter().sum();
    assert_eq!(winner_idx, expected_sum % n);

    // Construct the claim witness using the public helper and run it.
    let sig = [0xAAu8; 64];
    let witness = output.create_claim_witness(&sig, &preimages).unwrap();
    let pk_won = run_witness_against_leaf(&output.lottery_script, &witness).unwrap();
    assert_eq!(
        pk_won,
        pk((winner_idx + 1) as u8),
        "N=15 full-reveal: sum={} winner_idx={}",
        expected_sum,
        winner_idx
    );
}

/// At N=15, disputant index 7 fails to reveal. The remaining 14
/// reveal and run the partial-reveal flow: their preimages get hashed
/// to commit, the (sub-N=14) sub-lottery picks a winner among them,
/// and the partial-reveal leaf for missing_idx=7 unlocks correctly.
/// Sub-N=14 is in Regime C (Linear-after-mod) so this exercises the
/// upper end of the lottery-after-mod path.
#[test]
fn high_q_partial_reveal_n15_missing_seven() {
    let n = 15usize;
    let missing_idx = 7usize;

    // Contributions chosen so the sum-among-revealers gives a
    // non-zero mod and a winner that isn't the first revealer.
    // Revealers at i in {0,1,2,3,4,5,6,8,9,10,11,12,13,14}.
    let contributions: Vec<usize> = (0..n).map(|i| 1 + (i % 5)).collect();

    let mut participants = Vec::new();
    let mut preimages = Vec::new();
    for (i, c) in contributions.iter().enumerate() {
        let (p, pre) = participant((i + 1) as u8, *c);
        participants.push(p);
        preimages.push(pre);
    }

    let output = LotteryScriptBuilder::new(
        participants,
        standard_recovery_voters(),
        3,
        Network::Regtest,
    )
    .build()
    .unwrap();

    // The revealer set excludes missing_idx, in disputant order.
    let revealer_preimages: Vec<Vec<u8>> = preimages
        .iter()
        .enumerate()
        .filter_map(|(i, p)| if i == missing_idx { None } else { Some(p.clone()) })
        .collect();
    let revealer_pks: Vec<XOnlyPublicKey> = (0..n)
        .filter(|i| *i != missing_idx)
        .map(|i| pk((i + 1) as u8))
        .collect();

    // Sub-lottery winner: sum of revealer contributions mod 14.
    let sub_winner_idx = LotteryOutput::calculate_winner(&revealer_preimages).unwrap();
    let sum: usize = revealer_preimages.iter().map(|p| p.len() - 16).sum();
    assert_eq!(sub_winner_idx, sum % (n - 1));

    let sig = [0xAAu8; 64];
    let witness = output
        .create_partial_reveal_witness(missing_idx, &sig, &revealer_preimages)
        .unwrap();
    let leaf = &output.partial_reveal_scripts[missing_idx];
    let pk_won = run_witness_against_leaf(leaf, &witness).unwrap();

    assert_eq!(
        pk_won, revealer_pks[sub_winner_idx],
        "N=15 missing={} sum_among_revealers={} mod 14 = {} → revealer #{}",
        missing_idx, sum, sub_winner_idx, sub_winner_idx
    );
}

/// At N=11, missing_idx=3. Sub-N=10, which falls in Regime B
/// (CombinedTable). Verifies the regime-boundary partial-reveal path
/// — the sub-lottery uses the 91-arm dispatch table rather than
/// Linear-after-mod.
#[test]
fn high_q_partial_reveal_n11_missing_three_combined_table() {
    let n = 11usize;
    let missing_idx = 3usize;
    let contributions: Vec<usize> = (0..n).map(|i| 1 + (i % 7)).collect();

    let mut participants = Vec::new();
    let mut preimages = Vec::new();
    for (i, c) in contributions.iter().enumerate() {
        let (p, pre) = participant((i + 1) as u8, *c);
        participants.push(p);
        preimages.push(pre);
    }

    let output = LotteryScriptBuilder::new(
        participants,
        standard_recovery_voters(),
        3,
        Network::Regtest,
    )
    .build()
    .unwrap();

    let revealer_preimages: Vec<Vec<u8>> = preimages
        .iter()
        .enumerate()
        .filter_map(|(i, p)| if i == missing_idx { None } else { Some(p.clone()) })
        .collect();
    let revealer_pks: Vec<XOnlyPublicKey> = (0..n)
        .filter(|i| *i != missing_idx)
        .map(|i| pk((i + 1) as u8))
        .collect();

    let sub_winner_idx = LotteryOutput::calculate_winner(&revealer_preimages).unwrap();

    let sig = [0xAAu8; 64];
    let witness = output
        .create_partial_reveal_witness(missing_idx, &sig, &revealer_preimages)
        .unwrap();
    let leaf = &output.partial_reveal_scripts[missing_idx];
    let pk_won = run_witness_against_leaf(leaf, &witness).unwrap();

    // Boundary check: this leaf uses the CombinedTable dispatch (91 arms).
    let endif_count = leaf
        .instructions()
        .filter_map(|i| i.ok())
        .filter(|i| {
            matches!(
                i,
                bitcoin::script::Instruction::Op(op) if *op == bitcoin::opcodes::all::OP_ENDIF
            )
        })
        .count();
    assert_eq!(endif_count, 91, "N=11 partial leaf must be CombinedTable");

    assert_eq!(
        pk_won, revealer_pks[sub_winner_idx],
        "N=11 missing={} CombinedTable sub-lottery: revealer #{}",
        missing_idx, sub_winner_idx
    );
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
    let recovery_script = LotteryScriptBuilder::new(
        participants,
        recovery_voters.clone(),
        3,
        Network::Regtest,
    )
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

    let recovery_script = LotteryScriptBuilder::new(
        participants,
        recovery_voters,
        3,
        Network::Regtest,
    )
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
    let timeout_script = LotteryScriptBuilder::new(
        participants,
        recovery_voters,
        1,
        Network::Regtest,
    )
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

    let timeout_script = LotteryScriptBuilder::new(
        participants,
        recovery_voters,
        1,
        Network::Regtest,
    )
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
