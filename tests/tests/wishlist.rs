//! Adversarial wishlist — testing items from the full attack taxonomy.
//!
//! Each test covers one item from the adversarial testing roadmap.

use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use deposits_core::descriptor::CoreWitnessVerifier;
use deposits_core::ledger::Ledger;
use deposits_integration_tests::adversarial::*;
use deposits_integration_tests::*;
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::*;

fn make_key(seed: u8) -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = 0x42;
    let sk = SecretKey::from_slice(&bytes).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    (sk, pk)
}

// =========================================================================
// Tier 2.1: NUMS point — audit the actual implementation
// =========================================================================

#[test]
fn tier2_1_nums_point_audit() {
    let mut log = AttackLog::new();

    use deposits_core::tapscript_reserves::{TapscriptReservesBuilder, ThresholdConfig, VoterSet};

    let (_, tie_breaker) = make_key(1);
    let others: Vec<_> = (2..=4).map(|i| make_key(i).1).collect();
    let voter_set = VoterSet::new(tie_breaker, others);
    let config = ThresholdConfig::default_for_voter_count(4);
    let ledger_hash = [0xAB; 32];

    let builder =
        TapscriptReservesBuilder::new(voter_set, config, bitcoin::Network::Regtest, ledger_hash);
    let output = builder.build().unwrap();

    // The BIP-341 recommended NUMS point for the internal key is:
    // lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
    // This is SHA256("TapTweak") interpreted as an x-coordinate.
    //
    // Extract the internal key from the TaprootReservesOutput.
    // The output has an `address` which is the tweaked key, but we need
    // to check the INTERNAL key before tweaking.

    // Check: does the builder use a known-unspendable internal key?
    // We can verify by building with different quorum compositions and
    // checking that the same internal key is used (it shouldn't depend
    // on the quorum — it should be a fixed NUMS point).

    let (_, other_tie) = make_key(99);
    let other_others: Vec<_> = (10..=12).map(|i| make_key(i).1).collect();
    let other_set = VoterSet::new(other_tie, other_others);
    let other_config = ThresholdConfig::default_for_voter_count(4);

    let other_builder = TapscriptReservesBuilder::new(
        other_set,
        other_config,
        bitcoin::Network::Regtest,
        [0xCD; 32],
    );
    let other_output = other_builder.build().unwrap();

    // Different quorum should produce different address
    // (because the tapscript tree differs)
    assert_ne!(output.address, other_output.address);

    // The internal key should be the SAME for both — it's NUMS, not derived
    // from the quorum. We can't directly access the internal key from the
    // TaprootReservesOutput, but we can check the spending info.
    //
    // If the implementation uses a key derived from the operator's pubkey
    // instead of a NUMS point, that's the vulnerability.

    // Check: can we key-path spend? The test is whether a Taproot output
    // can be spent via the key path (which would mean the internal key
    // has a known discrete log). We can't test this without trying to
    // sign with the secret key, which we shouldn't have.

    // Grep the source for the internal key construction
    let source_check = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("deposits-core/src/tapscript_reserves.rs"),
    )
    .unwrap_or_default();

    let uses_nums = source_check.contains("NUMS")
        || source_check.contains("nums")
        || source_check.contains("unspendable")
        || source_check.contains("50929b74c1a04954");

    let uses_operator_key_as_internal = source_check.contains("internal_key")
        && (source_check.contains("operator") || source_check.contains("tie_breaker"));

    // Look for how the internal key is constructed
    let internal_key_lines: Vec<&str> = source_check
        .lines()
        .filter(|l| {
            l.contains("internal_key")
                || l.contains("TaprootBuilder")
                || l.contains("finalize")
                || l.contains("UntweakedPublicKey")
        })
        .collect();

    log.record(AttackResult {
        name: "Tier 2.1: NUMS point audit".into(),
        invariant: Invariant::NUMSPoint,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 100_000_000,
        blocked: uses_nums && !uses_operator_key_as_internal,
        defense: if uses_nums {
            DefenseLayer::Implementation
        } else {
            DefenseLayer::Undefended
        },
        scaling: Scaling::Constant,
        notes: format!(
            "Source mentions NUMS/unspendable: {}. Uses operator key as internal: {}. \
             Internal key construction: {:?}",
            uses_nums,
            uses_operator_key_as_internal,
            internal_key_lines
                .iter()
                .take(5)
                .map(|l| l.trim())
                .collect::<Vec<_>>()
        ),
    });

    // This is an audit finding — report what was found
    println!("  NUMS/unspendable mentioned in source: {}", uses_nums);
    println!(
        "  Operator key used as internal key: {}",
        uses_operator_key_as_internal
    );
    println!("  Internal key construction lines:");
    for line in internal_key_lines.iter().take(10) {
        println!("    {}", line.trim());
    }
}

// =========================================================================
// Tier 2.3: Cosigner validation scope — abbreviated history attack
// =========================================================================

#[test]
fn tier2_3_cosigner_abbreviated_history() {
    let mut log = AttackLog::new();

    // Attack: operator presents a partial history to a new quorum joiner,
    // hiding prior equivocation.
    //
    // Scenario:
    // 1. Alice operates a ledger, creates valid history (seq 0-5)
    // 2. Alice equivocates: creates two conflicting updates at seq 3
    //    (fork A and fork B)
    // 3. Bob joins as quorum member at seq 5
    // 4. Alice only shows Bob the fork A history, hiding fork B
    //
    // Question: does the protocol force Bob to validate from genesis?

    let mut net = TestNetwork::new(&["alice"], 1_000_000);
    let user = net.create_depositor("u", 10);
    let did = net.op_mut("alice").open_deposit(&user);
    net.op_mut("alice").credit_deposit(did, 100_000, [0x01; 32]);
    net.op_mut("alice").credit_deposit(did, 200_000, [0x02; 32]);

    // Alice's honest history is now: LedgerOpen, DepositOpen, Credit, Credit (seq 0-3)
    let honest_seq = net.op("alice").ledger.state.sequence;
    let honest_hash = net.op("alice").ledger.state.chain_tip_hash;
    let full_history_len = net.op("alice").ledger.history.len();

    // Create a watcher that starts from seq 0 — this represents Bob
    // doing a FULL validation from genesis
    let mut full_watcher = net.create_watcher("alice");
    net.op("alice").sync_to(&mut full_watcher);

    assert_eq!(
        full_watcher.state.sequence, honest_seq,
        "Full watcher should sync to current sequence"
    );
    assert_eq!(full_watcher.history.len(), full_history_len);

    // Now simulate abbreviated validation: watcher starts from seq 2,
    // only seeing the last 2 updates. The first 2 (LedgerOpen, DepositOpen)
    // are not validated.
    let mut partial_watcher = net.create_watcher("alice");
    // Only replay the last 2 operations
    for update in net
        .op("alice")
        .ledger
        .history
        .iter()
        .skip(full_history_len - 2)
    {
        if let Ok(op) = deposits_protocol::LedgerOperation::tlv_decode(&update.message) {
            let _ = partial_watcher.apply_state_changes(&op);
            partial_watcher.state.sequence = update.sequence_number;
            partial_watcher.state.chain_tip_hash = update.chain_hash();
        }
    }

    // The partial watcher has the right sequence but wrong deposit state —
    // it didn't see the DepositOpen, so it has no deposit to credit.
    // The Credits would have failed on the partial watcher.
    let partial_balance = partial_watcher.state.total_deposit_balance();
    let full_balance = full_watcher.state.total_deposit_balance();

    // The abbreviated view gives different state
    let states_match = partial_balance == full_balance;

    log.record(AttackResult {
        name: "Tier 2.3: Cosigner abbreviated history".into(),
        invariant: Invariant::HashChainIntegrity,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 0,
        blocked: !states_match, // divergent state = attack detected (if checked)
        defense: DefenseLayer::NodePolicy,
        scaling: Scaling::Constant,
        notes: format!(
            "Full replay balance: {} sats, partial replay: {} sats. \
             States match: {}. New quorum members MUST replay from genesis \
             to detect hidden equivocation. The protocol relies on hash chain \
             continuity — if a joiner accepts a mid-chain starting point, \
             they can't verify earlier operations. Implementation must enforce \
             full-chain validation for new members.",
            full_balance, partial_balance, states_match
        ),
    });

    // The finding: abbreviated history produces different state.
    // This is correct behavior — but the protocol must REQUIRE full replay.
    assert_ne!(
        partial_balance, full_balance,
        "Abbreviated history must produce different state (proving full replay is needed)"
    );
}

use deposits_protocol::TlvDecode;

// =========================================================================
// Tier 5.1: Signature malleability
// =========================================================================

#[test]
fn tier5_1_signature_malleability() {
    let mut log = AttackLog::new();

    // Schnorr signatures (BIP-340) are non-malleable by construction:
    // there's exactly one valid 64-byte encoding for each (key, message) pair.
    // But the implementation must:
    // 1. Accept only 64-byte signatures (not DER, not compact+recovery)
    // 2. Reject signatures with s > curve order / 2 (if applicable)
    // 3. Not accept the same signature for different messages

    let (sk, pk) = make_key(10);
    let descriptor = format!("pk({})", hex::encode(pk.serialize()));
    let msg_hash = [0xAA; 32];

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let msg = Message::from_digest(msg_hash);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    let sig_bytes = sig.serialize();

    let witness = DescriptorWitness {
        stack: vec![sig_bytes.to_vec()],
    };

    // Canonical signature should verify
    let valid = deposits_core::descriptor::verify_witness(&descriptor, &witness, &msg_hash)
        .unwrap_or(false);
    assert!(valid, "Canonical Schnorr signature must verify");

    // Test: wrong-length signature should be rejected
    let short_witness = DescriptorWitness {
        stack: vec![sig_bytes[..32].to_vec()], // only 32 bytes
    };
    let short_result =
        deposits_core::descriptor::verify_witness(&descriptor, &short_witness, &msg_hash)
            .unwrap_or(false);
    assert!(!short_result, "Short signature must be rejected");

    // Test: flipped bit should be rejected
    let mut malleated = sig_bytes;
    malleated[31] ^= 0x01;
    let mal_witness = DescriptorWitness {
        stack: vec![malleated.to_vec()],
    };
    let mal_result =
        deposits_core::descriptor::verify_witness(&descriptor, &mal_witness, &msg_hash)
            .unwrap_or(false);
    assert!(!mal_result, "Bit-flipped signature must be rejected");

    // Test: all-zero signature should be rejected
    let zero_witness = DescriptorWitness {
        stack: vec![vec![0u8; 64]],
    };
    let zero_result =
        deposits_core::descriptor::verify_witness(&descriptor, &zero_witness, &msg_hash)
            .unwrap_or(false);
    assert!(!zero_result, "All-zero signature must be rejected");

    // Test: signature for different message should be rejected
    let wrong_msg = [0xBB; 32];
    let wrong_result = deposits_core::descriptor::verify_witness(&descriptor, &witness, &wrong_msg)
        .unwrap_or(false);
    assert!(
        !wrong_result,
        "Signature for wrong message must be rejected"
    );

    log.record(AttackResult {
        name: "Tier 5.1: Signature malleability".into(),
        invariant: Invariant::WitnessValidity,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 0,
        blocked: true,
        defense: DefenseLayer::Implementation,
        scaling: Scaling::Constant,
        notes: "BIP-340 Schnorr: canonical verified, short rejected, \
                bit-flip rejected, zero rejected, wrong-message rejected."
            .into(),
    });
}

// =========================================================================
// Tier 5.5: Descriptor parsing — pathological inputs
// =========================================================================

#[test]
fn tier5_5_descriptor_parsing_edge_cases() {
    let mut log = AttackLog::new();
    let msg_hash = [0xAA; 32];

    // Test various pathological descriptor strings

    // Empty descriptor
    let empty = deposits_core::descriptor::verify_witness(
        "",
        &DescriptorWitness {
            stack: vec![vec![0xFF; 64]],
        },
        &msg_hash,
    );
    let empty_safe = empty.is_err() || !empty.unwrap_or(true);

    // Very long descriptor
    let long_desc = format!("pk({})", "ab".repeat(1000));
    let long = deposits_core::descriptor::verify_witness(
        &long_desc,
        &DescriptorWitness {
            stack: vec![vec![0xFF; 64]],
        },
        &msg_hash,
    );
    let long_safe = long.is_err() || !long.unwrap_or(true);

    // Nested parentheses
    let nested = "pk(pk(pk(aabb)))";
    let nested_result = deposits_core::descriptor::verify_witness(
        nested,
        &DescriptorWitness {
            stack: vec![vec![0xFF; 64]],
        },
        &msg_hash,
    );
    let nested_safe = nested_result.is_err() || !nested_result.unwrap_or(true);

    // Null bytes in descriptor
    let null_desc = "pk(\x00\x00)";
    let null_result = deposits_core::descriptor::verify_witness(
        null_desc,
        &DescriptorWitness {
            stack: vec![vec![0xFF; 64]],
        },
        &msg_hash,
    );
    let null_safe = null_result.is_err() || !null_result.unwrap_or(true);

    // Unicode in descriptor
    let unicode_desc = "pk(🔑)";
    let unicode_result = deposits_core::descriptor::verify_witness(
        unicode_desc,
        &DescriptorWitness {
            stack: vec![vec![0xFF; 64]],
        },
        &msg_hash,
    );
    let unicode_safe = unicode_result.is_err() || !unicode_result.unwrap_or(true);

    let all_safe = empty_safe && long_safe && nested_safe && null_safe && unicode_safe;

    log.record(AttackResult {
        name: "Tier 5.5: Descriptor parsing edge cases".into(),
        invariant: Invariant::WitnessValidity,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 0,
        blocked: all_safe,
        defense: DefenseLayer::Implementation,
        scaling: Scaling::Constant,
        notes: format!(
            "empty={} long={} nested={} null={} unicode={}",
            if empty_safe { "safe" } else { "UNSAFE" },
            if long_safe { "safe" } else { "UNSAFE" },
            if nested_safe { "safe" } else { "UNSAFE" },
            if null_safe { "safe" } else { "UNSAFE" },
            if unicode_safe { "safe" } else { "UNSAFE" },
        ),
    });
}

// =========================================================================
// Tier 5.5: Deposit ID collision resistance
// =========================================================================

#[test]
fn tier5_5_deposit_id_collision_resistance() {
    let mut log = AttackLog::new();

    // deposit_id = SHA256(descriptor)[0..16] — 128-bit truncation.
    // Birthday attack needs ~2^64 attempts for 50% collision.
    //
    // Test: generate many descriptors and check for collisions.
    // We can't do 2^64 in a test, but we can verify the hash
    // distributes uniformly across a smaller sample.

    let mut ids = std::collections::HashSet::new();
    let sample_size = 10_000;
    let mut collisions = 0;

    for i in 0u64..sample_size {
        let desc = format!("pk({:064x})", i);
        let id = compute_deposit_id(&desc);
        if !ids.insert(id) {
            collisions += 1;
        }
    }

    log.record(AttackResult {
        name: "Tier 5.5: Deposit ID collision resistance (10k sample)".into(),
        invariant: Invariant::PaymentUniqueness,
        adversary: AdversaryCapability {
            operators: 1,
            quorum_fraction: 0.25,
            controls_relay: false,
            controls_miner: false,
            computational_advantage: Some("2^64 hash computations for birthday attack".into()),
        },
        cost_sats: 0,
        extraction_sats: 0,
        blocked: collisions == 0,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Constant,
        notes: format!(
            "{} unique IDs from {} descriptors, {} collisions. \
             128-bit truncated SHA256 provides 2^64 birthday resistance.",
            ids.len(),
            sample_size,
            collisions
        ),
    });

    assert_eq!(collisions, 0, "No collisions expected in 10k sample");
}

// =========================================================================
// Tier 3.3: Dispute-lottery griefing — commit but don't reveal
// =========================================================================

#[test]
fn tier3_3_lottery_griefing() {
    let mut log = AttackLog::new();

    // Attack: participant commits to lottery (DisputeArmed with commitment_hash)
    // but then refuses to reveal the preimage.
    //
    // The protocol must handle this via:
    // 1. Liveness proofs (non-revealers violate their obligations)
    // 2. Quorum can slash non-revealers' collateral
    // 3. Degrading Taproot timelocks provide fallback spending
    //
    // Test: verify the state machine allows progression even when
    // a participant doesn't reveal.

    let mut net = TestNetwork::new(&["alice", "bob", "charlie", "diana"], 1_000_000);
    let snapshots: Vec<_> = net
        .operators
        .iter()
        .map(|o| Operator {
            name: o.name.clone(),
            secret_key: o.secret_key,
            public_key: o.public_key,
            ledger: o.ledger.clone(),
        })
        .collect();

    // Setup quorum on alice's ledger
    for member in &snapshots {
        if member.name == "alice" {
            continue;
        }
        let lid = hex::encode(member.ledger.state.ledger_id);
        net.op_mut("alice").add_quorum_member(member, &lid);
    }
    net.op_mut("alice").begin_quorum(1_000_000);
    for member in &snapshots {
        if member.name == "alice" {
            continue;
        }
        net.op_mut("alice").record_attestation(member, 500_000);
    }

    // Enter dispute
    let seq = net.op("alice").ledger.state.sequence;
    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::DisputeEnter {
            last_valid_sequence: seq,
            reason: "test".into(),
        })
        .unwrap();

    // Rebuild quorum
    for member in &snapshots {
        if member.name == "alice" {
            continue;
        }
        net.op_mut("alice")
            .add_quorum_member(member, &hex::encode(member.ledger.state.ledger_id));
    }
    net.op_mut("alice")
        .record_attestation(&snapshots[1], 500_000);

    // Bob arms (commits to lottery)
    net.op_mut("alice")
        .ledger
        .apply_operation(&LedgerOperation::DisputeArmed {
            armed_block: 800_000,
            commitment_hash: [0xBB; 20], // bob's commitment
            target_reserves: "bcrt1qbob".into(),
        })
        .unwrap();

    // State should be Armed
    assert_eq!(
        net.op("alice").ledger.state.dispute_state,
        DisputeState::Armed
    );

    // Now bob "doesn't reveal" — but other participants can still:
    // 1. DisputeAcquire (if they win the lottery based on other reveals)
    // 2. DisputeYield (if they lose)
    // The protocol doesn't stall — it just proceeds without bob's reveal.

    // Charlie can claim (DisputeAcquire) even without bob's reveal
    let charlie_pk = snapshots
        .iter()
        .find(|s| s.name == "charlie")
        .unwrap()
        .public_key;
    let acquire_result =
        net.op_mut("alice")
            .ledger
            .apply_operation(&LedgerOperation::DisputeAcquire {
                new_custodian: charlie_pk,
                entropy_block_height: 850_000,
                entropy_block_hash: [0xEE; 32],
                spend_txid: [0xCC; 32],
                new_reserves_address: "bcrt1qcharlie".into(),
            });

    let can_proceed = acquire_result.is_ok();

    log.record(AttackResult {
        name: "Tier 3.3: Lottery griefing (commit, don't reveal)".into(),
        invariant: Invariant::LotteryLiveness,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 500_000, // griefer's collateral at risk
        extraction_sats: 0, // griefing doesn't extract funds
        blocked: can_proceed,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Constant,
        notes: format!(
            "Protocol progresses despite non-reveal: {}. \
             Non-revealers face quorum slashing (liveness proof violation). \
             Degrading Taproot timelocks provide fallback if all participants grief.",
            if can_proceed {
                "DisputeAcquire succeeded"
            } else {
                "STALLED — cannot proceed"
            }
        ),
    });

    assert!(
        can_proceed,
        "Protocol must allow DisputeAcquire even if some participants don't reveal"
    );
}

// =========================================================================
// Tier 3.4: Entropy block MEV
// =========================================================================

#[test]
fn tier3_4_entropy_mev_model() {
    let mut log = AttackLog::new();

    // A miner who is also a lottery participant can:
    // 1. See the entropy (their own block header) before publishing
    // 2. Check if they win the lottery with that entropy
    // 3. Withhold the block if they don't win
    //
    // Cost: opportunity cost of withholding a block (block reward)
    // Benefit: lottery prize (reserves at stake in dispute)
    //
    // Profitable when: reserves_at_stake > block_reward / mining_probability
    //
    // At current BTC: block_reward ≈ 3.125 BTC
    // A miner with 1% hashrate has ~1% chance of finding a block
    // So they'd need to withhold ~100 blocks to guarantee winning
    // Cost: 100 × 3.125 BTC = 312.5 BTC
    //
    // This means MEV is only profitable when reserves > 312.5 BTC
    // for a 1% miner.

    let block_reward_sats = 312_500_000u64; // 3.125 BTC
    let miner_hashrate = 0.01f64; // 1% of total hashrate

    // Expected blocks to withhold = 1 / miner_hashrate (geometric distribution)
    let expected_blocks_withheld = (1.0 / miner_hashrate) as u64;
    let withholding_cost = expected_blocks_withheld * block_reward_sats;

    // Find threshold: reserves at which MEV becomes profitable
    let threshold_reserves = withholding_cost;

    log.record(AttackResult {
        name: "Tier 3.4: Entropy block MEV".into(),
        invariant: Invariant::NegativeExpectedValue,
        adversary: AdversaryCapability {
            operators: 1,
            quorum_fraction: 0.25,
            controls_relay: false,
            controls_miner: true,
            computational_advantage: Some(format!("{:.1}% hashrate", miner_hashrate * 100.0)),
        },
        cost_sats: withholding_cost,
        extraction_sats: 0, // depends on reserves
        blocked: true,      // for typical deposit sizes
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Linear,
        notes: format!(
            "Miner with {:.1}% hashrate: withholding cost = {} BTC ({} blocks × {} BTC reward). \
             MEV profitable only when reserves > {} BTC. \
             For typical deposits (<10 BTC), MEV is deeply unprofitable.",
            miner_hashrate * 100.0,
            withholding_cost as f64 / 100_000_000.0,
            expected_blocks_withheld,
            block_reward_sats as f64 / 100_000_000.0,
            threshold_reserves as f64 / 100_000_000.0,
        ),
    });
}

// =========================================================================
// Tier 2.4: Proof hash embedding — canonical location
// =========================================================================

#[test]
fn tier2_4_proof_hash_embedding() {
    let mut log = AttackLog::new();

    // DEP-06 says proof hash is "typically" embedded in the nonce field
    // of a self-transfer. Check if the implementation enforces a canonical
    // embedding location or accepts proofs from any field.

    // The fraud proof system in deposits-protocol/src/fraud.rs
    let source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("deposits-protocol/src/fraud.rs"),
    )
    .unwrap_or_default();

    // Check: is there a single canonical location?
    let has_canonical_location =
        source.contains("nonce") || source.contains("self_transfer") || source.contains("embed");

    // Check: are multiple embedding locations accepted?
    let accepts_multiple = source.contains("any field")
        || source.contains("any location")
        || source.contains("alternative");

    log.record(AttackResult {
        name: "Tier 2.4: Proof hash embedding ambiguity".into(),
        invariant: Invariant::SignatureBinding,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 0,
        blocked: has_canonical_location && !accepts_multiple,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Constant,
        notes: format!(
            "Canonical embedding location referenced: {}. Multiple locations accepted: {}. \
             fraud.rs is {} lines. Spec should mandate exactly one canonical location.",
            has_canonical_location,
            accepts_multiple,
            source.lines().count()
        ),
    });
}
