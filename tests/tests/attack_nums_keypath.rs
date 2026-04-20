//! Attack #1: Can the operator key-path spend reserves?
//!
//! Two sub-tests:
//! (a) With current reference implementation, can operator key-path spend?
//! (b) With spec-only-conformant wallet, would this be detected?
//!
//! The fix: require BIP-341 NUMS point, wallets verify on QuorumBegin.

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use deposits_core::tapscript_reserves::{TapscriptReservesBuilder, ThresholdConfig, VoterSet};
use deposits_integration_tests::adversarial::*;

fn make_key(seed: u8) -> (SecretKey, bitcoin::secp256k1::PublicKey) {
    let secp = Secp256k1::new();
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = 0x42;
    let sk = SecretKey::from_slice(&bytes).unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    (sk, pk)
}

#[test]
fn attack_nums_keypath_spend_attempt() {
    let mut log = AttackLog::new();
    let secp = Secp256k1::new();

    // Build a reserves output using the reference implementation
    let (operator_sk, operator_pk) = make_key(1);
    let others: Vec<_> = (2..=4).map(|i| make_key(i).1).collect();
    let voter_set = VoterSet::new(operator_pk, others);
    let config = ThresholdConfig::default_for_voter_count(4);
    let ledger_hash = [0xAB; 32];

    let builder =
        TapscriptReservesBuilder::new(voter_set, config, bitcoin::Network::Regtest, ledger_hash);
    let output = builder.build().unwrap();

    // Step 1: The internal key IS the operator's key (tie-breaker).
    // In BIP-341, the key-path spend requires a Schnorr signature
    // with the tweaked internal key. If we know the internal key's
    // secret, we can compute the tweaked secret and sign.

    let steps = vec![AttackStep {
        action: "Build reserves output".into(),
        outcome: StepOutcome::Succeeded,
        detail: format!("Address: {}", &output.address.to_string()[..24]),
    }];

    // Step 2: Try to compute the tweaked key.
    // The tweak is: t = tagged_hash("TapTweak", internal_key || merkle_root)
    // The tweaked secret key is: sk_tweaked = sk + t
    // If we can compute this, we can key-path spend.

    // The operator knows their secret key. The merkle root is derivable
    // from the public script tree (which is announced in the quorum).
    // So: operator CAN compute the tweaked key.

    let internal_x_only = operator_pk.x_only_public_key().0;
    let merkle_root = output.spend_info.merkle_root();

    // Compute the tweak
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let mut eng = sha256::Hash::engine();
    // BIP-341 tagged hash: SHA256(SHA256("TapTweak") || SHA256("TapTweak") || data)
    let tag_hash = sha256::Hash::hash(b"TapTweak");
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(&internal_x_only.serialize());
    if let Some(root) = merkle_root {
        eng.input(root.as_ref());
    }
    let tweak_bytes = sha256::Hash::from_engine(eng).to_byte_array();

    // Try to create tweaked keypair
    let keypair = Keypair::from_secret_key(&secp, &operator_sk);
    let tweaked = keypair.add_xonly_tweak(
        &secp,
        &bitcoin::secp256k1::Scalar::from_be_bytes(tweak_bytes).expect("valid scalar"),
    );

    let can_tweak = tweaked.is_ok();

    let mut steps = steps;
    steps.push(AttackStep {
        action: "Compute tweaked secret key".into(),
        outcome: if can_tweak {
            StepOutcome::Succeeded
        } else {
            StepOutcome::Rejected
        },
        detail: format!("Operator can derive tweaked key: {}", can_tweak),
    });

    if can_tweak {
        // Step 3: Sign a sighash with the tweaked key
        let test_sighash = [0xDE; 32];
        let msg = Message::from_digest(test_sighash);
        let tweaked_kp = tweaked.unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked_kp);

        // Verify: does this signature validate against the output's public key?
        let output_key = output.spend_info.output_key();
        let verify_result = secp.verify_schnorr(&sig, &msg, &output_key.to_x_only_public_key());
        let sig_valid = verify_result.is_ok();

        steps.push(AttackStep {
            action: "Sign with tweaked key".into(),
            outcome: if sig_valid {
                StepOutcome::Succeeded
            } else {
                StepOutcome::Rejected
            },
            detail: format!("Signature valid against output key: {}", sig_valid),
        });

        // Step 4: Verify the internal key is NUMS
        let is_nums = deposits_core::tapscript_reserves::verify_nums_internal_key(&output);
        steps.push(AttackStep {
            action: "Verify internal key is NUMS".into(),
            outcome: if is_nums {
                StepOutcome::Rejected
            } else {
                StepOutcome::Undetected
            },
            detail: format!("Internal key matches BIP-341 NUMS: {}", is_nums),
        });

        log.record(AttackResult {
            name: "NUMS key-path spend: operator cannot sign (FIXED)".into(),
            invariant: Invariant::NUMSPoint,
            adversary: AdversaryCapability::single_operator(4),
            cost_sats: 0,
            extraction_sats: 0,
            blocked: !sig_valid && is_nums,
            defense: DefenseLayer::Implementation,
            scaling: Scaling::Constant,
            notes: format!(
                "FIXED: Internal key is now BIP-341 NUMS point. \
                 Operator can compute tweak from their own key but the resulting \
                 signature does NOT validate against the output key (which uses NUMS). \
                 Key-path spend is impossible. All spends must use Tapscript leaves. \
                 sig_valid={}, is_nums={}",
                sig_valid, is_nums
            ),
            steps,
        });

        // The fix works: operator CANNOT key-path spend
        assert!(
            !sig_valid,
            "Operator must NOT be able to key-path spend after NUMS fix"
        );
        assert!(is_nums, "Internal key must be BIP-341 NUMS point");
    }
}

#[test]
fn attack_nums_verify_fix() {
    let mut log = AttackLog::new();

    // What would a fixed implementation look like?
    // The BIP-341 NUMS point is:
    // lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
    //
    // A wallet verifying QuorumBegin would:
    // 1. Reconstruct the Taproot tree from the announced quorum members
    // 2. Use the NUMS point as internal key
    // 3. Compute the expected address
    // 4. Reject if the announced address doesn't match

    let bip341_nums_hex = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
    let nums_bytes = hex::decode(bip341_nums_hex).unwrap();
    let nums_x_only = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&nums_bytes);

    let nums_is_valid_x = nums_x_only.is_ok();

    log.record(AttackResult {
        name: "NUMS fix verification: BIP-341 point is valid".into(),
        invariant: Invariant::NUMSPoint,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 0,
        blocked: nums_is_valid_x,
        defense: DefenseLayer::Implementation,
        scaling: Scaling::Constant,
        notes: format!(
            "BIP-341 NUMS x-coordinate is valid: {}. \
             Fix requires: (1) use this as internal key in TapscriptReservesBuilder, \
             (2) add verification in wallet on QuorumBegin, \
             (3) add normative requirement to DEP-03.",
            nums_is_valid_x
        ),
        steps: vec![AttackStep {
            action: "Parse BIP-341 NUMS x-coordinate".into(),
            outcome: if nums_is_valid_x {
                StepOutcome::Succeeded
            } else {
                StepOutcome::Rejected
            },
            detail: format!(
                "0x{}... → valid x-only pubkey: {}",
                &bip341_nums_hex[..16],
                nums_is_valid_x
            ),
        }],
    });
}
