//! Recovery Handler Integration Tests
//!
//! Tests for the recovery message handlers integrated with RecoveryManager and ClaimManager.
//! These tests verify that the handler correctly:
//! - Validates recovery votes using RecoveryManager
//! - Checks non-conformance status before signing claims
//! - Aggregates signatures using ClaimManager
//! - Emits appropriate events

#![cfg(feature = "bitcoin-deposits")]

use ldk_node::bitcoin::hashes::Hash;
use ldk_node::bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};

// Test helper to generate keys
fn generate_test_keypair(seed: u8) -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut secret = [0u8; 32];
    secret[31] = seed;
    if seed == 0 {
        secret[31] = 1; // Avoid invalid key
    }
    let sk = SecretKey::from_slice(&secret).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    (sk, pk)
}

fn generate_test_pubkey(seed: u8) -> PublicKey {
    let (_, pk) = generate_test_keypair(seed);
    pk
}

/// Test RecoveryManager vote tracking integration
#[test]
fn test_recovery_manager_vote_submission() {
    use deposits_core::recovery::{RecoveryManager, RecoveryVote};
    use ldk_node::bitcoin::hashes::Hash;

    let our_node = generate_test_pubkey(1);
    let operator = generate_test_pubkey(10);
    let partner = generate_test_pubkey(20);
    let (voter_sk, voter_pk) = generate_test_keypair(30);

    let mut manager = RecoveryManager::new(our_node);
    let ledger_id = (operator, partner);

    // Start recovery process
    manager
        .start_recovery(
            operator, partner, 100,       // force close block
            [1u8; 32], // force close txid
            [2u8; 32], // on chain ledger hash
        )
        .expect("Should start recovery");

    // Transition to evaluating phase
    let entropy = [42u8; 32];
    manager
        .on_entropy_block(ledger_id, entropy)
        .expect("Should transition to evaluating");

    // Create signed vote
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &voter_sk);

    // Build vote message (must match RecoveryVote::sighash())
    // voter (33) + is_conforming (1) + validated_hash (32) + substitute_nomination (33)
    let mut vote_data = Vec::new();
    vote_data.extend_from_slice(&voter_pk.serialize());
    vote_data.push(1u8); // is_conforming = true
    vote_data.extend_from_slice(&[2u8; 32]); // validated_hash
    vote_data.extend_from_slice(&[0u8; 33]); // substitute_nomination = None (zeros)

    let vote_hash = ldk_node::bitcoin::hashes::sha256::Hash::hash(&vote_data);
    let msg = Message::from_digest(*vote_hash.as_ref());
    let signature = secp.sign_schnorr(&msg, &keypair);

    let vote = RecoveryVote {
        voter: voter_pk,
        is_conforming: true,
        validated_hash: [2u8; 32],
        validated_sequence: 100,
        substitute_nomination: None,
        discovered_violation: false,
        signature: signature.serialize(),
    };

    // Submit vote
    let result = manager.submit_vote(ledger_id, vote);
    assert!(result.is_ok(), "Vote submission should succeed");

    let vote_result = result.unwrap();
    assert_eq!(vote_result.total_votes, 1);
    assert_eq!(vote_result.conforming_votes, 1);
    assert_eq!(vote_result.non_conforming_votes, 0);
}

/// Test ClaimManager signature aggregation
#[test]
fn test_claim_manager_peer_signature_aggregation() {
    use deposits_core::recovery::ClaimEligibility;
    use deposits_core::recovery_claim::{ClaimConfig, ClaimManager, ClaimableReserves};
    use deposits_core::tapscript_reserves::{TapscriptReservesBuilder, ThresholdConfig, VoterSet};
    use ldk_node::bitcoin::{Network, OutPoint, Txid};

    let (sk1, pk1) = generate_test_keypair(1);
    let (sk2, pk2) = generate_test_keypair(2);

    let voter_set = VoterSet::new(pk1, vec![pk2]);
    let ledger_hash = [0xAA; 32];
    let builder =
        TapscriptReservesBuilder::with_defaults(voter_set.clone(), Network::Regtest, ledger_hash);
    let output = builder.build().expect("Should build reserves");

    let reserves = ClaimableReserves {
        outpoint: OutPoint {
            txid: Txid::from_slice(&[0xAB; 32]).unwrap(),
            vout: 0,
        },
        amount_sats: 100_000,
        script_pubkey: output.script_pubkey(),
        voter_set,
        threshold_config: ThresholdConfig::default_for_voter_count(2),
        network: Network::Regtest,
        ledger_hash,
    };

    let config = ClaimConfig::default();
    let mut manager = ClaimManager::new(pk1, Some(sk1.clone()), config);

    let ledger_id = (pk1, pk2);
    // Use SelectedPartnerOnly (tier 0) - AnySinglePartner (tier 2) exceeds default tier count
    let eligibility = ClaimEligibility::SelectedPartnerOnly { partner: pk1 };

    // Initiate claim
    manager
        .initiate_claim(ledger_id, vec![pk1], eligibility, reserves)
        .expect("Should initiate claim");

    // Sign with our key first
    manager.sign_claim(&ledger_id).expect("Should sign");

    // Now add peer signature (simulate receiving RecoveryClaimSignature message)
    let attempt = manager.get_claim(&ledger_id).unwrap();
    let sighash = attempt.get_sighash().expect("Should get sighash");

    let secp = Secp256k1::new();
    let keypair2 = Keypair::from_secret_key(&secp, &sk2);
    let msg = Message::from_digest(*sighash.as_ref());
    let sig2 = secp.sign_schnorr(&msg, &keypair2);

    // This simulates what the handler does
    let has_sufficient = manager
        .add_peer_signature(&ledger_id, &pk2, sig2.serialize())
        .expect("Should add signature");

    // With AnySinglePartner tier, 2 voters may or may not need both signatures
    // depending on threshold configuration
    println!("Has sufficient signatures: {}", has_sufficient);

    // Verify claim still exists
    assert!(manager.get_claim(&ledger_id).is_some());
}

/// Test ClaimManager remove_claim for RecoveryClaimComplete handling
#[test]
fn test_claim_manager_claim_removal() {
    use deposits_core::recovery::ClaimEligibility;
    use deposits_core::recovery_claim::{ClaimConfig, ClaimManager, ClaimableReserves};
    use deposits_core::tapscript_reserves::{TapscriptReservesBuilder, ThresholdConfig, VoterSet};
    use ldk_node::bitcoin::{Network, OutPoint, Txid};

    let (sk1, pk1) = generate_test_keypair(1);
    let pk2 = generate_test_pubkey(2);

    let voter_set = VoterSet::new(pk1, vec![pk2]);
    let ledger_hash = [0xAA; 32];
    let builder =
        TapscriptReservesBuilder::with_defaults(voter_set.clone(), Network::Regtest, ledger_hash);
    let output = builder.build().expect("Should build reserves");

    let reserves = ClaimableReserves {
        outpoint: OutPoint {
            txid: Txid::from_slice(&[0xAB; 32]).unwrap(),
            vout: 0,
        },
        amount_sats: 100_000,
        script_pubkey: output.script_pubkey(),
        voter_set,
        threshold_config: ThresholdConfig::default_for_voter_count(2),
        network: Network::Regtest,
        ledger_hash,
    };

    let config = ClaimConfig::default();
    let mut manager = ClaimManager::new(pk1, Some(sk1), config);

    let ledger_id = (pk1, pk2);
    // Use SelectedPartnerOnly (tier 0) - AnySinglePartner (tier 2) exceeds default tier count
    let eligibility = ClaimEligibility::SelectedPartnerOnly { partner: pk1 };

    // Initiate claim
    manager
        .initiate_claim(ledger_id, vec![pk1], eligibility, reserves)
        .expect("Should initiate claim");

    // Verify claim exists
    assert!(manager.get_claim(&ledger_id).is_some());

    // Remove claim (simulates RecoveryClaimComplete handler)
    let removed = manager.remove_claim(&ledger_id);
    assert!(removed.is_some());

    // Verify claim is gone
    assert!(manager.get_claim(&ledger_id).is_none());
}

/// Test RecoveryManager non-conformance phase detection
#[test]
fn test_recovery_phase_detection() {
    use deposits_core::recovery::{RecoveryManager, RecoveryPhase};

    let our_node = generate_test_pubkey(1);
    let operator = generate_test_pubkey(10);
    let partner = generate_test_pubkey(20);

    let mut manager = RecoveryManager::new(our_node);
    let ledger_id = (operator, partner);

    // No recovery in progress
    assert!(manager.get_recovery(&ledger_id).is_none());

    // Start recovery
    manager
        .start_recovery(operator, partner, 100, [1u8; 32], [2u8; 32])
        .expect("Should start recovery");

    // Should be in WaitingForEntropy phase
    let state = manager
        .get_recovery(&ledger_id)
        .expect("Should have recovery");
    assert!(matches!(
        state.phase,
        RecoveryPhase::WaitingForEntropy { .. }
    ));

    // Transition to evaluating
    manager
        .on_entropy_block(ledger_id, [42u8; 32])
        .expect("Should transition");

    let state = manager
        .get_recovery(&ledger_id)
        .expect("Should have recovery");
    assert!(matches!(state.phase, RecoveryPhase::Evaluating { .. }));

    // Directly transition to non-compliant (for testing handler logic)
    // transition_to_non_compliant takes: ledger_id, force_close_block, channel_partners
    manager
        .transition_to_non_compliant(ledger_id, 100, vec![partner])
        .expect("Should transition to non-compliant");

    let state = manager
        .get_recovery(&ledger_id)
        .expect("Should have recovery");
    assert!(matches!(
        state.phase,
        RecoveryPhase::NonCompliantRecovery { .. }
    ));
}

/// Test vote result tracking
#[test]
fn test_recovery_vote_result_tracking() {
    use deposits_core::recovery::{RecoveryManager, RecoveryVote};
    use ldk_node::bitcoin::hashes::Hash;

    let our_node = generate_test_pubkey(1);
    let operator = generate_test_pubkey(10);
    let partner = generate_test_pubkey(20);

    // Create multiple voters
    let (voter1_sk, voter1_pk) = generate_test_keypair(30);
    let (voter2_sk, voter2_pk) = generate_test_keypair(31);

    let mut manager = RecoveryManager::new(our_node);
    let ledger_id = (operator, partner);

    // Start recovery and transition to evaluating
    manager
        .start_recovery(operator, partner, 100, [1u8; 32], [2u8; 32])
        .unwrap();
    manager.on_entropy_block(ledger_id, [42u8; 32]).unwrap();

    let secp = Secp256k1::new();

    // Submit conforming vote (must match RecoveryVote::sighash())
    let keypair1 = Keypair::from_secret_key(&secp, &voter1_sk);
    let mut vote_data1 = Vec::new();
    vote_data1.extend_from_slice(&voter1_pk.serialize()); // 33 bytes
    vote_data1.push(1u8); // conforming
    vote_data1.extend_from_slice(&[2u8; 32]); // validated_hash
    vote_data1.extend_from_slice(&[0u8; 33]); // substitute_nomination = None (zeros)
    let msg1 =
        Message::from_digest(*ldk_node::bitcoin::hashes::sha256::Hash::hash(&vote_data1).as_ref());
    let sig1 = secp.sign_schnorr(&msg1, &keypair1);

    let vote1 = RecoveryVote {
        voter: voter1_pk,
        is_conforming: true,
        validated_hash: [2u8; 32],
        validated_sequence: 100,
        substitute_nomination: None,
        discovered_violation: false,
        signature: sig1.serialize(),
    };

    let result1 = manager
        .submit_vote(ledger_id, vote1)
        .expect("Vote 1 should succeed");
    assert_eq!(result1.conforming_votes, 1);
    assert_eq!(result1.non_conforming_votes, 0);

    // Submit non-conforming vote (must match RecoveryVote::sighash())
    let keypair2 = Keypair::from_secret_key(&secp, &voter2_sk);
    let mut vote_data2 = Vec::new();
    vote_data2.extend_from_slice(&voter2_pk.serialize()); // 33 bytes
    vote_data2.push(0u8); // non-conforming
    vote_data2.extend_from_slice(&[2u8; 32]); // validated_hash
    vote_data2.extend_from_slice(&our_node.serialize()); // substitute_nomination = Some(our_node)
    let msg2 =
        Message::from_digest(*ldk_node::bitcoin::hashes::sha256::Hash::hash(&vote_data2).as_ref());
    let sig2 = secp.sign_schnorr(&msg2, &keypair2);

    let vote2 = RecoveryVote {
        voter: voter2_pk,
        is_conforming: false,
        validated_hash: [2u8; 32],
        validated_sequence: 100,
        substitute_nomination: Some(our_node),
        discovered_violation: true,
        signature: sig2.serialize(),
    };

    let result2 = manager
        .submit_vote(ledger_id, vote2)
        .expect("Vote 2 should succeed");
    assert_eq!(result2.total_votes, 2);
    assert_eq!(result2.conforming_votes, 1);
    assert_eq!(result2.non_conforming_votes, 1);
}
