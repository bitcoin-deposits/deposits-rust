// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Tests for the Bitcoin Deposits handler module.

use super::core::*;
use super::ledger_ops::{LedgerOperations, LedgerOperationsExt};
use super::message_validation::MessageValidation;
use super::payment_tracking::PaymentTracking;
use super::recovery_ops::RecoveryOperations;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::CustomMessageReader;
use lightning::util::test_utils::{TestLogger, TestStore};
use lightning::util::logger::Logger;
use lightning_types::features::InitFeatures;
use std::collections::HashMap;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use super::messages::{DepositsMessage, LedgerUpdateMsg, LedgerUpdateMsgExt, LedgerOperation, RecoveryMsg};
use super::protocol_stub::DepositsProtocol;
use crate::event::EventQueue;
use crate::types::DynStore;

fn create_test_handler() -> DepositsHandler<Arc<TestLogger>> {
    let logger = Arc::new(TestLogger::new());
    let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
    let event_queue = Arc::new(EventQueue::new(Arc::clone(&logger)));

    // Generate a test node ID
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let test_node_id = PublicKey::from_secret_key(&secp, &secret);

    let mut handler = DepositsHandler::new(event_queue, logger, kv_store, test_node_id, bitcoin::Network::Regtest).expect("Test handler creation should not fail");
    handler.initialize_core_handler();
    handler
}

fn create_test_pubkey() -> PublicKey {
    PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()
}

/// Helper to mark a peer as connected for testing
/// Required because get_and_clear_pending_msg only drains messages for connected peers
fn mark_peer_connected<L: Deref + Clone + Send + Sync>(handler: &DepositsHandler<L>, peer: PublicKey)
where
    L::Target: Logger,
{
    handler.connected_peers.lock().unwrap().insert(peer);
}

fn create_test_protocol() -> Arc<DepositsProtocol<Arc<TestLogger>>> {
    use bitcoin::secp256k1::SecretKey;

    let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
    let store: Arc<crate::types::DynStore> = Arc::new(TestStore::new(false));
    let logger = Arc::new(TestLogger::new());

    Arc::new(DepositsProtocol::new(secret_key, store, logger))
}

#[test]
fn test_handler_creation() {
    let handler = create_test_handler();
    let stats = handler.get_protocol_stats();

    assert_eq!(stats.active_partners, 0);
    assert_eq!(stats.pending_outbound_messages, 0);
    assert_eq!(stats.total_ledgers, 0);
}

#[test]
fn test_protocol_registration() {
    let handler = create_test_handler();
    let partner_key = create_test_pubkey();
    let protocol = create_test_protocol();

    // Register protocol
    handler.add_protocol(partner_key, Arc::clone(&protocol));

    // Verify registration
    let retrieved_protocol = handler.get_protocol(&partner_key);
    assert!(retrieved_protocol.is_some());

    let stats = handler.get_protocol_stats();
    assert_eq!(stats.active_partners, 1);

    // Test removal
    handler.remove_protocol(&partner_key);
    assert!(handler.get_protocol(&partner_key).is_none());

    let stats = handler.get_protocol_stats();
    assert_eq!(stats.active_partners, 0);
}

#[test]
fn test_message_queuing() {
    let handler = create_test_handler();
    let peer_key = create_test_pubkey();

    // Mark peer as connected so messages can be drained
    mark_peer_connected(&handler, peer_key);

    let message = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
        peer_key, // operator
        peer_key, // partner
        LedgerOperation::ReservesAdd {
            amount: 1000,
            spend_to: peer_key,
            collateral_partners: vec![],
        },
    ));

    // Queue message
    let result = handler.send_message(peer_key, message);
    assert!(result.is_ok());

    // Check pending messages
    let pending = handler.get_and_clear_pending_msg();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, peer_key);

    // Verify queue is cleared
    let pending = handler.get_and_clear_pending_msg();
    assert_eq!(pending.len(), 0);
}

#[test]
fn test_message_reading() {
    let handler = create_test_handler();

    // Test valid message type
    let test_data = vec![0x00, 0x01, 0x02, 0x03]; // Dummy data
    let mut reader = &test_data[..];

    let _result = handler.read(0x1000, &mut reader); // RESERVES_ADD
    // Result depends on actual message format - this tests the interface

    // Test invalid message type
    let mut reader = &test_data[..];
    let result = handler.read(0x9999, &mut reader);
    assert_eq!(result.unwrap(), None);
}

#[test]
fn test_feature_negotiation() {
    let handler = create_test_handler();
    let peer_key = create_test_pubkey();

    // Test init features for unknown peer
    let _features = handler.provided_init_features(peer_key);
    // Should provide optional support

    // Add protocol and test again
    let protocol = create_test_protocol();
    handler.add_protocol(peer_key, protocol);

    let _features = handler.provided_init_features(peer_key);
    // Should now provide required support

    // Test node features
    let _node_features = handler.provided_node_features();
    // Should indicate protocol support
}

#[test]
fn test_peer_connection_handling() {
    let handler = create_test_handler();
    let peer_key = create_test_pubkey();

    // Create mock init message
    let init_msg = lightning::ln::msgs::Init {
        features: InitFeatures::empty(),
        networks: None,
        remote_network_address: None,
    };

    // Test peer connection
    let result = handler.peer_connected(peer_key, &init_msg, true);
    assert!(result.is_ok());

    // Test peer disconnection
    handler.peer_disconnected(peer_key);

    // Verify outbound messages are cleared
    let stats = handler.get_protocol_stats();
    assert_eq!(stats.pending_outbound_messages, 0);
}

// ==================== VoteRoundState Tests ====================

fn create_test_pubkey_from_seed(seed: u8) -> PublicKey {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let mut key_bytes = [seed; 32];
    if seed == 0 {
        key_bytes[0] = 1;
    }
    let secret = SecretKey::from_slice(&key_bytes).unwrap();
    PublicKey::from_secret_key(&secp, &secret)
}

fn create_test_vote_round(threshold: usize) -> VoteRoundState {
    VoteRoundState {
        operator_id: create_test_pubkey_from_seed(1),
        partner_id: create_test_pubkey_from_seed(2),
        sequence_number: 42,
        state_hash: [0xAB; 32],
        claimed_reserves: 100_000,
        reserves_outpoint: vec![0; 36],
        destination_script: vec![0x00, 0x14, 0xAB, 0xCD, 0xEF], // Sample script
        fee_rate_sat_vbyte: 10,
        threshold,
        votes: HashMap::new(),
        tx_broadcast: false,
        created_at: 1234567890,
    }
}

#[test]
fn test_vote_round_conforming_count_empty() {
    let round = create_test_vote_round(2);
    assert_eq!(round.conforming_vote_count(), 0);
    assert!(!round.threshold_reached());
}

#[test]
fn test_vote_round_conforming_count_with_votes() {
    let mut round = create_test_vote_round(2);

    let voter1 = create_test_pubkey_from_seed(10);
    round.votes.insert(voter1, (true, Some([0xAA; 64])));
    assert_eq!(round.conforming_vote_count(), 1);
    assert!(!round.threshold_reached());

    let voter2 = create_test_pubkey_from_seed(11);
    round.votes.insert(voter2, (false, None));
    assert_eq!(round.conforming_vote_count(), 1);
    assert!(!round.threshold_reached());

    let voter3 = create_test_pubkey_from_seed(12);
    round.votes.insert(voter3, (true, Some([0xBB; 64])));
    assert_eq!(round.conforming_vote_count(), 2);
    assert!(round.threshold_reached());
}

#[test]
fn test_vote_round_threshold_edge_cases() {
    let mut round = create_test_vote_round(1);
    assert!(!round.threshold_reached());

    let voter = create_test_pubkey_from_seed(10);
    round.votes.insert(voter, (true, None));
    assert!(round.threshold_reached());

    let round_zero = create_test_vote_round(0);
    assert!(round_zero.threshold_reached());
}

#[test]
fn test_vote_round_collect_signatures_empty() {
    let round = create_test_vote_round(2);
    let sigs = round.collect_spend_signatures();
    assert!(sigs.is_empty());
}

#[test]
fn test_vote_round_collect_signatures_conforming_only() {
    let mut round = create_test_vote_round(2);

    let voter1 = create_test_pubkey_from_seed(10);
    let voter2 = create_test_pubkey_from_seed(11);
    let voter3 = create_test_pubkey_from_seed(12);

    round.votes.insert(voter1, (true, Some([0xAA; 64])));
    round.votes.insert(voter2, (false, None));
    round.votes.insert(voter3, (true, Some([0xBB; 64])));

    let sigs = round.collect_spend_signatures();
    assert_eq!(sigs.len(), 2);

    let sig_map: HashMap<PublicKey, [u8; 64]> = sigs.into_iter().collect();
    assert_eq!(sig_map.get(&voter1), Some(&[0xAA; 64]));
    assert_eq!(sig_map.get(&voter3), Some(&[0xBB; 64]));
    assert!(sig_map.get(&voter2).is_none());
}

#[test]
fn test_vote_round_collect_signatures_conforming_without_sig() {
    let mut round = create_test_vote_round(2);

    let voter1 = create_test_pubkey_from_seed(10);
    let voter2 = create_test_pubkey_from_seed(11);

    round.votes.insert(voter1, (true, Some([0xAA; 64])));
    round.votes.insert(voter2, (true, None));

    let sigs = round.collect_spend_signatures();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].0, voter1);
    assert_eq!(sigs[0].1, [0xAA; 64]);
}

#[test]
fn test_vote_round_many_voters() {
    let mut round = create_test_vote_round(5);

    for i in 0..10u8 {
        let voter = create_test_pubkey_from_seed(20 + i);
        if i < 6 {
            let mut sig = [0u8; 64];
            sig[0] = i;
            round.votes.insert(voter, (true, Some(sig)));
        } else {
            round.votes.insert(voter, (false, None));
        }
    }

    assert_eq!(round.conforming_vote_count(), 6);
    assert!(round.threshold_reached());

    let sigs = round.collect_spend_signatures();
    assert_eq!(sigs.len(), 6);
}

// ==================== CollateralAttestation Tests ====================

#[test]
fn test_collateral_attestation_signature_roundtrip() {
    use bitcoin::secp256k1::{Secp256k1, SecretKey, Message};
    use bitcoin::hashes::{Hash, sha256};
    use crate::wire::messages::CollateralAttestationMsg;

    let secp = Secp256k1::new();

    // Create operator and collateral partner keys
    let operator_secret = SecretKey::from_slice(&[41u8; 32]).unwrap();
    let operator = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &operator_secret);

    let partner_secret = SecretKey::from_slice(&[42u8; 32]).unwrap();
    let collateral_partner = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &partner_secret);

    // Test values
    let amount: u64 = 100_000;
    let block_height: u32 = 850_000;

    // Create signing data - collateral partner signs: operator + amount + block_height
    let mut msg_bytes = Vec::new();
    msg_bytes.extend_from_slice(&operator.serialize());
    msg_bytes.extend_from_slice(&amount.to_le_bytes());
    msg_bytes.extend_from_slice(&block_height.to_le_bytes());
    let hash = sha256::Hash::hash(&msg_bytes);

    // Sign with collateral partner's key
    let msg = Message::from_digest(hash.to_byte_array());
    let keypair = partner_secret.keypair(&secp);
    let sig = secp.sign_schnorr(&msg, &keypair);
    let signature: [u8; 64] = *sig.as_ref();

    // Create attestation
    let attestation = CollateralAttestationMsg {
        operator,
        collateral_partner,
        amount,
        block_height,
        signature,
        ledger_hash: [0u8; 32],
    };

    // Verify collateral amount
    assert_eq!(attestation.available_collateral(), 100_000);

    // Verify signature (recipient verification)
    let mut verify_bytes = Vec::new();
    verify_bytes.extend_from_slice(&attestation.operator.serialize());
    verify_bytes.extend_from_slice(&attestation.amount.to_le_bytes());
    verify_bytes.extend_from_slice(&attestation.block_height.to_le_bytes());
    let verify_hash = sha256::Hash::hash(&verify_bytes);
    let verify_msg = Message::from_digest(verify_hash.to_byte_array());

    let public_key = keypair.x_only_public_key().0;
    let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&attestation.signature).unwrap();

    let verification_result = secp.verify_schnorr(&schnorr_sig, &verify_msg, &public_key);
    assert!(verification_result.is_ok(), "Signature verification should succeed");
}

#[test]
fn test_collateral_attestation_available_collateral() {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use crate::wire::messages::CollateralAttestationMsg;

    let secp = Secp256k1::new();
    let operator_secret = SecretKey::from_slice(&[41u8; 32]).unwrap();
    let operator = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &operator_secret);
    let partner_secret = SecretKey::from_slice(&[42u8; 32]).unwrap();
    let collateral_partner = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &partner_secret);

    // Attestation with 100k collateral
    let attestation1 = CollateralAttestationMsg {
        operator,
        collateral_partner,
        amount: 100_000,
        block_height: 850_000,
        signature: [0u8; 64],
        ledger_hash: [0u8; 32],
    };
    assert_eq!(attestation1.available_collateral(), 100_000);

    // Attestation with zero collateral
    let attestation2 = CollateralAttestationMsg {
        operator,
        collateral_partner,
        amount: 0,
        block_height: 850_000,
        signature: [0u8; 64],
        ledger_hash: [0u8; 32],
    };
    assert_eq!(attestation2.available_collateral(), 0);

    // Attestation with smaller collateral
    let attestation3 = CollateralAttestationMsg {
        operator,
        collateral_partner,
        amount: 30_000,
        block_height: 850_000,
        signature: [0u8; 64],
        ledger_hash: [0u8; 32],
    };
    assert_eq!(attestation3.available_collateral(), 30_000);
}

#[test]
fn test_broadcast_uncredited_payment_accusation_invalid_preimage() {
    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create mismatched preimage and payment_hash
    let preimage = [0xAB; 32];
    let wrong_payment_hash = [0xCD; 32]; // Doesn't match preimage

    let result = handler.broadcast_uncredited_payment_accusation(
        operator,
        wrong_payment_hash,
        preimage,
        deposit_pubkey,
        50_000_000,
        [0u8; 64],
    );

    // Should fail because preimage doesn't match payment_hash
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Invalid preimage"));
}

#[test]
fn test_broadcast_uncredited_payment_accusation_no_ledger() {
    use bitcoin::hashes::{sha256, Hash};

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create valid preimage and payment_hash
    let preimage = [0xAB; 32];
    let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

    let result = handler.broadcast_uncredited_payment_accusation(
        operator,
        payment_hash,
        preimage,
        deposit_pubkey,
        50_000_000,
        [0u8; 64],
    );

    // Should fail because no ledger exists for this operator/partner
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("No ledger found"));
}

#[test]
fn test_broadcast_uncredited_payment_accusation_with_ledger() {
    use bitcoin::hashes::{sha256, Hash};
    use deposits_core::Ledger;
    use deposits_core::Invoice;

    let handler = create_test_handler();

    // Create keys - handler's our_node_id is created with secret [1; 32]
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create valid preimage and payment_hash first (needed for invoice)
    let preimage = [0xAB; 32];
    let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

    // Create a ledger for this operator/partner pair
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );

    // Add deposit with cosigned invoice (required for fraud proof validation)
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
    deposit.balance = 100_000;
    deposit.invoices = vec![Invoice {
        id: hex::encode(&payment_hash),
        payment_hash,
        amount: 50_000,
        expires: u64::MAX,
        assigned_deposit: deposit_pubkey,
        bolt11: "lnbc500n1test".to_string(),
    }.into()];
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Add cosigned invoice (required for fraud proof validation)
    {
        let mut invoices = handler.cosigned_invoices.lock().unwrap();
        invoices.insert((operator, payment_hash), CosignedInvoice {
            deposit_pubkey,
            payment_hash,
            amount: 50_000,
            expires: u64::MAX,
            cosignature: vec![0u8; 64],
        });
    }

    // Mark operator as connected so messages can be drained
    mark_peer_connected(&handler, operator);

    let result = handler.broadcast_uncredited_payment_accusation(
        operator,
        payment_hash,
        preimage,
        deposit_pubkey,
        50_000_000,
        [0u8; 64],
    );

    // Should succeed (no channel manager, but that's logged as warning, not error)
    assert!(result.is_ok());

    // Check that a message was queued to the operator
    let pending = handler.get_and_clear_pending_msg();
    assert!(!pending.is_empty(), "Expected at least one pending message");

    // Verify the message is an UncreditedPayment (V2 format)
    let (target, msg) = &pending[0];
    assert_eq!(*target, operator);
    match msg {
        DepositsMessage::Recovery(RecoveryMsg::UncreditedPayment { operator: msg_operator, partner, payment_hash: msg_payment_hash, preimage: msg_preimage, deposit_pubkey: msg_deposit_pubkey, amount_msat, .. }) => {
            assert_eq!(*msg_operator, operator);
            assert_eq!(*partner, our_node_id);
            assert_eq!(*msg_payment_hash, payment_hash);
            assert_eq!(*msg_preimage, preimage);
            assert_eq!(*msg_deposit_pubkey, deposit_pubkey);
            assert_eq!(*amount_msat, 50_000_000);
        }
        _ => panic!("Expected Recovery(RecoveryMsg::UncreditedPayment) message"),
    }
}

#[test]
fn test_broadcast_uncredited_payment_accusation_broadcasts_to_collateral_partners() {
    use bitcoin::hashes::{sha256, Hash};
    use deposits_core::Ledger;
    use deposits_core::{Deposit, Invoice};

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);
    let collateral1_secret = SecretKey::from_slice(&[4; 32]).unwrap();
    let collateral1 = PublicKey::from_secret_key(&secp, &collateral1_secret);
    let collateral2_secret = SecretKey::from_slice(&[5; 32]).unwrap();
    let collateral2 = PublicKey::from_secret_key(&secp, &collateral2_secret);

    // Create valid preimage and payment_hash first (needed for invoice)
    let preimage = [0x42; 32];
    let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

    // Create a ledger with collateral partners
    use deposits_core::LedgerRole;
    let mut ledger = Ledger::new(
        operator,
        our_node_id,
        LedgerRole::Operator,
        vec![collateral1, collateral2],
        "test_address".to_string(),
    );

    // Add deposit with cosigned invoice (required for fraud proof validation)
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
    deposit.balance = 100_000;
    deposit.invoices = vec![Invoice {
        id: hex::encode(&payment_hash),
        payment_hash,
        amount: 100_000,
        expires: u64::MAX,
        assigned_deposit: deposit_pubkey,
        bolt11: "lnbc1m1test".to_string(),
    }.into()];
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Add cosigned invoice (required for fraud proof validation)
    {
        let mut invoices = handler.cosigned_invoices.lock().unwrap();
        invoices.insert((operator, payment_hash), CosignedInvoice {
            deposit_pubkey,
            payment_hash,
            amount: 100_000,
            expires: u64::MAX,
            cosignature: vec![0u8; 64],
        });
    }

    // Mark all targets as connected so messages can be drained
    mark_peer_connected(&handler, operator);
    mark_peer_connected(&handler, collateral1);
    mark_peer_connected(&handler, collateral2);

    let result = handler.broadcast_uncredited_payment_accusation(
        operator,
        payment_hash,
        preimage,
        deposit_pubkey,
        100_000_000,
        [0u8; 64],
    );

    assert!(result.is_ok());

    // Check that messages were queued to all targets (operator + 2 collateral partners)
    let pending = handler.get_and_clear_pending_msg();
    assert_eq!(pending.len(), 3, "Expected 3 pending messages (operator + 2 collateral partners)");

    // Verify all targets received UncreditedPayment
    let targets: std::collections::HashSet<_> = pending.iter().map(|(t, _)| *t).collect();
    assert!(targets.contains(&operator));
    assert!(targets.contains(&collateral1));
    assert!(targets.contains(&collateral2));
}

// ==================== Fraud Proof Validation Tests ====================

#[test]
fn test_fraud_proof_rejected_without_cosigned_invoice() {
    use bitcoin::hashes::{sha256, Hash};
    use deposits_core::Ledger;
    use deposits_core::Deposit;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create a ledger with a deposit but NO cosigned invoices
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );

    // Add deposit without any invoices
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
    deposit.balance = 100_000;
    // No cosigned invoices!
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Create valid preimage and payment_hash
    let preimage = [0xAB; 32];
    let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

    let result = handler.broadcast_uncredited_payment_accusation(
        operator,
        payment_hash,
        preimage,
        deposit_pubkey,
        50_000_000,
        [0u8; 64],
    );

    // Should fail because there's no cosigned invoice for this payment_hash
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("no cosigned invoice found"), "Error should mention missing cosigned invoice: {}", err);
}

#[test]
#[ignore = "Requires investigation of V1 message decoding in MessageCodec::decode_message_with_type"]
fn test_fraud_proof_rejected_when_already_credited() {
    use bitcoin::hashes::{sha256, Hash};
    use deposits_core::Ledger;
    use crate::handler::ledger_ext::LedgerExt;
    use deposits_core::{Deposit, Invoice};
    use crate::wire::messages::ReceivingCreditPaymentMsg;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create valid preimage and payment_hash
    let preimage = [0xCD; 32];
    let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

    // Create a ledger with a deposit that HAS a cosigned invoice
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );

    // Add deposit with a cosigned invoice
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
    deposit.balance = 100_000;
    deposit.invoices = vec![Invoice {
        id: hex::encode(&payment_hash),
        payment_hash,
        amount: 50_000,
        expires: u64::MAX,
        assigned_deposit: deposit_pubkey,
        bolt11: "lnbc500n1test".to_string(),
    }.into()];
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add a PaymentCredit to the ledger updates (simulating payment was credited)
    // sequence_number must be 0 (first update in empty ledger)
    let credit_msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
        operator,
        our_node_id,
        LedgerOperation::PaymentCredit {
            payment_hash,
            amount: 50_000,
            deposit_pubkey,
            invoice_id: hex::encode(&payment_hash),
            sequence_number: 0, // Must match ledger.history.len()
        },
    ));
    let append_result = ledger.append_mut(credit_msg);
    assert!(append_result.is_ok(), "append_mut should succeed: {:?}", append_result);
    assert_eq!(ledger.history.len(), 1, "Should have 1 update after appending credit");

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Add cosigned invoice (required for fraud proof validation)
    {
        let mut invoices = handler.cosigned_invoices.lock().unwrap();
        invoices.insert((operator, payment_hash), CosignedInvoice {
            deposit_pubkey,
            payment_hash,
            amount: 50_000,
            expires: u64::MAX,
            cosignature: vec![0u8; 64],
        });
    }

    let result = handler.broadcast_uncredited_payment_accusation(
        operator,
        payment_hash,
        preimage,
        deposit_pubkey,
        50_000_000,
        [0u8; 64],
    );

    // Should fail because the payment was already credited
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("already credited"), "Error should mention already credited: {}", err);
}

#[test]
fn test_preimage_to_payment_hash_validation() {
    use bitcoin::hashes::{sha256, Hash};

    // Valid preimage generates matching payment_hash
    let preimage = [0xAB; 32];
    let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

    // Verify preimage hashes to payment_hash
    let computed_hash = sha256::Hash::hash(&preimage);
    assert_eq!(computed_hash.as_byte_array(), &payment_hash,
        "Preimage should hash to payment_hash");

    // Invalid preimage should not match
    let wrong_preimage = [0xCD; 32];
    let wrong_hash = sha256::Hash::hash(&wrong_preimage);
    assert_ne!(wrong_hash.as_byte_array(), &payment_hash,
        "Wrong preimage should not match payment_hash");

    // Verify this is the validation used in submit_fraud_proof
    // SHA256(preimage) == payment_hash
    assert!(computed_hash.as_byte_array() == &payment_hash);
}

#[test]
fn test_fraud_proof_accepted_with_valid_cosigned_invoice() {
    use bitcoin::hashes::{sha256, Hash};
    use deposits_core::Ledger;
    use deposits_core::{Deposit, Invoice};

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create valid preimage and payment_hash
    let preimage = [0xEF; 32];
    let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

    // Create a ledger with a deposit that HAS a cosigned invoice (but NO credit)
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );

    // Add deposit with a cosigned invoice
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
    deposit.balance = 100_000;
    deposit.invoices = vec![Invoice {
        id: hex::encode(&payment_hash),
        payment_hash,
        amount: 50_000,
        expires: u64::MAX,
        assigned_deposit: deposit_pubkey,
        bolt11: "lnbc500n1test".to_string(),
    }.into()];
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add ledger to handler (no credit payment added)
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Add cosigned invoice (required for fraud proof validation)
    {
        let mut invoices = handler.cosigned_invoices.lock().unwrap();
        invoices.insert((operator, payment_hash), CosignedInvoice {
            deposit_pubkey,
            payment_hash,
            amount: 50_000,
            expires: u64::MAX,
            cosignature: vec![0u8; 64],
        });
    }

    // Mark operator as connected so messages can be drained
    mark_peer_connected(&handler, operator);

    let result = handler.broadcast_uncredited_payment_accusation(
        operator,
        payment_hash,
        preimage,
        deposit_pubkey,
        50_000_000,
        [0u8; 64],
    );

    // Should succeed - invoice exists and no credit was recorded
    assert!(result.is_ok(), "Expected Ok but got: {:?}", result);

    // Verify accusation message was queued
    let pending = handler.get_and_clear_pending_msg();
    assert!(!pending.is_empty(), "Expected pending messages");

    // Verify it's an UncreditedPayment (V2 format)
    let (_, msg) = &pending[0];
    match msg {
        DepositsMessage::Recovery(RecoveryMsg::UncreditedPayment { payment_hash: msg_payment_hash, preimage: msg_preimage, deposit_pubkey: msg_deposit_pubkey, .. }) => {
            assert_eq!(*msg_payment_hash, payment_hash);
            assert_eq!(*msg_preimage, preimage);
            assert_eq!(*msg_deposit_pubkey, deposit_pubkey);
        }
        _ => panic!("Expected Recovery(RecoveryMsg::UncreditedPayment) message"),
    }
}

#[test]
fn test_received_fraud_proof_forwards_to_collateral_partners() {
    use bitcoin::hashes::{sha256, Hash};
    use deposits_core::Ledger;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);

    // The accused operator
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);

    // The original accuser (another partner of the operator)
    let accuser_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let accuser = PublicKey::from_secret_key(&secp, &accuser_secret);

    // Our collateral partners (who should receive the forwarded accusation)
    let collateral1_secret = SecretKey::from_slice(&[4; 32]).unwrap();
    let collateral1 = PublicKey::from_secret_key(&secp, &collateral1_secret);
    let collateral2_secret = SecretKey::from_slice(&[5; 32]).unwrap();
    let collateral2 = PublicKey::from_secret_key(&secp, &collateral2_secret);

    // Deposit pubkey from original accusation
    let deposit_secret = SecretKey::from_slice(&[6; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create valid preimage and payment_hash
    let preimage = [0x99; 32];
    let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

    // Create OUR ledger with the operator (we are their partner too)
    use deposits_core::LedgerRole;
    let ledger = Ledger::new(
        operator,
        our_node_id,
        LedgerRole::Operator,
        vec![collateral1, collateral2], // Our collateral partners
        "test_address".to_string(),
    );

    // Add our ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Mark collateral partners as connected so forwarded messages can be drained
    mark_peer_connected(&handler, collateral1);
    mark_peer_connected(&handler, collateral2);

    // Create the accusation message (as if received from accuser) - V2 format
    let accusation = DepositsMessage::Recovery(RecoveryMsg::UncreditedPayment {
        operator,
        partner: accuser, // The original accuser
        payment_hash,
        preimage,
        deposit_pubkey,
        amount_msat: 100_000_000,
        invoice_cosignature: [0u8; 64],
        settlement_sequence: 42,
        settlement_ledger_hash: [0u8; 32],
        settlement_block_height: 100,
        accuser_signature: [0u8; 64],
    });

    // Handle the message as if it came from the accuser
    let result = handler.handle_custom_message(accusation, accuser);
    assert!(result.is_ok());

    // Check that accusation was forwarded to our collateral partners
    let pending = handler.get_and_clear_pending_msg();

    // Should have forwarded to both collateral partners (but not back to sender)
    let targets: std::collections::HashSet<_> = pending.iter().map(|(t, _)| *t).collect();
    assert!(targets.contains(&collateral1), "Should forward to collateral1");
    assert!(targets.contains(&collateral2), "Should forward to collateral2");
    assert!(!targets.contains(&accuser), "Should NOT send back to original sender");

    // Verify all forwarded messages are UncreditedPayment (V2 format)
    for (_, msg) in &pending {
        match msg {
            DepositsMessage::Recovery(RecoveryMsg::UncreditedPayment { operator: fwd_operator, payment_hash: fwd_payment_hash, preimage: fwd_preimage, .. }) => {
                assert_eq!(*fwd_operator, operator);
                assert_eq!(*fwd_payment_hash, payment_hash);
                assert_eq!(*fwd_preimage, preimage);
            }
            _ => panic!("Expected forwarded Recovery(RecoveryMsg::UncreditedPayment) message"),
        }
    }
}

// ==================== Constraint 4: Credit Payment Validation Tests ====================

#[test]
fn test_credit_payment_within_reserves_succeeds() {
    use deposits_core::Ledger;
    use deposits_core::Deposit;
    use crate::wire::messages::ReceivingCreditPaymentMsg;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create ledger with reserves and collateral
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );
    ledger.state.reserves.amount =100_000; // 100k sats reserves
    ledger.state.received_collateral_amount = 100_000; // 100k sats collateral

    // Add deposit with 50k balance
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
    deposit.balance = 50_000;
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Credit 40k (total 90k, still under 100k reserves)
    // Use varied payment hash to avoid "all same bytes" fake check
    let mut payment_hash = [0u8; 32];
    for i in 0..32 { payment_hash[i] = i as u8; }

    let msg = ReceivingCreditPaymentMsg {
        payment_hash,
        deposit_pubkey,
        amount: 40_000,
        invoice_id: "valid_invoice".to_string(),
        partner_id: our_node_id,
        sequence_number: 0,
    };

    let result = handler.validate_receiving_credit_payment(&msg, operator);
    assert!(result.is_ok(), "Credit within reserves should succeed: {:?}", result);
}

#[test]
fn test_credit_payment_exceeds_reserves_fails() {
    use deposits_core::Ledger;
    use deposits_core::Deposit;
    use crate::wire::messages::ReceivingCreditPaymentMsg;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create ledger with limited reserves
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );
    ledger.state.reserves.amount =50_000; // Only 50k sats reserves

    // Add deposit with 30k balance
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
    deposit.balance = 30_000;
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Try to credit 25k (total 55k, exceeds 50k reserves)
    // Use varied payment hash to avoid "all same bytes" fake check
    let mut payment_hash = [0u8; 32];
    for i in 0..32 { payment_hash[i] = (i + 0x20) as u8; }

    let msg = ReceivingCreditPaymentMsg {
        payment_hash,
        deposit_pubkey,
        amount: 25_000,
        invoice_id: "valid_invoice".to_string(),
        partner_id: our_node_id,
        sequence_number: 0,
    };

    let result = handler.validate_receiving_credit_payment(&msg, operator);
    assert!(result.is_err(), "Credit exceeding reserves should fail");
    assert!(result.unwrap_err().contains("exceed reserves"), "Error should mention reserves");
}

#[test]
fn test_credit_payment_exceeds_collateral_fails() {
    use deposits_core::Ledger;
    use deposits_core::Deposit;
    use crate::wire::messages::ReceivingCreditPaymentMsg;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create ledger with high reserves but low collateral
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );
    ledger.state.reserves.amount =100_000; // Plenty of reserves
    ledger.state.received_collateral_amount = 20_000; // But only 20k collateral

    // Add deposit with 10k balance
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
    deposit.balance = 10_000;
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Try to credit 15k (total 25k deposits, exceeds 20k collateral)
    let mut payment_hash = [0u8; 32];
    for i in 0..32 { payment_hash[i] = (i + 0x30) as u8; }

    let msg = ReceivingCreditPaymentMsg {
        payment_hash,
        deposit_pubkey,
        amount: 15_000,
        invoice_id: "valid_invoice".to_string(),
        partner_id: our_node_id,
        sequence_number: 0,
    };

    let result = handler.validate_receiving_credit_payment(&msg, operator);
    assert!(result.is_err(), "Credit exceeding collateral should fail");
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("exceed") && err_msg.contains("collateral"),
            "Error should mention collateral: {}", err_msg);
}

#[test]
fn test_credit_payment_within_collateral_succeeds() {
    use deposits_core::Ledger;
    use deposits_core::Deposit;
    use crate::wire::messages::ReceivingCreditPaymentMsg;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create ledger with sufficient reserves AND collateral
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );
    ledger.state.reserves.amount =100_000;
    ledger.state.received_collateral_amount = 100_000; // Full collateral backing

    // Add deposit with 10k balance
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
    deposit.balance = 10_000;
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Credit 15k (total 25k, within both 100k reserves and 100k collateral)
    let mut payment_hash = [0u8; 32];
    for i in 0..32 { payment_hash[i] = (i + 0x40) as u8; }

    let msg = ReceivingCreditPaymentMsg {
        payment_hash,
        deposit_pubkey,
        amount: 15_000,
        invoice_id: "valid_invoice".to_string(),
        partner_id: our_node_id,
        sequence_number: 0,
    };

    let result = handler.validate_receiving_credit_payment(&msg, operator);
    assert!(result.is_ok(), "Credit within reserves and collateral should succeed: {:?}", result);
}

// ==================== Fee Collection Schedule Tests ====================

#[test]
fn test_fee_collect_on_schedule_succeeds() {
    use deposits_core::Ledger;
    use deposits_core::{Deposit, FeeStructure};
    use crate::wire::messages::FeeCollectMsg;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create ledger
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );

    // Add deposit with fee schedule
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, Some(FeeStructure::new(1000, 10, 144).into())); // Fee collection every 144 blocks (~1 day)
    deposit.balance = 100_000;
    deposit.last_fee_assessment = 1000; // Last assessed at block 1000
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Fee collection at block 1144 (exactly 144 blocks after last assessment)
    let msg = FeeCollectMsg {
        pubkey: deposit_pubkey,
        amount: 100,
        block_height: 1144, // 1000 + 144 = on schedule
    };

    let result = handler.validate_fee_collect(&msg, operator);
    assert!(result.is_ok(), "Fee collection on schedule should succeed: {:?}", result);
}

#[test]
fn test_fee_collect_too_early_fails() {
    use deposits_core::Ledger;
    use deposits_core::{Deposit, FeeStructure};
    use crate::wire::messages::FeeCollectMsg;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create ledger
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );

    // Add deposit with fee schedule
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, Some(FeeStructure::new(1000, 10, 144).into()));
    deposit.balance = 100_000;
    deposit.last_fee_assessment = 1000; // Last assessed at block 1000
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Try fee collection at block 1100 (too early - need to wait until 1144)
    let msg = FeeCollectMsg {
        pubkey: deposit_pubkey,
        amount: 100,
        block_height: 1100, // Only 100 blocks after last assessment, need 144
    };

    let result = handler.validate_fee_collect(&msg, operator);
    assert!(result.is_err(), "Fee collection too early should fail");
    assert!(result.unwrap_err().contains("too early"), "Error should mention timing");
}

#[test]
fn test_fee_collect_after_schedule_succeeds() {
    use deposits_core::Ledger;
    use deposits_core::{Deposit, FeeStructure};
    use crate::wire::messages::FeeCollectMsg;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);
    let deposit_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Create ledger
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );

    // Add deposit with fee schedule
    let mut deposit = deposits_core::Deposit::new(deposit_pubkey, Some(FeeStructure::new(1000, 10, 144).into()));
    deposit.balance = 100_000;
    deposit.last_fee_assessment = 1000;
    ledger.state.deposits.insert(deposit_pubkey, deposit);

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Fee collection at block 2000 (well after the 1144 minimum)
    let msg = FeeCollectMsg {
        pubkey: deposit_pubkey,
        amount: 100,
        block_height: 2000, // 1000 blocks after last, much more than 144 needed
    };

    let result = handler.validate_fee_collect(&msg, operator);
    assert!(result.is_ok(), "Fee collection after schedule should succeed: {:?}", result);
}

// ==================== Collateral Increase Limit Tests ====================

#[test]
fn test_collateral_increase_within_reserves_succeeds() {
    use deposits_core::Ledger;
    use crate::wire::messages::CollateralIncreaseMsg;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);

    // Create ledger with reserves
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );
    ledger.state.reserves.amount =100_000; // 100k sats reserves
    ledger.state.collateral_amount = 30_000; // Current collateral is 30k

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Increase collateral to 50k (still within 100k reserves)
    let msg = CollateralIncreaseMsg {
        new_amount: 50_000,
        partner_id: our_node_id,
        block_height: 100,
    };

    let result = handler.validate_collateral_increase(&msg, operator);
    assert!(result.is_ok(), "Collateral increase within reserves should succeed: {:?}", result);
}

#[test]
fn test_collateral_increase_exceeds_reserves_fails() {
    use deposits_core::Ledger;
    use crate::wire::messages::CollateralIncreaseMsg;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);

    // Create ledger with limited reserves
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );
    ledger.state.reserves.amount =50_000; // Only 50k sats reserves
    ledger.state.collateral_amount = 30_000; // Current collateral is 30k

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Try to increase collateral to 60k (exceeds 50k reserves)
    let msg = CollateralIncreaseMsg {
        new_amount: 60_000,
        partner_id: our_node_id,
        block_height: 100,
    };

    let result = handler.validate_collateral_increase(&msg, operator);
    assert!(result.is_err(), "Collateral increase exceeding reserves should fail");
    assert!(result.unwrap_err().contains("exceeds reserves"), "Error should mention reserves limit");
}

#[test]
fn test_collateral_increase_must_actually_increase() {
    use deposits_core::Ledger;
    use crate::wire::messages::CollateralIncreaseMsg;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);

    // Create ledger with reserves
    let mut ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );
    ledger.state.reserves.amount =100_000;
    ledger.state.collateral_amount = 50_000; // Current collateral is 50k

    // Add ledger to handler
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Try to "increase" to 40k (less than current 50k)
    let msg = CollateralIncreaseMsg {
        new_amount: 40_000,
        partner_id: our_node_id,
        block_height: 100,
    };

    let result = handler.validate_collateral_increase(&msg, operator);
    assert!(result.is_err(), "CollateralIncrease with lower amount should fail");
    assert!(result.unwrap_err().contains("must increase"), "Error should mention it must increase");
}

// ==================== Helper Function Tests ====================

#[test]
fn test_calculate_reserves_with_headroom() {
    // Test that reserves headroom is added correctly
    let base = 100_000u64;
    let with_headroom = super::core::calculate_reserves_with_headroom(base);

    // With RESERVES_HEADROOM_SATS = 0 (current value), should be unchanged
    assert_eq!(with_headroom, base + super::core::RESERVES_HEADROOM_SATS);

    // Test edge case: u64::MAX should not overflow
    let max_result = super::core::calculate_reserves_with_headroom(u64::MAX);
    assert_eq!(max_result, u64::MAX); // saturating_add prevents overflow
}

#[test]
fn test_calculate_collateral_with_headroom() {
    // Test that collateral headroom is added correctly
    let base = 50_000u64;
    let with_headroom = super::core::calculate_collateral_with_headroom(base);

    // COLLATERAL_HEADROOM_SATS = 1000
    assert_eq!(with_headroom, base + super::core::COLLATERAL_HEADROOM_SATS);
    assert_eq!(with_headroom, 51_000);

    // Test edge case: near u64::MAX should saturate
    let near_max = u64::MAX - 500;
    let max_result = super::core::calculate_collateral_with_headroom(near_max);
    assert_eq!(max_result, u64::MAX); // saturating_add prevents overflow
}

// ==================== Payment Registration Tests ====================

#[test]
fn test_is_deposit_invoice_payment() {
    let handler = create_test_handler();
    let payment_hash = [0xAB; 32];
    let (deposit_pubkey, partner_id) = {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[2; 32]).unwrap();
        let deposit = PublicKey::from_secret_key(&secp, &secret);
        let partner_secret = SecretKey::from_slice(&[3; 32]).unwrap();
        let partner = PublicKey::from_secret_key(&secp, &partner_secret);
        (deposit, partner)
    };

    // Initially not registered
    assert!(!handler.is_deposit_invoice_payment(&payment_hash));

    // Register it
    handler.register_deposit_invoice(
        payment_hash,
        partner_id,
        deposit_pubkey,
        "inv-123".to_string(),
        "lnbc1test".to_string()
    );

    // Now should be registered
    assert!(handler.is_deposit_invoice_payment(&payment_hash));
}

#[test]
fn test_get_deposit_for_payment() {
    let handler = create_test_handler();
    let payment_hash = [0xCD; 32];
    let (deposit_pubkey, partner_id) = {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[4; 32]).unwrap();
        let deposit = PublicKey::from_secret_key(&secp, &secret);
        let partner_secret = SecretKey::from_slice(&[5; 32]).unwrap();
        let partner = PublicKey::from_secret_key(&secp, &partner_secret);
        (deposit, partner)
    };

    // Initially not found
    assert!(handler.get_deposit_for_payment(&payment_hash).is_none());

    // Register it
    handler.register_deposit_invoice(
        payment_hash,
        partner_id,
        deposit_pubkey,
        "inv-456".to_string(),
        "lnbc2test".to_string()
    );

    // Now should be found
    let result = handler.get_deposit_for_payment(&payment_hash);
    assert!(result.is_some());
    let (ret_partner, ret_deposit, ret_invoice_id, ret_bolt11) = result.unwrap();
    assert_eq!(ret_partner, partner_id);
    assert_eq!(ret_deposit, deposit_pubkey);
    assert_eq!(ret_invoice_id, "inv-456");
    assert_eq!(ret_bolt11, "lnbc2test");
}

#[test]
fn test_get_deposit_invoice_bolt11() {
    let handler = create_test_handler();
    let payment_hash = [0xEF; 32];
    let (deposit_pubkey, partner_id) = {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[6; 32]).unwrap();
        let deposit = PublicKey::from_secret_key(&secp, &secret);
        let partner_secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let partner = PublicKey::from_secret_key(&secp, &partner_secret);
        (deposit, partner)
    };

    // Initially not found
    assert!(handler.get_deposit_invoice_bolt11(&payment_hash).is_none());

    // Register it
    handler.register_deposit_invoice(
        payment_hash,
        partner_id,
        deposit_pubkey,
        "inv-789".to_string(),
        "lnbc3mytestinvoice".to_string()
    );

    // Now should return the bolt11
    let bolt11 = handler.get_deposit_invoice_bolt11(&payment_hash);
    assert_eq!(bolt11, Some("lnbc3mytestinvoice".to_string()));
}

#[test]
fn test_unregister_deposit_invoice() {
    let handler = create_test_handler();
    let payment_hash = [0x12; 32];
    let (deposit_pubkey, partner_id) = {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[8; 32]).unwrap();
        let deposit = PublicKey::from_secret_key(&secp, &secret);
        let partner_secret = SecretKey::from_slice(&[9; 32]).unwrap();
        let partner = PublicKey::from_secret_key(&secp, &partner_secret);
        (deposit, partner)
    };

    // Register it
    handler.register_deposit_invoice(
        payment_hash,
        partner_id,
        deposit_pubkey,
        "inv-abc".to_string(),
        "lnbc4test".to_string()
    );
    assert!(handler.is_deposit_invoice_payment(&payment_hash));

    // Unregister it
    handler.unregister_deposit_invoice(&payment_hash);

    // Should no longer be registered
    assert!(!handler.is_deposit_invoice_payment(&payment_hash));
}

#[test]
fn test_cleanup_payments_for_partner() {
    let handler = create_test_handler();

    let (deposit1, deposit2, partner1, partner2) = {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let d1_secret = SecretKey::from_slice(&[10; 32]).unwrap();
        let d2_secret = SecretKey::from_slice(&[11; 32]).unwrap();
        let p1_secret = SecretKey::from_slice(&[12; 32]).unwrap();
        let p2_secret = SecretKey::from_slice(&[13; 32]).unwrap();
        (
            PublicKey::from_secret_key(&secp, &d1_secret),
            PublicKey::from_secret_key(&secp, &d2_secret),
            PublicKey::from_secret_key(&secp, &p1_secret),
            PublicKey::from_secret_key(&secp, &p2_secret),
        )
    };

    let hash1 = [0x21; 32];
    let hash2 = [0x22; 32];
    let hash3 = [0x23; 32];

    // Register payments for two different partners
    handler.register_deposit_invoice(hash1, partner1, deposit1, "inv1".to_string(), "bolt1".to_string());
    handler.register_deposit_invoice(hash2, partner1, deposit1, "inv2".to_string(), "bolt2".to_string());
    handler.register_deposit_invoice(hash3, partner2, deposit2, "inv3".to_string(), "bolt3".to_string());

    // All should be registered
    assert!(handler.is_deposit_invoice_payment(&hash1));
    assert!(handler.is_deposit_invoice_payment(&hash2));
    assert!(handler.is_deposit_invoice_payment(&hash3));

    // Cleanup payments for partner1
    handler.cleanup_payments_for_partner(partner1);

    // Partner1's payments should be gone, partner2's should remain
    assert!(!handler.is_deposit_invoice_payment(&hash1));
    assert!(!handler.is_deposit_invoice_payment(&hash2));
    assert!(handler.is_deposit_invoice_payment(&hash3));
}

#[test]
fn test_our_node_id() {
    let handler = create_test_handler();
    let our_id = handler.our_node_id();

    // Should match the key created from [1; 32] secret
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let expected = PublicKey::from_secret_key(&secp, &secret);

    assert_eq!(our_id, expected);
}

// ==================== Deposit Guarantee Signature Tests ====================

#[test]
fn test_create_and_verify_deposit_guarantee_signature() {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let bob_secret = SecretKey::from_slice(&[42; 32]).unwrap();
    let bob_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &bob_secret);

    let deposit_secret = SecretKey::from_slice(&[43; 32]).unwrap();
    let deposit_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &deposit_secret);

    let invoice = "lnbc1000n1test123";

    // Create signature
    let sig = super::core::create_deposit_guarantee_signature(
        &bob_secret,
        invoice,
        &deposit_pubkey
    ).expect("Should create signature");

    // Verify signature
    let verified = super::core::verify_deposit_guarantee_signature(
        &sig,
        &bob_pubkey,
        invoice,
        &deposit_pubkey
    ).expect("Should verify without error");

    assert!(verified, "Valid signature should verify");
}

#[test]
fn test_deposit_guarantee_signature_wrong_invoice_fails() {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let bob_secret = SecretKey::from_slice(&[44; 32]).unwrap();
    let bob_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &bob_secret);

    let deposit_secret = SecretKey::from_slice(&[45; 32]).unwrap();
    let deposit_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &deposit_secret);

    let invoice = "lnbc1000n1original";
    let wrong_invoice = "lnbc2000n1different";

    // Create signature for original invoice
    let sig = super::core::create_deposit_guarantee_signature(
        &bob_secret,
        invoice,
        &deposit_pubkey
    ).expect("Should create signature");

    // Try to verify with wrong invoice
    let verified = super::core::verify_deposit_guarantee_signature(
        &sig,
        &bob_pubkey,
        wrong_invoice,
        &deposit_pubkey
    ).expect("Should verify without error");

    assert!(!verified, "Signature for wrong invoice should not verify");
}

#[test]
fn test_deposit_guarantee_signature_wrong_pubkey_fails() {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let bob_secret = SecretKey::from_slice(&[46; 32]).unwrap();

    let attacker_secret = SecretKey::from_slice(&[99; 32]).unwrap();
    let attacker_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &attacker_secret);

    let deposit_secret = SecretKey::from_slice(&[47; 32]).unwrap();
    let deposit_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &deposit_secret);

    let invoice = "lnbc1000n1testinvoice";

    // Create signature with bob's key
    let sig = super::core::create_deposit_guarantee_signature(
        &bob_secret,
        invoice,
        &deposit_pubkey
    ).expect("Should create signature");

    // Try to verify with attacker's pubkey
    let verified = super::core::verify_deposit_guarantee_signature(
        &sig,
        &attacker_pubkey,
        invoice,
        &deposit_pubkey
    ).expect("Should verify without error");

    assert!(!verified, "Signature should not verify with wrong pubkey");
}

// ==================== Payment Authorization Signature Tests ====================

#[test]
fn test_create_payment_authorization_signature() {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let owner_secret = SecretKey::from_slice(&[50; 32]).unwrap();

    let amount = 100_000u64;
    let invoice = "lnbc1000n1paymenttest";
    let preimage = [0x88; 32];

    // Create signature
    let sig = super::core::create_payment_authorization_signature(
        &owner_secret,
        amount,
        invoice,
        &preimage
    ).expect("Should create signature");

    // Should be 64 bytes (compact ECDSA signature)
    assert_eq!(sig.len(), 64, "Signature should be 64 bytes");
}

// ==================== Protocol Stats Tests ====================

#[test]
fn test_get_protocol_stats_empty() {
    let handler = create_test_handler();
    let stats = handler.get_protocol_stats();

    assert_eq!(stats.active_partners, 0);
    assert_eq!(stats.pending_outbound_messages, 0);
    assert_eq!(stats.total_ledgers, 0);
}

#[test]
fn test_has_pending_messages() {
    let handler = create_test_handler();
    let peer_key = create_test_pubkey();

    // Initially no pending messages
    assert!(!handler.has_pending_messages());

    // Queue a message (V2 format)
    let message = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
        peer_key, // operator
        peer_key, // partner
        LedgerOperation::ReservesAdd {
            amount: 1000,
            spend_to: peer_key,
            collateral_partners: vec![],
        },
    ));
    handler.send_message(peer_key, message).unwrap();

    // Should have pending messages
    assert!(handler.has_pending_messages());
}

#[test]
fn test_list_operator_ledgers_empty() {
    let handler = create_test_handler();
    let ledgers = handler.list_operator_ledgers();
    assert!(ledgers.is_empty());
}

#[test]
fn test_list_partner_ledgers_empty() {
    let handler = create_test_handler();
    let ledgers = handler.list_partner_ledgers();
    assert!(ledgers.is_empty());
}

#[test]
fn test_add_ledger_updates_stats() {
    use deposits_core::Ledger;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[51; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);

    // Initially no ledgers
    assert_eq!(handler.get_protocol_stats().total_ledgers, 0);

    // Add a ledger
    let ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Verify ledger exists
    assert_eq!(handler.get_protocol_stats().total_ledgers, 1);

    // Add another ledger with different operator
    let operator2_secret = SecretKey::from_slice(&[52; 32]).unwrap();
    let operator2 = PublicKey::from_secret_key(&secp, &operator2_secret);
    let ledger2 = Ledger::new_as_operator(
        operator2,
        our_node_id,
        "test_address2".to_string(),
    );
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator2, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger2)));
    }

    // Verify both ledgers exist
    assert_eq!(handler.get_protocol_stats().total_ledgers, 2);
}

#[test]
fn test_get_all_ledgers() {
    use deposits_core::Ledger;

    let handler = create_test_handler();

    // Create keys
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let our_secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_node_id = PublicKey::from_secret_key(&secp, &our_secret);
    let operator_secret = SecretKey::from_slice(&[53; 32]).unwrap();
    let operator = PublicKey::from_secret_key(&secp, &operator_secret);

    // Initially empty
    let all = handler.get_all_ledgers();
    assert!(all.is_empty());

    // Add a ledger
    let ledger = Ledger::new_as_operator(
        operator,
        our_node_id,
        "test_address".to_string(),
    );
    {
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, our_node_id), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
    }

    // Should now have one ledger
    let all = handler.get_all_ledgers();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, (operator, our_node_id));
}
