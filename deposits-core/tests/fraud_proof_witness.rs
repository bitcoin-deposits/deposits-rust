//! `NonConformingUpdate` proofs judged with the dep-16 descriptor verifier
//! (`Dep16Authorizer`), the one a node passes.
//!
//! On the devnet a cl operator committed a TransferLock with an empty
//! depositor witness, cosigned blind. The replica that watched it land flagged
//! `InvalidWitness`; but the proof, re-broadcast later, was rejected by every
//! reference node ("applies cleanly with no conformance violations"), because
//! the verifier ran conformance with `AllowAll`. Here the proof verifies, and
//! the same lock with a correct witness does not: the real verifier must not
//! condemn honest spends (the reason `DenyAll` was rejected).
//!
//! Also: under v2 signing the heights are signed, so a lock signed past its
//! expiry, or replaying a nonce, is proof.

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use deposits_core::dep16::{operations, Dep16Authorizer, EcdsaVerifier, Verifier};
use deposits_protocol::fraud::{
    find_non_conforming_update, verify_non_conforming_update, FraudEvidence, FraudProof,
    FraudProofType,
};
use deposits_protocol::messages::{LedgerOperation, QuorumMemberRef};
use deposits_protocol::tlv::TlvEncode;
use deposits_protocol::types::{AllowAll, DescriptorWitness, LedgerState, SignedLedgerUpdate};

const OP: u8 = 7;
const DEPOSITOR: u8 = 0x11;
const RESERVES: u64 = 20_000_000_000;
const COLLATERAL: u64 = 30_000_000_000;
const BALANCE: u64 = 480_000_000;
const DEPOSIT: [u8; 16] = [0xAB; 16];
const HEIGHT: u32 = 1_000;

fn pubkey(seed: u8) -> bitcoin::secp256k1::PublicKey {
    let secp = Secp256k1::new();
    Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap()).public_key()
}

fn ledger() -> [u8; 32] {
    LedgerState::compute_ledger_id(&pubkey(OP), "bcrt1qreserves", 0)
}

fn signed_update(
    seq: u64,
    prev: [u8; 32],
    op: &LedgerOperation,
    block_height: u32,
) -> SignedLedgerUpdate {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[OP; 32]).unwrap());
    let mut u = SignedLedgerUpdate {
        message: op.tlv_encode(),
        message_type: op.message_type(),
        operator_id: kp.public_key(),
        ledger_id: ledger(),
        sequence_number: seq,
        previous_hash: prev,
        content_hash: [0u8; 32],
        block_height,
        block_hash: [0u8; 32],
        operator_signature: [0u8; 64],
        cosignatures: Vec::new(),
    };
    u.content_hash = u.compute_hash();
    u.operator_signature = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(u.operator_digest()), &kp)
        .serialize();
    u
}

/// seq 0 LedgerOpen, 1 QuorumBegin, 2 DepositOpen whose descriptor is the
/// depositor's key, 3 a credit to it.
fn prefix() -> Vec<SignedLedgerUpdate> {
    let depositor = bitcoin::PublicKey::new(pubkey(DEPOSITOR));
    let ops = [
        LedgerOperation::LedgerOpen {
            operator_id: pubkey(OP),
            reserves_id: "bcrt1qreserves".to_string(),
            genesis_block: 0,
            reserves_amount: RESERVES,
            collateral_amount: COLLATERAL,
        },
        LedgerOperation::QuorumBegin {
            reserves_id: "bcrt1qreserves".to_string(),
            spending_txid: [0; 32],
            new_outpoint_txid: [1; 32],
            new_outpoint_vout: 0,
            amount: RESERVES,
            quorum_expiry: 1_000_000,
            ledger_hash: [0; 32],
            quorum_members: vec![QuorumMemberRef::pubkey_only(pubkey(2))],
            collateral_amount: COLLATERAL,
            protocol_version: Some("cltv-offset-v2".to_string()),
        },
        LedgerOperation::DepositOpen {
            deposit_id: DEPOSIT,
            descriptor: format!("wsh(prove(pk({})))", depositor),
            fees: None,
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
            commitment: None,
        },
        LedgerOperation::OnchainCredit {
            txid: [1; 32],
            vout: 0,
            deposit_id: DEPOSIT,
            amount: BALANCE,
            funding_address: "bcrt1qfund".to_string(),
            commitment: None,
        },
    ];
    let mut chain: Vec<SignedLedgerUpdate> = Vec::new();
    for (seq, op) in ops.iter().enumerate() {
        let prev = chain.last().map(|u| u.chain_hash()).unwrap_or([0u8; 32]);
        chain.push(signed_update(seq as u64, prev, op, HEIGHT));
    }
    chain
}

/// A TransferLock out of the deposit carrying `witness`.
fn lock(nonce: u64, expiry: u32, transfer: u8, witness: DescriptorWitness) -> LedgerOperation {
    LedgerOperation::TransferLock {
        transfer_nonce: [transfer; 32],
        source_deposit_id: DEPOSIT,
        destination_deposit_id: [0xCD; 16],
        amount: 1_000_000,
        fee: 0,
        completion_script: format!("wsh(prove(pk({})))", bitcoin::PublicKey::new(pubkey(3))),
        timeout_height: HEIGHT + 144,
        transfer_id: [transfer; 32],
        nonce,
        expiry,
        witness,
        commitment: None,
    }
}

/// The lock with an empty depositor witness.
fn unsigned_lock(nonce: u64, expiry: u32, transfer: u8) -> LedgerOperation {
    lock(nonce, expiry, transfer, DescriptorWitness::new())
}

/// The lock with the depositor's signature over its dep-17 operation
/// preimage, as a wallet builds it.
fn signed_lock(nonce: u64, expiry: u32, transfer: u8) -> LedgerOperation {
    let preimage = miniscript::calculus::operation_preimage(
        &operations::to_dep16(&unsigned_lock(nonce, expiry, transfer))
            .expect("descriptor-evaluated variant"),
    );
    let sk = SecretKey::from_slice(&[DEPOSITOR; 32]).unwrap();
    let sig = EcdsaVerifier::new().sign(&sk, &preimage);
    lock(
        nonce,
        expiry,
        transfer,
        DescriptorWitness { stack: vec![sig.0] },
    )
}

fn proof_for(update: &SignedLedgerUpdate) -> FraudProof {
    FraudProof {
        proof_type: FraudProofType::NonConformingUpdate,
        accused: hex::encode(update.operator_id.serialize()),
        ledger_id: hex::encode(update.ledger_id),
        evidence: FraudEvidence::NonConformingUpdate {
            fault_sequence: update.sequence_number,
            fault_update_hex: hex::encode(update.tlv_encode()),
        },
    }
}

/// What conformance reports for `update` on the state `chain` replays to,
/// with the dep-16 verifier, at the update's own height.
fn violations_at(
    chain: &[SignedLedgerUpdate],
    update: &SignedLedgerUpdate,
) -> Vec<deposits_protocol::types::ConformanceViolation> {
    use deposits_protocol::tlv::TlvDecode;
    let mut state = LedgerState::new(pubkey(OP), "bcrt1qreserves".to_string(), 0);
    for u in chain {
        state.apply_update_in_place(u).unwrap();
    }
    let op = LedgerOperation::tlv_decode(&update.message).unwrap();
    state
        .apply_with_verifier(&op, &Dep16Authorizer::new(), update.block_height)
        .unwrap()
        .1
}

#[test]
fn a_correctly_witnessed_transfer_lock_is_not_proof() {
    let prefix = prefix();
    let honest = signed_update(
        4,
        prefix[3].chain_hash(),
        &signed_lock(1, HEIGHT + 10, 1),
        HEIGHT,
    );
    assert_eq!(violations_at(&prefix, &honest), vec![]);
    let err = verify_non_conforming_update(&proof_for(&honest), &prefix, &Dep16Authorizer::new())
        .unwrap_err();
    assert!(err.contains("applies cleanly"), "wrong error: {}", err);

    let mut history = prefix.clone();
    history.push(honest);
    assert_eq!(
        find_non_conforming_update(&history, &pubkey(OP), &Dep16Authorizer::new()),
        None
    );
}

#[test]
fn the_same_lock_with_an_empty_witness_is_proof() {
    let prefix = prefix();
    let forged = signed_update(
        4,
        prefix[3].chain_hash(),
        &unsigned_lock(1, HEIGHT + 10, 1),
        HEIGHT,
    );
    let v = violations_at(&prefix, &forged);
    assert!(
        matches!(
            v[..],
            [deposits_protocol::types::ConformanceViolation::InvalidWitness { .. }]
        ),
        "{:?}",
        v
    );
    verify_non_conforming_update(&proof_for(&forged), &prefix, &Dep16Authorizer::new())
        .expect("a lock with no depositor witness is a forged spend");

    // Found by the resolver's scan too, from the history alone.
    let mut history = prefix.clone();
    history.push(forged.clone());
    let (seq, reason) =
        find_non_conforming_update(&history, &pubkey(OP), &Dep16Authorizer::new()).unwrap();
    assert_eq!(seq, 4);
    assert!(reason.contains("InvalidWitness"), "reason: {}", reason);

    // Without a descriptor evaluator it was unprovable: the devnet rejection.
    let err = verify_non_conforming_update(&proof_for(&forged), &prefix, &AllowAll).unwrap_err();
    assert!(err.contains("applies cleanly"), "wrong error: {}", err);
}

/// The lock's expiry is below the update's own block_height, which the
/// operator signed (DEP-02 v2): it committed a spend past its window.
#[test]
fn an_expired_lock_is_proof() {
    let prefix = prefix();
    let expired = signed_update(
        4,
        prefix[3].chain_hash(),
        &signed_lock(1, HEIGHT - 1, 1),
        HEIGHT,
    );
    // Its only defect: the witness is the depositor's.
    let v = violations_at(&prefix, &expired);
    assert!(
        matches!(
            v[..],
            [deposits_protocol::types::ConformanceViolation::ExpiryPassed { .. }]
        ),
        "{:?}",
        v
    );
    verify_non_conforming_update(&proof_for(&expired), &prefix, &Dep16Authorizer::new())
        .expect("a lock signed past its expiry is non-conforming");
}

/// A second lock reusing a nonce the deposit already accepted, inside its
/// window: a replayed authorization.
#[test]
fn a_nonce_replayed_lock_is_proof() {
    let mut chain = prefix();
    let first = signed_update(
        4,
        chain[3].chain_hash(),
        &signed_lock(1, HEIGHT + 10, 1),
        HEIGHT,
    );
    chain.push(first);
    // Its own transfer, correctly signed, but nonce 1 again.
    let replay = signed_update(
        5,
        chain[4].chain_hash(),
        &signed_lock(1, HEIGHT + 10, 2),
        HEIGHT,
    );
    let v = violations_at(&chain, &replay);
    assert!(
        matches!(
            v[..],
            [deposits_protocol::types::ConformanceViolation::NonceReplay { .. }]
        ),
        "{:?}",
        v
    );
    verify_non_conforming_update(&proof_for(&replay), &chain, &Dep16Authorizer::new())
        .expect("a replayed nonce is non-conforming");

    // A fresh nonce at the same place is fine.
    let fresh = signed_update(
        5,
        chain[4].chain_hash(),
        &signed_lock(2, HEIGHT + 10, 2),
        HEIGHT,
    );
    assert_eq!(violations_at(&chain, &fresh), vec![]);
    assert!(
        verify_non_conforming_update(&proof_for(&fresh), &chain, &Dep16Authorizer::new()).is_err()
    );
}
