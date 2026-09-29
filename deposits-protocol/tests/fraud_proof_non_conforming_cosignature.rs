//! `verify_non_conforming_cosignature` and `find_non_conforming_cosignature`
//! on a quorum ledger built from real operations with real signatures.
//!
//! The verifier used to run conformance with `DenyAll`, which refuses every
//! withdrawal's witness, so an honest cosigned withdrawal "proved" that its
//! operator and cosigners colluded. It now runs with the caller's authorizer
//! (`AllowAll` here; a node passes the dep-16 descriptor verifier), replays
//! the prefix the fault's signatures fix, and checks the accused's own
//! cosignature.

use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use deposits_protocol::fraud::{
    find_non_conforming_cosignature, verify_non_conforming_cosignature, FraudEvidence,
    FraudProof, FraudProofType,
};
use deposits_protocol::messages::{LedgerOperation, QuorumMemberRef};
use deposits_protocol::tlv::TlvEncode;
// This crate has no descriptor evaluator, so these verifier calls pass
// `AllowAll`: witnesses are not judged here. Nodes pass deposits-core's
// `Dep16Authorizer`; the witness cases are tested in
// deposits-core/tests/fraud_proof_witness.rs.
use deposits_protocol::types::{
    AllowAll, ConformanceViolation, CosignEntry, DenyAll, DescriptorWitness, LedgerState,
    SignedLedgerUpdate,
};
use sha2::{Digest, Sha256};

const OP: u8 = 7;
const MEMBER: u8 = 2;
const RESERVES: u64 = 20_000_000_000;
const COLLATERAL: u64 = 30_000_000_000;
const DEPOSIT: [u8; 16] = [0xAB; 16];

fn keypair(seed: u8) -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[seed; 32]).unwrap())
}

fn pubkey(seed: u8) -> PublicKey {
    keypair(seed).public_key()
}

fn ledger() -> [u8; 32] {
    LedgerState::compute_ledger_id(&pubkey(OP), "bcrt1qreserves", 0)
}

/// An update at `seq` on `prev`, cosigned by `cosigners` (each with a valid
/// v1 cosignature) and then operator-signed, as the daemon does.
fn update(seq: u64, prev: [u8; 32], op: &LedgerOperation, cosigners: &[u8]) -> SignedLedgerUpdate {
    let secp = Secp256k1::new();
    let mut u = SignedLedgerUpdate {
        message: op.tlv_encode(),
        message_type: 1,
        operator_id: pubkey(OP),
        ledger_id: ledger(),
        sequence_number: seq,
        previous_hash: prev,
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        operator_signature: [0u8; 64],
        cosignatures: Vec::new(),
    };
    for &c in cosigners {
        let mlh = [c; 32];
        let digest = u.cosign_digest(&mlh);
        u.cosignatures.push(CosignEntry {
            cosigner_pubkey: pubkey(c),
            cosign_signature: secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(c))
                .serialize(),
            member_ledger_hash: mlh,
        });
    }
    u.content_hash = u.compute_hash();
    let digest = u.operator_digest();
    u.operator_signature = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(OP))
        .serialize();
    u
}

fn credit(n: u8, amount: u64) -> LedgerOperation {
    LedgerOperation::OnchainCredit {
        txid: [n; 32],
        vout: 0,
        deposit_id: DEPOSIT,
        amount,
        funding_address: "bcrt1qfund".to_string(),
        commitment: None,
    }
}

fn withdrawal(amount: u64) -> LedgerOperation {
    LedgerOperation::OnchainLock {
        deposit_id: DEPOSIT,
        amount,
        fee_sats: 0,
        destination_address: "bcrt1qdest".to_string(),
        withdrawal_id: [5; 32],
        nonce: 1,
        expiry: 1_000,
        witness: DescriptorWitness {
            stack: vec![vec![0x30; 64]],
        },
        commitment: None,
    }
}

/// seq 0 LedgerOpen, 1 QuorumBegin (member `MEMBER`), 2 DepositOpen, 3 a
/// 480,000,000 credit, cosigned from the QuorumBegin on.
fn prefix() -> Vec<SignedLedgerUpdate> {
    let ops = vec![
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
            quorum_members: vec![QuorumMemberRef::pubkey_only(pubkey(MEMBER))],
            collateral_amount: COLLATERAL,
            protocol_version: None,
        },
        LedgerOperation::DepositOpen {
            deposit_id: DEPOSIT,
            descriptor: "wpkh(deadbeef)".to_string(),
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
        credit(1, 480_000_000),
    ];
    let mut chain: Vec<SignedLedgerUpdate> = Vec::new();
    for (seq, op) in ops.iter().enumerate() {
        let prev = chain.last().map(|u| u.chain_hash()).unwrap_or([0u8; 32]);
        let cosigners: &[u8] = if seq >= 2 { &[MEMBER] } else { &[] };
        chain.push(update(seq as u64, prev, op, cosigners));
    }
    chain
}

fn next(history: &[SignedLedgerUpdate], op: &LedgerOperation) -> SignedLedgerUpdate {
    let tip = history.last().unwrap();
    update(tip.sequence_number + 1, tip.chain_hash(), op, &[MEMBER])
}

fn proof(fault: &SignedLedgerUpdate, accused: PublicKey) -> FraudProof {
    FraudProof {
        proof_type: FraudProofType::NonConformingCosignature,
        accused: hex::encode(accused.serialize()),
        ledger_id: hex::encode([0x99; 32]), // the accused's own ledger
        evidence: FraudEvidence::NonConformingCosignature {
            fault_ledger_id: hex::encode(fault.ledger_id),
            fault_sequence: fault.sequence_number,
            governing_quorumbegin_seq: 1,
            fault_update_hex: hex::encode(fault.tlv_encode()),
        },
    }
}

fn state_before(history: &[SignedLedgerUpdate]) -> LedgerState {
    let mut state = LedgerState::new(pubkey(OP), "bcrt1qreserves".into(), 0);
    for u in history {
        state.apply_update_in_place(u).unwrap();
    }
    state
}

#[test]
fn an_honest_cosigned_withdrawal_is_not_proof() {
    let history = prefix();
    let honest = next(&history, &withdrawal(1_000_000));

    // What the old verifier saw: DenyAll refuses the withdrawal's witness.
    let op = deposits_protocol::tlv::TlvDecode::tlv_decode(&honest.message).unwrap();
    let (_, violations) = state_before(&history)
        .apply_with_verifier(&op, &DenyAll, 0)
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, ConformanceViolation::InvalidWitness { .. })),
        "{:?}",
        violations
    );

    for accused in [pubkey(OP), pubkey(MEMBER)] {
        let err = verify_non_conforming_cosignature(&proof(&honest, accused), &history, &AllowAll)
            .unwrap_err();
        assert!(err.contains("applies cleanly"), "{}", err);
    }
    let mut with_it = history.clone();
    with_it.push(honest);
    assert_eq!(find_non_conforming_cosignature(&with_it, &pubkey(OP), &AllowAll), None);
}

#[test]
fn a_genuine_non_conforming_cosignature_is_proof() {
    let history = prefix();
    // Cosigned credit past reserves and collateral, and a zero-amount lock.
    for op in [credit(2, 40_000_000_000), withdrawal(0)] {
        let fault = next(&history, &op);
        for accused in [pubkey(OP), pubkey(MEMBER)] {
            verify_non_conforming_cosignature(&proof(&fault, accused), &history, &AllowAll).unwrap();
        }
        let mut with_it = history.clone();
        with_it.push(fault);
        let (seq, qb, _) = find_non_conforming_cosignature(&with_it, &pubkey(OP), &AllowAll).unwrap();
        assert_eq!((seq, qb), (4, 1));
    }
}

#[test]
fn a_cosigner_listed_without_their_signature_is_not_accused() {
    let history = prefix();
    let mut fault = next(&history, &credit(2, 40_000_000_000));
    // The operator lists the member with a signature that isn't theirs and
    // re-signs: the update is the operator's claim, not the member's act.
    fault.cosignatures[0].cosign_signature = [0x42; 64];
    fault.content_hash = fault.compute_hash();
    let digest = fault.operator_digest();
    fault.operator_signature = Secp256k1::new()
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(OP))
        .serialize();
    assert!(verify_non_conforming_cosignature(&proof(&fault, pubkey(MEMBER)), &history, &AllowAll).is_err());
    // The operator did sign it.
    verify_non_conforming_cosignature(&proof(&fault, pubkey(OP)), &history, &AllowAll).unwrap();
}

#[test]
fn a_fault_that_links_to_nothing_is_not_judged() {
    let history = prefix();
    let mut fault = update(4, [0xEE; 32], &credit(2, 40_000_000_000), &[MEMBER]);
    fault.block_height = 0;
    let err = verify_non_conforming_cosignature(&proof(&fault, pubkey(OP)), &history, &AllowAll).unwrap_err();
    assert!(err.contains("links to no update"), "{}", err);
}

#[test]
fn a_rewritten_block_height_is_not_proof() {
    let history = prefix();
    let mut honest = next(&history, &withdrawal(1_000_000));
    honest.verify_operator_signature().unwrap();
    // Past the lock's expiry. block_height is signed (DEP-02 v2), so the
    // re-dated copy carries no valid operator signature or cosignature.
    honest.block_height = 50_000;
    assert!(honest.verify_operator_signature().is_err());
    assert!(honest.verify_cosign_signatures(&[pubkey(MEMBER)], 1).is_err());
    assert!(verify_non_conforming_cosignature(&proof(&honest, pubkey(OP)), &history, &AllowAll).is_err());
}
