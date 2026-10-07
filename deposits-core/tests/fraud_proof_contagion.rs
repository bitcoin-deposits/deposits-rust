//! Contagion (DEP-19 §5–6): everyone who signed a non-conforming update, its
//! operator and each cosigner, is slashable on every other ledger it
//! operates, by that ledger's own quorum.
//!
//! The producer (`contagion_proofs`) builds one `NonConformingCosignature` per
//! (signer, other ledger it operates); here the proofs it builds, and the ones
//! cl-deposits builds, verify through `verify_fraud_broadcast` with the dep-16
//! descriptor verifier a node passes. The fault is the devnet's: a TransferLock
//! with an empty depositor witness, signed by the operator and cosigned blind
//! by two colluders.

use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use deposits_core::dep16::Dep16Authorizer;
use deposits_protocol::fraud::{
    contagion_proofs, governing_quorum_begin_seq, verify_fraud_broadcast, BlockOracle,
    FraudBroadcast, FraudEvidence, FraudProofType, LedgerProvider,
};
use deposits_protocol::messages::{LedgerOperation, QuorumMemberRef};
use deposits_protocol::tlv::TlvEncode;
use deposits_protocol::types::{CosignEntry, DescriptorWitness, LedgerState, SignedLedgerUpdate};

const OP: u8 = 7;
const ACCUSED: u8 = 2;
const COLLUDER: u8 = 3;
const DEPOSITOR: u8 = 0x11;
const RESERVES: u64 = 20_000_000_000;
const COLLATERAL: u64 = 30_000_000_000;
const BALANCE: u64 = 480_000_000;
const DEPOSIT: [u8; 16] = [0xAB; 16];
const HEIGHT: u32 = 1_000;

fn keypair(seed: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[seed; 32]).unwrap(),
    )
}

fn pubkey(seed: u8) -> PublicKey {
    keypair(seed).public_key()
}

fn ledger() -> [u8; 32] {
    LedgerState::compute_ledger_id(&pubkey(OP), "bcrt1qreserves", 0)
}

/// The accused's and the colluder's own ledgers (as their advertisements
/// name them).
fn own_ledger(seed: u8, n: u8) -> String {
    hex::encode([seed ^ n; 32])
}

/// An update at `seq` on `prev`, cosigned by `cosigners`, operator-signed.
fn update(seq: u64, prev: [u8; 32], op: &LedgerOperation, cosigners: &[u8]) -> SignedLedgerUpdate {
    let secp = Secp256k1::new();
    let mut u = SignedLedgerUpdate {
        message: op.tlv_encode(),
        message_type: op.message_type(),
        operator_id: pubkey(OP),
        ledger_id: ledger(),
        sequence_number: seq,
        previous_hash: prev,
        content_hash: [0u8; 32],
        block_height: HEIGHT,
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
    u.operator_signature = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(u.operator_digest()), &keypair(OP))
        .serialize();
    u
}

fn quorum_begin() -> LedgerOperation {
    LedgerOperation::QuorumBegin {
        exit_cutoff_height: None,
        exit_outputs: Vec::new(),
        reserves_id: "bcrt1qreserves".to_string(),
        spending_txid: [0; 32],
        new_outpoint_txid: [1; 32],
        new_outpoint_vout: 0,
        amount: RESERVES,
        quorum_expiry: 1_000_000,
        ledger_hash: [0; 32],
        quorum_members: vec![
            QuorumMemberRef::pubkey_only(pubkey(ACCUSED)),
            QuorumMemberRef::pubkey_only(pubkey(COLLUDER)),
        ],
        collateral_amount: COLLATERAL,
        protocol_version: Some("cltv-offset-v2".to_string()),
    }
}

/// seq 0 LedgerOpen, 1 QuorumBegin (the accused and the colluder), 2
/// DepositOpen whose descriptor is the depositor's key, 3 a credit to it.
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
        quorum_begin(),
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
        let cosigners: &[u8] = if seq >= 2 { &[ACCUSED, COLLUDER] } else { &[] };
        chain.push(update(seq as u64, prev, op, cosigners));
    }
    chain
}

/// seq 4: a TransferLock out of the deposit with an empty depositor witness
/// (InvalidWitness), cosigned by the accused and the colluder.
fn fault(prefix: &[SignedLedgerUpdate]) -> SignedLedgerUpdate {
    let op = LedgerOperation::TransferLock {
        transfer_nonce: [1; 32],
        source_deposit_id: DEPOSIT,
        destination_deposit_id: [0xCD; 16],
        amount: 1_000_000,
        fee: 0,
        completion_script: format!("wsh(prove(pk({})))", bitcoin::PublicKey::new(pubkey(4))),
        timeout_height: HEIGHT + 144,
        transfer_id: [1; 32],
        nonce: 1,
        expiry: HEIGHT + 10,
        witness: DescriptorWitness::new(),
        commitment: None,
    };
    update(4, prefix[3].chain_hash(), &op, &[ACCUSED, COLLUDER])
}

struct Ledgers(Vec<(String, Vec<SignedLedgerUpdate>)>);
impl LedgerProvider for Ledgers {
    fn ledger_history(&self, ledger_id: &str) -> Option<Vec<SignedLedgerUpdate>> {
        self.0
            .iter()
            .find(|(id, _)| id == ledger_id)
            .map(|(_, h)| h.clone())
    }
}
struct NoChain;
impl BlockOracle for NoChain {
    fn confirms(&self, _: &[u8; 32]) -> Option<u32> {
        None
    }
}

/// What the receiving node's provider holds: the fault ledger, gap-filled
/// from the relay (the fault itself included, as the relay has it).
fn provider(prefix: &[SignedLedgerUpdate], fault: &SignedLedgerUpdate) -> Ledgers {
    let mut h = prefix.to_vec();
    h.push(fault.clone());
    Ledgers(vec![(hex::encode(ledger()), h)])
}

/// Advertisements: the fault's operator runs the fault ledger and one other,
/// the accused two ledgers (one advertised twice, as a mirror would), the
/// colluder one.
fn operated_by(pk: &PublicKey) -> Vec<String> {
    if *pk == pubkey(OP) {
        vec![hex::encode(ledger()), own_ledger(OP, 1)]
    } else if *pk == pubkey(ACCUSED) {
        vec![
            own_ledger(ACCUSED, 1),
            own_ledger(ACCUSED, 2),
            own_ledger(ACCUSED, 1),
        ]
    } else if *pk == pubkey(COLLUDER) {
        vec![own_ledger(COLLUDER, 1)]
    } else {
        vec![]
    }
}

#[test]
fn the_governing_quorum_begin_is_the_latest_at_or_before_the_fault() {
    let prefix = prefix();
    let fault = fault(&prefix);
    assert_eq!(governing_quorum_begin_seq(&prefix, &fault), Some(1));

    // A rotation at 4 governs a fault at 6; one at 7 does not.
    let qb = quorum_begin();
    let noop = LedgerOperation::OnchainCredit {
        txid: [2; 32],
        vout: 0,
        deposit_id: DEPOSIT,
        amount: 1,
        funding_address: "x".into(),
        commitment: None,
    };
    let at = |seq: u64, op: &LedgerOperation| update(seq, [0; 32], op, &[]);
    let history = vec![
        at(1, &qb),
        at(3, &noop),
        at(4, &qb),
        at(5, &noop),
        at(7, &qb),
    ];
    assert_eq!(governing_quorum_begin_seq(&history, &at(6, &noop)), Some(4));
    // The fault itself may be the QuorumBegin.
    assert_eq!(governing_quorum_begin_seq(&history, &at(4, &qb)), Some(4));
    assert_eq!(
        governing_quorum_begin_seq(&history[1..2], &at(3, &noop)),
        None
    );
}

#[test]
fn the_producer_accuses_each_signer_on_each_other_ledger_it_operates() {
    let prefix = prefix();
    let fault = fault(&prefix);
    let qb = governing_quorum_begin_seq(&prefix, &fault).unwrap();
    let proofs = contagion_proofs(&fault, qb, &operated_by, None);

    let got: Vec<(String, String)> = proofs
        .iter()
        .map(|b| (b.proof.accused.clone(), b.proof.ledger_id.clone()))
        .collect();
    let operator = hex::encode(pubkey(OP).serialize());
    let accused = hex::encode(pubkey(ACCUSED).serialize());
    let colluder = hex::encode(pubkey(COLLUDER).serialize());
    // The operator on its other ledger, never on the fault ledger itself:
    // that one is judged by its own dispute, from before the fault.
    assert_eq!(
        got,
        vec![
            (operator.clone(), own_ledger(OP, 1)),
            (accused.clone(), own_ledger(ACCUSED, 1)),
            (accused, own_ledger(ACCUSED, 2)),
            (colluder.clone(), own_ledger(COLLUDER, 1)),
        ]
    );
    for b in &proofs {
        assert!(matches!(
            b.proof.proof_type,
            FraudProofType::NonConformingCosignature
        ));
        assert!(b.embedding.is_none() && b.causal_chain.is_empty());
        let FraudEvidence::NonConformingCosignature {
            fault_ledger_id,
            fault_sequence,
            governing_quorumbegin_seq,
            fault_update_hex,
        } = &b.proof.evidence
        else {
            panic!("wrong evidence");
        };
        assert_eq!(fault_ledger_id, &hex::encode(ledger()));
        assert_eq!(*fault_sequence, 4);
        assert_eq!(*governing_quorumbegin_seq, 1);
        assert_eq!(fault_update_hex, &hex::encode(fault.tlv_encode()));
    }

    // Our own key is never accused.
    let mine = contagion_proofs(&fault, qb, &operated_by, Some(&pubkey(ACCUSED)));
    assert!(mine
        .iter()
        .all(|b| b.proof.accused != hex::encode(pubkey(ACCUSED).serialize())));
    assert_eq!(mine.len(), 2);
    assert!(proofs
        .iter()
        .all(|b| b.proof.ledger_id != hex::encode(ledger())));

    // A cosigner the operator listed without its signature is not accused.
    let mut forged = fault.clone();
    forged.cosignatures[0].cosign_signature = [0x42; 64];
    // The operator signs the update with the bogus listing on it.
    forged.content_hash = forged.compute_hash();
    forged.operator_signature = Secp256k1::new()
        .sign_schnorr_no_aux_rand(
            &Message::from_digest(forged.operator_digest()),
            &keypair(OP),
        )
        .serialize();
    let proofs = contagion_proofs(&forged, qb, &operated_by, None);
    assert_eq!(proofs.len(), 2);
    assert_eq!(proofs[0].proof.accused, operator);
    assert_eq!(proofs[1].proof.accused, colluder);

    // An operator signature that does not verify accuses no operator.
    let mut unsigned = fault.clone();
    unsigned.operator_signature = [0x42; 64];
    let proofs = contagion_proofs(&unsigned, qb, &operated_by, None);
    assert!(proofs.iter().all(|b| b.proof.accused != operator));
    assert_eq!(proofs.len(), 3);
}

#[test]
fn every_produced_proof_verifies_with_the_dep16_authorizer() {
    let prefix = prefix();
    let fault = fault(&prefix);
    let qb = governing_quorum_begin_seq(&prefix, &fault).unwrap();
    let proofs = contagion_proofs(&fault, qb, &operated_by, None);
    assert_eq!(proofs.len(), 4);
    let ledgers = provider(&prefix, &fault);
    for b in &proofs {
        // Through the wire, as a receiving node gets it.
        let json = serde_json::to_string(b).unwrap();
        let back: FraudBroadcast = serde_json::from_str(&json).unwrap();
        verify_fraud_broadcast(&back, &ledgers, &NoChain, &Dep16Authorizer::new())
            .unwrap_or_else(|e| panic!("{} on {}: {}", b.proof.accused, b.proof.ledger_id, e));
    }

    // The governing QuorumBegin is checked: a proof naming another sequence
    // fails.
    let mut wrong_qb = proofs[0].clone();
    if let FraudEvidence::NonConformingCosignature {
        governing_quorumbegin_seq,
        ..
    } = &mut wrong_qb.proof.evidence
    {
        *governing_quorumbegin_seq = 2; // a DepositOpen, not a QuorumBegin
    }
    assert!(
        verify_fraud_broadcast(&wrong_qb, &ledgers, &NoChain, &Dep16Authorizer::new()).is_err()
    );
}

/// Verbatim from cl-deposits (regenerated 2026-10-02 for the ruleset change): `(broadcast->json
/// (make-non-conforming-cosignature-proof accused target fault 1))`, with
/// `fault` cl's `decode-update` of this file's `fault(&prefix())` TLV (its
/// `fault_update_hex` re-encodes byte-identical), `accused` pubkey(ACCUSED)
/// and `target` own_ledger(ACCUSED, 1). The signatures are deterministic
/// (no aux rand), so it stays valid.
const CL_PROOF: &str = r#"{"proof":{"proof_type":"NonConformingCosignature","accused":"024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766","ledger_id":"0303030303030303030303030303030303030303030303030303030303030303","evidence":{"NonConformingCosignature":{"fault_ledger_id":"aa20ce2e3ce18104ccda10fe82f604622735833c88befb2434fd423ac6f7c96c","fault_sequence":4,"governing_quorumbegin_seq":1,"fault_update_hex":"002102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f0220aa20ce2e3ce18104ccda10fe82f604622735833c88befb2434fd423ac6f7c96c0408000000000000000406208480fdb175dd9039ec72447f2e770571b99920d0b75d7595d428922ea79ce6fa08f0000146020800000000000f42400c080000000000000000cc0100d2200101010101010101010101010101010101010101010101010101010101010101d410ababababababababababababababababd610cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdd8527773682870726f766528706b28303334363237373961643461616433393531343631343735316137313038356632663130653163376135393365346530333065666235623837323163653535623062292929da0400000478dc200101010101010101010101010101010101010101010101010101010101010101fd0120080000000000000001fd012204000003f20a04000003e8144048171d85b53aebd6b6e68868998cdb481072306b4454fa0efc712854afd97925890c96c92b67134b88cecee4b4467faad6b68f13a93f76bf2deb0eb1054356b916fd01060081024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07668bbe688aa42ecb0d91db74be60ee63fd922cb341ac23296d5539c7cb673a89106bba1bd3adb1044d52af1ee6ad4b3808bf3138f2eb4d1cf6fcbfe8c9655ab1b60202020202020202020202020202020202020202020202020202020202020202008102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337323c3e82d88ca2f0a1fa0668bc903ae55fddcf19a8b1d8342cde642df5163ca66eebd01de5435ce5afd7242192f9f482f38c92e3d1e9c363396d0f5e6aee97ac0303030303030303030303030303030303030303030303030303030303030303"}}},"causal_chain":[]}"#;

/// cl-deposits' `broadcast->json` of `make-non-conforming-cosignature-proof`:
/// snake_case evidence fields under the "NonConformingCosignature" variant,
/// no `embedding` key (NIL values are dropped), an empty `causal_chain`.
#[test]
fn a_cl_shaped_proof_against_the_accuseds_own_ledger_verifies() {
    let prefix = prefix();
    let fault = fault(&prefix);
    // The fault is the empty witness, nothing else.
    {
        use deposits_protocol::tlv::TlvDecode;
        let mut state = LedgerState::new(pubkey(OP), "bcrt1qreserves".to_string(), 0);
        for u in &prefix {
            state.apply_update_in_place(u).unwrap();
        }
        let op = LedgerOperation::tlv_decode(&fault.message).unwrap();
        let (_, v) = state
            .apply_with_verifier(&op, &Dep16Authorizer::new(), HEIGHT)
            .unwrap();
        assert!(
            matches!(
                v[..],
                [deposits_protocol::types::ConformanceViolation::InvalidWitness { .. }]
            ),
            "{:?}",
            v
        );
    }
    let target = own_ledger(ACCUSED, 1);
    let json = CL_PROOF;
    let b: FraudBroadcast = serde_json::from_str(json).expect("cl's JSON parses");
    assert_eq!(b.proof.ledger_id, target);
    // What the kind:9101 receive path checks before handing it on.
    b.verify_chain_structure()
        .expect("self-evident: no embedding needed");
    verify_fraud_broadcast(
        &b,
        &provider(&prefix, &fault),
        &NoChain,
        &Dep16Authorizer::new(),
    )
    .expect("cl's contagion proof verifies on the reference");
    // The fault ledger's history is what grounds it: withheld, it fails closed.
    let err = verify_fraud_broadcast(&b, &Ledgers(vec![]), &NoChain, &Dep16Authorizer::new())
        .unwrap_err();
    assert!(err.contains("not available"), "{}", err);
}

/// Operator contagion: the fault's operator, accused on its other ledger. Its
/// own signature is the evidence; the fault is judged as a
/// NonConformingUpdate of the fault ledger, with the real dep-16 authorizer.
fn operator_proof(fault: &SignedLedgerUpdate) -> FraudBroadcast {
    contagion_proofs(fault, 1, &operated_by, None)
        .into_iter()
        .find(|b| b.proof.accused == hex::encode(pubkey(OP).serialize()))
        .expect("the operator is accused")
}

#[test]
fn an_operator_accused_proof_on_its_other_ledger_verifies() {
    let prefix = prefix();
    let fault = fault(&prefix);
    let b = operator_proof(&fault);
    assert_eq!(b.proof.ledger_id, own_ledger(OP, 1));
    let ledgers = provider(&prefix, &fault);
    verify_fraud_broadcast(&b, &ledgers, &NoChain, &Dep16Authorizer::new())
        .expect("the operator's forged update proves it on its other ledger");

    // Uncosigned, the operator's signature alone still grounds it: no
    // cosignature or membership check applies to the operator.
    let op = deposits_protocol::tlv::TlvDecode::tlv_decode(&fault.message).unwrap();
    let alone = update(4, prefix[3].chain_hash(), &op, &[]);
    let b = operator_proof(&alone);
    verify_fraud_broadcast(
        &b,
        &provider(&prefix, &alone),
        &NoChain,
        &Dep16Authorizer::new(),
    )
    .expect("an uncosigned forgery accuses its operator too");
}

#[test]
fn an_operator_accused_proof_about_a_conforming_update_does_not_verify() {
    let prefix = prefix();
    // seq 4: an honest credit, operator-signed and cosigned. Nothing wrong.
    let credit = LedgerOperation::OnchainCredit {
        txid: [2; 32],
        vout: 0,
        deposit_id: DEPOSIT,
        amount: 1_000,
        funding_address: "bcrt1qfund".to_string(),
        commitment: None,
    };
    let honest = update(4, prefix[3].chain_hash(), &credit, &[ACCUSED, COLLUDER]);
    let b = operator_proof(&honest);
    let err = verify_fraud_broadcast(
        &b,
        &provider(&prefix, &honest),
        &NoChain,
        &Dep16Authorizer::new(),
    )
    .unwrap_err();
    assert!(err.contains("applies cleanly"), "{}", err);

    // Someone who signed nothing is not accused through the operator's slot.
    let mut stranger = operator_proof(&fault(&prefix));
    stranger.proof.accused = hex::encode(pubkey(9).serialize());
    let err = verify_fraud_broadcast(
        &stranger,
        &provider(&prefix, &fault(&prefix)),
        &NoChain,
        &Dep16Authorizer::new(),
    )
    .unwrap_err();
    assert!(err.contains("not operator nor cosigner"), "{}", err);
}

/// Verbatim from cl-deposits (62b69bb, operator contagion):
/// `(broadcast->json (make-non-conforming-cosignature-proof op target fault 1))`,
/// with `fault` cl's `decode-update` of this file's `fault(&prefix())` TLV
/// (re-encoding byte-identical), `op` its `update-operator-id` (pubkey(OP))
/// and `target` own_ledger(OP, 1).
const CL_OPERATOR_PROOF: &str = r#"{"proof":{"proof_type":"NonConformingCosignature","accused":"02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f","ledger_id":"0606060606060606060606060606060606060606060606060606060606060606","evidence":{"NonConformingCosignature":{"fault_ledger_id":"aa20ce2e3ce18104ccda10fe82f604622735833c88befb2434fd423ac6f7c96c","fault_sequence":4,"governing_quorumbegin_seq":1,"fault_update_hex":"002102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f0220aa20ce2e3ce18104ccda10fe82f604622735833c88befb2434fd423ac6f7c96c0408000000000000000406208480fdb175dd9039ec72447f2e770571b99920d0b75d7595d428922ea79ce6fa08f0000146020800000000000f42400c080000000000000000cc0100d2200101010101010101010101010101010101010101010101010101010101010101d410ababababababababababababababababd610cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdd8527773682870726f766528706b28303334363237373961643461616433393531343631343735316137313038356632663130653163376135393365346530333065666235623837323163653535623062292929da0400000478dc200101010101010101010101010101010101010101010101010101010101010101fd0120080000000000000001fd012204000003f20a04000003e8144048171d85b53aebd6b6e68868998cdb481072306b4454fa0efc712854afd97925890c96c92b67134b88cecee4b4467faad6b68f13a93f76bf2deb0eb1054356b916fd01060081024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07668bbe688aa42ecb0d91db74be60ee63fd922cb341ac23296d5539c7cb673a89106bba1bd3adb1044d52af1ee6ad4b3808bf3138f2eb4d1cf6fcbfe8c9655ab1b60202020202020202020202020202020202020202020202020202020202020202008102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337323c3e82d88ca2f0a1fa0668bc903ae55fddcf19a8b1d8342cde642df5163ca66eebd01de5435ce5afd7242192f9f482f38c92e3d1e9c363396d0f5e6aee97ac0303030303030303030303030303030303030303030303030303030303030303"}}},"causal_chain":[]}"#;

#[test]
fn a_cl_shaped_operator_accused_proof_verifies() {
    let prefix = prefix();
    let fault = fault(&prefix);
    let b: FraudBroadcast = serde_json::from_str(CL_OPERATOR_PROOF).expect("cl's JSON parses");
    assert_eq!(b.proof.accused, hex::encode(pubkey(OP).serialize()));
    assert_eq!(b.proof.ledger_id, own_ledger(OP, 1));
    // Byte-for-byte what the reference's producer builds.
    assert_eq!(
        b.proof.proof_hash(),
        operator_proof(&fault).proof.proof_hash()
    );
    b.verify_chain_structure()
        .expect("self-evident: no embedding needed");
    verify_fraud_broadcast(
        &b,
        &provider(&prefix, &fault),
        &NoChain,
        &Dep16Authorizer::new(),
    )
    .expect("cl's operator-contagion proof verifies on the reference");
}
