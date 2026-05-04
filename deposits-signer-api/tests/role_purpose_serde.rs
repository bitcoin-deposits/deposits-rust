//! Smoke tests for the wire types — `SigRole` and `SigPurpose` need to be
//! round-trip-stable as soon as `RemoteSigner` lands. Lock the format here.

use deposits_signer_api::{SigPurpose, SigRole, SignContext};

#[test]
fn no_ledger_round_trip() {
    let ctx = SignContext {
        role: SigRole::NoLedger,
        purpose: SigPurpose::InvoiceCosign,
    };
    let bytes = serde_json::to_vec(&ctx).unwrap();
    let decoded: SignContext = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ctx, decoded);
}

#[test]
fn operator_update_round_trip() {
    let ctx = SignContext::operator_update([0xab; 32], 42);
    let bytes = serde_json::to_vec(&ctx).unwrap();
    let decoded: SignContext = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ctx, decoded);
    if let SigRole::OperatorUpdate { ledger_id, seq } = decoded.role {
        assert_eq!(ledger_id, [0xab; 32]);
        assert_eq!(seq, 42);
    } else {
        panic!("expected OperatorUpdate role");
    }
}

#[test]
fn cosign_update_round_trip() {
    let ctx = SignContext::cosign_update([0xcd; 32], 7, [0xef; 32]);
    let bytes = serde_json::to_vec(&ctx).unwrap();
    let decoded: SignContext = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ctx, decoded);
}

#[test]
fn every_purpose_round_trips() {
    for purpose in [
        SigPurpose::Bip340Untagged,
        SigPurpose::InvoiceCosign,
        SigPurpose::NostrEvent,
        SigPurpose::Attestation,
        SigPurpose::DepositGuarantee,
        SigPurpose::Payment,
        SigPurpose::PaymentAuthorization,
        SigPurpose::DepositOffer,
        SigPurpose::Withdrawal,
        SigPurpose::OnchainSighash,
    ] {
        let ctx = SignContext::no_ledger(purpose);
        let bytes = serde_json::to_vec(&ctx).unwrap();
        let decoded: SignContext = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ctx, decoded);
    }
}
