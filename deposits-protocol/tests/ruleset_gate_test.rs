//! Tests for the ruleset-attestation gate inside `LedgerState::apply`
//! at `QuorumBegin` time.
//!
//! Rule: when `protocol_version` is set to a non-`legacy` ruleset, every
//! promoted member must have declared support for that ruleset in their
//! signed `QuorumMemberResponse` (which lands in
//! `QuorumMember.supported_rulesets` at apply time). For `legacy`
//! (or absent → defaults to `legacy`), the gate is a no-op so pre-Q1
//! ledgers continue to validate.

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use deposits_protocol::messages::{LedgerOperation, QuorumMemberRef};
use deposits_protocol::types::{LedgerState, QuorumMember};

fn pk(seed: u8) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
}

/// Build a state with the given operator and one staged member whose
/// `supported_rulesets` is set to `member_supports`. All other fields
/// take defaults — only `apply(QuorumBegin)` consumes them in this test.
fn state_with_staged_member(
    operator: PublicKey,
    member: PublicKey,
    member_supports: Vec<String>,
) -> LedgerState {
    let mut s = LedgerState::new(operator, "rid".into(), 0);
    s.next_quorum_members.push(QuorumMember {
        min_collateral_bps: None,
        pubkey: member,
        ledger_id: "member-ledger".into(),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        membership_until: None,
        dispute_response_blocks: None,
        dispute_arm_blocks: None,
        service_response_blocks: None,
        max_transfer_timeout_blocks: None,
        max_descriptor_bytes: None,
        compensation_bps: None,
        compensation_deposit_id: None,
        compensation_frequency_blocks: None,
        supported_rulesets: member_supports,
    });
    s
}

fn quorum_begin(member: PublicKey, protocol_version: Option<String>) -> LedgerOperation {
    LedgerOperation::QuorumBegin {
        reserves_id: "rid2".into(),
        spending_txid: [0x11; 32],
        new_outpoint_txid: [0x22; 32],
        new_outpoint_vout: 0,
        amount: 1_000_000,
        quorum_expiry: 800_000,
        ledger_hash: [0x33; 32],
        quorum_members: vec![QuorumMemberRef::new(member, "member-ledger")],
        collateral_amount: 100_000,
        protocol_version,
    }
}

/// A QuorumBegin must name a ruleset: one without `protocol_version` is
/// refused (the pre-anchor `legacy` default was removed).
#[test]
fn quorum_begin_without_protocol_version_is_refused() {
    let operator = pk(1);
    let member = pk(2);
    let s = state_with_staged_member(operator, member, vec!["cltv-offset-v2".into()]);
    assert!(s.apply(&quorum_begin(member, None)).is_err());
}

/// `legacy` is no longer a ruleset.
#[test]
fn explicit_legacy_protocol_version_is_refused() {
    let operator = pk(1);
    let member = pk(2);
    let s = state_with_staged_member(operator, member, vec!["legacy".into()]);
    assert!(s
        .apply(&quorum_begin(member, Some("legacy".into())))
        .is_err());
}

/// Non-legacy ruleset with a member who never declared support →
/// reject. This is the failure mode the gate exists for: a node
/// replaying the chain refuses a QuorumBegin pinning to semantics
/// some member can't validate.
#[test]
fn nonlegacy_quorum_begin_rejects_unattested_member() {
    let operator = pk(1);
    let member = pk(2);
    let s = state_with_staged_member(operator, member, Vec::new());
    let op = quorum_begin(member, Some("cltv-offset-v2".into()));
    let err = s.apply(&op).unwrap_err();
    let msg = format!("{:?}", err);
    assert!(
        msg.contains("ruleset_unsupported_by_member"),
        "expected ruleset_unsupported_by_member, got: {}",
        msg
    );
    assert!(msg.contains("cltv-offset-v2"), "got: {}", msg);
}

/// A rejected `QuorumBegin` must leave state untouched — the documented
/// `apply_in_place` atomicity invariant. Regression guard: an earlier version
/// drained `next_quorum_members` *before* the ruleset gate, so a rejected
/// QuorumBegin silently emptied the staged set (the functional `apply` clone
/// hid it, but the in-place build/replay path corrupted state).
#[test]
fn rejected_quorum_begin_leaves_state_untouched() {
    let operator = pk(1);
    let member = pk(2);
    let mut s = state_with_staged_member(operator, member, Vec::new());
    let before = s.clone();
    let op = quorum_begin(member, Some("cltv-offset-v2".into()));

    let err = s.apply_in_place(&op).unwrap_err();
    assert!(format!("{:?}", err).contains("ruleset_unsupported_by_member"));

    // Nothing moved: staged set intact, quorum not activated.
    assert_eq!(s.next_quorum_members, before.next_quorum_members);
    assert!(s.quorum_members.is_empty());
    assert_eq!(s.quorum_state, before.quorum_state);
    assert_eq!(
        s, before,
        "rejected QuorumBegin must leave the whole state unchanged"
    );
}

/// A member who declared support only for `legacy` cannot be promoted
/// into a `cltv-offset-v2` quorum.
#[test]
fn nonlegacy_quorum_begin_rejects_legacy_only_member() {
    let operator = pk(1);
    let member = pk(2);
    let s = state_with_staged_member(operator, member, vec!["legacy".into()]);
    let op = quorum_begin(member, Some("cltv-offset-v2".into()));
    let err = s.apply(&op).unwrap_err();
    assert!(format!("{:?}", err).contains("ruleset_unsupported_by_member"));
}

/// Member explicitly supports `cltv-offset-v2` → apply succeeds and
/// the ledger pins to that ruleset for the rest of this quorum's
/// lifetime.
#[test]
fn nonlegacy_quorum_begin_accepts_attested_member() {
    let operator = pk(1);
    let member = pk(2);
    let s = state_with_staged_member(
        operator,
        member,
        vec!["legacy".into(), "cltv-offset-v2".into()],
    );
    let op = quorum_begin(member, Some("cltv-offset-v2".into()));
    let next = s
        .apply(&op)
        .expect("attested non-legacy QuorumBegin must apply");
    assert_eq!(next.active_ruleset_name, "cltv-offset-v2");
    assert_eq!(next.quorum_members.len(), 1);
}

/// Mixed quorum where one of three members is unattested → reject.
/// Ensures the rule fires per-member, not just on the first.
#[test]
fn nonlegacy_quorum_begin_rejects_when_any_member_unattested() {
    let operator = pk(1);
    let m1 = pk(2);
    let m2 = pk(3);
    let m3 = pk(4);

    let mut s = LedgerState::new(operator, "rid".into(), 0);
    for (m, support) in [
        (m1, vec!["cltv-offset-v2".into()]),
        (m2, vec!["cltv-offset-v2".into()]),
        (m3, Vec::<String>::new()), // legacy-only by inference
    ] {
        s.next_quorum_members.push(QuorumMember {
            min_collateral_bps: None,
            pubkey: m,
            ledger_id: "x".into(),
            min_fee_bps: None,
            min_fee_fixed: None,
            max_fee_period: None,
            membership_until: None,
            dispute_response_blocks: None,
            dispute_arm_blocks: None,
            service_response_blocks: None,
            max_transfer_timeout_blocks: None,
            max_descriptor_bytes: None,
            compensation_bps: None,
            compensation_deposit_id: None,
            compensation_frequency_blocks: None,
            supported_rulesets: support,
        });
    }
    let op = LedgerOperation::QuorumBegin {
        reserves_id: "rid2".into(),
        spending_txid: [0x11; 32],
        new_outpoint_txid: [0x22; 32],
        new_outpoint_vout: 0,
        amount: 1_000_000,
        quorum_expiry: 800_000,
        ledger_hash: [0x33; 32],
        quorum_members: vec![
            QuorumMemberRef::new(m1, "x"),
            QuorumMemberRef::new(m2, "x"),
            QuorumMemberRef::new(m3, "x"),
        ],
        collateral_amount: 100_000,
        protocol_version: Some("cltv-offset-v2".into()),
    };
    let err = s.apply(&op).unwrap_err();
    let msg = format!("{:?}", err);
    assert!(msg.contains("ruleset_unsupported_by_member"), "{}", msg);
    // Only m3 is missing — error message must name it (and not name
    // the others).
    let m3_hex = hex::encode(m3.serialize());
    assert!(msg.contains(&m3_hex), "{} missing m3 hex {}", msg, m3_hex);
}
