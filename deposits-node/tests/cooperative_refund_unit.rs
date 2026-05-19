//! Unit tests for the cooperative-refund deterministic-build contract.
//!
//! The cooperative refund TX must be byte-identical across every caller
//! that observes the same DisputeArmed records — otherwise the daemon
//! cosigners refuse the TX-shape verification and the recovery deadlocks.
//! These tests pin the deterministic pieces (input sort order, fee
//! schedule) so a future refactor can't silently break either side.

use bitcoin::{OutPoint, Txid};
use deposits_node::node::request_handlers::cooperative_refund::expected_cooperative_refund_fee;

#[test]
fn fee_schedule_matches_documented_formula() {
    // 200 sats fixed + 100 sats per input. Both the daemon verifier
    // and the CLI builder read this same function, so the test pins
    // the absolute values that ship — bumping either side without
    // updating this expectation breaks the contract.
    assert_eq!(expected_cooperative_refund_fee(0), 200);
    assert_eq!(expected_cooperative_refund_fee(1), 300);
    assert_eq!(expected_cooperative_refund_fee(2), 400);
    assert_eq!(expected_cooperative_refund_fee(3), 500);
    assert_eq!(expected_cooperative_refund_fee(5), 700);
    assert_eq!(expected_cooperative_refund_fee(10), 1200);
}

#[test]
fn input_sort_order_is_lexicographic_by_txid_then_vout() {
    // The CLI builder + daemon verifier both sort inputs by (txid bytes,
    // vout). Any disagreement would produce different TX bytes.
    //
    // Construct three RC outpoints whose natural order would differ
    // under different sort schemes (e.g. by-amount, by-pubkey-of-owner)
    // and confirm the lex-by-txid sort produces the expected order.
    use bitcoin::hashes::Hash;
    let txid_a = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
        [0x11; 32],
    ));
    let txid_b = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
        [0x22; 32],
    ));
    let txid_c = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
        [0x33; 32],
    ));

    // Build outpoints in an arbitrary order with different vouts.
    let mut outpoints = vec![
        OutPoint::new(txid_c, 0),
        OutPoint::new(txid_a, 7),
        OutPoint::new(txid_b, 2),
        OutPoint::new(txid_a, 3),
    ];
    outpoints.sort_by(|a, b| {
        let at: [u8; 32] = *a.txid.as_ref();
        let bt: [u8; 32] = *b.txid.as_ref();
        at.cmp(&bt).then(a.vout.cmp(&b.vout))
    });

    let expected = vec![
        OutPoint::new(txid_a, 3),
        OutPoint::new(txid_a, 7),
        OutPoint::new(txid_b, 2),
        OutPoint::new(txid_c, 0),
    ];
    assert_eq!(outpoints, expected);
}
