//! Validates `audit_base64` against a frozen fixture captured from the live
//! relay (ledger 57f60e1d). The expected figures were cross-checked against the
//! `replay-ledger` CLI on the same data, so this pins the browser/CLI audit to
//! the canonical `LedgerState` replay. The fixture intentionally contains the
//! duplicate republished events from the relay, exercising chain dedup.

use deposits_audit::audit_base64;

fn load_fixture() -> Vec<String> {
    let raw = include_str!("fixtures/ledger_57f60e1dbef339e2.json");
    serde_json::from_str(raw).expect("fixture json")
}

#[test]
fn fixture_report_is_sane_and_solvent() {
    let blobs = load_fixture();
    let r = audit_base64(&blobs);
    eprintln!("AUDIT REPORT: {}", serde_json::to_string_pretty(&r).unwrap());

    // Stable ledger config (set at QuorumBegin): 15.6k reserves / 23.4k collateral.
    assert_eq!(r.reserves_msats, 15_600_000, "reserves");
    assert_eq!(r.collateral_msats, 23_400_000, "collateral");

    // Exact figures, cross-checked against `replay-ledger` on the same frozen
    // data: total_bal 132.029 sat, deposits 3, solvent YES. This pins the
    // audit to the canonical LedgerState replay (same numbers in CLI + wasm).
    assert_eq!(r.obligations_msats, 132_029, "obligations (= replay-ledger total_bal)");
    assert_eq!(r.locked_msats, 0, "all locks resolved in this snapshot");
    assert_eq!(r.deposits, 3, "deposits");
    assert!(r.solvent, "should be solvent");
    assert!(r.obligations_msats <= r.reserves_msats, "obligations fit reserves");
    assert!(r.locked_msats <= r.obligations_msats, "locked is a subset of balance");

    // Op tally: this snapshot reconciled (10 locks ↔ 10 fulfills, 0 fail).
    assert_eq!(r.op_counts.get("InvoiceLock").copied().unwrap_or(0), 10);
    assert_eq!(r.op_counts.get("InvoiceFulfill").copied().unwrap_or(0), 10);
    assert_eq!(r.op_counts.get("InvoiceCredit").copied().unwrap_or(0), 11);
    assert_eq!(r.replay_errors, 0, "fixture replays cleanly");
}

#[test]
fn deposit_rows_match_aggregate() {
    let blobs = load_fixture();
    let rows = deposits_audit::deposit_rows_base64(&blobs);
    let agg = audit_base64(&blobs);

    // Per-deposit list agrees with the aggregate audit.
    assert_eq!(rows.len(), agg.deposits, "row count == deposit count");
    let sum: u64 = rows.iter().map(|r| r.balance_msats).sum();
    assert_eq!(sum, agg.obligations_msats, "Σ row balance == obligations");
    let locked: u64 = rows.iter().map(|r| r.locked_msats).sum();
    assert_eq!(locked, agg.locked_msats, "Σ row locked == locked total");

    // Sorted descending; each row internally consistent + has a descriptor.
    for w in rows.windows(2) {
        assert!(w[0].balance_msats >= w[1].balance_msats, "sorted by balance desc");
    }
    for r in &rows {
        assert_eq!(r.available_msats, r.balance_msats - r.locked_msats);
        assert!(!r.descriptor.is_empty(), "deposit has a descriptor");
        assert_eq!(r.deposit_id.len(), 32, "16-byte id as 32 hex chars");
    }
}
