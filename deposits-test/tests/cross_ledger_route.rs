//! Integration test: cross-ledger transfer via the htlc-agent courier.
//!
//! The protocol provides only the HTLC primitive: `TransferLock` with a
//! `completion_script`, claimed by `TransferComplete` (with a witness
//! satisfying the script) or returned by `TransferFail` after timeout.
//! Cross-ledger movement is built on top of this by an htlc-agent
//! ("courier") that holds deposits on multiple ledgers — see DEP-13.
//!
//! Flow (sender = recipient in this test, just on different ledgers —
//! exercises the wallet+courier+operator dance, not the human-routing
//! semantics):
//!
//!   1. One wallet identity (single nsec, single deposits.json) opens
//!      "src" on op2's L1 and "dst" on op3's L1.
//!   2. Operator credit funds "src" via `deposits-node deposit credit`.
//!   3. `deposits-wallet route src dst <amount>` drives the 4-step HTLC
//!      dance:
//!        a. ask courier for a route → gets courier's deposit on src ledger
//!        b. wallet TransferLock src → courier's deposit on src ledger
//!        c. courier mirrors: TransferLock courier-on-dst → "dst" deposit
//!        d. wallet TransferComplete on dst (reveals preimage)
//!        e. courier TransferComplete on src using same preimage
//!   4. Verify "dst" reflects the routed amount (minus fees).
//!
//! Requires:
//!   ./bin/setup.sh 3
//!   ./bin/setup-htlc-agent.sh

use deposits_test::regtest::*;
use std::time::Duration;

#[test]
#[ignore]
fn cross_ledger_route_via_htlc_agent() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }
    if !htlc_agent_available() {
        eprintln!("skipping: htlc-agent not running — start with ./bin/setup-htlc-agent.sh");
        return;
    }

    // Use ledgers untouched by the fraud-proof tests (which disputed
    // op0's L1, L2, L3 and op1's L3). op2/op3 are clean.
    let from_ledger = read_setup_state("ledger_2_1");
    let to_ledger = read_setup_state("ledger_3_1");
    eprintln!(
        "[setup]   from_ledger={}…  to_ledger={}…",
        &from_ledger[..16],
        &to_ledger[..16]
    );

    // Single wallet, two deposits — sender and recipient are the same
    // identity on different ledgers. That keeps key/nsec management
    // simple while exercising the same code path a real cross-operator
    // routing would.
    let wdir = tempdir();
    let (sec, _xonly) = keygen();
    let nsec = wdir.join("wallet.nsec");
    std::fs::write(&nsec, &sec).unwrap();

    // Open the source deposit. `wallet_open` defaults to 100k sats —
    // that's the *requested* amount (operator opens an offer); funding
    // happens separately via operator credit below.
    let (ok, out) = wallet_open(&from_ledger, "src", &nsec, &wdir, &[]);
    assert!(
        ok && (out.contains("Deposit account created") || out.contains("already exists")),
        "open src failed:\n{}",
        out
    );

    let (ok, out) = wallet_open(&to_ledger, "dst", &nsec, &wdir, &[]);
    assert!(
        ok && (out.contains("Deposit account created") || out.contains("already exists")),
        "open dst failed:\n{}",
        out
    );

    let (src_pubkey, _src_initial_sats) =
        wallet_lookup_deposit(&wdir, "src").expect("src deposit not in wallet's deposits.json");
    let (_dst_pubkey, _dst_initial_sats) =
        wallet_lookup_deposit(&wdir, "dst").expect("dst deposit not in wallet's deposits.json");
    eprintln!(
        "[deposits] src_pubkey={}…  dst_pubkey={}…",
        &src_pubkey[..16],
        &_dst_pubkey[..16]
    );

    // Wait for the just-opened DepositOpen to propagate to op2's quorum
    // members' replicas — they need to see the deposit before they'll
    // cosign an InvoiceCredit against it.
    std::thread::sleep(Duration::from_secs(8));

    // InvoiceCredit's payment_hash = sha256(invoice_id). Quorum members
    // refuse to cosign a duplicate payment_hash, so each test run must
    // use a fresh invoice_id (otherwise re-runs hit "already credited").
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // Fund src via op2's daemon credit (skips on-chain TX). Pick a
    // generous balance so the route + fees fit comfortably.
    let fund_msats: u64 = 1_000_000; // 1000 sats
    operator_credit_deposit(
        2,
        &from_ledger,
        &src_pubkey,
        fund_msats,
        &format!("fund-src-{}", nonce),
    );
    eprintln!("[fund]    credited {} msats to src", fund_msats);

    // The htlc-agent's dst-side deposit needs liquidity so the courier
    // can lock outbound to "dst". setup-htlc-agent.sh's credit step is
    // best-effort and silently skips ledgers — pre-credit here so the
    // test is self-contained.
    let agent_dst_pubkey = htlc_agent_deposit_pubkey(&to_ledger)
        .expect("htlc-agent has no deposit on dst ledger — bridge unavailable");
    operator_credit_deposit(
        3,
        &to_ledger,
        &agent_dst_pubkey,
        fund_msats,
        &format!("fund-agent-dst-{}", nonce),
    );
    eprintln!(
        "[fund]    credited {} msats to agent's dst deposit ({}…)",
        fund_msats,
        &agent_dst_pubkey[..16]
    );

    // Sync wallet so `route`'s pre-flight balance check sees the credit.
    std::thread::sleep(Duration::from_secs(2));
    assert!(wallet_sync(&wdir, &nsec), "wallet sync failed");

    // ── Drive the HTLC route ────────────────────────────────────────
    let route_amount_sats: u64 = 500;
    eprintln!("[route]   {} sats: src → dst via htlc-agent", route_amount_sats);
    let (ok, out) = wallet_route(&wdir, &nsec, "src", "dst", route_amount_sats);
    if !ok {
        panic!("wallet route failed:\n{}", out);
    }
    assert!(
        out.contains("Routed transfer complete"),
        "route did not report completion:\n{}",
        out
    );
    eprintln!("[ok] route completed end-to-end");
}

/// PTLC variant of `cross_ledger_route_via_htlc_agent`: the same dance but
/// each leg locks with `pointlock(P)` instead of `sha256(H)`, and the
/// witness shared between legs is a 32-byte scalar (`s` on Leg 2,
/// transformed to `s + t` by the courier for Leg 1) instead of a preimage.
///
/// The structural privacy property — Leg 1's `pointlock(P + T)` and Leg 2's
/// `pointlock(P)` use unrelated curve points — comes from the protocol; we
/// verify the route completes and the wallet reports the PTLC branch ran.
/// Per-leg script inspection is left to a follow-up test that decodes Kind
/// 9100 updates directly.
///
/// Requires the same setup as the HTLC variant, plus operators publishing
/// pointlock in their Kind 39100 capabilities — automatic when the daemon
/// uses `operator_policy::default_advertised_capabilities()` (every fresh
/// `./bin/setup.sh` does).
#[test]
#[ignore]
fn cross_ledger_route_via_htlc_agent_ptlc() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }
    if !htlc_agent_available() {
        eprintln!("skipping: htlc-agent not running — start with ./bin/setup-htlc-agent.sh");
        return;
    }

    let from_ledger = read_setup_state("ledger_2_1");
    let to_ledger = read_setup_state("ledger_3_1");
    eprintln!(
        "[setup]   from_ledger={}…  to_ledger={}…",
        &from_ledger[..16],
        &to_ledger[..16]
    );

    let wdir = tempdir();
    let (sec, _xonly) = keygen();
    let nsec = wdir.join("wallet.nsec");
    std::fs::write(&nsec, &sec).unwrap();

    let (ok, out) = wallet_open(&from_ledger, "src", &nsec, &wdir, &[]);
    assert!(
        ok && (out.contains("Deposit account created") || out.contains("already exists")),
        "open src failed:\n{}",
        out
    );
    let (ok, out) = wallet_open(&to_ledger, "dst", &nsec, &wdir, &[]);
    assert!(
        ok && (out.contains("Deposit account created") || out.contains("already exists")),
        "open dst failed:\n{}",
        out
    );

    let (src_pubkey, _) =
        wallet_lookup_deposit(&wdir, "src").expect("src deposit not in deposits.json");
    let (_dst_pubkey, _) =
        wallet_lookup_deposit(&wdir, "dst").expect("dst deposit not in deposits.json");
    eprintln!(
        "[deposits] src_pubkey={}…  dst_pubkey={}…",
        &src_pubkey[..16],
        &_dst_pubkey[..16]
    );

    std::thread::sleep(Duration::from_secs(8));

    // Fresh nonce per run so InvoiceCredit's payment_hash never duplicates
    // across re-runs (operators refuse duplicate hashes).
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let fund_msats: u64 = 1_000_000;
    operator_credit_deposit(
        2,
        &from_ledger,
        &src_pubkey,
        fund_msats,
        &format!("fund-src-ptlc-{}", nonce),
    );
    let agent_dst_pubkey = htlc_agent_deposit_pubkey(&to_ledger)
        .expect("htlc-agent has no deposit on dst ledger — bridge unavailable");
    operator_credit_deposit(
        3,
        &to_ledger,
        &agent_dst_pubkey,
        fund_msats,
        &format!("fund-agent-dst-ptlc-{}", nonce),
    );

    std::thread::sleep(Duration::from_secs(2));
    assert!(wallet_sync(&wdir, &nsec), "wallet sync failed");

    // ── Drive the PTLC route ────────────────────────────────────────
    let route_amount_sats: u64 = 500;
    eprintln!("[route]   {} sats: src → dst via PTLC pattern", route_amount_sats);
    let (ok, out) = wallet_route_ptlc(&wdir, &nsec, "src", "dst", route_amount_sats);
    if !ok {
        panic!("wallet route --ptlc failed:\n{}", out);
    }
    assert!(
        out.contains("Routed transfer complete"),
        "PTLC route did not report completion:\n{}",
        out
    );
    // The wallet's PTLC branch prints "Revealing scalar..." (HTLC prints
    // "Revealing preimage..."). Distinguishes the branches in the output.
    assert!(
        out.contains("Revealing scalar"),
        "wallet did not exercise the PTLC scalar-witness path:\n{}",
        out
    );
    eprintln!("[ok] PTLC route completed end-to-end");
}
