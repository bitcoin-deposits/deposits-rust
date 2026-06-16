//! Large-ledger performance characterization — the "long arc" toward ~1M
//! entries. Grows a single operator ledger by repeated InvoiceCredit (history
//! and the `credited_payments` replay-protection set both grow O(n), modelling
//! a high-volume payment ledger) and, at each checkpoint, measures the costs
//! that actually scale with history length:
//!
//!   - append µs/op   — steady-state per-op cost over the window since the last
//!                      checkpoint. Flat ⇒ O(1) appends; rising ⇒ a hidden O(n)
//!                      per-op cost (→ O(n²) overall).
//!   - recompute ms   — `recompute_state()`: clear + replay the whole history.
//!                      This is what the joined-ledger re-import / reconstruct
//!                      paths pay; O(n) and run on demand, so its absolute cost
//!                      at 1M is an operational number worth knowing.
//!   - chainwalk ms   — `find_valid_chain_length()`: full chain continuity walk.
//!   - binary MB      — `export_binary()` size (≈ on-wire / on-disk size).
//!   - RSS MB         — process resident memory (Linux /proc/self/statm).
//!
//! Ignored by default. Run:
//!   cargo test --release -p deposits-core --test large_ledger \
//!       -- --ignored --nocapture
//! Override the target (and add it as a checkpoint):
//!   LARGE_LEDGER_N=100000 cargo test --release ... -- --ignored --nocapture
//!
//! ## Findings
//!
//! Original characterization (2026-06-16, release) — **before** the fix:
//!
//! | entries | append us/op | recompute | binary |
//! |---------|--------------|-----------|--------|
//! | 10,000  |    299       |   3.4 s   | 4.5 MB |
//! | 100,000 |  4,077       |   478 s   |  45 MB |
//!
//! Both append/op (×13.6 per ×10) and recompute (×138 per ×10) were super-linear
//! → **O(n²)**. Root cause: `LedgerState::apply` did `let next = self.clone()` on
//! every operation, copying the whole state (deposits map + credited_payments set
//! + …). Each apply was O(current size) → O(n²) to build and to replay; ~1M was
//! unreachable (extrapolated ~13 h to recompute).
//!
//! **Fixed** (2026-06-16, release) — split `apply` into a functional wrapper that
//! clones once and `apply_in_place(&mut self)` that mutates the real state
//! machine; all hot paths (append, recompute, fraud replay, Batch inner ops) now
//! call `apply_in_place`, so there is no per-op full-state clone. The functional
//! `apply` is kept as a one-clone wrapper for validate-scratch callers
//! (check_speculative, apply_with_verifier) so failure-leaves-state-unchanged
//! still holds for free there.
//!
//! | entries   | append us/op | recompute | binary  | RSS    |
//! |-----------|--------------|-----------|---------|--------|
//! | 10,000    |     2.5      |    14 ms  |  4.5 MB |  11 MB |
//! | 100,000   |     2.0      |   138 ms  |   45 MB |  88 MB |
//! | 1,000,000 |     3.0      | 1,794 ms  |  451 MB | 852 MB |
//!
//! append/op is now flat (~2–3 µs, O(1) per op → O(n) build) and recompute is
//! linear; **1M entries is reachable** (≈3 s to build, 1.8 s to recompute). The
//! default target is small so this stays a quick smoke run; override
//! `LARGE_LEDGER_N` to re-characterize.

use deposits_core::ledger::Ledger;
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{compute_deposit_id, FeeStructure};
use std::time::Instant;

fn fixed_pubkey() -> bitcoin::secp256k1::PublicKey {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
    bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
}

/// Resident set size in MB (Linux). 0 if unavailable.
fn rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1).and_then(|p| p.parse::<u64>().ok()))
        .map(|pages| (pages * 4096) as f64 / 1e6)
        .unwrap_or(0.0)
}

#[test]
#[ignore = "perf characterization; run explicitly with --release --ignored --nocapture"]
fn large_ledger_characterization() {
    let target: usize = std::env::var("LARGE_LEDGER_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000); // small default — quick smoke; override for deep runs

    let mut checkpoints: Vec<usize> = [10_000usize, 100_000, 1_000_000]
        .into_iter()
        .filter(|&c| c <= target)
        .collect();
    if !checkpoints.contains(&target) {
        checkpoints.push(target);
    }
    checkpoints.sort_unstable();

    // Operator ledger + LedgerOpen (large reserves so credits never trip a
    // reserve check) + one deposit to credit against. All appended to history
    // so the chain replays cleanly.
    let op = fixed_pubkey();
    let mut ledger = Ledger::new_as_operator(op, hex::encode(op.serialize()), 0);
    ledger
        .append_operation_with_block(
            LedgerOperation::LedgerOpen {
                operator_id: op,
                reserves_id: hex::encode(op.serialize()),
                genesis_block: 0,
                reserves_amount: u64::MAX / 4,
                collateral_amount: 0,
            },
            0,
            [0u8; 32],
        )
        .expect("LedgerOpen");
    let descriptor = format!("pk({})", hex::encode(op.serialize()));
    let deposit_id = compute_deposit_id(&descriptor);
    ledger
        .append_operation_with_block(
            LedgerOperation::DepositOpen {
                deposit_id,
                descriptor,
                fees: Some(FeeStructure::default()),
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
            },
            0,
            [0u8; 32],
        )
        .expect("DepositOpen");

    println!("\nlarge-ledger characterization: target={} checkpoints={:?}", target, checkpoints);
    println!(
        "{:>11}  {:>12}  {:>13}  {:>13}  {:>10}  {:>9}",
        "entries", "append us/op", "recompute ms", "chainwalk ms", "binary MB", "RSS MB"
    );

    let mut i: u64 = 0;
    let mut prev_len = ledger.history.len();
    for &cp in &checkpoints {
        // Append InvoiceCredits until history reaches the checkpoint.
        let t_append = Instant::now();
        while ledger.history.len() < cp {
            let mut payment_hash = [0u8; 32];
            payment_hash[..8].copy_from_slice(&i.to_le_bytes());
            ledger
                .append_operation_with_block(
                    LedgerOperation::InvoiceCredit {
                        payment_hash,
                        deposit_id,
                        amount: 1,
                        invoice_id: format!("i{}", i),
                        sequence_number: 0,
                        wallet_authorization: None,
                    },
                    0,
                    [0u8; 32],
                )
                .expect("InvoiceCredit append");
            i += 1;
        }
        let appended = (ledger.history.len() - prev_len).max(1);
        let per_op_us = t_append.elapsed().as_micros() as f64 / appended as f64;
        prev_len = ledger.history.len();

        // Full-replay cost (re-import / reconstruct pays this).
        let t_rc = Instant::now();
        ledger.recompute_state().expect("recompute_state");
        let recompute_ms = t_rc.elapsed().as_millis();

        // Chain-continuity walk.
        let t_walk = Instant::now();
        let _ = deposits_core::ledger::LedgerValidator::find_valid_chain_length(&ledger);
        let walk_ms = t_walk.elapsed().as_millis();

        // Serialized size.
        let bin_mb = ledger.export_binary(0).len() as f64 / 1e6;

        println!(
            "{:>11}  {:>12.3}  {:>13}  {:>13}  {:>10.1}  {:>9.0}",
            ledger.history.len(),
            per_op_us,
            recompute_ms,
            walk_ms,
            bin_mb,
            rss_mb()
        );
    }
    println!();
}
