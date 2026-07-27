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
//! **Fix, part 1** — split `apply` into a functional wrapper that clones once
//! and `apply_in_place(&mut self)` that mutates the real state machine; the
//! build/replay hot paths (append, recompute, fraud replay, Batch inner ops)
//! call `apply_in_place`, removing the per-op full-state clone there. This fixed
//! append + recompute but NOT the clone-based verifier paths — `apply_and_check`
//! (joined-ledger re-import / watcher) still went through the cloning
//! `apply_with_verifier`, so re-import stayed O(n²): 4,083 ms @10k → 35,576 ms
//! @30k (the `reimport` column was added to catch exactly this).
//!
//! **Fix, part 2 (the real one)** — make the clone itself cheap. `deposits` and
//! `credited_payments` (the two collections that grow with n) became persistent
//! structures (`im::OrdMap` / `im::OrdSet`): `LedgerState::clone()` is now O(1)
//! structural sharing and mutation is O(log n) copy-on-write. Every clone-based
//! path — re-import, `check_speculative`, `apply_signed` — drops to O(n log n)
//! with zero logic changes, and failure-leaves-state-unchanged comes back for
//! free (the discarded clone). This is what the COW migration bought.
//!
//! | entries   | append us/op | recompute | inbound us/op | reimport  | chainwalk | binary  | RSS    |
//! |-----------|--------------|-----------|---------------|-----------|-----------|---------|--------|
//! | 10,000    |     3.2      |    14 ms  |     9.9       |    92 ms  |    0 ms   |  4.5 MB |  11 MB |
//! | 100,000   |     2.5      |   166 ms  |    15.7       | 1,339 ms  |   13 ms   |   45 MB |  94 MB |
//! | 1,000,000 |     3.2      | 2,318 ms  |    84.2       | 24,275 ms |  234 ms   |  451 MB | 869 MB |
//!
//! `inbound us/op` is the MARGINAL cost of one more op on a ledger whose state
//! is already this big — the routine path (`apply_inbound` /
//! `apply_updates_to_ledger` both call `apply_and_check` per op). It is the only
//! n-dependent work the routine path does: the wrappers' dedup scan is over the
//! *bounded* in-memory history (truncated to HISTORY_RETAIN = 2000) and persist
//! is an incremental append, both n-independent.
//!
//! All columns are sub-quadratic (the old O(n²) clone is gone). But inbound/op
//! is NOT flat — it climbs with ledger size: ~9 µs @10k → ~18 µs @100k → ~53 µs
//! @300k → ~84 µs @1M. The curve is noisy at this 2000-op batch (±~15 % run to
//! run) so the exact exponent is fuzzy — somewhere between O(log n) with large
//! constants and a mild super-log term; it is clearly NOT linear-or-worse (the
//! 300k→1M step is sublinear) and clearly NOT flat. The driver is the price of
//! O(1) clone via persistent structures: every op clones the state (Arc share),
//! then the single mutation must COW-copy an O(log n) path because the structure
//! is shared — so each op allocates ~log n B-tree nodes, and as the ~450 MB
//! working set blows past cache those node accesses become DRAM chases. A flat
//! HashMap has better locality but O(n) clone, which is what gave us O(n²) to
//! begin with. Operationally 84 µs/op ≈ 12k ops/s of headroom at 1M, far above
//! any real payment rate — routine ops on a large ledger are fine — but if this
//! ever needs to be flat, the lever is to stop cloning on the verify path (apply
//! in place + restore-on-reject) rather than to drop persistent structures.
//!
//! The SECOND scaling axis — #deposits, not history — is characterized by
//! `deposit_count_characterization` (below). `check_conformance`'s reserve check
//! reads `total_deposit_balance()` on every credit/onchain/transfer op. That
//! used to be an O(#deposits) fold; it is now an O(1) read of a cached running
//! total maintained by `apply_in_place` (see `LedgerState::total_deposit_balance`
//! the field). Before vs after:
//!
//! | deposits | deposit_open us/op | credit us/op (fold) | credit us/op (cached) |
//! |----------|--------------------|---------------------|-----------------------|
//! |    1,000 |        ~5          |          20         |          15           |
//! |   10,000 |        ~3          |          88         |          16           |
//! |  100,000 |        ~3          |       1,200         |          21           |
//!
//! With the fold, `credit us/op` was ~linear in #deposits (×13.6 per ×10) — at
//! 100k deposits a single credit cost ~1.2 ms (~830/s). With the cached total
//! it is flat (~15-21 µs; the mild rise is OrdMap cache effects, not the deposit
//! count), 57× faster at 100k. `deposit_open` stays flat (O(log d) insert) in
//! both. The cache is kept honest by a debug_assert in `apply_in_place` that
//! recomputes the fold and compares on every apply across the whole test suite.
//!
//! **1M entries is reachable**: ~3 s build, 2.3 s recompute, 24 s full
//! conformance re-import (was projected hours). Slightly higher constants than
//! the std-collection numbers — the price of O(1) clone — but the curve is the
//! point. The default target is small so this stays a quick smoke run; override
//! `LARGE_LEDGER_N`.
//!
//! Note: the `chainwalk` column reported a deceptive 0 ms before this harness
//! called `finalize_chain_hash()` after each append. `append_operation_with_block`
//! leaves `chain_tip_hash = content_hash`; production advances it to `chain_hash()`
//! once the operator signs. Without that step the chain links via content_hash
//! while `find_valid_chain_length` expects `chain_hash()`, so the walk bailed
//! after one entry. The harness now finalizes each update and asserts the walk
//! covers the whole history — so a broken chain can never again read as "0 ms".
//! (`find_valid_chain_length` itself was correct; this was a harness-only flaw.)

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
        .and_then(|s| {
            s.split_whitespace()
                .nth(1)
                .and_then(|p| p.parse::<u64>().ok())
        })
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
    // append_operation_with_block leaves chain_tip_hash = content_hash; prod
    // advances it to chain_hash() after the operator signs. The harness never
    // signs, so finalize explicitly — otherwise the chain links via content_hash
    // while find_valid_chain_length expects chain_hash(), and the walk bails
    // after one entry (a deceptive "0 ms").
    ledger.finalize_chain_hash();
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
                commitment: None,
            },
            0,
            [0u8; 32],
        )
        .expect("DepositOpen");
    ledger.finalize_chain_hash();

    println!(
        "\nlarge-ledger characterization: target={} checkpoints={:?}",
        target, checkpoints
    );
    println!(
        "{:>11}  {:>12}  {:>13}  {:>12}  {:>13}  {:>13}  {:>10}  {:>9}",
        "entries",
        "append us/op",
        "recompute ms",
        "inbound us/op",
        "reimport ms",
        "chainwalk ms",
        "binary MB",
        "RSS MB"
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
                        commitment: None,
                    },
                    0,
                    [0u8; 32],
                )
                .expect("InvoiceCredit append");
            ledger.finalize_chain_hash();
            i += 1;
        }
        let appended = (ledger.history.len() - prev_len).max(1);
        let per_op_us = t_append.elapsed().as_micros() as f64 / appended as f64;
        prev_len = ledger.history.len();

        // Full-replay cost (re-import / reconstruct pays this).
        let t_rc = Instant::now();
        ledger.recompute_state().expect("recompute_state");
        let recompute_ms = t_rc.elapsed().as_millis();

        // Re-import cost: replay the whole history through `apply_and_check`
        // (apply + conformance per op) — the joined-ledger re-import / watcher
        // path behind the stranded-quorum incident. Distinct from recompute:
        // it runs the conformance verifier on every op as a member would.
        let t_reimport = Instant::now();
        {
            use deposits_core::tlv::TlvDecode;
            let mut fresh = Ledger::new_as_operator(op, hex::encode(op.serialize()), 0);
            for update in &ledger.history {
                let inner =
                    LedgerOperation::tlv_decode(&update.message).expect("tlv_decode history op");
                fresh
                    .apply_and_check(&inner, update.block_height)
                    .expect("apply_and_check");
            }
        }
        let reimport_ms = t_reimport.elapsed().as_millis();

        // Routine inbound cost: the MARGINAL cost of applying one more op to a
        // ledger whose state is already this big. apply_inbound and
        // apply_updates_to_ledger both call `apply_and_check` (apply +
        // conformance) per op; that's the only n-dependent work in the routine
        // path. The node wrappers add, per op: an O(HISTORY_RETAIN=2000) dedup
        // scan over the *bounded* in-memory history (it's truncated to 2000) and
        // an O(new) incremental jsonl append — both independent of total ledger
        // size, so they don't appear here. Flat µs/op across sizes ⇒ touching a
        // large ledger live stays O(log n). Fresh 0xFF-prefixed payment hashes
        // so they never collide with the i-counter credits above; the next
        // checkpoint's recompute_state rebuilds state from history and discards
        // these, so they don't accumulate.
        const INBOUND_BATCH: u64 = 2000;
        let t_inbound = Instant::now();
        for j in 0..INBOUND_BATCH {
            let mut payment_hash = [0xFFu8; 32];
            payment_hash[..8].copy_from_slice(&j.to_le_bytes());
            ledger
                .apply_and_check(
                    &LedgerOperation::InvoiceCredit {
                        payment_hash,
                        deposit_id,
                        amount: 1,
                        invoice_id: format!("inb{}", j),
                        sequence_number: 0,
                        wallet_authorization: None,
                        commitment: None,
                    },
                    0,
                )
                .expect("inbound apply_and_check");
        }
        let inbound_us = t_inbound.elapsed().as_micros() as f64 / INBOUND_BATCH as f64;

        // Chain-continuity walk. Assert it covers the WHOLE history — a walk
        // that stops short means the chain is broken and the timing below is
        // measuring a partial walk, not a 1M-entry validation.
        let t_walk = Instant::now();
        let valid_len = deposits_core::ledger::LedgerValidator::find_valid_chain_length(&ledger);
        let walk_ms = t_walk.elapsed().as_millis();
        assert_eq!(
            valid_len,
            ledger.history.len(),
            "chain continuity broke at {} of {} — walk timing would be meaningless",
            valid_len,
            ledger.history.len()
        );

        // Serialized size.
        let bin_mb = ledger.export_binary(0).len() as f64 / 1e6;

        println!(
            "{:>11}  {:>12.3}  {:>13}  {:>12.3}  {:>13}  {:>13}  {:>10.1}  {:>9.0}",
            ledger.history.len(),
            per_op_us,
            recompute_ms,
            inbound_us,
            reimport_ms,
            walk_ms,
            bin_mb,
            rss_mb()
        );
    }
    println!();
}

/// The OTHER scaling axis: #deposits, not history length. `check_conformance`
/// computes `total_deposit_balance()` — a fold over EVERY deposit — on every
/// credit/onchain/transfer op, so the routine apply path is O(#deposits) per op
/// regardless of how short the history is. This grows the deposit count and
/// measures the marginal cost of one InvoiceCredit (via `apply_and_check`, the
/// routine path) at each size. We expect `credit us/op` to climb ~linearly with
/// #deposits while `deposit_open us/op` stays ~flat (O(log d) insert). Run:
///   LARGE_LEDGER_DEPOSITS=100000 cargo test --release -p deposits-core \
///       --test large_ledger deposit_count -- --ignored --nocapture
#[test]
#[ignore = "perf characterization; run explicitly with --release --ignored --nocapture"]
fn deposit_count_characterization() {
    let target: usize = std::env::var("LARGE_LEDGER_DEPOSITS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);

    let mut checkpoints: Vec<usize> = [1_000usize, 10_000, 100_000]
        .into_iter()
        .filter(|&c| c <= target)
        .collect();
    if !checkpoints.contains(&target) {
        checkpoints.push(target);
    }
    checkpoints.sort_unstable();

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
    ledger.finalize_chain_hash();

    println!(
        "\ndeposit-count characterization: target={} checkpoints={:?}",
        target, checkpoints
    );
    println!(
        "{:>11}  {:>16}  {:>13}  {:>9}",
        "deposits", "deposit_open us/op", "credit us/op", "RSS MB"
    );

    let mut opened: u64 = 0;
    let mut first_deposit_id: Option<_> = None;
    let mut credit_ctr: u64 = 0; // unique across checkpoints — state accumulates here
    let mut prev_len = ledger.state.deposits.len();
    for &cp in &checkpoints {
        // Open deposits (unique descriptor → unique deposit_id) until we hit cp.
        let t_open = Instant::now();
        while ledger.state.deposits.len() < cp {
            let descriptor = format!("deposit-{}", opened);
            let deposit_id = compute_deposit_id(&descriptor);
            if first_deposit_id.is_none() {
                first_deposit_id = Some(deposit_id);
            }
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
                        commitment: None,
                    },
                    0,
                    [0u8; 32],
                )
                .expect("DepositOpen");
            ledger.finalize_chain_hash();
            opened += 1;
        }
        let opened_now = (ledger.state.deposits.len() - prev_len).max(1);
        let open_us = t_open.elapsed().as_micros() as f64 / opened_now as f64;
        prev_len = ledger.state.deposits.len();

        // Marginal InvoiceCredit cost at this deposit count. Credits always land
        // on the same deposit; the cost we're isolating is conformance folding
        // total_deposit_balance() over all `cp` deposits. Unique payment hashes
        // (0xEE + global counter) since state accumulates across checkpoints.
        let did = first_deposit_id.unwrap();
        const CREDIT_BATCH: u64 = 2000;
        let t_credit = Instant::now();
        for _ in 0..CREDIT_BATCH {
            let mut payment_hash = [0xEEu8; 32];
            payment_hash[..8].copy_from_slice(&credit_ctr.to_le_bytes());
            credit_ctr += 1;
            ledger
                .apply_and_check(
                    &LedgerOperation::InvoiceCredit {
                        payment_hash,
                        deposit_id: did,
                        amount: 1,
                        invoice_id: format!("dc{}", credit_ctr),
                        sequence_number: 0,
                        wallet_authorization: None,
                        commitment: None,
                    },
                    0,
                )
                .expect("credit apply_and_check");
        }
        let credit_us = t_credit.elapsed().as_micros() as f64 / CREDIT_BATCH as f64;

        println!(
            "{:>11}  {:>16.3}  {:>13.3}  {:>9.0}",
            ledger.state.deposits.len(),
            open_us,
            credit_us,
            rss_mb()
        );
    }
    println!();
}
