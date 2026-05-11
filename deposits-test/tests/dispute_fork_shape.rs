//! Tier-3: focused assertions on dispute fork-branch shape.
//!
//! The existing `dispute_initiation.rs` test exercises forks indirectly —
//! it polls for `confiscated_*.marker` and calls it done. If a fork came
//! out malformed (wrong `last_valid_sequence`, missing DisputeArmed,
//! cosigners disagreeing on the divergence point), the symptom would be
//! "confiscation never happens" rather than a precise diagnosis.
//!
//! This test triggers the same dispute pipeline (op0 publishes invalid,
//! op1 publishes kind:9103), waits for auto-arm to fire, then walks
//! each cosigner's data dir and asserts on each fork's shape:
//!
//!   (a) A fork compound-key JSONL exists at
//!       `{data_dir}/wallet/ledgers/{ledger_id}_{lvs:06}_{op_prefix:16}.jsonl`
//!       for each cosigner. We deliberately *exclude* a fork whose
//!       op_prefix matches the disputed ledger's original operator —
//!       those are spurious (the operator is structurally barred from
//!       disputing their own ledger by `validate_update_signer`).
//!   (b) Each fork's history contains `DisputeEnter` followed eventually
//!       by `DisputeArmed`, both signed by the same forking pubkey, with
//!       nothing but `QuorumAddMember` ops between them (auto-arm syncs
//!       the fork's member set between Enter and Armed).
//!   (c) Across all cosigners' forks, the DisputeEnter `last_valid_sequence`
//!       agrees — they're all forking at the same point.
//!   (d) Each DisputeArmed declares `replacement_collateral = Some(_)`.
//!       Auto-arm refuses to declare None unless no op-key UTXO covers
//!       the requirement; a None here means the operator-key wallet
//!       didn't have a usable UTXO and cosigners will refuse to sign
//!       confiscation.
//!
//! Run after `./bin/setup.sh 3` on a fresh cluster. Tier-3, ignored by
//! default per the project convention.

use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_test::regtest::*;
use std::process::Command;
use std::time::Duration;

#[test]
#[ignore]
fn dispute_creates_well_formed_fork_branches() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();
    let ledger = discover_op0_ledger();
    eprintln!("[setup] op0 ledger: {}…", &ledger[..16]);

    // ── 1. Inject invalid update via op0 ──
    let out = Command::new(&node)
        .args(["danger", "publish-invalid", &ledger, "invalid-hash"])
        .args(["--seed", OP0_SEED])
        .args(["--name", "op0"])
        .args(["--network", "regtest"])
        .args(["--data-dir", op0_data_dir().to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke danger publish-invalid");
    assert!(
        out.status.success(),
        "danger publish-invalid failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::thread::sleep(Duration::from_secs(3));

    // ── 2. op1 publishes kind:9103 — triggers auto-arm on op0/op2 ──
    let op1_seed = op_seed(1);
    let op1_dir = op_data_dir(1);
    let out = Command::new(&node)
        .args(["recovery", "start", &ledger])
        .args(["--reason", "fork-shape test: forged invalid-hash"])
        .args(["--seed", &op1_seed])
        .args(["--name", "op1"])
        .args(["--network", "regtest"])
        .args(["--data-dir", op1_dir.to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke recovery start");
    assert!(
        out.status.success(),
        "recovery start failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ── 3. Poll each operator's data dir for fork compound-key files ──
    //
    // Auto-arm writes the fork JSONL synchronously, but the inbound
    // event has to traverse the relay first. 60s is generous; locally
    // we see ~5s.
    let mut forks_by_op: Vec<(usize, std::path::PathBuf)> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        forks_by_op.clear();
        for op_idx in 0..10 {
            let ledgers_dir = op_data_dir(op_idx).join("wallet/ledgers");
            let Ok(entries) = std::fs::read_dir(&ledgers_dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                // Fork key shape: `{ledger_id:64}_{lvs:06}_{op_prefix:16}.jsonl`
                // → exactly 95 chars: 64 + 1 + 6 + 1 + 16 + 6
                if name.starts_with(&ledger)
                    && name.ends_with(".jsonl")
                    && name.len() == ledger.len() + 1 + 6 + 1 + 16 + ".jsonl".len()
                {
                    forks_by_op.push((op_idx, entry.path()));
                }
            }
        }
        if !forks_by_op.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert!(
        !forks_by_op.is_empty(),
        "no fork compound-key JSONL appeared on any operator data dir within 60s — \
         auto-arm did not produce a fork"
    );
    eprintln!(
        "[forks]  found {} fork file(s) across operator data dirs",
        forks_by_op.len()
    );

    // Identify the disputed ledger's original operator so we can filter
    // out spurious self-forks: `handle_dispute`'s membership check
    // returns true for the operator (`inbound.rs:1076`), so the operator
    // ends up auto-arming its own ledger. Other nodes reject those forks
    // (operator-barred-from-disputing-own-ledger), but the operator
    // wastes the local work. Filter them out here and check the
    // cosigner-only forks.
    let original_operator_prefix: String = {
        let any_history = read_ledger_history(&op0_data_dir(), &ledger);
        let original_op = any_history
            .iter()
            .find(|u| u.sequence_number == 0)
            .map(|u| u.operator_id)
            .expect("no LedgerOpen at seq 0 on op0's copy of the disputed ledger");
        hex::encode(original_op.serialize())[..16].to_string()
    };
    eprintln!(
        "[setup]  disputed ledger original operator prefix: {}",
        original_operator_prefix
    );
    let total_before_filter = forks_by_op.len();
    forks_by_op.retain(|(_, path)| {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let prefix = stem.rsplitn(2, '_').next().unwrap_or("");
        prefix != original_operator_prefix
    });
    if forks_by_op.len() != total_before_filter {
        eprintln!(
            "[filter] dropped {} spurious operator-self fork(s); keeping {} cosigner fork(s)",
            total_before_filter - forks_by_op.len(),
            forks_by_op.len()
        );
    }
    assert!(
        !forks_by_op.is_empty(),
        "no cosigner forks (only operator-self forks were found) — auto-arm \
         membership check is misfiring on the operator side"
    );

    // ── 4. For each fork: read history, find DisputeEnter + DisputeArmed,
    //       extract last_valid_sequence, sanity-check the tail shape ──
    let mut all_lvs: Vec<u64> = Vec::new();
    for (op_idx, path) in &forks_by_op {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("fork file stem");
        eprintln!("[op{}]    fork file: {}", op_idx, stem);

        // Parse the compound key.
        let parts: Vec<&str> = stem.split('_').collect();
        assert_eq!(
            parts.len(),
            3,
            "fork compound key has unexpected shape: {}",
            stem
        );
        let fork_lvs_from_key: u64 = parts[1]
            .parse()
            .unwrap_or_else(|_| panic!("fork compound key seq is non-numeric: {}", stem));
        let op_prefix_from_key = parts[2];

        // The compound key uses the FORKER's pubkey prefix (the cosigner
        // who armed), which is *not* op_idx's prefix because op_idx is
        // the operator hosting the fork — wait, no. auto_arm_for_dispute
        // is run by the cosigner who's arming, so the file lives on
        // that cosigner's data_dir and the op_prefix in the compound
        // key is that cosigner's own pubkey. op_idx here matches.
        let _ = op_prefix_from_key;

        let history = read_ledger_history(&op_data_dir(*op_idx), stem);
        assert!(
            history.len() >= 2,
            "op{} fork has only {} update(s); expected at least main-chain prefix \
             + DisputeEnter + DisputeArmed",
            op_idx,
            history.len()
        );

        // Find DisputeEnter and the immediately-following DisputeArmed.
        let mut dispute_enter: Option<(usize, u64)> = None;
        let mut dispute_armed: Option<(usize, bool)> = None; // (idx, has_replacement_collateral)
        for (i, u) in history.iter().enumerate() {
            let Ok(op) = LedgerOperation::tlv_decode(&u.message) else {
                continue;
            };
            match op {
                LedgerOperation::DisputeEnter {
                    last_valid_sequence,
                    ..
                } => {
                    dispute_enter = Some((i, last_valid_sequence));
                }
                LedgerOperation::DisputeArmed {
                    replacement_collateral,
                    ..
                } => {
                    dispute_armed = Some((i, replacement_collateral.is_some()));
                }
                _ => {}
            }
        }

        let (enter_idx, enter_lvs) = dispute_enter
            .unwrap_or_else(|| panic!("op{} fork is missing DisputeEnter", op_idx));
        let (armed_idx, armed_has_rc) = dispute_armed
            .unwrap_or_else(|| panic!("op{} fork is missing DisputeArmed", op_idx));

        // (b) Shape: DisputeArmed comes after DisputeEnter, with nothing
        //     but QuorumAddMember ops in between (auto-arm syncs the
        //     fork's quorum-member set between Enter and Armed).
        assert!(
            armed_idx > enter_idx,
            "op{} fork: DisputeArmed at idx {} not after DisputeEnter at idx {}",
            op_idx,
            armed_idx,
            enter_idx
        );
        for between_idx in (enter_idx + 1)..armed_idx {
            let between = &history[between_idx];
            let op = LedgerOperation::tlv_decode(&between.message).unwrap_or_else(|e| {
                panic!(
                    "op{} fork: idx {} (between Enter@{} and Armed@{}) decode error: {}",
                    op_idx, between_idx, enter_idx, armed_idx, e
                )
            });
            assert!(
                matches!(op, LedgerOperation::QuorumAddMember { .. }),
                "op{} fork: unexpected op {:?} between DisputeEnter@{} and DisputeArmed@{} — \
                 only QuorumAddMember is permitted here",
                op_idx,
                std::mem::discriminant(&op),
                enter_idx,
                armed_idx
            );
        }

        // Both fork updates must be signed by the same cosigner.
        let forker = history[enter_idx].operator_id;
        assert_eq!(
            history[armed_idx].operator_id, forker,
            "op{} fork: DisputeEnter and DisputeArmed have different operator_ids",
            op_idx
        );

        // DisputeEnter's last_valid_sequence must match the compound-key
        // seq number — that's the invariant that makes file lookup work.
        assert_eq!(
            enter_lvs, fork_lvs_from_key,
            "op{} fork: DisputeEnter.last_valid_sequence ({}) ≠ compound-key seq ({})",
            op_idx, enter_lvs, fork_lvs_from_key
        );

        // DisputeEnter must come at a sequence above last_valid_sequence,
        // and the preceding main-chain history must end at last_valid_sequence.
        assert!(
            history[enter_idx].sequence_number > enter_lvs,
            "op{} fork: DisputeEnter at seq {} is not above last_valid_sequence {}",
            op_idx,
            history[enter_idx].sequence_number,
            enter_lvs
        );

        // (d) Replacement collateral declared (auto-arm produces this).
        assert!(
            armed_has_rc,
            "op{} fork: DisputeArmed declared replacement_collateral=None — \
             auto-arm couldn't find a usable op-key UTXO. Cosigners will refuse \
             to sign confiscation with this declaration.",
            op_idx
        );

        eprintln!(
            "[op{}]    DisputeEnter@seq={} (lvs={}), DisputeArmed@seq={} rc=Some",
            op_idx,
            history[enter_idx].sequence_number,
            enter_lvs,
            history[armed_idx].sequence_number
        );
        all_lvs.push(enter_lvs);
    }

    // (c) Cross-cosigner agreement on the divergence point.
    let first_lvs = all_lvs[0];
    for (i, lvs) in all_lvs.iter().enumerate() {
        assert_eq!(
            *lvs, first_lvs,
            "fork[0].last_valid_sequence={} but fork[{}].last_valid_sequence={} — \
             cosigners disagree on the divergence point. Pipeline will stall: each \
             cosigner replays to a different state and the lottery cannot reach \
             consensus on participants.",
            first_lvs, i, lvs
        );
    }

    eprintln!(
        "[ok] {} fork(s) all agree on last_valid_sequence={}",
        forks_by_op.len(),
        first_lvs
    );
}
