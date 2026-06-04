//! Tier-3: end-to-end auto-dispute when a quorum's expiry passes.
//!
//! The proper QuorumExpired-in-DisputeEnter path. No external kind:9101
//! fraud broadcast, no `recovery start`, no manual trigger of any kind —
//! daemons that observe `current_block > quorum_expiry` on a ledger
//! they cosign for fire `auto_dispute_expired_quorums` themselves,
//! commit a fork-branch `DisputeEnter` carrying inline anchor evidence
//! (`anchor_block_hash` + `anchor_block_height`), and other members
//! verify and arm.
//!
//! Pipeline asserted end-to-end:
//!
//!   1. Mine enough regtest blocks to push the chain past op0's
//!      ledger's `quorum_expiry`.
//!   2. Wait for at least one cosigner's periodic to fire
//!      `auto_dispute_expired_quorums` and write a fork compound-key
//!      JSONL. Verify the `DisputeEnter` op inside has both
//!      `anchor_block_hash` and `anchor_block_height` set, with
//!      `anchor_block_height > quorum_expiry`.
//!   3. Wait for at least 2 cosigners to arm (Q=3 majority threshold).
//!   4. Wait for the confiscation tx to broadcast and confirm
//!      (`confiscated_<prefix>.marker` appears on some op's data dir).
//!
//! Tier-3 (cluster + danger feature). Skipped by default per the
//! project convention. Cluster must have:
//!   - Q=3 (`./bin/setup.sh 3`)
//!   - cosigners' op-key P2WPKH addresses funded (see the
//!     `funding-precondition doc` in `dispute_fork_shape.rs`)
//!
//! Requires the cluster's quorum_expiry to be reachable by mining a
//! reasonable number of blocks. With setup.sh's default
//! `quorum_expiry = current_block + 1000`, this test mines ~1010
//! blocks. On a freshly-set-up regtest cluster that takes <5s.

use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_test::regtest::*;
use std::time::{Duration, Instant};

#[test]
#[ignore]
fn auto_dispute_fires_when_quorum_expires() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let _node = build_node_with_danger();
    let ledger = discover_op0_ledger();
    eprintln!("[setup] op0 ledger: {}…", &ledger[..16]);

    // ── 1. Read the ledger's quorum_expiry from history ──
    let history = read_ledger_history(&op0_data_dir(), &ledger);
    let mut quorum_expiry: Option<u32> = None;
    for u in history.iter().rev() {
        if let Ok(LedgerOperation::QuorumBegin {
            quorum_expiry: e, ..
        }) = LedgerOperation::tlv_decode(&u.message)
        {
            quorum_expiry = Some(e);
            break;
        }
    }
    let quorum_expiry = quorum_expiry.expect("op0's ledger has no QuorumBegin");
    eprintln!("[setup] quorum_expiry = {}", quorum_expiry);

    // ── 2a. Fund every operator's op-key P2WPKH address ──
    // auto_arm_for_dispute looks for a UTXO at the operator-key P2WPKH
    // (not the per-ledger BDK address) to declare as replacement
    // collateral. setup.sh doesn't fund these; without funding,
    // cosigners refuse to sign the confiscation tx. 10k sats per op is
    // well above the obligations × collateral/reserves floor for this
    // cluster. See `dispute_fork_shape.rs` precondition doc.
    eprintln!("[fund]  funding 10 operators' op-key P2WPKH addresses (10k sats each)");
    for op_idx in 0..10 {
        let _txid = fund_operator_key_address(op_idx, 10_000);
    }

    // ── 2b. Mine past the auto-dispute grace window ──
    // Production daemons hold off auto-dispute for
    // `DEPOSITS_AUTO_DISPUTE_GRACE_BLOCKS` (default 720) past
    // `quorum_expiry`, to give the operator the post-expiry Tier-0
    // window to self-rescue via `quorum repair` before partner
    // cosigners race to confiscate (see deposits-node/src/node/dispute.rs
    // ::DEFAULT_GRACE_BLOCKS). The test was originally written with
    // `+100` blocks past expiry — fine before the grace period landed,
    // a guaranteed timeout afterward. `+800` clears the grace window
    // with a comfortable 80-block margin. On a fresh chain that's
    // ~30s of additional mining; on an old/bloated chain it's
    // proportionally slower but still finite.
    let current_height = current_block_height();
    let target = quorum_expiry + 720 + 80;
    let to_mine = if current_height >= target {
        100
    } else {
        (target - current_height).max(100)
    };
    eprintln!(
        "[mine]  current={} expiry={} target={} → mining {} blocks",
        current_height, quorum_expiry, target, to_mine
    );
    mine_blocks(to_mine);
    // Wait for cosigner daemons to catch up. With +800 blocks and the
    // typical fast-poll interval, fixed-sleep was too short. Poll
    // every daemon's chain_tip via /api/lifecycle until they're past
    // the target.
    for op_idx in 0..10 {
        wait_for_daemon_chain_tip(op_idx, target, Duration::from_secs(120));
    }

    // ── 3. Wait for fork-branch DisputeEnter to appear on some op's
    //       data dir, carrying valid anchor evidence ──
    let prefix = &ledger[..16];
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut observed_fork: Option<(usize, std::path::PathBuf)> = None;
    while Instant::now() < deadline {
        for op_idx in 0..10 {
            let ledgers_dir = op_data_dir(op_idx).join("wallet/ledgers");
            let Ok(entries) = std::fs::read_dir(&ledgers_dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(&ledger[..])
                    && name.ends_with(".jsonl")
                    && name.len() == ledger.len() + 1 + 6 + 1 + 16 + ".jsonl".len()
                {
                    // Found a fork compound-key file. Open it and look
                    // for a DisputeEnter with anchor fields.
                    let stem = entry.path().file_stem().unwrap().to_string_lossy().into_owned();
                    let h = read_ledger_history(&op_data_dir(op_idx), &stem);
                    for u in &h {
                        if let Ok(LedgerOperation::DisputeEnter {
                            anchor_block_hash: Some(_),
                            anchor_block_height: Some(_),
                            ..
                        }) = LedgerOperation::tlv_decode(&u.message)
                        {
                            observed_fork = Some((op_idx, entry.path()));
                            break;
                        }
                    }
                    if observed_fork.is_some() {
                        break;
                    }
                }
            }
            if observed_fork.is_some() {
                break;
            }
        }
        if observed_fork.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    let (op_idx, fork_path) = observed_fork.expect(
        "no auto-fired fork-branch DisputeEnter with anchor evidence \
         appeared within 120s — `auto_dispute_expired_quorums` didn't fire \
         or block oracle disagreed",
    );
    eprintln!(
        "[ok]    fork-branch DisputeEnter on op{}: {}",
        op_idx,
        fork_path.display()
    );

    // ── 4. Verify the anchor fields satisfy our invariants ──
    let stem = fork_path.file_stem().unwrap().to_string_lossy().into_owned();
    let fork_history = read_ledger_history(&op_data_dir(op_idx), &stem);
    let dispute_enter = fork_history
        .iter()
        .find_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(op @ LedgerOperation::DisputeEnter { .. }) => Some(op),
            _ => None,
        })
        .expect("fork has DisputeEnter (we just matched it)");
    let LedgerOperation::DisputeEnter {
        anchor_block_hash,
        anchor_block_height,
        last_valid_sequence,
        reason,
        ..
    } = dispute_enter
    else {
        unreachable!()
    };
    let anchor_height = anchor_block_height.expect("anchor_block_height set");
    let anchor_hash = anchor_block_hash.expect("anchor_block_hash set");
    assert!(
        anchor_height > quorum_expiry,
        "anchor_block_height {} does not exceed quorum_expiry {}",
        anchor_height,
        quorum_expiry
    );
    assert_eq!(
        reason, "quorum_expired",
        "expected reason='quorum_expired', got {:?}",
        reason
    );
    eprintln!(
        "[ok]    anchor: hash={}… height={} > quorum_expiry={} (last_valid_seq={})",
        &hex::encode(anchor_hash)[..16],
        anchor_height,
        quorum_expiry,
        last_valid_sequence
    );

    // ── 5. Wait for confiscation marker (full pipeline) ──
    let marker_name = format!("confiscated_{}.marker", prefix);
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline {
        for op in 0..10 {
            if op_data_dir(op).join(&marker_name).exists() {
                eprintln!(
                    "[ok]    confiscation completed: marker at op{}/{}",
                    op, marker_name
                );
                return;
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    panic!(
        "no `{}` marker on any op's data dir within 180s — \
         auto-arm fired but confiscation pipeline didn't complete",
        marker_name
    );
}
