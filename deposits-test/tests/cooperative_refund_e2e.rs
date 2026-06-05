//! Tier-3 end-to-end: cooperative refund anchors the lottery after the
//! reserves UTXO has been drained out to the disputants.
//!
//! Scenario:
//!   1. Mark every operator with `.pause_auto_dispute_actions` so the
//!      daemons publish DisputeEnter on a fork and then stop —
//!      no auto-arm, no auto-confiscate racing the manual flow.
//!   2. Fire a `QuorumExpired` fraud broadcast. Daemons fork, publish
//!      DisputeEnter, pause.
//!   3. Drain the disputed ledger's reserves UTXO via `reserves spend
//!      --split` into one P2WPKH output per quorum member. Each member
//!      now holds a fresh UTXO at their operator-key P2WPKH (the RC
//!      address shape RC4 enforces).
//!   4. Remove the pause markers — auto-arm fires, each disputant
//!      declares their freshly-received P2WPKH UTXO as their
//!      `replacement_collateral`. Auto-confiscate also fires but
//!      can't find the (now-spent) reserves UTXO and noisily retries
//!      — harmless to this test.
//!   5. Re-arm the pause markers (defense-in-depth) and run
//!      `deposits-node recovery refund <ledger_id>` from op0.
//!   6. op1 and op2 daemons handle `cooperative_refund_sign`
//!      requests, sign their inputs, reply.
//!   7. CLI assembles witnesses, broadcasts the cooperative TX.
//!   8. Verify: TX confirmed on-chain at the rebuilt lottery script.
//!
//! TEST PRECONDITIONS:
//!   - Cluster started: `./bin/setup.sh 3`
//!   - L1 quorum has expired (set up cluster with short --quorum-expiry,
//!     or mine ~1010 blocks past the QuorumBegin tx). Same precondition
//!     as the other QuorumExpired fraud tests.
//!
//! Not in the default `cargo test` pass — `#[ignore]`'d.

use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_protocol::fraud::{
    CausalLink, FraudBroadcast, FraudEvidence, FraudProof, FraudProofType, ProofEmbedding,
};
use deposits_test::regtest::*;
use std::process::Command;
use std::time::{Duration, Instant};

/// Op the disputed ledger belongs to (its operator).
const ACCUSED_OP: usize = 8;
/// Setup-state key for the ledger we'll dispute.
const SETUP_LEDGER_KEY: &str = "ledger_8_1";
/// How many op{N} directories to probe when resolving quorum-member
/// pubkeys back to op indices. Setup.sh seeds are deterministic, so
/// derivation by index is cheap; scan up to 32 to cover any reasonable
/// cluster shape.
const MAX_OP_PROBE: usize = 32;

#[test]
#[ignore]
fn cooperative_refund_drains_and_anchors_lottery() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();
    let accused_ledger = read_setup_state(SETUP_LEDGER_KEY);

    // Wait for the accused's daemon to ingest its own QuorumBegin
    // before reading membership. setup.sh's phase 4 prints "30 ok"
    // once QuorumBegin is published; the daemon then takes a beat
    // to apply it locally. Without this poll, immediate-after-setup
    // runs see an empty (or pre-QB) ledger file and panic.
    wait_for_quorum_begin(ACCUSED_OP, &accused_ledger, Duration::from_secs(30));

    // Resolve the actual quorum membership for this ledger to op indices.
    // The setup cluster may have more ops than the quorum size, so we
    // need the *real* member subset — that's whose daemons must pause,
    // sign the reserves drain, and respond to cooperative_refund_sign.
    let member_ops = resolve_member_ops(&accused_ledger, ACCUSED_OP);
    let q = member_ops.len();
    assert!(q >= 2, "ledger has Q={} quorum members — need ≥2", q);
    eprintln!(
        "[setup]   accused=op{}  ledger={}…  members=op{:?}",
        ACCUSED_OP,
        &accused_ledger[..16],
        member_ops
    );

    // ── 1. Set pause markers on every quorum-member op so DisputeEnter
    //       is the only auto-published step — no auto-arm, no
    //       auto-confiscate.
    let pause_paths: Vec<_> = member_ops
        .iter()
        .map(|i| op_data_dir(*i).join(".pause_auto_dispute_actions"))
        .collect();
    for p in &pause_paths {
        std::fs::write(p, b"cooperative_refund_e2e").expect("write pause marker");
    }
    let _cleanup = ScopeGuard(Box::new({
        let pause_paths = pause_paths.clone();
        move || {
            for p in &pause_paths {
                let _ = std::fs::remove_file(p);
            }
        }
    }));
    eprintln!("[pause]   placed .pause_auto_dispute_actions on {} ops", q);

    // ── 2. Trigger DisputeEnter via a QuorumExpired fraud broadcast.
    //       Mirrors the fraud_proof_quorum_expired setup.
    let history = read_ledger_history(&op_data_dir(ACCUSED_OP), &accused_ledger);

    let quorum_expiry = history
        .iter()
        .rev()
        .find_map(|u| {
            if let Ok(LedgerOperation::QuorumBegin { quorum_expiry, .. }) =
                LedgerOperation::tlv_decode(&u.message)
            {
                Some(quorum_expiry)
            } else {
                None
            }
        })
        .expect("accused ledger has no QuorumBegin");

    // Chain tip past quorum_expiry + grace is the test precondition
    // (the daemons' auto-dispute uses chain_tip > expiry + 720). On a
    // fresh cluster the chain hasn't been advanced; mine the required
    // delta, then wait for the accused's daemon to catch up.
    let chain_tip = current_block_height();
    let target = quorum_expiry + 720 + 80;
    if chain_tip < target {
        let to_mine = target - chain_tip;
        eprintln!("[setup]   mining {} blocks → tip {} (past expiry+grace)", to_mine, target);
        mine_blocks(to_mine);
        wait_for_daemon_chain_tip(ACCUSED_OP, target, std::time::Duration::from_secs(120));
    }
    let chain_tip = current_block_height();
    if chain_tip <= quorum_expiry {
        panic!(
            "TEST PRECONDITION not met: chain tip {}, quorum_expiry {}. \
             Mine more regtest blocks past QuorumBegin.",
            chain_tip, quorum_expiry
        );
    }
    let anchor_block_hash = get_block_hash(chain_tip);
    eprintln!(
        "[anchor]  chain tip {} > quorum_expiry {} (anchor={}…)",
        chain_tip,
        quorum_expiry,
        &hex::encode(anchor_block_hash)[..16]
    );

    // No fraud broadcast: each member daemon auto-detects its joined
    // ledger's expired quorum and publishes fork-branch DisputeEnter
    // on its own (the periodic dispute task drives this). With the
    // pause marker in place, auto-arm halts after DisputeEnter — the
    // exact state we want for the manual orchestration that follows.
    let _ = (anchor_block_hash, &history); // keep precondition vars referenced
    eprintln!("[dispute] relying on daemons' auto-detect to publish DisputeEnter");

    // Give the daemons time to receive the fraud, fork, publish
    // DisputeEnter, then halt at the pause marker.
    poll_until_fork_disputed(&accused_ledger, &member_ops, Duration::from_secs(90));
    eprintln!("[fork]    all {} ops have a fork with DisputeEnter", q);

    // ── 3. Drain reserves to Q P2WPKH outputs.
    // We pass every operator's secret key via --key (reserves spend
    // collects the Q tapscript signatures itself), and use --split
    // <p2wpkh>:<sats> to route Q chunks to the disputants' op-key
    // addresses. The positional dest_address gets the remainder.
    let drain_per_op: u64 = 12_000_000; // 0.12 BTC; reserves is 0.4 BTC
    let driver_op = member_ops[0];
    let mut spend_args: Vec<String> = vec![
        "reserves".to_string(),
        "spend".to_string(),
        op_p2wpkh_address(driver_op).to_string(), // change destination
        "--ledger".to_string(),
        accused_ledger.clone(),
        "--fee-rate".to_string(),
        "2".to_string(),
    ];
    // Every quorum member's operator key is needed to sign the tapscript
    // recovery path — reserves spend handles the assembly. Pass each as
    // hex via --key.
    for &op_idx in &member_ops {
        let sk = op_operator_secret(op_idx);
        spend_args.push("--key".to_string());
        spend_args.push(hex::encode(sk.secret_bytes()));
    }
    // Each member gets a P2WPKH output sized for their RC declaration.
    for &op_idx in &member_ops {
        spend_args.push("--split".to_string());
        spend_args.push(format!(
            "{}:{}",
            op_p2wpkh_address(op_idx),
            drain_per_op
        ));
    }

    let out = Command::new(&node)
        .args(&spend_args)
        .args(["--seed", &op_seed(driver_op)])
        .args(["--name", &format!("op{}", driver_op)])
        .args(["--network", "regtest"])
        .args(["--data-dir", op_data_dir(driver_op).to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("spawn reserves spend");
    if !out.status.success() {
        panic!(
            "reserves spend failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let drain_stdout = String::from_utf8_lossy(&out.stdout).to_string();
    eprintln!("[drain]   reserves spend ok");

    // Mine to confirm the drain so auto-arm sees the new RC UTXOs.
    mine_blocks(3);

    // ── 4. Lift the pause briefly so auto-arm fires with the new
    //       RC UTXOs in-wallet, then re-arm the markers before
    //       cooperative refund (defense-in-depth).
    for p in &pause_paths {
        let _ = std::fs::remove_file(p);
    }
    eprintln!("[pause]   markers removed; awaiting auto-arm to declare RC");

    let expected_armed = member_ops
        .iter()
        .filter(|&&op| op != ACCUSED_OP)
        .count();
    poll_until_armed_with_rc(
        &accused_ledger,
        &member_ops,
        expected_armed,
        Duration::from_secs(120),
    );
    eprintln!(
        "[arm]     {} disputants armed with replacement_collateral",
        expected_armed
    );

    for p in &pause_paths {
        std::fs::write(p, b"cooperative_refund_e2e/post-arm").expect("re-pause");
    }
    eprintln!("[pause]   re-armed pause markers; running cooperative refund");

    // ── 5. Run `recovery refund` from the driver op.
    let out = Command::new(&node)
        .args(["recovery", "refund", &accused_ledger])
        .args(["--timeout", "90"])
        .args(["--seed", &op_seed(driver_op)])
        .args(["--name", &format!("op{}", driver_op)])
        .args(["--network", "regtest"])
        .args(["--data-dir", op_data_dir(driver_op).to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("spawn recovery refund");
    let refund_stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let refund_stderr = String::from_utf8_lossy(&out.stderr).to_string();
    eprintln!("[refund stdout]\n{}", refund_stdout);
    eprintln!("[refund stderr]\n{}", refund_stderr);
    assert!(
        out.status.success(),
        "recovery refund failed (status={:?})",
        out.status.code()
    );

    // CLI prints "Cooperative refund TX broadcast: <txid>" on success.
    let txid_line = refund_stdout
        .lines()
        .find(|l| l.contains("Cooperative refund TX broadcast"))
        .unwrap_or_else(|| {
            panic!(
                "recovery refund output missing 'Cooperative refund TX \
                 broadcast' marker. stdout was:\n{}",
                refund_stdout
            )
        });
    let txid_hex = txid_line
        .split(':')
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    assert_eq!(
        txid_hex.len(),
        64,
        "expected 64-char txid in: {}",
        txid_line
    );
    eprintln!("[txid]    cooperative refund: {}", txid_hex);

    // ── 6. Confirm on-chain and verify the TX has the expected shape.
    mine_blocks(3);
    let drain_txid = drain_stdout
        .lines()
        .find_map(|l| {
            // `reserves spend` prints "Broadcast successful: <txid>"
            // or similar — fall through if we can't find it.
            if l.to_lowercase().contains("txid") || l.to_lowercase().contains("broadcast") {
                l.split_whitespace()
                    .find(|w| w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()))
                    .map(|s| s.to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();
    let _ = drain_txid; // logged, not asserted on

    let confirmed = poll_tx_confirmed(&txid_hex, Duration::from_secs(60));
    assert!(
        confirmed,
        "cooperative refund TX {} did not confirm within 60s",
        txid_hex
    );
    eprintln!("[ok]      cooperative refund TX confirmed on-chain");
}

// ─────────────────────────────────────────────────────────────────────
// Local helpers (kept inline rather than in regtest.rs since they're
// specific to the post-DisputeEnter pause shape).
// ─────────────────────────────────────────────────────────────────────

struct ScopeGuard(Box<dyn FnMut()>);
impl Drop for ScopeGuard {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// Poll the given ops' wallet dirs for a fork-branch file matching
/// `ledger_id`; return once every one of them has a fork.
fn poll_until_fork_disputed(ledger_id: &str, ops: &[usize], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let mut have_fork = 0;
        for &op_idx in ops {
            let ledgers_dir = op_data_dir(op_idx).join("wallet/ledgers");
            let entries = match std::fs::read_dir(&ledgers_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(ledger_id)
                    && name.ends_with(".jsonl")
                    && name.len() > ledger_id.len() + 6
                {
                    have_fork += 1;
                    break;
                }
            }
        }
        if have_fork >= ops.len() {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {} forks; have {}",
                ops.len(),
                have_fork
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Poll until at least `min_count` of the given ops have a
/// DisputeArmed with a populated `replacement_collateral` on their
/// fork branch.
fn poll_until_armed_with_rc(
    ledger_id: &str,
    ops: &[usize],
    min_count: usize,
    timeout: Duration,
) {
    use deposits_core::SignedLedgerUpdate;
    let deadline = Instant::now() + timeout;
    loop {
        let mut armed_with_rc = 0;
        for &op_idx in ops {
            let ledgers_dir = op_data_dir(op_idx).join("wallet/ledgers");
            let entries = match std::fs::read_dir(&ledgers_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            'op: for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with(ledger_id) || !name.ends_with(".jsonl") {
                    continue;
                }
                let content = match std::fs::read_to_string(entry.path()) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                for line in content.lines() {
                    let mut v: serde_json::Value = match serde_json::from_str(line) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if v.get("type").and_then(|t| t.as_str()) != Some("Update") {
                        continue;
                    }
                    if let Some(obj) = v.as_object_mut() {
                        obj.remove("type");
                    }
                    if let Ok(upd) = serde_json::from_value::<SignedLedgerUpdate>(v) {
                        if let Ok(LedgerOperation::DisputeArmed {
                            replacement_collateral: Some(_),
                            ..
                        }) = LedgerOperation::tlv_decode(&upd.message)
                        {
                            armed_with_rc += 1;
                            break 'op;
                        }
                    }
                }
            }
        }
        if armed_with_rc >= min_count {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {} armed-with-RC; have {}",
                min_count, armed_with_rc
            );
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// Walk the accused op's ledger jsonl, decode each Update row's TLV
/// message, and pull `quorum_members` from the most recent
/// QuorumBegin. State-row snapshots can be stale (the daemon writes
/// them on a schedule that may pre-date QuorumBegin), so trust the
/// Update history directly.
fn resolve_member_ops(ledger_id: &str, accused_op: usize) -> Vec<usize> {
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    use deposits_core::SignedLedgerUpdate;

    let path = op_data_dir(accused_op)
        .join("wallet/ledgers")
        .join(format!("{}.jsonl", ledger_id));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));

    // SignedLedgerUpdate rows are flat — serde uses `#[serde(tag = "type")]`
    // on the LedgerLogRow enum, so the SignedLedgerUpdate fields sit
    // alongside `"type":"Update"` on the same JSON object. Strip the
    // `type` and deserialize directly. Walk newest→oldest and stop at
    // the first QuorumBegin.
    let mut member_pks_bytes: Vec<Vec<u8>> = Vec::new();
    for line in content.lines().rev() {
        let mut v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("type").and_then(|t| t.as_str()) != Some("Update") {
            continue;
        }
        if let Some(obj) = v.as_object_mut() {
            obj.remove("type");
        }
        let upd: SignedLedgerUpdate = match serde_json::from_value(v) {
            Ok(u) => u,
            Err(_) => continue,
        };
        if let Ok(LedgerOperation::QuorumBegin { quorum_members, .. }) =
            LedgerOperation::tlv_decode(&upd.message)
        {
            for m in &quorum_members {
                member_pks_bytes.push(m.pubkey.serialize().to_vec());
            }
            break; // most recent first (reverse iter)
        }
    }
    assert!(
        !member_pks_bytes.is_empty(),
        "no QuorumBegin found in {} — ledger may not have activated its quorum",
        path.display()
    );

    // Build idx → pubkey map for candidate ops, then look up each
    // member.
    let secp = Secp256k1::new();
    let mut idx_by_pk: std::collections::HashMap<[u8; 33], usize> =
        std::collections::HashMap::new();
    for i in 0..MAX_OP_PROBE {
        if !op_data_dir(i).exists() {
            break;
        }
        let sk = op_operator_secret(i);
        let pk = PublicKey::from_secret_key(&secp, &sk);
        idx_by_pk.insert(pk.serialize(), i);
    }

    let mut result = Vec::new();
    for pk_bytes in &member_pks_bytes {
        let mut key = [0u8; 33];
        key.copy_from_slice(pk_bytes);
        match idx_by_pk.get(&key) {
            Some(&i) => result.push(i),
            None => panic!(
                "quorum member pubkey {} does not match any op{{0..{}}} \
                 — cluster shape unknown",
                hex::encode(&key[..8]),
                MAX_OP_PROBE
            ),
        }
    }
    result.sort();
    result
}

/// Poll bitcoind for `txid` until it's in a block.
fn poll_tx_confirmed(txid_hex: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let out = Command::new("docker")
            .args([
                "exec",
                "bitcoind",
                "bitcoin-cli",
                "-regtest",
                "-rpcuser=user",
                "-rpcpassword=pass",
                "getrawtransaction",
                txid_hex,
                "true",
            ])
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                let stdout = String::from_utf8_lossy(&o.stdout);
                if stdout.contains("\"confirmations\"") {
                    return true;
                }
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}
