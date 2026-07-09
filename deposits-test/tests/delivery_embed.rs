//! Integration test: DEP-12 wallet → quorum-member delivery_embed transport.
//!
//! Flow:
//!   1. Discover op0's ledger and pubkey, op1's ledger.
//!   2. Generate a synthetic 32-byte request_hash (the wallet's "I asked
//!      op0 for X but they ignored me" hash).
//!   3. `deposits-wallet escalate --member-ledger <op1>
//!      --request-hash <h> --target-ledger <op0> --target-operator <op0_pk>`
//!   4. Read op1's ledger JSONL and look for a fresh DeliveryEmbed update
//!      whose `request_hash`, `target_ledger_id`, `target_operator` match
//!      what the wallet sent.
//!
//! What this verifies:
//!   - The wallet's `escalate` CLI generates a well-formed Kind 20101
//!     request and routes it to the right member node.
//!   - The member's `process_delivery_embed_request` handler parses
//!     params, builds `LedgerOperation::DeliveryEmbed`, and commits via
//!     `commit_operation` (signing + persisting + broadcasting).
//!   - The member's ledger picks up the embed at the next sequence.
//!
//! What this does NOT verify (separate concerns):
//!   - Payment/pricing. The handler accepts the embed unconditionally
//!     today; a future commit can gate on a payment_commitment param.
//!   - Operator co-signing the post-embed member ledger update (the
//!     causal entanglement that makes this evidence). That happens in
//!     the normal cosig flow once op0 signs op1's next update; the
//!     embed itself is what this test pins.
//!
//! Requires:
//!   ./bin/setup.sh 3
//!
//! Run with:
//!   cargo test -p deposits-test --test delivery_embed -- --ignored

use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::tlv::TlvDecode;
use deposits_test::regtest::*;
use std::process::Command;
use std::time::{Duration, Instant};

fn discover_ledger_for_operator(name: &str) -> (String, String) {
    let scratch = tempdir();
    let out = Command::new(wallet_bin())
        .args(["discover", "--json"])
        .args(["--relay", relay_ledgers()])
        .args(["--network", "regtest"])
        .args(["--data-dir", scratch.to_str().unwrap()])
        .output()
        .expect("discover failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("type").and_then(|x| x.as_str()) == Some("ledger")
            && v.get("operator_name").and_then(|x| x.as_str()) == Some(name)
        {
            let ledger = v
                .get("ledger_id")
                .and_then(|x| x.as_str())
                .expect("ledger_id field")
                .to_string();
            let pubkey = v
                .get("operator_pubkey")
                .and_then(|x| x.as_str())
                .expect("operator_pubkey field")
                .to_string();
            return (ledger, pubkey);
        }
    }
    panic!("couldn't find a ledger owned by {}", name);
}

#[test]
#[ignore]
fn wallet_escalate_lands_delivery_embed_on_member_ledger() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    // ── 1. Pick a clean+healthy+undisputed ledger to embed on.
    //      Once a peer auto-disputes the member's ledger, the member's
    //      cosign round for the new DeliveryEmbed times out (peers
    //      won't ingest new updates past their dispute-fork sequence).
    //      Then pick any *other* op via discover as the target the
    //      wallet is "escalating against" (only its pubkey + ledger_id
    //      are referenced in the embed payload — target doesn't need
    //      to be healthy). ───────────────────────────────────────────
    let (member_op_idx, member_ledger) = match find_clean_healthy_setup_ledger(100) {
        Some(p) => p,
        None => {
            eprintln!(
                "skipping: no clean+healthy+undisputed setup ledger available — \
                 rerun against `setup.sh --fresh 3`."
            );
            return;
        }
    };
    // The hub cluster advertises operators as `node{i}` (not `op{i}`);
    // pick a different node than the member as the complaint target.
    let target_op_name = if member_op_idx == 0 { op_name(1) } else { op_name(0) };
    let (target_ledger, target_pubkey) = discover_ledger_for_operator(&target_op_name);
    eprintln!("[setup] target ({}) ledger: {}…", target_op_name, &target_ledger[..16]);
    eprintln!("[setup] target pubkey: {}…", &target_pubkey[..16]);
    eprintln!(
        "[setup] member (op{}) ledger (embed target): {}…",
        member_op_idx,
        &member_ledger[..16]
    );

    // Keep the legacy names so the rest of the test (which queries
    // `op0_ledger`, `op0_pubkey`, `op1_ledger`) stays untouched —
    // the var names are now semantic stand-ins for "complaint target"
    // and "embed host", not literally op0/op1.
    let op0_ledger = target_ledger;
    let op0_pubkey = target_pubkey;
    let op1_ledger = member_ledger;
    let op1_data = op_data_dir(member_op_idx);

    // ── 2. Capture op1's ledger sequence BEFORE the embed so we can
    //      identify the new update unambiguously. ──────────────────
    let pre_count = read_ledger_history(&op1_data, &op1_ledger).len();
    eprintln!("[setup] op1 ledger pre-embed update count: {}", pre_count);

    // ── 3. Synthetic 32-byte request hash (any value — the embed
    //      doesn't care, only that the bytes round-trip). ───────────
    let request_hash_bytes: [u8; 32] = {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(0x4D);
        }
        h
    };
    let request_hash_hex = hex::encode(request_hash_bytes);
    eprintln!("[setup] request_hash: {}…", &request_hash_hex[..16]);

    // ── 4. Run the wallet's `escalate` command. The wallet uses a
    //      throwaway seed since we're not paying yet — the handler
    //      currently accepts unconditionally. ───────────────────────
    let scratch = tempdir();
    let wallet_seed = "feed".repeat(16); // 32 bytes hex, doesn't need to be real
    let out = Command::new(wallet_bin())
        .args(["escalate"])
        .args(["--member-ledger", &op1_ledger])
        .args(["--request-hash", &request_hash_hex])
        .args(["--target-ledger", &op0_ledger])
        .args(["--target-operator", &op0_pubkey])
        .args(["--seed", &wallet_seed])
        .args(["--relay", relay_messaging()])
        .args(["--network", "regtest"])
        .args(["--data-dir", scratch.to_str().unwrap()])
        .output()
        .expect("wallet escalate spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("[wallet] stdout:\n{}", stdout);
    if !out.status.success() {
        panic!("wallet escalate failed:\nstdout: {}\nstderr: {}", stdout, stderr);
    }
    assert!(
        stdout.contains("Embed committed on member ledger"),
        "wallet did not report a successful embed:\n{}",
        stdout
    );

    // ── 5. Poll op1's ledger JSONL for the new DeliveryEmbed update.
    //      The member's node persists the update to disk before it
    //      broadcasts, but writes are async — give it a few seconds
    //      to land before scanning. ─────────────────────────────────
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut found: Option<LedgerOperation> = None;
    while Instant::now() < deadline && found.is_none() {
        let updates = read_ledger_history(&op1_data, &op1_ledger);
        if updates.len() > pre_count {
            // Scan the new tail entries for a DeliveryEmbed whose
            // fields match what we sent.
            for u in &updates[pre_count..] {
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    if let LedgerOperation::DeliveryEmbed {
                        request_hash,
                        target_ledger_id,
                        target_operator,
                    } = &op
                    {
                        if request_hash == &request_hash_bytes
                            && hex::encode(target_ledger_id) == op0_ledger
                            && target_operator.to_string() == op0_pubkey
                        {
                            found = Some(op);
                            break;
                        }
                    }
                }
            }
        }
        if found.is_none() {
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    let op = found.unwrap_or_else(|| {
        let updates = read_ledger_history(&op1_data, &op1_ledger);
        panic!(
            "no DeliveryEmbed matching the wallet's request appeared on op1's ledger \
             within 15s. pre_count={}, post_count={}",
            pre_count,
            updates.len()
        );
    });

    // Final verification — defensive type-shape check (the find-loop
    // above already matched on the variant, but assert here so test
    // failures point at the assertion rather than at panic in find).
    match op {
        LedgerOperation::DeliveryEmbed {
            request_hash,
            target_ledger_id,
            target_operator,
        } => {
            assert_eq!(request_hash, request_hash_bytes);
            assert_eq!(hex::encode(target_ledger_id), op0_ledger);
            assert_eq!(target_operator.to_string(), op0_pubkey);
        }
        other => panic!("expected DeliveryEmbed, got {:?}", other),
    }

    eprintln!("[verify] DeliveryEmbed landed on op1's ledger with matching fields");
}
