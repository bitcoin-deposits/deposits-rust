//! Integration test: an operator that publishes two valid-cosigned
//! `SignedLedgerUpdate`s at the same `{seq, prev_hash}` cannot get both
//! into honest quorum members' state. The first update wins; the second
//! is rejected on chain-continuity (replicas have already advanced past
//! the equivocated seq).
//!
//! `danger fork-update` mints both updates with valid cosignatures
//! (using cluster operator seeds passed as `--cosigner-seed`), then
//! broadcasts U_A first and U_B four seconds later. The pause is long
//! enough for honest quorum members to ingest U_A and advance their
//! replicas, so U_B's `previous_hash` no longer matches their
//! `chain_tip_hash`.
//!
//! What we're testing:
//!   - Each quorum member's on-disk JSONL has exactly one Update entry
//!     at the equivocated seq, with content_hash == U_A's.
//!   - U_B's content_hash is *absent* from every quorum member's view.
//!
//! What we're *not* testing here (out of scope):
//!   - The simultaneous-broadcast race (U_A and U_B arrive interleaved).
//!     Different quorum members might split-brain there. Testing that
//!     would need finer Nostr timing control than this test exercises.
//!   - Late-discovery semantics. If U_B is discovered after the chain
//!     has progressed many seqs past N, the protocol's design choice is
//!     "as of now": don't unwind, treat U_B as evidence of past
//!     misbehavior (future `FraudProofType::Equivocation`). Rewinding
//!     would invalidate downstream legitimate ops.

use deposits_test::regtest::*;
use std::process::Command;
use std::time::Duration;

#[test]
#[ignore]
fn equivocation_chain_continuity_keeps_quorum_consistent() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // Pick an op + ledger that no prior fraud-proof test has disrupted.
    // op4 + L1 is untouched (op0 L1/L2/L3 + op1 L3 were used by the
    // fraud-proof tests; op2 + op3 by the cross-ledger route test).
    let attacker_op_idx: usize = 4;
    let accused_ledger = read_setup_state("ledger_4_1");
    eprintln!(
        "[setup]   attacker=op{}  ledger={}…",
        attacker_op_idx,
        &accused_ledger[..16]
    );

    // Read quorum_members from a peer's view (op0 doesn't have op4's
    // ledger imported by default; pick a peer that does).
    let peer_op_idx = find_peer_with_ledger(&accused_ledger, attacker_op_idx)
        .expect("no peer has op4's L1 imported — cluster setup incomplete");
    eprintln!("[setup]   reading quorum_members from peer=op{}", peer_op_idx);

    // Map each quorum_member pubkey to the cluster operator index whose
    // seed produces it. We need the seeds to forge cosignatures.
    let history = read_ledger_history(&op_data_dir(peer_op_idx), &accused_ledger);
    let quorum_pubkeys = quorum_members_from_history(&history)
        .expect("ledger has no QuorumBegin yet — quorum not active");
    eprintln!(
        "[setup]   quorum has {} members; threshold = {}",
        quorum_pubkeys.len(),
        quorum_pubkeys.len() / 2 + 1
    );
    let cosigner_seeds: Vec<String> = quorum_pubkeys
        .iter()
        .filter_map(|pk_hex| op_idx_for_pubkey(pk_hex).map(|i| op_seed(i)))
        .collect();
    assert_eq!(
        cosigner_seeds.len(),
        quorum_pubkeys.len(),
        "couldn't map every quorum member to a cluster operator seed — \
         this test scans cluster ops up to the `op_idx_for_pubkey` ceiling, \
         which is sized for the largest cluster setup.sh emits (Q=7 ⇒ 22 ops). \
         If you're seeing this fail with members on a fresh cluster, the \
         scan limit needs to be bumped."
    );

    // Note the pre-broadcast tip — we'll look for the next seq.
    let pre_seq = history.last().map(|u| u.sequence_number).unwrap_or(0);
    let equivocated_seq = pre_seq + 1;
    eprintln!(
        "[setup]   pre-broadcast tip seq={}  equivocated seq={}",
        pre_seq, equivocated_seq
    );

    // ── Mint U_A and U_B with valid cosignatures, broadcast staggered ──
    let mut cmd = Command::new(&node);
    cmd.args(["danger", "fork-update", &accused_ledger])
        .args(["--seed", &op_seed(attacker_op_idx)])
        .args(["--name", &format!("op{}", attacker_op_idx)])
        .args(["--network", "regtest"])
        .args(["--data-dir", op_data_dir(attacker_op_idx).to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()]);
    for seed in &cosigner_seeds {
        cmd.args(["--cosigner-seed", seed]);
    }
    let out = cmd.output().expect("invoke danger fork-update");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "fork-update failed:\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    let (u_a_content_hash, u_b_content_hash) = parse_fork_output(&stdout)
        .expect("could not parse U_A/U_B content_hashes from fork-update output");
    eprintln!(
        "[forked]  U_A content_hash={}…  U_B content_hash={}…",
        &u_a_content_hash[..16],
        &u_b_content_hash[..16]
    );
    assert_ne!(u_a_content_hash, u_b_content_hash);

    // Give a margin past the CLI's internal post-broadcast sleep so
    // every quorum member has had time to ingest both broadcasts.
    std::thread::sleep(Duration::from_secs(3));

    // ── Verify: every quorum member converged on U_A only ──
    let mut checked = 0;
    for op_idx in 0..10 {
        if op_idx == attacker_op_idx {
            continue; // attacker's own daemon skips inbound on its own ledger
        }
        let history = match try_read_ledger_history(op_idx, &accused_ledger) {
            Some(h) => h,
            None => continue,
        };
        let updates_at_seq: Vec<_> = history
            .iter()
            .filter(|u| u.sequence_number == equivocated_seq)
            .collect();
        assert!(
            updates_at_seq.len() <= 1,
            "op{} has {} updates at seq={} — equivocation slipped through",
            op_idx,
            updates_at_seq.len(),
            equivocated_seq
        );
        if let Some(u) = updates_at_seq.first() {
            let ch = hex::encode(u.content_hash);
            assert_eq!(
                ch, u_a_content_hash,
                "op{} accepted U_B (or some other content) at seq={}; expected U_A",
                op_idx, equivocated_seq
            );
            assert_ne!(ch, u_b_content_hash);
            checked += 1;
        }
    }
    assert!(
        checked >= 2,
        "expected at least 2 quorum members to have ingested U_A; checked {}",
        checked
    );
    eprintln!(
        "[ok]      {} quorum member(s) converged on U_A; none accepted U_B",
        checked
    );
}

/// Walk a ledger's history and return the active quorum members'
/// pubkey hex strings, drawn from the most recent QuorumBegin
/// (message_type `QuorumBegin`'s discriminant). Returns `None` if no
/// QuorumBegin exists in history.
fn quorum_members_from_history(
    history: &[deposits_protocol::types::SignedLedgerUpdate],
) -> Option<Vec<String>> {
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvDecode;
    for update in history.iter().rev() {
        let Ok(op) = LedgerOperation::tlv_decode(&update.message) else {
            continue;
        };
        if let LedgerOperation::QuorumBegin { quorum_members, .. } = op {
            return Some(
                quorum_members
                    .iter()
                    .map(|m| hex::encode(m.pubkey.serialize()))
                    .collect(),
            );
        }
    }
    None
}

/// Return the cluster operator index whose seed derives to the given
/// x-only-or-compressed pubkey hex, or None if none match. Scans up to
/// the largest cluster `setup.sh` emits (Q=7 ⇒ NODE_COUNT=22).
fn op_idx_for_pubkey(pubkey_hex: &str) -> Option<usize> {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::Network;
    use std::str::FromStr;

    let secp = Secp256k1::new();
    for i in 0..22 {
        let seed_hex = op_seed(i);
        let bytes: [u8; 32] = match hex::decode(&seed_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
        {
            Some(b) => b,
            None => continue,
        };
        let xpriv = match Xpriv::new_master(Network::Regtest, &bytes) {
            Ok(x) => x,
            Err(_) => continue,
        };
        let path = DerivationPath::from_str("m/86'/0'/0'/0/0").ok()?;
        let derived = match xpriv.derive_priv(&secp, &path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let kp = Keypair::from_secret_key(&secp, &derived.private_key);
        let pk_hex = hex::encode(kp.public_key().serialize());
        if pk_hex == pubkey_hex {
            return Some(i);
        }
    }
    None
}

/// Pull the U_A and U_B content_hashes out of `danger fork-update`
/// stdout, which prints them on dedicated lines:
///   `U_A content_hash=<64 hex chars>`
///   `U_B content_hash=<64 hex chars>`
fn parse_fork_output(stdout: &str) -> Option<(String, String)> {
    let mut a: Option<String> = None;
    let mut b: Option<String> = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("U_A content_hash=") {
            a = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("U_B content_hash=") {
            b = Some(rest.trim().to_string());
        }
    }
    Some((a?, b?))
}

/// Like `read_ledger_history` but returns `None` if the JSONL doesn't
/// exist (op isn't a quorum member of this ledger), rather than panicking.
fn try_read_ledger_history(
    op_idx: usize,
    ledger_id: &str,
) -> Option<Vec<deposits_protocol::types::SignedLedgerUpdate>> {
    let path = op_data_dir(op_idx)
        .join("wallet/ledgers")
        .join(format!("{}.jsonl", ledger_id));
    if !path.exists() {
        return None;
    }
    Some(read_ledger_history(&op_data_dir(op_idx), ledger_id))
}
