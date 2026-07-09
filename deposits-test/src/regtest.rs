//! Helpers for docker-backed integration tests that drive a running
//! regtest cluster (`./bin/setup.sh`) via `deposits-node` / `deposits-wallet`
//! release binaries.
//!
//! Tests using these helpers should be `#[ignore]` so they don't run in
//! the default `cargo test` pass. They assume op0 is reachable and the
//! release binaries are built.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// op0's seed, read from the hub-bootstrapped cluster on disk.
///
/// The regtest cluster is now the production `deposits-hub bootstrap`
/// shape (`deposits-tools/data/bootstrap-nodes/node{i}/`), so op0's seed
/// is whatever `hub bootstrap` derived and wrote to
/// `bootstrap-nodes/node0/seed.hex` — NOT the old `"op0"`-hex-padded
/// constant. Reading it off disk keeps the harness in lockstep with the
/// daemon: whatever key the node0 daemon runs as is exactly the key the
/// tests sign / match quorum members against.
///
/// Kept as a function-like `&'static str` (via `op_seed(0)`) so the many
/// `op0_seed()` call sites compile unchanged. Panics if the cluster hasn't
/// been bootstrapped (no seed.hex) — the same failure mode as a missing
/// data dir, surfaced early.
pub fn op0_seed() -> &'static str {
    use std::sync::OnceLock;
    static SEED: OnceLock<String> = OnceLock::new();
    SEED.get_or_init(|| op_seed(0))
}

pub const ELECTRS_URL: &str = "http://localhost:3102";

/// Default ledgers (durable) relay URL.
///
/// Tests read `RELAY_LEDGERS` from the environment with this fallback.
/// Centralized here so a port change touches one constant; the matching
/// shell-side default lives in `deposits-tools/bin/_common.sh`. Override
/// for ad-hoc runs: `RELAY_LEDGERS=ws://localhost:9999 cargo test ...`.
const DEFAULT_RELAY_LEDGERS: &str = "ws://localhost:17779";
const DEFAULT_RELAY_MESSAGING: &str = "ws://localhost:17780";

/// URL of the ledgers (durable) relay. Reads `RELAY_LEDGERS` env var
/// with [`DEFAULT_RELAY_LEDGERS`] as the fallback. Cached on first call
/// so subsequent calls return the same `&'static str` — interchangeable
/// with the previous `pub const RELAY_LEDGERS`.
pub fn relay_ledgers() -> &'static str {
    use std::sync::OnceLock;
    static URL: OnceLock<String> = OnceLock::new();
    URL.get_or_init(|| {
        std::env::var("RELAY_LEDGERS").unwrap_or_else(|_| DEFAULT_RELAY_LEDGERS.to_string())
    })
}

/// URL of the messaging (ephemeral) relay. See [`relay_ledgers`].
pub fn relay_messaging() -> &'static str {
    use std::sync::OnceLock;
    static URL: OnceLock<String> = OnceLock::new();
    URL.get_or_init(|| {
        std::env::var("RELAY_MESSAGING").unwrap_or_else(|_| DEFAULT_RELAY_MESSAGING.to_string())
    })
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Binary paths honor the same env overrides as deposits-tools/bin/*.sh
/// (`DEPOSITS_NODE` / `DEPOSITS_WALLET`), so a cluster running debug
/// binaries can be tested without a release build present.
pub fn node_bin() -> PathBuf {
    std::env::var("DEPOSITS_NODE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target/release/deposits-node"))
}

pub fn wallet_bin() -> PathBuf {
    std::env::var("DEPOSITS_WALLET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target/release/deposits-wallet"))
}

pub fn op0_data_dir() -> PathBuf {
    op_data_dir(0)
}

/// The daemon `--name` for operator `i`. The regtest cluster is stood up
/// by `deposits-hub bootstrap`, which names its daemons `node{i}`; this
/// is the name they advertise under (Kind 39100) and match on. The tests
/// call operators "op{i}" colloquially, but the on-the-wire name is
/// `node{i}` — so any CLI `--name` or ad-filter that must line up with
/// the running daemon has to use THIS, not the literal "op{i}".
pub fn op_name(i: usize) -> String {
    format!("node{}", i)
}

/// Admin-UI HTTP port for operator `i`. Hub bootstrap binds each daemon's
/// admin API at `8870 + i` (`deposits-hub/src/bootstrap.rs::admin_port`),
/// clear of the legacy setup.sh `8765+` range. Centralized here so the
/// `/api/lifecycle` + `/api/ledgers` pollers below (and tests) resolve to
/// the daemon that hub actually spawned.
pub fn admin_port(i: usize) -> u16 {
    8870 + i as u16
}

/// Seed for operator at index `i`, read from the hub-bootstrapped cluster.
///
/// `deposits-hub bootstrap` derives every node seed from one
/// `hub-master-seed` (BIP-85) and writes it to
/// `bootstrap-nodes/node{i}/seed.hex`. Reading it off disk — rather than
/// recomputing the derivation — guarantees the seed the harness signs
/// with is byte-for-byte the one the node{i} daemon is running. Panics if
/// the cluster hasn't been bootstrapped yet (the seed file is the
/// canonical "is the cluster up?" artifact).
pub fn op_seed(i: usize) -> String {
    let path = op_data_dir(i).join("seed.hex");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| {
            panic!(
                "reading operator seed at {} — is the cluster bootstrapped? \
                 (`deposits-tools/bin/setup.sh 10`). {}",
                path.display(),
                e
            )
        })
        .trim()
        .to_string()
}

/// Data dir for operator at index `i` under the running cluster.
///
/// Points at the hub-bootstrap layout (`bootstrap-nodes/node{i}`), which
/// is the SAME shape production runs — so sweep-all / archive / hub-admin
/// work against regtest exactly as against mainnet, with no layout
/// adapter. Overridable via `DEPOSITS_DATA_ROOT` for ad-hoc clusters
/// (matches setup.sh's `DATA_ROOT`).
pub fn op_data_dir(i: usize) -> PathBuf {
    data_root().join("bootstrap-nodes").join(format!("node{}", i))
}

/// True iff node `i` exists in the bootstrapped cluster (its seed.hex is
/// on disk). The tests scan fixed index ranges (`0..16`) that are wider
/// than the cluster; helpers that fund/derive per-op keys use this to
/// skip absent nodes rather than panic. On the legacy 10-op cluster the
/// scans over-provisioned harmlessly because seeds were computed, never
/// read; now they're read from disk, so absent nodes must be skipped.
pub fn op_exists(i: usize) -> bool {
    op_data_dir(i).join("seed.hex").is_file()
}

/// Like [`op_seed`] but returns `None` for a node that isn't in the
/// cluster (its seed.hex is missing), for scan loops over a fixed index
/// range wider than the actual node count.
pub fn try_op_seed(i: usize) -> Option<String> {
    let path = op_data_dir(i).join("seed.hex");
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Root of the bootstrapped cluster's data (the hub `--data-dir`).
/// Defaults to `deposits-tools/data`, matching setup.sh's `DATA_ROOT`.
pub fn data_root() -> PathBuf {
    std::env::var("DEPOSITS_DATA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("deposits-tools/data"))
}

/// Derive operator `i`'s secret key (BIP-86 `m/86'/0'/0'/0/0` from seed).
/// Mirrors `derive_operator_secret` in `deposits-node`.
pub fn op_operator_secret(i: usize) -> bitcoin::secp256k1::SecretKey {
    use std::str::FromStr;
    let seed_bytes = hex::decode(op_seed(i)).expect("op seed hex");
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let xpriv = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &seed_bytes)
        .expect("xpriv");
    let path = bitcoin::bip32::DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap();
    xpriv.derive_priv(&secp, &path).expect("derive").private_key
}

/// Operator `i`'s P2WPKH address under the operator key.
pub fn op_p2wpkh_address(i: usize) -> bitcoin::Address {
    let sk = op_operator_secret(i);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let compressed = bitcoin::CompressedPublicKey::from_slice(&pk.serialize()).unwrap();
    bitcoin::Address::p2wpkh(&compressed, bitcoin::Network::Regtest)
}

/// Derive a wallet's per-deposit secret key at `key_index`, mirroring
/// `deposits-wallet`'s `derive_secret_key_at_index` so tests can sign
/// witnesses against the deposit's BIP-340 identity. Path matches the
/// wallet: `m/84'/0'/0'/0/{key_index}`.
pub fn derive_deposit_secret(
    seed: &[u8; 32],
    network: bitcoin::Network,
    key_index: u32,
) -> bitcoin::secp256k1::SecretKey {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::Secp256k1;
    use std::str::FromStr;

    let xpriv = Xpriv::new_master(network, seed).expect("xpriv from seed");
    let secp = Secp256k1::new();
    let path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", key_index))
        .expect("derivation path");
    xpriv
        .derive_priv(&secp, &path)
        .expect("derive_priv")
        .private_key
}

/// Build (or rebuild) `deposits-node` with the `dangerous-testing` feature
/// enabled and return the binary path. The release build at
/// `target/release/deposits-node` is replaced; `cluster_available()` will
/// continue to find it. Re-runs are cheap (cargo no-ops).
pub fn build_node_with_danger() -> PathBuf {
    let status = Command::new("cargo")
        .current_dir(repo_root())
        .args([
            "build",
            "--release",
            "-p",
            "deposits-node",
            "--features",
            "dangerous-testing",
        ])
        .status()
        .expect("cargo build deposits-node --features dangerous-testing");
    assert!(status.success(), "build failed");
    node_bin()
}

/// Run `deposits-node ledger health <ledger_id>` from operator `op_idx`'s
/// perspective and return the combined stdout+stderr. The output
/// includes a `Dispute: <state>` line which is the canonical place
/// integration tests assert on for dispute-flow visibility.
///
/// Use op0 to observe its own ledgers' state, or any quorum-member op
/// to observe a partner ledger.
/// Read a ledger's append-only JSONL log from disk and extract the
/// list of `SignedLedgerUpdate` entries (skipping the Role + State
/// header rows). Returns updates in chronological order.
///
/// Used by integration tests that need to inspect existing ledger
/// state to construct fraud proofs or verify post-conditions.
pub fn read_ledger_history(
    data_dir: &Path,
    ledger_id: &str,
) -> Vec<deposits_protocol::types::SignedLedgerUpdate> {
    use std::io::{BufRead, BufReader};

    let path = data_dir
        .join("wallet/ledgers")
        .join(format!("{}.jsonl", ledger_id));
    let file = std::fs::File::open(&path)
        .unwrap_or_else(|e| panic!("opening {}: {}", path.display(), e));
    let reader = BufReader::new(file);
    let mut updates = Vec::new();
    for line in reader.lines() {
        let line = line.expect("read line");
        if line.trim().is_empty() {
            continue;
        }
        let mut value: serde_json::Value =
            serde_json::from_str(&line).expect("ledger jsonl line is valid JSON");
        // Header rows have type ∈ {"Role","State"}; skip them. Update
        // rows are tagged "Update" with the rest of the fields being a
        // SignedLedgerUpdate.
        if value.get("type").and_then(|t| t.as_str()) != Some("Update") {
            continue;
        }
        if let Some(obj) = value.as_object_mut() {
            obj.remove("type");
        }
        let update: deposits_protocol::types::SignedLedgerUpdate =
            serde_json::from_value(value).expect("Update row deserializes");
        updates.push(update);
    }
    updates
}

/// The hub's `bootstrap-state.json` as a raw JSON value — the
/// authoritative record of the regtest cluster's topology (node → ledger
/// id, node → operator pubkey). Replaces the old per-key
/// `data/state/<key>` files setup.sh used to scatter: the cluster is now
/// `deposits-hub bootstrap`, which persists everything here, so the
/// harness reads THIS (no separate state dir to keep in sync).
fn bootstrap_state() -> serde_json::Value {
    let path = data_root().join("bootstrap-state.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "reading {} — is the cluster bootstrapped? (`deposits-tools/bin/setup.sh 10`): {}",
            path.display(),
            e
        )
    });
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("parsing {}: {}", path.display(), e))
}

/// node{i}'s activated ledger id from `bootstrap-state.json`.
pub fn op_ledger(i: usize) -> String {
    try_op_ledger(i)
        .unwrap_or_else(|| panic!("no ledger for {} in bootstrap-state.json", op_name(i)))
}

/// Like [`op_ledger`] but returns `None` (instead of panicking) when the
/// node has no ledger recorded — for scan loops that walk a fixed index
/// range wider than the cluster.
pub fn try_op_ledger(i: usize) -> Option<String> {
    bootstrap_state()
        .get("ledgers")
        .and_then(|m| m.get(op_name(i)))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// node{i}'s operator pubkey (Node ID, compressed hex) from
/// `bootstrap-state.json`.
pub fn op_node_id(i: usize) -> Option<String> {
    bootstrap_state()
        .get("node_ids")
        .and_then(|m| m.get(op_name(i)))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Resolve a legacy `setup.sh`-style state key against the hub cluster.
///
/// The old cluster gave each operator 3 ledgers and stored their ids at
/// `data/state/ledger_{i}_{l}` (l ∈ 1..3) and node ids at
/// `data/state/node_id_{i}`. The hub cluster gives each node exactly ONE
/// ledger. We map every `ledger_{i}_{l}` → node{i}'s single ledger and
/// `node_id_{i}` → node{i}'s operator pubkey, so the callers that pick
/// distinct operators (op1 vs op3 vs op4) for cross-test isolation still
/// land on distinct nodes — the isolation those picks provide is
/// preserved (it was always "distinct OPERATOR", the ledger-index was
/// just how a single op fanned out its three ledgers).
pub fn read_setup_state(key: &str) -> String {
    if let Some(rest) = key.strip_prefix("ledger_") {
        // `ledger_{i}_{l}` → node{i}'s ledger.
        let i: usize = rest
            .split('_')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("malformed setup-state key `{}`", key));
        return op_ledger(i);
    }
    if let Some(rest) = key.strip_prefix("node_id_") {
        let i: usize = rest
            .parse()
            .unwrap_or_else(|_| panic!("malformed setup-state key `{}`", key));
        return op_node_id(i)
            .unwrap_or_else(|| panic!("no node id for {} in bootstrap-state.json", op_name(i)));
    }
    panic!(
        "read_setup_state: unrecognized key `{}` (expected ledger_i_l or node_id_i)",
        key
    );
}

/// True iff the htlc-agent process is running. Tests that exercise
/// cross-ledger routing through a courier need this; start it with
/// `./bin/setup-htlc-agent.sh` after the cluster is up.
pub fn htlc_agent_available() -> bool {
    Command::new("pgrep")
        .args(["-f", "htlc-agent --"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

/// Credit `amount_msats` to a deposit on `ledger_id` via
/// `deposits-node deposit credit` from `op_idx`'s data dir. This is the
/// fast fund-a-deposit path used by setup-htlc-agent — bypasses real
/// on-chain confirmation, so tests run in seconds.
///
/// `deposit_pubkey_or_id_hex` may be either a 33-byte compressed pubkey
/// (legacy) or a 16-byte deposit_id (post-Wave-1). The CLI now takes
/// deposit_id directly; if a pubkey is passed we synthesize pk(...) and
/// hash it ourselves.
///
/// `invoice_id` should be unique per call (using `payment_hash` style).
/// Returns combined stdout+stderr; panics on non-zero exit.
pub fn operator_credit_deposit(
    op_idx: usize,
    ledger_id: &str,
    deposit_pubkey_or_id_hex: &str,
    amount_msats: u64,
    invoice_id: &str,
) -> String {
    // Normalize to deposit_id. 32 hex chars = 16 raw bytes = id; 66 hex
    // chars = 33 raw bytes = compressed pubkey, hash to id.
    let deposit_id_hex = match deposit_pubkey_or_id_hex.len() {
        32 => deposit_pubkey_or_id_hex.to_string(),
        66 => {
            let descriptor = format!("pk({})", deposit_pubkey_or_id_hex);
            hex::encode(deposits_core::types::compute_deposit_id(&descriptor))
        }
        n => panic!(
            "operator_credit_deposit: expected 32 or 66 hex chars, got {} (`{}`)",
            n, deposit_pubkey_or_id_hex
        ),
    };

    let seed = op_seed(op_idx);
    let data_dir = op_data_dir(op_idx);
    let name = op_name(op_idx);
    let out = Command::new(node_bin())
        .args([
            "deposit",
            "credit",
            ledger_id,
            &deposit_id_hex,
            &amount_msats.to_string(),
            invoice_id,
        ])
        .args(["--seed", &seed])
        .args(["--name", &name])
        .args(["--network", "regtest"])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke deposit credit");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "deposit credit failed:\n{}",
        combined
    );
    combined
}

/// Drive the wallet's `route` command — performs a cross-ledger transfer
/// via an htlc-agent courier. Returns combined stdout+stderr and exit
/// success. The wallet must have deposits with both aliases in the
/// given `data_dir`'s deposits.json.
pub fn wallet_route(
    data_dir: &Path,
    nsec_path: &Path,
    from_alias: &str,
    to_alias: &str,
    amount_sats: u64,
) -> (bool, String) {
    wallet_route_inner(data_dir, nsec_path, from_alias, to_alias, amount_sats, false)
}

/// `wallet route --ptlc` — point-locked variant (DEP-13 §"Courier PTLC pattern").
/// Pre-flights operator capabilities; both hop operators must advertise
/// `pointlock` in their Kind 39100 ads. Otherwise behaves the same way.
pub fn wallet_route_ptlc(
    data_dir: &Path,
    nsec_path: &Path,
    from_alias: &str,
    to_alias: &str,
    amount_sats: u64,
) -> (bool, String) {
    wallet_route_inner(data_dir, nsec_path, from_alias, to_alias, amount_sats, true)
}

fn wallet_route_inner(
    data_dir: &Path,
    nsec_path: &Path,
    from_alias: &str,
    to_alias: &str,
    amount_sats: u64,
    ptlc: bool,
) -> (bool, String) {
    let mut cmd = Command::new(wallet_bin());
    cmd.args([
        "route",
        from_alias,
        to_alias,
        &amount_sats.to_string(),
    ]);
    if ptlc {
        cmd.arg("--ptlc");
    }
    let out = cmd
        .args(["--nsec-file", nsec_path.to_str().unwrap()])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--relay", relay_ledgers()])
        .args(["--network", "regtest"])
        .output()
        .expect("invoke wallet route");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), combined)
}

/// Look up the htlc-agent's deposit on `ledger_id` and return the
/// deposit_id hex (32-char hash of the descriptor). Returns `None` if
/// the agent doesn't have a deposit on that ledger or if its
/// deposits.json is missing. Useful for tests that need to credit the
/// agent's destination deposit before triggering a route.
pub fn htlc_agent_deposit_pubkey(ledger_id: &str) -> Option<String> {
    let path = repo_root()
        .join("deposits-tools/data/htlc-agent/deposits.json");
    let raw = std::fs::read_to_string(&path).ok()?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&raw).ok()?;
    for d in deposits {
        if d.get("ledger_id").and_then(|v| v.as_str()) != Some(ledger_id) {
            continue;
        }
        // Wave-2 record: `deposit_id` directly. Older record: synthesize
        // pk(<deposit_pubkey>) and hash.
        if let Some(id) = d.get("deposit_id").and_then(|v| v.as_str()) {
            return Some(id.to_string());
        }
        if let Some(pk) = d.get("deposit_pubkey").and_then(|v| v.as_str()) {
            let descriptor = format!("pk({})", pk);
            return Some(hex::encode(
                deposits_core::types::compute_deposit_id(&descriptor),
            ));
        }
    }
    None
}

/// Read a wallet's `deposits.json` and return `(deposit_id_hex,
/// amount_sats)` for the deposit with the given alias. `amount_sats`
/// is `0` for a deposit that hasn't been funded yet. Returns `None`
/// if no deposit with that alias is present, or if the record is
/// missing both `deposit_id` and `deposit_pubkey`.
pub fn wallet_lookup_deposit(
    data_dir: &Path,
    alias: &str,
) -> Option<(String, u64)> {
    let path = data_dir.join("deposits.json");
    let raw = std::fs::read_to_string(&path).ok()?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&raw).ok()?;
    for d in deposits {
        if d.get("alias").and_then(|v| v.as_str()) != Some(alias) {
            continue;
        }
        let id_hex = if let Some(id) = d.get("deposit_id").and_then(|v| v.as_str()) {
            id.to_string()
        } else if let Some(pk) = d.get("deposit_pubkey").and_then(|v| v.as_str()) {
            let descriptor = format!("pk({})", pk);
            hex::encode(deposits_core::types::compute_deposit_id(&descriptor))
        } else {
            return None;
        };
        let amount = d.get("amount_sats").and_then(|v| v.as_u64()).unwrap_or(0);
        return Some((id_hex, amount));
    }
    None
}

/// Run `deposits-wallet sync` to refresh local balances from the
/// operator daemons. Used after a route to observe credited amounts.
pub fn wallet_sync(data_dir: &Path, nsec_path: &Path) -> bool {
    Command::new(wallet_bin())
        .args(["sync"])
        .args(["--nsec-file", nsec_path.to_str().unwrap()])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--relay", relay_ledgers()])
        .args(["--network", "regtest"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Scan every imported ledger in `op_idx`'s data dir for the
/// non-zero update with the lowest `block_height`, returning its
/// `block_hash`. Useful as an "earlier confirmed block" anchor in
/// fraud-proof tests where the accused ledger's own updates may all
/// share a single block (e.g. activation-only quorum ledgers).
///
/// Returns `None` if no non-zero block_hash is found anywhere in the
/// op's ledger directory.
pub fn earliest_anchored_block_hash(op_idx: usize) -> Option<[u8; 32]> {
    let ledgers_dir = op_data_dir(op_idx).join("wallet/ledgers");
    let entries = std::fs::read_dir(&ledgers_dir).ok()?;
    let mut best: Option<(u32, [u8; 32])> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
            continue;
        }
        let ledger_id = path.file_stem()?.to_str()?.to_string();
        for u in read_ledger_history(&op_data_dir(op_idx), &ledger_id) {
            if u.block_hash == [0u8; 32] {
                continue;
            }
            if best.map(|(h, _)| u.block_height < h).unwrap_or(true) {
                best = Some((u.block_height, u.block_hash));
            }
        }
    }
    best.map(|(_, h)| h)
}

/// Find any operator (other than `exclude_op_idx`) whose `wallet/ledgers`
/// directory contains a JSONL file for `ledger_id`. Useful for tests
/// that need to read an accused ledger from a quorum member's view —
/// they don't know in advance which ops are quorum members, since
/// setup.sh's assignment is randomized.
pub fn find_peer_with_ledger(ledger_id: &str, exclude_op_idx: usize) -> Option<usize> {
    for op_idx in 0..10 {
        if op_idx == exclude_op_idx {
            continue;
        }
        let path = op_data_dir(op_idx)
            .join("wallet/ledgers")
            .join(format!("{}.jsonl", ledger_id));
        if path.exists() {
            return Some(op_idx);
        }
    }
    None
}

/// Embed a fraud-proof hash on `op_idx`'s ledger via the
/// `recovery embed-hash` CLI, then re-read the ledger from `peer_op_idx`
/// (a quorum member of the accused ledger) and return the resulting
/// embedding update. Looking from a peer's view sidesteps the daemon's
/// "skip own-ledger inbound" guard — see project_own_ledger_inbound_skip.
pub fn embed_proof_hash(
    node_bin: &Path,
    op_idx: usize,
    peer_op_idx: usize,
    ledger_id: &str,
    proof_hash: [u8; 32],
) -> deposits_protocol::types::SignedLedgerUpdate {
    let seed = op_seed(op_idx);
    let data_dir = op_data_dir(op_idx);
    let name = op_name(op_idx);
    let out = Command::new(node_bin)
        .args(["recovery", "embed-hash", ledger_id, &hex::encode(proof_hash)])
        .args(["--seed", &seed])
        .args(["--name", &name])
        .args(["--network", "regtest"])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke recovery embed-hash");
    assert!(
        out.status.success(),
        "embed-hash failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Poll the peer for the embedding update. The operator's embed-hash
    // publishes a kind:9100 update on the ledgers relay; the peer's
    // daemon subscribes and writes the update to its own JSONL on
    // arrival. On a busy 10-daemon cluster the relay roundtrip + the
    // peer's `apply_signed` path can take a few seconds — a fixed 3s
    // sleep was the test-suite-wide cause of regtest.rs:481 panics.
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvDecode;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(u) = read_ledger_history(&op_data_dir(peer_op_idx), ledger_id)
            .into_iter()
            .rev()
            .find(|u| {
                LedgerOperation::tlv_decode(&u.message)
                    .ok()
                    .and_then(|op| op.embedded_hash().copied())
                    .map(|h| h == proof_hash)
                    .unwrap_or(false)
            })
        {
            return u;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "embedding update with proof_hash {} should be in op{}'s view \
                 of ledger {} within 30s — relay propagation stalled, peer \
                 daemon down, or accused didn't actually publish",
                hex::encode(proof_hash),
                peer_op_idx,
                &ledger_id[..16.min(ledger_id.len())],
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Publish a `FraudBroadcast` as a kind:9101 Nostr event from `op_idx`'s
/// daemon-key context using the `recovery publish-fraud-broadcast` CLI.
pub fn publish_fraud_broadcast(
    node_bin: &Path,
    op_idx: usize,
    broadcast: &deposits_protocol::fraud::FraudBroadcast,
) {
    let seed = op_seed(op_idx);
    let data_dir = op_data_dir(op_idx);
    let name = op_name(op_idx);
    let json = serde_json::to_string(broadcast).unwrap();
    let json_path = std::env::temp_dir().join(format!(
        "fp_broadcast_op{}_{}.json",
        op_idx,
        broadcast.proof.proof_hash().iter().take(4).fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
            s
        })
    ));
    std::fs::write(&json_path, &json).unwrap();
    let out = Command::new(node_bin)
        .args([
            "recovery",
            "publish-fraud-broadcast",
            json_path.to_str().unwrap(),
        ])
        .args(["--seed", &seed])
        .args(["--name", &name])
        .args(["--network", "regtest"])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke publish-fraud-broadcast");
    assert!(
        out.status.success(),
        "publish-fraud-broadcast failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Send `amount_sats` to an operator's operator-key P2WPKH address from
/// the cluster's bitcoin-cli faucet. Used by tests that exercise the
/// dispute → auto-arm → multi-input claim TX path: RC6's auto-arm pulls
/// a UTXO at this address to declare as `replacement_collateral`, and
/// RC4's claim-TX builder signs against it. Without this funding step,
/// the disputant would arm with `replacement_collateral: None` and a
/// strict cosigner refuses confiscation per DEP-03.
///
/// Returns the txid of the funding transaction. Caller is responsible
/// for mining sufficient confirmations (default cosigner policy is 1).
/// The operator's on-chain identity pubkey (`m/86'/0'/0'/0/0` from the
/// op seed) — the key that becomes `new_custodian` in a `DisputeAcquire`
/// when this operator wins the lottery. Returned as compressed-hex and
/// as x-only-hex so callers can match either form.
pub fn op_identity_pubkey(op_idx: usize) -> (String, String) {
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    use std::str::FromStr;
    let seed = op_seed(op_idx);
    let seed_bytes = hex::decode(&seed).expect("op seed hex");
    let secp = Secp256k1::new();
    let xpriv =
        bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &seed_bytes).expect("xpriv");
    let path = bitcoin::bip32::DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap();
    let derived = xpriv.derive_priv(&secp, &path).expect("derive");
    let pk = PublicKey::from_secret_key(&secp, &derived.private_key);
    (
        hex::encode(pk.serialize()),
        hex::encode(pk.x_only_public_key().0.serialize()),
    )
}

/// Send `amount_sats` to node `op_idx`'s operator-key P2WPKH from the
/// faucet, returning the funding txid — or `None` if node `op_idx` isn't
/// in the cluster. Tests fund "all potential disputants" by looping a
/// fixed index range (`0..16`) wider than the actual node count; funding
/// an absent node is meaningless, so skip it (the legacy harness derived
/// a seed for any index and funded a throwaway address; the hub harness
/// reads real seeds from disk and there simply is no node beyond N-1).
pub fn fund_operator_key_address(op_idx: usize, amount_sats: u64) -> Option<bitcoin::Txid> {
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    use std::str::FromStr;
    // Skip nodes that don't exist in the cluster.
    let seed = try_op_seed(op_idx)?;
    // Mirror derive_operator_secret: `m/86'/0'/0'/0/0` from seed.
    let seed_bytes = hex::decode(&seed).expect("op seed hex");
    let secp = Secp256k1::new();
    let xpriv = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &seed_bytes)
        .expect("xpriv");
    let path = bitcoin::bip32::DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap();
    let derived = xpriv.derive_priv(&secp, &path).expect("derive");
    let op_pubkey = PublicKey::from_secret_key(&secp, &derived.private_key);
    let compressed = bitcoin::CompressedPublicKey::from_slice(&op_pubkey.serialize()).unwrap();
    let address = bitcoin::Address::p2wpkh(&compressed, bitcoin::Network::Regtest).to_string();

    // Convert sats to BTC (bitcoin-cli sendtoaddress takes BTC). Use 8
    // decimal places to avoid float precision issues for sub-sat amounts.
    let btc_str = format!("{}.{:08}", amount_sats / 100_000_000, amount_sats % 100_000_000);
    let out = Command::new("docker")
        .args([
            "exec",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            "-rpcuser=user",
            "-rpcpassword=pass",
            "sendtoaddress",
            &address,
            &btc_str,
        ])
        .output()
        .expect("docker exec bitcoin-cli sendtoaddress");
    assert!(
        out.status.success(),
        "sendtoaddress failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let txid_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Some(bitcoin::Txid::from_str(&txid_str).expect("parse txid"))
}

/// Mine `n` blocks to a throwaway address (regtest). Used to confirm the
/// funding tx from `fund_operator_key_address` so the cosigner's Esplora
/// check sees it as ≥ 1 confirmation.
///
/// Mines in chunks of 50 with a short pause between calls. A single
/// large `-generate N` call saturates bitcoind for the duration —
/// when other components (electrs, ~10 deposits-node daemons) are
/// subscribed to chaintip notifications, the RPC client can time out
/// before the mining completes. Chunking keeps individual RPC calls
/// short and gives subscribers time to drain between batches.
/// Query bitcoind for the current best-chain block height. Useful for
/// tests that want to mine a relative number of blocks ("100 past the
/// quorum's expiry") without over-mining on a re-used cluster.
/// Block until daemon op_idx's view of the chain tip catches up to
/// at least `target_height` (i.e. it has applied that many blocks via
/// esplora). Returns the daemon's tip on success; panics on timeout.
/// Used after `mine_blocks` for large N (~hundreds) — esplora indexing
/// + the daemon's BDK wallet processing add real wall-clock time, and
/// a fixed sleep is unreliable.
///
/// The /api/lifecycle endpoint reports chain_tip per ledger; using
/// any one ledger's view suffices for "the daemon's wallet has
/// caught up".
pub fn wait_for_daemon_chain_tip(op_idx: usize, target_height: u32, timeout: Duration) -> u32 {
    let token_path = op_data_dir(op_idx).join("admin-token");
    let token = std::fs::read_to_string(&token_path)
        .unwrap_or_default()
        .trim()
        .to_string();
    let url = format!("http://127.0.0.1:{}/api/lifecycle", admin_port(op_idx));
    let deadline = std::time::Instant::now() + timeout;
    let mut last_tip = 0u32;
    while std::time::Instant::now() < deadline {
        let out = Command::new("curl")
            .args(["-s", "-H", &format!("Authorization: Bearer {}", token), &url])
            .output();
        if let Ok(out) = out {
            let body = String::from_utf8_lossy(&out.stdout);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(arr) = v.as_array() {
                    for entry in arr {
                        if let Some(tip) = entry.get("chain_tip").and_then(|x| x.as_u64()) {
                            last_tip = tip as u32;
                            if last_tip >= target_height {
                                return last_tip;
                            }
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!(
        "daemon op{}'s chain_tip ({}) never reached target {} within {:?} — \
         esplora/BDK sync stalled or admin API not responding",
        op_idx, last_tip, target_height, timeout
    );
}

/// Block until op_idx's local jsonl for `ledger_id` contains a
/// committed `QuorumBegin`. Same shape as the discover_op0_ledger
/// poll, but for callers that already know which (op, ledger) they
/// want and just need to wait for the daemon to ingest its own
/// QuorumBegin from the relay (race with `setup.sh` returning).
pub fn wait_for_quorum_begin(op_idx: usize, ledger_id: &str, timeout: Duration) {
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvDecode;

    let path = op_data_dir(op_idx)
        .join("wallet/ledgers")
        .join(format!("{}.jsonl", ledger_id));
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            let updates = read_ledger_history(&op_data_dir(op_idx), ledger_id);
            let has_qb = updates.iter().any(|u| {
                matches!(
                    LedgerOperation::tlv_decode(&u.message),
                    Ok(LedgerOperation::QuorumBegin { .. })
                )
            });
            if has_qb {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!(
        "op{}'s view of ledger {} never contained QuorumBegin within {:?} — \
         daemon may still be ingesting from the relay, or quorum-begin failed",
        op_idx, &ledger_id[..16.min(ledger_id.len())], timeout
    );
}

/// Query op_idx's /api/lifecycle for the latest expiry seen for
/// `ledger_id`. Returns `Some((chain_tip, expiry))` when both are
/// known. Used by tests that need to avoid acting on a ledger whose
/// quorum has already expired (deposit_open / quorum_add / etc. will
/// refuse). Returns `None` if the daemon isn't responding, the
/// ledger isn't in its lifecycle view, or the entry hasn't yet
/// learned its expiry.
pub fn lifecycle_expiry(op_idx: usize, ledger_id: &str) -> Option<(u32, u32)> {
    let token_path = op_data_dir(op_idx).join("admin-token");
    let token = std::fs::read_to_string(&token_path).ok()?.trim().to_string();
    let url = format!("http://127.0.0.1:{}/api/lifecycle", admin_port(op_idx));
    let out = Command::new("curl")
        .args(["-s", "-H", &format!("Authorization: Bearer {}", token), &url])
        .output()
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let arr = v.as_array()?;
    let prefix = &ledger_id[..16];
    let mut best: Option<(u32, u32)> = None;
    for entry in arr {
        let lid = entry.get("ledger_id").and_then(|x| x.as_str()).unwrap_or("");
        // /api/lifecycle truncates the ledger_id to 16 hex chars.
        if !(lid == ledger_id || lid == prefix) {
            continue;
        }
        let tip = entry.get("chain_tip").and_then(|x| x.as_u64())? as u32;
        let exp = entry.get("quorum_expiry").and_then(|x| x.as_u64())? as u32;
        // Duplicate rows can appear when fork-branches surface in the
        // lifecycle view — take the highest expiry the daemon knows.
        if best.map_or(true, |(_, prev_exp)| exp > prev_exp) {
            best = Some((tip, exp));
        }
    }
    best
}

/// Walk `setup.sh`-provisioned ledgers and return the first
/// `(op_idx, ledger_id)` that is:
///   - Not custody-armed by any operator (fraud tests poison ledgers
///     via `custody_armed_*.marker`, after which `deposit_open` is
///     refused).
///   - Still in its healthy quorum window (chain_tip + headroom < expiry).
///     Tests that mine past expiry to exercise auto-dispute leave
///     setup ledgers stranded; lightning / cosign tests that try to
///     `deposit_open` on those get back "operator's quorum has expired."
///   - Not auto-disputed by any peer (no `<lid>_<seq>_<pk>.jsonl`
///     fork-branch file anywhere in the cluster). When a peer fires
///     `DisputeEnter`, that peer's canonical view of the ledger is
///     frozen at the fork sequence — subsequent updates from the
///     operator never reach the peer's canonical chain, so cosign
///     rounds (delivery_embed, invoice cosign, etc.) time out.
///
/// Returns `None` when no clean+healthy+undisputed ledger is left —
/// caller should skip rather than fail, and rerun against
/// `setup.sh --fresh`.
pub fn find_clean_healthy_setup_ledger(min_headroom_blocks: u32) -> Option<(usize, String)> {
    // Hub cluster: each node{op} has exactly one ledger. Walk the nodes
    // and return the first whose ledger is clean + healthy + undisputed.
    for op in 0..16 {
        let Some(ledger_id) = try_op_ledger(op) else {
            continue;
        };
        if ledger_id.len() != 64 {
            continue;
        }
        // Custody-armed check.
        let marker = format!("custody_armed_{}.marker", &ledger_id[..16]);
        let any_armed = (0..16).any(|i| op_data_dir(i).join(&marker).exists());
        if any_armed {
            continue;
        }
        // Quorum-healthy check — query the owning op's daemon.
        let Some((tip, exp)) = lifecycle_expiry(op, &ledger_id) else {
            continue;
        };
        if tip + min_headroom_blocks >= exp {
            continue;
        }
        // No fork-branch file on this ledger at any peer. Fork
        // names are `<lid:64>_<seq:06>_<pk16>.jsonl` (94 chars);
        // canonical is `<lid>.jsonl` (70 chars).
        let fork_name_len = ledger_id.len() + 1 + 6 + 1 + 16 + ".jsonl".len();
        let mut any_disputed = false;
        for peer in 0..16 {
            let ledgers_dir = op_data_dir(peer).join("wallet/ledgers");
            let Ok(entries) = std::fs::read_dir(&ledgers_dir) else { continue };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(&ledger_id[..]) && name.len() == fork_name_len {
                    any_disputed = true;
                    break;
                }
            }
            if any_disputed {
                break;
            }
        }
        if any_disputed {
            continue;
        }
        return Some((op, ledger_id));
    }
    None
}

pub fn current_block_height() -> u32 {
    let out = Command::new("docker")
        .args([
            "exec",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            "-rpcuser=user",
            "-rpcpassword=pass",
            "getblockcount",
        ])
        .output()
        .expect("docker exec bitcoin-cli getblockcount");
    assert!(
        out.status.success(),
        "getblockcount failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("parse blockcount")
}

/// Fetch the block hash at `height` from bitcoind. Used by tests that
/// need a confirmed anchor at a specific height without having to wait
/// for any operator to commit something that gets anchored there.
pub fn get_block_hash(height: u32) -> [u8; 32] {
    let out = Command::new("docker")
        .args([
            "exec",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            "-rpcuser=user",
            "-rpcpassword=pass",
            "getblockhash",
            &height.to_string(),
        ])
        .output()
        .expect("docker exec bitcoin-cli getblockhash");
    assert!(
        out.status.success(),
        "getblockhash {} failed:\n{}",
        height,
        String::from_utf8_lossy(&out.stderr)
    );
    let hex_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let bytes = hex::decode(&hex_str).expect("parse blockhash hex");
    // bitcoind prints block hashes in big-endian display form. Reverse to
    // get the internal byte order used everywhere in our protocol.
    let mut h: [u8; 32] = bytes.try_into().expect("blockhash is 32 bytes");
    h.reverse();
    h
}

pub fn mine_blocks(n: u32) {
    // Two things made test mining absurdly slow until we caught them:
    //
    // 1. The `miner` Docker container in `deposits-tools/docker-compose.yml`
    //    runs `generatetoaddress 1 <faucet_addr>` in a loop, sleep 1s — a
    //    deliberate "feel like mainnet" throttle for casual dev. While
    //    it's running, every test-driven `generate` call serializes
    //    behind it in bitcoind's RPC queue and effectively inherits the
    //    1-block/sec cadence. For a test that mines 1100 blocks that's
    //    ~18 minutes of dead time.
    //
    // 2. `-generate N` mines through the `-rpcwallet=faucet` wallet so
    //    every coinbase reward gets `AddToWallet`'d. After 8+ days of
    //    miner-container blocks the wallet's UTXO set is huge and each
    //    additional add is non-trivial. `generatetoaddress N <addr>`
    //    with an address bitcoind doesn't index avoids the wallet path
    //    entirely.
    //
    // So: pause the miner container, mine into a fixed throwaway
    // address, restart the miner. Empirically: 100 blocks in 1 sec
    // vs. 437 sec.
    let _ = Command::new("docker").args(["stop", "miner"]).output();

    // Bech32-valid regtest P2WPKH address, not in any cluster wallet.
    // Derived from a fixed test pubkey so the constant is stable.
    const THROWAWAY: &str = "bcrt1qrxv9d5gkdz6xmsqav6sl6su24jjs4qafn2yk4a";
    let out = Command::new("docker")
        .args([
            "exec",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            "-rpcuser=user",
            "-rpcpassword=pass",
            "-rpcclienttimeout=3600",
            "generatetoaddress",
            &n.to_string(),
            THROWAWAY,
        ])
        .output()
        .expect("docker exec bitcoin-cli generatetoaddress");

    // Always try to bring the miner back up — even if the mine itself
    // failed — so subsequent test runs don't inherit a paused miner.
    let _ = Command::new("docker").args(["start", "miner"]).output();

    assert!(
        out.status.success(),
        "mine_blocks({}) failed:\n{}\n{}",
        n,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Wait for the dispute pipeline's confiscation TX to land on chain
/// by polling Esplora until the ledger's reserves UTXO is spent.
///
/// Previously this polled for a `confiscated_<prefix>.marker` file
/// the daemon wrote after broadcasting confiscation. That marker
/// went away in the on-disk-state cleanup; the authoritative
/// equivalent is the chain itself — once the reserves UTXO is gone
/// (spent by the confiscation TX, signed by the quorum threshold),
/// the pipeline has run end-to-end.
///
/// Returns the operator index whose ledger JSONL we read to discover
/// the reserves address (purely for logging compatibility with the
/// prior helper signature). Panics on timeout.
pub fn poll_confiscation_marker(ledger_id: &str, timeout: Duration) -> usize {
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvDecode;

    // The real reserves address lives in the most recent QuorumBegin
    // (its `reserves_id` is the Taproot P2TR script that holds the
    // activation funds). The seq-0 LedgerOpen's `reserves_id` is just
    // the `"genesis:<pubkey>.<idx>"` placeholder — polling that
    // address against esplora returns nothing useful, so the timeout
    // would always fire even after a successful confiscation.
    let (observed_op, reserves_addr): (usize, String) = (0..10)
        .find_map(|op_idx| {
            let path = op_data_dir(op_idx)
                .join("wallet/ledgers")
                .join(format!("{}.jsonl", ledger_id));
            if !path.exists() {
                return None;
            }
            let history = read_ledger_history(&op_data_dir(op_idx), ledger_id);
            history.iter().rev().find_map(|u| {
                let op = LedgerOperation::tlv_decode(&u.message).ok()?;
                if let LedgerOperation::QuorumBegin { reserves_id, .. } = op {
                    Some((op_idx, reserves_id))
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| panic!(
            "no QuorumBegin found anywhere for ledger {} — cannot derive reserves address",
            &ledger_id[..16]
        ));

    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if is_address_fully_spent(&reserves_addr) {
            return observed_op;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    panic!(
        "reserves address {} for ledger {} still has an unspent output after {:?} — \
         confiscation TX never landed",
        reserves_addr, &ledger_id[..16], timeout
    );
}

/// One-shot Esplora query: true iff `address_str` has no unspent
/// outputs at all (`/scripthash/<hash>/utxo` returns `[]`). On any
/// Like `poll_confiscation_marker`, but also returns the confiscation
/// txid (the on-chain TX that spent the reserves UTXO). Use this when
/// the test needs to inspect the confiscation TX shape (output count,
/// values, change address).
pub fn poll_confiscation_txid(ledger_id: &str, timeout: Duration) -> (usize, String) {
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvDecode;

    let (observed_op, reserves_addr): (usize, String) = (0..10)
        .find_map(|op_idx| {
            let path = op_data_dir(op_idx)
                .join("wallet/ledgers")
                .join(format!("{}.jsonl", ledger_id));
            if !path.exists() {
                return None;
            }
            let history = read_ledger_history(&op_data_dir(op_idx), ledger_id);
            history.iter().rev().find_map(|u| {
                let op = LedgerOperation::tlv_decode(&u.message).ok()?;
                if let LedgerOperation::QuorumBegin { reserves_id, .. } = op {
                    Some((op_idx, reserves_id))
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| {
            panic!(
                "no QuorumBegin found anywhere for ledger {} — cannot derive reserves address",
                &ledger_id[..16]
            )
        });

    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Some(txid) = find_spending_txid_for_address(&reserves_addr) {
            return (observed_op, txid);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    panic!(
        "reserves address {} for ledger {} not spent within {:?} — \
         confiscation TX never landed",
        reserves_addr,
        &ledger_id[..16],
        timeout
    );
}

/// After a respectful confiscation lands, return the on-chain txid
/// that spent `reserves_addr`. Used by tests that need to inspect
/// the confiscation TX shape (the old `confiscated_<prefix>.marker`
/// file the daemon used to write went away in the on-disk-state
/// cleanup; the spending TX on chain is the equivalent record).
///
/// Walks `/scripthash/<h>/txs` and picks the TX where the address
/// appears on the *input* side. Returns None if no spend has landed
/// (test caller should poll until present, or assert via
/// `poll_confiscation_marker` first).
pub fn find_spending_txid_for_address(address_str: &str) -> Option<String> {
    use bitcoin::hashes::{sha256, Hash};

    let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        address_str.parse().ok()?;
    let address = address.require_network(bitcoin::Network::Regtest).ok()?;
    let script_hex = hex::encode(address.script_pubkey().as_bytes());
    let script_hash = sha256::Hash::hash(address.script_pubkey().as_bytes());
    let url = format!(
        "{}/scripthash/{}/txs",
        ELECTRS_URL,
        hex::encode(script_hash.to_byte_array())
    );
    let txs: Vec<serde_json::Value> = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?
        .get(&url)
        .send()
        .ok()?
        .json()
        .ok()?;
    for t in txs {
        let vins = t.get("vin")?.as_array()?;
        for vin in vins {
            let prev_spk = vin
                .get("prevout")
                .and_then(|p| p.get("scriptpubkey"))
                .and_then(|s| s.as_str())
                .unwrap_or("");
            if prev_spk == script_hex {
                return t.get("txid").and_then(|x| x.as_str()).map(|s| s.to_string());
            }
        }
    }
    None
}

/// One-shot Esplora query: true iff `address_str` has no unspent
/// outputs at all (`/scripthash/<hash>/utxo` returns `[]`). On any
/// connection / parse error, returns false so the caller keeps
/// retrying within its own deadline.
fn is_address_fully_spent(address_str: &str) -> bool {
    use bitcoin::hashes::{sha256, Hash};

    let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        match address_str.parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
    let address = match address.require_network(bitcoin::Network::Regtest) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let script_hash = sha256::Hash::hash(address.script_pubkey().as_bytes());
    let url = format!(
        "{}/scripthash/{}/utxo",
        ELECTRS_URL,
        hex::encode(script_hash.to_byte_array())
    );
    let resp = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .and_then(|c| c.get(&url).send())
    {
        Ok(r) => r,
        Err(_) => return false,
    };
    if !resp.status().is_success() {
        return false;
    }
    let utxos: Vec<serde_json::Value> = match resp.json() {
        Ok(v) => v,
        Err(_) => return false,
    };
    // Fully spent = no unspent outputs at this address. Esplora
    // returns an empty array when the scripthash has no UTXOs.
    utxos.is_empty()
}

/// Poll until the confiscation output (`reserves_addr` was already spent
/// INTO it; here we watch the lottery P2TR output itself) is spent by the
/// lottery-claim TX — i.e. the fast lottery-claim leaf was successfully
/// spent by the winner. Returns the claim txid and its input-0 witness
/// item byte-lengths (so callers can assert the revealed preimages sit in
/// the valid `[17, 16+N]` band — the exact thing the fixed-length-preimage
/// bug broke). Mines blocks each cycle to advance confirmations.
///
/// `lottery_addr` is the confiscation TX's P2TR output address (the
/// lottery UTXO). Returns `None` on timeout.
pub fn poll_lottery_claim_witness(
    lottery_addr: &str,
    timeout: Duration,
) -> Option<(String, Vec<usize>)> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Some(txid) = find_spending_txid_for_address(lottery_addr) {
            // Fetch the claim TX and return input-0 witness item lengths.
            let url = format!("{}/tx/{}", ELECTRS_URL, txid);
            if let Ok(resp) = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap()
                .get(&url)
                .send()
            {
                if let Ok(v) = resp.json::<serde_json::Value>() {
                    if let Some(w) = v["vin"][0]["witness"].as_array() {
                        let lens: Vec<usize> = w
                            .iter()
                            .filter_map(|x| x.as_str())
                            .map(|h| h.len() / 2)
                            .collect();
                        return Some((txid, lens));
                    }
                }
            }
            return Some((txid, vec![]));
        }
        mine_blocks(2);
        std::thread::sleep(Duration::from_secs(3));
    }
    None
}

/// The confiscation TX's single P2TR output address (the lottery UTXO),
/// read from the on-chain TX that spent the ledger's reserves address.
pub fn lottery_output_address(reserves_spend_txid: &str) -> Option<String> {
    let url = format!("{}/tx/{}", ELECTRS_URL, reserves_spend_txid);
    let v: serde_json::Value = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?
        .get(&url)
        .send()
        .ok()?
        .json()
        .ok()?;
    v["vout"]
        .as_array()?
        .iter()
        .find_map(|o| o["scriptpubkey_address"].as_str().map(|s| s.to_string()))
}

pub fn ledger_health(op_idx: usize, ledger_id: &str) -> String {
    let seed = op_seed(op_idx);
    let data_dir = op_data_dir(op_idx);
    let name = op_name(op_idx);
    let out = Command::new(node_bin())
        .args(["ledger", "health", ledger_id])
        .args(["--seed", &seed])
        .args(["--name", &name])
        .args(["--network", "regtest"])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("deposits-node ledger health");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    combined
}

/// Query `deposits-node nostr dispute status <ledger>` and return the
/// combined stdout+stderr. The command prints one of
/// `DISPUTE_STATUS: SAFE | DISPUTED | RESOLVED`, and (on RESOLVED) a
/// `New custodian:` line. This is the depositor-facing serviceability
/// signal: a wallet refuses to open on DISPUTED and proceeds on
/// SAFE/RESOLVED.
pub fn dispute_status(op_idx: usize, ledger_id: &str) -> String {
    let seed = op_seed(op_idx);
    let data_dir = op_data_dir(op_idx);
    let name = op_name(op_idx);
    let out = Command::new(node_bin())
        .args(["nostr", "dispute", "status", ledger_id])
        .args(["--seed", &seed])
        .args(["--name", &name])
        .args(["--network", "regtest"])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("deposits-node nostr dispute status");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    combined
}

/// True iff any operator's fork of `ledger_id` carries a confirmed
/// `DisputeAcquire` (winner selected + custody transferred). Scans every
/// op's on-disk fork JSONLs — the winner publishes DisputeAcquire on its
/// own fork branch, whose file name is prefixed by the base `ledger_id`.
pub fn dispute_acquire_custodian(ledger_id: &str) -> Option<bitcoin::secp256k1::PublicKey> {
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvDecode;
    for op_idx in 0..10 {
        let dir = op_data_dir(op_idx).join("wallet/ledgers");
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().into_owned();
            // Base ledger file and every fork branch begin with the id.
            if !fname.starts_with(ledger_id) {
                continue;
            }
            let stem = fname.trim_end_matches(".jsonl");
            let history = read_ledger_history(&op_data_dir(op_idx), stem);
            for u in history.iter().rev() {
                if let Ok(LedgerOperation::DisputeAcquire { new_custodian, .. }) =
                    LedgerOperation::tlv_decode(&u.message)
                {
                    return Some(new_custodian);
                }
            }
        }
    }
    None
}

/// Poll until a `DisputeAcquire` (custody transfer to the lottery
/// winner) appears on any op's fork of `ledger_id`, mining a couple of
/// blocks each cycle to advance confirmations / CSV windows that the
/// reveal→claim→acquire cascade waits on. Returns the new custodian, or
/// `None` on timeout.
pub fn poll_dispute_acquire(
    ledger_id: &str,
    timeout: Duration,
) -> Option<bitcoin::secp256k1::PublicKey> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Some(nc) = dispute_acquire_custodian(ledger_id) {
            return Some(nc);
        }
        // Nudge chain forward: reveal fires at confiscation +3 confs, and
        // the claim leaf / CSV paths need blocks. The shared auto-miner
        // also mines, but explicit blocks keep the test deterministic.
        mine_blocks(2);
        std::thread::sleep(Duration::from_secs(3));
    }
    None
}

/// True iff bitcoind is reachable AND the release binaries are built.
pub fn cluster_available() -> bool {
    let bitcoind = Command::new("docker")
        .args([
            "exec",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            "-rpcuser=user",
            "-rpcpassword=pass",
            "getblockcount",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    bitcoind && node_bin().is_file() && wallet_bin().is_file()
}

/// True iff the `lightning` container (LDK) is running. Tests that
/// exercise the invoice/payment path need this; default `./bin/setup.sh`
/// doesn't bring it up — start it with
/// `docker compose --profile lightning up -d lightning`.
pub fn lightning_available() -> bool {
    container_running("lightning")
}

/// True iff the `lnaddr-attest` container is running. Tests that
/// exercise the attestation + domain-allowlist path need this.
pub fn lnaddr_attest_available() -> bool {
    container_running("lnaddr-attest")
}

fn container_running(name: &str) -> bool {
    Command::new("docker")
        .args([
            "ps",
            "--filter",
            &format!("name=^{}$", name),
            "--format",
            "{{.Names}}",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == name)
        .unwrap_or(false)
}

/// Derive the xonly pubkey (hex, 64 chars) from a 64-char hex secret.
pub fn derive_xonly_pubkey(secret_hex: &str) -> Result<String, String> {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    let bytes = hex::decode(secret_hex.trim()).map_err(|e| format!("hex decode: {}", e))?;
    let sk = SecretKey::from_slice(&bytes).map_err(|e| format!("bad secret: {}", e))?;
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    Ok(hex::encode(xonly.serialize()))
}

/// Read `deposits-tools/secrets/verify_nsec` and derive the attestation
/// verifier's xonly pubkey (hex).
pub fn verifier_pubkey_xonly() -> Result<String, String> {
    let path = repo_root().join("deposits-tools/secrets/verify_nsec");
    let sec = std::fs::read_to_string(&path)
        .map_err(|e| format!("read {}: {}", path.display(), e))?;
    derive_xonly_pubkey(&sec)
}

/// Register `<username>` → `<xonly_pubkey>` in the lnaddr-attest
/// container's nip05 fixture (the Python lnurl-server.py reads
/// `/data/nostr.json`). Replaces any prior value for the same username.
pub fn nip05_register(username: &str, xonly_pubkey: &str) -> Result<(), String> {
    // Read the current file, merge in the new name, write it back.
    // All operations happen inside the container where /data is
    // root-owned, side-stepping host sudo.
    let read = Command::new("docker")
        .args(["exec", "lnaddr-attest", "sh", "-c", "cat /data/nostr.json 2>/dev/null || echo '{\"names\":{}}'"])
        .output()
        .map_err(|e| format!("docker exec (read): {}", e))?;
    let current: serde_json::Value = serde_json::from_slice(&read.stdout)
        .unwrap_or_else(|_| serde_json::json!({"names": {}}));
    let mut names = current
        .get("names")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    names.insert(
        username.to_string(),
        serde_json::Value::String(xonly_pubkey.to_string()),
    );
    let merged = serde_json::json!({ "names": names }).to_string();

    let write = Command::new("docker")
        .args(["exec", "-i", "lnaddr-attest", "sh", "-c", "cat > /data/nostr.json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(merged.as_bytes()).ok();
            }
            child.wait_with_output()
        })
        .map_err(|e| format!("docker exec (write): {}", e))?;
    if !write.status.success() {
        return Err(format!(
            "nip05 register failed: {}",
            String::from_utf8_lossy(&write.stderr)
        ));
    }
    Ok(())
}

/// Generate a fresh keypair via `deposits-node keygen`.
/// Returns `(secret_hex, xonly_pubkey_hex)`.
pub fn keygen() -> (String, String) {
    let out = Command::new(node_bin())
        .arg("keygen")
        .output()
        .expect("keygen failed");
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let mut parts = s.split_whitespace();
    let sec = parts.next().expect("keygen: no secret").to_string();
    let compressed = parts.next().expect("keygen: no pubkey").to_string();
    // Strip the leading 02/03 compression byte.
    let xonly = compressed[2..].to_string();
    (sec, xonly)
}

/// Unique scratch directory under /tmp for a single test run.
pub fn tempdir() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "deposits-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Kill the current op0 (= node0) daemon, matching by `--name node0` in
/// the cmdline. Blocks until the process is gone (up to ~5s).
///
/// The hub cluster names node0's daemon `node0`, so the match pattern is
/// `name node0` — NOT the legacy `name op0`. (`--name` and the data-dir
/// path both carry `node0`, so this is unambiguous.)
pub fn kill_op0() {
    let _ = Command::new("pkill").args(["-f", "name node0"]).output();
    for _ in 0..20 {
        let still = Command::new("pgrep")
            .args(["-f", "name node0"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !still {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Spawn op0 (= node0) with the SAME argument shape the hub bootstrap
/// uses (`--name node0`, `--seed-file`, admin/metrics ports, `--fast-poll`)
/// plus any caller-supplied extra env vars (e.g.
/// `DEPOSIT_ACCESS_CONTROL=true`, `ATTESTATION_VERIFIER_PUBKEY=<hex>`).
/// Sleeps briefly so the daemon is up and has loaded its on-disk lists
/// before callers continue.
///
/// Mirroring bootstrap's spawn line matters: the ACL tests kill the
/// hub-spawned node0 and relaunch it here, so the relaunched daemon has
/// to bind the same admin port (8870) and advertise under the same name
/// as the rest of the cluster expects.
pub fn spawn_op0(extra_env: &[(&str, &str)]) {
    let dir = op0_data_dir();
    let log = dir.join("daemon.log");
    let log_out = std::fs::File::options()
        .append(true)
        .create(true)
        .open(&log)
        .unwrap();
    let log_err = log_out.try_clone().unwrap();
    let seed_file = dir.join("seed.hex");
    let mut cmd = Command::new(node_bin());
    cmd.arg("run")
        .args(["--seed-file", seed_file.to_str().unwrap()])
        .args(["--name", &op_name(0)])
        .args(["--network", "regtest"])
        .args(["--data-dir", dir.to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        // node0's metrics port (hub bootstrap: metrics_port(i) = 9200 + i).
        .args(["--metrics-port", "9200"])
        .args(["--admin-bind", &format!("127.0.0.1:{}", admin_port(0))])
        .arg("--fast-poll")
        .args(["--relay", relay_ledgers()])
        .args(["--relay", relay_messaging()])
        .env("RUST_LOG", "warn")
        .stdout(log_out)
        .stderr(log_err);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("op0 spawn failed");
    let _ = std::fs::write(dir.join("daemon.pid"), child.id().to_string());
    std::thread::sleep(Duration::from_secs(6));
}

/// Discover op0's ledger id via `deposits-wallet discover --json`.
/// Returns the first op0-owned ledger whose on-disk history actually
/// contains a committed `QuorumBegin` — i.e., the quorum is active.
/// Polls for up to 60s if no ledger is yet activated: setup.sh's
/// phase-4 prints "Quorums active" based on the operator-side
/// publish, but op0's local daemon needs a few seconds to ingest
/// its own QuorumBegin and write it to local jsonl. Falls back to
/// the first op0 ledger ID seen if nothing's quorum-begun within
/// the window — that preserves the prior behavior for tests that
/// just want SOME op0 ledger (e.g. allowlist tests), so this poll
/// is purely additive: faster path for active-quorum callers, no
/// regression for not-yet-active fallback callers.
pub fn discover_op0_ledger() -> String {
    // node0's ledger id is authoritative in bootstrap-state.json — no need
    // to sift relay ads by operator_name (which the hub cluster advertises
    // as "node0", not "op0"). Poll node0's local jsonl for a committed
    // QuorumBegin so callers that expect an *active* quorum still get one;
    // fall back to the bare ledger id after the window for callers that
    // just want SOME op0 ledger (allowlist tests).
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tlv::TlvDecode;

    let ledger_id = op_ledger(0);
    let op0_data_dir = op0_data_dir();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let path = op0_data_dir
            .join("wallet/ledgers")
            .join(format!("{}.jsonl", ledger_id));
        if path.exists() {
            let history = read_ledger_history(&op0_data_dir, &ledger_id);
            let has_quorum_begin = history.iter().any(|u| {
                matches!(
                    LedgerOperation::tlv_decode(&u.message),
                    Ok(LedgerOperation::QuorumBegin { .. })
                )
            });
            if has_quorum_begin {
                return ledger_id;
            }
        }
        if std::time::Instant::now() >= deadline {
            return ledger_id;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Run `deposits-wallet open` with the given args. Returns combined
/// stdout+stderr and the success flag.
///
/// `extra_args` lets a caller pass subkey-delegation flags
/// (`--subkey-of`, `--attestation-sig`) without bloating the base
/// signature.
pub fn wallet_open(
    ledger: &str,
    alias: &str,
    nsec_path: &Path,
    data_dir: &Path,
    extra_args: &[&str],
) -> (bool, String) {
    let mut cmd = Command::new(wallet_bin());
    cmd.args(["open", ledger, "100000"])
        .args(["--alias", alias])
        .args(["--nsec-file", nsec_path.to_str().unwrap()])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--relay", relay_messaging()])
        .args(["--network", "regtest"]);
    for a in extra_args {
        cmd.arg(a);
    }
    let out = cmd.output().expect("wallet open invocation failed");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), combined)
}

/// Open `n` throwaway deposits on `ledger_id` so the chain advances
/// past whatever sequence the caller cares about. Used by the
/// fraud-proof tests whose evidence cites a `proof_sequence` past
/// `QuorumBegin` — fresh setup ledgers have QB at the tip, so a
/// proof_sequence picked from the visible chain lands AT QB, and the
/// daemon's `LVS = proof_sequence - 1` falls BEFORE QB; cosigners
/// then refuse with "no QuorumBegin observed at or before
/// last_valid_sequence." Open a few deposits to shove the chain
/// past QB and the proof can cite something post-rotation.
///
/// Each open lands one update (a `DepositOpen` that gets cosigned).
/// Returns the new chain tip sequence as observed from the
/// `peer_op_idx` (any quorum member of `ledger_id` works).
pub fn extend_chain_past_qb(
    ledger_id: &str,
    peer_op_idx: usize,
    n: usize,
) -> u64 {
    use std::time::Instant;

    let wdir = tempdir();
    let (sec_hex, _xonly) = keygen();
    let nsec = wdir.join("wallet.nsec");
    std::fs::write(&nsec, &sec_hex).expect("write wallet nsec");

    for i in 0..n {
        let alias = format!("chain-ext-{}", i);
        let (ok, out) = wallet_open(ledger_id, &alias, &nsec, &wdir, &[]);
        if !ok {
            // Don't abort the test — even a partial extension may be
            // enough to push past QB. Just log and continue.
            eprintln!(
                "[extend_chain_past_qb] wallet open #{} failed; continuing:\n{}",
                i, out
            );
        }
    }

    // Poll for the chain to actually catch up on the peer's view.
    // wallet_open returns once the operator commits, but the peer's
    // ledger_actor needs a moment to apply the broadcast update.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_tip = 0u64;
    while Instant::now() < deadline {
        let h = read_ledger_history(&op_data_dir(peer_op_idx), ledger_id);
        if let Some(u) = h.last() {
            last_tip = u.sequence_number;
        }
        // Heuristic: stop polling once we've seen at least `n` more
        // updates than were present before extension (or after 30s).
        if last_tip > 0 {
            std::thread::sleep(Duration::from_millis(500));
        }
        if Instant::now() + Duration::from_secs(5) >= deadline {
            break;
        }
    }
    last_tip
}

/// Publish a DEP-04 Kind 10301 subkey attestation: `account_nsec`
/// attests that `subkey_xonly` is delegated to it. Returns the signature
/// hex that wallets bake into their `va` tag.
pub fn wallet_attest(
    subkey_xonly: &str,
    account_nsec: &Path,
    data_dir: &Path,
) -> Result<String, String> {
    let out = Command::new(wallet_bin())
        .args(["attest", subkey_xonly])
        .args(["--nsec-file", account_nsec.to_str().unwrap()])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--relay", relay_messaging()])
        .args(["--network", "regtest"])
        .output()
        .expect("wallet attest invocation failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The command prints "  attestation:  <hex>" on success.
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("attestation:") {
            return Ok(rest.trim().to_string());
        }
    }
    Err(format!(
        "attest produced no attestation signature\nstdout:\n{}\nstderr:\n{}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// Revoke a previously-attested subkey. Fire-and-forget — errors are
/// surfaced via the process exit code only.
pub fn wallet_revoke(subkey_xonly: &str, account_nsec: &Path, data_dir: &Path) {
    let _ = Command::new(wallet_bin())
        .args(["revoke", subkey_xonly])
        .args(["--nsec-file", account_nsec.to_str().unwrap()])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--relay", relay_messaging()])
        .args(["--network", "regtest"])
        .output();
}

/// RAII guard: snapshots op0's `deposit_allowlist.txt` on construction,
/// restores it and relaunches op0 with ACL off on drop. Runs even on
/// panic, so a failing test doesn't leave op0 half-configured.
pub struct Op0AccessControl {
    allowlist_backup: Option<Vec<u8>>,
    domain_allowlist_backup: Option<Vec<u8>>,
}

fn allowlist_path() -> PathBuf {
    op0_data_dir().join("deposit_allowlist.txt")
}

fn domain_allowlist_path() -> PathBuf {
    op0_data_dir().join("deposit_domain_allowlist.txt")
}

fn write_list(path: &Path, entries: &[&str]) {
    let body = entries
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path, body).unwrap();
}

impl Op0AccessControl {
    /// Capture the current allowlist, kill op0, write `allowlist` to
    /// disk, and relaunch op0 with `DEPOSIT_ACCESS_CONTROL=true`.
    /// Each line of `allowlist` is one xonly pubkey hex.
    pub fn enable(allowlist: &[&str]) -> Self {
        Self::enable_inner(allowlist, &[], None)
    }

    /// Like `enable`, but also writes a domain allowlist and sets
    /// `ATTESTATION_VERIFIER_PUBKEY` so op0 accepts deposit_open
    /// requests when the account's attestation references one of the
    /// allowed domains.
    pub fn enable_with_attestation(
        allowlist: &[&str],
        domain_allowlist: &[&str],
        verifier_xonly: &str,
    ) -> Self {
        Self::enable_inner(allowlist, domain_allowlist, Some(verifier_xonly))
    }

    fn enable_inner(
        allowlist: &[&str],
        domain_allowlist: &[&str],
        verifier_xonly: Option<&str>,
    ) -> Self {
        let allowlist_backup = std::fs::read(allowlist_path()).ok();
        let domain_allowlist_backup = std::fs::read(domain_allowlist_path()).ok();
        kill_op0();
        write_list(&allowlist_path(), allowlist);
        write_list(&domain_allowlist_path(), domain_allowlist);

        let mut env: Vec<(&str, &str)> = vec![("DEPOSIT_ACCESS_CONTROL", "true")];
        if let Some(vk) = verifier_xonly {
            env.push(("ATTESTATION_VERIFIER_PUBKEY", vk));
        }
        spawn_op0(&env);
        Self {
            allowlist_backup,
            domain_allowlist_backup,
        }
    }

    /// Rewrite the allowlist and restart op0 (still with ACL on).
    pub fn set_allowlist(&self, allowlist: &[&str]) {
        kill_op0();
        write_list(&allowlist_path(), allowlist);
        spawn_op0(&[("DEPOSIT_ACCESS_CONTROL", "true")]);
    }
}

impl Drop for Op0AccessControl {
    fn drop(&mut self) {
        kill_op0();
        restore_file(&allowlist_path(), self.allowlist_backup.as_deref());
        restore_file(&domain_allowlist_path(), self.domain_allowlist_backup.as_deref());
        spawn_op0(&[]);
    }
}

fn restore_file(path: &Path, backup: Option<&[u8]>) {
    match backup {
        Some(bytes) => {
            let _ = std::fs::write(path, bytes);
        }
        None => {
            let _ = std::fs::remove_file(path);
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Per-test fresh-victim helpers
//
// Tests that need a known-healthy ledger to drive a specific
// failure mode (fraud_proof_*, lifecycle_self_rescue) can't lean
// on setup.sh-provisioned ledgers — once other tests in the same
// `cargo test` run mine past expiry or fork-dispute a ledger, the
// state is unreachable from a hardcoded `ledger_X_Y` pick.
//
// These helpers open a fresh victim ledger on a chosen operator,
// add Q healthy cosigners, activate the quorum with a configurable
// `--quorum-expiry-blocks`, and return enough handles for the
// caller's downstream forge / dispute work.
// ─────────────────────────────────────────────────────────────────

/// Build the standard CLI arg block for invoking `deposits-node`
/// against operator `i`'s data dir + seed.
pub fn op_cli_args(i: usize) -> Vec<String> {
    vec![
        "--seed".into(), op_seed(i),
        "--name".into(), op_name(i),
        "--data-dir".into(), op_data_dir(i).to_string_lossy().into_owned(),
        "--network".into(), "regtest".into(),
        "--esplora".into(), ELECTRS_URL.into(),
        "--relay".into(), relay_ledgers().to_string(),
        "--relay".into(), relay_messaging().to_string(),
    ]
}

/// Invoke `deposits-node <args>` against operator `i`. Returns
/// stdout on success, panics on non-zero with stdout+stderr.
pub fn run_op_node(node: &Path, op_idx: usize, subcmd_args: &[&str]) -> String {
    let mut cmd = Command::new(node);
    for a in subcmd_args {
        cmd.arg(a);
    }
    for a in op_cli_args(op_idx) {
        cmd.arg(a);
    }
    cmd.env("RUST_LOG", "warn");
    let out = cmd.output().expect("deposits-node invocation failed to spawn");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        panic!(
            "deposits-node {:?} on op{} exited {}: stdout={} stderr={}",
            subcmd_args, op_idx, out.status, stdout, stderr
        );
    }
    stdout
}

/// Send `amount_sats` from the regtest faucet to `address`.
/// Mirrors `setup.sh`'s `bitcoin_cli ... sendtoaddress`.
pub fn faucet_send(address: &str, amount_sats: u64) -> String {
    let btc_str = format!("{}.{:08}", amount_sats / 100_000_000, amount_sats % 100_000_000);
    let out = Command::new("docker")
        .args([
            "exec", "bitcoind", "bitcoin-cli", "-regtest",
            "-rpcwallet=faucet",
            "-rpcuser=user", "-rpcpassword=pass",
            "sendtoaddress", address, &btc_str,
        ])
        .output()
        .expect("docker exec bitcoin-cli sendtoaddress");
    assert!(
        out.status.success(),
        "faucet sendtoaddress failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Scan operators `1..upper` for ones whose own primary ledger
/// (`ledger_<i>_1`) is still inside its quorum window with at
/// least `min_headroom` blocks of cushion. Returns up to `wanted`
/// `(op_idx, member_pk, member_ledger_id)` triples — the data
/// `quorum add` needs to register them as cosigners.
///
/// Excludes `exclude_op` from the candidate set (the victim's own
/// operator shouldn't be a cosigner on its own ledger).
pub fn find_healthy_members(wanted: usize, exclude_op: usize) -> Vec<(usize, String, String)> {
    let mut found = Vec::new();
    for op_idx in 1..10 {
        if found.len() >= wanted {
            break;
        }
        if op_idx == exclude_op {
            continue;
        }
        // node{op_idx}'s operator pubkey + its single ledger, from the
        // hub's bootstrap-state.json.
        let (Some(pk), Some(lid)) = (op_node_id(op_idx), try_op_ledger(op_idx)) else {
            continue;
        };
        let Some((tip, exp)) = lifecycle_expiry(op_idx, &lid) else {
            continue;
        };
        // Need real cushion — quorum-begin on the victim mines a
        // confirmation block, the funding wait elapses, etc.
        if tip + 50 < exp {
            found.push((op_idx, pk, lid));
        }
    }
    found
}

/// Result of [`open_victim_quorum_ledger`].
pub struct VictimQuorum {
    /// The freshly-opened victim ledger ID.
    pub victim_ledger: String,
    /// Members added to the victim's quorum: `(op_idx, member_pk, member_ledger_id)`.
    pub members: Vec<(usize, String, String)>,
    /// The block height at which `quorum begin` activated the victim's quorum.
    pub activation_tip: u32,
    /// The `quorum_expiry` recorded on the victim's `QuorumBegin`.
    pub quorum_expiry: u32,
}

/// Open + fund + activate a fresh victim ledger on operator
/// `owner_op_idx`. Q members are pulled from
/// [`find_healthy_members`] (any op other than `owner_op_idx`
/// whose own primary ledger is still healthy). The activated
/// quorum gets `expiry_blocks` of life (call sites pick this
/// based on test intent: short for "I want to expire this within
/// the test," long for "I want this stable through the whole
/// test").
///
/// Returns `None` if Q healthy members can't be found — caller
/// should skip with a "rerun against `setup.sh --fresh 3`"
/// message rather than panic.
///
/// Cost: ~80–120s end-to-end (mostly the funding-sync wait
/// + activation mining). Lift the victim to a `OnceLock`-style
/// per-process cache if a single test file needs many fresh
/// victims.
pub fn open_victim_quorum_ledger(
    node: &Path,
    owner_op_idx: usize,
    expiry_blocks: u32,
    member_count: usize,
) -> Option<VictimQuorum> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tlv::TlvDecode;
    use std::time::Instant;

    // ── 1. Open the victim ──
    let open_out = run_op_node(node, owner_op_idx, &["ledger", "open"]);
    let victim = open_out
        .lines()
        .find_map(|l| {
            l.strip_prefix("  Ledger ID: ")
                .or_else(|| l.strip_prefix("Ledger ID: "))
                .map(str::to_string)
        })?;
    eprintln!("[victim] op{} opened victim ledger: {}…", owner_op_idx, &victim[..16]);

    // ── 2. Fund the victim's per-ledger wallet ──
    let address_out = run_op_node(node, owner_op_idx, &["ledger", "address", &victim]);
    let address = address_out
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())?
        .trim()
        .to_string();
    eprintln!("[victim] funding {}…  → {}", &victim[..16], address);
    let _ = faucet_send(&address, 100_000_000);
    mine_blocks(6);
    let funding_tip = current_block_height();
    let _ = wait_for_daemon_chain_tip(owner_op_idx, funding_tip, Duration::from_secs(60));
    // BDK wallet poller can lag the chain tip; give it one fast-poll
    // cycle to ingest the new UTXO.
    std::thread::sleep(Duration::from_secs(45));
    let _ = run_op_node(node, owner_op_idx, &[
        "ledger", "advertise",
        "--name", &op_name(owner_op_idx),
        "--advertise-relay", relay_ledgers(),
    ]);

    // ── 3. Add Q healthy cosigners ──
    let members = find_healthy_members(member_count, owner_op_idx);
    if members.len() < member_count {
        eprintln!(
            "[victim] only found {} healthy members (need {}); aborting victim setup",
            members.len(),
            member_count
        );
        return None;
    }
    for (op_idx, member_pk, member_ledger) in &members {
        run_op_node(node, owner_op_idx, &[
            "quorum", "add", &victim, member_pk, member_ledger,
        ]);
        eprintln!("[victim] op{} added as cosigner", op_idx);
    }

    // ── 4. Activate quorum with the requested expiry ──
    eprintln!(
        "[victim] quorum begin --quorum-expiry-blocks {} on victim",
        expiry_blocks
    );
    let mut begin_cmd = Command::new(node);
    begin_cmd.args(["quorum", "begin", &victim])
        .args(["--amount-sats", "99999000"])
        .args(["--collateral-ratio", "0.6"])
        .args(["--protocol-version", "cltv-offset-v2"])
        .args(["--quorum-expiry-blocks", &expiry_blocks.to_string()]);
    for a in op_cli_args(owner_op_idx) {
        begin_cmd.arg(a);
    }
    begin_cmd.env("RUST_LOG", "warn");
    let mut begin_child = begin_cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("quorum begin spawn");
    // Mine periodic blocks so the rotation TX gets a confirmation
    // — mirrors setup.sh Phase 4.
    let begin_deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if begin_child.try_wait().expect("try_wait").is_some() {
            break;
        }
        if Instant::now() > begin_deadline {
            let _ = begin_child.kill();
            panic!("quorum begin did not exit within 180s");
        }
        mine_blocks(1);
        std::thread::sleep(Duration::from_secs(3));
    }
    let begin_out = begin_child.wait_with_output().expect("wait_with_output");
    if !begin_out.status.success() {
        panic!(
            "quorum begin failed: stdout={} stderr={}",
            String::from_utf8_lossy(&begin_out.stdout),
            String::from_utf8_lossy(&begin_out.stderr),
        );
    }

    // ── 5. Read activation block + expiry from local history ──
    let history = read_ledger_history(&op_data_dir(owner_op_idx), &victim);
    let mut quorum_expiry: Option<u32> = None;
    for u in history.iter().rev() {
        if let Ok(LedgerOperation::QuorumBegin { quorum_expiry: qe, .. }) =
            LedgerOperation::tlv_decode(&u.message)
        {
            quorum_expiry = Some(qe);
            break;
        }
    }
    let quorum_expiry = quorum_expiry?;
    let activation_tip = current_block_height();
    eprintln!(
        "[victim] activated at tip={} with quorum_expiry={}",
        activation_tip, quorum_expiry
    );

    Some(VictimQuorum {
        victim_ledger: victim,
        members,
        activation_tip,
        quorum_expiry,
    })
}
