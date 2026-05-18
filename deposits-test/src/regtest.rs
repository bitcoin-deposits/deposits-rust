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

pub const OP0_SEED: &str = "6f70300000000000000000000000000000000000000000000000000000000000";
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

pub fn node_bin() -> PathBuf {
    repo_root().join("target/release/deposits-node")
}

pub fn wallet_bin() -> PathBuf {
    repo_root().join("target/release/deposits-wallet")
}

pub fn op0_data_dir() -> PathBuf {
    repo_root().join("deposits-tools/data/op0")
}

/// Seed for operator at index `i`. Matches setup.sh's convention:
///   SEEDS["op$i"] = python3 -c "print('op$i'.encode().hex().ljust(64, '0'))"
/// So op0 → "6f7030..." (= "op0" hex, zero-padded to 64).
pub fn op_seed(i: usize) -> String {
    let label = format!("op{}", i);
    let mut hex = hex::encode(label.as_bytes());
    while hex.len() < 64 {
        hex.push('0');
    }
    hex
}

/// Data dir for operator at index `i` under the running cluster.
pub fn op_data_dir(i: usize) -> PathBuf {
    repo_root().join(format!("deposits-tools/data/op{}", i))
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

/// Look up a ledger ID stored under `data_dir/state/<key>` by `setup.sh`.
pub fn read_setup_state(key: &str) -> String {
    let path = repo_root()
        .join("deposits-tools/data/state")
        .join(key);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e))
        .trim()
        .to_string()
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
    let name = format!("op{}", op_idx);
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
    let out = Command::new(wallet_bin())
        .args([
            "route",
            from_alias,
            to_alias,
            &amount_sats.to_string(),
        ])
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
    let name = format!("op{}", op_idx);
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
    std::thread::sleep(Duration::from_secs(3));

    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvDecode;
    read_ledger_history(&op_data_dir(peer_op_idx), ledger_id)
        .into_iter()
        .rev()
        .find(|u| {
            LedgerOperation::tlv_decode(&u.message)
                .ok()
                .and_then(|op| op.embedded_hash().copied())
                .map(|h| h == proof_hash)
                .unwrap_or(false)
        })
        .expect("embedding update should be in peer's view of accused history")
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
    let name = format!("op{}", op_idx);
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
pub fn fund_operator_key_address(op_idx: usize, amount_sats: u64) -> bitcoin::Txid {
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    use std::str::FromStr;
    // Mirror derive_operator_secret: `m/86'/0'/0'/0/0` from seed.
    let seed = op_seed(op_idx);
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
    bitcoin::Txid::from_str(&txid_str).expect("parse txid")
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

    // Find the LedgerOpen's `reserves_id` in any operator's view.
    let (observed_op, reserves_addr): (usize, String) = (0..10)
        .find_map(|op_idx| {
            let path = op_data_dir(op_idx)
                .join("wallet/ledgers")
                .join(format!("{}.jsonl", ledger_id));
            if !path.exists() {
                return None;
            }
            let history = read_ledger_history(&op_data_dir(op_idx), ledger_id);
            history.iter().find_map(|u| {
                let op = LedgerOperation::tlv_decode(&u.message).ok()?;
                if let LedgerOperation::LedgerOpen { reserves_id, .. } = op {
                    Some((op_idx, reserves_id))
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| panic!(
            "no LedgerOpen found anywhere for ledger {} — cannot derive reserves address",
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

pub fn ledger_health(op_idx: usize, ledger_id: &str) -> String {
    let seed = op_seed(op_idx);
    let data_dir = op_data_dir(op_idx);
    let name = format!("op{}", op_idx);
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

/// Kill the current op0 daemon, matching by `name op0` in the cmdline.
/// Blocks until the process is gone (up to ~5s).
pub fn kill_op0() {
    let _ = Command::new("pkill").args(["-f", "name op0"]).output();
    for _ in 0..20 {
        let still = Command::new("pgrep")
            .args(["-f", "name op0"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !still {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Spawn op0 with the standard release-binary arguments plus any caller-
/// supplied extra env vars (e.g. `DEPOSIT_ACCESS_CONTROL=true`,
/// `ATTESTATION_VERIFIER_PUBKEY=<hex>`). Sleeps briefly so the daemon
/// is up and has loaded its on-disk lists before callers continue.
pub fn spawn_op0(extra_env: &[(&str, &str)]) {
    let log = op0_data_dir().join("daemon.log");
    let log_out = std::fs::File::options()
        .append(true)
        .create(true)
        .open(&log)
        .unwrap();
    let log_err = log_out.try_clone().unwrap();
    let mut cmd = Command::new(node_bin());
    cmd.arg("run")
        .args(["--seed", OP0_SEED])
        .args(["--name", "op0"])
        .args(["--network", "regtest"])
        .args(["--data-dir", op0_data_dir().to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .args(["--relay", relay_messaging()])
        .env("RUST_LOG", "warn")
        .stdout(log_out)
        .stderr(log_err);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let _child = cmd.spawn().expect("op0 spawn failed");
    std::thread::sleep(Duration::from_secs(6));
}

/// Discover op0's ledger id via `deposits-wallet discover --json`.
/// Returns the first op0-owned ledger whose on-disk history actually
/// contains a committed `QuorumBegin` — i.e., the quorum is active.
/// Phase 4 of `setup.sh` is racy and may leave 1-3 of op0's ledgers
/// stuck in the staged state; picking one of those would panic the
/// caller looking for `quorum_expiry`.
pub fn discover_op0_ledger() -> String {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tlv::TlvDecode;

    let scratch = tempdir();
    let out = Command::new(wallet_bin())
        .args(["discover", "--json"])
        .args(["--relay", relay_ledgers()])
        .args(["--network", "regtest"])
        .args(["--data-dir", scratch.to_str().unwrap()])
        .output()
        .expect("discover failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let op0_data_dir = op0_data_dir();
    let mut fallback: Option<String> = None;
    for line in stdout.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("type").and_then(|x| x.as_str()) != Some("ledger")
            || v.get("operator_name").and_then(|x| x.as_str()) != Some("op0")
        {
            continue;
        }
        let ledger_id = v
            .get("ledger_id")
            .and_then(|x| x.as_str())
            .unwrap()
            .to_string();
        if fallback.is_none() {
            fallback = Some(ledger_id.clone());
        }
        // Inspect the local jsonl for a QuorumBegin operation. If
        // present, this ledger is activated and usable; otherwise
        // it's still staged and would fail downstream.
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
    fallback.expect("couldn't find a ledger owned by op0")
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
