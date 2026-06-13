//! `deposits-hub bootstrap` — fund once, `--nodes N`, walk away.
//!
//! Stands up a self-connected cluster: N operator daemons, one ledger
//! each, every ledger's quorum being Q=3 cosigners drawn from the other
//! operators (so N ≥ 4 — the dispute lottery's partial-reveal leaves
//! need at least 3 participants, see `PARTIAL_REVEAL_MIN_N`).
//!
//! On-chain footprint is the protocol floor: ONE funding transaction
//! into the hub's treasury, ONE disbursement transaction paying all N
//! ledger addresses (`deposits-node wallet send-many`), then the N
//! unavoidable quorum-begin activation transactions.
//!
//! All keys derive from `hub-master-seed` via the existing BIP-85 path
//! (`state::derive_signer_seed`): node i at index 1_000_000+i, the
//! treasury at 999_999. One mnemonic backs up the entire cluster.
//!
//! The pipeline persists `bootstrap-state.json` after every phase and is
//! resumable: re-running the command skips completed phases, re-spawns
//! dead daemons, and re-polls pending confirmations. Mainnet runs are
//! expected to be interrupted by confirmation waits — that's normal;
//! re-run (or just leave it running).
//!
//! Phases:
//!   1. seeds      — derive treasury + N node seeds, write seed files
//!   2. daemons    — spawn N `deposits-node run` children, wait Node IDs
//!   3. funding    — print the treasury address + required amount, poll
//!                   the esplora until the UTXO confirms
//!   4. ledgers    — `ledger open` on each node, collect funding addrs
//!   5. disburse   — ONE send-many from the treasury to all N ledgers,
//!                   wait confirmations + wallet ingestion
//!   6. quorums    — cross-wire `quorum add` (3 members per ledger),
//!                   then `quorum begin` all ledgers in parallel
//!   7. verify     — poll every daemon's admin API until lifecycle
//!                   reports the quorum Active

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use crate::state;

const TREASURY_INDEX: u32 = 999_999;
const NODE_INDEX_BASE: u32 = 1_000_000;
/// Cosigners per ledger. Protocol floor — see PARTIAL_REVEAL_MIN_N.
const Q: usize = 3;
const DEFAULT_PER_LEDGER_SATS: u64 = 1_000_000; // 0.01 BTC
/// Multiplier on the estimated disbursement fee — covers vsize rounding
/// and fee-estimate drift between funding and broadcast. The whole flow
/// is "fund once", so erring high beats a stall; 2× of a real estimate
/// is generous without being the old flat 50k.
const DISBURSEMENT_FEE_SAFETY: u64 = 2;

/// Estimated fee for the single disbursement tx: one P2WPKH input, N
/// ledger outputs + 1 change. Standard segwit sizing (witness
/// discounted); the safety multiplier absorbs the approximation.
///
///   non-witness: 10 overhead + 41 input + 31 per output
///   witness:     (2 marker/flag + ~107 input witness) / 4 ≈ 28 vB
fn disbursement_fee_sats(nodes: u32, fee_rate_sat_vb: u64) -> u64 {
    let outputs = nodes as u64 + 1; // N ledgers + change
    let vsize = 10 + 41 + 28 + 31 * outputs;
    vsize * fee_rate_sat_vb.max(1) * DISBURSEMENT_FEE_SAFETY
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct BootstrapState {
    network: String,
    nodes: u32,
    per_ledger_sats: u64,
    treasury_address: Option<String>,
    /// node name -> Node ID (operator pubkey, compressed hex)
    node_ids: BTreeMap<String, String>,
    /// node name -> ledger id
    ledgers: BTreeMap<String, String>,
    /// node name -> ledger funding address
    ledger_addresses: BTreeMap<String, String>,
    disbursement_txid: Option<String>,
    /// node name -> quorum members added
    quorums_added: BTreeMap<String, bool>,
    begun: BTreeMap<String, bool>,
    active: BTreeMap<String, bool>,
}

impl BootstrapState {
    fn path(dir: &Path) -> PathBuf {
        dir.join("bootstrap-state.json")
    }
    fn load(dir: &Path) -> Self {
        std::fs::read_to_string(Self::path(dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    fn save(&self, dir: &Path) {
        let tmp = Self::path(dir).with_extension("json.tmp");
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&tmp, json)
                .and_then(|_| std::fs::rename(&tmp, Self::path(dir)));
        }
    }
}

pub struct BootstrapArgs {
    pub data_dir: PathBuf,
    pub nodes: u32,
    pub network: String,
    pub relays: Vec<String>,
    pub esplora: String,
    pub per_ledger_sats: u64,
    pub fee_rate: u64,
    pub node_bin: PathBuf,
    pub quorum_expiry_blocks: Option<u32>,
}

pub fn parse_args(rest: &[String]) -> Result<BootstrapArgs, String> {
    let mut data_dir: Option<PathBuf> = None;
    let mut nodes: u32 = 4;
    let mut network = "regtest".to_string();
    let mut relays = Vec::new();
    let mut esplora: Option<String> = None;
    let mut per_ledger_sats = DEFAULT_PER_LEDGER_SATS;
    let mut fee_rate = 2u64;
    let mut node_bin: Option<PathBuf> = None;
    let mut quorum_expiry_blocks: Option<u32> = None;

    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--data-dir" => {
                data_dir = Some(PathBuf::from(&rest[i + 1]));
                i += 1;
            }
            "--nodes" => {
                nodes = rest[i + 1].parse().map_err(|e| format!("--nodes: {}", e))?;
                i += 1;
            }
            "--network" => {
                network = rest[i + 1].clone();
                i += 1;
            }
            "--relay" => {
                relays.push(rest[i + 1].clone());
                i += 1;
            }
            "--esplora" => {
                esplora = Some(rest[i + 1].clone());
                i += 1;
            }
            "--per-ledger-sats" => {
                per_ledger_sats = rest[i + 1]
                    .parse()
                    .map_err(|e| format!("--per-ledger-sats: {}", e))?;
                i += 1;
            }
            "--fee-rate" => {
                fee_rate = rest[i + 1].parse().map_err(|e| format!("--fee-rate: {}", e))?;
                i += 1;
            }
            "--node-bin" => {
                node_bin = Some(PathBuf::from(&rest[i + 1]));
                i += 1;
            }
            "--quorum-expiry-blocks" => {
                quorum_expiry_blocks = Some(
                    rest[i + 1]
                        .parse()
                        .map_err(|e| format!("--quorum-expiry-blocks: {}", e))?,
                );
                i += 1;
            }
            other => return Err(format!("unknown flag {}", other)),
        }
        i += 1;
    }

    // Q=3 cosigners per ledger, operator excluded → at least 4 nodes.
    if nodes < (Q as u32 + 1) {
        return Err(format!(
            "--nodes must be ≥ {} (each ledger needs Q={} cosigners besides its operator)",
            Q + 1,
            Q
        ));
    }
    if relays.is_empty() {
        return Err("at least one --relay is required".into());
    }
    let esplora = esplora.ok_or("--esplora is required")?;
    let data_dir = data_dir.unwrap_or_else(|| {
        dirs_home().join(".deposits-hub")
    });
    let node_bin = node_bin
        .or_else(|| std::env::var("DEPOSITS_NODE").ok().map(PathBuf::from))
        .or_else(|| {
            // Sibling of this binary, then target/debug fallback.
            std::env::current_exe().ok().and_then(|p| {
                let sib = p.parent()?.join("deposits-node");
                sib.exists().then_some(sib)
            })
        })
        .ok_or("deposits-node binary not found — pass --node-bin or set DEPOSITS_NODE")?;

    Ok(BootstrapArgs {
        data_dir,
        nodes,
        network,
        relays,
        esplora,
        per_ledger_sats,
        fee_rate,
        node_bin,
        quorum_expiry_blocks,
    })
}


/// Pull a bitcoin address out of CLI output that may be interleaved with
/// tracing lines. Last plausible token wins.
fn extract_address(out: &str) -> Option<String> {
    out.lines()
        .rev()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains(' '))
        .find(|l| {
            let lower = l.to_lowercase();
            (lower.starts_with("bc1") || lower.starts_with("tb1") || lower.starts_with("bcrt1"))
                && l.len() >= 14
                && l.chars().all(|c| c.is_ascii_alphanumeric())
        })
        .map(str::to_string)
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."))
}

fn node_name(i: u32) -> String {
    format!("node{}", i)
}

/// Run the deposits-node CLI with config flags appended; capture output.
async fn node_cli(
    args: &BootstrapArgs,
    seed_file: &Path,
    data_dir: &Path,
    name: &str,
    cmd: &[&str],
) -> Result<String, String> {
    let mut c = tokio::process::Command::new(&args.node_bin);
    c.args(cmd)
        .arg("--seed-file")
        .arg(seed_file)
        .arg("--name")
        .arg(name)
        .arg("--network")
        .arg(&args.network)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--esplora")
        .arg(&args.esplora);
    for r in &args.relays {
        c.arg("--relay").arg(r);
    }
    let out = c
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("spawn {}: {}", args.node_bin.display(), e))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        return Err(format!("`{}` failed:\n{}", cmd.join(" "), combined));
    }
    Ok(combined)
}

fn node_dir(args: &BootstrapArgs, i: u32) -> PathBuf {
    args.data_dir.join("bootstrap-nodes").join(node_name(i))
}

fn seed_file_for(dir: &Path) -> PathBuf {
    dir.join("seed.hex")
}

/// `deposits-hub bootstrap --reset [--data-dir D] [--force]`
///
/// Tear a bootstrapped cluster down to bare metal: kill the spawned
/// daemons and delete the per-run state so the next `bootstrap` starts
/// clean. Always safe to re-run.
///
/// The one irreplaceable thing is `hub-master-seed` — every node and
/// treasury key derives from it, so deleting it on a network with real
/// funds means losing access. The guard: the seed is removed only when
/// `bootstrap-state.json` records `network=regtest`, or `--force` is
/// passed. Without proof of regtest and without --force, everything
/// else is wiped but the seed is kept (with a printed note).
fn reset(rest: &[String]) -> Result<(), String> {
    let mut data_dir: Option<PathBuf> = None;
    let mut force = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--data-dir" => {
                data_dir = Some(PathBuf::from(rest.get(i + 1).ok_or("--data-dir needs a value")?));
                i += 1;
            }
            "--force" => force = true,
            "--reset" => {}
            other => return Err(format!("--reset: unexpected flag {}", other)),
        }
        i += 1;
    }
    let data_dir = data_dir.unwrap_or_else(|| dirs_home().join(".deposits-hub"));

    // Determine the network from any surviving state (to gate seed deletion).
    let network = std::fs::read_to_string(BootstrapState::path(&data_dir))
        .ok()
        .and_then(|s| serde_json::from_str::<BootstrapState>(&s).ok())
        .map(|st| st.network)
        .unwrap_or_default();

    // Kill spawned daemons via their pid files.
    let nodes_root = data_dir.join("bootstrap-nodes");
    let mut killed = 0;
    if let Ok(entries) = std::fs::read_dir(&nodes_root) {
        for e in entries.flatten() {
            let pidf = e.path().join("daemon.pid");
            if let Ok(pid) = std::fs::read_to_string(&pidf) {
                if let Ok(pid) = pid.trim().parse::<i32>() {
                    if unsafe { libc_kill(pid, 15) } == 0 {
                        killed += 1;
                    }
                }
            }
        }
    }
    if killed > 0 {
        println!("reset: signalled {} daemon(s) to stop", killed);
        std::thread::sleep(Duration::from_millis(500));
    }

    // Remove per-run state + node/treasury workspaces.
    for p in [
        BootstrapState::path(&data_dir),
        nodes_root,
        data_dir.join("bootstrap-treasury"),
    ] {
        if p.exists() {
            let r = if p.is_dir() {
                std::fs::remove_dir_all(&p)
            } else {
                std::fs::remove_file(&p)
            };
            r.map_err(|e| format!("remove {}: {}", p.display(), e))?;
            println!("reset: removed {}", p.display());
        }
    }

    // The seed is the dangerous one — gate on confirmed-regtest or --force.
    let seed = state::HubState::master_seed_path(&data_dir);
    if seed.exists() {
        let regtest = network == "regtest";
        if regtest || force {
            std::fs::remove_file(&seed).map_err(|e| format!("remove {}: {}", seed.display(), e))?;
            println!(
                "reset: removed {} ({})",
                seed.display(),
                if regtest { "regtest" } else { "forced" }
            );
        } else {
            println!(
                "reset: KEPT {} — network is '{}', not confirmed regtest.\n        \
                 The next bootstrap will reuse these keys. To wipe the seed too, \
                 re-run with --force (only if no real funds depend on it).",
                seed.display(),
                if network.is_empty() { "unknown" } else { &network }
            );
        }
    }

    println!("reset: done — next `bootstrap` on {} starts clean", data_dir.display());
    Ok(())
}

async fn esplora_get(esplora: &str, path: &str) -> Result<String, String> {
    let url = format!("{}{}", esplora.trim_end_matches('/'), path);
    let resp = reqwest::get(&url).await.map_err(|e| format!("GET {}: {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!("GET {} -> {}", url, resp.status()));
    }
    resp.text().await.map_err(|e| e.to_string())
}

/// Sum of confirmed sats sitting on `address`.
async fn confirmed_sats(esplora: &str, address: &str) -> Result<u64, String> {
    let body = esplora_get(esplora, &format!("/address/{}/utxo", address)).await?;
    let utxos: Vec<serde_json::Value> =
        serde_json::from_str(&body).map_err(|e| format!("utxo parse: {}", e))?;
    Ok(utxos
        .iter()
        .filter(|u| u["status"]["confirmed"].as_bool() == Some(true))
        .filter_map(|u| u["value"].as_u64())
        .sum())
}

pub async fn run(rest: &[String]) -> Result<(), String> {
    // `--reset` is handled before the normal arg parse: it doesn't need
    // --relay/--esplora and short-circuits the whole pipeline.
    if rest.iter().any(|a| a == "--reset") {
        return reset(rest);
    }
    let args = parse_args(rest)?;
    std::fs::create_dir_all(&args.data_dir).map_err(|e| e.to_string())?;

    let master = state::HubState::load_or_init_master_seed(&args.data_dir)
        .map_err(|e| format!("master seed: {:?}", e))?;
    let mut st = BootstrapState::load(&args.data_dir);
    if st.nodes != 0 && st.nodes != args.nodes {
        return Err(format!(
            "bootstrap-state.json was created with --nodes {} — finish or wipe it before \
             changing the count",
            st.nodes
        ));
    }
    st.nodes = args.nodes;
    st.network = args.network.clone();
    st.per_ledger_sats = args.per_ledger_sats;
    st.save(&args.data_dir);

    // ── Phase 1: seeds ──────────────────────────────────────────────────
    println!("[1/7] seeds — deriving treasury + {} node keys from hub-master-seed", args.nodes);
    let treasury_dir = args.data_dir.join("bootstrap-treasury");
    std::fs::create_dir_all(&treasury_dir).map_err(|e| e.to_string())?;
    let t_seed = state::derive_signer_seed(&master, TREASURY_INDEX)
        .map_err(|e| format!("treasury seed: {:?}", e))?;
    write_seed_once(&seed_file_for(&treasury_dir), &t_seed)?;
    for i in 0..args.nodes {
        let dir = node_dir(&args, i);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let seed = state::derive_signer_seed(&master, NODE_INDEX_BASE + i)
            .map_err(|e| format!("node {} seed: {:?}", i, e))?;
        write_seed_once(&seed_file_for(&dir), &seed)?;
    }

    // ── Phase 2: daemons ────────────────────────────────────────────────
    println!("[2/7] daemons — spawning {} operators", args.nodes);
    for i in 0..args.nodes {
        let name = node_name(i);
        let dir = node_dir(&args, i);
        if daemon_alive(&dir) {
            println!("  {} already running", name);
        } else {
            spawn_daemon(&args, i)?;
            println!("  {} spawned (admin 127.0.0.1:{})", name, admin_port(i));
        }
    }
    // Node IDs (read-only `info` works alongside the daemon).
    for i in 0..args.nodes {
        let name = node_name(i);
        if st.node_ids.contains_key(&name) {
            continue;
        }
        let dir = node_dir(&args, i);
        let seed_path = seed_file_for(&dir);
        let out = retry(20, Duration::from_secs(3), || {
            node_cli(&args, &seed_path, &dir, &name, &["info"])
        })
        .await?;
        let id = out
            .lines()
            .find_map(|l| l.split("Node ID:").nth(1))
            .map(|s| s.trim().to_string())
            .ok_or_else(|| format!("{}: no Node ID in `info` output", name))?;
        st.node_ids.insert(name, id);
        st.save(&args.data_dir);
    }

    // ── Phase 3: funding ────────────────────────────────────────────────
    let required_sats = args.per_ledger_sats * args.nodes as u64
        + disbursement_fee_sats(args.nodes, args.fee_rate);
    if st.treasury_address.is_none() {
        let out = node_cli(
            &args,
            &seed_file_for(&treasury_dir),
            &treasury_dir,
            "treasury",
            &["address"],
        )
        .await?;
        let addr = extract_address(&out)
            .ok_or_else(|| format!("no address in treasury `address` output:\n{}", out))?;
        st.treasury_address = Some(addr);
        st.save(&args.data_dir);
    }
    let treasury_addr = st.treasury_address.clone().unwrap();
    println!("[3/7] funding — send AT LEAST {} sats ({:.8} BTC) to:", required_sats, required_sats as f64 / 1e8);
    println!();
    println!("    {}", treasury_addr);
    println!();
    // Preflight the esplora endpoint BEFORE the wait loop. A wrong base
    // URL (the classic: a mempool/blockstream host without the `/api`
    // suffix returns an HTML 200 that fails JSON parse) used to swallow
    // to "0 sats" and wait forever. Fail fast with the real error and a
    // hint instead.
    match confirmed_sats(&args.esplora, &treasury_addr).await {
        Ok(_) => {}
        Err(e) => {
            return Err(format!(
                "esplora at `{}` is not returning a usable address/utxo response: {}\n\
                 The funding poll needs an esplora REST base URL. mempool.space /\n\
                 blockstream-style hosts need the `/api` suffix (e.g.\n\
                 `https://blockstream.info/api`); a raw electrs-esplora serves it\n\
                 at the root. Re-run with a corrected --esplora (bootstrap is\n\
                 resumable; the treasury address is unchanged).",
                args.esplora, e
            ));
        }
    }
    println!("  (waiting for confirmed funds — safe to interrupt and re-run)");
    loop {
        match confirmed_sats(&args.esplora, &treasury_addr).await {
            Ok(have) if have >= required_sats => {
                println!("  funded: {} sats confirmed", have);
                break;
            }
            Ok(_) => {}
            // Transient after a successful preflight (network blip, provider
            // hiccup) — surface it but keep waiting rather than abort a
            // mainnet run.
            Err(e) => eprintln!("  [poll] esplora error (will retry): {}", e),
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    // ── Phase 4: ledgers ────────────────────────────────────────────────
    println!("[4/7] ledgers — opening one per node");
    for i in 0..args.nodes {
        let name = node_name(i);
        let dir = node_dir(&args, i);
        if !st.ledgers.contains_key(&name) {
            let mut cmd: Vec<&str> = vec!["ledger", "open"];
            let qe;
            if let Some(q) = args.quorum_expiry_blocks {
                qe = q.to_string();
                cmd.push("--quorum-expiry-blocks");
                cmd.push(&qe);
            }
            let out = node_cli(&args, &seed_file_for(&dir), &dir, &name, &cmd).await?;
            let lid = out
                .lines()
                .find_map(|l| l.split("Ledger ID:").nth(1))
                .map(|s| s.trim().to_string())
                .ok_or_else(|| format!("{}: no Ledger ID in `ledger open` output:\n{}", name, out))?;
            println!("  {} ledger {}…", name, &lid[..16.min(lid.len())]);
            st.ledgers.insert(name.clone(), lid);
            st.save(&args.data_dir);
        }
        if !st.ledger_addresses.contains_key(&name) {
            let lid = st.ledgers[&name].clone();
            let out =
                node_cli(&args, &seed_file_for(&dir), &dir, &name, &["ledger", "address", &lid])
                    .await?;
            let addr = extract_address(&out)
                .ok_or_else(|| format!("{}: no address in `ledger address` output:\n{}", name, out))?;
            st.ledger_addresses.insert(name, addr);
            st.save(&args.data_dir);
        }
    }

    // ── Phase 5: disburse ───────────────────────────────────────────────
    if st.disbursement_txid.is_none() {
        println!("[5/7] disburse — ONE tx funding all {} ledgers", args.nodes);
        let recipients: Vec<String> = (0..args.nodes)
            .map(|i| {
                format!(
                    "{}:{}",
                    st.ledger_addresses[&node_name(i)], args.per_ledger_sats
                )
            })
            .collect();
        let mut cmd: Vec<&str> = vec!["wallet", "send-many"];
        for r in &recipients {
            cmd.push(r);
        }
        let fr = args.fee_rate.to_string();
        cmd.push("--fee-rate");
        cmd.push(&fr);
        let out = node_cli(
            &args,
            &seed_file_for(&treasury_dir),
            &treasury_dir,
            "treasury",
            &cmd,
        )
        .await?;
        let txid = out
            .lines()
            .find_map(|l| l.split("send-many broadcast:").nth(1))
            .and_then(|s| s.trim().split_whitespace().next())
            .map(str::to_string)
            .ok_or_else(|| format!("no txid in send-many output:\n{}", out))?;
        println!("  disbursement: {}", txid);
        st.disbursement_txid = Some(txid);
        st.save(&args.data_dir);
    }
    // Wait for every ledger address to show confirmed funds, then give the
    // per-ledger BDK wallets one sync cycle to ingest (same reasoning as
    // setup.sh's 45s pad).
    println!("  waiting for the disbursement to confirm on every ledger address…");
    for i in 0..args.nodes {
        let addr = st.ledger_addresses[&node_name(i)].clone();
        loop {
            match confirmed_sats(&args.esplora, &addr).await {
                Ok(have) if have >= args.per_ledger_sats => break,
                Ok(_) => {}
                Err(e) => eprintln!("  [poll] esplora error (will retry): {}", e),
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }
    println!("  confirmed; waiting 45s for ledger wallets to ingest");
    tokio::time::sleep(Duration::from_secs(45)).await;

    // ── Phase 6: quorums ────────────────────────────────────────────────
    println!("[6/7] quorums — cross-wiring Q={} and beginning", Q);
    for i in 0..args.nodes {
        let name = node_name(i);
        if st.quorums_added.get(&name).copied().unwrap_or(false) {
            continue;
        }
        let dir = node_dir(&args, i);
        let lid = st.ledgers[&name].clone();
        // Members: the next Q operators after us (mod N), skipping self —
        // for N=4 / Q=3 that's exactly "everyone else".
        let mut added = 0;
        let mut j = 1;
        while added < Q {
            let m = (i + j) % args.nodes;
            j += 1;
            if m == i {
                continue;
            }
            let m_name = node_name(m);
            let m_id = st.node_ids[&m_name].clone();
            let m_lid = st.ledgers[&m_name].clone();
            node_cli(
                &args,
                &seed_file_for(&dir),
                &dir,
                &name,
                &["quorum", "add", &lid, &m_id, &m_lid],
            )
            .await?;
            added += 1;
        }
        st.quorums_added.insert(name, true);
        st.save(&args.data_dir);
    }
    // Members cosign a QuorumBegin only when their copy of the ledger's
    // history has reached the QB's sequence — and the QuorumAdd updates
    // race the members' post-consent subscriptions ("Cosign stale: have
    // seq 5, need 7" in the wild). Deterministic fix: every owner
    // re-broadcasts its full history, members ingest, THEN begin.
    println!("  republishing ledger histories so members are current");
    for i in 0..args.nodes {
        let name = node_name(i);
        let dir = node_dir(&args, i);
        let lid = st.ledgers[&name].clone();
        node_cli(
            &args,
            &seed_file_for(&dir),
            &dir,
            &name,
            &["ledger", "republish", &lid],
        )
        .await?;
    }
    // Freshness barrier: a member only cosigns a QuorumBegin once its
    // copy of the ledger has reached the QB's sequence, and the begin
    // actor gives up after one 10s cosign round — so don't begin until
    // every member's admin API reports the owner's tip for the ledger.
    println!("  freshness barrier — waiting until every member is at its owners' tips");
    for i in 0..args.nodes {
        let name = node_name(i);
        let lid = st.ledgers[&name].clone();
        let owner_tip = ledger_tip(&args, i, &lid)
            .await?
            .ok_or_else(|| format!("{}: own ledger missing from admin API", name))?;
        // Same member arithmetic as the add loop above.
        let mut checked = 0;
        let mut j = 1;
        while checked < Q {
            let m = (i as usize + j) % args.nodes as usize;
            j += 1;
            if m == i as usize {
                continue;
            }
            // Best-effort: relays dedup republished event ids, so a member
            // that missed the originals only catches up via its stale-fetch
            // path — which the FIRST cosign round triggers. The daemon now
            // retries QuorumBegin cosign rounds for exactly that reason, so
            // a member still behind here is a warning, not a failure.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                match ledger_tip(&args, m as u32, &lid).await {
                    Ok(Some(tip)) if tip >= owner_tip => break,
                    _ if tokio::time::Instant::now() > deadline => {
                        println!(
                            "  note: node{} still behind on {}… — the begin's cosign \
                             retry will pull it current",
                            m,
                            &lid[..16.min(lid.len())]
                        );
                        break;
                    }
                    _ => tokio::time::sleep(Duration::from_secs(3)).await,
                }
            }
            checked += 1;
        }
        println!("  {} members current at seq {}", name, owner_tip);
    }

    // Begin all ledgers in parallel — each broadcasts its activation tx,
    // waits for confs, then runs the cosign round.
    let activation_sats = args.per_ledger_sats.saturating_sub(1_000);
    let mut joins = Vec::new();
    for i in 0..args.nodes {
        let name = node_name(i);
        if st.begun.get(&name).copied().unwrap_or(false) {
            continue;
        }
        let dir = node_dir(&args, i);
        let lid = st.ledgers[&name].clone();
        let a = activation_sats.to_string();
        let args_ref = &args;
        joins.push(async move {
            let seed_path = seed_file_for(&dir);
            let begin_args = [
                "quorum",
                "begin",
                lid.as_str(),
                "--amount-sats",
                a.as_str(),
                "--collateral-ratio",
                "0.6",
                "--protocol-version",
                "cltv-offset-v2",
            ];
            // Retry policy: ONLY pre-broadcast failures may be retried.
            // "Insufficient funds" on a fresh ledger = the wallet's
            // fast-poll sync hasn't landed the funding UTXO; the build
            // failed, nothing went on-chain, retrying is free. A COSIGN
            // TIMEOUT is the opposite: the activation tx is ALREADY
            // on-chain, and a re-begin would try to rebuild it from the
            // now-emptied ledger wallet (failing with a misleading
            // "Insufficient funds" forever). The republish step exists
            // precisely so cosign timeouts don't happen; if one does,
            // stop and surface it instead of digging deeper.
            let mut r = node_cli(args_ref, &seed_path, &dir, &name, &begin_args).await;
            let mut attempts = 1;
            while attempts < 6 {
                match &r {
                    Err(e) if e.contains("Insufficient funds") => {
                        println!(
                            "  {} begin attempt {}: ledger wallet not synced yet; retry in 20s",
                            name, attempts
                        );
                        tokio::time::sleep(Duration::from_secs(20)).await;
                        r = node_cli(args_ref, &seed_path, &dir, &name, &begin_args).await;
                        attempts += 1;
                    }
                    Err(e) if e.contains("Cosign timeout") => {
                        r = Err(format!(
                            "cosign timeout AFTER broadcasting the activation tx — do NOT \
                             re-run `quorum begin`; the funds sit in the broadcast vault. \
                             Bring members current and re-drive the cosign round. {}",
                            e
                        ));
                        break;
                    }
                    _ => break,
                }
            }
            (name, r)
        });
    }
    for (name, r) in futures::future::join_all(joins).await {
        match r {
            Ok(_) => {
                println!("  {} quorum begun", name);
                st.begun.insert(name, true);
                st.save(&args.data_dir);
            }
            Err(e) => return Err(format!("{} quorum begin failed: {}", name, e)),
        }
    }

    // ── Phase 7: verify ─────────────────────────────────────────────────
    println!("[7/7] verify — waiting for every quorum to report Active");
    for i in 0..args.nodes {
        let name = node_name(i);
        if st.active.get(&name).copied().unwrap_or(false) {
            continue;
        }
        let lid = st.ledgers[&name].clone();
        let dir = node_dir(&args, i);
        let token = read_admin_token(&dir)?;
        let url = format!("http://127.0.0.1:{}/api/ledgers", admin_port(i));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(format!("{}: quorum not Active after 300s", name));
            }
            let active = reqwest::Client::new()
                .get(&url)
                .bearer_auth(&token)
                .timeout(Duration::from_secs(5))
                .send()
                .await
                .ok();
            if let Some(resp) = active {
                if let Ok(ledgers) = resp.json::<Vec<serde_json::Value>>().await {
                    let ours = ledgers
                        .iter()
                        .find(|l| l["ledger_id"].as_str() == Some(lid.as_str()));
                    if ours
                        .and_then(|l| l["quorum_active"].as_bool())
                        .unwrap_or(false)
                    {
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        println!("  {} Active", name);
        st.active.insert(name, true);
        st.save(&args.data_dir);
    }

    println!();
    println!("bootstrap complete: {} nodes, {} ledgers, Q={}", args.nodes, args.nodes, Q);
    for i in 0..args.nodes {
        let name = node_name(i);
        // Display handle derives from the Node ID — same words on every
        // surface, no naming coordination (the dir name nodeN is just a
        // filesystem detail).
        let display =
            deposits_protocol::display_name::pubkey_display_name_hex(&st.node_ids[&name]);
        println!("  {}  {}  ledger {}", name, display, st.ledgers[&name]);
    }
    println!("on-chain: 1 funding tx + 1 disbursement ({}) + {} activations",
        st.disbursement_txid.as_deref().unwrap_or("?"), args.nodes);
    Ok(())
}

/// Read a node's admin-token (the hub co-locates with its nodes).
fn read_admin_token(dir: &Path) -> Result<String, String> {
    std::fs::read_to_string(dir.join("admin-token"))
        .map(|t| t.trim().to_string())
        .map_err(|e| format!("read admin-token in {}: {}", dir.display(), e))
}

/// `next_sequence` a node's admin API reports for `ledger_id`
/// (None when the node doesn't track that ledger yet).
async fn ledger_tip(args: &BootstrapArgs, i: u32, ledger_id: &str) -> Result<Option<u64>, String> {
    let dir = node_dir(args, i);
    let token = read_admin_token(&dir)?;
    let url = format!("http://127.0.0.1:{}/api/ledgers", admin_port(i));
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&token)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("GET {}: {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!("GET {} -> {}", url, resp.status()));
    }
    let ledgers: Vec<serde_json::Value> = resp.json().await.map_err(|e| e.to_string())?;
    Ok(ledgers
        .iter()
        .find(|l| l["ledger_id"].as_str() == Some(ledger_id))
        .and_then(|l| l["next_sequence"].as_u64()))
}

fn write_seed_once(path: &Path, seed: &[u8; 32]) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    std::fs::write(path, hex::encode(seed)).map_err(|e| e.to_string())?;
    // Seed files are keys — owner-read-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn admin_port(i: u32) -> u16 {
    // Clear of setup.sh's op cluster range (8765+i for up to ~16 ops).
    8870 + i as u16
}

fn metrics_port(i: u32) -> u16 {
    9200 + i as u16
}

fn pid_file(dir: &Path) -> PathBuf {
    dir.join("daemon.pid")
}

fn daemon_alive(dir: &Path) -> bool {
    let Ok(pid) = std::fs::read_to_string(pid_file(dir)) else {
        return false;
    };
    let Ok(pid) = pid.trim().parse::<i32>() else {
        return false;
    };
    // kill -0
    unsafe { libc_kill(pid, 0) == 0 }
}

extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

fn spawn_daemon(args: &BootstrapArgs, i: u32) -> Result<(), String> {
    let dir = node_dir(args, i);
    let name = node_name(i);
    let log = std::fs::File::create(dir.join("daemon.log")).map_err(|e| e.to_string())?;
    let log_err = log.try_clone().map_err(|e| e.to_string())?;
    let mut c = std::process::Command::new(&args.node_bin);
    c.arg("run")
        .arg("--seed-file")
        .arg(seed_file_for(&dir))
        .arg("--name")
        .arg(&name)
        .arg("--network")
        .arg(&args.network)
        .arg("--data-dir")
        .arg(&dir)
        .arg("--esplora")
        .arg(&args.esplora)
        .arg("--metrics-port")
        .arg(metrics_port(i).to_string())
        .arg("--admin-bind")
        .arg(format!("127.0.0.1:{}", admin_port(i)));
    for r in &args.relays {
        c.arg("--relay").arg(r);
    }
    if args.network == "regtest" {
        c.arg("--fast-poll");
    }
    let child = c
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|e| format!("spawn daemon {}: {}", name, e))?;
    std::fs::write(pid_file(&dir), child.id().to_string()).map_err(|e| e.to_string())?;
    Ok(())
}

async fn retry<F, Fut, T>(times: u32, delay: Duration, mut f: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let mut last = String::new();
    for _ in 0..times {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => last = e,
        }
        tokio::time::sleep(delay).await;
    }
    Err(format!("retries exhausted: {}", last))
}
