//! `deposits-hub` entry point.
//!
//! Subcommands:
//!   - `run` — boot the hub: load state, open nostr client, launch the TUI
//!   - `pubkey` — print the hub's nostr pubkey (so an external signer
//!                can be pointed at this hub via `--hub-pubkey <hex>`)

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
deposits-hub — operator control plane for deposits-rust

USAGE:
    deposits-hub <COMMAND> [OPTIONS]

COMMANDS:
    run                          Boot the hub: load state, open nostr client, launch the TUI.
                                  Pass --headless to skip the TUI (for CI / unattended hosts) —
                                  registrations still get parked, approve them via `approve`.
                                  Pass --steal to take over the data dir from a running hub
                                  (SIGTERM, then SIGKILL after 3s).
    pubkey                       Print the hub's nostr pubkey
    approve --pubkey <HEX>       Move the given pending peer into the inventory and ack it.
                                  Mirror of hitting `a` in the TUI's pending tab.
    reject  --pubkey <HEX>       Drop the given pending peer and ack with Shutdown.
    restore                      Pull the latest backup snapshot from the relay (NIP-44
                                  decrypted from the kind-30421 replaceable event) and
                                  write `hub.json` + `hub-master-seed` into --data-dir.
                                  Bootstraps a fresh box from just the hub nostr secret +
                                  a relay URL.
    publish-backup               One-shot republish of the current state to the
                                  parameterized-replaceable backup event on the relay.
                                  The `run` loop does this automatically on each mutation;
                                  this is for manual re-publish (testing, recovery flows).
    spawn-line --name <NAME>     Print the launch command for a signer that auto-registers
                                  [--seed <HEX>]              with this hub. Creates the workspace + seed on first
                                                              use (or uses --seed if provided — for harnesses where
                                                              the operator seed is fixed). Subsequent calls re-print
                                                              the same line.
    spawn      --name <NAME>     Same as spawn-line, but exec the signer in the foreground
               [--seed <HEX>]    (logs to <data-dir>/spawned/<NAME>/{stdout,stderr}.log).
    qr [--text <STR>]            Print a QR code for the hub pubkey (or arbitrary --text).
                                  Renders with Unicode half-blocks; one terminal cell = two
                                  QR modules so the code stays roughly square.
    status --relay <URL>         Query every bootstrapped node over the Nostr admin RPC and
                                  print per-node + per-ledger status (owned vs member, quorum
                                  active, reserves). Requires the nodes to trust the hub
                                  (admin.npub — written automatically by `bootstrap`).
    bootstrap --nodes <N>        Fund once, deploy a self-connected cluster: N daemons,
              --relay <URL>               one ledger each, Q=3 cross-wired quorums, ONE funding
              --esplora <URL>             tx + ONE disbursement + N activations. Resumable —
              [--per-ledger-sats <S>]     re-run after any interruption. All keys derive from
              [--network <NET>]           hub-master-seed (BIP-85); one mnemonic backs up the
              [--node-bin <PATH>]         entire cluster.
    bootstrap --reset            Tear down a bootstrapped cluster: kill spawned daemons,
              [--data-dir <DIR>]          delete bootstrap state + node/treasury workspaces.
              [--force]                   Keeps hub-master-seed unless network is regtest or
                                          --force is given (the seed is the keys — guarded).
    help                         Show this message

OPTIONS:
    --data-dir <DIR>   Hub data directory (default: ~/.deposits-hub)
    --relay <URL>      Nostr relay (can be passed more than once; required for `run`, `spawn*`)
    --name <NAME>      Signer name (workspace + label)

EXAMPLES:
    deposits-hub run --relay wss://relay.bitcoindeposits.net
    deposits-hub pubkey
    deposits-hub spawn-line --name op-alice --relay wss://relay.bitcoindeposits.net
";

fn main() -> ExitCode {
    // Install rustls' ring crypto provider explicitly. Both `ring` and
    // `aws-lc-rs` end up in our dep tree (rustls feature + transitively
    // via nostr-sdk), so rustls' auto-detection fails — it panics on
    // first TLS connection rather than picking one. Install the ring
    // provider before any wss:// connect; ignore "already installed"
    // errors so subcommands that re-enter the runtime don't trip.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => {
            eprintln!("{}", USAGE);
            return ExitCode::FAILURE;
        }
    };

    let result = match cmd {
        "help" | "-h" | "--help" => {
            print!("{}", USAGE);
            Ok(())
        }
        "run" => cmd_run(rest),
        "pubkey" => cmd_pubkey(rest),
        "approve" => cmd_approve(rest),
        "status" => cmd_status(rest),
        "reject" => cmd_reject(rest),
        "restore" => cmd_restore(rest),
        "publish-backup" => cmd_publish_backup(rest),
        "spawn-line" => cmd_spawn_line(rest),
        "spawn" => cmd_spawn(rest),
        "bootstrap" => {
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string());
            match rt {
                Ok(rt) => rt.block_on(deposits_hub::bootstrap::run(rest)),
                Err(e) => Err(e),
            }
        }
        "qr" => cmd_qr(rest),
        other => {
            eprintln!("unknown command: {}\n\n{}", other, USAGE);
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hub: {}", e);
            ExitCode::FAILURE
        }
    }
}

#[derive(Default)]
struct CommonArgs {
    data_dir: Option<PathBuf>,
    relays: Vec<String>,
    name: Option<String>,
    text: Option<String>,
    pubkey: Option<String>,
    seed: Option<String>,
    headless: bool,
    auto_approve: bool,
    steal: bool,
    docker: bool,
    docker_image: Option<String>,
}

fn parse_common(args: &[String]) -> Result<CommonArgs, String> {
    let mut out = CommonArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                let v = args
                    .get(i + 1)
                    .ok_or("--data-dir requires a value")?
                    .to_string();
                out.data_dir = Some(PathBuf::from(v));
                i += 2;
            }
            "--relay" => {
                let v = args.get(i + 1).ok_or("--relay requires a value")?.to_string();
                out.relays.push(v);
                i += 2;
            }
            "--name" => {
                let v = args.get(i + 1).ok_or("--name requires a value")?.to_string();
                out.name = Some(v);
                i += 2;
            }
            "--text" => {
                let v = args.get(i + 1).ok_or("--text requires a value")?.to_string();
                out.text = Some(v);
                i += 2;
            }
            "--pubkey" => {
                let v = args
                    .get(i + 1)
                    .ok_or("--pubkey requires a value")?
                    .to_string();
                out.pubkey = Some(v);
                i += 2;
            }
            "--seed" => {
                let v = args.get(i + 1).ok_or("--seed requires a 32-byte hex value")?.to_string();
                out.seed = Some(v);
                i += 2;
            }
            "--headless" => {
                out.headless = true;
                i += 1;
            }
            "--auto-approve" => {
                out.auto_approve = true;
                i += 1;
            }
            "--steal" => {
                out.steal = true;
                i += 1;
            }
            "--docker" => {
                out.docker = true;
                i += 1;
            }
            "--docker-image" => {
                let v = args
                    .get(i + 1)
                    .ok_or("--docker-image requires a value")?
                    .to_string();
                out.docker_image = Some(v);
                i += 2;
            }
            unknown => return Err(format!("unknown option: {}", unknown)),
        }
    }
    Ok(out)
}

/// Decide what seed the spawned signer should use.
///
///   * If the operator passed `--seed <hex>`, honor it verbatim
///     (existing harness/test path).
///   * Otherwise derive from the hub master + a stable per-name index
///     allocated in hub.json. One master backup recovers every
///     hub-spawned signer.
///
/// Returns `None` only if the workspace already exists — in that case
/// `Spawner::ensure_initialized_with_seed` is a no-op and the
/// pre-existing on-disk seed is reused regardless. (We never overwrite
/// a workspace's seed, to preserve the signer's nostr identity.)
fn derive_seed_if_unspecified(
    data_dir: &PathBuf,
    state: &mut deposits_hub::state::HubState,
    name: &str,
    explicit: Option<[u8; 32]>,
) -> Result<Option<[u8; 32]>, String> {
    if explicit.is_some() {
        return Ok(explicit);
    }
    // Skip derivation if the workspace's seed already exists — the
    // signer's identity is locked in and re-deriving would either
    // be a no-op (ensure_initialized doesn't overwrite) or, worse,
    // mislead the operator about which key is in effect.
    let ws = deposits_hub::spawn::Workspace::for_name(data_dir, name);
    if ws.data_dir.join("seed").exists() {
        return Ok(None);
    }
    let master = deposits_hub::state::HubState::load_or_init_master_seed(data_dir)
        .map_err(|e| format!("master seed: {}", e))?;
    let index = state
        .signer_index_for(name, data_dir)
        .map_err(|e| format!("allocate signer index: {}", e))?;
    let seed = deposits_hub::state::derive_signer_seed(&master, index)
        .map_err(|e| format!("derive signer seed: {}", e))?;
    tracing::info!(
        "hub: derived seed for signer '{}' from master at m/89'/{}'",
        name,
        index
    );
    Ok(Some(seed))
}

fn parse_seed_arg(s: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    let Some(hex_str) = s else { return Ok(None) };
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| format!("--seed must be 32 bytes of hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("--seed must be 32 bytes hex, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Some(out))
}

fn data_dir_or_default(opt: Option<PathBuf>) -> PathBuf {
    opt.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".deposits-hub")
    })
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let c = parse_common(args)?;
    let data_dir = data_dir_or_default(c.data_dir);
    if c.relays.is_empty() {
        return Err("`run` requires at least one --relay".to_string());
    }

    // Ensure the data dir exists with permissions tight enough for the
    // hub's nostr secret to live alongside the JSON state. 0700 keeps
    // it operator-only.
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("create data dir {}: {}", data_dir.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&data_dir)
            .map_err(|e| format!("stat data dir: {}", e))?
            .permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&data_dir, perms)
            .map_err(|e| format!("chmod data dir: {}", e))?;
    }

    // Take the data-dir lock BEFORE loading state. Two concurrent runs
    // would otherwise share `hub-nostr-secret` (dup gift wraps) and
    // race on hub.json (lost writes). Bound to the function — drop
    // at return releases. Kernel auto-releases on process exit too,
    // so SIGKILL / panic don't leave a stale lock.
    //
    // `--steal` swaps in the kill-then-acquire variant for operators
    // who want their new hub to take over from a running one (e.g.,
    // headless from setup.sh → interactive TUI without manual kill).
    let _hub_lock = if c.steal {
        deposits_hub::lock::HubLock::acquire_or_steal(&data_dir)
    } else {
        deposits_hub::lock::HubLock::acquire(&data_dir)
    }
    .map_err(|e| e.to_string())?;

    let state = deposits_hub::state::HubState::load_or_init(&data_dir)
        .map_err(|e| format!("hub state: {}", e))?;
    eprintln!("hub pubkey: {}", state.hub_pubkey_hex());
    eprintln!("data dir:   {}", data_dir.display());
    eprintln!("relays:     {:?}", c.relays);
    eprintln!(
        "registered: {} signer(s), {} node(s)",
        state.signers.len(),
        state.nodes.len()
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {}", e))?;
    if c.auto_approve && !c.headless {
        return Err("--auto-approve requires --headless".to_string());
    }
    rt.block_on(run_async(data_dir, state, c.relays, c.headless, c.auto_approve))
}

async fn run_async(
    data_dir: PathBuf,
    state: deposits_hub::state::HubState,
    relays: Vec<String>,
    headless: bool,
    auto_approve: bool,
) -> Result<(), String> {
    // Load the secret hex from the sibling file (state stores only the
    // pubkey — the secret stays in a 0600 file). HubState::load_or_init
    // already validated it exists + decodes, so a re-read here is
    // straight I/O.
    let secret_path = deposits_hub::state::HubState::nostr_secret_path(&data_dir);
    let secret_hex = std::fs::read_to_string(&secret_path)
        .map_err(|e| format!("read nostr secret {}: {}", secret_path.display(), e))?
        .trim()
        .to_string();

    let transport = deposits_hub::nostr::HubTransport::connect(&secret_hex, &relays)
        .await
        .map_err(|e| format!("nostr connect: {}", e))?;
    let inbox = transport
        .subscribe()
        .await
        .map_err(|e| format!("subscribe: {}", e))?;

    let state = std::sync::Arc::new(tokio::sync::Mutex::new(state));

    if headless {
        run_headless(data_dir, state, transport, inbox, auto_approve).await
    } else {
        let app = deposits_hub::tui::App::new_with_relays(
            data_dir,
            state,
            transport,
            relays.clone(),
        );
        app.run(inbox).await
    }
}

/// Headless inbound dispatch loop. Same parking behavior as the TUI's
/// `absorb_inbound`, but no terminal — exits on ctrl-c. Used by CI and
/// unattended hosts; the operator drives approvals via the `approve` /
/// `reject` subcommands against the same data dir.
async fn run_headless(
    data_dir: PathBuf,
    state: std::sync::Arc<tokio::sync::Mutex<deposits_hub::state::HubState>>,
    transport: deposits_hub::nostr::HubTransport,
    mut inbox: tokio::sync::mpsc::Receiver<deposits_hub::nostr::Inbound>,
    auto_approve: bool,
) -> Result<(), String> {
    use deposits_hub::control;
    use deposits_hub::proto::HubMessage;

    if auto_approve {
        eprintln!("hub: headless + auto-approve mode — every Register is accepted");
    } else {
        eprintln!("hub: headless mode — listening for registrations");
    }
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                eprintln!("hub: shutdown signal — exiting");
                return Ok(());
            }
            maybe = inbox.recv() => {
                let Some(inbound) = maybe else {
                    return Err("nostr inbox closed".to_string());
                };
                let from = inbound.from.to_hex();
                match inbound.msg {
                    HubMessage::Register { role, identity_pubkey, version, label, signer_pubkey } => {
                        let mut st = state.lock().await;
                        match control::ingest_register(
                            &mut st, &data_dir, &from, role, identity_pubkey, version, label, signer_pubkey,
                        ) {
                            Ok(true) => {
                                // No state mutation on already-approved (ingest_register
                                // does refresh signer_pubkey on a Node re-register though,
                                // so play it safe and backup either way).
                                let snapshot = st.clone();
                                drop(st);
                                control::send_already_approved_ack(&transport, &from).await;
                                control::publish_backup(&transport, &snapshot, &data_dir).await;
                            }
                            Ok(false) => {
                                if auto_approve {
                                    let pkey = control::pending_key(role, &from);
                                    let label = match control::approve(&mut st, &data_dir, &pkey, None) {
                                        Ok(l) => l,
                                        Err(e) => {
                                            tracing::warn!("auto-approve: {}", e);
                                            drop(st);
                                            continue;
                                        }
                                    };
                                    let snapshot = st.clone();
                                    drop(st);
                                    tracing::info!(
                                        "auto-approved {} as '{}'",
                                        &from[..16],
                                        label
                                    );
                                    control::send_accept_ack(&transport, &from, &label).await;
                                    control::publish_backup(&transport, &snapshot, &data_dir).await;
                                } else {
                                    let snapshot = st.clone();
                                    drop(st);
                                    tracing::info!("register from {} — parked", &from[..16]);
                                    control::send_waiting_ack(&transport, &from).await;
                                    control::publish_backup(&transport, &snapshot, &data_dir).await;
                                }
                            }
                            Err(e) => tracing::warn!("ingest register: {}", e),
                        }
                    }
                    HubMessage::Heartbeat { ts, .. } => {
                        tracing::debug!("heartbeat from {} (ts={})", &from[..16], ts);
                    }
                    HubMessage::StatusResp { ready, node_stats, .. } => {
                        match node_stats {
                            Some(s) => {
                                let addr_note = match s.next_address.as_deref() {
                                    Some(a) if a.len() > 12 => {
                                        format!(" addr={}…{}", &a[..6], &a[a.len()-4..])
                                    }
                                    _ => String::new(),
                                };
                                tracing::info!(
                                    "status from {}: ready={} wallet={:.4}BTC ledgers={} active={} quorums={} tip={}{}",
                                    &from[..16], ready,
                                    (s.wallet_balance_sats as f64) / 100_000_000.0,
                                    s.ledger_count, s.active_ledger_count, s.quorum_member_count, s.chain_tip,
                                    addr_note,
                                );
                            }
                            None => tracing::info!("status from {}: ready={}", &from[..16], ready),
                        }
                    }
                    HubMessage::RegisterAck { .. } | HubMessage::StatusReq => {
                        tracing::debug!("unexpected inbound from {}", &from[..16]);
                    }
                }
            }
        }
    }
}

fn cmd_approve(args: &[String]) -> Result<(), String> {
    let c = parse_common(args)?;
    let data_dir = data_dir_or_default(c.data_dir);
    let pubkey = c.pubkey.ok_or("missing --pubkey")?;
    if c.relays.is_empty() {
        return Err("`approve` requires at least one --relay so the ack reaches the peer".to_string());
    }
    let secret_path = deposits_hub::state::HubState::nostr_secret_path(&data_dir);
    let secret_hex = std::fs::read_to_string(&secret_path)
        .map_err(|e| format!("read hub secret: {}", e))?
        .trim()
        .to_string();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {}", e))?;
    rt.block_on(async move {
        let mut state = deposits_hub::state::HubState::load_or_init(&data_dir)
            .map_err(|e| format!("hub state: {}", e))?;
        let label = deposits_hub::control::approve(&mut state, &data_dir, &pubkey, None)?;
        let transport = deposits_hub::nostr::HubTransport::connect(&secret_hex, &c.relays)
            .await
            .map_err(|e| format!("nostr connect: {}", e))?;
        deposits_hub::control::send_accept_ack(&transport, &pubkey, &label).await;
        println!("approved {} as '{}'", pubkey, label);
        Ok::<(), String>(())
    })
}

/// `deposits-hub status [--relay <URL>]+ [--data-dir <DIR>]`
///
/// Query every bootstrapped node over the Nostr admin RPC (gift-wrapped,
/// signed by the hub key the nodes trust via admin.npub) and print a per-node
/// + per-ledger summary. First management command on the hub's control plane;
/// liquidity + advertising follow on the same path.
fn cmd_status(args: &[String]) -> Result<(), String> {
    let c = parse_common(args)?;
    let data_dir = data_dir_or_default(c.data_dir);
    if c.relays.is_empty() {
        return Err("`status` requires at least one --relay (the cluster's relay)".to_string());
    }
    let secret_hex =
        std::fs::read_to_string(deposits_hub::state::HubState::nostr_secret_path(&data_dir))
            .map_err(|e| format!("read hub secret: {}", e))?
            .trim()
            .to_string();

    // Node operator pubkeys come from the bootstrap state (parsed loosely so we
    // don't depend on the private BootstrapState struct).
    let state_path = data_dir.join("bootstrap-state.json");
    let raw = std::fs::read_to_string(&state_path).map_err(|e| {
        format!(
            "read {}: {} (run `deposits-hub bootstrap` first)",
            state_path.display(),
            e
        )
    })?;
    let sv: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse bootstrap-state: {}", e))?;
    let nodes: Vec<(String, String)> = sv
        .get("node_ids")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .map(|(name, v)| (name.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default();
    if nodes.is_empty() {
        println!("no nodes in {} yet", state_path.display());
        return Ok(());
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {}", e))?;
    rt.block_on(async move {
        for (name, node_id) in nodes {
            // Gift-wrap recipient is the operator's x-only key (drop the
            // 02/03 compressed-pubkey parity prefix).
            let xonly = if node_id.len() == 66 {
                &node_id[2..]
            } else {
                node_id.as_str()
            };
            match deposits_hub::admin_client::send_admin_request(
                &secret_hex,
                &c.relays,
                xonly,
                xonly,
                "admin_status",
                serde_json::json!({}),
                deposits_hub::admin_client::DEFAULT_TIMEOUT_MS,
            )
            .await
            {
                Ok(res) => {
                    let tip = res.get("chain_tip").and_then(|v| v.as_u64()).unwrap_or(0);
                    let bal = res
                        .get("wallet_balance_sats")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let empty = Vec::new();
                    let ledgers = res.get("ledgers").and_then(|v| v.as_array()).unwrap_or(&empty);
                    let is_owned =
                        |l: &serde_json::Value| l.get("role").and_then(|v| v.as_str()) == Some("Operator");
                    let owned: Vec<&serde_json::Value> =
                        ledgers.iter().filter(|l| is_owned(l)).collect();
                    let owned_active = owned
                        .iter()
                        .filter(|l| l.get("quorum_active").and_then(|v| v.as_bool()).unwrap_or(false))
                        .count();
                    let member_count = ledgers.len() - owned.len();
                    println!(
                        "{}  tip={}  wallet={} sats  owned: {}/{} active (+{} member replicas)",
                        name,
                        tip,
                        bal,
                        owned_active,
                        owned.len(),
                        member_count
                    );
                    // Owned ledgers first (the ones this node operates), then
                    // member replicas (its co-signed copies of peers' ledgers).
                    let mut sorted: Vec<&serde_json::Value> = ledgers.iter().collect();
                    sorted.sort_by_key(|l| !is_owned(l));
                    for l in sorted {
                        let lid = l.get("ledger_id").and_then(|v| v.as_str()).unwrap_or("?");
                        let role = l.get("role").and_then(|v| v.as_str()).unwrap_or("?");
                        let act = l
                            .get("quorum_active")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let q = l.get("quorum_size").and_then(|v| v.as_u64()).unwrap_or(0);
                        let reserves = l.get("reserves_sats").and_then(|v| v.as_u64()).unwrap_or(0);
                        let collateral =
                            l.get("collateral_sats").and_then(|v| v.as_u64()).unwrap_or(0);
                        println!(
                            "    {:<10} {}  Q={}  {}  vault={} sats (reserves {} + collateral {})",
                            role,
                            &lid[..16.min(lid.len())],
                            q,
                            if act { "active" } else { "PreQuorum" },
                            reserves + collateral,
                            reserves,
                            collateral
                        );
                    }
                }
                Err(e) => println!("{}  ERROR: {}", name, e),
            }
        }
        Ok::<(), String>(())
    })
}

fn cmd_publish_backup(args: &[String]) -> Result<(), String> {
    let c = parse_common(args)?;
    let data_dir = data_dir_or_default(c.data_dir);
    if c.relays.is_empty() {
        return Err("`publish-backup` requires at least one --relay".to_string());
    }
    let state = deposits_hub::state::HubState::load_or_init(&data_dir)
        .map_err(|e| format!("hub state: {}", e))?;
    let secret_hex = std::fs::read_to_string(
        deposits_hub::state::HubState::nostr_secret_path(&data_dir),
    )
    .map_err(|e| format!("read hub secret: {}", e))?
    .trim()
    .to_string();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {}", e))?;
    rt.block_on(async move {
        let transport = deposits_hub::nostr::HubTransport::connect(&secret_hex, &c.relays)
            .await
            .map_err(|e| format!("nostr connect: {}", e))?;
        deposits_hub::control::publish_backup(&transport, &state, &data_dir).await;
        println!("published snapshot for hub {}", state.hub_pubkey_hex());
        Ok::<(), String>(())
    })
}

fn cmd_restore(args: &[String]) -> Result<(), String> {
    let c = parse_common(args)?;
    let data_dir = data_dir_or_default(c.data_dir);
    if c.relays.is_empty() {
        return Err("`restore` requires at least one --relay".to_string());
    }
    // The data dir must already have the hub nostr secret — that's
    // the operator's required backup. Everything else (hub.json,
    // master seed) gets pulled from the relay.
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("create data dir {}: {}", data_dir.display(), e))?;
    let secret_path = deposits_hub::state::HubState::nostr_secret_path(&data_dir);
    if !secret_path.exists() {
        return Err(format!(
            "restore needs hub-nostr-secret at {}. Put your backed-up 32-byte hex \
             secret there (chmod 0600) before running restore.",
            secret_path.display()
        ));
    }
    let secret_hex = std::fs::read_to_string(&secret_path)
        .map_err(|e| format!("read hub secret: {}", e))?
        .trim()
        .to_string();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {}", e))?;
    rt.block_on(async move {
        let transport = deposits_hub::nostr::HubTransport::connect(&secret_hex, &c.relays)
            .await
            .map_err(|e| format!("nostr connect: {}", e))?;

        eprintln!(
            "hub: restoring from {} relay(s); fetching latest snapshot (up to 10s) …",
            c.relays.len()
        );

        let blob = transport
            .fetch_replaceable_from_self(
                deposits_hub::proto::KIND_HUB_STATE_BACKUP,
                deposits_hub::proto::HUB_STATE_BACKUP_D_TAG,
                std::time::Duration::from_secs(10),
            )
            .await
            .map_err(|e| format!("fetch backup: {}", e))?
            .ok_or_else(|| {
                "no backup found on relay — wrong secret, never-published hub identity, \
                 or relay doesn't have a snapshot yet"
                    .to_string()
            })?;
        let (_created_at, payload_json) = blob;
        let payload: deposits_hub::proto::BackupPayload = serde_json::from_str(&payload_json)
            .map_err(|e| format!("parse backup payload: {}", e))?;
        let ts = payload.last_modified;
        let hub_json = payload.hub_json;
        let master_seed = payload.master_seed;

        // Re-pretty-print to match what `HubState::save` writes, so
        // byte-compare against a co-running source hub matches. The
        // backup payload itself is compact JSON (saves a few bytes
        // per push); the operator-facing on-disk file isn't.
        let parsed: deposits_hub::state::HubState = serde_json::from_str(&hub_json)
            .map_err(|e| format!("parse restored hub.json: {}", e))?;
        let pretty = serde_json::to_string_pretty(&parsed)
            .map_err(|e| format!("pretty-print hub.json: {}", e))?;
        let hub_json_path = data_dir.join("hub.json");
        // Atomic write via tmp + rename to keep an existing file
        // intact if the write somehow fails midway.
        let tmp = hub_json_path.with_extension("json.tmp");
        std::fs::write(&tmp, &pretty).map_err(|e| format!("write tmp hub.json: {}", e))?;
        std::fs::rename(&tmp, &hub_json_path)
            .map_err(|e| format!("rename hub.json: {}", e))?;

        let mut wrote_master = false;
        if let Some(seed_hex) = master_seed {
            let mp = deposits_hub::state::HubState::master_seed_path(&data_dir);
            std::fs::write(&mp, &seed_hex)
                .map_err(|e| format!("write master seed: {}", e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&mp)
                    .map_err(|e| format!("stat master seed: {}", e))?
                    .permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&mp, perms)
                    .map_err(|e| format!("chmod master seed: {}", e))?;
            }
            wrote_master = true;
        }

        println!(
            "restored hub.json (snapshot ts={}) {} master seed{}",
            ts,
            if wrote_master { "+" } else { "(no" },
            if wrote_master { "" } else { " in snapshot)" }
        );
        Ok::<(), String>(())
    })
}

fn cmd_reject(args: &[String]) -> Result<(), String> {
    let c = parse_common(args)?;
    let data_dir = data_dir_or_default(c.data_dir);
    let pubkey = c.pubkey.ok_or("missing --pubkey")?;
    if c.relays.is_empty() {
        return Err("`reject` requires at least one --relay so the ack reaches the peer".to_string());
    }
    let secret_path = deposits_hub::state::HubState::nostr_secret_path(&data_dir);
    let secret_hex = std::fs::read_to_string(&secret_path)
        .map_err(|e| format!("read hub secret: {}", e))?
        .trim()
        .to_string();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {}", e))?;
    rt.block_on(async move {
        let mut state = deposits_hub::state::HubState::load_or_init(&data_dir)
            .map_err(|e| format!("hub state: {}", e))?;
        deposits_hub::control::reject(&mut state, &data_dir, &pubkey)?;
        let transport = deposits_hub::nostr::HubTransport::connect(&secret_hex, &c.relays)
            .await
            .map_err(|e| format!("nostr connect: {}", e))?;
        deposits_hub::control::send_reject_ack(&transport, &pubkey).await;
        println!("rejected {}", pubkey);
        Ok::<(), String>(())
    })
}

fn cmd_pubkey(args: &[String]) -> Result<(), String> {
    let c = parse_common(args)?;
    let data_dir = data_dir_or_default(c.data_dir);
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("create data dir {}: {}", data_dir.display(), e))?;
    let state = deposits_hub::state::HubState::load_or_init(&data_dir)
        .map_err(|e| format!("hub state: {}", e))?;
    println!("{}", state.hub_pubkey_hex());
    Ok(())
}

fn cmd_spawn_line(args: &[String]) -> Result<(), String> {
    let c = parse_common(args)?;
    let data_dir = data_dir_or_default(c.data_dir);
    let name = c.name.ok_or("missing --name")?;
    if c.relays.is_empty() {
        return Err("`spawn-line` requires at least one --relay (the signer needs to know where to find the hub)".to_string());
    }
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("create data dir {}: {}", data_dir.display(), e))?;
    let mut state = deposits_hub::state::HubState::load_or_init(&data_dir)
        .map_err(|e| format!("hub state: {}", e))?;

    // First-time initialization (seed + signer data-dir) so the
    // operator can copy the line to another host and have the signer
    // start cleanly without a separate `init` step. The launch line
    // itself is identical whether the workspace existed already or not.
    let spawner =
        deposits_hub::spawn::Spawner::new(state.hub_pubkey_hex().to_string(), c.relays.clone());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {}", e))?;
    let seed_bytes = parse_seed_arg(c.seed.as_deref())?;
    // If --seed wasn't provided, derive deterministically from the
    // hub master + a stable per-name index. Operator backs up
    // `hub-master-seed` once; recovery only needs that file + the
    // `signer_indexes` map in hub.json.
    let effective_seed = derive_seed_if_unspecified(&data_dir, &mut state, &name, seed_bytes)?;
    let ws = rt
        .block_on(spawner.ensure_initialized_with_seed(&data_dir, &name, effective_seed))
        .map_err(|e| format!("init signer workspace: {}", e))?;

    let transport_pk = std::fs::read_to_string(ws.data_dir.join("transport_pubkey"))
        .map_err(|e| format!("read signer transport pubkey: {}", e))?
        .trim()
        .to_string();

    println!("# signer name:           {}", name);
    println!("# signer transport pk:   {}", transport_pk);
    println!("# hub pubkey:            {}", state.hub_pubkey_hex());
    println!("# data dir:              {}", ws.data_dir.display());
    println!();
    if c.docker {
        println!("# docker variant — workspace mounted at /workspace in the container.");
        println!(
            "{}",
            spawner.launch_line_docker(&data_dir, &name, c.docker_image.as_deref())
        );
    } else {
        println!("{}", spawner.launch_line(&data_dir, &name));
    }
    Ok(())
}

fn cmd_qr(args: &[String]) -> Result<(), String> {
    let c = parse_common(args)?;
    let payload = if let Some(t) = c.text {
        t
    } else {
        let data_dir = data_dir_or_default(c.data_dir);
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| format!("create data dir {}: {}", data_dir.display(), e))?;
        let state = deposits_hub::state::HubState::load_or_init(&data_dir)
            .map_err(|e| format!("hub state: {}", e))?;
        state.hub_pubkey_hex().to_string()
    };
    print!("{}", deposits_hub::qr::render(&payload));
    println!("{}", payload);
    Ok(())
}

fn cmd_spawn(args: &[String]) -> Result<(), String> {
    let c = parse_common(args)?;
    let data_dir = data_dir_or_default(c.data_dir);
    let name = c.name.ok_or("missing --name")?;
    if c.relays.is_empty() {
        return Err("`spawn` requires at least one --relay".to_string());
    }
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("create data dir {}: {}", data_dir.display(), e))?;
    let mut state = deposits_hub::state::HubState::load_or_init(&data_dir)
        .map_err(|e| format!("hub state: {}", e))?;
    let spawner = deposits_hub::spawn::Spawner::new(state.hub_pubkey_hex().to_string(), c.relays);

    let seed_bytes = parse_seed_arg(c.seed.as_deref())?;
    let effective_seed = derive_seed_if_unspecified(&data_dir, &mut state, &name, seed_bytes)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {}", e))?;
    rt.block_on(async move {
        // ensure_initialized first so we can honor --seed; then spawn.
        spawner
            .ensure_initialized_with_seed(&data_dir, &name, effective_seed)
            .await
            .map_err(|e| format!("init signer workspace: {}", e))?;
        let handle = spawner
            .spawn(&data_dir, &name)
            .await
            .map_err(|e| format!("spawn: {}", e))?;
        eprintln!(
            "spawned signer '{}' (transport pk: {}); logs in {}",
            handle.name,
            handle.transport_pubkey_hex,
            handle.workspace.root.display()
        );
        // Wait for ctrl-c, then kill the child.
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| format!("ctrl_c: {}", e))?;
        eprintln!("stopping spawned signer");
        let _ = handle.kill().await;
        Ok::<(), String>(())
    })
}
