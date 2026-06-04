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
        "reject" => cmd_reject(rest),
        "spawn-line" => cmd_spawn_line(rest),
        "spawn" => cmd_spawn(rest),
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
            unknown => return Err(format!("unknown option: {}", unknown)),
        }
    }
    Ok(out)
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
        let app = deposits_hub::tui::App::new(data_dir, state, transport);
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
                                drop(st);
                                control::send_already_approved_ack(&transport, &from).await;
                            }
                            Ok(false) => {
                                if auto_approve {
                                    // Promote pending → signers/nodes immediately + ack.
                                    // Use the role-scoped pending key so a signer+node
                                    // pair from the same operator (same nostr identity)
                                    // doesn't disambiguation-fail under approve().
                                    let pkey = control::pending_key(role, &from);
                                    let label = match control::approve(&mut st, &data_dir, &pkey, None) {
                                        Ok(l) => l,
                                        Err(e) => {
                                            tracing::warn!("auto-approve: {}", e);
                                            drop(st);
                                            continue;
                                        }
                                    };
                                    drop(st);
                                    tracing::info!(
                                        "auto-approved {} as '{}'",
                                        &from[..16],
                                        label
                                    );
                                    control::send_accept_ack(&transport, &from, &label).await;
                                } else {
                                    drop(st);
                                    tracing::info!("register from {} — parked", &from[..16]);
                                    control::send_waiting_ack(&transport, &from).await;
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
                            Some(s) => tracing::info!(
                                "status from {}: ready={} wallet={:.4}BTC ledgers={} active={} quorums={} tip={}",
                                &from[..16], ready,
                                (s.wallet_balance_sats as f64) / 100_000_000.0,
                                s.ledger_count, s.active_ledger_count, s.quorum_member_count, s.chain_tip,
                            ),
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
    let state = deposits_hub::state::HubState::load_or_init(&data_dir)
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
    let ws = rt
        .block_on(spawner.ensure_initialized_with_seed(&data_dir, &name, seed_bytes))
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
    println!("{}", spawner.launch_line(&data_dir, &name));
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
    let state = deposits_hub::state::HubState::load_or_init(&data_dir)
        .map_err(|e| format!("hub state: {}", e))?;
    let spawner = deposits_hub::spawn::Spawner::new(state.hub_pubkey_hex().to_string(), c.relays);

    let seed_bytes = parse_seed_arg(c.seed.as_deref())?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {}", e))?;
    rt.block_on(async move {
        // ensure_initialized first so we can honor --seed; then spawn.
        spawner
            .ensure_initialized_with_seed(&data_dir, &name, seed_bytes)
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
