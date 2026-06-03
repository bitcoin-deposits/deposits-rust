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
    run         Boot the hub: load state, open nostr client, launch the TUI
    pubkey      Print the hub's nostr pubkey
    help        Show this message

OPTIONS:
    --data-dir <DIR>   Hub data directory (default: ~/.deposits-hub)
    --relay <URL>      Nostr relay (can be passed more than once; required for `run`)

EXAMPLES:
    deposits-hub run --relay wss://relay.bitcoindeposits.net
    deposits-hub pubkey
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
            unknown => return Err(format!("unknown option: {}", unknown)),
        }
    }
    Ok(out)
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
    rt.block_on(run_async(data_dir, state, c.relays))
}

async fn run_async(
    data_dir: PathBuf,
    state: deposits_hub::state::HubState,
    relays: Vec<String>,
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

    // Hand control to the TUI. The TUI owns the terminal + the inbound
    // dispatch loop until the operator quits with `q`. Tracing logs
    // route to stderr — when the TUI's alt-screen is active they end
    // up in the scrollback once we leave.
    let app = deposits_hub::tui::App::new(data_dir, state, transport);
    app.run(inbox).await
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
