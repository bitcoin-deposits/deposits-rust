//! `deposits-signer` binary entrypoint.
//!
//! Subcommands:
//!   - `init --data-dir <p> [--seed-file <p>]`
//!   - `pubkey --data-dir <p>` — print the transport pubkey for paste into
//!     the daemon's `--signer-pubkey`.
//!   - `trust add --data-dir <p> <node_pubkey>`
//!   - `trust list --data-dir <p>`
//!   - `import-seed --data-dir <p> --seed-file <p>`
//!   - `run --data-dir <p> --socket <p>`

use std::path::PathBuf;
use std::process::ExitCode;

use deposits_signer::data::{DataDir, DataError};
use deposits_signer::policy::SeqPolicy;
use deposits_signer::server::{serve_connection, ServerCtx};

const USAGE: &str = r#"deposits-signer — out-of-process signer for deposits-node

USAGE:
    deposits-signer <SUBCOMMAND>

SUBCOMMANDS:
    init        --data-dir <path> [--seed-file <path>]
                Generate a transport keypair and (optionally) install the
                seed. Refuses if the data dir is already initialized.

    pubkey      --data-dir <path>
                Print the signer's transport pubkey (paste into the daemon's
                --signer-pubkey arg).

    import-seed --data-dir <path> --seed-file <path>
                Install or replace the operator/identity seed. The seed
                file must contain 32 bytes of hex.

    trust add   --data-dir <path> <node_pubkey_hex>
                Allow a node transport pubkey (33-byte compressed hex)
                to connect.

    trust list  --data-dir <path>
                List currently allowed node pubkeys.

    run         --data-dir <path> --socket <path>
                Start the signer on a Unix socket. Connections must come
                from a node in the trust list.

ENVIRONMENT:
    RUST_LOG    Tracing filter, e.g. RUST_LOG=deposits_signer=info
"#;

fn main() -> ExitCode {
    init_tracing();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{}", USAGE);
        return ExitCode::from(2);
    }

    let result = match args[0].as_str() {
        "init" => cmd_init(&args[1..]),
        "pubkey" => cmd_pubkey(&args[1..]),
        "import-seed" => cmd_import_seed(&args[1..]),
        "trust" => cmd_trust(&args[1..]),
        "run" => cmd_run(&args[1..]),
        "help" | "--help" | "-h" => {
            print!("{}", USAGE);
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("error: unknown subcommand {:?}", other);
            eprintln!();
            eprint!("{}", USAGE);
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

#[derive(Default)]
struct CommonArgs {
    data_dir: Option<PathBuf>,
    seed_file: Option<PathBuf>,
    socket: Option<PathBuf>,
    positional: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<CommonArgs, String> {
    let mut out = CommonArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                out.data_dir = Some(args.get(i).ok_or("--data-dir needs a value")?.into());
            }
            "--seed-file" => {
                i += 1;
                out.seed_file = Some(args.get(i).ok_or("--seed-file needs a value")?.into());
            }
            "--socket" => {
                i += 1;
                out.socket = Some(args.get(i).ok_or("--socket needs a value")?.into());
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown flag {:?}", other));
            }
            other => out.positional.push(other.to_string()),
        }
        i += 1;
    }
    Ok(out)
}

fn require_data_dir(c: &CommonArgs) -> Result<DataDir, String> {
    let p = c
        .data_dir
        .clone()
        .ok_or("missing --data-dir".to_string())?;
    Ok(DataDir::new(p))
}

fn read_seed_file(path: &PathBuf) -> Result<[u8; 32], String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let bytes = hex::decode(s.trim()).map_err(|e| format!("hex parse seed file: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("seed file must contain 32 bytes hex, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ---- subcommand impls -----------------------------------------------------

fn cmd_init(args: &[String]) -> Result<(), String> {
    let c = parse_args(args)?;
    let dd = require_data_dir(&c)?;
    let seed = if let Some(seed_path) = c.seed_file.as_ref() {
        Some(read_seed_file(seed_path)?)
    } else {
        None
    };
    let key = dd
        .init(seed.as_ref())
        .map_err(|e| e.to_string())?;
    println!("data dir: {}", dd.root.display());
    println!("transport pubkey: {}", hex::encode(key.public.serialize()));
    if seed.is_some() {
        println!("seed installed: {} bytes hex", 32);
    } else {
        println!("seed not installed; run `import-seed` later");
    }
    Ok(())
}

fn cmd_pubkey(args: &[String]) -> Result<(), String> {
    let c = parse_args(args)?;
    let dd = require_data_dir(&c)?;
    let key = dd.load_transport().map_err(|e| e.to_string())?;
    println!("{}", hex::encode(key.public.serialize()));
    Ok(())
}

fn cmd_import_seed(args: &[String]) -> Result<(), String> {
    let c = parse_args(args)?;
    let dd = require_data_dir(&c)?;
    let seed_path = c
        .seed_file
        .ok_or_else(|| "missing --seed-file".to_string())?;
    let seed = read_seed_file(&seed_path)?;
    dd.write_seed(&seed).map_err(|e| e.to_string())?;
    println!("seed installed at {}", dd.seed_path().display());
    Ok(())
}

fn cmd_trust(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("trust requires a subcommand: add | list".into());
    }
    let sub = &args[0];
    let rest = &args[1..];
    match sub.as_str() {
        "add" => {
            let c = parse_args(rest)?;
            let dd = require_data_dir(&c)?;
            let pk_hex = c
                .positional
                .first()
                .ok_or("trust add needs a node_pubkey_hex argument")?;
            let bytes = hex::decode(pk_hex).map_err(|e| format!("hex: {}", e))?;
            let pk = bitcoin::secp256k1::PublicKey::from_slice(&bytes)
                .map_err(|e| format!("pubkey: {}", e))?;
            let added = dd.add_allowlist(&pk).map_err(|e| e.to_string())?;
            if added {
                println!("allowlisted {}", hex::encode(pk.serialize()));
            } else {
                println!("already allowlisted {}", hex::encode(pk.serialize()));
            }
            Ok(())
        }
        "list" => {
            let c = parse_args(rest)?;
            let dd = require_data_dir(&c)?;
            let pks = dd.load_allowlist().map_err(|e| e.to_string())?;
            if pks.is_empty() {
                println!("(empty)");
            } else {
                for pk in pks {
                    println!("{}", hex::encode(pk.serialize()));
                }
            }
            Ok(())
        }
        other => Err(format!("unknown trust subcommand {:?}", other)),
    }
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let c = parse_args(args)?;
    let dd = require_data_dir(&c)?;
    let socket_path = c.socket.ok_or_else(|| "missing --socket".to_string())?;

    let transport = dd.load_transport().map_err(|e| e.to_string())?;
    let allowlist = dd.load_allowlist().map_err(|e| e.to_string())?;
    // Derive both the operator secret (m/86'/0'/0'/0/0) and the Nostr
    // identity secret (m/85'/0'/0'/0/0) from the loaded seed. The Nostr
    // key is what `IssueNostrSecret` hands back to the daemon.
    let (operator_secret, nostr_secret) = dd
        .derive_keys(bitcoin::Network::Bitcoin)
        .map_err(|e| format!("derive keys: {}", e))?;

    if allowlist.is_empty() {
        tracing::warn!("allowlist is empty — no daemon will be permitted to connect");
    }

    let policy = std::sync::Arc::new(
        SeqPolicy::load(dd.policy_path()).map_err(|e| format!("load policy: {}", e))?,
    );

    let ctx = std::sync::Arc::new(ServerCtx::from_local(
        transport.secret,
        allowlist,
        operator_secret,
        nostr_secret,
        policy,
    ));

    // Async runtime for the listener + per-conn tasks.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {}", e))?;

    rt.block_on(async move {
        // Best-effort cleanup of a stale socket file.
        let _ = std::fs::remove_file(&socket_path);
        let listener = tokio::net::UnixListener::bind(&socket_path)
            .map_err(|e| format!("bind {}: {}", socket_path.display(), e))?;
        tracing::info!("listening on {}", socket_path.display());

        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("accept: {}", e);
                    continue;
                }
            };
            let ctx_for_task = std::sync::Arc::clone(&ctx);
            tokio::spawn(async move {
                let mut stream = stream;
                if let Err(e) = serve_connection(&mut stream, &ctx_for_task).await {
                    tracing::warn!("connection ended with error: {}", e);
                }
            });
        }
    })
}

// Convert the `cmd_run` error type since rt.block_on returns `Result<(), String>`.
trait MapErrToString<T> {
    fn map_err_string(self) -> Result<T, String>;
}
impl<T, E: std::fmt::Display> MapErrToString<T> for Result<T, E> {
    fn map_err_string(self) -> Result<T, String> {
        self.map_err(|e| e.to_string())
    }
}

#[allow(dead_code)]
fn _silence_data_error_use(e: DataError) -> String {
    e.to_string()
}
