// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! deposits-node CLI
//!
//! A deposits protocol node using BDK for on-chain reserves and Nostr for messaging.

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use deposits_node::node_cli;
use deposits_node::node_cli::{nostr_commands, recovery};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // rustls 0.23+ doesn't auto-pick a CryptoProvider even when only
    // one is feature-enabled; the first wss:// handshake panics
    // otherwise. The helper is idempotent.
    deposits_nostr::install_default_crypto_provider();
    if std::env::var_os("DEPOSITS_STACK_DUMP").is_some() {
        install_stack_dump_handler();
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name_fn(|| {
            static ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let id = ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            format!("dep-worker-{}", id)
        })
        .build()?;
    runtime.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging + (optionally) span flamegraph capture.
    //
    // Set TRACING_FLAME_PATH=<file> to record `tracing` spans into a
    // .folded file alongside normal log output. After the process
    // exits cleanly, render with:
    //   inferno-flamegraph < tracing.folded > flamegraph.svg
    //
    // Span density depends on `#[tracing::instrument]` attributes
    // and `tracing::info_span!` calls in the codebase. Use this to
    // see which call paths dominate wall-clock time during a test.
    let _flame_guard: Option<tracing_flame::FlushGuard<std::io::BufWriter<std::fs::File>>> = {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        // tracing writes to stderr so subcommands that produce parseable
        // stdout output (e.g. `transport-pubkey` printing a single hex
        // line for bash capture) aren't polluted by structured log
        // output. fmt::layer's default writer is stdout, which conflicts.
        // `with_span_events(CLOSE)` makes every #[instrument] span emit a line
        // when it closes, carrying `time.busy`/`time.idle` — that's the span
        // metric. Combined with the span-scope field prefix (e.g. the
        // payment_hash on the make_invoice/pay_invoice spans), every nested log
        // line is tagged with the correlation id, so a single payment can be
        // followed across handlers and grepped across processes.
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE);

        match std::env::var("TRACING_FLAME_PATH") {
            Ok(path) if !path.is_empty() => {
                let (flame_layer, guard) = tracing_flame::FlameLayer::with_file(&path)
                    .map_err(|e| format!("TRACING_FLAME_PATH {}: {}", path, e))?;
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(fmt_layer)
                    .with(flame_layer)
                    .init();
                eprintln!(
                    "tracing-flame: capturing spans to {} (render with `inferno-flamegraph`)",
                    path
                );
                Some(guard)
            }
            _ => {
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(fmt_layer)
                    .init();
                None
            }
        }
    };

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        node_cli::print_usage(&args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "run" => node_cli::run::run_node(&args[2..]).await?,
        "info" => node_cli::show_info(&args[2..]).await?,
        "address" => node_cli::show_address(&args[2..]).await?,
        "admin" => node_cli::admin::admin_command(&args[2..]).await?,
        "bootstrap" => node_cli::bootstrap::bootstrap_command(&args[2..]).await?,
        "reserves" => node_cli::reserves::reserves_command(&args[2..]).await?,
        "quorum" => node_cli::quorum::quorum_command(&args[2..]).await?,
        "dormancy" => node_cli::dormancy::dormancy_command(&args[2..]).await?,
        "ledger" => node_cli::ledger::ledger_command(&args[2..]).await?,
        "collateral" => node_cli::collateral_command(&args[2..]).await?,
        "deposit" => node_cli::deposit::deposit_command(&args[2..]).await?,
        "withdraw" => node_cli::withdraw::withdraw_command(&args[2..]).await?,
        "wallet" => node_cli::wallet_command(&args[2..]).await?,
        "lightning" | "ln" => node_cli::lightning::lightning_command(&args[2..]).await?,
        "liquidity" => node_cli::liquidity::liquidity_command(&args[2..]).await?,
        "nostr" => nostr_commands::nostr_command(&args[2..]).await?,
        "recovery" => recovery::recovery_command(&args[2..]).await?,
        "disputes" => node_cli::disputes::disputes_command(&args[2..]).await?,
        "archive" => node_cli::archive::archive_command(&args[2..]).await?,
        "health" => node_cli::health::health_command(&args[2..]).await?,
        "version" | "--version" | "-V" => {
            println!(
                "deposits-node {} (sha {}, built {})",
                env!("CARGO_PKG_VERSION"),
                env!("GIT_SHA"),
                env!("BUILD_TIMESTAMP")
            );
        }
        "keygen" => node_cli::keys::keygen(),
        "derive-deposit-key" => node_cli::keys::derive_deposit_key(&args[2..])?,
        "transport-pubkey" => node_cli::keys::transport_pubkey(&args[2..])?,
        "delegate-pubkey" => node_cli::keys::delegate_pubkey(&args[2..])?,
        "pubkey-to-p2wpkh" => node_cli::keys::pubkey_to_p2wpkh(&args[2..])?,
        #[cfg(feature = "dangerous-testing")]
        "danger" => node_cli::danger::danger_command(&args[2..]).await?,
        "help" | "--help" | "-h" => node_cli::print_usage(&args[0]),
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            node_cli::print_usage(&args[0]);
        }
    }

    Ok(())
}

/// With `DEPOSITS_STACK_DUMP` set, SIGUSR2 writes the receiving thread's backtrace to stderr,
/// and SIGUSR1 writes every thread's (`kill -USR1 <pid>`): a watcher thread walks
/// /proc/self/task and sends each thread SIGUSR2 in turn. For a node that stalls where no
/// debugger may attach (ptrace is often restricted); the handler allocates, so it is
/// diagnostic only. Async tasks show only where they block a thread: a parked future is
/// not on any stack.
#[cfg(unix)]
fn install_stack_dump_handler() {
    use std::sync::atomic::{AtomicI32, Ordering};
    static DUMP_ALL_PIPE: AtomicI32 = AtomicI32::new(-1);
    extern "C" fn on_usr2(_: libc::c_int) {
        let bt = std::backtrace::Backtrace::force_capture();
        let s = format!(
            "=== SIGUSR2 stack (thread {:?}, tid {}) ===\n{}\n",
            std::thread::current().name(),
            unsafe { libc::syscall(libc::SYS_gettid) },
            bt
        );
        unsafe { libc::write(2, s.as_ptr() as *const libc::c_void, s.len()) };
    }
    extern "C" fn on_usr1(_: libc::c_int) {
        // Async-signal-safe: one byte to the watcher.
        let fd = DUMP_ALL_PIPE.load(Ordering::Relaxed);
        if fd >= 0 {
            unsafe { libc::write(fd, b"!".as_ptr() as *const libc::c_void, 1) };
        }
    }
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == 0 {
        DUMP_ALL_PIPE.store(fds[1], Ordering::Relaxed);
        let read_fd = fds[0];
        let _ = std::thread::Builder::new()
            .name("stack-dump".into())
            .spawn(move || loop {
                let mut b = [0u8; 1];
                if unsafe { libc::read(read_fd, b.as_mut_ptr() as *mut libc::c_void, 1) } <= 0 {
                    return;
                }
                let pid = std::process::id() as libc::c_int;
                let me = unsafe { libc::syscall(libc::SYS_gettid) } as libc::c_int;
                let mut tids: Vec<libc::c_int> = std::fs::read_dir("/proc/self/task")
                    .map(|d| {
                        d.flatten()
                            .filter_map(|e| e.file_name().to_str()?.parse().ok())
                            .collect()
                    })
                    .unwrap_or_default();
                tids.sort();
                let head = format!("=== SIGUSR1: all {} threads ===\n", tids.len());
                unsafe { libc::write(2, head.as_ptr() as *const libc::c_void, head.len()) };
                for tid in tids.into_iter().filter(|t| *t != me) {
                    unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGUSR2) };
                    // One at a time, so the backtraces do not interleave.
                    std::thread::sleep(std::time::Duration::from_millis(30));
                }
            });
        unsafe {
            libc::signal(libc::SIGUSR1, on_usr1 as *const () as libc::sighandler_t);
        }
    }
    unsafe {
        libc::signal(libc::SIGUSR2, on_usr2 as *const () as libc::sighandler_t);
    }
}

#[cfg(not(unix))]
fn install_stack_dump_handler() {}
