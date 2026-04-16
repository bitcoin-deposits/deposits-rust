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

mod node_cli;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::Network;
use deposits_node::cli::{nostr_commands, recovery};
use std::str::FromStr;

/// Derive the operator secret key from a seed using HD derivation.
/// This matches what the Wallet does, ensuring consistent key usage across the codebase.
fn derive_operator_secret(seed: &[u8; 32], network: Network) -> Result<SecretKey, String> {
    let secp = Secp256k1::new();

    let xpriv = Xpriv::new_master(network, seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;

    // Use the same derivation path as the Wallet: m/86'/0'/0'/0/0
    let operator_path = DerivationPath::from_str("m/86'/0'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;

    let operator_xpriv = xpriv
        .derive_priv(&secp, &operator_path)
        .map_err(|e| format!("Failed to derive operator key: {}", e))?;

    Ok(operator_xpriv.private_key)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install ring as the default rustls crypto provider (required by nostr-sdk).
    let _ = rustls::crypto::ring::default_provider().install_default();

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
    // Initialize logging — RUST_LOG takes precedence, default to INFO
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

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
        "reserves" => node_cli::reserves::reserves_command(&args[2..]).await?,
        "quorum" => node_cli::quorum::quorum_command(&args[2..]).await?,
        "ledger" => node_cli::ledger::ledger_command(&args[2..]).await?,
        "collateral" => node_cli::collateral_command(&args[2..]).await?,
        "deposit" => node_cli::deposit::deposit_command(&args[2..]).await?,
        "withdraw" => node_cli::withdraw::withdraw_command(&args[2..]).await?,
        "lightning" | "ln" => node_cli::lightning::lightning_command(&args[2..]).await?,
        "nostr" => nostr_commands::nostr_command(&args[2..]).await?,
        "recovery" => recovery::recovery_command(&args[2..]).await?,
        "health" => node_cli::health::health_command(&args[2..]).await?,
        "version" | "--version" | "-V" => {
            println!(
                "deposits-node {} (built {})",
                env!("CARGO_PKG_VERSION"),
                env!("BUILD_TIMESTAMP")
            );
        }
        "keygen" => node_cli::keys::keygen(),
        "derive-deposit-key" => node_cli::keys::derive_deposit_key(&args[2..])?,
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
