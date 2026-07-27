// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use super::parse_config;
use crate::Node;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use std::sync::Arc;

pub async fn run_node(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse --metrics-port, --admin-bind, --admin-disabled separately
    // (before parse_config since they're run-specific). Defaults match
    // The admin UI binds 127.0.0.1:8765 unless
    // disabled. Loopback-only by default — operators terminate TLS
    // upstream (caddy/nginx) before exposing to the public internet.
    let mut metrics_port: Option<u16> = None;
    let mut admin_bind: String = "127.0.0.1:8765".to_string();
    let mut admin_disabled = false;
    let mut filtered_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--metrics-port" {
            i += 1;
            if i < args.len() {
                metrics_port = Some(args[i].parse().map_err(|_| "Invalid metrics port")?);
            }
        } else if args[i] == "--admin-bind" {
            i += 1;
            if i < args.len() {
                admin_bind = args[i].clone();
            }
        } else if args[i] == "--admin-disabled" {
            admin_disabled = true;
        } else {
            filtered_args.push(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&filtered_args)?;

    // Snapshot the bits we need for the hub task before `config` moves
    // into `Node::new`. The hub thread runs alongside the daemon's
    // own nostr transport — separate keys, separate filter (kind
    // KIND_HUB / 1059 #p=<hub_pk>) — so there's no conflict with the
    // daemon's regular peer traffic.
    let hub_cfg = config.hub.clone();
    let hub_seed = config.seed;
    let hub_network = config.network;
    let hub_label = config.operator_name.clone();
    // Signer transport pk (if any) — sent in the Node Register so the
    // hub can render which signer this daemon is paired with.
    let hub_signer_pk = config
        .signer
        .as_ref()
        .map(|s| hex::encode(s.signer_pubkey.serialize()));

    // Initialize metrics if port specified
    if let Some(port) = metrics_port {
        if let Err(e) = crate::metrics::init_metrics(port) {
            tracing::warn!("Failed to initialize metrics: {}", e);
        }
    }

    tracing::info!("Starting deposits-node node...");
    tracing::info!("Network: {:?}", config.network);
    tracing::info!("Electrum: {}", config.electrum_url);
    tracing::info!(
        "Relays: {:?}",
        if config.relays.is_empty() {
            crate::nostr::DEFAULT_RELAYS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            config.relays.clone()
        }
    );
    if !config.slow_relays.is_empty() {
        tracing::info!("Slow relays: {:?}", config.slow_relays);
    }

    let node = Arc::new(Node::new(config).await?);

    tracing::info!("Node ID: {}", node.node_id);

    // Start the operator admin UI as early as
    // possible — before sync, before nostr subscribe, before the main
    // event loop. That way if any of those fail, the operator can
    // still load the UI and see *why* (signer tab will report the
    // connection state, dashboard shows the current chain tip
    // (cached) and operator pubkey). Loopback-bound by default.
    if !admin_disabled {
        let bind_addr: std::net::SocketAddr = admin_bind
            .parse()
            .map_err(|e| format!("Invalid --admin-bind {}: {}", admin_bind, e))?;
        let token = crate::admin_api::ensure_token(node.data_dir())?;
        let admin_node = node.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::admin_api::serve(
                crate::admin_api::AdminConfig { bind_addr, token },
                admin_node,
            )
            .await
            {
                tracing::warn!("admin UI exited: {}", e);
            }
        });
    } else {
        tracing::info!("Admin UI disabled (--admin-disabled)");
    }

    // Start the node's message loop FIRST, then sync the wallet in the
    // background. `sync_wallet()` is a blocking call into the chain backend
    // (esplora/electrum); if that backend is slow or rate-limited, a
    // foreground sync here freezes startup *before* the message loop runs.
    // The daemon would still connect + subscribe to the relay (that happens
    // in `Node::new`, earlier) — so it looks alive and answers pings — yet
    // never drains incoming requests, and every `ledger_open`/cosign times
    // out with no error. Opening a ledger is a pure declaration that needs
    // no wallet, and on-chain ops sync their per-ledger wallet on demand,
    // so nothing the daemon serves should ever wait on this initial sync.
    node.start().await?;

    {
        let node = node.clone();
        tokio::task::spawn_blocking(move || {
            tracing::info!("Syncing wallet (background)...");
            match node.sync_wallet() {
                Ok(()) => match node.wallet_balance() {
                    Ok(balance) => tracing::info!("Wallet synced; balance: {} sats", balance),
                    Err(e) => tracing::warn!("Wallet balance after sync: {}", e),
                },
                Err(e) => tracing::warn!("Initial wallet sync failed: {}", e),
            }
        });
    }

    // Spawn the hub registration loop alongside the node's main event
    // loop. Same nostr identity (`m/85'/.../0`) the daemon uses for
    // operator-protocol events, but addressed to the operator-provided
    // hub pubkey on a separate gift-wrapped channel. Hub liveness is
    // not load-bearing — failures here log and exit the task; the
    // daemon keeps serving.
    if let Some(hc) = hub_cfg {
        match deposits_signer::data::derive_keys_from_seed(&hub_seed, hub_network) {
            Ok((op_secret, nostr_secret)) => {
                let secp = Secp256k1::new();
                let op_pk = PublicKey::from_secret_key(&secp, &op_secret);
                let op_pk_hex = hex::encode(op_pk.serialize());
                let nostr_secret_hex = hex::encode(nostr_secret.secret_bytes());
                let node_for_hub = node.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::hub::run(
                        nostr_secret_hex,
                        hc.pubkey_hex,
                        hc.relays,
                        op_pk_hex,
                        hub_label,
                        hub_signer_pk,
                        node_for_hub,
                    )
                    .await
                    {
                        tracing::warn!("hub loop exited: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("hub registration: derive keys: {} — skipping", e);
            }
        }
    }

    // Refresh ledger advertisements so the chain tip and obligation counters
    // reflect reality after a restart (the original ad could be hours old).
    let published = super::republish_ledger_advertisements(&node).await;
    if published > 0 {
        tracing::info!("Refreshed {} ledger advertisement(s)", published);
    }

    // Continuous CPU profiler using pprof-rs (timer-based sampling via ITIMER_PROF).
    // Works in Docker on any host OS — no hardware PMU or perf_event support needed.
    // SIGUSR1 triggers: stop guard, dump collapsed stacks, restart profiling.
    // Also auto-dumps every 60s.
    // Opt-in: set ENABLE_PROFILING=1 to activate (ITIMER can conflict with jemalloc).
    #[cfg(unix)]
    {
        let data_dir = node.data_dir().to_path_buf();
        let profiling_enabled = std::env::var("ENABLE_PROFILING")
            .map(|v| v == "1")
            .unwrap_or(false);
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sig =
                signal(SignalKind::user_defined1()).expect("Failed to register SIGUSR1 handler");

            if !profiling_enabled {
                tracing::info!("CPU profiling disabled (set ENABLE_PROFILING=1 to enable)");
                // Still handle SIGUSR1 to avoid killing the process
                loop {
                    sig.recv().await;
                    tracing::info!("SIGUSR1 received but profiling disabled");
                }
            }

            use pprof::ProfilerGuardBuilder;
            let profile_dir = data_dir.clone();
            let mut dump_count = 0u32;

            let start_profiler = || -> Option<pprof::ProfilerGuard<'static>> {
                match ProfilerGuardBuilder::default()
                    .frequency(99)
                    .blocklist(&["libc", "libgcc", "pthread", "vdso", "jemalloc"])
                    .build()
                {
                    Ok(guard) => {
                        tracing::info!("Started pprof CPU profiling (99 Hz)");
                        Some(guard)
                    }
                    Err(e) => {
                        tracing::error!("Failed to start pprof: {}", e);
                        None
                    }
                }
            };

            let mut guard = start_profiler();
            let mut dump_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = sig.recv() => {
                        tracing::info!("SIGUSR1 received — dumping profile");
                    }
                    _ = dump_interval.tick() => {}
                }

                dump_count += 1;

                if let Some(g) = guard.take() {
                    match g.report().build() {
                        Ok(report) => {
                            // Write collapsed stacks (compatible with flamegraph.pl and speedscope)
                            let collapsed_path = profile_dir.join("profile-latest.collapsed");
                            let mut stacks: std::collections::HashMap<String, isize> =
                                std::collections::HashMap::new();

                            for (frames, count) in report.data.iter() {
                                // Frames.frames is Vec<Vec<Symbol>> — flatten inline frames
                                let names: Vec<String> = frames
                                    .frames
                                    .iter()
                                    .rev()
                                    .flat_map(|syms| syms.iter().map(|s| s.name()))
                                    .collect();
                                if !names.is_empty() {
                                    *stacks.entry(names.join(";")).or_insert(0) += *count;
                                }
                            }

                            if !stacks.is_empty() {
                                let total: isize = stacks.values().sum();
                                let mut sorted: Vec<_> = stacks.into_iter().collect();
                                sorted.sort_by(|a, b| b.1.cmp(&a.1));
                                if let Ok(mut f) = std::fs::File::create(&collapsed_path) {
                                    use std::io::Write;
                                    for (stack, count) in &sorted {
                                        let _ = writeln!(f, "{} {}", stack, count);
                                    }
                                }
                                tracing::info!(
                                    "Profile dump #{}: {} samples, {} unique stacks",
                                    dump_count,
                                    total,
                                    sorted.len()
                                );
                            } else {
                                tracing::debug!("Profile dump #{}: no samples", dump_count);
                            }

                            // Also write protobuf for pprof tooling
                            let proto_path = profile_dir.join("profile-latest.pb");
                            if let Ok(mut f) = std::fs::File::create(&proto_path) {
                                use pprof::protos::Message;
                                if let Ok(proto) = report.pprof() {
                                    let _ = proto.write_to_writer(&mut f);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to build profile report: {}", e);
                        }
                    }
                }

                // Restart profiler
                guard = start_profiler();
            }
        });
    }

    tracing::info!("Node running. Press Ctrl+C to stop.");

    // Run the event loop
    node.run().await?;

    Ok(())
}
