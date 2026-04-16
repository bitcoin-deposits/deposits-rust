// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use super::parse_config;
use deposits_node::Node;
use std::sync::Arc;

pub async fn run_node(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse --metrics-port separately (before parse_config since it's run-specific)
    let mut metrics_port: Option<u16> = None;
    let mut filtered_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--metrics-port" {
            i += 1;
            if i < args.len() {
                metrics_port = Some(args[i].parse().map_err(|_| "Invalid metrics port")?);
            }
        } else {
            filtered_args.push(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&filtered_args)?;

    // Initialize metrics if port specified
    if let Some(port) = metrics_port {
        if let Err(e) = deposits_node::metrics::init_metrics(port) {
            tracing::warn!("Failed to initialize metrics: {}", e);
        }
    }

    tracing::info!("Starting deposits-node node...");
    tracing::info!("Network: {:?}", config.network);
    tracing::info!("Electrum: {}", config.electrum_url);
    tracing::info!(
        "Relays: {:?}",
        if config.relays.is_empty() {
            deposits_node::nostr::DEFAULT_RELAYS
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

    // Sync wallet
    tracing::info!("Syncing wallet...");
    if let Err(e) = node.sync_wallet() {
        tracing::warn!("Initial wallet sync failed: {}", e);
    }

    // Show balance
    match node.wallet_balance() {
        Ok(balance) => tracing::info!("Wallet balance: {} sats", balance),
        Err(e) => tracing::warn!("Failed to get balance: {}", e),
    }

    // Start the node
    node.start().await?;

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
