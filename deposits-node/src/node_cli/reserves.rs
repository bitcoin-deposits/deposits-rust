// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use super::parse_config;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use crate::Node;

/// Handle reserves subcommands
pub async fn reserves_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() || args[0].starts_with("--") {
        eprintln!(
            "Usage: deposits-node reserves <list|spend> [args...]\n\
             \n\
             Subcommands:\n\
               list    List the operator's Taproot reserves UTXOs\n\
               spend   Emergency-spend a Taproot reserves UTXO using quorum keys"
        );
        return Ok(());
    }

    match args[0].as_str() {
        "list" => reserves_list(&args[1..]).await,
        "spend" => reserves_spend(&args[1..]).await,
        cmd => {
            eprintln!("Unknown reserves subcommand: {}", cmd);
            eprintln!("Run `deposits-node reserves` for usage.");
            Ok(())
        }
    }
}

/// List Taproot reserves UTXOs across every per-ledger wallet on this
/// operator. Each ledger's vault has its own entry; the listing groups
/// by ledger id.
pub async fn reserves_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    let ledger_wallets: Vec<_> = node
        .ledger_wallets
        .read()
        .unwrap()
        .iter()
        .map(|(id, w)| (id.clone(), w.clone()))
        .collect();

    let mut found_any = false;
    for (ledger_id, lw) in ledger_wallets {
        let info = match lw.taproot_reserves() {
            Some(i) => i,
            None => continue,
        };
        found_any = true;
        println!("=== Ledger {} ===", &ledger_id);
        println!("  Outpoint: {}", info.outpoint);
        println!("    Amount: {} sats", info.amount);
        println!("    Operator: {}", info.operator);
        println!("    Quorum Members: {}", info.quorum_members.len());
        for (i, member) in info.quorum_members.iter().enumerate() {
            println!("      {}: {}", i + 1, member);
        }
        println!("    First Expiry: block {}", info.quorum_expiry);
        println!("    Ledger Hash: {}", hex::encode(&info.ledger_hash[..8]));
        println!("    Confirmed: {}", info.confirmed);

        println!();
        println!("    === Taproot Script Details ===");
        println!("    Internal Key: {}", info.taproot_output.internal_key());
        if let Some(merkle_root) = info.taproot_output.merkle_root() {
            println!("    Merkle Root: {}", merkle_root);
        }
        println!(
            "    ScriptPubKey: {}",
            hex::encode(info.taproot_output.script_pubkey().as_bytes())
        );
        println!();
        println!("    === Spending Tiers (Script Leaves) ===");
        for (i, tier) in info.taproot_output.config.tiers.iter().enumerate() {
            println!(
                "    Tier {}: {} (threshold={}, tie_breaker={}, timelock={})",
                i,
                tier.description,
                tier.threshold,
                tier.requires_tie_breaker,
                tier.timelock_blocks
            );
            if let Some(cb) = info.taproot_output.control_block_for_tier(i) {
                println!("      Control Block: {}", hex::encode(cb.serialize()));
            }
        }
        println!();
        println!("    === Full Script Tree (for decoding) ===");
        let voter_set = deposits_core::VoterSet::new(info.operator, info.quorum_members.clone());
        for (i, tier) in info.taproot_output.config.tiers.iter().enumerate() {
            let builder = deposits_core::TapscriptReservesBuilder::new(
                voter_set.clone(),
                info.taproot_output.config.clone(),
                lw.network(),
                info.ledger_hash,
            );
            if let Ok(script) = builder.build_threshold_leaf(tier) {
                println!("    Leaf {}: {}", i, hex::encode(script.as_bytes()));
            }
        }
        println!();
    }

    if !found_any {
        println!("No reserves outputs found.");
    }
    Ok(())
}

/// Emergency spend: move reserves UTXO to a destination address using quorum keys.
///
/// Usage: reserves spend <destination_address> --key <hex_secret> [--key <hex_secret> ...] [--tier <N>] [--fee-rate <sat/vb>]
///
/// Requires enough keys to satisfy the chosen spending tier (default: tier 0 = majority of quorum).
/// The operator's key is required for tiers that include the operator (tie-breaker).
async fn reserves_spend(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use deposits_core::tapscript_reserves::TapscriptReservesBuilder;

    let mut config_args = Vec::new();
    let mut destination: Option<String> = None;
    let mut keys: Vec<String> = Vec::new();
    let mut seed_dir: Option<String> = None;
    let mut ledger_id_arg: Option<String> = None;
    let mut tier: usize = 0;
    let mut fee_rate: u64 = 2; // sat/vb default
    // `--split <addr>:<sats>` fixed-amount outputs that come before the
    // change output (positional `dest_address`). With one or more `--split`
    // entries, the positional dest receives `reserves − Σsplits − fee` as
    // change rather than the whole UTXO. Single-positional callers without
    // any `--split` get the original 1-output behavior unchanged.
    let mut splits_raw: Vec<String> = Vec::new();
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" | "-k" if i + 1 < args.len() => {
                keys.push(args[i + 1].clone());
                i += 2;
            }
            "--seed-dir" if i + 1 < args.len() => {
                seed_dir = Some(args[i + 1].clone());
                i += 2;
            }
            "--ledger" if i + 1 < args.len() => {
                ledger_id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--tier" if i + 1 < args.len() => {
                tier = args[i + 1].parse().map_err(|_| "Invalid --tier")?;
                i += 2;
            }
            "--fee-rate" if i + 1 < args.len() => {
                fee_rate = args[i + 1].parse().map_err(|_| "Invalid --fee-rate")?;
                i += 2;
            }
            "--split" if i + 1 < args.len() => {
                splits_raw.push(args[i + 1].clone());
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
                i += 1;
            }
            _ => {
                if destination.is_none() {
                    destination = Some(args[i].clone());
                }
                i += 1;
            }
        }
    }

    let destination = destination.ok_or(
        "Usage: reserves spend <dest_address> --ledger <ledger_id> --seed-dir <path> \
         [--key <hex>] [--tier N] [--fee-rate N] [--split <addr>:<sats> [--split ...]] \
         [--dry-run]\n\n\
         With one or more `--split <addr>:<sats>`, each split is a separate output and \
         `dest_address` becomes the change output receiving `reserves − Σsplits − fee`. \
         Pass `--dry-run` to print the decoded tx + hex without broadcasting."
    )?;

    if keys.is_empty() && seed_dir.is_none() {
        return Err("Provide --seed-dir <path> or at least one --key <hex>".into());
    }

    let config = parse_config(&config_args)?;
    let node = Node::new(config.clone()).await?;
    node.sync_wallet()?;

    let secp = Secp256k1::new();

    // Parse destination address
    let dest_addr = destination
        .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
        .map_err(|e| format!("Invalid destination address: {}", e))?
        .require_network(config.network)
        .map_err(|e| format!("Address network mismatch: {}", e))?;
    let dest_script = dest_addr.script_pubkey();

    // Collect secret keys from --key flags
    let mut secret_keys: Vec<SecretKey> = keys
        .iter()
        .map(|hex_str| {
            let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid key hex: {}", e))?;
            SecretKey::from_slice(&bytes).map_err(|e| format!("Invalid secret key: {}", e))
        })
        .collect::<Result<Vec<_>, String>>()?;

    // Auto-discover keys from --seed-dir: find all files named "seed", derive operator key
    if let Some(ref dir) = seed_dir {
        let seed_path = std::path::Path::new(dir);
        if !seed_path.is_dir() {
            return Err(format!("Seed directory not found: {}", dir).into());
        }
        fn find_seed_files(dir: &std::path::Path, results: &mut Vec<std::path::PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        find_seed_files(&path, results);
                    } else if matches!(
                        path.file_name().and_then(|n| n.to_str()),
                        Some("seed") | Some("seed.hex")
                    ) {
                        results.push(path);
                    }
                }
            }
        }
        let mut seed_files = Vec::new();
        find_seed_files(seed_path, &mut seed_files);

        for seed_file in &seed_files {
            let seed_hex = match std::fs::read_to_string(seed_file) {
                Ok(s) => s.trim().to_string(),
                Err(_) => continue,
            };
            if seed_hex.len() != 64 {
                continue;
            }
            if let Ok(seed_bytes) = hex::decode(&seed_hex) {
                if seed_bytes.len() == 32 {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&seed_bytes);
                    if let Ok(sk) = super::derive_operator_secret(&seed, config.network) {
                        let pk = PublicKey::from_secret_key(&secp, &sk);
                        let label = seed_file
                            .parent()
                            .and_then(|p| p.file_name())
                            .and_then(|n| n.to_str())
                            .unwrap_or("?");
                        println!(
                            "  Found seed: {} -> {}...",
                            label,
                            &hex::encode(pk.serialize())[..16]
                        );
                        secret_keys.push(sk);
                    }
                }
            }
        }
    }

    if secret_keys.is_empty() {
        return Err("No keys found. Provide --seed-dir or --key.".into());
    }

    // Locate the ledger's taproot reserves. Per-ledger storage means the
    // caller must say which ledger they're recovering — there's no
    // global "first reserves" anymore.
    let ledger_id = ledger_id_arg.ok_or(
        "Pass --ledger <id> to identify which ledger's reserves to spend (use `reserves list` to enumerate).",
    )?;
    // Try the per-ledger BDK wallet first (fast path — the daemon wrote
    // it when this node opened/operated the ledger). If absent (e.g. the
    // CLI is running with a `--data-dir` that doesn't match the daemon's,
    // or this ledger was migrated in from a peer), reconstruct the same
    // info from the ledger's history + an esplora UTXO lookup.
    let (outpoint, amount, taproot_output, ledger_hash, ruleset_at_qb): (
        bitcoin::OutPoint,
        u64,
        deposits_core::tapscript_reserves::TaprootReservesOutput,
        [u8; 32],
        Option<String>,
    ) = if let Some(lw) = node.ledger_wallet(&ledger_id) {
        let r = lw
            .taproot_reserves()
            .ok_or_else(|| format!("Ledger {} has no taproot reserves", ledger_id))?;
        (
            r.outpoint,
            r.amount,
            r.taproot_output.clone(),
            r.ledger_hash,
            Some(r.ruleset_name.clone()),
        )
    } else {
        // Reconstruction path. Walk the ledger's history → latest QuorumBegin,
        // extract reserves_id / ledger_hash / quorum_members / quorum_expiry /
        // protocol_version. Look up the UTXO on-chain.
        eprintln!(
            "  (no per-ledger wallet on disk for {}; reconstructing from history + esplora)",
            &ledger_id[..16]
        );
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{TapscriptReservesBuilder, VoterSet};
        use deposits_core::TlvDecode;

        let arc = {
            let map = node.handler.ledgers.lock().unwrap();
            map.get(&ledger_id)
                .cloned()
                .ok_or_else(|| format!("Ledger {} not loaded; check --data-dir", ledger_id))?
        };
        let ledger = arc.read().unwrap();
        let original_operator = ledger.state.parent_pubkey;

        let mut qb_reserves_id: Option<String> = None;
        let mut qb_ledger_hash: Option<[u8; 32]> = None;
        let mut qb_members: Vec<bitcoin::secp256k1::PublicKey> = Vec::new();
        let mut qb_expiry: u32 = 0;
        let mut qb_ruleset: Option<String> = None;
        for u in &ledger.history {
            if let Ok(LedgerOperation::QuorumBegin {
                reserves_id,
                ledger_hash,
                quorum_members,
                quorum_expiry,
                protocol_version,
                ..
            }) = LedgerOperation::tlv_decode(&u.message)
            {
                qb_reserves_id = Some(reserves_id);
                qb_ledger_hash = Some(ledger_hash);
                qb_members = quorum_members.into_iter().map(|m| m.pubkey).collect();
                qb_expiry = quorum_expiry;
                qb_ruleset = protocol_version;
            }
        }
        let reserves_id = qb_reserves_id
            .ok_or_else(|| format!("Ledger {} has no QuorumBegin yet", ledger_id))?;
        let qb_recorded_hash = qb_ledger_hash.expect("ledger_hash set alongside reserves_id");

        // Prefer the legacy `wallet/taproot_reserves.json` snapshot if it
        // exists and lists this reserves address. The JSON records the
        // exact build inputs the daemon used at rotation time; the
        // QuorumBegin op's `ledger_hash` field is a separate snapshot
        // (apparently the ledger state hash, not the commitment value)
        // and at least one production rotation has them diverge.
        let ledger_hash = {
            let json_path = std::path::Path::new(&config.data_dir)
                .join("wallet/taproot_reserves.json");
            let mut found: Option<[u8; 32]> = None;
            if json_path.exists() {
                if let Ok(raw) = std::fs::read_to_string(&json_path) {
                    if let Ok(arr) =
                        serde_json::from_str::<serde_json::Value>(&raw)
                    {
                        if let Some(entries) = arr.as_array() {
                            for entry in entries {
                                let addr = entry
                                    .get("address")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("");
                                if addr == reserves_id {
                                    if let Some(h) = entry
                                        .get("ledger_hash")
                                        .and_then(|x| x.as_str())
                                        .and_then(|s| hex::decode(s).ok())
                                    {
                                        if h.len() == 32 {
                                            let mut a = [0u8; 32];
                                            a.copy_from_slice(&h);
                                            found = Some(a);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            match found {
                Some(h) if h != qb_recorded_hash => {
                    eprintln!(
                        "  prefer wallet/taproot_reserves.json ledger_hash={}",
                        hex::encode(h)
                    );
                    eprintln!(
                        "  (QuorumBegin op records {}; they diverge)",
                        hex::encode(qb_recorded_hash)
                    );
                    h
                }
                Some(h) => h,
                None => qb_recorded_hash,
            }
        };

        // Look up the actual UTXO on-chain.
        let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = reserves_id
            .parse()
            .map_err(|e| format!("parse reserves_id: {}", e))?;
        let reserves_addr = reserves_addr
            .require_network(config.network)
            .map_err(|e| format!("network mismatch: {}", e))?;
        let reserves_script = reserves_addr.script_pubkey();
        let utxo = node
            .wallet
            .find_utxo_for_script(&reserves_script)
            .map_err(|e| format!("esplora reserves lookup: {}", e))?
            .ok_or_else(|| {
                format!("reserves UTXO not found at {} (already spent?)", reserves_id)
            })?;
        let (outpoint, amount) = utxo;

        // Reconstruct the taproot reserves under the ledger's recorded
        // ruleset *first* — if that matches the on-chain script, we're
        // done. Otherwise fall back to scanning every known ruleset
        // (same pattern validate-relay uses to handle pre-Q1 production
        // ledgers whose `protocol_version` field was absent but whose
        // on-chain shape happens to match one of the registered
        // factories). Fail only if no ruleset reconstructs to the
        // observed address.
        let voter_set = VoterSet::new(original_operator, qb_members.clone());
        let voter_count = voter_set.all_voters().len();

        // Try each (ruleset, internal_key) combination. Pre-NUMS-fix
        // legacy UTXOs (built before commit b3d38ac) commit the
        // tie-breaker's x-only pubkey as the internal key instead of
        // NUMS — necessary for any production ledger whose
        // QuorumBegin tx predates that fix.
        let tie_breaker_xonly = voter_set
            .tie_breaker()
            .map(|v| v.x_only());
        let try_ruleset_and_key = |name: &str,
                                   internal_key: Option<
            bitcoin::secp256k1::XOnlyPublicKey,
        >|
         -> Option<deposits_core::tapscript_reserves::TaprootReservesOutput> {
            let rs = deposits_core::ruleset::lookup(name)?;
            let cfg = (rs.tier_config_factory)(voter_count, qb_expiry);
            let out = TapscriptReservesBuilder::new(
                voter_set.clone(),
                cfg,
                config.network,
                ledger_hash,
            )
            .build_with_internal_key(internal_key)
            .ok()?;
            if out.script_pubkey() == reserves_script {
                Some(out)
            } else {
                None
            }
        };

        let mut matched_name: Option<String> = None;
        let mut taproot_output: Option<deposits_core::tapscript_reserves::TaprootReservesOutput> =
            None;

        // Search order: each known ruleset under (1) NUMS, then (2)
        // tie-breaker. We start with the ledger's recorded ruleset
        // when present so the happy path is fastest.
        let mut search_order: Vec<String> = Vec::new();
        if let Some(name) = qb_ruleset.as_deref() {
            search_order.push(name.to_string());
        }
        for n in deposits_core::ruleset::all_supported_names() {
            if !search_order.iter().any(|s| s == n) {
                search_order.push(n.to_string());
            }
        }
        'outer: for name in &search_order {
            for (desc, key) in [
                ("NUMS", None::<bitcoin::secp256k1::XOnlyPublicKey>),
                ("tie-breaker", tie_breaker_xonly),
            ] {
                if desc == "tie-breaker" && key.is_none() {
                    continue;
                }
                if let Some(out) = try_ruleset_and_key(name, key) {
                    matched_name = Some(name.clone());
                    taproot_output = Some(out);
                    eprintln!(
                        "  matched on-chain script under ruleset={:?} internal_key={} \
                         (QuorumBegin recorded ruleset={:?})",
                        name, desc, qb_ruleset
                    );
                    break 'outer;
                }
            }
        }

        // Diagnostic: when nothing matches, dump what we tried so the
        // operator can compare addresses and figure out which dimension
        // diverges (tier shape vs internal key vs voter ordering vs
        // ledger_hash vs network).
        if taproot_output.is_none() {
            eprintln!();
            eprintln!("=== Reconstruction diagnostic — nothing matched ===");
            eprintln!("  on-chain reserves_id: {}", reserves_id);
            eprintln!("  network:              {:?}", config.network);
            eprintln!("  ledger_hash:          {}", hex::encode(ledger_hash));
            eprintln!("  quorum_expiry:        {}", qb_expiry);
            eprintln!("  original_operator:    {}", hex::encode(original_operator.serialize()));
            eprintln!("  quorum_members ({}):", qb_members.len());
            for m in &qb_members {
                eprintln!("    - {}", hex::encode(m.serialize()));
            }
            eprintln!("  voter_set total:      {}", voter_count);
            eprintln!();
            eprintln!("  Reconstructions tried (ruleset × internal_key):");
            for name in &search_order {
                if let Some(rs) = deposits_core::ruleset::lookup(name) {
                    let cfg = (rs.tier_config_factory)(voter_count, qb_expiry);
                    for (desc, key) in [
                        ("NUMS", None::<bitcoin::secp256k1::XOnlyPublicKey>),
                        ("tie-breaker", tie_breaker_xonly),
                    ] {
                        if desc == "tie-breaker" && key.is_none() {
                            continue;
                        }
                        let built = TapscriptReservesBuilder::new(
                            voter_set.clone(),
                            cfg.clone(),
                            config.network,
                            ledger_hash,
                        )
                        .build_with_internal_key(key);
                        match built {
                            Ok(out) => eprintln!(
                                "    {:>14} × {:>11}  → {}",
                                name,
                                desc,
                                out.address
                            ),
                            Err(e) => eprintln!(
                                "    {:>14} × {:>11}  → BUILD ERROR: {:?}",
                                name, desc, e
                            ),
                        }
                    }
                }
            }
            eprintln!();
        }
        let taproot_output = taproot_output.ok_or_else(|| {
            format!(
                "no known ruleset reconstructs the on-chain reserves \
                 address for ledger {} — this build is too old or the \
                 chain state has diverged",
                &ledger_id[..16]
            )
        })?;
        let resolved_ruleset = matched_name.unwrap_or_else(|| "legacy".to_string());

        (outpoint, amount, taproot_output, ledger_hash, Some(resolved_ruleset))
    };

    // Bridge: downstream code reads `reserves.taproot_output` / `.outpoint`
    // / `.amount`. Re-wrap into the same shape so the existing logic below
    // works unchanged. The fields not needed for spending (operator,
    // quorum_members, quorum_expiry, confirmed) are filled with defaults
    // / placeholders that downstream code doesn't read.
    let operator_pk = taproot_output
        .voter_set
        .tie_breaker()
        .map(|v| v.pubkey)
        .unwrap_or_else(|| {
            // No tie-breaker would only happen for a synthetic VoterSet.
            // Use the all_voters first entry as a safe fallback for the
            // info field downstream code doesn't actually consume.
            taproot_output.voter_set.all_voters()[0]
        });
    let member_pks: Vec<bitcoin::secp256k1::PublicKey> = taproot_output
        .voter_set
        .primary_voters()
        .iter()
        .map(|v| v.pubkey)
        .collect();
    let reserves = crate::wallet::TaprootReservesInfo {
        outpoint,
        amount,
        operator: operator_pk,
        quorum_members: member_pks,
        quorum_expiry: 0,
        ledger_hash,
        taproot_output,
        ruleset_name: ruleset_at_qb.unwrap_or_else(|| "legacy".to_string()),
        confirmed: true,
    };

    println!("Emergency Reserves Spend");
    println!("========================");
    println!("  Outpoint:    {}", outpoint);
    println!("  Amount:      {} sats", amount);
    println!("  Destination: {}", destination);
    println!(
        "  Tier:        {} ({})",
        tier,
        reserves
            .taproot_output
            .config
            .tiers
            .get(tier)
            .map(|t| t.description.as_str())
            .unwrap_or("?")
    );
    println!("  Fee rate:    {} sat/vb", fee_rate);
    println!("  Keys:        {}", keys.len());
    println!();

    // Get tier info
    let tier_info = reserves
        .taproot_output
        .config
        .tiers
        .get(tier)
        .ok_or(format!(
            "Tier {} does not exist (max: {})",
            tier,
            reserves.taproot_output.config.tiers.len() - 1
        ))?;

    // Build the leaf script for this tier
    let builder = TapscriptReservesBuilder::new(
        reserves.taproot_output.voter_set.clone(),
        reserves.taproot_output.config.clone(),
        config.network,
        reserves.ledger_hash,
    );
    let leaf_script = builder
        .build_threshold_leaf(tier_info)
        .map_err(|e| format!("Failed to build leaf script: {:?}", e))?;

    // Get control block
    let control_block = reserves
        .taproot_output
        .control_block_for_tier(tier)
        .ok_or("Failed to get control block for tier")?;

    // Build unsigned transaction. nLockTime is `quorum_expiry +
    // `tier_info.timelock_blocks` IS the absolute CLTV target (the
    // Ruleset's tier-config factory baked it in: legacy returns plain
    // literals; cltv-offset-v2 returns `quorum_expiry + offset`).
    // The spending TX's nLockTime just mirrors that target.
    let reserves_script_pubkey = reserves.taproot_output.script_pubkey();
    let lock_time = tier_info.timelock_blocks;

    // Parse `--split <addr>:<sats>` into (ScriptBuf, u64) outputs.
    let mut splits: Vec<(bitcoin::ScriptBuf, u64)> = Vec::with_capacity(splits_raw.len());
    for raw in &splits_raw {
        let (addr_s, amt_s) = raw.split_once(':').ok_or_else(|| {
            format!("Invalid --split {:?}: expected <addr>:<sats>", raw)
        })?;
        let addr = addr_s
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| format!("Invalid split address {:?}: {}", addr_s, e))?
            .require_network(config.network)
            .map_err(|e| format!("Split address {:?} network mismatch: {}", addr_s, e))?;
        let amt: u64 = amt_s
            .parse()
            .map_err(|_| format!("Invalid split amount {:?}", amt_s))?;
        splits.push((addr.script_pubkey(), amt));
    }
    if !splits.is_empty() {
        println!("  Splits:      {} extra output(s) before change", splits.len());
        for (i, (script, amt)) in splits.iter().enumerate() {
            println!(
                "    [{}] {} sats → {}",
                i,
                amt,
                bitcoin::Address::from_script(script, config.network)
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| hex::encode(script.as_bytes()))
            );
        }
        let total_splits: u64 = splits.iter().map(|(_, n)| *n).sum();
        println!("    Σ splits:    {} sats", total_splits);
        println!("    change to:   {} (gets reserves − Σsplits − fee)", destination);
    }

    let params = deposits_core::tapscript_reserves::SpendTxParams {
        reserves_outpoint: outpoint,
        reserves_amount: amount,
        destination_script: dest_script.clone(),
        splits,
        fee_rate_sat_vbyte: fee_rate,
        lock_time,
    };
    println!(
        "  Lock time:   {}{}",
        lock_time,
        if lock_time > 0 {
            " (absolute CLTV target from tier config)".to_string()
        } else {
            String::new()
        }
    );
    let mut tx = deposits_core::tapscript_reserves::ReservesSpendBuilder::build_spend_transaction(
        &params,
        &reserves_script_pubkey,
    )?;

    // Compute sighash
    let sighash = deposits_core::tapscript_reserves::ReservesSpendBuilder::compute_sighash(
        &tx,
        0,
        amount,
        &reserves_script_pubkey,
        &leaf_script,
    )?;

    let sighash_bytes: &[u8] = sighash.as_ref();
    println!("  Sighash: {}", hex::encode(sighash_bytes));

    // Sign with each provided key
    // Get the voter set's sorted x-only pubkeys to know which slot each key fills
    let voter_pubkeys = reserves.taproot_output.voter_set.sorted_x_only_pubkeys();

    let mut signatures: Vec<Option<[u8; 64]>> = vec![None; voter_pubkeys.len()];
    let msg = Message::from_digest(*sighash.as_ref());

    for sk in &secret_keys {
        let keypair = Keypair::from_secret_key(&secp, sk);
        let xonly = keypair.x_only_public_key().0;

        if let Some(slot) = voter_pubkeys.iter().position(|pk| *pk == xonly) {
            let sig = secp.sign_schnorr(&msg, &keypair);
            signatures[slot] = Some(sig.serialize());
            println!(
                "  Signed slot {} ({}...)",
                slot,
                &hex::encode(xonly.serialize())[..16]
            );
        } else {
            eprintln!(
                "  WARNING: Key {}... is not in the voter set",
                &hex::encode(xonly.serialize())[..16]
            );
        }
    }

    let signed_count = signatures.iter().filter(|s| s.is_some()).count();
    println!(
        "\n  Signed: {}/{} required",
        signed_count, tier_info.threshold
    );

    if signed_count < tier_info.threshold {
        return Err(format!(
            "Not enough signatures: {} of {} required for tier {}",
            signed_count, tier_info.threshold, tier
        )
        .into());
    }

    // Build witness
    let witness =
        deposits_core::tapscript_reserves::ReservesSpendBuilder::create_checksigadd_witness(
            &signatures,
            &leaf_script,
            &control_block,
        );
    tx.input[0].witness = witness;

    // Serialize and display
    let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    println!("\n  TxID:   {}", tx.compute_txid());
    println!("  Size:   {} vbytes", tx.vsize());

    // Always show the decoded outputs so the operator can eyeball the
    // shape before committing. Useful both on dry-run and on the real
    // path (the broadcast error path also prints raw hex below).
    println!("  Outputs ({}):", tx.output.len());
    for (idx, out) in tx.output.iter().enumerate() {
        let addr_str = bitcoin::Address::from_script(&out.script_pubkey, config.network)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| hex::encode(out.script_pubkey.as_bytes()));
        println!(
            "    [{}] {:>10} sats → {}",
            idx,
            out.value.to_sat(),
            addr_str
        );
    }
    let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let actual_fee = amount.saturating_sub(total_out);
    println!(
        "  Fee:    {} sats ({} sat/vb effective)",
        actual_fee,
        if tx.vsize() > 0 {
            actual_fee as f64 / tx.vsize() as f64
        } else {
            0.0
        }
    );

    if dry_run {
        println!();
        println!("=== DRY RUN — not broadcasting ===");
        println!("Full tx hex (broadcast manually with `bitcoin-cli sendrawtransaction`):");
        println!("{}", tx_hex);
        return Ok(());
    }

    println!("  Hex:    {}", &tx_hex[..80.min(tx_hex.len())]);
    println!("          (full hex: {} chars)", tx_hex.len());

    // Broadcast
    println!("\nBroadcasting...");
    match node.wallet.broadcast(&tx) {
        Ok(txid) => println!("  SUCCESS: Transaction broadcast (txid: {})", txid),
        Err(e) => {
            eprintln!("  Broadcast failed: {}", e);
            eprintln!("\n  Raw transaction (for manual broadcast):");
            println!("{}", tx_hex);
        }
    }

    Ok(())
}
