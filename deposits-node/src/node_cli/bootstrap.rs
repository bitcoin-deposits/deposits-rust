//! `deposits-node bootstrap` — zero-config operator bring-up.
//!
//! Three phases, invoked sequentially by the Docker entrypoint:
//!
//! 1. `bootstrap init <admin_npub>` — generates a seed, validates that the
//!    admin npub has a published profile, DMs the admin the BIP39 mnemonic
//!    and funding address via NIP-17 gift-wrapped message. Writes
//!    `seed.hex` to data_dir. Idempotent: if the seed file exists, this is
//!    a no-op.
//!
//! 2. `bootstrap reserves` — derives the funding address, polls the chain
//!    until a UTXO arrives, then creates the reserves UTXO (with the full
//!    received amount) and opens a ledger. Must run BEFORE the daemon is
//!    started.
//!
//! 3. `bootstrap quorum` — discovers peer operators from ledger
//!    advertisements, pings each to measure round-trip latency, then issues
//!    `QuorumAddMember` for the top `quorum_size` peers (Q = cosigner count;
//!    operator is not counted) and finally `QuorumBegin`. Must run AFTER the
//!    daemon is started (it delegates to the daemon over Nostr).

use super::{derive_operator_secret, parse_config, send_daemon_request};
use crate::nostr::NostrTransportBuilder;
use crate::{Node, NodeConfig};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;
use nostr_sdk::prelude::*;
use std::time::Duration;

const DEFAULT_QUORUM_SIZE: usize = 3;

pub async fn bootstrap_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!(
            "Usage: deposits-node bootstrap <init|reserves|quorum> [args...]\n\
             \n\
             Phases:\n\
               init <admin_npub>  Generate seed, DM admin mnemonic + funding address\n\
               reserves            Wait for UTXO, create reserves, open ledger\n\
               quorum              Discover peers, add top N-1 as quorum, begin"
        );
        return Ok(());
    }
    match args[0].as_str() {
        "init" => bootstrap_init(&args[1..]).await,
        "reserves" => bootstrap_reserves(&args[1..]).await,
        "quorum" => bootstrap_quorum(&args[1..]).await,
        cmd => {
            eprintln!("Unknown bootstrap phase: {}", cmd);
            Ok(())
        }
    }
}

// ─────────────────────────── Phase 1: init ────────────────────────────

async fn bootstrap_init(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut admin_npub: Option<String> = None;
    let mut config_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if admin_npub.is_none() {
            admin_npub = Some(args[i].clone());
        }
        i += 1;
    }

    let admin_npub = admin_npub
        .ok_or("Usage: deposits-node bootstrap init <admin_npub> --data-dir ... --relay ...")?;
    let config = parse_config(&config_args)?;
    let seed_path = config.data_dir.join("seed.hex");

    if seed_path.exists() {
        eprintln!(
            "bootstrap init: seed already exists at {}, skipping",
            seed_path.display()
        );
        return Ok(());
    }

    if config.relays.is_empty() {
        return Err("bootstrap init: --relay required to DM admin".into());
    }

    // Validate admin npub BEFORE generating any state, so a typo doesn't
    // leave orphan seed files or half-initialized data dirs.
    let admin_pk = parse_npub_or_hex(&admin_npub)?;
    let relay = &config.relays[0];
    println!("Validating admin npub has a published profile...");
    validate_admin_profile(relay, &admin_pk).await?;
    println!("  profile found on {}", relay);

    // Persist the admin pubkey so the daemon authorizes admin-class requests
    // gift-wrapped by this identity on every startup.
    std::fs::write(config.data_dir.join("admin.npub"), admin_pk.to_hex())?;

    // Generate a fresh 128-bit entropy → BIP39 mnemonic. 128 bits = 12 words,
    // which is short enough to copy into a password manager. The first 32
    // bytes of the PBKDF2 seed go into `seed.hex` (existing wallet format).
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;
    let mut entropy = [0u8; 16];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)?;
    let bip39_seed = mnemonic.to_seed("");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bip39_seed[..32]);

    // Write the generated seed to disk before deriving the funding address,
    // and override config.seed with it so the Node built for the address
    // derivation uses the same identity the container will run as.
    std::fs::write(&seed_path, hex::encode(seed))?;
    let mut derived_config = config.clone();
    derived_config.seed = seed;
    let funding_address = derive_funding_address(&derived_config).await?;
    // Persist the funding address so subsequent phases display the same one
    // the admin saw in the DM (new_address rotates each call).
    std::fs::write(
        config.data_dir.join("funding_address"),
        funding_address.to_string(),
    )?;
    let node_pubkey = derive_node_pubkey(&seed, config.network)?;

    println!();
    println!("Generated operator identity");
    println!("  node pubkey:     {}", node_pubkey);
    println!("  funding address: {}", funding_address);
    println!();

    // DM the admin with the mnemonic + funding address via NIP-17.
    println!("DMing admin via NIP-17 gift-wrap...");
    let body = format!(
        "deposits-node operator bootstrap\n\
         \n\
         mnemonic (12 words): {}\n\
         \n\
         network:  {:?}\n\
         pubkey:   {}\n\
         funding:  {}\n\
         \n\
         Send any amount to the funding address. The first on-chain payment \
         becomes the reserves UTXO, and the container will form a Q={} quorum \
         (Q cosigners + operator) with the fastest peers it can find.",
        mnemonic, config.network, node_pubkey, funding_address, DEFAULT_QUORUM_SIZE
    );

    send_private_msg_nip17(relay, &seed, config.network, &admin_pk, &body).await?;
    println!("  DM delivered to {}", admin_npub);
    println!();
    println!("bootstrap init: done. Fund {} to proceed.", funding_address);

    Ok(())
}

fn parse_npub_or_hex(s: &str) -> Result<nostr_sdk::PublicKey, Box<dyn std::error::Error>> {
    if let Some(stripped) = s.strip_prefix("npub1") {
        let _ = stripped; // satisfy lint
        nostr_sdk::PublicKey::from_bech32(s).map_err(|e| format!("Invalid npub: {}", e).into())
    } else if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        nostr_sdk::PublicKey::from_hex(s).map_err(|e| format!("Invalid hex pubkey: {}", e).into())
    } else {
        Err("Expected npub1... or 64-char hex pubkey".into())
    }
}

async fn validate_admin_profile(
    relay: &str,
    admin_pk: &nostr_sdk::PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::default();
    client
        .add_relay(relay)
        .await
        .map_err(|e| format!("add_relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Metadata)
        .author(*admin_pk)
        .limit(1);
    let events = client
        .fetch_events(vec![filter], Some(Duration::from_secs(8)))
        .await
        .map_err(|e| format!("fetch profile: {}", e))?;
    client.disconnect().await.ok();

    if events.is_empty() {
        return Err(format!(
            "admin npub has no published profile (Kind 0) on {}. \
             Publish a profile first, then retry.",
            relay
        )
        .into());
    }
    Ok(())
}

async fn derive_funding_address(
    config: &NodeConfig,
) -> Result<bitcoin::Address, Box<dyn std::error::Error>> {
    let node = Node::new(config.clone()).await?;
    let addr = node.new_address()?;
    Ok(addr)
}

fn derive_node_pubkey(
    seed: &[u8; 32],
    network: Network,
) -> Result<String, Box<dyn std::error::Error>> {
    let sk = derive_operator_secret(seed, network)?;
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    Ok(hex::encode(pk.serialize()))
}

async fn send_private_msg_nip17(
    relay: &str,
    seed: &[u8; 32],
    network: Network,
    recipient: &nostr_sdk::PublicKey,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let sk = derive_operator_secret(seed, network)?;
    let nostr_sk = nostr_sdk::SecretKey::from_slice(&sk.secret_bytes())
        .map_err(|e| format!("nostr key: {}", e))?;
    let keys = Keys::new(nostr_sk);

    let client = Client::builder().signer(keys.clone()).build();
    client
        .add_relay(relay)
        .await
        .map_err(|e| format!("add_relay: {}", e))?;
    client.connect().await;

    // Real NIP-17 DM: Kind 1059 outer, NIP-44 encryption, Kind 14 rumor.
    // Distinct from the custom Kind-20101 envelope in NostrTransport
    // ::send_admin_request (see that fn's doc for the divergences). We use
    // real NIP-17 here because the recipient is an *external* admin running
    // a normal Nostr client, not our own daemon.
    let extra: Vec<Tag> = Vec::new();
    let event = EventBuilder::private_msg(&keys, *recipient, body, extra)
        .await
        .map_err(|e| format!("nip17 build: {}", e))?;

    client
        .send_event(event)
        .await
        .map_err(|e| format!("send DM: {}", e))?;
    // Give the relay a moment to persist before we tear down the connection;
    // nostr-sdk's send_event is fire-and-forget at the wire level.
    tokio::time::sleep(Duration::from_millis(500)).await;
    client.disconnect().await.ok();
    Ok(())
}

// ──────────────────────── Phase 2: reserves + ledger ─────────────────────

async fn bootstrap_reserves(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    // Phase 2 talks to a running daemon over gift-wrapped admin requests —
    // the daemon holds the wallet lock, so we never instantiate a second
    // Node against this data_dir.

    let addr_file = config.data_dir.join("funding_address");
    let funding_addr = if addr_file.exists() {
        std::fs::read_to_string(&addr_file)?.trim().to_string()
    } else {
        String::from("(unknown — bootstrap init was not run)")
    };

    // Retry reserves_create until the daemon reports the wallet is funded.
    // The daemon validates balance internally; we use its "insufficient"
    // error as the cue to sleep and retry. On the first successful call we
    // know the UTXO has arrived and a reserves tx was broadcast.
    let mut waited = 0u64;
    let reserves_result = loop {
        match super::send_admin_daemon_request(&config, "reserves_create", serde_json::json!({}))
            .await
        {
            Ok(r) => break r,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("insufficient balance") {
                    if waited % 60 == 0 {
                        println!(
                            "bootstrap reserves: waiting for funding at {} ({}s elapsed)",
                            funding_addr, waited
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    waited += 15;
                    continue;
                }
                return Err(format!("reserves_create: {}", e).into());
            }
        }
    };

    if let Some(txid) = reserves_result.get("txid").and_then(|v| v.as_str()) {
        println!("bootstrap reserves: tx {}", txid);
    }
    if let Some(amt) = reserves_result.get("amount_sats").and_then(|v| v.as_u64()) {
        println!("  amount: {} sats", amt);
    }

    // Open a ledger against the newly-created reserves UTXO.
    let open_result =
        super::send_admin_daemon_request(&config, "ledger_open", serde_json::json!({})).await?;
    if let Some(lid) = open_result.get("ledger_id").and_then(|v| v.as_str()) {
        println!("bootstrap reserves: ledger opened {}", lid);
    }

    Ok(())
}

// ──────────────────────── Phase 3: quorum ────────────────────────────────

async fn bootstrap_quorum(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut quorum_size: usize = DEFAULT_QUORUM_SIZE;
    let mut config_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--quorum-size" if i + 1 < args.len() => {
                quorum_size = args[i + 1].parse()?;
                if !deposits_core::VALID_QUORUM_SIZES.contains(&quorum_size) {
                    return Err(format!(
                        "--quorum-size {} is not in the allowed set {:?} \
                         (Q is the cosigner count; operator is not counted)",
                        quorum_size,
                        deposits_core::VALID_QUORUM_SIZES,
                    )
                    .into());
                }
                i += 1;
            }
            _ => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
        }
        i += 1;
    }
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("bootstrap quorum: --relay required".into());
    }

    // Resolve our ledger_id without blocking the running daemon: create a
    // short-lived Node, read the ledger id, drop it. `get_primary_ledger`
    // only reads from disk-backed state that the daemon also holds, but BDK
    // wallet locking is fine for a read-only Node instance.
    let (ledger_id, our_pubkey_hex, quorum_already_active) = {
        let node = Node::new(config.clone()).await?;
        let (lid, ledger) = node
            .get_primary_ledger()
            .ok_or("bootstrap quorum: no ledger open (run `bootstrap reserves` first)")?;
        let pk = hex::encode(
            PublicKey::from_secret_key(
                &Secp256k1::new(),
                &derive_operator_secret(&config.seed, config.network)?,
            )
            .serialize(),
        );
        let active = ledger.state.quorum_state == deposits_core::types::QuorumState::Active;
        (lid, pk, active)
    };

    println!("bootstrap quorum: ledger={}...", &ledger_id[..16]);
    println!("bootstrap quorum: own pubkey={}...", &our_pubkey_hex[..16]);

    // Skip if quorum already formed. Authoritative signal is the
    // primary ledger's `quorum_state == Active` (set by the first
    // applied QuorumBegin); no separate marker file is needed.
    if quorum_already_active {
        eprintln!("bootstrap quorum: already active, skipping");
        return Ok(());
    }

    // Honor an operator-set manual-override marker. Drop a file named
    // `manual_override.marker` in the data dir (ad hoc, no daemon
    // interaction needed) to disable the auto-bootstrap loop while you
    // intervene by hand. Without this, an unattended bootstrap retry
    // can race with manual `quorum begin` invocations and produce
    // "input already spent" loops on stranded state.
    let override_marker = config.data_dir.join("manual_override.marker");
    if override_marker.exists() {
        eprintln!(
            "bootstrap quorum: manual override marker present at {} — skipping auto-bootstrap. \
             Remove the file to re-enable.",
            override_marker.display()
        );
        return Ok(());
    }

    // Sleep between rounds when something transient fails. Long enough to
    // not hammer the relay, short enough to converge within minutes when
    // peers do come up. Block time (~10 min) would be cheaper but less
    // responsive for the common "peer booted a minute ago" case.
    const RETRY_SLEEP_SECS: u64 = 300; // 5 min

    // Errors that won't resolve by retrying. When we see one of these,
    // bail the auto-bootstrap loop entirely — the operator must
    // intervene by hand. Returning Err propagates to the caller (often
    // entrypoint.sh), which logs and stops looping. Without this, the
    // process busy-loops forever on a stranded state.
    fn is_permanent_error(msg: &str) -> bool {
        msg.contains("bad-txns-inputs-missingorspent")
            || msg.contains("No existing reserves to rotate")
            || msg.contains("quorum_member_unstaged")
            || msg.contains("quorum_size_invalid")
            || msg.contains("quorum_expiry_exceeds_commitment")
            || msg.contains("Ledger not found")
    }

    // Q is the cosigner count and excludes the operator. Each peer we
    // need to recruit becomes one cosigner, so `need == quorum_size`
    // exactly (no off-by-one for "the operator slot").
    let need = quorum_size;
    let mut round = 0;
    loop {
        round += 1;
        println!();
        println!("bootstrap quorum: round {}", round);

        // --- Discovery ---
        let candidates = discover_candidate_peers(&config, &our_pubkey_hex).await?;
        println!("  discovery: {} candidate peer(s)", candidates.len());
        if candidates.len() < need {
            println!(
                "  need {}, have {} — sleeping {}s",
                need,
                candidates.len(),
                RETRY_SLEEP_SECS
            );
            tokio::time::sleep(Duration::from_secs(RETRY_SLEEP_SECS)).await;
            continue;
        }

        // --- Ping ranking ---
        let ranked = rank_peers_by_ping(&config, &candidates).await?;
        println!("  ping:      {} peer(s) responded", ranked.len());
        if ranked.len() < need {
            println!(
                "  need {} responders, have {} — sleeping {}s",
                need,
                ranked.len(),
                RETRY_SLEEP_SECS
            );
            tokio::time::sleep(Duration::from_secs(RETRY_SLEEP_SECS)).await;
            continue;
        }

        let selected: Vec<_> = ranked.into_iter().take(need).collect();
        println!("  selected {} peer(s):", selected.len());
        for (i, (pk, lid, rtt_ms)) in selected.iter().enumerate() {
            println!(
                "    {}. {}... (ledger {}...) rtt={}ms",
                i + 1,
                &pk[..16],
                &lid[..16],
                rtt_ms
            );
        }

        // --- Add members ---
        //
        // On any failure, we restart from discovery after a sleep rather
        // than retrying just the failed add — the peer set may have
        // shifted, and a different selection may succeed. Re-adding a
        // member who already landed in next_quorum_members is safe: the
        // state machine dedupes at apply() (ledger_state.rs).
        let mut add_ok = true;
        for (pk, member_ledger_id, _) in &selected {
            println!("  quorum_add: {}...", &pk[..16]);
            let params = serde_json::json!({
                "member_pubkey": pk,
                "member_ledger_id": member_ledger_id,
            });
            match send_daemon_request(&config, &ledger_id, "quorum_add", params).await {
                Ok(_) => println!("    added"),
                Err(e) => {
                    let msg = e.to_string();
                    println!("    FAILED: {}", msg);
                    if is_permanent_error(&msg) {
                        return Err(format!(
                            "bootstrap quorum: permanent error during quorum_add: {}. \
                             Manual intervention required; not retrying.",
                            msg
                        )
                        .into());
                    }
                    add_ok = false;
                    break;
                }
            }
        }
        if !add_ok {
            println!(
                "  quorum_add failed — sleeping {}s and restarting from discovery",
                RETRY_SLEEP_SECS
            );
            tokio::time::sleep(Duration::from_secs(RETRY_SLEEP_SECS)).await;
            continue;
        }

        // --- Seal ---
        println!("  quorum_begin");
        match send_daemon_request(&config, &ledger_id, "quorum_begin", serde_json::json!({})).await
        {
            Ok(_) => {
                println!("bootstrap quorum: active");
                break;
            }
            Err(e) => {
                let msg = e.to_string();
                if is_permanent_error(&msg) {
                    return Err(format!(
                        "bootstrap quorum: permanent error during quorum_begin: {}. \
                         Manual intervention required; not retrying. Drop a \
                         `manual_override.marker` file in the data dir to disable \
                         this auto-bootstrap on subsequent restarts.",
                        msg
                    )
                    .into());
                }
                println!(
                    "    FAILED: {} — sleeping {}s and retrying",
                    msg, RETRY_SLEEP_SECS
                );
                tokio::time::sleep(Duration::from_secs(RETRY_SLEEP_SECS)).await;
                continue;
            }
        }
    }

    Ok(())
}

/// Fetch ledger advertisements and return unique (operator_pubkey, ledger_id)
/// pairs for peers other than ourselves. When an operator advertises multiple
/// ledgers, we keep the first one we see — the quorum add only needs one
/// "member collateral ledger" per peer.
async fn discover_candidate_peers(
    config: &NodeConfig,
    our_pubkey_hex: &str,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let sk = derive_operator_secret(&config.seed, config.network)?;
    let transport = NostrTransportBuilder::new(sk)
        .relay(&config.relays[0])
        .build()
        .await?;

    let net_str = match config.network {
        Network::Bitcoin => "bitcoin",
        Network::Testnet => "testnet",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
        _ => "unknown",
    };
    let ads = transport.fetch_ledger_advertisements(net_str).await?;

    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for ad in ads {
        if ad.operator_pubkey == our_pubkey_hex {
            continue;
        }
        if seen.insert(ad.operator_pubkey.clone()) {
            out.push((ad.operator_pubkey, ad.ledger_id));
        }
    }
    Ok(out)
}

/// Ping each candidate by sending a Kind 20101 `health_status` request
/// addressed to the peer via `#p`. The operator's handler answers regardless
/// of ledger membership, so this measures pure request→response round-trip.
async fn rank_peers_by_ping(
    config: &NodeConfig,
    candidates: &[(String, String)],
) -> Result<Vec<(String, String, u64)>, Box<dyn std::error::Error>> {
    let sk = derive_operator_secret(&config.seed, config.network)?;
    let transport = NostrTransportBuilder::new(sk)
        .relay(&config.relays[0])
        .build()
        .await?;

    let mut results: Vec<(String, String, u64)> = Vec::new();
    for (peer_pk, peer_ledger) in candidates {
        let start = std::time::Instant::now();
        // Route against one of the peer's own ledgers so the request passes
        // their interested_ledgers filter. Handler dispatches by action, so
        // `#l` is just for routing.
        let req_id = match transport
            .send_agent_request_on_ledger(
                peer_pk,
                peer_ledger,
                "health_status",
                serde_json::json!({}),
            )
            .await
        {
            Ok(id) => id,
            Err(_) => continue,
        };
        match transport.wait_for_response(&req_id, 3_000).await {
            Ok(resp) if resp.success => {
                let rtt = start.elapsed().as_millis() as u64;
                results.push((peer_pk.clone(), peer_ledger.clone(), rtt));
            }
            _ => {
                // unresponsive within 3s — drop
            }
        }
    }
    results.sort_by_key(|(_, _, rtt)| *rtt);
    Ok(results)
}
