//! Recovery CLI commands
//!
//! Commands for dispute resolution and custody recovery.

use std::str::FromStr;
use std::sync::OnceLock;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::{hash160, sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1};

use deposits_core::messages::LedgerOperation;
use deposits_core::types::select_entropy_winner;
use deposits_core::{SignedLedgerUpdate, TlvDecode, TlvEncode};

use crate::nostr::{NostrTransportBuilder, KIND_LEDGER_DISPUTE, KIND_LEDGER_UPDATE};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bdk_esplora::esplora_client::Builder as EsploraBuilder;
use nostr_sdk::prelude::*;
use tokio::sync::Mutex;

use crate::node_cli::{derive_operator_secret, parse_config};

/// Cached nostr client for recovery commands
static RECOVERY_NOSTR_CLIENT: OnceLock<Mutex<Option<(String, Client)>>> = OnceLock::new();

/// Get or create a connected nostr client for the given relay URL
async fn get_or_create_client(relay_url: &str) -> Result<Client, Box<dyn std::error::Error>> {
    let mutex = RECOVERY_NOSTR_CLIENT.get_or_init(|| Mutex::new(None));
    let mut guard = mutex.lock().await;

    // Check if we have a cached client for this relay
    if let Some((cached_url, client)) = guard.as_ref() {
        if cached_url == relay_url {
            return Ok(client.clone());
        }
    }

    // Create new client
    let keys = Keys::generate();
    let client = Client::new(keys);
    client
        .add_relay(relay_url)
        .await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    // Cache it
    *guard = Some((relay_url.to_string(), client.clone()));

    Ok(client)
}

/// Handle recovery subcommands for non-conforming ledgers
pub async fn recovery_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node recovery <dispute|rebuild|arm|claim|continue|spend|status> [args...]");
        eprintln!();
        eprintln!("Subcommands (Dispute Protocol):");
        eprintln!(
            "  dispute <ledger_id> [--reason <text>]  Open dispute: publish DisputeEnter operation"
        );
        eprintln!("  rebuild <ledger_id>                    Rebuild quorum: add members + get attestations");
        eprintln!(
            "  arm <ledger_id>                        Pre-commit: publish DisputeArmed operation"
        );
        eprintln!(
            "    [--target-reserves <addr>]           Bitcoin address for winnings (defaults to operator P2WPKH)"
        );
        eprintln!(
            "    [--replacement-collateral-outpoint <txid:vout>"
        );
        eprintln!(
            "     --replacement-collateral-amount <sats>]"
        );
        eprintln!(
            "                                         Pledge a wallet UTXO as replacement collateral"
        );
        eprintln!(
            "                                         (must be at operator-key P2WPKH; see DEP-03)"
        );
        eprintln!("  claim <ledger_id>                      After entropy: DisputeAcquire (win) or DisputeYield (lose)");
        eprintln!("  continue <ledger_id> [--count N]       Winner: add operations to continue the ledger");
        eprintln!("  spend <ledger_id>                      Execute on-chain spend (winner only)");
        eprintln!("  status <ledger_id>                     Show recovery status and candidates");
        eprintln!();
        eprintln!("Lottery Protocol (on-chain winner selection):");
        eprintln!("  confiscate <ledger_id>                 Build and broadcast confiscation TX to lottery");
        eprintln!("  reveal <ledger_id>                     Reveal lottery preimage via Nostr");
        eprintln!("  lottery-claim <ledger_id>              Claim lottery output if winner");
        eprintln!();
        eprintln!("Stranded-state recovery:");
        eprintln!("  reconstruct-taproot [<ledger_id>] [--quorum-expiry <block>]");
        eprintln!("                                         Rebuild taproot_reserves.json from on-chain");
        eprintln!("                                         state when a previous quorum_begin rotated");
        eprintln!("                                         the legacy P2WSH UTXO but failed to persist");
        eprintln!("                                         the new entry locally. Run with the daemon");
        eprintln!("                                         stopped (or behind manual_override.marker).");
        eprintln!();
        eprintln!("Recovery flow (entropy-based):");
        eprintln!("  1. dispute - Detect violation, publish DisputeEnter (quorum disbanded)");
        eprintln!("  2. rebuild - Add new quorum members, collect attestations");
        eprintln!("  3. arm     - Publish DisputeArmed (locks in for entropy selection)");
        eprintln!("  4. (wait)  - Wait for entropy block to be mined");
        eprintln!("  5. claim   - Winner: DisputeAcquire, Losers: DisputeYield");
        eprintln!("  6. continue- Winner adds operations to resume normal ledger operation");
        eprintln!("  7. spend   - Winner broadcasts on-chain spend to claim reserves");
        eprintln!();
        eprintln!("Recovery flow (lottery-based):");
        eprintln!("  1-3. Same as above (dispute, rebuild, arm with commitment_hash)");
        eprintln!("  4. confiscate - Quorum signs TX spending reserves to lottery output");
        eprintln!("  5. reveal     - All disputants reveal their preimages");
        eprintln!("  6. lottery-claim - Winner (determined by preimage sizes) claims lottery");
        eprintln!("  7. continue   - Winner adds operations to resume normal operation");
        eprintln!();
        eprintln!(
            "State machine: NORMAL -> DISPUTED -> ARMED -> NORMAL (winner) / TOMBSTONED (losers)"
        );
        return Ok(());
    }

    match args[0].as_str() {
        "embed-hash" => recovery_embed_hash(&args[1..]).await,
        "publish-fraud-broadcast" => recovery_publish_fraud_broadcast(&args[1..]).await,
        "reconstruct-taproot" => recovery_reconstruct_taproot(&args[1..]).await,
        // New dispute protocol commands
        "dispute" => recovery_dispute(&args[1..]).await,
        "rebuild" => recovery_rebuild(&args[1..]).await,
        "arm" => recovery_arm(&args[1..]).await,
        "claim" => recovery_claim_new(&args[1..]).await,
        "continue" => recovery_continue(&args[1..]).await,
        "spend" => recovery_spend(&args[1..]).await,
        "status" => recovery_status(&args[1..]).await,
        // Lottery protocol commands
        "confiscate" => recovery_confiscate(&args[1..]).await,
        "reveal" => recovery_reveal(&args[1..]).await,
        "lottery-claim" => recovery_lottery_claim(&args[1..]).await,
        "rotate-to-quorum" => recovery_rotate_to_quorum(&args[1..]).await,
        // Legacy commands (for backward compatibility)
        "start" => recovery_start(&args[1..]).await,
        "agree" => recovery_agree(&args[1..]).await,
        "prepare" => recovery_prepare(&args[1..]).await,
        "release" => recovery_release(&args[1..]).await,
        cmd => {
            eprintln!("Unknown recovery subcommand: {}", cmd);
            eprintln!(
                "Usage: deposits-node recovery <dispute|rebuild|arm|claim|spend|status> [args...]"
            );
            Ok(())
        }
    }
}

/// Reconstruct `taproot_reserves.json` from on-chain state when a previous
/// `quorum begin` rotated the legacy P2WSH UTXO into a taproot vault but
/// failed to persist the new entry locally — typically a daemon crash
/// between broadcast and the (pre-fix) wallet state mutation.
///
/// The funds aren't lost; they're sitting in a Q=N taproot vault. This
/// command re-derives the local view from the chain so `quorum begin`
/// can hit the resume path and complete the bootstrap.
///
/// Operates entirely on files + Esplora HTTP — does NOT instantiate a
/// `Node` (which would lock the wallet against a running daemon). The
/// operator should drop a `manual_override.marker` and stop the daemon
/// before running this, then restart and retry `quorum begin`.
pub async fn recovery_reconstruct_taproot(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use serde::{Deserialize, Serialize};

    let mut ledger_id_arg: Option<String> = None;
    let mut quorum_expiry_arg: Option<u32> = None;
    let mut config_args = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--quorum-expiry" if i + 1 < args.len() => {
                quorum_expiry_arg = Some(args[i + 1].parse().map_err(|_| {
                    format!("Invalid --quorum-expiry: {}", args[i + 1])
                })?);
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id_arg.is_none() {
                    ledger_id_arg = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    let wallet_dir = config.data_dir.join("wallet");
    let reserves_path = wallet_dir.join("reserves.json");
    let taproot_path = wallet_dir.join("taproot_reserves.json");
    let ledgers_dir = wallet_dir.join("ledgers");

    if !reserves_path.exists() {
        return Err(format!(
            "{} does not exist — nothing to reconstruct",
            reserves_path.display()
        )
        .into());
    }

    // Wallet's serde shapes — kept private in wallet.rs, redefined here.
    // Drift between the two is caught at daemon load time when it parses
    // the file we write.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct LegacyEntry {
        outpoint_txid: String,
        outpoint_vout: u32,
        amount: u64,
        operator: String,
        partners: Vec<String>,
        threshold: usize,
        timeout_height: u32,
        redeem_script_hex: String,
        confirmed: bool,
    }
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TaprootEntry {
        outpoint_txid: String,
        outpoint_vout: u32,
        amount: u64,
        operator: String,
        quorum_members: Vec<String>,
        quorum_expiry: u32,
        ledger_hash: String,
        address: String,
        confirmed: bool,
    }

    let legacy: Vec<LegacyEntry> = {
        let raw = std::fs::read_to_string(&reserves_path)?;
        serde_json::from_str(&raw)?
    };
    if legacy.is_empty() {
        eprintln!("reserves.json is empty — nothing to reconstruct");
        return Ok(());
    }

    // Resolve ledger_id: explicit arg, or auto-detect the unique ledger
    // where this node holds the Operator role (partner replicas of peer
    // ledgers also live in this dir but aren't candidates — only our own
    // legacy reserves UTXO would have been rotated).
    let ledger_id = match ledger_id_arg {
        Some(id) => id,
        None => {
            let mut operator_ledgers: Vec<String> = Vec::new();
            for e in std::fs::read_dir(&ledgers_dir)?.filter_map(|e| e.ok()) {
                if e.path().extension().map_or(true, |x| x != "jsonl") {
                    continue;
                }
                let raw = match std::fs::read_to_string(e.path()) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                // Role line is the first record; check it cheaply.
                let is_operator = raw.lines().next().map_or(false, |l| {
                    serde_json::from_str::<serde_json::Value>(l)
                        .ok()
                        .and_then(|v| {
                            (v.get("type")?.as_str()? == "Role"
                                && v.get("role")?.as_str()? == "Operator")
                                .then_some(())
                        })
                        .is_some()
                });
                if is_operator {
                    operator_ledgers.push(
                        e.path()
                            .file_stem()
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
            match operator_ledgers.len() {
                0 => {
                    return Err(format!(
                        "No ledger with Operator role found in {}. \
                         Has `ledger open` ever succeeded on this node?",
                        ledgers_dir.display()
                    )
                    .into());
                }
                1 => operator_ledgers.into_iter().next().unwrap(),
                n => {
                    return Err(format!(
                        "Found {} operator-role ledgers in {}; specify one as \
                         a positional arg.",
                        n,
                        ledgers_dir.display()
                    )
                    .into());
                }
            }
        }
    };

    // Read the ledger's latest State line.
    let ledger_jsonl = ledgers_dir.join(format!("{}.jsonl", ledger_id));
    let raw = std::fs::read_to_string(&ledger_jsonl)?;
    let mut latest_state: Option<serde_json::Value> = None;
    for line in raw.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("type").and_then(|x| x.as_str()) == Some("State") {
            latest_state = Some(v);
        }
    }
    let state = latest_state.ok_or_else(|| {
        format!(
            "no State line found in {} — ledger file is malformed",
            ledger_jsonl.display()
        )
    })?;

    let operator_key_bytes: Vec<u8> = serde_json::from_value(state["operator_key"].clone())?;
    let operator_hex = hex::encode(&operator_key_bytes);
    let chain_tip_bytes: Vec<u8> = serde_json::from_value(state["chain_tip_hash"].clone())?;
    let ledger_hash_hex = hex::encode(&chain_tip_bytes);
    let next_quorum_members: Vec<serde_json::Value> =
        serde_json::from_value(state["next_quorum_members"].clone()).unwrap_or_default();
    let active_quorum_members: Vec<serde_json::Value> =
        serde_json::from_value(state["quorum_members"].clone()).unwrap_or_default();
    let members_source = if !next_quorum_members.is_empty() {
        next_quorum_members
    } else {
        active_quorum_members
    };
    let member_pks: Vec<String> = members_source
        .iter()
        .filter_map(|m| {
            let pk: Option<Vec<u8>> = m.get("pubkey").and_then(|v| serde_json::from_value(v.clone()).ok());
            pk.map(|b| hex::encode(b))
        })
        .collect();
    if member_pks.is_empty() {
        return Err(format!(
            "ledger {} has no quorum members (next_quorum_members and quorum_members both empty)",
            ledger_id
        )
        .into());
    }

    // Inspect each legacy entry against the chain.
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let esplora = config.electrum_url.trim_end_matches('/').to_string();
    let mut new_taproot_entries: Vec<TaprootEntry> = Vec::new();
    let mut keep_legacy: Vec<LegacyEntry> = Vec::new();

    for entry in legacy {
        let outspend_url =
            format!("{}/tx/{}/outspend/{}", esplora, entry.outpoint_txid, entry.outpoint_vout);
        let outspend: serde_json::Value = match http.get(&outspend_url).send() {
            Ok(r) if r.status().is_success() => r.json()?,
            Ok(r) => {
                eprintln!(
                    "  outspend lookup failed ({}): {}",
                    r.status(),
                    outspend_url
                );
                keep_legacy.push(entry);
                continue;
            }
            Err(e) => {
                eprintln!("  outspend HTTP error: {}", e);
                keep_legacy.push(entry);
                continue;
            }
        };
        if !outspend.get("spent").and_then(|v| v.as_bool()).unwrap_or(false) {
            println!(
                "  {}:{} not spent on-chain — leaving in reserves.json",
                entry.outpoint_txid, entry.outpoint_vout
            );
            keep_legacy.push(entry);
            continue;
        }
        let spending_txid = outspend["txid"]
            .as_str()
            .ok_or("outspend missing txid")?
            .to_string();
        let confirm_block =
            outspend["status"]["block_height"].as_u64().unwrap_or(0) as u32;

        // Fetch the spending tx to find the P2TR output.
        let tx_url = format!("{}/tx/{}", esplora, spending_txid);
        let tx: serde_json::Value = http.get(&tx_url).send()?.json()?;
        let outputs = tx["vout"]
            .as_array()
            .ok_or("spending tx has no vout array")?;
        let (out_idx, out) = outputs
            .iter()
            .enumerate()
            .find(|(_, o)| o["scriptpubkey_type"].as_str() == Some("v1_p2tr"))
            .ok_or("spending tx has no P2TR output (not a rotation pattern)")?;

        let address = out["scriptpubkey_address"]
            .as_str()
            .ok_or("output missing address")?
            .to_string();
        let amount = out["value"].as_u64().ok_or("output missing value")?;

        // Default expiry: rotate_reserves_to_quorum used current_block + 1000;
        // current_block was approximately confirm_block - 3 (typical mempool age).
        let derived_expiry = confirm_block.saturating_sub(3) + 1000;
        let quorum_expiry = quorum_expiry_arg.unwrap_or(derived_expiry);

        let new_entry = TaprootEntry {
            outpoint_txid: spending_txid.clone(),
            outpoint_vout: out_idx as u32,
            amount,
            operator: operator_hex.clone(),
            quorum_members: member_pks.clone(),
            quorum_expiry,
            ledger_hash: ledger_hash_hex.clone(),
            address: address.clone(),
            confirmed: true,
        };

        println!(
            "  {}:{} spent by {} → reconstructing as taproot {}:{}",
            entry.outpoint_txid, entry.outpoint_vout, &spending_txid[..16], &spending_txid[..16], out_idx
        );
        println!("    address:   {}", address);
        println!("    amount:    {} sats", amount);
        println!("    Q members: {}", member_pks.len());
        println!("    expiry:    {} (derived from confirm block {})", quorum_expiry, confirm_block);
        println!("    ledger:    {}...", &ledger_hash_hex[..16]);

        new_taproot_entries.push(new_entry);
    }

    if new_taproot_entries.is_empty() {
        eprintln!("nothing to reconstruct: all legacy entries are still unspent on-chain");
        return Ok(());
    }

    // Merge with existing taproot entries (don't overwrite).
    let mut existing_taproot: Vec<TaprootEntry> = if taproot_path.exists() {
        let raw = std::fs::read_to_string(&taproot_path)?;
        if raw.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(&raw)?
        }
    } else {
        Vec::new()
    };
    existing_taproot.extend(new_taproot_entries.iter().cloned());

    std::fs::write(&taproot_path, serde_json::to_string_pretty(&existing_taproot)?)?;
    std::fs::write(&reserves_path, serde_json::to_string_pretty(&keep_legacy)?)?;

    println!();
    println!(
        "Wrote {} reconstructed taproot entries to {}.",
        new_taproot_entries.len(),
        taproot_path.display()
    );
    println!(
        "Updated {} ({} legacy entries remaining).",
        reserves_path.display(),
        keep_legacy.len()
    );
    println!();
    println!("Next steps:");
    println!("  1. Restart the daemon so it reloads wallet state from disk");
    println!("  2. Run `quorum begin` — it will hit the resume path and complete the bootstrap");
    println!();
    println!(
        "If the cosign step rejects the reconstructed entry, the derived expiry ({}) may be \
         wrong. Re-run with --quorum-expiry <correct-block> to override.",
        new_taproot_entries[0].quorum_expiry
    );

    Ok(())
}

/// Start a recovery process for a non-conforming ledger
/// Validates the ledger from Nostr and publishes a dispute if invalid.
pub async fn recovery_start(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reason" | "-r" => {
                i += 1;
                if i < args.len() {
                    reason = Some(args[i].clone());
                }
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let reason = reason.unwrap_or_else(|| "Non-conforming ledger detected".to_string());

    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    // Build keypair from seed
    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    println!(
        "Starting recovery for ledger: {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );
    println!("  Reason: {}", reason);
    println!();

    // Fetch and validate ledger from Nostr
    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }
    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    updates.dedup_by(|a, b| {
        a.sequence_number == b.sequence_number
            && a.operator_id == b.operator_id
            && a.content_hash == b.content_hash
    });

    println!("  Found {} updates", updates.len());

    // Validate the hash chain to find the violation
    let mut last_valid_hash = [0u8; 32];
    let mut last_valid_sequence: i64 = -1;
    let mut violation_details = String::new();
    let mut violation_sequence: Option<u64> = None;

    for update in &updates {
        let expected_seq = (last_valid_sequence + 1) as u64;
        if update.sequence_number != expected_seq && last_valid_sequence >= 0 {
            violation_details = format!(
                "Sequence gap at seq {}: expected {}, got {}",
                update.sequence_number, expected_seq, update.sequence_number
            );
            violation_sequence = Some(update.sequence_number);
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            violation_details = format!(
                "Hash chain broken at seq {}: expected {}..., got {}...",
                update.sequence_number,
                hex::encode(&expected_prev[..4]),
                hex::encode(&update.previous_hash[..4])
            );
            violation_sequence = Some(update.sequence_number);
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.content_hash {
            violation_details = format!(
                "Invalid hash at seq {}: computed {}..., stored {}...",
                update.sequence_number,
                hex::encode(&computed_hash[..4]),
                hex::encode(&update.content_hash[..4])
            );
            violation_sequence = Some(update.sequence_number);
            break;
        }

        // Chain links via chain_hash() (folds in operator_signature),
        // not content_hash. See `commit_staged` in deposits-core/src/ledger.rs
        // which sets `state.chain_tip_hash = update.chain_hash()`.
        last_valid_hash = update.chain_hash();
        last_valid_sequence = update.sequence_number as i64;
    }

    if violation_sequence.is_none() {
        println!();
        println!("Ledger appears conforming (no violation found).");
        println!("Cannot start recovery for a conforming ledger.");
        return Ok(());
    }

    let last_valid_sequence_u64 = if last_valid_sequence >= 0 {
        last_valid_sequence as u64
    } else {
        0
    };

    println!();
    println!("Violation detected!");
    println!("  {}", violation_details);
    println!("  Last valid sequence: {}", last_valid_sequence_u64);
    println!(
        "  Last valid hash: {}...",
        hex::encode(&last_valid_hash[..8])
    );
    println!();

    // Publish dispute to Nostr
    println!("Publishing dispute to Nostr...");
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    // publish_dispute takes &dyn Signer post phase-3; wrap the
    // CLI-derived secret in a LocalSigner.
    let dispute_signer = deposits_signer_api::LocalSigner::new(secret_key);
    let dispute_id = transport
        .publish_dispute(
            &ledger_id,
            &reason,
            &violation_details,
            last_valid_hash,
            last_valid_sequence_u64,
            violation_sequence,
            &dispute_signer,
        )
        .await?;

    transport.disconnect().await;

    println!("  Dispute published: {}", &dispute_id[..16]);
    println!();
    println!("Next steps:");
    println!(
        "  1. Other quorum members run: deposits-node recovery agree {}",
        &ledger_id[..16]
    );
    println!(
        "  2. Once enough agree, run: deposits-node recovery complete {}",
        &ledger_id[..16]
    );

    Ok(())
}

/// Agree to a recovery (respond to a dispute)
/// Independently validates the ledger and publishes agreement if violation confirmed.
pub async fn recovery_agree(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();

    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    // Build keypair from seed
    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!(
        "Checking for disputes on ledger: {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );
    println!("  Our key: {}...", &our_pubkey.to_string()[..16]);
    println!();

    // Fetch disputes for this ledger
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let disputes = transport.fetch_disputes(&ledger_id).await?;

    if disputes.is_empty() {
        println!("No disputes found for this ledger.");
        println!("Run 'recovery start' to initiate a dispute first.");
        transport.disconnect().await;
        return Ok(());
    }

    // Use the most recent dispute
    let dispute = disputes.last().unwrap();
    println!("Found dispute:");
    println!(
        "  From: {}...",
        &dispute.disputer_pubkey[..16.min(dispute.disputer_pubkey.len())]
    );
    println!("  Reason: {}", dispute.reason);
    println!("  Details: {}", dispute.details);
    println!("  Last valid seq: {}", dispute.last_valid_sequence);
    println!("  Event: {}...", &dispute.event_id[..16]);
    println!();

    // Independently validate the ledger
    println!("Independently validating ledger...");

    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }
    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    updates.dedup_by(|a, b| {
        a.sequence_number == b.sequence_number
            && a.operator_id == b.operator_id
            && a.content_hash == b.content_hash
    });

    println!("  Found {} updates", updates.len());

    // Validate the hash chain
    let mut last_valid_hash = [0u8; 32];
    let mut last_valid_sequence: i64 = -1;
    let mut found_violation = false;

    for update in &updates {
        let expected_seq = (last_valid_sequence + 1) as u64;
        if update.sequence_number != expected_seq && last_valid_sequence >= 0 {
            found_violation = true;
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            found_violation = true;
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.content_hash {
            found_violation = true;
            break;
        }

        last_valid_hash = update.chain_hash();
        last_valid_sequence = update.sequence_number as i64;
    }

    let our_last_valid = if last_valid_sequence >= 0 {
        last_valid_sequence as u64
    } else {
        0
    };

    if !found_violation {
        println!();
        println!("We did NOT find a violation. Ledger appears conforming.");
        println!("Not publishing agreement.");
        transport.disconnect().await;
        return Ok(());
    }

    println!("  Violation confirmed!");
    println!("  Our last valid sequence: {}", our_last_valid);
    println!(
        "  Our last valid hash: {}...",
        hex::encode(&last_valid_hash[..8])
    );
    println!();

    // Publish agreement
    println!("Publishing recovery agreement...");

    let agreement_id = transport
        .publish_recovery_agreement(
            &ledger_id,
            &dispute.event_id,
            our_last_valid,
            last_valid_hash,
            &keypair,
        )
        .await?;

    transport.disconnect().await;

    println!("  Agreement published: {}", &agreement_id[..16]);
    println!();
    println!("Next step:");
    println!(
        "  Once enough quorum members agree, run: deposits-node recovery complete {}",
        &ledger_id[..16]
    );

    Ok(())
}

/// Show recovery status for a ledger
pub async fn recovery_status(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?;

    println!("Recovery status for: {}", ledger_id);
    println!();
    println!("Note: Recovery state is currently ephemeral (in-memory).");
    println!("In a production implementation, recovery state would be persisted.");
    println!();
    println!("To participate in recovery:");
    println!(
        "  1. Validate the ledger: deposits-node nostr validate {}",
        ledger_id
    );
    println!("  2. If invalid, publish dispute: deposits-node nostr dispute publish {} <reason> <details>", ledger_id);
    println!(
        "  3. Submit vote: deposits-node recovery vote {} non-conforming",
        ledger_id
    );
    println!(
        "  4. Claim if eligible: deposits-node recovery claim {}",
        ledger_id
    );

    Ok(())
}

/// Prepare as a candidate for custody acquisition.
pub async fn recovery_prepare(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            arg if arg.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Ledger ID required")?;
    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first().ok_or("No relay configured")?.clone();

    println!("Preparing as custody acquisition candidate...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Relay: {}", relay_url);
    println!();

    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(config.network, &config.seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;
    let operator_path = DerivationPath::from_str("m/86'/0'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;
    let operator_xpriv = xpriv
        .derive_priv(&secp, &operator_path)
        .map_err(|e| format!("Failed to derive operator key: {}", e))?;
    let secret_key = operator_xpriv.private_key;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!(
        "Our pubkey (candidate): {}...",
        &our_pubkey.to_string()[..16]
    );

    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    updates.dedup_by(|a, b| {
        a.sequence_number == b.sequence_number
            && a.operator_id == b.operator_id
            && a.content_hash == b.content_hash
    });

    println!("  Found {} updates", updates.len());

    if updates.is_empty() {
        return Err("No ledger updates found".into());
    }

    let mut last_valid_sequence = 0u64;
    let mut last_valid_hash = [0u8; 32];
    let mut violation_details = String::new();
    let mut original_operator = None;

    for (idx, update) in updates.iter().enumerate() {
        if idx == 0 {
            original_operator = Some(update.operator_id);
        }

        if idx > 0 {
            let prev = &updates[idx - 1];
            if update.previous_hash != prev.content_hash {
                violation_details = format!("Hash chain broken at seq {}", update.sequence_number);
                break;
            }
        }

        last_valid_sequence = update.sequence_number;
        last_valid_hash = update.chain_hash();
    }

    if violation_details.is_empty() {
        let dispute_filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
            .custom_tag(crate::nostr::TAG_LEDGER_ID, [ledger_id.as_str()])
            .limit(10);

        let disputes = client
            .fetch_events(vec![dispute_filter], None)
            .await
            .map_err(|e| format!("Failed to fetch disputes: {}", e))?;

        if disputes.is_empty() {
            return Err(
                "No violation found and no dispute published. Run 'recovery start' first.".into(),
            );
        }

        violation_details = "Dispute published - preparing candidate branch".to_string();
    }

    println!("  Last valid sequence: {}", last_valid_sequence);
    println!("  Violation: {}", violation_details);

    let original_operator = original_operator.ok_or("Could not determine original operator")?;
    println!(
        "  Original operator: {}...",
        &original_operator.to_string()[..16]
    );

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora
        .get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let initiation_block = current_block_height;
    let entropy_block_height = initiation_block + 6;
    let entropy_block_hash = [0u8; 32];

    println!("  Initiation block: {}", initiation_block);
    println!("  Entropy block (expected): {}", entropy_block_height);

    let custody_dispute = LedgerOperation::DisputeEnter {
        last_valid_sequence,
        reason: violation_details.clone(),
    };

    let message_bytes = custody_dispute.tlv_encode();

    let sequence = last_valid_sequence + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&last_valid_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(last_valid_hash),
        sequence,
        hex::encode(new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(&Message::from_digest(*msg_hash.as_ref()), &keypair);
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded =
            hex::decode(&ledger_id).map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded
            .try_into()
            .map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: last_valid_hash,
        content_hash: new_hash,
        block_height: current_block_height,
        block_hash: entropy_block_hash,
    };

    println!();
    println!("Publishing DisputeEnter to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport
        .broadcast_ledger_update(&signed_update)
        .await?;

    println!();
    println!("DisputeEnter published successfully!");
    println!("  Disputer: {}...", &our_pubkey.to_string()[..16]);
    println!(
        "  Sequence: {} (forked from {})",
        sequence, last_valid_sequence
    );
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!("  Reason: {}", violation_details);
    println!();
    println!("Next steps (dispute protocol):");
    println!("  1. Rebuild quorum: recovery rebuild <ledger_id>");
    println!("  2. Arm for entropy: recovery arm <ledger_id>");
    println!("  3. Wait for entropy block (armed_block + 6)");
    println!("  4. Claim custody: recovery claim <ledger_id>");
    println!("  5. On-chain spend: recovery spend <ledger_id>");

    Ok(())
}

/// Execute the on-chain spend to transfer reserves to the selected candidate.
/// This is the final step after all participants have revealed their preimages.
pub async fn recovery_spend(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    recovery_lottery_claim(args).await
}

/// Publish DisputeYield to close a candidate branch after not being selected.
pub async fn recovery_release(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            arg if arg.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Ledger ID required")?;
    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first().ok_or("No relay configured")?.clone();

    println!("Publishing DisputeYield (closing candidate branch)...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Relay: {}", relay_url);
    println!();

    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(config.network, &config.seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;
    let operator_path = DerivationPath::from_str("m/86'/0'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;
    let operator_xpriv = xpriv
        .derive_priv(&secp, &operator_path)
        .map_err(|e| format!("Failed to derive operator key: {}", e))?;
    let secret_key = operator_xpriv.private_key;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Our pubkey: {}...", &our_pubkey.to_string()[..16]);

    println!("Fetching our DisputeArmed branch...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    let mut our_armed: Option<SignedLedgerUpdate> = None;
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if matches!(op, LedgerOperation::DisputeArmed { .. }) {
                            our_armed = Some(update);
                            break;
                        }
                    }
                }
            }
        }
    }

    let our_armed =
        our_armed.ok_or("Could not find our DisputeArmed. Did you run 'recovery arm' first?")?;

    println!(
        "  Found our DisputeArmed at sequence {}",
        our_armed.sequence_number
    );

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora
        .get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let custody_release = LedgerOperation::DisputeYield;
    let message_bytes = custody_release.tlv_encode();

    let sequence = our_armed.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_armed.content_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_armed.content_hash),
        sequence,
        hex::encode(new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(&Message::from_digest(*msg_hash.as_ref()), &keypair);
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded =
            hex::decode(&ledger_id).map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded
            .try_into()
            .map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_armed.content_hash,
        content_hash: new_hash,
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!();
    println!("Publishing DisputeYield to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport
        .broadcast_ledger_update(&signed_update)
        .await?;

    println!();
    println!("DisputeYield published successfully!");
    println!("  Sequence: {}", sequence);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!();
    println!("Your candidate branch is now closed.");
    println!("Your quorum members are released from attestation obligations.");

    Ok(())
}

// =============================================================================
// NEW DISPUTE PROTOCOL COMMANDS
// =============================================================================

/// Open a custody dispute by publishing a DisputeEnter ledger operation.
pub async fn recovery_dispute(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reason" | "-r" => {
                i += 1;
                if i < args.len() {
                    reason = Some(args[i].clone());
                }
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let reason = reason.unwrap_or_else(|| "Non-conforming ledger detected".to_string());

    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!(
        "Opening custody dispute for ledger: {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );
    println!("  Reason: {}", reason);
    println!("  Our pubkey: {}", our_pubkey);
    println!();

    // Fetch ledger from Nostr
    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    // Decode all updates
    let mut all_updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                all_updates.push(update);
            }
        }
    }

    println!("  Found {} total updates", all_updates.len());

    // Find the original operator
    let original_operator = all_updates
        .iter()
        .find(|u| u.sequence_number == 0)
        .map(|u| u.operator_id)
        .ok_or("No LedgerOpen found (seq 0)")?;

    println!(
        "  Original operator: {}...",
        &original_operator.to_string()[..16]
    );

    // Filter to only the original operator's updates
    let mut updates: Vec<&SignedLedgerUpdate> = all_updates
        .iter()
        .filter(|u| u.operator_id == original_operator)
        .collect();
    updates.sort_by_key(|u| u.sequence_number);
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number);

    println!("  Original operator's updates: {}", updates.len());

    // Validate the hash chain to find the last valid point
    let mut last_valid_hash = [0u8; 32];
    let mut last_valid_sequence: i64 = -1;
    let mut violation_details = String::new();
    let mut invalid_update_hash: Option<[u8; 32]> = None;

    for update in &updates {
        let expected_seq = (last_valid_sequence + 1) as u64;
        if update.sequence_number != expected_seq && last_valid_sequence >= 0 {
            violation_details = format!(
                "Sequence gap: expected {}, got {}",
                expected_seq, update.sequence_number
            );
            invalid_update_hash = Some(update.content_hash);
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            violation_details = format!(
                "Hash chain broken at seq {}: expected {}..., got {}...",
                update.sequence_number,
                hex::encode(&expected_prev[..4]),
                hex::encode(&update.previous_hash[..4])
            );
            invalid_update_hash = Some(update.content_hash);
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.content_hash {
            violation_details = format!(
                "Invalid hash at seq {}: computed {}..., stored {}...",
                update.sequence_number,
                hex::encode(&computed_hash[..4]),
                hex::encode(&update.content_hash[..4])
            );
            invalid_update_hash = Some(update.content_hash);
            break;
        }

        last_valid_hash = update.chain_hash();
        last_valid_sequence = update.sequence_number as i64;
    }

    let last_valid_sequence_u64 = if last_valid_sequence >= 0 {
        last_valid_sequence as u64
    } else {
        0
    };

    if violation_details.is_empty() {
        println!();
        println!("Ledger appears conforming (no violation found).");
        println!("Cannot open dispute for a conforming ledger.");
        return Ok(());
    }

    println!();
    println!("Violation detected!");
    println!("  {}", violation_details);
    println!("  Last valid sequence: {}", last_valid_sequence_u64);
    println!(
        "  Last valid hash: {}...",
        hex::encode(&last_valid_hash[..8])
    );

    // Create DisputeEnter operation
    let dispute_reason = if let Some(hash) = invalid_update_hash {
        hex::encode(hash)
    } else {
        violation_details.clone()
    };
    let custody_dispute = LedgerOperation::DisputeEnter {
        last_valid_sequence: last_valid_sequence_u64,
        reason: dispute_reason,
    };

    let message_bytes = custody_dispute.tlv_encode();

    let sequence = last_valid_sequence_u64 + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&last_valid_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora
        .get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(last_valid_hash),
        sequence,
        hex::encode(new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(&Message::from_digest(*msg_hash.as_ref()), &keypair);
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded =
            hex::decode(&ledger_id).map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded
            .try_into()
            .map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: last_valid_hash,
        content_hash: new_hash,
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!();
    println!("Publishing DisputeEnter to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport
        .broadcast_ledger_update(&signed_update)
        .await?;

    println!();
    println!("DisputeEnter published successfully!");
    println!("  Dispute opener: {}...", &our_pubkey.to_string()[..16]);
    println!(
        "  Sequence: {} (forked from {})",
        sequence, last_valid_sequence_u64
    );
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!();
    println!("Ledger is now in DISPUTED state. Quorum has been disbanded.");
    println!();
    println!("Next steps:");
    println!("  1. Rebuild quorum: recovery rebuild {}", &ledger_id[..16]);
    println!("  2. Collect attestations from new quorum members");
    println!("  3. Pre-commit: recovery arm {}", &ledger_id[..16]);

    Ok(())
}

/// Rebuild the quorum during a dispute.
pub async fn recovery_rebuild(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!(
            "Usage: deposits-node recovery rebuild <ledger_id> <quorum-add|status> [args...]"
        );
        eprintln!();
        eprintln!("Subcommands:");
        eprintln!("  quorum-add <member_pubkey>     Add a quorum member to your dispute branch");
        eprintln!("  status                         Show current quorum state");
        return Ok(());
    }

    let ledger_id = args[0].trim().to_string();

    if args.len() < 2 {
        eprintln!("Missing subcommand. Use: quorum-add or status");
        return Ok(());
    }

    match args[1].as_str() {
        "quorum-add" => recovery_rebuild_quorum_add(&ledger_id, &args[2..]).await,
        "status" => recovery_rebuild_status(&ledger_id, &args[2..]).await,
        cmd => {
            eprintln!("Unknown rebuild subcommand: {}", cmd);
            eprintln!("Use: quorum-add or status");
            Ok(())
        }
    }
}

/// Add a quorum member to our dispute branch.
/// Usage: recovery rebuild <ledger_id> quorum-add <member_pubkey> <member_ledger_id>
pub async fn recovery_rebuild_quorum_add(
    ledger_id: &str,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut member_pubkey_str: Option<String> = None;
    let mut member_ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    for (i, arg) in args.iter().enumerate() {
        if arg.starts_with("--") {
            config_args.push(arg.clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
            }
        } else if member_pubkey_str.is_none() {
            member_pubkey_str = Some(arg.clone());
        } else if member_ledger_id.is_none() {
            member_ledger_id = Some(arg.clone());
        }
    }

    let member_pubkey_str = member_pubkey_str.ok_or("Missing member_pubkey")?;
    let member_ledger_id = member_ledger_id.ok_or("Missing member_ledger_id (64-char hex hash)")?;
    let member_pubkey = PublicKey::from_str(&member_pubkey_str)
        .map_err(|e| format!("Invalid member pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Adding quorum member to dispute branch...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!(
        "  Member: {}...",
        &member_pubkey_str[..16.min(member_pubkey_str.len())]
    );

    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id)],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    let mut our_updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    our_updates.push(update);
                }
            }
        }
    }

    if our_updates.is_empty() {
        return Err("No updates found from you. Run 'recovery dispute' first.".into());
    }

    our_updates.sort_by_key(|u| u.sequence_number);
    let our_latest = our_updates.last().unwrap().clone();
    println!(
        "  Found {} updates from you, latest at sequence {}",
        our_updates.len(),
        our_latest.sequence_number
    );

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora
        .get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let operation = LedgerOperation::QuorumAddMember {
        quorum_member: member_pubkey,
        quorum_member_signature: [0u8; 64],
        member_ledger_id: member_ledger_id.clone(),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        membership_until: None,
        dispute_response_blocks: None,
        dispute_arm_blocks: None,
        service_response_blocks: None,
        max_transfer_timeout_blocks: None,
        max_descriptor_bytes: None,
        compensation_bps: None,
        compensation_deposit_id: None,
        compensation_frequency_blocks: None,
    };

    let message_bytes = operation.tlv_encode();

    let sequence = our_latest.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_latest.content_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_latest.content_hash),
        sequence,
        hex::encode(new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(&Message::from_digest(*msg_hash.as_ref()), &keypair);
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded =
            hex::decode(ledger_id).map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded
            .try_into()
            .map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: deposits_core::messages::consts::QUORUM_ADD_MEMBER,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_latest.content_hash,
        content_hash: new_hash,
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!("Publishing QuorumAddMember to Nostr...");
    let publishing_keys = Keys::new(
        nostr_sdk::SecretKey::from_slice(&config.seed)
            .map_err(|e| format!("Invalid key: {}", e))?,
    );
    let publishing_client = Client::new(publishing_keys.clone());
    publishing_client
        .add_relay(&relay_url)
        .await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    publishing_client.connect().await;

    let update_bytes = signed_update.tlv_encode();
    let content = BASE64.encode(&update_bytes);

    let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_UPDATE), content)
        .tags(vec![Tag::custom(
            TagKind::SingleLetter(crate::nostr::TAG_LEDGER_ID),
            [ledger_id],
        )])
        .sign_with_keys(&publishing_keys)
        .map_err(|e| format!("Failed to sign event: {}", e))?;

    publishing_client
        .send_event(event)
        .await
        .map_err(|e| format!("Failed to publish: {}", e))?;

    publishing_client.disconnect().await.ok();

    println!();
    println!("QuorumAddMember published!");
    println!("  Sequence: {}", sequence);
    println!(
        "  Member: {}...",
        &member_pubkey_str[..16.min(member_pubkey_str.len())]
    );

    Ok(())
}

/// Show the current quorum status on our dispute branch.
pub async fn recovery_rebuild_status(
    ledger_id: &str,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let our_pubkey = PublicKey::from_secret_key(&secp, &secret_key);

    println!(
        "Checking dispute branch status for ledger: {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );

    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id)],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    let mut our_updates: Vec<SignedLedgerUpdate> = Vec::new();
    let mut quorum_members: Vec<PublicKey> = Vec::new();
    let mut has_dispute = false;
    let mut has_armed = false;

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        match op {
                            LedgerOperation::DisputeEnter { .. } => has_dispute = true,
                            LedgerOperation::DisputeArmed { .. } => has_armed = true,
                            LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                                if !quorum_members.contains(&quorum_member) {
                                    quorum_members.push(quorum_member);
                                }
                            }
                            _ => {}
                        }
                    }
                    our_updates.push(update);
                }
            }
        }
    }

    println!();
    if our_updates.is_empty() {
        println!("No updates found from you on this ledger.");
        println!("Run 'recovery dispute <ledger_id>' first to open a dispute.");
        return Ok(());
    }

    println!("Your dispute branch status:");
    println!("  Updates: {}", our_updates.len());
    println!(
        "  Has DisputeEnter: {}",
        if has_dispute {
            "yes"
        } else {
            "NO - run 'recovery dispute' first"
        }
    );
    println!(
        "  Has DisputeArmed: {}",
        if has_armed { "yes (locked in)" } else { "no" }
    );
    println!();
    println!("Quorum members: {}", quorum_members.len());
    for member in &quorum_members {
        println!("  - {}...", &member.to_string()[..16]);
    }
    println!();

    if !has_dispute {
        println!("Next: Run 'recovery dispute <ledger_id>' to open a dispute.");
    } else if quorum_members.is_empty() {
        println!(
            "Next: Add quorum members with 'recovery rebuild <ledger_id> quorum-add <pubkey>'"
        );
    } else if !has_armed {
        println!("Ready to arm! Run 'recovery arm <ledger_id>'");
    } else {
        println!(
            "You are armed. Wait for the entropy block, then run 'recovery claim <ledger_id>'"
        );
    }

    Ok(())
}

/// Publish DisputeArmed to pre-commit for entropy selection.
pub async fn recovery_arm(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use rand::Rng;

    let mut ledger_id: Option<String> = None;
    let mut target_reserves: Option<String> = None;
    let mut rc_outpoint_str: Option<String> = None;
    let mut rc_amount_sats: Option<u64> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target-reserves" | "--target" => {
                if i + 1 < args.len() {
                    target_reserves = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--replacement-collateral-outpoint" => {
                if i + 1 < args.len() {
                    rc_outpoint_str = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--replacement-collateral-amount" => {
                if i + 1 < args.len() {
                    rc_amount_sats = args[i + 1].parse::<u64>().ok();
                    if rc_amount_sats.is_none() {
                        return Err(format!(
                            "--replacement-collateral-amount expects a u64 sats value, got: {}",
                            args[i + 1]
                        )
                        .into());
                    }
                    i += 1;
                }
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    // Both replacement-collateral flags must come together. Strict cosigners
    // require a populated declaration; falling back to None when only one
    // flag is supplied is almost certainly a typo.
    if rc_outpoint_str.is_some() != rc_amount_sats.is_some() {
        return Err(
            "--replacement-collateral-outpoint requires --replacement-collateral-amount \
             (and vice versa)"
                .into(),
        );
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!(
        "Arming (pre-committing) for ledger: {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );

    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    let mut our_updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    our_updates.push(update);
                }
            }
        }
    }
    our_updates.sort_by_key(|u| u.sequence_number);

    if our_updates.is_empty() {
        return Err("No updates found from you. Did you run 'recovery dispute' first?".into());
    }

    let latest = our_updates.last().unwrap();
    println!("  Found {} updates from you", our_updates.len());
    println!("  Latest sequence: {}", latest.sequence_number);

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora
        .get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    // Generate random preimage (17-20 bytes for lottery entropy)
    let mut rng = rand::thread_rng();
    let preimage_len = rng.gen_range(17..=20);
    let mut preimage = vec![0u8; preimage_len];
    rng.fill(&mut preimage[..]);

    // Compute commitment_hash = HASH160(preimage)
    let commitment_hash: [u8; 20] = *hash160::Hash::hash(&preimage).as_byte_array();

    // Get target_reserves address
    let target_reserves_addr = if let Some(addr) = target_reserves {
        addr
    } else {
        use bitcoin::Address;
        let pubkey_bytes: [u8; 33] = our_pubkey.serialize();
        let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| format!("Invalid pubkey: {}", e))?;
        Address::p2wpkh(&compressed, config.network).to_string()
    };

    // Store preimage for later reveal
    let preimage_file = format!(
        "{}/lottery_preimage_{}.hex",
        config.data_dir.display(),
        &ledger_id[..16.min(ledger_id.len())]
    );
    std::fs::write(&preimage_file, hex::encode(&preimage))
        .map_err(|e| format!("Failed to store preimage: {}", e))?;
    println!("  Stored lottery preimage in: {}", preimage_file);

    // Resolve --replacement-collateral-outpoint into a structured declaration.
    // Verifies the UTXO exists and sits at the operator-key P2WPKH (which is
    // what the RC4 claim-TX path knows how to sign). Other address types
    // need extending the claim-TX builder; we fail loudly here rather than
    // accept a declaration the winner can't actually claim against.
    let replacement_collateral = match (rc_outpoint_str.as_deref(), rc_amount_sats) {
        (None, _) => None,
        (Some(s), Some(amount)) => {
            let (txid_hex, vout_str) = s.split_once(':').ok_or_else(|| {
                format!(
                    "--replacement-collateral-outpoint: expected TXID:VOUT, got {}",
                    s
                )
            })?;
            let txid_bytes_vec = hex::decode(txid_hex).map_err(|e| {
                format!("--replacement-collateral-outpoint txid: {}", e)
            })?;
            let txid_bytes: [u8; 32] = txid_bytes_vec.try_into().map_err(|_| {
                "--replacement-collateral-outpoint txid: must be 32 bytes (64 hex chars)"
                    .to_string()
            })?;
            let vout: u32 = vout_str.parse().map_err(|e| {
                format!("--replacement-collateral-outpoint vout: {}", e)
            })?;
            // Verify the UTXO on-chain.
            let txid_obj = bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::Hash::from_byte_array(txid_bytes),
            );
            let tx = esplora
                .get_tx(&txid_obj)
                .map_err(|e| format!("Failed to fetch declared UTXO tx: {:?}", e))?
                .ok_or_else(|| format!("declared UTXO tx {} not on-chain", txid_obj))?;
            let output = tx
                .output
                .get(vout as usize)
                .ok_or_else(|| format!("declared UTXO vout {} out of range", vout))?;
            if output.value.to_sat() < amount {
                return Err(format!(
                    "declared UTXO holds {} sats < declared amount {}",
                    output.value.to_sat(),
                    amount
                )
                .into());
            }
            // Script-type guardrail: must be operator-key P2WPKH so the
            // RC4 claim-TX builder can sign it. Loosening this requires
            // generalising the claim path's signing logic — file a
            // follow-up before declaring at any other script type.
            let pk_bytes: [u8; 33] = our_pubkey.serialize();
            let compressed = bitcoin::CompressedPublicKey::from_slice(&pk_bytes)
                .map_err(|e| format!("compressed pubkey: {}", e))?;
            let expected_script =
                bitcoin::Address::p2wpkh(&compressed, config.network).script_pubkey();
            if output.script_pubkey != expected_script {
                return Err(
                    "declared UTXO is not at the operator-key P2WPKH address. \
                     The RC4 claim-TX builder only signs that script type today; \
                     send funds to your operator address before arming, or extend \
                     the claim-TX builder to handle other scripts."
                        .into(),
                );
            }
            Some(deposits_core::messages::ReplacementCollateral {
                txid: txid_bytes,
                vout,
                amount,
            })
        }
        (Some(_), None) => unreachable!("guarded above"),
    };

    if replacement_collateral.is_none() {
        eprintln!(
            "WARNING: arming without replacement_collateral. Strict cosigners will \
             refuse to sign confiscation; use --replacement-collateral-outpoint \
             TXID:VOUT --replacement-collateral-amount SATS to declare a UTXO."
        );
    }

    let custody_armed = LedgerOperation::DisputeArmed {
        armed_block: current_block_height,
        commitment_hash,
        target_reserves: target_reserves_addr.clone(),
        replacement_collateral,
    };

    let message_bytes = custody_armed.tlv_encode();

    let sequence = latest.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&latest.content_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(latest.content_hash),
        sequence,
        hex::encode(new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(&Message::from_digest(*msg_hash.as_ref()), &keypair);
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded =
            hex::decode(&ledger_id).map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded
            .try_into()
            .map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: latest.content_hash,
        content_hash: new_hash,
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!();
    println!("Publishing DisputeArmed to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport
        .broadcast_ledger_update(&signed_update)
        .await?;

    let entropy_block = current_block_height + 6;

    println!();
    println!("DisputeArmed published successfully!");
    println!("  Armed block: {}", current_block_height);
    println!("  Sequence: {}", sequence);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!();
    println!("Ledger is now in ARMED state. Quorum is locked.");
    println!();
    println!("Next steps:");
    println!(
        "  1. Wait for entropy block: {} (current: {})",
        entropy_block, current_block_height
    );
    println!(
        "  2. After entropy block: recovery claim {}",
        &ledger_id[..16]
    );

    Ok(())
}

/// Claim custody after entropy block - publish DisputeAcquire (winner) or DisputeYield (loser).
pub async fn recovery_claim_new(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!(
        "Claiming custody for ledger: {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );

    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    // Find all DisputeArmed candidates
    let mut candidates: Vec<(PublicKey, u32, SignedLedgerUpdate)> = Vec::new();
    let mut our_latest: Option<SignedLedgerUpdate> = None;
    let mut our_armed_block: Option<u32> = None;

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::DisputeArmed { armed_block, .. } = op {
                        candidates.push((update.operator_id, armed_block, update.clone()));
                        if update.operator_id == our_pubkey {
                            our_armed_block = Some(armed_block);
                        }
                    }
                }

                if update.operator_id == our_pubkey
                    && (our_latest.is_none()
                        || update.sequence_number > our_latest.as_ref().unwrap().sequence_number)
                {
                    our_latest = Some(update);
                }
            }
        }
    }

    if candidates.is_empty() {
        return Err("No DisputeArmed candidates found.".into());
    }

    let our_latest = our_latest.ok_or("No updates found from you")?;
    if our_armed_block.is_none() {
        return Err("You haven't published DisputeArmed yet. Run 'recovery arm' first.".into());
    }

    println!("  Found {} armed candidates", candidates.len());
    for (pk, block, _) in &candidates {
        let marker = if *pk == our_pubkey { " (you)" } else { "" };
        println!(
            "    - {}... armed at block {}{}",
            &pk.to_string()[..16],
            block,
            marker
        );
    }

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora
        .get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let earliest_armed = candidates.iter().map(|(_, b, _)| *b).min().unwrap();
    let entropy_block_height = earliest_armed + 6;

    if current_block_height < entropy_block_height {
        println!();
        println!("Entropy block not yet mined!");
        println!("  Current block: {}", current_block_height);
        println!(
            "  Entropy block: {} (need {} more blocks)",
            entropy_block_height,
            entropy_block_height - current_block_height
        );
        println!();
        println!("Please wait for the entropy block to be mined, then run this command again.");
        return Ok(());
    }

    let entropy_block_hash_hex = esplora
        .get_block_hash(entropy_block_height)
        .map_err(|e| format!("Failed to get entropy block hash: {:?}", e))?;
    let entropy_block_hash: [u8; 32] = {
        let hash_bytes = entropy_block_hash_hex.to_byte_array();
        let mut reversed = hash_bytes;
        reversed.reverse();
        reversed
    };

    println!();
    println!(
        "Entropy block: {} (hash: {}...)",
        entropy_block_height,
        hex::encode(&entropy_block_hash[..8])
    );

    let eligible_candidates: Vec<PublicKey> = candidates
        .iter()
        .filter(|(_, armed_block, _)| *armed_block < entropy_block_height)
        .map(|(pk, _, _)| *pk)
        .collect();

    if eligible_candidates.is_empty() {
        return Err("No eligible candidates".into());
    }

    let winner = select_entropy_winner(&entropy_block_hash, &eligible_candidates)
        .ok_or("Failed to select winner")?;

    let we_won = winner == our_pubkey;

    println!();
    println!("Entropy selection result:");
    println!("  Winner: {}...", &winner.to_string()[..16]);
    println!();

    if we_won {
        println!("YOU WON! Publishing DisputeAcquire...");

        // Phase 5d: the entropy-based selection path is deprecated.
        // `recovery_claim_new` will be removed once all integration
        // tests migrate to `recovery lottery-claim`. Until then we
        // synthesize a placeholder claim_txid (the entropy block hash,
        // which is at least non-zero) so the wire format is honoured;
        // validators will reject this if used in earnest.
        let _ = entropy_block_height; // silence unused warning
        let operation = LedgerOperation::DisputeAcquire {
            new_custodian: our_pubkey,
            claim_txid: entropy_block_hash,
            new_reserves_address: String::new(),
        };

        let message_bytes = operation.tlv_encode();

        let sequence = our_latest.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&our_latest.content_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(our_latest.content_hash),
            sequence,
            hex::encode(new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let signature = secp.sign_schnorr(&Message::from_digest(*msg_hash.as_ref()), &keypair);
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let ledger_id_bytes: [u8; 32] = {
            let decoded =
                hex::decode(&ledger_id).map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
            decoded
                .try_into()
                .map_err(|_| "Ledger ID must be 32 bytes")?
        };

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_latest.content_hash,
            content_hash: new_hash,
            block_height: current_block_height,
            block_hash: entropy_block_hash,
        };

        let publish_transport = NostrTransportBuilder::new(secret_key)
            .relay(&relay_url)
            .build()
            .await?;

        publish_transport
            .broadcast_ledger_update(&signed_update)
            .await?;

        println!();
        println!("DisputeAcquire published successfully!");
        println!("  Sequence: {}", sequence);
        println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    } else {
        println!("You did NOT win. Publishing DisputeYield...");

        let operation = LedgerOperation::DisputeYield;
        let message_bytes = operation.tlv_encode();

        let sequence = our_latest.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&our_latest.content_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(our_latest.content_hash),
            sequence,
            hex::encode(new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let signature = secp.sign_schnorr(&Message::from_digest(*msg_hash.as_ref()), &keypair);
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let ledger_id_bytes: [u8; 32] = {
            let decoded =
                hex::decode(&ledger_id).map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
            decoded
                .try_into()
                .map_err(|_| "Ledger ID must be 32 bytes")?
        };

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_latest.content_hash,
            content_hash: new_hash,
            block_height: current_block_height,
            block_hash: entropy_block_hash,
        };

        let publish_transport = NostrTransportBuilder::new(secret_key)
            .relay(&relay_url)
            .build()
            .await?;

        publish_transport
            .broadcast_ledger_update(&signed_update)
            .await?;

        println!();
        println!("DisputeYield published successfully!");
        println!("  Sequence: {}", sequence);
        println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
        println!();
        println!("Your branch is now TOMBSTONED.");
    }

    Ok(())
}

/// Continue the ledger after winning custody
pub async fn recovery_continue(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut count: u32 = 2;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--count" => {
                if i + 1 < args.len() {
                    count = args[i + 1].parse().unwrap_or(2);
                    i += 1;
                }
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!(
        "Continuing ledger: {}... (adding {} operations)",
        &ledger_id[..16.min(ledger_id.len())],
        count
    );

    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    let mut our_latest: Option<SignedLedgerUpdate> = None;
    let mut has_custody_acquire = false;
    let mut original_deposit_ids: Vec<deposits_core::types::DepositId> = Vec::new();

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::DepositOpen { deposit_id, .. } = op {
                        if !original_deposit_ids.contains(&deposit_id) {
                            original_deposit_ids.push(deposit_id);
                        }
                    }
                }

                if update.operator_id == our_pubkey {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if matches!(op, LedgerOperation::DisputeAcquire { .. }) {
                            has_custody_acquire = true;
                        }
                    }
                    if our_latest.is_none()
                        || update.sequence_number > our_latest.as_ref().unwrap().sequence_number
                    {
                        our_latest = Some(update);
                    }
                }
            }
        }
    }

    let mut latest = our_latest.ok_or("No updates found from you. Did you win custody?")?;

    if !has_custody_acquire {
        return Err(
            "You don't have DisputeAcquire. You must win custody first (recovery claim).".into(),
        );
    }

    println!(
        "  Your latest: seq {} (hash: {}...)",
        latest.sequence_number,
        hex::encode(&latest.content_hash[..8])
    );

    // Use first deposit_id or derive from our pubkey
    let deposit_id = original_deposit_ids.first().copied().unwrap_or_else(|| {
        let descriptor = format!("pk({})", hex::encode(our_pubkey.serialize()));
        deposits_core::types::compute_deposit_id(&descriptor)
    });

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora
        .get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;
    let block_hash_hex = esplora
        .get_block_hash(current_block_height)
        .map_err(|e| format!("Failed to get block hash: {:?}", e))?;
    let block_hash: [u8; 32] = {
        let hash_bytes = block_hash_hex.to_byte_array();
        let mut reversed = hash_bytes;
        reversed.reverse();
        reversed
    };

    let ledger_id_bytes: [u8; 32] = {
        let decoded =
            hex::decode(&ledger_id).map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded
            .try_into()
            .map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    println!();
    println!("Adding {} continuation operations...", count);

    for op_num in 0..count {
        let mut payment_hash = [0u8; 32];
        payment_hash[0..8].copy_from_slice(&(op_num as u64).to_le_bytes());
        payment_hash[8..16].copy_from_slice(&latest.content_hash[0..8]);

        let operation = LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id,
            amount: 50000 + (op_num as u64 * 10000),
            invoice_id: format!("post-recovery-{}", op_num + 1),
            sequence_number: latest.sequence_number + 1,
        };

        let message_bytes = operation.tlv_encode();

        let sequence = latest.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&latest.content_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(latest.content_hash),
            sequence,
            hex::encode(new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let signature = secp.sign_schnorr(&Message::from_digest(*msg_hash.as_ref()), &keypair);
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: latest.content_hash,
            content_hash: new_hash,
            block_height: current_block_height,
            block_hash,
        };

        publish_transport
            .broadcast_ledger_update(&signed_update)
            .await?;

        println!(
            "  [{}/{}] seq {} - InvoiceCredit {} msat",
            op_num + 1,
            count,
            sequence,
            50000 + (op_num as u64 * 10000)
        );

        latest = signed_update;
    }

    println!();
    println!("Ledger continued successfully!");
    println!(
        "  New latest: seq {} (hash: {}...)",
        latest.sequence_number,
        hex::encode(&latest.content_hash[..8])
    );

    Ok(())
}

// =============================================================================
// LOTTERY PROTOCOL COMMANDS
// =============================================================================

/// Build and broadcast the confiscation transaction (reserves -> lottery output).
pub async fn recovery_confiscate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, XOnlyPublicKey};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tapscript_reserves::{
        check_economic_precondition, check_recovery_quorum_precondition, LotteryParticipant,
        LotteryScriptBuilder,
    };
    use deposits_core::{SignedLedgerUpdate, TlvDecode};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
    let mut respectful = false;
    let mut obligations_sats: Option<u64> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--respectful" => {
                // Marks this confiscation as a respectful dispute
                // (currently only QuorumExpired). Bifurcates the
                // confiscation tx: `obligations_sats` of reserves go
                // to the lottery winner; the change (excess reserves +
                // full collateral) returns to the operator's pubkey.
                // Without this flag, the punitive single-output
                // behavior is used (full UTXO to lottery; the corrected
                // Q-split punitive shape lands in a follow-up commit).
                respectful = true;
            }
            "--obligations-sats" if i + 1 < args.len() => {
                obligations_sats = Some(
                    args[i + 1]
                        .parse()
                        .map_err(|_| format!("Invalid --obligations-sats: {}", args[i + 1]))?,
                );
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    if obligations_sats.is_none() {
        return Err(
            "--obligations-sats <N> is required. The lottery output \
             carries `obligations` worth of reserves (the new operator \
             inherits those obligations against that backing); the \
             remainder is split per the dispute classification — \
             back to operator (respectful) or among Q cosigners \
             (punitive). The auto-arm path computes obligations from \
             the fork-ledger's deposit balances; manual operators \
             pass it explicitly."
                .into(),
        );
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!(
        "Building confiscation transaction for ledger: {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );

    // Fetch all updates from Nostr
    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    // Extract DisputeArmed data and quorum info
    let mut participants: Vec<LotteryParticipant> = Vec::new();
    let mut quorum_members: Vec<PublicKey> = Vec::new();
    let mut reserves_address: Option<String> = None;
    let mut ledger_hash: Option<[u8; 32]> = None;
    let mut original_operator: Option<PublicKey> = None;

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    match op {
                        LedgerOperation::LedgerOpen { operator_id, .. } => {
                            original_operator = Some(operator_id);
                        }
                        LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                            if !quorum_members.contains(&quorum_member) {
                                quorum_members.push(quorum_member);
                            }
                        }
                        LedgerOperation::QuorumBegin {
                            reserves_id,
                            ledger_hash: lh,
                            ..
                        } => {
                            reserves_address = Some(reserves_id);
                            ledger_hash = Some(lh);
                        }
                        LedgerOperation::DisputeArmed {
                            commitment_hash,
                            target_reserves,
                            ..
                        } => {
                            let x_only = update.operator_id.x_only_public_key().0;
                            participants.push(LotteryParticipant::new(
                                x_only,
                                commitment_hash,
                                target_reserves,
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    if participants.len() < 2 {
        return Err(format!(
            "Need at least 2 DisputeArmed participants, found {}",
            participants.len()
        )
        .into());
    }

    // Phase 4c precondition: protocol-level disputant cap. The lottery
    // builder also enforces this via `n > MAX_DISPUTANTS`, but failing
    // here gives a clearer error and avoids spending CPU on the build.
    if participants.len() > deposits_core::MAX_DISPUTANTS {
        return Err(format!(
            "Too many disputants: {} found, MAX_DISPUTANTS = {}. \
             The lottery construction's hard cap is N=15 — see CUSTODY_LOTTERY.md.",
            participants.len(),
            deposits_core::MAX_DISPUTANTS
        )
        .into());
    }

    // Pre-release policy cap. Disputants equal Q exactly — every
    // cosigner can dispute, the operator is barred by
    // `validate_update_signer` from arming on their own ledger and
    // already isn't counted in Q. QuorumBegin validation catches the
    // policy violation earlier; we re-check here as defence-in-depth in
    // case a pre-policy ledger reaches confiscate time.
    if participants.len() > deposits_core::MAX_QUORUM_SIZE_POLICY {
        return Err(format!(
            "Disputants {} exceeds the pre-release policy cap of {} \
             (= MAX_QUORUM_SIZE_POLICY). The lottery script supports \
             up to {}, but Q is policy-capped until production reliability \
             data justifies lifting it.",
            participants.len(),
            deposits_core::MAX_QUORUM_SIZE_POLICY,
            deposits_core::MAX_DISPUTANTS,
        )
        .into());
    }

    // Sort participants by pubkey for deterministic order
    participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

    // Debug: print participant order
    println!("  Participant order (confiscate):");
    for (i, p) in participants.iter().enumerate() {
        println!("    {}: {}...", i, hex::encode(&p.pubkey.serialize()[..8]));
    }

    let original_operator = original_operator.ok_or("Could not find original operator")?;
    let reserves_address_str = reserves_address.ok_or("No reserves address found")?;
    let _ledger_hash = ledger_hash.ok_or("Could not find ledger_hash")?;

    println!("  Found {} lottery participants", participants.len());
    println!(
        "  Reserves address: {}...",
        &reserves_address_str[..20.min(reserves_address_str.len())]
    );

    // Build recovery voters (quorum minus original operator)
    let recovery_voters: Vec<XOnlyPublicKey> = quorum_members
        .iter()
        .filter(|pk| **pk != original_operator)
        .map(|pk| pk.x_only_public_key().0)
        .collect();

    let recovery_threshold = (recovery_voters.len() / 2) + 1;

    // Phase 2 precondition: recovery-quorum reachability.
    //
    // The lottery output's long-tail leaves degrade `T → T-1 → T-2` with
    // CSV 144/1008/4032. If the non-disputing remainder of the quorum is
    // smaller than the lowest tail threshold (`T-2`, floored at 1), no
    // recovery leaf is ever satisfiable and the output is permanently
    // unspendable when participants vanish.
    let t_emergency = recovery_threshold.saturating_sub(2).max(1);
    check_recovery_quorum_precondition(quorum_members.len(), participants.len(), t_emergency)
        .map_err(|e| format!("{}", e))?;

    // Build the lottery output
    let lottery_builder = LotteryScriptBuilder::new(
        participants.clone(),
        recovery_voters,
        recovery_threshold,
        config.network,
    );

    let lottery_output = lottery_builder
        .build()
        .map_err(|e| format!("Failed to build lottery output: {:?}", e))?;

    println!("  Lottery address: {}", lottery_output.address);

    // Look up reserves UTXO
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();

    let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = reserves_address_str
        .parse()
        .map_err(|e| format!("Invalid reserves address: {}", e))?;
    let reserves_addr = reserves_addr
        .require_network(config.network)
        .map_err(|e| format!("Address network mismatch: {}", e))?;

    let script_pubkey = reserves_addr.script_pubkey();
    let utxos = esplora
        .scripthash_txs(&script_pubkey, None)
        .map_err(|e| format!("Failed to query Esplora: {:?}", e))?;

    // Find unspent output
    let mut reserves_utxo: Option<(bitcoin::OutPoint, u64)> = None;
    for tx in &utxos {
        for (vout, output) in tx.vout.iter().enumerate() {
            if output.scriptpubkey == script_pubkey {
                let outpoint = bitcoin::OutPoint::new(tx.txid, vout as u32);
                let status = esplora
                    .get_output_status(&tx.txid, vout as u64)
                    .map_err(|e| format!("Failed to check output status: {:?}", e))?;
                if status.map(|s| !s.spent).unwrap_or(true) {
                    reserves_utxo = Some((outpoint, output.value));
                    break;
                }
            }
        }
        if reserves_utxo.is_some() {
            break;
        }
    }

    let (reserves_outpoint, reserves_amount) = reserves_utxo.ok_or("No unspent reserves found")?;

    println!(
        "  Found reserves: {} sats at {}",
        reserves_amount, reserves_outpoint
    );

    // Build confiscation transaction
    use bitcoin::{Amount, Sequence, Transaction, TxIn, TxOut, Witness};

    let fee_rate = 2u64;
    let estimated_vsize = 200u64;
    let fee = fee_rate * estimated_vsize;

    // Phase 2 precondition: economic rationality. If reserves can't cover
    // 5x the on-chain claim fee, no winner has reason to spend the lottery
    // output and it stays stuck.
    check_economic_precondition(reserves_amount, fee).map_err(|e| format!("{}", e))?;

    let spendable = reserves_amount.saturating_sub(fee);

    // Build outputs based on dispute classification.
    //
    // Respectful (QuorumExpired): bifurcated. The lottery output carries
    // exactly `obligations` worth of reserves — the new operator inherits
    // those obligations against that backing. The change (excess reserves
    // + full collateral) returns to the original operator's pubkey via
    // P2TR. The operator keeps their bond; the deposits get a new
    // custodian. Respectful proofs do NOT propagate cross-ledger.
    //
    // Punitive (everything else): obligations to lottery, the remainder
    // (excess reserves + full collateral) split equally among the Q
    // cosigners. The lottery winner does NOT retain the confiscated
    // collateral as a windfall — they receive their per-cosigner share
    // alongside everyone else, evenly aligning incentives across the
    // quorum. The winner provides replacement collateral when claiming
    // the lottery output (separate concern, not modeled here).
    //
    // Dust handling: integer division of the remainder by Q drops a
    // residue (≤ Q-1 sats). It silently increases the actual fee paid
    // to miners — small enough to ignore.
    let obligations = obligations_sats.expect("checked above");
    if obligations > spendable {
        return Err(format!(
            "Confiscation: obligations {} sats exceed spendable {} sats \
             (reserves {} - fee {}). The dispute can't proceed — the \
             operator's reserves can't cover declared obligations.",
            obligations, spendable, reserves_amount, fee
        )
        .into());
    }
    let remainder = spendable - obligations;
    let secp_local = Secp256k1::new();

    let outputs: Vec<TxOut> = if respectful {
        let operator_xonly = original_operator.x_only_public_key().0;
        let operator_addr =
            bitcoin::Address::p2tr(&secp_local, operator_xonly, None, config.network);
        println!(
            "  Respectful split: lottery={} sats (obligations), \
             change={} sats → operator's pubkey ({})",
            obligations, remainder, operator_addr
        );
        vec![
            TxOut {
                value: Amount::from_sat(obligations),
                script_pubkey: lottery_output.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(remainder),
                script_pubkey: operator_addr.script_pubkey(),
            },
        ]
    } else {
        // Punitive: obligations to lottery + Q equal slices to cosigners.
        // Cosigner ordering is by xonly pubkey (matches the recovery
        // voter ordering convention used elsewhere) so the tx is
        // deterministic and reproducible by every quorum member.
        let q = quorum_members.len() as u64;
        if q == 0 {
            return Err("Punitive confiscation: zero quorum members — \
                       nowhere to send the slashed value."
                .into());
        }
        let per_cosigner = remainder / q;
        let dust = remainder - (per_cosigner * q);
        let mut cosigners_sorted: Vec<PublicKey> = quorum_members.clone();
        cosigners_sorted.sort_by_key(|pk| pk.x_only_public_key().0.serialize());
        println!(
            "  Punitive split: lottery={} sats (obligations), \
             {} sats × {} cosigners ({} sats dust → fee)",
            obligations, per_cosigner, q, dust
        );
        let mut outs = vec![TxOut {
            value: Amount::from_sat(obligations),
            script_pubkey: lottery_output.script_pubkey(),
        }];
        for pk in &cosigners_sorted {
            let xonly = pk.x_only_public_key().0;
            let addr = bitcoin::Address::p2tr(&secp_local, xonly, None, config.network);
            outs.push(TxOut {
                value: Amount::from_sat(per_cosigner),
                script_pubkey: addr.script_pubkey(),
            });
        }
        outs
    };

    let confiscation_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: reserves_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: outputs,
    };

    // Build the Taproot reserves structure for signing
    use bitcoin::sighash::{SighashCache, TapSighashType};
    use deposits_core::{TapscriptReservesBuilder, ThresholdConfig, VoterSet};

    let ledger_hash_val = ledger_hash.ok_or("Could not find ledger_hash")?;
    let voter_set = VoterSet::new(original_operator, quorum_members.clone());
    let voter_count = voter_set.all_voters().len();
    let threshold_config = ThresholdConfig::default_for_voter_count(voter_count);

    let taproot_builder = TapscriptReservesBuilder::new(
        voter_set.clone(),
        threshold_config.clone(),
        config.network,
        ledger_hash_val,
    );

    let taproot_output = taproot_builder
        .build()
        .map_err(|e| format!("Failed to build Taproot output: {:?}", e))?;

    // Use quorum-override tier (threshold without tie-breaker)
    let (tier_index, tier) = threshold_config
        .tiers
        .iter()
        .enumerate()
        .find(|(_, t)| !t.requires_tie_breaker && t.threshold > 1)
        .ok_or("No quorum-override tier found")?;

    println!(
        "  Using Tier {} for confiscation (threshold={}/{})",
        tier_index, tier.threshold, voter_count
    );

    // Build leaf script and compute sighash
    let leaf_script = taproot_builder
        .build_threshold_leaf(tier)
        .map_err(|e| format!("Failed to build leaf script: {:?}", e))?;

    let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
        &leaf_script,
        bitcoin::taproot::LeafVersion::TapScript,
    );

    let prevouts = vec![TxOut {
        value: Amount::from_sat(reserves_amount),
        script_pubkey: reserves_addr.script_pubkey(),
    }];

    let mut confiscation_tx = confiscation_tx; // Make mutable
    let mut sighash_cache = SighashCache::new(&confiscation_tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| format!("Failed to compute sighash: {}", e))?;

    let sighash_bytes: [u8; 32] = *sighash.as_ref();

    // Sign with our key
    let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
    let our_signature = secp.sign_schnorr(&msg, &keypair);

    let mut signatures = std::collections::HashMap::new();
    signatures.insert(our_pubkey, our_signature.serialize());

    println!("  Signed with our key");

    // Request signatures from other quorum members
    let required_sigs = tier.threshold;
    println!("  Need {}/{} signatures", required_sigs, voter_count);

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    if signatures.len() < required_sigs {
        println!();
        println!("  Requesting signatures from quorum members via Nostr...");

        use crate::nostr::KIND_LEDGER_RESPONSE;

        let unsigned_tx_bytes = bitcoin::consensus::encode::serialize(&confiscation_tx);
        let unsigned_tx_hex = hex::encode(&unsigned_tx_bytes);

        let request_params = serde_json::json!({
            "ledger_id": ledger_id,
            "sighash": hex::encode(sighash_bytes),
            "unsigned_tx": unsigned_tx_hex,
            "lottery_address": lottery_output.address.to_string(),
            "violation_details": "Confiscation to lottery for dispute resolution",
            "last_valid_sequence": 0,
        });

        let request_id = publish_transport
            .send_ledger_request(&ledger_id, "confiscation_sign", request_params)
            .await
            .map_err(|e| format!("Failed to send sign request: {:?}", e))?;

        println!("  Request ID: {}...", &request_id[..16]);

        let max_attempts = 20;
        let poll_interval = std::time::Duration::from_secs(3);

        for attempt in 1..=max_attempts {
            tokio::time::sleep(poll_interval).await;

            let since = nostr_sdk::Timestamp::now() - 120;
            let filter = Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
                .since(since);

            let response_events = publish_transport
                .client()
                .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
                .await
                .map_err(|e| format!("Failed to fetch responses: {:?}", e))?;

            for event in response_events.iter() {
                let mut is_our_request = false;
                for tag in event.tags.iter() {
                    if tag.kind() == TagKind::SingleLetter(crate::nostr::TAG_EVENT_REF) {
                        if let Some(val) = tag.content() {
                            if val == request_id {
                                is_our_request = true;
                                break;
                            }
                        }
                    }
                }

                if !is_our_request {
                    continue;
                }

                if let Ok(response) =
                    serde_json::from_str::<crate::nostr::LedgerResponse>(&event.content)
                {
                    if response.success {
                        if let Some(result) = &response.result {
                            if let (Some(signer_hex), Some(sig_hex)) = (
                                result.get("signer").and_then(|v| v.as_str()),
                                result.get("signature").and_then(|v| v.as_str()),
                            ) {
                                if let (Ok(signer), Ok(sig_bytes)) =
                                    (signer_hex.parse::<PublicKey>(), hex::decode(sig_hex))
                                {
                                    if sig_bytes.len() == 64 && !signatures.contains_key(&signer) {
                                        let mut sig_arr = [0u8; 64];
                                        sig_arr.copy_from_slice(&sig_bytes);
                                        signatures.insert(signer, sig_arr);
                                        println!(
                                            "    Received signature from {}...",
                                            &signer.to_string()[..16]
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }

            println!(
                "    Poll {}/{}: {}/{} signatures",
                attempt,
                max_attempts,
                signatures.len(),
                required_sigs
            );

            if signatures.len() >= required_sigs {
                break;
            }
        }
    }

    if signatures.len() < required_sigs {
        return Err(format!(
            "Could not collect enough signatures ({}/{}). Confiscation failed.",
            signatures.len(),
            required_sigs
        )
        .into());
    }

    // Build witness
    println!();
    println!("  Building witness with {} signatures...", signatures.len());

    let control_block = taproot_output
        .control_block_for_tier(tier_index)
        .ok_or("Failed to get control block for tier")?;

    let mut witness = Witness::new();
    let sorted_keys = voter_set.sorted_x_only_pubkeys();

    for x_only in sorted_keys.iter().rev() {
        for voter in voter_set.all_voters() {
            if voter.x_only_public_key().0 == *x_only {
                if let Some(sig) = signatures.get(&voter) {
                    witness.push(sig);
                } else {
                    witness.push(&[] as &[u8]);
                }
                break;
            }
        }
    }

    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());

    confiscation_tx.input[0].witness = witness;

    // Broadcast
    println!("  Broadcasting confiscation transaction...");

    let data_dir = config.data_dir.clone();
    // CLI builds a transient watch-only wallet for the broadcast.
    // The seed travels through a per-call LocalSigner — same key
    // material, same on-chain addresses as the legacy seed-embedded
    // descriptor, just routed via the Signer trait.
    let xpriv_for_wallet =
        bitcoin::bip32::Xpriv::new_master(config.network, &config.seed).map_err(|e| {
            crate::Error::Wallet(format!("xpriv from seed for transient wallet: {}", e))
        })?;
    let signer_for_wallet =
        deposits_signer_api::LocalSigner::from_xpriv(xpriv_for_wallet).map_err(|e| {
            crate::Error::Wallet(format!("LocalSigner::from_xpriv for transient wallet: {}", e))
        })?;
    let wallet = crate::wallet::Wallet::new(
        &signer_for_wallet,
        config.network,
        data_dir,
        config.electrum_url.clone(),
    )?;
    wallet.broadcast(&confiscation_tx)?;

    let confiscation_txid = confiscation_tx.compute_txid();
    println!();
    println!("Confiscation transaction broadcast!");
    println!("  Txid: {}", confiscation_txid);
    println!("  Lottery address: {}", lottery_output.address);
    println!();
    println!("Next steps:");
    println!("  1. Wait for confirmation");
    println!(
        "  2. All participants run: recovery reveal {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );
    println!(
        "  3. Winner runs: recovery lottery-claim {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );

    Ok(())
}

/// Reveal the lottery preimage via Nostr.
///
/// Publishes a durable `KIND_CUSTODY_LOTTERY_REVEAL` (9106) event so
/// other disputants can fetch the preimage during the
/// `recovery lottery-claim` phase. The signature on the reveal binds
/// the preimage to this disputant's identity.
pub async fn recovery_reveal(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::{Keypair, Secp256k1};

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    println!(
        "Revealing lottery preimage for ledger: {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );

    // Load preimage from file (stored during `recovery arm`).
    let preimage_file = format!(
        "{}/lottery_preimage_{}.hex",
        config.data_dir.display(),
        &ledger_id[..16.min(ledger_id.len())]
    );

    let preimage_hex = std::fs::read_to_string(&preimage_file)
        .map_err(|e| format!("Failed to read preimage file {}: {}", preimage_file, e))?;

    let preimage =
        hex::decode(preimage_hex.trim()).map_err(|e| format!("Invalid preimage hex: {}", e))?;

    println!(
        "  Preimage length: {} bytes (contribution: {})",
        preimage.len(),
        preimage.len() - 16
    );

    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let event_id = transport
        .publish_custody_lottery_reveal(&ledger_id, &preimage, &keypair)
        .await
        .map_err(|e| format!("Failed to publish reveal: {:?}", e))?;

    println!();
    println!("Lottery preimage revealed!");
    println!("  Event ID: {}...", &event_id[..16]);
    println!();
    println!("Wait for all participants to reveal, then run:");
    println!(
        "  recovery lottery-claim {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );

    Ok(())
}

/// Claim the lottery output if we are the winner.
pub async fn recovery_lottery_claim(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tapscript_reserves::{
        LotteryOutput, LotteryParticipant, LotteryScriptBuilder,
    };
    use deposits_core::{SignedLedgerUpdate, TlvDecode};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    // Signer for claim-TX inputs. Routes both the lottery script-spend
    // (Schnorr) and the replacement-collateral wpkh input (ECDSA) through
    // the trait so deployments running deposits-signer (RemoteSigner)
    // don't have to keep the seed locally for the manual claim step.
    // LocalSigner (default) reuses the seed-derived secret in process —
    // identical bytes to the prior `secp.sign_*` path.
    let signer = crate::node_cli::signer_from_config(&config)?;

    println!(
        "Checking lottery result for ledger: {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );

    // Fetch updates and reveals from Nostr
    let client = get_or_create_client(&relay_url).await?;

    // Fetch ledger updates
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let update_events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch updates: {}", e))?;

    // Fetch lottery reveals via the durable KIND_CUSTODY_LOTTERY_REVEAL
    // helper. Each reveal carries a Schnorr signature binding
    // (ledger_id, preimage) to the publishing disputant's identity.
    let reveal_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;
    let reveals = reveal_transport
        .fetch_custody_lottery_reveals(&ledger_id)
        .await
        .map_err(|e| format!("Failed to fetch reveals: {:?}", e))?;

    // Extract DisputeArmed participants. Also keep the per-participant
    // `replacement_collateral` declaration so the winner can build a
    // multi-input claim TX (DEP-03 §"Claim transaction (multi-input)").
    let mut participants: Vec<(PublicKey, LotteryParticipant)> = Vec::new();
    let mut replacement_collateral_decls: std::collections::HashMap<
        PublicKey,
        deposits_core::messages::ReplacementCollateral,
    > = std::collections::HashMap::new();

    for event in update_events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::DisputeArmed {
                        commitment_hash,
                        target_reserves,
                        replacement_collateral,
                        ..
                    } = op
                    {
                        let x_only = update.operator_id.x_only_public_key().0;
                        participants.push((
                            update.operator_id,
                            LotteryParticipant::new(x_only, commitment_hash, target_reserves),
                        ));
                        if let Some(rc) = replacement_collateral {
                            replacement_collateral_decls.insert(update.operator_id, rc);
                        }
                    }
                }
            }
        }
    }

    if participants.is_empty() {
        return Err("No DisputeArmed participants found".into());
    }

    // Sort participants by x-only pubkey for deterministic order (must match confiscate)
    participants.sort_by(|a, b| a.1.pubkey.serialize().cmp(&b.1.pubkey.serialize()));

    // Debug: print participant order with full details
    println!("  Participant order (lottery-claim):");
    for (i, (op_id, p)) in participants.iter().enumerate() {
        let op_hex = hex::encode(&op_id.serialize()[..8]);
        let xonly_hex = hex::encode(&p.pubkey.serialize()[..8]);
        let target_short = if p.target_reserves.len() > 20 {
            format!("{}...", &p.target_reserves[..20])
        } else {
            p.target_reserves.clone()
        };
        println!(
            "    {}: x-only={} op_id={} target={}",
            i, xonly_hex, op_hex, target_short
        );
    }

    println!("  Found {} participants", participants.len());

    // Collect revealed preimages keyed by the disputant's x-only pubkey
    // (matches the LotteryParticipant ordering used by the script).
    let mut preimages: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();

    println!("  Checking {} reveal events...", reveals.len());

    for reveal in &reveals {
        match hex::decode(&reveal.preimage_hex) {
            Ok(preimage) => {
                // The Nostr event's pubkey is x-only by construction;
                // member_pubkey in the content is the same disputant's
                // pubkey (compressed 33-byte form). Convert and key on
                // x-only so we can match against LotteryParticipant.
                let member_pk_bytes = match hex::decode(&reveal.member_pubkey) {
                    Ok(b) => b,
                    Err(_) => {
                        println!(
                            "    Skipping reveal with malformed member_pubkey: {}",
                            &reveal.member_pubkey[..16.min(reveal.member_pubkey.len())]
                        );
                        continue;
                    }
                };
                let pk = match PublicKey::from_slice(&member_pk_bytes) {
                    Ok(pk) => pk,
                    Err(_) => {
                        println!(
                            "    Skipping reveal with non-pubkey member: {}...",
                            &reveal.member_pubkey[..16.min(reveal.member_pubkey.len())]
                        );
                        continue;
                    }
                };
                let x_only = pk.x_only_public_key().0;
                let key = x_only.to_string();
                println!("    Found reveal from: {}...", &key[..16]);
                preimages.insert(key, preimage);
            }
            Err(_) => {
                println!(
                    "    Skipping reveal with non-hex preimage from {}...",
                    &reveal.member_pubkey[..16.min(reveal.member_pubkey.len())]
                );
            }
        }
    }

    println!("  Found {} preimage reveals", preimages.len());

    if preimages.len() < participants.len() {
        println!();
        println!("Not all preimages revealed yet.");
        println!("  Have: {}, Need: {}", preimages.len(), participants.len());
        println!();
        println!("Waiting for remaining participants to run 'recovery reveal'...");
        return Ok(());
    }

    // Match preimages to participants and calculate winner
    // Use x-only pubkey format for matching (Nostr event pubkeys are x-only)
    let mut ordered_preimages: Vec<Vec<u8>> = Vec::new();
    for (pubkey, participant) in &participants {
        // Convert Bitcoin PublicKey to x-only format to match Nostr pubkeys
        let x_only = pubkey.x_only_public_key().0;
        let pubkey_str = x_only.to_string();
        if let Some(preimage) = preimages.get(&pubkey_str) {
            // Debug: verify hash matches commitment
            let computed_hash: [u8; 20] =
                *bitcoin::hashes::hash160::Hash::hash(preimage).as_byte_array();
            let expected_hash = participant.commitment_hash;
            if computed_hash != expected_hash {
                println!("  WARNING: Hash mismatch for {}...", &pubkey_str[..16]);
                println!(
                    "    Preimage: {}...",
                    &hex::encode(preimage)[..32.min(preimage.len() * 2)]
                );
                println!("    Computed HASH160:  {}", hex::encode(computed_hash));
                println!("    Expected (commit): {}", hex::encode(expected_hash));
            } else {
                println!("  Hash OK for {}...", &pubkey_str[..16]);
            }
            ordered_preimages.push(preimage.clone());
        } else {
            return Err(format!("Missing preimage from participant {}", &pubkey_str[..16]).into());
        }
    }

    let winner_index = LotteryOutput::calculate_winner(&ordered_preimages)
        .map_err(|e| format!("Failed to calculate winner: {:?}", e))?;

    let (winner_pubkey, winner_participant) = &participants[winner_index];

    println!();
    println!("Lottery result:");
    for (i, preimage) in ordered_preimages.iter().enumerate() {
        let marker = if i == winner_index { " <-- WINNER" } else { "" };
        println!(
            "  Participant {}: {} bytes (contribution {}){}",
            i,
            preimage.len(),
            preimage.len() - 16,
            marker
        );
    }
    println!();
    println!("Winner: {}...", &winner_pubkey.to_string()[..16]);
    println!(
        "Target reserves: {}...",
        &winner_participant.target_reserves[..20.min(winner_participant.target_reserves.len())]
    );

    if *winner_pubkey != our_pubkey {
        println!();
        println!("You did not win. Run 'recovery release' to publish DisputeYield.");
        return Ok(());
    }

    println!();
    println!("YOU WON! Building claim transaction...");
    println!();

    // Look up our own replacement collateral declaration. The multi-input
    // claim TX consumes (lottery_output + declared_replacement_utxo) and
    // sweeps both into the new vault. Failing to include the declared
    // input is observable on-chain — see DEP-03 §"Claim transaction
    // (multi-input)" and the WinnerCollateralDeviation fraud type.
    let our_replacement_collateral = replacement_collateral_decls.get(&our_pubkey).copied();
    if our_replacement_collateral.is_none() {
        eprintln!(
            "WARNING: no replacement_collateral declared in your DisputeArmed; \
             building single-input claim TX (legacy path). Strict cosigners \
             would have refused confiscation, so this path is only reachable \
             when nobody enforced the inequality. The post-takeover ledger \
             will be under-collateralized."
        );
    } else {
        println!(
            "  Replacement collateral: {} sats from {}:{}",
            our_replacement_collateral.unwrap().amount,
            hex::encode(our_replacement_collateral.unwrap().txid),
            our_replacement_collateral.unwrap().vout
        );
    }

    // Extract quorum members and original operator from ledger
    let mut quorum_members: Vec<PublicKey> = Vec::new();
    let mut original_operator: Option<PublicKey> = None;

    for event in update_events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.sequence_number == 0 {
                    original_operator = Some(update.operator_id);
                }
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::QuorumAddMember { quorum_member, .. } = op {
                        if !quorum_members.contains(&quorum_member) {
                            quorum_members.push(quorum_member);
                        }
                    }
                }
            }
        }
    }

    let original_operator = original_operator.ok_or("Could not find original operator")?;

    // Build the recovery voters list (quorum members minus original operator)
    let recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey> = quorum_members
        .iter()
        .filter(|pk| **pk != original_operator)
        .map(|pk| pk.x_only_public_key().0)
        .collect();

    println!(
        "  Original operator: {}...",
        &original_operator.to_string()[..16]
    );
    println!("  Quorum members: {}", quorum_members.len());
    println!("  Recovery voters: {}", recovery_voters.len());

    // Build lottery participants (just the LotteryParticipant part)
    let lottery_participants: Vec<LotteryParticipant> =
        participants.iter().map(|(_, p)| p.clone()).collect();

    // Calculate recovery threshold (majority of recovery voters)
    let recovery_threshold = recovery_voters.len().div_ceil(2);
    if recovery_threshold == 0 {
        return Err("Not enough recovery voters".into());
    }

    // Build the lottery output to get the address and scripts
    let lottery_builder = LotteryScriptBuilder::new(
        lottery_participants.clone(),
        recovery_voters.clone(),
        recovery_threshold,
        config.network,
    );

    let lottery_output = lottery_builder
        .build()
        .map_err(|e| format!("Failed to build lottery output: {:?}", e))?;

    println!(
        "  Lottery address: {}...",
        &lottery_output.address.to_string()[..20]
    );

    // Find the lottery UTXO on-chain
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();

    let lottery_script = lottery_output.address.script_pubkey();

    // Query for transactions at the lottery address
    let txs = esplora
        .scripthash_txs(&lottery_script, None)
        .map_err(|e| format!("Failed to query lottery address: {:?}", e))?;

    // Find unspent output
    let mut lottery_utxo: Option<(bitcoin::OutPoint, u64)> = None;
    for tx in &txs {
        for (vout, output) in tx.vout.iter().enumerate() {
            if output.scriptpubkey == lottery_script {
                let outpoint = bitcoin::OutPoint::new(tx.txid, vout as u32);
                let status = esplora
                    .get_output_status(&tx.txid, vout as u64)
                    .map_err(|e| format!("Failed to check output status: {:?}", e))?;
                if status.map(|s| !s.spent).unwrap_or(true) {
                    lottery_utxo = Some((outpoint, output.value));
                    break;
                }
            }
        }
        if lottery_utxo.is_some() {
            break;
        }
    }

    let (lottery_outpoint, lottery_amount) = lottery_utxo.ok_or(
        "No unspent UTXO found at lottery address. Was confiscation transaction confirmed?",
    )?;

    println!(
        "  Found lottery UTXO: {} ({} sats)",
        lottery_outpoint, lottery_amount
    );

    // Parse the winner's target_reserves address
    let target_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = winner_participant
        .target_reserves
        .parse()
        .map_err(|e| format!("Invalid target_reserves address: {}", e))?;
    let target_address = target_address
        .require_network(config.network)
        .map_err(|e| format!("Address network mismatch: {}", e))?;

    // Build claim transaction. Single-input shape (lottery only) is the
    // legacy path used when no `replacement_collateral` is declared; the
    // multi-input shape (lottery + declared collateral UTXO) is what
    // strict cosigners expect (DEP-03 §"Claim transaction (multi-input)").
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness};

    // Fee budget: 400 sats for single-input parity; 1200 sats for the
    // multi-input case (~3× the bytes due to the second input + ECDSA
    // witness). Both are well under the cosigner policy default of 5000.
    let (claim_fee, mut tx_inputs, mut prevouts, replacement_collateral_input) =
        if let Some(rc) = our_replacement_collateral {
            let rc_txid = bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::Hash::from_byte_array(rc.txid),
            );
            let rc_outpoint = OutPoint::new(rc_txid, rc.vout);
            // Operator-key controlled wpkh — see RC4 design note in
            // recovery.rs: the disputant declares a UTXO at their
            // operator pubkey's P2WPKH address. RC6 will tighten arm-time
            // construction to enforce that placement.
            let our_compressed = bitcoin::CompressedPublicKey::from_slice(
                &our_pubkey.serialize(),
            )
            .map_err(|e| format!("Compressed pubkey: {}", e))?;
            let rc_script = bitcoin::Address::p2wpkh(&our_compressed, config.network)
                .script_pubkey();
            let prevs = vec![
                TxOut {
                    value: Amount::from_sat(lottery_amount),
                    script_pubkey: lottery_script.clone(),
                },
                TxOut {
                    value: Amount::from_sat(rc.amount),
                    script_pubkey: rc_script.clone(),
                },
            ];
            let inputs = vec![
                TxIn {
                    previous_output: lottery_outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: rc_outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ];
            (1200u64, inputs, prevs, Some((rc, rc_script)))
        } else {
            let prevs = vec![TxOut {
                value: Amount::from_sat(lottery_amount),
                script_pubkey: lottery_script.clone(),
            }];
            let inputs = vec![TxIn {
                previous_output: lottery_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }];
            (400u64, inputs, prevs, None)
        };
    let _ = (&mut tx_inputs, &mut prevouts);

    let total_input_value: u64 = prevouts.iter().map(|o| o.value.to_sat()).sum();
    let output_amount = total_input_value.saturating_sub(claim_fee);

    let claim_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: tx_inputs,
        output: vec![TxOut {
            value: Amount::from_sat(output_amount),
            script_pubkey: target_address.script_pubkey(),
        }],
    };

    // Compute sighashes. Lottery input (index 0) uses Taproot script-spend;
    // replacement collateral input (index 1, if present) uses BIP143 wpkh.
    use bitcoin::sighash::{EcdsaSighashType, SighashCache, TapSighashType};
    use bitcoin::taproot::TapLeafHash;

    let leaf_hash = TapLeafHash::from_script(
        &lottery_output.lottery_script,
        bitcoin::taproot::LeafVersion::TapScript,
    );

    let mut sighash_cache = SighashCache::new(&claim_tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| format!("Failed to compute lottery sighash: {}", e))?;

    let sighash_bytes: [u8; 32] = *sighash.as_ref();

    // Lottery script-spend: BIP-340 Schnorr via the Signer trait. Routed
    // through `signer.bip340_sign` so RemoteSigner deployments work without
    // shipping the seed to the recovery operator. SignContext is no_ledger
    // because the claim TX itself doesn't carry a sequence commitment —
    // matches the rotation TX path in wallet.rs.
    use deposits_signer_api::{SigPurpose, SignContext};
    let sig_bytes = signer
        .bip340_sign(
            &SignContext::no_ledger(SigPurpose::OnchainSighash),
            &sighash_bytes,
        )
        .map_err(|e| format!("lottery sighash sign: {}", e))?;

    let lottery_witness = lottery_output
        .create_claim_witness(&sig_bytes, &ordered_preimages)
        .map_err(|e| format!("Failed to create lottery witness: {:?}", e))?;

    let mut claim_tx = claim_tx;
    claim_tx.input[0].witness = lottery_witness;

    // Replacement-collateral input (BIP143 wpkh, ECDSA via Signer).
    if let Some((rc, rc_script)) = replacement_collateral_input {
        let mut sighash_cache = SighashCache::new(&claim_tx);
        let rc_sighash = sighash_cache
            .p2wpkh_signature_hash(
                1,
                &rc_script,
                Amount::from_sat(rc.amount),
                EcdsaSighashType::All,
            )
            .map_err(|e| format!("Failed to compute collateral sighash: {}", e))?;
        let rc_sighash_bytes: [u8; 32] = *rc_sighash.as_ref();
        let rc_sig = signer
            .ecdsa_sign_sighash(
                &SignContext::no_ledger(SigPurpose::OnchainSighash),
                &rc_sighash_bytes,
            )
            .map_err(|e| format!("collateral sighash sign: {}", e))?;
        let mut rc_sig_bytes = rc_sig.serialize_der().to_vec();
        rc_sig_bytes.push(EcdsaSighashType::All as u8);
        let mut rc_witness = Witness::new();
        rc_witness.push(&rc_sig_bytes);
        rc_witness.push(&our_pubkey.serialize());
        claim_tx.input[1].witness = rc_witness;
    }

    println!("  Signed claim transaction");

    // Broadcast
    println!("  Broadcasting claim transaction...");

    let data_dir = config.data_dir.clone();
    // CLI builds a transient watch-only wallet for the broadcast.
    // The seed travels through a per-call LocalSigner — same key
    // material, same on-chain addresses as the legacy seed-embedded
    // descriptor, just routed via the Signer trait.
    let xpriv_for_wallet =
        bitcoin::bip32::Xpriv::new_master(config.network, &config.seed).map_err(|e| {
            crate::Error::Wallet(format!("xpriv from seed for transient wallet: {}", e))
        })?;
    let signer_for_wallet =
        deposits_signer_api::LocalSigner::from_xpriv(xpriv_for_wallet).map_err(|e| {
            crate::Error::Wallet(format!("LocalSigner::from_xpriv for transient wallet: {}", e))
        })?;
    let wallet = crate::wallet::Wallet::new(
        &signer_for_wallet,
        config.network,
        data_dir,
        config.electrum_url.clone(),
    )?;
    wallet.broadcast(&claim_tx)?;

    let claim_txid = claim_tx.compute_txid();
    println!();
    println!("Claim transaction broadcast!");
    println!("  Txid: {}", claim_txid);
    println!(
        "  Output: {} sats to {}",
        output_amount, winner_participant.target_reserves
    );

    // Publish DisputeAcquire to Nostr
    println!();
    println!("Publishing DisputeAcquire to Nostr...");

    use bitcoin::hashes::{sha256, Hash};
    use deposits_core::TlvEncode;

    // Find our DisputeArmed to get sequence number and hash
    let mut our_armed: Option<SignedLedgerUpdate> = None;
    for event in update_events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if matches!(op, LedgerOperation::DisputeArmed { .. }) {
                            our_armed = Some(update);
                        }
                    }
                }
            }
        }
    }

    let our_armed = our_armed.ok_or("Could not find our DisputeArmed update")?;

    // Get current block for entropy reference
    let current_block_height = esplora
        .get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;
    let current_block_hash = esplora
        .get_block_hash(current_block_height)
        .map_err(|e| format!("Failed to get block hash: {:?}", e))?;
    let current_block_hash: [u8; 32] = *current_block_hash.as_ref();

    // Create DisputeAcquire operation
    let claim_txid_bytes: [u8; 32] = *claim_txid.as_ref();
    let _ = current_block_height;
    let _ = current_block_hash;

    let operation = LedgerOperation::DisputeAcquire {
        new_custodian: our_pubkey,
        claim_txid: claim_txid_bytes,
        new_reserves_address: winner_participant.target_reserves.clone(),
    };

    let message_bytes = operation.tlv_encode();

    // Build update continuing from our DisputeArmed
    let sequence = our_armed.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_armed.content_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    // Sign the update
    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_armed.content_hash),
        sequence,
        hex::encode(new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let msg = bitcoin::secp256k1::Message::from_digest(*msg_hash.as_ref());
    let signature = secp.sign_schnorr(&msg, &keypair);
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    // Parse ledger_id into bytes
    let ledger_id_bytes: [u8; 32] = {
        let decoded =
            hex::decode(&ledger_id).map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded
            .try_into()
            .map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_armed.content_hash,
        content_hash: new_hash,
        block_height: current_block_height,
        block_hash: current_block_hash,
    };

    // Publish to Nostr
    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport
        .broadcast_ledger_update(&signed_update)
        .await?;

    println!();
    println!("DisputeAcquire published successfully!");
    println!("  Sequence: {}", sequence);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!("  Claim txid: {}...", &hex::encode(claim_txid_bytes)[..16]);
    println!(
        "  New reserves: {}...",
        &winner_participant.target_reserves[..20.min(winner_participant.target_reserves.len())]
    );
    println!();
    println!("Custody transfer complete. You are now the operator.");
    println!();
    println!("Next: Run 'recovery rotate-to-quorum {}' to move funds to quorum-controlled Taproot address.", &ledger_id[..16.min(ledger_id.len())]);

    Ok(())
}

/// Rotate lottery winnings to a quorum-controlled Taproot address.
pub async fn recovery_rotate_to_quorum(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::nostr::NostrTransportBuilder;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1};
    use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::{
        SignedLedgerUpdate, TapscriptReservesBuilder, ThresholdConfig, TlvDecode, TlvEncode,
        VoterSet,
    };
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Rotating lottery winnings to quorum-controlled Taproot...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);

    // Fetch ledger updates from Nostr
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
        .custom_tag(
            crate::nostr::TAG_LEDGER_ID,
            [crate::nostr::ledger_tag(ledger_id.as_str())],
        )
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch updates: {}", e))?;

    // Decode updates and find our branch
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    updates.dedup_by(|a, b| {
        a.sequence_number == b.sequence_number
            && a.operator_id == b.operator_id
            && a.content_hash == b.content_hash
    });

    // Find our updates (we're the new operator after DisputeAcquire)
    let our_updates: Vec<&SignedLedgerUpdate> = updates
        .iter()
        .filter(|u| u.operator_id == our_pubkey)
        .collect();

    if our_updates.is_empty() {
        return Err("No updates found from you. Did you win the lottery?".into());
    }

    // Find our DisputeAcquire to get the current reserves address
    let mut current_reserves_address: Option<String> = None;
    let mut our_latest: Option<&SignedLedgerUpdate> = None;

    for update in &our_updates {
        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
            if let LedgerOperation::DisputeAcquire {
                new_reserves_address,
                ..
            } = op
            {
                current_reserves_address = Some(new_reserves_address);
            }
        }
        if our_latest.is_none() || update.sequence_number > our_latest.unwrap().sequence_number {
            our_latest = Some(update);
        }
    }

    let current_reserves_address =
        current_reserves_address.ok_or("Could not find DisputeAcquire with reserves address")?;
    let our_latest = our_latest.ok_or("Could not find latest update")?;

    println!(
        "  Current reserves: {}...",
        &current_reserves_address[..20.min(current_reserves_address.len())]
    );
    println!("  Latest sequence: {}", our_latest.sequence_number);

    // Get quorum members from our branch (rebuilt during dispute).
    // Capture each member's ledger_id from the QuorumAddMember op so
    // the QuorumBegin we build below carries that pairing too.
    let mut quorum_members: Vec<PublicKey> = Vec::new();
    let mut member_ledger_ids: std::collections::HashMap<PublicKey, String> =
        std::collections::HashMap::new();
    for update in &our_updates {
        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
            if let LedgerOperation::QuorumAddMember {
                quorum_member,
                ref member_ledger_id,
                ..
            } = op
            {
                if !quorum_members.contains(&quorum_member) {
                    quorum_members.push(quorum_member);
                }
                member_ledger_ids.insert(quorum_member, member_ledger_id.clone());
            }
        }
    }

    if quorum_members.is_empty() {
        return Err("No quorum members found. Did you rebuild the quorum?".into());
    }

    println!("  Quorum members: {}", quorum_members.len());

    // Find the UTXO at current_reserves_address
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();

    let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        current_reserves_address
            .parse()
            .map_err(|e| format!("Invalid reserves address: {}", e))?;
    let reserves_addr = reserves_addr
        .require_network(config.network)
        .map_err(|e| format!("Address network mismatch: {}", e))?;

    let script_pubkey = reserves_addr.script_pubkey();
    let txs = esplora
        .scripthash_txs(&script_pubkey, None)
        .map_err(|e| format!("Failed to query address: {:?}", e))?;

    // Find unspent output
    let mut reserves_utxo: Option<(bitcoin::OutPoint, u64)> = None;
    for tx in &txs {
        for (vout, output) in tx.vout.iter().enumerate() {
            if output.scriptpubkey == script_pubkey {
                let outpoint = bitcoin::OutPoint::new(tx.txid, vout as u32);
                let status = esplora
                    .get_output_status(&tx.txid, vout as u64)
                    .map_err(|e| format!("Failed to check output status: {:?}", e))?;
                if status.map(|s| !s.spent).unwrap_or(true) {
                    reserves_utxo = Some((outpoint, output.value));
                    break;
                }
            }
        }
        if reserves_utxo.is_some() {
            break;
        }
    }

    let (reserves_outpoint, reserves_amount) =
        reserves_utxo.ok_or("No unspent UTXO found at reserves address")?;

    println!(
        "  Found UTXO: {} ({} sats)",
        reserves_outpoint, reserves_amount
    );

    // Compute ledger hash for Taproot address derivation
    let ledger_hash: [u8; 32] = our_latest.content_hash;

    // Build Taproot quorum address
    let voter_set = VoterSet::new(our_pubkey, quorum_members.clone());
    let voter_count = voter_set.all_voters().len();
    let threshold_config = ThresholdConfig::default_for_voter_count(voter_count);

    let taproot_builder =
        TapscriptReservesBuilder::new(voter_set, threshold_config, config.network, ledger_hash);

    let taproot_output = taproot_builder
        .build()
        .map_err(|e| format!("Failed to build Taproot output: {:?}", e))?;

    let new_reserves_address = &taproot_output.address;
    println!(
        "  New Taproot address: {}...",
        &new_reserves_address.to_string()[..20]
    );

    // Build rotation transaction
    let fee = 200u64;
    let output_amount = reserves_amount.saturating_sub(fee);

    let mut rotation_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: reserves_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount),
            script_pubkey: new_reserves_address.script_pubkey(),
        }],
    };

    // Sign the transaction (P2WPKH input)
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};

    let mut sighash_cache = SighashCache::new(&rotation_tx);
    let sighash = sighash_cache
        .p2wpkh_signature_hash(
            0,
            &script_pubkey,
            Amount::from_sat(reserves_amount),
            EcdsaSighashType::All,
        )
        .map_err(|e| format!("Failed to compute sighash: {}", e))?;

    let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_ref());
    let ecdsa_sig = secp.sign_ecdsa(&msg, &secret_key);
    let signature = bitcoin::ecdsa::Signature::sighash_all(ecdsa_sig);

    // Build witness for P2WPKH
    let mut witness = Witness::new();
    witness.push(signature.serialize());
    witness.push(our_pubkey.serialize());
    rotation_tx.input[0].witness = witness;

    // Broadcast
    println!("  Broadcasting rotation transaction...");

    let data_dir = config.data_dir.clone();
    // CLI builds a transient watch-only wallet for the broadcast.
    // The seed travels through a per-call LocalSigner — same key
    // material, same on-chain addresses as the legacy seed-embedded
    // descriptor, just routed via the Signer trait.
    let xpriv_for_wallet =
        bitcoin::bip32::Xpriv::new_master(config.network, &config.seed).map_err(|e| {
            crate::Error::Wallet(format!("xpriv from seed for transient wallet: {}", e))
        })?;
    let signer_for_wallet =
        deposits_signer_api::LocalSigner::from_xpriv(xpriv_for_wallet).map_err(|e| {
            crate::Error::Wallet(format!("LocalSigner::from_xpriv for transient wallet: {}", e))
        })?;
    let wallet = crate::wallet::Wallet::new(
        &signer_for_wallet,
        config.network,
        data_dir,
        config.electrum_url.clone(),
    )?;
    wallet.broadcast(&rotation_tx)?;

    let rotation_txid = rotation_tx.compute_txid();
    println!("  Rotation txid: {}", rotation_txid);

    // Publish QuorumBegin operation
    println!();
    println!("Publishing QuorumBegin to Nostr...");

    let txid_bytes: [u8; 32] = *rotation_txid.as_ref();

    // Get current block height for quorum_expiry calculation
    let current_block_height = esplora
        .get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;
    let current_block_hash = esplora
        .get_block_hash(current_block_height)
        .map_err(|e| format!("Failed to get block hash: {:?}", e))?;
    let block_hash: [u8; 32] = *current_block_hash.as_ref();

    let quorum_size = (quorum_members.len() + 1) as u8;
    let _quorum_threshold = (quorum_size / 2) + 1;
    let quorum_expiry = current_block_height + 144; // ~1 day for degraded spending

    let operation = LedgerOperation::QuorumBegin {
        reserves_id: new_reserves_address.to_string(),
        spending_txid: txid_bytes,
        new_outpoint_txid: txid_bytes,
        new_outpoint_vout: 0,
        amount: output_amount,
        quorum_expiry,
        ledger_hash,
        quorum_members: quorum_members
            .iter()
            .map(|pk| deposits_core::messages::QuorumMemberRef::new(
                *pk,
                member_ledger_ids.get(pk).cloned().unwrap_or_default(),
            ))
            .collect(),
        collateral_amount: 0, // recovery — collateral will be re-attested
    };

    let message_bytes = operation.tlv_encode();

    let sequence = our_latest.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_latest.content_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_latest.content_hash),
        sequence,
        hex::encode(new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let msg = bitcoin::secp256k1::Message::from_digest(*msg_hash.as_ref());
    let signature = secp.sign_schnorr(&msg, &keypair);
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded =
            hex::decode(&ledger_id).map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded
            .try_into()
            .map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_latest.content_hash,
        content_hash: new_hash,
        block_height: current_block_height,
        block_hash,
    };

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport
        .broadcast_ledger_update(&signed_update)
        .await?;

    println!();
    println!("Reserves rotated to quorum-controlled Taproot!");
    println!("  New address: {}", new_reserves_address);
    println!("  Amount: {} sats", output_amount);
    println!(
        "  Quorum: {}-of-{}",
        quorum_members.len().div_ceil(2) + 1,
        quorum_members.len() + 1
    );
    println!("  Sequence: {}", sequence);

    Ok(())
}

/// Append a `DeliveryEmbed` operation to the operator's ledger that
/// records `request_hash` for causal-tree purposes. Used by wallets and
/// fraud-proof producers to entangle a hash into the operator's chain
/// without going through the full transfer-cosign flow.
///
/// Usage: `recovery embed-hash <reserves_id> <hash_hex>`
pub async fn recovery_embed_hash(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::nostr::NostrTransportBuilder;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::SignedLedgerUpdate;
    use deposits_core::TlvEncode;
    use sha2::{Digest, Sha256};

    if args.len() < 2 {
        eprintln!("Usage: deposits-node recovery embed-hash <reserves_id> <hash_hex>");
        return Ok(());
    }

    let reserves_id = &args[0];
    let request_hash: [u8; 32] = {
        let bytes = hex::decode(&args[1])?;
        bytes
            .try_into()
            .map_err(|_| "hash must be 32 bytes hex")?
    };

    let mut config_args = Vec::new();
    let mut i = 2;
    while i < args.len() {
        config_args.push(args[i].clone());
        if i + 1 < args.len() && !args[i + 1].starts_with("--") {
            config_args.push(args[i + 1].clone());
            i += 1;
        }
        i += 1;
    }
    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured")?
        .clone();
    let data_dir = config.data_dir.clone();

    let secp = Secp256k1::new();
    let secret_key = super::derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let operator_pubkey = keypair.public_key();

    let node = crate::Node::new(config).await?;
    let (ledger_id, ledger) = node
        .get_ledger_with_id(reserves_id)
        .ok_or_else(|| format!("Ledger not found: {}", reserves_id))?;
    let last = ledger
        .history
        .last()
        .ok_or("Ledger has no history")?
        .clone();
    let next_seq = last.sequence_number + 1;
    let prev_chain_hash = last.chain_hash();

    let op = LedgerOperation::DeliveryEmbed {
        request_hash,
        target_ledger_id: ledger.state.ledger_id,
        target_operator: operator_pubkey,
    };
    let message_bytes = op.tlv_encode();
    // content_hash is derived via the protocol's formula so the on-disk
    // value matches what receivers compute on TLV decode.
    let mut update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: op.message_type(),
        operator_id: operator_pubkey,
        ledger_id: ledger.state.ledger_id,
        sequence_number: next_seq,
        previous_hash: prev_chain_hash,
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
    };
    update.content_hash = update.compute_hash();
    let content_hash = update.content_hash;

    let signing_data = update.operator_signing_data();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&Sha256::digest(&signing_data));
    let msg = Message::from_digest(hash_bytes);
    update.operator_signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair).serialize();

    println!("DeliveryEmbed update:");
    println!("  Ledger:        {}", ledger_id);
    println!("  Sequence:      {}", next_seq);
    println!("  request_hash:  {}", hex::encode(request_hash));
    println!("  content_hash:  {}", hex::encode(content_hash));
    println!();

    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;
    let event_id = transport.broadcast_ledger_update(&update).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    transport.disconnect().await;
    let _ = data_dir; // step 3: own-ledger inbound is no longer skipped

    println!("Broadcast: {}", event_id);
    Ok(())
}

/// Read a `FraudBroadcast` from a JSON file (or `-` for stdin) and
/// publish it as a kind:9101 Nostr event. The publisher's operator
/// secret is used to sign the outer Nostr event; the broadcast itself
/// already binds to the accused operator via its embedded `proof`.
///
/// Usage: `recovery publish-fraud-broadcast <broadcast.json|->`
pub async fn recovery_publish_fraud_broadcast(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_core::fraud::FraudBroadcast;
    use nostr_sdk::{Client, EventBuilder, Keys, Kind, SecretKey as NostrSecret};

    if args.is_empty() {
        eprintln!("Usage: deposits-node recovery publish-fraud-broadcast <broadcast.json|->");
        return Ok(());
    }

    let json_source = &args[0];
    let json = if json_source == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else {
        std::fs::read_to_string(json_source)?
    };
    let broadcast: FraudBroadcast = serde_json::from_str(&json)
        .map_err(|e| format!("Failed to parse FraudBroadcast JSON: {}", e))?;

    let mut config_args = Vec::new();
    let mut i = 1;
    while i < args.len() {
        config_args.push(args[i].clone());
        if i + 1 < args.len() && !args[i + 1].starts_with("--") {
            config_args.push(args[i + 1].clone());
            i += 1;
        }
        i += 1;
    }
    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first().ok_or("No relay configured")?;

    let secret_key = super::derive_operator_secret(&config.seed, config.network)?;
    let nostr_sk = NostrSecret::from_slice(&secret_key.secret_bytes())?;
    let keys = Keys::new(nostr_sk);

    let client = Client::new(keys.clone());
    client.add_relay(relay_url).await?;
    client.connect().await;

    // Re-serialize through our own serializer (no extra fields, etc.).
    let content = serde_json::to_string(&broadcast)?;
    // KIND_FRAUD_PROOF = 9101
    let event = EventBuilder::new(Kind::Custom(9101), &content).build(keys.public_key()).sign_with_keys(&keys)?;
    let event_id = event.id;
    client.send_event(event).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let _ = client.disconnect().await;

    println!("Published fraud-broadcast (kind:9101)");
    println!("  event_id: {}", event_id);
    println!("  proof:    {:?}", broadcast.proof.proof_type);
    println!(
        "  accused:  {}",
        &broadcast.proof.accused[..16.min(broadcast.proof.accused.len())]
    );
    Ok(())
}
