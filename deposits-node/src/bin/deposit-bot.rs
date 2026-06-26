//! deposit-bot — one independent, autonomous deposit agent for stress soaks.
//!
//! Each process is a single bot with no shared state and no controller: you
//! launch ~a dozen of them (optionally with different `--behavior`s) and they
//! form an organic economy that churns transfers until the funds bleed to
//! fees. Since you operate the nodes, those fees return to you; top a bot back
//! up out of band (faucet / `deposits-wallet send`) and it resumes.
//!
//! Behavior (v1): `forward` — whenever the bot's balance rises above a floor,
//! it forwards (balance − reserve) to a random peer. It's self-clocked:
//! balance only grows when someone pays it, so paying-onward is effectively
//! pay-on-receive. More behaviors slot in behind `--behavior`.
//!
//! The rail is chosen per peer:
//!   * same ledger     → `transfer_lock` + `transfer_complete`
//!   * different ledger → Lightning: mint the peer's invoice on its ledger
//!     (`make_invoice`), then `pay_invoice` from our deposit.
//!   * (multi-ledger via a PTLC courier is a future rail — not wired, since
//!     nothing is running a courier here.)
//!
//! How a bot works, decentrally:
//!   * It loads ONE deposit (its keypair + deposit_id + ledger) from a wallet
//!     `deposits.json`, like the transfer-simulator does.
//!   * It learns its real balance by subscribing to that deposit's Kind 9100
//!     updates (`#d`=ledger tag, `#i`=deposit id — the affected-deposit tag)
//!     and decoding them with the real codec: on-chain/invoice credits and
//!     inbound transfers raise it.
//!   * To pay, it drives BOTH `transfer_lock` and `transfer_complete` itself
//!     (the sender reveals a fresh random preimage), so receiving is passive —
//!     no cross-bot coordination, no central control.
//!
//! All deposits derive from ONE master seed kept in a well-known place —
//! `<data-dir>/seed.hex` (the same file the wallet writes) — so you never
//! put a real-money key on the command line. Inline `--seed` still works
//! for throwaway/regtest keys but is refused on mainnet without
//! `--i-understand`.
//!
//! Usage:
//!   deposit-bot --relay ws://localhost:7801 --data-dir /data/alice \
//!     --alias alice-1 [--peer <deposit_id_hex> ...] \
//!     [--floor-sats 1000] [--reserve-sats 200] [--interval-ms 1500]

use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::{Rng, RngCore};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_core::types::{DepositId, SignedLedgerUpdate};
use deposits_node::nostr::{TAG_EVENT_REF, TAG_LEDGER_REQ};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

const KIND_LEDGER_REQUEST: u16 = 20101;
const KIND_LEDGER_RESPONSE: u16 = 20102;
const KIND_LEDGER_UPDATE: u16 = 9100;

// ─── config ──────────────────────────────────────────────────────────────

struct Config {
    relay: String,
    data_dir: PathBuf,
    /// Inline `--seed` (discouraged; a real-money secret on the command
    /// line). Refused on mainnet unless `--i-understand`.
    seed_inline: Option<[u8; 32]>,
    /// Explicit `--seed-file`. Defaults to `<data-dir>/seed.hex` — the
    /// well-known location the wallet itself writes — so the bot derives
    /// the same per-deposit keys the wallet created.
    seed_file: Option<PathBuf>,
    i_understand: bool,
    alias: String,
    network: bitcoin::Network,
    behavior: String,
    extra_peers: Vec<DepositId>,
    floor_msats: i64,
    reserve_msats: i64,
    min_payment_msats: u64,
    interval_ms: u64,
    fee_fixed_msats: u64,
    fee_rate_bps: u64,
    timeout_offset: u32,
    timeout_height: u32, // 0 = auto via bitcoin-cli
    bitcoin_cli: String,
    initial_sats: u64,
    /// One-shot: mint a BOLT11 funding invoice for this deposit and exit,
    /// instead of running the forward loop.
    make_invoice_sats: Option<u64>,
    description: String,
}

fn parse_seed(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("--seed not hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("--seed must be 32 bytes (64 hex), got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_deposit_id(s: &str) -> Result<DepositId, String> {
    let bytes = hex::decode(s).map_err(|e| format!("bad deposit id hex: {}", e))?;
    if bytes.len() != 16 {
        return Err(format!("deposit id must be 16 bytes (32 hex), got {}", bytes.len()));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_args() -> Result<Config, String> {
    let mut cfg = Config {
        relay: "ws://localhost:7801".into(),
        data_dir: PathBuf::from("."),
        seed_inline: None,
        seed_file: None,
        i_understand: false,
        alias: String::new(),
        network: bitcoin::Network::Regtest,
        behavior: "forward".into(),
        extra_peers: Vec::new(),
        floor_msats: 1_000_000,    // 1000 sats
        reserve_msats: 200_000,    // 200 sats kept back so we never hit 0
        min_payment_msats: 1_000,  // 1 sat
        interval_ms: 1500,
        fee_fixed_msats: 2,
        fee_rate_bps: 20,
        timeout_offset: 500,
        timeout_height: 0,
        bitcoin_cli: "bitcoin-cli -regtest".into(),
        initial_sats: 0,
        make_invoice_sats: None,
        description: "deposit-bot funding".into(),
    };
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        let need = |i: usize| -> Result<String, String> {
            args.get(i + 1).cloned().ok_or_else(|| format!("{} needs a value", args[i]))
        };
        match args[i].as_str() {
            "--relay" => { cfg.relay = need(i)?; i += 1; }
            "--data-dir" => { cfg.data_dir = PathBuf::from(need(i)?); i += 1; }
            "--seed" => { cfg.seed_inline = Some(parse_seed(&need(i)?)?); i += 1; }
            "--seed-file" => { cfg.seed_file = Some(PathBuf::from(need(i)?)); i += 1; }
            "--i-understand" => { cfg.i_understand = true; }
            "--alias" => { cfg.alias = need(i)?; i += 1; }
            "--network" => {
                cfg.network = match need(i)?.as_str() {
                    "bitcoin" | "mainnet" => bitcoin::Network::Bitcoin,
                    "testnet" => bitcoin::Network::Testnet,
                    "signet" => bitcoin::Network::Signet,
                    "regtest" => bitcoin::Network::Regtest,
                    other => return Err(format!("unknown network {}", other)),
                };
                i += 1;
            }
            "--behavior" => { cfg.behavior = need(i)?; i += 1; }
            "--peer" => { cfg.extra_peers.push(parse_deposit_id(&need(i)?)?); i += 1; }
            "--floor-sats" => { cfg.floor_msats = need(i)?.parse::<i64>().map_err(|e| e.to_string())? * 1000; i += 1; }
            "--reserve-sats" => { cfg.reserve_msats = need(i)?.parse::<i64>().map_err(|e| e.to_string())? * 1000; i += 1; }
            "--floor-msats" => { cfg.floor_msats = need(i)?.parse::<i64>().map_err(|e| e.to_string())?; i += 1; }
            "--min-payment-sats" => { cfg.min_payment_msats = need(i)?.parse::<u64>().map_err(|e: std::num::ParseIntError| e.to_string())? * 1000; i += 1; }
            "--min-payment-msats" => { cfg.min_payment_msats = need(i)?.parse().map_err(|e: std::num::ParseIntError| e.to_string())?; i += 1; }
            "--interval-ms" => { cfg.interval_ms = need(i)?.parse().map_err(|e: std::num::ParseIntError| e.to_string())?; i += 1; }
            "--fee-fixed-msats" => { cfg.fee_fixed_msats = need(i)?.parse().map_err(|e: std::num::ParseIntError| e.to_string())?; i += 1; }
            "--fee-rate-bps" => { cfg.fee_rate_bps = need(i)?.parse().map_err(|e: std::num::ParseIntError| e.to_string())?; i += 1; }
            "--timeout-offset" => { cfg.timeout_offset = need(i)?.parse().map_err(|e: std::num::ParseIntError| e.to_string())?; i += 1; }
            "--timeout-height" => { cfg.timeout_height = need(i)?.parse().map_err(|e: std::num::ParseIntError| e.to_string())?; i += 1; }
            "--bitcoin-cli" => { cfg.bitcoin_cli = need(i)?; i += 1; }
            "--initial-sats" => { cfg.initial_sats = need(i)?.parse().map_err(|e: std::num::ParseIntError| e.to_string())?; i += 1; }
            "--make-invoice" => { cfg.make_invoice_sats = Some(need(i)?.parse().map_err(|e: std::num::ParseIntError| e.to_string())?); i += 1; }
            "--description" => { cfg.description = need(i)?; i += 1; }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {}", other)),
        }
        i += 1;
    }
    if cfg.alias.is_empty() {
        return Err("--alias <deposit alias> is required".into());
    }
    if cfg.behavior != "forward" {
        return Err(format!("unknown --behavior '{}' (only 'forward' so far)", cfg.behavior));
    }
    Ok(cfg)
}

fn print_help() {
    eprintln!("deposit-bot — one autonomous deposit agent (stress soak)\n");
    eprintln!("Required: --alias <deposit alias>");
    eprintln!("Seed (one master key derives every deposit): read from");
    eprintln!("  <data-dir>/seed.hex by default (the wallet's own location).");
    eprintln!("  --seed-file <path>        read the 32-byte hex seed from here");
    eprintln!("  --seed <64-hex>           inline (refused on mainnet w/o --i-understand)");
    eprintln!("  --i-understand            allow inline --seed on mainnet (discouraged)");
    eprintln!("  --relay <url>             relay (default ws://localhost:7801)");
    eprintln!("  --data-dir <dir>          wallet dir holding deposits.json + seed.hex (default .)");
    eprintln!("  --network <net>           regtest|signet|testnet|mainnet (default regtest)");
    eprintln!("  --behavior <name>         forward (default; more later)");
    eprintln!("  --peer <deposit_id_hex>   add a payable peer (repeatable; else auto from deposits.json)");
    eprintln!("  --floor-sats / --floor-msats <n>   don't pay below this balance (default 1000 sat)");
    eprintln!("  --reserve-sats <n>        always keep this much back (default 200)");
    eprintln!("  --min-payment-sats / --min-payment-msats <n>   smallest payment to bother making (default 1 sat)");
    eprintln!("  --interval-ms <n>         tick interval, jittered ±50% (default 1500)");
    eprintln!("  --fee-fixed-msats / --fee-rate-bps   transfer fee (default 2 + 20bps)");
    eprintln!("  --timeout-height <n>      explicit lock timeout height (0 = auto via bitcoin-cli)");
    eprintln!("  --timeout-offset <n>      blocks above tip for the lock timeout (default 500)");
    eprintln!("  --bitcoin-cli <cmd>       for auto timeout height (default 'bitcoin-cli -regtest')");
    eprintln!("  --initial-sats <n>        seed the local balance estimate (default 0)");
    eprintln!("  --make-invoice <sats>     one-shot: mint a BOLT11 funding invoice and exit");
    eprintln!("  --description <text>      invoice description (default 'deposit-bot funding')");
}

/// Resolve the master seed all deposits derive from. Order:
///   1. inline `--seed` (refused on mainnet without `--i-understand`),
///   2. `--seed-file <path>`,
///   3. the wallet's well-known `<data-dir>/seed.hex`.
///
/// Reading from a file keeps the secret off the command line — that's the
/// path the mainnet guard nudges you toward.
fn resolve_seed(cfg: &Config) -> Result<[u8; 32], String> {
    if let Some(s) = cfg.seed_inline {
        if cfg.network == bitcoin::Network::Bitcoin && !cfg.i_understand {
            return Err(
                "refusing inline --seed on mainnet — it lands in shell history / ps. \
                 Put it at <data-dir>/seed.hex (or --seed-file), or pass --i-understand."
                    .into(),
            );
        }
        return Ok(s);
    }
    let path = cfg
        .seed_file
        .clone()
        .unwrap_or_else(|| cfg.data_dir.join("seed.hex"));
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "no seed: read {}: {} — pass --seed-file or put the 32-byte hex seed at <data-dir>/seed.hex",
            path.display(),
            e
        )
    })?;
    parse_seed(raw.trim())
}

// ─── deposit identity ────────────────────────────────────────────────────

/// A payable peer. Same-ledger peers get paid by transfer; different-ledger
/// peers get paid over Lightning (mint their invoice, pay it from us).
#[derive(Clone)]
struct Peer {
    deposit_id: DepositId,
    ledger_id: String,
}

struct Identity {
    ledger_id: String,
    deposit_id: DepositId,
    descriptor: String,
    keypair: Keypair,
    /// Every other deposit in deposits.json (any ledger) + any `--peer`s.
    /// Recipients for the forward behavior; the rail is chosen per peer.
    peers: Vec<Peer>,
}

fn derive_secret_key_at_index(
    seed: &[u8; 32],
    network: bitcoin::Network,
    index: u32,
) -> Result<SecretKey, String> {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use std::str::FromStr;
    let xpriv = Xpriv::new_master(network, seed).map_err(|e| e.to_string())?;
    let secp = Secp256k1::new();
    let path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", index))
        .map_err(|e| e.to_string())?;
    let derived = xpriv.derive_priv(&secp, &path).map_err(|e| e.to_string())?;
    Ok(derived.private_key)
}

/// Load this bot's deposit (by alias) from `<data_dir>/deposits.json`, and
/// collect the other deposits on the same ledger as default peers.
fn load_identity(cfg: &Config, seed: &[u8; 32]) -> Result<Identity, String> {
    let secp = Secp256k1::new();
    let path = cfg.data_dir.join("deposits.json");
    let data = std::fs::read_to_string(&path)
        .map_err(|e| format!("read {}: {}", path.display(), e))?;
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&data).map_err(|e| format!("parse deposits.json: {}", e))?;

    let mut me: Option<(String, u32)> = None; // (ledger_id, key_index)
    // First pass: find ourselves.
    for d in &entries {
        if d.get("alias").and_then(|v| v.as_str()) == Some(cfg.alias.as_str()) {
            let ledger_id = d
                .get("ledger_id")
                .and_then(|v| v.as_str())
                .ok_or("our deposit has no ledger_id")?
                .to_string();
            let key_index = d.get("key_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            me = Some((ledger_id, key_index));
            break;
        }
    }
    let (ledger_id, key_index) =
        me.ok_or_else(|| format!("no deposit with alias '{}' in deposits.json", cfg.alias))?;

    let sk = derive_secret_key_at_index(seed, cfg.network, key_index)?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let descriptor = format!("pk({})", hex::encode(keypair.public_key().serialize()));
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

    // Second pass: peers = every other deposit in the wallet, on ANY ledger.
    // Same-ledger peers get paid by transfer; cross-ledger ones over Lightning.
    let mut peers: Vec<Peer> = Vec::new();
    for d in &entries {
        let Some(pledger) = d.get("ledger_id").and_then(|v| v.as_str()) else { continue };
        let idx = d.get("key_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let Ok(psk) = derive_secret_key_at_index(seed, cfg.network, idx) else { continue };
        let pkp = Keypair::from_secret_key(&secp, &psk);
        let pdesc = format!("pk({})", hex::encode(pkp.public_key().serialize()));
        let pid = deposits_core::types::compute_deposit_id(&pdesc);
        if pid != deposit_id && !peers.iter().any(|p| p.deposit_id == pid) {
            peers.push(Peer { deposit_id: pid, ledger_id: pledger.to_string() });
        }
    }
    // --peer entries are assumed to be on our own ledger (transfer rail).
    for p in &cfg.extra_peers {
        if *p != deposit_id && !peers.iter().any(|x| x.deposit_id == *p) {
            peers.push(Peer { deposit_id: *p, ledger_id: ledger_id.clone() });
        }
    }

    Ok(Identity { ledger_id, deposit_id, descriptor, keypair, peers })
}

// ─── transport ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ResponseData {
    success: bool,
    error: Option<String>,
    result: Option<serde_json::Value>,
}

/// Shared bot state.
struct Bot {
    client: Client,
    ledger_id: String,
    deposit_id: DepositId,
    descriptor: String,
    keypair: Keypair,
    peers: Vec<Peer>,
    /// Local balance estimate (msats). Credited from observed `#i` updates,
    /// debited optimistically when we send (refunded if the lock fails).
    balance: AtomicI64,
    timeout_height: AtomicU32,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<ResponseData>>>>,
    cfg_fee_fixed: u64,
    cfg_fee_rate_bps: u64,
}

impl Bot {
    async fn send_request(&self, ledger_id: &str, action: &str, params: serde_json::Value) -> Result<ResponseData, String> {
        let content = serde_json::to_string(&params).map_err(|e| e.to_string())?;
        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_REQUEST), &content)
            .tag(Tag::custom(TagKind::SingleLetter(TAG_LEDGER_REQ), [ledger_id.to_string()]))
            .tag(Tag::custom(TagKind::custom("action"), [action]))
            .sign_with_keys(&Keys::new(
                nostr_sdk::SecretKey::from_slice(&self.keypair.secret_key().secret_bytes())
                    .map_err(|e| e.to_string())?,
            ))
            .map_err(|e| format!("sign: {}", e))?;
        let event_id = event.id.to_hex();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(event_id.clone(), tx);
        let urls: Vec<_> = self.client.relays().await.keys().cloned().collect();
        self.client
            .send_msg_to(urls, ClientMessage::event(event))
            .await
            .map_err(|e| format!("send: {}", e))?;
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err("response channel closed".into()),
            Err(_) => {
                self.pending.lock().unwrap().remove(&event_id);
                Err("response timeout".into())
            }
        }
    }

    /// Drive a full transfer (lock + complete) to `dest`. Returns Ok on a
    /// committed transfer. The fee is taken from us on top of `amount_msats`.
    /// Transfers are msat-native, so this leg goes sub-sat freely.
    async fn pay(&self, dest: DepositId, amount_msats: u64, fee_msats: u64) -> Result<(), String> {
        let mut rng = OsRng;
        let mut transfer_nonce = [0u8; 32];
        rng.fill_bytes(&mut transfer_nonce);
        let mut transfer_id = [0u8; 32];
        rng.fill_bytes(&mut transfer_id);
        let mut preimage = [0u8; 32];
        rng.fill_bytes(&mut preimage);
        let hash = sha256::Hash::hash(&preimage);
        let completion_script = format!("sha256({})", hex::encode(hash.to_byte_array()));

        let timeout_height = self.timeout_height.load(Ordering::Relaxed);
        let op_nonce = deposits_core::signing::fresh_op_nonce();
        let op_expiry = u32::MAX;

        let proto = LedgerOperation::TransferLock {
            transfer_nonce,
            source_deposit_id: self.deposit_id,
            destination_deposit_id: dest,
            amount: amount_msats,
            fee: fee_msats,
            completion_script: completion_script.clone(),
            timeout_height,
            transfer_id,
            nonce: op_nonce,
            expiry: op_expiry,
            witness: deposits_core::types::DescriptorWitness::new(),
        };
        let signed = deposits_core::signing::sign_op(proto, &self.keypair.secret_key())
            .ok_or("sign_op failed")?;
        let signature_bytes = match &signed {
            LedgerOperation::TransferLock { witness, .. } => witness.stack[0].clone(),
            _ => unreachable!("sign_op preserves variant"),
        };

        let lock_params = serde_json::json!({
            "transfer_nonce": hex::encode(transfer_nonce),
            "source_deposit_id": hex::encode(self.deposit_id),
            "destination_deposit_id": hex::encode(dest),
            "amount": amount_msats,
            "fee": fee_msats,
            "completion_script": completion_script,
            "timeout_height": timeout_height,
            "transfer_id": hex::encode(transfer_id),
            "op_nonce": op_nonce,
            "op_expiry": op_expiry,
            "signature": hex::encode(&signature_bytes),
        });

        let lock = self.send_request(&self.ledger_id, "transfer_lock", lock_params).await?;
        if !lock.success {
            return Err(format!("lock rejected: {}", lock.error.unwrap_or_default()));
        }

        let complete_params = serde_json::json!({
            "transfer_id": hex::encode(transfer_id),
            "preimage": hex::encode(preimage),
        });
        let complete = self.send_request(&self.ledger_id, "transfer_complete", complete_params).await?;
        if !complete.success {
            return Err(format!("complete rejected: {}", complete.error.unwrap_or_default()));
        }
        Ok(())
    }

    /// Ask `ledger_id`'s operator to mint a BOLT11 for `deposit_id` (the same
    /// `make_invoice` the LNURL gateway uses — callable by anyone, since the
    /// operator looks the descriptor up from deposit state). Returns
    /// (bolt11, payment_hash, amount_msats) — all carried in the response, so
    /// we never have to parse the invoice.
    async fn make_invoice_for(
        &self,
        ledger_id: &str,
        deposit_id: DepositId,
        amount_msats: u64,
        description: &str,
    ) -> Result<(String, [u8; 32], u64), String> {
        // Send both: a new operator prefers `amount_msats` (sub-sat capable);
        // an operator still on the old binary reads `amount_sats` (rounded up to
        // ≥1 sat so it never mints a 0-amount "any" invoice). This lets the bot
        // roll out ahead of the operators — the LN leg just floors to whole sats
        // until they upgrade.
        let params = serde_json::json!({
            "deposit_id": hex::encode(deposit_id),
            "amount_msats": amount_msats,
            "amount_sats": (amount_msats / 1000).max(1),
            "description": description,
        });
        let resp = self.send_request(ledger_id, "make_invoice", params).await?;
        if !resp.success {
            return Err(format!("make_invoice rejected: {}", resp.error.unwrap_or_default()));
        }
        let r = resp.result.ok_or("make_invoice response had no result")?;
        let bolt11 = r.get("invoice").and_then(|v| v.as_str())
            .ok_or("response had no `invoice`")?.to_string();
        let ph_hex = r.get("payment_hash").and_then(|v| v.as_str())
            .ok_or("response had no `payment_hash`")?;
        let ph = hex::decode(ph_hex).map_err(|e| format!("bad payment_hash: {}", e))?;
        let mut payment_hash = [0u8; 32];
        if ph.len() != 32 {
            return Err(format!("payment_hash not 32 bytes: {}", ph.len()));
        }
        payment_hash.copy_from_slice(&ph);
        // Use the operator's *authoritative* minted amount, not our request: an
        // operator on the old binary floors sub-sat requests to whole sats and
        // returns `amount_sats`, so paying our requested sub-sat value would
        // trip "amount_msats does not match invoice". Prefer amount_msat (new
        // operator, exact), else amount_sats×1000 (current operator, floored),
        // else our request as a last resort.
        let amount_msats = r
            .get("amount_msat")
            .or_else(|| r.get("amount_msats"))
            .and_then(|v| v.as_u64())
            .or_else(|| r.get("amount_sats").and_then(|v| v.as_u64()).map(|s| s * 1000))
            .unwrap_or(amount_msats);
        Ok((bolt11, payment_hash, amount_msats))
    }

    /// Ask our operator for the authoritative balance of our own deposit and
    /// return the *available* (balance − locked) in msats.
    ///
    /// The streamed local estimate only ever drifts upward: on every relay
    /// resubscribe the operator re-sends our deposit's historical InvoiceCredit
    /// updates and we re-add each (and the relay even republishes duplicates),
    /// while we never observe the matching debits. Left unchecked the bot thinks
    /// it's rich, over-sizes every forward, and the operator rejects it forever.
    /// Snapping to this ground truth before sizing a payment is what keeps it
    /// from getting stuck.
    async fn query_balance(&self) -> Result<i64, String> {
        let params = serde_json::json!({ "deposit_id": hex::encode(self.deposit_id) });
        let resp = self.send_request(&self.ledger_id, "balance_query", params).await?;
        if !resp.success {
            return Err(resp.error.unwrap_or_else(|| "balance_query rejected".into()));
        }
        let r = resp.result.ok_or("balance_query: no result")?;
        let bal = r.get("balance_msats").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
        let locked = r.get("locked_msats").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
        Ok((bal - locked).max(0))
    }

    /// Pay `peer` on a *different* ledger over Lightning: mint its invoice on
    /// its ledger, then `pay_invoice` from our deposit on our ledger. Funds
    /// leave us and land in the peer's deposit as an InvoiceCredit.
    async fn lightning_pay(&self, peer: &Peer, amount_msats: u64) -> Result<(), String> {
        let (invoice, payment_hash, amount_msats) = self
            .make_invoice_for(&peer.ledger_id, peer.deposit_id, amount_msats, "swarm")
            .await?;

        // Fee budget on top of the invoice amount: the LN routing reserve plus
        // the operator's margin. The operator caps routing at this; we sign it
        // into the preimage so it can't be inflated. 1% (min 1 sat) is plenty
        // for the small amounts the swarm moves.
        let fee_msats = (amount_msats / 100).max(1000);

        // Sign the dep-17 InvoiceLock preimage so the operator can lock our
        // funds against the descriptor (mirrors the wallet's pay_invoice).
        let op_nonce = deposits_core::signing::fresh_op_nonce();
        let op_expiry = u32::MAX;
        let proto = LedgerOperation::InvoiceLock {
            deposit_id: self.deposit_id,
            amount: amount_msats,
            payment_id: payment_hash,
            sequence_number: 0,
            nonce: op_nonce,
            expiry: op_expiry,
            timeout_height: None,
            fee: Some(fee_msats),
            witness: deposits_core::types::DescriptorWitness::new(),
        };
        let signed = deposits_core::signing::sign_op(proto, &self.keypair.secret_key())
            .ok_or("InvoiceLock sign failed")?;
        let witness = match &signed {
            LedgerOperation::InvoiceLock { witness, .. } => witness.clone(),
            _ => unreachable!("sign_op preserves variant"),
        };

        let params = serde_json::json!({
            "descriptor": self.descriptor,
            "invoice": invoice,
            "payment_hash": hex::encode(payment_hash),
            "amount_msats": amount_msats,
            "fee_msats": fee_msats,
            "nonce": op_nonce,
            "expiry": op_expiry,
            "witness": witness,
        });
        let resp = self.send_request(&self.ledger_id, "pay_invoice", params).await?;
        if !resp.success {
            return Err(format!("pay_invoice rejected: {}", resp.error.unwrap_or_default()));
        }
        Ok(())
    }
}

/// Decode a Kind 9100 update and return the msat delta to OUR deposit from an
/// inbound credit (on-chain/invoice credit, or a transfer where we're the
/// destination and not the source). Our own outbound transfers are ignored
/// here — we debit those optimistically at send time.
/// Size a forward payment so the operator's fee formula matches EXACTLY.
/// The operator charges `fee = fixed + amount_msats * rate / 10000` on top of
/// the amount, so the fee must be computed on the *final* amount — computing
/// it on the spendable budget overcharges by the fee-on-the-fee and gets the
/// lock rejected ("Fee mismatch"). Returns the largest msat amount (and its
/// matching fee in msats) that fits `spend_msats`, or None if below floor.
/// Sizing is msat-native — transfers carry the sub-sat amount through; the
/// Lightning leg's operator mints a whole-msat invoice from it.
fn size_payment(spend_msats: i64, fixed: u64, rate_bps: u64, min_msats: u64) -> Option<(u64, u64)> {
    let spend = u64::try_from(spend_msats).ok()?;
    if spend <= fixed {
        return None;
    }
    // Solve amount_msats * (1 + rate/10000) + fixed <= spend for the largest amount.
    let amount_msats = (spend - fixed) * 10_000 / (10_000 + rate_bps);
    if amount_msats < min_msats {
        return None;
    }
    let fee_msats = fixed + amount_msats * rate_bps / 10_000;
    Some((amount_msats, fee_msats))
}

/// Pull the authoritative available balance out of an operator rejection so a
/// bot can snap its local estimate back to ledger truth. The operator phrases
/// the figure three ways depending on which stage rejects:
///   1. "Insufficient balance: 1003029 msats available, 4799582 msats needed"
///   2. "Insufficient deposit balance: available 12345, required 99999"
///   3. "InsufficientDepositBalance { available: 12345, required: 99999 }"
/// In (1) the available figure precedes "available"; in (2)/(3) it follows it.
fn parse_available_msats(err: &str) -> Option<i64> {
    let grab_after = |marker: &str| -> Option<i64> {
        let after = &err[err.find(marker)? + marker.len()..];
        let digits: String = after
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.parse().ok()
    };
    // Form 3 — struct Debug: "available: 12345".
    if err.contains("available:") {
        return grab_after("available:");
    }
    // Form 2 — "available 12345" (space then a digit, vs. form 1's
    // "available," with a comma).
    if let Some(pos) = err.find("available ") {
        if err[pos + "available ".len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
        {
            return grab_after("available ");
        }
    }
    // Form 1 — figure right after "balance:".
    grab_after("balance:")
}

fn inbound_credit_msats(content: &str, me: &DepositId) -> Option<u64> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD.decode(content).ok()?;
    let update = SignedLedgerUpdate::tlv_decode(&raw).ok()?;
    let op = LedgerOperation::tlv_decode(&update.message).ok()?;
    match op {
        LedgerOperation::OnchainCredit { deposit_id, amount, .. }
        | LedgerOperation::InvoiceCredit { deposit_id, amount, .. }
            if deposit_id == *me =>
        {
            Some(amount)
        }
        LedgerOperation::TransferLock {
            source_deposit_id,
            destination_deposit_id,
            amount,
            ..
        } if destination_deposit_id == *me && source_deposit_id != *me => Some(amount),
        _ => None,
    }
}

// ─── main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // rustls 0.23+ won't auto-pick a CryptoProvider; install one before any
    // wss/TLS connection or the relay client panics in a worker thread.
    deposits_nostr::install_default_crypto_provider();

    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {}\n", e);
            print_help();
            std::process::exit(2);
        }
    };

    let seed = match resolve_seed(&cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(2);
        }
    };
    let id = load_identity(&cfg, &seed)?;
    let ledger_tag = id.ledger_id[..16.min(id.ledger_id.len())].to_string();
    let same = id.peers.iter().filter(|p| p.ledger_id == id.ledger_id).count();
    let cross = id.peers.len() - same;
    eprintln!(
        "deposit-bot '{}' · deposit {} · ledger {}… · {} peers ({} transfer, {} lightning) · behavior={}",
        cfg.alias,
        hex::encode(id.deposit_id),
        &ledger_tag,
        id.peers.len(),
        same,
        cross,
        cfg.behavior,
    );
    if id.peers.is_empty() && cfg.make_invoice_sats.is_none() {
        return Err("no peers on this ledger — need at least one other deposit to pay".into());
    }

    // Nostr client signed with the deposit key (the operator authenticates the
    // operation via the in-params signature, not the event signer).
    let nostr_secret = nostr_sdk::SecretKey::from_slice(&id.keypair.secret_key().secret_bytes())?;
    let keys = Keys::new(nostr_secret);
    let opts = Options::default().notification_channel_size(8192);
    let client = Client::builder().signer(keys.clone()).opts(opts).build();
    client.add_relay(cfg.relay.as_str()).await?;
    client.connect_with_timeout(Duration::from_secs(10)).await;

    // Two subscriptions: request responses (20102) and our deposit's ledger
    // updates (9100, #d=tag, #i=deposit) for balance. Responses aren't
    // filtered by ledger — we also query *peer* ledgers' operators for
    // cross-ledger make_invoice, so we accept any 20102 and match by the #e
    // (request-id) tag.
    let resp_filter = Filter::new().kind(Kind::Custom(KIND_LEDGER_RESPONSE));
    let upd_filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_tag.clone()])
        .custom_tag(SingleLetterTag::lowercase(Alphabet::I), [hex::encode(id.deposit_id)]);
    client.subscribe(vec![resp_filter, upd_filter], None).await?;

    let bot = Arc::new(Bot {
        client: client.clone(),
        ledger_id: id.ledger_id.clone(),
        deposit_id: id.deposit_id,
        descriptor: id.descriptor,
        keypair: id.keypair,
        peers: id.peers,
        balance: AtomicI64::new(cfg.initial_sats as i64 * 1000),
        timeout_height: AtomicU32::new(cfg.timeout_height),
        pending: Arc::new(Mutex::new(HashMap::new())),
        cfg_fee_fixed: cfg.fee_fixed_msats,
        cfg_fee_rate_bps: cfg.fee_rate_bps,
    });

    // Notification loop: route responses to waiters, credit balance on inbound.
    {
        let bot = bot.clone();
        let mut rx = client.notifications();
        let me = id.deposit_id;
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        match event.kind.as_u16() {
                            KIND_LEDGER_RESPONSE => {
                                let req_id = event.tags.iter().find_map(|t| {
                                    if t.kind() == TagKind::SingleLetter(TAG_EVENT_REF) {
                                        t.content().map(|s| s.to_string())
                                    } else {
                                        None
                                    }
                                });
                                if let Some(req_id) = req_id {
                                    let resp = serde_json::from_str::<serde_json::Value>(&event.content)
                                        .map(|v| ResponseData {
                                            success: v.get("success").and_then(|s| s.as_bool()).unwrap_or(false),
                                            error: v.get("error").and_then(|s| s.as_str()).map(String::from),
                                            result: v.get("result").cloned(),
                                        })
                                        .unwrap_or(ResponseData { success: false, error: Some("bad response json".into()), result: None });
                                    if let Some(tx) = bot.pending.lock().unwrap().remove(&req_id) {
                                        let _ = tx.send(resp);
                                    }
                                }
                            }
                            KIND_LEDGER_UPDATE => {
                                if let Some(credit) = inbound_credit_msats(&event.content, &me) {
                                    let nb = bot.balance.fetch_add(credit as i64, Ordering::Relaxed) + credit as i64;
                                    eprintln!("  ← received {} sats (balance ~{} sats)", credit / 1000, nb / 1000);
                                }
                            }
                            _ => {}
                        }
                    }
                    Ok(RelayPoolNotification::Shutdown) => break,
                    _ => {}
                }
            }
        });
    }

    // One-shot invoice mode: mint a funding BOLT11 for this deposit, print
    // it to stdout, and exit. Doesn't need peers or a timeout height.
    if let Some(sats) = cfg.make_invoice_sats {
        eprintln!("requesting a {} sat funding invoice from the operator…", sats);
        match bot
            .make_invoice_for(&bot.ledger_id, bot.deposit_id, sats * 1000, &cfg.description)
            .await
        {
            Ok((bolt11, _, _)) => {
                eprintln!("pay this to fund '{}' (seeds the swarm):", cfg.alias);
                println!("{}", bolt11);
                return Ok(());
            }
            Err(e) => {
                eprintln!("make_invoice failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Background timeout-height refresher (auto mode): keep the lock timeout
    // comfortably above the chain tip over a long soak.
    if cfg.timeout_height == 0 {
        let bot = bot.clone();
        let cli = cfg.bitcoin_cli.clone();
        let offset = cfg.timeout_offset;
        tokio::spawn(async move {
            loop {
                let tip = std::process::Command::new("sh")
                    .args(["-c", &format!("{} getblockcount", cli)])
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().ok());
                if let Some(tip) = tip {
                    bot.timeout_height.store(tip + offset, Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
        // Give the first refresh a moment to land.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    eprintln!("running — forwarding above floor {} sats, reserve {} sats\n", cfg.floor_msats / 1000, cfg.reserve_msats / 1000);

    // ── forward loop ──
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let s = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("\nshutting down…");
            s.store(true, Ordering::Relaxed);
        });
    }

    let mut rng = OsRng;
    while !shutdown.load(Ordering::Relaxed) {
        // Jitter ±50% so independent bots don't lock-step.
        let base = cfg.interval_ms;
        let jitter = rng.gen_range(0..=base);
        let sleep_ms = base / 2 + jitter;
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

        if bot.timeout_height.load(Ordering::Relaxed) == 0 {
            continue; // no usable timeout height yet
        }

        // Snap to the operator's authoritative balance before sizing a payment.
        // The streamed local estimate drifts upward (replayed/duplicate credit
        // updates with no matching debits), which otherwise makes us over-send
        // and stick in a reject loop. Ground-truth wins. Size off the queried
        // value directly — not a re-read of the shared counter, which the inbound
        // credit task can inflate in the gap between snap and sizing.
        let available = match bot.query_balance().await {
            Ok(avail) => {
                bot.balance.store(avail, Ordering::Relaxed);
                avail
            }
            Err(e) => {
                eprintln!("  (balance check failed: {} — using local estimate)", e);
                bot.balance.load(Ordering::Relaxed)
            }
        };
        // Spend only ~95% of what's available. The operator charges the
        // *deposit's* fee schedule (which can run a touch higher than our
        // --fee estimate), and the balance can drift a hair between this query
        // and the pay; without headroom the total lands just over available and
        // pay_invoice rejects ("Insufficient balance"). A penny-shuffler can
        // happily leave 5% on the table to always complete.
        let spend = (available - cfg.reserve_msats) * 95 / 100;
        if available < cfg.floor_msats || spend < (cfg.min_payment_msats as i64) {
            continue; // below floor — idle until we receive
        }

        let Some((amount_msats, fee_msats)) = size_payment(
            spend,
            bot.cfg_fee_fixed,
            bot.cfg_fee_rate_bps,
            cfg.min_payment_msats,
        ) else {
            continue;
        };
        // Pick a peer and a rail: same ledger → transfer, else → Lightning.
        let peer = bot.peers[rng.gen_range(0..bot.peers.len())].clone();
        let same_ledger = peer.ledger_id == bot.ledger_id;
        let rail = if same_ledger { "transfer" } else { "lightning" };

        // Transfers are msat-native, so they carry the sub-sat amount as sized.
        // Lightning can't: the operator floors the invoice up to a whole sat and
        // lightning_pay adds a routing-fee budget on top, so a sub-sat balance
        // would size an amount the lock can't cover. For the LN rail, floor to
        // whole sats with the same fee lightning_pay uses and skip if a whole
        // sat + its fee won't fit the budget.
        let (amount_msats, fee_msats) = if same_ledger {
            (amount_msats, fee_msats)
        } else {
            let whole = (amount_msats / 1000) * 1000;
            let ln_fee = (whole / 100).max(1000);
            if whole == 0 || (whole + ln_fee) as i64 > spend {
                continue; // too small for the Lightning rail — wait for more
            }
            (whole, ln_fee)
        };
        let total_debit = amount_msats as i64 + fee_msats as i64;

        // Optimistic debit, refund on failure.
        bot.balance.fetch_sub(total_debit, Ordering::Relaxed);
        let result = if same_ledger {
            bot.pay(peer.deposit_id, amount_msats, fee_msats).await
        } else {
            bot.lightning_pay(&peer, amount_msats).await
        };
        match result {
            Ok(()) => {
                eprintln!(
                    "  → {} {} msat to {}…  (balance ~{} sats)",
                    rail,
                    amount_msats,
                    &hex::encode(peer.deposit_id)[..8],
                    bot.balance.load(Ordering::Relaxed) / 1000,
                );
            }
            Err(e) => {
                bot.balance.fetch_add(total_debit, Ordering::Relaxed); // refund
                // "still reconciling — do not retry": the operator accepted the
                // pay and its InvoiceFulfill is settling asynchronously; the
                // funds already moved. Not a failure — just wait it out so we
                // don't fire a second pay against a balance it hasn't settled
                // yet (a double-spend attempt). The next-tick balance_query
                // picks up the real outcome.
                if e.contains("reconciling") || e.contains("do not retry") {
                    eprintln!("  ⧖ {} in flight (reconciling) — backing off", rail);
                    tokio::time::sleep(Duration::from_secs(8)).await;
                    continue;
                }
                // The operator's ledger is authoritative. If it tells us the
                // real available balance, snap our local estimate to it — a
                // replayed InvoiceCredit on resubscribe (the relay re-sends
                // historical #i updates) or any drift would otherwise keep us
                // overshooting forever.
                if let Some(real) = parse_available_msats(&e) {
                    bot.balance.store(real, Ordering::Relaxed);
                }
                eprintln!("  ✗ {} failed: {}", rail, e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_matches_operator_formula_exactly() {
        // The operator recomputes fee = fixed + amount_msats * rate / 10000
        // and rejects on any mismatch. Whatever we size, the fee we attach
        // must equal that recomputation for the chosen amount.
        for &(spend, fixed, rate) in &[
            (4_800_000i64, 2u64, 20u64), // the original 5000-sat case (−200 reserve)
            (803_029, 2, 20),            // a drifted-down balance
            (1_000_000, 0, 10),
            (50_000, 100, 50),
        ] {
            let (amount_msats, fee_msats) = size_payment(spend, fixed, rate, 1).unwrap();
            // Operator's recomputation:
            assert_eq!(fee_msats, fixed + amount_msats * rate / 10_000);
            // And it all fits inside the spendable budget.
            assert!(amount_msats as i64 + fee_msats as i64 <= spend);
        }
    }

    #[test]
    fn fee_regression_5000_sats() {
        // Exactly the live mainnet case that produced the "Fee mismatch:
        // expected 9582, got 9602" rejection. Msat-native sizing keeps the
        // same fee (the fee formula floors identically) but no longer throws
        // away the sub-sat remainder of the amount.
        let (amount_msats, fee_msats) = size_payment(4_800_000, 2, 20, 1).unwrap();
        assert_eq!(amount_msats, 4_790_417);
        assert_eq!(fee_msats, 9582);
        assert!(amount_msats as i64 + fee_msats as i64 <= 4_800_000);
    }

    #[test]
    fn below_floor_returns_none() {
        assert_eq!(size_payment(500_000, 2, 20, 1_000_000), None); // 500 sats < 1000-sat (1M msat) floor
        assert_eq!(size_payment(0, 2, 20, 1), None);
        assert_eq!(size_payment(-100, 2, 20, 1), None);
    }

    #[test]
    fn parse_available_from_rejection() {
        // Form 1 — figure precedes "available".
        let e1 = "pay_invoice rejected: Insufficient balance: 1003029 msats available, 4799582 msats needed";
        assert_eq!(parse_available_msats(e1), Some(1_003_029));
        // Form 2 — "Insufficient deposit balance: available N, required N".
        let e2 = "lock rejected: Insufficient deposit balance: available 800000, required 4799582";
        assert_eq!(parse_available_msats(e2), Some(800_000));
        // Form 3 — struct Debug: "InsufficientDepositBalance { available: N, required: N }".
        let e3 = "state machine refused transition: InsufficientDepositBalance { available: 123456, required: 999999 }";
        assert_eq!(parse_available_msats(e3), Some(123_456));
        // Unrelated errors yield nothing (so we don't clobber the estimate).
        assert_eq!(parse_available_msats("some other error"), None);
        assert_eq!(
            parse_available_msats("Invoice co-signature required but no quorum member responded"),
            None
        );
    }
}
