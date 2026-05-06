pub mod attest;
pub mod batch;
pub mod deposit;
pub mod discover;
pub mod escalate;
pub mod ledger;
pub mod payments;
pub mod regtest;
pub mod swap;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, Message, PublicKey, Secp256k1, SecretKey};
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_nostr::NostrTransportBuilder;
use std::path::PathBuf;

// ANSI color codes for --color-by-pk (used by ledger module)
pub const COLORS: &[&str] = &[
    "\x1b[31m",
    "\x1b[32m",
    "\x1b[33m",
    "\x1b[34m",
    "\x1b[35m",
    "\x1b[36m",
    "\x1b[91m",
    "\x1b[92m",
    "\x1b[93m",
    "\x1b[94m",
    "\x1b[95m",
    "\x1b[96m",
    "\x1b[38;5;208m",
    "\x1b[38;5;205m",
    "\x1b[38;5;118m",
    "\x1b[38;5;39m",
];
pub const RESET: &str = "\x1b[0m";

#[derive(Debug, Clone)]
pub struct WalletConfig {
    pub seed: [u8; 32],
    pub network: bitcoin::Network,
    pub data_dir: PathBuf,
    pub relays: Vec<String>,
    /// Explicit Nostr identity override (from `--nsec-file`). When set,
    /// this key is used for ALL wallet-side Nostr signing (deposit_open,
    /// swaps, verify flow, etc.) instead of the BIP32-derived key. Using
    /// the same identity for both deposit_open and verify is required so
    /// the attestation issued by the verifier matches the sender the
    /// operator sees.
    pub nostr_nsec: Option<SecretKey>,
    /// DEP-04 subkey delegation: the account pubkey we're acting on
    /// behalf of, in 64-char xonly hex. When set, outgoing Kind 20101
    /// requests carry `["v", <account>]` + `["va", <attestation>]`
    /// tags so the operator's `resolve_attested_sender` collapses us
    /// back to the account for ACL purposes.
    pub subkey_account: Option<String>,
    /// DEP-04 attestation signature (64-byte Schnorr hex) that matches
    /// `subkey_account`. Both must be present for the tags to be added.
    pub subkey_attestation: Option<String>,
}

impl WalletConfig {
    /// Return the Nostr secret key this wallet should sign with. If
    /// `--nsec` was supplied, use that; otherwise derive from the seed
    /// at BIP32 index 0 (the default nostr identity slot).
    pub fn nostr_key(&self) -> Result<SecretKey, Box<dyn std::error::Error>> {
        if let Some(sk) = self.nostr_nsec {
            return Ok(sk);
        }
        derive_secret_key(&self.seed, self.network)
    }

    /// If both `--subkey-of` and `--attestation-sig` were supplied,
    /// return (account_xonly_hex, attestation_sig_hex). Otherwise None.
    pub fn subkey_credential(&self) -> Option<(&str, &str)> {
        match (&self.subkey_account, &self.subkey_attestation) {
            (Some(a), Some(s)) => Some((a.as_str(), s.as_str())),
            _ => None,
        }
    }
}

pub fn print_usage(program: &str) {
    eprintln!("Deposits Wallet - Nostr-based custody wallet");
    eprintln!();
    eprintln!("Usage: {} <command> [options]", program);
    eprintln!();
    eprintln!("Discovery:");
    eprintln!("  discover                         Find available ledgers on the network");
    eprintln!("  info <ledger_id>                 Get details about a specific ledger");
    eprintln!();
    eprintln!("Deposits:");
    eprintln!("  open <ledger_id>                 Create a deposit account (no funding yet)");
    eprintln!("  list                             List all your deposits with aliases");
    eprintln!("  balance                          Show balances across all deposits");
    eprintln!("  sync                             Sync deposit statuses from daemon");
    eprintln!();
    eprintln!("Funding (pick one; combine freely):");
    eprintln!("  offer <alias> <sats>             Request an on-chain funding address");
    eprintln!("  make_invoice <alias> <sats>      Get a BOLT11 invoice to fund via Lightning");
    eprintln!("  spread <total> [--count N]       Open + offer across N discovered operators");
    eprintln!();
    eprintln!("Outgoing payments:");
    eprintln!("  pay_invoice <alias> <bolt11>     Pay a BOLT11 from a deposit");
    eprintln!("  send <alias> <amt> --to <dst>    Happy-path intra-ledger transfer");
    eprintln!("  transfer <alias> <amt>           Lock funds for conditional transfer (HTLC)");
    eprintln!("  transfer_complete <id>           Complete a locked transfer with preimage");
    eprintln!("  withdraw <alias> <amt> --to <dst> On-chain withdrawal");
    eprintln!("  route <from> <to> <amt>          Send across ledgers via a courier");
    eprintln!();
    eprintln!("Swaps:");
    eprintln!("  swap-advertise <alias> <sats>    Publish an open swap offer");
    eprintln!("  swap-list                        Discover open swap advertisements");
    eprintln!("  swap-request / swap-listen       Initiate / serve swap requests");
    eprintln!();
    eprintln!("History & inspection:");
    eprintln!("  history <alias>                  Show transaction history");
    eprintln!("  ledger list                      List all ledgers on the relay");
    eprintln!("  ledger show <id>                 Show all updates for a ledger");
    eprintln!("  ledger validate <id>             Validate ledger hash chain");
    eprintln!("  ledger custody <id>              Trace rotations / disputes / acquisitions");
    eprintln!();
    eprintln!("Identity:");
    eprintln!("  attest / revoke / subkeys        Manage subkey delegation (DEP-04)");
    eprintln!();
    eprintln!("Regtest helpers (network=regtest only):");
    eprintln!("  regtest-faucet <alias|addr> [sats]  Send faucet sats + mine a block");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --relay <url>       Nostr relay URL. Pass multiple for fallback.");
    eprintln!("                      Default: wss://relay.bitcoindeposits.net");
    eprintln!(
        "  --network <net>     Network: bitcoin, testnet, signet, regtest (default: bitcoin)"
    );
    eprintln!("  --data-dir <path>   Data directory (default: ~/.deposits-wallet)");
    eprintln!("  --seed <hex>        Wallet seed (32 bytes hex)");
    eprintln!("  --alias <name>      Local alias for the deposit (for open command)");
    eprintln!("  --nsec-file <path>  Override Nostr identity. The file must contain an");
    eprintln!("                      nsec1… bech32 or 64-char hex secret key. Use this to");
    eprintln!("                      sign as your own npub instead of the seed-derived key");
    eprintln!("                      — required when an operator gates deposits behind a");
    eprintln!("                      lightning-verify attestation tied to your identity.");
    eprintln!();
    eprintln!("Environment (defaults when the matching flag isn't passed):");
    eprintln!("  WALLET_SEED          64-char hex seed");
    eprintln!("  WALLET_NETWORK       bitcoin / testnet / signet / regtest");
    eprintln!("  WALLET_DATA_DIR      Directory for seed + deposits.json");
    eprintln!("  WALLET_RELAY         Single relay URL (use --relay for multiple)");
    eprintln!("  BITCOIN_RPC_{{HOST,PORT,USER,PASS,WALLET}}  regtest-faucet RPC target");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} discover                                        # bitcoin via the default relay", program);
    eprintln!("  {} discover --network regtest --relay ws://localhost:17779", program);
    eprintln!("  {} open abc123... --alias savings", program);
    eprintln!("  {} offer savings 50000          # on-chain: returns funding address", program);
    eprintln!("  {} make_invoice savings 50000   # lightning: returns BOLT11", program);
    eprintln!("  {} regtest-faucet savings       # fund locally (regtest only)", program);
}

pub fn parse_config(args: &[String]) -> Result<WalletConfig, Box<dyn std::error::Error>> {
    // Env var fallbacks — used when the corresponding CLI flag isn't
    // supplied. Explicit flags always win.
    //   WALLET_SEED      — 64-char hex seed
    //   WALLET_NETWORK   — bitcoin / testnet / signet / regtest
    //   WALLET_DATA_DIR  — absolute path
    //   WALLET_RELAY     — a single relay URL; pass --relay multiple times
    //                      for more.
    let mut seed: Option<[u8; 32]> = if let Ok(hex) = std::env::var("WALLET_SEED") {
        let b = hex::decode(hex.trim())?;
        if b.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            Some(arr)
        } else {
            None
        }
    } else {
        None
    };
    let mut network = match std::env::var("WALLET_NETWORK").as_deref() {
        Ok("bitcoin") | Ok("mainnet") | Ok("") | Err(_) => bitcoin::Network::Bitcoin,
        Ok("testnet") => bitcoin::Network::Testnet,
        Ok("signet") => bitcoin::Network::Signet,
        Ok("regtest") => bitcoin::Network::Regtest,
        Ok(other) => return Err(format!("Unknown WALLET_NETWORK: {}", other).into()),
    };
    let mut data_dir: Option<PathBuf> = std::env::var("WALLET_DATA_DIR").ok().map(PathBuf::from);
    // No `--relay` and no `WALLET_RELAY` → fall back to the public
    // deposits relay so a fresh checkout can `discover` against the
    // live network without extra flags. Any explicit `--relay` (or
    // `WALLET_RELAY`) wins.
    let mut relays = match std::env::var("WALLET_RELAY") {
        Ok(url) if !url.is_empty() => vec![url],
        _ => vec!["wss://relay.bitcoindeposits.net".to_string()],
    };
    let mut explicit_relay = false;
    let mut nostr_nsec: Option<SecretKey> = None;
    let mut subkey_account: Option<String> = None;
    let mut subkey_attestation: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" if i + 1 < args.len() => {
                let seed_hex = &args[i + 1];
                let seed_bytes = hex::decode(seed_hex)?;
                if seed_bytes.len() != 32 {
                    return Err("Seed must be 32 bytes".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&seed_bytes);
                seed = Some(arr);
                i += 1;
            }
            "--nsec-file" if i + 1 < args.len() => {
                nostr_nsec = Some(load_nsec_file(&args[i + 1])?);
                i += 1;
            }
            "--subkey-of" if i + 1 < args.len() => {
                subkey_account = Some(parse_xonly_arg(&args[i + 1])?);
                i += 1;
            }
            "--attestation-sig" if i + 1 < args.len() => {
                let s = args[i + 1].trim();
                if s.len() != 128 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(
                        "--attestation-sig must be 64-byte Schnorr hex (128 chars)".into(),
                    );
                }
                subkey_attestation = Some(s.to_lowercase());
                i += 1;
            }
            "--network" if i + 1 < args.len() => {
                network = match args[i + 1].as_str() {
                    "bitcoin" | "mainnet" => bitcoin::Network::Bitcoin,
                    "testnet" => bitcoin::Network::Testnet,
                    "signet" => bitcoin::Network::Signet,
                    "regtest" => bitcoin::Network::Regtest,
                    _ => return Err(format!("Unknown network: {}", args[i + 1]).into()),
                };
                i += 1;
            }
            "--data-dir" if i + 1 < args.len() => {
                data_dir = Some(PathBuf::from(&args[i + 1]));
                i += 1;
            }
            "--relay" if i + 1 < args.len() => {
                if !explicit_relay {
                    // First explicit --relay drops the default. Subsequent
                    // --relay flags on the same command line accumulate.
                    relays.clear();
                    explicit_relay = true;
                }
                relays.push(args[i + 1].clone());
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    // Default data directory
    let data_dir = data_dir.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".deposits-wallet")
    });

    // Create data dir if needed
    std::fs::create_dir_all(&data_dir)?;

    // Load or generate seed
    let seed = if let Some(s) = seed {
        s
    } else {
        let seed_file = data_dir.join("seed.hex");
        if seed_file.exists() {
            let seed_hex = std::fs::read_to_string(&seed_file)?;
            let seed_bytes = hex::decode(seed_hex.trim())?;
            if seed_bytes.len() != 32 {
                return Err("Invalid seed file".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&seed_bytes);
            arr
        } else {
            // Generate new seed
            use bitcoin::secp256k1::rand::rngs::OsRng;
            use bitcoin::secp256k1::rand::RngCore;
            let mut rng = OsRng;
            let mut arr = [0u8; 32];
            rng.fill_bytes(&mut arr);
            std::fs::write(&seed_file, hex::encode(arr))?;
            eprintln!("Generated new wallet seed: {}", seed_file.display());
            arr
        }
    };

    // A DEP-04 subkey delegation is (account, attestation) — either both
    // supplied or neither. Half a credential has no meaning.
    if subkey_account.is_some() != subkey_attestation.is_some() {
        return Err(
            "--subkey-of and --attestation-sig must be supplied together".into(),
        );
    }

    Ok(WalletConfig {
        seed,
        network,
        data_dir,
        relays,
        nostr_nsec,
        subkey_account,
        subkey_attestation,
    })
}

/// Parse an npub1... or xonly hex pubkey into xonly hex.
fn parse_xonly_arg(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.starts_with("npub1") {
        let pk = nostr_sdk::PublicKey::parse(s)
            .map_err(|e| format!("invalid npub: {}", e))?;
        return Ok(pk.to_hex());
    }
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(s.to_lowercase());
    }
    if s.len() == 66 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(s[2..].to_lowercase());
    }
    Err(format!("expected npub1... or 64-char hex, got {:?}", s).into())
}

/// Load a Nostr secret key from a file. The file contents (trimmed of
/// whitespace) must be either `nsec1...` bech32 or 64-char hex.
///
/// Files-only — we deliberately don't accept the key inline on the
/// command line. argv is visible in `ps`, shell history, process
/// snapshots, and various logging layers; rotating a leaked nsec is
/// painful (every attestation signed against it becomes orphaned). A
/// 0600-permissioned file on disk is the more defensible default.
fn load_nsec_file(path: &str) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read --nsec-file {}: {}", path, e))?;
    let s = raw.trim();
    if s.is_empty() {
        return Err(format!("--nsec-file {} is empty", path).into());
    }
    if s.starts_with("nsec1") {
        let sk = nostr_sdk::SecretKey::parse(s)
            .map_err(|e| format!("invalid nsec bech32 in {}: {}", path, e))?;
        let bytes = sk.as_secret_bytes();
        return SecretKey::from_slice(bytes)
            .map_err(|e| format!("nsec bytes invalid for secp256k1 ({}): {}", path, e).into());
    }
    let bytes = hex::decode(s)
        .map_err(|e| format!("--nsec-file {} is neither nsec1… nor valid hex: {}", path, e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "--nsec-file {} hex key must be 32 bytes (64 chars), got {}",
            path,
            bytes.len()
        )
        .into());
    }
    SecretKey::from_slice(&bytes).map_err(|e| format!("--nsec-file {}: {}", path, e).into())
}

pub fn derive_secret_key(
    seed: &[u8; 32],
    network: bitcoin::Network,
) -> Result<SecretKey, Box<dyn std::error::Error>> {
    derive_secret_key_at_index(seed, network, 0)
}

/// Resolve a deposit record's descriptor and deposit_id (hex) from the
/// shape stored in `deposits.json`. New records carry `descriptor` and
/// `deposit_id` directly; older records have `deposit_pubkey` only, in
/// which case we synthesize `pk(<pubkey>)` and recompute the id. The
/// returned descriptor is the source of identity — always pass it
/// through to the daemon, never re-derive from the pubkey.
pub fn deposit_record_identity(
    deposit: &serde_json::Value,
) -> Option<(String, String)> {
    let descriptor = match deposit.get("descriptor").and_then(|v| v.as_str()) {
        Some(d) => d.to_string(),
        None => {
            let pk = deposit.get("deposit_pubkey").and_then(|v| v.as_str())?;
            format!("pk({})", pk)
        }
    };
    let deposit_id_hex = match deposit.get("deposit_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => hex::encode(deposits_core::types::compute_deposit_id(&descriptor)),
    };
    Some((descriptor, deposit_id_hex))
}

/// Derive a secret key at a specific index for per-deposit key isolation
pub fn derive_secret_key_at_index(
    seed: &[u8; 32],
    network: bitcoin::Network,
    index: u32,
) -> Result<SecretKey, Box<dyn std::error::Error>> {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use std::str::FromStr;

    let xpriv = Xpriv::new_master(network, seed)?;
    let secp = Secp256k1::new();

    // Use BIP-84 path for wallet keys with varying index
    // m/84'/0'/0'/0/{index} - each deposit gets a unique key
    let path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", index))?;
    let derived = xpriv.derive_priv(&secp, &path)?;

    Ok(derived.private_key)
}

/// Load the next available deposit key index from disk
pub fn load_deposit_key_index(data_dir: &std::path::PathBuf) -> u32 {
    let index_file = data_dir.join("deposit_key_index.txt");
    if !index_file.exists() {
        return 0;
    }
    std::fs::read_to_string(&index_file)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Save the deposit key index to disk
pub fn save_deposit_key_index(
    data_dir: &std::path::PathBuf,
    index: u32,
) -> Result<(), std::io::Error> {
    let index_file = data_dir.join("deposit_key_index.txt");
    std::fs::write(&index_file, index.to_string())
}


/// Verify an offer co-signature from a quorum member
pub fn verify_offer_cosignature(
    ledger_id: &str,
    offer_id: &[u8; 32],
    operator_id: &PublicKey,
    funding_address: &str,
    deadline_block: u32,
    cosigner_pubkey: &PublicKey,
    member_ledger_hash: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    // Canonical signing message in deposits-protocol; same routine the
    // operator uses to produce the signature.
    let msg_hash = deposits_core::signature_utils::offer_cosign_signing_message(
        ledger_id,
        offer_id,
        operator_id,
        funding_address,
        deadline_block,
        member_ledger_hash,
    );

    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(msg_hash);

    let (xonly, _parity) = cosigner_pubkey.x_only_public_key();
    match schnorr::Signature::from_slice(signature) {
        Ok(sig) => secp.verify_schnorr(&sig, &msg, &xonly).is_ok(),
        Err(_) => false,
    }
}

/// Verify that a public key is a quorum member for a ledger by checking ledger history
pub async fn verify_quorum_membership(
    transport: &deposits_nostr::NostrTransport,
    ledger_id: &str,
    cosigner_pubkey: &PublicKey,
) -> bool {
    // Fetch ledger updates to check for QuorumAddMember operations
    let updates = match transport.fetch_ledger_updates(ledger_id).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!(
                "Warning: Failed to fetch ledger updates for verification: {}",
                e
            );
            return false;
        }
    };

    // Look for a QuorumAddMember operation that added this cosigner
    for update in &updates {
        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
            if let LedgerOperation::QuorumAddMember { quorum_member, .. } = op {
                // Compare x-coordinates (pubkeys may have different y-parity)
                let cosigner_x = &cosigner_pubkey.serialize()[1..];
                let member_x = &quorum_member.serialize()[1..];
                if cosigner_x == member_x {
                    return true;
                }
            }
        }
    }

    false
}
