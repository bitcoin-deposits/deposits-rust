pub mod batch;
pub mod deposit;
pub mod discover;
pub mod ledger;
pub mod payments;
pub mod swap;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, Message, PublicKey, Secp256k1, SecretKey};
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_node::nostr::NostrTransportBuilder;
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
}

pub fn print_usage(program: &str) {
    eprintln!("Deposits Wallet - Nostr-based custody wallet");
    eprintln!();
    eprintln!("Usage: {} <command> [options]", program);
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  discover                    Find available ledgers on the network");
    eprintln!("  info <ledger_id>            Get details about a specific ledger");
    eprintln!("  open <ledger_id> <sats>     Open a new deposit on a ledger");
    eprintln!("  offer <alias> <sats>        Add funds to an existing deposit");
    eprintln!("  balance                     Show balances across all deposits");
    eprintln!("  sync                        Sync deposit statuses from daemon");
    eprintln!("  withdraw <alias> <amt>      Withdraw from a deposit (on-chain)");
    eprintln!("  send <alias> <amt> --to <dst>  Happy-path intra-ledger transfer (lock+complete)");
    eprintln!("  transfer <alias> <amt>      Lock funds for conditional transfer (HTLC)");
    eprintln!("  transfer_complete <id>      Complete a transfer with preimage");
    eprintln!("  swap-advertise <alias> <sats>  Publish an open swap offer");
    eprintln!("  swap-list                   Discover open swap advertisements");
    eprintln!("  route <from> <to> <amt>     Send across ledgers via a courier");
    eprintln!("  spread <amt> [--count N]    Open deposits across N operators");
    eprintln!("  make_invoice <alias> <amt>  Create Lightning invoice for deposit");
    eprintln!("  pay_invoice <alias> <bolt11> Pay Lightning invoice from deposit");
    eprintln!("  history <alias>             Show transaction history");
    eprintln!("  list                        List all your deposits with aliases");
    eprintln!();
    eprintln!("Ledger inspection (read-only from Nostr):");
    eprintln!("  ledger list                 List all ledgers on the relay");
    eprintln!("  ledger show <id>            Show all updates for a ledger");
    eprintln!("  ledger validate <id>        Validate ledger hash chain");
    eprintln!(
        "  ledger custody <id>         Trace custody chain (rotations, disputes, acquisitions)"
    );
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --relay <url>       Nostr relay URL (required)");
    eprintln!(
        "  --network <net>     Network: bitcoin, testnet, signet, regtest (default: regtest)"
    );
    eprintln!("  --data-dir <path>   Data directory (default: ~/.deposits-wallet)");
    eprintln!("  --seed <hex>        Wallet seed (32 bytes hex)");
    eprintln!("  --nsec-file <path>  Override Nostr identity. The file must contain");
    eprintln!("                      an nsec1... bech32 or 64-char hex secret key.");
    eprintln!("                      Use this to sign as your own npub instead of the");
    eprintln!("                      seed-derived key — required when an operator gates");
    eprintln!("                      deposits behind a lightning-verify attestation tied");
    eprintln!("                      to your identity. (The key is read from a file,");
    eprintln!("                      never taken on the command line, so it doesn't leak");
    eprintln!("                      through argv/shell history.)");
    eprintln!("  --alias <name>      Local alias for the deposit (for open command)");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} discover --relay ws://localhost:8080", program);
    eprintln!(
        "  {} open abc123... 100000 --alias savings --relay ws://localhost:8080",
        program
    );
    eprintln!(
        "  {} offer savings 50000 --relay ws://localhost:8080",
        program
    );
    eprintln!(
        "  {} withdraw savings 25000 --to bc1q... --relay ws://localhost:8080",
        program
    );
}

pub fn parse_config(args: &[String]) -> Result<WalletConfig, Box<dyn std::error::Error>> {
    let mut seed: Option<[u8; 32]> = None;
    let mut network = bitcoin::Network::Regtest;
    let mut data_dir: Option<PathBuf> = None;
    let mut relays = Vec::new();
    let mut nostr_nsec: Option<SecretKey> = None;

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

    Ok(WalletConfig {
        seed,
        network,
        data_dir,
        relays,
        nostr_nsec,
    })
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

/// Build canonical signing data for deposit offer co-signatures (must match server-side)
pub fn build_offer_signing_data(
    ledger_id: &str,
    offer_id: &[u8; 32],
    operator_id: &PublicKey,
    funding_address: &str,
    deadline_block: u32,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(ledger_id.as_bytes());
    data.extend_from_slice(offer_id);
    data.extend_from_slice(&operator_id.serialize()[1..]);
    let addr_bytes = funding_address.as_bytes();
    data.push(addr_bytes.len() as u8);
    data.extend_from_slice(addr_bytes);
    data.extend_from_slice(&deadline_block.to_le_bytes());
    data
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
    // Build the offer signing data
    let signing_data = build_offer_signing_data(
        ledger_id,
        offer_id,
        operator_id,
        funding_address,
        deadline_block,
    );

    // Build tagged hash following BIP-340 convention
    let tag = b"deposits/offer_cosign";
    let tag_hash = sha256::Hash::hash(tag);

    let mut tagged_input = Vec::new();
    tagged_input.extend_from_slice(tag_hash.as_byte_array());
    tagged_input.extend_from_slice(tag_hash.as_byte_array());
    tagged_input.extend_from_slice(&signing_data);
    tagged_input.extend_from_slice(member_ledger_hash);

    let hash = sha256::Hash::hash(&tagged_input);

    // Verify Schnorr (BIP-340) signature
    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(hash.to_byte_array());

    let (xonly, _parity) = cosigner_pubkey.x_only_public_key();
    match schnorr::Signature::from_slice(signature) {
        Ok(sig) => secp.verify_schnorr(&sig, &msg, &xonly).is_ok(),
        Err(_) => false,
    }
}

/// Verify that a public key is a quorum member for a ledger by checking ledger history
pub async fn verify_quorum_membership(
    transport: &deposits_node::nostr::NostrTransport,
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
