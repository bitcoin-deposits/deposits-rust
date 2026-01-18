//! Simple utility to derive a treasury address from a hex seed file.
//!
//! Usage: cargo run --bin treasury-address [seed_file]
//!
//! The seed file should contain 32 bytes of hex (64 characters).
//! Default path: treasury/treasury_seed

use std::fs;
use std::path::PathBuf;

use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Address, CompressedPublicKey, Network, PrivateKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("treasury/treasury_seed"));

    if !seed_path.exists() {
        eprintln!("Seed file not found: {}", seed_path.display());
        eprintln!("Run: ./mutinynet-treasury.sh init");
        std::process::exit(1);
    }

    let seed_hex = fs::read_to_string(&seed_path)?
        .trim()
        .to_string();

    if seed_hex.len() != 64 {
        eprintln!("Invalid seed length: expected 64 hex chars, got {}", seed_hex.len());
        std::process::exit(1);
    }

    let seed_bytes: [u8; 32] = hex::decode(&seed_hex)?
        .try_into()
        .map_err(|_| "Invalid seed length")?;

    // Extend 32-byte seed to 64 bytes for BIP32 (first 32 for key, second 32 for chain code)
    let mut extended_seed = [0u8; 64];
    extended_seed[..32].copy_from_slice(&seed_bytes);
    // Use SHA256 of seed for chain code
    use bdk_wallet::bitcoin::hashes::{sha256, Hash};
    let chain_code = sha256::Hash::hash(&seed_bytes);
    extended_seed[32..].copy_from_slice(chain_code.as_ref());

    let secp = Secp256k1::new();

    // Create master key from extended seed
    // Use signet (mutinynet is a signet)
    let network = Network::Signet;
    let master = Xpriv::new_master(network, &extended_seed)?;

    // Derive BIP84 path for native segwit: m/84'/1'/0'/0/0
    // 1' = testnet/signet coin type
    let path: DerivationPath = "m/84'/1'/0'/0/0".parse()?;
    let derived = master.derive_priv(&secp, &path)?;

    // Get the public key and create address
    let private_key = PrivateKey::new(derived.private_key, network);
    let public_key = CompressedPublicKey::from_private_key(&secp, &private_key)?;
    let address = Address::p2wpkh(&public_key, network);

    println!("Treasury Address (Mutinynet/Signet):");
    println!("{}", address);
    println!();
    println!("Fund from: https://faucet.mutinynet.com/");
    println!();
    println!("Derivation: m/84'/1'/0'/0/0 (BIP84 Native SegWit)");
    println!("Seed file: {}", seed_path.display());

    Ok(())
}
