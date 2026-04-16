// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;
use std::str::FromStr;

pub fn keygen() {
    use bitcoin::secp256k1::rand::rngs::OsRng;

    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);

    // Output: secret_key_hex public_key_hex
    println!("{} {}", hex::encode(secret_key.secret_bytes()), public_key);
}

/// Derive the wallet deposit secret key from seed.
/// This matches the derivation used by deposits-wallet at m/84'/0'/0'/0/{index}.
pub fn derive_deposit_key(args: &[String]) -> Result<(), String> {
    let mut seed: Option<[u8; 32]> = None;
    let mut network = Network::Signet;
    let mut index: u32 = 0;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                i += 1;
                if i >= args.len() {
                    return Err("--seed requires a value".to_string());
                }
                let hex_str = &args[i];
                if hex_str.len() != 64 {
                    return Err("Seed must be 64 hex characters".to_string());
                }
                let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                seed = Some(arr);
            }
            "--network" => {
                i += 1;
                if i >= args.len() {
                    return Err("--network requires a value".to_string());
                }
                network = match args[i].as_str() {
                    "mainnet" | "bitcoin" => Network::Bitcoin,
                    "testnet" | "testnet3" => Network::Testnet,
                    "signet" => Network::Signet,
                    "regtest" => Network::Regtest,
                    n => return Err(format!("Unknown network: {}", n)),
                };
            }
            "--index" => {
                i += 1;
                if i >= args.len() {
                    return Err("--index requires a value".to_string());
                }
                index = args[i]
                    .parse::<u32>()
                    .map_err(|e| format!("Invalid index: {}", e))?;
            }
            _ => {}
        }
        i += 1;
    }

    let seed = seed.ok_or("--seed is required")?;

    // Derive the deposit key using BIP-84 path (same as wallet)
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(network, &seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;

    let deposit_path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", index))
        .map_err(|e| format!("Invalid derivation path: {}", e))?;

    let deposit_xpriv = xpriv
        .derive_priv(&secp, &deposit_path)
        .map_err(|e| format!("Failed to derive deposit key: {}", e))?;

    let pubkey = PublicKey::from_secret_key(&secp, &deposit_xpriv.private_key);
    // Output compressed pubkey on stdout (for use with deposit open)
    // Secret key on stderr (for signing operations)
    println!("{}", pubkey);
    eprintln!(
        "secret: {}",
        hex::encode(deposit_xpriv.private_key.secret_bytes())
    );

    Ok(())
}
