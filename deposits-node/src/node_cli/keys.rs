// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;
use std::path::PathBuf;
use std::str::FromStr;

/// Print the P2WPKH address corresponding to a compressed-secp256k1
/// public key. This is the *operator-key* address — the one
/// `auto_arm_for_dispute` queries for replacement-collateral UTXOs, the one
/// `reserves spend` change-and-splits go to, and the one a recovery sweep
/// returns funds to.
///
/// With no positional pubkey, defaults to *this node's own pubkey* — the
/// same one `info` prints — derived from `--seed`/`--seed-file` via
/// `m/86'/0'/0'/0/0`. So under the typical `./docker/node-cli.sh <op>`
/// wrapper that pre-supplies the seed, plain `pubkey-to-p2wpkh` prints
/// that operator's own funding address.
///
/// We derive the address the same way the daemon does
/// (`bitcoin::Address::p2wpkh(CompressedPublicKey, network)`), so what's
/// printed here exactly matches what the daemon searches on-chain.
///
/// Usage:
///   deposits-node pubkey-to-p2wpkh [<66-char-hex-pubkey>] [--network <name>]
pub fn pubkey_to_p2wpkh(args: &[String]) -> Result<(), String> {
    let mut pubkey_hex: Option<String> = None;
    let mut network = Network::Bitcoin;
    let mut seed: Option<[u8; 32]> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--network" if i + 1 < args.len() => {
                network = match args[i + 1].as_str() {
                    "mainnet" | "bitcoin" => Network::Bitcoin,
                    "testnet" | "testnet3" => Network::Testnet,
                    "signet" => Network::Signet,
                    "regtest" => Network::Regtest,
                    other => return Err(format!("Unknown --network {:?}", other)),
                };
                i += 2;
            }
            "--seed" if i + 1 < args.len() => {
                let bytes = hex::decode(args[i + 1].trim())
                    .map_err(|e| format!("Invalid --seed hex: {}", e))?;
                if bytes.len() != 32 {
                    return Err("--seed must be 64 hex chars".to_string());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                seed = Some(arr);
                i += 2;
            }
            "--seed-file" if i + 1 < args.len() => {
                let path = &args[i + 1];
                let raw = std::fs::read_to_string(path)
                    .map_err(|e| format!("Read --seed-file {}: {}", path, e))?;
                let hex_str = raw.trim();
                let bytes = hex::decode(hex_str)
                    .map_err(|e| format!("Invalid hex in --seed-file: {}", e))?;
                if bytes.len() != 32 {
                    return Err("Seed in --seed-file must be 64 hex chars".to_string());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                seed = Some(arr);
                i += 2;
            }
            // Tolerate other flags that the wrapper script may forward
            // (e.g. --name, --data-dir, --network, --relay, --esplora) so
            // `./docker/node-cli.sh <op> pubkey-to-p2wpkh` works without
            // any extra args.
            s if s.starts_with("--") => {
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => {
                if pubkey_hex.is_none() {
                    pubkey_hex = Some(args[i].clone());
                }
                i += 1;
            }
        }
    }

    // Resolve the pubkey: explicit positional wins, else derive from seed.
    let arr: [u8; 33] = match pubkey_hex {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim())
                .map_err(|e| format!("Invalid hex: {}", e))?;
            if bytes.len() != 33 {
                return Err(format!(
                    "Pubkey must be 33 bytes compressed (66 hex chars); got {}",
                    bytes.len()
                ));
            }
            let mut a = [0u8; 33];
            a.copy_from_slice(&bytes);
            a
        }
        None => {
            let seed = seed.ok_or(
                "No pubkey provided and no --seed/--seed-file given to derive our own. \
                 Pass a pubkey positionally OR supply a seed.",
            )?;
            let sk = super::derive_operator_secret(&seed, network)?;
            let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
            pk.serialize()
        }
    };

    let compressed = bitcoin::CompressedPublicKey::from_slice(&arr)
        .map_err(|e| format!("Invalid compressed pubkey: {}", e))?;
    let addr = bitcoin::Address::p2wpkh(&compressed, network);
    println!("{}", addr);
    Ok(())
}

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

/// Print the daemon's *delegate Nostr pubkey* — the one used for
/// Nostr-layer ops (event signing, NIP-04 ECDH for inbound DMs).
/// Prefers a persisted `<data-dir>/delegate_secret` if one exists
/// (pre-derivation operators); otherwise derives the key from
/// `<data-dir>/seed.hex` at `m/85'/0'/0'/0/0`, matching the daemon's
/// `Signer::issue_nostr_secret`. What's printed here is what
/// subsequent Kind 39100 advertisements will carry as
/// `delegate_pubkey`.
///
/// Use case: admin tooling on the same host that needs to encrypt
/// NIP-04 DMs to the daemon (e.g. setup.sh's `reserves create` /
/// `ledger open` admin requests) before any advertisement has been
/// published.
pub fn delegate_pubkey(args: &[String]) -> Result<(), String> {
    let mut data_dir: Option<PathBuf> = None;
    let mut network = Network::Bitcoin;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                if i >= args.len() {
                    return Err("--data-dir requires a value".to_string());
                }
                data_dir = Some(PathBuf::from(&args[i]));
            }
            "--network" if i + 1 < args.len() => {
                network = match args[i + 1].as_str() {
                    "mainnet" | "bitcoin" => Network::Bitcoin,
                    "testnet" | "testnet3" => Network::Testnet,
                    "signet" => Network::Signet,
                    "regtest" => Network::Regtest,
                    other => return Err(format!("Unknown --network {:?}", other)),
                };
                i += 1;
            }
            other => return Err(format!("unknown flag {:?}", other)),
        }
        i += 1;
    }
    let data_dir = data_dir.ok_or_else(|| "missing --data-dir".to_string())?;
    if !data_dir.exists() {
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| format!("create_dir_all {}: {}", data_dir.display(), e))?;
    }
    let secp = Secp256k1::new();
    let secret = match crate::Node::load_persisted_delegate_secret(&data_dir)
        .map_err(|e| format!("load_persisted_delegate_secret: {}", e))?
    {
        Some(sk) => sk,
        None => {
            // Derive from seed at m/85'/0'/0'/0/0 (same path
            // LocalSigner uses for `issue_nostr_secret`).
            let seed_path = data_dir.join("seed.hex");
            let raw = std::fs::read_to_string(&seed_path).map_err(|e| {
                format!(
                    "no persisted delegate_secret and seed.hex not readable at {}: {}",
                    seed_path.display(),
                    e
                )
            })?;
            let bytes = hex::decode(raw.trim())
                .map_err(|e| format!("seed.hex hex decode: {}", e))?;
            if bytes.len() != 32 {
                return Err("seed.hex must be 64 hex chars".to_string());
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            let xpriv = Xpriv::new_master(network, &seed)
                .map_err(|e| format!("xpriv from seed: {}", e))?;
            let path = DerivationPath::from_str("m/85'/0'/0'/0/0")
                .map_err(|e| format!("delegate path: {}", e))?;
            let derived = xpriv
                .derive_priv(&secp, &path)
                .map_err(|e| format!("derive delegate: {}", e))?;
            derived.private_key
        }
    };
    let pubkey = PublicKey::from_secret_key(&secp, &secret);
    println!("{}", hex::encode(pubkey.serialize()));
    Ok(())
}

/// Print the daemon's transport pubkey (the one a `deposits-signer` allowlist
/// must contain). Idempotent: generates a fresh transport keypair under
/// `<data-dir>/transport_secret` if absent, otherwise reads the persisted one.
/// Same code path as `Node::new` takes when bootstrapping `RemoteSigner`,
/// so the pubkey printed here is exactly what the daemon will present
/// during the handshake.
///
/// Use case: cluster bring-up scripts that need to allowlist the daemon
/// on the signer side *before* starting either process.
pub fn transport_pubkey(args: &[String]) -> Result<(), String> {
    let mut data_dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                if i >= args.len() {
                    return Err("--data-dir requires a value".to_string());
                }
                data_dir = Some(PathBuf::from(&args[i]));
            }
            other => return Err(format!("unknown flag {:?}", other)),
        }
        i += 1;
    }
    let data_dir = data_dir.ok_or_else(|| "missing --data-dir".to_string())?;
    if !data_dir.exists() {
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| format!("create_dir_all {}: {}", data_dir.display(), e))?;
    }
    let secret = crate::Node::load_or_init_transport_secret(&data_dir)
        .map_err(|e| format!("load_or_init_transport_secret: {}", e))?;
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, &secret);
    // 33-byte compressed hex on stdout (single line, no trailing prose),
    // for trivial bash capture: `pk=$(deposits-node transport-pubkey ...)`.
    println!("{}", hex::encode(pubkey.serialize()));
    Ok(())
}
