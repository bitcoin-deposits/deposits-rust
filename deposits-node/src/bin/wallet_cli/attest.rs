//! Subkey attestation commands (DEP-04 §"Subkey Attestation").
//!
//! A root identity ("account") delegates authority to independent
//! subkey identities by:
//!
//!   1. Signing `SHA256("nostr301:" + subkey_xonly_hex)` with BIP-340
//!      Schnorr. Subkey events include this signature as
//!      `["va", "<hex>"]` + the account pubkey as `["v", "<hex>"]`.
//!   2. Publishing a Kind 10301 replaceable event listing all
//!      currently-authorized subkeys in `inbox_keys` and any revoked
//!      ones in `revoked_subkeys`. Verifiers consult this list
//!      before trusting a delegated signature.
//!
//! This module exposes three commands on the wallet CLI:
//!   - `attest <subkey>`      add a subkey (prints the attestation sig)
//!   - `revoke <subkey>`      move a subkey from inbox_keys to revoked
//!   - `subkeys`              print the current list
//!
//! The wallet signs with its Nostr identity (seed-derived by default,
//! or the `--nsec-file` override), so the account pubkey that signs
//! the attestation is whatever identity the wallet is currently
//! running as.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};

use super::{parse_config, NostrTransportBuilder};

/// Parse an npub1 or 64-char hex pubkey into xonly hex (always 64 chars).
fn parse_target_xonly(s: &str) -> Result<String, Box<dyn std::error::Error>> {
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
        // Strip compressed prefix (02/03) — common mistake.
        return Ok(s[2..].to_lowercase());
    }
    Err(format!("expected npub1... or 64-char hex, got {:?}", s).into())
}

/// Our xonly pubkey (for publishing + self-lookup in the Kind 10301 list).
fn our_xonly(
    config: &super::WalletConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    let sk = config.nostr_key()?;
    let secp = Secp256k1::new();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let (xo, _) = pk.x_only_public_key();
    Ok(hex::encode(xo.serialize()))
}

/// Sign the DEP-04 attestation message `SHA256("nostr301:<subkey>")`.
fn sign_attestation(
    config: &super::WalletConfig,
    subkey_xonly_hex: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let sk = config.nostr_key()?;
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &sk);

    let message_str = format!("nostr301:{}", subkey_xonly_hex);
    let digest = sha256::Hash::hash(message_str.as_bytes());
    let msg = Message::from_digest(digest.to_byte_array());
    let sig = secp.sign_schnorr(&msg, &kp);
    Ok(hex::encode(sig.serialize()))
}

/// `deposits-wallet attest <subkey>`: add a subkey to the account's
/// Kind 10301 list, publish the signed attestation signature, and
/// print the signature so the subkey holder can attach it to their
/// own events via the `["va", "<sig>"]` tag.
pub async fn attest_subkey(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut target: Option<String> = None;
    let mut config_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if target.is_none() {
            target = Some(args[i].clone());
        }
        i += 1;
    }
    let target = target.ok_or(
        "Usage: deposits-wallet attest <subkey_npub_or_hex> [--nsec-file <path>] --relay <url>",
    )?;
    let config = parse_config(&config_args)?;
    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let subkey_hex = parse_target_xonly(&target)?;
    let account_hex = our_xonly(&config)?;

    if subkey_hex == account_hex {
        return Err("Refusing to attest yourself as a subkey (account == subkey)".into());
    }

    let sig = sign_attestation(&config, &subkey_hex)?;

    // Load the current Kind 10301 list (if any) so we preserve prior
    // inbox_keys and revoked_subkeys — replaceable events overwrite on
    // publish, so a partial update would silently drop them.
    let nostr_key = config.nostr_key()?;
    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;
    let (mut inbox, mut revoked) = transport.fetch_subkey_list(&account_hex).await?;

    // If the subkey was previously revoked, un-revoke; always ensure it's
    // in inbox_keys without duplicates.
    revoked.retain(|k| k != &subkey_hex);
    if !inbox.iter().any(|k| k == &subkey_hex) {
        inbox.push(subkey_hex.clone());
    }

    let event_id = transport.publish_subkey_list(&inbox, &revoked).await?;

    println!("Subkey attested.");
    println!("  account:      {}", account_hex);
    println!("  subkey:       {}", subkey_hex);
    println!("  attestation:  {}", sig);
    println!("  10301 event:  {}...", &event_id[..16]);
    println!();
    println!("Share the attestation signature with the subkey holder.");
    println!("Their events should carry these two tags to verify as you:");
    println!("  [\"v\",  \"{}\"]", account_hex);
    println!("  [\"va\", \"{}\"]", sig);

    Ok(())
}

/// `deposits-wallet revoke <subkey>`: move a subkey from inbox_keys
/// into revoked_subkeys, republish the Kind 10301 list. The existing
/// attestation signature remains cryptographically valid; revocation
/// is a policy decision by verifiers, not a cryptographic invalidation.
pub async fn revoke_subkey(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut target: Option<String> = None;
    let mut config_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if target.is_none() {
            target = Some(args[i].clone());
        }
        i += 1;
    }
    let target = target.ok_or("Usage: deposits-wallet revoke <subkey_npub_or_hex> --relay <url>")?;
    let config = parse_config(&config_args)?;
    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let subkey_hex = parse_target_xonly(&target)?;
    let account_hex = our_xonly(&config)?;

    let nostr_key = config.nostr_key()?;
    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;
    let (mut inbox, mut revoked) = transport.fetch_subkey_list(&account_hex).await?;

    let was_active = inbox.iter().any(|k| k == &subkey_hex);
    inbox.retain(|k| k != &subkey_hex);
    if !revoked.iter().any(|k| k == &subkey_hex) {
        revoked.push(subkey_hex.clone());
    }

    let event_id = transport.publish_subkey_list(&inbox, &revoked).await?;
    println!(
        "Subkey {} ({}).",
        if was_active { "revoked" } else { "marked revoked (was already inactive)" },
        &subkey_hex[..16]
    );
    println!("  10301 event: {}...", &event_id[..16]);
    Ok(())
}

/// `deposits-wallet subkeys`: print the account's current Kind 10301
/// list (or fetch for another account via `--account <npub_or_hex>`).
pub async fn list_subkeys(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut account_override: Option<String> = None;
    let mut config_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--account" if i + 1 < args.len() => {
                account_override = Some(args[i + 1].clone());
                i += 1;
            }
            _ => {
                config_args.push(args[i].clone());
                if args[i].starts_with("--")
                    && i + 1 < args.len()
                    && !args[i + 1].starts_with("--")
                {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
        }
        i += 1;
    }
    let config = parse_config(&config_args)?;
    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let account_hex = match account_override {
        Some(s) => parse_target_xonly(&s)?,
        None => our_xonly(&config)?,
    };

    let nostr_key = config.nostr_key()?;
    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;
    let (inbox, revoked) = transport.fetch_subkey_list(&account_hex).await?;

    println!("Subkey list for {}", &account_hex[..16]);
    if inbox.is_empty() && revoked.is_empty() {
        println!("  (no 10301 event published)");
        return Ok(());
    }
    if !inbox.is_empty() {
        println!("  active ({}):", inbox.len());
        for k in &inbox {
            println!("    {}", k);
        }
    }
    if !revoked.is_empty() {
        println!("  revoked ({}):", revoked.len());
        for k in &revoked {
            println!("    {}", k);
        }
    }
    Ok(())
}
