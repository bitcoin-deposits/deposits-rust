//! NIP-XX: Subkey Attestation and Management
//!
//! Separates identity from authentication using subkey attestations. A root
//! keypair (account0) signs attestations authorizing independent subkeys to
//! post on its behalf. If a subkey is compromised, the root key revokes it
//! via a Kind 10301 replaceable event.
//!
//! # Attestation
//!
//! The attestation message is `"nostr301:<hex-subkey-pubkey>"`, hashed with
//! SHA-256 and signed with BIP-340 Schnorr using the account key.
//!
//! # Event Tags
//!
//! Events signed by a subkey include:
//! - `["v", "<hex-account-pubkey>"]` — the account this subkey acts for
//! - `["va", "<hex-attestation-signature>"]` — proof of authorization
//!
//! # Kind 10301 (Replaceable)
//!
//! Published by the account key to manage subkeys:
//! ```json
//! {
//!   "inbox_keys": ["<hex-subkey1>", "<hex-subkey2>"],
//!   "revoked_subkeys": ["<hex-subkey3>"]
//! }
//! ```

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

/// Nostr event kind for subkey management (replaceable: 10000-19999).
pub const KIND_SUBKEY_MANAGEMENT: u16 = 10301;

/// Tag name for the account pubkey on subkey-signed events.
pub const TAG_ACCOUNT: &str = "v";

/// Tag name for the attestation signature on subkey-signed events.
pub const TAG_ATTESTATION: &str = "va";

/// Prefix for the attestation signing message.
const ATTESTATION_PREFIX: &str = "nostr301:";

/// Content of a Kind 10301 subkey management event.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubkeyManagement {
    /// Subkeys the account prefers for encrypted message delivery.
    #[serde(default)]
    pub inbox_keys: Vec<String>,
    /// Subkeys that have been revoked and should no longer be trusted.
    #[serde(default)]
    pub revoked_subkeys: Vec<String>,
}

/// Create the 32-byte message digest for an attestation.
///
/// The message is `SHA256("nostr301:<hex-subkey-pubkey>")`.
pub fn attestation_digest(subkey_pubkey: &XOnlyPublicKey) -> [u8; 32] {
    let msg = format!(
        "{}{}",
        ATTESTATION_PREFIX,
        hex::encode(subkey_pubkey.serialize())
    );
    sha256::Hash::hash(msg.as_bytes()).to_byte_array()
}

/// Create a subkey attestation: the account key signs authorization for the subkey.
///
/// Returns the 64-byte Schnorr signature as a hex string.
pub fn create_attestation(account_secret: &SecretKey, subkey_pubkey: &XOnlyPublicKey) -> String {
    let secp = Secp256k1::signing_only();
    let keypair = Keypair::from_secret_key(&secp, account_secret);
    let digest = attestation_digest(subkey_pubkey);
    let msg = Message::from_digest(digest);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    hex::encode(sig.serialize())
}

/// Verify a subkey attestation.
///
/// Checks that `attestation_hex` is a valid Schnorr signature by `account_pubkey`
/// over the message `SHA256("nostr301:<hex-subkey-pubkey>")`.
pub fn verify_attestation(
    account_pubkey: &XOnlyPublicKey,
    subkey_pubkey: &XOnlyPublicKey,
    attestation_hex: &str,
) -> bool {
    let sig_bytes = match hex::decode(attestation_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };

    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let digest = attestation_digest(subkey_pubkey);
    let msg = Message::from_digest(digest);
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&sig, &msg, account_pubkey).is_ok()
}

/// Validate the `v` / `va` tags on a nostr event.
///
/// Given the event's signing pubkey (the subkey), the `v` tag value (account
/// pubkey hex), and the `va` tag value (attestation hex), verify that the
/// account authorized this subkey.
///
/// Returns the parsed account `XOnlyPublicKey` on success.
pub fn validate_event_tags(
    subkey_pubkey_hex: &str,
    account_pubkey_hex: &str,
    attestation_hex: &str,
) -> Result<XOnlyPublicKey, String> {
    let account_bytes =
        hex::decode(account_pubkey_hex).map_err(|_| "Invalid account pubkey hex".to_string())?;
    let account_pubkey = XOnlyPublicKey::from_slice(&account_bytes)
        .map_err(|_| "Invalid account pubkey".to_string())?;

    let subkey_bytes =
        hex::decode(subkey_pubkey_hex).map_err(|_| "Invalid subkey pubkey hex".to_string())?;
    let subkey_pubkey = XOnlyPublicKey::from_slice(&subkey_bytes)
        .map_err(|_| "Invalid subkey pubkey".to_string())?;

    if verify_attestation(&account_pubkey, &subkey_pubkey, attestation_hex) {
        Ok(account_pubkey)
    } else {
        Err("Attestation signature invalid".to_string())
    }
}

/// Check if a subkey has been revoked by parsing a Kind 10301 event's content.
pub fn is_revoked(management_content: &str, subkey_pubkey_hex: &str) -> bool {
    let mgmt: SubkeyManagement = match serde_json::from_str(management_content) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let normalized = subkey_pubkey_hex.to_lowercase();
    mgmt.revoked_subkeys
        .iter()
        .any(|k| k.to_lowercase() == normalized)
}

/// Build the JSON content for a Kind 10301 subkey management event.
pub fn build_management_content(inbox_keys: &[&str], revoked_subkeys: &[&str]) -> String {
    let mgmt = SubkeyManagement {
        inbox_keys: inbox_keys.iter().map(|s| s.to_string()).collect(),
        revoked_subkeys: revoked_subkeys.iter().map(|s| s.to_string()).collect(),
    };
    serde_json::to_string(&mgmt).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    fn test_keypair(seed: u8) -> (SecretKey, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = keypair.x_only_public_key();
        (secret, xonly)
    }

    // -- attestation creation and verification --

    #[test]
    fn create_and_verify_attestation() {
        let (account_secret, account_pubkey) = test_keypair(0xAA);
        let (_, subkey_pubkey) = test_keypair(0xBB);

        let attestation = create_attestation(&account_secret, &subkey_pubkey);
        assert_eq!(attestation.len(), 128); // 64 bytes hex-encoded
        assert!(verify_attestation(
            &account_pubkey,
            &subkey_pubkey,
            &attestation
        ));
    }

    #[test]
    fn attestation_wrong_account_fails() {
        let (account_secret, _) = test_keypair(0xAA);
        let (_, other_pubkey) = test_keypair(0xCC);
        let (_, subkey_pubkey) = test_keypair(0xBB);

        let attestation = create_attestation(&account_secret, &subkey_pubkey);
        assert!(!verify_attestation(
            &other_pubkey,
            &subkey_pubkey,
            &attestation
        ));
    }

    #[test]
    fn attestation_wrong_subkey_fails() {
        let (account_secret, account_pubkey) = test_keypair(0xAA);
        let (_, subkey_pubkey) = test_keypair(0xBB);
        let (_, other_subkey) = test_keypair(0xCC);

        let attestation = create_attestation(&account_secret, &subkey_pubkey);
        assert!(!verify_attestation(
            &account_pubkey,
            &other_subkey,
            &attestation
        ));
    }

    #[test]
    fn attestation_garbage_signature_fails() {
        let (_, account_pubkey) = test_keypair(0xAA);
        let (_, subkey_pubkey) = test_keypair(0xBB);

        assert!(!verify_attestation(
            &account_pubkey,
            &subkey_pubkey,
            "not_hex"
        ));
        assert!(!verify_attestation(
            &account_pubkey,
            &subkey_pubkey,
            "deadbeef"
        ));
        assert!(!verify_attestation(
            &account_pubkey,
            &subkey_pubkey,
            &"00".repeat(64)
        ));
    }

    #[test]
    fn attestation_deterministic() {
        let (account_secret, _) = test_keypair(0xAA);
        let (_, subkey_pubkey) = test_keypair(0xBB);

        let a1 = create_attestation(&account_secret, &subkey_pubkey);
        let a2 = create_attestation(&account_secret, &subkey_pubkey);
        assert_eq!(a1, a2); // no aux rand = deterministic
    }

    // -- digest --

    #[test]
    fn digest_includes_prefix() {
        let (_, subkey_pubkey) = test_keypair(0xBB);
        let hex_pk = hex::encode(subkey_pubkey.serialize());
        let expected_msg = format!("nostr301:{}", hex_pk);
        let expected_digest = sha256::Hash::hash(expected_msg.as_bytes()).to_byte_array();
        assert_eq!(attestation_digest(&subkey_pubkey), expected_digest);
    }

    #[test]
    fn digest_different_keys_differ() {
        let (_, pk1) = test_keypair(0xAA);
        let (_, pk2) = test_keypair(0xBB);
        assert_ne!(attestation_digest(&pk1), attestation_digest(&pk2));
    }

    // -- validate_event_tags --

    #[test]
    fn validate_event_tags_valid() {
        let (account_secret, account_pubkey) = test_keypair(0xAA);
        let (_, subkey_pubkey) = test_keypair(0xBB);

        let attestation = create_attestation(&account_secret, &subkey_pubkey);
        let account_hex = hex::encode(account_pubkey.serialize());
        let subkey_hex = hex::encode(subkey_pubkey.serialize());

        let result = validate_event_tags(&subkey_hex, &account_hex, &attestation);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), account_pubkey);
    }

    #[test]
    fn validate_event_tags_invalid_attestation() {
        let (_, account_pubkey) = test_keypair(0xAA);
        let (_, subkey_pubkey) = test_keypair(0xBB);

        let account_hex = hex::encode(account_pubkey.serialize());
        let subkey_hex = hex::encode(subkey_pubkey.serialize());

        let result = validate_event_tags(&subkey_hex, &account_hex, &"ff".repeat(64));
        assert!(result.is_err());
    }

    #[test]
    fn validate_event_tags_bad_hex() {
        assert!(validate_event_tags("zzzz", "aaaa", "bbbb").is_err());
    }

    // -- revocation --

    #[test]
    fn is_revoked_true() {
        let (_, subkey_pubkey) = test_keypair(0xBB);
        let hex_pk = hex::encode(subkey_pubkey.serialize());
        let content = format!(r#"{{"inbox_keys": [], "revoked_subkeys": ["{}"]}}"#, hex_pk);
        assert!(is_revoked(&content, &hex_pk));
    }

    #[test]
    fn is_revoked_false() {
        let (_, subkey_pubkey) = test_keypair(0xBB);
        let (_, other_pubkey) = test_keypair(0xCC);
        let hex_pk = hex::encode(subkey_pubkey.serialize());
        let other_hex = hex::encode(other_pubkey.serialize());
        let content = format!(
            r#"{{"inbox_keys": [], "revoked_subkeys": ["{}"]}}"#,
            other_hex
        );
        assert!(!is_revoked(&content, &hex_pk));
    }

    #[test]
    fn is_revoked_empty() {
        let content = r#"{"inbox_keys": [], "revoked_subkeys": []}"#;
        assert!(!is_revoked(content, "aabbccdd"));
    }

    #[test]
    fn is_revoked_case_insensitive() {
        let content = r#"{"inbox_keys": [], "revoked_subkeys": ["AABB"]}"#;
        assert!(is_revoked(content, "aabb"));
    }

    #[test]
    fn is_revoked_bad_json() {
        assert!(!is_revoked("not json", "aabb"));
    }

    // -- management content --

    #[test]
    fn build_management_content_roundtrip() {
        let content = build_management_content(&["aabb", "ccdd"], &["eeff"]);
        let parsed: SubkeyManagement = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.inbox_keys, vec!["aabb", "ccdd"]);
        assert_eq!(parsed.revoked_subkeys, vec!["eeff"]);
    }

    #[test]
    fn build_management_content_empty() {
        let content = build_management_content(&[], &[]);
        let parsed: SubkeyManagement = serde_json::from_str(&content).unwrap();
        assert!(parsed.inbox_keys.is_empty());
        assert!(parsed.revoked_subkeys.is_empty());
    }

    // -- full workflow test --

    #[test]
    fn full_subkey_lifecycle() {
        let (account_secret, account_pubkey) = test_keypair(0xAA);
        let (_, subkey1) = test_keypair(0xBB);
        let (_, subkey2) = test_keypair(0xCC);

        let account_hex = hex::encode(account_pubkey.serialize());
        let subkey1_hex = hex::encode(subkey1.serialize());
        let subkey2_hex = hex::encode(subkey2.serialize());

        // Account attests both subkeys
        let att1 = create_attestation(&account_secret, &subkey1);
        let att2 = create_attestation(&account_secret, &subkey2);

        // Both are valid
        assert!(validate_event_tags(&subkey1_hex, &account_hex, &att1).is_ok());
        assert!(validate_event_tags(&subkey2_hex, &account_hex, &att2).is_ok());

        // Cross-use fails (att1 doesn't authorize subkey2)
        assert!(validate_event_tags(&subkey2_hex, &account_hex, &att1).is_err());

        // Account revokes subkey1
        let mgmt = build_management_content(
            &[&subkey2_hex], // only subkey2 for inbox
            &[&subkey1_hex], // subkey1 revoked
        );

        assert!(is_revoked(&mgmt, &subkey1_hex));
        assert!(!is_revoked(&mgmt, &subkey2_hex));

        // The attestation signature is still cryptographically valid
        // (revocation is a policy check, not a crypto check)
        assert!(verify_attestation(&account_pubkey, &subkey1, &att1));
    }
}
