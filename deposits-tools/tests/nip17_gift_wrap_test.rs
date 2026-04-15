//! NIP-17 Gift Wrap encryption tests
//! Tests the full gift wrap flow: create -> transmit -> unwrap
//! This validates that our server and client implementations are compatible.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
// chacha20poly1305 import removed - using chacha20 stream cipher directly per NIP-44 spec
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// =============================================================================
// NIP-44 Helper Functions (same as nip44_test.rs)
// =============================================================================

fn ecdh_raw_x(our_secret: &SecretKey, their_pubkey: &PublicKey) -> [u8; 32] {
    use bitcoin::secp256k1::ecdh::shared_secret_point;
    let shared_point = shared_secret_point(their_pubkey, our_secret);
    let mut x_coord = [0u8; 32];
    x_coord.copy_from_slice(&shared_point[..32]);
    x_coord
}

fn get_conversation_key(our_secret: &SecretKey, their_xonly: &XOnlyPublicKey) -> [u8; 32] {
    // Convert x-only to full pubkey (assume even y)
    let their_bytes = their_xonly.serialize();
    let mut full_pubkey_bytes = [0u8; 33];
    full_pubkey_bytes[0] = 0x02;
    full_pubkey_bytes[1..].copy_from_slice(&their_bytes);
    let their_full_pubkey = PublicKey::from_slice(&full_pubkey_bytes).unwrap();

    let shared_x = ecdh_raw_x(our_secret, &their_full_pubkey);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(b"nip44-v2").unwrap();
    mac.update(&shared_x);
    let result = mac.finalize();

    let mut conversation_key = [0u8; 32];
    conversation_key.copy_from_slice(&result.into_bytes());
    conversation_key
}

fn calc_padded_len(unpadded_len: usize) -> usize {
    if unpadded_len <= 32 {
        return 32;
    }
    let next_power = 1usize << ((unpadded_len - 1) as u64).ilog2() as usize + 1;
    let chunk = (next_power / 8).max(32);
    chunk * ((unpadded_len - 1) / chunk + 1)
}

fn pad_plaintext(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let padded_len = calc_padded_len(len);
    let mut padded = Vec::with_capacity(2 + padded_len);
    padded.push((len >> 8) as u8);
    padded.push(len as u8);
    padded.extend_from_slice(data);
    padded.resize(2 + padded_len, 0);
    padded
}

fn unpad_plaintext(data: &[u8]) -> Vec<u8> {
    let len = ((data[0] as usize) << 8) | (data[1] as usize);
    data[2..2 + len].to_vec()
}

fn nip44_encrypt(conversation_key: &[u8; 32], plaintext: &str) -> String {
    use chacha20::{
        cipher::{KeyIvInit, StreamCipher},
        ChaCha20,
    };

    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let hk = Hkdf::<Sha256>::from_prk(conversation_key).unwrap();
    let mut full_key_material = [0u8; 76];
    hk.expand(&nonce, &mut full_key_material).unwrap();

    let chacha_key: [u8; 32] = full_key_material[0..32].try_into().unwrap();
    let chacha_nonce: [u8; 12] = full_key_material[32..44].try_into().unwrap();
    let hmac_key: [u8; 32] = full_key_material[44..76].try_into().unwrap();

    let padded = pad_plaintext(plaintext.as_bytes());
    let mut cipher = ChaCha20::new(&chacha_key.into(), &chacha_nonce.into());
    let mut ciphertext = padded;
    cipher.apply_keystream(&mut ciphertext);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_key).unwrap();
    mac.update(&nonce);
    mac.update(&ciphertext);
    let hmac_result = mac.finalize().into_bytes();

    let mut payload = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
    payload.push(2); // NIP44_VERSION
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&hmac_result);

    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&payload)
}

fn nip44_decrypt(conversation_key: &[u8; 32], payload_b64: &str) -> Result<String, String> {
    use base64::Engine;
    use chacha20::{
        cipher::{KeyIvInit, StreamCipher},
        ChaCha20,
    };

    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    if payload.len() < 1 + 32 + 34 + 32 {
        return Err("Payload too short".into());
    }
    if payload[0] != 2 {
        return Err(format!("Unsupported version: {}", payload[0]));
    }

    let nonce: [u8; 32] = payload[1..33].try_into().unwrap();
    let ciphertext_with_hmac = &payload[33..];
    let ciphertext = &ciphertext_with_hmac[..ciphertext_with_hmac.len() - 32];
    let received_hmac = &ciphertext_with_hmac[ciphertext_with_hmac.len() - 32..];

    let hk = Hkdf::<Sha256>::from_prk(conversation_key).unwrap();
    let mut full_key_material = [0u8; 76];
    hk.expand(&nonce, &mut full_key_material).unwrap();

    let chacha_key: [u8; 32] = full_key_material[0..32].try_into().unwrap();
    let chacha_nonce: [u8; 12] = full_key_material[32..44].try_into().unwrap();
    let hmac_key: [u8; 32] = full_key_material[44..76].try_into().unwrap();

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_key).unwrap();
    mac.update(&nonce);
    mac.update(ciphertext);
    mac.verify_slice(received_hmac)
        .map_err(|_| "HMAC verification failed")?;

    let mut cipher = ChaCha20::new(&chacha_key.into(), &chacha_nonce.into());
    let mut padded = ciphertext.to_vec();
    cipher.apply_keystream(&mut padded);

    let plaintext = unpad_plaintext(&padded);
    String::from_utf8(plaintext).map_err(|e| format!("UTF-8 decode failed: {}", e))
}

// =============================================================================
// NIP-17 Gift Wrap Functions
// =============================================================================

/// Create a gift-wrapped DM (NIP-17)
/// Returns the complete gift wrap event as JSON
fn create_gift_wrap(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    sender_keypair: &Keypair,
    recipient_xonly: &XOnlyPublicKey,
    content: &str,
) -> Value {
    let (sender_xonly, _) = XOnlyPublicKey::from_keypair(sender_keypair);
    let mut rng = rand::thread_rng();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 1. Create kind 14 rumor (unsigned)
    let rumor_created_at = now - (rng.next_u64() % 172800);
    let rumor = json!({
        "kind": 14,
        "content": content,
        "pubkey": sender_xonly.to_string(),
        "created_at": rumor_created_at,
        "tags": [["p", recipient_xonly.to_string()]]
    });

    // 2. Create kind 13 seal (encrypt rumor with sender's key to recipient)
    let seal_conv_key = get_conversation_key(&sender_keypair.secret_key(), recipient_xonly);
    let encrypted_rumor = nip44_encrypt(&seal_conv_key, &rumor.to_string());

    let seal_created_at = now - (rng.next_u64() % 172800);
    let seal_data = json!([
        0,
        sender_xonly.to_string(),
        seal_created_at,
        13,
        [],
        encrypted_rumor
    ]);
    let seal_id = sha256::Hash::hash(seal_data.to_string().as_bytes());
    let seal_id_hex = hex::encode(seal_id.as_byte_array());
    let seal_message =
        bitcoin::secp256k1::Message::from_digest_slice(seal_id.as_byte_array()).unwrap();
    let seal_sig = secp.sign_schnorr(&seal_message, sender_keypair);

    let seal = json!({
        "id": seal_id_hex,
        "kind": 13,
        "content": encrypted_rumor,
        "pubkey": sender_xonly.to_string(),
        "created_at": seal_created_at,
        "tags": [],
        "sig": seal_sig.to_string()
    });

    // 3. Create kind 1059 gift wrap with ephemeral key
    let mut ephemeral_secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_secret_bytes);
    let ephemeral_secret = SecretKey::from_slice(&ephemeral_secret_bytes).unwrap();
    let ephemeral_keypair = Keypair::from_secret_key(secp, &ephemeral_secret);
    let (ephemeral_xonly, _) = XOnlyPublicKey::from_keypair(&ephemeral_keypair);

    let wrap_conv_key = get_conversation_key(&ephemeral_secret, recipient_xonly);
    let encrypted_seal = nip44_encrypt(&wrap_conv_key, &seal.to_string());

    let wrap_created_at = now - (rng.next_u64() % 172800);
    let wrap_data = json!([
        0,
        ephemeral_xonly.to_string(),
        wrap_created_at,
        1059,
        [["p", recipient_xonly.to_string()]],
        encrypted_seal
    ]);
    let wrap_id = sha256::Hash::hash(wrap_data.to_string().as_bytes());
    let wrap_id_hex = hex::encode(wrap_id.as_byte_array());
    let wrap_message =
        bitcoin::secp256k1::Message::from_digest_slice(wrap_id.as_byte_array()).unwrap();
    let wrap_sig = secp.sign_schnorr(&wrap_message, &ephemeral_keypair);

    json!({
        "id": wrap_id_hex,
        "kind": 1059,
        "content": encrypted_seal,
        "pubkey": ephemeral_xonly.to_string(),
        "created_at": wrap_created_at,
        "tags": [["p", recipient_xonly.to_string()]],
        "sig": wrap_sig.to_string()
    })
}

/// Unwrap a gift-wrapped DM (NIP-17)
/// Returns (sender_pubkey, content)
fn unwrap_gift_wrap(
    recipient_secret: &SecretKey,
    event: &Value,
) -> Result<(String, String), String> {
    // Get ephemeral pubkey and encrypted content from gift wrap
    let ephemeral_pubkey_str = event
        .get("pubkey")
        .and_then(|p| p.as_str())
        .ok_or("Gift wrap missing pubkey")?;
    let ephemeral_xonly = XOnlyPublicKey::from_str(ephemeral_pubkey_str)
        .map_err(|e| format!("Invalid ephemeral pubkey: {}", e))?;

    let encrypted_seal = event
        .get("content")
        .and_then(|c| c.as_str())
        .ok_or("Gift wrap missing content")?;

    // Decrypt gift wrap layer
    let wrap_conv_key = get_conversation_key(recipient_secret, &ephemeral_xonly);
    let seal_json = nip44_decrypt(&wrap_conv_key, encrypted_seal)?;

    // Parse seal
    let seal: Value =
        serde_json::from_str(&seal_json).map_err(|e| format!("Invalid seal JSON: {}", e))?;

    let sender_pubkey_str = seal
        .get("pubkey")
        .and_then(|p| p.as_str())
        .ok_or("Seal missing pubkey")?;
    let sender_xonly = XOnlyPublicKey::from_str(sender_pubkey_str)
        .map_err(|e| format!("Invalid sender pubkey: {}", e))?;

    let encrypted_rumor = seal
        .get("content")
        .and_then(|c| c.as_str())
        .ok_or("Seal missing content")?;

    // Decrypt seal layer
    let seal_conv_key = get_conversation_key(recipient_secret, &sender_xonly);
    let rumor_json = nip44_decrypt(&seal_conv_key, encrypted_rumor)?;

    // Parse rumor and extract content
    let rumor: Value =
        serde_json::from_str(&rumor_json).map_err(|e| format!("Invalid rumor JSON: {}", e))?;

    let content = rumor
        .get("content")
        .and_then(|c| c.as_str())
        .ok_or("Rumor missing content")?;

    Ok((sender_pubkey_str.to_string(), content.to_string()))
}

use std::str::FromStr;

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_gift_wrap_roundtrip() {
    let secp = Secp256k1::new();

    // Generate sender keypair
    let mut sender_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sender_secret_bytes);
    let sender_secret = SecretKey::from_slice(&sender_secret_bytes).unwrap();
    let sender_keypair = Keypair::from_secret_key(&secp, &sender_secret);
    let (sender_xonly, _) = XOnlyPublicKey::from_keypair(&sender_keypair);

    // Generate recipient keypair
    let mut recipient_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut recipient_secret_bytes);
    let recipient_secret = SecretKey::from_slice(&recipient_secret_bytes).unwrap();
    let recipient_keypair = Keypair::from_secret_key(&secp, &recipient_secret);
    let (recipient_xonly, _) = XOnlyPublicKey::from_keypair(&recipient_keypair);

    // Test messages
    let test_messages = [
        "init-deposit",
        "Hello, this is a test message!",
        r#"{"deposit_pubkey":"abc123","balance_sat":100000}"#,
        "Short",
        &"Long message ".repeat(100),
    ];

    for message in test_messages {
        // Create gift wrap
        let gift_wrap = create_gift_wrap(&secp, &sender_keypair, &recipient_xonly, message);

        // Verify it's kind 1059
        assert_eq!(gift_wrap["kind"], 1059, "Gift wrap should be kind 1059");

        // Unwrap as recipient
        let (recovered_sender, recovered_content) =
            unwrap_gift_wrap(&recipient_secret, &gift_wrap).expect("Failed to unwrap gift wrap");

        // Verify sender and content
        assert_eq!(
            recovered_sender,
            sender_xonly.to_string(),
            "Sender pubkey mismatch"
        );
        assert_eq!(
            recovered_content, message,
            "Content mismatch for message: {}",
            message
        );
    }
}

#[test]
fn test_gift_wrap_wrong_recipient_fails() {
    let secp = Secp256k1::new();

    // Generate sender keypair
    let mut sender_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sender_secret_bytes);
    let sender_secret = SecretKey::from_slice(&sender_secret_bytes).unwrap();
    let sender_keypair = Keypair::from_secret_key(&secp, &sender_secret);

    // Generate intended recipient keypair
    let mut recipient_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut recipient_secret_bytes);
    let recipient_secret = SecretKey::from_slice(&recipient_secret_bytes).unwrap();
    let recipient_keypair = Keypair::from_secret_key(&secp, &recipient_secret);
    let (recipient_xonly, _) = XOnlyPublicKey::from_keypair(&recipient_keypair);

    // Generate wrong recipient keypair
    let mut wrong_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut wrong_secret_bytes);
    let wrong_secret = SecretKey::from_slice(&wrong_secret_bytes).unwrap();

    // Create gift wrap for intended recipient
    let gift_wrap = create_gift_wrap(&secp, &sender_keypair, &recipient_xonly, "secret message");

    // Try to unwrap with wrong recipient - should fail
    let result = unwrap_gift_wrap(&wrong_secret, &gift_wrap);
    assert!(result.is_err(), "Unwrapping with wrong key should fail");
}

#[test]
fn test_gift_wrap_structure() {
    let secp = Secp256k1::new();

    // Generate keypairs
    let mut sender_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sender_secret_bytes);
    let sender_secret = SecretKey::from_slice(&sender_secret_bytes).unwrap();
    let sender_keypair = Keypair::from_secret_key(&secp, &sender_secret);

    let mut recipient_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut recipient_secret_bytes);
    let recipient_secret = SecretKey::from_slice(&recipient_secret_bytes).unwrap();
    let recipient_keypair = Keypair::from_secret_key(&secp, &recipient_secret);
    let (recipient_xonly, _) = XOnlyPublicKey::from_keypair(&recipient_keypair);

    let gift_wrap = create_gift_wrap(&secp, &sender_keypair, &recipient_xonly, "test");

    // Verify structure
    assert!(gift_wrap.get("id").is_some(), "Gift wrap should have id");
    assert_eq!(gift_wrap["kind"], 1059, "Gift wrap should be kind 1059");
    assert!(
        gift_wrap.get("pubkey").is_some(),
        "Gift wrap should have pubkey"
    );
    assert!(
        gift_wrap.get("content").is_some(),
        "Gift wrap should have content"
    );
    assert!(
        gift_wrap.get("created_at").is_some(),
        "Gift wrap should have created_at"
    );
    assert!(gift_wrap.get("sig").is_some(), "Gift wrap should have sig");
    assert!(
        gift_wrap.get("tags").is_some(),
        "Gift wrap should have tags"
    );

    // Verify p tag points to recipient
    let tags = gift_wrap["tags"].as_array().unwrap();
    assert_eq!(tags.len(), 1, "Gift wrap should have one tag");
    assert_eq!(tags[0][0], "p", "Tag should be p tag");
    assert_eq!(
        tags[0][1],
        recipient_xonly.to_string(),
        "p tag should contain recipient"
    );
}

#[test]
fn test_gift_wrap_ephemeral_key_is_unique() {
    let secp = Secp256k1::new();

    // Generate keypairs
    let mut sender_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sender_secret_bytes);
    let sender_secret = SecretKey::from_slice(&sender_secret_bytes).unwrap();
    let sender_keypair = Keypair::from_secret_key(&secp, &sender_secret);
    let (sender_xonly, _) = XOnlyPublicKey::from_keypair(&sender_keypair);

    let mut recipient_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut recipient_secret_bytes);
    let recipient_keypair = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&recipient_secret_bytes).unwrap(),
    );
    let (recipient_xonly, _) = XOnlyPublicKey::from_keypair(&recipient_keypair);

    // Create two gift wraps
    let gift_wrap1 = create_gift_wrap(&secp, &sender_keypair, &recipient_xonly, "test1");
    let gift_wrap2 = create_gift_wrap(&secp, &sender_keypair, &recipient_xonly, "test2");

    // Ephemeral keys should be different
    let pubkey1 = gift_wrap1["pubkey"].as_str().unwrap();
    let pubkey2 = gift_wrap2["pubkey"].as_str().unwrap();
    assert_ne!(pubkey1, pubkey2, "Ephemeral keys should be unique");

    // Neither should be the sender's key
    assert_ne!(
        pubkey1,
        sender_xonly.to_string(),
        "Ephemeral key should not be sender key"
    );
    assert_ne!(
        pubkey2,
        sender_xonly.to_string(),
        "Ephemeral key should not be sender key"
    );
}

#[test]
fn test_gift_wrap_bidirectional() {
    let secp = Secp256k1::new();

    // Generate Alice and Bob keypairs
    let mut alice_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut alice_secret_bytes);
    let alice_secret = SecretKey::from_slice(&alice_secret_bytes).unwrap();
    let alice_keypair = Keypair::from_secret_key(&secp, &alice_secret);
    let (alice_xonly, _) = XOnlyPublicKey::from_keypair(&alice_keypair);

    let mut bob_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bob_secret_bytes);
    let bob_secret = SecretKey::from_slice(&bob_secret_bytes).unwrap();
    let bob_keypair = Keypair::from_secret_key(&secp, &bob_secret);
    let (bob_xonly, _) = XOnlyPublicKey::from_keypair(&bob_keypair);

    // Alice sends to Bob
    let alice_to_bob = create_gift_wrap(&secp, &alice_keypair, &bob_xonly, "Hello Bob!");
    let (sender, content) = unwrap_gift_wrap(&bob_secret, &alice_to_bob).unwrap();
    assert_eq!(sender, alice_xonly.to_string());
    assert_eq!(content, "Hello Bob!");

    // Bob sends to Alice
    let bob_to_alice = create_gift_wrap(&secp, &bob_keypair, &alice_xonly, "Hello Alice!");
    let (sender, content) = unwrap_gift_wrap(&alice_secret, &bob_to_alice).unwrap();
    assert_eq!(sender, bob_xonly.to_string());
    assert_eq!(content, "Hello Alice!");
}

#[test]
fn test_gift_wrap_json_content() {
    let secp = Secp256k1::new();

    // Generate keypairs
    let mut sender_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sender_secret_bytes);
    let sender_keypair =
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sender_secret_bytes).unwrap());

    let mut recipient_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut recipient_secret_bytes);
    let recipient_secret = SecretKey::from_slice(&recipient_secret_bytes).unwrap();
    let recipient_keypair = Keypair::from_secret_key(&secp, &recipient_secret);
    let (recipient_xonly, _) = XOnlyPublicKey::from_keypair(&recipient_keypair);

    // Test with JSON content (typical deposit response)
    let json_content = json!({
        "deposit_pubkey": "02abc123def456",
        "channel_id": "channel123",
        "balance_sat": 100000,
        "nwc_connection_string": "nostr+walletconnect://..."
    })
    .to_string();

    let gift_wrap = create_gift_wrap(&secp, &sender_keypair, &recipient_xonly, &json_content);
    let (_, content) = unwrap_gift_wrap(&recipient_secret, &gift_wrap).unwrap();

    // Verify JSON can be parsed back
    let parsed: Value = serde_json::from_str(&content).expect("Should be valid JSON");
    assert_eq!(parsed["balance_sat"], 100000);
    assert_eq!(parsed["deposit_pubkey"], "02abc123def456");
}
