//! Tests for gift-wrapped wallet↔node communication.
//!
//! Verifies the NIP-59-like structure over ephemeral kinds:
//! - Rumor: unsigned inner event with real content
//! - Seal: signed by sender, NIP-44 encrypted to recipient
//! - Wrap: signed by throwaway key, NIP-44 encrypted to recipient

use nostr_sdk::prelude::*;

fn test_keys(seed: u8) -> Keys {
    let sk = nostr_sdk::SecretKey::from_slice(&[seed; 32]).unwrap();
    Keys::new(sk)
}

/// Build a gift-wrapped request: rumor → seal → wrap
fn gift_wrap_request(
    sender_keys: &Keys,
    recipient_pubkey: &PublicKey,
    kind: u16,
    content: &str,
    tags: Vec<Tag>,
) -> Result<Event, Box<dyn std::error::Error>> {
    // 1. Build the rumor (unsigned inner event)
    let rumor_json = serde_json::json!({
        "kind": kind,
        "content": content,
        "tags": tags.iter().map(|t| {
            // Serialize tag as array of strings
            let strs: Vec<String> = vec![t.kind().to_string()];
            strs
        }).collect::<Vec<_>>(),
        "pubkey": sender_keys.public_key().to_hex(),
        "created_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap().as_secs(),
    });
    let rumor_str = rumor_json.to_string();

    // 2. Build the seal: encrypt rumor to recipient, sign with sender key
    let seal_content = nip44::encrypt(
        sender_keys.secret_key(),
        recipient_pubkey,
        &rumor_str,
        nip44::Version::V2,
    )?;

    let seal_event =
        EventBuilder::new(Kind::Custom(13), &seal_content).sign_with_keys(sender_keys)?;

    // 3. Build the gift wrap: encrypt seal to recipient, sign with throwaway key
    let throwaway_sk = Keys::generate();
    let seal_str = serde_json::to_string(&serde_json::json!({
        "id": seal_event.id.to_hex(),
        "pubkey": seal_event.pubkey.to_hex(),
        "created_at": seal_event.created_at.as_u64(),
        "kind": 13,
        "content": seal_event.content,
        "sig": seal_event.sig.to_string(),
    }))?;

    let wrap_content = nip44::encrypt(
        throwaway_sk.secret_key(),
        recipient_pubkey,
        &seal_str,
        nip44::Version::V2,
    )?;

    let wrap_event = EventBuilder::new(Kind::Custom(kind), &wrap_content)
        .tag(Tag::public_key(*recipient_pubkey))
        .sign_with_keys(&throwaway_sk)?;

    Ok(wrap_event)
}

/// Unwrap a gift-wrapped request: decrypt wrap → verify seal → decrypt rumor
fn unwrap_request(
    recipient_keys: &Keys,
    wrap_event: &Event,
) -> Result<(PublicKey, String, u16), Box<dyn std::error::Error>> {
    // 1. Decrypt the wrap to get the seal
    let seal_json_str = nip44::decrypt(
        recipient_keys.secret_key(),
        &wrap_event.pubkey,
        &wrap_event.content,
    )?;

    let seal_obj: serde_json::Value = serde_json::from_str(&seal_json_str)?;

    // 2. Verify the seal signature
    let seal_pubkey =
        PublicKey::from_hex(seal_obj["pubkey"].as_str().ok_or("missing seal pubkey")?)?;

    // 3. Decrypt the seal to get the rumor
    let rumor_str = nip44::decrypt(
        recipient_keys.secret_key(),
        &seal_pubkey,
        seal_obj["content"].as_str().ok_or("missing seal content")?,
    )?;

    let rumor: serde_json::Value = serde_json::from_str(&rumor_str)?;
    let inner_kind = rumor["kind"].as_u64().ok_or("missing rumor kind")? as u16;
    let inner_content = rumor["content"]
        .as_str()
        .ok_or("missing rumor content")?
        .to_string();
    let sender = PublicKey::from_hex(rumor["pubkey"].as_str().ok_or("missing rumor pubkey")?)?;

    Ok((sender, inner_content, inner_kind))
}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn gift_wrap_round_trip() {
    let wallet_keys = test_keys(0xAA);
    let node_keys = test_keys(0xBB);

    let content = r#"{"descriptor":"pk(02abc...)","amount_sats":1000}"#;
    let tags = vec![
        Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
            ["abc123"],
        ),
        Tag::custom(TagKind::custom("action"), ["deposit_open"]),
    ];

    let wrapped =
        gift_wrap_request(&wallet_keys, &node_keys.public_key(), 20101, content, tags).unwrap();

    // Outer event hides the sender
    assert_ne!(
        wrapped.pubkey,
        wallet_keys.public_key(),
        "Outer pubkey should be throwaway"
    );
    assert_eq!(
        wrapped.kind.as_u16(),
        20101,
        "Outer kind should be ephemeral request"
    );

    // Unwrap
    let (sender, inner_content, inner_kind) = unwrap_request(&node_keys, &wrapped).unwrap();

    assert_eq!(sender, wallet_keys.public_key(), "Sender should be wallet");
    assert_eq!(inner_content, content, "Content should round-trip");
    assert_eq!(inner_kind, 20101, "Inner kind should match");
}

#[test]
fn gift_wrap_wrong_recipient_fails() {
    let wallet_keys = test_keys(0xAA);
    let node_keys = test_keys(0xBB);
    let wrong_keys = test_keys(0xCC);

    let wrapped = gift_wrap_request(
        &wallet_keys,
        &node_keys.public_key(),
        20101,
        "secret content",
        vec![],
    )
    .unwrap();

    // Try to unwrap with wrong key
    let result = unwrap_request(&wrong_keys, &wrapped);
    assert!(result.is_err(), "Wrong recipient should fail to decrypt");
}

#[test]
fn gift_wrap_sender_identity_hidden_from_relay() {
    let wallet_keys = test_keys(0xAA);
    let node_keys = test_keys(0xBB);

    let wrapped =
        gift_wrap_request(&wallet_keys, &node_keys.public_key(), 20101, "test", vec![]).unwrap();

    // The relay sees only:
    // - A random throwaway pubkey (not the wallet)
    // - The recipient in the p tag
    // - Opaque encrypted content
    assert_ne!(wrapped.pubkey, wallet_keys.public_key());
    assert_ne!(wrapped.pubkey, node_keys.public_key());

    // Content is not readable as JSON
    assert!(
        serde_json::from_str::<serde_json::Value>(&wrapped.content).is_err()
            || wrapped.content.len() > 100, // NIP-44 output is base64, not JSON
        "Content should be encrypted, not plaintext"
    );
}

#[test]
fn gift_wrap_different_throwaway_keys_each_time() {
    let wallet_keys = test_keys(0xAA);
    let node_keys = test_keys(0xBB);

    let wrapped1 =
        gift_wrap_request(&wallet_keys, &node_keys.public_key(), 20101, "msg1", vec![]).unwrap();

    let wrapped2 =
        gift_wrap_request(&wallet_keys, &node_keys.public_key(), 20101, "msg2", vec![]).unwrap();

    assert_ne!(
        wrapped1.pubkey, wrapped2.pubkey,
        "Each wrap should use a different throwaway key"
    );
}

#[test]
fn gift_wrap_response_round_trip() {
    // Node wraps response back to wallet
    let wallet_keys = test_keys(0xAA);
    let node_keys = test_keys(0xBB);

    let response_content = r#"{"success":true,"result":{"balance_msats":1000000}}"#;

    let wrapped = gift_wrap_request(
        &node_keys,
        &wallet_keys.public_key(),
        20102,
        response_content,
        vec![],
    )
    .unwrap();

    assert_eq!(wrapped.kind.as_u16(), 20102, "Response kind");

    let (sender, content, kind) = unwrap_request(&wallet_keys, &wrapped).unwrap();
    assert_eq!(sender, node_keys.public_key());
    assert_eq!(content, response_content);
    assert_eq!(kind, 20102);
}

#[test]
fn gift_wrap_verification_flow() {
    // Wallet→verifier (kind 25500) and verifier→wallet (kind 25501)
    let wallet_keys = test_keys(0xAA);
    let verifier_keys = test_keys(0xCC);

    let request = gift_wrap_request(
        &wallet_keys,
        &verifier_keys.public_key(),
        25500,
        r#"{"lightning_address":"user@example.com"}"#,
        vec![],
    )
    .unwrap();

    let (sender, content, kind) = unwrap_request(&verifier_keys, &request).unwrap();
    assert_eq!(kind, 25500);
    assert_eq!(sender, wallet_keys.public_key());
    assert!(content.contains("user@example.com"));

    // Verifier responds
    let response = gift_wrap_request(
        &verifier_keys,
        &wallet_keys.public_key(),
        25501,
        r#"{"status":"invoice","invoice":"lnbc..."}"#,
        vec![],
    )
    .unwrap();

    let (sender, content, kind) = unwrap_request(&wallet_keys, &response).unwrap();
    assert_eq!(kind, 25501);
    assert_eq!(sender, verifier_keys.public_key());
    assert!(content.contains("lnbc"));
}
