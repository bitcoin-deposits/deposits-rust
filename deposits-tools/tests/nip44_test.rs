//! NIP-44 encryption test vectors from https://github.com/paulmillr/nip44
//! These tests verify our NIP-44 v2 implementation against the official test vectors.

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use chacha20::{ChaCha20, cipher::{KeyIvInit, StreamCipher}};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const NIP44_VERSION: u8 = 2;

/// Custom ECDH that returns raw x-coordinate (NIP-44 requirement)
/// secp256k1's SharedSecret::new applies SHA256, which we don't want for NIP-44
fn ecdh_raw_x(our_secret: &SecretKey, their_pubkey: &PublicKey) -> [u8; 32] {
    use bitcoin::secp256k1::ecdh::shared_secret_point;

    // shared_secret_point returns the 64-byte (x, y) coordinates
    let shared_point = shared_secret_point(their_pubkey, our_secret);

    // NIP-44 uses just the x-coordinate (first 32 bytes)
    let mut x_coord = [0u8; 32];
    x_coord.copy_from_slice(&shared_point[..32]);
    x_coord
}

/// Compute NIP-44 conversation key using ECDH + HKDF
/// NIP-44 uses secp256k1 ECDH with the raw x-coordinate as shared secret
fn get_conversation_key(
    our_secret: &SecretKey,
    their_pubkey_hex: &str,
) -> [u8; 32] {
    // Parse x-only pubkey and convert to full pubkey (assume even y)
    let their_pubkey_bytes = hex::decode(their_pubkey_hex).unwrap();
    let mut full_pubkey_bytes = [0u8; 33];
    full_pubkey_bytes[0] = 0x02; // Even y coordinate
    full_pubkey_bytes[1..].copy_from_slice(&their_pubkey_bytes);
    let their_full_pubkey = PublicKey::from_slice(&full_pubkey_bytes).unwrap();

    // ECDH shared secret - use raw x-coordinate (not hashed)
    let shared_x = ecdh_raw_x(our_secret, &their_full_pubkey);

    // NIP-44: conversation_key = HKDF-extract(salt="nip44-v2", IKM=shared_x)
    // HKDF-extract is just HMAC(salt, IKM), the result is the PRK (conversation key)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(b"nip44-v2").unwrap();
    mac.update(&shared_x);
    let result = mac.finalize();

    let mut conversation_key = [0u8; 32];
    conversation_key.copy_from_slice(&result.into_bytes());
    conversation_key
}

/// Derive message keys from conversation key and nonce
/// Returns: (chacha_key: 32 bytes, chacha_nonce: 12 bytes, hmac_key: 32 bytes)
fn get_message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
) -> ([u8; 32], [u8; 12], [u8; 32]) {
    // HKDF-expand with conversation_key as PRK and nonce as info
    let hk = Hkdf::<Sha256>::from_prk(conversation_key).unwrap();
    let mut full_key_material = [0u8; 76];
    hk.expand(nonce, &mut full_key_material).unwrap();

    let chacha_key: [u8; 32] = full_key_material[0..32].try_into().unwrap();
    let chacha_nonce: [u8; 12] = full_key_material[32..44].try_into().unwrap();
    let hmac_key: [u8; 32] = full_key_material[44..76].try_into().unwrap();

    (chacha_key, chacha_nonce, hmac_key)
}

/// Calculate padded length per NIP-44 spec
fn calc_padded_len(unpadded_len: usize) -> usize {
    if unpadded_len <= 32 {
        return 32;
    }
    // Calculate next power of 2 based on (unpadded_len - 1)
    let next_power = 1usize << ((unpadded_len - 1) as u64).ilog2() as usize + 1;
    let chunk = (next_power / 8).max(32);
    chunk * ((unpadded_len - 1) / chunk + 1)
}

/// Pad plaintext according to NIP-44 spec
fn pad_plaintext(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let padded_len = calc_padded_len(len);

    let mut padded = Vec::with_capacity(2 + padded_len);
    // Length prefix (big endian u16)
    padded.push((len >> 8) as u8);
    padded.push(len as u8);
    padded.extend_from_slice(data);
    padded.resize(2 + padded_len, 0);
    padded
}

/// Unpad plaintext according to NIP-44 spec
fn unpad_plaintext(data: &[u8]) -> Vec<u8> {
    assert!(data.len() >= 2);
    let len = ((data[0] as usize) << 8) | (data[1] as usize);
    assert!(2 + len <= data.len());
    data[2..2+len].to_vec()
}

/// Encrypt with specific nonce (for testing)
fn encrypt_with_nonce(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
    plaintext: &str,
) -> String {
    let (chacha_key, chacha_nonce, hmac_key) = get_message_keys(conversation_key, nonce);

    let padded = pad_plaintext(plaintext.as_bytes());

    // NIP-44 uses ChaCha20 stream cipher (NOT ChaCha20-Poly1305)
    let mut cipher = ChaCha20::new(&chacha_key.into(), &chacha_nonce.into());
    let mut ciphertext = padded.clone();
    cipher.apply_keystream(&mut ciphertext);

    // Compute HMAC-SHA256(hmac_key, nonce || ciphertext)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_key).unwrap();
    mac.update(nonce);
    mac.update(&ciphertext);
    let hmac_result = mac.finalize().into_bytes();

    // Build payload: version + nonce + ciphertext + hmac
    let mut payload = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
    payload.push(NIP44_VERSION);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&hmac_result);

    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&payload)
}

/// Decrypt NIP-44 payload
fn decrypt(
    conversation_key: &[u8; 32],
    payload_b64: &str,
) -> String {
    use base64::Engine;
    let payload = base64::engine::general_purpose::STANDARD.decode(payload_b64).unwrap();

    // Minimum: version(1) + nonce(32) + min_ciphertext(34 = 2 len + 32 padded) + hmac(32)
    assert!(payload.len() >= 1 + 32 + 34 + 32);
    assert_eq!(payload[0], NIP44_VERSION);

    let nonce: [u8; 32] = payload[1..33].try_into().unwrap();
    let ciphertext_with_hmac = &payload[33..];
    let ciphertext = &ciphertext_with_hmac[..ciphertext_with_hmac.len() - 32];
    let received_hmac = &ciphertext_with_hmac[ciphertext_with_hmac.len() - 32..];

    let (chacha_key, chacha_nonce, hmac_key) = get_message_keys(conversation_key, &nonce);

    // Verify HMAC-SHA256(hmac_key, nonce || ciphertext)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_key).unwrap();
    mac.update(&nonce);
    mac.update(ciphertext);
    mac.verify_slice(received_hmac).expect("HMAC verification failed");

    // Decrypt with ChaCha20 stream cipher
    let mut cipher = ChaCha20::new(&chacha_key.into(), &chacha_nonce.into());
    let mut padded = ciphertext.to_vec();
    cipher.apply_keystream(&mut padded);

    let plaintext = unpad_plaintext(&padded);
    String::from_utf8(plaintext).unwrap()
}

// =============================================================================
// Test: Conversation Key Derivation
// =============================================================================

#[test]
fn test_get_conversation_key() {
    let test_vectors = [
        ("315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268",
         "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133",
         "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1"),
        ("a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e",
         "03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800",
         "4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b"),
        ("98a5902fd67518a0c900f0fb62158f278f94a21d6f9d33d30cd3091195500311",
         "aae65c15f98e5e677b5050de82e3aba47a6fe49b3dab7863cf35d9478ba9f7d1",
         "9c00b769d5f54d02bf175b7284a1cbd28b6911b06cda6666b2243561ac96bad7"),
        ("86ae5ac8034eb2542ce23ec2f84375655dab7f836836bbd3c54cefe9fdc9c19f",
         "59f90272378089d73f1339710c02e2be6db584e9cdbe86eed3578f0c67c23585",
         "19f934aafd3324e8415299b64df42049afaa051c71c98d0aa10e1081f2e3e2ba"),
        ("2528c287fe822421bc0dc4c3615878eb98e8a8c31657616d08b29c00ce209e34",
         "f66ea16104c01a1c532e03f166c5370a22a5505753005a566366097150c6df60",
         "c833bbb292956c43366145326d53b955ffb5da4e4998a2d853611841903f5442"),
        ("49808637b2d21129478041813aceb6f2c9d4929cd1303cdaf4fbdbd690905ff2",
         "74d2aab13e97827ea21baf253ad7e39b974bb2498cc747cdb168582a11847b65",
         "4bf304d3c8c4608864c0fe03890b90279328cd24a018ffa9eb8f8ccec06b505d"),
        ("af67c382106242c5baabf856efdc0629cc1c5b4061f85b8ceaba52aa7e4b4082",
         "bdaf0001d63e7ec994fad736eab178ee3c2d7cfc925ae29f37d19224486db57b",
         "a3a575dd66d45e9379904047ebfb9a7873c471687d0535db00ef2daa24b391db"),
        ("0e44e2d1db3c1717b05ffa0f08d102a09c554a1cbbf678ab158b259a44e682f1",
         "1ffa76c5cc7a836af6914b840483726207cb750889753d7499fb8b76aa8fe0de",
         "a39970a667b7f861f100e3827f4adbf6f464e2697686fe1a81aeda817d6b8bdf"),
        ("5fc0070dbd0666dbddc21d788db04050b86ed8b456b080794c2a0c8e33287bb6",
         "31990752f296dd22e146c9e6f152a269d84b241cc95bb3ff8ec341628a54caf0",
         "72c21075f4b2349ce01a3e604e02a9ab9f07e35dd07eff746de348b4f3c6365e"),
        ("1b7de0d64d9b12ddbb52ef217a3a7c47c4362ce7ea837d760dad58ab313cba64",
         "24383541dd8083b93d144b431679d70ef4eec10c98fceef1eff08b1d81d4b065",
         "dd152a76b44e63d1afd4dfff0785fa07b3e494a9e8401aba31ff925caeb8f5b1"),
        // Edge case: sec1 = n-2
        ("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139",
         "0000000000000000000000000000000000000000000000000000000000000002",
         "8b6392dbf2ec6a2b2d5b1477fc2be84d63ef254b667cadd31bd3f444c44ae6ba"),
        // Edge case: sec1 = 2
        ("0000000000000000000000000000000000000000000000000000000000000002",
         "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdeb",
         "be234f46f60a250bef52a5ee34c758800c4ca8e5030bf4cc1a31d37ba2104d43"),
        // Edge case: sec1 == pub2 (G point)
        ("0000000000000000000000000000000000000000000000000000000000000001",
         "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
         "3b4610cb7189beb9cc29eb3716ecc6102f1247e8f3101a03a1787d8908aeb54e"),
    ];

    for (sec1_hex, pub2_hex, expected_conv_key) in test_vectors {
        let sec1_bytes = hex::decode(sec1_hex).unwrap();
        let sec1 = SecretKey::from_slice(&sec1_bytes).unwrap();

        let conv_key = get_conversation_key(&sec1, pub2_hex);
        let conv_key_hex = hex::encode(conv_key);

        assert_eq!(conv_key_hex, expected_conv_key,
            "Failed for sec1={}, pub2={}", sec1_hex, pub2_hex);
    }
}

// =============================================================================
// Test: Message Key Derivation
// =============================================================================

#[test]
fn test_get_message_keys() {
    let conversation_key_hex = "a1a3d60f3470a8612633924e91febf96dc5366ce130f658b1f0fc652c20b3b54";
    let conversation_key: [u8; 32] = hex::decode(conversation_key_hex).unwrap().try_into().unwrap();

    let test_vectors = [
        ("e1e6f880560d6d149ed83dcc7e5861ee62a5ee051f7fde9975fe5d25d2a02d72",
         "f145f3bed47cb70dbeaac07f3a3fe683e822b3715edb7c4fe310829014ce7d76",
         "c4ad129bb01180c0933a160c",
         "027c1db445f05e2eee864a0975b0ddef5b7110583c8c192de3732571ca5838c4"),
        ("e1d6d28c46de60168b43d79dacc519698512ec35e8ccb12640fc8e9f26121101",
         "e35b88f8d4a8f1606c5082f7a64b100e5d85fcdb2e62aeafbec03fb9e860ad92",
         "22925e920cee4a50a478be90",
         "46a7c55d4283cb0df1d5e29540be67abfe709e3b2e14b7bf9976e6df994ded30"),
        ("cfc13bef512ac9c15951ab00030dfaf2626fdca638dedb35f2993a9eeb85d650",
         "020783eb35fdf5b80ef8c75377f4e937efb26bcbad0e61b4190e39939860c4bf",
         "d3594987af769a52904656ac",
         "237ec0ccb6ebd53d179fa8fd319e092acff599ef174c1fdafd499ef2b8dee745"),
        ("ea6eb84cac23c5c1607c334e8bdf66f7977a7e374052327ec28c6906cbe25967",
         "ff68db24b34fa62c78ac5ffeeaf19533afaedf651fb6a08384e46787f6ce94be",
         "50bb859aa2dde938cc49ec7a",
         "06ff32e1f7b29753a727d7927b25c2dd175aca47751462d37a2039023ec6b5a6"),
        ("8c2e1dd3792802f1f9f7842e0323e5d52ad7472daf360f26e15f97290173605d",
         "2f9daeda8683fdeede81adac247c63cc7671fa817a1fd47352e95d9487989d8b",
         "400224ba67fc2f1b76736916",
         "465c05302aeeb514e41c13ed6405297e261048cfb75a6f851ffa5b445b746e4b"),
    ];

    for (nonce_hex, expected_chacha_key, expected_chacha_nonce, expected_hmac_key) in test_vectors {
        let nonce: [u8; 32] = hex::decode(nonce_hex).unwrap().try_into().unwrap();
        let (chacha_key, chacha_nonce, hmac_key) = get_message_keys(&conversation_key, &nonce);

        assert_eq!(hex::encode(chacha_key), expected_chacha_key,
            "ChaCha key mismatch for nonce {}", nonce_hex);
        assert_eq!(hex::encode(chacha_nonce), expected_chacha_nonce,
            "ChaCha nonce mismatch for nonce {}", nonce_hex);
        assert_eq!(hex::encode(hmac_key), expected_hmac_key,
            "HMAC key mismatch for nonce {}", nonce_hex);
    }
}

// =============================================================================
// Test: Padded Length Calculation
// =============================================================================

#[test]
fn test_calc_padded_len() {
    let test_vectors = [
        (16, 32), (32, 32), (33, 64), (37, 64), (45, 64), (49, 64),
        (64, 64), (65, 96), (100, 128), (111, 128), (200, 224),
        (250, 256), (320, 320), (383, 384), (384, 384), (400, 448),
        (500, 512), (512, 512), (515, 640), (700, 768), (800, 896),
        (900, 1024), (1020, 1024), (65536, 65536),
    ];

    for (input, expected) in test_vectors {
        let result = calc_padded_len(input);
        assert_eq!(result, expected, "calc_padded_len({}) = {}, expected {}", input, result, expected);
    }
}

// =============================================================================
// Test: Full Encryption/Decryption
// =============================================================================

#[test]
fn test_encrypt_decrypt() {
    let test_vectors = [
        // (sec1, sec2, conversation_key, nonce, plaintext, payload)
        ("0000000000000000000000000000000000000000000000000000000000000001",
         "0000000000000000000000000000000000000000000000000000000000000002",
         "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
         "0000000000000000000000000000000000000000000000000000000000000001",
         "a",
         "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"),
        ("0000000000000000000000000000000000000000000000000000000000000002",
         "0000000000000000000000000000000000000000000000000000000000000001",
         "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
         "f00000000000000000000000000000f00000000000000000000000000000000f",
         "🍕🫃",
         "AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPSKSK6is9ngkX2+cSq85Th16oRTISAOfhStnixqZziKMDvB0QQzgFZdjLTPicCJaV8nDITO+QfaQ61+KbWQIOO2Yj"),
        ("5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a",
         "4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d",
         "3e2b52a63be47d34fe0a80e34e73d436d6963bc8f39827f327057a9986c20a45",
         "b635236c42db20f021bb8d1cdff5ca75dd1a0cc72ea742ad750f33010b24f73b",
         "表ポあA鷗ŒéＢ逍Üßªąñ丂㐀𠀀",
         "ArY1I2xC2yDwIbuNHN/1ynXdGgzHLqdCrXUPMwELJPc7s7JqlCMJBAIIjfkpHReBPXeoMCyuClwgbT419jUWU1PwaNl4FEQYKCDKVJz+97Mp3K+Q2YGa77B6gpxB/lr1QgoqpDf7wDVrDmOqGoiPjWDqy8KzLueKDcm9BVP8xeTJIxs="),
        ("8f40e50a84a7462e2b8d24c28898ef1f23359fff50d8c509e6fb7ce06e142f9c",
         "b9b0a1e9cc20100c5faa3bbe2777303d25950616c4c6a3fa2e3e046f936ec2ba",
         "d5a2f879123145a4b291d767428870f5a8d9e5007193321795b40183d4ab8c2b",
         "b20989adc3ddc41cd2c435952c0d59a91315d8c5218d5040573fc3749543acaf",
         "ability🤝的 ȺȾ",
         "ArIJia3D3cQc0sQ1lSwNWakTFdjFIY1QQFc/w3SVQ6yvbG2S0x4Yu86QGwPTy7mP3961I1XqB6SFFTzqDZZavhxoWMj7mEVGMQIsh2RLWI5EYQaQDIePSnXPlzf7CIt+voTD"),
        ("875adb475056aec0b4809bd2db9aa00cff53a649e7b59d8edcbf4e6330b0995c",
         "9c05781112d5b0a2a7148a222e50e0bd891d6b60c5483f03456e982185944aae",
         "3b15c977e20bfe4b8482991274635edd94f366595b1a3d2993515705ca3cedb8",
         "8d4442713eb9d4791175cb040d98d6fc5be8864d6ec2f89cf0895a2b2b72d1b1",
         "pepper👀їжак",
         "Ao1EQnE+udR5EXXLBA2Y1vxb6IZNbsL4nPCJWisrctGxY3AduCS+jTUgAAnfvKafkmpy15+i9YMwCdccisRa8SvzW671T2JO4LFSPX31K4kYUKelSAdSPwe9NwO6LhOsnoJ+"),
        ("eba1687cab6a3101bfc68fd70f214aa4cc059e9ec1b79fdb9ad0a0a4e259829f",
         "dff20d262bef9dfd94666548f556393085e6ea421c8af86e9d333fa8747e94b3",
         "4f1538411098cf11c8af216836444787c462d47f97287f46cf7edb2c4915b8a5",
         "2180b52ae645fcf9f5080d81b1f0b5d6f2cd77ff3c986882bb549158462f3407",
         "( ͡° ͜ʖ ͡°)",
         "AiGAtSrmRfz59QgNgbHwtdbyzXf/PJhogrtUkVhGLzQHv4qhKQwnFQ54OjVMgqCea/Vj0YqBSdhqNR777TJ4zIUk7R0fnizp6l1zwgzWv7+ee6u+0/89KIjY5q1wu6inyuiv"),
    ];

    for (sec1_hex, _sec2_hex, conv_key_hex, nonce_hex, plaintext, expected_payload) in test_vectors {
        let sec1_bytes = hex::decode(sec1_hex).unwrap();
        let sec1 = SecretKey::from_slice(&sec1_bytes).unwrap();
        let conv_key: [u8; 32] = hex::decode(conv_key_hex).unwrap().try_into().unwrap();
        let nonce: [u8; 32] = hex::decode(nonce_hex).unwrap().try_into().unwrap();

        // Test encryption produces expected payload
        let encrypted = encrypt_with_nonce(&conv_key, &nonce, plaintext);
        assert_eq!(encrypted, expected_payload,
            "Encryption mismatch for plaintext: {}", plaintext);

        // Test decryption recovers plaintext
        let decrypted = decrypt(&conv_key, expected_payload);
        assert_eq!(decrypted, plaintext,
            "Decryption mismatch for payload");
    }
}

// =============================================================================
// Test: Roundtrip Encryption/Decryption
// =============================================================================

#[test]
fn test_roundtrip() {
    use rand::RngCore;

    let secp = Secp256k1::new();

    // Generate random keypair
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let secret = SecretKey::from_slice(&secret_bytes).unwrap();
    let public = secret.public_key(&secp);

    // Convert to x-only for conversation key
    let xonly_hex = hex::encode(&public.serialize()[1..33]);

    let conv_key = get_conversation_key(&secret, &xonly_hex);

    let test_messages = [
        "Hello, world!",
        "🔐 Encrypted message with emoji 🎉",
        "Short",
        &"A".repeat(1000), // Long message
        "Special chars: <>&\"'\\n\\t",
    ];

    for msg in test_messages {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        let encrypted = encrypt_with_nonce(&conv_key, &nonce, msg);
        let decrypted = decrypt(&conv_key, &encrypted);

        assert_eq!(decrypted, msg, "Roundtrip failed for: {}", msg);
    }
}

// =============================================================================
// Test: Conversation Key Symmetry
// =============================================================================

#[test]
fn test_conversation_key_symmetry() {
    // ECDH should produce the same shared secret regardless of who is sender/receiver
    let sec1_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let sec2_hex = "0000000000000000000000000000000000000000000000000000000000000002";

    let sec1 = SecretKey::from_slice(&hex::decode(sec1_hex).unwrap()).unwrap();
    let sec2 = SecretKey::from_slice(&hex::decode(sec2_hex).unwrap()).unwrap();

    let secp = Secp256k1::new();
    let pub1 = sec1.public_key(&secp);
    let pub2 = sec2.public_key(&secp);

    let pub1_xonly_hex = hex::encode(&pub1.serialize()[1..33]);
    let pub2_xonly_hex = hex::encode(&pub2.serialize()[1..33]);

    // sec1 + pub2 should equal sec2 + pub1
    let conv_key_1_to_2 = get_conversation_key(&sec1, &pub2_xonly_hex);
    let conv_key_2_to_1 = get_conversation_key(&sec2, &pub1_xonly_hex);

    assert_eq!(conv_key_1_to_2, conv_key_2_to_1,
        "Conversation keys should be symmetric");
}
