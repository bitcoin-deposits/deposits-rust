//! Deterministic display names for pubkeys.
//!
//! Hand-assigned node names are coordination state: every party has to
//! learn them, they collide, and they can lie. A name *derived from* the
//! pubkey is the same on every surface — hub dashboard, node CLI, wallet,
//! explorer — with zero agreement, and it can't be chosen to impersonate.
//!
//! Convention: `sha256(pubkey_bytes)` → first 4 BIP-39 English words,
//! hyphenated (hyphens convey "this is an identifier, not prose"):
//!
//! ```text
//! 03b1c4…e2 → "ribbon-mad-hotel-clip"
//! ```
//!
//! Hashing first matters: compressed pubkeys start with 02/03, so raw
//! bytes would give half the network the same first word.
//!
//! Four words ≈ 44 bits. That's a DISPLAY handle, not an identifier —
//! plenty against accidental collision in any human-scale operator set,
//! useless against a grinding adversary (2²² work for a visual twin).
//! UIs should keep the real pubkey one hover/click away.

use sha2::{Digest, Sha256};

/// English BIP-39 wordlist indexed 11 bits at a time. We avoid pulling
/// the full `bip39` crate down here — the convention only needs the
/// wordlist, and `bip39::Language::English` word ordering is fixed by
/// the BIP. Keep in lock-step with the JS mirror in
/// `deposits-web/wallet` (pinned by cross-impl test vectors).
const WORDS: &str = include_str!("bip39_english.txt");

/// First four BIP-39 words of sha256(pubkey), hyphenated.
///
/// Accepts any byte serialization of the key (33-byte compressed,
/// 32-byte x-only) — callers must be consistent about which they feed
/// in. Protocol-wide convention: the COMPRESSED operator pubkey
/// (`Node ID`) for operators; the 32-byte nostr key for agents that
/// have no secp identity.
pub fn pubkey_display_name(pubkey: &[u8]) -> String {
    let hash = Sha256::digest(pubkey);
    let words: Vec<&str> = WORDS.lines().collect();
    debug_assert_eq!(words.len(), 2048);

    // 4 words × 11 bits = 44 bits from the hash's big-endian bit stream.
    let mut out = Vec::with_capacity(4);
    for w in 0..4 {
        let bit_off = w * 11;
        let mut idx: usize = 0;
        for b in 0..11 {
            let bit = bit_off + b;
            let byte = hash[bit / 8];
            let mask = 0x80u8 >> (bit % 8);
            idx = (idx << 1) | usize::from(byte & mask != 0);
        }
        out.push(words[idx]);
    }
    out.join("-")
}

/// Hex-input convenience: decodes and names, or falls back to a
/// truncated-hex handle when the input isn't valid hex (never panics —
/// display paths shouldn't take down a dashboard).
pub fn pubkey_display_name_hex(pubkey_hex: &str) -> String {
    match hex::decode(pubkey_hex) {
        Ok(bytes) if !bytes.is_empty() => pubkey_display_name(&bytes),
        _ => format!("{}…", &pubkey_hex[..8.min(pubkey_hex.len())]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_complete() {
        assert_eq!(WORDS.lines().count(), 2048);
        assert_eq!(WORDS.lines().next(), Some("abandon"));
        assert_eq!(WORDS.lines().last(), Some("zoo"));
    }

    #[test]
    fn deterministic_and_distinct() {
        let a = pubkey_display_name(&[2u8; 33]);
        let b = pubkey_display_name(&[3u8; 33]);
        assert_eq!(a, pubkey_display_name(&[2u8; 33]));
        assert_ne!(a, b);
        assert_eq!(a.split('-').count(), 4);
    }

    /// Cross-impl pin — the JS mirror in deposits-web/wallet must
    /// produce these exact names for these exact inputs. If this test
    /// needs changing, change the JS (and its test) in the same commit.
    #[test]
    fn cross_impl_vectors() {
        // sha256(0x02 * 33) and a realistic compressed-pubkey shape.
        let v1 = pubkey_display_name(&[0x02u8; 33]);
        let v2 = pubkey_display_name(
            &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        );
        // Computed once from the reference implementation above; pinned
        // so neither side can drift silently.
        assert_eq!(v1, "left-kingdom-divide-chuckle");
        assert_eq!(v2, "author-member-type-ritual");
    }
}
