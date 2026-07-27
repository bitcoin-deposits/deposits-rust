//! Wire format for the NIP-XX event kinds and the structured payloads
//! they carry.
//!
//! Kind assignments (see `RING-SIGNATURES.md` for the full spec):
//!
//! ```text
//! 25500 / 25501   lightning-verify request / response  (existing service)
//! 25502 / 25503   ringsig request / response           (this NIP)
//! 35500           ringsig cover (parameterized replaceable)
//! 55502           durable attestation (extended with method: "ringsig")
//! ```
//!
//! `25502` carries both first-contact and continuation requests; the
//! verifier dispatches on the `action` field of the JSON payload, the
//! same way `kind:25500` already discriminates between `link`,
//! `challenge`, and `verify`. `25503` is the response kind, correlated
//! with its request via the `e` tag.
//!
//! This module covers serialization of the *structured payloads* —
//! `RingsigRequest`, `RingsigResponse`, and the `Cover` body. Wrapping
//! them in a Nostr event (kind, pubkey, sig, etc.) is the caller's
//! job; we deliberately don't take a dependency on a Nostr event type
//! here so this crate stays usable from contexts that aren't actively
//! holding a Nostr client.

use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::binding::BoundPubkeyProof;
use crate::blsag::RingSignature;

/// Ephemeral kind a wallet uses to send a ringsig request.
pub const KIND_RINGSIG_REQUEST: u16 = 25502;

/// Ephemeral kind a verifier uses to reply to a 25502 request,
/// correlated via an `e` tag pointing at the request event.
pub const KIND_RINGSIG_RESPONSE: u16 = 25503;

/// Parameterized-replaceable kind the verifier publishes to advertise
/// the current cover (the set of acceptable rings).
pub const KIND_RINGSIG_COVER: u16 = 35500;

/// Durable attestation kind (shared with the lightning-verify service).
/// Ringsig attestations carry `method: "ringsig"` in the content.
pub const KIND_ATTESTATION: u16 = 55502;

/// Method tag used inside `kind:55502` attestation bodies issued via
/// the ringsig flow.
pub const ATTESTATION_METHOD_RINGSIG: &str = "ringsig";

/// Encode a `RingSignature` into the hex blob that goes into the event's
/// `["ringsig", "<hex>"]` tag: 33-byte `I` ‖ 32-byte `c_0` ‖ n × 32-byte
/// responses.
pub fn ringsig_to_hex(sig: &RingSignature) -> String {
    let mut buf = Vec::with_capacity(33 + 32 + 32 * sig.responses.len());
    buf.extend_from_slice(&sig.key_image.serialize());
    buf.extend_from_slice(&sig.c_0);
    for r in &sig.responses {
        buf.extend_from_slice(r);
    }
    hex::encode(buf)
}

/// Inverse of [`ringsig_to_hex`]. `ring_size` is the expected number of
/// responses (i.e., the size of the ring the verifier will check
/// against); the function rejects any encoded length that doesn't match.
pub fn ringsig_from_hex(hex_str: &str, ring_size: usize) -> Result<RingSignature, &'static str> {
    let bytes = hex::decode(hex_str.trim()).map_err(|_| "ringsig: bad hex")?;
    let expected = 33 + 32 + 32 * ring_size;
    if bytes.len() != expected {
        return Err("ringsig: wrong length for declared ring size");
    }
    let key_image =
        PublicKey::from_slice(&bytes[..33]).map_err(|_| "ringsig: bad key_image point")?;
    let mut c_0 = [0u8; 32];
    c_0.copy_from_slice(&bytes[33..65]);
    let mut responses = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[65 + 32 * i..65 + 32 * (i + 1)]);
        responses.push(r);
    }
    Ok(RingSignature {
        key_image,
        c_0,
        responses,
    })
}

/// Encode a `BoundPubkeyProof` into the hex blob for the
/// `["binding", "<hex>"]` tag: 33-byte `R` ‖ 32-byte `s`.
pub fn binding_to_hex(proof: &BoundPubkeyProof) -> String {
    let mut buf = Vec::with_capacity(33 + 32);
    buf.extend_from_slice(&proof.r.serialize());
    buf.extend_from_slice(&proof.s);
    hex::encode(buf)
}

/// Inverse of [`binding_to_hex`].
pub fn binding_from_hex(hex_str: &str) -> Result<BoundPubkeyProof, &'static str> {
    let bytes = hex::decode(hex_str.trim()).map_err(|_| "binding: bad hex")?;
    if bytes.len() != 65 {
        return Err("binding: expected 65 bytes (33-byte R + 32-byte s)");
    }
    let r = PublicKey::from_slice(&bytes[..33]).map_err(|_| "binding: bad R point")?;
    let mut s = [0u8; 32];
    s.copy_from_slice(&bytes[33..]);
    Ok(BoundPubkeyProof { r, s })
}

/// Compute the canonical Nostr event digest per NIP-01:
/// `SHA256(JSON([0, pubkey, created_at, kind, tags, content]))`.
///
/// The ringsig signature in the spec covers this digest computed with
/// the `ringsig` and `binding` tags *removed*, so the wallet and the
/// verifier feed those filtered tags in here. Once the ringsig +
/// binding values are appended back as tags, the BIP-340 `sig` is
/// produced over the full event id (this digest including the new
/// tags).
pub fn canonical_event_digest(
    pubkey_hex: &str,
    created_at: u64,
    kind: u16,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    let value = serde_json::json!([0, pubkey_hex, created_at, kind, tags, content]);
    // serde_json's compact form has no whitespace, which is what NIP-01
    // requires. Edge-case Unicode escaping rules in NIP-01 are slightly
    // tighter than serde_json's default, but for our request payloads
    // (JSON ASCII, well-formed hex tags) the two coincide.
    let bytes = serde_json::to_vec(&value).expect("event digest serialize");
    Sha256::digest(&bytes).into()
}

// ─── Cover body ─────────────────────────────────────────────────────────
//
// The cover is canonicalized into Nostr `tags` rather than `content`
// because rings are independently consumable (a wallet typically picks
// one ring and ignores the rest); JSON-in-tags keeps each ring on its
// own line and lets relay-side filters target a specific ring by tag.
//
// `Cover` here is the *typed view*, not the on-wire JSON: callers serialize
// it into the event's `tags` array via `Cover::to_tags()` and parse back
// via `Cover::from_tags()`.

/// One ring in a cover: an identifier and the ordered list of member
/// xonly pubkeys, all hex-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ring {
    pub id: String,
    pub members: Vec<String>,
}

/// Cover (kind 35500) body: snapshot timestamp, minimum ring size, and
/// the rings themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cover {
    /// `d` tag: cover-version identifier. A verifier may run multiple
    /// concurrent covers distinguished by this.
    pub d_tag: String,
    /// Unix seconds when the verifier snapshotted follow lists.
    pub snapshot: u64,
    /// Minimum acceptable ring size; verifiers reject smaller rings
    /// regardless of cover content.
    pub k_min: u32,
    /// Rings in declaration order (the verifier's choice; clients
    /// shouldn't reorder).
    pub rings: Vec<Ring>,
}

impl Cover {
    /// Serialize to the Nostr event tag form:
    /// `[["d", d_tag], ["snapshot", "..."], ["k_min", "..."], ["ring", id, pk, pk, ...], ...]`.
    pub fn to_tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["d".to_string(), self.d_tag.clone()],
            vec!["snapshot".to_string(), self.snapshot.to_string()],
            vec!["k_min".to_string(), self.k_min.to_string()],
        ];
        for ring in &self.rings {
            let mut row = Vec::with_capacity(2 + ring.members.len());
            row.push("ring".to_string());
            row.push(ring.id.clone());
            row.extend(ring.members.iter().cloned());
            tags.push(row);
        }
        tags
    }

    /// Inverse of `to_tags`. Tolerates any ordering of the meta tags
    /// (`d`, `snapshot`, `k_min`) but expects each ring to be a single
    /// `["ring", id, members...]` row.
    pub fn from_tags(tags: &[Vec<String>]) -> Result<Self, &'static str> {
        let mut d_tag = None;
        let mut snapshot = None;
        let mut k_min = None;
        let mut rings = Vec::new();
        for tag in tags {
            match tag.first().map(String::as_str) {
                Some("d") => d_tag = tag.get(1).cloned(),
                Some("snapshot") => {
                    snapshot = tag.get(1).and_then(|s| s.parse::<u64>().ok());
                }
                Some("k_min") => {
                    k_min = tag.get(1).and_then(|s| s.parse::<u32>().ok());
                }
                Some("ring") => {
                    let id = tag.get(1).ok_or("ring tag missing id")?.clone();
                    let members = tag.iter().skip(2).cloned().collect();
                    rings.push(Ring { id, members });
                }
                _ => {} // unknown tag — pass through silently
            }
        }
        Ok(Cover {
            d_tag: d_tag.ok_or("cover missing `d` tag")?,
            snapshot: snapshot.ok_or("cover missing `snapshot` tag")?,
            k_min: k_min.ok_or("cover missing `k_min` tag")?,
            rings,
        })
    }
}

// ─── Request / response payloads ────────────────────────────────────────
//
// Both kinds carry their structured body in the event's `content` as
// JSON. The shape matches the lightning-verify pattern: a flat object
// with an `action` discriminator and action-specific fields. Verifiers
// dispatch on `action`.

/// Request body sent under kind 25502. The `action` field selects the
/// processing path; `first_contact` carries the ring-sig + binding
/// proof references, `continuation` carries only the bound-pubkey
/// authentication path. Both are accompanied by event-level tags
/// (`anchor`, `nullifier`, …) — those live on the Nostr event, not in
/// this body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum RingsigRequest {
    #[serde(rename = "first_contact")]
    FirstContact {
        /// Application-level payload — what the wallet is actually
        /// asking the verifier to do (open a deposit, etc.).
        payload: serde_json::Value,
    },
    #[serde(rename = "continuation")]
    Continuation { payload: serde_json::Value },
}

/// Response body sent under kind 25503.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum RingsigResponse {
    #[serde(rename = "accepted")]
    Accepted {
        /// For first-contact responses, the durable attestation event
        /// id (kind 55502) the verifier published. Optional for
        /// continuation responses, where the verifier may have no
        /// durable artifact to point at.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attestation_event_id: Option<String>,
        /// Verifier-policy-specific result body.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<serde_json::Value>,
    },
    #[serde(rename = "rejected")]
    Rejected {
        /// Short machine-friendly code (e.g. `"unknown_cover"`,
        /// `"ring_signature_invalid"`, `"nullifier_already_bound"`).
        code: String,
        /// Optional human-readable detail.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cover_round_trip() {
        let cover = Cover {
            d_tag: "v1".to_string(),
            snapshot: 1_700_000_000,
            k_min: 10,
            rings: vec![
                Ring {
                    id: "r1".to_string(),
                    members: vec!["aa".to_string(), "bb".to_string()],
                },
                Ring {
                    id: "r2".to_string(),
                    members: vec!["cc".to_string(), "dd".to_string(), "ee".to_string()],
                },
            ],
        };
        let tags = cover.to_tags();
        let parsed = Cover::from_tags(&tags).unwrap();
        assert_eq!(parsed, cover);
    }

    #[test]
    fn cover_ignores_unknown_tags() {
        let mut tags = Cover {
            d_tag: "v1".to_string(),
            snapshot: 1,
            k_min: 1,
            rings: vec![],
        }
        .to_tags();
        tags.push(vec!["unknown".to_string(), "ignored".to_string()]);
        Cover::from_tags(&tags).expect("unknown tags should be tolerated");
    }

    #[test]
    fn cover_rejects_missing_metadata() {
        let tags = vec![vec!["ring".to_string(), "r1".to_string(), "aa".to_string()]];
        assert!(Cover::from_tags(&tags).is_err());
    }

    #[test]
    fn request_first_contact_round_trip() {
        let req = RingsigRequest::FirstContact {
            payload: serde_json::json!({"hello": "world"}),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""action":"first_contact""#));
        let parsed: RingsigRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn request_continuation_round_trip() {
        let req = RingsigRequest::Continuation {
            payload: serde_json::json!({"k": 1}),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""action":"continuation""#));
        let parsed: RingsigRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn response_accepted_round_trip() {
        let resp = RingsigResponse::Accepted {
            attestation_event_id: Some("abcd".to_string()),
            result: Some(serde_json::json!({"x": true})),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""status":"accepted""#));
        let parsed: RingsigResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn response_rejected_round_trip() {
        let resp = RingsigResponse::Rejected {
            code: "unknown_cover".to_string(),
            message: Some("haven't seen this cover".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""status":"rejected""#));
        assert!(json.contains(r#""code":"unknown_cover""#));
        let parsed: RingsigResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn ringsig_hex_round_trip() {
        use crate::blsag;
        use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let n = 4;
        let sks: Vec<_> = (0..n).map(|_| SecretKey::new(&mut OsRng)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key(&secp)).collect();
        let sig = blsag::sign(&secp, &pks, 1, &sks[1], b"m", &mut OsRng).unwrap();
        let hex_str = ringsig_to_hex(&sig);
        let parsed = ringsig_from_hex(&hex_str, n).unwrap();
        assert_eq!(parsed, sig);
    }

    #[test]
    fn ringsig_from_hex_size_mismatch() {
        use crate::blsag;
        use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sks: Vec<_> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key(&secp)).collect();
        let sig = blsag::sign(&secp, &pks, 0, &sks[0], b"m", &mut OsRng).unwrap();
        let hex_str = ringsig_to_hex(&sig);
        assert!(ringsig_from_hex(&hex_str, 4).is_err()); // wrong ring size
        assert!(ringsig_from_hex(&hex_str, 2).is_err());
    }

    #[test]
    fn binding_hex_round_trip() {
        use crate::{binding, blsag};
        use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sks: Vec<_> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key(&secp)).collect();
        let ring = blsag::sign(&secp, &pks, 0, &sks[0], b"m", &mut OsRng).unwrap();
        let sk_p = SecretKey::new(&mut OsRng);
        let proof = binding::prove(&secp, &sk_p, &ring, &mut OsRng).unwrap();
        let hex_str = binding_to_hex(&proof);
        let parsed = binding_from_hex(&hex_str).unwrap();
        assert_eq!(parsed, proof);
    }

    #[test]
    fn canonical_digest_stable_across_runs() {
        let tags = vec![
            vec!["a".to_string(), "1".to_string()],
            vec!["b".to_string(), "2".to_string()],
        ];
        let d1 = canonical_event_digest("aa", 100, 25502, &tags, "hi");
        let d2 = canonical_event_digest("aa", 100, 25502, &tags, "hi");
        assert_eq!(d1, d2);
    }

    #[test]
    fn canonical_digest_distinguishes_tag_changes() {
        let base = canonical_event_digest("aa", 100, 25502, &[], "hi");
        let with_tag = canonical_event_digest(
            "aa",
            100,
            25502,
            &[vec!["a".to_string(), "1".to_string()]],
            "hi",
        );
        assert_ne!(base, with_tag);
    }

    #[test]
    fn response_accepted_drops_optional_fields() {
        let resp = RingsigResponse::Accepted {
            attestation_event_id: None,
            result: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("attestation_event_id"));
        assert!(!json.contains("result"));
    }
}
