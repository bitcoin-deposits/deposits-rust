// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Canonical, signed member-response blob carried inside a QuorumAddMember
//! operation.
//!
//! When an operator asks a candidate member to join a quorum, the member
//! returns a TLV-encoded `QuorumMemberResponse` plus a BIP-340 signature over
//! its tagged digest. The operator stores both the blob and the signature
//! verbatim inside the resulting `QuorumAddMember` operation, so any third
//! party reading the ledger can verify the member's terms and chosen ruleset
//! without trusting how the operator unpacked the negotiation.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;

use super::serde_helpers::DepositId;
use crate::tlv::{TlvBuilder, TlvDecode, TlvEncode, TlvReader, TlvResult};

/// BIP-340 tag for the digest signed by the member.
///
/// Tagging via `SHA256(SHA256(tag) || SHA256(tag) || msg)` (BIP-340 §"Tagged
/// Hashes") domain-separates this signature from every other digest in the
/// protocol so that a signature here cannot be replayed against, e.g., a
/// cosign request.
pub const QUORUM_MEMBER_RESPONSE_TAG: &str = "deposits/quorum-member-response/v1";

/// Current response shape version. Bumped if the canonical wire encoding
/// of `QuorumMemberResponse` changes incompatibly.
pub const QUORUM_MEMBER_RESPONSE_VERSION: u16 = 1;

/// A member's signed response to an operator's join request.
///
/// All fields except the four bindings (`response_version`, `member_pubkey`,
/// `operator_pubkey`, `operator_ledger_id`, `chosen_ruleset`,
/// `member_ledger_id`) are optional terms the member offers. Operators must
/// preserve every set field verbatim when constructing the corresponding
/// `QuorumAddMember`; validators reject any mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumMemberResponse {
    /// Encoding version. Currently always [`QUORUM_MEMBER_RESPONSE_VERSION`].
    pub response_version: u16,
    /// The member's pubkey. Must match `quorum_member` on the parent
    /// `QuorumAddMember` and the BIP-340 verifying key of `member_signature`.
    pub member_pubkey: PublicKey,
    /// The operator the member is consenting to. Binds the blob to a
    /// specific operator so it cannot be replayed across operators.
    pub operator_pubkey: PublicKey,
    /// The operator's ledger this response is bound to (64-char hex).
    pub operator_ledger_id: String,
    /// Ruleset name the member chose for this quorum (must be one of the
    /// ruleset names the operator offered in `quorum request`).
    pub chosen_ruleset: String,
    /// Every ruleset name this member is willing to validate under for the
    /// rest of this quorum's lifetime. Includes `chosen_ruleset` by
    /// construction. Operators read this at `quorum begin` to confirm that
    /// the `protocol_version` they're about to commit to is one every member
    /// can enforce. Always non-empty when produced by Q1+ members.
    pub supported_rulesets: Vec<String>,
    /// Ledger where the member commits collateral.
    pub member_ledger_id: String,

    pub min_fee_bps: Option<u16>,
    pub min_fee_fixed: Option<u64>,
    pub max_fee_period: Option<u32>,
    pub membership_until: Option<u32>,

    pub dispute_response_blocks: Option<u32>,
    pub dispute_arm_blocks: Option<u32>,
    pub service_response_blocks: Option<u32>,
    pub max_transfer_timeout_blocks: Option<u32>,
    pub max_descriptor_bytes: Option<u32>,

    pub compensation_bps: Option<u16>,
    pub compensation_deposit_id: Option<DepositId>,
    pub compensation_frequency_blocks: Option<u32>,
}

mod tlv_id {
    pub const RESPONSE_VERSION: u64 = 1;
    pub const MEMBER_PUBKEY: u64 = 2;
    pub const OPERATOR_PUBKEY: u64 = 3;
    pub const OPERATOR_LEDGER_ID: u64 = 4;
    pub const CHOSEN_RULESET: u64 = 5;
    pub const MEMBER_LEDGER_ID: u64 = 6;
    /// Variable-length, length-prefixed list of ruleset name strings
    /// (each: u8 len || utf8 bytes). Optional; absent → `[chosen_ruleset]`
    /// (legacy producers).
    pub const SUPPORTED_RULESETS: u64 = 7;

    pub const MIN_FEE_BPS: u64 = 10;
    pub const MIN_FEE_FIXED: u64 = 11;
    pub const MAX_FEE_PERIOD: u64 = 12;
    pub const MEMBERSHIP_UNTIL: u64 = 13;

    pub const DISPUTE_RESPONSE_BLOCKS: u64 = 20;
    pub const DISPUTE_ARM_BLOCKS: u64 = 21;
    pub const SERVICE_RESPONSE_BLOCKS: u64 = 22;
    pub const MAX_TRANSFER_TIMEOUT_BLOCKS: u64 = 23;
    pub const MAX_DESCRIPTOR_BYTES: u64 = 24;

    pub const COMPENSATION_BPS: u64 = 30;
    pub const COMPENSATION_DEPOSIT_ID: u64 = 31;
    pub const COMPENSATION_FREQUENCY_BLOCKS: u64 = 32;
}

impl TlvEncode for QuorumMemberResponse {
    fn tlv_encode(&self) -> Vec<u8> {
        use tlv_id::*;
        let mut b = TlvBuilder::new()
            .u16_field(RESPONSE_VERSION, self.response_version)
            .pubkey_field(MEMBER_PUBKEY, &self.member_pubkey)
            .pubkey_field(OPERATOR_PUBKEY, &self.operator_pubkey)
            .string_field(OPERATOR_LEDGER_ID, &self.operator_ledger_id)
            .string_field(CHOSEN_RULESET, &self.chosen_ruleset)
            .string_field(MEMBER_LEDGER_ID, &self.member_ledger_id);
        if !self.supported_rulesets.is_empty() {
            // Each entry: u8 len || utf-8 bytes. Names are short
            // identifiers (e.g. "legacy", "cltv-offset-v2"), so u8 length
            // prefix is sufficient.
            let mut buf = Vec::new();
            for name in &self.supported_rulesets {
                let bytes = name.as_bytes();
                let len: u8 = bytes.len().try_into().unwrap_or(u8::MAX);
                buf.push(len);
                buf.extend_from_slice(&bytes[..len as usize]);
            }
            b = b.bytes_field(SUPPORTED_RULESETS, &buf);
        }
        if let Some(v) = self.min_fee_bps {
            b = b.u16_field(MIN_FEE_BPS, v);
        }
        if let Some(v) = self.min_fee_fixed {
            b = b.u64_field(MIN_FEE_FIXED, v);
        }
        if let Some(v) = self.max_fee_period {
            b = b.u32_field(MAX_FEE_PERIOD, v);
        }
        if let Some(v) = self.membership_until {
            b = b.u32_field(MEMBERSHIP_UNTIL, v);
        }
        if let Some(v) = self.dispute_response_blocks {
            b = b.u32_field(DISPUTE_RESPONSE_BLOCKS, v);
        }
        if let Some(v) = self.dispute_arm_blocks {
            b = b.u32_field(DISPUTE_ARM_BLOCKS, v);
        }
        if let Some(v) = self.service_response_blocks {
            b = b.u32_field(SERVICE_RESPONSE_BLOCKS, v);
        }
        if let Some(v) = self.max_transfer_timeout_blocks {
            b = b.u32_field(MAX_TRANSFER_TIMEOUT_BLOCKS, v);
        }
        if let Some(v) = self.max_descriptor_bytes {
            b = b.u32_field(MAX_DESCRIPTOR_BYTES, v);
        }
        if let Some(v) = self.compensation_bps {
            b = b.u16_field(COMPENSATION_BPS, v);
        }
        if let Some(v) = self.compensation_deposit_id {
            b = b.deposit_id_field(COMPENSATION_DEPOSIT_ID, &v);
        }
        if let Some(v) = self.compensation_frequency_blocks {
            b = b.u32_field(COMPENSATION_FREQUENCY_BLOCKS, v);
        }
        b.build()
    }
}

impl TlvDecode for QuorumMemberResponse {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use tlv_id::*;
        let r = TlvReader::new(data)?;
        let chosen_ruleset = r.read_string(CHOSEN_RULESET)?;
        let supported_rulesets = match r.read_raw_opt(SUPPORTED_RULESETS) {
            Some(buf) => {
                let mut out = Vec::new();
                let mut i = 0usize;
                while i < buf.len() {
                    let len = buf[i] as usize;
                    i += 1;
                    if i + len > buf.len() {
                        return Err(crate::tlv::TlvError::InvalidFieldValue {
                            field_type: SUPPORTED_RULESETS,
                            reason: "truncated entry".to_string(),
                        });
                    }
                    out.push(
                        std::str::from_utf8(&buf[i..i + len])
                            .map_err(|e| crate::tlv::TlvError::InvalidFieldValue {
                                field_type: SUPPORTED_RULESETS,
                                reason: format!("invalid UTF-8: {}", e),
                            })?
                            .to_string(),
                    );
                    i += len;
                }
                out
            }
            // Legacy blob: only the chosen ruleset is "supported" by
            // assumption. Members on Q1+ wire always populate the list
            // explicitly, so this only hits replays of older blobs.
            None => vec![chosen_ruleset.clone()],
        };
        Ok(Self {
            response_version: r.read_u16(RESPONSE_VERSION)?,
            member_pubkey: r.read_pubkey(MEMBER_PUBKEY)?,
            operator_pubkey: r.read_pubkey(OPERATOR_PUBKEY)?,
            operator_ledger_id: r.read_string(OPERATOR_LEDGER_ID)?,
            chosen_ruleset,
            supported_rulesets,
            member_ledger_id: r.read_string(MEMBER_LEDGER_ID)?,
            min_fee_bps: r.read_u16_opt(MIN_FEE_BPS)?,
            min_fee_fixed: r.read_u64_opt(MIN_FEE_FIXED)?,
            max_fee_period: r.read_u32_opt(MAX_FEE_PERIOD)?,
            membership_until: r.read_u32_opt(MEMBERSHIP_UNTIL)?,
            dispute_response_blocks: r.read_u32_opt(DISPUTE_RESPONSE_BLOCKS)?,
            dispute_arm_blocks: r.read_u32_opt(DISPUTE_ARM_BLOCKS)?,
            service_response_blocks: r.read_u32_opt(SERVICE_RESPONSE_BLOCKS)?,
            max_transfer_timeout_blocks: r.read_u32_opt(MAX_TRANSFER_TIMEOUT_BLOCKS)?,
            max_descriptor_bytes: r.read_u32_opt(MAX_DESCRIPTOR_BYTES)?,
            compensation_bps: r.read_u16_opt(COMPENSATION_BPS)?,
            compensation_deposit_id: r.read_deposit_id_opt(COMPENSATION_DEPOSIT_ID)?,
            compensation_frequency_blocks: r.read_u32_opt(COMPENSATION_FREQUENCY_BLOCKS)?,
        })
    }
}

/// BIP-340 tagged digest: `SHA256(SHA256(tag) || SHA256(tag) || encoded)`.
///
/// `encoded` is the canonical TLV bytes from [`QuorumMemberResponse::tlv_encode`].
/// Pass the digest into a `bip340_sign` / `bip340_verify` call.
pub fn quorum_member_response_digest(encoded: &[u8]) -> [u8; 32] {
    let tag = sha256::Hash::hash(QUORUM_MEMBER_RESPONSE_TAG.as_bytes());
    let mut buf = Vec::with_capacity(64 + encoded.len());
    buf.extend_from_slice(tag.as_byte_array());
    buf.extend_from_slice(tag.as_byte_array());
    buf.extend_from_slice(encoded);
    *sha256::Hash::hash(&buf).as_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn sample() -> QuorumMemberResponse {
        let secp = Secp256k1::new();
        let m = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let o = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());
        QuorumMemberResponse {
            response_version: QUORUM_MEMBER_RESPONSE_VERSION,
            member_pubkey: m,
            operator_pubkey: o,
            operator_ledger_id: "ab".repeat(32),
            chosen_ruleset: "legacy".to_string(),
            supported_rulesets: vec!["legacy".to_string(), "cltv-offset-v2".to_string()],
            member_ledger_id: "cd".repeat(32),
            min_fee_bps: Some(100),
            min_fee_fixed: None,
            max_fee_period: Some(52_560),
            membership_until: Some(900_000),
            dispute_response_blocks: Some(144),
            dispute_arm_blocks: Some(48),
            service_response_blocks: None,
            max_transfer_timeout_blocks: Some(1008),
            max_descriptor_bytes: Some(2048),
            compensation_bps: Some(300),
            compensation_deposit_id: Some([0xAB; 16]),
            compensation_frequency_blocks: Some(4032),
        }
    }

    #[test]
    fn roundtrip_full() {
        let r = sample();
        let bytes = r.tlv_encode();
        let decoded = QuorumMemberResponse::tlv_decode(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn roundtrip_minimal() {
        let mut r = sample();
        r.min_fee_bps = None;
        r.max_fee_period = None;
        r.membership_until = None;
        r.dispute_response_blocks = None;
        r.dispute_arm_blocks = None;
        r.max_transfer_timeout_blocks = None;
        r.max_descriptor_bytes = None;
        r.compensation_bps = None;
        r.compensation_deposit_id = None;
        r.compensation_frequency_blocks = None;
        let bytes = r.tlv_encode();
        let decoded = QuorumMemberResponse::tlv_decode(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn digest_is_stable_under_reencoding() {
        let r = sample();
        let d1 = quorum_member_response_digest(&r.tlv_encode());
        let d2 = quorum_member_response_digest(&r.tlv_encode());
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_changes_when_any_field_changes() {
        let r = sample();
        let d_orig = quorum_member_response_digest(&r.tlv_encode());

        let mut r2 = r.clone();
        r2.chosen_ruleset = "cltv-offset-v2".to_string();
        let d_alt = quorum_member_response_digest(&r2.tlv_encode());
        assert_ne!(d_orig, d_alt);

        let mut r3 = r;
        r3.min_fee_bps = Some(101);
        let d_alt = quorum_member_response_digest(&r3.tlv_encode());
        assert_ne!(d_orig, d_alt);
    }
}
