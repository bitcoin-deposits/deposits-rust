//! Wire types for the daemon ↔ signer RPC.
//!
//! Both the `deposits-signer` binary and the `RemoteSigner` client in
//! `deposits-node` depend on these; landing the shape here in the shared
//! crate keeps them in sync.
//!
//! ## Framing
//!
//! Every frame on the socket is `[len: u32 big-endian][payload]`. The payload
//! is JSON for v1. After the [`Auth`] step completes, payloads are AEAD-sealed
//! under a session key derived from the two transport keypairs (see
//! `PLAN-remote-signer.md` §wire). Phase-4a defines the message shapes; the
//! binary in phase-4b layers the framing + encryption on top.
//!
//! ## Sequence
//!
//! ```text
//!   daemon                                              signer
//!     |                                                    |
//!     | --- Hello { node_pubkey, nonce_a }              -->|
//!     |                                                    | (allowlist check)
//!     | <-- HelloAck { signer_pubkey, nonce_b, sig_a }  ---|
//!     | (verify sig_a, derive session key via ECDH)        |
//!     | --- Auth { sig_b }                              -->|
//!     |                                                    | (verify sig_b)
//!     | <----- (channel becomes AEAD-sealed) ---------     |
//!     |                                                    |
//!     | --- SignRequest { id, ctx, op } (sealed)        -->|
//!     | <-- SignResponse { id, result } (sealed)       ----|
//!     | ...                                                |
//! ```
//!
//! Multiple sign requests can be in flight; `id` matches responses to
//! requests. Phase-4b's binary serializes a single mpsc on the server side
//! so policy enforcement sees them in arrival order.

use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use crate::SignContext;

/// Hex-string serde shim for fixed byte arrays. JSON readability over raw
/// JSON arrays of integers, and round-trip stable. Used for the 32- and
/// 64-byte fields in the wire types.
mod hexarray {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = <&str>::deserialize(d)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != N {
            return Err(serde::de::Error::custom(format!(
                "expected {} hex bytes, got {}",
                N,
                bytes.len()
            )));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// Opening message from the daemon to the signer.
///
/// `node_pubkey` is the daemon's transport pubkey (separate from the operator
/// key the protocol cares about). `nonce_a` is fresh per connection;
/// `sig_signer` in [`HelloAck`] commits to `nonce_a || node_pubkey`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// 32-byte protocol version + capabilities tag. v1: all-zero.
    #[serde(with = "hexarray")]
    pub version: [u8; 16],
    /// Daemon's transport pubkey (must be in the signer's allowlist).
    pub node_pubkey: PublicKey,
    /// Fresh 32-byte challenge nonce.
    #[serde(with = "hexarray")]
    pub nonce_a: [u8; 32],
    /// Bitcoin network the daemon is operating on. The signer uses
    /// this to construct its master xpriv with matching version
    /// bytes so any xpub it returns (e.g. via [`SignOp::WalletAccountXpub`])
    /// parses correctly in BDK descriptors on the daemon side.
    /// `#[serde(default)]` keeps wire compatibility — older daemons
    /// that don't include the field will be treated as `Bitcoin`,
    /// matching the prior hard-coded default in deposits-signer.
    #[serde(default = "default_network")]
    pub network: bitcoin::Network,
}

fn default_network() -> bitcoin::Network {
    bitcoin::Network::Bitcoin
}

/// Signer's response to [`Hello`].
///
/// `sig_signer` proves possession of the signer's transport secret; the
/// daemon verifies it against the configured `--signer-pubkey`. `nonce_b`
/// is the signer's challenge for the daemon to sign in [`Auth`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    /// Signer's transport pubkey. Daemon must match against
    /// `--signer-pubkey`.
    pub signer_pubkey: PublicKey,
    /// Fresh 32-byte challenge from the signer.
    #[serde(with = "hexarray")]
    pub nonce_b: [u8; 32],
    /// BIP-340 sig over `sha256("deposits-signer/hello-ack" || nonce_a ||
    /// node_pubkey)` with the signer's transport key.
    #[serde(with = "hexarray")]
    pub sig_signer: [u8; 64],
}

/// Daemon's reply to [`HelloAck`], completing the handshake.
///
/// Both sides then derive a session key by ECDH on the two transport
/// pubkeys, mixed with both nonces. Subsequent frames are AEAD-sealed under
/// that key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Auth {
    /// BIP-340 sig over `sha256("deposits-signer/auth" || nonce_b ||
    /// signer_pubkey)` with the daemon's transport key.
    #[serde(with = "hexarray")]
    pub sig_node: [u8; 64],
}

/// Per-call signing request. Sent inside an AEAD-sealed frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    /// Caller-allocated correlation id. The signer echoes it on the response.
    pub id: u64,
    /// Role + purpose context (audit + future anti-equivocation policy).
    pub ctx: SignContext,
    /// What to sign / compute.
    pub op: SignOp,
}

/// Operations a signer can perform. Payload-bearing variants carry the
/// caller-prepared 32-byte digest (BIP-340 / ECDSA) or peer pubkey (ECDH);
/// the signer doesn't re-hash. See `lib.rs` for the rationale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignOp {
    /// BIP-340 over a 32-byte digest. The dominant op on the daemon hot path.
    Bip340 {
        #[serde(with = "hexarray")]
        digest: [u8; 32],
    },
    /// ECDSA over a 32-byte sighash, for the legacy P2WSH single-sig path
    /// in `wallet.rs:1134`. Returns a compact (64-byte) signature.
    Ecdsa {
        #[serde(with = "hexarray")]
        sighash: [u8; 32],
    },
    /// ECDH shared secret with `peer` (SHA-256-hashed form). Used by
    /// NIP-44 and other consumers that expect the standard hashed
    /// shared-secret.
    Ecdh {
        peer: PublicKey,
    },
    /// NIP-04 raw-X shared key with `peer`. Returns the first 32 bytes
    /// of the ECDH shared *point* (no hashing) — what NIP-04's AES-CBC
    /// envelope uses as its symmetric key. Distinct wire op from `Ecdh`
    /// because the two derivations produce different bytes; using the
    /// wrong one yields unreadable ciphertext.
    Nip04SharedKey {
        peer: PublicKey,
    },
    /// Just return the signer's identity pubkeys. The daemon caches these
    /// after handshake; `PubkeyQuery` exists for warm reconnect.
    PubkeyQuery,
    /// Issue a sibling-derived Nostr identity secret. Distinct from the
    /// per-call sign ops: the signer relinquishes a long-lived secret to
    /// the daemon (smaller blast-radius than the operator key, but still a
    /// privilege escalation). Daemon caches the result.
    IssueNostrSecret,
    /// Return the BIP-32 xpub at `m/86'/0'/<account>'`. The daemon embeds
    /// this in a watch-only descriptor so a per-ledger BDK wallet can
    /// derive its own receive/change addresses without holding the seed,
    /// and asks the signer to sign each PSBT input via
    /// [`crate::KeyPath::Wallet`].
    WalletAccountXpub {
        account: u32,
    },
    /// Return the master xpub at path `m`. The daemon embeds it in a
    /// watch-only node-level wallet descriptor `wpkh(master_xpub/<change>/*)`
    /// (the operator's general-balance wallet, used for incoming
    /// deposit funding addresses + outbound withdrawals). Signing
    /// routes back via [`crate::KeyPath::NodeWallet`].
    MasterXpub,
    /// Return the pubkey at the given [`crate::KeyPath`] without
    /// exposing the secret. Used by daemon admin flows that need to
    /// advertise public material at a derivation path (e.g.
    /// buffer-deposit `deposit_pubkey` for a freshly-issued buffer
    /// index) without ever holding the secret.
    PubkeyAt {
        key_path: crate::KeyPath,
    },
}

/// Server response to a [`SignRequest`]. Sent inside an AEAD-sealed frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignResponse {
    /// Echo of `SignRequest::id`.
    pub id: u64,
    /// Result, either a successful op or an error (policy refusal,
    /// crypto error, malformed request).
    pub result: SignResult,
}

/// Outcome of a [`SignOp`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignResult {
    Bip340Sig {
        #[serde(with = "hexarray")]
        sig: [u8; 64],
    },
    /// Compact (64-byte) ECDSA signature; caller appends the sighash flag
    /// byte before constructing the witness.
    EcdsaSig {
        #[serde(with = "hexarray")]
        sig_compact: [u8; 64],
    },
    EcdhSecret {
        #[serde(with = "hexarray")]
        shared: [u8; 32],
    },
    /// Result of [`SignOp::Nip04SharedKey`]: 32-byte raw-X NIP-04 key.
    Nip04SharedKey {
        #[serde(with = "hexarray")]
        key: [u8; 32],
    },
    Pubkey {
        pubkey: PublicKey,
        xonly: XOnlyPublicKey,
    },
    /// Result of `IssueNostrSecret`. The signer-side encoding is a 32-byte
    /// secret; the daemon imports it as its long-lived Nostr identity key.
    IssuedSecret {
        #[serde(with = "hexarray")]
        sk: [u8; 32],
    },
    /// Result of `WalletAccountXpub`. The serialized xpub (Base58Check
    /// encoded). Daemon parses with `bitcoin::bip32::Xpub::from_str`.
    WalletAccountXpub {
        xpub_str: String,
    },
    /// Result of `MasterXpub`. The serialized master xpub (Base58Check).
    MasterXpub {
        xpub_str: String,
    },
    /// Result of [`SignOp::PubkeyAt`]. The 33-byte compressed pubkey.
    PubkeyAt {
        pubkey: PublicKey,
    },
    /// Signer refused or failed to satisfy the request. The daemon
    /// surfaces this as a `SignerError`.
    Error {
        kind: SignErrorKind,
        message: String,
    },
}

/// Categorical error from the signer. Maps to [`crate::SignerError`] on the
/// daemon side after the wire result is decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignErrorKind {
    PolicyRefused,
    Crypto,
    Unsupported,
}

/// Domain-separation tag for the signer's `HelloAck` signature.
pub const HELLO_ACK_TAG: &[u8] = b"deposits-signer/hello-ack/v1";

/// Domain-separation tag for the daemon's `Auth` signature.
pub const AUTH_TAG: &[u8] = b"deposits-signer/auth/v1";

/// Compute the digest the signer signs in `HelloAck`:
/// `sha256(HELLO_ACK_TAG || nonce_a || node_pubkey)`.
pub fn hello_ack_digest(nonce_a: &[u8; 32], node_pubkey: &PublicKey) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};
    let mut buf = Vec::with_capacity(HELLO_ACK_TAG.len() + 32 + 33);
    buf.extend_from_slice(HELLO_ACK_TAG);
    buf.extend_from_slice(nonce_a);
    buf.extend_from_slice(&node_pubkey.serialize());
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Compute the digest the daemon signs in `Auth`:
/// `sha256(AUTH_TAG || nonce_b || signer_pubkey)`.
pub fn auth_digest(nonce_b: &[u8; 32], signer_pubkey: &PublicKey) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};
    let mut buf = Vec::with_capacity(AUTH_TAG.len() + 32 + 33);
    buf.extend_from_slice(AUTH_TAG);
    buf.extend_from_slice(nonce_b);
    buf.extend_from_slice(&signer_pubkey.serialize());
    sha256::Hash::hash(&buf).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalSigner, SigPurpose, Signer};

    #[test]
    fn hello_ack_digest_is_deterministic_and_distinct() {
        let pk1 = LocalSigner::random().pubkey();
        let pk2 = LocalSigner::random().pubkey();
        let nonce = [7u8; 32];

        let a = hello_ack_digest(&nonce, &pk1);
        let b = hello_ack_digest(&nonce, &pk1);
        let c = hello_ack_digest(&nonce, &pk2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn auth_digest_is_deterministic_and_distinct() {
        let pk1 = LocalSigner::random().pubkey();
        let pk2 = LocalSigner::random().pubkey();
        let nonce = [11u8; 32];

        let a = auth_digest(&nonce, &pk1);
        let b = auth_digest(&nonce, &pk1);
        let c = auth_digest(&nonce, &pk2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn hello_ack_and_auth_digests_have_different_domains() {
        // Tag separation: same nonce + same pubkey must produce
        // unrelated digests across the two contexts.
        let pk = LocalSigner::random().pubkey();
        let nonce = [1u8; 32];
        assert_ne!(hello_ack_digest(&nonce, &pk), auth_digest(&nonce, &pk));
    }

    #[test]
    fn hello_round_trips() {
        let pk = LocalSigner::random().pubkey();
        let hello = Hello {
            version: [0u8; 16],
            node_pubkey: pk,
            nonce_a: [42u8; 32],
            network: bitcoin::Network::Regtest,
        };
        let bytes = serde_json::to_vec(&hello).unwrap();
        let decoded: Hello = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(hello, decoded);
    }

    #[test]
    fn sign_request_round_trips_per_op() {
        let pk = LocalSigner::random().pubkey();
        let cases = vec![
            SignOp::Bip340 { digest: [3u8; 32] },
            SignOp::Ecdsa { sighash: [4u8; 32] },
            SignOp::Ecdh { peer: pk },
            SignOp::Nip04SharedKey { peer: pk },
            SignOp::PubkeyQuery,
            SignOp::IssueNostrSecret,
        ];
        for op in cases {
            let req = SignRequest {
                id: 99,
                ctx: SignContext::no_ledger(SigPurpose::Bip340Untagged),
                op,
            };
            let bytes = serde_json::to_vec(&req).unwrap();
            let decoded: SignRequest = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(req, decoded);
        }
    }

    #[test]
    fn sign_response_round_trips_per_result() {
        let pk = LocalSigner::random().pubkey();
        let xonly = pk.x_only_public_key().0;
        let cases = vec![
            SignResult::Bip340Sig { sig: [5u8; 64] },
            SignResult::EcdsaSig {
                sig_compact: [6u8; 64],
            },
            SignResult::EcdhSecret { shared: [7u8; 32] },
            SignResult::Nip04SharedKey { key: [0xa5u8; 32] },
            SignResult::Pubkey { pubkey: pk, xonly },
            SignResult::IssuedSecret { sk: [8u8; 32] },
            SignResult::Error {
                kind: SignErrorKind::PolicyRefused,
                message: "seq regression".to_string(),
            },
        ];
        for result in cases {
            let resp = SignResponse { id: 1, result };
            let bytes = serde_json::to_vec(&resp).unwrap();
            let decoded: SignResponse = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(resp, decoded);
        }
    }
}
