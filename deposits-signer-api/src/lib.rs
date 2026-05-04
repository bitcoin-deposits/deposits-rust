//! Signer abstraction for deposits-node.
//!
//! The `Signer` trait is the single interface through which the daemon obtains
//! BIP-340 / ECDSA signatures and ECDH shared secrets. Two impls live behind it:
//!
//! - [`LocalSigner`] — holds a `SecretKey` in process; matches today's behaviour.
//! - `RemoteSigner` (in `deposits-node`) — talks to the `deposits-signer` binary
//!   over a Unix socket; the daemon never sees the seed.
//!
//! See `PLAN-remote-signer.md` for the full design.
//!
//! # Why callers pre-hash for BIP-340
//!
//! The trait takes a 32-byte digest, not a payload. Two reasons:
//!
//! 1. Existing call sites already compute their own domain-separated digests
//!    (BIP-340 tagged hashes for `invoice_cosign_signing_message`,
//!    `sha256("DEPOSIT_GUARANTEE:…")` and so on). Phase-2 keeps the contract
//!    the same so the refactor in phase-3 is mechanical.
//! 2. The `purpose` field on [`SignContext`] still travels alongside the
//!    digest. A future signer-side enforcement layer can refuse to sign a
//!    digest under a `purpose` that doesn't match — once we move the hashing
//!    into the signer (phase-6+), this gets stronger.

mod local;
pub mod wire;

pub use local::LocalSigner;

use bitcoin::secp256k1::ecdsa;
use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

/// Errors a [`Signer`] can return.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("signer policy refused: {0}")]
    PolicyRefused(String),
    #[error("signer transport error: {0}")]
    Transport(String),
    #[error("signer crypto error: {0}")]
    Crypto(String),
    #[error("signer was asked for an unsupported operation: {0}")]
    Unsupported(String),
}

/// What role the daemon is playing for this signature.
///
/// `OperatorUpdate` and `CosignUpdate` carry the `seq` so the signer's
/// anti-equivocation policy (phase-6) can refuse regressions. Phase-2
/// `LocalSigner` ignores the role; the field is on the wire so the protocol
/// is forward-compatible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigRole {
    /// Not bound to a ledger — Nostr identity sigs, attestations, invoice
    /// cosignatures over BOLT11, ad-hoc protocol sigs.
    NoLedger,

    /// We are signing the `content_hash` of *our own* ledger update at `seq`.
    /// Anti-equivocation policy: refuse `seq <= last_seq_signed[ledger_id]`.
    OperatorUpdate {
        ledger_id: [u8; 32],
        seq: u64,
    },

    /// We are signing a cosignature on *another operator's* ledger at `seq`,
    /// committing to our own ledger head `member_ledger_hash`.
    ///
    /// Anti-equivocation policy: refuse `seq <= last_cosign_seq[op_ledger_id]`,
    /// and (later) refuse a `member_ledger_hash` that's older than our last
    /// commitment.
    CosignUpdate {
        operator_ledger_id: [u8; 32],
        seq: u64,
        member_ledger_hash: [u8; 32],
    },
}

/// Why we are asking for this signature. Distinct from `SigRole`: a single
/// role can produce multiple purpose-tagged signatures, and a single purpose
/// can apply across roles.
///
/// The signer uses `purpose` for audit logging and (eventually) to refuse
/// signing a digest whose claimed purpose doesn't match the digest's
/// domain-separation hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigPurpose {
    /// Raw BIP-340 over a 32-byte digest with no domain separation.
    /// Used for `content_hash` signing on ledger updates.
    Bip340Untagged,

    /// BIP-340 with the `invoice_cosign_signing_message` tagged hash.
    /// Caller has already applied the tag.
    InvoiceCosign,

    /// Nostr event signature (over the event id).
    NostrEvent,

    /// DEP-04 subkey attestation.
    Attestation,

    /// `DEPOSIT_GUARANTEE:…` domain-separated message.
    DepositGuarantee,

    /// Payment co-signature (`deposits-core::signing::create_payment_signature`).
    Payment,

    /// Payment authorization signature.
    PaymentAuthorization,

    /// Deposit-offer signature.
    DepositOffer,

    /// Withdrawal signature.
    Withdrawal,

    /// On-chain sighash for ECDSA (legacy P2WSH path).
    OnchainSighash,
}

/// All metadata a signer needs about a single signature request.
///
/// Carried as a thin struct so future extensions (audit timestamp, request id,
/// transport headers) don't churn the trait.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignContext {
    pub role: SigRole,
    pub purpose: SigPurpose,
}

impl SignContext {
    /// No-ledger context with a given purpose. Used everywhere the signature
    /// isn't bound to a ledger seq — Nostr events, invoice cosignatures,
    /// attestations, ECDSA-sighash for wallet PSBTs, etc.
    pub fn no_ledger(purpose: SigPurpose) -> Self {
        Self {
            role: SigRole::NoLedger,
            purpose,
        }
    }

    /// Operator signing their own ledger update at `seq`.
    pub fn operator_update(ledger_id: [u8; 32], seq: u64) -> Self {
        Self {
            role: SigRole::OperatorUpdate { ledger_id, seq },
            purpose: SigPurpose::Bip340Untagged,
        }
    }

    /// Cosignature on another operator's ledger update at `seq`.
    pub fn cosign_update(
        operator_ledger_id: [u8; 32],
        seq: u64,
        member_ledger_hash: [u8; 32],
    ) -> Self {
        Self {
            role: SigRole::CosignUpdate {
                operator_ledger_id,
                seq,
                member_ledger_hash,
            },
            purpose: SigPurpose::Bip340Untagged,
        }
    }
}

/// The single interface the daemon uses to obtain signatures and ECDH secrets.
///
/// Implementations are expected to be `Send + Sync`; the daemon will share a
/// single `Arc<dyn Signer>` across its actor pool.
pub trait Signer: Send + Sync {
    /// Public key of this signer (the operator/identity key today; one signer
    /// = one key in v1).
    fn pubkey(&self) -> PublicKey;

    /// X-only form of [`pubkey`], for BIP-340 verification and Nostr.
    fn xonly_pubkey(&self) -> XOnlyPublicKey;

    /// BIP-340 sign a 32-byte digest.
    ///
    /// `ctx.role` and `ctx.purpose` carry context for audit and (later)
    /// signer-side policy. Phase-2 `LocalSigner` ignores both.
    fn bip340_sign(
        &self,
        ctx: &SignContext,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], SignerError>;

    /// ECDSA sign a sighash. Used by the legacy P2WSH single-sig path in
    /// `wallet.rs:1134`. The returned signature does not include the sighash
    /// flag byte; callers append it.
    fn ecdsa_sign_sighash(
        &self,
        ctx: &SignContext,
        sighash: &[u8; 32],
    ) -> Result<ecdsa::Signature, SignerError>;

    /// ECDH shared secret with `peer`, used by `nostr.rs` for NIP-04 / NIP-44
    /// envelope crypto. The signer does only the asymmetric step; the daemon
    /// runs the symmetric AEAD.
    fn ecdh(&self, peer: &PublicKey) -> Result<[u8; 32], SignerError>;

    /// Issue a sibling-derived **Nostr identity** secret that the daemon
    /// holds locally for Nostr-layer ops (event signing, NIP-04 ECDH,
    /// gift-wrap seals).
    ///
    /// The Nostr key is structurally separate from the operator/protocol key:
    /// compromise of the daemon leaks the Nostr key (attacker can sign fake
    /// events from the daemon's Nostr pubkey, decrypt DMs sent to it,
    /// encrypt outbound), but the operator key — the one slashing depends on
    /// — stays put on the signer. The `Signer` trait sees this as an
    /// explicit privilege escalation request, distinct from
    /// per-call signature ops.
    ///
    /// Returns the 32-byte secret. Default impl returns `Unsupported` for
    /// signer flavors that don't support derivation (e.g. a single-key
    /// `LocalSigner` constructed via [`LocalSigner::new`]).
    fn issue_nostr_secret(&self) -> Result<[u8; 32], SignerError> {
        Err(SignerError::Unsupported(
            "this signer does not issue a Nostr identity secret".to_string(),
        ))
    }
}

/// Newtype around a 64-byte BIP-340 signature so callers don't accidentally
/// confuse it with arbitrary 64-byte buffers. (Internal use; trait still
/// returns the raw array for compatibility with existing call sites.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bip340Sig(pub [u8; 64]);

impl Bip340Sig {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}
