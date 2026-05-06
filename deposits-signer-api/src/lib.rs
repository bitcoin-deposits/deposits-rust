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

/// Which seed-derived key this signature should come from.
///
/// `Operator` is the default — it's the one the signer's transport
/// pubkey resolves to and the one the protocol's slashing semantics
/// gate on. `Deposit { index }` covers the daemon's "internal deposit"
/// flows (`admin.rs` lock/fulfill, `node_cli/{lightning,withdraw}.rs`
/// settle paths) that historically derived their key locally via
/// `derive_deposit_key_at(index)` against the daemon's master seed.
/// Routing them through the same Signer means the daemon doesn't need
/// the master seed in process for those paths either.
///
/// New variants land here when more daemon-internal keys need
/// signer-mediated access. Kept narrow on purpose: every variant the
/// signer accepts is a privilege escalation, so each addition is
/// deliberate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPath {
    /// Operator/identity key. BIP-32 path `m/86'/0'/0'/0/0` against the
    /// master seed. The default for every protocol-level sign.
    Operator,
    /// Internal-deposit key at `m/84'/0'/0'/0/{index}`. Same derivation
    /// `derive_deposit_key_at(index)` produces in `node_cli/keys.rs`.
    Deposit {
        index: u32,
    },
    /// Per-ledger BDK wallet key at `m/86'/0'/<account>'/<change>/<index>`.
    /// Used by the watch-only on-chain signing path: the daemon holds an
    /// xpub at `m/86'/0'/<account>'` and asks the signer to sign each
    /// PSBT input's sighash at the corresponding `<change>/<index>` leaf.
    /// `change` is 0 for external (receive) and 1 for internal (change).
    Wallet {
        account: u32,
        change: u8,
        index: u32,
    },
    /// Node-level (operator general-balance) wallet key at
    /// `m/<change>/<index>`. The daemon holds the *master* xpub
    /// (via [`Signer::master_xpub`]) and embeds it in a watch-only
    /// descriptor; signing routes back through the signer here.
    NodeWallet {
        change: u8,
        index: u32,
    },
}

impl Default for KeyPath {
    fn default() -> Self {
        Self::Operator
    }
}

/// All metadata a signer needs about a single signature request.
///
/// Carried as a thin struct so future extensions (audit timestamp, request id,
/// transport headers) don't churn the trait.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignContext {
    pub role: SigRole,
    pub purpose: SigPurpose,
    /// Which seed-derived key to sign with. Defaults to `Operator` so
    /// existing call sites that don't care about the new field don't
    /// need to change.
    #[serde(default)]
    pub key: KeyPath,
}

impl SignContext {
    /// No-ledger context with a given purpose. Used everywhere the signature
    /// isn't bound to a ledger seq — Nostr events, invoice cosignatures,
    /// attestations, ECDSA-sighash for wallet PSBTs, etc.
    pub fn no_ledger(purpose: SigPurpose) -> Self {
        Self {
            role: SigRole::NoLedger,
            purpose,
            key: KeyPath::Operator,
        }
    }

    /// Operator signing their own ledger update at `seq`.
    pub fn operator_update(ledger_id: [u8; 32], seq: u64) -> Self {
        Self {
            role: SigRole::OperatorUpdate { ledger_id, seq },
            purpose: SigPurpose::Bip340Untagged,
            key: KeyPath::Operator,
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
            key: KeyPath::Operator,
        }
    }

    /// Sign with an internal deposit key at the given index. Used by
    /// admin lock/fulfill and node_cli/{lightning,withdraw}.rs flows
    /// that act on behalf of internal deposits the daemon owns.
    pub fn deposit(index: u32, purpose: SigPurpose) -> Self {
        Self {
            role: SigRole::NoLedger,
            purpose,
            key: KeyPath::Deposit { index },
        }
    }

    /// Builder-style override: change which key this context targets.
    /// Useful for tests or for specializing a stock context.
    pub fn with_key(mut self, key: KeyPath) -> Self {
        self.key = key;
        self
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

    /// Return the pubkey at the given [`KeyPath`] without exposing the
    /// secret. Used by daemon flows that need to *advertise* the
    /// public material at a derivation path (e.g. compute a buffer
    /// deposit's `deposit_pubkey` for a freshly-issued buffer index)
    /// but never need to sign with it themselves.
    ///
    /// Default impl maps the common variants on top of [`pubkey`]
    /// (which every signer must support). Signers that can derive
    /// other paths override.
    fn pubkey_at(&self, key_path: KeyPath) -> Result<PublicKey, SignerError> {
        match key_path {
            KeyPath::Operator => Ok(self.pubkey()),
            other => Err(SignerError::Unsupported(format!(
                "this signer does not support pubkey_at({:?})",
                other
            ))),
        }
    }

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

    /// ECDH shared secret with `peer` — *SHA-256-hashed form*, returned by
    /// `bitcoin::secp256k1::ecdh::SharedSecret::new`. Used by NIP-44 (which
    /// HKDFs over this) and any caller that wants the standard hashed
    /// shared-secret. **Not** what NIP-04 uses; NIP-04 wants the raw X
    /// coordinate of the shared point — see [`nip04_shared_key`].
    fn ecdh(&self, peer: &PublicKey) -> Result<[u8; 32], SignerError>;

    /// NIP-04 shared key with `peer`: the first 32 bytes of the raw ECDH
    /// shared *point* (`ecdh::shared_secret_point`), no hashing applied.
    /// Matches `nostr/util::generate_shared_key` and is the symmetric key
    /// for NIP-04's AES-256-CBC envelope.
    ///
    /// Distinct from [`ecdh`] because NIP-04 chose a non-standard
    /// derivation that pre-dates the convention `secp256k1::SharedSecret`
    /// applies. They produce different bytes; using the wrong one yields
    /// unreadable ciphertext.
    ///
    /// Default impl returns `Unsupported` for signers that don't support
    /// the raw-X form (e.g. an HSM-style signer that only exposes the
    /// hashed variant). Production deposits-signer + LocalSigner both
    /// override.
    fn nip04_shared_key(&self, peer: &PublicKey) -> Result<[u8; 32], SignerError> {
        let _ = peer;
        Err(SignerError::Unsupported(
            "this signer does not expose the NIP-04 raw-X shared key".to_string(),
        ))
    }

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

    /// BIP-32 xpub at `m/86'/0'/<account>'`. The daemon embeds this in
    /// the watch-only descriptor `wpkh(account_xpub/<change>/*)` for a
    /// per-ledger BDK wallet, then asks the signer to sign each PSBT
    /// input's sighash via [`KeyPath::Wallet { account, change, index }`].
    /// The seed never leaves the signer; the daemon only ever sees
    /// derived-public material.
    ///
    /// Default impl returns `Unsupported` for signers that don't have a
    /// master xpriv. Production deposits-signer + xpriv-aware
    /// LocalSigner override.
    fn wallet_account_xpub(&self, account: u32) -> Result<bitcoin::bip32::Xpub, SignerError> {
        let _ = account;
        Err(SignerError::Unsupported(
            "this signer cannot issue per-account xpubs".to_string(),
        ))
    }

    /// BIP-32 xpub at the master path `m`. The daemon embeds it in a
    /// watch-only descriptor `wpkh(master_xpub/<change>/*)` for the
    /// node-level (operator general-balance) wallet — receiving
    /// addresses for incoming deposits, change/internal addresses,
    /// and the source of `wallet.send_withdrawal` UTXOs. Signing
    /// routes back through the signer via [`KeyPath::NodeWallet`].
    ///
    /// Default impl returns `Unsupported`. Production deposits-signer
    /// + xpriv-aware LocalSigner override.
    fn master_xpub(&self) -> Result<bitcoin::bip32::Xpub, SignerError> {
        Err(SignerError::Unsupported(
            "this signer cannot issue a master xpub".to_string(),
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
