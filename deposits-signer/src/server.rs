//! Server side of the daemon ↔ signer RPC.
//!
//! `serve_connection` runs the handshake + per-call dispatch on a single
//! accepted stream. Today's implementation uses the `LocalSigner` from
//! `deposits-signer-api` to carry out signs; phase-6 will wrap it with an
//! anti-equivocation policy layer.

use bitcoin::secp256k1::{
    rand::{rngs::OsRng, RngCore},
    Keypair, Message, PublicKey, Secp256k1,
};
use deposits_signer_api::{
    wire::{
        auth_digest, hello_ack_digest, Auth, Hello, HelloAck, SignErrorKind, SignOp, SignRequest,
        SignResponse, SignResult,
    },
    LocalSigner, SignContext, Signer, SignerError,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::framing::{read_frame, write_frame, FrameError};
use crate::policy::SeqPolicy;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("framing: {0}")]
    Frame(#[from] FrameError),
    #[error("handshake: {0}")]
    Handshake(String),
    #[error("crypto: {0}")]
    Crypto(String),
}

/// Server-side configuration for a single signer connection.
pub struct ServerCtx {
    /// The signer's transport keypair (long-lived; loaded from `data-dir/transport_secret`).
    pub transport: Keypair,
    /// Pubkeys allowed to connect.
    pub allowlist: Vec<PublicKey>,
    /// Carries out the actual signs once the handshake completes.
    /// Used as a fallback when no `seed` is configured (legacy
    /// constructors), or before the per-connection signer is built
    /// from the daemon-supplied network.
    pub signer: Arc<dyn Signer>,
    /// Master seed. When present, every connection builds its own
    /// `LocalSigner` from `(seed, network from Hello)` so the xpubs
    /// the daemon receives carry version bytes that match the
    /// daemon's network — no `Invalid network` rejection on the BDK
    /// descriptor side.
    pub seed: Option<[u8; 32]>,
    /// Anti-equivocation policy: refuses operator/cosigner sigs that would
    /// regress or repeat a `(ledger_id, role) → max_seq`. Shared across all
    /// connections (a hot-spare daemon racing on the same key would have
    /// both nodes hit the same instance — only one of their `seq` values
    /// gets through).
    pub policy: Arc<SeqPolicy>,
}

impl ServerCtx {
    /// Legacy two-secret constructor — operator + Nostr only. Refuses
    /// `KeyPath::Deposit { index }` requests because there's no master
    /// xpriv to derive from. Kept for tests; production builds use
    /// `from_seed` which can serve every key path *and* match the
    /// daemon's network on per-connection xpubs.
    pub fn from_local(
        transport_secret: bitcoin::secp256k1::SecretKey,
        allowlist: Vec<PublicKey>,
        operator_secret: bitcoin::secp256k1::SecretKey,
        nostr_secret: bitcoin::secp256k1::SecretKey,
        policy: Arc<SeqPolicy>,
    ) -> Self {
        let secp = Secp256k1::new();
        let transport = Keypair::from_secret_key(&secp, &transport_secret);
        let signer: Arc<dyn Signer> = Arc::new(LocalSigner::with_nostr_secret(
            operator_secret,
            nostr_secret,
        ));
        Self {
            transport,
            allowlist,
            signer,
            seed: None,
            policy,
        }
    }

    /// Master-xpriv constructor. Kept for tests that hand in a
    /// pre-built xpriv and don't need network-aware xpubs (the xpriv's
    /// network is whatever the caller picked at construction).
    /// Production code uses [`from_seed`] instead.
    pub fn from_xpriv(
        transport_secret: bitcoin::secp256k1::SecretKey,
        allowlist: Vec<PublicKey>,
        xpriv: bitcoin::bip32::Xpriv,
        policy: Arc<SeqPolicy>,
    ) -> Result<Self, ServerError> {
        let secp = Secp256k1::new();
        let transport = Keypair::from_secret_key(&secp, &transport_secret);
        let local = LocalSigner::from_xpriv_with_nostr(xpriv).map_err(|e| {
            ServerError::Crypto(format!("LocalSigner::from_xpriv_with_nostr: {}", e))
        })?;
        let signer: Arc<dyn Signer> = Arc::new(local);
        Ok(Self {
            transport,
            allowlist,
            signer,
            seed: None,
            policy,
        })
    }

    /// Seed-based constructor. The seed is retained so each
    /// connection can build a per-network LocalSigner once Hello
    /// reports the daemon's network. The fallback `signer` is built
    /// at `Network::Bitcoin` (matches the prior hard-coded default
    /// for any code path that doesn't yet read the network).
    pub fn from_seed(
        transport_secret: bitcoin::secp256k1::SecretKey,
        allowlist: Vec<PublicKey>,
        seed: [u8; 32],
        policy: Arc<SeqPolicy>,
    ) -> Result<Self, ServerError> {
        let secp = Secp256k1::new();
        let transport = Keypair::from_secret_key(&secp, &transport_secret);
        let xpriv = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Bitcoin, &seed)
            .map_err(|e| ServerError::Crypto(format!("Xpriv::new_master: {}", e)))?;
        let local = LocalSigner::from_xpriv_with_nostr(xpriv).map_err(|e| {
            ServerError::Crypto(format!("LocalSigner::from_xpriv_with_nostr: {}", e))
        })?;
        let signer: Arc<dyn Signer> = Arc::new(local);
        Ok(Self {
            transport,
            allowlist,
            signer,
            seed: Some(seed),
            policy,
        })
    }

    /// Build a per-connection `Signer` for the given network. Falls
    /// back to the pre-built `self.signer` when `self.seed` is None.
    pub(crate) fn signer_for_network(&self, network: bitcoin::Network) -> Arc<dyn Signer> {
        let seed = match self.seed {
            Some(s) => s,
            None => return Arc::clone(&self.signer),
        };
        let xpriv = match bitcoin::bip32::Xpriv::new_master(network, &seed) {
            Ok(x) => x,
            Err(_) => return Arc::clone(&self.signer),
        };
        match LocalSigner::from_xpriv_with_nostr(xpriv) {
            Ok(local) => Arc::new(local),
            Err(_) => Arc::clone(&self.signer),
        }
    }
}

pub async fn serve_connection<S>(stream: &mut S, ctx: &ServerCtx) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let secp = Secp256k1::<bitcoin::secp256k1::All>::new();

    // 1. Receive Hello.
    let hello: Hello = read_frame(stream).await?;
    if !ctx.allowlist.iter().any(|pk| *pk == hello.node_pubkey) {
        return Err(ServerError::Handshake(format!(
            "node pubkey {} not in allowlist",
            hex::encode(hello.node_pubkey.serialize())
        )));
    }

    // 2. Build + sign HelloAck. Sign over hello_ack_digest(nonce_a, node_pubkey).
    let mut nonce_b = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_b);
    let ack_digest = hello_ack_digest(&hello.nonce_a, &hello.node_pubkey);
    let ack_msg = Message::from_digest(ack_digest);
    let sig_signer = secp
        .sign_schnorr_no_aux_rand(&ack_msg, &ctx.transport)
        .serialize();
    let signer_pubkey = PublicKey::from_keypair(&ctx.transport);
    let ack = HelloAck {
        signer_pubkey,
        nonce_b,
        sig_signer,
    };
    write_frame(stream, &ack).await?;

    // 3. Receive Auth from daemon. Verify against auth_digest(nonce_b, signer_pubkey).
    let auth: Auth = read_frame(stream).await?;
    let auth_dgst = auth_digest(&nonce_b, &signer_pubkey);
    let auth_msg = Message::from_digest(auth_dgst);
    let auth_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&auth.sig_node)
        .map_err(|e| ServerError::Handshake(format!("auth sig parse: {}", e)))?;
    let node_xonly = hello.node_pubkey.x_only_public_key().0;
    secp.verify_schnorr(&auth_sig, &auth_msg, &node_xonly)
        .map_err(|e| ServerError::Handshake(format!("auth sig verify: {}", e)))?;

    tracing::info!(
        "handshake ok with node {} (network={:?})",
        &hex::encode(hello.node_pubkey.serialize())[..12],
        hello.network,
    );

    // Build a per-connection signer rooted at the daemon's network.
    // For seed-based ServerCtx this means xpubs returned via
    // `WalletAccountXpub` carry the right version bytes for the
    // daemon's BDK descriptors. Fallback ctx (no seed configured)
    // uses the pre-built signer as before.
    let conn_signer = ctx.signer_for_network(hello.network);

    // 4. Per-call dispatch loop. Frames stay plaintext over the local
    //    Unix socket (filesystem perms + handshake do the access control);
    //    AEAD sealing is a future-phase concern when transport goes remote.
    loop {
        let req: SignRequest = match read_frame(stream).await {
            Ok(r) => r,
            Err(FrameError::Eof) => {
                tracing::debug!("connection closed by client");
                return Ok(());
            }
            Err(e) => return Err(ServerError::Frame(e)),
        };
        let response = handle_request(&*conn_signer, &ctx.policy, req);
        write_frame(stream, &response).await?;
    }
}

fn handle_request(
    signer: &dyn Signer,
    policy: &SeqPolicy,
    req: SignRequest,
) -> SignResponse {
    // Anti-equivocation gate. Only BIP-340 ops with a ledger-bound role
    // run through the policy; ECDSA sighashes and ECDH have no SeqContext,
    // PubkeyQuery is read-only.
    if matches!(&req.op, SignOp::Bip340 { .. }) {
        if let Err(e) = policy.check_and_record(&req.ctx.role) {
            return SignResponse {
                id: req.id,
                result: SignResult::Error {
                    kind: SignErrorKind::PolicyRefused,
                    message: e.to_string(),
                },
            };
        }
    }

    let result = match req.op {
        SignOp::Bip340 { digest } => match signer.bip340_sign(&req.ctx, &digest) {
            Ok(sig) => SignResult::Bip340Sig { sig },
            Err(e) => signer_error_to_result(e),
        },
        SignOp::Ecdsa { sighash } => match signer.ecdsa_sign_sighash(&req.ctx, &sighash) {
            Ok(sig) => SignResult::EcdsaSig {
                sig_compact: sig.serialize_compact(),
            },
            Err(e) => signer_error_to_result(e),
        },
        SignOp::Ecdh { peer } => match signer.ecdh(&peer) {
            Ok(shared) => SignResult::EcdhSecret { shared },
            Err(e) => signer_error_to_result(e),
        },
        SignOp::Nip04SharedKey { peer } => match signer.nip04_shared_key(&peer) {
            Ok(key) => SignResult::Nip04SharedKey { key },
            Err(e) => signer_error_to_result(e),
        },
        SignOp::PubkeyQuery => SignResult::Pubkey {
            pubkey: signer.pubkey(),
            xonly: signer.xonly_pubkey(),
        },
        SignOp::IssueNostrSecret => match signer.issue_nostr_secret() {
            Ok(sk) => SignResult::IssuedSecret { sk },
            Err(e) => signer_error_to_result(e),
        },
        SignOp::WalletAccountXpub { account } => match signer.wallet_account_xpub(account) {
            Ok(xpub) => SignResult::WalletAccountXpub {
                xpub_str: xpub.to_string(),
            },
            Err(e) => signer_error_to_result(e),
        },
    };
    SignResponse { id: req.id, result }
}

fn signer_error_to_result(e: SignerError) -> SignResult {
    let (kind, message) = match e {
        SignerError::PolicyRefused(m) => (SignErrorKind::PolicyRefused, m),
        SignerError::Crypto(m) => (SignErrorKind::Crypto, m),
        SignerError::Transport(m) => (SignErrorKind::Crypto, m),
        SignerError::Unsupported(m) => (SignErrorKind::Unsupported, m),
    };
    SignResult::Error { kind, message }
}

/// Used by the integration test in `deposits-signer-api`-aware crates to
/// drive a server side directly without standing up a Unix socket.
#[doc(hidden)]
pub fn _handle_request_for_test(
    signer: &dyn Signer,
    policy: &SeqPolicy,
    req: SignRequest,
) -> SignResponse {
    handle_request(signer, policy, req)
}

/// Re-export of [`SignContext`] so the integration test (in `deposits-signer-api`'s
/// downstream) can import a single thing.
pub use deposits_signer_api::SignContext as ReexportedSignContext;
#[allow(dead_code)]
fn _suppress_unused_reexport() {
    let _ = std::any::TypeId::of::<SignContext>();
}
