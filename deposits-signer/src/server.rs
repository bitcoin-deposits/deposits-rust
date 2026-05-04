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
    pub signer: Arc<dyn Signer>,
}

impl ServerCtx {
    pub fn from_local(
        transport_secret: bitcoin::secp256k1::SecretKey,
        allowlist: Vec<PublicKey>,
        operator_secret: bitcoin::secp256k1::SecretKey,
    ) -> Self {
        let secp = Secp256k1::new();
        let transport = Keypair::from_secret_key(&secp, &transport_secret);
        let signer: Arc<dyn Signer> = Arc::new(LocalSigner::new(operator_secret));
        Self {
            transport,
            allowlist,
            signer,
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
        "handshake ok with node {}",
        &hex::encode(hello.node_pubkey.serialize())[..12]
    );

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
        let response = handle_request(&*ctx.signer, req);
        write_frame(stream, &response).await?;
    }
}

fn handle_request(signer: &dyn Signer, req: SignRequest) -> SignResponse {
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
        SignOp::PubkeyQuery => SignResult::Pubkey {
            pubkey: signer.pubkey(),
            xonly: signer.xonly_pubkey(),
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
pub fn _handle_request_for_test(signer: &dyn Signer, req: SignRequest) -> SignResponse {
    handle_request(signer, req)
}

/// Re-export of [`SignContext`] so the integration test (in `deposits-signer-api`'s
/// downstream) can import a single thing.
pub use deposits_signer_api::SignContext as ReexportedSignContext;
#[allow(dead_code)]
fn _suppress_unused_reexport() {
    let _ = std::any::TypeId::of::<SignContext>();
}
