//! `RemoteSigner` — a `Signer` impl that talks to a `deposits-signer`
//! process over a Unix socket.
//!
//! The `Signer` trait is sync; the wire is async. To bridge the two,
//! `RemoteSigner` owns a single-thread tokio runtime and serializes calls
//! through a per-call `block_on`. A `tokio::sync::Mutex<UnixStream>`
//! guards the connection so one request finishes before the next starts;
//! id-correlation on the wire lets the protocol stay in lock-step with
//! the server's request loop.
//!
//! Connection lifecycle: opened in [`RemoteSigner::connect`] (the daemon
//! does the handshake there). Reused for the daemon's lifetime. If the
//! socket disconnects, every subsequent call returns `SignerError::Transport`
//! and the daemon is responsible for handling the failure (today: bubble
//! up; phase 6+: reconnect).

use bitcoin::secp256k1::{
    ecdh::SharedSecret, ecdsa, Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use deposits_signer_api::{
    wire::{
        auth_digest, hello_ack_digest, Auth, Hello, HelloAck, SignErrorKind, SignOp, SignRequest,
        SignResponse, SignResult,
    },
    SignContext, Signer, SignerError,
};
use deposits_signer::framing::{read_frame, write_frame, FrameError};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::UnixStream;
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;

/// `Signer` impl backed by a connected `deposits-signer` over Unix socket.
pub struct RemoteSigner {
    rt: Runtime,
    inner: Arc<AsyncMutex<Conn>>,
    next_id: AtomicU64,
    pubkey: PublicKey,
    xonly: XOnlyPublicKey,
}

struct Conn {
    reader: ReadHalf<UnixStream>,
    writer: WriteHalf<UnixStream>,
}

impl RemoteSigner {
    /// Connect to a signer at `socket_path`, run the handshake, and pin the
    /// remote's transport pubkey to `expected_signer_pubkey`. Returns a ready
    /// `RemoteSigner` whose underlying signer is the operator key the
    /// `deposits-signer` process is configured with.
    pub fn connect(
        socket_path: &Path,
        node_transport_secret: SecretKey,
        expected_signer_pubkey: PublicKey,
    ) -> Result<Self, SignerError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SignerError::Transport(format!("tokio rt: {}", e)))?;

        let conn = rt.block_on(async {
            let mut stream = UnixStream::connect(socket_path)
                .await
                .map_err(|e| SignerError::Transport(format!("connect {:?}: {}", socket_path, e)))?;

            handshake(
                &mut stream,
                node_transport_secret,
                expected_signer_pubkey,
            )
            .await?;

            let (reader, writer) = tokio::io::split(stream);
            Ok::<_, SignerError>(Conn { reader, writer })
        })?;

        // Cache pubkey via PubkeyQuery so the trait's pubkey() / xonly_pubkey()
        // can answer synchronously without a wire round-trip.
        let conn_arc = Arc::new(AsyncMutex::new(conn));
        let (pubkey, xonly) = rt.block_on(query_pubkey(Arc::clone(&conn_arc)))?;

        Ok(Self {
            rt,
            inner: conn_arc,
            next_id: AtomicU64::new(1),
            pubkey,
            xonly,
        })
    }

    fn rpc(&self, ctx: &SignContext, op: SignOp) -> Result<SignResult, SignerError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = SignRequest {
            id,
            ctx: ctx.clone(),
            op,
        };
        self.rt.block_on(rpc_one(Arc::clone(&self.inner), req, id))
    }
}

async fn handshake(
    stream: &mut UnixStream,
    node_transport_secret: SecretKey,
    expected_signer_pubkey: PublicKey,
) -> Result<(), SignerError> {
    let secp = Secp256k1::<bitcoin::secp256k1::All>::new();
    let node_kp = Keypair::from_secret_key(&secp, &node_transport_secret);
    let node_pubkey = PublicKey::from_keypair(&node_kp);

    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;
    let mut nonce_a = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_a);

    let hello = Hello {
        version: [0u8; 16],
        node_pubkey,
        nonce_a,
    };
    write_frame(stream, &hello)
        .await
        .map_err(map_frame_err)?;

    let ack: HelloAck = read_frame(stream).await.map_err(map_frame_err)?;
    if ack.signer_pubkey != expected_signer_pubkey {
        return Err(SignerError::Transport(format!(
            "signer pubkey mismatch: expected {}, got {}",
            hex::encode(expected_signer_pubkey.serialize()),
            hex::encode(ack.signer_pubkey.serialize()),
        )));
    }

    // Verify HelloAck sig against signer_pubkey + nonce_a + node_pubkey.
    let dgst = hello_ack_digest(&nonce_a, &node_pubkey);
    let msg = Message::from_digest(dgst);
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&ack.sig_signer)
        .map_err(|e| SignerError::Transport(format!("ack sig parse: {}", e)))?;
    let signer_xonly = ack.signer_pubkey.x_only_public_key().0;
    secp.verify_schnorr(&sig, &msg, &signer_xonly)
        .map_err(|e| SignerError::Transport(format!("ack sig verify: {}", e)))?;

    // Sign + send Auth.
    let auth_dgst = auth_digest(&ack.nonce_b, &ack.signer_pubkey);
    let auth_msg = Message::from_digest(auth_dgst);
    let sig_node = secp
        .sign_schnorr_no_aux_rand(&auth_msg, &node_kp)
        .serialize();
    let auth = Auth { sig_node };
    write_frame(stream, &auth).await.map_err(map_frame_err)?;
    Ok(())
}

async fn query_pubkey(
    conn: Arc<AsyncMutex<Conn>>,
) -> Result<(PublicKey, XOnlyPublicKey), SignerError> {
    let req = SignRequest {
        id: 0,
        ctx: SignContext::no_ledger(deposits_signer_api::SigPurpose::Bip340Untagged),
        op: SignOp::PubkeyQuery,
    };
    let res = rpc_one(conn, req, 0).await?;
    match res {
        SignResult::Pubkey { pubkey, xonly } => Ok((pubkey, xonly)),
        other => Err(SignerError::Transport(format!(
            "PubkeyQuery returned unexpected variant: {:?}",
            other
        ))),
    }
}

async fn rpc_one(
    conn: Arc<AsyncMutex<Conn>>,
    req: SignRequest,
    expected_id: u64,
) -> Result<SignResult, SignerError> {
    let mut guard = conn.lock().await;
    write_frame(&mut guard.writer, &req)
        .await
        .map_err(map_frame_err)?;
    let resp: SignResponse = read_frame(&mut guard.reader).await.map_err(map_frame_err)?;
    if resp.id != expected_id {
        return Err(SignerError::Transport(format!(
            "id mismatch: sent {}, got {}",
            expected_id, resp.id
        )));
    }
    Ok(resp.result)
}

fn map_frame_err(e: FrameError) -> SignerError {
    SignerError::Transport(format!("frame: {}", e))
}

fn map_sign_result_to_error(kind: SignErrorKind, message: String) -> SignerError {
    match kind {
        SignErrorKind::PolicyRefused => SignerError::PolicyRefused(message),
        SignErrorKind::Crypto => SignerError::Crypto(message),
        SignErrorKind::Unsupported => SignerError::Unsupported(message),
    }
}

impl Signer for RemoteSigner {
    fn pubkey(&self) -> PublicKey {
        self.pubkey
    }

    fn xonly_pubkey(&self) -> XOnlyPublicKey {
        self.xonly
    }

    fn bip340_sign(
        &self,
        ctx: &SignContext,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], SignerError> {
        match self.rpc(ctx, SignOp::Bip340 { digest: *digest })? {
            SignResult::Bip340Sig { sig } => Ok(sig),
            SignResult::Error { kind, message } => Err(map_sign_result_to_error(kind, message)),
            other => Err(SignerError::Transport(format!(
                "Bip340 returned unexpected variant: {:?}",
                other
            ))),
        }
    }

    fn ecdsa_sign_sighash(
        &self,
        ctx: &SignContext,
        sighash: &[u8; 32],
    ) -> Result<ecdsa::Signature, SignerError> {
        match self.rpc(ctx, SignOp::Ecdsa { sighash: *sighash })? {
            SignResult::EcdsaSig { sig_compact } => ecdsa::Signature::from_compact(&sig_compact)
                .map_err(|e| SignerError::Crypto(format!("ECDSA from_compact: {}", e))),
            SignResult::Error { kind, message } => Err(map_sign_result_to_error(kind, message)),
            other => Err(SignerError::Transport(format!(
                "Ecdsa returned unexpected variant: {:?}",
                other
            ))),
        }
    }

    fn ecdh(&self, peer: &PublicKey) -> Result<[u8; 32], SignerError> {
        // ECDH has no ledger context; use a placeholder SignContext.
        let ctx = SignContext::no_ledger(deposits_signer_api::SigPurpose::Bip340Untagged);
        match self.rpc(&ctx, SignOp::Ecdh { peer: *peer })? {
            SignResult::EcdhSecret { shared } => Ok(shared),
            SignResult::Error { kind, message } => Err(map_sign_result_to_error(kind, message)),
            other => Err(SignerError::Transport(format!(
                "Ecdh returned unexpected variant: {:?}",
                other
            ))),
        }
    }
}

// Suppress dead_code warning on `SharedSecret` since the trait surface
// re-uses LocalSigner's import path; we want to keep `SharedSecret` reachable
// here for cross-checking in tests, but no in-tree code uses it directly.
#[allow(dead_code)]
fn _shared_secret_kept_for_test_imports() -> usize {
    std::mem::size_of::<SharedSecret>()
}
