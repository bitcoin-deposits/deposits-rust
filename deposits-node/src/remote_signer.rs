//! `RemoteSigner` — a `Signer` impl that talks to a `deposits-signer`
//! process over a Unix socket.
//!
//! The `Signer` trait is sync; the wire is async. Bridging the two in a
//! way that works whether the *caller* is inside a tokio runtime or not
//! is the whole point of this module:
//!
//!   - A dedicated OS thread owns a tokio runtime + the connection.
//!   - Trait calls send a `RpcRequest` (the SignOp + a oneshot reply
//!     channel) into the worker over an `std::sync::mpsc`. The trait
//!     method blocks on the reply.
//!   - The worker reads requests off its channel, drives the wire, and
//!     forwards results back. Connection state stays single-threaded
//!     inside the worker, so no `Arc<Mutex<Conn>>` for the connection.
//!
//! Why this shape: an earlier iteration had `RemoteSigner::connect`
//! create its own `current_thread` runtime and `block_on` directly.
//! That panicked when `Node::new` (which itself runs under tokio) called
//! it: "Cannot start a runtime from within a runtime." Worker-thread
//! pattern dodges that — the worker's runtime is created on a thread
//! that isn't inside any other runtime.

use bitcoin::secp256k1::{
    ecdsa, Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use deposits_signer_api::{
    wire::{
        auth_digest, hello_ack_digest, Auth, Hello, HelloAck, SignErrorKind, SignOp, SignRequest,
        SignResponse, SignResult,
    },
    SigPurpose, SignContext, Signer, SignerError,
};
use deposits_signer::framing::{read_frame, write_frame, FrameError};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread::{self, JoinHandle};
use tokio::net::UnixStream;

/// `Signer` impl backed by a connected `deposits-signer` over Unix socket.
///
/// Construct via [`RemoteSigner::connect`]. The instance owns a worker
/// thread + tokio runtime + connection until dropped.
pub struct RemoteSigner {
    /// Worker-bound request channel. `Mutex` because `mpsc::Sender` is
    /// `Send` but not `Sync`, and the `Signer` trait requires `Sync`.
    /// The lock is held only across a non-blocking `send()`, so contention
    /// is bounded by the daemon's outbound rate.
    request_tx: Mutex<mpsc::Sender<RpcRequest>>,
    /// Joined on drop. `Option` so `Drop` can take ownership.
    worker: Mutex<Option<JoinHandle<()>>>,
    /// Caller-allocated id; the worker echoes it on the response. Lives
    /// outside the worker so the trait's pubkey()/xonly_pubkey() can stay
    /// synchronous (cached from the connect-time PubkeyQuery).
    next_id: AtomicU64,
    pubkey: PublicKey,
    xonly: XOnlyPublicKey,
}

struct RpcRequest {
    ctx: SignContext,
    op: SignOp,
    /// One-shot reply channel. We use `mpsc::Sender` with capacity 1 in
    /// std rather than tokio's oneshot since the trait method blocks on
    /// `recv()` from a (possibly) sync context.
    reply: mpsc::Sender<Result<SignResult, SignerError>>,
}

impl RemoteSigner {
    /// Connect to a signer at `socket_path`, run the handshake, and pin
    /// the remote's transport pubkey to `expected_signer_pubkey`. Returns
    /// a ready `RemoteSigner`.
    ///
    /// Safe to call from inside a tokio runtime — the worker thread that
    /// drives async I/O is spawned via `std::thread::spawn`, so it
    /// doesn't inherit the caller's runtime.
    pub fn connect(
        socket_path: &Path,
        node_transport_secret: SecretKey,
        expected_signer_pubkey: PublicKey,
        network: bitcoin::Network,
    ) -> Result<Self, SignerError> {
        let socket_path = socket_path.to_path_buf();

        let (request_tx, request_rx) = mpsc::channel::<RpcRequest>();
        // Worker uses this to deliver the connect-time pubkey query result
        // (or a connect error) back to the constructor.
        let (ready_tx, ready_rx) =
            mpsc::channel::<Result<(PublicKey, XOnlyPublicKey), SignerError>>();

        let worker = thread::spawn(move || {
            worker_main(
                socket_path,
                node_transport_secret,
                expected_signer_pubkey,
                network,
                request_rx,
                ready_tx,
            );
        });

        let (pubkey, xonly) = match ready_rx.recv() {
            Ok(res) => res?,
            Err(_) => {
                return Err(SignerError::Transport(
                    "signer worker thread exited before handshake completed".into(),
                ));
            }
        };

        Ok(Self {
            request_tx: Mutex::new(request_tx),
            worker: Mutex::new(Some(worker)),
            next_id: AtomicU64::new(1),
            pubkey,
            xonly,
        })
    }

    fn rpc(&self, ctx: &SignContext, op: SignOp) -> Result<SignResult, SignerError> {
        let (reply_tx, reply_rx) = mpsc::channel::<Result<SignResult, SignerError>>();
        let req = RpcRequest {
            ctx: ctx.clone(),
            op,
            reply: reply_tx,
        };
        // Bump the id (wire-side correlation) — actually unused on the
        // sender end since the worker assigns its own monotonic ids inside
        // its single-flight loop. Kept here for symmetry / future fan-out.
        let _ = self.next_id.fetch_add(1, Ordering::Relaxed);

        self.request_tx
            .lock()
            .map_err(|_| SignerError::Transport("RemoteSigner mutex poisoned".into()))?
            .send(req)
            .map_err(|_| SignerError::Transport("RemoteSigner worker channel closed".into()))?;

        match reply_rx.recv() {
            Ok(result) => result,
            Err(_) => Err(SignerError::Transport(
                "RemoteSigner worker dropped reply channel".into(),
            )),
        }
    }
}

impl Drop for RemoteSigner {
    fn drop(&mut self) {
        // Drop the sender so the worker's `request_rx.recv()` returns
        // `Err`, breaking the loop. Then join.
        //
        // The lock here is best-effort — if it's poisoned we still want
        // to take the handle and try to join. Replace-then-drop pattern
        // gets the Sender out of the Mutex so its destructor runs.
        if let Ok(mut guard) = self.request_tx.lock() {
            // Replace with a fresh dead channel; the original Sender is
            // dropped at end of scope.
            let (dead_tx, _dead_rx) = mpsc::channel();
            let _old = std::mem::replace(&mut *guard, dead_tx);
        }
        if let Ok(mut guard) = self.worker.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

fn worker_main(
    socket_path: std::path::PathBuf,
    node_transport_secret: SecretKey,
    expected_signer_pubkey: PublicKey,
    network: bitcoin::Network,
    request_rx: mpsc::Receiver<RpcRequest>,
    ready_tx: mpsc::Sender<Result<(PublicKey, XOnlyPublicKey), SignerError>>,
) {
    // Worker-owned runtime. Created on this thread, which is *not* part
    // of any caller's runtime (we spawned via std::thread::spawn).
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready_tx.send(Err(SignerError::Transport(format!("tokio rt: {}", e))));
            return;
        }
    };

    rt.block_on(async move {
        // 1. Connect + handshake.
        let mut stream = match UnixStream::connect(&socket_path).await {
            Ok(s) => s,
            Err(e) => {
                let _ = ready_tx.send(Err(SignerError::Transport(format!(
                    "connect {:?}: {}",
                    socket_path, e
                ))));
                return;
            }
        };
        if let Err(e) = handshake(
            &mut stream,
            node_transport_secret,
            expected_signer_pubkey,
            network,
        )
        .await
        {
            let _ = ready_tx.send(Err(e));
            return;
        }

        let (mut reader, mut writer) = tokio::io::split(stream);

        // 2. Cache the operator's pubkey (PubkeyQuery on the freshly
        //    handshaken connection). Send the result back through the
        //    `ready_tx` to unblock RemoteSigner::connect.
        let mut next_id: u64 = 1;
        let pk_id = next_id;
        next_id += 1;
        let pk_req = SignRequest {
            id: pk_id,
            ctx: SignContext::no_ledger(SigPurpose::Bip340Untagged),
            op: SignOp::PubkeyQuery,
        };
        let pk_result = rpc_one(&mut reader, &mut writer, pk_req, pk_id).await;
        let (pubkey, xonly) = match pk_result {
            Ok(SignResult::Pubkey { pubkey, xonly }) => (pubkey, xonly),
            Ok(other) => {
                let _ = ready_tx.send(Err(SignerError::Transport(format!(
                    "PubkeyQuery returned unexpected variant: {:?}",
                    other
                ))));
                return;
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        if ready_tx.send(Ok((pubkey, xonly))).is_err() {
            // RemoteSigner went away during connect — give up.
            return;
        }

        // 3. Serve trait calls until the request channel closes
        //    (RemoteSigner dropped).
        while let Ok(req) = request_rx.recv() {
            let id = next_id;
            next_id += 1;
            let wire_req = SignRequest {
                id,
                ctx: req.ctx,
                op: req.op,
            };
            let result = rpc_one(&mut reader, &mut writer, wire_req, id).await;
            let _ = req.reply.send(result);
        }
    });
}

async fn handshake(
    stream: &mut UnixStream,
    node_transport_secret: SecretKey,
    expected_signer_pubkey: PublicKey,
    network: bitcoin::Network,
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
        network,
    };
    write_frame(stream, &hello).await.map_err(map_frame_err)?;

    let ack: HelloAck = read_frame(stream).await.map_err(map_frame_err)?;
    if ack.signer_pubkey != expected_signer_pubkey {
        return Err(SignerError::Transport(format!(
            "signer pubkey mismatch: expected {}, got {}",
            hex::encode(expected_signer_pubkey.serialize()),
            hex::encode(ack.signer_pubkey.serialize()),
        )));
    }

    let dgst = hello_ack_digest(&nonce_a, &node_pubkey);
    let msg = Message::from_digest(dgst);
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&ack.sig_signer)
        .map_err(|e| SignerError::Transport(format!("ack sig parse: {}", e)))?;
    let signer_xonly = ack.signer_pubkey.x_only_public_key().0;
    secp.verify_schnorr(&sig, &msg, &signer_xonly)
        .map_err(|e| SignerError::Transport(format!("ack sig verify: {}", e)))?;

    let auth_dgst = auth_digest(&ack.nonce_b, &ack.signer_pubkey);
    let auth_msg = Message::from_digest(auth_dgst);
    let sig_node = secp
        .sign_schnorr_no_aux_rand(&auth_msg, &node_kp)
        .serialize();
    let auth = Auth { sig_node };
    write_frame(stream, &auth).await.map_err(map_frame_err)?;
    Ok(())
}

async fn rpc_one<R, W>(
    reader: &mut R,
    writer: &mut W,
    req: SignRequest,
    expected_id: u64,
) -> Result<SignResult, SignerError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    write_frame(writer, &req).await.map_err(map_frame_err)?;
    let resp: SignResponse = read_frame(reader).await.map_err(map_frame_err)?;
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

    fn issue_nostr_secret(&self) -> Result<[u8; 32], SignerError> {
        let ctx = SignContext::no_ledger(SigPurpose::Bip340Untagged);
        match self.rpc(&ctx, SignOp::IssueNostrSecret)? {
            SignResult::IssuedSecret { sk } => Ok(sk),
            SignResult::Error { kind, message } => Err(map_sign_result_to_error(kind, message)),
            other => Err(SignerError::Transport(format!(
                "IssueNostrSecret returned unexpected variant: {:?}",
                other
            ))),
        }
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
        let ctx = SignContext::no_ledger(SigPurpose::Bip340Untagged);
        match self.rpc(&ctx, SignOp::Ecdh { peer: *peer })? {
            SignResult::EcdhSecret { shared } => Ok(shared),
            SignResult::Error { kind, message } => Err(map_sign_result_to_error(kind, message)),
            other => Err(SignerError::Transport(format!(
                "Ecdh returned unexpected variant: {:?}",
                other
            ))),
        }
    }

    fn nip04_shared_key(&self, peer: &PublicKey) -> Result<[u8; 32], SignerError> {
        let ctx = SignContext::no_ledger(SigPurpose::Bip340Untagged);
        match self.rpc(&ctx, SignOp::Nip04SharedKey { peer: *peer })? {
            SignResult::Nip04SharedKey { key } => Ok(key),
            SignResult::Error { kind, message } => Err(map_sign_result_to_error(kind, message)),
            other => Err(SignerError::Transport(format!(
                "Nip04SharedKey returned unexpected variant: {:?}",
                other
            ))),
        }
    }

    fn wallet_account_xpub(&self, account: u32) -> Result<bitcoin::bip32::Xpub, SignerError> {
        let ctx = SignContext::no_ledger(SigPurpose::Bip340Untagged);
        match self.rpc(&ctx, SignOp::WalletAccountXpub { account })? {
            SignResult::WalletAccountXpub { xpub_str } => {
                use std::str::FromStr;
                bitcoin::bip32::Xpub::from_str(&xpub_str).map_err(|e| {
                    SignerError::Transport(format!(
                        "WalletAccountXpub parse: {} (xpub_str={})",
                        e, xpub_str
                    ))
                })
            }
            SignResult::Error { kind, message } => Err(map_sign_result_to_error(kind, message)),
            other => Err(SignerError::Transport(format!(
                "WalletAccountXpub returned unexpected variant: {:?}",
                other
            ))),
        }
    }

    fn master_xpub(&self) -> Result<bitcoin::bip32::Xpub, SignerError> {
        let ctx = SignContext::no_ledger(SigPurpose::Bip340Untagged);
        match self.rpc(&ctx, SignOp::MasterXpub)? {
            SignResult::MasterXpub { xpub_str } => {
                use std::str::FromStr;
                bitcoin::bip32::Xpub::from_str(&xpub_str).map_err(|e| {
                    SignerError::Transport(format!(
                        "MasterXpub parse: {} (xpub_str={})",
                        e, xpub_str
                    ))
                })
            }
            SignResult::Error { kind, message } => Err(map_sign_result_to_error(kind, message)),
            other => Err(SignerError::Transport(format!(
                "MasterXpub returned unexpected variant: {:?}",
                other
            ))),
        }
    }

    fn pubkey_at(
        &self,
        key_path: deposits_signer_api::KeyPath,
    ) -> Result<PublicKey, SignerError> {
        let ctx = SignContext::no_ledger(SigPurpose::Bip340Untagged);
        match self.rpc(&ctx, SignOp::PubkeyAt { key_path })? {
            SignResult::PubkeyAt { pubkey } => Ok(pubkey),
            SignResult::Error { kind, message } => Err(map_sign_result_to_error(kind, message)),
            other => Err(SignerError::Transport(format!(
                "PubkeyAt returned unexpected variant: {:?}",
                other
            ))),
        }
    }
}
