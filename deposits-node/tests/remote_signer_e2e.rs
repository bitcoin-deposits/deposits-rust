//! End-to-end test: a real `deposits-signer` process listening on a Unix
//! socket in a tmpdir, with a `RemoteSigner` client driving the `Signer`
//! trait. Validates that a daemon-side `Signer` call produces the same
//! signature as a `LocalSigner` would, against the same operator key.
//!
//! This is the "integration testing infrastructure" the remote-signer
//! work is aimed at: any future test that wants to exercise the daemon
//! against a remote signer can crib this setup.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::Network;
use deposits_node::remote_signer::RemoteSigner;
use deposits_signer::data::{derive_keys_from_seed, DataDir, TransportKey};
use deposits_signer_api::{LocalSigner, SigPurpose, SignContext, Signer, SignerError};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct SignerProc {
    child: Child,
    data_dir: PathBuf,
    socket: PathBuf,
}

impl Drop for SignerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Spawn a `deposits-signer run` process in a tmpdir, with the given
/// operator seed installed and the given node transport pubkey allowlisted.
/// Returns once the socket is listenable.
fn spawn_signer(
    operator_seed: [u8; 32],
    node_transport_pubkey: bitcoin::secp256k1::PublicKey,
) -> (SignerProc, bitcoin::secp256k1::PublicKey) {
    let suffix = rand_suffix();
    let mut data_dir = std::env::temp_dir();
    data_dir.push(format!("dsigner-e2e-{}", suffix));
    let mut socket = std::env::temp_dir();
    socket.push(format!("dsigner-e2e-{}.sock", suffix));

    let dd = DataDir::new(&data_dir);
    dd.init(Some(&operator_seed)).expect("init signer data dir");
    dd.add_allowlist(&node_transport_pubkey)
        .expect("allowlist node");

    let signer_pubkey = dd.load_transport().expect("load transport").public;

    let bin = signer_binary();
    let mut child = Command::new(&bin)
        .arg("run")
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("spawn deposits-signer run");

    // Wait up to ~3 s for the socket to come up.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if socket.exists() {
            std::thread::sleep(Duration::from_millis(50));
            return (
                SignerProc {
                    child,
                    data_dir,
                    socket,
                },
                signer_pubkey,
            );
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("deposits-signer exited early with {:?}", status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("deposits-signer never bound socket {}", socket.display());
}

fn signer_binary() -> PathBuf {
    // Location of the just-built `deposits-signer` binary. Cargo's CARGO_BIN_*
    // doesn't help us across crates, so we walk the workspace target dir.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target");
    p.push("debug");
    p.push("deposits-signer");
    assert!(
        p.exists(),
        "deposits-signer binary not found at {} — run `cargo build -p deposits-signer` first",
        p.display()
    );
    p
}

fn rand_suffix() -> String {
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[test]
fn remote_signer_bip340_matches_local_signer() {
    // Pick an operator seed; build the LocalSigner counterpart so we can
    // compute the expected sig locally. (Deterministic signing means we can
    // compare bit-for-bit.)
    let operator_seed = [0x42u8; 32];
    // Mirror the signer's derivation so the local comparison key matches
    // what the deposits-signer process derives at m/86'/0'/0'/0/0.
    let (operator_secret, _nostr_secret) =
        derive_keys_from_seed(&operator_seed, Network::Bitcoin).unwrap();
    let local = LocalSigner::new(operator_secret);
    let expected_pubkey = local.pubkey();
    let expected_xonly = local.xonly_pubkey();

    // Daemon's transport key.
    let node_transport = TransportKey::random();

    let (proc, signer_transport_pubkey) = spawn_signer(operator_seed, node_transport.public);

    // Connect the RemoteSigner.
    let remote = RemoteSigner::connect(
        &proc.socket,
        node_transport.secret,
        signer_transport_pubkey,
    )
    .expect("connect remote signer");

    // Pubkeys via PubkeyQuery match the operator key.
    assert_eq!(remote.pubkey(), expected_pubkey);
    assert_eq!(remote.xonly_pubkey(), expected_xonly);

    // BIP-340 sig over a known digest matches the local computation.
    let payload = b"phase-4 e2e test payload";
    let digest = sha256::Hash::hash(payload).to_byte_array();
    let ctx = SignContext::operator_update([0xAB; 32], 17);

    let sig_local = local.bip340_sign(&ctx, &digest).unwrap();
    let sig_remote = remote.bip340_sign(&ctx, &digest).unwrap();
    assert_eq!(
        sig_remote, sig_local,
        "RemoteSigner BIP-340 sig must match LocalSigner (deterministic signing)"
    );

    // Independent verification against the operator's xonly pubkey.
    let secp = Secp256k1::verification_only();
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_remote).unwrap();
    let msg = Message::from_digest(digest);
    secp.verify_schnorr(&sig, &msg, &expected_xonly)
        .expect("remote signer's sig must verify against operator xonly");
}

#[test]
fn remote_signer_ecdsa_matches_local_signer() {
    let operator_seed = [0x33u8; 32];
    // Mirror the signer's derivation so the local comparison key matches
    // what the deposits-signer process derives at m/86'/0'/0'/0/0.
    let (operator_secret, _nostr_secret) =
        derive_keys_from_seed(&operator_seed, Network::Bitcoin).unwrap();
    let local = LocalSigner::new(operator_secret);

    let node_transport = TransportKey::random();
    let (proc, signer_transport_pubkey) = spawn_signer(operator_seed, node_transport.public);
    let remote = RemoteSigner::connect(
        &proc.socket,
        node_transport.secret,
        signer_transport_pubkey,
    )
    .unwrap();

    let sighash = [0x77u8; 32];
    let ctx = SignContext::no_ledger(SigPurpose::OnchainSighash);
    let sig_local = local.ecdsa_sign_sighash(&ctx, &sighash).unwrap();
    let sig_remote = remote.ecdsa_sign_sighash(&ctx, &sighash).unwrap();
    assert_eq!(
        sig_local.serialize_compact(),
        sig_remote.serialize_compact()
    );
}

#[test]
fn remote_signer_issues_nostr_secret_distinct_from_operator() {
    // Confirm the signer derives a Nostr secret at m/85'/0'/0'/0/0 which is
    // distinct from the operator at m/86'/0'/0'/0/0, returns it over the
    // wire, and that the issued bytes are a valid secp256k1 secret.
    let operator_seed = [0x77u8; 32];
    let node_transport = TransportKey::random();
    let (proc, signer_transport_pubkey) = spawn_signer(operator_seed, node_transport.public);
    let remote = RemoteSigner::connect(
        &proc.socket,
        node_transport.secret,
        signer_transport_pubkey,
    )
    .unwrap();

    let issued = remote.issue_nostr_secret().expect("issue must succeed");
    let issued_sk = bitcoin::secp256k1::SecretKey::from_slice(&issued)
        .expect("issued bytes must form a valid secret");

    // The Nostr secret must not be the operator secret.
    let issued_pk = bitcoin::secp256k1::PublicKey::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &issued_sk,
    );
    assert_ne!(
        issued_pk,
        remote.pubkey(),
        "Nostr identity pubkey must differ from operator pubkey"
    );

    // Idempotent: a second call returns the same secret. (The signer's
    // derivation is stable; no surprise rotation.)
    let issued2 = remote.issue_nostr_secret().expect("idempotent");
    assert_eq!(issued, issued2);
}

#[test]
fn remote_signer_anti_equivocation_refuses_seq_regression() {
    // Sign at seq=10, then try seq=10 again — RemoteSigner should surface
    // a PolicyRefused error from the signer.
    let operator_seed = [0x66u8; 32];
    let node_transport = TransportKey::random();
    let (proc, signer_transport_pubkey) = spawn_signer(operator_seed, node_transport.public);
    let remote = RemoteSigner::connect(
        &proc.socket,
        node_transport.secret,
        signer_transport_pubkey,
    )
    .unwrap();

    let ledger_id = [0xDD; 32];
    let digest_a = [0x01u8; 32];
    let digest_b = [0x02u8; 32];

    // First sign goes through.
    let _sig = remote
        .bip340_sign(&SignContext::operator_update(ledger_id, 10), &digest_a)
        .expect("first sign at seq=10 must succeed");

    // Same seq, different digest → still a regression because we already
    // committed seq=10. The policy refuses regardless of digest content.
    let err = remote
        .bip340_sign(&SignContext::operator_update(ledger_id, 10), &digest_b)
        .expect_err("repeat sign at seq=10 must be refused");
    match err {
        SignerError::PolicyRefused(msg) => {
            assert!(msg.contains("seq regression"), "unexpected message: {}", msg);
        }
        other => panic!("expected PolicyRefused, got {:?}", other),
    }

    // seq=11 now works — state is intact past the refusal.
    let _sig = remote
        .bip340_sign(&SignContext::operator_update(ledger_id, 11), &digest_b)
        .expect("seq=11 must succeed after refusal");
}

#[test]
fn remote_signer_ecdh_matches_local_signer() {
    let operator_seed = [0x55u8; 32];
    // Mirror the signer's derivation so the local comparison key matches
    // what the deposits-signer process derives at m/86'/0'/0'/0/0.
    let (operator_secret, _nostr_secret) =
        derive_keys_from_seed(&operator_seed, Network::Bitcoin).unwrap();
    let local = LocalSigner::new(operator_secret);

    let node_transport = TransportKey::random();
    let (proc, signer_transport_pubkey) = spawn_signer(operator_seed, node_transport.public);
    let remote = RemoteSigner::connect(
        &proc.socket,
        node_transport.secret,
        signer_transport_pubkey,
    )
    .unwrap();

    let peer = LocalSigner::random();
    let local_shared = local.ecdh(&peer.pubkey()).unwrap();
    let remote_shared = remote.ecdh(&peer.pubkey()).unwrap();
    assert_eq!(local_shared, remote_shared);
}
