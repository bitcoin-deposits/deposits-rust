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
use deposits_node::node_cli::parse_config;
use deposits_node::remote_signer::RemoteSigner;
use deposits_node::Node;
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

/// Parsing `--signer-pubkey` + `--signer-socket` populates `NodeConfig.signer`
/// with a `RemoteSignerConfig`; either alone is a parse error.
#[test]
fn parse_config_wires_signer_flags() {
    use std::path::PathBuf;
    let seed = "11".repeat(32);
    let socket = "/tmp/dsigner.sock";
    let signer_pk = LocalSigner::random().pubkey();
    let signer_pk_hex = hex::encode(signer_pk.serialize());

    // Both flags present → signer config is populated.
    let args: Vec<String> = vec![
        "--seed",
        &seed,
        "--network",
        "regtest",
        "--data-dir",
        "/tmp/dnode-pcfg-test",
        "--signer-socket",
        socket,
        "--signer-pubkey",
        &signer_pk_hex,
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let cfg = parse_config(&args).expect("parse with both flags");
    let sig = cfg.signer.expect("signer config populated");
    assert_eq!(sig.signer_pubkey, signer_pk);
    assert_eq!(sig.socket_path, PathBuf::from(socket));

    // Neither flag → no signer config.
    let args: Vec<String> = vec![
        "--seed",
        &seed,
        "--network",
        "regtest",
        "--data-dir",
        "/tmp/dnode-pcfg-test",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let cfg = parse_config(&args).expect("parse without signer flags");
    assert!(cfg.signer.is_none());

    // --signer-socket alone → error.
    let args: Vec<String> = vec![
        "--seed",
        &seed,
        "--network",
        "regtest",
        "--data-dir",
        "/tmp/dnode-pcfg-test",
        "--signer-socket",
        socket,
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let err = match parse_config(&args) {
        Ok(_) => panic!("half-config should be rejected"),
        Err(e) => e,
    };
    assert!(err.contains("--signer-pubkey"), "unexpected: {}", err);

    // --signer-pubkey alone → error.
    let args: Vec<String> = vec![
        "--seed",
        &seed,
        "--network",
        "regtest",
        "--data-dir",
        "/tmp/dnode-pcfg-test",
        "--signer-pubkey",
        &signer_pk_hex,
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let err = match parse_config(&args) {
        Ok(_) => panic!("half-config should be rejected"),
        Err(e) => e,
    };
    assert!(err.contains("--signer-socket"), "unexpected: {}", err);
}

/// `Node::load_or_init_transport_secret` generates fresh on first call and
/// returns the same secret on a second call. File permissions are 0600.
#[test]
fn load_or_init_transport_secret_round_trip_and_perms() {
    use std::os::unix::fs::PermissionsExt;
    let suffix = rand_suffix();
    let mut data_dir = std::env::temp_dir();
    data_dir.push(format!("dnode-tport-{}", suffix));
    std::fs::create_dir_all(&data_dir).unwrap();

    let sk1 = Node::load_or_init_transport_secret(&data_dir).unwrap();
    let path = data_dir.join("transport_secret");
    assert!(path.exists(), "transport_secret should be written");
    let perms = std::fs::metadata(&path).unwrap().permissions();
    assert_eq!(perms.mode() & 0o777, 0o600, "transport_secret must be 0600");

    let sk2 = Node::load_or_init_transport_secret(&data_dir).unwrap();
    assert_eq!(
        sk1.secret_bytes(),
        sk2.secret_bytes(),
        "second call must return the persisted secret",
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Layer-1 end-to-end smoke: spawn a real `deposits-signer`, persist the
/// daemon's transport secret in a tmpdir-data-dir, allowlist it on the
/// signer, and confirm `RemoteSigner::connect` (the inner of `Node::new`'s
/// signer-init path) succeeds and signs.
///
/// We don't spin up the full `Node::new` here — that would pull in relays
/// + electrum + Nostr connection setup which Layer 2 will exercise via
/// regtest cluster bring-up. This test validates that the data-dir persistence
/// + transport keypair + handshake chain works end-to-end given a config
/// that exercises the same paths `parse_config` produces.
#[test]
fn signer_backed_daemon_init_path_round_trips() {
    let operator_seed = [0xAAu8; 32];

    // Daemon-side data dir; the same Node::load_or_init_transport_secret
    // helper that init.rs uses on real startup writes a fresh keypair on
    // first call.
    let suffix = rand_suffix();
    let mut daemon_data_dir = std::env::temp_dir();
    daemon_data_dir.push(format!("dnode-l1-{}", suffix));
    std::fs::create_dir_all(&daemon_data_dir).unwrap();
    let node_transport_secret =
        Node::load_or_init_transport_secret(&daemon_data_dir).unwrap();

    // Derive the daemon's transport pubkey to allowlist it.
    let secp = Secp256k1::new();
    let node_pubkey =
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &node_transport_secret);

    // Spawn the signer with the daemon's transport pubkey allowlisted.
    let (proc, signer_pubkey) = spawn_signer(operator_seed, node_pubkey);

    // This is what init.rs's RemoteSigner branch does, end-to-end.
    let remote = RemoteSigner::connect(&proc.socket, node_transport_secret, signer_pubkey)
        .expect("signer-backed Node init path must connect");

    // Exercise both the operator-protocol sign path and the Nostr-key
    // issuance — the two things Node::new actually calls before passing
    // signers down into the handler / Nostr layer.
    let digest = sha256::Hash::hash(b"layer-1 e2e").to_byte_array();
    let ctx = SignContext::operator_update([0xBB; 32], 1);
    let sig = remote.bip340_sign(&ctx, &digest).expect("bip340_sign");

    let (operator_secret, _nostr_secret) =
        derive_keys_from_seed(&operator_seed, Network::Bitcoin).unwrap();
    let local = LocalSigner::new(operator_secret);
    let expected = local.bip340_sign(&ctx, &digest).unwrap();
    assert_eq!(
        sig, expected,
        "remote-via-Layer-1 path must produce the same sig as LocalSigner",
    );

    // Nostr-secret issuance through the same connection.
    let issued = remote.issue_nostr_secret().expect("issue_nostr_secret");
    let issued_pk =
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &
            bitcoin::secp256k1::SecretKey::from_slice(&issued).unwrap());
    assert_ne!(issued_pk, remote.pubkey(), "Nostr key must differ from operator");

    let _ = std::fs::remove_dir_all(&daemon_data_dir);
}

#[test]
fn remote_signer_deposit_keypath_signs_at_correct_derivation() {
    // KeyPath::Deposit { index } signs with m/84'/0'/0'/0/{index} from the
    // signer's master xpriv — the same derivation the daemon's
    // derive_deposit_key_at(index) used to produce locally. This is the
    // wire-level confirmation that the KeyPath extension (cluster-#1
    // follow-up) works end-to-end.
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use deposits_signer_api::KeyPath;
    use std::str::FromStr;

    let operator_seed = [0xABu8; 32];
    let node_transport = TransportKey::random();
    let (proc, signer_transport_pubkey) = spawn_signer(operator_seed, node_transport.public);
    let remote = RemoteSigner::connect(
        &proc.socket,
        node_transport.secret,
        signer_transport_pubkey,
    )
    .unwrap();

    // Sign at index=0.
    let digest = sha256::Hash::hash(b"deposit keypath test").to_byte_array();
    let ctx = SignContext::deposit(0, SigPurpose::DepositGuarantee);
    let sig_bytes = remote
        .bip340_sign(&ctx, &digest)
        .expect("Deposit { index: 0 } sign must succeed");

    // Independent expected pubkey: same derivation against the seed.
    let xpriv = Xpriv::new_master(Network::Bitcoin, &operator_seed).unwrap();
    let path = DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap();
    let secp = Secp256k1::new();
    let expected_secret = xpriv.derive_priv(&secp, &path).unwrap().private_key;
    let expected_pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &expected_secret);
    let (expected_xonly, _) = expected_pk.x_only_public_key();

    let sig =
        bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).expect("sig parse");
    let msg = Message::from_digest(digest);
    secp.verify_schnorr(&sig, &msg, &expected_xonly)
        .expect("sig must verify against m/84'/0'/0'/0/0 xonly pubkey");

    // The signer's operator pubkey is m/86' — different from the deposit key.
    let operator_xonly = remote.xonly_pubkey();
    assert_ne!(operator_xonly, expected_xonly);
    assert!(
        secp.verify_schnorr(&sig, &msg, &operator_xonly).is_err(),
        "deposit-key sig must NOT verify against operator pubkey"
    );

    // Different indexes → different sigs.
    let ctx_3 = SignContext::deposit(3, SigPurpose::DepositGuarantee);
    let sig_3 = remote.bip340_sign(&ctx_3, &digest).unwrap();
    assert_ne!(sig_bytes, sig_3, "different KeyPath::Deposit indexes must sign distinctly");

    // The KeyPath::Operator path still signs with the operator key.
    let ctx_op = SignContext {
        role: deposits_signer_api::SigRole::NoLedger,
        purpose: SigPurpose::Bip340Untagged,
        key: KeyPath::Operator,
    };
    let sig_op = remote.bip340_sign(&ctx_op, &digest).unwrap();
    let parsed = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_op).unwrap();
    secp.verify_schnorr(&parsed, &msg, &operator_xonly)
        .expect("operator-key sig must verify against operator xonly");
}

#[test]
fn remote_signer_wallet_account_xpub_matches_local_derivation() {
    // The signer should hand back the BIP-32 xpub at m/86'/0'/<account>'.
    // The daemon embeds it into a watch-only descriptor so per-ledger
    // BDK wallets can derive their own addresses without holding the
    // seed. We check parity against an independent local derivation
    // from the same seed.
    use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
    use std::str::FromStr;

    let operator_seed = [0x5Au8; 32];
    let node_transport = TransportKey::random();
    let (proc, signer_transport_pubkey) = spawn_signer(operator_seed, node_transport.public);
    let remote = RemoteSigner::connect(
        &proc.socket,
        node_transport.secret,
        signer_transport_pubkey,
    )
    .unwrap();

    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(Network::Bitcoin, &operator_seed).unwrap();
    for account in [0u32, 1, 2, 7, 100] {
        let got = remote.wallet_account_xpub(account).unwrap_or_else(|e| {
            panic!("wallet_account_xpub({}) failed: {:?}", account, e)
        });

        let path = DerivationPath::from_str(&format!("m/86'/0'/{}'", account)).unwrap();
        let derived = xpriv.derive_priv(&secp, &path).unwrap();
        let expected = Xpub::from_priv(&secp, &derived);

        assert_eq!(
            got, expected,
            "remote signer's xpub at account={} differs from local derivation",
            account
        );
    }

    // Distinct accounts must produce distinct xpubs.
    let a0 = remote.wallet_account_xpub(0).unwrap();
    let a1 = remote.wallet_account_xpub(1).unwrap();
    assert_ne!(a0, a1, "different accounts must yield different xpubs");
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
fn remote_signer_nip04_shared_key_matches_local() {
    // The wire op that unblocks NIP-04 fallback decrypt against the
    // operator key when the daemon's self.keys is the delegate.
    let operator_seed = [0xBBu8; 32];
    let (operator_secret, _) =
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

    // Pick an arbitrary peer.
    let peer = LocalSigner::random();
    let local_key = local.nip04_shared_key(&peer.pubkey()).unwrap();
    let remote_key = remote.nip04_shared_key(&peer.pubkey()).unwrap();
    assert_eq!(
        local_key, remote_key,
        "RemoteSigner NIP-04 raw-X must match LocalSigner bit-for-bit"
    );

    // Also distinct from the hashed ECDH form — confirm both endpoints agree.
    let hashed = remote.ecdh(&peer.pubkey()).unwrap();
    assert_ne!(remote_key, hashed);
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
