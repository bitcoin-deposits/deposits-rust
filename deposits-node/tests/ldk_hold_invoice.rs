//! Integration test: LdkBackend hold invoices against OUR fork of
//! ldk-server (deposits-hold-invoices branch).
//!
//! This is the test that validates both halves of the fork work live:
//!   - the for-hash command set (bolt11-receive-for-hash / claim / fail),
//!     upstream code but never exercised by us before
//!   - the GetClaimableDetails endpoint + PaymentClaimable event tracking
//!     we added — the Accepted-state assertion below fails if the event
//!     loop's claimable_payments map or the claim_deadline plumbing breaks
//!
//! Mirrors cln_hold_invoice.rs / lnd_hold_invoice.rs. The payer is the CLN
//! node from ./bin/setup-cln-hold.sh with a channel into the host-run
//! ldk-server holder (./bin/setup-ldk-hold.sh).
//!
//!   LDK_CLI=/home/claude/ldk-server/target/debug/ldk-server-cli \
//!   LDK_HOST=localhost LDK_PORT=3201 \
//!   LDK_API_KEY=<hex of /tmp/ldk-hold-test/data/regtest/api_key> \
//!   LDK_TLS_CERT=/tmp/ldk-hold-test/data/tls.crt \
//!   CLN_PAYER_SOCKET_PATH=/tmp/cln-payer-test/regtest/lightning-rpc \
//!     cargo test -p deposits-node --test ldk_hold_invoice -- --ignored --nocapture
//!
//! Skips cleanly when LDK_CLI is unset.

use deposits_node::ldk_backend::{LdkBackend, LdkBackendConfig};
use deposits_node::lightning_backend::{HoldInvoiceState, LightningBackend};
use std::time::{Duration, Instant};

fn rand_preimage() -> ([u8; 32], [u8; 32]) {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    use bitcoin::secp256k1::rand::{rngs::OsRng, RngCore};
    let mut preimage = [0u8; 32];
    OsRng.fill_bytes(&mut preimage);
    let mut engine = sha256::Hash::engine();
    engine.input(&preimage);
    (preimage, sha256::Hash::from_engine(engine).to_byte_array())
}

fn spawn_payer_pay(
    payer_socket: &str,
    bolt11: &str,
) -> std::thread::JoinHandle<Result<serde_json::Value, String>> {
    let payer_socket = payer_socket.to_string();
    let bolt11 = bolt11.to_string();
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixStream;
        let mut stream =
            UnixStream::connect(&payer_socket).map_err(|e| format!("connect payer: {}", e))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(120)))
            .map_err(|e| e.to_string())?;
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "pay",
            "params": { "bolt11": bolt11 },
        });
        let mut bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        stream
            .write_all(&bytes)
            .map_err(|e| format!("write pay: {}", e))?;
        let mut line = String::new();
        BufReader::new(&stream)
            .read_line(&mut line)
            .map_err(|e| format!("read pay response: {}", e))?;
        serde_json::from_str(&line).map_err(|e| format!("parse pay response: {}", e))
    })
}

fn poll_state(
    backend: &LdkBackend,
    hash_hex: &str,
    deadline: Duration,
    pred: impl Fn(&HoldInvoiceState) -> bool,
) -> HoldInvoiceState {
    let start = Instant::now();
    loop {
        let state = backend
            .lookup_hold_invoice(hash_hex)
            .expect("lookup_hold_invoice");
        if pred(&state) || start.elapsed() > deadline {
            return state;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
#[ignore]
fn ldk_hold_invoice_settle_and_cancel() {
    if std::env::var("LDK_CLI").is_err() {
        eprintln!("skipping: LDK_CLI unset — start with ./bin/setup-ldk-hold.sh");
        return;
    }
    let payer_socket = match std::env::var("CLN_PAYER_SOCKET_PATH") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skipping: CLN_PAYER_SOCKET_PATH unset — start with ./bin/setup-cln-hold.sh");
            return;
        }
    };

    let backend = LdkBackend::new(LdkBackendConfig::from_env());

    // ── 1. Probe ────────────────────────────────────────────────────────────
    assert!(
        backend.supports_hold_invoices(),
        "fork CLI should know the for-hash command set"
    );
    eprintln!("[probe]   for-hash command set detected");

    // ── 2-4. Happy path ─────────────────────────────────────────────────────
    let (preimage, hash) = rand_preimage();
    let hash_hex = hex::encode(hash);
    let preimage_hex = hex::encode(preimage);

    let bolt11 = backend
        .create_hold_invoice(250_000, &hash_hex, "ldk-hold-test", 3600, None)
        .expect("create_hold_invoice");
    assert!(
        bolt11.starts_with("lnbcrt"),
        "expected a regtest BOLT-11, got: {}",
        &bolt11[..20.min(bolt11.len())]
    );
    eprintln!("[create]  hold invoice for hash {}…", &hash_hex[..16]);

    // Before payment: PENDING + not claimable → Open.
    let state = backend.lookup_hold_invoice(&hash_hex).expect("lookup");
    assert_eq!(
        state,
        HoldInvoiceState::Open,
        "expected Open before payment"
    );

    let pay_handle = spawn_payer_pay(&payer_socket, &bolt11);

    // HTLCs park → ldk-node emits PaymentClaimable → OUR fork's event loop
    // records (payment_id, claim_deadline) → GetClaimableDetails reports it.
    // This is the assertion that validates the fork's plumbing end-to-end.
    let state = poll_state(&backend, &hash_hex, Duration::from_secs(60), |s| {
        matches!(s, HoldInvoiceState::Accepted { .. })
    });
    match state {
        HoldInvoiceState::Accepted { htlc_expiry_height } => {
            let h =
                htlc_expiry_height.expect("fork must surface claim_deadline from PaymentClaimable");
            assert!(h > 0, "claim_deadline should be a real block height");
            eprintln!("[hold]    HTLCs parked, claim_deadline={}", h);
        }
        other => panic!("expected Accepted while payer blocks, got {:?}", other),
    }

    backend
        .settle_hold_invoice(&preimage_hex)
        .expect("settle_hold_invoice (bolt11-claim-for-hash)");
    let state = poll_state(&backend, &hash_hex, Duration::from_secs(30), |s| {
        *s == HoldInvoiceState::Settled
    });
    assert_eq!(
        state,
        HoldInvoiceState::Settled,
        "expected Settled after claim"
    );
    eprintln!("[settle]  payment claimed");

    let pay_result = pay_handle.join().expect("payer thread").expect("pay rpc");
    let paid_preimage = pay_result
        .pointer("/result/payment_preimage")
        .and_then(|p| p.as_str())
        .unwrap_or_else(|| panic!("pay response missing preimage: {}", pay_result));
    assert_eq!(
        paid_preimage, preimage_hex,
        "payer must receive exactly the preimage we claimed with"
    );
    eprintln!("[payer]   pay completed with matching preimage");

    // ── 5. Cancel path ──────────────────────────────────────────────────────
    let (_, hash2) = rand_preimage();
    let hash2_hex = hex::encode(hash2);
    let bolt11_2 = backend
        .create_hold_invoice(150_000, &hash2_hex, "ldk-hold-cancel-test", 3600, None)
        .expect("create second hold invoice");

    let pay2_handle = spawn_payer_pay(&payer_socket, &bolt11_2);
    let state = poll_state(&backend, &hash2_hex, Duration::from_secs(60), |s| {
        matches!(s, HoldInvoiceState::Accepted { .. })
    });
    assert!(
        matches!(state, HoldInvoiceState::Accepted { .. }),
        "second invoice should reach Accepted, got {:?}",
        state
    );

    backend
        .cancel_hold_invoice(&hash2_hex)
        .expect("cancel_hold_invoice (bolt11-fail-for-hash)");
    // Cancel must both fail the payment (terminal state) AND clear the
    // claimable entry — the PaymentFailed arm of the fork's event loop.
    let state = poll_state(&backend, &hash2_hex, Duration::from_secs(30), |s| {
        *s == HoldInvoiceState::Canceled
    });
    assert_eq!(
        state,
        HoldInvoiceState::Canceled,
        "expected Canceled after fail"
    );

    let pay2_result = pay2_handle.join().expect("payer thread");
    match pay2_result {
        Ok(v) => assert!(
            v.get("error").is_some(),
            "payer's pay should error after cancel, got: {}",
            v
        ),
        Err(e) => eprintln!("[cancel]  payer pay aborted as expected ({})", e),
    }
    eprintln!("[cancel]  hold released, payer refunded");
    eprintln!("[ok] ldk-server fork hold-invoice lifecycle verified end-to-end");
}

/// Restart-resilience drill (#204): the fork's claimable_payments map is
/// in-memory, and the GetClaimableDetails handler claims it repopulates
/// after a restart because rust-lightning regenerates `PaymentClaimable`
/// for still-unclaimed payments on ChannelManager deserialization. This
/// test verifies that claim live: park HTLCs, kill ldk-server, restart it,
/// and assert Accepted{claim_deadline} comes back — then settle through
/// the restarted server and confirm the payer still completes with the
/// right preimage (the whole pipeline survived, not just the map).
///
/// Extra env (printed by ./bin/setup-ldk-hold.sh):
///   LDK_SERVER_BIN       path to the fork ldk-server binary
///   LDK_SERVER_CONFIG    path to its config.toml
///   LDK_SERVER_PID_FILE  pidfile written at startup
#[test]
#[ignore]
fn ldk_hold_invoice_survives_restart() {
    for var in [
        "LDK_CLI",
        "LDK_SERVER_BIN",
        "LDK_SERVER_CONFIG",
        "LDK_SERVER_PID_FILE",
    ] {
        if std::env::var(var).is_err() {
            eprintln!(
                "skipping: {} unset — start with ./bin/setup-ldk-hold.sh",
                var
            );
            return;
        }
    }
    let payer_socket = match std::env::var("CLN_PAYER_SOCKET_PATH") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skipping: CLN_PAYER_SOCKET_PATH unset");
            return;
        }
    };
    let server_bin = std::env::var("LDK_SERVER_BIN").unwrap();
    let server_config = std::env::var("LDK_SERVER_CONFIG").unwrap();
    let pid_file = std::env::var("LDK_SERVER_PID_FILE").unwrap();

    let backend = LdkBackend::new(LdkBackendConfig::from_env());

    // Park HTLCs.
    let (preimage, hash) = rand_preimage();
    let hash_hex = hex::encode(hash);
    let preimage_hex = hex::encode(preimage);
    let bolt11 = backend
        .create_hold_invoice(200_000, &hash_hex, "ldk-restart-test", 3600, None)
        .expect("create_hold_invoice");
    let pay_handle = spawn_payer_pay(&payer_socket, &bolt11);
    let state = poll_state(&backend, &hash_hex, Duration::from_secs(60), |s| {
        matches!(s, HoldInvoiceState::Accepted { .. })
    });
    let deadline_before = match state {
        HoldInvoiceState::Accepted { htlc_expiry_height } => {
            htlc_expiry_height.expect("claim_deadline before restart")
        }
        other => panic!("expected Accepted before restart, got {:?}", other),
    };
    eprintln!("[hold]    HTLCs parked, claim_deadline={}", deadline_before);

    // Kill the server.
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .expect("read pidfile")
        .trim()
        .parse()
        .expect("parse pid");
    unsafe { libc::kill(pid, libc::SIGTERM) };
    // Wait for exit (poll /proc).
    let start = Instant::now();
    while std::path::Path::new(&format!("/proc/{}", pid)).exists() {
        if start.elapsed() > Duration::from_secs(30) {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    eprintln!(
        "[kill]    ldk-server (pid {}) stopped while holding HTLCs",
        pid
    );

    // Restart it. The child outlives the test process (no kill-on-drop).
    let child = std::process::Command::new(&server_bin)
        .arg(&server_config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("respawn ldk-server");
    std::fs::write(&pid_file, child.id().to_string()).expect("rewrite pidfile");
    eprintln!("[restart] ldk-server respawned (pid {})", child.id());

    // The map must repopulate: rust-lightning regenerates PaymentClaimable
    // for unclaimed payments on deserialize; our event loop re-records it.
    // Allow generous time: server startup + payer channel reestablish
    // (CLN's reconnect timer) + event replay. Tolerate transient
    // connection-refused while the REST listener comes back up.
    let state = {
        let start = Instant::now();
        loop {
            match backend.lookup_hold_invoice(&hash_hex) {
                Ok(s) if matches!(s, HoldInvoiceState::Accepted { .. }) => break s,
                Ok(s) if start.elapsed() > Duration::from_secs(120) => break s,
                Ok(_) => {}
                Err(e) if start.elapsed() > Duration::from_secs(120) => {
                    panic!("server never came back after restart: {}", e)
                }
                Err(_) => {} // REST not up yet — keep waiting
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    match state {
        HoldInvoiceState::Accepted { htlc_expiry_height } => {
            let after = htlc_expiry_height.expect("claim_deadline must survive restart");
            eprintln!("[replay]  Accepted repopulated, claim_deadline={}", after);
        }
        other => panic!(
            "claimable state lost across restart (got {:?}) — the in-memory map \
             did NOT repopulate from event replay; persist it or re-derive at startup",
            other
        ),
    }

    // Settle through the restarted server: proves the full pipeline survived.
    backend
        .settle_hold_invoice(&preimage_hex)
        .expect("settle through restarted server");
    let state = poll_state(&backend, &hash_hex, Duration::from_secs(30), |s| {
        *s == HoldInvoiceState::Settled
    });
    assert_eq!(state, HoldInvoiceState::Settled);
    let pay_result = pay_handle.join().expect("payer thread").expect("pay rpc");
    let paid = pay_result
        .pointer("/result/payment_preimage")
        .and_then(|p| p.as_str())
        .unwrap_or_else(|| panic!("pay response missing preimage: {}", pay_result));
    assert_eq!(
        paid, preimage_hex,
        "payer preimage must match across restart"
    );
    eprintln!("[ok] hold survived ldk-server restart: park → kill → replay → settle");
}
