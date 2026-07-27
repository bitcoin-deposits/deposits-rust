//! Integration test: LndBackend hold invoices against a live LND node
//! (native `invoicesrpc` — /v2/invoices/hodl, settle, cancel).
//!
//! Mirrors `cln_hold_invoice.rs`: the full bridge-receive lifecycle from the
//! backend's point of view (DEP-10 §Receive, LN side only). The payer is the
//! CLN node from ./bin/setup-cln-hold.sh, with a channel into the LND holder
//! opened by ./bin/setup-lnd-hold.sh.
//!
//!   LND_REST_URL=https://localhost:8180 \
//!   LND_MACAROON_FILE=/tmp/lnd-hold-test/data/chain/bitcoin/regtest/admin.macaroon \
//!   LND_TLS_INSECURE=1 \
//!   CLN_PAYER_SOCKET_PATH=/tmp/cln-payer-test/regtest/lightning-rpc \
//!     cargo test -p deposits-node --test lnd_hold_invoice -- --ignored --nocapture
//!
//! Skips cleanly when the env vars are absent.
//!
//! The encoding seams this exists to catch: LND's REST byte fields are
//! base64 in POST bodies (hash, preimage, payment_hash) but URL-safe base64
//! in the lookup path segment, while our trait traffics in hex — plus the
//! grpc-gateway's string-typed numbers and the OPEN/ACCEPTED/SETTLED/
//! CANCELED state names. All four conversions are exercised live here.

use deposits_node::lightning_backend::{HoldInvoiceState, LightningBackend};
use deposits_node::lnd_backend::LndBackend;
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

/// Drive `pay` on the CLN payer via its unix socket in a background thread
/// (it blocks while the LND holder parks the HTLCs).
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
    backend: &LndBackend,
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
fn lnd_hold_invoice_settle_and_cancel() {
    if std::env::var("LND_REST_URL").is_err() {
        eprintln!("skipping: LND_REST_URL unset — start with ./bin/setup-lnd-hold.sh");
        return;
    }
    let payer_socket = match std::env::var("CLN_PAYER_SOCKET_PATH") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skipping: CLN_PAYER_SOCKET_PATH unset — start with ./bin/setup-cln-hold.sh");
            return;
        }
    };

    let backend = LndBackend::from_env().expect("LndBackend::from_env");

    // ── 1. Probe ────────────────────────────────────────────────────────────
    assert!(
        backend.supports_hold_invoices(),
        "LND always supports hold invoices"
    );
    eprintln!("[probe]   invoicesrpc available");

    // ── 2-4. Happy path: create → pay → accepted → settle ──────────────────
    let (preimage, hash) = rand_preimage();
    let hash_hex = hex::encode(hash);
    let preimage_hex = hex::encode(preimage);

    // Request a 200-block hold window (LND honors cltv_expiry — #205).
    // The Accepted assertion below verifies the request was applied by
    // measuring the actual HTLC expiry against the chain tip.
    let bolt11 = backend
        .create_hold_invoice(250_000, &hash_hex, "lnd-hold-test", 3600, Some(200))
        .expect("create_hold_invoice");
    assert!(
        bolt11.starts_with("lnbcrt"),
        "expected a regtest BOLT-11, got: {}",
        &bolt11[..20.min(bolt11.len())]
    );
    eprintln!("[create]  hold invoice for hash {}…", &hash_hex[..16]);

    // Before payment: OPEN.
    let state = backend.lookup_hold_invoice(&hash_hex).expect("lookup");
    assert_eq!(
        state,
        HoldInvoiceState::Open,
        "expected Open before payment"
    );

    let pay_handle = spawn_payer_pay(&payer_socket, &bolt11);

    // HTLCs park: OPEN → ACCEPTED, with htlcs[].expiry_height surfaced.
    let state = poll_state(&backend, &hash_hex, Duration::from_secs(60), |s| {
        matches!(s, HoldInvoiceState::Accepted { .. })
    });
    let expiry = match state {
        HoldInvoiceState::Accepted { htlc_expiry_height } => {
            let h = htlc_expiry_height.expect("LND reports htlcs[].expiry_height");
            assert!(h > 0, "expiry_height should be a real block height");
            h
        }
        other => panic!("expected Accepted while payer blocks, got {:?}", other),
    };
    // Verify the requested 200-block window was honored: measured headroom
    // should be ~200 (payer shaves a few blocks in flight; the regtest miner
    // adds a few while we poll). Well above LND's default (~80-144) proves
    // the cltv_expiry request took effect.
    let tip = backend
        .get_node_info()
        .expect("get_node_info")
        .current_best_block_height
        .expect("LND reports block height");
    let headroom = expiry.saturating_sub(tip);
    assert!(
        (160..=220).contains(&headroom),
        "requested 200-block hold window, measured headroom {} (expiry {} - tip {})",
        headroom,
        expiry,
        tip
    );
    eprintln!(
        "[hold]    HTLCs parked, expiry_height={} (headroom {} of 200 requested)",
        expiry, headroom
    );

    backend
        .settle_hold_invoice(&preimage_hex)
        .expect("settle_hold_invoice");
    let state = poll_state(&backend, &hash_hex, Duration::from_secs(30), |s| {
        *s == HoldInvoiceState::Settled
    });
    assert_eq!(
        state,
        HoldInvoiceState::Settled,
        "expected Settled after settle"
    );
    eprintln!("[settle]  invoice settled");

    let pay_result = pay_handle.join().expect("payer thread").expect("pay rpc");
    let paid_preimage = pay_result
        .pointer("/result/payment_preimage")
        .and_then(|p| p.as_str())
        .unwrap_or_else(|| panic!("pay response missing preimage: {}", pay_result));
    assert_eq!(
        paid_preimage, preimage_hex,
        "payer must receive exactly the preimage we settled with"
    );
    eprintln!("[payer]   pay completed with matching preimage");

    // ── 5. Cancel path ──────────────────────────────────────────────────────
    let (_, hash2) = rand_preimage();
    let hash2_hex = hex::encode(hash2);
    let bolt11_2 = backend
        .create_hold_invoice(150_000, &hash2_hex, "lnd-hold-cancel-test", 3600, None)
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
        .expect("cancel_hold_invoice");
    let state = poll_state(&backend, &hash2_hex, Duration::from_secs(30), |s| {
        *s == HoldInvoiceState::Canceled
    });
    assert_eq!(
        state,
        HoldInvoiceState::Canceled,
        "expected Canceled after cancel"
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
    eprintln!("[ok] LND hold-invoice lifecycle verified end-to-end");
}
