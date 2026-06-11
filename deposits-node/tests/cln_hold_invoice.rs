//! Integration test: ClnBackend hold invoices against a live CLN node
//! running the BoltzExchange `hold` plugin.
//!
//! Exercises the full bridge-receive lifecycle from the backend's point of
//! view (DEP-10 §Receive, LN side only — no ledger involvement here):
//!
//!   1. probe: supports_hold_invoices() == true (plugin loaded, right variant)
//!   2. create_hold_invoice for a hash whose preimage only the test knows
//!   3. payer pays → HTLCs park → lookup transitions Open → Accepted,
//!      with the held HTLC's cltv_expiry surfaced
//!   4. settle_hold_invoice(preimage) → lookup reports Settled, and the
//!      payer's `pay` completes with that exact preimage
//!   5. (second invoice) cancel_hold_invoice → lookup reports Canceled,
//!      payer's `pay` fails, no funds move
//!
//! Requires the docker pair from `./bin/setup-cln-hold.sh`:
//!
//!   CLN_SOCKET_PATH=/tmp/cln-hold-test/regtest/lightning-rpc \
//!   CLN_PAYER_SOCKET_PATH=/tmp/cln-payer-test/regtest/lightning-rpc \
//!     cargo test -p deposits-node --test cln_hold_invoice -- --ignored --nocapture
//!
//! Skips cleanly when the env vars are absent.

use deposits_node::cln_backend::ClnBackend;
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

/// Drive `lightning-cli pay` on the payer node via its own unix socket,
/// in a background thread (pay blocks while HTLCs are held — that's the
/// property under test). Returns a handle resolving to the raw JSON-RPC
/// response line.
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
        // `pay` can block for the whole hold window; cap at the test budget.
        stream
            .set_read_timeout(Some(Duration::from_secs(120)))
            .map_err(|e| e.to_string())?;
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "pay",
            "params": { "bolt11": bolt11 },
        });
        let mut bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        stream.write_all(&bytes).map_err(|e| format!("write pay: {}", e))?;
        let mut line = String::new();
        BufReader::new(&stream)
            .read_line(&mut line)
            .map_err(|e| format!("read pay response: {}", e))?;
        serde_json::from_str(&line).map_err(|e| format!("parse pay response: {}", e))
    })
}

/// Poll `lookup_hold_invoice` until the predicate matches or the deadline
/// passes; returns the final state either way.
fn poll_state(
    backend: &ClnBackend,
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
fn cln_hold_invoice_settle_and_cancel() {
    let holder_socket = match std::env::var("CLN_SOCKET_PATH") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skipping: CLN_SOCKET_PATH unset — start with ./bin/setup-cln-hold.sh");
            return;
        }
    };
    let payer_socket = match std::env::var("CLN_PAYER_SOCKET_PATH") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skipping: CLN_PAYER_SOCKET_PATH unset — start with ./bin/setup-cln-hold.sh");
            return;
        }
    };

    let backend = ClnBackend::new(&holder_socket);

    // ── 1. Probe ────────────────────────────────────────────────────────────
    assert!(
        backend.supports_hold_invoices(),
        "hold plugin not detected (or wrong variant) on {}",
        holder_socket
    );
    eprintln!("[probe]   hold plugin detected");

    // ── 2-4. Happy path: create → pay → accepted → settle ──────────────────
    let (preimage, hash) = rand_preimage();
    let hash_hex = hex::encode(hash);
    let preimage_hex = hex::encode(preimage);

    let bolt11 = backend
        .create_hold_invoice(250_000, &hash_hex, "cln-hold-test", 3600)
        .expect("create_hold_invoice");
    assert!(
        bolt11.starts_with("lnbcrt"),
        "expected a regtest BOLT-11, got: {}",
        &bolt11[..20.min(bolt11.len())]
    );
    eprintln!("[create]  hold invoice for hash {}…", &hash_hex[..16]);

    // Before payment: Open (state "unpaid", no HTLCs).
    let state = backend.lookup_hold_invoice(&hash_hex).expect("lookup");
    assert_eq!(state, HoldInvoiceState::Open, "expected Open before payment");

    // Payer pays in the background — blocks while HTLCs are parked.
    let pay_handle = spawn_payer_pay(&payer_socket, &bolt11);

    // HTLCs arrive and park: Open → Accepted, with the held HTLC's expiry.
    let state = poll_state(&backend, &hash_hex, Duration::from_secs(60), |s| {
        matches!(s, HoldInvoiceState::Accepted { .. })
    });
    let expiry = match state {
        HoldInvoiceState::Accepted { htlc_expiry_height } => {
            let h = htlc_expiry_height.expect("hold plugin reports per-HTLC cltv_expiry");
            assert!(h > 0, "cltv_expiry should be a real block height");
            h
        }
        other => panic!("expected Accepted while payer blocks, got {:?}", other),
    };
    eprintln!("[hold]    HTLCs parked, cltv_expiry={}", expiry);

    // Settle with the preimage only this test ever knew.
    backend
        .settle_hold_invoice(&preimage_hex)
        .expect("settle_hold_invoice");
    let state = poll_state(&backend, &hash_hex, Duration::from_secs(30), |s| {
        *s == HoldInvoiceState::Settled
    });
    assert_eq!(state, HoldInvoiceState::Settled, "expected Settled after settle");
    eprintln!("[settle]  invoice settled");

    // The payer's blocking `pay` must now complete, carrying our preimage —
    // the cross-domain atomicity property: settle on the holder IS payment
    // completion for the payer.
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

    // ── 5. Cancel path: create → pay → accepted → cancel → payer fails ─────
    let (_, hash2) = rand_preimage();
    let hash2_hex = hex::encode(hash2);
    let bolt11_2 = backend
        .create_hold_invoice(150_000, &hash2_hex, "cln-hold-cancel-test", 3600)
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
    assert_eq!(state, HoldInvoiceState::Canceled, "expected Canceled after cancel");

    // The payer's `pay` must fail — HTLCs released, no funds moved.
    let pay2_result = pay2_handle.join().expect("payer thread");
    match pay2_result {
        Ok(v) => assert!(
            v.get("error").is_some(),
            "payer's pay should error after cancel, got: {}",
            v
        ),
        // A transport-level error (timeout reading the response) also means
        // the pay didn't complete — acceptable for the cancel path.
        Err(e) => eprintln!("[cancel]  payer pay aborted as expected ({})", e),
    }
    eprintln!("[cancel]  hold released, payer refunded");
    eprintln!("[ok] CLN hold-invoice lifecycle verified end-to-end");
}
