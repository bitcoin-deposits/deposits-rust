//! Integration test: `pay_invoice` self-pay path returns a real preimage.
//!
//! When two deposits served by the same operator pay each other, the
//! daemon takes the `self.pending_invoices.contains_key(payment_id)`
//! branch in `process_pay_invoice_request` and settles the BOLT11
//! internally — no Lightning hop. The preimage that hashes to the
//! invoice's payment_hash still has to be on the resulting
//! `InvoiceFulfill` ledger op (and on the response returned to the
//! payer); otherwise the on-ledger record is a placeholder, not real
//! proof-of-payment.
//!
//! For ~30s of bug history this branch hardcoded `preimage: [0u8; 32]`
//! because we never paid through LDK and didn't think we could
//! retrieve the receive-side preimage. Then we tried `list-payments`
//! (wrong — that command only enumerates OUTBOUND entries) and only
//! caught it after running `ldk-server-cli list-payments` against a
//! freshly-created invoice and getting `{"list": []}`. The fix uses
//! `get-payment-details <payment_hash>`, which returns the full
//! `payment.kind.kind.bolt11.preimage` for receive-side invoices.
//!
//! This test pins that down end-to-end:
//!
//!   1. Open two fresh deposits ("send", "recv") on the same operator's
//!      ledger so they share a `pending_invoices` map.
//!   2. Credit the sender via the operator's admin endpoint
//!      (`deposits-node deposit credit`) so the lock has funds.
//!   3. Issue a BOLT11 invoice for the recv deposit via `make_invoice`.
//!   4. Pay it from the send deposit via `pay_invoice` — same operator,
//!      so this hits the self-pay branch that the previous bug lived in.
//!   5. Assert the response carries a real (non-zero) preimage AND that
//!      preimage hashes to the payment_hash in the BOLT11.
//!
//! Requires:
//!   ./bin/setup.sh
//!   docker compose --profile lightning up -d lightning
//!
//! Run with:
//!   cargo test -p deposits-test --test pay_invoice_self_pay -- --ignored

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use deposits_node::nostr::NostrTransportBuilder;
use deposits_test::regtest::*;

// Uses the shared `find_clean_healthy_setup_ledger` helper from
// `deposits_test::regtest` — avoids custody-armed AND expired-quorum
// ledgers, both of which refuse `deposit_open`.

#[tokio::test]
#[ignore]
async fn pay_invoice_self_pay_returns_real_preimage() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh");
        return;
    }
    if !lightning_available() {
        eprintln!(
            "skipping: `lightning` container not running — \
             bring it up with `docker compose --profile lightning up -d lightning`"
        );
        return;
    }

    // ── Pick a clean + healthy ledger; both deposits live here ────────
    let (op_idx, ledger_id) = match find_clean_healthy_setup_ledger(100) {
        Some(p) => p,
        None => {
            eprintln!(
                "skipping: no clean+healthy setup ledger available — \
                 every ledger is either custody-armed or past quorum_expiry. \
                 Rerun against `setup.sh --fresh 3`."
            );
            return;
        }
    };
    eprintln!("[setup] ledger={}…  op={}", &ledger_id[..16], op_idx);

    // ── One wallet, two deposits ──────────────────────────────────────
    let wdir = tempdir();
    let (sec_hex, _xonly) = keygen();
    let nsec = wdir.join("wallet.nsec");
    std::fs::write(&nsec, &sec_hex).unwrap();

    // First open → key_index=0 → "send"; second → key_index=1 → "recv".
    let (ok1, out1) = wallet_open(&ledger_id, "send", &nsec, &wdir, &[]);
    assert!(
        ok1 && (out1.contains("Deposit account created")
            || out1.contains("Deposit account already exists")),
        "wallet open send:\n{}",
        out1
    );
    let (ok2, out2) = wallet_open(&ledger_id, "recv", &nsec, &wdir, &[]);
    assert!(
        ok2 && (out2.contains("Deposit account created")
            || out2.contains("Deposit account already exists")),
        "wallet open recv:\n{}",
        out2
    );

    let deposits: Vec<serde_json::Value> = serde_json::from_str(
        &std::fs::read_to_string(wdir.join("deposits.json")).unwrap(),
    )
    .unwrap();
    let send = deposits
        .iter()
        .find(|d| d["alias"].as_str() == Some("send"))
        .expect("send deposit");
    let recv = deposits
        .iter()
        .find(|d| d["alias"].as_str() == Some("recv"))
        .expect("recv deposit");
    let send_descriptor = send["descriptor"].as_str().unwrap().to_string();
    let recv_descriptor = recv["descriptor"].as_str().unwrap().to_string();
    let send_deposit_id_hex = send["deposit_id"].as_str().unwrap().to_string();
    let send_key_index = send["key_index"].as_u64().unwrap() as u32;

    // ── Fund the sender enough to cover invoice + transfer fees ───────
    //
    // Deposit credit is a daemon admin op that injects the credit
    // directly without going through Lightning. 100k sats is plenty
    // for a 1k-sat invoice plus the operator's per-transfer fee.
    let fund_msats = 100_000_000u64;
    operator_credit_deposit(
        op_idx,
        &ledger_id,
        &send_deposit_id_hex,
        fund_msats,
        &format!("self-pay-test-fund-{}", &send_deposit_id_hex[..8]),
    );
    // Give the credit a moment to propagate to the operator's in-memory state.
    std::thread::sleep(std::time::Duration::from_secs(1));

    // ── Wallet's Nostr signing identity ───────────────────────────────
    let user_secret_key =
        SecretKey::from_slice(&hex::decode(sec_hex.trim()).unwrap()).unwrap();
    let transport = NostrTransportBuilder::new(user_secret_key)
        .relay(relay_ledgers())
        .relay(relay_messaging())
        .build()
        .await
        .expect("nostr transport");

    // ── Step 1: make_invoice for `recv` ───────────────────────────────
    let amount_sats: u64 = 1_000;
    let mk_req = transport
        .send_ledger_request(
            &ledger_id,
            "make_invoice",
            serde_json::json!({
                "descriptor": recv_descriptor,
                "amount_sats": amount_sats,
                "description": "self-pay preimage test",
            }),
        )
        .await
        .expect("send make_invoice");
    let mk_resp = transport
        .wait_for_response(&mk_req, 30_000)
        .await
        .expect("make_invoice response");
    assert!(
        mk_resp.success,
        "make_invoice failed: {:?}",
        mk_resp.error.unwrap_or_default()
    );
    let mk_result = mk_resp.result.expect("make_invoice success but no result");
    let invoice = mk_result["invoice"]
        .as_str()
        .expect("missing invoice")
        .to_string();
    let payment_hash_hex = mk_result["payment_hash"]
        .as_str()
        .expect("missing payment_hash")
        .to_string();
    let payment_hash: [u8; 32] = hex::decode(&payment_hash_hex)
        .expect("payment_hash hex")
        .try_into()
        .expect("payment_hash 32 bytes");
    eprintln!(
        "[invoice] payment_hash={}…  amount={} sats",
        &payment_hash_hex[..16],
        amount_sats
    );

    // ── Step 2: build the pay_invoice witness from `send` ─────────────
    //
    // Wallet seed lives at <data_dir>/seed.hex — written by the first
    // `wallet_open`. Derive the send deposit's secret at its key_index
    // (matches `derive_secret_key_at_index` in the wallet) and sign the
    // dep-17 operation preimage via `sign_op`. The operator's pay_invoice
    // handler reads op_nonce/op_expiry from the request and binds them
    // into the InvoiceLock it stages, so the wallet's signature verifies.
    let seed_hex = std::fs::read_to_string(wdir.join("seed.hex")).unwrap();
    let seed_bytes = hex::decode(seed_hex.trim()).unwrap();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let send_sk = derive_deposit_secret(&seed, bitcoin::Network::Regtest, send_key_index);

    let mut send_deposit_id = [0u8; 16];
    send_deposit_id.copy_from_slice(
        &hex::decode(&send_deposit_id_hex).expect("send_deposit_id hex"),
    );
    let amount_msat = amount_sats * 1000;
    let op_nonce = deposits_core::signing::fresh_op_nonce();
    let op_expiry = u32::MAX;
    let proto = deposits_core::messages::LedgerOperation::InvoiceLock {
        deposit_id: send_deposit_id,
        amount: amount_msat,
        payment_id: payment_hash,
        sequence_number: 0,
        nonce: op_nonce,
        expiry: op_expiry,
        witness: deposits_core::types::DescriptorWitness::new(),
    };
    let signed = deposits_core::signing::sign_op(proto, &send_sk)
        .expect("InvoiceLock signs via dep-17 preimage");
    let witness = match signed {
        deposits_core::messages::LedgerOperation::InvoiceLock { witness, .. } => witness,
        _ => unreachable!(),
    };

    // ── Step 3: pay_invoice (self-pay path) ───────────────────────────
    let pay_req = transport
        .send_ledger_request(
            &ledger_id,
            "pay_invoice",
            serde_json::json!({
                "descriptor": send_descriptor,
                "invoice": invoice,
                "payment_hash": payment_hash_hex,
                "amount_msats": amount_msat,
                "witness": witness,
                "nonce": op_nonce,
                "expiry": op_expiry,
            }),
        )
        .await
        .expect("send pay_invoice");
    let pay_resp = transport
        .wait_for_response(&pay_req, 90_000)
        .await
        .expect("pay_invoice response");
    assert!(
        pay_resp.success,
        "pay_invoice failed: {:?}",
        pay_resp.error.unwrap_or_default()
    );
    let pay_result = pay_resp.result.expect("pay_invoice success but no result");

    // Should be the self-pay branch (same operator's pending_invoices).
    assert_eq!(
        pay_result["status"].as_str(),
        Some("succeeded"),
        "pay_invoice should succeed synchronously on self-pay"
    );
    assert_eq!(
        pay_result["self_pay"].as_bool(),
        Some(true),
        "expected self_pay=true; payment routed externally? response={}",
        pay_result
    );

    // ── Assertion 1: preimage is present and non-zero ─────────────────
    let preimage_hex = pay_result["preimage"]
        .as_str()
        .expect("missing preimage in self-pay response");
    assert_eq!(
        preimage_hex.len(),
        64,
        "expected 32-byte hex preimage, got {} chars",
        preimage_hex.len()
    );
    assert!(
        !preimage_hex.chars().all(|c| c == '0'),
        "preimage was all zeros — get-payment-details lookup probably failed; \
         check daemon log for 'Self-pay … LDK has no payment record'"
    );
    eprintln!("[pay] preimage={}…", &preimage_hex[..16]);

    // ── Assertion 2: preimage hashes to payment_hash ──────────────────
    let preimage_bytes: [u8; 32] = hex::decode(preimage_hex)
        .expect("preimage hex")
        .try_into()
        .expect("preimage 32 bytes");
    let computed_hash = *sha256::Hash::hash(&preimage_bytes).as_byte_array();
    assert_eq!(
        computed_hash, payment_hash,
        "preimage doesn't hash to payment_hash — that's not real proof of payment.\n\
         preimage:    {}\n\
         payment_hash: {}\n\
         computed:    {}",
        preimage_hex,
        hex::encode(payment_hash),
        hex::encode(computed_hash)
    );
    eprintln!("[pay] preimage verified: sha256(preimage) == payment_hash");
}
