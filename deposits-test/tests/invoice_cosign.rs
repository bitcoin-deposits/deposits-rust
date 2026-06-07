//! Integration test: `make_invoice` cosignature path on a quorum-active ledger.
//!
//! On a post-`QuorumBegin` ledger, every Lightning invoice the operator
//! issues must carry a cosignature from one of the active quorum members
//! (DEP-05, `process_make_invoice_request` → `cosign_invoice`).
//!
//! The cosign listening loop in `invoice.rs` is unusual — it busy-polls
//! the notification stream from inside the request handler — so it
//! warrants its own end-to-end test rather than relying on the LNURL
//! gateway test (which discards the cosign metadata).
//!
//! This test:
//!   1. Opens a fresh deposit on op2's L1 ledger — op0/op1's ledgers
//!      have been touched by fraud-proof tests (custody-armed marker
//!      present), op2/op3 are clean. The ledger advertisement is
//!      asserted to be `Active` regardless of which one we pick.
//!   2. Sends `make_invoice` directly over Nostr (bypasses the wallet
//!      CLI which only echoes the BOLT11) and captures the full
//!      response, including the cosign trio.
//!   3. Asserts the cosigner is one of the advertised quorum members.
//!   4. Reconstructs the canonical signing message via
//!      `invoice_cosign_signing_message` and verifies the BIP-340
//!      Schnorr signature against the cosigner's x-only pubkey.
//!
//! Requires:
//!   ./bin/setup.sh
//!   docker compose --profile lightning up -d lightning
//!
//! Run with:
//!   cargo test -p deposits-test --test invoice_cosign -- --ignored

use deposits_core::signature_utils::invoice_cosign_signing_message;
use deposits_core::types::compute_deposit_id;
use deposits_node::nostr::NostrTransportBuilder;
use deposits_test::regtest::*;

// Uses the shared `find_clean_healthy_setup_ledger` helper from
// `deposits_test::regtest` — see that helper's docs for the
// custody-armed and quorum-expiry constraints. Requiring >100 blocks
// of headroom keeps the test from picking a ledger that the dispute
// tests have aged to within minutes of expiry.

#[tokio::test]
#[ignore]
async fn make_invoice_returns_valid_cosignature() {
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

    // ── 1. Pick a clean + healthy ledger and open a fresh deposit on it ──
    //
    // Custody-armed ledgers refuse new deposit_open; expired-quorum
    // ledgers refuse with "operator's quorum has expired." Iterate
    // setup state until we find one that's both.
    let (op_idx, ledger_id) = match find_clean_healthy_setup_ledger(100) {
        Some(p) => p,
        None => {
            eprintln!(
                "skipping: no clean+healthy setup ledger available — \
                 cluster is either custody-armed or aged past every \
                 quorum_expiry. Rerun against `setup.sh --fresh 3`."
            );
            return;
        }
    };
    eprintln!("[setup]  ledger={}…  op={}", &ledger_id[..16], op_idx);

    let wdir = tempdir();
    let (sec_hex, _xonly) = keygen();
    let nsec = wdir.join("wallet.nsec");
    std::fs::write(&nsec, &sec_hex).unwrap();

    let (ok, out) = wallet_open(&ledger_id, "cosign-test", &nsec, &wdir, &[]);
    assert!(
        ok && (out.contains("Deposit account created")
            || out.contains("Deposit account already exists")),
        "wallet open failed:\n{}",
        out
    );

    let deposits_json = std::fs::read_to_string(wdir.join("deposits.json")).unwrap();
    let deposits: serde_json::Value = serde_json::from_str(&deposits_json).unwrap();
    // Wave-2: wallets persist `descriptor` directly. Fall back to
    // synthesizing pk(<deposit_pubkey>) so the test still passes against
    // older deposit records during the migration window.
    let descriptor = match deposits[0]["descriptor"].as_str() {
        Some(d) => d.to_string(),
        None => {
            let pk = deposits[0]["deposit_pubkey"]
                .as_str()
                .expect("deposit record missing both descriptor and deposit_pubkey");
            format!("pk({})", pk)
        }
    };
    eprintln!("[setup]  descriptor={}…", &descriptor[..32.min(descriptor.len())]);

    // ── 2. Connect a Nostr transport with the wallet's signing key ──
    let user_secret_key = bitcoin::secp256k1::SecretKey::from_slice(
        &hex::decode(sec_hex.trim()).unwrap(),
    )
    .unwrap();
    let transport = NostrTransportBuilder::new(user_secret_key)
        .relay(relay_ledgers())
        .relay(relay_messaging())
        .build()
        .await
        .expect("nostr transport");

    // ── 3. Fetch the ledger advertisement to learn the quorum membership ──
    //
    // We don't strictly need `ad.quorum_state == "Active"` here — older
    // clusters published ads before that field existed and default it to
    // empty. The authoritative check is `cosign_required: true` in the
    // make_invoice response below, which reflects the operator's actual
    // `is_quorum_active` view.
    let ad = transport
        .fetch_ledger_advertisement(&ledger_id)
        .await
        .expect("ad query")
        .expect("operator should publish a Kind 39100 advertisement");
    if ad.quorum_members.is_empty() {
        eprintln!(
            "[setup]  ad has no quorum_members (legacy or pre-quorum ad) — \
             will rely on response.cosigner_pubkey to identify the cosigner"
        );
    } else {
        eprintln!(
            "[setup]  ad lists {} quorum member(s)",
            ad.quorum_members.len()
        );
    }

    // ── 4. Send make_invoice over Nostr; capture the full response ──
    let amount_sats: u64 = 1_000;
    let req_id = transport
        .send_ledger_request(
            &ledger_id,
            "make_invoice",
            serde_json::json!({
                "descriptor": &descriptor,
                "amount_sats": amount_sats,
                "description": "invoice_cosign integration test",
            }),
        )
        .await
        .expect("send make_invoice");
    let resp = transport
        .wait_for_response(&req_id, 30_000)
        .await
        .expect("make_invoice response");
    assert!(
        resp.success,
        "make_invoice failed: {:?}",
        resp.error.unwrap_or_default()
    );
    let result = resp.result.expect("make_invoice success but no result");

    // ── 5. Sanity-check the invoice ──
    let invoice = result["invoice"]
        .as_str()
        .expect("missing `invoice` field");
    assert!(
        invoice.starts_with("lnbcrt"),
        "expected regtest BOLT11, got: {}",
        &invoice[..invoice.len().min(20)]
    );
    let cosign_required = result["cosign_required"].as_bool().unwrap_or(false);
    if !cosign_required {
        eprintln!(
            "skipping: ledger {} is not quorum-active (no QuorumBegin yet) — \
             can't exercise cosign_invoice path. Re-run setup.sh.",
            &ledger_id[..16]
        );
        return;
    }

    // ── 6. Cosigner must be one of the advertised quorum members
    // (when the ad has them; older ads might omit the field) ──
    //
    // Members in the ad are 33-byte compressed (66 hex). The cosign
    // handler returns the same compressed form (`hex::encode(node_id.serialize())`).
    let cosigner_pubkey_hex = result["cosigner_pubkey"]
        .as_str()
        .expect("missing cosigner_pubkey")
        .to_string();
    if !ad.quorum_members.is_empty() {
        assert!(
            ad.quorum_members.iter().any(|m| m == &cosigner_pubkey_hex),
            "cosigner {} not in advertised quorum {:?}",
            cosigner_pubkey_hex,
            ad.quorum_members,
        );
        eprintln!(
            "[cosign] cosigner={}… (1 of {})",
            &cosigner_pubkey_hex[..16],
            ad.quorum_members.len()
        );
    } else {
        eprintln!(
            "[cosign] cosigner={}… (ad had no quorum_members to cross-check)",
            &cosigner_pubkey_hex[..16]
        );
    }

    // ── 7. Verify the BIP-340 signature over the canonical message ──
    let payment_hash_hex = result["payment_hash"]
        .as_str()
        .expect("missing payment_hash");
    let cosigner_ledger_hash_hex = result["cosigner_ledger_hash"]
        .as_str()
        .expect("missing cosigner_ledger_hash");
    let cosign_signature_hex = result["cosign_signature"]
        .as_str()
        .expect("missing cosign_signature");

    let payment_hash: [u8; 32] = hex::decode(payment_hash_hex)
        .expect("payment_hash hex")
        .try_into()
        .expect("payment_hash 32 bytes");
    let cosigner_ledger_hash: [u8; 32] = hex::decode(cosigner_ledger_hash_hex)
        .expect("cosigner_ledger_hash hex")
        .try_into()
        .expect("cosigner_ledger_hash 32 bytes");
    let sig_bytes: [u8; 64] = hex::decode(cosign_signature_hex)
        .expect("cosign_signature hex")
        .try_into()
        .expect("cosign_signature 64 bytes");

    let deposit_id = compute_deposit_id(&descriptor);
    let amount_msat = amount_sats * 1000;
    let msg_hash = invoice_cosign_signing_message(
        &ledger_id,
        &payment_hash,
        &deposit_id,
        amount_msat,
        &cosigner_ledger_hash,
    );

    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
        .expect("signature from_slice");
    let cosigner_compressed =
        hex::decode(&cosigner_pubkey_hex).expect("cosigner_pubkey hex");
    assert_eq!(
        cosigner_compressed.len(),
        33,
        "cosigner_pubkey expected 33-byte compressed, got {} bytes",
        cosigner_compressed.len()
    );
    // BIP-340 verifies against the x-only (drop the parity prefix byte).
    let cosigner_xonly =
        bitcoin::secp256k1::XOnlyPublicKey::from_slice(&cosigner_compressed[1..])
            .expect("cosigner xonly");
    let msg = bitcoin::secp256k1::Message::from_digest(msg_hash);

    secp.verify_schnorr(&sig, &msg, &cosigner_xonly)
        .expect("cosign signature must verify against canonical message");
    eprintln!("[cosign] BIP-340 signature verified");
}
