//! Access control gate: manual allowlist + verifier `proclaim`.
//!
//! An account that's already on op0's `deposit_allowlist.txt` can ask
//! the verifier to attest a *different* (typically ephemeral) npub on
//! its behalf. The verifier only needs to confirm that the request
//! signer is in the allowlist file (mounted ro into the lnaddr-attest
//! container); no NIP-05, no LN payment.
//!
//!   1. test signs `{action: "proclaim", attest_pubkey: <ephemeral>}`
//!      with the allowlisted `account_key`
//!   2. verifier reads `VERIFY_ALLOWLIST_FILE`, sees the signer, and
//!      publishes a Kind 55502 with `allowlist_npub: <signer_xonly>`
//!      tagged `["p", <ephemeral>]`
//!   3. wallet (or test) opens a deposit signed by the ephemeral key —
//!      op0's `check_attestation` finds the event, sees `allowlist_npub`
//!      matches its own allowlist, accepts.
//!
//! Sibling tests:
//!   - `allowlist_pubkey.rs`            (allowlist, direct)
//!   - `allowlist_subkey.rs`            (allowlist + DEP-04 subkey)
//!   - `domain_allowlist_nip05.rs`      (domain allowlist + NIP-05)
//!   - `domain_allowlist_challenge.rs`  (domain allowlist + LN challenge)
//!
//! Requires:
//!   ./bin/setup.sh                                              (cluster)
//!   docker compose --profile lightning up -d lnaddr-attest      (verifier)
//!
//! Run with:
//!   cargo test -p deposits-test --test domain_allowlist_proclaim -- --ignored

use deposits_node::nostr::NostrTransportBuilder;
use deposits_test::regtest::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn proclaim_unlocks_deposit_open() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh");
        return;
    }
    if !lnaddr_attest_available() {
        eprintln!(
            "skipping: `lnaddr-attest` container not running — \
             bring it up with `docker compose --profile lightning up -d lnaddr-attest`"
        );
        return;
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let verifier_xonly = match verifier_pubkey_xonly() {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("skipping: can't derive verifier pubkey — {}", e);
            return;
        }
    };

    let ledger = discover_op0_ledger();

    // account_key — added to op0's allowlist; signs the proclaim
    // request the verifier checks.
    // ephemeral_key — gets attested + signs the eventual deposit_open.
    let (account_sec_hex, account_xonly) = keygen();
    let (ephemeral_sec_hex, ephemeral_xonly) = keygen();

    let scratch = tempdir();
    let ephemeral_nsec = scratch.join("ephemeral.nsec");
    std::fs::write(&ephemeral_nsec, &ephemeral_sec_hex).unwrap();
    let account_secret_key = bitcoin::secp256k1::SecretKey::from_slice(
        &hex::decode(account_sec_hex.trim()).unwrap(),
    )
    .unwrap();

    // Op0: ACL on, account on the allowlist (so the verifier accepts
    // its proclamation), no domain allowlist (the proclaim path
    // doesn't need one).
    let _guard = Op0AccessControl::enable_with_attestation(
        &[&account_xonly],
        &[],
        &verifier_xonly,
    );

    // Connect a Nostr transport signing as the account_key. The
    // verifier subscribes on both the ledgers and messaging relays
    // (configured in compose for the NIP-05 path); either reaches it.
    let transport = NostrTransportBuilder::new(account_secret_key)
        .relay(relay_ledgers())
        .relay(relay_messaging())
        .build()
        .await
        .expect("nostr transport");

    let req_id = transport
        .send_verify_request(
            &verifier_xonly,
            serde_json::json!({
                "action": "proclaim",
                "attest_pubkey": &ephemeral_xonly,
            }),
        )
        .await
        .expect("send proclaim");
    let resp = transport
        .wait_for_verify_response(&req_id, 30_000)
        .await
        .expect("proclaim response");
    assert_eq!(
        resp.get("status").and_then(|v| v.as_str()),
        Some("verified"),
        "verifier rejected the proclamation:\n{:#}",
        resp
    );
    assert_eq!(
        resp.get("method").and_then(|v| v.as_str()),
        Some("proclaim"),
    );
    assert_eq!(
        resp.get("allowlist_npub").and_then(|v| v.as_str()),
        Some(account_xonly.as_str()),
        "attestation should record the allowlisted signer:\n{:#}",
        resp
    );
    eprintln!(
        "[proclaim] attestation issued: {}",
        &resp.get("attestation_event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("(missing)")[..16]
    );

    // Give the relay a moment to gossip the new event before op0's
    // 5-second fetch_events kicks in.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Now open a deposit signed by the ephemeral key. Op0 looks up the
    // attestation tagged with ephemeral_xonly, sees `allowlist_npub` =
    // account_xonly is in its `deposit_allowlist`, accepts.
    let wallet_dir = tempdir();
    let (ok, out) = wallet_open(
        &ledger,
        "proclaimed",
        &ephemeral_nsec,
        &wallet_dir,
        &["--relay", relay_ledgers()],
    );
    assert!(
        ok && (out.contains("Deposit account created") || out.contains("Deposit account already exists")),
        "deposit_open should have been accepted via the proclaim attestation:\n{}",
        out
    );
}
