//! Access control gate: domain allowlist + NIP-05 attestation, with
//! the request signing key decoupled from the attested key.
//!
//! Two keypairs:
//!   * `nip05_key` — registered as `<username>` in the nip05 fixture.
//!     Signs the verify request (proves identity to the verifier).
//!   * `ephemeral_key` — what we actually want op0 to accept on
//!     `deposit_open`. Passed as `attest_pubkey` so the verifier
//!     stamps it (not the nip05 key) on the Kind 55502.
//!
//! Flow: test signs `link` with `nip05_key`, verifier confirms NIP-05
//! returns the signing key for the address, publishes attestation
//! tagged `["p", ephemeral_xonly]` and content
//! `{ npub: ephemeral, lightning_address: "<name>@172.21.0.50", method: "nip05" }`.
//! Op0 looks up the attestation, matches the domain, accepts a
//! `deposit_open` from `ephemeral_key`.
//!
//! Sibling tests:
//!   - `allowlist_pubkey.rs`           (pubkey allowlist, direct)
//!   - `allowlist_subkey.rs`           (pubkey allowlist + DEP-04 subkey)
//!   - `domain_allowlist_challenge.rs` (domain allowlist + LN challenge)
//!   - `domain_allowlist_proclaim.rs`  (manual allowlist + proclaim)
//!
//! Requires:
//!   ./bin/setup.sh                                        (cluster)
//!   docker compose --profile lightning up -d lnaddr-attest
//!   ./bin/setup-attestation.sh   # generates secrets/verify_nsec
//!
//! Run with:
//!   cargo test -p deposits-test --test domain_allowlist_nip05 -- --ignored

use deposits_node::nostr::NostrTransportBuilder;
use deposits_test::regtest::*;
use std::time::Duration;

const FIXTURE_DOMAIN: &str = "172.21.0.50";

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn domain_allowlist_nip05_unlocks_deposit_open() {
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
            eprintln!("  run `./bin/setup-attestation.sh` to generate the nsec");
            return;
        }
    };

    let ledger = discover_op0_ledger();

    // nip05_key: signs the verify request, registered in NIP-05.
    // ephemeral_key: gets attested + signs deposit_open.
    let (nip05_sec_hex, nip05_xonly) = keygen();
    let (ephemeral_sec_hex, ephemeral_xonly) = keygen();

    let username = format!("acc{}", &nip05_xonly[..8]);
    nip05_register(&username, &nip05_xonly).expect("nip05 register failed");

    let scratch = tempdir();
    let ephemeral_nsec = scratch.join("ephemeral.nsec");
    std::fs::write(&ephemeral_nsec, &ephemeral_sec_hex).unwrap();
    let nip05_secret_key =
        bitcoin::secp256k1::SecretKey::from_slice(&hex::decode(nip05_sec_hex.trim()).unwrap())
            .unwrap();

    let _guard = Op0AccessControl::enable_with_attestation(&[], &[FIXTURE_DOMAIN], &verifier_xonly);

    // The verifier's nip05 cache is keyed by domain. With the short
    // VERIFY_NIP05_CACHE_SECS in compose, sleep just past the TTL so a
    // names-map cached by an earlier test isn't authoritative for our
    // freshly-registered username.
    tokio::time::sleep(Duration::from_secs(6)).await;

    let address = format!("{}@{}", username, FIXTURE_DOMAIN);
    let transport = NostrTransportBuilder::new(nip05_secret_key)
        .relay(relay_ledgers())
        .relay(relay_messaging())
        .build()
        .await
        .expect("nostr transport");

    // Sign with nip05_key, ask the verifier to attest ephemeral_xonly.
    let req_id = transport
        .send_verify_request(
            &verifier_xonly,
            serde_json::json!({
                "lightning_address": &address,
                "attest_pubkey": &ephemeral_xonly,
            }),
        )
        .await
        .expect("send link");
    let resp = transport
        .wait_for_verify_response(&req_id, 30_000)
        .await
        .expect("link response");

    // Either the synchronous "verified" reply (cache miss → fetch →
    // match → publish) or "already_verified" (a previous test run
    // raced and wrote one) is fine — both prove the NIP-05 fast path
    // accepted the signer.
    let status = resp.get("status").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        status == "verified" || status == "already_verified",
        "verifier did not accept the NIP-05 link:\n{:#}",
        resp
    );
    if status == "verified" {
        assert_eq!(
            resp.get("method").and_then(|v| v.as_str()),
            Some("nip05"),
            "expected method=nip05:\n{:#}",
            resp
        );
        // The attestation is tagged with the ephemeral key, NOT the
        // signing key. That's the whole point of `attest_pubkey`.
        let npub = resp.get("npub").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            !npub.is_empty() && npub != format!("npub:{}", nip05_xonly),
            "expected the attested npub to be the ephemeral one, got:\n{:#}",
            resp
        );
    }

    // Brief pause for the relay to gossip before op0's fetch_events.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Op0 should accept a deposit_open signed by the ephemeral key —
    // the attestation event filter matches on `["p", ephemeral_xonly]`.
    let wallet_dir = tempdir();
    let (ok, out) = wallet_open(
        &ledger,
        "attested",
        &ephemeral_nsec,
        &wallet_dir,
        &["--relay", relay_ledgers()],
    );
    assert!(
        ok && (out.contains("Deposit account created")
            || out.contains("Deposit account already exists")),
        "deposit_open signed by ephemeral key should have been accepted via attestation:\n{}",
        out
    );
}
