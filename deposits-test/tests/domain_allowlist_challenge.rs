//! Access control gate: domain allowlist + lightning challenge-response.
//!
//! Same setup as `domain_allowlist_nip05.rs` (op0 with ACL on, domain
//! allowlist `[172.21.0.50]`, ATTESTATION_VERIFIER_PUBKEY pointing at
//! `lnaddr-attest`), but the user's lightning address is a name that's
//! NOT registered in nip05 — so the verifier's NIP-05 fast path
//! returns false and falls through to the challenge flow:
//!
//!   1. wallet sends `link` → service issues a BOLT11 invoice for
//!      `challenge_sats + N*fee + premium`
//!   2. wallet pays the invoice (self-pay through the LDK wrapper since
//!      the verifier and the lnurl fixture share the LDK node)
//!   3. wallet sends `action=challenge` → service pays N random amounts
//!      summing to `challenge_sats` to the user's lightning address;
//!      each payment goes via lnurl-server.py → bolt11-receive → the
//!      same wrapper, which records every invoice in
//!      `/self-pay/invoices.jsonl`. The records since our baseline are
//!      precisely the challenge payments.
//!   4. wallet sends `action=verify` with the amounts → service checks
//!      and publishes the attestation
//!   5. wallet runs `deposits-wallet open` — its retry loop calls
//!      `link` again, gets `already_verified`, retries deposit_open,
//!      op0 matches the domain on the existing attestation, accepted.
//!
//! The wallet's `open` command reads challenge amounts from stdin,
//! which makes it impractical to drive non-interactively. So this test
//! plays the user side of the verify protocol directly via
//! `NostrTransport::send_verify_request` / `wait_for_verify_response`,
//! and only invokes `deposits-wallet open` after the attestation is in
//! place.
//!
//! Sibling tests:
//!   - `domain_allowlist_nip05.rs` (NIP-05 fast path)
//!
//! Requires:
//!   ./bin/setup.sh                                            (cluster)
//!   docker compose --profile lightning up -d lnaddr-attest    (verifier)
//!   ./bin/setup-attestation.sh   # generates secrets/verify_nsec
//!
//! Run with:
//!   cargo test -p deposits-test --test domain_allowlist_challenge -- --ignored

use deposits_node::nostr::NostrTransportBuilder;
use deposits_test::regtest::*;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FIXTURE_DOMAIN: &str = "172.21.0.50";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pay `invoice` via the LDK self-pay wrapper inside the lnaddr-attest
/// container. The wrapper short-circuits when the invoice's
/// payment_hash is already in `/self-pay/invoices.jsonl`, which it is
/// because the verifier just created it.
fn ldk_pay_invoice(invoice: &str) -> Result<(), String> {
    let cmd = format!(
        // Set the LDK env vars exactly like the container's entrypoint does,
        // since `docker exec` doesn't inherit them from the original process.
        "export LDK_API_KEY=$(cat /ldk-data/regtest/api_key | od -A n -t x1 | tr -d ' \\n') && \
         export LDK_REAL_CLI=/ldk-cli/ldk-server-cli && \
         /app/ldk-cli-wrapper.sh bolt11-send {}",
        invoice
    );
    let out = Command::new("docker")
        .args(["exec", "lnaddr-attest", "sh", "-c", &cmd])
        .output()
        .map_err(|e| format!("docker exec: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "bolt11-send failed: {} / {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Read `/self-pay/invoices.jsonl` and return the `amount_msat` of
/// every record that's:
///   * `status: succeeded` — the verifier has already paid it (challenge
///     payments are bolt11-send'd, the challenge invoice is bolt11-send'd
///     by us; the LNURL fee probe stays pending);
///   * `amount_msat != exclude_msat` — drop the challenge invoice itself
///     (it has the same status as the payments since we just paid it);
///   * `ts >= since_ts` — drop anything from a prior test run.
fn ldk_challenge_amounts_msat(since_ts: u64, exclude_msat: u64) -> Result<Vec<u64>, String> {
    let out = Command::new("docker")
        .args([
            "exec",
            "lnaddr-attest",
            "cat",
            "/self-pay/invoices.jsonl",
        ])
        .output()
        .map_err(|e| format!("docker exec cat: {}", e))?;
    let body = String::from_utf8_lossy(&out.stdout);
    let mut amounts = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("status").and_then(|x| x.as_str()) != Some("succeeded") {
            continue;
        }
        let ts = v.get("ts").and_then(|x| x.as_u64()).unwrap_or(0);
        if ts < since_ts {
            continue;
        }
        let amt = match v.get("amount_msat").and_then(|x| x.as_u64()) {
            Some(a) => a,
            None => continue,
        };
        if amt == exclude_msat {
            continue;
        }
        amounts.push(amt);
    }
    Ok(amounts)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn domain_allowlist_challenge_unlocks_deposit_open() {
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

    // Same TLS provider install the wallet/node binaries do — nostr-sdk's
    // rustls connection setup will panic without it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let verifier_xonly = match verifier_pubkey_xonly() {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("skipping: can't derive verifier pubkey — {}", e);
            return;
        }
    };

    let ledger = discover_op0_ledger();

    // Fresh user keypair. The corresponding name is NOT registered in
    // nip05 → verifier's fast path falls through to the challenge flow.
    let (user_sec_hex, _user_xonly) = keygen();
    let scratch = tempdir();
    let user_nsec = scratch.join("user.nsec");
    std::fs::write(&user_nsec, &user_sec_hex).unwrap();
    let user_secret_key = bitcoin::secp256k1::SecretKey::from_slice(
        &hex::decode(user_sec_hex.trim()).unwrap(),
    )
    .unwrap();
    let username = format!("ch{}", &_user_xonly[..8]);
    let address = format!("{}@{}", username, FIXTURE_DOMAIN);

    // Op0: ACL + domain allowlist + verifier pubkey (no npub allowlist
    // entry, so the only path to acceptance is via attestation).
    let _guard = Op0AccessControl::enable_with_attestation(
        &[],
        &[FIXTURE_DOMAIN],
        &verifier_xonly,
    );

    // Connect a Nostr transport as the user. The verifier subscribes to
    // both the ledgers and messaging relays after our compose change in
    // case (3); publishing to either reaches it.
    let transport = NostrTransportBuilder::new(user_secret_key)
        .relay(RELAY_LEDGERS)
        .relay(RELAY_MESSAGING)
        .build()
        .await
        .expect("nostr transport");

    // ─── 1. link ────────────────────────────────────────────────────
    let link_req_id = transport
        .send_verify_request(
            &verifier_xonly,
            serde_json::json!({ "lightning_address": &address }),
        )
        .await
        .expect("send link");
    let link_resp = transport
        .wait_for_verify_response(&link_req_id, 30_000)
        .await
        .expect("link response");

    // We expect the AwaitingPayment branch (NIP-05 fast path should
    // miss because the username isn't registered).
    let invoice = link_resp
        .get("invoice")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            panic!(
                "verifier returned no invoice — fast path may have fired:\n{:#}",
                link_resp
            )
        })
        .to_string();
    let session_id = link_resp
        .get("session_id")
        .and_then(|v| v.as_str())
        .expect("session_id")
        .to_string();
    let amount_sats = link_resp
        .get("amount_sats")
        .and_then(|v| v.as_u64())
        .expect("amount_sats");
    eprintln!("[link] invoice for {} sats, session={}…", amount_sats, &session_id[..8]);

    // ─── 2. pay challenge invoice ──────────────────────────────────
    ldk_pay_invoice(&invoice).expect("pay challenge invoice");
    eprintln!("[pay] challenge invoice settled via self-pay wrapper");

    // Snapshot the registry size BEFORE asking the verifier to launch
    // the N challenge payments, so we can identify exactly the new
    // records they produce.
    let baseline_ts = now_secs();
    // The wrapper's `ts` is in seconds, so step back 1s to avoid an
    // off-by-second miss.
    let baseline_ts = baseline_ts.saturating_sub(1);

    // ─── 3. challenge: poll until challenge_sent ─────────────────────
    let mut sent_amounts: Vec<u64> = Vec::new();
    for attempt in 0..40 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let req_id = transport
            .send_verify_request(
                &verifier_xonly,
                serde_json::json!({
                    "action": "challenge",
                    "session_id": &session_id,
                }),
            )
            .await
            .expect("send challenge");
        let resp = transport
            .wait_for_verify_response(&req_id, 15_000)
            .await
            .expect("challenge response");
        match resp.get("status").and_then(|v| v.as_str()) {
            Some("challenge_sent") => {
                eprintln!("[challenge] sent (attempt {})", attempt + 1);
                sent_amounts =
                    ldk_challenge_amounts_msat(baseline_ts, amount_sats * 1000)
                        .expect("read self-pay registry");
                eprintln!("[challenge] registry amounts (msat): {:?}", sent_amounts);
                break;
            }
            Some("payment_pending") => continue,
            Some(other) => panic!(
                "challenge returned unexpected status `{}`:\n{:#}",
                other, resp
            ),
            None => panic!("challenge response missing status:\n{:#}", resp),
        }
    }
    assert!(
        !sent_amounts.is_empty(),
        "challenge_sent never observed within 40s"
    );

    // ─── 4. verify ──────────────────────────────────────────────────
    let amounts_sats: Vec<u64> = sent_amounts.iter().map(|m| m / 1000).collect();
    let verify_req_id = transport
        .send_verify_request(
            &verifier_xonly,
            serde_json::json!({
                "action": "verify",
                "session_id": &session_id,
                "amounts": amounts_sats,
            }),
        )
        .await
        .expect("send verify");
    let verify_resp = transport
        .wait_for_verify_response(&verify_req_id, 30_000)
        .await
        .expect("verify response");
    let status = verify_resp
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        status, "verified",
        "verify did not succeed:\n{:#}",
        verify_resp
    );
    eprintln!("[verify] attestation issued");

    // ─── 5. wallet open should now succeed via the existing attestation ──
    let wallet_dir = tempdir();
    let (ok, out) = wallet_open(
        &ledger,
        "ch-deposit",
        &user_nsec,
        &wallet_dir,
        &[
            "--lightning-address",
            &address,
            "--relay",
            RELAY_LEDGERS,
        ],
    );
    // With the attestation already on relays, op0 accepts the very
    // first deposit_open — the wallet never has to enter its retry/
    // verify branch, so don't assert on "Already verified" output.
    assert!(
        ok && (out.contains("Deposit account created") || out.contains("Deposit account already exists")),
        "deposit_open should have been accepted with the existing attestation:\n{}",
        out
    );
}
