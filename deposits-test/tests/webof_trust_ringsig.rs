//! Access control gate: anonymous web-of-trust via ring signature.
//!
//! End-to-end through the wallet binary — the test does NO crypto.
//! Setup and teardown are pure Nostr-event publication and shell-outs
//! to `deposits-wallet`, exactly matching the path a real user takes.
//!
//! Flow:
//!   1. Generate a wallet identity (xonly pubkey only — the secret is
//!      written to a nsec file the wallet reads via `--nsec-file`).
//!   2. Publish a kind:3 from the verifier's npub listing the wallet's
//!      xonly + 4 random decoy xonlys as `["p", …]` tags. The
//!      verifier's auto cover-builder samples this into a ring on its
//!      next refresh tick.
//!   3. Wait for the next refresh (compose ships `VERIFY_COVER_REFRESH_SECS=5`,
//!      so we wait 7s).
//!   4. Op0 — turn on access control, set the trusted verifier, leave
//!      pubkey/domain allowlists empty so the only path through is a
//!      ringsig attestation.
//!   5. `deposits-wallet ringsig-link <verifier_npub>` — wallet
//!      fetches the cover, finds itself in the ring, builds the
//!      ring-sig + binding proof, publishes the kind:25502 event,
//!      waits for the kind:25503 acceptance, persists a fresh bound
//!      nsec under the configured data dir.
//!   6. `deposits-wallet open <ledger> --nsec-file <bound>` —
//!      deposit_open is signed by the bound key. Op0's
//!      `check_attestation` finds the kind:55502 event tagged with
//!      that key, sees `method: "ringsig"`, accepts.
//!
//! Sibling tests:
//!   - `allowlist_pubkey.rs`           (allowlist, direct)
//!   - `allowlist_subkey.rs`           (allowlist + DEP-04 subkey)
//!   - `domain_allowlist_nip05.rs`     (domain allowlist + NIP-05)
//!   - `domain_allowlist_challenge.rs` (domain allowlist + LN challenge)
//!   - `domain_allowlist_proclaim.rs`  (manual allowlist + proclaim)
//!
//! Requires:
//!   ./bin/setup.sh                                              (cluster)
//!   docker compose --profile lightning up -d lnaddr-attest      (verifier)
//!   ./bin/setup-attestation.sh   # generates secrets/verify_nsec
//!
//! Run with:
//!   cargo test -p deposits-test --test webof_trust_ringsig -- --ignored

use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{Secp256k1, SecretKey as SecpSk};
use deposits_test::regtest::*;
use nostr_sdk::prelude::*;
use std::process::Command;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn ringsig_via_wallet_binary() {
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
    let verifier_nsec_hex = std::fs::read_to_string(
        repo_root().join("deposits-tools/secrets/verify_nsec"),
    )
    .expect("read verify_nsec")
    .trim()
    .to_string();
    let verifier_keys = Keys::new(SecretKey::from_hex(&verifier_nsec_hex).expect("nsec hex"));
    let verifier_npub = verifier_keys.public_key().to_bech32().expect("npub bech32");

    let ledger = discover_op0_ledger();
    let secp = Secp256k1::new();

    // ── Wallet identity ────────────────────────────────────────────
    //
    // The wallet's seed-derived nsec key is what gets ring-signed
    // with. We bypass the wallet's seed→key derivation by writing a
    // fresh secret key directly to `wallet.nsec` and passing it via
    // `--nsec-file`; that way the test's xonly (which we publish in
    // kind:3) and the wallet's xonly (which it looks up in the cover)
    // are guaranteed to match.
    let wallet_sk = SecpSk::new(&mut OsRng);
    let wallet_xonly = hex::encode(&wallet_sk.public_key(&secp).serialize()[1..]);
    let scratch = tempdir();
    let wallet_nsec = scratch.join("wallet.nsec");
    std::fs::write(&wallet_nsec, hex::encode(wallet_sk.secret_bytes())).unwrap();

    let decoys: Vec<String> = (0..4)
        .map(|_| {
            hex::encode(&SecpSk::new(&mut OsRng).public_key(&secp).serialize()[1..])
        })
        .collect();

    // ── Publish kind:3 from the verifier ───────────────────────────
    let mut p_tags: Vec<Tag> = decoys
        .iter()
        .chain(std::iter::once(&wallet_xonly))
        .map(|x| {
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)),
                [x.clone()],
            )
        })
        .collect();
    // The verifier's auto-cover-build dedups + sorts, but the kind:3
    // event's tag order doesn't matter for that.
    p_tags.sort_by_key(|t| t.clone().to_vec().get(1).cloned().unwrap_or_default());

    let pub_client = Client::new(verifier_keys.clone());
    pub_client.add_relay(relay_ledgers()).await.unwrap();
    pub_client.connect().await;
    // `connect` returns before the websocket handshake settles.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let kind3 = EventBuilder::new(Kind::ContactList, "")
        .tags(p_tags)
        .sign_with_keys(&verifier_keys)
        .unwrap();
    let kind3_id = kind3.id.to_hex();
    let send_out = pub_client.send_event(kind3).await.expect("send_event call");
    assert!(
        !send_out.success.is_empty(),
        "no relay accepted our kind:3 publish (failed={:?})",
        send_out.failed,
    );

    // Confirm the kind:3 is queryable on the relay before we ask
    // the verifier to refresh its cover. Use a *fresh* client to query —
    // `pub_client`'s local cache will happily echo back the event we
    // just sent regardless of whether the relay actually accepted it,
    // which can mask broken publish paths (e.g. a stray strfry process
    // SO_REUSEPORT-bound to the same port siphoning off connections).
    {
        let probe_keys = Keys::generate();
        let probe_client = Client::new(probe_keys);
        probe_client.add_relay(relay_ledgers()).await.unwrap();
        probe_client.connect().await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let confirm_filter = Filter::new()
            .kind(Kind::ContactList)
            .author(verifier_keys.public_key())
            .limit(20);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut visible = false;
        let mut last_seen: Vec<String> = Vec::new();
        while tokio::time::Instant::now() < deadline {
            if let Ok(events) = probe_client
                .fetch_events(vec![confirm_filter.clone()], Some(Duration::from_secs(2)))
                .await
            {
                last_seen = events
                    .iter()
                    .map(|e| format!("{}@{}", &e.id.to_hex()[..8], e.created_at.as_u64()))
                    .collect();
                if events.iter().any(|e| e.id.to_hex() == kind3_id) {
                    visible = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(
            visible,
            "kind:3 we just published (id={}) never appeared on the relay; \
             relay's view at last poll: [{}]",
            kind3_id,
            last_seen.join(", "),
        );
    }
    eprintln!("[setup] kind:3 (id={}…) confirmed on relay", &kind3_id[..16]);

    // ── Wait for the verifier to ingest our kind:3 + republish ────
    //
    // The verifier's cover-builder fetches the anchor's kind:3 every
    // VERIFY_COVER_REFRESH_SECS (compose pins this to 5s for tests).
    // We need at least one full cycle where it sees our kind:3 *and*
    // publishes the resulting cover after we started watching. In
    // back-to-back runs the relay's view of "latest kind:3" can lag
    // a bit, so give 4 ticks of buffer.
    tokio::time::sleep(Duration::from_secs(22)).await;

    // ── Op0: ACL on, no allowlist or domain — only ringsig works ───
    let _guard = Op0AccessControl::enable_with_attestation(&[], &[], &verifier_xonly);

    // ── Wallet: ringsig-link ──────────────────────────────────────
    let wallet_dir = tempdir();
    let alias = "ringsig-test";
    let out = Command::new(wallet_bin())
        .args([
            "ringsig-link",
            &verifier_npub,
            "--nsec-file",
            wallet_nsec.to_str().unwrap(),
            "--data-dir",
            wallet_dir.to_str().unwrap(),
            "--relay",
            relay_ledgers(),
            "--network",
            "regtest",
            "--alias",
            alias,
        ])
        .output()
        .expect("invoke ringsig-link");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "ringsig-link failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("Verified."),
        "expected `Verified.` in ringsig-link output:\n{}",
        stdout
    );
    eprintln!("[ringsig-link] succeeded");

    let bound_nsec = wallet_dir.join(format!("{}.nsec", alias));
    assert!(
        bound_nsec.exists(),
        "bound nsec file not written at {}",
        bound_nsec.display()
    );

    // ── Wallet: open a deposit signed by the bound key ────────────
    let deposit_dir = tempdir();
    let (ok, out) = wallet_open(
        &ledger,
        "rs-deposit",
        &bound_nsec,
        &deposit_dir,
        &["--relay", relay_ledgers()],
    );
    assert!(
        ok && (out.contains("Deposit account created")
            || out.contains("Deposit account already exists")),
        "deposit_open with bound key should have been accepted via ringsig:\n{}",
        out
    );
    eprintln!("[deposit_open] accepted");
}
