//! Access control gate: pubkey allowlist + DEP-04 subkey attestation.
//!
//! The allowlist only names an account; a separate subkey is attested
//! to that account via a Kind 10301 event. Op0 resolves the subkey back
//! to the account via the `v`/`va` tags on the deposit request.
//!
//!   a. Subkey signs with v/va → resolves to allowlisted account → accepted
//!   b. Subkey signs bare (no v/va) → only the subkey is visible, not
//!      on the allowlist → `not_authorized`
//!   c. Account revokes the subkey; subkey retries with the old
//!      attestation sig → `resolve_attested_sender` sees the revocation
//!      → `invalid_subkey_delegation` (or `revoked`)
//!
//! Sibling tests for the other gates:
//!   - `allowlist_pubkey.rs`       (pubkey allowlist only, no delegation)
//!   - `domain_allowlist_nip05.rs` (domain allowlist + NIP-05 attestation)
//!
//! Requires `./bin/setup.sh`. Run with:
//!   cargo test -p deposits-test --test allowlist_subkey -- --ignored

use deposits_test::regtest::*;

#[test]
#[ignore]
fn allowlist_subkey_resolves_to_allowlisted_account() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh");
        return;
    }

    let ledger = discover_op0_ledger();

    // Account + subkey keypairs.
    let (acct_sec, acct_xonly) = keygen();
    let (sub_sec, sub_xonly) = keygen();

    // Scratch dirs and nsec files.
    let scratch = tempdir();
    let nsec_acct = scratch.join("acct.nsec");
    let nsec_sub = scratch.join("sub.nsec");
    std::fs::write(&nsec_acct, &acct_sec).unwrap();
    std::fs::write(&nsec_sub, &sub_sec).unwrap();

    // Turn ACL on, allowlist = [account]. Subkey is deliberately absent.
    let _guard = Op0AccessControl::enable(&[&acct_xonly]);

    // The account's wallet state lives in its own dir so the 10301 event
    // and the later `revoke` call share the same context (their client
    // side tracks the subkey list).
    let acct_wdir = tempdir();

    // Publish the Kind 10301 attestation.
    let att_sig = wallet_attest(&sub_xonly, &nsec_acct, &acct_wdir).expect("attest should succeed");

    // --- Case 4a: subkey signs with v/va tags → accepted via DEP-04 resolution ---
    let sub_wdir = tempdir();
    let delegation_args: &[&str] = &["--subkey-of", &acct_xonly, "--attestation-sig", &att_sig];
    let (_ok, out) = wallet_open(&ledger, "sub-a", &nsec_sub, &sub_wdir, delegation_args);
    assert!(
        out.contains("Deposit account created") || out.contains("Deposit account already exists"),
        "subkey with v/va tags was not accepted:\n{}",
        out
    );

    // --- Case 4b: subkey signs bare (no v/va) → not_authorized ---
    let bare_wdir = tempdir();
    let (_ok, out) = wallet_open(&ledger, "sub-b", &nsec_sub, &bare_wdir, &[]);
    assert!(
        out.contains("not_authorized"),
        "bare subkey was not rejected with not_authorized:\n{}",
        out
    );

    // --- Case 4c: account revokes the subkey → attested open now rejected ---
    wallet_revoke(&sub_xonly, &nsec_acct, &acct_wdir);

    let revoked_wdir = tempdir();
    let (_ok, out) = wallet_open(&ledger, "sub-c", &nsec_sub, &revoked_wdir, delegation_args);
    assert!(
        out.contains("invalid_subkey_delegation") || out.contains("revoked"),
        "revoked subkey was not rejected by resolve_attested_sender:\n{}",
        out
    );

    // `_guard` drops here → allowlist restored, op0 relaunched without ACL.
}
