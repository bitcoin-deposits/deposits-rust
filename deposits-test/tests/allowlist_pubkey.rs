//! Access control gate: pubkey allowlist.
//!
//! Op0 runs with `DEPOSIT_ACCESS_CONTROL=true` and
//! `deposit_allowlist.txt` containing one xonly pubkey. Covers:
//!   1. allowlisted signer opens a deposit → accepted
//!   2. non-allowlisted signer → rejected (`not_authorized`)
//!   3. empty allowlist → previously-allowed signer also rejected
//!
//! Sibling tests for the other gates:
//!   - `allowlist_subkey.rs`       (pubkey allowlist + DEP-04 subkey attestation)
//!   - `domain_allowlist_nip05.rs` (domain allowlist + NIP-05 attestation)
//!
//! The test hijacks op0's lifecycle — kills it, relaunches with ACL on,
//! runs the cases, then restores the original op0 via a `Drop` guard.
//!
//! Requires `./bin/setup.sh`. Run with:
//!   cargo test -p deposits-test --test allowlist_pubkey -- --ignored

use deposits_test::regtest::*;

#[test]
#[ignore]
fn pubkey_allowlist_gates_deposit_open() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh");
        return;
    }

    let ledger = discover_op0_ledger();

    let (sec_a, xonly_a) = keygen();
    let (sec_b, _xonly_b) = keygen();
    let scratch = tempdir();
    let nsec_a = scratch.join("a.nsec");
    let nsec_b = scratch.join("b.nsec");
    std::fs::write(&nsec_a, &sec_a).unwrap();
    std::fs::write(&nsec_b, &sec_b).unwrap();

    let guard = Op0AccessControl::enable(&[&xonly_a]);

    // --- Case 1: allowlisted npub → accepted ---
    let (_ok, out) = wallet_open(&ledger, "ac-a", &nsec_a, &scratch, &[]);
    assert!(
        out.contains("Deposit account created") || out.contains("Deposit account already exists"),
        "allowlisted npub was not accepted:\n{}",
        out
    );

    // --- Case 2: outsider npub → not_authorized ---
    let wdir_b = tempdir();
    let (_ok, out) = wallet_open(&ledger, "ac-b", &nsec_b, &wdir_b, &[]);
    assert!(
        out.contains("not_authorized"),
        "outsider npub rejection did not include code=not_authorized:\n{}",
        out
    );

    // --- Case 3: empty allowlist → previously-allowed npub also rejected ---
    guard.set_allowlist(&[]);

    let wdir_c = tempdir();
    let (_ok, out) = wallet_open(&ledger, "ac-c", &nsec_a, &wdir_c, &[]);
    assert!(
        out.contains("not_authorized"),
        "after allowlist removal, KEY_A was still accepted:\n{}",
        out
    );

    // `guard` drops here, restoring op0 to its original (non-ACL) state.
}
