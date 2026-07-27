//! End-to-end drill: ledger → Lightning pay via the deposits-bridge
//! daemon (DEP-10 §Pay).
//!
//! Topology (reverse of bridge_receive):
//!   wallet ──TransferLock──▶ deposits-bridge ──LN pay──▶ cln-payer-test
//!     ▲                            │
//!     └──── preimage (proof) ◀─────┘  (TransferComplete witness)
//!
//! The wallet locks invoice_amount + service_fee to the bridge gated on
//! the INVOICE's payment_hash. The bridge can only claim the lock by
//! revealing the preimage — which it only learns by actually paying the
//! invoice. This drill runs the REAL wallet command end-to-end:
//!
//!   1. cln-payer issues a BOLT-11 invoice
//!   2. wallet `bridge-pay`: quote → lock → wait for the bridge's claim
//!   3. bridge pays the invoice over LN (liquidity pushed to its LND by
//!      the receive drill), scrapes the preimage, claims the lock
//!   4. test asserts the wallet got the preimage AND cln-payer marks the
//!      invoice paid
//!
//! Requires the same stack as bridge_receive.rs, plus at least one prior
//! receive so the bridge's LND has local balance toward cln-payer:
//!
//!   BRIDGE_NPUB=$(cat /tmp/deposits-bridge-test/bridge.npub) \
//!   BRIDGE_LEDGER=$(cat deposits-tools/data/state/ledger_2_1) \
//!   CLN_PAYER_SOCKET_PATH=/tmp/cln-payer-test/regtest/lightning-rpc \
//!     cargo test -p deposits-test --test bridge_pay -- --ignored --nocapture

use deposits_test::regtest::*;
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::Duration;

fn payer_rpc(socket: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
    let mut stream = UnixStream::connect(socket).expect("connect payer rpc");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    });
    let mut bytes = serde_json::to_vec(&req).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).unwrap();
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).expect("parse payer rpc reply")
}

#[test]
#[ignore]
fn bridge_pay_end_to_end() {
    let bridge_npub = match std::env::var("BRIDGE_NPUB") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("skipping: BRIDGE_NPUB unset — run ./bin/setup-bridge.sh");
            return;
        }
    };
    let ledger = match std::env::var("BRIDGE_LEDGER") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("skipping: BRIDGE_LEDGER unset");
            return;
        }
    };
    let payer_socket = match std::env::var("CLN_PAYER_SOCKET_PATH") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("skipping: CLN_PAYER_SOCKET_PATH unset");
            return;
        }
    };

    // Paying wallet: fresh identity, funded deposit on the bridge's ledger.
    let wdir = tempdir();
    let (sec, _) = keygen();
    let nsec = wdir.join("wallet.nsec");
    std::fs::write(&nsec, &sec).unwrap();

    let (ok, out) = wallet_open(&ledger, "payer", &nsec, &wdir, &[]);
    assert!(
        ok && (out.contains("Deposit account created") || out.contains("already exists")),
        "open payer failed:\n{}",
        out
    );
    std::thread::sleep(Duration::from_secs(4)); // DepositOpen propagation

    // Fund it via the ledger's operator (op2 owns ledger_2_*).
    let deposits: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(wdir.join("deposits.json")).unwrap())
            .unwrap();
    let dep = deposits
        .iter()
        .find(|d| d["alias"] == "payer")
        .expect("payer deposit entry");
    let dep_pk = dep["deposit_pubkey"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| {
            dep["descriptor"].as_str().unwrap()[3..69].to_string() // pk(<66 hex>)
        });
    let fund_sats: u64 = 20_000;
    let credit_out = operator_credit_deposit(
        2,
        &ledger,
        &dep_pk,
        fund_sats * 1000,
        &format!("bridge-pay-drill-{}", &dep_pk[..8]),
    );
    assert!(
        credit_out.contains("New balance"),
        "operator credit failed:\n{}",
        credit_out
    );
    eprintln!("[wallet]  payer deposit funded with {} sats", fund_sats);

    // Invoice on cln-payer — the bridge's LND has local balance toward it
    // (pushed by the receive drill's settled HTLC).
    let pay_sats: u64 = 1_000;
    let label = format!("bridge-pay-{}", &dep_pk[..8]);
    let inv = payer_rpc(
        &payer_socket,
        "invoice",
        serde_json::json!({
            "amount_msat": pay_sats * 1000,
            "label": label,
            "description": "bridge pay drill",
        }),
    );
    let bolt11 = inv
        .pointer("/result/bolt11")
        .and_then(|s| s.as_str())
        .unwrap_or_else(|| panic!("no bolt11 in invoice reply: {}", inv))
        .to_string();
    eprintln!("[invoice] {}…", &bolt11[..40]);

    // Run the REAL wallet command: quote → lock → wait for the claim.
    let out = Command::new(wallet_bin())
        .args(["bridge-pay", "payer", &bolt11])
        .args(["--bridge", &bridge_npub])
        .args(["--nsec-file", nsec.to_str().unwrap()])
        .args(["--data-dir", wdir.to_str().unwrap()])
        .args(["--relay", relay_ledgers()])
        .args(["--network", "regtest"])
        .args(["--timeout-secs", "90"])
        .output()
        .expect("spawn bridge-pay");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("[bridge-pay output]\n{}", combined);
    assert!(out.status.success(), "bridge-pay exited nonzero");
    assert!(
        combined.contains("Bridge pay complete"),
        "wallet did not report completion"
    );
    let proof_hex = combined
        .lines()
        .find_map(|l| l.trim().strip_prefix("proof of payment (preimage): "))
        .expect("no proof-of-payment line")
        .trim()
        .to_string();

    // The invoice must be PAID on cln-payer, and its preimage must be the
    // exact proof the wallet extracted from the ledger claim.
    let listed = payer_rpc(
        &payer_socket,
        "listinvoices",
        serde_json::json!({ "label": label }),
    );
    let entry = &listed["result"]["invoices"][0];
    assert_eq!(
        entry["status"].as_str(),
        Some("paid"),
        "invoice not paid on cln-payer: {}",
        listed
    );
    assert_eq!(
        entry["payment_preimage"].as_str(),
        Some(proof_hex.as_str()),
        "ledger proof != LN preimage"
    );
    eprintln!("[payer]   invoice paid; preimage matches the on-ledger proof");
    eprintln!("[ok] bridge pay verified end-to-end");
}
