//! End-to-end drill: Lightning → ledger receive via the deposits-bridge
//! daemon (DEP-10 §Receive).
//!
//! Topology:
//!   cln-payer-test ──LN──▶ lnd-hold-test (the bridge's LN node)
//!                              │
//!                       deposits-bridge ──TransferLock──▶ wallet deposit
//!                              ▲                              │
//!                              └────── preimage reveal ◀──────┘
//!
//! The wallet picks the preimage; the bridge can only settle the upstream
//! HTLC after the wallet's on-ledger credit is claimed. This drill runs the
//! REAL wallet command (`deposits-wallet bridge-receive`) end-to-end:
//!
//!   1. wallet opens + asks bridge for a hold invoice against its hash
//!   2. test scrapes the BOLT-11 from the wallet's output, payer pays it
//!      (blocks while LND holds)
//!   3. bridge measures the hold window, locks X on the ledger
//!   4. wallet reveals r via transfer_complete → credited
//!   5. bridge scrapes r, settles upstream → payer completes with r
//!
//! Requires:
//!   deposits-tools/bin/setup.sh           (cluster)
//!   ./bin/setup-cln-hold.sh && ./bin/setup-lnd-hold.sh   (LN pair + channel)
//!   ./bin/setup-bridge.sh                 (bridge deposit + daemon)
//!
//!   BRIDGE_NPUB=$(cat /tmp/deposits-bridge-test/bridge.npub) \
//!   BRIDGE_LEDGER=$(cat deposits-tools/data/state/ledger_2_1) \
//!   CLN_PAYER_SOCKET_PATH=/tmp/cln-payer-test/regtest/lightning-rpc \
//!     cargo test -p deposits-test --test bridge_receive -- --ignored --nocapture

use deposits_test::regtest::*;
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn payer_pay(
    socket: &str,
    bolt11: &str,
) -> std::thread::JoinHandle<Result<serde_json::Value, String>> {
    let socket = socket.to_string();
    let bolt11 = bolt11.to_string();
    std::thread::spawn(move || {
        let mut stream =
            UnixStream::connect(&socket).map_err(|e| format!("connect payer: {}", e))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(180)))
            .map_err(|e| e.to_string())?;
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "pay",
            "params": { "bolt11": bolt11 },
        });
        let mut bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        stream.write_all(&bytes).map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(&stream)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&line).map_err(|e| format!("parse pay: {}", e))
    })
}

#[test]
#[ignore]
fn bridge_receive_end_to_end() {
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

    // Receiving wallet: fresh identity, deposit on the bridge's ledger.
    let wdir = tempdir();
    let (sec, _) = keygen();
    let nsec = wdir.join("wallet.nsec");
    std::fs::write(&nsec, &sec).unwrap();

    let (ok, out) = wallet_open(&ledger, "recv", &nsec, &wdir, &[]);
    assert!(
        ok && (out.contains("Deposit account created") || out.contains("already exists")),
        "open recv failed:\n{}",
        out
    );
    eprintln!("[wallet]  deposit open on {}…", &ledger[..16]);
    std::thread::sleep(Duration::from_secs(4)); // DepositOpen propagation

    let receive_sats: u64 = 5_000;

    // Run the REAL wallet command; it prints the BOLT-11 then blocks waiting
    // for the bridge's lock, reveals, and reports completion.
    let mut child = Command::new(wallet_bin())
        .args(["bridge-receive", "recv", &receive_sats.to_string()])
        .args(["--bridge", &bridge_npub])
        .args(["--nsec-file", nsec.to_str().unwrap()])
        .args(["--data-dir", wdir.to_str().unwrap()])
        .args(["--relay", relay_ledgers()])
        .args(["--network", "regtest"])
        .args(["--timeout-secs", "120"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bridge-receive");

    // Scrape the BOLT-11 from the wallet's stdout as it streams.
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let collector = std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            eprintln!("[recv]    {}", line);
            if let Some(b) = line.strip_prefix("BOLT11: ") {
                let _ = tx.send(b.trim().to_string());
            }
            lines.push(line);
        }
        lines.join("\n")
    });

    let bolt11 = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("wallet did not print a BOLT-11 — bridge unreachable or refused");
    assert!(bolt11.starts_with("lnbcrt"), "not a regtest invoice: {}", bolt11);
    eprintln!("[invoice] {}…", &bolt11[..40]);

    // Payer pays — blocks while the bridge's LND holds the HTLC.
    let pay_handle = payer_pay(&payer_socket, &bolt11);

    // The wallet process drives the rest (waits for lock, reveals, exits 0).
    let start = Instant::now();
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(s) => break s,
            None if start.elapsed() > Duration::from_secs(150) => {
                let _ = child.kill();
                panic!("bridge-receive did not finish within 150s");
            }
            None => std::thread::sleep(Duration::from_millis(500)),
        }
    };
    let wallet_out = collector.join().unwrap();
    assert!(
        status.success(),
        "bridge-receive exited nonzero:\n{}",
        wallet_out
    );
    assert!(
        wallet_out.contains("Bridge receive complete"),
        "wallet did not report completion:\n{}",
        wallet_out
    );
    eprintln!("[wallet]  credited +{} sats", receive_sats);

    // The payer's pay must complete — and ONLY because the wallet revealed:
    // the preimage the payer received is the wallet's r, round-tripped
    // through the ledger and the bridge's upstream settle.
    let pay_result = pay_handle.join().expect("payer thread").expect("pay rpc");
    let status_str = pay_result
        .pointer("/result/status")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    assert_eq!(
        status_str, "complete",
        "payer's pay should complete after the bridge settles: {}",
        pay_result
    );
    eprintln!("[payer]   pay complete — preimage round-tripped LN→ledger→LN");
    eprintln!("[ok] bridge receive verified end-to-end");
}
