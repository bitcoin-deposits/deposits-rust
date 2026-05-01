//! LNURL-pay integration test ("zap" flow).
//!
//! Spawns `deposits-lnurl` against the running cluster, opens a fresh
//! deposit account, then:
//!   1. GET /.well-known/lnurlp/<pubkey>  — verifies the payRequest JSON.
//!   2. GET /lnurl/callback/<pubkey>?amount=N — verifies a BOLT11 regtest
//!      invoice comes back.
//!
//! The metadata step (1) is independent of Lightning and always runs.
//! The callback step (2) hits `make_invoice` on op0 which delegates to
//! LDK, so it's skipped if the `lightning` container isn't up. Start it
//! with:
//!     docker compose --profile lightning up -d lightning
//!
//! Run with:
//!   cargo test -p deposits-test --test lnurl_zap -- --ignored

use deposits_test::regtest::*;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Claim a free localhost port by binding and immediately dropping.
/// There's a small race here (another process could grab it before the
/// lnurl server does), but fine for single-developer integration runs.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    listener.local_addr().unwrap().port()
}

fn lnurl_bin() -> PathBuf {
    repo_root().join("target/release/deposits-lnurl")
}

/// Owns a spawned deposits-lnurl process. Drop kills it.
struct LnurlServer {
    child: Child,
    port: u16,
    domain: String,
}

impl LnurlServer {
    /// Spawn the gateway. The caller routes to specific ledgers by
    /// setting the `Host` header on each request to
    /// `<ledger_id_hex>.<domain>`, which the server parses via
    /// `extract_ledger_from_host` — no `LNURL_DEFAULT_LEDGER` fallback,
    /// exercising the same path production clients use.
    fn spawn(port: u16, domain: &str) -> Self {
        // Both relays — make_invoice flows on messaging (20101/20102),
        // Kind 39100 advertisements (used for short-subdomain prefix
        // resolution + operator pubkey discovery) live on the durable
        // ledgers relay.
        let relays = format!("{},{}", relay_messaging(), relay_ledgers());
        let child = Command::new(lnurl_bin())
            .env("LNURL_NSEC", "4c4e55524c746573740000000000000000000000000000000000000000000001")
            .env("LNURL_RELAYS", relays)
            .env("LNURL_DOMAIN", domain)
            .env("LNURL_LISTEN", format!("127.0.0.1:{}", port))
            .env("RUST_LOG", "warn")
            .spawn()
            .expect("spawn deposits-lnurl");

        // Wrap the child in Self immediately so that any panic below
        // runs our Drop and kills the process — Child's own Drop does
        // not kill, it just leaks.
        let mut server = Self {
            child,
            port,
            domain: domain.to_string(),
        };

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                // Give the Nostr client a moment to connect to the
                // relay before we issue requests that depend on it.
                std::thread::sleep(Duration::from_millis(1500));
                return server;
            }
            // If the subprocess died during startup, surface that now
            // rather than spinning the full 10s.
            if let Ok(Some(status)) = server.child.try_wait() {
                panic!(
                    "deposits-lnurl exited during startup (status {}) — \
                     check env vars (nsec / relay / ledger)",
                    status
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("deposits-lnurl didn't become reachable on :{} within 10s", port);
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for LnurlServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Open a fresh deposit account on `ledger` and return (wallet_dir,
/// deposit_pubkey_hex). Uses a brand-new seed each time so the test is
/// idempotent against repeated runs.
fn open_fresh_deposit(ledger: &str) -> (PathBuf, String) {
    let wdir = tempdir();
    let (sec, _xonly) = keygen();
    let nsec = wdir.join("signer.nsec");
    std::fs::write(&nsec, &sec).unwrap();

    let (ok, out) = wallet_open(ledger, "lnurl-zap", &nsec, &wdir, &[]);
    assert!(
        ok && (out.contains("Deposit account created") || out.contains("Deposit account already exists")),
        "wallet open failed:\n{}",
        out
    );

    let deposits_json = std::fs::read_to_string(wdir.join("deposits.json")).unwrap();
    let deposits: serde_json::Value = serde_json::from_str(&deposits_json).unwrap();
    let pubkey = deposits[0]["deposit_pubkey"].as_str().unwrap().to_string();
    (wdir, pubkey)
}

#[test]
#[ignore]
fn lnurl_pay_flow_metadata_and_invoice() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh");
        return;
    }
    if !lnurl_bin().is_file() {
        eprintln!(
            "skipping: deposits-lnurl binary missing — run `cargo build --release -p deposits-lnurl`"
        );
        return;
    }

    let ledger = discover_op0_ledger();
    let (_wdir, deposit_pubkey) = open_fresh_deposit(&ledger);

    let port = free_port();
    let domain = format!("lnurl-test.local:{}", port);
    let lnurl = LnurlServer::spawn(port, &domain);

    // Route requests to this ledger via the Host header —
    // `<ledger_hex>.<base_domain>`. `extract_ledger_from_host` accepts
    // a raw 64-char hex subdomain directly, no bech32 needed here.
    let ledger_host = format!("{}.{}", ledger, lnurl.domain);

    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();

    // --- Step 1: LNURL-pay metadata (LUD-06/LUD-16) ---
    let metadata_url = format!("{}/.well-known/lnurlp/{}", lnurl.base_url(), deposit_pubkey);
    let resp = http
        .get(&metadata_url)
        .header("Host", &ledger_host)
        .send()
        .expect("metadata GET failed");
    assert!(
        resp.status().is_success(),
        "metadata request returned {}",
        resp.status()
    );
    let meta: serde_json::Value = resp.json().expect("metadata response not JSON");
    assert_eq!(meta["tag"], "payRequest", "wrong tag in metadata: {:?}", meta);
    assert!(
        meta["callback"].as_str().unwrap().contains(&deposit_pubkey),
        "callback URL doesn't reference the deposit pubkey: {:?}",
        meta
    );
    let min = meta["minSendable"].as_u64().unwrap();
    let max = meta["maxSendable"].as_u64().unwrap();
    assert!(min > 0 && max >= min, "bad min/max: {}/{}", min, max);

    // --- Step 2: LNURL callback → BOLT11 invoice ---
    //
    // This hits make_invoice on op0, which requires LDK. Skip cleanly
    // if the `lightning` container isn't up.
    if !lightning_available() {
        eprintln!(
            "skipping invoice step: `lightning` container not running — \
             bring it up with `docker compose --profile lightning up -d lightning`"
        );
        return;
    }

    let amount_msats: u64 = 1_000_000; // 1000 sats
    let callback_url = format!(
        "{}/lnurl/callback/{}?amount={}",
        lnurl.base_url(),
        deposit_pubkey,
        amount_msats
    );
    let resp = http
        .get(&callback_url)
        .header("Host", &ledger_host)
        .send()
        .expect("callback GET failed");
    assert!(
        resp.status().is_success(),
        "callback returned {} — make_invoice likely failed on op0",
        resp.status()
    );
    let callback_body: serde_json::Value = resp.json().expect("callback response not JSON");
    let invoice = callback_body["pr"]
        .as_str()
        .expect("no `pr` field in callback response");
    assert!(
        invoice.starts_with("lnbcrt"),
        "expected a regtest BOLT11 (`lnbcrt…`), got: {}",
        &invoice[..invoice.len().min(20)]
    );
    assert!(invoice.len() > 100, "invoice looks truncated: {}", invoice);
}

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Encode bytes as bech32 data characters (no HRP, no checksum). Mirrors
/// the encoder in `deposits-lnurl/src/bin/deposits-lnurl.rs`. 32 bytes
/// produces 52 chars; truncating to N chars produces a prefix that the
/// gateway resolves back to the full ledger ID via Kind 39100 ad lookup.
fn bech32_data_encode(bytes: &[u8]) -> String {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BECH32_CHARSET[((acc >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        out.push(BECH32_CHARSET[((acc << (5 - bits)) & 0x1f) as usize]);
    }
    String::from_utf8(out).unwrap()
}

/// Short-subdomain path: hit the gateway with a 12-char bech32 prefix
/// instead of the full 52-char canonical subdomain. The gateway must
/// scan Kind 39100 ads, find the unique ledger whose ID starts with our
/// decoded hex prefix, and proceed normally. This is the path operator
/// deployments take when their TLS / DNS setup wants short labels.
#[test]
#[ignore]
fn lnurl_short_subdomain_resolves_via_ad() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh");
        return;
    }
    if !lnurl_bin().is_file() {
        eprintln!(
            "skipping: deposits-lnurl binary missing — run `cargo build --release -p deposits-lnurl`"
        );
        return;
    }
    if !lightning_available() {
        eprintln!("skipping: `lightning` container not running");
        return;
    }

    let ledger = discover_op0_ledger();
    let (_wdir, deposit_pubkey) = open_fresh_deposit(&ledger);

    let port = free_port();
    // Realistic-shape base domain so the short subdomain is the *only*
    // hint the gateway has about which ledger this is.
    let domain = format!("ledger.test.local:{}", port);
    let lnurl = LnurlServer::spawn(port, &domain);

    // Build the short subdomain: 12 bech32 chars covering 60 bits =
    // first 7.5 bytes (15 hex) of the ledger ID. With ~30 ledgers in
    // the standard cluster the ambiguity probability is negligible.
    let ledger_bytes = hex::decode(&ledger).expect("ledger hex");
    let full_subdomain = bech32_data_encode(&ledger_bytes);
    assert_eq!(full_subdomain.len(), 52);
    let short_subdomain = &full_subdomain[..12];
    let short_host = format!("{}.{}", short_subdomain, lnurl.domain);
    eprintln!(
        "[setup]  ledger={}…  short_subdomain={}",
        &ledger[..16],
        short_subdomain
    );

    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();

    // ── Metadata via short subdomain ──
    let resp = http
        .get(format!("{}/.well-known/lnurlp/{}", lnurl.base_url(), deposit_pubkey))
        .header("Host", &short_host)
        .send()
        .expect("metadata GET");
    assert!(
        resp.status().is_success(),
        "metadata via short subdomain returned {}",
        resp.status()
    );
    let meta: serde_json::Value = resp.json().expect("metadata not JSON");
    let callback = meta["callback"].as_str().expect("callback field");
    // Metadata should echo the short host back so the wallet hits a
    // subdomain length that the operator's wildcard cert / DNS supports.
    assert!(
        callback.contains(short_subdomain),
        "callback URL should preserve the short subdomain we came in on: {}",
        callback
    );

    // ── Callback (make_invoice) via short subdomain ──
    let amount_msats: u64 = 1_000_000;
    let resp = http
        .get(format!(
            "{}/lnurl/callback/{}?amount={}",
            lnurl.base_url(),
            deposit_pubkey,
            amount_msats
        ))
        .header("Host", &short_host)
        .send()
        .expect("callback GET");
    assert!(
        resp.status().is_success(),
        "callback via short subdomain returned {} — \
         body: {}",
        resp.status(),
        resp.text().unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().expect("callback not JSON");
    let invoice = body["pr"].as_str().expect("missing `pr`");
    assert!(
        invoice.starts_with("lnbcrt"),
        "expected lnbcrt invoice, got: {}",
        &invoice[..invoice.len().min(20)]
    );
}
