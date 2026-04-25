//! Helpers for docker-backed integration tests that drive a running
//! regtest cluster (`./bin/setup.sh`) via `deposits-node` / `deposits-wallet`
//! release binaries.
//!
//! Tests using these helpers should be `#[ignore]` so they don't run in
//! the default `cargo test` pass. They assume op0 is reachable and the
//! release binaries are built.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub const OP0_SEED: &str = "6f70300000000000000000000000000000000000000000000000000000000000";
pub const ELECTRS_URL: &str = "http://localhost:3102";

/// Default ledgers (durable) relay URL.
///
/// Tests read `RELAY_LEDGERS` from the environment with this fallback.
/// Centralized here so a port change touches one constant; the matching
/// shell-side default lives in `deposits-tools/bin/_common.sh`. Override
/// for ad-hoc runs: `RELAY_LEDGERS=ws://localhost:9999 cargo test ...`.
const DEFAULT_RELAY_LEDGERS: &str = "ws://localhost:17779";
const DEFAULT_RELAY_MESSAGING: &str = "ws://localhost:17780";

/// URL of the ledgers (durable) relay. Reads `RELAY_LEDGERS` env var
/// with [`DEFAULT_RELAY_LEDGERS`] as the fallback. Cached on first call
/// so subsequent calls return the same `&'static str` — interchangeable
/// with the previous `pub const RELAY_LEDGERS`.
pub fn relay_ledgers() -> &'static str {
    use std::sync::OnceLock;
    static URL: OnceLock<String> = OnceLock::new();
    URL.get_or_init(|| {
        std::env::var("RELAY_LEDGERS").unwrap_or_else(|_| DEFAULT_RELAY_LEDGERS.to_string())
    })
}

/// URL of the messaging (ephemeral) relay. See [`relay_ledgers`].
pub fn relay_messaging() -> &'static str {
    use std::sync::OnceLock;
    static URL: OnceLock<String> = OnceLock::new();
    URL.get_or_init(|| {
        std::env::var("RELAY_MESSAGING").unwrap_or_else(|_| DEFAULT_RELAY_MESSAGING.to_string())
    })
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

pub fn node_bin() -> PathBuf {
    repo_root().join("target/release/deposits-node")
}

pub fn wallet_bin() -> PathBuf {
    repo_root().join("target/release/deposits-wallet")
}

pub fn op0_data_dir() -> PathBuf {
    repo_root().join("deposits-tools/data/op0")
}

/// True iff bitcoind is reachable AND the release binaries are built.
pub fn cluster_available() -> bool {
    let bitcoind = Command::new("docker")
        .args([
            "exec",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            "-rpcuser=user",
            "-rpcpassword=pass",
            "getblockcount",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    bitcoind && node_bin().is_file() && wallet_bin().is_file()
}

/// True iff the `lightning` container (LDK) is running. Tests that
/// exercise the invoice/payment path need this; default `./bin/setup.sh`
/// doesn't bring it up — start it with
/// `docker compose --profile lightning up -d lightning`.
pub fn lightning_available() -> bool {
    container_running("lightning")
}

/// True iff the `lnaddr-attest` container is running. Tests that
/// exercise the attestation + domain-allowlist path need this.
pub fn lnaddr_attest_available() -> bool {
    container_running("lnaddr-attest")
}

fn container_running(name: &str) -> bool {
    Command::new("docker")
        .args([
            "ps",
            "--filter",
            &format!("name=^{}$", name),
            "--format",
            "{{.Names}}",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == name)
        .unwrap_or(false)
}

/// Derive the xonly pubkey (hex, 64 chars) from a 64-char hex secret.
pub fn derive_xonly_pubkey(secret_hex: &str) -> Result<String, String> {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    let bytes = hex::decode(secret_hex.trim()).map_err(|e| format!("hex decode: {}", e))?;
    let sk = SecretKey::from_slice(&bytes).map_err(|e| format!("bad secret: {}", e))?;
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    Ok(hex::encode(xonly.serialize()))
}

/// Read `deposits-tools/secrets/verify_nsec` and derive the attestation
/// verifier's xonly pubkey (hex).
pub fn verifier_pubkey_xonly() -> Result<String, String> {
    let path = repo_root().join("deposits-tools/secrets/verify_nsec");
    let sec = std::fs::read_to_string(&path)
        .map_err(|e| format!("read {}: {}", path.display(), e))?;
    derive_xonly_pubkey(&sec)
}

/// Register `<username>` → `<xonly_pubkey>` in the lnaddr-attest
/// container's nip05 fixture (the Python lnurl-server.py reads
/// `/data/nostr.json`). Replaces any prior value for the same username.
pub fn nip05_register(username: &str, xonly_pubkey: &str) -> Result<(), String> {
    // Read the current file, merge in the new name, write it back.
    // All operations happen inside the container where /data is
    // root-owned, side-stepping host sudo.
    let read = Command::new("docker")
        .args(["exec", "lnaddr-attest", "sh", "-c", "cat /data/nostr.json 2>/dev/null || echo '{\"names\":{}}'"])
        .output()
        .map_err(|e| format!("docker exec (read): {}", e))?;
    let current: serde_json::Value = serde_json::from_slice(&read.stdout)
        .unwrap_or_else(|_| serde_json::json!({"names": {}}));
    let mut names = current
        .get("names")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    names.insert(
        username.to_string(),
        serde_json::Value::String(xonly_pubkey.to_string()),
    );
    let merged = serde_json::json!({ "names": names }).to_string();

    let write = Command::new("docker")
        .args(["exec", "-i", "lnaddr-attest", "sh", "-c", "cat > /data/nostr.json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(merged.as_bytes()).ok();
            }
            child.wait_with_output()
        })
        .map_err(|e| format!("docker exec (write): {}", e))?;
    if !write.status.success() {
        return Err(format!(
            "nip05 register failed: {}",
            String::from_utf8_lossy(&write.stderr)
        ));
    }
    Ok(())
}

/// Generate a fresh keypair via `deposits-node keygen`.
/// Returns `(secret_hex, xonly_pubkey_hex)`.
pub fn keygen() -> (String, String) {
    let out = Command::new(node_bin())
        .arg("keygen")
        .output()
        .expect("keygen failed");
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let mut parts = s.split_whitespace();
    let sec = parts.next().expect("keygen: no secret").to_string();
    let compressed = parts.next().expect("keygen: no pubkey").to_string();
    // Strip the leading 02/03 compression byte.
    let xonly = compressed[2..].to_string();
    (sec, xonly)
}

/// Unique scratch directory under /tmp for a single test run.
pub fn tempdir() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "deposits-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Kill the current op0 daemon, matching by `name op0` in the cmdline.
/// Blocks until the process is gone (up to ~5s).
pub fn kill_op0() {
    let _ = Command::new("pkill").args(["-f", "name op0"]).output();
    for _ in 0..20 {
        let still = Command::new("pgrep")
            .args(["-f", "name op0"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !still {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Spawn op0 with the standard release-binary arguments plus any caller-
/// supplied extra env vars (e.g. `DEPOSIT_ACCESS_CONTROL=true`,
/// `ATTESTATION_VERIFIER_PUBKEY=<hex>`). Sleeps briefly so the daemon
/// is up and has loaded its on-disk lists before callers continue.
pub fn spawn_op0(extra_env: &[(&str, &str)]) {
    let log = op0_data_dir().join("daemon.log");
    let log_out = std::fs::File::options()
        .append(true)
        .create(true)
        .open(&log)
        .unwrap();
    let log_err = log_out.try_clone().unwrap();
    let mut cmd = Command::new(node_bin());
    cmd.arg("run")
        .args(["--seed", OP0_SEED])
        .args(["--name", "op0"])
        .args(["--network", "regtest"])
        .args(["--data-dir", op0_data_dir().to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .args(["--relay", relay_messaging()])
        .env("RUST_LOG", "warn")
        .stdout(log_out)
        .stderr(log_err);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let _child = cmd.spawn().expect("op0 spawn failed");
    std::thread::sleep(Duration::from_secs(6));
}

/// Discover op0's ledger id via `deposits-wallet discover --json`.
pub fn discover_op0_ledger() -> String {
    let scratch = tempdir();
    let out = Command::new(wallet_bin())
        .args(["discover", "--json"])
        .args(["--relay", relay_ledgers()])
        .args(["--network", "regtest"])
        .args(["--data-dir", scratch.to_str().unwrap()])
        .output()
        .expect("discover failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("type").and_then(|x| x.as_str()) == Some("ledger")
            && v.get("operator_name").and_then(|x| x.as_str()) == Some("op0")
        {
            return v
                .get("ledger_id")
                .and_then(|x| x.as_str())
                .unwrap()
                .to_string();
        }
    }
    panic!("couldn't find a ledger owned by op0");
}

/// Run `deposits-wallet open` with the given args. Returns combined
/// stdout+stderr and the success flag.
///
/// `extra_args` lets a caller pass subkey-delegation flags
/// (`--subkey-of`, `--attestation-sig`) without bloating the base
/// signature.
pub fn wallet_open(
    ledger: &str,
    alias: &str,
    nsec_path: &Path,
    data_dir: &Path,
    extra_args: &[&str],
) -> (bool, String) {
    let mut cmd = Command::new(wallet_bin());
    cmd.args(["open", ledger, "100000"])
        .args(["--alias", alias])
        .args(["--nsec-file", nsec_path.to_str().unwrap()])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--relay", relay_messaging()])
        .args(["--network", "regtest"]);
    for a in extra_args {
        cmd.arg(a);
    }
    let out = cmd.output().expect("wallet open invocation failed");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), combined)
}

/// Publish a DEP-04 Kind 10301 subkey attestation: `account_nsec`
/// attests that `subkey_xonly` is delegated to it. Returns the signature
/// hex that wallets bake into their `va` tag.
pub fn wallet_attest(
    subkey_xonly: &str,
    account_nsec: &Path,
    data_dir: &Path,
) -> Result<String, String> {
    let out = Command::new(wallet_bin())
        .args(["attest", subkey_xonly])
        .args(["--nsec-file", account_nsec.to_str().unwrap()])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--relay", relay_messaging()])
        .args(["--network", "regtest"])
        .output()
        .expect("wallet attest invocation failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The command prints "  attestation:  <hex>" on success.
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("attestation:") {
            return Ok(rest.trim().to_string());
        }
    }
    Err(format!(
        "attest produced no attestation signature\nstdout:\n{}\nstderr:\n{}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// Revoke a previously-attested subkey. Fire-and-forget — errors are
/// surfaced via the process exit code only.
pub fn wallet_revoke(subkey_xonly: &str, account_nsec: &Path, data_dir: &Path) {
    let _ = Command::new(wallet_bin())
        .args(["revoke", subkey_xonly])
        .args(["--nsec-file", account_nsec.to_str().unwrap()])
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["--relay", relay_messaging()])
        .args(["--network", "regtest"])
        .output();
}

/// RAII guard: snapshots op0's `deposit_allowlist.txt` on construction,
/// restores it and relaunches op0 with ACL off on drop. Runs even on
/// panic, so a failing test doesn't leave op0 half-configured.
pub struct Op0AccessControl {
    allowlist_backup: Option<Vec<u8>>,
    domain_allowlist_backup: Option<Vec<u8>>,
}

fn allowlist_path() -> PathBuf {
    op0_data_dir().join("deposit_allowlist.txt")
}

fn domain_allowlist_path() -> PathBuf {
    op0_data_dir().join("deposit_domain_allowlist.txt")
}

fn write_list(path: &Path, entries: &[&str]) {
    let body = entries
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path, body).unwrap();
}

impl Op0AccessControl {
    /// Capture the current allowlist, kill op0, write `allowlist` to
    /// disk, and relaunch op0 with `DEPOSIT_ACCESS_CONTROL=true`.
    /// Each line of `allowlist` is one xonly pubkey hex.
    pub fn enable(allowlist: &[&str]) -> Self {
        Self::enable_inner(allowlist, &[], None)
    }

    /// Like `enable`, but also writes a domain allowlist and sets
    /// `ATTESTATION_VERIFIER_PUBKEY` so op0 accepts deposit_open
    /// requests when the account's attestation references one of the
    /// allowed domains.
    pub fn enable_with_attestation(
        allowlist: &[&str],
        domain_allowlist: &[&str],
        verifier_xonly: &str,
    ) -> Self {
        Self::enable_inner(allowlist, domain_allowlist, Some(verifier_xonly))
    }

    fn enable_inner(
        allowlist: &[&str],
        domain_allowlist: &[&str],
        verifier_xonly: Option<&str>,
    ) -> Self {
        let allowlist_backup = std::fs::read(allowlist_path()).ok();
        let domain_allowlist_backup = std::fs::read(domain_allowlist_path()).ok();
        kill_op0();
        write_list(&allowlist_path(), allowlist);
        write_list(&domain_allowlist_path(), domain_allowlist);

        let mut env: Vec<(&str, &str)> = vec![("DEPOSIT_ACCESS_CONTROL", "true")];
        if let Some(vk) = verifier_xonly {
            env.push(("ATTESTATION_VERIFIER_PUBKEY", vk));
        }
        spawn_op0(&env);
        Self {
            allowlist_backup,
            domain_allowlist_backup,
        }
    }

    /// Rewrite the allowlist and restart op0 (still with ACL on).
    pub fn set_allowlist(&self, allowlist: &[&str]) {
        kill_op0();
        write_list(&allowlist_path(), allowlist);
        spawn_op0(&[("DEPOSIT_ACCESS_CONTROL", "true")]);
    }
}

impl Drop for Op0AccessControl {
    fn drop(&mut self) {
        kill_op0();
        restore_file(&allowlist_path(), self.allowlist_backup.as_deref());
        restore_file(&domain_allowlist_path(), self.domain_allowlist_backup.as_deref());
        spawn_op0(&[]);
    }
}

fn restore_file(path: &Path, backup: Option<&[u8]>) {
    match backup {
        Some(bytes) => {
            let _ = std::fs::write(path, bytes);
        }
        None => {
            let _ = std::fs::remove_file(path);
        }
    }
}
