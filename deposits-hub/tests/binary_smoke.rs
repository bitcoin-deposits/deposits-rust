//! Binary-level smoke test: launches the real `deposits-hub` and
//! `deposits-signer` binaries against a local test relay and asserts
//! the full lifecycle works end-to-end:
//!
//!   1. Start an in-process relay.
//!   2. Initialize a hub data dir (via `deposits-hub pubkey`).
//!   3. Spawn `deposits-hub run --headless` against the relay.
//!   4. Spawn `deposits-signer` configured to register with that hub.
//!   5. Poll the hub's `hub.json` until a pending entry shows up.
//!   6. Run `deposits-hub approve --pubkey <hex>` and verify the entry
//!      moves from `pending` to `signers`.
//!   7. Verify the signer process is still alive (it got an accepted
//!      ack rather than Shutdown).
//!
//! Catches the integration risks the unit/wire smokes don't:
//!   * arg-parser drift between cmd_run and the hub task,
//!   * wrong derivation path on the signer side,
//!   * pre-baked launch flags failing to register,
//!   * approve subcommand not actually moving inventory.

use deposits_hub::state::HubState;
use deposits_hub_proto::test_relay;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::{Child, Command};

/// Locate a workspace binary under `target/<profile>/`. Tests run with
/// `cargo test`, which sets `CARGO_BIN_EXE_<name>` for the test's own
/// crate but not for sibling binaries — so we have to derive the path
/// from our own test executable.
fn workspace_bin(name: &str) -> PathBuf {
    // `CARGO_MANIFEST_DIR` is set by cargo for tests.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // workspace root is one level above `deposits-hub/`.
    let target = manifest
        .parent()
        .expect("workspace root")
        .join("target");
    // Prefer debug, fall back to release.
    for profile in ["debug", "release"] {
        let candidate = target.join(profile).join(name);
        if candidate.exists() {
            return candidate;
        }
    }
    panic!("could not find binary `{}` under {}", name, target.display());
}

async fn spawn_hub(
    hub_data_dir: &Path,
    relay_url: &str,
    log_dir: &Path,
    extra_args: &[&str],
) -> Child {
    let stdout = std::fs::File::create(log_dir.join("hub.stdout")).unwrap();
    let stderr = std::fs::File::create(log_dir.join("hub.stderr")).unwrap();
    let mut cmd = Command::new(workspace_bin("deposits-hub"));
    cmd.arg("run")
        .arg("--headless")
        .arg("--data-dir")
        .arg(hub_data_dir)
        .arg("--relay")
        .arg(relay_url);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.env("RUST_LOG", "info,deposits_hub=debug,deposits_hub_proto=debug")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn deposits-hub")
}

/// Stage a signer data dir with a known seed and transport keypair via
/// the real `deposits-signer init` command, then return the dir +
/// derived nostr pubkey hex (which is what the hub will see as the
/// peer's identity in the gift wrap's rumor).
fn init_signer_workspace(signer_dir: &Path, seed_hex: &str) {
    let seed_path = signer_dir.with_file_name("seed.tmp");
    std::fs::write(&seed_path, seed_hex).expect("write seed");
    let out = std::process::Command::new(workspace_bin("deposits-signer"))
        .arg("init")
        .arg("--data-dir")
        .arg(signer_dir)
        .arg("--seed-file")
        .arg(&seed_path)
        .output()
        .expect("run deposits-signer init");
    let _ = std::fs::remove_file(&seed_path);
    assert!(
        out.status.success(),
        "signer init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Derive the signer's hub-nostr pubkey from the seed using the same
/// path the signer uses at runtime (`m/85'/0'/0'/0/0`). Returns the
/// 32-byte x-only form — that's what nostr-sdk emits on the wire and
/// what the hub keys its `pending` map by.
fn derive_signer_nostr_pk(seed_bytes: &[u8; 32]) -> String {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::Secp256k1;
    use std::str::FromStr;
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(bitcoin::Network::Bitcoin, seed_bytes).unwrap();
    let path = DerivationPath::from_str("m/85'/0'/0'/0/0").unwrap();
    let child = xpriv.derive_priv(&secp, &path).unwrap();
    let (xonly, _parity) = child.private_key.x_only_public_key(&secp);
    hex::encode(xonly.serialize())
}

async fn spawn_signer(
    signer_dir: &Path,
    socket: &Path,
    hub_pk: &str,
    relay_url: &str,
    log_dir: &Path,
) -> Child {
    let stdout = std::fs::File::create(log_dir.join("signer.stdout")).unwrap();
    let stderr = std::fs::File::create(log_dir.join("signer.stderr")).unwrap();
    Command::new(workspace_bin("deposits-signer"))
        .arg("run")
        .arg("--data-dir")
        .arg(signer_dir)
        .arg("--socket")
        .arg(socket)
        .arg("--hub-pubkey")
        .arg(hub_pk)
        .arg("--hub-relay")
        .arg(relay_url)
        .arg("--hub-label")
        .arg("smoke-signer")
        .env("RUST_LOG", "info,deposits_signer=debug,deposits_hub_proto=debug")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn deposits-signer")
}

async fn poll_hub_state<F>(hub_data_dir: &Path, mut check: F) -> Option<HubState>
where
    F: FnMut(&HubState) -> bool,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Ok(s) = HubState::load_or_init(hub_data_dir) {
            if check(&s) {
                return Some(s);
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signer_registers_then_gets_approved() {
    let relay_url = test_relay::spawn().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Persist the workspace so logs survive a failure. tempfile renamed
    // `into_path` → `keep` in newer versions; both work, allow the
    // deprecation for portability across compile envs.
    #[allow(deprecated)]
    let workspace_path = tempfile::TempDir::with_prefix("hub-smoke-")
        .expect("tempdir")
        .into_path();
    let hub_dir = workspace_path.join("hub");
    let signer_dir = workspace_path.join("signer");
    let signer_socket = workspace_path.join("signer.sock");
    let log_dir = workspace_path.join("logs");
    std::fs::create_dir_all(&hub_dir).unwrap();
    std::fs::create_dir_all(&log_dir).unwrap();
    eprintln!("smoke workspace: {}", workspace_path.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&hub_dir).unwrap().permissions();
        p.set_mode(0o700);
        std::fs::set_permissions(&hub_dir, p).unwrap();
    }

    // Init the hub (creates the keypair on disk) and snapshot the pk.
    let hub_state = HubState::load_or_init(&hub_dir).expect("hub init");
    let hub_pk = hub_state.hub_pubkey_hex().to_string();

    // Stage the signer with a known seed so we can predict its hub
    // nostr pubkey.
    let seed_bytes = [0x42u8; 32];
    let seed_hex = hex::encode(seed_bytes);
    init_signer_workspace(&signer_dir, &seed_hex);
    let signer_nostr_pk = derive_signer_nostr_pk(&seed_bytes);

    // Spawn hub + signer.
    let mut hub_proc = spawn_hub(&hub_dir, &relay_url, &log_dir, &[]).await;
    tokio::time::sleep(Duration::from_millis(500)).await; // give hub time to subscribe
    let mut signer_proc =
        spawn_signer(&signer_dir, &signer_socket, &hub_pk, &relay_url, &log_dir).await;

    // Wait for the pending entry to land.
    let pending_state = poll_hub_state(&hub_dir, |s| {
        s.pending.contains_key(&signer_nostr_pk)
    })
    .await
    .expect("signer never showed up in hub.pending within 15s");
    let pending_entry = pending_state.pending.get(&signer_nostr_pk).unwrap();
    assert_eq!(pending_entry.role, deposits_hub::proto::Role::Signer);
    assert!(
        pending_entry.identity_pubkey.len() == 66,
        "expected 33-byte hex transport pk, got len {}",
        pending_entry.identity_pubkey.len()
    );

    // Approve via the CLI mirror of the TUI's `a` key.
    let approve = Command::new(workspace_bin("deposits-hub"))
        .arg("approve")
        .arg("--data-dir")
        .arg(&hub_dir)
        .arg("--pubkey")
        .arg(&signer_nostr_pk)
        .arg("--relay")
        .arg(&relay_url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run deposits-hub approve");
    assert!(
        approve.status.success(),
        "approve failed: {}",
        String::from_utf8_lossy(&approve.stderr)
    );

    // Verify the entry moved out of pending into signers.
    let approved_state = poll_hub_state(&hub_dir, |s| {
        s.signers.contains_key(&signer_nostr_pk) && !s.pending.contains_key(&signer_nostr_pk)
    })
    .await
    .expect("approve never updated hub.json within 15s");
    let rec = approved_state.signers.get(&signer_nostr_pk).unwrap();
    assert_eq!(rec.label, "smoke-signer");
    assert!(!rec.last_version.is_empty());

    // Signer should still be alive (an accepted ack means Heartbeat
    // not Shutdown). Give it a beat to process the ack, then probe.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let signer_alive = signer_proc.try_wait().expect("try_wait signer").is_none();
    assert!(signer_alive, "signer process exited after approve");

    // Teardown.
    let _ = signer_proc.kill().await;
    let _ = hub_proc.kill().await;
}

/// Mirrors what `setup.sh::start_hub_signer` does: ask the hub for
/// a `spawn-line`, exec the result in a shell, watch the hub
/// auto-approve. Catches drift between the launch-line format and
/// what bash callers expect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spawn_line_then_bash_exec_then_auto_approve() {
    let relay_url = test_relay::spawn().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    #[allow(deprecated)]
    let workspace_path = tempfile::TempDir::with_prefix("hub-spawnline-")
        .expect("tempdir")
        .into_path();
    let hub_dir = workspace_path.join("hub");
    let log_dir = workspace_path.join("logs");
    std::fs::create_dir_all(&hub_dir).unwrap();
    std::fs::create_dir_all(&log_dir).unwrap();
    eprintln!("spawn-line workspace: {}", workspace_path.display());

    // Boot hub with auto-approve so we don't need a separate approve call.
    let mut hub_proc =
        spawn_hub(&hub_dir, &relay_url, &log_dir, &["--auto-approve"]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Ask the hub for a launch line, the same way setup.sh does.
    let seed_hex = hex::encode([0x33u8; 32]);
    let out = Command::new(workspace_bin("deposits-hub"))
        .arg("spawn-line")
        .arg("--data-dir")
        .arg(&hub_dir)
        .arg("--name")
        .arg("op0")
        .arg("--seed")
        .arg(&seed_hex)
        .arg("--relay")
        .arg(&relay_url)
        .output()
        .await
        .expect("run spawn-line");
    assert!(
        out.status.success(),
        "spawn-line failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let launch_line = stdout
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .last()
        .expect("spawn-line stdout has no launch line")
        .to_string();
    assert!(launch_line.contains("deposits-signer"));
    assert!(launch_line.contains("--hub-pubkey"));

    // Exec it via `bash -c` — same shell invocation path as setup.sh.
    let signer_stderr =
        std::fs::File::create(log_dir.join("signer.stderr")).unwrap();
    let signer_stdout =
        std::fs::File::create(log_dir.join("signer.stdout")).unwrap();
    let mut signer_proc = Command::new("bash")
        .arg("-c")
        .arg(format!("exec {}", launch_line))
        .env("RUST_LOG", "info,deposits_signer=debug,deposits_hub_proto=debug")
        .stdin(Stdio::null())
        .stdout(Stdio::from(signer_stdout))
        .stderr(Stdio::from(signer_stderr))
        .kill_on_drop(true)
        .spawn()
        .expect("bash -c launch line");

    // Wait for auto-approve to land.
    let approved = poll_hub_state(&hub_dir, |s| {
        s.signers.values().any(|r| r.label == "op0")
    })
    .await
    .expect("op0 never auto-approved within 15s");
    assert!(approved.pending.is_empty(), "pending should be empty");
    assert!(
        approved.signers.values().any(|r| r.label == "op0"),
        "no signer with label op0 in inventory"
    );

    let _ = signer_proc.kill().await;
    let _ = hub_proc.kill().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_approve_skips_pending_state() {
    let relay_url = test_relay::spawn().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    #[allow(deprecated)]
    let workspace_path = tempfile::TempDir::with_prefix("hub-auto-")
        .expect("tempdir")
        .into_path();
    let hub_dir = workspace_path.join("hub");
    let signer_dir = workspace_path.join("signer");
    let signer_socket = workspace_path.join("signer.sock");
    let log_dir = workspace_path.join("logs");
    std::fs::create_dir_all(&hub_dir).unwrap();
    std::fs::create_dir_all(&log_dir).unwrap();
    eprintln!("auto-approve workspace: {}", workspace_path.display());

    let hub_pk = HubState::load_or_init(&hub_dir)
        .expect("hub init")
        .hub_pubkey_hex()
        .to_string();

    let seed_bytes = [0x77u8; 32];
    let seed_hex = hex::encode(seed_bytes);
    init_signer_workspace(&signer_dir, &seed_hex);
    let signer_nostr_pk = derive_signer_nostr_pk(&seed_bytes);

    // Hub with --auto-approve.
    let mut hub_proc =
        spawn_hub(&hub_dir, &relay_url, &log_dir, &["--auto-approve"]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut signer_proc =
        spawn_signer(&signer_dir, &signer_socket, &hub_pk, &relay_url, &log_dir).await;

    // Skip straight to signers — no operator step needed.
    let approved = poll_hub_state(&hub_dir, |s| s.signers.contains_key(&signer_nostr_pk))
        .await
        .expect("signer never auto-approved within 15s");
    assert!(approved.pending.is_empty(), "pending should be empty when auto-approve is on");
    assert_eq!(approved.signers.get(&signer_nostr_pk).unwrap().label, "smoke-signer");

    let _ = signer_proc.kill().await;
    let _ = hub_proc.kill().await;
}
