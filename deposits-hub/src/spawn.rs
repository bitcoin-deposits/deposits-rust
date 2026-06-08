//! Signer subprocess supervisor.
//!
//! `Spawner` is the hub-side mirror of `deposits-signer run`. Given a
//! short name, it:
//!
//!   1. carves a workspace under `<hub-data-dir>/spawned/<name>/`,
//!   2. generates a fresh 32-byte seed,
//!   3. shells out to `deposits-signer init --data-dir …
//!      --seed-file <tmp>` (and deletes the tmp seed once installed),
//!   4. records the workspace + signer transport pubkey in `hub.json`
//!      so the operator's TUI can show it and the next spawn re-uses
//!      it instead of re-initializing,
//!   5. launches `deposits-signer run` with `--hub-pubkey`/`--hub-relay`
//!      already wired so the child registers itself on startup,
//!   6. tails stdout/stderr into the workspace log files.
//!
//! On child exit the supervisor logs the exit code; auto-restart is
//! intentionally out of scope here — the operator re-launches via the
//! TUI. (Auto-restart would mask "operator hit `x`" / "seed was
//! corrupted" / "binary upgrade broke" all the same, which is the
//! opposite of what a control plane wants.)

use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

/// Locate the `deposits-signer` binary. Strategy:
///   1. `DEPOSITS_SIGNER_BIN` env var if set (overrides everything),
///   2. a sibling of the current exe (so `target/debug/deposits-hub`
///      picks up `target/debug/deposits-signer` automatically),
///   3. plain `deposits-signer` resolved from `PATH`.
pub fn signer_bin() -> PathBuf {
    if let Ok(p) = std::env::var("DEPOSITS_SIGNER_BIN") {
        return PathBuf::from(p);
    }
    if let Ok(self_exe) = std::env::current_exe() {
        if let Some(dir) = self_exe.parent() {
            let sibling = dir.join("deposits-signer");
            if sibling.exists() {
                return sibling;
            }
        }
    }
    PathBuf::from("deposits-signer")
}

/// Per-spawned-signer workspace under `<hub-data-dir>/spawned/<name>/`.
pub struct Workspace {
    pub root: PathBuf,
    pub data_dir: PathBuf,
    pub socket: PathBuf,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
}

impl Workspace {
    pub fn for_name(hub_data_dir: &Path, name: &str) -> Self {
        let root = hub_data_dir.join("spawned").join(name);
        Self {
            data_dir: root.join("data-dir"),
            socket: root.join("signer.sock"),
            stdout_log: root.join("stdout.log"),
            stderr_log: root.join("stderr.log"),
            root,
        }
    }
}

/// Drives the init + run lifecycle for one spawned signer.
pub struct Spawner {
    hub_pubkey: String,
    relays: Vec<String>,
    bin: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("signer init exit {0}: {1}")]
    InitFailed(i32, String),
    #[error("spawn: {0}")]
    Spawn(String),
}

/// Handle on a running spawned signer. Drop the handle to leave the
/// process running; call `kill().await` to send SIGTERM first.
pub struct SpawnHandle {
    pub name: String,
    pub workspace: Workspace,
    pub transport_pubkey_hex: String,
    child: Mutex<Option<Child>>,
}

impl SpawnHandle {
    pub async fn kill(&self) -> std::io::Result<()> {
        let mut slot = self.child.lock().await;
        if let Some(mut c) = slot.take() {
            // SIGKILL — the signer doesn't carry uncommitted state
            // (the policy file is written before each ack), so a hard
            // kill is fine and faster than wait-on-SIGTERM.
            c.start_kill()?;
            let _ = c.wait().await;
        }
        Ok(())
    }
}

impl Spawner {
    pub fn new(hub_pubkey: String, relays: Vec<String>) -> Self {
        Self {
            hub_pubkey,
            relays,
            bin: signer_bin(),
        }
    }

    /// Override the binary path. Useful for tests pointing at a fixture
    /// binary, or to pin a specific build during operator-side rollouts.
    pub fn with_bin(mut self, bin: PathBuf) -> Self {
        self.bin = bin;
        self
    }

    /// Ensure the named workspace exists (generating a seed +
    /// initializing the signer's data-dir if not). Returns the
    /// workspace info without launching anything. Idempotent — a
    /// second call against an existing workspace is a no-op.
    pub async fn ensure_initialized(
        &self,
        hub_data_dir: &Path,
        name: &str,
    ) -> Result<Workspace, SpawnError> {
        self.ensure_initialized_with_seed(hub_data_dir, name, None).await
    }

    /// Like [`Self::ensure_initialized`], but accept a caller-provided
    /// seed instead of generating one. Used by regtest / CI harnesses
    /// where the operator seed is fixed and the signer's keys need to
    /// match the rest of the cluster. **Trusts the caller's seed
    /// blindly** — no entropy check; this is purely for harnesses.
    pub async fn ensure_initialized_with_seed(
        &self,
        hub_data_dir: &Path,
        name: &str,
        seed: Option<[u8; 32]>,
    ) -> Result<Workspace, SpawnError> {
        let ws = Workspace::for_name(hub_data_dir, name);
        if !ws.data_dir.exists() {
            self.init_workspace_with_seed(&ws, seed).await?;
        }
        Ok(ws)
    }

    /// Spawn (or re-spawn) a signer named `name` under the given hub
    /// data dir. If the workspace already exists, the signer is run
    /// against the existing seed — letting the operator re-launch
    /// without losing identity. If it doesn't exist, a fresh seed is
    /// generated, the signer is `init`-ed, and the seed tmpfile is
    /// removed before `run` starts.
    pub async fn spawn(
        &self,
        hub_data_dir: &Path,
        name: &str,
    ) -> Result<SpawnHandle, SpawnError> {
        let ws = self.ensure_initialized(hub_data_dir, name).await?;
        let transport_pubkey_hex = read_transport_pubkey(&ws.data_dir)?;

        let stdout_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ws.stdout_log)?;
        let stderr_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ws.stderr_log)?;

        let mut cmd = Command::new(&self.bin);
        cmd.arg("run")
            .arg("--data-dir")
            .arg(&ws.data_dir)
            .arg("--socket")
            .arg(&ws.socket)
            .arg("--hub-pubkey")
            .arg(&self.hub_pubkey)
            .arg("--hub-label")
            .arg(name);
        for r in &self.relays {
            cmd.arg("--hub-relay").arg(r);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .kill_on_drop(true);

        let child = cmd
            .spawn()
            .map_err(|e| SpawnError::Spawn(format!("exec {}: {}", self.bin.display(), e)))?;

        Ok(SpawnHandle {
            name: name.to_string(),
            workspace: ws,
            transport_pubkey_hex,
            child: Mutex::new(Some(child)),
        })
    }

    /// First-time init: create dirs, generate or accept seed, run
    /// `deposits-signer init --seed-file <tmp>`, scrub the tmp seed.
    async fn init_workspace_with_seed(
        &self,
        ws: &Workspace,
        seed: Option<[u8; 32]>,
    ) -> Result<(), SpawnError> {
        std::fs::create_dir_all(&ws.root)?;
        let seed_tmp = ws.root.join(".seed.tmp");
        match seed {
            Some(bytes) => write_seed(&seed_tmp, &bytes)?,
            None => write_random_seed(&seed_tmp)?,
        }

        // Init.
        let mut cmd = Command::new(&self.bin);
        cmd.arg("init")
            .arg("--data-dir")
            .arg(&ws.data_dir)
            .arg("--seed-file")
            .arg(&seed_tmp)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = cmd.output().await?;
        // Scrub the seed tmp file unconditionally — even on failure,
        // we don't want a stray seed lying on disk.
        let _ = std::fs::remove_file(&seed_tmp);

        if !out.status.success() {
            let code = out.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            return Err(SpawnError::InitFailed(code, stderr));
        }
        Ok(())
    }

    /// Format the equivalent shell command an operator could run by
    /// hand. Useful for the TUI's "launch line" feature (T114-adjacent)
    /// — operator copies the line, pastes onto another host, gets a
    /// signer that registers itself on first boot.
    pub fn launch_line(&self, hub_data_dir: &Path, name: &str) -> String {
        let ws = Workspace::for_name(hub_data_dir, name);
        let mut parts = vec![
            format!("{}", self.bin.display()),
            "run".to_string(),
            "--data-dir".to_string(),
            format!("{}", ws.data_dir.display()),
            "--socket".to_string(),
            format!("{}", ws.socket.display()),
            "--hub-pubkey".to_string(),
            self.hub_pubkey.clone(),
            "--hub-label".to_string(),
            name.to_string(),
        ];
        for r in &self.relays {
            parts.push("--hub-relay".to_string());
            parts.push(r.clone());
        }
        parts.join(" ")
    }

    /// Docker variant of [`launch_line`]: emit a `docker run` invocation
    /// that mounts the workspace into the container and runs the same
    /// signer args inside.
    ///
    /// The workspace dir is mounted at `/workspace` in the container;
    /// `--data-dir` and `--socket` point to paths underneath. Network
    /// is `host` so the signer can reach a localhost relay without
    /// extra port-forwarding ceremony (production deployments using
    /// public relays can drop `--network host` and rely on the
    /// container's default bridge network).
    ///
    /// The container image defaults to `deposits-signer:dev` —
    /// matches `deploy/systemd/` conventions for a locally-built
    /// image. Operators publishing under a different name can pass
    /// the image as `image_override`.
    pub fn launch_line_docker(
        &self,
        hub_data_dir: &Path,
        name: &str,
        image_override: Option<&str>,
    ) -> String {
        let ws = Workspace::for_name(hub_data_dir, name);
        let image = image_override.unwrap_or("deposits-signer:dev");
        let ws_host = ws
            .data_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| ws.data_dir.clone());
        // Compute container-relative paths for --data-dir and --socket
        // by replacing the workspace prefix with /workspace.
        let rel = |p: &Path| -> String {
            match p.strip_prefix(&ws_host) {
                Ok(suffix) => format!("/workspace/{}", suffix.display()),
                Err(_) => format!("{}", p.display()),
            }
        };
        let mut parts = vec![
            "docker".to_string(),
            "run".to_string(),
            "--rm".to_string(),
            "-it".to_string(),
            "--network".to_string(),
            "host".to_string(),
            "--name".to_string(),
            format!("deposits-signer-{}", name),
            "-v".to_string(),
            format!("{}:/workspace", ws_host.display()),
            image.to_string(),
            // ── signer args inside the container ──
            "run".to_string(),
            "--data-dir".to_string(),
            rel(&ws.data_dir),
            "--socket".to_string(),
            rel(&ws.socket),
            "--hub-pubkey".to_string(),
            self.hub_pubkey.clone(),
            "--hub-label".to_string(),
            name.to_string(),
        ];
        for r in &self.relays {
            parts.push("--hub-relay".to_string());
            parts.push(r.clone());
        }
        parts.join(" ")
    }
}

fn write_random_seed(path: &Path) -> std::io::Result<()> {
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    write_seed(path, &seed)
}

fn write_seed(path: &Path, seed: &[u8; 32]) -> std::io::Result<()> {
    std::fs::write(path, hex::encode(seed))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn read_transport_pubkey(data_dir: &Path) -> std::io::Result<String> {
    let p = data_dir.join("transport_pubkey");
    Ok(std::fs::read_to_string(&p)?.trim().to_string())
}

/// Optional helper: stream a spawned child's stdout/stderr line-by-line
/// into tracing logs (in addition to the workspace's log files). Not
/// used by `spawn()` directly because we want the log files to be the
/// canonical place; provided for future use if the TUI wants live tail.
#[allow(dead_code)]
pub async fn tail_into_tracing(mut child: Child, name: String) -> std::io::Result<i32> {
    if let Some(stdout) = child.stdout.take() {
        let n = name.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                tracing::info!(name = %n, "signer/stdout: {}", l);
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let n = name.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                tracing::info!(name = %n, "signer/stderr: {}", l);
            }
        });
    }
    let status = child.wait().await?;
    Ok(status.code().unwrap_or(-1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn launch_line_format_is_pasteable() {
        let s = Spawner::new("abc123".to_string(), vec!["wss://r1".to_string()])
            .with_bin(PathBuf::from("/opt/deposits-signer"));
        let line = s.launch_line(Path::new("/var/lib/hub"), "op-alice");
        assert!(line.contains("--hub-pubkey abc123"));
        assert!(line.contains("--hub-relay wss://r1"));
        assert!(line.contains("--hub-label op-alice"));
        assert!(line.contains("/var/lib/hub/spawned/op-alice/data-dir"));
        assert!(line.starts_with("/opt/deposits-signer run"));
    }

    #[test]
    fn workspace_layout_under_named_dir() {
        let tmp = TempDir::new().unwrap();
        let ws = Workspace::for_name(tmp.path(), "vault-1");
        assert!(ws.root.ends_with("spawned/vault-1"));
        assert!(ws.data_dir.ends_with("spawned/vault-1/data-dir"));
        assert!(ws.socket.ends_with("spawned/vault-1/signer.sock"));
    }

    #[test]
    fn launch_line_docker_mounts_workspace_and_rewrites_paths() {
        let s = Spawner::new("abc123".to_string(), vec!["wss://r1".to_string()])
            .with_bin(PathBuf::from("/opt/deposits-signer"));
        let line = s.launch_line_docker(Path::new("/var/lib/hub"), "op-alice", None);
        // Frame
        assert!(line.starts_with("docker run --rm -it"));
        assert!(line.contains("--network host"));
        assert!(line.contains("--name deposits-signer-op-alice"));
        // Workspace mount + rewritten paths
        assert!(line.contains("-v /var/lib/hub/spawned/op-alice:/workspace"));
        assert!(line.contains("--data-dir /workspace/data-dir"));
        assert!(line.contains("--socket /workspace/signer.sock"));
        // Default image
        assert!(line.contains("deposits-signer:dev"));
        // Signer args passed through
        assert!(line.contains("--hub-pubkey abc123"));
        assert!(line.contains("--hub-relay wss://r1"));
        assert!(line.contains("--hub-label op-alice"));
    }

    #[test]
    fn launch_line_docker_honours_image_override() {
        let s = Spawner::new("abc123".to_string(), vec!["wss://r1".to_string()]);
        let line = s.launch_line_docker(
            Path::new("/var/lib/hub"),
            "op-alice",
            Some("ghcr.io/example/deposits-signer:v2"),
        );
        assert!(line.contains("ghcr.io/example/deposits-signer:v2"));
        assert!(!line.contains("deposits-signer:dev"));
    }
}
