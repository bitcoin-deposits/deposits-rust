//! Single-process exclusion on the hub data dir.
//!
//! Two `deposits-hub run` processes against the same data dir would
//! share `hub-nostr-secret` (same nostr identity → duplicate gift wraps
//! on the relay) and race on `hub.json` writes (last-saver wins, half
//! the mutations get lost). The user can't always tell that's
//! happening — symptoms look like flaky registrations.
//!
//! We take an OS-level advisory lock via `flock(LOCK_EX | LOCK_NB)` on
//! `<data-dir>/hub.lock`. The kernel releases it automatically when
//! the holding process exits (even on SIGKILL / panic), so a stale
//! lock file from a previous crash isn't a problem — the lock state
//! is on the fd, not the file. The file's *contents* record the
//! holder's pid for the error message only; they have no semantic
//! weight.
//!
//! Approve/reject CLI deliberately doesn't take this lock — the
//! intended workflow is a headless hub serving approvals via the CLI,
//! and locking out the CLI while the hub holds the run-lock would
//! make that impossible. Operators who run both an interactive TUI
//! and concurrent CLI approvals get to keep both pieces.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("open {0}: {1}")]
    Open(PathBuf, std::io::Error),
    #[error(
        "hub data dir is already locked by another deposits-hub process \
         (lockfile: {lockfile}; reported pid: {pid}). Stop that process \
         (e.g. `kill {pid}`), or use a different --data-dir."
    )]
    Held { lockfile: PathBuf, pid: String },
}

/// RAII handle on the data-dir lock. Drop releases the lock (kernel
/// closes the fd on process exit even on panic, so we don't have to
/// rely on Drop running cleanly).
#[derive(Debug)]
pub struct HubLock {
    // Kept open for the lifetime of the process. Underscore prefix
    // signals "field exists only for its Drop side-effect."
    _file: File,
}

impl HubLock {
    /// Try to acquire the lock; if the holder is alive, signal it and
    /// retry until it dies. Caller intent: "I'm replacing the running
    /// hub." Used by `deposits-hub run --steal`.
    ///
    /// Sequence:
    ///   1. plain `acquire`. If it succeeds, return.
    ///   2. parse the contending pid from the lockfile.
    ///   3. SIGTERM, then poll the lock for up to 3 seconds (fd cleanup
    ///      on process exit releases the flock).
    ///   4. SIGKILL if still held, poll for up to 1 more second.
    ///   5. give up with the original `Held` error.
    ///
    /// Best-effort by design: if the pid is unknown, owned by a
    /// different user, or holding the lock from a longer-than-4s
    /// graceful-shutdown path, the steal fails — operator can re-run
    /// or `kill -9` manually.
    pub fn acquire_or_steal(data_dir: &Path) -> Result<Self, LockError> {
        match Self::acquire(data_dir) {
            Ok(h) => Ok(h),
            Err(LockError::Held { pid, .. }) => {
                let pid_num: i32 = match pid.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        // Lockfile didn't have a parseable pid — re-try
                        // a final time (the holder may have just died)
                        // then return the original error.
                        return Self::acquire(data_dir);
                    }
                };
                tracing::warn!(pid = pid_num, "hub: --steal sending SIGTERM");
                #[cfg(unix)]
                unsafe {
                    libc::kill(pid_num, libc::SIGTERM);
                }
                if let Some(h) = poll_acquire(data_dir, 30, 100) {
                    return Ok(h);
                }
                tracing::warn!(pid = pid_num, "hub: --steal escalating to SIGKILL");
                #[cfg(unix)]
                unsafe {
                    libc::kill(pid_num, libc::SIGKILL);
                }
                if let Some(h) = poll_acquire(data_dir, 10, 100) {
                    return Ok(h);
                }
                Self::acquire(data_dir)
            }
            Err(other) => Err(other),
        }
    }

    /// Try to acquire the data-dir lock. On contention, reads the
    /// existing lockfile contents (best-effort — the holder writes
    /// its pid) to produce a useful error message.
    pub fn acquire(data_dir: &Path) -> Result<Self, LockError> {
        let lockfile = data_dir.join("hub.lock");

        #[cfg(not(unix))]
        {
            // Non-unix: just open + write the pid, no real exclusion.
            // The hub's primary target is Unix anyway; we don't want
            // to silently let a Windows operator double-launch, but
            // a real lock is `cfg(unix)` only for now.
            tracing::warn!("hub.lock: non-unix build, advisory lock not enforced");
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&lockfile)
                .map_err(|e| LockError::Open(lockfile.clone(), e))?;
            return Ok(Self { _file: file });
        }

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;

            let file = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                // Advisory lock file — keep any existing contents (matches the
                // prior no-truncate default; clippy::suspicious_open_options).
                .truncate(false)
                .open(&lockfile)
                .map_err(|e| LockError::Open(lockfile.clone(), e))?;

            // LOCK_NB: fail fast on contention instead of blocking
            // until the other process exits.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                let mut buf = String::new();
                let pid = match (&file).read_to_string(&mut buf) {
                    Ok(_) => buf.trim().to_string(),
                    Err(_) => "unknown".to_string(),
                };
                let pid = if pid.is_empty() {
                    "unknown".to_string()
                } else {
                    pid
                };
                return Err(LockError::Held { lockfile, pid });
            }

            // Truncate + record our pid so a contending caller can
            // print something useful. Best-effort — the lock semantics
            // don't depend on this succeeding.
            let _ = file.set_len(0);
            let _ = (&file).write_all(format!("{}\n", std::process::id()).as_bytes());

            Ok(Self { _file: file })
        }
    }
}

/// Poll-loop helper: try to acquire the lock up to `attempts` times,
/// sleeping `sleep_ms` between tries. Returns the first successful
/// `HubLock` or `None` if all attempts failed.
fn poll_acquire(data_dir: &Path, attempts: u32, sleep_ms: u64) -> Option<HubLock> {
    for _ in 0..attempts {
        if let Ok(h) = HubLock::acquire(data_dir) {
            return Some(h);
        }
        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
    }
    None
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn acquire_then_second_attempt_fails() {
        let dir = TempDir::new().unwrap();
        let _held = HubLock::acquire(dir.path()).expect("first acquire");
        let err = HubLock::acquire(dir.path()).expect_err("second acquire should fail");
        match err {
            LockError::Held { pid, .. } => {
                let my_pid = std::process::id().to_string();
                assert_eq!(pid, my_pid, "held lock should record our pid");
            }
            other => panic!("expected Held, got {:?}", other),
        }
    }

    #[test]
    fn drop_releases_lock() {
        let dir = TempDir::new().unwrap();
        {
            let _h = HubLock::acquire(dir.path()).expect("acquire");
        }
        // First handle is dropped → lock should be free.
        let _second = HubLock::acquire(dir.path()).expect("reacquire after drop");
    }
}
