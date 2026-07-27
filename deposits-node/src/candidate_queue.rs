//! Per-operator queue of pre-vetted quorum-member candidates.
//!
//! When `auto_quorum_refresh` finds an active member it can't refresh
//! consent from (unreachable, declined, whatever), it pops a candidate
//! from this queue and tries `QuorumAddMember` against them via the
//! normal consent dance. If the candidate responds, they're staged for
//! the next `QuorumBegin` and the dead member is removed. If they
//! don't respond, they're dropped from the queue and the next one is
//! tried (small budget per rotation to avoid loops).
//!
//! This is purely daemon-local state — no protocol change. The
//! operator curates the queue out-of-band ("here are 5 peers I'd
//! accept as cosigners if I needed replacements"); the daemon
//! consumes from it when it needs to heal a quorum past `quorum_expiry`.
//!
//! Persisted to `<data-dir>/candidate_queue.json`. Loaded at startup,
//! mutated under a single lock.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const FILENAME: &str = "candidate_queue.json";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    /// Compressed secp256k1 pubkey, hex.
    pub pubkey: String,
    /// 64-hex `ledger_id` of the candidate's own ledger (where their
    /// collateral lives — same shape as
    /// `QuorumAddMember.member_ledger_id`).
    pub member_ledger_id: String,
    /// Unix seconds when the candidate was enqueued. Informational.
    pub added_at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CandidateQueue {
    pub entries: Vec<Candidate>,
}

impl CandidateQueue {
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(FILENAME)
    }

    /// Load from disk; empty queue if file is absent.
    pub fn load(data_dir: &Path) -> Self {
        let path = Self::path(data_dir);
        match fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                tracing::warn!(
                    "candidate_queue: failed to parse {}: {} — starting empty",
                    path.display(),
                    e
                );
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        let path = Self::path(data_dir);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        let s = serde_json::to_string_pretty(self).expect("queue serialize");
        fs::write(&tmp, s)?;
        fs::rename(tmp, path)?;
        Ok(())
    }

    /// True if the pubkey is already enqueued.
    pub fn contains(&self, pubkey: &str) -> bool {
        self.entries.iter().any(|c| c.pubkey == pubkey)
    }

    /// Append a candidate. No-op if the pubkey is already enqueued.
    /// Returns whether the candidate was newly added.
    pub fn enqueue(&mut self, data_dir: &Path, c: Candidate) -> std::io::Result<bool> {
        if self.contains(&c.pubkey) {
            return Ok(false);
        }
        self.entries.push(c);
        self.save(data_dir)?;
        Ok(true)
    }

    /// Remove an explicit pubkey from the queue. Returns whether anything
    /// was removed.
    pub fn drain(&mut self, data_dir: &Path, pubkey: &str) -> std::io::Result<bool> {
        let before = self.entries.len();
        self.entries.retain(|c| c.pubkey != pubkey);
        if self.entries.len() == before {
            return Ok(false);
        }
        self.save(data_dir)?;
        Ok(true)
    }

    /// Pop the next candidate (FIFO). Used by auto_quorum_refresh when
    /// it needs a replacement member.
    pub fn pop_front(&mut self, data_dir: &Path) -> Option<Candidate> {
        if self.entries.is_empty() {
            return None;
        }
        let c = self.entries.remove(0);
        // Save best-effort; a write failure here means the next load
        // might re-yield this same candidate, which is benign (the
        // consent dance is idempotent — they'd already be staged).
        if let Err(e) = self.save(data_dir) {
            tracing::warn!("candidate_queue: save failed after pop: {}", e);
        }
        Some(c)
    }

    /// True if any candidates remain.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn c(pk: &str, lid: &str) -> Candidate {
        Candidate {
            pubkey: pk.to_string(),
            member_ledger_id: lid.to_string(),
            added_at: 0,
        }
    }

    #[test]
    fn enqueue_persists_and_load_round_trips() {
        let tmp = TempDir::new().unwrap();
        let mut q = CandidateQueue::load(tmp.path());
        assert!(q.is_empty());
        q.enqueue(tmp.path(), c("02aaaa", "11".repeat(32).as_str()))
            .unwrap();
        q.enqueue(tmp.path(), c("02bbbb", "22".repeat(32).as_str()))
            .unwrap();
        let reloaded = CandidateQueue::load(tmp.path());
        assert_eq!(reloaded.entries.len(), 2);
        assert_eq!(reloaded.entries[0].pubkey, "02aaaa");
        assert_eq!(reloaded.entries[1].pubkey, "02bbbb");
    }

    #[test]
    fn enqueue_is_idempotent_per_pubkey() {
        let tmp = TempDir::new().unwrap();
        let mut q = CandidateQueue::load(tmp.path());
        assert!(q
            .enqueue(tmp.path(), c("02aa", "11".repeat(32).as_str()))
            .unwrap());
        assert!(!q
            .enqueue(tmp.path(), c("02aa", "22".repeat(32).as_str()))
            .unwrap());
        assert_eq!(q.entries.len(), 1);
        assert_eq!(q.entries[0].member_ledger_id, "11".repeat(32));
    }

    #[test]
    fn pop_front_yields_fifo_and_persists() {
        let tmp = TempDir::new().unwrap();
        let mut q = CandidateQueue::load(tmp.path());
        q.enqueue(tmp.path(), c("02aa", "aa".repeat(32).as_str()))
            .unwrap();
        q.enqueue(tmp.path(), c("02bb", "bb".repeat(32).as_str()))
            .unwrap();
        let popped = q.pop_front(tmp.path()).unwrap();
        assert_eq!(popped.pubkey, "02aa");
        let reloaded = CandidateQueue::load(tmp.path());
        assert_eq!(reloaded.entries.len(), 1);
        assert_eq!(reloaded.entries[0].pubkey, "02bb");
    }

    #[test]
    fn drain_removes_specific_pubkey() {
        let tmp = TempDir::new().unwrap();
        let mut q = CandidateQueue::load(tmp.path());
        q.enqueue(tmp.path(), c("02aa", "aa".repeat(32).as_str()))
            .unwrap();
        q.enqueue(tmp.path(), c("02bb", "bb".repeat(32).as_str()))
            .unwrap();
        assert!(q.drain(tmp.path(), "02aa").unwrap());
        assert!(!q.drain(tmp.path(), "02zz").unwrap()); // not present
        let reloaded = CandidateQueue::load(tmp.path());
        assert_eq!(reloaded.entries.len(), 1);
        assert_eq!(reloaded.entries[0].pubkey, "02bb");
    }
}
