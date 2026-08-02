//! Anti-equivocation policy on the signer.
//!
//! Tracks the highest seq we've signed as operator (per ledger) and as
//! cosigner (per other-operator ledger), and refuses to sign a request
//! that regresses or repeats that seq. This is the safety net that makes
//! a hot-spare daemon configuration viable: even if two daemons share the
//! same operator key and race into the same seq, only one of their sign
//! requests gets through — the other comes back as `PolicyRefused`.
//!
//! ## Why per-(ledger_id, role)
//!
//! Operator and cosigner sigs are protocol-distinct: signing as operator at
//! seq=5 on ledger A says "I, the operator of A, commit to update 5";
//! signing as cosigner at seq=5 on ledger A says "I, a quorum member, witness
//! the operator's update 5." They use the same key but mean different things,
//! and a future split into two seed-derived keys is plausible. Tracking them
//! independently keeps the policy correct under both today's single-key shape
//! and the future split.
//!
//! ## Storage
//!
//! Backed by a JSON file (`anti_equivocation.json` under the data dir). One
//! `Mutex<SeqState>` guards in-memory state; every accepted sign flushes
//! the state to disk before returning. This is durable enough for the
//! signer's rate (it caps at ~one per ledger update) and trivially
//! inspectable for debugging.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use deposits_signer_api::SigRole;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// A sign request would have regressed (or matched) the highest seq we
    /// already signed for this `(ledger_id, role)`. This is the load-bearing
    /// case — the daemon is either confused about its own state or someone
    /// else is racing it. The signer refuses; the daemon surfaces this as
    /// `SignerError::PolicyRefused`.
    #[error("seq regression: {role} on ledger {ledger}, requested seq={requested}, last signed={last_signed}")]
    SeqRegression {
        role: &'static str,
        ledger: String,
        requested: u64,
        last_signed: u64,
    },
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SeqState {
    /// `ledger_id (hex) → max seq we've ever signed as operator on it`.
    #[serde(default)]
    operator: HashMap<String, u64>,
    /// `operator_ledger_id (hex) → max seq we've ever cosigned for it`.
    #[serde(default)]
    cosigner: HashMap<String, u64>,
}

pub struct SeqPolicy {
    path: PathBuf,
    state: Mutex<SeqState>,
}

impl SeqPolicy {
    /// Load a policy from `path`; return an empty one if the file doesn't
    /// exist yet. Subsequent writes go to `path`.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, PolicyError> {
        let path = path.into();
        let state = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            if raw.trim().is_empty() {
                SeqState::default()
            } else {
                serde_json::from_str(&raw)?
            }
        } else {
            SeqState::default()
        };
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    /// Validate `role` against the policy. On accept, persist the new
    /// `(ledger_id, role) → seq` entry to disk; on refuse, return a
    /// [`PolicyError::SeqRegression`] without modifying state.
    ///
    /// `NoLedger` always passes through — those sigs (invoice cosigns,
    /// attestations, etc.) are not bound to a sequence so the policy has
    /// nothing to enforce.
    pub fn check_and_record(&self, role: &SigRole) -> Result<(), PolicyError> {
        let mut guard = self.state.lock().expect("policy mutex poisoned");

        match role {
            SigRole::NoLedger => Ok(()),
            SigRole::OperatorUpdate { ledger_id, seq } => {
                let key = hex::encode(ledger_id);
                if let Some(&prev) = guard.operator.get(&key) {
                    if *seq <= prev {
                        return Err(PolicyError::SeqRegression {
                            role: "operator",
                            ledger: key,
                            requested: *seq,
                            last_signed: prev,
                        });
                    }
                }
                guard.operator.insert(key, *seq);
                self.persist_unlocked(&guard)
            }
            SigRole::CosignUpdate {
                operator_ledger_id,
                seq,
                ..
            } => {
                let key = hex::encode(operator_ledger_id);
                if let Some(&prev) = guard.cosigner.get(&key) {
                    if *seq <= prev {
                        return Err(PolicyError::SeqRegression {
                            role: "cosigner",
                            ledger: key,
                            requested: *seq,
                            last_signed: prev,
                        });
                    }
                }
                guard.cosigner.insert(key, *seq);
                self.persist_unlocked(&guard)
            }
        }
    }

    fn persist_unlocked(&self, state: &SeqState) -> Result<(), PolicyError> {
        let body = serde_json::to_vec_pretty(state)?;
        // Atomic-ish write: tmp + rename. Important so a torn write doesn't
        // leave a half-flushed JSON file the next start can't parse.
        let tmp = self.tmp_path();
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&body)?;
            f.write_all(b"\n")?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn tmp_path(&self) -> PathBuf {
        let mut s = self.path.as_os_str().to_owned();
        s.push(".tmp");
        PathBuf::from(s)
    }

    #[cfg(test)]
    pub(crate) fn snapshot_for_test(&self) -> SeqState {
        self.state.lock().unwrap().clone()
    }

    /// Test helper for confirming the policy reads back from disk.
    #[doc(hidden)]
    pub fn _path_for_test(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmpfile() -> PathBuf {
        use bitcoin::secp256k1::rand::rngs::OsRng;
        use bitcoin::secp256k1::rand::RngCore;
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        let mut p = env::temp_dir();
        p.push(format!("anti-equiv-{}.json", hex::encode(bytes)));
        p
    }

    #[test]
    fn no_ledger_always_accepts() {
        let p = SeqPolicy::load(tmpfile()).unwrap();
        for _ in 0..3 {
            p.check_and_record(&SigRole::NoLedger).unwrap();
        }
        let _ = fs::remove_file(p._path_for_test());
    }

    #[test]
    fn operator_seq_must_strictly_increase() {
        let path = tmpfile();
        let p = SeqPolicy::load(&path).unwrap();
        let lid = [0xAB; 32];

        p.check_and_record(&SigRole::OperatorUpdate {
            ledger_id: lid,
            seq: 1,
        })
        .unwrap();
        p.check_and_record(&SigRole::OperatorUpdate {
            ledger_id: lid,
            seq: 2,
        })
        .unwrap();

        let same = p
            .check_and_record(&SigRole::OperatorUpdate {
                ledger_id: lid,
                seq: 2,
            })
            .unwrap_err();
        assert!(matches!(same, PolicyError::SeqRegression { .. }));

        let regress = p
            .check_and_record(&SigRole::OperatorUpdate {
                ledger_id: lid,
                seq: 1,
            })
            .unwrap_err();
        assert!(matches!(regress, PolicyError::SeqRegression { .. }));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn separate_ledgers_dont_interfere() {
        let path = tmpfile();
        let p = SeqPolicy::load(&path).unwrap();
        let lid_a = [0x11; 32];
        let lid_b = [0x22; 32];

        p.check_and_record(&SigRole::OperatorUpdate {
            ledger_id: lid_a,
            seq: 100,
        })
        .unwrap();
        // Different ledger, lower seq is fine.
        p.check_and_record(&SigRole::OperatorUpdate {
            ledger_id: lid_b,
            seq: 1,
        })
        .unwrap();

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn operator_and_cosigner_tracked_independently() {
        let path = tmpfile();
        let p = SeqPolicy::load(&path).unwrap();
        let lid = [0x33; 32];

        // Sign as operator at seq=5.
        p.check_and_record(&SigRole::OperatorUpdate {
            ledger_id: lid,
            seq: 5,
        })
        .unwrap();
        // Sign as cosigner at seq=1 on the *same* ledger — different role,
        // not blocked by the operator entry.
        p.check_and_record(&SigRole::CosignUpdate {
            operator_ledger_id: lid,
            seq: 1,
            member_ledger_hash: [0; 32],
        })
        .unwrap();
        // But cosigning at seq=1 again *is* blocked.
        let dup = p
            .check_and_record(&SigRole::CosignUpdate {
                operator_ledger_id: lid,
                seq: 1,
                member_ledger_hash: [0; 32],
            })
            .unwrap_err();
        assert!(matches!(dup, PolicyError::SeqRegression { .. }));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn persists_across_reload() {
        let path = tmpfile();
        let lid = [0x44; 32];

        {
            let p = SeqPolicy::load(&path).unwrap();
            p.check_and_record(&SigRole::OperatorUpdate {
                ledger_id: lid,
                seq: 10,
            })
            .unwrap();
        }

        let p2 = SeqPolicy::load(&path).unwrap();
        // After reload, repeating seq=10 must still be refused.
        let err = p2
            .check_and_record(&SigRole::OperatorUpdate {
                ledger_id: lid,
                seq: 10,
            })
            .unwrap_err();
        assert!(matches!(err, PolicyError::SeqRegression { .. }));
        // But seq=11 is accepted — and the stored state contains it.
        p2.check_and_record(&SigRole::OperatorUpdate {
            ledger_id: lid,
            seq: 11,
        })
        .unwrap();
        assert_eq!(
            p2.snapshot_for_test().operator.get(&hex::encode(lid)),
            Some(&11)
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn refuse_does_not_advance_state() {
        let path = tmpfile();
        let p = SeqPolicy::load(&path).unwrap();
        let lid = [0x55; 32];

        p.check_and_record(&SigRole::OperatorUpdate {
            ledger_id: lid,
            seq: 10,
        })
        .unwrap();
        // Refused requests do not bump the recorded max.
        let _ = p.check_and_record(&SigRole::OperatorUpdate {
            ledger_id: lid,
            seq: 5,
        });
        // Going from 10 → 11 still works.
        p.check_and_record(&SigRole::OperatorUpdate {
            ledger_id: lid,
            seq: 11,
        })
        .unwrap();
        assert_eq!(
            p.snapshot_for_test().operator.get(&hex::encode(lid)),
            Some(&11)
        );

        let _ = fs::remove_file(&path);
    }
}
