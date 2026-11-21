//! WRITE-AHEAD: every update we sign is durable on our disk before any relay sees it
//! (DEP-02 §Signing: a node SHOULD durably store an update it signs before publishing it, and
//! MUST NOT sign a different update at a sequence it has already signed).
//!
//! Publishing first left a window, killed between the broadcast and the persist, in which the
//! update was on the relays and not on our disk; the next attempt then signed another at the
//! same sequence under a later header, an equivocation by us. So a site that signs:
//!
//! 1. appends and signs the update in memory;
//! 2. [`Node::write_ahead`]: a PENDING file naming it (`pending/<key>_<seq>.json`), then the
//!    ledger file itself, both fsync'd on the dispute and rotation paths;
//! 3. broadcasts only if that returned `Ok`, and then drops the pending file.
//!
//! A pending file left behind (killed after 2, before 3) is published at the next start, as the
//! saved bytes, by [`Node::publish_pending_updates`]. One whose update the ledger does not hold
//! was never saved, so never left this node, and is dropped.
//!
//! An update signed with NO ledger of ours to hold it (the fork-less yield, a fork-less acquire)
//! goes to `signed/<ledger>_<seq>.json` instead, kept for good and consulted before signing at
//! that sequence again ([`Node::journal_signed`], [`Node::journaled_at`]).
//!
//! fsync: always on the dispute and rotation paths (DisputeEnter, Armed, Yield, Acquire, residue
//! credits, QuorumBegin, ledger continuation), where a power-loss re-sign is an equivocation and
//! the rate is low. For the operator's ledger updates it is [`fsync_operator_updates`]
//! (`DEPOSITS_FSYNC_OPERATOR_UPDATES`, off by default: measured, see there).

use super::*;
use deposits_core::SignedLedgerUpdate;
use std::path::{Path, PathBuf};

/// Whether operator ledger updates (the high-rate path) are fsync'd:
/// `DEPOSITS_FSYNC_OPERATOR_UPDATES=1` turns it on. OFF by default, measured (`handler::fsync_bench::fsync_cost`,
/// 2026-11-20, a 3379-update regtest ledger, 300 appended updates, interleaved runs): the
/// write-ahead of one update costs 0.48 ms without fsync and 456 ms with it on the nodes' zfs pool
/// (no SLOG), 0.235 ms and 11.1 ms on ext4: +94,600% and +4,600%, far past the 20% bar. A power
/// loss there can lose a published operator update; a kill (the common case) cannot.
pub(crate) fn fsync_operator_updates() -> bool {
    matches!(
        std::env::var("DEPOSITS_FSYNC_OPERATOR_UPDATES").as_deref(),
        Ok("1") | Ok("true") | Ok("on")
    )
}

fn pending_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("pending")
}

fn journal_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("signed")
}

fn write_durable(dir: &Path, name: &str, update: &SignedLedgerUpdate, sync: bool) -> Result<PathBuf, String> {
    use std::io::Write;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {}", dir.display(), e))?;
    let path = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    let json = serde_json::to_vec(update).map_err(|e| e.to_string())?;
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create {}: {}", tmp.display(), e))?;
    f.write_all(&json).map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    if sync {
        f.sync_all().map_err(|e| format!("fsync {}: {}", tmp.display(), e))?;
    }
    drop(f);
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename {}: {}", path.display(), e))?;
    if sync {
        crate::handler::sync_dir(dir).map_err(|e| format!("fsync {}: {}", dir.display(), e))?;
    }
    Ok(path)
}

fn read_update(path: &Path) -> Option<SignedLedgerUpdate> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// A pending file: its path, the update it names, and the ledger key it belongs to.
#[derive(Debug, Clone)]
pub(crate) struct Pending {
    pub path: PathBuf,
    pub key: String,
    pub update: SignedLedgerUpdate,
}

/// Every pending file under `data_dir`, in (key, seq) order. Unreadable ones are skipped.
pub(crate) fn scan_pending(data_dir: &Path) -> Vec<Pending> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(pending_dir(data_dir)) else {
        return out;
    };
    for e in rd.flatten() {
        let path = e.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        let Some(stem) = name.strip_suffix(".json") else { continue };
        let Some((key, _seq)) = stem.rsplit_once('_') else { continue };
        if let Some(update) = read_update(&path) {
            out.push(Pending { key: key.to_string(), update, path });
        }
    }
    out.sort_by(|a, b| (&a.key, a.update.sequence_number).cmp(&(&b.key, b.update.sequence_number)));
    out
}

/// What startup does with a pending file: publish it (the ledger holds those exact bytes), or
/// drop it (the ledger does not: never saved, so never published).
pub(crate) fn pending_held(history: Option<&[SignedLedgerUpdate]>, update: &SignedLedgerUpdate) -> bool {
    history.is_some_and(|h| {
        h.iter().any(|u| {
            u.sequence_number == update.sequence_number
                && u.content_hash == update.content_hash
                && u.operator_signature == update.operator_signature
        })
    })
}

/// The pending file for `key`'s `update` (step 2's first half), for callers with only a data
/// dir in hand (the ledger actor).
pub(crate) fn write_pending(data_dir: &Path, key: &str, update: &SignedLedgerUpdate, sync: bool) -> Result<PathBuf, String> {
    write_durable(&pending_dir(data_dir), &format!("{}_{}.json", key, update.sequence_number), update, sync)
}

/// `Node::journal_signed` for a data dir.
pub(crate) fn journal_put(data_dir: &Path, ledger_id: &str, update: &SignedLedgerUpdate) -> Result<(), String> {
    if let Some(prior) = journal_get(data_dir, ledger_id, update.sequence_number) {
        if prior != *update {
            return Err(format!(
                "{} seq {}: we already signed a different update there",
                &ledger_id[..16.min(ledger_id.len())],
                update.sequence_number
            ));
        }
        return Ok(());
    }
    write_durable(&journal_dir(data_dir), &format!("{}_{}.json", ledger_id, update.sequence_number), update, true)
        .map(|_| ())
}

/// `Node::journaled_at` for a data dir.
pub(crate) fn journal_get(data_dir: &Path, ledger_id: &str, seq: u64) -> Option<SignedLedgerUpdate> {
    read_update(&journal_dir(data_dir).join(format!("{}_{}.json", ledger_id, seq)))
}

impl Node {
    /// Step 2 of the module comment: `key`'s history already holds `update` (signed); make it
    /// durable before it is published. `Err` means do not publish.
    pub(crate) fn write_ahead(&self, key: &str, update: &SignedLedgerUpdate, sync: bool) -> Result<PathBuf, Error> {
        let path = write_pending(&self.handler.data_dir, key, update, sync)
        .map_err(|e| Error::Protocol(format!("write-ahead of {} seq {}: {}", &key[..16.min(key.len())], update.sequence_number, e)))?;
        self.handler.persist_ledger_durable(key, sync).map_err(|e| {
            Error::Protocol(format!(
                "write-ahead persist of {} seq {}: {}; not publishing it",
                &key[..16.min(key.len())],
                update.sequence_number,
                e
            ))
        })?;
        Ok(path)
    }

    /// Step 2 for a fork: its last update (the pass may have signed several before it; the
    /// pending file names the tip, and a restart republishes the whole own tail).
    pub(crate) fn write_ahead_fork(&self, fork_key: &str) -> Result<PathBuf, Error> {
        let tip = {
            let arc = self.handler.ledgers.lock().unwrap().get(fork_key).cloned();
            arc.and_then(|a| a.read().unwrap().history.last().cloned())
        }
        .ok_or_else(|| Error::Protocol(format!("write-ahead: no fork {}", fork_key)))?;
        self.write_ahead(fork_key, &tip, true)
    }

    /// Step 3, after a successful broadcast.
    pub(crate) fn published(&self, pending: &Path) {
        let _ = std::fs::remove_file(pending);
    }

    /// After a fork's tail went out in full: every pending file of `key`.
    pub(crate) fn published_all(&self, key: &str) {
        for p in scan_pending(&self.handler.data_dir).into_iter().filter(|p| p.key == key) {
            let _ = std::fs::remove_file(&p.path);
        }
    }

    /// Start (and every stand-down pass): publish what was saved and never published.
    pub(crate) async fn publish_pending_updates(&self) -> usize {
        let mut sent = 0;
        for p in scan_pending(&self.handler.data_dir) {
            let held = {
                let arc = self.handler.ledgers.lock().unwrap().get(&p.key).cloned();
                arc.is_some_and(|a| pending_held(Some(&a.read().unwrap().history), &p.update))
            };
            if !held {
                tracing::warn!(
                    "write-ahead: dropping pending {} seq {}: never saved, so never published",
                    &p.key[..16.min(p.key.len())],
                    p.update.sequence_number
                );
                let _ = std::fs::remove_file(&p.path);
                continue;
            }
            // A fork's pass may have signed several (members, arm; acquire, residue) and its
            // pending file names the last: publish its whole own tail, in order, as saved.
            if p.key.len() > 64 {
                if self.publish_fork(&p.key).await.is_ok() {
                    tracing::warn!(
                        "write-ahead: published saved fork {} through seq {} (killed before its publish)",
                        &p.key[..16.min(p.key.len())],
                        p.update.sequence_number
                    );
                    sent += 1;
                }
                continue;
            }
            match self.nostr.broadcast_ledger_update(&p.update).await {
                Ok(_) => {
                    tracing::warn!(
                        "write-ahead: published saved update {} seq {} (killed before its publish)",
                        &p.key[..16.min(p.key.len())],
                        p.update.sequence_number
                    );
                    let _ = std::fs::remove_file(&p.path);
                    sent += 1;
                }
                // Kept for the next pass; the later ones of this key wait behind it.
                Err(e) => tracing::warn!("write-ahead: pending {} not published yet: {:?}", &p.key[..16.min(p.key.len())], e),
            }
        }
        sent
    }

    /// A fork-less signature (no ledger of ours holds it): kept for good, fsync'd, before it is
    /// published. Refuses to record a DIFFERENT update at a (ledger, seq) already journaled.
    pub(crate) fn journal_signed(&self, ledger_id: &str, update: &SignedLedgerUpdate) -> Result<(), Error> {
        journal_put(&self.handler.data_dir, ledger_id, update).map_err(Error::Protocol)
    }

    /// The fork-less update we journaled at (ledger, seq), if any.
    pub(crate) fn journaled_at(&self, ledger_id: &str, seq: u64) -> Option<SignedLedgerUpdate> {
        journal_get(&self.handler.data_dir, ledger_id, seq)
    }

    /// Our own update at `seq` on `key`, if the ledger holds one (a retry must publish it, not
    /// sign another).
    pub(crate) fn own_update_at(&self, key: &str, seq: u64) -> Option<SignedLedgerUpdate> {
        let arc = self.handler.ledgers.lock().unwrap().get(key).cloned()?;
        let l = arc.read().unwrap();
        l.history
            .iter()
            .find(|u| u.sequence_number == seq && u.operator_id == self.node_id)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::DepositsHandler;
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvEncode;

    const KEY: &str = "04f435e315169389fe189a4236aaa56ad17f73370fcc96c880c7e4ac98f9f77b_000004_02a417593a974f4f";

    fn handler(dir: &Path) -> DepositsHandler {
        let wallet = std::sync::Arc::new(crate::wallet::Wallet::new_mock(dir.to_path_buf()));
        let signer: std::sync::Arc<dyn deposits_signer_api::Signer> = std::sync::Arc::new(
            deposits_signer_api::LocalSigner::new(bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap()),
        );
        DepositsHandler::new(signer, wallet, dir.to_path_buf(), false).0
    }

    /// The yield the fork's owner signs at arm+1 (signature irrelevant to the store).
    fn yield_on(tip: &SignedLedgerUpdate, header: u32) -> SignedLedgerUpdate {
        let mut y = SignedLedgerUpdate {
            message: LedgerOperation::DisputeYield.tlv_encode(),
            message_type: 0x8001,
            operator_id: tip.operator_id,
            ledger_id: tip.ledger_id,
            sequence_number: tip.sequence_number + 1,
            previous_hash: tip.chain_hash(),
            content_hash: [0; 32],
            block_height: header,
            block_hash: [header as u8; 32],
            operator_signature: [header as u8; 64],
            cosignatures: Vec::new(),
        };
        y.content_hash = y.compute_hash();
        y
    }

    /// cl's restart gate, in Rust: ref6's armed fork signs its yield, writes it ahead, and is
    /// KILLED before the broadcast. The restart holds it, publishes exactly those bytes once,
    /// and leaves nothing pending; the store never accepts a second, different update there.
    #[test]
    fn killed_between_the_save_and_the_publish_the_restart_publishes_the_saved_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/ref6_armed_fork.jsonl");
        let ledger = DepositsHandler::load_single_ledger_from_jsonl(KEY, &src).unwrap();
        let tip = ledger.history.last().unwrap().clone();
        let y = yield_on(&tip, tip.block_height + 3);
        {
            let h = handler(dir.path());
            h.ledgers.lock().unwrap().insert(KEY.into(), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
            h.persist_ledger_durable(KEY, true).unwrap();
            // Write-ahead (as withdraw_dispute): the pending file, then the record, fsync'd.
            write_pending(dir.path(), KEY, &y, true).unwrap();
            assert_eq!(
                h.commit_self_authored_update(KEY, &LedgerOperation::DisputeYield, y.clone(), y.block_height),
                Ok(true)
            );
            // KILLED: no broadcast, nothing removed.
        }
        let published: Vec<SignedLedgerUpdate> = {
            let h = handler(dir.path());
            let arc = h.ledgers.lock().unwrap().get(KEY).cloned().expect("the fork reloads");
            let history = arc.read().unwrap().history.clone();
            assert_eq!(history.last(), Some(&y), "the saved yield is the tip after the restart");
            assert!(
                crate::node::yield_backfill::armed_round1_tip(&history, &tip.operator_id).is_none(),
                "not an armed tip: nothing will sign at that seq again"
            );
            let pending = scan_pending(dir.path());
            assert_eq!(pending.len(), 1, "one update saved and not published");
            // The start pass: publish what the ledger holds, as held.
            let mut out = Vec::new();
            for p in pending {
                assert!(pending_held(Some(&history), &p.update));
                out.push(p.update.clone());
                std::fs::remove_file(&p.path).unwrap();
            }
            out
        };
        assert_eq!(published, vec![y.clone()], "published once, the saved bytes, not a re-signing");
        assert!(scan_pending(dir.path()).is_empty(), "nothing left pending");
        assert!(scan_pending(dir.path()).is_empty(), "a second start publishes nothing more");
    }

    /// A pending file whose update the ledger does not hold was never saved, so never left this
    /// node: dropped, not published. And the fork-less journal refuses a second, different
    /// update at a (ledger, seq) it holds, while the same bytes again are fine.
    #[test]
    fn never_saved_is_dropped_and_the_journal_refuses_a_second_signature() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/ref6_armed_fork.jsonl");
        let ledger = DepositsHandler::load_single_ledger_from_jsonl(KEY, &src).unwrap();
        let tip = ledger.history.last().unwrap().clone();
        let (a, b) = (yield_on(&tip, 200), yield_on(&tip, 201));
        assert!(!pending_held(Some(&ledger.history), &a));
        assert!(!pending_held(None, &a));
        let lid = &KEY[..64];
        journal_put(dir.path(), lid, &a).unwrap();
        journal_put(dir.path(), lid, &a).unwrap();
        assert!(journal_put(dir.path(), lid, &b).is_err(), "a different update at a journaled seq");
        assert_eq!(journal_get(dir.path(), lid, a.sequence_number), Some(a));
    }
}

