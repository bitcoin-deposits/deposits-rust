//! Unauthorised vault spend watch (DEP-06, `UnauthorizedVaultSpend`).
//!
//! One node-wide pass over the blocks that are `VAULT_SPEND_GRACE_BLOCKS` deep:
//! any spend of the vault outpoint of a ledger we replicate that its history
//! does not account for (a recorded rotation, or a confiscation we know) and
//! whose tier witness verifies is a theft. Every verified signer is accused on
//! every ledger it operates. Mirrors cl-deposits' `drive-vault-watch` and
//! `report-vault-spend`.

use super::*;

use crate::chain_backend::ScannedSpend;
use bitcoin::hashes::Hash;
use bitcoin::OutPoint;
use deposits_core::messages::LedgerOperation;
use deposits_core::vault_spend::{authorised_spend_txids, vault_spend_signers};
use deposits_core::{SignedLedgerUpdate, TlvDecode};
use std::collections::{HashMap, HashSet};

/// A rotation's `QuorumBegin` can reach us a block or two after the spend
/// confirms, so a spend is judged only once it is this deep.
pub(crate) const VAULT_SPEND_GRACE_BLOCKS: u32 = 3;
/// Blocks before our first scan to look back over.
const VAULT_SCAN_DEPTH: u32 = 30;
/// Blocks one pass reads at most; a long gap is caught up over several passes.
const VAULT_SCAN_CHUNK: u32 = 50;

/// The vault outpoint of the newest `QuorumBegin` in `history`, with its
/// sequence.
pub(crate) fn current_vault(history: &[SignedLedgerUpdate]) -> Option<(OutPoint, u64)> {
    history
        .iter()
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::QuorumBegin {
                new_outpoint_txid,
                new_outpoint_vout,
                ..
            }) => Some((
                OutPoint::new(
                    bitcoin::Txid::from_byte_array(new_outpoint_txid),
                    new_outpoint_vout,
                ),
                u.sequence_number,
            )),
            _ => None,
        })
        .max_by_key(|(_, seq)| *seq)
}

/// The vaults of the newest two `QuorumBegin`s in `history`, newest first. A QuorumBegin is
/// recorded before its rotation confirms (DEP-03), so the previous vault stays watched until
/// it is spent by that rotation (authorised) or by anything else (theft under the old quorum).
pub(crate) fn recent_vaults(history: &[SignedLedgerUpdate]) -> Vec<(OutPoint, u64)> {
    let mut v: Vec<(OutPoint, u64)> = history
        .iter()
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::QuorumBegin {
                new_outpoint_txid,
                new_outpoint_vout,
                ..
            }) => Some((
                OutPoint::new(
                    bitcoin::Txid::from_byte_array(new_outpoint_txid),
                    new_outpoint_vout,
                ),
                u.sequence_number,
            )),
            _ => None,
        })
        .collect();
    v.sort_by_key(|(_, seq)| std::cmp::Reverse(*seq));
    v.truncate(2);
    v
}

/// A theft found by the scan: which ledger's vault, the governing
/// `QuorumBegin`, the spend, and the keys that signed it.
#[derive(Debug)]
pub(crate) struct VaultTheft {
    pub ledger_id: String,
    pub governing_seq: u64,
    pub spend: ScannedSpend,
    pub signers: Vec<bitcoin::secp256k1::XOnlyPublicKey>,
}

/// Which of `spends` are thefts: they spend a ledger's vault, their txid is
/// none of its recorded rotations nor a confiscation we know, and a tier
/// witness on the vault input verifies. One per ledger per pass; spends whose
/// `vault_spend_key` is in `reported` (owed or done) are skipped.
pub(crate) fn find_vault_thefts(
    ledgers: &HashMap<String, Vec<SignedLedgerUpdate>>,
    spends: &[ScannedSpend],
    known_confiscations: &HashSet<[u8; 32]>,
    reported: &HashSet<String>,
) -> Vec<VaultTheft> {
    let mut out = Vec::new();
    for (id, history) in ledgers {
        // A fork-branch replica (`<ledger_id>_<seq>_<pk>`) shares its ledger's vault: the main
        // replica reports the spend, under the ledger id a proof must name.
        if crate::node::fork_publish::fork_key_last_valid_seq(id).is_some() {
            continue;
        }
        'vaults: for (vault, seq) in recent_vaults(history) {
            for spend in spends.iter().filter(|s| s.outpoint == vault) {
                let txid = spend.tx.compute_txid().to_byte_array();
                if reported.contains(&vault_spend_key(id, &spend.tx))
                    || known_confiscations.contains(&txid)
                    || authorised_spend_txids(history).contains(&txid)
                {
                    continue;
                }
                let Ok(signers) = vault_spend_signers(history, seq, &spend.tx, &spend.prevouts)
                else {
                    continue;
                };
                if signers.is_empty() {
                    continue;
                }
                out.push(VaultTheft {
                    ledger_id: id.clone(),
                    governing_seq: seq,
                    spend: spend.clone(),
                    signers,
                });
                break 'vaults;
            }
        }
    }
    out
}

/// The txid of the confiscation in a `confiscation_sign` request. Its
/// witness is not yet filled, but a segwit txid excludes the witness, so it is
/// the txid of the spend that will confirm.
pub(crate) fn confiscation_txid_from_params(params: &serde_json::Value) -> Option<[u8; 32]> {
    let bytes = hex::decode(params.get("unsigned_tx")?.as_str()?).ok()?;
    let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&bytes).ok()?;
    Some(tx.compute_txid().to_byte_array())
}

fn proof_against(
    accused: &bitcoin::secp256k1::PublicKey,
    target_ledger_id: &str,
    theft: &VaultTheft,
) -> deposits_core::fraud::FraudBroadcast {
    use deposits_core::fraud::{FraudBroadcast, FraudEvidence, FraudProof, FraudProofType};
    FraudBroadcast {
        proof: FraudProof {
            proof_type: FraudProofType::UnauthorizedVaultSpend,
            accused: hex::encode(accused.serialize()),
            ledger_id: target_ledger_id.to_string(),
            evidence: FraudEvidence::UnauthorizedVaultSpend {
                spent_ledger_id: theft.ledger_id.clone(),
                governing_quorumbegin_seq: theft.governing_seq,
                spend_tx_hex: hex::encode(bitcoin::consensus::serialize(&theft.spend.tx)),
                spend_block_hash: theft.spend.block_hash.to_byte_array(),
                prevouts: theft
                    .spend
                    .prevouts
                    .iter()
                    .map(|o| {
                        format!(
                            "{}:{}",
                            o.value.to_sat(),
                            hex::encode(o.script_pubkey.as_bytes())
                        )
                    })
                    .collect(),
            },
        },
        embedding: None,
        causal_chain: Vec::new(),
    }
}

/// One theft per (ledger, spending txid): a later theft on the same ledger is its own.
pub(crate) fn vault_spend_key(ledger_id: &str, tx: &bitcoin::Transaction) -> String {
    format!("{}:{}", ledger_id, tx.compute_txid())
}

/// Blocks after first seeing a theft during which we keep (re)publishing its proofs: to
/// targets a relay error hid, and to ledgers its signers start advertising later.
pub(crate) const VAULT_SPEND_PUBLISH_BLOCKS: u32 = 144;

/// A theft we still owe proofs for, as persisted in `{data_dir}/vault_watch.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct OwedTheft {
    pub ledger_id: String,
    pub governing_seq: u64,
    pub outpoint: String,
    pub tx_hex: String,
    pub prevouts: Vec<(u64, String)>,
    pub block_hash: String,
    #[serde(default)]
    pub height: u32,
    pub signers: Vec<String>,
    pub published: std::collections::BTreeSet<String>,
    pub first_tip: u32,
}

impl OwedTheft {
    pub(crate) fn from_theft(t: &VaultTheft, tip: u32) -> Self {
        OwedTheft {
            ledger_id: t.ledger_id.clone(),
            governing_seq: t.governing_seq,
            outpoint: t.spend.outpoint.to_string(),
            tx_hex: hex::encode(bitcoin::consensus::serialize(&t.spend.tx)),
            prevouts: t
                .spend
                .prevouts
                .iter()
                .map(|o| (o.value.to_sat(), hex::encode(o.script_pubkey.as_bytes())))
                .collect(),
            block_hash: t.spend.block_hash.to_string(),
            height: t.spend.height,
            signers: t
                .signers
                .iter()
                .map(|x| hex::encode(x.serialize()))
                .collect(),
            published: Default::default(),
            first_tip: tip,
        }
    }

    pub(crate) fn theft(&self) -> Option<VaultTheft> {
        use std::str::FromStr;
        let tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&hex::decode(&self.tx_hex).ok()?).ok()?;
        let prevouts = self
            .prevouts
            .iter()
            .map(|(v, spk)| {
                Some(bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(*v),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(hex::decode(spk).ok()?),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(VaultTheft {
            ledger_id: self.ledger_id.clone(),
            governing_seq: self.governing_seq,
            spend: ScannedSpend {
                outpoint: OutPoint::from_str(&self.outpoint).ok()?,
                tx,
                prevouts,
                block_hash: bitcoin::BlockHash::from_str(&self.block_hash).ok()?,
                height: self.height,
            },
            signers: self
                .signers
                .iter()
                .map(|h| bitcoin::secp256k1::XOnlyPublicKey::from_slice(&hex::decode(h).ok()?).ok())
                .collect::<Option<Vec<_>>>()?,
        })
    }
}

/// The persisted vault watch: how far we scanned, what we still owe, what is done.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct VaultWatchState {
    pub scanned: Option<u32>,
    pub owed: std::collections::BTreeMap<String, OwedTheft>,
    pub done: std::collections::BTreeSet<String>,
}

impl crate::Node {
    /// Scan the blocks that are now `VAULT_SPEND_GRACE_BLOCKS` deep for spends
    /// of any replicated ledger's vault, and report each theft found.
    pub(crate) async fn drive_vault_watch(&self) {
        let backend = self.wallet.chain_backend();
        if !self
            .vault_watch_loaded
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            self.load_vault_watch();
        }
        let Ok(tip) = backend.get_tip_height() else {
            return;
        };
        // Retry what we still owe even when there is nothing new to scan.
        self.publish_owed_vault_spends(tip).await;
        let Some(to) = tip.checked_sub(VAULT_SPEND_GRACE_BLOCKS) else {
            return;
        };
        let from = match *self.vault_scanned.lock().unwrap() {
            Some(done) => done + 1,
            None => to.saturating_sub(VAULT_SCAN_DEPTH),
        };
        if from > to {
            return;
        }
        let to = to.min(from + VAULT_SCAN_CHUNK - 1);

        let histories: HashMap<String, Vec<SignedLedgerUpdate>> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .map(|(id, arc)| (id.clone(), arc.read().unwrap().history.clone()))
                .collect()
        };
        let watched: HashSet<OutPoint> = histories
            .values()
            .flat_map(|h| recent_vaults(h).into_iter().map(|(o, _)| o))
            .collect();
        if !watched.is_empty() {
            let scan = {
                let watched = watched.clone();
                tokio::task::spawn_blocking(move || {
                    backend.scan_outpoint_spends(from, to, &watched)
                })
                .await
            };
            let spends = match scan {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!("vault watch: scan {}..={} failed: {}", from, to, e);
                    return;
                }
                Err(_) => return,
            };
            let known = self.known_confiscation_txids.lock().unwrap().clone();
            let mut skip = self.reported_vault_spends.lock().unwrap().clone();
            skip.extend(self.owed_vault_spends.lock().unwrap().keys().cloned());
            for theft in find_vault_thefts(&histories, &spends, &known, &skip) {
                tracing::warn!(
                    "VAULT SPEND: ledger {}'s reserves were spent by {}, which no rotation or \
                     confiscation accounts for; {} signers",
                    &theft.ledger_id[..8.min(theft.ledger_id.len())],
                    &theft.spend.tx.compute_txid().to_string()[..16],
                    theft.signers.len(),
                );
                // Owed BEFORE the scan height moves past its block: a publish failure or a
                // restart can no longer lose it.
                self.owed_vault_spends.lock().unwrap().insert(
                    vault_spend_key(&theft.ledger_id, &theft.spend.tx),
                    OwedTheft::from_theft(&theft, tip),
                );
            }
        }
        *self.vault_scanned.lock().unwrap() = Some(to);
        self.publish_owed_vault_spends(tip).await;
        self.save_vault_watch();
    }

    fn vault_watch_path(&self) -> std::path::PathBuf {
        self.data_dir.join("vault_watch.json")
    }

    pub(crate) fn save_vault_watch(&self) {
        let state = VaultWatchState {
            scanned: *self.vault_scanned.lock().unwrap(),
            owed: self
                .owed_vault_spends
                .lock()
                .unwrap()
                .clone()
                .into_iter()
                .collect(),
            done: self
                .reported_vault_spends
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .collect(),
        };
        let path = self.vault_watch_path();
        let tmp = path.with_extension("json.tmp");
        if let Ok(json) = serde_json::to_vec(&state) {
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }

    pub(crate) fn load_vault_watch(&self) {
        let Ok(bytes) = std::fs::read(self.vault_watch_path()) else {
            return;
        };
        let Ok(state) = serde_json::from_slice::<VaultWatchState>(&bytes) else {
            return;
        };
        *self.vault_scanned.lock().unwrap() = state.scanned;
        self.owed_vault_spends.lock().unwrap().extend(state.owed);
        self.reported_vault_spends
            .lock()
            .unwrap()
            .extend(state.done);
    }

    /// (Re)publish every owed theft's proofs not yet published. A theft is done only once
    /// every target lookup succeeded and its publish window has passed.
    async fn publish_owed_vault_spends(&self, tip: u32) {
        let owed: Vec<(String, OwedTheft)> = self
            .owed_vault_spends
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (key, mut entry) in owed {
            let Some(theft) = entry.theft() else {
                tracing::error!("vault spend {}: unreadable owed record dropped", key);
                self.owed_vault_spends.lock().unwrap().remove(&key);
                continue;
            };
            let complete = self.report_vault_spend(&theft, &mut entry.published).await;
            if complete && tip > entry.first_tip + VAULT_SPEND_PUBLISH_BLOCKS {
                self.owed_vault_spends.lock().unwrap().remove(&key);
                self.reported_vault_spends.lock().unwrap().insert(key);
            } else {
                self.owed_vault_spends.lock().unwrap().insert(key, entry);
            }
        }
    }

    /// DEP-20 §8.3: for each ledger we hold whose latest rotation migrated deposits, once the
    /// receiver has signed an update its own `service_response_blocks` after the migration
    /// confirmed without crediting every migrated entry, broadcast the UncreditedOnchainPayment
    /// proof against it. Mirrors cl-deposits' `drive-migration-watch`.
    pub(crate) async fn drive_migration_watch(&self) {
        use deposits_core::fraud::{
            latest_migration, uncredited_migration_proof, verify_uncredited_migration,
            FraudBroadcast,
        };
        let histories: Vec<(String, Vec<SignedLedgerUpdate>)> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .map(|(id, arc)| (id.clone(), arc.read().unwrap().history.clone()))
                .collect()
        };
        let tip = self.wallet.get_block_height().unwrap_or(0);
        for (id, source) in histories {
            let Some((qu, nu)) = latest_migration(&source) else {
                continue;
            };
            let key = format!("{}:{}", id, qu.sequence_number);
            if self.migrations_done.lock().unwrap().contains(&key) {
                continue;
            }
            let Ok(LedgerOperation::QuorumBegin {
                new_outpoint_txid, ..
            }) = LedgerOperation::tlv_decode(&qu.message)
            else {
                continue;
            };
            let txid = bitcoin::Txid::from_byte_array(new_outpoint_txid);
            let Ok(Some(confirmed)) = self.wallet.tx_block_height(txid) else {
                continue;
            };
            let Some(confirmed_hash) = self.wallet.block_hash_at(confirmed) else {
                continue;
            };
            let Ok(LedgerOperation::DormancyNotice {
                dormancy_accept: Some(accept),
                ..
            }) = LedgerOperation::tlv_decode(&nu.message)
            else {
                continue;
            };
            let Ok(au) = SignedLedgerUpdate::tlv_decode(&accept) else {
                continue;
            };
            let rid = hex::encode(au.ledger_id);
            let local = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .get(&rid)
                    .map(|arc| arc.read().unwrap().history.clone())
            };
            let receiver = match local {
                Some(h) => h,
                None => {
                    self.fetch_ledger_updates_paginated_filtered(&rid, &[])
                        .await
                }
            };
            match uncredited_migration_proof(&source, &receiver, confirmed_hash, confirmed) {
                Some(proof) => {
                    let wallet = &self.wallet;
                    let oracle = |b: &[u8; 32]| {
                        (confirmed..=tip)
                            .rev()
                            .find(|h| wallet.block_hash_at(*h).as_ref() == Some(b))
                    };
                    if let Err(e) = verify_uncredited_migration(&proof, &receiver, &oracle) {
                        tracing::warn!(
                            "uncredited-migration proof against {} does not verify: {}",
                            &rid[..8],
                            e
                        );
                        continue;
                    }
                    tracing::warn!(
                        "UNCREDITED MIGRATION: {} has not credited {}'s migration; proof broadcast",
                        &rid[..8],
                        &id[..8]
                    );
                    self.migrations_done.lock().unwrap().insert(key);
                    let b = FraudBroadcast {
                        proof,
                        embedding: None,
                        causal_chain: Vec::new(),
                    };
                    if let Err(e) = self.nostr.broadcast_fraud_proof(&b).await {
                        tracing::error!("migration watch: fraud broadcast failed: {}", e);
                    }
                }
                None => {
                    // All credited by the receiver's latest update: nothing more to watch.
                    if !receiver.is_empty()
                        && uncredited_migration_proof(&source, &receiver, confirmed_hash, 0)
                            .is_none()
                    {
                        self.migrations_done.lock().unwrap().insert(key);
                    }
                }
            }
        }
    }

    /// Publish `theft`'s proof to every target not in `published`; true when every target
    /// lookup succeeded and every proof found was published.
    async fn report_vault_spend(
        &self,
        theft: &VaultTheft,
        published: &mut std::collections::BTreeSet<String>,
    ) -> bool {
        let mut complete = true;
        for x in &theft.signers {
            // The operated ledgers are advertised under the full key; the
            // witness gives only its x coordinate, so try both parities.
            for parity in [0x02u8, 0x03] {
                let mut full = [parity; 33];
                full[1..].copy_from_slice(&x.serialize());
                let Ok(pk) = bitcoin::secp256k1::PublicKey::from_slice(&full) else {
                    continue;
                };
                if pk == self.node_id {
                    continue;
                }
                let (targets, ok) = self.ledgers_operated_by_checked(&pk).await;
                complete &= ok;
                for t in targets {
                    let pkey = format!("{}:{}", hex::encode(pk.serialize()), t);
                    if published.contains(&pkey) {
                        continue;
                    }
                    tracing::warn!(
                        "vault spend: {} signed it; proof against its ledger {}",
                        hex::encode(&x.serialize()[..4]),
                        &t[..8.min(t.len())]
                    );
                    let b = proof_against(&pk, &t, theft);
                    match self.nostr.broadcast_fraud_proof(&b).await {
                        Ok(_) => {
                            published.insert(pkey);
                        }
                        Err(e) => {
                            complete = false;
                            tracing::error!(
                                "vault spend: fraud broadcast failed (retrying): {}",
                                e
                            );
                        }
                    }
                }
            }
        }
        complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::sha256;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use deposits_core::fraud::{FraudEvidence, FraudProof};
    use deposits_core::messages::QuorumMemberRef;
    use deposits_core::TlvEncode;

    const CL_PROOF_HASH: &str = "53b34dbf1df8701b5ce43b0216ec4c2967a7cf989bfadfbed950df5978bb2485";

    fn pubkey(i: u64) -> PublicKey {
        let k = 1_000_000_007u64 + i * 987_654_321;
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&k.to_be_bytes());
        PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&b).unwrap())
    }

    fn sha(b: &[u8]) -> [u8; 32] {
        sha256::Hash::hash(b).to_byte_array()
    }

    fn update(seq: u64, op: &LedgerOperation) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: op.tlv_encode(),
            message_type: op.message_type(),
            operator_id: pubkey(1),
            ledger_id: sha(&[2]),
            sequence_number: seq,
            previous_hash: [0; 32],
            content_hash: [0; 32],
            block_height: 100,
            block_hash: [0; 32],
            operator_signature: [0; 64],
            cosignatures: Vec::new(),
        }
    }

    fn history(rotation_txid: [u8; 32]) -> Vec<SignedLedgerUpdate> {
        vec![
            update(
                0,
                &LedgerOperation::LedgerOpen {
                    operator_id: pubkey(1),
                    reserves_id: String::new(),
                    genesis_block: 0,
                    reserves_amount: 0,
                    collateral_amount: 0,
                },
            ),
            update(
                1,
                &LedgerOperation::QuorumBegin {
                    exit_cutoff_height: None,
                    exit_outputs: Vec::new(),
                    splice_in_outpoint: None,
                    splice_in_amount: None,
                    reference_feerate: None,
                    dormancy_outputs: Vec::new(),
                    migration_manifest: Vec::new(),
                    migration_receiver: None,
                    migration_vout: None,
                    reserves_id: String::new(),
                    spending_txid: rotation_txid,
                    new_outpoint_txid: sha(&[0xf0, 0x0d]),
                    new_outpoint_vout: 0,
                    amount: 39_000_000_000,
                    quorum_expiry: 5000,
                    ledger_hash: sha(&[0xaa]),
                    quorum_members: (2..=4)
                        .map(|i| QuorumMemberRef {
                            pubkey: pubkey(i),
                            member_ledger_id: String::new(),
                        })
                        .collect(),
                    collateral_amount: 0,
                    protocol_version: Some("cltv-offset-v2".into()),
                },
            ),
        ]
    }

    /// cl-deposits' signed theft of the vault the history above names.
    fn cl_theft() -> (FraudProof, ScannedSpend) {
        let p: FraudProof = serde_json::from_str(include_str!(
            "../../../deposits-core/tests/vectors/vault_spend_cl.json"
        ))
        .unwrap();
        let FraudEvidence::UnauthorizedVaultSpend {
            spend_tx_hex,
            spend_block_hash,
            prevouts,
            ..
        } = &p.evidence
        else {
            panic!()
        };
        let tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&hex::decode(spend_tx_hex).unwrap()).unwrap();
        let prevouts = prevouts
            .iter()
            .map(|s| {
                let (v, spk) = s.split_once(':').unwrap();
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(v.parse().unwrap()),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(hex::decode(spk).unwrap()),
                }
            })
            .collect();
        let spend = ScannedSpend {
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array(sha(&[0xf0, 0x0d])), 0),
            tx,
            prevouts,
            block_hash: bitcoin::BlockHash::from_byte_array(*spend_block_hash),
            height: 10,
        };
        (p, spend)
    }

    fn ledgers(rotation_txid: [u8; 32]) -> HashMap<String, Vec<SignedLedgerUpdate>> {
        HashMap::from([(hex::encode(sha(&[2])), history(rotation_txid))])
    }

    #[test]
    fn current_vault_is_the_newest_quorum_begin() {
        let (v, seq) = current_vault(&history([9; 32])).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(
            v,
            OutPoint::new(bitcoin::Txid::from_byte_array(sha(&[0xf0, 0x0d])), 0)
        );
    }

    #[test]
    fn finds_the_theft_and_its_signers() {
        let (_, spend) = cl_theft();
        let t = find_vault_thefts(
            &ledgers([9; 32]),
            &[spend],
            &HashSet::new(),
            &HashSet::new(),
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].governing_seq, 1);
        assert!(t[0].signers.len() >= 3);
    }

    #[test]
    fn a_fork_replica_is_reported_under_its_ledger_id_once() {
        let (_, spend) = cl_theft();
        let mut both = ledgers([9; 32]);
        let (id, history) = both
            .iter()
            .next()
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap();
        both.insert(format!("{}_000001_0123456789abcdef", id), history);
        let t = find_vault_thefts(&both, &[spend], &HashSet::new(), &HashSet::new());
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].ledger_id, id);
    }

    #[test]
    fn a_recorded_rotation_or_known_confiscation_is_not_theft() {
        let (_, spend) = cl_theft();
        let txid = spend.tx.compute_txid().to_byte_array();
        assert!(find_vault_thefts(
            &ledgers(txid),
            std::slice::from_ref(&spend),
            &HashSet::new(),
            &HashSet::new()
        )
        .is_empty());
        assert!(find_vault_thefts(
            &ledgers([9; 32]),
            &[spend],
            &HashSet::from([txid]),
            &HashSet::new()
        )
        .is_empty());
    }

    #[test]
    fn a_cosigned_confiscation_is_excused_by_its_unsigned_txid() {
        let (_, spend) = cl_theft();
        let mut unsigned = spend.tx.clone();
        for i in unsigned.input.iter_mut() {
            i.witness = bitcoin::Witness::new();
        }
        let params = serde_json::json!({
            "unsigned_tx": hex::encode(bitcoin::consensus::serialize(&unsigned)),
        });
        let txid = confiscation_txid_from_params(&params).expect("parses");
        assert_eq!(txid, spend.tx.compute_txid().to_byte_array());
        assert!(find_vault_thefts(
            &ledgers([9; 32]),
            &[spend],
            &HashSet::from([txid]),
            &HashSet::new()
        )
        .is_empty());
        assert!(confiscation_txid_from_params(&serde_json::json!({})).is_none());
    }

    #[test]
    fn reports_each_ledger_once_and_ignores_unrelated_spends() {
        let (_, spend) = cl_theft();
        let reported = HashSet::from([vault_spend_key(&hex::encode(sha(&[2])), &spend.tx)]);
        assert!(find_vault_thefts(
            &ledgers([9; 32]),
            std::slice::from_ref(&spend),
            &HashSet::new(),
            &reported
        )
        .is_empty());
        let mut other = spend;
        other.outpoint = OutPoint::new(bitcoin::Txid::from_byte_array([7; 32]), 0);
        assert!(find_vault_thefts(
            &ledgers([9; 32]),
            &[other],
            &HashSet::new(),
            &HashSet::new()
        )
        .is_empty());
    }

    #[test]
    fn the_proof_we_build_is_cls_proof_and_verifies() {
        let (cl, spend) = cl_theft();
        let theft = find_vault_thefts(
            &ledgers([9; 32]),
            &[spend],
            &HashSet::new(),
            &HashSet::new(),
        )
        .pop()
        .unwrap();
        let accused = PublicKey::from_slice(&hex::decode(&cl.accused).unwrap()).unwrap();
        let b = proof_against(&accused, &cl.ledger_id, &theft);
        assert_eq!(hex::encode(b.proof.proof_hash()), CL_PROOF_HASH);
        deposits_core::vault_spend::verify_unauthorized_vault_spend(
            &b.proof,
            &history([9; 32]),
            &[],
        )
        .unwrap();
    }

    /// DEP-03 §"Rotation ordering": which vault the next QuorumBegin rotates, and a
    /// cosigner's check of the carried rotation (a valid tier witness is not enough:
    /// it must be the DEP-03 rotation the QuorumBegin names).
    #[test]
    fn a_rotating_quorum_begin_is_checked_against_its_rotation() {
        use deposits_core::rotation_order::{rotating_quorum_begin_seq, verify_rotation_tx};
        let h = history([9; 32]);
        assert_eq!(rotating_quorum_begin_seq(&h), Some(1));
        let mut acquired = h.clone();
        acquired.push(update(
            2,
            &LedgerOperation::DisputeAcquire {
                new_custodian: pubkey(3),
                claim_txid: [0; 32],
                new_reserves_address: String::new(),
            },
        ));
        assert_eq!(rotating_quorum_begin_seq(&acquired), None);

        let (_, spend) = cl_theft();
        let txid = spend.tx.compute_txid().to_byte_array();
        let qb = |new_txid: [u8; 32]| LedgerOperation::QuorumBegin {
            exit_cutoff_height: None,
            exit_outputs: Vec::new(),
            splice_in_outpoint: None,
            splice_in_amount: None,
            reference_feerate: None,
            dormancy_outputs: Vec::new(),
            migration_manifest: Vec::new(),
            migration_receiver: None,
            migration_vout: None,
            reserves_id: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr".into(),
            spending_txid: new_txid,
            new_outpoint_txid: new_txid,
            new_outpoint_vout: 0,
            amount: 0,
            quorum_expiry: 6000,
            ledger_hash: sha(&[0xbb]),
            quorum_members: Vec::new(),
            collateral_amount: 0,
            protocol_version: Some("cltv-offset-v2".into()),
        };
        let net = bitcoin::Network::Bitcoin;
        let st = deposits_core::types::LedgerState::new(
            bitcoin::secp256k1::PublicKey::from_secret_key(
                &bitcoin::secp256k1::Secp256k1::new(),
                &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
            ),
            String::new(),
            0,
        );
        assert!(
            verify_rotation_tx(&h, &st, 0, &qb([7; 32]), &spend.tx, net, None)
                .unwrap_err()
                .contains("new outpoint")
        );
        // A validly signed spend of the vault that is not the DEP-03 rotation.
        let e = verify_rotation_tx(&h, &st, 0, &qb(txid), &spend.tx, net, None).unwrap_err();
        assert!(e.contains("differs from the DEP-03 rotation"), "{e}");
    }

    /// DEP-03 §"Rotation ordering": a node that did not cosign takes the rotation a
    /// QuorumBegin names from the published Kind 9107 candidates, by txid only.
    #[test]
    fn a_published_rotation_is_found_by_the_quorum_begin_txid() {
        use deposits_core::rotation_order::{latest_quorum_begin_txid, published_rotation};
        let (_, spend) = cl_theft();
        let hex = bitcoin::consensus::encode::serialize_hex(&spend.tx);
        let txid = spend.tx.compute_txid().to_byte_array();
        let found = published_rotation(txid, &["zz".to_string(), "00".to_string(), hex.clone()]);
        assert_eq!(found.map(|t| t.compute_txid().to_byte_array()), Some(txid));
        assert!(published_rotation([7; 32], &[hex]).is_none());
        assert_eq!(
            latest_quorum_begin_txid(&history([9; 32])),
            Some(sha(&[0xf0, 0x0d]))
        );
    }

    /// D3: a theft is owed per (ledger, txid), survives a JSON round trip (restart) with what
    /// was published, and a second theft on the same ledger is its own record.
    #[test]
    fn an_owed_theft_is_keyed_per_spend_and_survives_persistence() {
        let (_, spend) = cl_theft();
        let ts = find_vault_thefts(
            &ledgers([9; 32]),
            std::slice::from_ref(&spend),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert_eq!(ts.len(), 1);
        let mut owed = OwedTheft::from_theft(&ts[0], 1000);
        owed.published.insert("02ab:target".into());
        let mut state = VaultWatchState {
            scanned: Some(990),
            ..Default::default()
        };
        state
            .owed
            .insert(vault_spend_key(&ts[0].ledger_id, &spend.tx), owed);
        let back: VaultWatchState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(back.scanned, Some(990));
        let (k, o) = back.owed.iter().next().unwrap();
        assert!(k.ends_with(&spend.tx.compute_txid().to_string()));
        assert!(o.published.contains("02ab:target"));
        let t = o.theft().expect("rebuilds");
        assert_eq!(t.spend.tx.compute_txid(), spend.tx.compute_txid());
        assert_eq!(t.signers.len(), ts[0].signers.len());
        // Owed (or done) spends are not found again; a different spend on the ledger would be.
        let skip = HashSet::from([k.clone()]);
        assert!(find_vault_thefts(
            &ledgers([9; 32]),
            std::slice::from_ref(&spend),
            &HashSet::new(),
            &skip
        )
        .is_empty());
        let other_key = format!("{}:{}", ts[0].ledger_id, "00".repeat(32));
        let skip = HashSet::from([other_key]);
        assert_eq!(
            find_vault_thefts(&ledgers([9; 32]), &[spend], &HashSet::new(), &skip).len(),
            1
        );
    }
}
