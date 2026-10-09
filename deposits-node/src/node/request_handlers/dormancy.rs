//! DEP-20 §8 operator actions: a DormancyNotice (with an optional §8.3 migration), and the
//! receiver's side of a migration — the offer's manifest, the DormancyAccept, and the credits.
//! Mirrors cl-deposits' `:dormancy-offer`, `:dormancy-accept`, `:dormancy-notice` and
//! `:dormancy-credit` control commands.

use super::super::*;
use bitcoin::hashes::{sha256, Hash};
use deposits_core::messages::{decode_manifest, encode_manifest, LedgerOperation};
use deposits_core::types::migration_marker;
use deposits_core::TlvEncode;

type Reply = (bool, Option<String>, Option<String>);

fn err(msg: impl std::fmt::Display) -> Reply {
    (false, None, Some(msg.to_string()))
}

impl Node {
    /// A receiver ledger's history, ascending: our replica if we hold one, else the relays'.
    pub(crate) async fn receiver_history(
        &self,
        ledger_id: &str,
    ) -> Vec<deposits_core::SignedLedgerUpdate> {
        let local = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .map(|arc| arc.read().unwrap().history.clone())
        };
        match local {
            Some(h) => h,
            None => {
                self.fetch_ledger_updates_paginated_filtered(ledger_id, &[])
                    .await
            }
        }
    }

    /// DEP-20 §8.3 (L4), a source cosigner: the accept is in the receiver's canonical history, the
    /// carried QuorumBegin is the receiver's latest (its quorum is current), and that vault is
    /// funded and unspent on chain.
    pub(crate) async fn check_migration_receiver(
        &self,
        accept: &deposits_core::SignedLedgerUpdate,
        qb: &deposits_core::SignedLedgerUpdate,
    ) -> Result<(), String> {
        use deposits_core::TlvDecode;
        let hist = self.receiver_history(&hex::encode(accept.ledger_id)).await;
        if !hist.iter().any(|u| {
            u.sequence_number == accept.sequence_number && u.chain_hash() == accept.chain_hash()
        }) {
            return Err("the accept is not in the receiver's history".into());
        }
        let latest = hist.iter().rfind(|u| {
            matches!(
                LedgerOperation::tlv_decode(&u.message),
                Ok(LedgerOperation::QuorumBegin { .. })
            )
        });
        if latest.map(|u| u.chain_hash()) != Some(qb.chain_hash()) {
            return Err("the carried QuorumBegin is not the receiver's current one".into());
        }
        let Ok(LedgerOperation::QuorumBegin {
            new_outpoint_txid,
            new_outpoint_vout,
            amount,
            collateral_amount,
            ..
        }) = LedgerOperation::tlv_decode(&qb.message)
        else {
            return Err("receiver_quorum_begin is not a QuorumBegin".into());
        };
        match self.wallet.get_outpoint_value_and_confs(
            bitcoin::Txid::from_byte_array(new_outpoint_txid),
            new_outpoint_vout,
        ) {
            Ok(Some((sats, confs))) if confs > 0 && sats == (amount + collateral_amount) / 1000 => {
                Ok(())
            }
            Ok(_) => Err("the receiver's vault is not funded and unspent on chain".into()),
            Err(e) => Err(format!("the receiver's vault cannot be checked: {e}")),
        }
    }

    pub(crate) async fn process_dormancy_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> Reply {
        // The operator's own CLI only: these append and credit on our ledger.
        let (ours, _) = self.node_id.x_only_public_key();
        if request.sender != hex::encode(ours.serialize()) {
            return err("dormancy actions are the operator's own");
        }
        let p = &request.params;
        let ledger_id = request.ledger_id.clone();
        let height = self.wallet.get_block_height().unwrap_or(0);
        let state = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&ledger_id) {
                Some(arc) => arc.read().unwrap().state.clone(),
                None => {
                    return err(format!(
                        "Ledger not found: {}",
                        &ledger_id[..16.min(ledger_id.len())]
                    ))
                }
            }
        };
        let manifest_param =
            || -> Result<(Vec<u8>, Vec<deposits_core::messages::ManifestEntry>), String> {
                let b = p
                    .get("manifest")
                    .and_then(|v| v.as_str())
                    .and_then(|h| hex::decode(h).ok())
                    .ok_or("manifest (hex) required")?;
                let m = decode_manifest(&b)?;
                Ok((b, m))
            };
        match request.action.as_str() {
            "dormancy_offer" => {
                let m = state.dormancy_offer(height);
                let enc = encode_manifest(&m);
                let total: u64 = m.iter().map(|e| e.amount).sum();
                (
                    true,
                    Some(
                        serde_json::json!({
                            "manifest": hex::encode(&enc),
                            "manifest_hash": hex::encode(sha256::Hash::hash(&enc).to_byte_array()),
                            "total_msats": total,
                            "count": m.len(),
                        })
                        .to_string(),
                    ),
                    None,
                )
            }
            "dormancy_accept" => {
                let (bytes, _) = match manifest_param() {
                    Ok(x) => x,
                    Err(e) => return err(e),
                };
                let Some(total) = p.get("total_msats").and_then(|v| v.as_u64()) else {
                    return err("total_msats required");
                };
                let hash = sha256::Hash::hash(&bytes).to_byte_array();
                // Ruling 1: the address type of a DEP-10 offer — our operator key's P2WPKH.
                let spk = bitcoin::ScriptBuf::new_p2wpkh(
                    &bitcoin::CompressedPublicKey(self.node_id).wpubkey_hash(),
                );
                let offer_event_id: [u8; 32] = p
                    .get("offer_event_id")
                    .and_then(|v| v.as_str())
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0; 32]);
                let premium_deposit = p
                    .get("premium_deposit")
                    .and_then(|v| v.as_str())
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| b.try_into().ok());
                let expiry = p
                    .get("expiry_blocks")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(288) as u32;
                let op = LedgerOperation::DormancyAccept {
                    premium_deposit,
                    exit_address: spk.to_bytes(),
                    expires_at_height: height + expiry,
                    manifest_hash: hash,
                    offer_event_id,
                    accepted_total: total,
                };
                self.handler
                    .pending_migration_manifests
                    .lock()
                    .unwrap()
                    .insert(ledger_id.clone(), bytes);
                let r = self.commit_operation(&ledger_id, op).await;
                self.handler
                    .pending_migration_manifests
                    .lock()
                    .unwrap()
                    .remove(&ledger_id);
                if let Err(e) = r {
                    return err(format!("dormancy_accept failed: {e}"));
                }
                let accept = {
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    ledgers
                        .get(&ledger_id)
                        .and_then(|arc| arc.read().unwrap().history.last().cloned())
                };
                let Some(accept) = accept else {
                    return err("the accept is not in our history");
                };
                let address = bitcoin::Address::from_script(&spk, self.wallet.network())
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                (
                    true,
                    Some(
                        serde_json::json!({
                            "accept": hex::encode(accept.tlv_encode()),
                            "address": address,
                            "seq": accept.sequence_number,
                        })
                        .to_string(),
                    ),
                    None,
                )
            }
            "dormancy_notice" => {
                let Some(rotation_height) = p.get("rotation_height").and_then(|v| v.as_u64())
                else {
                    return err("rotation_height required");
                };
                let receiver = match p.get("receiver").and_then(|v| v.as_str()) {
                    None => None,
                    Some(h) => match hex::decode(h)
                        .ok()
                        .and_then(|b| bitcoin::secp256k1::PublicKey::from_slice(&b).ok())
                    {
                        Some(pk) => Some(pk),
                        None => return err("receiver: bad pubkey"),
                    },
                };
                let (manifest_hash, migration_manifest) = if receiver.is_some() {
                    match manifest_param() {
                        Ok((b, m)) => (Some(sha256::Hash::hash(&b).to_byte_array()), m),
                        Err(e) => return err(e),
                    }
                } else {
                    (None, Vec::new())
                };
                let dormancy_accept = p
                    .get("accept")
                    .and_then(|v| v.as_str())
                    .and_then(|h| hex::decode(h).ok());
                // L4: the receiver's governing QuorumBegin (the latest before the accept).
                let receiver_quorum_begin =
                    match &dormancy_accept {
                        None => None,
                        Some(b) => {
                            use deposits_core::TlvDecode;
                            let Ok(au) = deposits_core::SignedLedgerUpdate::tlv_decode(b) else {
                                return err("accept does not decode");
                            };
                            let hist = self.receiver_history(&hex::encode(au.ledger_id)).await;
                            match hist.iter().rfind(|u| {
                                u.sequence_number < au.sequence_number
                                    && matches!(
                                        LedgerOperation::tlv_decode(&u.message),
                                        Ok(LedgerOperation::QuorumBegin { .. })
                                    )
                            }) {
                                Some(q) => Some(q.tlv_encode()),
                                None => return err(
                                    "the receiver's ledger has no QuorumBegin before the accept",
                                ),
                            }
                        }
                    };
                let op = LedgerOperation::DormancyNotice {
                    rotation_height: rotation_height as u32,
                    migration_receiver: receiver,
                    manifest_hash,
                    migration_manifest,
                    dormancy_accept,
                    premium: p.get("premium_msats").and_then(|v| v.as_u64()),
                    receiver_quorum_begin,
                };
                match self.commit_operation(&ledger_id, op).await {
                    Ok(h) => (
                        true,
                        Some(serde_json::json!({"content_hash": h}).to_string()),
                        None,
                    ),
                    Err(e) => err(format!("dormancy_notice failed: {e}")),
                }
            }
            "dormancy_credit" => {
                let (_, manifest) = match manifest_param() {
                    Ok(x) => x,
                    Err(e) => return err(e),
                };
                let Some(accept) = state.dormancy_accept.clone() else {
                    return err("no outstanding accept");
                };
                // Display txid, as bitcoind prints it; the ledger names the internal order.
                let Some(txid) = p
                    .get("txid")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<bitcoin::Txid>().ok())
                    .map(|t| t.to_byte_array())
                else {
                    return err("txid required");
                };
                let Some(vout) = p.get("vout").and_then(|v| v.as_u64()) else {
                    return err("vout required");
                };
                let marker = migration_marker(&accept.manifest_hash);
                let mut credits: Vec<(deposits_core::types::DepositId, u64)> =
                    manifest.iter().map(|e| (e.deposit_id, e.amount)).collect();
                let premium = p.get("premium_msats").and_then(|v| v.as_u64()).unwrap_or(0);
                if premium > 0 {
                    if let Some(d) = accept.premium_deposit {
                        credits.push((d, premium));
                    }
                }
                for e in &manifest {
                    if !state.deposits.contains_key(&e.deposit_id) {
                        let op = LedgerOperation::DepositOpen {
                            deposit_id: e.deposit_id,
                            descriptor: e.descriptor.clone(),
                            fees: Some(e.fees.clone()),
                            transfer_fees: None,
                            payment_hash: None,
                            invoice: None,
                            cosigner_guarantee_signature: None,
                            receive_requires_sig: false,
                            fee_change_after_blocks: None,
                            fee_change_notice_blocks: None,
                            fee_change_limit_bps: None,
                            commitment: None,
                        };
                        if let Err(e) = self.commit_operation(&ledger_id, op).await {
                            return err(format!("dormancy_credit: DepositOpen failed: {e}"));
                        }
                    }
                }
                for (deposit_id, amount) in credits {
                    let op = LedgerOperation::OnchainCredit {
                        txid,
                        vout: vout as u32,
                        deposit_id,
                        amount,
                        funding_address: marker.clone(),
                        commitment: None,
                    };
                    if let Err(e) = self.commit_operation(&ledger_id, op).await {
                        return err(format!("dormancy_credit: OnchainCredit failed: {e}"));
                    }
                }
                (
                    true,
                    Some(serde_json::json!({"credited": true}).to_string()),
                    None,
                )
            }
            a => err(format!("unknown dormancy action {a}")),
        }
    }
}
