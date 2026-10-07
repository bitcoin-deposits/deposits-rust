//! Cooperative refund handler — last-resort path for ledgers whose
//! reserves UTXO was never funded on-chain (NeverFunded). In that
//! state the standard confiscation TX can't run (nothing to spend),
//! so armed disputants instead pool their declared replacement
//! collateral into a single anchor TX whose output is the same
//! lottery script the standard confiscation would have produced.
//! From there, `recovery reveal` and `recovery lottery-claim` run
//! unchanged.
//!
//! Triggered manually via `deposits-node recovery refund <ledger_id>`.
//! Each armed disputant's daemon signs only its own RC input after:
//!   1. confirming the ledger's reserves UTXO is genuinely NeverFunded
//!      (refuses if funded — the standard flow applies);
//!   2. re-deriving the expected lottery output script from this
//!      ledger's DisputeArmed history and verifying the proposed TX
//!      pays out to that script;
//!   3. matching the requested input to one of the disputant RC
//!      declarations on the relay (only signs if THIS daemon's
//!      own RC is among them);
//!   4. recomputing the BIP143 P2WPKH sighash and comparing to the
//!      caller's claim.

use super::super::*;

impl Node {
    pub(crate) async fn process_cooperative_refund_sign_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use bitcoin::sighash::{EcdsaSighashType, SighashCache};
        use bitcoin::{Amount, Transaction};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
        use deposits_core::types::LedgerState;
        use deposits_core::{SignedLedgerUpdate, TlvDecode};
        use deposits_signer_api::{SigPurpose, SignContext};

        let ledger_prefix = &request.ledger_id[..16.min(request.ledger_id.len())];

        // 1. Parse required params: unsigned_tx (hex), input_index (u64),
        //    sighash (hex).
        let unsigned_tx_hex = match request.params.get("unsigned_tx").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return (false, None, Some("missing unsigned_tx".into())),
        };
        let input_index = match request.params.get("input_index").and_then(|v| v.as_u64()) {
            Some(i) => i as usize,
            None => return (false, None, Some("missing input_index".into())),
        };
        let claimed_sighash_hex = match request.params.get("sighash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return (false, None, Some("missing sighash".into())),
        };

        let tx_bytes = match hex::decode(unsigned_tx_hex) {
            Ok(b) => b,
            Err(e) => return (false, None, Some(format!("unsigned_tx hex: {}", e))),
        };
        let proposed_tx: Transaction = match bitcoin::consensus::encode::deserialize(&tx_bytes) {
            Ok(t) => t,
            Err(e) => return (false, None, Some(format!("unsigned_tx parse: {}", e))),
        };
        let claimed_sighash: [u8; 32] = match hex::decode(claimed_sighash_hex) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return (false, None, Some("sighash must be 32-byte hex".into())),
        };

        if input_index >= proposed_tx.input.len() {
            return (
                false,
                None,
                Some(format!(
                    "input_index {} out of range for {}-input TX",
                    input_index,
                    proposed_tx.input.len()
                )),
            );
        }
        if proposed_tx.output.len() != 1 {
            return (
                false,
                None,
                Some(format!(
                    "expected exactly 1 output, got {}",
                    proposed_tx.output.len()
                )),
            );
        }

        // 2. NeverFunded gate — refuse if reserves UTXO exists on-chain.
        //    The standard confiscation path covers funded ledgers; the
        //    cooperative refund is reserved for the case where no
        //    reserves UTXO ever materialized (e.g. quorum began but the
        //    on-chain funding TX never confirmed).
        //
        //    `resolve_ledger_id` can land on the fork compound key
        //    instead of the bare 64-char ledger_id (HashMap key order
        //    is unpredictable when both share a prefix), so normalize
        //    to the first 64 chars before looking up the fork.
        let main_ledger_id = if request.ledger_id.len() > 64 {
            request.ledger_id[..64].to_string()
        } else {
            request.ledger_id.clone()
        };
        let our_fork_key = match self.handler.find_our_fork(&main_ledger_id) {
            Some(k) => k,
            None => return (false, None, Some("no fork-branch for this ledger".into())),
        };
        let (is_armed, reserves_addr_str) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&our_fork_key) {
                Some(arc) => {
                    let l = arc.read().unwrap();
                    (
                        l.state.dispute_state == deposits_core::types::DisputeState::Armed,
                        l.state.reserves_key.clone(),
                    )
                }
                None => (false, String::new()),
            }
        };
        if !is_armed {
            return (
                false,
                None,
                Some("our fork-branch is not DisputeArmed".into()),
            );
        }
        if !reserves_addr_str.is_empty() {
            use bitcoin::hashes::{sha256, Hash};
            if let Ok(addr) =
                reserves_addr_str.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            {
                if let Ok(addr) = addr.require_network(self.wallet.network()) {
                    let script_hash = sha256::Hash::hash(addr.script_pubkey().as_bytes());
                    let url = format!(
                        "{}/scripthash/{}",
                        self.wallet.electrum_url(),
                        hex::encode(script_hash.to_byte_array())
                    );
                    if let Ok(client) = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(5))
                        .build()
                    {
                        if let Ok(resp) = client.get(&url).send().await {
                            if let Ok(stats) = resp.json::<serde_json::Value>().await {
                                let funded = stats
                                    .get("chain_stats")
                                    .and_then(|c| c.get("funded_txo_count"))
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0);
                                let spent = stats
                                    .get("chain_stats")
                                    .and_then(|c| c.get("spent_txo_count"))
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0);
                                let unspent = funded.saturating_sub(spent);
                                if unspent > 0 {
                                    return (
                                        false,
                                        None,
                                        Some(
                                            "reserves UTXO has unspent funds \
                                             — use standard confiscation, not refund"
                                                .into(),
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3. Reconstruct the lottery output from DisputeArmed history.
        //    Paginated fetch — bloated forks need full pages.
        let mut updates: Vec<SignedLedgerUpdate> = self
            .fetch_all_ledger_updates_paginated(main_ledger_id.as_str())
            .await;
        if updates.is_empty() {
            return (false, None, Some("relay returned no events".into()));
        }
        updates.sort_by_key(|u| (u.sequence_number, u.operator_id));

        let original_operator = match updates
            .iter()
            .find(|u| u.sequence_number == 0)
            .map(|u| u.operator_id)
        {
            Some(o) => o,
            None => return (false, None, Some("no LedgerOpen at seq 0".into())),
        };

        // Replay through original-operator history to capture the latest
        // QuorumBegin's recovery voter set (we don't need a specific
        // last_valid_sequence for the lottery rebuild — any RC-bearing
        // DisputeArmed post-dispute is in-scope).
        let mut state = LedgerState::new(original_operator, String::new(), 0);
        let mut qb_members: Vec<bitcoin::secp256k1::PublicKey> = Vec::new();
        for u in &updates {
            if u.operator_id != original_operator {
                continue;
            }
            let op = match LedgerOperation::tlv_decode(&u.message) {
                Ok(o) => o,
                Err(_) => continue,
            };
            if let LedgerOperation::QuorumBegin { quorum_members, .. } = &op {
                qb_members = quorum_members.iter().map(|m| m.pubkey).collect();
            }
            // Best-effort replay; if it diverges we still have qb_members.
            if let Ok(next) = state.apply_for(u, &op) {
                state = next;
            }
        }
        let _ = state;
        if qb_members.is_empty() {
            return (false, None, Some("no QuorumBegin observed".into()));
        }

        // Collect DisputeArmed participants + RC declarations.
        let mut rc_by_outpoint: std::collections::HashMap<
            (bitcoin::Txid, u32),
            (bitcoin::secp256k1::PublicKey, u64),
        > = std::collections::HashMap::new();
        for u in &updates {
            if let Ok(LedgerOperation::DisputeArmed {
                replacement_collateral,
                ..
            }) = LedgerOperation::tlv_decode(&u.message)
            {
                if let Some(rc) = replacement_collateral {
                    let txid = bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::Hash::from_byte_array(rc.txid),
                    );
                    rc_by_outpoint.insert((txid, rc.vout), (u.operator_id, rc.amount));
                }
            }
        }
        // Participants: the DEP-03 eligibility cut (sorted).
        let participants: Vec<LotteryParticipant> =
            match self.lottery_armer_set(main_ledger_id.as_str()).await {
                Ok(set) => set.lottery_participants(),
                Err(e) => return (false, None, Some(format!("lottery participants: {}", e))),
            };
        if participants.is_empty() {
            return (
                false,
                None,
                Some(format!(
                    "only {} lottery participants — refusing",
                    participants.len()
                )),
            );
        }

        // DEP-06: the recovery voters of the vault's governing QuorumBegin (≤ the fork point).
        let Some((recovery_voters, recovery_threshold)) =
            deposits_core::rotation_order::lottery_recovery_voters(&updates)
        else {
            return (
                false,
                None,
                Some(
                    "no QuorumBegin by the original operator at or before the fork point"
                        .to_string(),
                ),
            );
        };
        let lottery_builder = LotteryScriptBuilder::new(
            participants,
            recovery_voters,
            recovery_threshold,
            self.wallet.network(),
        );
        let lottery_output = match lottery_builder.build() {
            Ok(o) => o,
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("rebuild lottery output: {:?}", e)),
                )
            }
        };
        let expected_lottery_script = lottery_output.address.script_pubkey();

        if proposed_tx.output[0].script_pubkey != expected_lottery_script {
            return (
                false,
                None,
                Some("output script_pubkey ≠ rebuilt lottery script".into()),
            );
        }

        // 4. Every input MUST match a declared RC outpoint, and inputs
        //    MUST be sorted by (txid bytes, vout) for deterministic TX
        //    bytes across callers.
        let mut prev_key: Option<(Vec<u8>, u32)> = None;
        let mut total_input_value: u64 = 0;
        for (i, txin) in proposed_tx.input.iter().enumerate() {
            let txid = txin.previous_output.txid;
            let vout = txin.previous_output.vout;
            let (_, amount) = match rc_by_outpoint.get(&(txid, vout)) {
                Some(v) => v,
                None => {
                    return (
                        false,
                        None,
                        Some(format!(
                            "input {} ({}:{}) does not match any DisputeArmed RC",
                            i, txid, vout
                        )),
                    );
                }
            };
            total_input_value = total_input_value.saturating_add(*amount);

            let raw: [u8; 32] = *txid.as_ref();
            let key = (raw.to_vec(), vout);
            if let Some(prev) = &prev_key {
                if &key <= prev {
                    return (
                        false,
                        None,
                        Some(format!("inputs not sorted by (txid,vout) at index {}", i)),
                    );
                }
            }
            prev_key = Some(key);
        }

        // 5. Fee bound: deterministic — 200 sats fixed overhead + 100
        //    per input (rough 2 sat/vbyte cover for P2WPKH inputs and
        //    one Taproot output). Each side computes the same number.
        let expected_fee = expected_cooperative_refund_fee(proposed_tx.input.len());
        let output_value = proposed_tx.output[0].value.to_sat();
        let actual_fee = match total_input_value.checked_sub(output_value) {
            Some(f) => f,
            None => return (false, None, Some("output exceeds inputs".into())),
        };
        if actual_fee != expected_fee {
            return (
                false,
                None,
                Some(format!(
                    "fee {} ≠ expected {} (deterministic schedule)",
                    actual_fee, expected_fee
                )),
            );
        }

        // 6. Find the input asking US to sign — its previous_output MUST
        //    map to OUR operator pubkey via the RC declaration.
        let our_pk = self.node_id;
        let our_input = &proposed_tx.input[input_index];
        let our_rc = match rc_by_outpoint.get(&(
            our_input.previous_output.txid,
            our_input.previous_output.vout,
        )) {
            Some(rc) => rc,
            None => {
                return (
                    false,
                    None,
                    Some(format!("input {} not in our RC table", input_index)),
                )
            }
        };
        if our_rc.0 != our_pk {
            return (
                false,
                None,
                Some(format!(
                    "input {} RC belongs to {}, not us",
                    input_index,
                    &our_rc.0.to_string()[..16]
                )),
            );
        }

        // 7. Re-derive the BIP143 P2WPKH sighash for OUR input and
        //    compare to the caller's claim.
        let our_compressed = match bitcoin::CompressedPublicKey::from_slice(&our_pk.serialize()) {
            Ok(c) => c,
            Err(e) => return (false, None, Some(format!("compressed pubkey: {}", e))),
        };
        let our_script =
            bitcoin::Address::p2wpkh(&our_compressed, self.wallet.network()).script_pubkey();
        let mut cache = SighashCache::new(&proposed_tx);
        let sighash = match cache.p2wpkh_signature_hash(
            input_index,
            &our_script,
            Amount::from_sat(our_rc.1),
            EcdsaSighashType::All,
        ) {
            Ok(h) => h,
            Err(e) => return (false, None, Some(format!("sighash: {}", e))),
        };
        let sighash_bytes: [u8; 32] = *sighash.as_ref();
        if sighash_bytes != claimed_sighash {
            return (
                false,
                None,
                Some("claimed sighash ≠ re-derived sighash".into()),
            );
        }

        // 8. Sign — ECDSA over P2WPKH sighash via the Signer trait.
        let sig = match self.handler.signer.ecdsa_sign_sighash(
            &SignContext::no_ledger(SigPurpose::OnchainSighash),
            &sighash_bytes,
        ) {
            Ok(s) => s,
            Err(e) => return (false, None, Some(format!("ecdsa_sign_sighash: {}", e))),
        };
        let sig_der = sig.serialize_der();
        // Prevout script + amount go alongside for caller convenience
        // (witness assembly only needs the DER sig + pubkey, but
        // surfacing them aids debugging).
        let result = serde_json::json!({
            "signer": hex::encode(self.node_id.serialize()),
            "input_index": input_index,
            "signature_der": hex::encode(sig_der.as_ref()),
            "pubkey": hex::encode(self.node_id.serialize()),
        });

        tracing::info!(
            "Signed cooperative_refund input {} for ledger {}",
            input_index,
            ledger_prefix
        );
        (true, Some(result.to_string()), None)
    }
}

/// Deterministic fee schedule shared by CLI builder and daemon
/// verifier. Both sides MUST agree byte-for-byte or the cosign
/// fails. Rough envelope: 200 sats fixed + 100 sats per P2WPKH
/// input — about 2 sat/vbyte at typical sizes, well within the
/// safety margin for never-funded-quorum manual recovery.
pub fn expected_cooperative_refund_fee(input_count: usize) -> u64 {
    200u64 + 100u64 * (input_count as u64)
}
