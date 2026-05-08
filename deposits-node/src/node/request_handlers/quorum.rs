//! Quorum request handlers — split out of the monolithic
//! request_handlers.rs. See the sibling mod.rs.

use super::super::*;

impl Node {
    pub(crate) async fn process_quorum_add_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!(
            "Processing quorum_add request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        let member_pubkey_hex = match request.params.get("member_pubkey").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("Missing member_pubkey parameter".to_string()),
                )
            }
        };
        let member_ledger_id = match request
            .params
            .get("member_ledger_id")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing member_ledger_id parameter".to_string()),
                )
            }
        };

        let quorum_member = match PublicKey::from_str(member_pubkey_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid member_pubkey: {}", e))),
        };

        if member_ledger_id.len() != 64 || !member_ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            return (
                false,
                None,
                Some("member_ledger_id must be 64 hex chars".to_string()),
            );
        }

        // Resolve ledger_id
        let ledger_id = if request.ledger_id.len() == 64
            && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            request.ledger_id.clone()
        } else {
            match self.get_ledger_by_reserves_key(&request.ledger_id) {
                Some((_, ledger)) => ledger.ledger_id_hex(),
                None => {
                    return (
                        false,
                        None,
                        Some(format!("Ledger not found: {}", &request.ledger_id[..16])),
                    )
                }
            }
        };

        // Extract fee limits the member is imposing (from their advertisement)
        let min_fee_bps = request
            .params
            .get("min_fee_bps")
            .and_then(|v| v.as_u64())
            .map(|v| v as u16);
        let min_fee_fixed = request.params.get("min_fee_fixed").and_then(|v| v.as_u64());
        let max_fee_period = request
            .params
            .get("max_fee_period")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        // Extract membership duration from request
        let membership_until = request
            .params
            .get("membership_until")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        // Resolve the ruleset this quorum will be locked into. For an initial
        // QuorumAdd before any QuorumBegin, our ledger's `active_ruleset_name`
        // may still be the default — that's fine, the member just signs the
        // value we propose, and a later QuorumBegin reaffirms it.
        let chosen_ruleset = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&ledger_id) {
                Some(arc) => arc.read().unwrap().state.active_ruleset_name.clone(),
                None => "legacy".to_string(),
            }
        };

        let proposed_terms = crate::node::coordination::ConsentProposedTerms {
            chosen_ruleset: &chosen_ruleset,
            min_fee_bps,
            min_fee_fixed,
            max_fee_period,
            membership_until,
        };

        // Request consent from the member — they sign and record QuorumJoin
        let consent_result = match self
            .request_consent(&member_ledger_id, &ledger_id, proposed_terms)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Consent request failed: {}", e);
                return (false, None, Some(format!("Member consent failed: {}", e)));
            }
        };

        match self
            .add_quorum_member(
                &ledger_id,
                quorum_member,
                &member_ledger_id,
                consent_result.consent_signature,
                min_fee_bps,
                min_fee_fixed,
                max_fee_period,
                membership_until,
                consent_result.member_response,
                consent_result.member_signature,
            )
            .await
        {
            Ok(event_id) => {
                let result = serde_json::json!({
                    "status": "SUCCESS",
                    "event_id": event_id,
                    "member": member_pubkey_hex,
                    "member_ledger_id": member_ledger_id,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("quorum_add failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    pub(crate) async fn process_quorum_remove_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        let member_pubkey_hex = match request.params.get("member_pubkey").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("Missing member_pubkey parameter".to_string()),
                )
            }
        };

        let quorum_member = match PublicKey::from_str(member_pubkey_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid member_pubkey: {}", e))),
        };

        let ledger_id = &request.ledger_id;

        tracing::info!(
            "Removing quorum member {}... from ledger {}...",
            &member_pubkey_hex[..16.min(member_pubkey_hex.len())],
            &ledger_id[..16.min(ledger_id.len())]
        );

        let operation = LedgerOperation::QuorumRemoveMember {
            quorum_member,
            operator_signature: [0u8; 64], // filled by commit_operation
        };

        match self.commit_operation(ledger_id, operation).await {
            Ok(_) => {
                tracing::info!(
                    "Quorum member removed: {}...",
                    &member_pubkey_hex[..16.min(member_pubkey_hex.len())]
                );
                let result = serde_json::json!({ "removed": member_pubkey_hex });
                (true, Some(result.to_string()), None)
            }
            Err(e) => (
                false,
                None,
                Some(format!("Failed to remove quorum member: {}", e)),
            ),
        }
    }

    pub(crate) async fn process_quorum_join_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!(
            "Processing quorum_join request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        let target_operator_hex = match request
            .params
            .get("target_operator")
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("Missing target_operator parameter".to_string()),
                )
            }
        };
        let target_ledger_id = match request
            .params
            .get("target_ledger_id")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing target_ledger_id parameter".to_string()),
                )
            }
        };
        let membership_expires = match request
            .params
            .get("membership_expires")
            .and_then(|v| v.as_u64())
        {
            Some(v) => v as u32,
            None => {
                return (
                    false,
                    None,
                    Some("Missing membership_expires parameter".to_string()),
                )
            }
        };

        let target_operator = match PublicKey::from_str(target_operator_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid target_operator: {}", e))),
        };

        if target_ledger_id.len() != 64 || !target_ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            return (
                false,
                None,
                Some("target_ledger_id must be 64 hex chars".to_string()),
            );
        }

        // Resolve our ledger_id
        let our_ledger_id = if request.ledger_id.len() == 64
            && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            request.ledger_id.clone()
        } else {
            match self.get_ledger_by_reserves_key(&request.ledger_id) {
                Some((_, ledger)) => ledger.ledger_id_hex(),
                None => {
                    return (
                        false,
                        None,
                        Some(format!("Ledger not found: {}", &request.ledger_id[..16])),
                    )
                }
            }
        };

        // Sign consent: COLLATERAL_CONSENT || operator_pubkey(33 bytes) || ledger_id(string bytes)
        let _signature = {
            use bitcoin::hashes::{sha256, Hash};
            use deposits_signer_api::{SigPurpose, SignContext};

            let mut sign_content = Vec::new();
            sign_content.extend_from_slice(b"COLLATERAL_CONSENT");
            sign_content.extend_from_slice(&target_operator.serialize());
            sign_content.extend_from_slice(target_ledger_id.as_bytes());

            let hash = sha256::Hash::hash(&sign_content);
            match self.handler.signer.bip340_sign(
                &SignContext::no_ledger(SigPurpose::Bip340Untagged),
                hash.as_byte_array(),
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    return (
                        false,
                        None,
                        Some(format!("collateral consent sign: {}", e)),
                    )
                }
            }
        };

        match self
            .record_quorum_join(
                &our_ledger_id,
                target_operator,
                &target_ledger_id,
                membership_expires,
            )
            .await
        {
            Ok(event_id) => {
                let result = serde_json::json!({
                    "status": "SUCCESS",
                    "event_id": event_id,
                    "target_operator": target_operator_hex,
                    "target_ledger_id": target_ledger_id,
                    "membership_expires": membership_expires,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("quorum_join failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    /// Handle a consent_request from an operator wanting us to join their quorum.
    ///
    /// Auto-consents: signs the consent content, records QuorumJoin on our ledger,
    /// and returns the signature so the operator can record QuorumAddMember.
    pub(crate) async fn process_consent_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        // The relay broadcasts kind:20101 events to every interested
        // subscriber, and our consent-time piggyback adds the operator's
        // ledger to our interested set. As a side effect, future
        // consent_requests targeting that operator's *member* ledger also
        // reach us — we'd then try to record QuorumJoin on a ledger we
        // don't operate, which the state machine rejects with
        // `quorum_join_wrong_role`. Drop silently when we're not the
        // intended recipient.
        if !self.is_operator_of_ledger(&request.ledger_id) {
            tracing::debug!(
                "Ignoring consent_request for ledger {}... (not our operator ledger)",
                &request.ledger_id[..16.min(request.ledger_id.len())]
            );
            return (false, None, None);
        }

        tracing::info!(
            "Processing consent_request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        let operator_pubkey_hex = match request
            .params
            .get("operator_pubkey")
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("Missing operator_pubkey parameter".to_string()),
                )
            }
        };
        let operator_ledger_id = match request
            .params
            .get("operator_ledger_id")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing operator_ledger_id parameter".to_string()),
                )
            }
        };

        let operator_pubkey = match PublicKey::from_str(operator_pubkey_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid operator_pubkey: {}", e))),
        };

        if operator_ledger_id.len() != 64
            || !operator_ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            return (
                false,
                None,
                Some("operator_ledger_id must be 64 hex chars".to_string()),
            );
        }

        // Validate the operator's ledger before consenting. The operator
        // piggybacks its full update history in `ledger_history`; we decode,
        // validate the chain via LedgerConformanceValidator (inside
        // import_ledger), and only sign if the ledger is well-formed and the
        // claimed operator_pubkey/operator_ledger_id match what's in the
        // genesis. Without this gate a member would attest blind, and the
        // dispute path later can't fork a ledger we never imported.
        {
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
            use deposits_core::messages::LedgerOperation;
            use deposits_core::validation::LedgerExport;
            use deposits_core::types::SignedLedgerUpdate;
            use deposits_core::types::LedgerState;
            use deposits_core::{TlvDecode, TlvEncode as _};

            let history_b64 = match request.params.get("ledger_history") {
                Some(serde_json::Value::Array(arr)) => arr,
                _ => {
                    return (
                        false,
                        None,
                        Some(
                            "Missing ledger_history (operator must piggyback ledger updates)"
                                .to_string(),
                        ),
                    );
                }
            };

            let mut updates: Vec<SignedLedgerUpdate> = Vec::with_capacity(history_b64.len());
            for (i, entry) in history_b64.iter().enumerate() {
                let s = match entry.as_str() {
                    Some(s) => s,
                    None => {
                        return (
                            false,
                            None,
                            Some(format!("ledger_history[{}] is not a string", i)),
                        );
                    }
                };
                let bytes = match BASE64.decode(s) {
                    Ok(b) => b,
                    Err(e) => {
                        return (
                            false,
                            None,
                            Some(format!("ledger_history[{}] base64 decode failed: {}", i, e)),
                        );
                    }
                };
                match SignedLedgerUpdate::tlv_decode(&bytes) {
                    Ok(u) => updates.push(u),
                    Err(e) => {
                        return (
                            false,
                            None,
                            Some(format!("ledger_history[{}] tlv decode failed: {:?}", i, e)),
                        );
                    }
                }
            }

            // Genesis must be the first update and a LedgerOpen.
            let (claimed_operator, reserves_id, genesis_block) = match updates.first() {
                Some(u) => match LedgerOperation::tlv_decode(&u.message) {
                    Ok(LedgerOperation::LedgerOpen {
                        operator_id,
                        reserves_id,
                        genesis_block,
                        ..
                    }) => (operator_id, reserves_id, genesis_block),
                    _ => {
                        return (
                            false,
                            None,
                            Some(
                                "ledger_history[0] must be a LedgerOpen operation".to_string(),
                            ),
                        );
                    }
                },
                None => {
                    return (
                        false,
                        None,
                        Some("ledger_history is empty (no LedgerOpen)".to_string()),
                    );
                }
            };

            // The claimed operator_pubkey must match the LedgerOpen's operator_id.
            if claimed_operator != operator_pubkey {
                return (
                    false,
                    None,
                    Some(format!(
                        "operator_pubkey mismatch: param={}, LedgerOpen={}",
                        operator_pubkey_hex,
                        hex::encode(claimed_operator.serialize())
                    )),
                );
            }

            // The computed ledger_id must match the claimed operator_ledger_id.
            let computed_ledger_id = LedgerState::compute_ledger_id(
                &claimed_operator,
                &reserves_id,
                genesis_block,
            );
            if hex::encode(computed_ledger_id) != operator_ledger_id {
                return (
                    false,
                    None,
                    Some(format!(
                        "operator_ledger_id mismatch: param={}, computed={}",
                        operator_ledger_id,
                        hex::encode(computed_ledger_id)
                    )),
                );
            }

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let export = LedgerExport::new(
                computed_ledger_id,
                genesis_block,
                claimed_operator,
                reserves_id,
                updates,
                block_height,
            );

            if let Err(e) = self.handler.import_ledger(export) {
                return (
                    false,
                    None,
                    Some(format!(
                        "Refusing consent: operator's ledger failed validation: {}",
                        e
                    )),
                );
            }
            tracing::info!(
                "Validated and imported operator ledger {}... before consenting",
                &operator_ledger_id[..16]
            );
            self.ensure_actor_for(&operator_ledger_id);
        }

        // Sign consent: COLLATERAL_CONSENT || operator_pubkey(33 bytes) || ledger_id(string bytes)
        let mut sign_content = Vec::new();
        sign_content.extend_from_slice(b"COLLATERAL_CONSENT");
        sign_content.extend_from_slice(&operator_pubkey.serialize());
        sign_content.extend_from_slice(operator_ledger_id.as_bytes());

        let signature = {
            use bitcoin::hashes::{sha256, Hash};
            use deposits_signer_api::{SigPurpose, SignContext};

            let hash = sha256::Hash::hash(&sign_content);
            match self.handler.signer.bip340_sign(
                &SignContext::no_ledger(SigPurpose::Bip340Untagged),
                hash.as_byte_array(),
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    return (
                        false,
                        None,
                        Some(format!("collateral consent sign: {}", e)),
                    )
                }
            }
        };

        // Q1: build + sign the canonical QuorumMemberResponse blob carrying
        // chosen ruleset and member terms. Operator-proposed terms are echoed
        // straight back; future Q2 work lets the member negotiate them.
        let chosen_ruleset = request
            .params
            .get("chosen_ruleset")
            .and_then(|v| v.as_str())
            .unwrap_or("legacy")
            .to_string();

        // Refuse to attest to a ruleset this binary can't enforce. Without
        // this gate a member could silently sign a blob promising semantics
        // it has no implementation for, and the resulting QuorumBegin would
        // be invalid against this peer at every later validation step.
        if deposits_core::ruleset::lookup(&chosen_ruleset).is_none() {
            return (
                false,
                None,
                Some(format!(
                    "Refusing consent: operator proposed ruleset '{}' which this node does not support (supports: {:?})",
                    chosen_ruleset,
                    deposits_core::ruleset::all_supported_names()
                )),
            );
        }
        let proposed_min_fee_bps = request
            .params
            .get("min_fee_bps")
            .and_then(|v| v.as_u64())
            .map(|v| v as u16);
        let proposed_min_fee_fixed = request.params.get("min_fee_fixed").and_then(|v| v.as_u64());
        let proposed_max_fee_period = request
            .params
            .get("max_fee_period")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let proposed_membership_until = request
            .params
            .get("membership_until")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let our_pubkey = match PublicKey::from_str(&self.node_id_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("our pubkey: {}", e))),
        };
        let response_blob = {
            use deposits_core::types::{
                QuorumMemberResponse, QUORUM_MEMBER_RESPONSE_VERSION,
            };
            use deposits_core::TlvEncode as _;
            let supported_rulesets: Vec<String> =
                deposits_core::ruleset::all_supported_names()
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
            let r = QuorumMemberResponse {
                response_version: QUORUM_MEMBER_RESPONSE_VERSION,
                member_pubkey: our_pubkey,
                operator_pubkey,
                operator_ledger_id: operator_ledger_id.clone(),
                chosen_ruleset,
                supported_rulesets,
                member_ledger_id: request.ledger_id.clone(),
                min_fee_bps: proposed_min_fee_bps,
                min_fee_fixed: proposed_min_fee_fixed,
                max_fee_period: proposed_max_fee_period,
                membership_until: proposed_membership_until,
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
                compensation_bps: None,
                compensation_deposit_id: None,
                compensation_frequency_blocks: None,
            };
            r.tlv_encode()
        };
        let response_signature = {
            use deposits_core::types::quorum_member_response_digest;
            use deposits_signer_api::{SigPurpose, SignContext};
            let digest = quorum_member_response_digest(&response_blob);
            match self.handler.signer.bip340_sign(
                &SignContext::no_ledger(SigPurpose::Bip340Untagged),
                &digest,
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    return (
                        false,
                        None,
                        Some(format!("member response sign: {}", e)),
                    )
                }
            }
        };

        // Record QuorumJoin on our own ledger
        let our_ledger_id = request.ledger_id.clone();
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let membership_expires = current_block + 1000; // ~1 week at 10 min/block

        match self
            .record_quorum_join(
                &our_ledger_id,
                operator_pubkey,
                &operator_ledger_id,
                membership_expires,
            )
            .await
        {
            Ok(_event_id) => {
                // Subscribe to the operator's ledger so future cosign requests
                // (kind 20101 with #l = operator_ledger_id) aren't dropped by
                // the interested-ledgers filter before they reach the handler.
                self.nostr.add_interested_ledger(operator_ledger_id.clone());

                tracing::info!(
                    "Consent granted: recorded QuorumJoin for operator {}... on our ledger {}...",
                    &operator_pubkey_hex[..16.min(operator_pubkey_hex.len())],
                    &our_ledger_id[..16]
                );
                use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
                let result = serde_json::json!({
                    "status": "CONSENT_GRANTED",
                    "consent_signature": hex::encode(signature),
                    "membership_expires": membership_expires,
                    "member_response": BASE64.encode(&response_blob),
                    "member_signature": hex::encode(response_signature),
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("Failed to record QuorumJoin: {}", e);
                (
                    false,
                    None,
                    Some(format!("Failed to record QuorumJoin: {}", e)),
                )
            }
        }
    }

    pub(crate) async fn process_quorum_begin_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        tracing::info!(
            "Processing quorum_begin request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Resolve ledger_id
        let ledger_id = if request.ledger_id.len() == 64
            && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            request.ledger_id.clone()
        } else {
            match self.get_ledger_by_reserves_key(&request.ledger_id) {
                Some((_, ledger)) => ledger.ledger_id_hex(),
                None => {
                    return (
                        false,
                        None,
                        Some(format!("Ledger not found: {}", &request.ledger_id[..16])),
                    )
                }
            }
        };

        // Sync wallet to see current UTXOs
        if let Err(e) = self.wallet.sync() {
            tracing::warn!("Wallet sync failed before quorum_begin: {}", e);
        }

        // Optional collateral-ratio override. When set, the new
        // QuorumBegin uses this ratio (and it carries forward as
        // the new "current ratio" for subsequent rotations). When
        // unset, the ratio from state is preserved.
        let collateral_bps = request
            .params
            .get("collateral_bps")
            .and_then(|v| v.as_u64())
            .map(|v| v as u16);

        // Optional amount_sats — used only by the genesis path (no
        // legacy reserves UTXO). Ignored when rotating an existing
        // reserves UTXO; that path uses the existing UTXO's amount.
        let amount_sats = request
            .params
            .get("amount_sats")
            .and_then(|v| v.as_u64());

        // Optional protocol_version override. Falls back to the
        // ledger's currently-active ruleset if absent.
        let protocol_version = request
            .params
            .get("protocol_version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        match self
            .rotate_reserves_to_quorum(
                &ledger_id,
                collateral_bps,
                amount_sats,
                protocol_version.as_deref(),
            )
            .await
        {
            Ok(result) => {
                // commit_operation inside rotate_reserves_to_quorum already
                // broadcasts the cosigned update via Nostr, so no separate
                // broadcast_last_update is needed here.

                let response = serde_json::json!({
                    "status": "SUCCESS",
                    "txid": result.txid,
                    "new_address": result.new_address,
                    "amount_sats": result.amount_sats,
                    "quorum_member_count": result.quorum_member_count,
                    "quorum_expiry": result.quorum_expiry,
                    "ledger_hash": hex::encode(&result.ledger_hash[..8]),
                });
                (true, Some(response.to_string()), None)
            }
            Err(e) => {
                tracing::error!("quorum_begin failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

}
