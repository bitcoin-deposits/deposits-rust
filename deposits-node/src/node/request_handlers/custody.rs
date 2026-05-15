//! Custody request handlers — split out of the monolithic
//! request_handlers.rs. See the sibling mod.rs.

use super::super::*;

impl Node {
    pub(crate) async fn process_custody_transfer_sign_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use bitcoin::secp256k1::{Keypair, Message};
        use deposits_core::SignedLedgerUpdate;
        use nostr_sdk::prelude::*;

        tracing::info!("Processing custody_transfer_sign request...");

        // Extract required parameters
        let ledger_id = match request.params.get("ledger_id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return (false, None, Some("Missing ledger_id parameter".to_string())),
        };

        let sighash_hex = match request.params.get("sighash").and_then(|v| v.as_str()) {
            Some(h) => h.to_string(),
            None => return (false, None, Some("Missing sighash parameter".to_string())),
        };

        let _unsigned_tx_hex = match request.params.get("unsigned_tx").and_then(|v| v.as_str()) {
            Some(tx) => tx.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing unsigned_tx parameter".to_string()),
                )
            }
        };

        let new_custodian_hex = match request.params.get("new_custodian").and_then(|v| v.as_str()) {
            Some(c) => c.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing new_custodian parameter".to_string()),
                )
            }
        };

        let violation_details = match request
            .params
            .get("violation_details")
            .and_then(|v| v.as_str())
        {
            Some(d) => d.to_string(),
            None => {
                return (
                    false,
                    None,
                    Some("Missing violation_details parameter".to_string()),
                )
            }
        };

        let last_valid_sequence = match request
            .params
            .get("last_valid_sequence")
            .and_then(|v| v.as_u64())
        {
            Some(seq) => seq,
            None => {
                return (
                    false,
                    None,
                    Some("Missing last_valid_sequence parameter".to_string()),
                )
            }
        };

        // Parse sighash
        let sighash_bytes: [u8; 32] = match hex::decode(&sighash_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            Ok(_) => return (false, None, Some("Invalid sighash length".to_string())),
            Err(e) => return (false, None, Some(format!("Invalid sighash hex: {}", e))),
        };

        // Parse new custodian (validated but not directly used in signing)
        let _new_custodian: PublicKey = match new_custodian_hex.parse() {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid new_custodian: {}", e))),
        };

        tracing::info!("    Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
        tracing::info!(
            "    New custodian: {}...",
            &new_custodian_hex[..16.min(new_custodian_hex.len())]
        );
        tracing::info!(
            "    Violation: {}",
            &violation_details[..50.min(violation_details.len())]
        );

        // Use the node's operator key
        let our_pubkey = self.node_id;

        tracing::info!("    Our key: {}...", &our_pubkey.to_string()[..16]);

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(
                crate::nostr::TAG_LEDGER_ID,
                [crate::nostr::ledger_tag(ledger_id.as_str())],
            )
            .limit(500);

        let events = match client.fetch_events(vec![filter], None).await {
            Ok(e) => e,
            Err(e) => {
                return (false, None, Some(format!("Failed to fetch ledger: {}", e)));
            }
        };

        // Decode and validate updates
        let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    updates.push(update);
                }
            }
        }

        updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
        updates.dedup_by(|a, b| {
            a.sequence_number == b.sequence_number
                && a.operator_id == b.operator_id
                && a.content_hash == b.content_hash
        });

        // Find the original operator (the one who opened the ledger)
        let original_operator = updates
            .iter()
            .find(|u| u.sequence_number == 0)
            .map(|u| u.operator_id);

        let original_operator = match original_operator {
            Some(op) => op,
            None => {
                return (
                    false,
                    None,
                    Some("Could not find ledger genesis (sequence 0)".to_string()),
                )
            }
        };

        // Filter to only the original operator's updates for violation validation
        let original_updates: Vec<&SignedLedgerUpdate> = updates
            .iter()
            .filter(|u| u.operator_id == original_operator)
            .collect();

        // Verify the violation exists on the original operator's chain
        let mut last_valid_hash = [0u8; 32];
        let mut found_violation = false;
        let mut validated_sequence: i64 = -1;

        for update in &original_updates {
            let expected_seq = (validated_sequence + 1) as u64;
            if update.sequence_number != expected_seq && validated_sequence >= 0 {
                found_violation = true;
                break;
            }

            let expected_prev = if update.sequence_number == 0 {
                [0u8; 32]
            } else {
                last_valid_hash
            };

            if update.previous_hash != expected_prev {
                found_violation = true;
                break;
            }

            let computed_hash = update.compute_hash();
            if computed_hash != update.content_hash {
                found_violation = true;
                break;
            }

            last_valid_hash = update.content_hash;
            validated_sequence = update.sequence_number as i64;
        }

        if !found_violation {
            return (
                false,
                None,
                Some("Could not verify violation - ledger appears conforming".to_string()),
            );
        }

        // Verify that the last_valid_sequence matches our validation
        if validated_sequence != last_valid_sequence as i64 {
            return (
                false,
                None,
                Some(format!(
                    "Sequence mismatch: requester says {}, we validated {}",
                    last_valid_sequence, validated_sequence
                )),
            );
        }

        tracing::info!("    Violation verified at seq {}", validated_sequence + 1);

        // Verify we're a quorum member by checking the ledger operations
        let mut is_quorum_member = false;
        for update in updates.iter().take((validated_sequence + 1) as usize) {
            if let Ok(operation) = LedgerOperation::tlv_decode(&update.message) {
                if let LedgerOperation::QuorumAddMember { quorum_member, .. } = operation {
                    if quorum_member == our_pubkey {
                        is_quorum_member = true;
                    }
                }
            }
        }

        if !is_quorum_member {
            return (
                false,
                None,
                Some("We are not a quorum member for this ledger".to_string()),
            );
        }

        tracing::info!("    Verified: we are a quorum member");

        // Sign the sighash via the Signer (Tapscript script-spend on confiscation tx).
        use deposits_signer_api::{SigPurpose, SignContext};
        let signature_bytes = match self.handler.signer.bip340_sign(
            &SignContext::no_ledger(SigPurpose::OnchainSighash),
            &sighash_bytes,
        ) {
            Ok(s) => s,
            Err(e) => return (false, None, Some(format!("custody sighash sign: {}", e))),
        };

        tracing::info!(
            "    Signed sighash: {}...",
            &hex::encode(&signature_bytes[..4])
        );

        // Return the signature
        let result = serde_json::json!({
            "signer": self.node_id_hex.clone(),
            "signature": hex::encode(signature_bytes),
            "sighash": sighash_hex,
        });

        (true, Some(result.to_string()), None)
    }

    pub(crate) async fn process_confiscation_sign_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        tracing::info!(
            "Processing confiscation_sign request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]
        );

        // Extract sighash from request params
        let sighash_hex = match request.params.get("sighash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return (false, None, Some("Missing sighash parameter".to_string())),
        };

        let sighash_bytes: [u8; 32] = match hex::decode(sighash_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => return (false, None, Some("Invalid sighash format".to_string())),
        };

        // Check if we have an armed marker for this ledger (meaning we're participating in the dispute)
        let ledger_prefix = &request.ledger_id[..16.min(request.ledger_id.len())];
        let armed_marker = self
            .data_dir
            .join(format!("custody_armed_{}.marker", ledger_prefix));

        if !armed_marker.exists() {
            return (false, None, Some("Not armed for this dispute".to_string()));
        }

        // Per DEP-03 §"Replacement collateral declaration": before
        // signing the confiscation TX, every cosigner verifies that
        // every disputant's pledged replacement collateral satisfies
        // the post-takeover collateralization inequality. A cosigner
        // that observes any failure MUST refuse to sign — the dispute
        // stalls until the failing disputant amends their declaration
        // or the arm window closes them out.
        if let Err(reason) = self
            .verify_disputants_replacement_collateral(request)
            .await
        {
            tracing::warn!(
                "Refusing confiscation_sign for ledger {}: {}",
                ledger_prefix,
                reason
            );
            return (false, None, Some(reason));
        }

        // DEP-03 §"Respectful confiscation tx": before signing the
        // operator's proposed confiscation tx, the cosigner re-derives
        // the expected output structure (lottery script + optional
        // operator change) and the sighash, then verifies the operator's
        // proposal byte-for-byte. Without this, cosigners would
        // rubber-stamp whatever sighash arrives — and an operator could
        // reshape outputs to drain the UTXO into their own pubkey while
        // claiming the dispute resolved respectfully. Refuses (and
        // surfaces a structured reason) on any mismatch.
        if let Err(reason) = self
            .verify_proposed_confiscation_tx(request, &sighash_bytes)
            .await
        {
            tracing::warn!(
                "Refusing confiscation_sign for ledger {}: tx-shape verification failed: {}",
                ledger_prefix,
                reason
            );
            return (
                false,
                None,
                Some(format!("confiscation tx verification: {}", reason)),
            );
        }

        // Sign the sighash via the Signer (confiscation tx Tapscript script-spend).
        use deposits_signer_api::{SigPurpose, SignContext};
        let signature_bytes = match self.handler.signer.bip340_sign(
            &SignContext::no_ledger(SigPurpose::OnchainSighash),
            &sighash_bytes,
        ) {
            Ok(s) => s,
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("confiscation sighash sign: {}", e)),
                )
            }
        };

        let result = serde_json::json!({
            "signer": self.node_id_hex.clone(),
            "signature": hex::encode(signature_bytes),
        });

        tracing::info!(
            "Signed confiscation sighash for ledger {}...",
            ledger_prefix
        );
        (true, Some(result.to_string()), None)
    }

    /// Walk the disputed ledger's history, replay to `last_valid_sequence`,
    /// and verify every fork-branch `DisputeArmed`'s replacement-collateral
    /// declaration. Returns `Err(refusal_reason)` for the cosigner to
    /// surface back to the requester.
    ///
    /// Verification mirrors DEP-03 §"Replacement collateral declaration":
    /// 1. Each disputant's `DisputeArmed` MUST carry a non-`None`
    ///    `replacement_collateral`.
    /// 2. The declared amount MUST satisfy
    ///    `amount ≥ obligations × (collateral / reserves) + fee_estimate`.
    /// 3. The declared outpoint MUST exist on-chain, be unspent, hold
    ///    at least the declared amount, and have at least
    ///    `policy.min_confirmations` confirmations.
    async fn verify_disputants_replacement_collateral(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> Result<(), String> {
        use crate::node::replacement_collateral::{
            check_inequality, compute_required_replacement_sats, CollateralCheck, CollateralPolicy,
        };
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use deposits_core::messages::ReplacementCollateral;
        use deposits_core::types::LedgerState;
        use deposits_core::SignedLedgerUpdate;
        use nostr_sdk::prelude::*;

        // The sender (operator initiating confiscation) provides
        // `last_valid_sequence`. Older clients that don't yet send this
        // field cause us to skip the replacement-collateral check and
        // fall back to legacy behaviour — log loudly so misconfigured
        // deployments are visible. RC6 will make this required.
        let last_valid_sequence = match request
            .params
            .get("last_valid_sequence")
            .and_then(|v| v.as_u64())
        {
            Some(seq) => seq,
            None => {
                tracing::warn!(
                    "confiscation_sign request missing last_valid_sequence — \
                     skipping replacement-collateral verification (legacy sender)"
                );
                return Ok(());
            }
        };

        let ledger_id = &request.ledger_id;

        // Fetch the ledger's full update history from the slow relay
        // (mirrors the fetch pattern in custody_transfer_sign).
        let client = self.nostr.fetch_client();
        let filter = Filter::new()
            .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
            .custom_tag(
                crate::nostr::TAG_LEDGER_ID,
                [crate::nostr::ledger_tag(ledger_id.as_str())],
            )
            .limit(500);
        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| format!("failed to fetch ledger updates: {}", e))?;

        let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    updates.push(update);
                }
            }
        }
        updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
        updates.dedup_by(|a, b| {
            a.sequence_number == b.sequence_number
                && a.operator_id == b.operator_id
                && a.content_hash == b.content_hash
        });

        // Identify the original operator (sequence 0). All operator-key
        // updates ≤ lvs come from them; updates with a different
        // operator_id and sequence > lvs are fork-branch DisputeArmed
        // candidates we need to verify.
        let original_operator = updates
            .iter()
            .find(|u| u.sequence_number == 0)
            .map(|u| u.operator_id)
            .ok_or_else(|| "could not find ledger genesis".to_string())?;

        // Replay LedgerState through lvs, capturing the latest QuorumBegin.
        // The initial state's specific fields don't matter — apply(LedgerOpen)
        // at seq 0 will overwrite operator_key/reserves_key/etc.
        let mut state = LedgerState::new(original_operator, String::new(), 0);
        let mut latest_qb_collateral_msat: u64 = 0;
        let mut latest_qb_reserves_msat: u64 = 0;
        let mut latest_qb_seq: i64 = -1;
        for update in &updates {
            if update.operator_id != original_operator {
                continue;
            }
            if update.sequence_number > last_valid_sequence {
                break;
            }
            let op = match deposits_core::messages::LedgerOperation::tlv_decode(&update.message) {
                Ok(o) => o,
                Err(e) => {
                    return Err(format!(
                        "decode error at seq {}: {}",
                        update.sequence_number, e
                    ));
                }
            };
            if let deposits_core::messages::LedgerOperation::QuorumBegin {
                amount,
                collateral_amount,
                ..
            } = &op
            {
                if (update.sequence_number as i64) > latest_qb_seq {
                    latest_qb_seq = update.sequence_number as i64;
                    latest_qb_collateral_msat = *collateral_amount;
                    latest_qb_reserves_msat = *amount;
                }
            }
            state = state
                .apply(&op)
                .map_err(|e| format!("replay failed at seq {}: {:?}", update.sequence_number, e))?;
        }
        if latest_qb_seq < 0 {
            // No QuorumBegin yet — there's no committed quorum to dispute,
            // so the request itself is malformed. Refuse.
            return Err("no QuorumBegin observed at or before last_valid_sequence".into());
        }

        let obligations_msat = state.total_deposit_balance();
        let policy = CollateralPolicy::default();
        let required_sats = compute_required_replacement_sats(
            obligations_msat,
            latest_qb_collateral_msat,
            latest_qb_reserves_msat,
            &policy,
        )
        .ok_or_else(|| "QuorumBegin reserves were zero".to_string())?;
        tracing::info!(
            "    Required replacement collateral ≥ {} sats (obligations_msat={}, ratio={}/{})",
            required_sats,
            obligations_msat,
            latest_qb_collateral_msat,
            latest_qb_reserves_msat
        );

        // Walk fork-branch DisputeArmed events. Each disputant's latest
        // armed event in this dispute is the one we verify.
        use std::collections::HashMap;
        let mut latest_armed: HashMap<
            bitcoin::secp256k1::PublicKey,
            (u64, Option<ReplacementCollateral>),
        > = HashMap::new();
        for update in &updates {
            if update.operator_id == original_operator {
                continue;
            }
            if update.sequence_number <= last_valid_sequence {
                continue;
            }
            let op = match deposits_core::messages::LedgerOperation::tlv_decode(&update.message) {
                Ok(o) => o,
                Err(_) => continue,
            };
            if let deposits_core::messages::LedgerOperation::DisputeArmed {
                replacement_collateral,
                ..
            } = op
            {
                let entry = latest_armed
                    .entry(update.operator_id)
                    .or_insert((0, None));
                if update.sequence_number >= entry.0 {
                    *entry = (update.sequence_number, replacement_collateral);
                }
            }
        }

        if latest_armed.is_empty() {
            return Err("no fork-branch DisputeArmed events observed".into());
        }

        for (disputant, (_, decl)) in &latest_armed {
            let serialized: [u8; 33] = disputant.serialize();
            let prefix = hex::encode(&serialized[..8]);
            let rc = match decl {
                Some(rc) => rc,
                None => {
                    return Err(format!(
                        "disputant {} declared no replacement_collateral",
                        prefix
                    ));
                }
            };
            // Pure inequality check first (no I/O).
            match check_inequality(rc.amount, required_sats) {
                CollateralCheck::Ok => {}
                other => {
                    return Err(format!(
                        "disputant {} replacement_collateral fails inequality: {:?}",
                        prefix, other
                    ));
                }
            }
            // Esplora outpoint check.
            let txid = bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::Hash::from_byte_array(rc.txid),
            );
            match self.wallet.get_outpoint_value_and_confs(txid, rc.vout).await {
                Ok(Some((value_sats, confs))) => {
                    if value_sats < rc.amount {
                        return Err(format!(
                            "disputant {} declared {} sats but UTXO holds only {} sats",
                            prefix, rc.amount, value_sats
                        ));
                    }
                    if confs < policy.min_confirmations {
                        return Err(format!(
                            "disputant {} UTXO has {} confirmations (< {} required)",
                            prefix, confs, policy.min_confirmations
                        ));
                    }
                    tracing::info!(
                        "    Disputant {} replacement_collateral OK ({} sats @ {} confs)",
                        prefix,
                        value_sats,
                        confs
                    );
                }
                Ok(None) => {
                    return Err(format!(
                        "disputant {} replacement_collateral outpoint not on-chain or spent",
                        prefix
                    ));
                }
                Err(e) => {
                    return Err(format!(
                        "esplora error checking disputant {}: {}",
                        prefix, e
                    ));
                }
            }
        }

        Ok(())
    }

    /// Verify the operator's proposed confiscation tx before signing.
    ///
    /// The cosigner independently re-derives:
    /// 1. The fraud proof type (kind:9101 from relay) → `is_respectful`.
    /// 2. The original operator (LedgerOpen seq 0).
    /// 3. The reserves UTXO from the latest QuorumBegin's `reserves_id`.
    /// 4. The lottery output script from the fork-branch DisputeArmed
    ///    participants + recovery-voter set.
    /// 5. The expected output structure via
    ///    `build_expected_confiscation_outputs` — same function the
    ///    operator used to build the tx.
    /// 6. The tap-leaf sighash from the proposed tx + reserves prevout.
    ///
    /// Then compares each derivation to what the operator proposed:
    /// input outpoint, output count, output values, output scripts, and
    /// sighash. Any mismatch is a refusal — the cosigner stalls the
    /// dispute rather than rubber-stamp a tx whose semantics they
    /// can't reproduce. DEP-03 §"Respectful confiscation tx".
    ///
    /// Also reachable from `recovery confiscate-plan` for dry-run
    /// inspection — that path constructs the same `LedgerRequest`
    /// shape the operator would send and pipes it through here so
    /// the cosigner-perspective check runs identically.
    pub(crate) async fn verify_proposed_confiscation_tx(
        &self,
        request: &crate::nostr::LedgerRequest,
        expected_sighash: &[u8; 32],
    ) -> Result<(), String> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use bitcoin::sighash::{SighashCache, TapSighashType};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};
        use bitcoin::{Amount, Transaction, TxOut};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
        use deposits_core::types::LedgerState;
        use deposits_core::{SignedLedgerUpdate, TapscriptReservesBuilder, TlvDecode, VoterSet};
        use nostr_sdk::prelude::*;

        // 1. Decode proposed tx
        let unsigned_tx_hex = request
            .params
            .get("unsigned_tx")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing unsigned_tx parameter".to_string())?;
        let tx_bytes = hex::decode(unsigned_tx_hex)
            .map_err(|e| format!("unsigned_tx hex decode: {}", e))?;
        let proposed_tx: Transaction = bitcoin::consensus::encode::deserialize(&tx_bytes)
            .map_err(|e| format!("unsigned_tx parse: {}", e))?;

        if proposed_tx.input.len() != 1 {
            return Err(format!(
                "expected exactly 1 input, got {}",
                proposed_tx.input.len()
            ));
        }
        if proposed_tx.output.is_empty() || proposed_tx.output.len() > 2 {
            return Err(format!(
                "expected 1 or 2 outputs, got {}",
                proposed_tx.output.len()
            ));
        }

        // 2. is_respectful from authoritative deadline evidence. Two
        //    paths are accepted:
        //      a) A kind:9101 `FraudBroadcast` on the relay — used for
        //         every fraud type whose embedding-via-cosign is
        //         feasible.
        //      b) A fork-branch `DisputeEnter` with inline anchor
        //         evidence + reason="quorum_expired" — used for the
        //         deadline-miss case, where embedding-via-cosign is
        //         impossible (cosigners refuse on an expired quorum).
        //    Either is sufficient for the verifier to know the
        //    confiscation is grounded; we refuse only if neither is
        //    on the relay.
        let proof_type = match self.fetch_fraud_proof_type_for_ledger(&request.ledger_id).await {
            Some(pt) => pt,
            None => self
                .fetch_quorum_expired_inline_evidence(&request.ledger_id)
                .await
                .ok_or_else(|| {
                    "no kind:9101 fraud broadcast or fork-branch \
                     QuorumExpired evidence on relay for this ledger"
                        .to_string()
                })?,
        };
        let is_respectful = proof_type.is_respectful();

        // 3. last_valid_sequence — the fork point we replay to
        let last_valid_sequence = request
            .params
            .get("last_valid_sequence")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "missing last_valid_sequence".to_string())?;

        let ledger_id = &request.ledger_id;

        // 4. Fetch the disputed ledger's full update history
        let client = self.nostr.fetch_client();
        let filter = Filter::new()
            .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
            .custom_tag(
                crate::nostr::TAG_LEDGER_ID,
                [crate::nostr::ledger_tag(ledger_id.as_str())],
            )
            .limit(500);
        let events = client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| format!("fetch updates: {}", e))?;

        let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
        for ev in events.iter() {
            if let Ok(b) = BASE64.decode(&ev.content) {
                if let Ok(u) = SignedLedgerUpdate::tlv_decode(&b) {
                    updates.push(u);
                }
            }
        }
        updates.sort_by_key(|u| (u.sequence_number, u.operator_id));

        let original_operator = updates
            .iter()
            .find(|u| u.sequence_number == 0)
            .map(|u| u.operator_id)
            .ok_or_else(|| "no LedgerOpen at seq 0".to_string())?;

        // 5. Replay through last_valid_sequence to capture obligations + latest QB
        let mut state = LedgerState::new(original_operator, String::new(), 0);
        let mut latest_qb: Option<(
            String,
            [u8; 32],
            Vec<bitcoin::secp256k1::PublicKey>,
            u32,
            Option<String>,
        )> = None;
        let mut latest_qb_seq: i64 = -1;
        for u in &updates {
            if u.operator_id != original_operator {
                continue;
            }
            if u.sequence_number > last_valid_sequence {
                break;
            }
            let op = LedgerOperation::tlv_decode(&u.message)
                .map_err(|e| format!("decode at seq {}: {}", u.sequence_number, e))?;
            if let LedgerOperation::QuorumBegin {
                reserves_id,
                ledger_hash,
                quorum_members,
                quorum_expiry,
                protocol_version,
                ..
            } = &op
            {
                if (u.sequence_number as i64) > latest_qb_seq {
                    latest_qb_seq = u.sequence_number as i64;
                    latest_qb = Some((
                        reserves_id.clone(),
                        *ledger_hash,
                        quorum_members.iter().map(|m| m.pubkey).collect(),
                        *quorum_expiry,
                        protocol_version.clone(),
                    ));
                }
            }
            state = state
                .apply(&op)
                .map_err(|e| format!("replay seq {}: {:?}", u.sequence_number, e))?;
        }
        let (qb_reserves_id, qb_ledger_hash, qb_members, qb_expiry, qb_ruleset) =
            latest_qb.ok_or_else(|| "no QuorumBegin observed".to_string())?;
        let obligations_sats = state.total_deposit_balance() / 1000;

        // 6. Collect fork-branch DisputeArmed participants (post last_valid_sequence)
        let mut participants: Vec<LotteryParticipant> = Vec::new();
        for u in &updates {
            if u.sequence_number <= last_valid_sequence {
                continue;
            }
            if let Ok(LedgerOperation::DisputeArmed {
                commitment_hash,
                target_reserves,
                ..
            }) = LedgerOperation::tlv_decode(&u.message)
            {
                let xonly = u.operator_id.x_only_public_key().0;
                if !participants.iter().any(|p| p.pubkey == xonly) {
                    participants.push(LotteryParticipant::new(
                        xonly,
                        commitment_hash,
                        target_reserves,
                    ));
                }
            }
        }
        if participants.len() < 2 {
            return Err(format!(
                "only {} DisputeArmed participants found",
                participants.len()
            ));
        }
        participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

        let recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey> = qb_members
            .iter()
            .filter(|pk| **pk != original_operator)
            .map(|pk| pk.x_only_public_key().0)
            .collect();
        let recovery_threshold = (recovery_voters.len() / 2) + 1;

        let lottery_builder = LotteryScriptBuilder::new(
            participants.clone(),
            recovery_voters,
            recovery_threshold,
            self.wallet.network(),
        );
        let lottery_output = lottery_builder
            .build()
            .map_err(|e| format!("rebuild lottery output: {:?}", e))?;

        // 7. Verify input + look up reserves UTXO on-chain for amount
        let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            qb_reserves_id
                .parse()
                .map_err(|e| format!("parse reserves_id: {}", e))?;
        let reserves_addr = reserves_addr
            .require_network(self.wallet.network())
            .map_err(|e| format!("network mismatch: {}", e))?;
        let reserves_script = reserves_addr.script_pubkey();
        let reserves_utxo = self
            .wallet
            .find_utxo_for_script(&reserves_script)
            .map_err(|e| format!("esplora reserves lookup: {}", e))?
            .ok_or_else(|| "reserves UTXO not found on-chain (already spent?)".to_string())?;
        let (reserves_outpoint, reserves_amount) = reserves_utxo;

        if proposed_tx.input[0].previous_output != reserves_outpoint {
            return Err(format!(
                "input outpoint {} ≠ on-chain reserves UTXO {}",
                proposed_tx.input[0].previous_output, reserves_outpoint
            ));
        }

        // 8. Derive fee from proposed tx, then compute expected outputs
        let total_out: u64 = proposed_tx.output.iter().map(|o| o.value.to_sat()).sum();
        let fee = reserves_amount.checked_sub(total_out).ok_or_else(|| {
            format!(
                "outputs ({} sats) exceed input ({} sats)",
                total_out, reserves_amount
            )
        })?;

        let expected_outputs = crate::node::dispute::build_expected_confiscation_outputs(
            lottery_output.script_pubkey(),
            original_operator,
            self.wallet.network(),
            reserves_amount,
            fee,
            is_respectful,
            obligations_sats,
        )
        .map_err(|e| format!("expected outputs: {}", e))?;

        if proposed_tx.output.len() != expected_outputs.len() {
            return Err(format!(
                "output count: proposed={}, expected={}",
                proposed_tx.output.len(),
                expected_outputs.len()
            ));
        }
        for (i, (proposed, expected)) in proposed_tx
            .output
            .iter()
            .zip(expected_outputs.iter())
            .enumerate()
        {
            if proposed.value != expected.value {
                return Err(format!(
                    "output[{}] value: proposed={}, expected={}",
                    i, proposed.value, expected.value
                ));
            }
            if proposed.script_pubkey != expected.script_pubkey {
                return Err(format!(
                    "output[{}] script: proposed={}, expected={}",
                    i,
                    hex::encode(proposed.script_pubkey.as_bytes()),
                    hex::encode(expected.script_pubkey.as_bytes())
                ));
            }
        }

        // 9. Re-derive the sighash from the proposed tx + reconstructed
        //    reserves prevout + tap leaf, then compare to the sighash
        //    the operator told us to sign.
        let voter_set = VoterSet::new(original_operator, qb_members.clone());
        let voter_count = voter_set.all_voters().len();
        let ruleset = deposits_core::ruleset::resolve_or_legacy(qb_ruleset.as_deref());
        let threshold_config = (ruleset.tier_config_factory)(voter_count, qb_expiry);

        let taproot_builder = TapscriptReservesBuilder::new(
            voter_set,
            threshold_config.clone(),
            self.wallet.network(),
            qb_ledger_hash,
        );
        let _taproot_output = taproot_builder
            .build()
            .map_err(|e| format!("rebuild taproot: {:?}", e))?;

        let tier = threshold_config
            .tiers
            .iter()
            .find(|t| !t.requires_tie_breaker && t.threshold > 1)
            .ok_or_else(|| "no quorum-override tier".to_string())?;
        let leaf_script = taproot_builder
            .build_threshold_leaf(tier)
            .map_err(|e| format!("rebuild leaf script: {:?}", e))?;
        let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

        let prevouts = vec![TxOut {
            value: Amount::from_sat(reserves_amount),
            script_pubkey: reserves_script,
        }];

        let mut sighash_cache = SighashCache::new(&proposed_tx);
        let derived_sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| format!("compute sighash: {}", e))?;
        let derived_bytes: [u8; 32] = derived_sighash.to_byte_array();

        if &derived_bytes != expected_sighash {
            return Err(format!(
                "sighash mismatch: derived={}, claimed={}",
                hex::encode(derived_bytes),
                hex::encode(expected_sighash)
            ));
        }

        Ok(())
    }

    pub(crate) async fn process_custodian_query_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        // Get ledger
        let (reserves_id, ledger) = match self
            .get_ledger_by_ledger_id(&request.ledger_id)
            .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
        {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        let custodian_hex = hex::encode(ledger.operator_key().serialize());
        let attester_hex = hex::encode(self.node_id.serialize());

        let result = serde_json::json!({
            "status": "SUCCESS",
            "custodian": custodian_hex,
            "attester": attester_hex,
            "reserves_id": reserves_id,
            "ledger_id": ledger.ledger_id_hex(),
        });
        (true, Some(result.to_string()), None)
    }

    // ========================================================================
    // Daemon-mediated CLI request handlers
    // ========================================================================

}
