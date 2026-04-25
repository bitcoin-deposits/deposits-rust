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
        let secp = &self.secp;
        let secret_key = self.wallet.operator_secret();
        let keypair = Keypair::from_secret_key(secp, &secret_key);
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

        // Sign the sighash
        let msg = Message::from_digest(sighash_bytes);
        let signature = secp.sign_schnorr(&msg, &keypair);
        let signature_bytes = signature.serialize();

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
        use bitcoin::secp256k1::Message;

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

        // Sign the sighash
        let secp = &self.secp;
        let keypair =
            bitcoin::secp256k1::Keypair::from_secret_key(secp, &self.wallet.operator_secret());
        let msg = Message::from_digest(sighash_bytes);
        let signature = secp.sign_schnorr(&msg, &keypair);

        let _our_pubkey = keypair.public_key();
        let result = serde_json::json!({
            "signer": self.node_id_hex.clone(),
            "signature": hex::encode(signature.serialize()),
        });

        tracing::info!(
            "Signed confiscation sighash for ledger {}...",
            ledger_prefix
        );
        (true, Some(result.to_string()), None)
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
