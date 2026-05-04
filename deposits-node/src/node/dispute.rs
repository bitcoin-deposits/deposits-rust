use super::*;

impl Node {
    /// Auto-arm for a dispute by creating a fork of the disputed ledger,
    /// then publishing DisputeEnter and DisputeArmed on the fork.
    ///
    /// This ensures the operator's own ledger stays in Normal state and is
    /// not affected by the dispute. The fork is stored under a compound
    /// tracking key and persisted as a separate JSONL file.
    pub(crate) async fn auto_arm_for_dispute(
        &self,
        ledger_id: &str,
        last_valid_seq: u64,
    ) -> Result<(), Error> {
        use bitcoin::hashes::{hash160, Hash};
        use bitcoin::secp256k1::rand::rngs::OsRng;
        use bitcoin::secp256k1::rand::Rng;

        use deposits_core::messages::LedgerOperation;

        let secp = &self.secp;

        // Get our operator keypair
        let keypair =
            bitcoin::secp256k1::Keypair::from_secret_key(secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // 0. Create a fork of the disputed ledger (or reuse existing one)
        let fork_key = self.create_dispute_fork(ledger_id, last_valid_seq)?;

        // Get the fork ledger's arc
        let fork_arc = self
            .handler
            .ledgers
            .lock()
            .unwrap()
            .get(&fork_key)
            .cloned()
            .ok_or_else(|| Error::Protocol("Fork ledger not found after creation".to_string()))?;
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Track whether we actually added new operations (to avoid re-broadcast loops)
        let mut added_new_operations = false;

        // 1. Publish DisputeEnter on the fork
        {
            let mut fork_ledger = fork_arc.write().unwrap();

            // Check if we've already published a DisputeEnter on this fork
            let already_disputed = fork_ledger.history.iter().any(|u| {
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    matches!(op, LedgerOperation::DisputeEnter { .. })
                } else {
                    false
                }
            });

            if already_disputed {
                tracing::info!("Already have DisputeEnter on fork");
            } else {
                let dispute_op = LedgerOperation::DisputeEnter {
                    last_valid_sequence: last_valid_seq,
                    reason: "auto_dispute".to_string(),
                };

                fork_ledger
                    .append_operation_with_block(dispute_op, current_block, block_hash)
                    .map_err(|e| {
                        Error::Protocol(format!("Failed to append DisputeEnter to fork: {:?}", e))
                    })?;

                // Set parent_pubkey to our key (we now operate this fork branch)
                fork_ledger.state.parent_pubkey = our_pubkey;

                // Patch operator_id on the appended update to our pubkey
                if let Some(update) = fork_ledger.history.last_mut() {
                    update.operator_id = our_pubkey;
                }

                tracing::info!("Published DisputeEnter on fork (parent_pubkey set to us)");
                added_new_operations = true;
            }
        }

        // Sign the dispute update on the fork
        self.sign_last_update(&fork_key)?;

        // 2. Copy our existing attestations from ALL of our operator ledger histories
        // (not from the fork - those prove we have collateral backing).
        // With multi-ledger operators, attestations may be spread across any of our
        // ledgers, so we must scan all of them.
        {
            // Collect arcs for all our owned ledgers
            let our_ledger_arcs: Vec<_> = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .iter()
                    .filter(|(lid, arc)| {
                        let l = arc.read().unwrap();
                        l.operator_key() == self.node_id && lid.len() <= 64
                    })
                    .map(|(_, arc)| arc.clone())
                    .collect()
            };

            // Collateral is now tracked at the UTXO level; no attestations to copy.
            // Add quorum members from our ledgers to the fork if needed.
            let mut quorum_members_to_add: Vec<(bitcoin::secp256k1::PublicKey, String)> =
                Vec::new();

            for ledger_arc in &our_ledger_arcs {
                let ledger = ledger_arc.read().unwrap();
                for member in &ledger.state.quorum_members {
                    if !quorum_members_to_add
                        .iter()
                        .any(|(pk, _)| pk == &member.pubkey)
                    {
                        quorum_members_to_add.push((member.pubkey, member.ledger_id.clone()));
                    }
                }
            }

            if !quorum_members_to_add.is_empty() {
                // Add quorum members to the fork
                for (member, member_ledger_id) in &quorum_members_to_add {
                    let mut fork_ledger = fork_arc.write().unwrap();

                    if fork_ledger
                        .state
                        .quorum_members
                        .iter()
                        .any(|m| m.pubkey == *member)
                    {
                        continue;
                    }

                    let add_op = LedgerOperation::QuorumAddMember {
                        quorum_member: *member,
                        quorum_member_signature: [0u8; 64],
                        member_ledger_id: member_ledger_id.clone(),
                        min_fee_bps: None,
                        min_fee_fixed: None,
                        max_fee_period: None,
                        membership_until: None,
                        dispute_response_blocks: None,
                        dispute_arm_blocks: None,
                        service_response_blocks: None,
                        max_transfer_timeout_blocks: None,
                        max_descriptor_bytes: None,
                        compensation_bps: None,
                        compensation_deposit_id: None,
                        compensation_frequency_blocks: None,
                    };

                    if let Err(e) =
                        fork_ledger.append_operation_with_block(add_op, current_block, block_hash)
                    {
                        tracing::warn!("Failed to add quorum member to fork: {:?}", e);
                    } else {
                        if let Some(update) = fork_ledger.history.last_mut() {
                            update.operator_id = our_pubkey;
                        }
                        tracing::info!(
                            "Added quorum member to fork: {}...",
                            &hex::encode(member.serialize())[..16]
                        );
                        added_new_operations = true;
                    }
                }

                // Sign after adding members
                self.sign_last_update(&fork_key)?;
            }
        }

        // 3. Publish DisputeArmed with preimage commitment on the fork
        {
            let mut fork_ledger = fork_arc.write().unwrap();

            let already_armed = fork_ledger.history.iter().any(|u| {
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    matches!(op, LedgerOperation::DisputeArmed { .. })
                } else {
                    false
                }
            });

            if already_armed {
                tracing::info!("Already have DisputeArmed on fork");
            } else {
                // Generate random preimage (32 bytes for lottery entropy)
                let mut rng = OsRng;
                let mut preimage = vec![0u8; 32];
                rng.fill(&mut preimage[..]);

                // Compute commitment_hash = HASH160(preimage)
                let commitment_hash: [u8; 20] = *hash160::Hash::hash(&preimage).as_byte_array();

                // Store preimage for later reveal (keyed by disputed ledger_id prefix)
                let preimage_file = self.data_dir.join(format!(
                    "lottery_preimage_{}.hex",
                    &ledger_id[..16.min(ledger_id.len())]
                ));
                if let Err(e) = std::fs::write(&preimage_file, hex::encode(&preimage)) {
                    tracing::warn!("Failed to store preimage: {}", e);
                } else {
                    tracing::info!("Stored lottery preimage in: {:?}", preimage_file);
                }

                // Use P2WPKH address derived from our operator pubkey for target_reserves
                let pubkey_bytes: [u8; 33] = our_pubkey.serialize();
                let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes)
                    .map_err(|e| Error::Protocol(format!("Invalid pubkey: {}", e)))?;
                let target_reserves =
                    bitcoin::Address::p2wpkh(&compressed, self.wallet.network()).to_string();

                let armed_op = LedgerOperation::DisputeArmed {
                    armed_block: current_block,
                    commitment_hash,
                    target_reserves,
                };

                fork_ledger
                    .append_operation_with_block(armed_op, current_block, block_hash)
                    .map_err(|e| {
                        Error::Protocol(format!("Failed to append DisputeArmed to fork: {:?}", e))
                    })?;

                // Patch operator_id
                if let Some(update) = fork_ledger.history.last_mut() {
                    update.operator_id = our_pubkey;
                }

                tracing::info!("Published DisputeArmed on fork");
                added_new_operations = true;
            }
        }

        // Sign the armed update on the fork
        self.sign_last_update(&fork_key)?;

        // Persist the fork (new JSONL file with compound key as filename)
        if let Err(e) = self.handler.persist_ledger_to_disk(&fork_key) {
            tracing::error!("Failed to persist fork ledger: {}", e);
        }

        // Create custody_armed marker (needed by auto_confiscate)
        let armed_marker = self.data_dir.join(format!(
            "custody_armed_{}.marker",
            &ledger_id[..16.min(ledger_id.len())]
        ));
        if let Err(e) = std::fs::write(&armed_marker, "armed") {
            tracing::warn!("Failed to write armed marker: {}", e);
        } else {
            tracing::info!("Created custody_armed marker: {:?}", armed_marker);
        }

        // Only broadcast if we actually added new operations to the fork.
        // Without this guard, incoming fork events re-trigger auto_arm_for_dispute,
        // which re-broadcasts all updates, creating an infinite feedback loop.
        if added_new_operations {
            if let Err(e) = self.broadcast_all_updates(&fork_key).await {
                tracing::warn!("Failed to broadcast dispute fork updates: {}", e);
            }
        } else {
            tracing::debug!("Fork already fully armed, skipping re-broadcast");
        }

        Ok(())
    }

    /// Auto-reveal our lottery preimage when we see another participant's reveal
    pub(crate) async fn auto_reveal_preimage(&self, ledger_id: &str) {
        // Check if we're a quorum member of this ledger
        if !self.is_quorum_member_of_ledger(ledger_id) {
            return;
        }

        // Check if we have a preimage file for this ledger
        let preimage_file = self.data_dir.join(format!(
            "lottery_preimage_{}.hex",
            &ledger_id[..16.min(ledger_id.len())]
        ));

        if !preimage_file.exists() {
            tracing::debug!("No preimage file for ledger {}", &ledger_id[..16]);
            return;
        }

        // Check if we already revealed (marker file)
        let revealed_marker = self.data_dir.join(format!(
            "lottery_revealed_{}.marker",
            &ledger_id[..16.min(ledger_id.len())]
        ));
        if revealed_marker.exists() {
            tracing::debug!("Already revealed preimage for ledger {}", &ledger_id[..16]);
            return;
        }

        // Load and reveal the preimage
        let preimage_hex = match std::fs::read_to_string(&preimage_file) {
            Ok(hex) => hex.trim().to_string(),
            Err(e) => {
                tracing::warn!("Failed to read preimage file: {}", e);
                return;
            }
        };

        let preimage = match hex::decode(&preimage_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!("Invalid preimage hex: {}", e);
                return;
            }
        };

        tracing::info!(
            "Auto-revealing lottery preimage for ledger {}...",
            &ledger_id[..16]
        );
        tracing::info!(
            "  Preimage length: {} bytes (contribution: {})",
            preimage.len(),
            preimage.len().saturating_sub(16)
        );

        // Publish reveal via Nostr
        let reveal_params = serde_json::json!({
            "ledger_id": ledger_id,
            "preimage": preimage_hex,
        });

        match self
            .nostr
            .send_ledger_request(ledger_id, "lottery_reveal", reveal_params)
            .await
        {
            Ok(request_id) => {
                self.track_sent_event(&request_id);
                tracing::info!(
                    "Lottery preimage revealed! Request ID: {}...",
                    &request_id[..16.min(request_id.len())]
                );

                // Create marker file to prevent double-reveal
                if let Err(e) = std::fs::write(&revealed_marker, "revealed") {
                    tracing::warn!("Failed to write revealed marker: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to send reveal: {:?}", e);
            }
        }
    }

    /// Auto-claim or yield for any pending lottery disputes
    ///
    /// For each ledger where we've revealed our preimage:
    /// 1. Check if all preimages are collected
    /// 2. Determine winner
    /// 3. Winner: claim lottery output + publish DisputeAcquire
    /// 4. Loser: publish DisputeYield
    pub(crate) async fn auto_lottery_claim_or_yield(&self) {
        let secp = &self.secp;
        let keypair =
            bitcoin::secp256k1::Keypair::from_secret_key(secp, &self.wallet.operator_secret());

        // Find revealed marker files in data_dir
        let entries = match std::fs::read_dir(&self.data_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        let revealed_markers: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("lottery_revealed_")
                    && e.file_name().to_string_lossy().ends_with(".marker")
            })
            .collect();

        for entry in revealed_markers {
            let marker_path = entry.path();
            // Extract ledger_id prefix from filename
            let filename = match marker_path.file_name().and_then(|f| f.to_str()) {
                Some(f) => f,
                None => continue,
            };

            // lottery_revealed_<prefix>.marker
            let ledger_prefix = filename
                .strip_prefix("lottery_revealed_")
                .and_then(|s| s.strip_suffix(".marker"))
                .unwrap_or("");

            if ledger_prefix.is_empty() {
                continue;
            }

            // Check if we've already claimed/yielded (completed marker)
            let completed_marker = self
                .data_dir
                .join(format!("lottery_completed_{}.marker", ledger_prefix));
            if completed_marker.exists() {
                continue;
            }

            // Find the fork or original ledger key (prefer fork for dispute operations)
            let ledger_key = match self.find_fork_or_original_by_prefix(ledger_prefix) {
                Some(key) => key,
                None => continue,
            };

            // Extract the base ledger_id (first 64 chars) for Nostr queries
            let ledger_id = if ledger_key.len() > 64 {
                ledger_key[..64].to_string()
            } else {
                ledger_key.clone()
            };

            // Try to claim or yield
            match self.try_lottery_claim_or_yield(&ledger_id, &keypair).await {
                Ok(completed) => {
                    if completed {
                        // Create completed marker
                        if let Err(e) = std::fs::write(&completed_marker, "completed") {
                            tracing::warn!("Failed to write completed marker: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Lottery claim/yield not ready for {}: {}", ledger_prefix, e);
                }
            }
        }
    }

    /// Try to claim or yield for a specific ledger
    /// Returns Ok(true) if completed, Ok(false) if not ready, Err if failed
    pub(crate) async fn try_lottery_claim_or_yield(
        &self,
        ledger_id: &str,
        keypair: &bitcoin::secp256k1::Keypair,
    ) -> Result<bool, Error> {
        use crate::nostr::{KIND_LEDGER_REQUEST, KIND_LEDGER_UPDATE};
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        use bitcoin::secp256k1::PublicKey;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryOutput, LotteryParticipant};
        use deposits_core::{SignedLedgerUpdate, TlvDecode};

        use nostr_sdk::{Filter, Kind, TagKind};

        let our_pubkey = keypair.public_key();

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

        // Fetch ledger updates
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(
                crate::nostr::TAG_LEDGER_ID,
                [crate::nostr::ledger_tag(ledger_id)],
            )
            .limit(500);

        let update_events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch updates: {}", e)))?;

        // Fetch lottery reveals
        let reveal_filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_REQUEST))
            .custom_tag(crate::nostr::TAG_LEDGER_REQ, [ledger_id])
            .limit(100);

        let reveal_events = client
            .fetch_events(vec![reveal_filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch reveals: {}", e)))?;

        // Extract DisputeArmed participants
        let mut participants: Vec<(PublicKey, LotteryParticipant)> = Vec::new();
        let mut our_armed: Option<SignedLedgerUpdate> = None;

        for event in update_events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::DisputeArmed {
                            commitment_hash,
                            target_reserves,
                            ..
                        } = op
                        {
                            let x_only = update.operator_id.x_only_public_key().0;
                            participants.push((
                                update.operator_id,
                                LotteryParticipant::new(x_only, commitment_hash, target_reserves),
                            ));
                            if update.operator_id == our_pubkey {
                                our_armed = Some(update);
                            }
                        }
                    }
                }
            }
        }

        if participants.is_empty() {
            return Err(Error::Protocol(
                "No DisputeArmed participants found".to_string(),
            ));
        }

        let our_armed = our_armed
            .ok_or_else(|| Error::Protocol("Could not find our DisputeArmed".to_string()))?;

        // Sort participants by x-only pubkey for deterministic order
        participants.sort_by(|a, b| a.1.pubkey.serialize().cmp(&b.1.pubkey.serialize()));

        // Collect revealed preimages
        let mut preimages: std::collections::HashMap<String, Vec<u8>> =
            std::collections::HashMap::new();

        for event in reveal_events.iter() {
            let is_lottery_reveal = event.tags.iter().any(|tag| {
                tag.kind() == TagKind::custom("action")
                    && tag
                        .content()
                        .map(|c| c == "lottery_reveal")
                        .unwrap_or(false)
            });

            if is_lottery_reveal {
                if let Ok(content) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    if let Some(preimage_hex) = content.get("preimage").and_then(|v| v.as_str()) {
                        if let Ok(preimage) = hex::decode(preimage_hex) {
                            preimages.insert(event.pubkey.to_string(), preimage);
                        }
                    }
                }
            }
        }

        // Not ready if not all preimages revealed
        if preimages.len() < participants.len() {
            return Ok(false);
        }

        // Match preimages to participants
        let mut ordered_preimages: Vec<Vec<u8>> = Vec::new();
        for (pubkey, _participant) in &participants {
            let x_only = pubkey.x_only_public_key().0;
            let pubkey_str = x_only.to_string();
            if let Some(preimage) = preimages.get(&pubkey_str) {
                ordered_preimages.push(preimage.clone());
            } else {
                return Err(Error::Protocol(
                    "Missing preimage from participant".to_string(),
                ));
            }
        }

        // Determine winner
        let winner_index = LotteryOutput::calculate_winner(&ordered_preimages)
            .map_err(|e| Error::Protocol(format!("Failed to calculate winner: {:?}", e)))?;

        let (winner_pubkey, _winner_participant) = &participants[winner_index];

        if *winner_pubkey == our_pubkey {
            // WE WON - claim the lottery
            tracing::info!("We won the lottery for ledger {}!", &ledger_id[..16]);
            self.claim_lottery(
                ledger_id,
                &participants,
                &ordered_preimages,
                winner_index,
                &our_armed,
                keypair,
            )
            .await?;
        } else {
            // We lost - yield
            tracing::info!(
                "We lost the lottery for ledger {}. Publishing DisputeYield.",
                &ledger_id[..16]
            );
            self.publish_custody_yield(ledger_id, &our_armed, keypair)
                .await?;
        }

        Ok(true)
    }

    /// Claim the lottery output as the winner
    pub(crate) async fn claim_lottery(
        &self,
        ledger_id: &str,
        participants: &[(
            bitcoin::secp256k1::PublicKey,
            deposits_core::tapscript_reserves::LotteryParticipant,
        )],
        ordered_preimages: &[Vec<u8>],
        winner_index: usize,
        our_armed: &deposits_core::SignedLedgerUpdate,
        keypair: &bitcoin::secp256k1::Keypair,
    ) -> Result<(), Error> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::Message;
        use bitcoin::sighash::{SighashCache, TapSighashType};
        use bitcoin::taproot::TapLeafHash;
        use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
        use deposits_core::{SignedLedgerUpdate, TlvEncode};

        let secp = &self.secp;
        let our_pubkey = keypair.public_key();
        let (_, winner_participant) = &participants[winner_index];

        // Build lottery participants list
        let lottery_participants: Vec<LotteryParticipant> =
            participants.iter().map(|(_, p)| p.clone()).collect();

        // Get recovery voters (need to fetch from ledger)
        // For now, use participants as recovery voters
        let recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey> = participants
            .iter()
            .map(|(pk, _)| pk.x_only_public_key().0)
            .collect();

        let recovery_threshold = (recovery_voters.len() / 2) + 1;

        // Build the lottery output
        let lottery_builder = LotteryScriptBuilder::new(
            lottery_participants.clone(),
            recovery_voters.clone(),
            recovery_threshold,
            self.wallet.network(),
        );

        let lottery_output = lottery_builder
            .build()
            .map_err(|e| Error::Protocol(format!("Failed to build lottery output: {:?}", e)))?;

        // Find the lottery UTXO on-chain
        let lottery_script = lottery_output.address.script_pubkey();

        // Use wallet's esplora to find UTXO
        let lottery_utxo = self
            .wallet
            .find_utxo_for_script(&lottery_script)
            .map_err(|e| Error::Protocol(format!("Failed to find lottery UTXO: {:?}", e)))?;

        let (lottery_outpoint, lottery_amount) = lottery_utxo
            .ok_or_else(|| Error::Protocol("No unspent UTXO at lottery address".to_string()))?;

        tracing::info!(
            "Found lottery UTXO: {} ({} sats)",
            lottery_outpoint,
            lottery_amount
        );

        // Parse winner's target address
        let target_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            winner_participant
                .target_reserves
                .parse()
                .map_err(|e| Error::Protocol(format!("Invalid target address: {}", e)))?;
        let target_address = target_address
            .require_network(self.wallet.network())
            .map_err(|e| Error::Protocol(format!("Address network mismatch: {}", e)))?;

        // Build claim transaction
        let claim_fee = 400u64;
        let output_amount = lottery_amount.saturating_sub(claim_fee);

        let claim_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: lottery_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_amount),
                script_pubkey: target_address.script_pubkey(),
            }],
        };

        // Compute sighash
        let prevouts = vec![TxOut {
            value: Amount::from_sat(lottery_amount),
            script_pubkey: lottery_script.clone(),
        }];

        let leaf_hash = TapLeafHash::from_script(
            &lottery_output.lottery_script,
            bitcoin::taproot::LeafVersion::TapScript,
        );

        let mut sighash_cache = SighashCache::new(&claim_tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| Error::Protocol(format!("Failed to compute sighash: {}", e)))?;

        // Sign
        let msg = Message::from_digest(*sighash.as_ref());
        let signature = secp.sign_schnorr(&msg, keypair);
        let sig_bytes: [u8; 64] = *signature.as_ref();

        // Create witness
        let witness = lottery_output
            .create_claim_witness(&sig_bytes, ordered_preimages)
            .map_err(|e| Error::Protocol(format!("Failed to create witness: {:?}", e)))?;

        let mut claim_tx = claim_tx;
        claim_tx.input[0].witness = witness;

        // Broadcast
        tracing::info!("Broadcasting claim transaction...");
        self.wallet.broadcast(&claim_tx)?;

        let claim_txid = claim_tx.compute_txid();
        tracing::info!("Claim TX broadcast: {}", claim_txid);

        // Publish DisputeAcquire. The block_height and block_hash on
        // the SignedLedgerUpdate envelope still need to reflect a
        // recent on-chain anchor for fraud-proof anchoring; they are
        // unrelated to the lottery selection (which is enforced by
        // the on-chain claim TX itself).
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let current_block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
        let claim_txid_bytes: [u8; 32] = *claim_txid.as_ref();

        let operation = LedgerOperation::DisputeAcquire {
            new_custodian: our_pubkey,
            claim_txid: claim_txid_bytes,
            new_reserves_address: winner_participant.target_reserves.clone(),
        };

        let message_bytes = operation.tlv_encode();

        // Build update continuing from our DisputeArmed
        let sequence = our_armed.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&our_armed.content_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        // Sign the update
        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(our_armed.content_hash),
            sequence,
            hex::encode(new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let msg = Message::from_digest(*msg_hash.as_ref());
        let signature = secp.sign_schnorr(&msg, keypair);
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
            .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_armed.content_hash,
            content_hash: new_hash,
            block_height: current_block,
            block_hash: current_block_hash,
        };

        // Broadcast to Nostr
        self.nostr
            .broadcast_ledger_update(&signed_update)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast DisputeAcquire: {:?}", e)))?;

        tracing::info!("DisputeAcquire published! We are now the operator.");
        Ok(())
    }

    /// Publish DisputeYield as a loser
    pub(crate) async fn publish_custody_yield(
        &self,
        ledger_id: &str,
        our_armed: &deposits_core::SignedLedgerUpdate,
        keypair: &bitcoin::secp256k1::Keypair,
    ) -> Result<(), Error> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::Message;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::{SignedLedgerUpdate, TlvEncode};

        let secp = &self.secp;
        let our_pubkey = keypair.public_key();

        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let current_block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Create DisputeYield operation
        let operation = LedgerOperation::DisputeYield;
        let message_bytes = operation.tlv_encode();

        // Build update continuing from our DisputeArmed
        let sequence = our_armed.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&our_armed.content_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        // Sign the update
        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(our_armed.content_hash),
            sequence,
            hex::encode(new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let msg = Message::from_digest(*msg_hash.as_ref());
        let signature = secp.sign_schnorr(&msg, keypair);
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
            .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_armed.content_hash,
            content_hash: new_hash,
            block_height: current_block,
            block_hash: current_block_hash,
        };

        // Broadcast to Nostr
        self.nostr
            .broadcast_ledger_update(&signed_update)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast DisputeYield: {:?}", e)))?;

        tracing::info!("DisputeYield published. Branch terminated.");
        Ok(())
    }

    /// Auto-initiate confiscation when all participants are armed
    ///
    /// For each ledger where we're armed but confiscation hasn't happened yet,
    /// check if all participants have armed. If so, build the confiscation TX,
    /// request signatures from quorum members, and broadcast.
    pub(crate) async fn auto_confiscate(&self) {
        // Phase 1: Check for pending confiscations that need signature collection
        self.collect_confiscation_signatures().await;

        // Phase 2: Initiate new confiscations for armed ledgers that don't have one pending
        self.initiate_confiscations().await;
    }

    /// Non-blocking: collect signatures for pending confiscation requests and broadcast when ready.
    pub(crate) async fn collect_confiscation_signatures(&self) {
        use bitcoin::secp256k1::PublicKey;

        use nostr_sdk::{Filter, Kind};

        let prefixes: Vec<String> = {
            let pending = self.pending_confiscations.lock().unwrap();
            pending.keys().cloned().collect()
        };

        for prefix in prefixes {
            // Check timeout (120s) — drop stale requests so we can re-initiate
            {
                let pending = self.pending_confiscations.lock().unwrap();
                if let Some(pc) = pending.get(&prefix) {
                    if pc.created_at.elapsed() > std::time::Duration::from_secs(120) {
                        tracing::warn!(
                            "Confiscation request for {} timed out, will re-initiate",
                            prefix
                        );
                        drop(pending);
                        self.pending_confiscations.lock().unwrap().remove(&prefix);
                        continue;
                    }
                }
            }

            // Fetch recent response events (non-blocking, single fetch)
            let (request_id, required_sigs) = {
                let pending = self.pending_confiscations.lock().unwrap();
                match pending.get(&prefix) {
                    Some(pc) => (pc.request_id.clone(), pc.required_sigs),
                    None => continue,
                }
            };

            let since = nostr_sdk::Timestamp::now() - 120;
            let filter = Filter::new()
                .kind(Kind::Custom(crate::nostr::KIND_LEDGER_RESPONSE))
                .since(since);

            let response_events = match self
                .nostr
                .client()
                .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
                .await
            {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Process responses and add signatures
            let mut ready_to_broadcast = false;
            {
                let mut pending = self.pending_confiscations.lock().unwrap();
                let pc = match pending.get_mut(&prefix) {
                    Some(pc) => pc,
                    None => continue,
                };

                for event in response_events.iter() {
                    let mut is_our_request = false;
                    for tag in event.tags.iter() {
                        if tag.kind()
                            == nostr_sdk::TagKind::SingleLetter(crate::nostr::TAG_EVENT_REF)
                        {
                            if let Some(val) = tag.content() {
                                if val == request_id {
                                    is_our_request = true;
                                    break;
                                }
                            }
                        }
                    }

                    if !is_our_request {
                        continue;
                    }

                    if let Ok(response) =
                        serde_json::from_str::<crate::nostr::LedgerResponse>(&event.content)
                    {
                        if response.success {
                            if let Some(result) = &response.result {
                                if let (Some(signer_hex), Some(sig_hex)) = (
                                    result.get("signer").and_then(|v| v.as_str()),
                                    result.get("signature").and_then(|v| v.as_str()),
                                ) {
                                    if let (Ok(signer), Ok(sig_bytes)) =
                                        (signer_hex.parse::<PublicKey>(), hex::decode(sig_hex))
                                    {
                                        if sig_bytes.len() == 64
                                            && !pc.signatures.contains_key(&signer)
                                        {
                                            let mut sig_arr = [0u8; 64];
                                            sig_arr.copy_from_slice(&sig_bytes);
                                            pc.signatures.insert(signer, sig_arr);
                                            tracing::info!("  Confiscation {}: received signature from {}... ({}/{})",
                                                &prefix, &signer.to_string()[..16], pc.signatures.len(), required_sigs);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if pc.signatures.len() >= required_sigs {
                    ready_to_broadcast = true;
                }
            }

            if ready_to_broadcast {
                self.broadcast_confiscation(&prefix).await;
            }
        }
    }

    /// Build witness and broadcast a confiscation transaction that has enough signatures.
    pub(crate) async fn broadcast_confiscation(&self, prefix: &str) {
        use bitcoin::Witness;

        let pc = match self.pending_confiscations.lock().unwrap().remove(prefix) {
            Some(pc) => pc,
            None => return,
        };

        tracing::info!(
            "  Building witness with {} signatures for {}...",
            pc.signatures.len(),
            prefix
        );

        let control_block = match pc.taproot_output.control_block_for_tier(pc.tier_index) {
            Some(cb) => cb,
            None => {
                tracing::error!("Failed to get control block for tier");
                return;
            }
        };

        let mut witness = Witness::new();
        let sorted_keys = pc.voter_set.sorted_x_only_pubkeys();

        for x_only in sorted_keys.iter().rev() {
            for voter in pc.voter_set.all_voters() {
                if voter.x_only_public_key().0 == *x_only {
                    if let Some(sig) = pc.signatures.get(&voter) {
                        witness.push(sig);
                    } else {
                        witness.push(&[] as &[u8]);
                    }
                    break;
                }
            }
        }

        witness.push(pc.leaf_script.as_bytes());
        witness.push(control_block.serialize());

        let mut confiscation_tx = pc.confiscation_tx;
        confiscation_tx.input[0].witness = witness;

        // Broadcast
        tracing::info!("  Broadcasting confiscation transaction...");

        match self.wallet.broadcast(&confiscation_tx) {
            Ok(_) => {
                let confiscation_txid = confiscation_tx.compute_txid();
                tracing::info!(
                    "Confiscation transaction broadcast! Txid: {}",
                    confiscation_txid
                );
                tracing::info!("  Lottery address: {}", pc.lottery_address);

                // Write confiscated marker
                if let Err(e) =
                    std::fs::write(&pc.confiscated_marker, confiscation_txid.to_string())
                {
                    tracing::warn!("Failed to write confiscated marker: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to broadcast confiscation TX: {}", e);
            }
        }
    }

    /// Non-blocking: initiate confiscation for armed ledgers that don't already have a pending request.
    pub(crate) async fn initiate_confiscations(&self) {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use bitcoin::secp256k1::{Keypair, Message, PublicKey, XOnlyPublicKey};
        use bitcoin::sighash::{SighashCache, TapSighashType};
        use bitcoin::{Amount, Transaction, TxIn, TxOut, Witness};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
        use deposits_core::{
            SignedLedgerUpdate, TapscriptReservesBuilder, ThresholdConfig, TlvDecode, VoterSet,
        };

        use nostr_sdk::{Filter, Kind};
        use std::collections::HashMap;

        let secp = &self.secp;
        let keypair = Keypair::from_secret_key(secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // Find armed markers (ledgers where we've armed)
        let entries = match std::fs::read_dir(&self.data_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("custody_armed_") || !name.ends_with(".marker") {
                continue;
            }

            // Extract ledger prefix from marker name
            let ledger_prefix = name
                .trim_start_matches("custody_armed_")
                .trim_end_matches(".marker");

            // Skip if already confiscated or revealed
            let confiscated_marker = self
                .data_dir
                .join(format!("confiscated_{}.marker", ledger_prefix));
            let revealed_marker = self
                .data_dir
                .join(format!("lottery_revealed_{}.marker", ledger_prefix));
            if confiscated_marker.exists() || revealed_marker.exists() {
                continue;
            }

            // Skip if we already have a pending confiscation for this ledger
            {
                let pending = self.pending_confiscations.lock().unwrap();
                if pending.contains_key(ledger_prefix) {
                    continue;
                }
            }

            tracing::debug!(
                "Checking if confiscation ready for ledger {}...",
                ledger_prefix
            );

            // Find the fork or original ledger key (prefer fork for dispute operations)
            let ledger_key = match self.find_fork_or_original_by_prefix(ledger_prefix) {
                Some(key) => key,
                None => continue,
            };

            // Extract the base ledger_id (first 64 chars) for Nostr queries
            let ledger_id = if ledger_key.len() > 64 {
                ledger_key[..64].to_string()
            } else {
                ledger_key.clone()
            };

            // Use the slow relay client for historical fetch
            let client = self.nostr.fetch_client();

            let filter = Filter::new()
                .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
                .custom_tag(
                    crate::nostr::TAG_LEDGER_ID,
                    [crate::nostr::ledger_tag(ledger_id.as_str())],
                )
                .limit(500);

            let events = match client
                .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
                .await
            {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Extract DisputeArmed participants, quorum members, and reserves info.
            //
            // The voter set committed in the on-chain Taproot UTXO is exactly
            // what the operator put in the latest `QuorumBegin.quorum_members`
            // — that's the canonical source. Inferring it from QuorumAddMember
            // updates was unreliable: forks rebroadcast the operator's history
            // alongside their own additions; even with the patch that retags
            // fork additions to the forker's pubkey, dispute-time noise (e.g.
            // late QuorumJoin records, multi-fork interactions) added stray
            // members and broke the Taproot reconstruction with a
            // "Witness program hash mismatch".
            let mut participants: Vec<LotteryParticipant> = Vec::new();
            let mut quorum_members: Vec<PublicKey> = Vec::new();
            let mut reserves_address: Option<String> = None;
            let mut ledger_hash: Option<[u8; 32]> = None;
            let mut original_operator: Option<PublicKey> = None;
            let mut latest_quorum_begin_seq: Option<u64> = None;

            for event in events.iter() {
                if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                    if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                            match op {
                                LedgerOperation::LedgerOpen {
                                    operator_id,
                                    reserves_id,
                                    ..
                                } => {
                                    original_operator = Some(operator_id);
                                    // Use LedgerOpen reserves_id as fallback if no QuorumBegin
                                    if reserves_address.is_none() {
                                        reserves_address = Some(reserves_id);
                                    }
                                }
                                LedgerOperation::QuorumBegin {
                                    reserves_id,
                                    ledger_hash: lh,
                                    quorum_members: qm,
                                    ..
                                } => {
                                    // Keep the latest QuorumBegin (highest sequence) since
                                    // multiple rotations may exist on the relay.
                                    let seq = update.sequence_number;
                                    if latest_quorum_begin_seq
                                        .map(|cur| seq > cur)
                                        .unwrap_or(true)
                                    {
                                        latest_quorum_begin_seq = Some(seq);
                                        reserves_address = Some(reserves_id);
                                        ledger_hash = Some(lh);
                                        // Local var is Vec<PublicKey> for downstream
                                        // Taproot reconstruction; extract just the keys.
                                        quorum_members = qm.into_iter().map(|m| m.pubkey).collect();
                                    }
                                }
                                LedgerOperation::DisputeArmed {
                                    commitment_hash,
                                    target_reserves,
                                    ..
                                } => {
                                    let x_only = update.operator_id.x_only_public_key().0;
                                    // Check if we already have this participant
                                    if !participants.iter().any(|p| p.pubkey == x_only) {
                                        participants.push(LotteryParticipant::new(
                                            x_only,
                                            commitment_hash,
                                            target_reserves,
                                        ));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            // Need at least 2 participants to proceed
            if participants.len() < 2 {
                tracing::debug!(
                    "Not enough DisputeArmed participants yet ({}/2)",
                    participants.len()
                );
                continue;
            }

            let original_operator = match original_operator {
                Some(op) => op,
                None => {
                    tracing::debug!(
                        "Could not find original operator (LedgerOpen) for {}",
                        ledger_prefix
                    );
                    continue;
                }
            };
            let reserves_address_str = match reserves_address {
                Some(addr) => addr,
                None => {
                    tracing::debug!("Could not find reserves address for {}", ledger_prefix);
                    continue;
                }
            };
            // ledger_hash comes from QuorumBegin; fall back to fork's current hash
            let ledger_hash_val = match ledger_hash {
                Some(lh) => lh,
                None => {
                    // No QuorumBegin found — use the fork ledger's current hash
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    if let Some(fork_arc) = ledgers.get(&ledger_key) {
                        let fork = fork_arc.read().unwrap();
                        fork.state.chain_tip_hash
                    } else {
                        tracing::debug!("Could not find ledger hash for {}", ledger_prefix);
                        continue;
                    }
                }
            };

            // Filter out original operator from quorum_members (VoterSet adds operator as tie_breaker)
            quorum_members.retain(|pk| *pk != original_operator);

            tracing::info!("All {} participants armed for ledger {}..., initiating confiscation ({} quorum members)",
                participants.len(), ledger_prefix, quorum_members.len());

            // Sort participants by pubkey for deterministic order
            participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

            // Build recovery voters (quorum minus original operator)
            let recovery_voters: Vec<XOnlyPublicKey> = quorum_members
                .iter()
                .filter(|pk| **pk != original_operator)
                .map(|pk| pk.x_only_public_key().0)
                .collect();

            let recovery_threshold = (recovery_voters.len() / 2) + 1;

            // Build the lottery output
            let lottery_builder = LotteryScriptBuilder::new(
                participants.clone(),
                recovery_voters,
                recovery_threshold,
                self.wallet.network(),
            );

            let lottery_output = match lottery_builder.build() {
                Ok(out) => out,
                Err(e) => {
                    tracing::error!("Failed to build lottery output: {:?}", e);
                    continue;
                }
            };

            tracing::info!("  Lottery address: {}", lottery_output.address);

            // Look up reserves UTXO
            let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
                match reserves_address_str.parse() {
                    Ok(a) => a,
                    Err(_) => continue,
                };
            let reserves_addr = match reserves_addr.require_network(self.wallet.network()) {
                Ok(a) => a,
                Err(_) => continue,
            };

            let script_pubkey = reserves_addr.script_pubkey();
            let utxo = match self.wallet.find_utxo_for_script(&script_pubkey) {
                Ok(Some(u)) => u,
                Ok(None) => {
                    tracing::debug!("No unspent reserves UTXO found");
                    continue;
                }
                Err(_) => continue,
            };

            let (reserves_outpoint, reserves_amount) = utxo;
            tracing::info!(
                "  Found reserves: {} sats at {}",
                reserves_amount,
                reserves_outpoint
            );

            // Build confiscation transaction
            let fee_rate = 2u64;
            let estimated_vsize = 200u64;
            let fee = fee_rate * estimated_vsize;
            let output_amount = reserves_amount.saturating_sub(fee);

            let confiscation_tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: reserves_outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(output_amount),
                    script_pubkey: lottery_output.script_pubkey(),
                }],
            };

            // Build the Taproot reserves structure for signing
            let voter_set = VoterSet::new(original_operator, quorum_members.clone());
            let voter_count = voter_set.all_voters().len();
            let threshold_config = ThresholdConfig::default_for_voter_count(voter_count);

            let taproot_builder = TapscriptReservesBuilder::new(
                voter_set.clone(),
                threshold_config.clone(),
                self.wallet.network(),
                ledger_hash_val,
            );

            let taproot_output = match taproot_builder.build() {
                Ok(out) => out,
                Err(e) => {
                    tracing::error!("Failed to build Taproot output: {:?}", e);
                    continue;
                }
            };

            // Diagnostic: confirm the reconstructed Taproot script_pubkey
            // matches the on-chain reserves UTXO. A mismatch here is the
            // root cause of `Witness program hash mismatch` at broadcast,
            // and indicates the reconstruction inputs (voter_set,
            // ledger_hash, threshold_config) drifted from what was used
            // when the rotation tx was built.
            {
                let reconstructed = taproot_output.script_pubkey();
                let on_chain = reserves_addr.script_pubkey();
                if reconstructed != on_chain {
                    tracing::warn!(
                        "Confiscation Taproot mismatch for ledger {}: \
                         reconstructed={}, on-chain={}, voter_count={}, \
                         ledger_hash={}, original_operator={}, members=[{}]",
                        ledger_prefix,
                        hex::encode(reconstructed.as_bytes()),
                        hex::encode(on_chain.as_bytes()),
                        voter_count,
                        hex::encode(ledger_hash_val),
                        hex::encode(original_operator.serialize()),
                        quorum_members
                            .iter()
                            .map(|m| hex::encode(&m.serialize()[..8]))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                }
            }

            // Use quorum-override tier (threshold without tie-breaker)
            let (tier_index, tier) = match threshold_config
                .tiers
                .iter()
                .enumerate()
                .find(|(_, t)| !t.requires_tie_breaker && t.threshold > 1)
            {
                Some(t) => t,
                None => {
                    tracing::error!("No quorum-override tier found");
                    continue;
                }
            };

            tracing::info!(
                "  Using Tier {} for confiscation (threshold={}/{})",
                tier_index,
                tier.threshold,
                voter_count
            );

            // Build leaf script and compute sighash
            let leaf_script = match taproot_builder.build_threshold_leaf(tier) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to build leaf script: {:?}", e);
                    continue;
                }
            };

            let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
                &leaf_script,
                bitcoin::taproot::LeafVersion::TapScript,
            );

            let prevouts = vec![TxOut {
                value: Amount::from_sat(reserves_amount),
                script_pubkey: reserves_addr.script_pubkey(),
            }];

            let mut sighash_cache = SighashCache::new(&confiscation_tx);
            let sighash = match sighash_cache.taproot_script_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            ) {
                Ok(sh) => sh,
                Err(e) => {
                    tracing::error!("Failed to compute sighash: {}", e);
                    continue;
                }
            };

            let sighash_bytes: [u8; 32] = *sighash.as_ref();

            // Sign with our key
            let msg = Message::from_digest(sighash_bytes);
            let our_signature = secp.sign_schnorr(&msg, &keypair);

            let mut signatures: HashMap<PublicKey, [u8; 64]> = HashMap::new();
            signatures.insert(our_pubkey, our_signature.serialize());

            tracing::info!("  Signed with our key");

            // Request signatures from other quorum members via Nostr
            let required_sigs = tier.threshold;
            tracing::info!(
                "  Need {}/{} signatures, requesting co-signatures...",
                required_sigs,
                voter_count
            );

            // If we already have enough signatures (e.g., threshold=1), broadcast immediately
            if signatures.len() >= required_sigs {
                let control_block = match taproot_output.control_block_for_tier(tier_index) {
                    Some(cb) => cb,
                    None => {
                        tracing::error!("Failed to get control block for tier");
                        continue;
                    }
                };

                let mut witness = bitcoin::Witness::new();
                let sorted_keys = voter_set.sorted_x_only_pubkeys();

                for x_only in sorted_keys.iter().rev() {
                    for voter in voter_set.all_voters() {
                        if voter.x_only_public_key().0 == *x_only {
                            if let Some(sig) = signatures.get(&voter) {
                                witness.push(sig);
                            } else {
                                witness.push(&[] as &[u8]);
                            }
                            break;
                        }
                    }
                }

                witness.push(leaf_script.as_bytes());
                witness.push(control_block.serialize());

                let mut confiscation_tx = confiscation_tx;
                confiscation_tx.input[0].witness = witness;

                tracing::info!("  Broadcasting confiscation transaction (enough sigs locally)...");
                match self.wallet.broadcast(&confiscation_tx) {
                    Ok(_) => {
                        let txid = confiscation_tx.compute_txid();
                        tracing::info!("Confiscation transaction broadcast! Txid: {}", txid);
                        if let Err(e) = std::fs::write(&confiscated_marker, txid.to_string()) {
                            tracing::warn!("Failed to write confiscated marker: {}", e);
                        }
                    }
                    Err(e) => tracing::error!("Failed to broadcast confiscation TX: {}", e),
                }
                continue;
            }

            // Send the request and store pending state (non-blocking)
            let unsigned_tx_bytes = bitcoin::consensus::encode::serialize(&confiscation_tx);
            let unsigned_tx_hex = hex::encode(&unsigned_tx_bytes);

            let request_params = serde_json::json!({
                "ledger_id": ledger_id,
                "sighash": hex::encode(sighash_bytes),
                "unsigned_tx": unsigned_tx_hex,
                "lottery_address": lottery_output.address.to_string(),
                "violation_details": "Confiscation to lottery for dispute resolution",
            });

            let request_id = match self
                .nostr
                .send_ledger_request(&ledger_id, "confiscation_sign", request_params)
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("Failed to send sign request: {:?}", e);
                    continue;
                }
            };
            self.track_sent_event(&request_id);

            tracing::info!(
                "  Sent confiscation_sign request {}..., will collect signatures on next cycle",
                &request_id[..16.min(request_id.len())]
            );

            // Store pending state — signatures will be collected on subsequent periodic cycles
            let pending = PendingConfiscation {
                request_id,
                confiscation_tx,
                sighash_bytes,
                signatures,
                required_sigs,
                voter_set,
                tier_index,
                leaf_script,
                taproot_output,
                confiscated_marker,
                lottery_address: lottery_output.address.to_string(),
                ledger_prefix: ledger_prefix.to_string(),
                created_at: std::time::Instant::now(),
            };

            self.pending_confiscations
                .lock()
                .unwrap()
                .insert(ledger_prefix.to_string(), pending);
        }
    }

    /// Auto-reveal preimage when confiscation TX has 3+ confirmations
    ///
    /// For each ledger where we're armed but haven't revealed yet,
    /// check if the lottery UTXO exists with 3+ confirmations.
    pub(crate) async fn auto_reveal_on_confiscation(&self) {
        // Find armed marker files (preimage exists but not revealed)
        let entries = match std::fs::read_dir(&self.data_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        let preimage_files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with("lottery_preimage_") && name.ends_with(".hex")
            })
            .collect();

        for entry in preimage_files {
            let filename = entry.file_name().to_string_lossy().to_string();
            let ledger_prefix = filename
                .strip_prefix("lottery_preimage_")
                .and_then(|s| s.strip_suffix(".hex"))
                .unwrap_or("");

            if ledger_prefix.is_empty() {
                continue;
            }

            // Skip if already revealed
            let revealed_marker = self
                .data_dir
                .join(format!("lottery_revealed_{}.marker", ledger_prefix));
            if revealed_marker.exists() {
                continue;
            }

            // Find the fork or original ledger key (prefer fork for dispute operations)
            let ledger_key = match self.find_fork_or_original_by_prefix(ledger_prefix) {
                Some(key) => key,
                None => continue,
            };

            // Extract the base ledger_id (first 64 chars) for Nostr queries
            let ledger_id = if ledger_key.len() > 64 {
                ledger_key[..64].to_string()
            } else {
                ledger_key.clone()
            };

            // Check if confiscation TX is confirmed with 3+ blocks
            match self.check_confiscation_confirmed(&ledger_id, 3).await {
                Ok(true) => {
                    tracing::info!(
                        "Confiscation TX confirmed +3 for ledger {}. Auto-revealing preimage.",
                        &ledger_id[..16]
                    );
                    self.auto_reveal_preimage(&ledger_id).await;
                }
                Ok(false) => {
                    // Not yet confirmed enough
                }
                Err(e) => {
                    tracing::debug!(
                        "Could not check confiscation for {}: {}",
                        &ledger_id[..16],
                        e
                    );
                }
            }
        }
    }

    /// Check if the confiscation TX for a ledger has enough confirmations
    pub(crate) async fn check_confiscation_confirmed(
        &self,
        ledger_id: &str,
        min_confirmations: u32,
    ) -> Result<bool, Error> {
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use bitcoin::secp256k1::PublicKey;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
        use deposits_core::TlvDecode;

        use nostr_sdk::{Filter, Kind};

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(
                crate::nostr::TAG_LEDGER_ID,
                [crate::nostr::ledger_tag(ledger_id)],
            )
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

        // Extract DisputeArmed participants AND quorum members (must match auto_confiscate)
        let mut participants: Vec<LotteryParticipant> = Vec::new();
        let mut quorum_members: Vec<PublicKey> = Vec::new();
        let mut original_operator: Option<PublicKey> = None;

        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        match op {
                            LedgerOperation::LedgerOpen { operator_id, .. } => {
                                original_operator = Some(operator_id);
                            }
                            LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                                // Only use QuorumAddMember from original operator's updates
                                // (must match auto_confiscate's filtering)
                                let is_from_original = original_operator
                                    .map(|op| update.operator_id == op)
                                    .unwrap_or(true);
                                if is_from_original && !quorum_members.contains(&quorum_member) {
                                    quorum_members.push(quorum_member);
                                }
                            }
                            LedgerOperation::DisputeArmed {
                                commitment_hash,
                                target_reserves,
                                ..
                            } => {
                                let x_only = update.operator_id.x_only_public_key().0;
                                if !participants.iter().any(|p| p.pubkey == x_only) {
                                    participants.push(LotteryParticipant::new(
                                        x_only,
                                        commitment_hash,
                                        target_reserves,
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if participants.len() < 2 {
            return Err(Error::Protocol(
                "Not enough participants for lottery".to_string(),
            ));
        }

        // Sort participants by x-only pubkey for deterministic order
        participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

        // Build recovery voters from quorum_members (must match auto_confiscate)
        if let Some(orig_op) = original_operator {
            quorum_members.retain(|pk| *pk != orig_op);
        }

        let recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey> = quorum_members
            .iter()
            .filter(|pk| original_operator != Some(**pk))
            .map(|pk| pk.x_only_public_key().0)
            .collect();
        let recovery_threshold = (recovery_voters.len() / 2) + 1;

        let lottery_builder = LotteryScriptBuilder::new(
            participants,
            recovery_voters,
            recovery_threshold,
            self.wallet.network(),
        );

        let lottery_output = lottery_builder
            .build()
            .map_err(|e| Error::Protocol(format!("Failed to build lottery output: {:?}", e)))?;

        tracing::debug!(
            "check_confiscation_confirmed: lottery address = {}",
            lottery_output.address
        );

        // Check if lottery address has a UTXO with enough confirmations
        let lottery_script = lottery_output.address.script_pubkey();

        let utxo_result = self.wallet.find_utxo_for_script(&lottery_script)?;

        if utxo_result.is_none() {
            return Ok(false); // No UTXO at lottery address yet
        }

        // Check confirmations
        let current_height = self.wallet.get_block_height().unwrap_or(0);

        // Use armed height heuristic: if UTXO exists and 3+ blocks since we first saw it, confirmed
        let armed_height_file = self.data_dir.join(format!(
            "lottery_armed_height_{}.txt",
            &ledger_id[..16.min(ledger_id.len())]
        ));

        if let Ok(height_str) = std::fs::read_to_string(&armed_height_file) {
            if let Ok(armed_height) = height_str.trim().parse::<u32>() {
                if current_height >= armed_height + min_confirmations {
                    return Ok(true);
                }
            }
        }

        // If no armed height file, create one (first time seeing the UTXO)
        if !armed_height_file.exists() {
            let _ = std::fs::write(&armed_height_file, current_height.to_string());
        }

        Ok(false)
    }

    /// Auto-rotate to quorum and continue ledger after winning
    pub(crate) async fn auto_post_win_cleanup(&self) {
        // Find completed marker files (lottery finished, we might have won)
        let entries = match std::fs::read_dir(&self.data_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        let completed_markers: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with("lottery_completed_") && name.ends_with(".marker")
            })
            .collect();

        for entry in completed_markers {
            let filename = entry.file_name().to_string_lossy().to_string();
            let ledger_prefix = filename
                .strip_prefix("lottery_completed_")
                .and_then(|s| s.strip_suffix(".marker"))
                .unwrap_or("");

            if ledger_prefix.is_empty() {
                continue;
            }

            // Skip if already rotated
            let rotated_marker = self
                .data_dir
                .join(format!("lottery_rotated_{}.marker", ledger_prefix));
            if rotated_marker.exists() {
                continue;
            }

            // Find the fork or original ledger key (prefer fork for dispute operations)
            let ledger_key = match self.find_fork_or_original_by_prefix(ledger_prefix) {
                Some(key) => key,
                None => continue,
            };

            // Extract the base ledger_id (first 64 chars) for Nostr queries
            let ledger_id = if ledger_key.len() > 64 {
                ledger_key[..64].to_string()
            } else {
                ledger_key.clone()
            };

            // Check if we won (we published DisputeAcquire)
            match self.check_if_we_won(&ledger_id).await {
                Ok(true) => {
                    tracing::info!(
                        "We won lottery for {}. Auto-rotating to quorum...",
                        &ledger_id[..16]
                    );

                    // Auto-rotate
                    match self.auto_rotate_to_quorum(&ledger_id).await {
                        Ok(()) => {
                            // Mark as rotated
                            let _ = std::fs::write(&rotated_marker, "rotated");
                            tracing::info!("Rotation complete for {}", &ledger_id[..16]);

                            // Auto-continue
                            if let Err(e) = self.auto_continue_ledger(&ledger_id).await {
                                tracing::warn!("Auto-continue failed: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Auto-rotate failed for {}: {}", &ledger_id[..16], e);
                        }
                    }
                }
                Ok(false) => {
                    // We didn't win, nothing to do
                    let _ = std::fs::write(&rotated_marker, "not_winner");
                }
                Err(e) => {
                    tracing::debug!("Could not check win status for {}: {}", &ledger_id[..16], e);
                }
            }
        }
    }

    /// Check if we won the lottery for a ledger (we published DisputeAcquire)
    pub(crate) async fn check_if_we_won(&self, ledger_id: &str) -> Result<bool, Error> {
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        use deposits_core::messages::LedgerOperation;
        use deposits_core::TlvDecode;

        use nostr_sdk::{Filter, Kind};

        let secp = &self.secp;
        let keypair =
            bitcoin::secp256k1::Keypair::from_secret_key(secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(
                crate::nostr::TAG_LEDGER_ID,
                [crate::nostr::ledger_tag(ledger_id)],
            )
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

        // Check if we have a DisputeAcquire
        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if update.operator_id == our_pubkey {
                        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                            if matches!(op, LedgerOperation::DisputeAcquire { .. }) {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }
}
