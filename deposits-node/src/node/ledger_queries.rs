use super::*;

impl Node {
    /// Auto-rotate winnings to quorum-controlled Taproot
    pub(crate) async fn auto_rotate_to_quorum(&self, ledger_id: &str) -> Result<(), Error> {
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Message, PublicKey};
        use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::{
            SignedLedgerUpdate, TapscriptReservesBuilder, TlvDecode, TlvEncode, VoterSet,
        };

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

        // Find our DisputeAcquire and quorum members
        let mut current_reserves_address: Option<String> = None;
        let mut our_latest: Option<SignedLedgerUpdate> = None;
        let mut quorum_members: Vec<PublicKey> = Vec::new();

        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if update.operator_id == our_pubkey {
                        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                            if let LedgerOperation::DisputeAcquire {
                                ref new_reserves_address,
                                ..
                            } = op
                            {
                                current_reserves_address = Some(new_reserves_address.clone());
                            }
                            if let LedgerOperation::QuorumAddMember { quorum_member, .. } = op {
                                if !quorum_members.contains(&quorum_member) {
                                    quorum_members.push(quorum_member);
                                }
                            }
                        }
                        if our_latest.is_none()
                            || update.sequence_number > our_latest.as_ref().unwrap().sequence_number
                        {
                            our_latest = Some(update);
                        }
                    }
                }
            }
        }

        let current_reserves_address = current_reserves_address
            .ok_or_else(|| Error::Protocol("No DisputeAcquire found".to_string()))?;
        let our_latest =
            our_latest.ok_or_else(|| Error::Protocol("No latest update found".to_string()))?;

        if quorum_members.is_empty() {
            return Err(Error::Protocol("No quorum members found".to_string()));
        }

        tracing::info!(
            "Rotating from {} with {} quorum members",
            &current_reserves_address[..20.min(current_reserves_address.len())],
            quorum_members.len()
        );

        // Find UTXO at current reserves address
        let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            current_reserves_address
                .parse()
                .map_err(|e| Error::Protocol(format!("Invalid address: {}", e)))?;
        let reserves_addr = reserves_addr
            .require_network(self.wallet.network())
            .map_err(|e| Error::Protocol(format!("Network mismatch: {}", e)))?;

        let script_pubkey = reserves_addr.script_pubkey();
        let utxo = self
            .wallet
            .find_utxo_for_script(&script_pubkey)?
            .ok_or_else(|| Error::Protocol("No UTXO at reserves address".to_string()))?;

        let (outpoint, amount) = utxo;

        // Build new Taproot reserves with quorum
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let expiry_block = current_block + 1000; // 1000 blocks expiry

        // Build voter set - we are tie-breaker, others are additional voters
        let other_voters: Vec<bitcoin::secp256k1::PublicKey> = quorum_members
            .iter()
            .filter(|m| **m != our_pubkey)
            .copied()
            .collect();
        let voter_set = VoterSet::new(our_pubkey, other_voters);

        // Compute quorum parameters for QuorumBegin
        let _quorum_size = quorum_members.len() as u8;
        let _quorum_threshold = quorum_members.len().div_ceil(2) as u8;
        let quorum_expiry = expiry_block;

        // Compute ledger hash
        let ledger_hash = our_latest.current_hash;

        // Build Taproot reserves with default config
        let tapscript_builder =
            TapscriptReservesBuilder::with_defaults(voter_set, self.wallet.network(), ledger_hash);

        let taproot_output = tapscript_builder
            .build()
            .map_err(|e| Error::Protocol(format!("Failed to build taproot output: {:?}", e)))?;

        // Build rotation TX
        let fee = 300u64;
        let output_amount = amount.saturating_sub(fee);

        let rotate_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_amount),
                script_pubkey: taproot_output.address.script_pubkey(),
            }],
        };

        // Sign the transaction (P2WPKH spend from our target_reserves)
        let pubkey_bytes: [u8; 33] = our_pubkey.serialize();
        let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| Error::Protocol(format!("Invalid pubkey: {}", e)))?;

        use bitcoin::sighash::{EcdsaSighashType, SighashCache};
        let _prevouts = [TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: script_pubkey.clone(),
        }];

        let mut sighash_cache = SighashCache::new(&rotate_tx);
        let sighash = sighash_cache
            .p2wpkh_signature_hash(
                0,
                &script_pubkey,
                Amount::from_sat(amount),
                EcdsaSighashType::All,
            )
            .map_err(|e| Error::Protocol(format!("Sighash error: {}", e)))?;

        let msg = Message::from_digest(*sighash.as_ref());
        let signature = secp.sign_ecdsa(&msg, &self.wallet.operator_secret());

        // Build witness
        let mut sig_bytes = signature.serialize_der().to_vec();
        sig_bytes.push(EcdsaSighashType::All as u8);

        let mut rotate_tx = rotate_tx;
        rotate_tx.input[0].witness.push(sig_bytes);
        rotate_tx.input[0].witness.push(compressed.to_bytes());

        // Broadcast
        let rotate_txid = self.wallet.broadcast(&rotate_tx)?;
        tracing::info!("Rotation TX broadcast: {}", rotate_txid);

        // Compute total attested collateral from the ledger state
        let total_collateral = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .map(|arc| arc.read().unwrap().state.total_collateral())
                .unwrap_or(0)
        };

        // Publish QuorumBegin operation (convert sats to msats at boundary)
        let operation = LedgerOperation::QuorumBegin {
            reserves_id: taproot_output.address.to_string(),
            spending_txid: *outpoint.txid.as_ref(),
            new_outpoint_txid: *rotate_txid.as_ref(),
            new_outpoint_vout: 0,
            amount: output_amount.saturating_mul(1000), // sats to msats
            quorum_expiry,
            ledger_hash,
            quorum_members: quorum_members.clone(),
            collateral_amount: total_collateral,
        };

        let message_bytes = operation.tlv_encode();

        let sequence = our_latest.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&our_latest.current_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(our_latest.current_hash),
            sequence,
            hex::encode(new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let msg = Message::from_digest(*msg_hash.as_ref());
        let signature = secp.sign_schnorr(&msg, &keypair);
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
            .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: deposits_core::messages::consts::QUORUM_BEGIN,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_latest.current_hash,
            current_hash: new_hash,
            block_height: current_block,
            block_hash,
        };

        self.nostr
            .broadcast_ledger_update(&signed_update)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast QuorumBegin: {:?}", e)))?;

        tracing::info!(
            "QuorumBegin published. New reserves at: {}",
            taproot_output.address
        );
        Ok(())
    }

    /// Auto-continue ledger after rotation (re-open deposits)
    pub(crate) async fn auto_continue_ledger(&self, ledger_id: &str) -> Result<(), Error> {
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::Message;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::{SignedLedgerUpdate, TlvDecode, TlvEncode};

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

        // Find our latest update and collect original depositors (deposit_id, descriptor)
        let mut our_latest: Option<SignedLedgerUpdate> = None;
        let mut original_depositors: Vec<(DepositId, String)> = Vec::new();

        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    // Collect depositors
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::DepositOpen {
                            deposit_id,
                            descriptor,
                            ..
                        } = op
                        {
                            if !original_depositors.iter().any(|(id, _)| *id == deposit_id) {
                                original_depositors.push((deposit_id, descriptor));
                            }
                        }
                    }

                    if update.operator_id == our_pubkey
                        && (our_latest.is_none()
                            || update.sequence_number
                                > our_latest.as_ref().unwrap().sequence_number)
                    {
                        our_latest = Some(update);
                    }
                }
            }
        }

        let mut our_latest =
            our_latest.ok_or_else(|| Error::Protocol("No latest update found".to_string()))?;

        if original_depositors.is_empty() {
            tracing::info!("No original depositors to re-open");
            return Ok(());
        }

        tracing::info!("Re-opening {} deposits", original_depositors.len());

        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Re-open each deposit
        for (deposit_id, descriptor) in original_depositors {
            let operation = LedgerOperation::DepositOpen {
                deposit_id,
                descriptor: descriptor.clone(),
                fees: None,
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
            };

            let message_bytes = operation.tlv_encode();

            let sequence = our_latest.sequence_number + 1;
            let mut hash_input = Vec::new();
            hash_input.extend_from_slice(&sequence.to_le_bytes());
            hash_input.extend_from_slice(&our_latest.current_hash);
            hash_input.extend_from_slice(&message_bytes);
            let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

            let update_msg = format!(
                "deposits:ledger:{}:{}:{}",
                hex::encode(our_latest.current_hash),
                sequence,
                hex::encode(new_hash)
            );
            let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
            let msg = Message::from_digest(*msg_hash.as_ref());
            let signature = secp.sign_schnorr(&msg, &keypair);
            let operator_sig_bytes: [u8; 64] = *signature.as_ref();

            let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
                .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
                .try_into()
                .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

            let signed_update = SignedLedgerUpdate {
                message: message_bytes,
                message_type: deposits_core::messages::consts::DEPOSIT_OPEN,
                operator_signature: operator_sig_bytes,
                cosigner_pubkey: None,
                member_ledger_hash: None,
                cosignatures: Vec::new(),
                cosign_signature: [0u8; 64],
                operator_id: our_pubkey,
                ledger_id: ledger_id_bytes,
                sequence_number: sequence,
                previous_hash: our_latest.current_hash,
                current_hash: new_hash,
                block_height: current_block,
                block_hash,
            };

            self.nostr
                .broadcast_ledger_update(&signed_update)
                .await
                .map_err(|e| {
                    Error::Protocol(format!("Failed to broadcast DepositOpen: {:?}", e))
                })?;

            tracing::info!("Re-opened deposit {}...", hex::encode(&deposit_id[..8]));

            // Update our_latest for next iteration
            our_latest = signed_update;
        }

        tracing::info!("Ledger continue complete");
        Ok(())
    }

    /// Handle an inbound message
    pub(crate) fn handle_inbound(&self, inbound: InboundMessage) {
        tracing::debug!("Received message from {}", inbound.sender);
        if let Err(e) = self.handler.handle_message(inbound.message, inbound.sender) {
            tracing::error!("Failed to handle message: {}", e);
        }
    }

    /// Get the data directory path.
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    /// Get the wallet balance
    pub fn wallet_balance(&self) -> Result<u64, Error> {
        self.wallet.get_wallet_balance()
    }

    /// Get the reserves balance
    pub fn reserves_balance(&self) -> Result<u64, Error> {
        self.wallet.get_reserves_balance()
    }

    /// Get a new address
    pub fn new_address(&self) -> Result<bitcoin::Address, Error> {
        self.wallet.get_new_address()
    }

    /// Create a reserves output
    pub fn create_reserves(
        &self,
        amount_sats: u64,
        partners: Vec<PublicKey>,
        threshold: usize,
    ) -> Result<crate::wallet::ReservesOutput, Error> {
        self.wallet
            .create_reserves_output(amount_sats, partners, threshold)
    }

    // ========================================================================
    // Ledger Management
    // ========================================================================

    /// Open a new ledger backed by our reserves UTXO
    ///
    /// This creates a self-ledger where we are the operator.
    ///
    /// For BDK, the ledger is identified by the reserves UTXO address (stored in
    /// reserves_id). The reserves_id field uses our own pubkey since there is
    /// no separate partner node.
    pub fn open_ledger(&self) -> Result<Ledger, Error> {
        // Find an unused reserves output (not already backing a ledger)
        let all_reserves = self.wallet.get_reserves();
        if all_reserves.is_empty() {
            return Err(Error::NoReserves);
        }

        // Addresses of reserves already backing ledgers.
        // Each reserves has a unique P2WSH address (ensured by timeout_height offset
        // in create_reserves_output), so address-based matching is correct.
        let used_addresses: std::collections::HashSet<String> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .values()
                .map(|l| l.read().unwrap().state.reserves_key.clone())
                .collect()
        };

        let unused = all_reserves
            .iter()
            .find(|r| {
                let addr =
                    bitcoin::Address::p2wsh(&r.redeem_script, self.wallet.network()).to_string();
                !used_addresses.contains(&addr)
            })
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "All {} reserves are already backing ledgers ({} used addresses)",
                    all_reserves.len(),
                    used_addresses.len()
                ))
            })?;

        let reserves_balance = unused.amount;
        let reserves_outpoint = Some(unused.outpoint);
        let reserves_address =
            bitcoin::Address::p2wsh(&unused.redeem_script, self.wallet.network()).to_string();

        if reserves_balance == 0 {
            return Err(Error::NoReserves);
        }

        // Get funding txid and vout from reserves outpoint
        let (funding_txid, funding_vout) = if let Some(outpoint) = reserves_outpoint {
            (outpoint.txid.to_byte_array(), outpoint.vout as u16)
        } else {
            ([0u8; 32], 0u16)
        };

        // For BDK, use the reserves address as the reserves_id (identifies the reserves UTXO)
        let reserves_id = reserves_address;

        // Get or create the ledger - this automatically adds LedgerOpen (with reserves_amount)
        // if it's a new ledger for our own operator
        // Convert reserves_balance from sats to msats at the on-chain boundary
        let reserves_balance_msats = reserves_balance.saturating_mul(1000);
        let ledger_arc = self.handler.get_or_create_ledger_with_outpoint(
            self.node_id,
            reserves_id.clone(),
            Some(reserves_balance_msats),
            None,
        );

        // Update state, get ledger_id
        let ledger_id = {
            let ledger_guard = ledger_arc.write().unwrap();
            // spend_to removed with legacy ReservesOutput struct
            ledger_guard.ledger_id_hex()
        };

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger_to_disk(&ledger_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        // Create handshake message to send to partner (wire protocol)
        // Note: For BDK self-ledger, this handshake may be sent to self or skipped
        let handshake_msg = deposits_core::messages::HandshakeMsg {
            protocol_version: deposits_core::messages::PROTOCOL_VERSION,
            min_protocol_version: deposits_core::messages::PROTOCOL_VERSION,
            features: 0,
            operator_id: self.node_id,
            reserves_id: reserves_id.clone(),
            funding_txid,
            funding_vout,
        };

        // Queue the handshake message (for BDK, sent to self as there's no remote partner)
        let _ = self.handler.queue_message(
            self.node_id,
            deposits_core::messages::DepositsMessage::Handshake(handshake_msg),
        );

        // Return the ledger (we already have ledger_arc from above)
        let ledger = ledger_arc.read().unwrap().clone();
        Ok(ledger)
    }

    /// List all ledgers
    pub fn list_ledgers(&self) -> HashMap<String, Arc<RwLock<Ledger>>> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        ledgers.clone()
    }

    /// Import a ledger from an export (validates before storing)
    pub fn import_ledger(
        &self,
        export: deposits_core::validation::LedgerExport,
    ) -> Result<(deposits_core::validation::ValidationReport, Ledger), String> {
        let (report, ledger_arc) = self.handler.import_ledger(export)?;
        let ledger = ledger_arc.read().unwrap().clone();
        Ok((report, ledger))
    }

    // ========================================================================
    // Quorum Member Management
    // ========================================================================

    /// Request a peer to be a quorum member
    pub async fn request_quorum_member(&self, peer: PublicKey) -> Result<(), Error> {
        // Create a coordination message for quorum membership request
        // For now, this is a simple handshake-like message
        let request_msg = deposits_core::messages::DepositsMessage::Handshake(
            deposits_core::messages::HandshakeMsg {
                protocol_version: deposits_core::messages::PROTOCOL_VERSION,
                min_protocol_version: deposits_core::messages::PROTOCOL_VERSION,
                features: 0x01, // Flag indicating partnership request
                operator_id: self.node_id,
                reserves_id: peer.to_string(),
                funding_txid: [0u8; 32],
                funding_vout: 0,
            },
        );

        // Send via Nostr
        self.nostr.send_message(peer, request_msg).await?;

        Ok(())
    }

    /// List all quorum members across all ledgers
    /// Returns (identifier, role) tuples where identifier is pubkey or ledger_id string
    /// Returns (our_ledgers, joined_quorums) for display.
    /// our_ledgers: Vec<(ledger_id, active_members, pending_members)>
    /// joined_quorums: grouped by our_ledger_id -> Vec<(operator_id, their_ledger_id, expires)>
    pub fn list_quorum_info(
        &self,
    ) -> (
        Vec<(String, Vec<PublicKey>, Vec<PublicKey>)>,
        Vec<(String, Vec<(PublicKey, String, u32)>)>,
    ) {
        let ledgers = self.handler.ledgers.lock().unwrap();

        let mut our_ledgers = Vec::new();
        // Map from our_ledger_id -> Vec<(operator, their_ledger, expires)>
        let mut joined_by_ledger: std::collections::BTreeMap<
            String,
            Vec<(PublicKey, String, u32)>,
        > = std::collections::BTreeMap::new();

        for (ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();

            if ledger.operator_key() == self.node_id {
                let active: Vec<PublicKey> = ledger
                    .state
                    .quorum_members
                    .iter()
                    .map(|m| m.pubkey)
                    .collect();
                let pending: Vec<PublicKey> = ledger
                    .state
                    .next_quorum_members
                    .iter()
                    .filter(|m| !active.contains(&m.pubkey))
                    .map(|m| m.pubkey)
                    .collect();
                our_ledgers.push((ledger_id.clone(), active, pending));

                // Collect joined quorums only from our own ledgers
                for jq in &ledger.state.joined_quorums {
                    joined_by_ledger
                        .entry(ledger_id.clone())
                        .or_default()
                        .push((jq.operator_id, jq.ledger_id.clone(), jq.membership_expires));
                }
            }
        }

        our_ledgers.sort_by(|a, b| a.0.cmp(&b.0));
        let joined: Vec<_> = joined_by_ledger.into_iter().collect();

        (our_ledgers, joined)
    }

    /// Rotate reserves to use quorum-based Taproot spending
    ///
    /// This creates a new reserves output with tiered spending:
    /// - Tier 0: Majority of quorum + operator (immediate)
    /// - Tier 1: Operator only after first quorum member expires
    /// - Tier 2: Emergency recovery after extended timeout
    ///
    /// The rotation should be scheduled before the first quorum member expires
    /// to maintain quorum-based security.
    ///
    /// # Arguments
    /// * `ledger_id` - The ledger ID (hex-encoded hash)
    ///
    /// # Returns
    /// The new Taproot reserves address and txid, or error if rotation fails
    pub async fn rotate_reserves_to_quorum(
        &self,
        ledger_id: &str,
    ) -> Result<RotateReservesResult, Error> {
        // --- Phase 1: snapshot membership + ledger state ---
        let ledger_arc = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone()
        };

        let (quorum_members, quorum_expiries, ledger_hash, total_collateral) = {
            let ledger = ledger_arc.read().unwrap();

            // QuorumBegin promotes next_quorum_members -> quorum_members, so at rotation
            // time the members are still in next_quorum_members (pending).
            // Fall back to active quorum_members for re-rotation after an existing QuorumBegin.
            let members: Vec<PublicKey> = if !ledger.state.next_quorum_members.is_empty() {
                ledger
                    .state
                    .next_quorum_members
                    .iter()
                    .map(|m| m.pubkey)
                    .collect()
            } else {
                ledger
                    .state
                    .quorum_members
                    .iter()
                    .map(|m| m.pubkey)
                    .collect()
            };

            let current_block = self.wallet.get_block_height().unwrap_or(0);
            let default_expiry = current_block + 1000; // ~1 week

            // TODO: Get actual expiries from quorum member info in ledger
            let expiries: Vec<u32> = members.iter().map(|_| default_expiry).collect();

            let hash = ledger.hash();
            let collateral = ledger.state.total_collateral();

            (members, expiries, hash, collateral)
        };

        if quorum_members.is_empty() {
            return Err(Error::Protocol(
                "No quorum members to rotate to. Add quorum members first.".to_string(),
            ));
        }

        // --- Phase 2: construct + broadcast rotation tx ---
        let result = self.wallet.rotate_reserves_to_taproot(
            quorum_members.clone(),
            quorum_expiries.clone(),
            ledger_hash,
        )?;
        let txid = self.wallet.broadcast(&result.tx)?;

        tracing::info!(
            "Rotated reserves to Taproot quorum-based output: txid={}, address={}, {} members, first expiry at block {}",
            txid,
            result.address,
            quorum_members.len(),
            result.quorum_expiry
        );

        // --- Phase 3: wait for the UTXO to reach the cosigner's required depth ---
        //
        // Staged members will refuse to cosign a QuorumBegin whose referenced
        // UTXO hasn't confirmed yet (they independently verify via Esplora).
        // Without this wait the cosign round immediately times out on every
        // first QuorumBegin. Timeout is generous so block-time variance
        // doesn't sporadically fail legitimate rotations; tune shorter if a
        // genuine bad-UTXO is suspected.
        let required_confs =
            deposits_core::quorum_policy::default_quorum_begin_confs(self.wallet.network());
        wait_for_outpoint_confs(
            &self.wallet,
            txid,
            result.outpoint.vout,
            required_confs,
            std::time::Duration::from_secs(600),
        )
        .await?;

        // --- Phase 4: stage + cosign + commit the QuorumBegin operation ---
        let txid_bytes: [u8; 32] = {
            let mut bytes = txid.to_byte_array();
            bytes.reverse(); // Bitcoin txids are displayed in reverse byte order
            bytes
        };
        let operation = LedgerOperation::QuorumBegin {
            reserves_id: result.address.to_string(),
            spending_txid: txid_bytes,
            new_outpoint_txid: txid_bytes,
            new_outpoint_vout: result.outpoint.vout,
            amount: result.amount.saturating_mul(1000),
            quorum_expiry: result.quorum_expiry,
            ledger_hash,
            quorum_members: quorum_members.clone(),
            collateral_amount: total_collateral,
        };

        // commit_operation runs the full stage → cosign → operator-sign →
        // apply → persist → broadcast flow. For a first QuorumBegin (state
        // is still PreQuorum here) it goes through request_cosign against
        // next_quorum_members and embeds their signatures into the update,
        // producing a result that peers' validators will accept.
        self.commit_operation(ledger_id, operation).await?;

        tracing::info!(
            "Committed QuorumBegin operation to ledger: txid={}, quorum={} members",
            txid,
            quorum_members.len()
        );

        Ok(RotateReservesResult {
            txid: txid.to_string(),
            new_address: result.address.to_string(),
            amount_sats: result.amount,
            quorum_member_count: quorum_members.len(),
            quorum_expiry: result.quorum_expiry,
            ledger_hash,
        })
    }

    // ========================================================================
    // Deposit Offer Management (On-Chain Funding)
    // ========================================================================

    /// Create a deposit offer for on-chain funding
    ///
    /// This creates a signed commitment from the operator to credit a deposit
    /// with funds sent to a specific address, up to a maximum amount, before
    /// a deadline block.
    ///
    /// The `ledger_id` should be the 64-char hex hash that identifies the ledger
    /// (stable across custody transfers).
    pub fn create_deposit_offer(
        &self,
        ledger_id: &str,
        deposit_pubkey: PublicKey,
        max_amount_sats: u64,
        min_amount_sats: u64,
        blocks_valid: u32,
        fees: Option<FeeStructure>,
    ) -> Result<DepositOffer, Error> {
        // Get current block height
        let current_block = self.wallet.get_block_height()?;
        let deadline_block = current_block + blocks_valid;

        // Generate a new funding address
        let funding_address = self.wallet.get_new_address()?;
        let funding_address_str = funding_address.to_string();

        // Create descriptor and compute deposit_id from pubkey
        let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);

        // Get the signing message and compute offer ID
        let signing_message = DepositOffer::signing_message(
            &self.node_id,
            ledger_id,
            &deposit_id,
            &funding_address_str,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        );
        let offer_id = DepositOffer::compute_offer_id(&signing_message);

        // Sign the offer
        let signature = deposits_core::create_deposit_offer_signature(
            &self.wallet.operator_secret(),
            &self.node_id,
            ledger_id,
            &deposit_id,
            &funding_address_str,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        )
        .map_err(|e| Error::Protocol(format!("Failed to sign offer: {:?}", e)))?;

        // Create the offer
        let offer = DepositOffer {
            operator_id: self.node_id,
            ledger_id: ledger_id.to_string(),
            deposit_id,
            descriptor,
            funding_address: funding_address_str,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
            created_at_block: current_block,
            offer_id,
            operator_signature: signature,
            fees,
            transfer_fees: None,
        };

        // Store the offer
        {
            let mut offers = self.deposit_offers.lock().unwrap();
            offers.insert(offer_id, (offer.clone(), DepositOfferStatus::Pending));
        }

        // Persist to disk
        self.save_deposit_offers()?;

        tracing::info!(
            "Created deposit offer {} for {} sats to {}",
            hex::encode(&offer_id[..8]),
            max_amount_sats,
            offer.funding_address
        );

        Ok(offer)
    }

    /// List all deposit offers
    pub fn list_deposit_offers(&self) -> Vec<(DepositOffer, DepositOfferStatus)> {
        let offers = self.deposit_offers.lock().unwrap();
        offers.values().cloned().collect()
    }

    /// Get a specific deposit offer by ID
    pub fn get_deposit_offer(
        &self,
        offer_id: &[u8; 32],
    ) -> Option<(DepositOffer, DepositOfferStatus)> {
        let offers = self.deposit_offers.lock().unwrap();
        offers.get(offer_id).cloned()
    }

    /// Update the status of a deposit offer
    pub fn update_deposit_offer_status(
        &self,
        offer_id: &[u8; 32],
        status: DepositOfferStatus,
    ) -> Result<(), Error> {
        {
            let mut offers = self.deposit_offers.lock().unwrap();
            if let Some((_, ref mut current_status)) = offers.get_mut(offer_id) {
                *current_status = status;
            } else {
                return Err(Error::Protocol("Deposit offer not found".to_string()));
            }
        }
        self.save_deposit_offers()
    }

    /// Check for expired offers and update their status
    pub fn check_expired_offers(&self) -> Result<Vec<[u8; 32]>, Error> {
        let current_block = self.wallet.get_block_height()?;
        let mut expired = Vec::new();

        {
            let mut offers = self.deposit_offers.lock().unwrap();
            for (offer_id, (offer, status)) in offers.iter_mut() {
                if matches!(status, DepositOfferStatus::Pending) && offer.is_expired(current_block)
                {
                    *status = DepositOfferStatus::Expired {
                        expired_at_block: current_block,
                    };
                    expired.push(*offer_id);
                }
            }
        }

        if !expired.is_empty() {
            self.save_deposit_offers()?;
        }

        Ok(expired)
    }

    /// Load deposit offers from disk
    /// Load pending invoices from disk
    pub(crate) fn load_pending_invoices(data_dir: &PathBuf) -> HashMap<[u8; 32], PendingInvoice> {
        let path = data_dir.join("wallet").join("pending_invoices.json");
        if !path.exists() {
            return HashMap::new();
        }
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let invoices: Vec<PendingInvoice> =
                    serde_json::from_str(&contents).unwrap_or_default();
                let mut map = HashMap::new();
                for inv in invoices {
                    if let Ok(hash_bytes) = hex::decode(&inv.payment_hash_hex) {
                        if hash_bytes.len() == 32 {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&hash_bytes);
                            map.insert(key, inv);
                        }
                    }
                }
                if !map.is_empty() {
                    tracing::info!("Loaded {} pending invoices from disk", map.len());
                }
                map
            }
            Err(e) => {
                tracing::warn!("Failed to read pending invoices: {}", e);
                HashMap::new()
            }
        }
    }

    /// Save pending invoices to disk
    pub(crate) fn save_pending_invoices(&self) {
        let path = self.data_dir.join("wallet").join("pending_invoices.json");
        let invoices: Vec<PendingInvoice> = self
            .pending_invoices
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&invoices) {
            if let Err(e) = std::fs::write(&path, json) {
                tracing::warn!("Failed to save pending invoices: {}", e);
            }
        }
    }

    pub(crate) fn load_deposit_offers(
        data_dir: &PathBuf,
    ) -> Result<HashMap<[u8; 32], (DepositOffer, DepositOfferStatus)>, Error> {
        let offers_file = data_dir.join("wallet").join("deposit_offers.json");
        if !offers_file.exists() {
            return Ok(HashMap::new());
        }

        let contents = std::fs::read_to_string(&offers_file)
            .map_err(|e| Error::Wallet(format!("Failed to read deposit offers: {}", e)))?;

        let offers: Vec<(DepositOffer, DepositOfferStatus)> = serde_json::from_str(&contents)
            .map_err(|e| Error::Wallet(format!("Failed to parse deposit offers: {}", e)))?;

        let mut map = HashMap::new();
        for (offer, status) in offers {
            map.insert(offer.offer_id, (offer, status));
        }

        tracing::debug!("Loaded {} deposit offers from disk", map.len());
        Ok(map)
    }

    /// Save deposit offers to disk
    pub(crate) fn save_deposit_offers(&self) -> Result<(), Error> {
        let offers_file = self.data_dir.join("wallet").join("deposit_offers.json");

        let offers: Vec<(DepositOffer, DepositOfferStatus)> = {
            let offers = self.deposit_offers.lock().unwrap();
            offers.values().cloned().collect()
        };

        let contents = serde_json::to_string_pretty(&offers)
            .map_err(|e| Error::Wallet(format!("Failed to serialize deposit offers: {}", e)))?;

        std::fs::write(&offers_file, contents)
            .map_err(|e| Error::Wallet(format!("Failed to write deposit offers: {}", e)))?;

        tracing::info!("Saved {} deposit offers to disk", offers.len());

        // Update metrics
        self.update_pending_offers_metric();

        Ok(())
    }

    /// Update the pending deposit offers metric
    pub(crate) fn update_pending_offers_metric(&self) {
        let offers = self.deposit_offers.lock().unwrap();
        let pending_count = offers
            .values()
            .filter(|(_, status)| matches!(status, DepositOfferStatus::Pending))
            .count();
        metrics::set_pending_deposit_offers(pending_count);
    }

    /// Reload deposit offers from disk (merges with in-memory state)
    ///
    /// This is needed when CLI commands modify the deposit_offers file
    /// outside of the running daemon.
    pub(crate) fn reload_deposit_offers(&self) {
        let disk_offers = match Self::load_deposit_offers(&self.data_dir) {
            Ok(offers) => offers,
            Err(e) => {
                tracing::warn!("Failed to reload deposit offers: {}", e);
                return;
            }
        };

        let mut memory_offers = self.deposit_offers.lock().unwrap();

        // Update in-memory state with any changes from disk
        for (offer_id, (disk_offer, disk_status)) in disk_offers {
            if let Some((_, ref mut memory_status)) = memory_offers.get_mut(&offer_id) {
                // If disk has a "more complete" status, use it
                // Pending < FundingReceived < Completed/Expired/Cancelled
                let should_update = matches!(
                    (&*memory_status, &disk_status),
                    (
                        DepositOfferStatus::Pending,
                        DepositOfferStatus::FundingReceived { .. }
                    ) | (
                        DepositOfferStatus::Pending,
                        DepositOfferStatus::Completed { .. }
                    ) | (
                        DepositOfferStatus::Pending,
                        DepositOfferStatus::Expired { .. }
                    ) | (DepositOfferStatus::Pending, DepositOfferStatus::Cancelled)
                        | (
                            DepositOfferStatus::FundingReceived { .. },
                            DepositOfferStatus::Completed { .. },
                        )
                );

                if should_update {
                    tracing::debug!(
                        "Reloaded deposit offer {}...: {:?} -> {:?}",
                        hex::encode(&offer_id[..8]),
                        memory_status,
                        disk_status
                    );
                    *memory_status = disk_status;
                }
            } else {
                // New offer on disk, add to memory
                memory_offers.insert(offer_id, (disk_offer, disk_status));
            }
        }

        // Update metrics - need to count pending within the lock
        let pending_count = memory_offers
            .values()
            .filter(|(_, status)| matches!(status, DepositOfferStatus::Pending))
            .count();
        drop(memory_offers);
        metrics::set_pending_deposit_offers(pending_count);
    }

    // ========================================================================
    // On-Chain Withdrawal Management
    // ========================================================================

    /// Cancel a withdrawal (only if not yet broadcast)
    pub fn cancel_withdrawal(&self, withdrawal_id: &[u8; 32], reason: String) -> Result<(), Error> {
        let current_block = self.wallet.get_block_height()?;

        {
            let mut withdrawals = self.withdrawals.lock().unwrap();
            match withdrawals.get_mut(withdrawal_id) {
                Some((_, status @ OnChainWithdrawalStatus::Locked { .. })) => {
                    *status = OnChainWithdrawalStatus::Cancelled {
                        cancelled_at_block: current_block,
                        reason,
                    };
                }
                Some((_, status)) => {
                    return Err(Error::Protocol(format!(
                        "Cannot cancel withdrawal in state: {:?}",
                        status
                    )));
                }
                None => return Err(Error::OfferNotFound),
            }
        }

        self.save_withdrawals()?;
        Ok(())
    }

    /// List all withdrawals
    pub fn list_withdrawals(&self) -> Vec<(OnChainWithdrawal, OnChainWithdrawalStatus)> {
        let withdrawals = self.withdrawals.lock().unwrap();
        withdrawals.values().cloned().collect()
    }

    /// Get a specific withdrawal by ID
    pub fn get_withdrawal(
        &self,
        withdrawal_id: &[u8; 32],
    ) -> Option<(OnChainWithdrawal, OnChainWithdrawalStatus)> {
        let withdrawals = self.withdrawals.lock().unwrap();
        withdrawals.get(withdrawal_id).cloned()
    }

    /// Fetch BTC/USD price and publish as a Nostr price oracle event.
    pub(crate) async fn publish_price_oracle(&self) {
        // Fetch from mempool.space (or esplora — operator has its own)
        let url = "https://mempool.space/api/v1/prices";
        let price = match reqwest::get(url).await {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(data) => data.get("USD").and_then(|v| v.as_f64()).unwrap_or(0.0),
                Err(_) => return,
            },
            Err(_) => return,
        };
        if price <= 0.0 {
            return;
        }
        if let Err(e) = self.nostr.publish_price(price).await {
            tracing::debug!("Failed to publish price: {}", e);
        }
    }

    /// Load a line-based list from {data_dir}/{filename}.
    /// Returns empty set if file doesn't exist.
    pub(crate) fn load_list(
        data_dir: &std::path::Path,
        filename: &str,
    ) -> std::collections::HashSet<String> {
        let path = data_dir.join(filename);
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let list: std::collections::HashSet<String> = content
                    .lines()
                    .map(|l| l.trim().to_lowercase())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
                if !list.is_empty() {
                    tracing::info!("{} loaded: {} entries", filename, list.len());
                }
                list
            }
            Err(_) => std::collections::HashSet::new(),
        }
    }

    /// Reload a single list file if changed.
    pub(crate) fn reload_list(
        data_dir: &std::path::Path,
        filename: &str,
        current: &RwLock<std::collections::HashSet<String>>,
    ) {
        let new_list = Self::load_list(data_dir, filename);
        let guard = current.read().unwrap();
        if *guard != new_list {
            let count = new_list.len();
            drop(guard);
            *current.write().unwrap() = new_list;
            tracing::info!("{} updated: {} entries", filename, count);
        }
    }

    /// Query relays for a lightning-verify attestation (kind 55502)
    /// for the given sender pubkey, then accept on either of two paths:
    ///
    ///   * `lightning_address` whose `@`-domain is in
    ///     `deposit_domain_allowlist` — the canonical NIP-05 / challenge
    ///     attestation flow.
    ///   * `allowlist_npub` that itself appears in `deposit_allowlist`
    ///     — the `proclaim` flow, where an already-trusted account
    ///     vouches for an ephemeral key without going through any
    ///     external proof.
    ///
    /// Returns a short matched-reason string on success (e.g.
    /// `"domain=example.com"` or `"allowlist_npub=ab12…"`) for logging.
    pub(crate) async fn check_attestation(
        &self,
        sender_hex: &str,
        allowed_domains: &std::collections::HashSet<String>,
        allowed_pubkeys: &std::collections::HashSet<String>,
    ) -> Option<String> {
        let verifier_hex = self.attestation_verifier_pubkey.as_ref()?;

        let verifier_pubkey = match nostr_sdk::PublicKey::from_hex(verifier_hex) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::error!("Invalid ATTESTATION_VERIFIER_PUBKEY: {}", e);
                return None;
            }
        };

        let sender_pubkey = match nostr_sdk::PublicKey::from_hex(sender_hex) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::warn!("Invalid sender pubkey for attestation lookup: {}", e);
                return None;
            }
        };

        // Query for kind 55502 from the verifier, tagged with the sender
        let filter = nostr_sdk::Filter::new()
            .kind(nostr_sdk::Kind::Custom(55502))
            .author(verifier_pubkey)
            .custom_tag(
                nostr_sdk::SingleLetterTag::lowercase(nostr_sdk::Alphabet::P),
                [sender_pubkey.to_hex()],
            );

        let events = match self
            .nostr
            .client()
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
        {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!("Attestation query failed: {}", e);
                return None;
            }
        };

        for event in events.iter() {
            let content: serde_json::Value = match serde_json::from_str(&event.content) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Path A: lightning_address → domain allowlist
            if let Some(address) = content.get("lightning_address").and_then(|v| v.as_str()) {
                if let Some(domain) = address.split('@').nth(1) {
                    let domain_lower = domain.to_lowercase();
                    if allowed_domains.contains(&domain_lower) {
                        return Some(format!("domain={}", domain_lower));
                    }
                }
            }

            // Path B: allowlist_npub → manual pubkey allowlist (proclaim)
            if let Some(npub) = content.get("allowlist_npub").and_then(|v| v.as_str()) {
                let npub_lower = npub.to_lowercase();
                if allowed_pubkeys.contains(&npub_lower) {
                    return Some(format!("allowlist_npub={}", &npub_lower[..16.min(npub_lower.len())]));
                }
            }

            // Path C: method = "ringsig" → trust the verifier wholesale.
            // The verifier has already confirmed ring membership and the
            // bound-pubkey binding proof; op0's job here is just to
            // confirm the attestation is signed by the configured
            // verifier (already enforced by the filter's `author`
            // clause above). No domain or pubkey allowlist applies —
            // the anonymity-set membership IS the access criterion.
            if content.get("method").and_then(|v| v.as_str()) == Some("ringsig") {
                return Some("method=ringsig".to_string());
            }
        }

        None
    }

    /// Reload all deposit access lists from disk.
    pub fn reload_allowlist(&self) {
        Self::reload_list(
            &self.data_dir,
            "deposit_allowlist.txt",
            &self.deposit_allowlist,
        );
        Self::reload_list(
            &self.data_dir,
            "deposit_denylist.txt",
            &self.deposit_denylist,
        );
        Self::reload_list(
            &self.data_dir,
            "deposit_domain_allowlist.txt",
            &self.deposit_domain_allowlist,
        );
    }

    /// Generate a random nonce for withdrawal uniqueness
    pub(crate) fn generate_nonce() -> [u8; 32] {
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut nonce = [0u8; 32];

        // Use timestamp + some pseudo-randomness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        nonce[0..16].copy_from_slice(&now.to_le_bytes());

        // Hash it for better distribution
        use bitcoin::hashes::{sha256, Hash};
        let hash = sha256::Hash::hash(&nonce);
        hash.to_byte_array()
    }

    /// Load withdrawals from disk
    pub(crate) fn load_withdrawals(
        data_dir: &PathBuf,
    ) -> Result<HashMap<[u8; 32], (OnChainWithdrawal, OnChainWithdrawalStatus)>, Error> {
        let withdrawals_file = data_dir.join("wallet").join("withdrawals.json");
        if !withdrawals_file.exists() {
            return Ok(HashMap::new());
        }

        let contents = std::fs::read_to_string(&withdrawals_file)
            .map_err(|e| Error::Wallet(format!("Failed to read withdrawals: {}", e)))?;

        let withdrawals: Vec<(OnChainWithdrawal, OnChainWithdrawalStatus)> =
            serde_json::from_str(&contents)
                .map_err(|e| Error::Wallet(format!("Failed to parse withdrawals: {}", e)))?;

        let mut map = HashMap::new();
        for (withdrawal, status) in withdrawals {
            map.insert(withdrawal.withdrawal_id, (withdrawal, status));
        }

        tracing::info!("Loaded {} withdrawals from disk", map.len());
        Ok(map)
    }

    /// Save withdrawals to disk
    pub(crate) fn save_withdrawals(&self) -> Result<(), Error> {
        let withdrawals_file = self.data_dir.join("wallet").join("withdrawals.json");

        let withdrawals: Vec<(OnChainWithdrawal, OnChainWithdrawalStatus)> = {
            let withdrawals = self.withdrawals.lock().unwrap();
            withdrawals.values().cloned().collect()
        };

        let contents = serde_json::to_string_pretty(&withdrawals)
            .map_err(|e| Error::Wallet(format!("Failed to serialize withdrawals: {}", e)))?;

        std::fs::write(&withdrawals_file, contents)
            .map_err(|e| Error::Wallet(format!("Failed to write withdrawals: {}", e)))?;

        tracing::info!("Saved {} withdrawals to disk", withdrawals.len());
        Ok(())
    }

    // ========================================================================
    // Deposit Management
    // ========================================================================

    /// Get a deposit by deposit_id from a ledger
    pub fn get_deposit(&self, ledger_id: &str, deposit_id: DepositId) -> Option<Deposit> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            let ledger = ledger_arc.read().unwrap();
            return ledger.state.deposits.get(&deposit_id).cloned();
        }
        None
    }

    /// List all deposits in a ledger
    pub fn list_deposits(&self, ledger_id: &str) -> Vec<(DepositId, Deposit)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            let ledger = ledger_arc.read().unwrap();
            return ledger
                .state
                .deposits
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect();
        }
        Vec::new()
    }

    /// Complete a deposit offer with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow.
    /// Uses a per-offer lock file to prevent concurrent completion by daemon and CLI.
    pub async fn complete_deposit_offer(
        &self,
        offer_id: &[u8; 32],
        funding_txid: String,
        funding_amount_sats: u64,
    ) -> Result<u64, Error> {
        use deposits_core::types::DepositOfferStatus;

        // Get the offer
        let (offer, status) = self
            .get_deposit_offer(offer_id)
            .ok_or(Error::OfferNotFound)?;

        // Only the ledger operator may complete deposits
        if !self.is_operator_of_ledger(&offer.ledger_id) {
            return Err(Error::Protocol(
                "Cannot complete deposit: not the operator of this ledger".to_string(),
            ));
        }

        // Check offer is in correct state.
        // If already Completed (another process finished just before we got the lock), return its result.
        if let DepositOfferStatus::Completed { amount_sats, .. } = &status {
            tracing::info!(
                "Deposit already completed (detected after reload): {} sats",
                amount_sats
            );
            return Ok(*amount_sats * 1000);
        }
        if !matches!(status, DepositOfferStatus::Pending) {
            return Err(Error::Protocol(format!(
                "Deposit offer not in Pending state: {:?}",
                status
            )));
        }

        // Check amount is within bounds
        if funding_amount_sats < offer.min_amount_sats {
            return Err(Error::Protocol(format!(
                "Funding amount {} sats below minimum {} sats",
                funding_amount_sats, offer.min_amount_sats
            )));
        }
        let credited_amount = funding_amount_sats.min(offer.max_amount_sats);

        // Check deadline
        let current_block = self.wallet.get_block_height()?;
        if offer.is_expired(current_block) {
            return Err(Error::Protocol("Deposit offer has expired".to_string()));
        }

        // Credit the deposit (convert sats to msats)
        let amount_msats = credited_amount * 1000;

        // Parse txid from hex string to bytes
        let txid_bytes: [u8; 32] = hex::decode(&funding_txid)
            .map_err(|e| Error::Protocol(format!("Invalid txid hex: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Invalid txid length".to_string()))?;

        // Look up the ledger by ledger_id hash
        let (reserves_id, _) = self
            .get_ledger_by_ledger_id(&offer.ledger_id)
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "Ledger not found for ledger_id: {}",
                    &offer.ledger_id[..16.min(offer.ledger_id.len())]
                ))
            })?;

        // First, open the deposit if it doesn't already exist (with co-signing)
        match self
            .open_deposit(
                &reserves_id,
                &offer.descriptor,
                offer.fees.clone(),
                offer.transfer_fees.clone(),
                false,
            )
            .await
        {
            Ok(_) => {
                tracing::info!(
                    "Opened deposit for {} in ledger {}",
                    hex::encode(offer.deposit_id),
                    &reserves_id[..16.min(reserves_id.len())]
                );
            }
            Err(e) => {
                // If deposit already exists, that's fine - continue to credit
                let err_msg = format!("{}", e);
                if !err_msg.contains("already exists") {
                    return Err(e);
                }
                tracing::debug!("Deposit already exists, proceeding to credit");
            }
        }

        // Credit the deposit with co-signing
        let new_balance = self
            .credit_deposit_onchain(
                &reserves_id,
                &offer.descriptor,
                amount_msats,
                txid_bytes,
                0, // vout - typically 0 for deposit offers
                offer.funding_address.clone(),
            )
            .await?;

        // Update offer status
        {
            let mut offers = self.deposit_offers.lock().unwrap();
            if let Some((_, ref mut current_status)) = offers.get_mut(offer_id) {
                *current_status = DepositOfferStatus::Completed {
                    txid: funding_txid,
                    amount_sats: credited_amount,
                    confirmed_at_block: current_block,
                };
            }
        }
        self.save_deposit_offers()?;

        tracing::info!(
            "Completed deposit offer {}: credited {} msats to {}",
            hex::encode(&offer_id[..8]),
            amount_msats,
            hex::encode(offer.deposit_id)
        );

        Ok(new_balance)
    }

    /// Check if a deposit offer's funding address has received funds
    ///
    /// Returns Some((txid, amount_sats)) if funds are detected, None otherwise.
    /// This version syncs the wallet before checking - use for single-call CLI usage.
    pub fn check_deposit_offer_funding(
        &self,
        offer_id: &[u8; 32],
    ) -> Result<Option<(String, u64)>, Error> {
        // Sync wallet first for CLI/single-call usage
        self.wallet.sync()?;
        self.check_deposit_offer_funding_inner(offer_id, true)
    }

    /// Inner implementation of check_deposit_offer_funding
    ///
    /// If skip_sync is true, assumes wallet is already synced (for batch operations).
    pub(crate) fn check_deposit_offer_funding_inner(
        &self,
        offer_id: &[u8; 32],
        skip_sync: bool,
    ) -> Result<Option<(String, u64)>, Error> {
        let (offer, status) = self
            .get_deposit_offer(offer_id)
            .ok_or(Error::OfferNotFound)?;

        tracing::debug!(
            "check_deposit_offer_funding: offer {} status {:?}",
            hex::encode(&offer_id[..8]),
            status
        );

        // If already completed, return the completed info
        if let DepositOfferStatus::Completed {
            txid, amount_sats, ..
        } = &status
        {
            tracing::debug!("check_deposit_offer_funding: already completed");
            return Ok(Some((txid.clone(), *amount_sats)));
        }

        // Only check pending offers
        if !matches!(status, DepositOfferStatus::Pending) {
            tracing::debug!("check_deposit_offer_funding: skipping non-pending offer");
            return Ok(None);
        }

        // Parse the funding address and check for received funds
        let address = offer
            .funding_address
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| Error::Protocol(format!("Invalid funding address: {}", e)))?;

        // Sync wallet if not already synced
        if !skip_sync {
            self.wallet.sync()?;
        }

        // Check if any transactions have been received to this address
        if let Some((txid, amount)) = self.wallet.check_address_received(&address)? {
            return Ok(Some((txid, amount)));
        }

        Ok(None)
    }

    /// Get ledger history (for display purposes)
    ///
    /// Returns the list of signed updates in the ledger's history.
    pub fn get_ledger_history(
        &self,
        ledger_id: &str,
    ) -> Option<Vec<deposits_core::types::SignedLedgerUpdate>> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            let ledger = ledger_arc.read().unwrap();
            return Some(ledger.history.clone());
        }
        None
    }

    /// Get a specific ledger by ledger_id
    pub fn get_ledger(&self, ledger_id: &str) -> Option<Ledger> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            let ledger = ledger_arc.read().unwrap();
            return Some(ledger.clone());
        }
        None
    }

    /// Get the primary ledger (operator ledger backed by reserves)
    /// Returns (ledger_id, ledger) tuple
    /// Only returns ledgers with non-zero reserves (the actual reserves ledger)
    pub fn get_primary_ledger(&self) -> Option<(String, Ledger)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        for (ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.operator_key() == self.node_id {
                // Only return ledgers backed by reserves
                if ledger.reserves_amount() > 0 {
                    return Some((ledger_id.clone(), ledger.clone()));
                }
            }
        }
        None
    }

    /// Get a ledger by reserves_key (Bitcoin address string)
    /// Returns (ledger_id, ledger) tuple
    /// Searches all ledgers (both operator and partner roles)
    pub fn get_ledger_by_reserves_key(&self, reserves_key: &str) -> Option<(String, Ledger)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        for (ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.reserves_key() == reserves_key {
                return Some((ledger_id.clone(), ledger.clone()));
            }
        }
        None
    }

    /// Get a ledger by ledger_id (64-char hex hash)
    /// Returns (ledger_id, ledger) tuple
    /// The ledger_id is stable across custody transfers
    pub fn get_ledger_by_ledger_id(&self, ledger_id_hex: &str) -> Option<(String, Ledger)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        // Direct lookup since ledger_id is now the key
        if let Some(ledger_arc) = ledgers.get(ledger_id_hex) {
            let ledger = ledger_arc.read().unwrap();
            return Some((ledger_id_hex.to_string(), ledger.clone()));
        }
        None
    }

    /// Get a ledger by either ledger_id (64-char hex hash) or reserves_key (Bitcoin address)
    /// Returns (ledger_id, ledger) tuple
    /// Tries ledger_id first, then falls back to reserves_key lookup
    pub fn get_ledger_with_id(&self, identifier: &str) -> Option<(String, Ledger)> {
        // First try by ledger_id (more common after rotation)
        if let Some(result) = self.get_ledger_by_ledger_id(identifier) {
            return Some(result);
        }
        // Fall back to reserves_key (Bitcoin address)
        self.get_ledger_by_reserves_key(identifier)
    }

    /// Resolve a ledger_id or reserves_key to ledger_id
    /// Returns error string if ledger is not found
    pub(crate) fn resolve_to_ledger_id(&self, identifier: &str) -> Result<String, String> {
        // First try direct lookup by ledger_id
        if let Some((lid, _)) = self.get_ledger_by_ledger_id(identifier) {
            return Ok(lid);
        }
        // Fall back to reserves_key lookup
        if let Some((lid, _)) = self.get_ledger_by_reserves_key(identifier) {
            return Ok(lid);
        }
        Err(format!(
            "Ledger not found: {}",
            &identifier[..16.min(identifier.len())]
        ))
    }

    /// Check if a ledger exists by ledger_id (no clone).
    /// Resolve a possibly-truncated ledger ID to the full 64-char ID.
    /// Returns the input unchanged if already full-length or not found.
    pub(crate) fn resolve_ledger_id(&self, ledger_id: &str) -> String {
        if ledger_id.len() >= 64 {
            return ledger_id.to_string();
        }
        let ledgers = self.handler.ledgers.lock().unwrap();
        ledgers
            .keys()
            .find(|k| k.starts_with(ledger_id))
            .cloned()
            .unwrap_or_else(|| ledger_id.to_string())
    }

    pub(crate) fn has_ledger(&self, ledger_id: &str) -> bool {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if ledgers.contains_key(ledger_id) {
            return true;
        }
        // Prefix match for truncated IDs (16-char tags from Nostr events)
        if ledger_id.len() < 64 {
            return ledgers.keys().any(|k| k.starts_with(ledger_id));
        }
        false
    }

    /// Check if a ledger exists by reserves_key (no clone).
    pub(crate) fn has_ledger_by_reserves_key(&self, reserves_key: &str) -> bool {
        let ledgers = self.handler.ledgers.lock().unwrap();
        ledgers
            .values()
            .any(|arc| arc.read().unwrap().reserves_key() == reserves_key)
    }

    /// Check if we are the operator of the given ledger.
    ///
    /// Returns true when either:
    /// - The ledger's original operator_key matches our node_id, OR
    /// - A DisputeAcquire operation transferred custody to our node_id.
    ///
    /// Results are cached by (ledger_id, history_len). Once true, the cache
    /// entry is permanent. False entries use incremental scanning — only new
    /// history entries since the last check are scanned for DisputeAcquire.
    pub(crate) fn is_operator_of_ledger(&self, ledger_id: &str) -> bool {
        // Single lock: resolve canonical_id + get Arc clone
        let (canonical_id, arc) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(arc) = ledgers.get(ledger_id) {
                (ledger_id.to_string(), arc.clone())
            } else if ledger_id.len() < 64 {
                // Prefix match for truncated IDs
                match ledgers.iter().find(|(k, _)| k.starts_with(ledger_id)) {
                    Some((lid, arc)) => (lid.clone(), arc.clone()),
                    None => return false,
                }
            } else {
                // Try reserves_key lookup
                match ledgers
                    .iter()
                    .find(|(_, a)| a.read().unwrap().reserves_key() == ledger_id)
                {
                    Some((lid, arc)) => (lid.clone(), arc.clone()),
                    None => return false,
                }
            }
        };

        let ledger = arc.read().unwrap();
        let history_len = ledger.history.len();

        // Check cache — determine if we can return early or need incremental scan
        let scan_from = {
            let cache = self.operator_of_cache.lock().unwrap();
            if let Some(&(result, cached_len)) = cache.get(&canonical_id) {
                if result {
                    return true; // Permanent: we are the operator
                }
                if cached_len == history_len {
                    return false; // No new entries since last check
                }
                // Stale false — only scan new entries [cached_len..]
                // Cap at history_len in case history was truncated
                cached_len.min(history_len)
            } else {
                0 // First check — full scan needed
            }
        };

        // Compute result: full check on first call, incremental on subsequent
        let result = if scan_from == 0 {
            // First check: test operator_key, then scan entire history
            if ledger.operator_key() == self.node_id {
                true
            } else {
                ledger.history.iter().rev().any(|u| {
                    u.message_type == 55
                        && deposits_core::messages::LedgerOperation::tlv_decode(&u.message)
                            .map(|op| matches!(op, deposits_core::messages::LedgerOperation::DisputeAcquire { new_custodian, .. } if new_custodian == self.node_id))
                            .unwrap_or(false)
                })
            }
        } else {
            // Incremental: only scan entries [scan_from..] for DisputeAcquire
            ledger.history[scan_from..].iter().rev().any(|u| {
                u.message_type == 55
                    && deposits_core::messages::LedgerOperation::tlv_decode(&u.message)
                        .map(|op| matches!(op, deposits_core::messages::LedgerOperation::DisputeAcquire { new_custodian, .. } if new_custodian == self.node_id))
                        .unwrap_or(false)
            })
        };

        drop(ledger);

        // Store in cache
        self.operator_of_cache
            .lock()
            .unwrap()
            .insert(canonical_id, (result, history_len));
        result
    }
}

/// Poll the chain until the given outpoint has at least `required` confirmations,
/// or `timeout` elapses (whichever first). Used by first-QuorumBegin flow where
/// the operator has just broadcast the rotation tx and must wait before
/// requesting cosigs — staged members refuse to cosign an under-confirmed UTXO.
async fn wait_for_outpoint_confs(
    wallet: &crate::wallet::Wallet,
    txid: bitcoin::Txid,
    vout: u32,
    required: u32,
    timeout: std::time::Duration,
) -> Result<u32, Error> {
    let start = std::time::Instant::now();
    let poll_interval = std::time::Duration::from_secs(3);
    loop {
        match wallet.get_outpoint_value_and_confs(txid, vout) {
            Ok(Some((_, confs))) if confs >= required => {
                tracing::debug!(
                    "Outpoint {}:{} reached {} confirmations (required {})",
                    txid,
                    vout,
                    confs,
                    required
                );
                return Ok(confs);
            }
            Ok(Some((_, confs))) => {
                tracing::debug!(
                    "Outpoint {}:{} has {} of {} required confirmations, waiting…",
                    txid,
                    vout,
                    confs,
                    required
                );
            }
            Ok(None) => {
                tracing::debug!(
                    "Outpoint {}:{} not yet visible on-chain, waiting…",
                    txid,
                    vout
                );
            }
            Err(e) => {
                // Transient Esplora errors shouldn't abort the whole rotation;
                // log and keep polling until the deadline.
                tracing::warn!(
                    "Outpoint {}:{} lookup error (will retry): {}",
                    txid,
                    vout,
                    e
                );
            }
        }
        if start.elapsed() > timeout {
            return Err(Error::Protocol(format!(
                "Timed out waiting for {}:{} to reach {} confirmations",
                txid, vout, required
            )));
        }
        tokio::time::sleep(poll_interval).await;
    }
}
