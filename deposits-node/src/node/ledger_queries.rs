use super::*;

impl Node {
    /// Auto-rotate winnings to quorum-controlled Taproot
    pub(crate) async fn auto_rotate_to_quorum(&self, ledger_id: &str) -> Result<(), Error> {
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::PublicKey;
        use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::{
            SignedLedgerUpdate, TapscriptReservesBuilder, TlvDecode, TlvEncode, VoterSet,
        };
        use deposits_signer_api::{SigPurpose, SignContext};

        use nostr_sdk::{Filter, Kind};

        let our_pubkey = self.node_id;

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

        // Decode every fetched update once so we can (a) find OUR
        // DisputeAcquire + latest signed op, and (b) derive the canonical
        // recovery quorum from the ledger's CANONICAL (pre-dispute)
        // QuorumBegin — the members the reserves UTXO actually committed to,
        // minus the accused operator. See below for why QuorumAddMember
        // scanning is WRONG here.
        let mut all_updates: Vec<SignedLedgerUpdate> = Vec::new();
        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    all_updates.push(update);
                }
            }
        }

        // Find our DisputeAcquire and quorum members
        let mut current_reserves_address: Option<String> = None;
        let mut our_latest: Option<SignedLedgerUpdate> = None;
        // Pubkey → member_ledger_id, sourced from the original QuorumAddMember
        // rows (which DO carry the per-member ledger pairing) for the honest
        // recovery members only. Used at QuorumBegin construction time so the
        // rotation summary doesn't lose the pairing.
        let mut member_ledger_ids: std::collections::HashMap<PublicKey, String> =
            std::collections::HashMap::new();

        for update in &all_updates {
            if update.operator_id == our_pubkey {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::DisputeAcquire {
                        ref new_reserves_address,
                        ..
                    } = op
                    {
                        current_reserves_address = Some(new_reserves_address.clone());
                    }
                }
                if our_latest.is_none()
                    || update.sequence_number > our_latest.as_ref().unwrap().sequence_number
                {
                    our_latest = Some(update.clone());
                }
            }
            // Harvest member→ledger_id pairings from ALL QuorumAddMember rows;
            // we filter to the canonical recovery set below.
            if let Ok(LedgerOperation::QuorumAddMember {
                quorum_member,
                ref member_ledger_id,
                ..
            }) = LedgerOperation::tlv_decode(&update.message)
            {
                member_ledger_ids
                    .entry(quorum_member)
                    .or_insert_with(|| member_ledger_id.clone());
            }
        }

        let current_reserves_address = current_reserves_address
            .ok_or_else(|| Error::Protocol("No DisputeAcquire found".to_string()))?;
        let our_latest =
            our_latest.ok_or_else(|| Error::Protocol("No latest update found".to_string()))?;

        // The rotation quorum MUST be the ledger's canonical honest cosigners
        // — the CANONICAL QuorumBegin's members minus the accused operator —
        // NOT the union of QuorumAddMember rows. The fork-arming path
        // (`create_dispute_fork`) appends QuorumAddMember rows for the
        // winner's OTHER, unrelated ledgers' members; scanning those rows
        // promoted the wrong set into the rotation QuorumBegin, so every
        // honest cosigner's cosignature was rejected as
        // "Cosigner … not in quorum" and no post-recovery deposit could
        // reach threshold. `recovery_voters_from_updates` is the SAME
        // canonical derivation the on-chain confiscation voter set uses.
        let (recovery_voters_xonly, _threshold) =
            crate::node::dispute::recovery_voters_from_updates(&all_updates).ok_or_else(|| {
                Error::Protocol(
                    "cannot derive recovery quorum: no canonical QuorumBegin in history"
                        .to_string(),
                )
            })?;
        let recovery_xonly: std::collections::HashSet<_> =
            recovery_voters_xonly.iter().copied().collect();
        // Map the canonical x-only voters back to the full compressed pubkeys
        // seen in history (QuorumBegin/QuorumAddMember rows), so VoterSet and
        // QuorumMemberRef carry 33-byte keys. Always include our own key.
        let mut quorum_members: Vec<PublicKey> = Vec::new();
        let mut seen: std::collections::HashSet<[u8; 33]> = std::collections::HashSet::new();
        let mut consider =
            |pk: PublicKey,
             out: &mut Vec<PublicKey>,
             seen: &mut std::collections::HashSet<[u8; 33]>| {
                if pk == our_pubkey || recovery_xonly.contains(&pk.x_only_public_key().0) {
                    if seen.insert(pk.serialize()) {
                        out.push(pk);
                    }
                }
            };
        consider(our_pubkey, &mut quorum_members, &mut seen);
        for update in &all_updates {
            if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                match op {
                    LedgerOperation::QuorumBegin {
                        quorum_members: qm, ..
                    } => {
                        for m in qm {
                            consider(m.pubkey, &mut quorum_members, &mut seen);
                        }
                    }
                    LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                        consider(quorum_member, &mut quorum_members, &mut seen);
                    }
                    _ => {}
                }
            }
        }

        if quorum_members.is_empty() {
            return Err(Error::Protocol("No quorum members found".to_string()));
        }
        tracing::info!(
            "Recovery rotation quorum ({} members): {:?}",
            quorum_members.len(),
            quorum_members
                .iter()
                .map(|m| hex::encode(&m.serialize()[..4]))
                .collect::<Vec<_>>()
        );

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
        let expiry_block = current_block + crate::node::DEFAULT_QUORUM_EXPIRY_BLOCKS;

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
        let ledger_hash = our_latest.content_hash;

        // Build Taproot reserves with default (legacy) config. P0d
        // will route through the active ruleset's factory once
        // QuorumBegin carries `protocol_version`.
        let _ = quorum_expiry;
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

        let signature = self
            .handler
            .signer
            .ecdsa_sign_sighash(
                &SignContext::no_ledger(SigPurpose::OnchainSighash),
                sighash.as_ref(),
            )
            .map_err(|e| Error::Protocol(format!("rotate sighash sign: {}", e)))?;

        // Build witness
        let mut sig_bytes = signature.serialize_der().to_vec();
        sig_bytes.push(EcdsaSighashType::All as u8);

        let mut rotate_tx = rotate_tx;
        rotate_tx.input[0].witness.push(sig_bytes);
        rotate_tx.input[0].witness.push(compressed.to_bytes());

        // Broadcast
        let rotate_txid = self.wallet.broadcast(&rotate_tx)?;
        tracing::info!("Rotation TX broadcast: {}", rotate_txid);

        // Recovery-path rotation: preserve the reserves/collateral
        // ratio from current state (same as the operator-driven
        // path in `rotate_reserves_to_quorum`). The split was set
        // at `ledger open` and carries forward.
        let total_msats = output_amount.saturating_mul(1000);
        let (reserves_msats, collateral_msats) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let l_opt = ledgers.get(ledger_id);
            if let Some(arc) = l_opt {
                let l = arc.read().unwrap();
                let prev_total = l
                    .state
                    .reserves_amount
                    .saturating_add(l.state.collateral_amount);
                if prev_total > 0 {
                    let collateral = (l.state.collateral_amount as u128 * total_msats as u128
                        / prev_total as u128) as u64;
                    (total_msats.saturating_sub(collateral), collateral)
                } else {
                    (total_msats, 0)
                }
            } else {
                (total_msats, 0)
            }
        };

        // Publish QuorumBegin operation. Total UTXO = reserves + collateral.
        let operation = LedgerOperation::QuorumBegin {
            reserves_id: taproot_output.address.to_string(),
            spending_txid: *outpoint.txid.as_ref(),
            new_outpoint_txid: *rotate_txid.as_ref(),
            new_outpoint_vout: 0,
            amount: reserves_msats,
            quorum_expiry,
            ledger_hash,
            quorum_members: quorum_members
                .iter()
                .map(|pk| {
                    deposits_core::messages::QuorumMemberRef::new(
                        *pk,
                        member_ledger_ids.get(pk).cloned().unwrap_or_default(),
                    )
                })
                .collect(),
            collateral_amount: collateral_msats,
            protocol_version: None,
        };

        let message_bytes = operation.tlv_encode();

        // Chain the rotation's QuorumBegin on the parent's `chain_hash()`
        // (= SHA256(content_hash || operator_signature)) — the unified
        // convention `validate_hash_chain` enforces. `our_latest` is the
        // winner's own DisputeAcquire, fetched fully-signed from the relay.
        // NOTE: `ledger_hash` (the QuorumBegin state commitment, used by the
        // tapscript reserves builder above) intentionally stays
        // `our_latest.content_hash` — that's a state anchor, not a chain link.
        let parent_chain_hash = our_latest.chain_hash();
        let sequence = our_latest.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&parent_chain_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(parent_chain_hash),
            sequence,
            hex::encode(new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());

        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
            .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

        let operator_sig_bytes = self
            .handler
            .signer
            .bip340_sign(
                &SignContext::operator_update(ledger_id_bytes, sequence),
                msg_hash.as_ref(),
            )
            .map_err(|e| Error::Protocol(format!("operator sign: {}", e)))?;

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
            previous_hash: parent_chain_hash,
            content_hash: new_hash,
            block_height: current_block,
            block_hash,
        };

        self.nostr
            .broadcast_ledger_update(&signed_update)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast QuorumBegin: {:?}", e)))?;

        // Apply the rotation QuorumBegin to our OWN base ledger too. Publishing
        // to the relay alone left the winner's local base stuck at the
        // DisputeAcquire tip (seq N): the losers fetched + applied this seq-(N+1)
        // QuorumBegin and advanced, but the winner's next_sequence stayed N+1,
        // so a subsequent `deposit_open` committed a DepositOpen at the SAME
        // seq the network already holds a QuorumBegin for — and every cosigner
        // refused it as an equivocation ("seq N+1 already committed to a
        // different update"). Applying locally keeps the winner in lockstep
        // with what it just broadcast, so the re-opened deposits land at N+2+.
        if let Err(e) = self
            .handler
            .apply_updates_to_ledger(ledger_id, vec![signed_update])
        {
            tracing::warn!(
                "Rotation QuorumBegin broadcast but not applied to local base {}: {} \
                 (local base will lag the relay by one op)",
                &ledger_id[..16.min(ledger_id.len())],
                e
            );
        }
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
            tracing::warn!("Failed to persist rotated base ledger {}: {}", ledger_id, e);
        }

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
        use deposits_core::messages::LedgerOperation;
        use deposits_core::{SignedLedgerUpdate, TlvDecode, TlvEncode};
        use deposits_signer_api::SignContext;

        use nostr_sdk::{Filter, Kind};

        let our_pubkey = self.node_id;

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
                commitment: None,
            };

            let message_bytes = operation.tlv_encode();

            // Chain each re-opened DepositOpen on the parent's
            // `chain_hash()` (unified convention). On the first iteration
            // the parent is the winner's QuorumBegin; on later iterations
            // it's the DepositOpen we built last pass — which we sign
            // below, so its `operator_signature` (and thus `chain_hash()`)
            // is populated before it becomes the next parent.
            let parent_chain_hash = our_latest.chain_hash();
            let sequence = our_latest.sequence_number + 1;
            let mut hash_input = Vec::new();
            hash_input.extend_from_slice(&sequence.to_le_bytes());
            hash_input.extend_from_slice(&parent_chain_hash);
            hash_input.extend_from_slice(&message_bytes);
            let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

            let update_msg = format!(
                "deposits:ledger:{}:{}:{}",
                hex::encode(parent_chain_hash),
                sequence,
                hex::encode(new_hash)
            );
            let msg_hash = sha256::Hash::hash(update_msg.as_bytes());

            let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
                .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
                .try_into()
                .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

            let operator_sig_bytes = self
                .handler
                .signer
                .bip340_sign(
                    &SignContext::operator_update(ledger_id_bytes, sequence),
                    msg_hash.as_ref(),
                )
                .map_err(|e| Error::Protocol(format!("operator sign: {}", e)))?;

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
                previous_hash: parent_chain_hash,
                content_hash: new_hash,
                block_height: current_block,
                block_hash,
            };

            self.nostr
                .broadcast_ledger_update(&signed_update)
                .await
                .map_err(|e| {
                    Error::Protocol(format!("Failed to broadcast DepositOpen: {:?}", e))
                })?;

            // Apply the re-opened DepositOpen to our OWN base ledger too — the
            // same lockstep invariant as the rotation QuorumBegin above.
            // Without it the winner's local next_sequence trails every op it
            // continues, and the next real depositor's open collides with an
            // already-committed sequence.
            if let Err(e) = self
                .handler
                .apply_updates_to_ledger(ledger_id, vec![signed_update.clone()])
            {
                tracing::warn!(
                    "Continued DepositOpen broadcast but not applied to local base {}: {}",
                    &ledger_id[..16.min(ledger_id.len())],
                    e
                );
            }

            tracing::info!("Re-opened deposit {}...", hex::encode(&deposit_id[..8]));

            // Update our_latest for next iteration
            our_latest = signed_update;
        }
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
            tracing::warn!(
                "Failed to persist continued base ledger {}: {}",
                ledger_id,
                e
            );
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

    /// Get a new address
    pub fn new_address(&self) -> Result<bitcoin::Address, Error> {
        self.wallet.get_new_address()
    }

    // ========================================================================
    // Ledger Management
    // ========================================================================

    /// Open a new ledger.
    ///
    /// `LedgerOpen` is a pure declaration: `reserves_amount = 0`,
    /// `collateral_amount = 0`, and a synthetic `reserves_id` derived
    /// from the operator pubkey. The first `quorum begin` populates
    /// the real amounts when it builds the Taproot Q=N vault from
    /// the ledger's pre-funded UTXOs.
    ///
    /// `collateral_bps` is reserved for callers that supply a pre-known
    /// split; under the genesis-only flow the first `quorum begin` is
    /// authoritative, so this is currently unused.
    pub fn open_ledger(&self, _collateral_bps: Option<u16>) -> Result<Ledger, Error> {
        let used_addresses: std::collections::HashSet<String> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .values()
                .map(|l| l.read().unwrap().state.reserves_key.clone())
                .collect()
        };

        // Synthetic reserves_id derived from the operator pubkey, with a
        // numeric suffix when the same operator opens multiple genesis
        // ledgers in one process lifetime.
        let synth = format!("genesis:{}", hex::encode(&self.node_id.serialize()[..16]));
        let mut reserves_id = synth.clone();
        let mut counter: u32 = 0;
        while used_addresses.contains(&reserves_id) {
            counter += 1;
            reserves_id = format!("{}.{}", synth, counter);
        }
        tracing::info!("open_ledger: reserves_id={}", reserves_id);
        let reserves_msats = 0u64;
        let collateral_msats = 0u64;

        // Funding outpoint is unknown until the first QuorumBegin builds
        // the activation tx; carry zeros in the handshake.
        let (funding_txid, funding_vout) = ([0u8; 32], 0u16);

        let ledger_arc = self.handler.get_or_create_ledger_with_outpoint(
            self.node_id,
            reserves_id.clone(),
            Some((reserves_msats, collateral_msats)),
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

        // Provision the per-ledger BDK wallet now so the operator can
        // hand `deposits-node ledger address <id>` to whoever is
        // pre-funding this ledger before `quorum begin` activates it.
        if let Err(e) = self.ensure_ledger_wallet(&ledger_id) {
            tracing::error!(
                "Failed to provision per-ledger wallet for {}: {}",
                ledger_id,
                e
            );
        }

        // Lazy-spawn an actor for this freshly-created ledger so
        // future inbound + commit events go through the single-writer
        // apply path. The initial actor pool was sized from
        // `handler.ledgers` at `Node::new` time and doesn't pick up
        // ledgers opened afterward.
        self.ensure_actor_for(&ledger_id);

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
        // Lazy-spawn an actor for the imported ledger so subsequent
        // inbound updates from the operator go through the single-writer
        // apply path. (See Node::ensure_actor_for for context.)
        self.ensure_actor_for(&ledger.ledger_id_hex());
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
    /// Rotate the reserves UTXO into a quorum-controlled Taproot
    /// output and commit a `QuorumBegin` operation that activates
    /// the quorum.
    ///
    /// `collateral_bps`:
    ///   - `Some(b)`: explicit override, used as-is (and carried
    ///     forward as the new "current ratio" for subsequent
    ///     rotations).
    ///   - `None`: preserve the ratio from current state. The
    ///     split was set at `ledger open` and propagates through
    ///     every rotation absent an explicit override.
    pub async fn rotate_reserves_to_quorum(
        &self,
        ledger_id: &str,
        collateral_bps: Option<u16>,
        amount_sats: Option<u64>,
        requested_ruleset: Option<&str>,
        expiry_blocks_override: Option<u32>,
    ) -> Result<RotateReservesResult, Error> {
        // --- Phase 1: snapshot membership + ledger state ---
        let ledger_arc = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone()
        };

        let (
            quorum_members,
            member_ledger_ids,
            quorum_expiries,
            ledger_hash,
            total_collateral,
            new_ruleset_name,
        ) = {
            let ledger = ledger_arc.read().unwrap();

            // QuorumBegin promotes next_quorum_members -> quorum_members, so at rotation
            // time the members are still in next_quorum_members (pending).
            // Fall back to active quorum_members for re-rotation after an existing QuorumBegin.
            //
            // Build a parallel ledger_id list so the QuorumBegin we publish
            // below can carry both halves. The local `members` stays
            // Vec<PublicKey> because downstream code (taproot reconstruction,
            // logging, length checks) keys off pubkeys.
            let source = if !ledger.state.next_quorum_members.is_empty() {
                &ledger.state.next_quorum_members
            } else {
                &ledger.state.quorum_members
            };
            let members: Vec<PublicKey> = source.iter().map(|m| m.pubkey).collect();
            let lids: Vec<String> = source.iter().map(|m| m.ledger_id.clone()).collect();

            let current_block = self.wallet.get_block_height().unwrap_or(0);
            // Caller-supplied override wins (used by tests that need a
            // short-lived quorum); otherwise the standard 30-day window.
            let default_expiry = current_block
                + expiry_blocks_override.unwrap_or(crate::node::DEFAULT_QUORUM_EXPIRY_BLOCKS);

            // TODO: Get actual expiries from quorum member info in ledger
            let expiries: Vec<u32> = members.iter().map(|_| default_expiry).collect();

            let hash = ledger.hash();
            let collateral = ledger.state.total_collateral();

            // Inherit the active ruleset by default — rotating an
            // existing legacy ledger keeps it on legacy. Operator
            // overrides via `--protocol-version`; we still verify
            // every pending member supports it before proceeding.
            let rs = ledger.state.active_ruleset_name.clone();

            (members, lids, expiries, hash, collateral, rs)
        };

        if quorum_members.is_empty() {
            return Err(Error::Protocol(
                "No quorum members to rotate to. Add quorum members first.".to_string(),
            ));
        }

        // Resolve which ruleset this rotation will commit to and check
        // that this binary can actually enforce it. Migrating to an
        // unknown ruleset would produce a UTXO whose tapscript we can't
        // reconstruct.
        let new_ruleset_name = match requested_ruleset {
            Some(name) => {
                if deposits_core::ruleset::lookup(name).is_none() {
                    return Err(Error::Protocol(format!(
                        "Unknown protocol_version '{}' (this node supports: {:?})",
                        name,
                        deposits_core::ruleset::all_supported_names()
                    )));
                }
                name.to_string()
            }
            None => new_ruleset_name,
        };

        // Cross-check the chosen ruleset against every pending member's
        // signed support list. A member that didn't declare support
        // cannot validate operations under that ruleset, so committing
        // a QuorumBegin pinned to it would silently break their
        // ability to cosign — refuse here with a clear error.
        {
            let ledger = ledger_arc.read().unwrap();
            let source = if !ledger.state.next_quorum_members.is_empty() {
                &ledger.state.next_quorum_members
            } else {
                &ledger.state.quorum_members
            };
            let mut unsupported: Vec<String> = Vec::new();
            for m in source {
                if !deposits_core::ruleset::member_supports(
                    &m.supported_rulesets,
                    &new_ruleset_name,
                ) {
                    let declared: Vec<&str> = if m.supported_rulesets.is_empty() {
                        vec!["legacy"]
                    } else {
                        m.supported_rulesets.iter().map(|s| s.as_str()).collect()
                    };
                    unsupported.push(format!(
                        "{} (supports: {:?})",
                        hex::encode(m.pubkey.serialize()),
                        declared
                    ));
                }
            }
            if !unsupported.is_empty() {
                return Err(Error::Protocol(format!(
                    "Cannot start quorum under ruleset '{}': {} member(s) did not declare support: {}",
                    new_ruleset_name,
                    unsupported.len(),
                    unsupported.join(", ")
                )));
            }
        }

        use crate::wallet::{TaprootReservesCreateResult, TaprootReservesInfo};
        use bitcoin::OutPoint;
        use deposits_core::QuorumState;

        // --- Phase 2: build the activation tx on the per-ledger wallet ---
        //
        // Each ledger has its own BDK wallet rooted at a per-ledger
        // BIP-32 account. Inputs come exclusively from that wallet's
        // own UTXOs, so concurrent `quorum begin` calls across ledgers
        // can't race for shared coins.
        //
        // First, detect a resume case: a previous QuorumBegin attempt
        // may have built and broadcast the activation tx and recorded
        // its TaprootReservesInfo, but timed out before the QuorumBegin
        // ledger op committed. The ledger stays PreQuorum and the
        // ledger wallet still has the entry. Reuse it instead of
        // building a fresh tx.
        let ledger_wallet = self.ensure_ledger_wallet(ledger_id)?;
        let sync_err: Option<String> = match ledger_wallet.sync() {
            Ok(()) => None,
            Err(e) => {
                tracing::warn!("Ledger wallet sync failed before quorum_begin: {}", e);
                Some(e.to_string())
            }
        };

        // Detect a refresh case: ledger is already Active and has an
        // existing on-chain reserves UTXO. We rotate by spending the
        // existing UTXO via quorum cosign (tier-0 majority leaf) into
        // a new Taproot output with the staged (`next_quorum_members`)
        // key set. Fee is deducted from the reserves amount.
        let refresh_existing = {
            let l = ledger_arc.read().unwrap();
            let is_active = l.state.quorum_state == QuorumState::Active;
            drop(l);
            if is_active {
                ledger_wallet.taproot_reserves()
            } else {
                None
            }
        };

        let pending_resume = {
            let pre_quorum =
                ledger_arc.read().unwrap().state.quorum_state == QuorumState::PreQuorum;
            if pre_quorum {
                ledger_wallet
                    .taproot_reserves()
                    .filter(|t| t.quorum_members == quorum_members)
            } else {
                None
            }
        };

        let (result, pending_taproot): (TaprootReservesCreateResult, TaprootReservesInfo) =
            if let Some(existing) = refresh_existing {
                // Refresh path: spend the existing Taproot reserves UTXO
                // via majority cosign into a new Taproot output with the
                // rotated key set. Fee is deducted from the reserves
                // amount; the wpkh wallet is not consulted.
                self.build_rotation_via_cosign(
                    ledger_id,
                    &existing,
                    quorum_members.clone(),
                    quorum_expiries.clone(),
                    ledger_hash,
                    &new_ruleset_name,
                )
                .await?
            } else if let Some(existing) = pending_resume {
                tracing::info!(
                    "Detected half-finished QuorumBegin: reusing taproot UTXO {}:{} ({}sat) — \
                     skipping build+broadcast, jumping to confirmation+cosign",
                    existing.outpoint.txid,
                    existing.outpoint.vout,
                    existing.amount
                );
                let synth_result = TaprootReservesCreateResult {
                    outpoint: existing.outpoint,
                    address: existing.taproot_output.address.clone(),
                    amount: existing.amount,
                    tx: bitcoin::Transaction {
                        version: bitcoin::transaction::Version::TWO,
                        lock_time: bitcoin::absolute::LockTime::ZERO,
                        input: vec![],
                        output: vec![],
                    },
                    taproot_output: existing.taproot_output.clone(),
                    quorum_expiry: existing.quorum_expiry,
                    ledger_hash: existing.ledger_hash,
                };
                (synth_result, existing)
            } else {
                // amount_sats defaults to the ledger wallet's confirmed
                // balance minus a small fee buffer. With external
                // pre-funding, the operator has already sent the
                // activation amount to the ledger's deposit address.
                let chosen_amount = match amount_sats {
                    Some(a) => a,
                    None => {
                        let bal = ledger_wallet.balance_sats().unwrap_or(0);
                        if bal <= 1000 {
                            return Err(Error::Wallet(format!(
                                "QuorumBegin: insufficient ledger wallet balance: {} sats \
                                 (need > 1000 sats to leave a fee buffer; \
                                 use `deposits-node ledger address {}` and pre-fund it)",
                                bal,
                                &ledger_id[..16.min(ledger_id.len())]
                            )));
                        }
                        bal.saturating_sub(1000)
                    }
                };
                // Guard against the cryptic "Insufficient funds: 0 available"
                // that BDK's coin selector emits when the ledger wallet is
                // empty. With an explicit --amount-sats (the bootstrap always
                // passes one) the friendly balance check above is skipped, so a
                // wallet that simply hasn't seen its on-chain coins falls
                // straight through to a confusing error that looks like the
                // funds are gone. They almost never are — the usual cause is the
                // daemon's chain backend not seeing them (a stale daemon from an
                // earlier run keeps its original --esplora; or electrs isn't
                // fully synced). Surface that distinction here, including the
                // swallowed sync error if there was one.
                let confirmed = ledger_wallet.balance_sats().unwrap_or(0);
                if confirmed < chosen_amount {
                    return Err(Error::Wallet(format!(
                        "QuorumBegin: ledger {} wallet sees {} confirmed sats but needs {} to \
                         build the activation tx. If the funds are confirmed on-chain at the \
                         ledger deposit address, this daemon's chain backend isn't seeing them — \
                         check its --esplora and that electrs is fully synced, then retry. (A \
                         daemon left running from an earlier bootstrap keeps its original \
                         --esplora; restart it to pick up a corrected one.){}",
                        &ledger_id[..16.min(ledger_id.len())],
                        confirmed,
                        chosen_amount,
                        match &sync_err {
                            Some(e) => format!(" Wallet sync also errored: {}", e),
                            None => String::new(),
                        },
                    )));
                }
                tracing::info!(
                    "QuorumBegin: spending {} sats from ledger {} wallet into Q={} taproot vault",
                    chosen_amount,
                    &ledger_id[..16.min(ledger_id.len())],
                    quorum_members.len()
                );
                let (result, pending) = ledger_wallet.build_activation_tx(
                    &*self.handler.signer,
                    quorum_members.clone(),
                    quorum_expiries.clone(),
                    ledger_hash,
                    chosen_amount,
                    5.0,
                    &new_ruleset_name,
                )?;
                let txid = ledger_wallet.broadcast(&result.tx)?;
                tracing::info!(
                    "Broadcast taproot activation: txid={}, address={}, {} members, first expiry at block {}",
                    txid,
                    result.address,
                    quorum_members.len(),
                    result.quorum_expiry
                );
                // Persist the pending taproot record NOW — before the
                // confirmation wait below (up to ~1h on mainnet, 6 confs), not
                // at Phase 5 after cosign. The activation tx is already
                // broadcast and has spent the ledger wallet's funding UTXO. If
                // begin times out or the daemon restarts during that long wait
                // (routine on mainnet), a later retry MUST find this entry and
                // resume via `pending_resume` above. Without the early persist
                // the retry rebuilds against a now-spent input and dead-ends at
                // "Insufficient funds: 0 available", with the funds stranded in
                // the vault and no local record of them. `confirmed` stays false
                // until the depth wait completes; Phase 5 re-commits the
                // identical record idempotently (save guard allows same
                // outpoint+script). This is the recoverability the Phase-5-only
                // commit previously failed to provide.
                if let Err(e) = ledger_wallet.commit_taproot_reserves(pending.clone()) {
                    tracing::warn!(
                        "failed to persist pending taproot reserves before conf-wait for \
                         ledger {} ({}): a restart during the wait would rebuild instead of \
                         resume",
                        &ledger_id[..16.min(ledger_id.len())],
                        e
                    );
                }
                (result, pending)
            };

        let txid = result.outpoint.txid;

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
            // Budget ~30 min per required confirmation. On mainnet
            // `required_confs` is 6 (≈1h of blocks, longer on slow stretches),
            // so a single begin attempt waits it out rather than giving up at
            // ~1 conf (the old flat 600s). Scales with the network's
            // required_confs (regtest=1 → 30 min, ample).
            std::time::Duration::from_secs(required_confs.max(1) as u64 * 30 * 60),
        )
        .await?;

        // --- Phase 4: stage + cosign + commit the QuorumBegin operation ---
        // Store the rotation txid in internal sha256d byte order (the natural
        // `to_byte_array()`). Cosigners reconstruct via `Txid::from_raw_hash`
        // which expects internal order, and the other QuorumBegin writer in
        // this file (`*rotate_txid.as_ref()`) uses the same convention.
        let txid_bytes: [u8; 32] = txid.to_byte_array();

        // Resolve the reserves/collateral split. Explicit override
        // wins; otherwise preserve the ratio from current state
        // (set at `ledger open`, carried forward through every
        // rotation).
        let total_msats = result.amount.saturating_mul(1000);
        let (reserves_msats, collateral_msats) = if let Some(bps) = collateral_bps {
            let collateral = (total_msats as u128 * bps as u128 / 10_000) as u64;
            (total_msats.saturating_sub(collateral), collateral)
        } else {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let l = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .read()
                .unwrap();
            let prev_total = l
                .state
                .reserves_amount
                .saturating_add(l.state.collateral_amount);
            if prev_total > 0 {
                let collateral = (l.state.collateral_amount as u128 * total_msats as u128
                    / prev_total as u128) as u64;
                (total_msats.saturating_sub(collateral), collateral)
            } else {
                // Defensive: no prior amounts to anchor a ratio.
                // Treat the whole UTXO as reserves; the operator
                // can pass --collateral-ratio to fix.
                (total_msats, 0)
            }
        };
        tracing::info!(
            "QuorumBegin split: total={} msats, reserves={} msats, collateral={} msats ({}%)",
            total_msats,
            reserves_msats,
            collateral_msats,
            if total_msats > 0 {
                (collateral_msats * 100) / total_msats
            } else {
                0
            },
        );

        let operation = LedgerOperation::QuorumBegin {
            reserves_id: result.address.to_string(),
            spending_txid: txid_bytes,
            new_outpoint_txid: txid_bytes,
            new_outpoint_vout: result.outpoint.vout,
            // QuorumBegin's `amount` is the reserves portion only —
            // see the state-machine apply in ledger_state.rs.
            // Total UTXO = amount + collateral_amount.
            amount: reserves_msats,
            quorum_expiry: result.quorum_expiry,
            ledger_hash,
            quorum_members: quorum_members
                .iter()
                .zip(member_ledger_ids.iter())
                .map(|(pk, lid)| deposits_core::messages::QuorumMemberRef::new(*pk, lid.clone()))
                .collect(),
            collateral_amount: collateral_msats,
            // Pin the ledger to the same ruleset the rotation TX
            // built the on-chain UTXO under. Inherits the ledger's
            // active ruleset (legacy by default) — migrations to a
            // different ruleset are an explicit deployer action.
            protocol_version: Some(new_ruleset_name.clone()),
        };

        // commit_operation runs the full stage → cosign → operator-sign →
        // apply → persist → broadcast flow. For a first QuorumBegin (state
        // is still PreQuorum here) it goes through request_cosign against
        // next_quorum_members and embeds their signatures into the update,
        // producing a result that peers' validators will accept.
        self.commit_operation(ledger_id, operation).await?;

        // --- Phase 5: the ledger op has committed → confirm wallet state ---
        // The taproot record was already persisted right after broadcast (see
        // the fresh-build branch above), so a crash anywhere between broadcast
        // and here resumes via `pending_resume` rather than rebuilding against a
        // spent input. This re-commit is idempotent for the fresh path (same
        // outpoint + script) and is the *first* persist for the resume path
        // (where build+broadcast were skipped); both are required.
        ledger_wallet.commit_taproot_reserves(pending_taproot)?;

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

    /// Build + cosign + broadcast a quorum rotation transaction.
    ///
    /// Spends the existing Taproot reserves UTXO via the tier-0 "majority
    /// immediate" leaf into a new Taproot output for the rotated key set
    /// (operator + `new_members`). The fee is deducted from the reserves
    /// amount; no wpkh wallet input is consumed.
    ///
    /// Returns `(TaprootReservesCreateResult, TaprootReservesInfo)` shaped
    /// identically to `build_activation_tx` so the caller's downstream
    /// phases (UTXO-depth wait, QuorumBegin op publish + cosign) work
    /// unchanged.
    #[allow(clippy::too_many_arguments)]
    async fn build_rotation_via_cosign(
        &self,
        ledger_id: &str,
        existing: &crate::wallet::TaprootReservesInfo,
        new_members: Vec<PublicKey>,
        new_expiries: Vec<u32>,
        new_ledger_hash: [u8; 32],
        new_ruleset_name: &str,
    ) -> Result<
        (
            crate::wallet::TaprootReservesCreateResult,
            crate::wallet::TaprootReservesInfo,
        ),
        Error,
    > {
        use bitcoin::taproot::LeafVersion;
        use bitcoin::Witness;
        use deposits_core::tapscript_reserves::{
            ReservesSpendBuilder, SpendTxParams, TapscriptReservesBuilder, VoterSet,
        };
        use deposits_signer_api::{SigPurpose, SignContext};
        use nostr_sdk::{Filter, Kind};

        let operator_key = self.node_id;

        // Build the *new* Taproot output (rotated keys). This is what the
        // refresh rotates *to*.
        let new_others: Vec<PublicKey> = new_members
            .iter()
            .filter(|pk| **pk != operator_key)
            .copied()
            .collect();
        let new_voter_set = VoterSet::new(operator_key, new_others);
        let ruleset = deposits_core::ruleset::resolve_or_legacy(Some(new_ruleset_name));
        let new_first_expiry = *new_expiries.iter().min().unwrap_or(&0);
        let new_config =
            (ruleset.tier_config_factory)(new_voter_set.all_voters().len(), new_first_expiry);
        let new_taproot_output = TapscriptReservesBuilder::new(
            new_voter_set,
            new_config,
            self.wallet.network(),
            new_ledger_hash,
        )
        .build()
        .map_err(|e| Error::Wallet(format!("build rotated taproot output: {:?}", e)))?;
        let new_script_pubkey = new_taproot_output.script_pubkey();
        let new_address = new_taproot_output.address.clone();

        // Rebuild the *current* (pre-rotation) builder + config so we can
        // address any tier's leaf script for sighash + witness assembly.
        let cur_voters_others: Vec<PublicKey> = existing
            .quorum_members
            .iter()
            .filter(|pk| **pk != existing.operator)
            .copied()
            .collect();
        let cur_voter_set = VoterSet::new(existing.operator, cur_voters_others);
        let cur_ruleset = deposits_core::ruleset::resolve_or_legacy(Some(&existing.ruleset_name));
        let cur_config = (cur_ruleset.tier_config_factory)(
            cur_voter_set.all_voters().len(),
            existing.quorum_expiry,
        );

        // DEP-05 §Lifecycle: pick the highest-numbered tier whose CLTV
        // is satisfied at the current chain tip. Higher = more
        // degraded = fewer cosigner sigs required. All Tier N >= 1 use
        // CHECKSIGADD over the voter set (after the build_threshold_
        // leaf cleanup); the witness shape is uniform across tiers.
        // Tier 3 (operator-alone, `threshold == 1 &&
        // requires_tie_breaker`) is the one exception — single CHECKSIG
        // of the operator key, handled by `operator_alone` below.
        let current_height = self.wallet.get_block_height().unwrap_or(0);
        let (tier_index, tier) = {
            let mut chosen: Option<(usize, deposits_core::tapscript_reserves::ThresholdTier)> =
                None;
            for (idx, t) in cur_config.tiers.iter().enumerate() {
                if current_height < t.timelock_blocks {
                    continue; // CLTV not yet satisfied
                }
                chosen = Some((idx, t.clone()));
            }
            chosen.ok_or_else(|| {
                Error::Protocol(format!(
                    "no usable tier at chain tip {} for ledger expiry {} \
                     (ruleset={}, quorum_size={})",
                    current_height,
                    existing.quorum_expiry,
                    existing.ruleset_name,
                    cur_voter_set.all_voters().len(),
                ))
            })?
        };
        let tier_lock_time = tier.timelock_blocks;
        let operator_alone = tier.threshold == 1 && tier.requires_tie_breaker;

        // Build the deterministic rotation TX (1 input → 1 output).
        // lock_time matches the tier's CLTV target (0 for Tier 0).
        let params = SpendTxParams {
            reserves_outpoint: existing.outpoint,
            reserves_amount: existing.amount,
            destination_script: new_script_pubkey.clone(),
            splits: Vec::new(),
            fee_rate_sat_vbyte: 5,
            lock_time: tier_lock_time,
        };
        let prev_script_pubkey = existing.taproot_output.script_pubkey();
        let rotation_tx =
            ReservesSpendBuilder::build_spend_transaction(&params, &prev_script_pubkey)
                .map_err(|e| Error::Wallet(format!("build rotation tx: {:?}", e)))?;
        let new_amount = rotation_tx.output[0].value.to_sat();
        let new_txid = rotation_tx.compute_txid();

        let cur_builder = TapscriptReservesBuilder::new(
            cur_voter_set.clone(),
            cur_config,
            self.wallet.network(),
            existing.ledger_hash,
        );
        let leaf_script = cur_builder
            .build_threshold_leaf(&tier)
            .map_err(|e| Error::Wallet(format!("build tier-{} leaf: {:?}", tier_index, e)))?;

        let sighash = ReservesSpendBuilder::compute_sighash(
            &rotation_tx,
            0,
            existing.amount,
            &prev_script_pubkey,
            &leaf_script,
        )
        .map_err(|e| Error::Wallet(format!("compute rotation sighash: {:?}", e)))?;
        let sighash_bytes: [u8; 32] = *sighash.as_ref();

        // Operator signs first.
        let our_sig = self
            .handler
            .signer
            .bip340_sign(
                &SignContext::no_ledger(SigPurpose::OnchainSighash),
                &sighash_bytes,
            )
            .map_err(|e| Error::Protocol(format!("operator rotation sighash sign: {}", e)))?;

        let mut sigs: std::collections::HashMap<PublicKey, [u8; 64]> =
            std::collections::HashMap::new();
        sigs.insert(operator_key, our_sig);

        // Tier-aware cosigner threshold. Tier 3 (operator-alone) needs
        // zero cosigner sigs — we short-circuit the multicast entirely
        // below. Tier 0 needs majority (= tier.threshold) total sigs,
        // and the operator's already in `sigs`.
        let cosigner_threshold = if operator_alone {
            0
        } else {
            tier.threshold.saturating_sub(1)
        };

        // Send rotation_sign request to the ledger; cosigners verify
        // TX shape + sighash and reply via KIND_LEDGER_RESPONSE.
        // tier_index lets the cosigner-side rebuild the same leaf
        // script we used for sighash; otherwise they'd default to
        // Tier 0 and the sighash check would fail when the operator
        // is rotating at a degraded tier.
        let unsigned_tx_hex = hex::encode(bitcoin::consensus::encode::serialize(&rotation_tx));
        let request_params = serde_json::json!({
            "sighash": hex::encode(sighash_bytes),
            "unsigned_tx": unsigned_tx_hex,
            "tier_index": tier_index,
            // Operator's own ledger_hash + new_first_expiry so the cosigner
            // rebuilds the *expected* rotated Taproot output with the same
            // inputs the operator used. Until chain_tip_hash is consistent
            // across replay paths, computing this independently on the
            // cosigner side produces a different hash → script mismatch
            // → refusal. The cosigner still validates the operator's claim
            // by checking the resulting script against the proposed TX.
            "ledger_hash": hex::encode(new_ledger_hash),
            "new_quorum_expiry": new_first_expiry,
        });
        // Tier-3 short-circuit: operator-alone path. No cosignatures
        // needed for the on-chain spend; skip the multicast + poll.
        // The off-chain ledger update's cosignatures are handled
        // separately by the cosign coordinator (which also short-
        // circuits at Tier 3).
        let request_id = if operator_alone {
            tracing::info!(
                "auto_rotation: Tier-{} operator-alone path for ledger {}... — skipping cosigner multicast",
                tier_index,
                &ledger_id[..16],
            );
            String::new()
        } else {
            let id = self
                .nostr
                .send_ledger_request(ledger_id, "rotation_sign", request_params)
                .await
                .map_err(|e| Error::Protocol(format!("publish rotation_sign: {:?}", e)))?;
            tracing::info!(
                "auto_rotation: published rotation_sign request {} for ledger {}... \
                 (tier={}, need {} cosigner sigs)",
                &id[..16.min(id.len())],
                &ledger_id[..16],
                tier_index,
                cosigner_threshold
            );
            id
        };

        // Poll relay for responses tagged with our request_id (skip for
        // operator-alone path).
        if !operator_alone {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
            let active_set: std::collections::HashSet<PublicKey> =
                existing.quorum_members.iter().copied().collect();
            while std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                let since = nostr_sdk::Timestamp::now() - 120;
                let filter = Filter::new()
                    .kind(Kind::Custom(crate::nostr::KIND_LEDGER_RESPONSE))
                    .since(since);
                // Responses are KIND_LEDGER_RESPONSE (ephemeral 20102); they
                // arrive on the fast (main) relay, not the slow/durable one.
                // Using fetch_client() would silently miss every response.
                let events = self
                    .nostr
                    .client()
                    .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
                    .await
                    .map_err(|e| {
                        Error::Protocol(format!("fetch rotation_sign responses: {}", e))
                    })?;

                for event in events.iter() {
                    let mut matches_request = false;
                    for tag in event.tags.iter() {
                        if tag.kind()
                            == nostr_sdk::TagKind::SingleLetter(crate::nostr::TAG_EVENT_REF)
                        {
                            if let Some(v) = tag.content() {
                                if v == request_id {
                                    matches_request = true;
                                    break;
                                }
                            }
                        }
                    }
                    if !matches_request {
                        continue;
                    }
                    let resp: crate::nostr::LedgerResponse =
                        match serde_json::from_str(&event.content) {
                            Ok(r) => r,
                            Err(_) => continue,
                        };
                    if !resp.success {
                        tracing::info!(
                            "auto_rotation: cosigner refused: {}",
                            resp.error
                                .clone()
                                .unwrap_or_else(|| "no reason".to_string())
                        );
                        continue;
                    }
                    let result = match resp.result.as_ref() {
                        Some(r) => r,
                        None => continue,
                    };
                    let signer_hex = match result.get("signer").and_then(|v| v.as_str()) {
                        Some(s) => s,
                        None => continue,
                    };
                    let sig_hex = match result.get("signature").and_then(|v| v.as_str()) {
                        Some(s) => s,
                        None => continue,
                    };
                    let signer_pk: PublicKey = match signer_hex.parse() {
                        Ok(pk) => pk,
                        Err(_) => continue,
                    };
                    if !active_set.contains(&signer_pk) {
                        continue; // ignore non-members
                    }
                    if sigs.contains_key(&signer_pk) {
                        continue;
                    }
                    let sig_bytes = match hex::decode(sig_hex) {
                        Ok(b) if b.len() == 64 => b,
                        _ => continue,
                    };
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(&sig_bytes);
                    sigs.insert(signer_pk, arr);
                    tracing::info!(
                        "auto_rotation: collected sig from {}... ({}/{})",
                        &signer_pk.to_string()[..16],
                        sigs.len() - 1, // exclude operator
                        cosigner_threshold
                    );
                }

                // We need majority of all voters (operator + cosigners). The
                // operator already signed; check we have ≥ cosigner_threshold
                // from cosigners.
                if sigs.len() > cosigner_threshold {
                    break;
                }
            }
            tracing::info!(
                "auto_rotation: polling exited for request {} — {} cosigner sigs collected",
                &request_id[..16.min(request_id.len())],
                sigs.len() - 1
            );
            if sigs.len() - 1 < cosigner_threshold {
                return Err(Error::Protocol(format!(
                    "rotation cosign timeout: got {}/{} cosigner sigs",
                    sigs.len() - 1,
                    cosigner_threshold
                )));
            }
        } // end if !operator_alone

        // Assemble the witness, shape depending on the tier we picked.
        let control_block = existing
            .taproot_output
            .control_block_for_tier(tier_index)
            .ok_or_else(|| Error::Protocol(format!("no control block for tier {}", tier_index)))?;

        let mut witness = Witness::new();
        if operator_alone {
            // Tier-3 leaf: `<operator_xonly> CHECKSIG`. Witness is just
            // the operator's sig.
            let op_sig = sigs.get(&operator_key).ok_or_else(|| {
                Error::Protocol("operator sig missing for Tier-3 path".to_string())
            })?;
            witness.push(op_sig);
        } else {
            // Tier-0 (and any future multisig tier): CHECKSIGADD pattern.
            // Stack order: [sig_N, sig_{N-1}, ..., sig_0, leaf, ctrl]
            // where sig_i corresponds to voter at sorted_x_only_pubkeys()[i].
            // Empty bytes for voters that didn't sign (still a valid
            // stack entry for OP_CHECKSIGADD).
            let sorted = cur_voter_set.sorted_x_only_pubkeys();
            for x_only in sorted.iter().rev() {
                let mut pushed = false;
                for (pk, sig) in &sigs {
                    if pk.x_only_public_key().0 == *x_only {
                        witness.push(sig);
                        pushed = true;
                        break;
                    }
                }
                if !pushed {
                    witness.push([] as [u8; 0]);
                }
            }
        }
        witness.push(leaf_script.as_bytes());
        witness.push(control_block.serialize());

        let mut signed_tx = rotation_tx;
        signed_tx.input[0].witness = witness;

        let _ = LeafVersion::TapScript;

        // Broadcast via the node wallet (regular Bitcoin RPC / esplora).
        let broadcast_txid = self.wallet.broadcast(&signed_tx)?;
        tracing::info!(
            "auto_rotation: broadcast rotation tx {} (ledger {}..., {} -> {} sats, fee {})",
            broadcast_txid,
            &ledger_id[..16],
            existing.amount,
            new_amount,
            existing.amount - new_amount,
        );

        let new_outpoint = bitcoin::OutPoint {
            txid: new_txid,
            vout: 0,
        };
        let synth_result = crate::wallet::TaprootReservesCreateResult {
            outpoint: new_outpoint,
            address: new_address,
            amount: new_amount,
            tx: signed_tx,
            taproot_output: new_taproot_output.clone(),
            quorum_expiry: new_first_expiry,
            ledger_hash: new_ledger_hash,
        };
        let pending = crate::wallet::TaprootReservesInfo {
            outpoint: new_outpoint,
            amount: new_amount,
            operator: operator_key,
            quorum_members: new_members.clone(),
            quorum_expiry: new_first_expiry,
            ledger_hash: new_ledger_hash,
            taproot_output: new_taproot_output,
            ruleset_name: new_ruleset_name.to_string(),
            confirmed: false,
        };
        Ok((synth_result, pending))
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
        descriptor: &str,
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

        // The descriptor is the source of identity; deposit_id is its hash.
        let deposit_id = compute_deposit_id(descriptor);

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

        // Sign the offer through the Signer (digest construction stays in
        // deposits-core; signing goes through the trait so RemoteSigner /
        // anti-equivocation policy can intercept).
        let offer_digest = deposits_core::signing::deposit_offer_signing_digest(
            &self.node_id,
            ledger_id,
            &deposit_id,
            &funding_address_str,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        );
        let signature = self
            .handler
            .signer
            .bip340_sign(
                &deposits_signer_api::SignContext::no_ledger(
                    deposits_signer_api::SigPurpose::DepositOffer,
                ),
                &offer_digest,
            )
            .map_err(|e| Error::Protocol(format!("Failed to sign offer: {}", e)))?;

        // Create the offer
        let offer = DepositOffer {
            operator_id: self.node_id,
            ledger_id: ledger_id.to_string(),
            deposit_id,
            descriptor: descriptor.to_string(),
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
        let tip = self.wallet.get_block_height().unwrap_or(0);
        if let Err(e) = self.nostr.publish_price(price, tip).await {
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
                    return Some(format!(
                        "allowlist_npub={}",
                        &npub_lower[..16.min(npub_lower.len())]
                    ));
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

    // ========================================================================
    // Per-ledger wallet management (phase 1c).
    // ========================================================================

    /// Return the per-ledger wallet for `ledger_id`, creating one at the
    /// next available BIP-32 account if it doesn't exist yet.
    ///
    /// Idempotent: a second call with the same `ledger_id` returns the
    /// existing wallet at the original account, without consuming an
    /// account index.
    /// Snapshot the staged quorum membership + ledger hash for a ledger, in
    /// the same (`next_quorum_members` first, else active) order
    /// `rotate_reserves_to_quorum` uses to build the activation tx. Used by
    /// the `recovery adopt-vault` path to re-derive a lost taproot record.
    pub fn quorum_snapshot(&self, ledger_id: &str) -> Result<(Vec<PublicKey>, [u8; 32]), Error> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        let l = ledgers
            .get(ledger_id)
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
            .read()
            .unwrap();
        let source = if !l.state.next_quorum_members.is_empty() {
            &l.state.next_quorum_members
        } else {
            &l.state.quorum_members
        };
        let members: Vec<PublicKey> = source.iter().map(|m| m.pubkey).collect();
        Ok((members, l.hash()))
    }

    pub fn ensure_ledger_wallet(
        &self,
        ledger_id: &str,
    ) -> Result<Arc<crate::ledger_wallet::LedgerWallet>, Error> {
        if let Some(w) = self.ledger_wallets.read().unwrap().get(ledger_id).cloned() {
            return Ok(w);
        }
        let mut wallets = self.ledger_wallets.write().unwrap();
        // Re-check after lock upgrade in case another thread raced to create.
        if let Some(w) = wallets.get(ledger_id).cloned() {
            return Ok(w);
        }
        // Disk-side reconciliation: a sibling process (e.g. the CLI
        // `ledger address` invoked between `ledger open` and the next
        // daemon op) may have already created the ledger wallet on
        // disk. Detect that and `load` instead of refusing on the
        // "already exists" check.
        let existing_dir =
            crate::ledger_wallet::LedgerWallet::ledger_dir(&self.data_dir, ledger_id);
        let lw = if existing_dir.join("account_index.txt").exists() {
            crate::ledger_wallet::LedgerWallet::load(
                &*self.handler.signer,
                self.wallet.network(),
                ledger_id,
                &self.data_dir,
                self.electrum_url.clone(),
            )?
        } else {
            let mut next = self.next_ledger_account.lock().unwrap();
            let account = *next;
            let lw = crate::ledger_wallet::LedgerWallet::create(
                &*self.handler.signer,
                self.wallet.network(),
                account,
                ledger_id,
                &self.data_dir,
                self.electrum_url.clone(),
            )?;
            *next = next.checked_add(1).ok_or_else(|| {
                Error::Wallet("BIP-32 ledger-wallet account counter overflowed u32".into())
            })?;
            tracing::info!(
                "Created ledger wallet for {} at BIP-32 account {}",
                &ledger_id[..16.min(ledger_id.len())],
                account,
            );
            lw
        };
        let arc = Arc::new(lw);
        wallets.insert(ledger_id.to_string(), Arc::clone(&arc));
        // The on-disk counter may have advanced past `next_ledger_account`
        // if a sibling process bumped it; re-sync so the daemon doesn't
        // hand out a duplicate account on its next create.
        let on_disk_acct = arc.account_index();
        let mut next = self.next_ledger_account.lock().unwrap();
        if *next <= on_disk_acct {
            *next = on_disk_acct + 1;
        }
        Ok(arc)
    }

    /// Look up an existing per-ledger wallet without creating one.
    pub fn ledger_wallet(
        &self,
        ledger_id: &str,
    ) -> Option<Arc<crate::ledger_wallet::LedgerWallet>> {
        self.ledger_wallets.read().unwrap().get(ledger_id).cloned()
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
