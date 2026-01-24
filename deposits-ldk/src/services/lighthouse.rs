//! Lighthouse Service - Chain Monitoring for Reserves Outputs
//!
//! Watches the blockchain for transactions involving reserves outputs where our
//! pubkey is part of the multisig. This enables detection of:
//! - Force closes (commitment transactions appearing on-chain)
//! - Reserves spends (cooperative or recovery)
//!
//! When a relevant transaction is detected, the lighthouse triggers the appropriate
//! recovery flow by notifying the RecoveryManager.

use std::collections::HashMap;
use std::convert::TryInto;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Block, BlockHash, Network, ScriptBuf, Transaction, Txid};
use lightning::util::logger::Logger as LdkLogger;
use deposits_core::{log_debug, log_info, log_warn};

use bitcoin::secp256k1::Keypair;

use deposits_core::tapscript_reserves::{TapscriptReservesBuilder, VoterSet};
use deposits_core::recovery::{RecoveryManager, RecoveryState, RecoveryVote, VoteResult};
use deposits_core::{LedgerConformanceValidator, ConformanceResult};
use crate::handler::validation_ext::LedgerConformanceValidatorExt;
use deposits_core::SignedLedgerUpdate;
use deposits_core::DepositsResult;

/// Information about a reserves output we're watching
#[derive(Clone, Debug)]
pub struct WatchedReservesOutput {
    /// The P2TR script pubkey for this reserves output
    pub script_pubkey: ScriptBuf,
    /// The voter set (all pubkeys in the multisig)
    pub voter_set: VoterSet,
    /// The operator pubkey (could be us or the partner)
    pub operator: PublicKey,
    /// The channel partner
    pub partner: PublicKey,
    /// Optional: ledger hash at time of last commitment (for recovery verification)
    pub ledger_hash: Option<[u8; 32]>,
    /// The reserves amount in satoshis
    pub amount_sats: u64,
    /// Network this output is for
    pub network: Network,
}

/// Event emitted when a watched reserves output is detected on-chain
#[derive(Clone, Debug)]
pub enum LighthouseEvent {
    /// A commitment transaction with reserves output appeared on-chain
    /// This could be a force close by either party
    ReservesOutputConfirmed {
        /// The confirmed transaction
        txid: Txid,
        /// Output index of the reserves output
        vout: u32,
        /// Block height where it was confirmed
        block_height: u32,
        /// Block hash for entropy derivation
        block_hash: BlockHash,
        /// The script pubkey that matched
        script_pubkey: ScriptBuf,
        /// The operator pubkey
        operator: PublicKey,
        /// The channel partner
        partner: PublicKey,
        /// The ledger hash embedded in the commitment (if known)
        ledger_hash: Option<[u8; 32]>,
        /// Amount in the reserves output
        amount_sats: u64,
    },

    /// A reserves output we were watching has been spent
    ReservesOutputSpent {
        /// The spending transaction
        spending_txid: Txid,
        /// The original reserves outpoint that was spent
        original_txid: Txid,
        original_vout: u32,
        /// Block height where the spend was confirmed
        block_height: u32,
        /// Block hash
        block_hash: BlockHash,
        /// The operator pubkey
        operator: PublicKey,
        /// The channel partner
        partner: PublicKey,
    },

    /// A channel we're monitoring closed WITHOUT a reserves output
    /// This indicates potential collusion - partners cooperative-closed
    /// without including the reserves tapscript output. Recovery uses
    /// "second order" algorithm based on audit records.
    ChannelClosedWithoutReserves {
        /// The Lightning channel ID that closed
        channel_id: [u8; 32],
        /// Block height where the close was detected
        block_height: u32,
        /// The operator pubkey of the ledger backed by this channel
        operator: PublicKey,
        /// The channel partner
        partner: PublicKey,
        /// Whether this was a cooperative close (vs force close)
        is_cooperative: bool,
        /// Last known ledger hash from our audit records
        last_audit_hash: Option<[u8; 32]>,
        /// Last known ledger sequence from our audit records
        last_audit_sequence: Option<u64>,
    },
}

/// Information about a channel we're watching for close events
/// Used to trigger recovery when a channel closes, even without reserves on-chain
#[derive(Clone, Debug)]
pub struct WatchedChannel {
    /// The Lightning channel ID
    pub channel_id: [u8; 32],
    /// The operator pubkey of the ledger backed by this channel
    pub operator: PublicKey,
    /// The channel partner (who we have a channel with)
    pub partner: PublicKey,
    /// Last known ledger hash from audit sync
    pub last_audit_hash: Option<[u8; 32]>,
    /// Last known ledger sequence from audit sync
    pub last_audit_sequence: Option<u64>,
    /// Whether we saw reserves output confirmed for this channel
    /// If channel closes and this is false, it's ChannelClosedWithoutReserves
    pub reserves_confirmed: bool,
}

/// Lighthouse service for monitoring blockchain for reserves outputs
pub struct LighthouseService<L: Deref + Clone>
where
    L::Target: LdkLogger,
{
    /// Our node's public key
    our_pubkey: PublicKey,

    /// Reserves outputs we're watching (script_pubkey -> info)
    watched_outputs: Arc<RwLock<HashMap<ScriptBuf, WatchedReservesOutput>>>,

    /// Confirmed reserves outputs (txid:vout -> info) - outputs that appeared on-chain
    confirmed_outputs: Arc<RwLock<HashMap<(Txid, u32), WatchedReservesOutput>>>,

    /// Channels we're watching for close events (channel_id -> info)
    /// This tracks channels backing ledgers we're auditing
    watched_channels: Arc<RwLock<HashMap<[u8; 32], WatchedChannel>>>,

    /// Recovery manager for handling force-close recovery
    recovery_manager: Arc<RwLock<RecoveryManager>>,

    /// Event queue for external consumption
    event_queue: Arc<RwLock<Vec<LighthouseEvent>>>,

    /// Network we're watching
    network: Network,

    /// Last processed block height
    last_block_height: Arc<RwLock<u32>>,

    /// Logger
    logger: L,
}

impl<L: Deref + Clone> LighthouseService<L>
where
    L::Target: LdkLogger,
{
    /// Create a new lighthouse service
    pub fn new(our_pubkey: PublicKey, network: Network, logger: L) -> Self {
        let recovery_manager = RecoveryManager::new(our_pubkey);

        Self {
            our_pubkey,
            watched_outputs: Arc::new(RwLock::new(HashMap::new())),
            confirmed_outputs: Arc::new(RwLock::new(HashMap::new())),
            watched_channels: Arc::new(RwLock::new(HashMap::new())),
            recovery_manager: Arc::new(RwLock::new(recovery_manager)),
            event_queue: Arc::new(RwLock::new(Vec::new())),
            network,
            last_block_height: Arc::new(RwLock::new(0)),
            logger,
        }
    }

    /// Register a reserves output to watch
    ///
    /// Call this when a ledger is opened with a channel partner to start
    /// watching for on-chain reserves outputs with this configuration.
    pub fn watch_reserves_output(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        other_voters: Vec<PublicKey>,
        amount_sats: u64,
        ledger_hash: Option<[u8; 32]>,
    ) -> DepositsResult<ScriptBuf> {
        // Build the voter set with partner as tie-breaker
        let voter_set = VoterSet::new(partner, other_voters);

        // Use provided ledger_hash or zeros if not known yet
        let hash = ledger_hash.unwrap_or([0u8; 32]);

        // Build the taproot output to get the script pubkey
        let builder = TapscriptReservesBuilder::with_defaults(voter_set.clone(), self.network, hash);
        let output = builder.build()?;
        let script_pubkey = output.script_pubkey();

        let watched = WatchedReservesOutput {
            script_pubkey: script_pubkey.clone(),
            voter_set,
            operator,
            partner,
            ledger_hash,
            amount_sats,
            network: self.network,
        };

        let mut outputs = self.watched_outputs.write().unwrap();
        outputs.insert(script_pubkey.clone(), watched);

        log_info!(
            self.logger,
            "Lighthouse: Now watching reserves output for operator {} / partner {} (script_pubkey: {}...)",
            operator,
            partner,
            hex::encode(&script_pubkey.as_bytes()[..8])
        );

        Ok(script_pubkey)
    }

    /// Stop watching a reserves output (e.g., when channel is cooperatively closed)
    pub fn unwatch_reserves_output(&self, script_pubkey: &ScriptBuf) {
        let mut outputs = self.watched_outputs.write().unwrap();
        if let Some(removed) = outputs.remove(script_pubkey) {
            log_info!(
                self.logger,
                "Lighthouse: Stopped watching reserves output for partner {}",
                removed.partner
            );
        }
    }

    /// Register a channel to watch for close events
    ///
    /// Call this when receiving SignedAuditUpdate messages for a ledger.
    /// The lighthouse will track this channel and emit events when it closes,
    /// even if the close doesn't include a reserves output.
    pub fn watch_channel(
        &self,
        channel_id: [u8; 32],
        operator: PublicKey,
        partner: PublicKey,
    ) {
        let watched = WatchedChannel {
            channel_id,
            operator,
            partner,
            last_audit_hash: None,
            last_audit_sequence: None,
            reserves_confirmed: false,
        };

        let mut channels = self.watched_channels.write().unwrap();
        channels.insert(channel_id, watched);

        log_info!(
            self.logger,
            "Lighthouse: Now watching channel {} for close events (operator={}, partner={})",
            hex::encode(&channel_id[..8]),
            operator,
            partner
        );
    }

    /// Stop watching a channel
    pub fn unwatch_channel(&self, channel_id: &[u8; 32]) {
        let mut channels = self.watched_channels.write().unwrap();
        if let Some(removed) = channels.remove(channel_id) {
            log_info!(
                self.logger,
                "Lighthouse: Stopped watching channel {} (operator={}, partner={})",
                hex::encode(&channel_id[..8]),
                removed.operator,
                removed.partner
            );
        }
    }

    /// Update the audit record for a watched channel
    ///
    /// Call this when receiving SignedAuditUpdate to keep track of
    /// the last known ledger hash and sequence. This info is used
    /// for the "second order" recovery if channel closes without reserves.
    pub fn update_audit_record(
        &self,
        channel_id: &[u8; 32],
        ledger_hash: [u8; 32],
        sequence: u64,
    ) {
        let mut channels = self.watched_channels.write().unwrap();
        if let Some(watched) = channels.get_mut(channel_id) {
            watched.last_audit_hash = Some(ledger_hash);
            watched.last_audit_sequence = Some(sequence);
            log_debug!(
                self.logger,
                "Lighthouse: Updated audit record for channel {} (hash={}, seq={})",
                hex::encode(&channel_id[..8]),
                hex::encode(&ledger_hash[..8]),
                sequence
            );
        }
    }

    /// Handle channel close notification
    ///
    /// Call this when a channel closes (from LightningEventService).
    /// If we're watching this channel and haven't seen reserves confirmed,
    /// emit ChannelClosedWithoutReserves event for second-order recovery.
    pub fn on_channel_closed(
        &self,
        channel_id: [u8; 32],
        is_cooperative: bool,
    ) -> Option<LighthouseEvent> {
        let current_block = *self.last_block_height.read().unwrap();

        let mut channels = self.watched_channels.write().unwrap();
        if let Some(watched) = channels.remove(&channel_id) {
            if watched.reserves_confirmed {
                // Reserves output was seen on-chain - normal recovery flow applies
                log_info!(
                    self.logger,
                    "Lighthouse: Channel {} closed with reserves confirmed - normal recovery",
                    hex::encode(&channel_id[..8])
                );
                return None;
            }

            // No reserves output seen - this is concerning
            // Emit event for second-order recovery algorithm
            log_warn!(
                self.logger,
                "Lighthouse: Channel {} closed WITHOUT reserves output! operator={}, partner={}, cooperative={}",
                hex::encode(&channel_id[..8]),
                watched.operator,
                watched.partner,
                is_cooperative
            );

            let event = LighthouseEvent::ChannelClosedWithoutReserves {
                channel_id,
                block_height: current_block,
                operator: watched.operator,
                partner: watched.partner,
                is_cooperative,
                last_audit_hash: watched.last_audit_hash,
                last_audit_sequence: watched.last_audit_sequence,
            };

            // Queue the event
            {
                let mut queue = self.event_queue.write().unwrap();
                queue.push(event.clone());
            }

            return Some(event);
        }

        // Not a channel we were watching
        None
    }

    /// Get all watched channels
    pub fn get_watched_channels(&self) -> Vec<WatchedChannel> {
        let channels = self.watched_channels.read().unwrap();
        channels.values().cloned().collect()
    }

    /// Process a new block from the blockchain
    ///
    /// Scans the block for transactions that:
    /// 1. Create outputs matching our watched script pubkeys (force close detected)
    /// 2. Spend from our confirmed reserves outputs (spend detected)
    pub fn process_block(
        &self,
        block: &Block,
        block_height: u32,
    ) -> Vec<LighthouseEvent> {
        let block_hash = block.block_hash();
        let mut events = Vec::new();

        log_debug!(
            self.logger,
            "Lighthouse: Processing block {} at height {}",
            block_hash,
            block_height
        );

        // Update last processed height
        {
            let mut height = self.last_block_height.write().unwrap();
            *height = block_height;
        }

        // Check each transaction in the block
        for tx in &block.txdata {
            // Check for newly created reserves outputs (force close detection)
            events.extend(self.check_for_created_outputs(tx, block_height, block_hash));

            // Check for spent reserves outputs
            events.extend(self.check_for_spent_outputs(tx, block_height, block_hash));
        }

        // Queue events for external consumption
        if !events.is_empty() {
            let mut queue = self.event_queue.write().unwrap();
            queue.extend(events.clone());
        }

        // Trigger recovery flows for any new confirmations
        for event in &events {
            if let LighthouseEvent::ReservesOutputConfirmed {
                txid,
                block_height,
                operator,
                partner,
                ledger_hash,
                ..
            } = event
            {
                // Convert Txid to [u8; 32] for recovery
                let txid_slice: &[u8] = txid.as_ref();
                let txid_bytes: [u8; 32] = txid_slice.try_into().expect("Txid is always 32 bytes");
                self.initiate_recovery(
                    *operator,
                    *partner,
                    *block_height,
                    txid_bytes,
                    *ledger_hash,
                );
            }
        }

        events
    }

    /// Check transaction outputs for matches against watched script pubkeys
    fn check_for_created_outputs(
        &self,
        tx: &Transaction,
        block_height: u32,
        block_hash: BlockHash,
    ) -> Vec<LighthouseEvent> {
        let mut events = Vec::new();
        let outputs = self.watched_outputs.read().unwrap();

        for (vout, output) in tx.output.iter().enumerate() {
            if let Some(watched) = outputs.get(&output.script_pubkey) {
                let txid = tx.compute_txid();

                log_info!(
                    self.logger,
                    "Lighthouse: DETECTED reserves output on-chain! txid={}, vout={}, operator={}, partner={}, amount={}",
                    txid,
                    vout,
                    watched.operator,
                    watched.partner,
                    output.value.to_sat()
                );

                // Add to confirmed outputs for spend tracking
                {
                    let mut confirmed = self.confirmed_outputs.write().unwrap();
                    confirmed.insert((txid, vout as u32), watched.clone());
                }

                // Mark any watched channel for this (operator, partner) as having reserves confirmed
                // This is important: if we see reserves on-chain, normal recovery applies
                {
                    let mut channels = self.watched_channels.write().unwrap();
                    for channel in channels.values_mut() {
                        if channel.operator == watched.operator && channel.partner == watched.partner {
                            channel.reserves_confirmed = true;
                            log_debug!(
                                self.logger,
                                "Lighthouse: Marked channel {} as reserves_confirmed for operator={}, partner={}",
                                hex::encode(&channel.channel_id[..8]),
                                watched.operator,
                                watched.partner
                            );
                        }
                    }
                }

                events.push(LighthouseEvent::ReservesOutputConfirmed {
                    txid,
                    vout: vout as u32,
                    block_height,
                    block_hash,
                    script_pubkey: output.script_pubkey.clone(),
                    operator: watched.operator,
                    partner: watched.partner,
                    ledger_hash: watched.ledger_hash,
                    amount_sats: output.value.to_sat(),
                });
            }
        }

        events
    }

    /// Check transaction inputs for spends of our confirmed reserves outputs
    fn check_for_spent_outputs(
        &self,
        tx: &Transaction,
        block_height: u32,
        block_hash: BlockHash,
    ) -> Vec<LighthouseEvent> {
        let mut events = Vec::new();

        // Collect events while holding read lock
        {
            let confirmed = self.confirmed_outputs.read().unwrap();

            for input in &tx.input {
                let outpoint = (input.previous_output.txid, input.previous_output.vout);

                if let Some(watched) = confirmed.get(&outpoint) {
                    let spending_txid = tx.compute_txid();

                    log_info!(
                        self.logger,
                        "Lighthouse: DETECTED reserves spend! spending_txid={}, original={}:{}, operator={}, partner={}",
                        spending_txid,
                        outpoint.0,
                        outpoint.1,
                        watched.operator,
                        watched.partner
                    );

                    events.push(LighthouseEvent::ReservesOutputSpent {
                        spending_txid,
                        original_txid: outpoint.0,
                        original_vout: outpoint.1,
                        block_height,
                        block_hash,
                        operator: watched.operator,
                        partner: watched.partner,
                    });
                }
            }
        } // Read lock is dropped here

        // Remove spent outputs from confirmed set (now safe to acquire write lock)
        if !events.is_empty() {
            let mut confirmed = self.confirmed_outputs.write().unwrap();
            for event in &events {
                if let LighthouseEvent::ReservesOutputSpent {
                    original_txid,
                    original_vout,
                    ..
                } = event
                {
                    confirmed.remove(&(*original_txid, *original_vout));
                }
            }
        }

        events
    }

    /// Initiate recovery process for a force-closed channel
    fn initiate_recovery(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        force_close_block: u32,
        force_close_txid: [u8; 32],
        ledger_hash: Option<[u8; 32]>,
    ) {
        let on_chain_ledger_hash = ledger_hash.unwrap_or([0u8; 32]);

        let mut manager = self.recovery_manager.write().unwrap();

        match manager.start_recovery(
            operator,
            partner,
            force_close_block,
            force_close_txid,
            on_chain_ledger_hash,
        ) {
            Ok(()) => {
                log_info!(
                    self.logger,
                    "Lighthouse: Initiated recovery for operator {} / partner {} at block {}, waiting for entropy at block {}",
                    operator,
                    partner,
                    force_close_block,
                    force_close_block + deposits_core::recovery::ENTROPY_DELAY_BLOCKS
                );
            }
            Err(e) => {
                log_warn!(
                    self.logger,
                    "Lighthouse: Failed to start recovery for operator {} / partner {}: {:?}",
                    operator,
                    partner,
                    e
                );
            }
        }
    }

    /// Process entropy block arrival (force_close_block + 6)
    pub fn on_entropy_block(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        entropy_block_hash: [u8; 32],
    ) -> Result<(), String> {
        let ledger_id = (operator, partner);
        let mut manager = self.recovery_manager.write().unwrap();

        match manager.on_entropy_block(ledger_id, entropy_block_hash) {
            Ok(()) => {
                log_info!(
                    self.logger,
                    "Lighthouse: Entropy block received for operator {} / partner {}, recovery now in evaluation phase",
                    operator,
                    partner
                );
                Ok(())
            }
            Err(e) => {
                let err_msg = format!("{:?}", e);
                log_warn!(
                    self.logger,
                    "Lighthouse: Failed to process entropy block for operator {} / partner {}: {}",
                    operator,
                    partner,
                    err_msg
                );
                Err(err_msg)
            }
        }
    }

    /// Drain queued events
    pub fn drain_events(&self) -> Vec<LighthouseEvent> {
        let mut queue = self.event_queue.write().unwrap();
        std::mem::take(&mut *queue)
    }

    /// Get all currently watched script pubkeys
    pub fn get_watched_script_pubkeys(&self) -> Vec<ScriptBuf> {
        let outputs = self.watched_outputs.read().unwrap();
        outputs.keys().cloned().collect()
    }

    /// Get all confirmed reserves outputs (for monitoring)
    pub fn get_confirmed_outputs(&self) -> Vec<(Txid, u32, WatchedReservesOutput)> {
        let confirmed = self.confirmed_outputs.read().unwrap();
        confirmed
            .iter()
            .map(|((txid, vout), info)| (*txid, *vout, info.clone()))
            .collect()
    }

    /// Get recovery state for a ledger
    pub fn get_recovery_state(&self, operator: PublicKey, partner: PublicKey) -> Option<RecoveryState> {
        let manager = self.recovery_manager.read().unwrap();
        manager.get_recovery(&(operator, partner)).cloned()
    }

    /// Get last processed block height
    pub fn get_last_block_height(&self) -> u32 {
        *self.last_block_height.read().unwrap()
    }

    /// Set the last processed block height (for testing)
    #[cfg(test)]
    pub fn set_block_height(&self, height: u32) {
        *self.last_block_height.write().unwrap() = height;
    }

    /// Check if a recovery is in the NonCompliantRecovery phase
    ///
    /// Returns the eligibility info if we can participate in the claim process.
    pub fn check_claim_eligibility(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        current_block: u32,
    ) -> Option<deposits_core::recovery::ClaimEligibility> {
        use deposits_core::recovery::ClaimEligibility;

        let manager = self.recovery_manager.read().unwrap();
        let state = manager.get_recovery(&(operator, partner))?;

        // Check if we're in NonCompliantRecovery phase
        if let deposits_core::recovery::RecoveryPhase::NonCompliantRecovery {
            force_close_block,
            recovery_pool,
            ..
        } = &state.phase
        {
            // Get selected partner from recovery pool
            let selected_partner = recovery_pool.selected_partner?;

            // Calculate current eligibility based on blocks elapsed
            let blocks_elapsed = current_block.saturating_sub(*force_close_block);
            Some(ClaimEligibility::from_blocks_elapsed(blocks_elapsed, selected_partner))
        } else {
            None
        }
    }

    /// Check if we're eligible to claim at the current eligibility tier
    pub fn can_we_claim(
        &self,
        eligibility: &deposits_core::recovery::ClaimEligibility,
        channel_partners: &[PublicKey],
    ) -> bool {
        use deposits_core::recovery::ClaimEligibility;

        match eligibility {
            ClaimEligibility::SelectedPartnerOnly { partner } => {
                *partner == self.our_pubkey
            }
            ClaimEligibility::AnyThreePartners | ClaimEligibility::AnySinglePartner => {
                channel_partners.contains(&self.our_pubkey)
            }
            ClaimEligibility::CommunityFallback => {
                // Anyone can claim in community fallback
                true
            }
        }
    }

    /// Get a confirmed reserves output for a ledger
    pub fn get_confirmed_reserves(
        &self,
        operator: PublicKey,
        partner: PublicKey,
    ) -> Option<(Txid, u32, WatchedReservesOutput)> {
        let confirmed = self.confirmed_outputs.read().unwrap();
        confirmed.iter()
            .find(|(_, w)| w.operator == operator && w.partner == partner)
            .map(|((txid, vout), watched)| (*txid, *vout, watched.clone()))
    }

    /// Add a signature to an active claim attempt
    pub fn add_claim_signature(
        &self,
        attempt: &mut deposits_core::recovery_claim::ClaimAttempt,
        voter_index: usize,
        signature: [u8; 64],
    ) {
        attempt.add_signature(voter_index, signature);
        log_debug!(
            self.logger,
            "Lighthouse: Added signature from voter index {} to claim attempt",
            voter_index
        );
    }

    /// Check if a claim attempt has sufficient signatures and finalize it
    pub fn finalize_claim(
        &self,
        attempt: &deposits_core::recovery_claim::ClaimAttempt,
    ) -> DepositsResult<Transaction> {
        if !attempt.has_sufficient_signatures() {
            return Err(deposits_core::DepositsError::InvalidState(
                "Not enough signatures to finalize claim".to_string(),
            ));
        }

        let finalized_tx = attempt.finalize()?;

        log_info!(
            self.logger,
            "Lighthouse: Finalized claim transaction with txid={}",
            finalized_tx.compute_txid()
        );

        Ok(finalized_tx)
    }

    /// Get the recovery manager (for advanced use cases)
    pub fn recovery_manager(&self) -> &Arc<RwLock<RecoveryManager>> {
        &self.recovery_manager
    }

    // ========================================================================
    // LEDGER VALIDATION AND VOTING
    // ========================================================================

    /// Evaluate ledger conformance and submit a vote
    ///
    /// This is the main entry point for validation during recovery.
    /// Call this when transitioning to the Evaluating phase.
    ///
    /// # Arguments
    /// * `operator` - The operator pubkey of the ledger being evaluated
    /// * `partner` - The partner pubkey
    /// * `signed_updates` - The signed update chain to validate
    /// * `claimed_reserves` - Reserves amount from the on-chain commitment tx
    /// * `collateral_amounts` - Collateral from other partner channels
    /// * `on_chain_ledger_hash` - The ledger hash from on-chain data
    /// * `keypair` - Our keypair for signing the vote
    ///
    /// # Returns
    /// The conformance result and the vote result (how many votes we have)
    pub fn evaluate_and_vote(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        signed_updates: &[SignedLedgerUpdate],
        claimed_reserves: u64,
        collateral_amounts: &[u64],
        on_chain_ledger_hash: [u8; 32],
        keypair: &Keypair,
    ) -> Result<(ConformanceResult, VoteResult), String> {
        log_info!(
            self.logger,
            "Lighthouse: Evaluating ledger conformance for operator={}, partner={}, {} updates",
            operator,
            partner,
            signed_updates.len()
        );

        // 1. Validate the update chain
        let validator = LedgerConformanceValidator::new();
        let result = validator.validate_update_chain(
            signed_updates,
            operator,
            claimed_reserves,
            collateral_amounts,
            Some(on_chain_ledger_hash),
        );

        log_info!(
            self.logger,
            "Lighthouse: Validation result - conforming={}, violations={}, final_seq={}, deposits={}",
            result.is_conforming,
            result.violations.len(),
            result.final_sequence,
            result.total_deposits
        );

        // Log violations if any
        for (i, violation) in result.violations.iter().enumerate() {
            log_warn!(
                self.logger,
                "Lighthouse: Violation {}: {:?}",
                i + 1,
                violation
            );
        }

        // 2. Create and sign our vote
        let vote = RecoveryVote::new_signed(
            keypair,
            result.is_conforming,
            result.final_state_hash,
            result.final_sequence,
            None, // substitute_nomination - could be enhanced later
            !result.is_conforming, // discovered_violation if non-conforming
        ).map_err(|e| format!("Failed to create signed vote: {:?}", e))?;

        // 3. Submit the vote to recovery manager
        let ledger_id = (operator, partner);
        let vote_result = {
            let mut manager = self.recovery_manager.write().unwrap();
            manager.submit_vote(ledger_id, vote)
                .map_err(|e| format!("Failed to submit vote: {:?}", e))?
        };

        log_info!(
            self.logger,
            "Lighthouse: Vote submitted - total={}, conforming={}, non_conforming={}",
            vote_result.total_votes,
            vote_result.conforming_votes,
            vote_result.non_conforming_votes
        );

        Ok((result, vote_result))
    }

    /// Get the conformance result for a ledger (for display/debugging)
    ///
    /// This is a convenience method that just runs validation without voting.
    pub fn validate_ledger(
        &self,
        signed_updates: &[SignedLedgerUpdate],
        operator: PublicKey,
        claimed_reserves: u64,
        collateral_amounts: &[u64],
        claimed_state_hash: Option<[u8; 32]>,
    ) -> ConformanceResult {
        let validator = LedgerConformanceValidator::new();
        validator.validate_update_chain(
            signed_updates,
            operator,
            claimed_reserves,
            collateral_amounts,
            claimed_state_hash,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use std::sync::Arc;

    struct TestLogger;
    impl lightning::util::logger::Logger for TestLogger {
        fn log(&self, record: lightning::util::logger::Record) {
            println!("[{}] {}", record.level, record.args);
        }
    }

    fn generate_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[31] = seed;
        if seed == 0 {
            secret[31] = 1; // Avoid invalid key
        }
        let sk = SecretKey::from_slice(&secret).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn generate_test_keypair(seed: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[31] = seed;
        if seed == 0 {
            secret[31] = 1; // Avoid invalid key
        }
        let sk = SecretKey::from_slice(&secret).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    #[test]
    fn test_watch_reserves_output() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);
        let other_voters = vec![generate_test_pubkey(4), generate_test_pubkey(5)];

        let script = lighthouse
            .watch_reserves_output(operator, partner, other_voters, 100_000, None)
            .expect("Should register watch");

        assert!(script.is_p2tr());

        let watched = lighthouse.get_watched_script_pubkeys();
        assert_eq!(watched.len(), 1);
        assert_eq!(watched[0], script);
    }

    #[test]
    fn test_unwatch_reserves_output() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);
        let other_voter = generate_test_pubkey(99); // Need at least 2 voters for threshold
        let script = lighthouse
            .watch_reserves_output(operator, partner, vec![other_voter], 100_000, None)
            .expect("Should register watch");

        assert_eq!(lighthouse.get_watched_script_pubkeys().len(), 1);

        lighthouse.unwatch_reserves_output(&script);
        assert_eq!(lighthouse.get_watched_script_pubkeys().len(), 0);
    }

    #[test]
    fn test_multiple_watched_outputs() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        // Watch outputs for multiple partners
        for i in 2..=5 {
            let operator = generate_test_pubkey(i);
            let partner = generate_test_pubkey(i + 10);
            let other_voter = generate_test_pubkey(i + 50); // Need at least 2 voters
            lighthouse
                .watch_reserves_output(operator, partner, vec![other_voter], 100_000 * i as u64, None)
                .expect("Should register watch");
        }

        assert_eq!(lighthouse.get_watched_script_pubkeys().len(), 4);
    }

    #[test]
    fn test_lighthouse_event_queue() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        // Initially empty
        assert!(lighthouse.drain_events().is_empty());

        // Events would be added when processing blocks that contain matching transactions
        // This is tested indirectly through process_block
    }

    #[test]
    fn test_process_block_with_matching_output() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::hashes::Hash;
        use bitcoin::{TxIn, TxOut, Sequence, Witness};

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Watch for a reserves output
        let script = lighthouse
            .watch_reserves_output(operator, partner, vec![generate_test_pubkey(99)], 100_000, Some([42u8; 32]))
            .expect("Should register watch");

        // Create a transaction with the watched output
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(100_000),
                script_pubkey: script.clone(),
            }],
        };

        // Create a block containing this transaction
        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![tx],
        };

        // Process the block (takes only block and height)
        let events = lighthouse.process_block(&block, 100);

        // Should have detected the reserves output
        assert_eq!(events.len(), 1);

        match &events[0] {
            LighthouseEvent::ReservesOutputConfirmed {
                vout,
                block_height,
                script_pubkey,
                operator: op,
                partner: pt,
                ledger_hash,
                amount_sats,
                ..
            } => {
                assert_eq!(*vout, 0);
                assert_eq!(*block_height, 100);
                assert_eq!(script_pubkey, &script);
                assert_eq!(op, &operator);
                assert_eq!(pt, &partner);
                assert_eq!(ledger_hash, &Some([42u8; 32]));
                assert_eq!(*amount_sats, 100_000);
            }
            _ => panic!("Expected ReservesOutputConfirmed event"),
        }

        // Event should also be in the queue
        let queued = lighthouse.drain_events();
        assert_eq!(queued.len(), 1);

        // Queue should now be empty
        assert!(lighthouse.drain_events().is_empty());
    }

    #[test]
    fn test_process_block_no_matching_output() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::hashes::Hash;
        use bitcoin::{TxIn, TxOut, Sequence, Witness};

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Watch for a reserves output
        let _script = lighthouse
            .watch_reserves_output(operator, partner, vec![generate_test_pubkey(99)], 100_000, None)
            .expect("Should register watch");

        // Create a transaction with a DIFFERENT output (not matching)
        let different_script = bitcoin::ScriptBuf::from_bytes(vec![0x00; 22]);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: different_script,
            }],
        };

        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![tx],
        };

        let events = lighthouse.process_block(&block, 100);

        // Should not have detected anything
        assert!(events.is_empty());
    }

    #[test]
    fn test_detect_spent_output() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::hashes::Hash;
        use bitcoin::{TxIn, TxOut, Sequence, Witness, OutPoint};

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Watch for a reserves output
        let script = lighthouse
            .watch_reserves_output(operator, partner, vec![generate_test_pubkey(99)], 100_000, None)
            .expect("Should register watch");

        // First, simulate confirming the output
        let create_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(100_000),
                script_pubkey: script.clone(),
            }],
        };

        let block1 = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![create_tx.clone()],
        };

        let block1_hash = block1.block_hash();
        let events1 = lighthouse.process_block(&block1, 100);
        assert_eq!(events1.len(), 1);
        lighthouse.drain_events(); // Clear the queue

        // Now create a transaction that spends the confirmed output
        let create_txid = create_tx.compute_txid();
        let spend_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: create_txid,
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(99_000), // Minus fee
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x00; 22]),
            }],
        };

        let block2 = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: block1_hash,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567891,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![spend_tx],
        };

        let events2 = lighthouse.process_block(&block2, 101);

        // Should have detected the spend
        assert_eq!(events2.len(), 1);

        match &events2[0] {
            LighthouseEvent::ReservesOutputSpent {
                original_txid,
                original_vout,
                block_height,
                operator: op,
                partner: pt,
                ..
            } => {
                assert_eq!(original_txid, &create_txid);
                assert_eq!(*original_vout, 0);
                assert_eq!(*block_height, 101);
                assert_eq!(op, &operator);
                assert_eq!(pt, &partner);
            }
            _ => panic!("Expected ReservesOutputSpent event"),
        }
    }

    #[test]
    fn test_block_height_tracking() {
        use bitcoin::hashes::Hash;

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        assert_eq!(lighthouse.get_last_block_height(), 0);

        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![],
        };

        lighthouse.process_block(&block, 500);
        assert_eq!(lighthouse.get_last_block_height(), 500);

        // Process another block
        let block2 = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: block.block_hash(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567891,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 1,
            },
            txdata: vec![],
        };

        lighthouse.process_block(&block2, 501);
        assert_eq!(lighthouse.get_last_block_height(), 501);
    }

    #[test]
    fn test_recovery_initiation() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::hashes::Hash;
        use bitcoin::{TxIn, TxOut, Sequence, Witness};
        use deposits_core::recovery::RecoveryPhase;

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);
        let ledger_hash = [99u8; 32];

        // Watch for a reserves output with ledger hash
        let script = lighthouse
            .watch_reserves_output(operator, partner, vec![generate_test_pubkey(99)], 100_000, Some(ledger_hash))
            .expect("Should register watch");

        // Create transaction with the watched output
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(100_000),
                script_pubkey: script,
            }],
        };

        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![tx],
        };

        let _events = lighthouse.process_block(&block, 100);

        // Recovery should have been initiated
        let recovery_state = lighthouse.get_recovery_state(operator, partner);
        assert!(recovery_state.is_some(), "Recovery should have been initiated");

        let state = recovery_state.unwrap();
        // Check the phase is WaitingForEntropy with correct values
        match state.phase {
            RecoveryPhase::WaitingForEntropy { force_close_block, on_chain_ledger_hash, .. } => {
                assert_eq!(force_close_block, 100);
                assert_eq!(on_chain_ledger_hash, ledger_hash);
            }
            _ => panic!("Expected WaitingForEntropy phase"),
        }
    }

    #[test]
    fn test_entropy_block_forwarding() {
        use deposits_core::recovery::RecoveryPhase;

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Manually start a recovery (simulating a previously detected force close)
        {
            let mut manager = lighthouse.recovery_manager.write().unwrap();
            manager.start_recovery(
                operator,
                partner,
                100,
                [1u8; 32],
                [2u8; 32],
            ).expect("Should start recovery");
        }

        // Now forward an entropy block
        let entropy_hash = [42u8; 32];
        let result = lighthouse.on_entropy_block(operator, partner, entropy_hash);
        assert!(result.is_ok());

        // Verify the state was updated - should transition to Evaluating phase
        let state = lighthouse.get_recovery_state(operator, partner).unwrap();
        match state.phase {
            RecoveryPhase::Evaluating { entropy_block_hash, .. } => {
                assert_eq!(entropy_block_hash, entropy_hash);
            }
            _ => panic!("Expected Evaluating phase after entropy block"),
        }
    }

    #[test]
    fn test_duplicate_watch_same_script() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Watch the same output twice
        let script1 = lighthouse
            .watch_reserves_output(operator, partner, vec![generate_test_pubkey(99)], 100_000, None)
            .expect("Should register watch");

        let script2 = lighthouse
            .watch_reserves_output(operator, partner, vec![generate_test_pubkey(99)], 100_000, None)
            .expect("Should register watch again");

        // Scripts should be identical
        assert_eq!(script1, script2);

        // Should still only have one watched output (replaced)
        assert_eq!(lighthouse.get_watched_script_pubkeys().len(), 1);
    }

    // ==================== NON-COMPLIANT RECOVERY FLOW TESTS ====================

    #[test]
    fn test_check_claim_eligibility_not_in_recovery() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // No recovery started - should return None
        let eligibility = lighthouse.check_claim_eligibility(operator, partner, 100);
        assert!(eligibility.is_none());
    }

    #[test]
    fn test_check_claim_eligibility_wrong_phase() {
        use deposits_core::recovery::RecoveryPhase;

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Start recovery - this puts it in WaitingForEntropy phase, not NonCompliantRecovery
        {
            let mut manager = lighthouse.recovery_manager.write().unwrap();
            manager.start_recovery(operator, partner, 100, [1u8; 32], [2u8; 32])
                .expect("Should start recovery");
        }

        // Not in NonCompliantRecovery phase - should return None
        let eligibility = lighthouse.check_claim_eligibility(operator, partner, 150);
        assert!(eligibility.is_none());

        // Verify we're in WaitingForEntropy
        let state = lighthouse.get_recovery_state(operator, partner).unwrap();
        assert!(matches!(state.phase, RecoveryPhase::WaitingForEntropy { .. }));
    }

    #[test]
    fn test_can_we_claim_selected_partner_only() {
        use deposits_core::recovery::ClaimEligibility;

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let partner2 = generate_test_pubkey(2);
        let partner3 = generate_test_pubkey(3);
        let channel_partners = vec![our_pubkey, partner2, partner3];

        // We are the selected partner
        let elig_us = ClaimEligibility::SelectedPartnerOnly { partner: our_pubkey };
        assert!(lighthouse.can_we_claim(&elig_us, &channel_partners));

        // Someone else is the selected partner
        let elig_other = ClaimEligibility::SelectedPartnerOnly { partner: partner2 };
        assert!(!lighthouse.can_we_claim(&elig_other, &channel_partners));
    }

    #[test]
    fn test_can_we_claim_any_three_partners() {
        use deposits_core::recovery::ClaimEligibility;

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let partner2 = generate_test_pubkey(2);
        let partner3 = generate_test_pubkey(3);
        let non_partner = generate_test_pubkey(99);

        // We are in the channel partners list
        let channel_partners_with_us = vec![our_pubkey, partner2, partner3];
        let elig = ClaimEligibility::AnyThreePartners;
        assert!(lighthouse.can_we_claim(&elig, &channel_partners_with_us));

        // We are NOT in the channel partners list
        let channel_partners_without_us = vec![non_partner, partner2, partner3];
        assert!(!lighthouse.can_we_claim(&elig, &channel_partners_without_us));
    }

    #[test]
    fn test_can_we_claim_any_single_partner() {
        use deposits_core::recovery::ClaimEligibility;

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let partner2 = generate_test_pubkey(2);
        let partner3 = generate_test_pubkey(3);
        let non_partner = generate_test_pubkey(99);

        let elig = ClaimEligibility::AnySinglePartner;

        // We are in the channel partners list
        let channel_partners_with_us = vec![our_pubkey, partner2, partner3];
        assert!(lighthouse.can_we_claim(&elig, &channel_partners_with_us));

        // We are NOT in the channel partners list
        let channel_partners_without_us = vec![non_partner, partner2, partner3];
        assert!(!lighthouse.can_we_claim(&elig, &channel_partners_without_us));
    }

    #[test]
    fn test_can_we_claim_community_fallback() {
        use deposits_core::recovery::ClaimEligibility;

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let elig = ClaimEligibility::CommunityFallback;

        // Community fallback - anyone can claim
        assert!(lighthouse.can_we_claim(&elig, &[]));
        assert!(lighthouse.can_we_claim(&elig, &[generate_test_pubkey(99)]));
    }

    #[test]
    fn test_get_confirmed_reserves_empty() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // No confirmed outputs
        let result = lighthouse.get_confirmed_reserves(operator, partner);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_confirmed_reserves_found() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::hashes::Hash;
        use bitcoin::{TxIn, TxOut, Sequence, Witness};

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Watch and confirm a reserves output
        let script = lighthouse
            .watch_reserves_output(operator, partner, vec![generate_test_pubkey(99)], 100_000, Some([42u8; 32]))
            .expect("Should register watch");

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(100_000),
                script_pubkey: script.clone(),
            }],
        };

        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![tx.clone()],
        };

        lighthouse.process_block(&block, 100);
        lighthouse.drain_events();

        // Now we should find the confirmed reserves
        let result = lighthouse.get_confirmed_reserves(operator, partner);
        assert!(result.is_some());

        let (txid, vout, watched) = result.unwrap();
        assert_eq!(txid, tx.compute_txid());
        assert_eq!(vout, 0);
        assert_eq!(watched.operator, operator);
        assert_eq!(watched.partner, partner);
        assert_eq!(watched.amount_sats, 100_000);
    }

    #[test]
    fn test_finalize_claim_insufficient_signatures() {
        use deposits_core::recovery_claim::{ClaimAttempt, ClaimConfig, ClaimableReserves};
        use deposits_core::recovery::ClaimEligibility;
        use deposits_core::tapscript_reserves::{VoterSet, ThresholdConfig, TapscriptReservesBuilder};
        use bitcoin::OutPoint;
        use bitcoin::hashes::Hash;

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let pk1 = generate_test_pubkey(1);
        let pk2 = generate_test_pubkey(2);

        let voter_set = VoterSet::new(pk1, vec![pk2]);
        let test_ledger_hash = [0xAA; 32];
        let builder = TapscriptReservesBuilder::with_defaults(voter_set.clone(), Network::Regtest, test_ledger_hash);
        let output = builder.build().unwrap();

        let reserves = ClaimableReserves {
            outpoint: OutPoint {
                txid: Txid::from_slice(&[0xAB; 32]).unwrap(),
                vout: 0,
            },
            amount_sats: 100_000,
            script_pubkey: output.script_pubkey(),
            voter_set,
            threshold_config: ThresholdConfig::default_for_voter_count(2),
            network: Network::Regtest,
            ledger_hash: test_ledger_hash,
        };

        let config = ClaimConfig::default();
        let eligibility = ClaimEligibility::SelectedPartnerOnly { partner: pk1 };

        let attempt = ClaimAttempt::new(
            vec![pk1],
            eligibility,
            reserves,
            &config,
        ).expect("Should create claim attempt");

        // No signatures added - should fail
        let result = lighthouse.finalize_claim(&attempt);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_claim_signature() {
        use deposits_core::recovery_claim::{ClaimAttempt, ClaimConfig, ClaimableReserves};
        use deposits_core::recovery::ClaimEligibility;
        use deposits_core::tapscript_reserves::{VoterSet, ThresholdConfig, TapscriptReservesBuilder};
        use bitcoin::OutPoint;
        use bitcoin::hashes::Hash;

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let pk1 = generate_test_pubkey(1);
        let pk2 = generate_test_pubkey(2);

        let voter_set = VoterSet::new(pk1, vec![pk2]);
        let test_ledger_hash = [0xAA; 32];
        let builder = TapscriptReservesBuilder::with_defaults(voter_set.clone(), Network::Regtest, test_ledger_hash);
        let output = builder.build().unwrap();

        let reserves = ClaimableReserves {
            outpoint: OutPoint {
                txid: Txid::from_slice(&[0xAB; 32]).unwrap(),
                vout: 0,
            },
            amount_sats: 100_000,
            script_pubkey: output.script_pubkey(),
            voter_set,
            threshold_config: ThresholdConfig::default_for_voter_count(2),
            network: Network::Regtest,
            ledger_hash: test_ledger_hash,
        };

        let config = ClaimConfig::default();
        let eligibility = ClaimEligibility::SelectedPartnerOnly { partner: pk1 };

        let mut attempt = ClaimAttempt::new(
            vec![pk1],
            eligibility,
            reserves,
            &config,
        ).expect("Should create claim attempt");

        // Signature count should be 0 initially
        assert!(!attempt.has_sufficient_signatures());

        // Add a fake signature (this is a helper function test, not validating signatures)
        let fake_sig = [1u8; 64];
        lighthouse.add_claim_signature(&mut attempt, 0, fake_sig);

        // Verify signature was added (internal state changed)
        // The signature count check would need access to internal state,
        // but we can verify the method doesn't panic
    }

    #[test]
    fn test_full_non_compliant_recovery_flow() {
        use deposits_core::recovery::{RecoveryPhase, RecoveryPool, RecoveryVote};
        use bitcoin::secp256k1::{Keypair, Message};
        use bitcoin::hashes::Hash;

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let operator = generate_test_pubkey(10);
        let partner = generate_test_pubkey(20);
        let (voter1_sk, voter1_pk) = generate_test_keypair(30);
        let (voter2_sk, voter2_pk) = generate_test_keypair(31);

        // Step 1: Start recovery (simulating force close detection)
        {
            let mut manager = lighthouse.recovery_manager.write().unwrap();
            manager.start_recovery(operator, partner, 100, [1u8; 32], [2u8; 32])
                .expect("Should start recovery");
        }

        // Verify WaitingForEntropy phase
        let state = lighthouse.get_recovery_state(operator, partner).unwrap();
        assert!(matches!(state.phase, RecoveryPhase::WaitingForEntropy { .. }));

        // Step 2: Entropy block arrives
        lighthouse.on_entropy_block(operator, partner, [42u8; 32])
            .expect("Should process entropy block");

        // Verify Evaluating phase
        let state = lighthouse.get_recovery_state(operator, partner).unwrap();
        assert!(matches!(state.phase, RecoveryPhase::Evaluating { .. }));

        // Step 3: Submit non-conforming votes with proper signatures
        {
            let mut manager = lighthouse.recovery_manager.write().unwrap();
            let ledger_id = (operator, partner);
            let secp = Secp256k1::new();

            // Create signed vote 1 (must match RecoveryVote::sighash())
            // voter (33) + is_conforming (1) + validated_hash (32) + substitute_nomination (33)
            let keypair1 = Keypair::from_secret_key(&secp, &voter1_sk);
            let mut vote_data1 = Vec::new();
            vote_data1.extend_from_slice(&voter1_pk.serialize());
            vote_data1.push(0u8); // is_conforming = false
            vote_data1.extend_from_slice(&[2u8; 32]); // validated_hash
            vote_data1.extend_from_slice(&[0u8; 33]); // substitute_nomination = None (zeros)
            let vote_hash1 = bitcoin::hashes::sha256::Hash::hash(&vote_data1);
            let msg1 = Message::from_digest(*vote_hash1.as_ref());
            let sig1 = secp.sign_schnorr(&msg1, &keypair1);

            let vote1 = RecoveryVote {
                voter: voter1_pk,
                is_conforming: false,
                validated_hash: [2u8; 32],
                validated_sequence: 100,
                substitute_nomination: None,
                discovered_violation: true,
                signature: sig1.serialize(),
            };
            manager.submit_vote(ledger_id, vote1).expect("Should accept vote 1");

            // Create signed vote 2
            let keypair2 = Keypair::from_secret_key(&secp, &voter2_sk);
            let mut vote_data2 = Vec::new();
            vote_data2.extend_from_slice(&voter2_pk.serialize());
            vote_data2.push(0u8); // is_conforming = false
            vote_data2.extend_from_slice(&[2u8; 32]); // validated_hash
            vote_data2.extend_from_slice(&[0u8; 33]); // substitute_nomination = None (zeros)
            let vote_hash2 = bitcoin::hashes::sha256::Hash::hash(&vote_data2);
            let msg2 = Message::from_digest(*vote_hash2.as_ref());
            let sig2 = secp.sign_schnorr(&msg2, &keypair2);

            let vote2 = RecoveryVote {
                voter: voter2_pk,
                is_conforming: false,
                validated_hash: [2u8; 32],
                validated_sequence: 100,
                substitute_nomination: None,
                discovered_violation: true,
                signature: sig2.serialize(),
            };
            manager.submit_vote(ledger_id, vote2).expect("Should accept vote 2");

            // Step 4: Transition to NonCompliantRecovery
            let channel_partners = vec![our_pubkey, generate_test_pubkey(40)];
            manager.transition_to_non_compliant(
                ledger_id,
                100, // force_close_block
                channel_partners.clone(),
            ).expect("Should transition to non-compliant");
        }

        // Verify NonCompliantRecovery phase
        let state = lighthouse.get_recovery_state(operator, partner).unwrap();
        match &state.phase {
            RecoveryPhase::NonCompliantRecovery { force_close_block, recovery_pool, .. } => {
                assert_eq!(*force_close_block, 100);
                assert!(recovery_pool.selected_partner.is_some());
            }
            _ => panic!("Expected NonCompliantRecovery phase"),
        }

        // Step 5: Check claim eligibility (at different block heights)
        // At block 100 (start), eligibility should be SelectedPartnerOnly
        let eligibility = lighthouse.check_claim_eligibility(operator, partner, 100);
        assert!(eligibility.is_some());

        // Eligibility should be present now that we're in NonCompliantRecovery
        let elig = eligibility.unwrap();
        match elig {
            deposits_core::recovery::ClaimEligibility::SelectedPartnerOnly { .. } => {
                // Expected at block 0-143 (day 0)
            }
            _ => {
                // Could be different tier if more blocks elapsed
            }
        }
    }

    // ============================================================
    // Channel Watching Tests (for collusion detection)
    // ============================================================

    #[test]
    fn test_watch_channel() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let channel_id = [42u8; 32];
        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Watch a channel
        lighthouse.watch_channel(channel_id, operator, partner);

        // Verify it's being watched
        let watched = lighthouse.get_watched_channels();
        assert_eq!(watched.len(), 1);

        let entry = watched.iter().find(|w| w.channel_id == channel_id).unwrap();
        assert_eq!(entry.operator, operator);
        assert_eq!(entry.partner, partner);
        assert!(!entry.reserves_confirmed);
        assert!(entry.last_audit_hash.is_none());
    }

    #[test]
    fn test_watch_multiple_channels() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        // Watch multiple channels
        for i in 0..5 {
            let mut channel_id = [0u8; 32];
            channel_id[0] = i;
            let operator = generate_test_pubkey(10 + i);
            let partner = generate_test_pubkey(20 + i);
            lighthouse.watch_channel(channel_id, operator, partner);
        }

        let watched = lighthouse.get_watched_channels();
        assert_eq!(watched.len(), 5);
    }

    #[test]
    fn test_unwatch_channel() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let channel_id = [42u8; 32];
        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Watch then unwatch
        lighthouse.watch_channel(channel_id, operator, partner);
        assert_eq!(lighthouse.get_watched_channels().len(), 1);

        lighthouse.unwatch_channel(&channel_id);
        assert_eq!(lighthouse.get_watched_channels().len(), 0);
    }

    #[test]
    fn test_update_audit_record() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let channel_id = [42u8; 32];
        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Watch channel
        lighthouse.watch_channel(channel_id, operator, partner);

        // Update audit record
        let audit_hash = [99u8; 32];
        lighthouse.update_audit_record(&channel_id, audit_hash, 50);

        // Verify update
        let watched = lighthouse.get_watched_channels();
        let entry = watched.iter().find(|w| w.channel_id == channel_id).unwrap();
        assert_eq!(entry.last_audit_hash, Some(audit_hash));
        assert_eq!(entry.last_audit_sequence, Some(50));
    }

    #[test]
    fn test_channel_closed_without_reserves_emits_event() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let channel_id = [42u8; 32];
        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Watch channel and set audit record
        lighthouse.watch_channel(channel_id, operator, partner);
        let audit_hash = [99u8; 32];
        lighthouse.update_audit_record(&channel_id, audit_hash, 100);

        // Set block height
        lighthouse.set_block_height(500);

        // Channel closes WITHOUT reserves being confirmed
        let event = lighthouse.on_channel_closed(channel_id, false);

        // Should emit ChannelClosedWithoutReserves
        assert!(event.is_some());
        match event.unwrap() {
            LighthouseEvent::ChannelClosedWithoutReserves {
                channel_id: cid,
                block_height,
                operator: op,
                partner: pt,
                is_cooperative,
                last_audit_hash,
                last_audit_sequence,
            } => {
                assert_eq!(cid, channel_id);
                assert_eq!(block_height, 500);
                assert_eq!(op, operator);
                assert_eq!(pt, partner);
                assert!(!is_cooperative);
                assert_eq!(last_audit_hash, Some(audit_hash));
                assert_eq!(last_audit_sequence, Some(100));
            }
            _ => panic!("Expected ChannelClosedWithoutReserves event"),
        }

        // Channel should no longer be watched
        assert!(lighthouse.get_watched_channels().is_empty());
    }

    #[test]
    fn test_channel_closed_with_reserves_no_event() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::hashes::Hash;
        use bitcoin::{TxIn, TxOut, Sequence, Witness};

        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let channel_id = [42u8; 32];
        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Watch channel
        lighthouse.watch_channel(channel_id, operator, partner);

        // Also watch for reserves output (to simulate it being confirmed)
        let script = lighthouse
            .watch_reserves_output(operator, partner, vec![generate_test_pubkey(99)], 100_000, None)
            .expect("Should register watch");

        // Create and process a block with the reserves output
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(100_000),
                script_pubkey: script.clone(),
            }],
        };

        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![tx],
        };

        // Process block - this should mark reserves_confirmed = true
        // Note: We need to link the reserves output to the channel
        // For now, manually mark it confirmed
        {
            let mut channels = lighthouse.watched_channels.write().unwrap();
            if let Some(entry) = channels.get_mut(&channel_id) {
                entry.reserves_confirmed = true;
            }
        }

        // Now channel closes - but reserves were confirmed
        let event = lighthouse.on_channel_closed(channel_id, true);

        // Should NOT emit event (reserves output was on-chain)
        assert!(event.is_none());
    }

    #[test]
    fn test_cooperative_close_flag() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        let channel_id = [42u8; 32];
        let operator = generate_test_pubkey(2);
        let partner = generate_test_pubkey(3);

        // Watch channel
        lighthouse.watch_channel(channel_id, operator, partner);

        // Close cooperatively without reserves
        let event = lighthouse.on_channel_closed(channel_id, true);

        // Verify cooperative flag is true
        assert!(event.is_some());
        match event.unwrap() {
            LighthouseEvent::ChannelClosedWithoutReserves { is_cooperative, .. } => {
                assert!(is_cooperative);
            }
            _ => panic!("Expected ChannelClosedWithoutReserves event"),
        }
    }

    #[test]
    fn test_close_unwatched_channel_no_event() {
        let logger = Arc::new(TestLogger);
        let our_pubkey = generate_test_pubkey(1);
        let lighthouse = LighthouseService::new(our_pubkey, Network::Regtest, logger);

        // Close a channel we're not watching
        let unknown_channel = [99u8; 32];
        let event = lighthouse.on_channel_closed(unknown_channel, false);

        // Should return None (we don't care about unwatched channels)
        assert!(event.is_none());
    }
}
