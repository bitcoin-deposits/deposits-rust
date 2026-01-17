// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Reserves commitment operations for the Bitcoin Deposits protocol.
//!
//! This module contains operations for managing reserves commitment to Lightning channels,
//! including syncing ledger hashes to commitment transactions.

use bitcoin::secp256k1::PublicKey;

use super::core::{build_taproot_reserves_script, DepositsHandler};
use deposits_core::DepositsError;
use super::ledger_ext::LedgerExt;
use deposits_core::VoterSet;
use lightning::{log_debug, log_error, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// This is called after any ledger update to keep the commitment transaction in sync with ledger state
    /// Uses the partner_deepest_ack_hash (most recently ACKed state) to ensure we only commit agreed-upon state
    ///
    /// IMPORTANT: Only the OPERATOR should send UpdateReserves. Partners should never originate
    /// UpdateReserves messages - they only respond with AcceptReserves when they receive one.
    pub(super) fn refresh_reserves_commitment(&self, partner_node_id: PublicKey) -> Result<(), DepositsError> {
        // Get the ledger hash, reserves amount, voter set, and key for later update
        // ONLY consider ledgers where we are the OPERATOR (key1)
        // Partners should NOT send UpdateReserves - only operators do
        // Also get the remote ledger hash (partner's operator ledger, where we are the partner)
        let (holder_ledger_hash, holder_ledger_key, reserves_amount, needs_update, remote_ledger_hash, voter_set) = {
            let ledgers = self.ledgers.lock().unwrap();

            // Only check for ledger where WE are the operator
            let operator_key = (self.our_node_id, partner_node_id);

            if let Some(ledger_arc) = ledgers.get(&operator_key) {
                let ledger = ledger_arc.read().unwrap();
                // Use partner_deepest_ack_hash - only commit state that partner has ACKed
                // This ensures we don't commit un-acked state to the channel
                let acked_hash = ledger.state.partner_deepest_ack_hash;
                let commit_hash = ledger.state.channel_deepest_commitment_hash;
                let needs_update = acked_hash != commit_hash && acked_hash != [0u8; 32];
                println!(
                    "[COMMIT] partner={} acked={:02x?} committed={:02x?} needs_update={} reserves={}",
                    partner_node_id,
                    &acked_hash[0..8],
                    &commit_hash[0..8],
                    needs_update,
                    ledger.reserves_amount()
                );
                // Get the actual reserves amount from the ledger
                let reserves = ledger.reserves_amount();
                // Construct the VoterSet from the ledger state
                let voter_set = ledger.construct_voter_set();

                // Also look up partner's operator ledger (where partner is operator, we are partner)
                // This gives us our view of their ledger hash for bidirectional verification
                let partner_operator_key = (partner_node_id, self.our_node_id);
                let remote_hash = if let Some(partner_ledger_arc) = ledgers.get(&partner_operator_key) {
                    let partner_ledger = partner_ledger_arc.read().unwrap();
                    // Use tail_hash() - the current state of their ledger
                    partner_ledger.tail_hash()
                } else {
                    // No partner operator ledger yet - use zero hash
                    [0u8; 32]
                };

                (acked_hash, Some(operator_key), reserves, needs_update, remote_hash, voter_set)
            } else {
                // No ledger where we're the operator - we're either the partner or have no ledger
                // Partners should NOT send UpdateReserves, so return early
                log_debug!(
                    self.logger,
                    "No operator ledger found for {}, skipping UpdateReserves (we may be the partner)",
                    partner_node_id
                );
                return Ok(());
            }
        };

        // Only send UpdateReserves if there's new ACKed state to commit
        // This implements one-commitment-per-update: each ACKed ledger update triggers exactly one commitment
        if !needs_update {
            println!(
                "[COMMIT] no update needed for {} ack={:02x?}",
                partner_node_id,
                &holder_ledger_hash[0..4]
            );
            return Ok(());
        }

        println!(
            "[COMMIT] update needed for {} ack={:02x?}",
            partner_node_id,
            &holder_ledger_hash[0..4]
        );

        // Find the channel with this partner
        if let Some(ref cm) = self.channel_manager {
            let channels = cm.list_channels_with_counterparty(&partner_node_id);
            if let Some(channel) = channels.first() {
                // Use actual reserves amount from ledger (minimum 330 sats for dust limit)
                let reserves_sats = std::cmp::max(reserves_amount, 330);

                // Build Taproot reserves script (P2TR) with ledger hash committed
                // Uses VoterSet from ledger state (partner as tie-breaker, collateral_partners as other voters)
                let script_pubkey = build_taproot_reserves_script(
                    voter_set,
                    holder_ledger_hash,
                    self.network,
                )?;

                log_info!(
                    self.logger,
                    "🔄 Sending UpdateReserves to {} with ACKed hash {:02x?} (one commitment per ACKed update)",
                    partner_node_id,
                    &holder_ledger_hash[0..8]
                );

                // Update commitment transaction with ACKed ledger hash (not tail_hash)
                // This ensures both parties commit the same state (the most recently ACKed update)
                // Include remote_ledger_hash for bidirectional verification
                println!(
                    "[COMMIT] calling send_update_reserves for {} hash={:02x?}",
                    partner_node_id,
                    &holder_ledger_hash[0..4]
                );
                cm.send_update_reserves(
                    &partner_node_id,
                    &channel.channel_id,
                    reserves_sats,
                    script_pubkey,
                    holder_ledger_hash,
                    remote_ledger_hash,
                ).map_err(|e| {
                    // Log the error - Ignore errors mean a pending UpdateReserves exists
                    // The commitment will be refreshed when the pending one completes
                    println!(
                        "[COMMIT] send_update_reserves FAILED for {}: {:?}",
                        partner_node_id,
                        e
                    );
                    DepositsError::InvalidChannelState
                })?;
                println!(
                    "[COMMIT] send_update_reserves OK for {}",
                    partner_node_id
                );

                // Update channel_deepest_commitment_hash AFTER sending UpdateReserves succeeds
                // This ensures we only record the hash after the send was actually accepted
                // (If send_update_reserves returns Ignore because one is pending, we don't update)
                if let Some(ledger_key) = holder_ledger_key {
                    let ledgers = self.ledgers.lock().unwrap();
                    if let Some(ledger_arc) = ledgers.get(&ledger_key) {
                        let mut ledger = ledger_arc.write().unwrap();
                        ledger.state.channel_deepest_commitment_hash = holder_ledger_hash;
                        log_info!(
                            self.logger,
                            "✅ Updated channel_deepest_commitment_hash to {:02x?} AFTER UpdateReserves sent",
                            &holder_ledger_hash[0..8]
                        );
                        // Persist the updated commitment hash
                        self.persist_ledger_state(&ledger)?;
                    }
                }

                log_debug!(
                    self.logger,
                    "Refreshed reserves commitment with {} (holder_hash: {:02x?})",
                    partner_node_id,
                    &holder_ledger_hash[0..8]
                );
            } else {
                log_error!(
                    self.logger,
                    "No channel found with {} during reserves refresh",
                    partner_node_id
                );
                return Err(DepositsError::InvalidChannelState);
            }
        } else {
            log_error!(self.logger, "Channel manager not available for reserves refresh");
            return Err(DepositsError::InvalidChannelState);
        }

        Ok(())
    }

    /// Strategy-aware reserves commitment refresh.
    ///
    /// This function checks the HashStrategy for the given message type and only
    /// triggers an UpdateReserves if the operation requires synchronization.
    ///
    /// Hash strategies:
    /// - CurrentCommitted: Amount-changing ops (ReservesAdd, ReservesToReserves, etc.)
    ///   Sync AFTER the operation is applied, using the current ledger hash.
    /// - PredictedAfterOp: ReceivingCreditPayment only.
    ///   Sync BEFORE the operation, with predicted hash. (Handled separately via
    ///   commit_specific_hash_to_channel, not this function.)
    /// - None: All other operations. No sync needed, hash catches up lazily.
    ///
    /// Returns Ok(()) without sending UpdateReserves if the strategy is None.
    fn maybe_refresh_reserves_commitment(
        &self,
        partner_node_id: PublicKey,
        message_type: u16,
    ) -> Result<(), DepositsError> {
        use crate::types::HashStrategy;

        let (needs_sync, strategy) = HashStrategy::for_message_type(message_type);

        if !needs_sync || strategy == HashStrategy::None {
            log_debug!(
                self.logger,
                "📝 HASH_STRATEGY: Skipping reserves sync for message type {} (strategy: {:?})",
                message_type,
                strategy
            );
            return Ok(());
        }

        if strategy == HashStrategy::PredictedAfterOp {
            // PredictedAfterOp should use commit_specific_hash_to_channel, not this function
            log_debug!(
                self.logger,
                "📝 HASH_STRATEGY: PredictedAfterOp for message type {} - caller should use commit_specific_hash_to_channel",
                message_type
            );
            return Ok(());
        }

        // HashStrategy::CurrentCommitted - sync with current ledger hash
        log_info!(
            self.logger,
            "📝 HASH_STRATEGY: Syncing reserves for message type {} (CurrentCommitted)",
            message_type
        );
        self.refresh_reserves_commitment(partner_node_id)
    }

    /// Commit a specific ledger hash to the channel commitment transaction.
    ///
    /// This is used for the "predict-then-commit-then-record" pattern where we need to:
    /// 1. Predict what the hash will be after an operation
    /// 2. Commit that hash to the channel BEFORE recording to the ledger
    /// 3. Wait for commitment to complete
    /// 4. Then record the operation to the ledger
    ///
    /// This ensures the commitment always has the correct hash, preventing race conditions
    /// where the ledger is updated but commitment hasn't caught up yet.
    pub(super) fn commit_specific_hash_to_channel(
        &self,
        partner_node_id: PublicKey,
        ledger_hash: [u8; 32],
        reserves_amount: u64,
        voter_set: VoterSet,
    ) -> Result<(), DepositsError> {
        // Get remote ledger hash for bidirectional verification
        let remote_ledger_hash = {
            let ledgers = self.ledgers.lock().unwrap();
            let partner_operator_key = (partner_node_id, self.our_node_id);
            if let Some(partner_ledger_arc) = ledgers.get(&partner_operator_key) {
                let partner_ledger = partner_ledger_arc.read().unwrap();
                partner_ledger.tail_hash()
            } else {
                [0u8; 32]
            }
        };

        if let Some(ref cm) = self.channel_manager {
            let channels = cm.list_channels_with_counterparty(&partner_node_id);
            if let Some(channel) = channels.first() {
                let reserves_sats = std::cmp::max(reserves_amount, 330);

                let script_pubkey = build_taproot_reserves_script(
                    voter_set,
                    ledger_hash,
                    self.network,
                )?;

                log_info!(
                    self.logger,
                    "🔄 PREDICT-COMMIT: Sending UpdateReserves to {} with PREDICTED hash {:02x?}",
                    partner_node_id,
                    &ledger_hash[0..8]
                );

                cm.send_update_reserves(
                    &partner_node_id,
                    &channel.channel_id,
                    reserves_sats,
                    script_pubkey,
                    ledger_hash,
                    remote_ledger_hash,
                ).map_err(|e| {
                    println!(
                        "[PREDICT-COMMIT] send_update_reserves FAILED for {}: {:?}",
                        partner_node_id, e
                    );
                    DepositsError::InvalidChannelState
                })?;

                println!(
                    "[PREDICT-COMMIT] send_update_reserves OK for {} hash={:02x?}",
                    partner_node_id, &ledger_hash[0..4]
                );

                Ok(())
            } else {
                log_error!(self.logger, "No channel found with {} for predicted commit", partner_node_id);
                Err(DepositsError::InvalidChannelState)
            }
        } else {
            log_error!(self.logger, "Channel manager not available for predicted commit");
            Err(DepositsError::InvalidChannelState)
        }
    }
}
