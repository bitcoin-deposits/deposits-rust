// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Background maintenance operations for the Bitcoin Deposits protocol.
//!
//! This module contains operations for periodically flushing stale updates,
//! cleaning up pending ACKs, retrying failed broadcasts, and managing
//! lazy sync for commitment updates.

use bitcoin::secp256k1::PublicKey;
use std::sync::Arc;

use super::core::{DepositsHandler, STALE_ACK_THRESHOLD_SECS, LAZY_SYNC_DELAY_SECS};
use deposits_core::{log_debug, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Flush stale updates to prevent chronic staleness
    ///
    /// This method:
    /// 1. Cleans up stale pending ACK entries (fire-and-forget doesn't wait for ACKs)
    /// 2. Retries broadcasts for messages stuck in sent_messages_for_broadcast
    /// 3. Triggers commits for ledgers with ACK'd state that hasn't been committed yet
    ///    (this ensures fire-and-forget operations like SendingLockPayment get committed)
    ///
    /// Should be called periodically (e.g., every 1 second) by a background task
    pub fn flush_stale_updates(&self) -> (usize, usize) {
        let now = deposits_core::time_utils::now_unix_timestamp();
        #[allow(unused_variables)]
        let mut stale_acks_cleared = 0;
        let mut broadcasts_retried = 0;

        // 1. Clean up stale pending ACKs
        // With fire-and-forget, we don't wait for ACKs, so old entries can be cleaned
        {
            let mut pending_acks = self.pending_acks.lock().unwrap();
            let initial_count = pending_acks.len();

            pending_acks.retain(|hash, ack| {
                let age_secs = now.saturating_sub(ack.timestamp);
                if age_secs > STALE_ACK_THRESHOLD_SECS {
                    log_debug!(
                        self.logger,
                        "🧹 Clearing stale pending ACK: hash={:02x?}, type={:#06x}, age={}s",
                        &hash[0..4], ack.message_type, age_secs
                    );
                    false // Remove
                } else {
                    true // Keep
                }
            });

            stale_acks_cleared = initial_count - pending_acks.len();
        }

        // 2. Retry stale broadcasts
        // Messages in sent_messages_for_broadcast that haven't been processed
        // This can happen if the initial broadcast attempt failed
        let stale_broadcasts: Vec<([u8; 32], PublicKey)> = {
            let sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.iter()
                .filter_map(|(hash, (_op, partner, _msg, _prev, _new, _idx))| {
                    // We don't have timestamps on these entries, so just retry all
                    // In practice, they should be processed quickly
                    Some((*hash, *partner))
                })
                .collect()
        };

        for (message_hash, partner_id) in stale_broadcasts {
            log_debug!(
                self.logger,
                "🔄 Retrying broadcast for hash {:02x?} to partner {}",
                &message_hash[0..4], partner_id
            );

            if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_id, None) {
                log_debug!(
                    self.logger,
                    "⚠️ Retry broadcast failed for {:02x?}: {}",
                    &message_hash[0..4], e
                );
            } else {
                broadcasts_retried += 1;
            }
        }

        // 3. Lazy sync: Commit ledgers with uncommitted ACKed updates after quiet period
        // This coalesces rapid updates into a single commitment.
        // Only triggers after LAZY_SYNC_DELAY_SECS of no new operations.
        let mut lazy_syncs_triggered = 0;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let partners_ready_for_lazy_sync: Vec<PublicKey> = {
            let pending_lazy_syncs = self.pending_lazy_syncs.lock().unwrap();
            pending_lazy_syncs.iter()
                .filter_map(|(partner_id, requested_at)| {
                    // Only sync if enough quiet time has passed
                    if now >= requested_at + LAZY_SYNC_DELAY_SECS {
                        Some(*partner_id)
                    } else {
                        None
                    }
                })
                .collect()
        };

        for partner_id in partners_ready_for_lazy_sync {
            // Check if there's actually uncommitted state
            let needs_commit = {
                let ledgers = self.ledgers.lock().unwrap();
                if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_id)) {
                    let ledger = ledger_arc.read().unwrap();
                    let acked_hash = ledger.state.partner_deepest_ack_hash;
                    let commit_hash = ledger.state.channel_deepest_commitment_hash;
                    acked_hash != commit_hash && acked_hash != [0u8; 32]
                } else {
                    false
                }
            };

            if needs_commit {
                if self.refresh_reserves_commitment(partner_id).is_ok() {
                    lazy_syncs_triggered += 1;
                }
            }

            // Remove from pending regardless of outcome
            {
                let mut pending_lazy_syncs = self.pending_lazy_syncs.lock().unwrap();
                pending_lazy_syncs.remove(&partner_id);
            }
        }

        if stale_acks_cleared > 0 || broadcasts_retried > 0 || lazy_syncs_triggered > 0 {
            log_debug!(
                self.logger,
                "🧹 Flush complete: cleared {} stale ACKs, retried {} broadcasts, {} lazy syncs",
                stale_acks_cleared, broadcasts_retried, lazy_syncs_triggered
            );
        }

        (stale_acks_cleared, broadcasts_retried)
    }

    /// Mark a ledger for lazy sync after receiving an ACK
    /// This will trigger a commit after LAZY_SYNC_DELAY_SECS of quiet
    pub(super) fn mark_for_lazy_sync(&self, partner_id: PublicKey) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut pending_lazy_syncs = self.pending_lazy_syncs.lock().unwrap();
        // Reset the timer - this coalesces rapid updates
        pending_lazy_syncs.insert(partner_id, now);
    }

    /// Cancel a pending lazy sync (called when immediate sync happens)
    pub(super) fn cancel_lazy_sync(&self, partner_id: PublicKey) {
        let mut pending_lazy_syncs = self.pending_lazy_syncs.lock().unwrap();
        pending_lazy_syncs.remove(&partner_id);
    }

    /// Start a background task that periodically flushes stale updates
    ///
    /// This spawns a tokio task that runs every second to:
    /// - Clean up stale pending ACKs
    /// - Retry failed broadcasts
    /// - Lazy sync: Commit uncommitted ACKed updates after quiet period
    ///
    /// With HashStrategy, commitment sync is driven by operation type:
    /// - Amount-changing ops sync immediately after applying
    /// - ReceivingCreditPayment uses predict-then-commit
    /// - All other ops mark for lazy sync (commits after LAZY_SYNC_DELAY_SECS)
    ///
    /// The handler must be wrapped in an Arc for this to work.
    /// Returns a handle that can be used to abort the task.
    ///
    /// Example usage:
    /// ```ignore
    /// let handler = Arc::new(DepositsHandler::new(...)?);
    /// let flush_handle = DepositsHandler::start_background_flush_arc(Arc::clone(&handler));
    /// // Later: flush_handle.abort() to stop
    /// ```
    pub fn start_background_flush_arc(handler: Arc<Self>) -> tokio::task::JoinHandle<()>
    where
        L: Send + Sync + 'static,
    {
        use std::time::Duration;

        let _logger = handler.logger.clone();
        log_info!(_logger, "📋 Starting background flush task (1s interval)");

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                interval.tick().await;
                let (acks_cleared, broadcasts_retried) = handler.flush_stale_updates();

                // Only log if something happened
                if acks_cleared > 0 || broadcasts_retried > 0 {
                    log_debug!(
                        handler.logger,
                        "🧹 Background flush: {} ACKs cleared, {} broadcasts retried",
                        acks_cleared, broadcasts_retried
                    );
                }
            }
        })
    }
}
