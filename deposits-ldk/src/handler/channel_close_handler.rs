// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Channel close handler for the Bitcoin Deposits protocol.
//!
//! This module contains handlers for channel close operations,
//! extracted from core.rs to improve maintainability.

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use super::ledger_ext::LedgerExt;
use deposits_core::{log_debug, log_error, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Handle channel closure - broadcast tombstone and mark ledger as closed
    /// This prevents sequence number mismatches when channels reopen
    pub fn handle_channel_closed(&self, channel_id: [u8; 32], partner_node_id: PublicKey) {
        log_info!(
            self.logger,
            "₿ Bitcoin Deposits: Channel {} closed with partner {} - broadcasting tombstone",
            crate::hex_utils::to_string(&channel_id),
            partner_node_id
        );

        // Check if we have a ledger with this partner
        let has_ledger = {
            let ledgers = self.ledgers.lock().unwrap();
            let ledger_key_1 = (self.our_node_id, partner_node_id);
            let ledger_key_2 = (partner_node_id, self.our_node_id);
            ledgers.contains_key(&ledger_key_1) || ledgers.contains_key(&ledger_key_2)
        };

        if !has_ledger {
            log_debug!(
                self.logger,
                "₿ No Bitcoin Deposits ledger found for partner {} - no tombstone needed",
                partner_node_id
            );
            return;
        }

        // Get sequence number and create/append tombstone while holding ledger lock
        // Then broadcast after releasing the lock
        let mut ledgers = self.ledgers.lock().unwrap();
        let ledger_key = (self.our_node_id, partner_node_id);

        let Some(ledger_arc) = ledgers.get_mut(&ledger_key) else {
            log_error!(self.logger, "Ledger disappeared between check and append");
            return;
        };

        let mut ledger_guard = ledger_arc.write().unwrap();

        // Get prev_hash BEFORE appending
        let prev_hash = ledger_guard.tail_hash();

        // Note: sequence number will be computed by the ledger append

        // Create Tombstone message via V2 LedgerUpdate
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let tombstone = super::messages::DepositsMessage::new_tombstone(
            self.our_node_id,
            partner_node_id,
            channel_id,
            Some("Channel force-closed".to_string()),
            timestamp,
        );
        let message_hash = self.calculate_message_hash(&tombstone);

        // Extract values before mem::replace
        let operator_node_id = ledger_guard.operator_key();
        let partner_node_id_inner = ledger_guard.partner_key();
        let our_role = ledger_guard.role;
        let collateral_partners = ledger_guard.state.collateral_partners.clone();
        let ledger_address = ledger_guard.state.ledger_address.clone();

        // Take ownership of the ledger
        let ledger_owned = std::mem::replace(
            &mut *ledger_guard,
            deposits_core::Ledger::new(
                operator_node_id,
                partner_node_id_inner,
                our_role,
                collateral_partners,
                ledger_address.clone(),
            )
        );

        match ledger_owned.append(tombstone.clone()) {
            Ok((updated_ledger, new_hash)) => {
                *ledger_guard = updated_ledger;
                // Get sequence number from updated ledger (0-indexed, so len-1)
                let sequence_number = ledger_guard.history.len().saturating_sub(1) as u64;
                log_info!(
                    self.logger,
                    "✅ Tombstone appended to local ledger. Ledger is now closed."
                );

                // Update sent_messages_for_broadcast with correct new_hash and sequence
                // so audit broadcasts can proceed
                println!("🟣 UPDATE SENT_MESSAGES (tombstone): hash={:02x?}, type={:#06x}, prev_hash={:02x?}, new_hash={:02x?}, seq={}",
                    &message_hash[0..4], tombstone.message_type(), &prev_hash[0..8], &new_hash[0..8], sequence_number);
                {
                    let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                    sent_messages.insert(message_hash, (self.our_node_id, partner_node_id, tombstone.clone(), prev_hash, new_hash, sequence_number));
                }

                // Release locks before broadcast
                drop(ledger_guard);
                drop(ledgers);

                // Send tombstone to partner
                if let Err(e) = self.send_message(partner_node_id, tombstone.clone()) {
                    log_error!(
                        self.logger,
                        "Failed to send ChannelCloseTombstone to partner {}: {:?}",
                        partner_node_id, e
                    );
                } else {
                    log_info!(
                        self.logger,
                        "✅ Successfully sent ChannelCloseTombstone to partner {}",
                        partner_node_id
                    );
                }

                // Broadcast SignedAuditUpdate to all partners/auditors
                if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, None) {
                    log_error!(self.logger, "Failed to broadcast ChannelCloseTombstone: {:?}", e);
                }

                log_info!(
                    self.logger,
                    "₿ Channel {} with partner {} marked as closed via tombstone broadcast",
                    crate::hex_utils::to_string(&channel_id),
                    partner_node_id
                );
            }
            Err(e) => {
                log_error!(
                    self.logger,
                    "Failed to append tombstone to local ledger: {:?}",
                    e
                );
            }
        }
    }
}
