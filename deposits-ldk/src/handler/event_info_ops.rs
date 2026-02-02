// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Event generation and protocol info operations for the Bitcoin Deposits protocol.
//!
//! This module contains operations for:
//! - Generating protocol events from messages
//! - Checking peer protocol support
//! - Listing active partners
//! - Protocol statistics
//! - Ledger private key management

use bitcoin::secp256k1::PublicKey;
use lightning_types::features::InitFeatures;

use super::core::{DepositsHandler, ProtocolStats};
use super::messages::{DepositsMessage, LedgerOperation};
use super::DepositsEvent;
use deposits_core::{log_debug, log_warn};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

/// Generate event from a LedgerOperation (V2 only)
fn event_from_operation(operation: &LedgerOperation) -> Option<DepositsEvent> {
    match operation {
        LedgerOperation::DepositOpen { pubkey, .. } => {
            Some(DepositsEvent::DepositAdded {
                pubkey: *pubkey,
            })
        }
        LedgerOperation::DepositClose { pubkey } => {
            Some(DepositsEvent::DepositRemoved {
                pubkey: *pubkey,
            })
        }
        LedgerOperation::ReservesIncrease { new_amount, .. } => {
            Some(DepositsEvent::ReservesIncreased {
                amount: *new_amount,
            })
        }
        LedgerOperation::InvoiceCredit { deposit_pubkey, amount, .. } => {
            Some(DepositsEvent::InvoiceCredited {
                deposit_pubkey: *deposit_pubkey,
                amount: *amount,
            })
        }
        LedgerOperation::InvoiceFulfill { pubkey, amount, .. } => {
            Some(DepositsEvent::PaymentDebited {
                deposit_pubkey: *pubkey,
                amount: *amount,
            })
        }
        _ => None,
    }
}

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Generate appropriate events based on message type
    /// Uses to_operation() to extract LedgerOperation from LedgerUpdate messages
    pub(super) fn generate_protocol_event(
        &self,
        message: &DepositsMessage,
        _sender_node_id: PublicKey,
    ) {
        // V2: All ledger operations are wrapped in LedgerUpdate
        // to_operation() extracts the LedgerOperation from LedgerUpdate messages
        let event = message.to_operation().and_then(|op| event_from_operation(&op));

        if let Some(event) = event {
            let _ = self.event_queue.emit_deposits_event(event);
        }
    }

    /// Check if peer supports Bitcoin Deposits protocol
    pub(super) fn peer_supports_protocol(&self, features: &InitFeatures) -> bool {
        // For Bitcoin Deposits, we assume any Lightning node can handle custom messages
        // in the 0x8000-0x80FF range per Lightning spec
        // We'll rely on the custom message handler routing rather than explicit feature bits

        log_debug!(
            self.logger,
            "₿ Checking peer protocol support: unknown_bits={}, assuming custom message support",
            features.supports_unknown_bits()
        );

        // Accept all peers - Lightning should route custom messages to our handler
        true
    }

    /// Get list of active protocol partners
    /// Returns partners where we have BOTH:
    /// 1. A ledger (recovered from storage or newly initialized)
    /// 2. An active Lightning channel
    ///
    /// This prevents using ledgers from force-closed channels
    pub fn list_active_partners(&self) -> Vec<PublicKey> {
        use std::str::FromStr;
        // Get all ledger partners where we are the operator
        let ledger_partners: Vec<PublicKey> = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.keys()
                .filter(|(operator, _partner)| *operator == self.our_node_id)
                .filter_map(|(_operator, partner)| PublicKey::from_str(partner).ok())
                .collect()
        };

        // Filter to only partners with active channels
        if let Some(ref cm) = self.channel_manager {
            let all_channels = cm.list_channels();
            let channel_partners: std::collections::HashSet<PublicKey> =
                all_channels.iter().map(|ch| ch.counterparty_node_id).collect();

            let active_partners: Vec<PublicKey> = ledger_partners.iter()
                .filter(|partner| channel_partners.contains(partner))
                .copied()
                .collect();

            log_debug!(
                self.logger,
                "list_active_partners: {} ledgers, {} channels, {} active (ledger+channel)",
                ledger_partners.len(),
                all_channels.len(),
                active_partners.len()
            );

            active_partners
        } else {
            // No channel manager yet (during startup) - return empty
            log_warn!(self.logger, "list_active_partners called before channel_manager set, returning empty list");
            Vec::new()
        }
    }

    /// Store a ledger private key for a partner
    /// Only operators store private keys - partners do not need them
    pub fn store_ledger_private_key(
        &self,
        partner_node_id: PublicKey,
        secret_key: bitcoin::secp256k1::SecretKey,
    ) -> Result<(), deposits_core::DepositsError> {
        use deposits_core::log_info;

        let mut private_keys = self.ledger_private_keys.lock().unwrap();
        private_keys.insert(partner_node_id, secret_key);

        // TODO: Persist to disk for recovery after restart
        log_info!(self.logger, "Stored ledger private key for partner {}", partner_node_id);

        Ok(())
    }

    /// Get a ledger private key for a partner (if we are the operator)
    pub fn get_ledger_private_key(
        &self,
        partner_node_id: PublicKey,
    ) -> Option<bitcoin::secp256k1::SecretKey> {
        let private_keys = self.ledger_private_keys.lock().unwrap();
        private_keys.get(&partner_node_id).copied()
    }

    /// Get protocol statistics
    pub fn get_protocol_stats(&self) -> ProtocolStats {
        let protocols = self.protocols.lock().unwrap();
        let ledgers = self.ledgers.lock().unwrap();
        let outbound_messages = self.outbound_messages.lock().unwrap();

        ProtocolStats {
            active_partners: protocols.len(),
            pending_outbound_messages: outbound_messages.values().map(|v| v.len()).sum(),
            total_ledgers: ledgers.len(),
        }
    }
}
