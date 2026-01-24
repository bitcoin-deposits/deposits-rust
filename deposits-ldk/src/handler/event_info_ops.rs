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
use lightning::log_debug;
use lightning::util::logger::Logger as LdkLogger;
use lightning::log_warn;

use std::ops::Deref;

/// Generate event from a LedgerOperation (unified handler for V1 and V2)
fn event_from_operation(operation: &LedgerOperation) -> Option<DepositsEvent> {
    match operation {
        LedgerOperation::DepositOpen { pubkey, .. } => {
            Some(DepositsEvent::DepositAdded {
                pubkey: *pubkey,
                initial_balance: 0,
            })
        }
        LedgerOperation::DepositClose { pubkey } => {
            Some(DepositsEvent::DepositRemoved {
                pubkey: *pubkey,
            })
        }
        LedgerOperation::ReservesIncrease { new_amount } => {
            Some(DepositsEvent::ReservesIncreased {
                amount: *new_amount,
            })
        }
        LedgerOperation::PaymentCredit { deposit_pubkey, amount, .. } => {
            Some(DepositsEvent::PaymentCredited {
                deposit_pubkey: *deposit_pubkey,
                amount: *amount,
            })
        }
        LedgerOperation::PaymentFulfill { pubkey, amount, .. } => {
            Some(DepositsEvent::PaymentDebited {
                deposit_pubkey: *pubkey,
                amount: *amount,
            })
        }
        _ => None,
    }
}

impl<L: Deref + Clone> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Generate appropriate events based on message type
    /// Uses to_operation() to handle both V1 and V2 message formats uniformly
    pub(super) fn generate_protocol_event(
        &self,
        message: &DepositsMessage,
        _sender_node_id: PublicKey,
    ) {
        let event = if let Some(operation) = message.to_operation() {
            // Unified handling for V1 variants and V2 LedgerUpdate via to_operation()
            event_from_operation(&operation)
        } else {
            // Handle special cases that don't convert to LedgerOperation
            match message {
                DepositsMessage::ReceivingCosignInvoice { amount, assigned_deposit, ref invoice_id, .. } => {
                    Some(DepositsEvent::InvoiceCosigned {
                        invoice_id: invoice_id.clone(),
                        deposit_pubkey: *assigned_deposit,
                        amount: *amount,
                    })
                }
                DepositsMessage::SignedUpdate(update_msg) => {
                    // SignedUpdate has operation field but isn't covered by to_operation()
                    event_from_operation(&update_msg.operation)
                }
                _ => None,
            }
        };

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
        // Get all ledger partners where we are the operator
        let ledger_partners: Vec<PublicKey> = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.keys()
                .filter(|(operator, _partner)| *operator == self.our_node_id)
                .map(|(_operator, partner)| *partner)
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
        use lightning::log_info;

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
