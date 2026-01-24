// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Setup operations for the Bitcoin Deposits protocol.
//!
//! This module contains initialization and configuration methods for DepositsHandler,
//! including setting up the channel manager and node secret key.

use bitcoin::secp256k1::PublicKey;
use std::sync::Arc;
use std::ops::Deref;

use super::core::DepositsHandler;
use crate::channel_manager_ops::ChannelManagerOps;
use deposits_core::{log_debug, log_info};
use lightning::util::logger::Logger as LdkLogger;

impl<L: Deref + Clone> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Set the channel manager reference (must be called after construction)
    pub fn set_channel_manager(&mut self, channel_manager: Arc<dyn ChannelManagerOps>) {
        log_info!(self.logger, "Setting channel manager reference...");
        self.channel_manager = Some(channel_manager);

        // Collect partners to refresh (must drop lock before calling refresh_reserves_commitment)
        // IMPORTANT: Only refresh ledgers where WE are the OPERATOR.
        // Partners do NOT send UpdateReserves - only operators do.
        let partners_to_refresh: Vec<PublicKey> = {
            log_info!(self.logger, "Collecting partners to refresh commitments...");
            let ledgers = self.ledgers.lock().unwrap();
            let partners: Vec<PublicKey> = ledgers.iter()
                .filter_map(|((operator_id, partner_id), _ledger_arc)| {
                    // Only refresh if we're the operator - partners don't send UpdateReserves
                    if *operator_id == self.our_node_id {
                        Some(*partner_id)
                    } else {
                        None
                    }
                })
                .collect();
            log_info!(self.logger, "Found {} operator ledgers to refresh", partners.len());
            partners
        };

        // Now refresh commitments with lock dropped
        log_info!(self.logger, "Refreshing channel commitments for {} partners...", partners_to_refresh.len());
        for partner_id in &partners_to_refresh {
            log_info!(self.logger, "Refreshing commitment with partner {}...", partner_id);
            if let Err(e) = self.refresh_reserves_commitment(*partner_id) {
                log_debug!(
                    self.logger,
                    "Could not refresh reserves commitment with {} on startup: {:?}",
                    partner_id,
                    e
                );
            } else {
                log_info!(self.logger, "Successfully refreshed commitment with partner {}", partner_id);
            }
        }
        log_info!(self.logger, "Finished refreshing channel commitments for {} ledgers", partners_to_refresh.len());
    }

    /// Set the node's secret key for signing audit messages
    /// This should be called with the Lightning node's identity key
    /// Required for operators who need to sign ledger updates for auditors
    pub fn set_node_secret_key(&mut self, secret_key: bitcoin::secp256k1::SecretKey) {
        self.node_secret_key = Some(secret_key);
    }
}
