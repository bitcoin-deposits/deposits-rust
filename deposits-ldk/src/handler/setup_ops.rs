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

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
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

        // Initialize core handler now that channel_manager is available
        self.initialize_core_handler();
    }

    /// Set the node's secret key for signing audit messages
    /// This should be called with the Lightning node's identity key
    /// Required for operators who need to sign ledger updates for auditors
    pub fn set_node_secret_key(&mut self, secret_key: bitcoin::secp256k1::SecretKey) {
        self.node_secret_key = Some(secret_key);
    }

    /// Initialize the core protocol handler from deposits-core
    ///
    /// This creates and configures the core Handler with LDK adapters.
    /// Should be called after set_channel_manager and set_node_secret_key.
    ///
    /// The core handler enables testing protocol logic in deposits-core
    /// and will gradually take over operations from LDK-specific code.
    pub fn initialize_core_handler(&mut self) {
        use super::ldk_adapters::{
            LdkStorageAdapter, LdkTransportAdapter, LdkLoggerAdapter,
            LdkChainAdapter, LdkEventAdapter, LdkSignerAdapter,
            LdkPaymentAdapter, LdkChannelAdapter, LdkBroadcasterAdapter,
        };

        log_info!(self.logger, "Initializing core protocol handler...");

        // Create adapters
        let storage = Arc::new(LdkStorageAdapter::new(self.kv_store.clone()));
        let transport = Arc::new(LdkTransportAdapter::new(
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())), // Will be connected to outbound_messages
            Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())), // Will be connected to connected_peers
        ));
        // Create a new payment index for the core handler
        // In a full migration, this would share state with DepositsHandler's payment_index
        let payments = Arc::new(LdkPaymentAdapter::new(Arc::new(deposits_core::DepositInvoiceIndex::new())));
        let channels = Arc::new(LdkChannelAdapter::new(self.channel_manager.clone()));
        let broadcaster = Arc::new(LdkBroadcasterAdapter::new(None)); // No broadcaster configured yet
        let chain = Arc::new(LdkChainAdapter::new(self.channel_manager.clone()));
        let signer = Arc::new(LdkSignerAdapter::new(self.our_node_id, self.node_secret_key));
        let events = Arc::new(LdkEventAdapter::new(self.event_queue.clone()));
        let logger = Arc::new(LdkLoggerAdapter::new(self.logger.clone()));

        // Create the core handler with shared ledgers
        // This allows both DepositsHandler and core Handler to operate on the same ledger state
        let handler = deposits_core::Handler::with_ledgers(
            self.ledgers.clone(), // Share ledger storage
            storage,
            transport,
            payments,
            channels,
            broadcaster,
            chain,
            signer,
            events,
            logger,
        );

        self.core_handler = Some(Arc::new(handler));
        log_info!(self.logger, "Core protocol handler initialized with shared ledgers");
    }
}
