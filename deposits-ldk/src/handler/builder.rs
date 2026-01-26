// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Builder pattern for creating Bitcoin Deposits handlers.
//!
//! This module provides a builder for constructing DepositsHandler instances
//! with configurable options.

use bitcoin::secp256k1::PublicKey;
use std::sync::Arc;
use std::ops::Deref;

use super::core::DepositsHandler;
use crate::DepositsEventEmitter;
use lightning::util::logger::Logger as LdkLogger;

/// Builder for creating Bitcoin Deposits message handlers
pub struct DepositsHandlerBuilder<L: Deref + Clone + Send + Sync>
where
    L::Target: LdkLogger,
{
    event_queue: Option<Arc<dyn DepositsEventEmitter>>,
    logger: Option<L>,
}

impl<L: Deref + Clone + Send + Sync> DepositsHandlerBuilder<L>
where
    L::Target: LdkLogger,
{
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            event_queue: None,
            logger: None,
        }
    }

    /// Set the event emitter
    pub fn event_queue(mut self, event_queue: Arc<dyn DepositsEventEmitter>) -> Self {
        self.event_queue = Some(event_queue);
        self
    }

    /// Set the logger
    pub fn logger(mut self, logger: L) -> Self {
        self.logger = Some(logger);
        self
    }

    /// Build the handler
    pub fn build(self) -> Result<DepositsHandler<L>, &'static str> {
        let event_queue = self.event_queue.ok_or("Event queue is required")?;
        let logger = self.logger.ok_or("Logger is required")?;

        // For testing, create a dummy KVStore and node ID
        let dummy_store = Arc::new(lightning_persister::fs_store::FilesystemStore::new(std::path::PathBuf::from("/tmp")));
        // Generate a test node ID
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let test_node_id = PublicKey::from_secret_key(&secp, &secret);
        DepositsHandler::new(event_queue, logger, dummy_store, test_node_id, bitcoin::Network::Regtest)
            .map_err(|_| "Failed to create Bitcoin Deposits handler")
    }
}

impl<L: Deref + Clone + Send + Sync> Default for DepositsHandlerBuilder<L>
where
    L::Target: LdkLogger,
{
    fn default() -> Self {
        Self::new()
    }
}
