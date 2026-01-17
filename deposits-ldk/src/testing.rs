// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Testing utilities for the Bitcoin Deposits protocol.
//!
//! This module provides convenience functions for creating test handlers
//! using lightning's TestLogger.

use bitcoin::secp256k1::PublicKey;
use lightning::util::test_utils::TestLogger;
use std::sync::Arc;

use crate::handler::DepositsHandler;

/// Create a fully functional DepositsHandler for testing.
///
/// Uses lightning's TestLogger for logging.
pub fn create_test_handler() -> DepositsHandler<Arc<TestLogger>> {
    let logger = Arc::new(TestLogger::new());
    DepositsHandler::new_for_testing(logger)
}

/// Create a test handler with a specific node ID for replay testing.
///
/// This is useful when replaying captured peer messages where the node ID
/// must match the original node that received the messages.
pub fn create_test_handler_with_node_id(node_id: PublicKey) -> DepositsHandler<Arc<TestLogger>> {
    let logger = Arc::new(TestLogger::new());
    DepositsHandler::new_for_testing_with_node_id(logger, node_id)
}

/// Create a pair of handlers for testing peer-to-peer scenarios.
pub fn create_test_handler_pair() -> (
    DepositsHandler<Arc<TestLogger>>,
    DepositsHandler<Arc<TestLogger>>,
) {
    (create_test_handler(), create_test_handler())
}
