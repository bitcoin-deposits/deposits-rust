// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Constants and helper functions for the Bitcoin Deposits protocol handler.
//!
//! This module re-exports handler constants from deposits-core.

// Re-export all handler constants from deposits-core
pub(crate) use deposits_core::constants::{
    RESERVES_HEADROOM_SATS,
    calculate_reserves_with_headroom,
    COLLATERAL_HEADROOM_SATS,
    calculate_collateral_with_headroom,
    STALE_ACK_THRESHOLD_SECS,
    STALE_BROADCAST_THRESHOLD_SECS,
    LAZY_SYNC_DELAY_SECS,
};
