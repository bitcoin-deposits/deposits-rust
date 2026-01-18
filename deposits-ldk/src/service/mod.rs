//! Service Layer for Bitcoin Deposits API
//!
//! This module provides HTTP-compatible handlers for the deposits API,
//! following ldk-server conventions with protobuf message types.
//!
//! # Architecture
//!
//! The service layer sits between the transport (HTTP) and the business logic (handler):
//!
//! ```text
//! HTTP Request → Proto Decode → Service Handler → Business Logic → Proto Encode → HTTP Response
//! ```
//!
//! Each handler takes a proto request message and returns a proto response message,
//! with errors encoded as `DepositsError` proto messages.

// Include generated protobuf types
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/deposits.rs"));
}

// Handler implementations
pub mod ledger;
pub mod deposit;
pub mod reserves;
pub mod collateral;
pub mod updates;

// Re-export commonly used types
pub use proto::*;

/// API endpoint constants for route matching in ldk-server
pub mod endpoints {
    // Ledger operations
    pub const DEPOSITS_INIT_LEDGER_PATH: &str = "/deposits/init_ledger";
    pub const DEPOSITS_LIST_LEDGERS_PATH: &str = "/deposits/list_ledgers";
    pub const DEPOSITS_GET_LEDGER_PATH: &str = "/deposits/get_ledger";
    pub const DEPOSITS_CLOSE_LEDGER_PATH: &str = "/deposits/close_ledger";

    // Deposit operations
    pub const DEPOSITS_ADD_DEPOSIT_PATH: &str = "/deposits/add_deposit";
    pub const DEPOSITS_LIST_DEPOSITS_PATH: &str = "/deposits/list_deposits";
    pub const DEPOSITS_REMOVE_DEPOSIT_PATH: &str = "/deposits/remove_deposit";

    // Reserves operations
    pub const DEPOSITS_GET_RESERVES_STATUS_PATH: &str = "/deposits/get_reserves_status";
    pub const DEPOSITS_REDUCE_RESERVES_PATH: &str = "/deposits/reduce_reserves";

    // Collateral operations
    pub const DEPOSITS_ADD_COLLATERAL_PARTNER_PATH: &str = "/deposits/add_collateral_partner";
    pub const DEPOSITS_REMOVE_COLLATERAL_PARTNER_PATH: &str = "/deposits/remove_collateral_partner";
    pub const DEPOSITS_GET_COLLATERAL_INFO_PATH: &str = "/deposits/get_collateral_info";

    // Ledger updates
    pub const DEPOSITS_GET_LEDGER_UPDATES_PATH: &str = "/deposits/get_ledger_updates";
}
