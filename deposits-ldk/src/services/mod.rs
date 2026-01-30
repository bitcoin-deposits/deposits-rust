// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Service architecture for Bitcoin Deposits production automation
//!
//! This module provides event-driven services that automate the coordination
//! between Lightning Network operations and Bitcoin Deposits protocol state.
//! These services replace the manual orchestration required in tests with
//! production-ready automation.

pub mod lightning_events;
pub mod lighthouse;
pub mod payment_orchestration;
pub mod reserves_management;
pub mod service_coordinator;

// Re-export main service types
pub use lightning_events::{LightningEventService, LightningEvent};
pub use lighthouse::{LighthouseService, LighthouseEvent, WatchedReservesOutput};
pub use payment_orchestration::PaymentOrchestrationService;
pub use reserves_management::ReservesManagementService;
pub use service_coordinator::DepositsService;

use deposits_core::DepositsError;

/// Service-specific error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// Bitcoin Deposits protocol error
    Protocol(DepositsError),

    /// Lightning network operation failed
    LightningError(String),

    /// Payment processing error
    InvoiceFailed,

    /// Payment initiation failed
    PaymentInitiationFailed(String),

    /// NWC protocol error
    NostrWalletConnectError(String),

    /// Unsupported NWC method
    UnsupportedMethod(String),

    /// Service is not running
    NotRunning,

    /// Invalid request parameters
    InvalidRequest,

    /// Partner node not found
    PartnerNotFound,

    /// Deposit not found
    DepositNotFound,

    /// Channel not found
    ChannelNotFound,
}

impl From<DepositsError> for ServiceError {
    fn from(err: DepositsError) -> Self {
        ServiceError::Protocol(err)
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Protocol(e) => write!(f, "Protocol error: {}", e),
            ServiceError::LightningError(msg) => write!(f, "Lightning error: {}", msg),
            ServiceError::InvoiceFailed => write!(f, "Payment failed"),
            ServiceError::PaymentInitiationFailed(msg) => write!(f, "Payment initiation failed: {}", msg),
            ServiceError::NostrWalletConnectError(msg) => write!(f, "NWC error: {}", msg),
            ServiceError::UnsupportedMethod(method) => write!(f, "Unsupported NWC method: {}", method),
            ServiceError::NotRunning => write!(f, "Service is not running"),
            ServiceError::InvalidRequest => write!(f, "Invalid request"),
            ServiceError::PartnerNotFound => write!(f, "Partner node not found"),
            ServiceError::DepositNotFound => write!(f, "Deposit not found"),
            ServiceError::ChannelNotFound => write!(f, "Channel not found"),
        }
    }
}

impl std::error::Error for ServiceError {}

/// Service configuration
#[derive(Clone, Debug)]
pub struct DepositsServiceConfig {
    /// Enable NWC server
    pub enable_nwc_server: bool,

    /// NWC relay URLs
    pub nwc_relay_urls: Vec<String>,

    /// Reserves monitoring interval in seconds
    pub reserves_monitoring_interval_secs: u64,

    /// Excess reserves threshold (amount above required to keep)
    pub excess_reserves_threshold_msat: u64,
}

impl Default for DepositsServiceConfig {
    fn default() -> Self {
        Self {
            enable_nwc_server: true,
            nwc_relay_urls: vec!["wss://relay.damus.io".to_string()],
            reserves_monitoring_interval_secs: 300, // 5 minutes
            excess_reserves_threshold_msat: 100_000, // 100 sats
        }
    }
}
