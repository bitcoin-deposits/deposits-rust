// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! # Bitcoin Deposits Protocol - LDK Adapter
//!
//! This crate provides LDK-specific implementations of the adapter traits
//! defined in `deposits-core`, enabling the Bitcoin Deposits protocol to
//! run on Lightning nodes using the LDK library.
//!
//! ## Components
//!
//! - [`transport`]: CustomMessageHandler implementation for peer messaging
//! - [`storage`]: KVStore-based persistence
//! - [`channels`]: Channel manager integration
//! - [`chain`]: Block source integration
//! - [`signer`]: Node key signing
//!
//! ## Usage
//!
//! ```ignore
//! use deposits_ldk::{LdkTransport, LdkStorage, LdkChannelRegistry};
//! use deposits_core::HandlerConfig;
//!
//! // Create LDK adapters
//! let transport = Arc::new(LdkTransport::new(peer_manager));
//! let storage = Arc::new(LdkStorage::new(kv_store));
//! let channels = Arc::new(LdkChannelRegistry::new(channel_manager));
//!
//! // Wire up with deposits-core handler
//! let config = HandlerConfig {
//!     storage,
//!     transport,
//!     // ... other adapters
//! };
//! ```

#![allow(missing_docs)] // TODO: Add comprehensive documentation

pub mod chain;
pub mod channel_extension;
pub mod channel_manager_ops;
pub mod channels;
pub mod commitment;
pub mod event;
pub mod events;
pub mod handler;
pub mod hex_utils;
pub mod logger;
pub mod payments;
pub mod reserves;
pub mod services;
pub mod signer;
pub mod storage;
pub mod transport;
pub mod types;
pub mod wire;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

// Re-exports for convenience
pub use chain::{LdkBroadcaster, LdkChainSource, MemoryBroadcaster};
pub use wire::message_types;
pub use channel_manager_ops::{ChannelManagerOps, ChannelDetails, NullChannelManager};
pub use channels::{
    ChannelInfo, LdkChannelRegistry, MemoryChannelRegistry,
    LdkChannelOperations, LdkReservesOperations, MemoryReservesOperations,
};
pub use event::DepositsEventEmitter;
pub use events::{CallbackEventEmitter, ChannelEventEmitter, MemoryEventEmitter, NullEventEmitter};
pub use logger::{LdkLoggerAdapter, StdoutLogger};
pub use payments::{LdkPaymentTracker, MemoryPaymentTracker, PaymentRecord};
pub use signer::MemorySigner;
pub use storage::{LdkStorage, MemoryStorage};
pub use transport::{LdkTransport, RawDepositsMessage};
