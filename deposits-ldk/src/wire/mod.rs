// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Wire Protocol Implementation for Bitcoin Deposits
//!
//! This module provides LDK-compatible wire format encoding/decoding for the
//! Bitcoin Deposits protocol. It implements Lightning's `Readable`/`Writeable`
//! traits and `CustomMessageReader` for peer-to-peer message transport.
//!
//! ## Architecture
//!
//! The wire protocol provides encoding/decoding for all Bitcoin Deposits
//! message types using the consolidated format from `deposits-core`.
//!
//! ## Modules
//!
//! - [`message_types`]: Message type constants
//! - [`reader`]: CustomMessageReader implementation
//!
//! ## Usage
//!
//! ```ignore
//! use deposits_ldk::wire::{DepositsMessageReader, message_types};
//!
//! // Create a message reader for LDK integration
//! let reader = DepositsMessageReader;
//!
//! // Check if a message type is a deposits message
//! if message_types::is_deposits_message_type(0x80D1) {
//!     // Handle deposits message
//! }
//! ```

pub mod adapters;
pub mod codec;
pub mod message_types;
pub mod messages;
pub mod types;
pub mod channel_ledger;

// Re-exports
pub use codec::MessageCodec;
pub use message_types::*;
pub use messages::*;
pub use types::{
    Deposit, FeeStructure, Invoice, PendingInvoice, ReservesOutput,
    LedgerState, SignedLedgerUpdate, SignedLedgerUpdateLog,
};
pub use channel_ledger::{ChannelLedger, LedgerUpdate};
