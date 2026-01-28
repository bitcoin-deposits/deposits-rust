// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Bitcoin Deposits Protocol - BDK + Nostr Implementation
//!
//! This crate provides an alternative implementation of the Bitcoin Deposits protocol
//! using BDK for on-chain wallet management and Nostr relays for peer messaging.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      deposits-bdk                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
//! │  │   Wallet    │  │   Nostr     │  │    Handler          │ │
//! │  │   (BDK)     │  │  Transport  │  │ (HandlerContext)    │ │
//! │  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
//! │         │                │                    │            │
//! │         └────────────────┼────────────────────┘            │
//! │                          │                                 │
//! ├──────────────────────────┼─────────────────────────────────┤
//! │                   deposits-core                            │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
//! │  │   Ledger    │  │  Messages   │  │  HandlerContext     │ │
//! │  │   State     │  │  & Codec    │  │  Trait              │ │
//! │  └─────────────┘  └─────────────┘  └─────────────────────┘ │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Key Differences from deposits-ldk
//!
//! | Feature | deposits-ldk | deposits-bdk |
//! |---------|--------------|--------------|
//! | Reserves | LN commitment tx outputs | On-chain UTXOs |
//! | Messaging | LN custom messages | Nostr encrypted DMs |
//! | Wallet | Channel manager | BDK wallet |
//! | Peer discovery | LN peer connections | Nostr pubkeys |

pub mod error;
pub mod handler;
pub mod nostr;
pub mod wallet;

pub use error::Error;
pub use handler::DepositsHandler;
