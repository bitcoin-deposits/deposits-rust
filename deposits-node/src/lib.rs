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
//! │                      deposits-node                           │
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
//! | Feature | deposits-ldk | deposits-node |
//! |---------|--------------|--------------|
//! | Reserves | LN commitment tx outputs | On-chain UTXOs |
//! | Messaging | LN custom messages | Nostr encrypted DMs |
//! | Wallet | Channel manager | BDK wallet |
//! | Peer discovery | LN peer connections | Nostr pubkeys |

pub mod error;
pub mod handler;
pub mod ldk_cli;
pub mod ledger_wallet;
pub mod metrics;
pub mod node;
pub mod node_cli;
/// Re-export of the `deposits-nostr` crate. The transport, message
/// types, and wire constants used to live here as an inline module;
/// they were lifted into a sibling crate so wallet-side consumers
/// don't have to depend on the daemon. Existing `crate::nostr::…`
/// paths inside deposits-node still resolve through this re-export.
pub use deposits_nostr as nostr;
pub mod operator_policy;
pub mod remote_signer;
// deposits-node/src/cli was split: nostr_commands + recovery moved to
// node_cli/; handlers.rs was dead code (zero callers) and got deleted.
pub mod wallet;

pub use error::Error;
pub use handler::DepositsHandler;
pub use node::{Node, NodeConfig};
