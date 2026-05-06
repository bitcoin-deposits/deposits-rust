// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Error types for deposits-node

use bitcoin::secp256k1::PublicKey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Wallet error: {0}")]
    Wallet(String),

    #[error("Nostr error: {0}")]
    Nostr(String),

    #[error("Ledger not found: operator={operator}, partner={partner}")]
    LedgerNotFound {
        operator: PublicKey,
        partner: PublicKey,
    },

    #[error("Handler error: {0}")]
    Handler(#[from] deposits_core::error::HandlerError),

    #[error(transparent)]
    NostrTransport(#[from] deposits_nostr::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("No reserves found. Create reserves first with 'reserves' command.")]
    NoReserves,

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Deposit offer not found")]
    OfferNotFound,
}
