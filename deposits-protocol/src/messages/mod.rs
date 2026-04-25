// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Bitcoin Deposits Protocol Messages
//!
//! Consolidated message protocol with 12 message types (6 request/response pairs).
//! All message types use odd numbers per BOLT 1 "it's OK to be odd" rule for safe ignorability.
//!
//! ## Message Types
//!
//! | Request              | Response                  | Purpose                    |
//! |---------------------|---------------------------|----------------------------|
//! | LEDGER_UPDATE (0x8001) | LEDGER_UPDATE_RESPONSE (0x8003) | All ledger operations |
//! | HANDSHAKE (0x8005)     | HANDSHAKE_RESPONSE (0x8007)     | Protocol negotiation  |
//! | SYNC (0x8009)          | SYNC_RESPONSE (0x800B)          | State synchronization |
//! | COORDINATION (0x8011)  | COORDINATION_RESPONSE (0x8013)  | Invoice cosigning etc |
//!
//! Type IDs 0x800D and 0x800F are reserved (formerly RECOVERY /
//! RECOVERY_RESPONSE for the Lightning-channel-era recovery flow,
//! removed when the protocol moved to collateral-in-UTXO).

use bitcoin::secp256k1::PublicKey;
use std::io::{self, Read, Write};

use crate::types::SignedLedgerUpdate;
use crate::types::{DepositId, DescriptorWitness, FeeStructure, TransferFeeSchedule};

mod constants;
mod tlv_codec;
mod types;
mod wire_types;

pub use constants::*;
pub use tlv_codec::*;
pub use types::*;
pub use wire_types::*;
