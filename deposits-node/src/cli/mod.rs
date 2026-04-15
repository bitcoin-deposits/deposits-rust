//! CLI modules for deposits-node binary
//!
//! This module contains command implementations extracted from the main binary
//! to improve organization and maintainability.

pub mod common;
pub mod handlers;
pub mod nostr_commands;
pub mod recovery;

pub use common::{derive_operator_secret, parse_config, resolve_ledger_id_to_reserves_key};
pub use recovery::recovery_command;
