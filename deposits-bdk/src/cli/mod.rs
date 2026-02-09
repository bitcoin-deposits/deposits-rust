//! CLI modules for deposits-bdk binary
//!
//! This module contains command implementations extracted from the main binary
//! to improve organization and maintainability.

pub mod common;
pub mod handlers;
pub mod nostr_commands;
pub mod recovery;

pub use common::{parse_config, derive_operator_secret, resolve_ledger_id_to_reserves_id};
pub use recovery::recovery_command;
