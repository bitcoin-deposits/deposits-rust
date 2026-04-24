//! Legacy CLI modules — predates the gift-wrapped-admin-DM CLI in
//! `node_cli/`, retained because `nostr_commands` (the `nostr watch`
//! helper) and `recovery` (DEP-06 dispute phases) are still exercised
//! by the integration-test scripts. New subcommands go in `node_cli/`;
//! shared helpers (`derive_operator_secret`, `parse_config`) live
//! there now too.

pub mod handlers;
pub mod nostr_commands;
pub mod recovery;

pub use recovery::recovery_command;
