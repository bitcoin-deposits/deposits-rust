//! Shared wire types + nostr transport for the deposits hub
//! control plane.
//!
//! Both sides of the hub ↔ peer conversation pull this crate in:
//!
//!   * `deposits-hub`     — the operator's dashboard process
//!   * `deposits-signer`  — registers with the hub via `--hub-pubkey`
//!   * `deposits-node`    — same, when wired up later
//!
//! Keeping the wire definition + transport in a dedicated crate avoids
//! pulling the hub's TUI deps (`ratatui`, `crossterm`, …) into every
//! daemon that only needs to send `Register` and `Heartbeat`.

pub mod proto;
pub mod transport;
