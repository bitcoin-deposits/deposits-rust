//! deposits-hub — operator control plane.
//!
//! Single dashboard for "things I control in the deposits ecosystem":
//! a TUI showing every signer + node tied to this operator, with
//! health + lifecycle controls. Comms with signers/nodes go over
//! gift-wrapped nostr DMs (one new KIND, JSON payloads). Hub never
//! relays signing traffic — that path stays daemon↔signer over their
//! existing socket.
//!
//! See `proto.rs` for the wire shape, `state.rs` for the persistent
//! inventory, and `tui.rs` for the interactive surface.

// Wire protocol + nostr transport live in `deposits-hub-proto` so the
// signer (and later, the node) can pull them in without dragging the
// hub's TUI deps along.
pub use deposits_hub_proto::{proto, transport as nostr};

pub mod control;
pub mod lock;
pub mod peers;
pub mod qr;
pub mod spawn;
pub mod state;
pub mod tui;
