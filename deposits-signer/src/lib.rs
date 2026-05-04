//! Out-of-process signer daemon for `deposits-node`.
//!
//! Holds the operator/identity seed and answers BIP-340 / ECDSA / ECDH
//! requests over a Unix socket. The daemon never sees the seed once
//! `deposits-signer` is provisioned with it.
//!
//! See `PLAN-remote-signer.md` for the architecture, threat model, and
//! phasing.

pub mod data;
pub mod framing;
pub mod policy;
pub mod server;
