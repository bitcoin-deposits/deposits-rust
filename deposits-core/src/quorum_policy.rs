// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Per-network policy thresholds used by quorum members when deciding whether
//! to cosign. These are not consensus rules — a stricter peer is free to
//! refuse a cosign request a laxer peer would accept. The defaults below are
//! what an honest peer with no explicit policy override uses.

use bitcoin::Network;

/// Minimum on-chain confirmations a cosigner requires on the reserves
/// outpoint referenced by a `QuorumBegin` before they will cosign it.
///
/// The first `QuorumBegin` transitions the ledger into Active — post-transition
/// the on-chain UTXO is load-bearing (it is the reserves the quorum now
/// controls). A cosigner who signs without confirming the UTXO exists + has
/// settled risks endorsing a rotation that never actually happened on-chain,
/// or that got reorged away.
///
/// Values are conservative but not paranoid — the on-chain UTXO is the
/// reserves, not a payout; reorgs at these depths are vanishingly rare.
pub const fn default_quorum_begin_confs(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 6,
        Network::Testnet | Network::Signet => 3,
        Network::Regtest => 1,
        // Fallback for any future bitcoin-rust variants.
        _ => 3,
    }
}
