//! Pluggable bitcoin chain-data backend.
//!
//! Today's `deposits-node` constructs `EsploraBuilder::new(&url).build_blocking()`
//! at ~14 sites in `wallet.rs` (plus a few in `ledger_wallet.rs` and
//! `recovery.rs`) — hardcoded to the esplora HTTP API. That forces every
//! operator to also run an esplora instance, even when they already have
//! `bitcoind` (Umbrel/Start9 default) or `electrs` (common in larger
//! self-host stacks). This module is the structural fix.
//!
//! Per [PACKAGING_PLAN.md](../../PACKAGING_PLAN.md) Tier 1b: the trait
//! lands first as the EsploraBackend impl wrapping current behaviour, then
//! `BitcoindRpcBackend` / `ElectrumBackend` follow as separate commits.
//!
//! ## Relationship to BDK
//!
//! BDK has its own chain-source abstraction (`bdk_esplora`, `bdk_bitcoind_rpc`,
//! `bdk_electrum`) used inside its `Wallet::sync` path. This trait sits
//! *above* BDK for the operations BDK doesn't cover (broadcast, fetch-by-id,
//! get-tip, output-status, fee-estimate) and *parallel to* BDK for the sync
//! path — each backend impl wires the matching BDK chain source for sync.
//! BDK stays in-process; this trait isn't an attempt to replace it.
//!
//! ## Why neutral types
//!
//! Same reasoning as `lightning_backend`: surfacing one backend's response
//! struct directly would force the others to fabricate values to satisfy
//! the type. The neutral types here are the intersection of what the
//! backends agree on plus what daemon callers actually consume.
//!
//! ## Sync vs async
//!
//! Sync for the same reasons `LightningBackend` is sync — every current
//! caller is sync; async-native impls (bitcoind-rpc's async clients,
//! electrum-client async) block on their own tokio runtime via the
//! [`crate::remote_signer::RemoteSigner`] worker-thread pattern if needed.
//! A few callers today are `async` because `bdk_esplora` exposes both;
//! those callers migrate to sync (or wrap on the trait) when the caller
//! migration lands.

use bitcoin::{BlockHash, OutPoint, Script, Transaction, Txid};

use crate::Error;

/// Bitcoin chain-data backend the daemon talks to for non-BDK chain
/// operations. See module docs for design rationale and the path to
/// bitcoind-rpc / electrum impls.
pub trait ChainBackend: Send + Sync {
    /// Best block height the backend has seen.
    fn get_tip_height(&self) -> Result<u32, Error>;

    /// Block hash at the given height. Errors if the backend doesn't have
    /// the block (typically: height > tip, or pre-prune for backends with
    /// pruning).
    fn get_block_hash(&self, height: u32) -> Result<BlockHash, Error>;

    /// Height of a block hash IF the backend recognizes the hash AND it's
    /// in the best chain. `Ok(None)` for unknown hashes and for known
    /// hashes on a stale fork — both mean "this block isn't confirming
    /// anything from the caller's perspective."
    fn get_block_height_if_in_best_chain(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<u32>, Error>;

    /// Fetch a transaction by id. `Ok(None)` if the backend doesn't know
    /// the txid (typically: not in mempool, not in chain, or backend
    /// doesn't index unrelated txs — bitcoind without `txindex=1` only
    /// knows its own wallet txs).
    fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error>;

    /// Confirmation height of a transaction.
    /// - `Ok(Some(height))` — confirmed in the best chain at this height.
    /// - `Ok(None)` — known but unconfirmed (mempool), OR unknown.
    ///   Callers that need to distinguish should also call `get_tx`.
    fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u32>, Error>;

    /// Whether a transaction output is currently unspent per the backend's
    /// mempool+chain view.
    /// - `Ok(Some(true))` — output exists and is unspent.
    /// - `Ok(Some(false))` — output exists but is spent.
    /// - `Ok(None)` — backend doesn't know the outpoint at all.
    fn is_output_unspent(&self, txid: &Txid, vout: u32) -> Result<Option<bool>, Error>;

    /// Find the first unspent output paying to `script`, if any. Used by
    /// the reserves-UTXO scan path — callers want "the live UTXO at this
    /// address" without paginating through the address's full history.
    ///
    /// Different backends have different cost models for this:
    /// esplora exposes it via `/scripthash/{hash}/utxo`; electrum via
    /// `script_hash.listunspent`; bitcoind needs `scantxoutset` (which is
    /// expensive but doesn't require `txindex`).
    fn find_unspent_output_at(
        &self,
        script: &Script,
    ) -> Result<Option<UnspentOutput>, Error>;

    /// Broadcast a signed transaction. Returns the txid on success.
    /// Backends propagate to mempool; whether the broadcast actually
    /// reaches the rest of the network depends on the backend's peer
    /// connectivity (always fine for esplora/electrum public hosts; for
    /// bitcoind RPC, depends on the node's peer count).
    fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid, Error>;
}

/// A single unspent UTXO at a script. Used as the return shape of
/// [`ChainBackend::find_unspent_output_at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnspentOutput {
    /// Where the UTXO lives on-chain.
    pub outpoint: OutPoint,
    /// Output value, sats.
    pub value_sats: u64,
}

/// Build the [`ChainBackend`] selected at runtime via environment.
///
/// `CHAIN_BACKEND` selects the impl. Defaults to `esplora` so existing
/// deployments keep working without any env changes.
///
/// `url` is the esplora-only fallback hint — every caller passes it from
/// their wallet's config because esplora is the default. The other backends
/// read their own connection config from env (and ignore `url`):
/// - `esplora`  — uses `url` directly
/// - `bitcoind` — `BITCOIND_RPC_URL`, `BITCOIND_RPC_USER`+`BITCOIND_RPC_PASS`
///   or `BITCOIND_COOKIE_FILE`
/// - `electrum` — `ELECTRUM_HOST`, `ELECTRUM_PORT`
///
/// Construction errors panic — these are startup-time misconfiguration
/// the operator needs to see immediately.
pub fn from_env(url: &str) -> Box<dyn ChainBackend> {
    match std::env::var("CHAIN_BACKEND")
        .ok()
        .as_deref()
        .unwrap_or("esplora")
    {
        "esplora" => Box::new(crate::esplora_backend::EsploraBackend::new(url)),
        "bitcoind" => Box::new(
            crate::bitcoind_backend::BitcoindRpcBackend::from_env()
                .unwrap_or_else(|e| panic!("bitcoind backend init failed: {}", e)),
        ),
        "electrum" => Box::new(
            crate::electrum_backend::ElectrumBackend::from_env()
                .unwrap_or_else(|e| panic!("electrum backend init failed: {}", e)),
        ),
        other => panic!(
            "CHAIN_BACKEND={:?} not supported. Supported: \"esplora\", \"bitcoind\", \"electrum\".",
            other
        ),
    }
}
