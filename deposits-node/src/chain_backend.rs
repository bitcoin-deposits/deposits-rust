//! Pluggable bitcoin chain-data backend.
//!
//! Today's `deposits-node` constructs `EsploraBuilder::new(&url).build_blocking()`
//! at ~14 sites in `wallet.rs` (plus a few in `ledger_wallet.rs` and
//! `recovery.rs`) — hardcoded to the esplora HTTP API. That forces every
//! operator to also run an esplora instance, even when they already have
//! `bitcoind` (Umbrel/Start9 default) or `electrs` (common in larger
//! self-host stacks). This module is the structural fix.
//!
//! The trait
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
    fn get_block_height_if_in_best_chain(&self, hash: &BlockHash) -> Result<Option<u32>, Error>;

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
    fn find_unspent_output_at(&self, script: &Script) -> Result<Option<UnspentOutput>, Error>;

    /// Find the transaction that SPENDS `outpoint`, if the backend can
    /// see one. Used by the forfeit-sweep flow to locate the lottery
    /// claim TX (the spender of the confiscation TX's vout 0) so the
    /// revealer set can be extracted from its witness.
    ///
    /// `script` is the outpoint's scriptPubKey — electrum can only key
    /// lookups by scripthash, so it's required there and ignored by
    /// esplora. `scan_from_height` is a lower bound on the spender's
    /// block height — bitcoind (which has no spent-output index without
    /// `txindex` add-ons) walks raw blocks from there to the tip, so
    /// callers should pass the funding TX's confirmation height to keep
    /// the walk bounded.
    ///
    /// `Ok(None)` — the outpoint is unspent, unknown, or the spend isn't
    /// visible to this backend (e.g. mempool-only spend on bitcoind).
    fn find_spending_tx(
        &self,
        outpoint: &OutPoint,
        script: &Script,
        scan_from_height: u32,
    ) -> Result<Option<Transaction>, Error>;

    /// Every transaction confirmed in blocks `from..=to` that spends one of
    /// `watched`, with the prevouts of all its inputs (the taproot sighash
    /// commits to them) and the block it is in. One pass over the range, so
    /// the cost does not grow with the number of watched outpoints. Only a
    /// backend that can read whole blocks with prevouts implements it
    /// (bitcoind, `getblock` verbosity 3); the default declines.
    fn scan_outpoint_spends(
        &self,
        _from: u32,
        _to: u32,
        _watched: &std::collections::HashSet<OutPoint>,
    ) -> Result<Vec<ScannedSpend>, Error> {
        Err(Error::Wallet(
            "this chain backend cannot scan blocks for outpoint spends".into(),
        ))
    }

    /// Broadcast a signed transaction. Returns the txid on success.
    /// Backends propagate to mempool; whether the broadcast actually
    /// reaches the rest of the network depends on the backend's peer
    /// connectivity (always fine for esplora/electrum public hosts; for
    /// bitcoind RPC, depends on the node's peer count).
    fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid, Error>;
}

/// A confirmed spend of a watched outpoint, as found by
/// [`ChainBackend::scan_outpoint_spends`].
#[derive(Debug, Clone)]
pub struct ScannedSpend {
    /// The watched outpoint spent.
    pub outpoint: OutPoint,
    /// The spending transaction.
    pub tx: Transaction,
    /// The output each of `tx`'s inputs spends, in input order.
    pub prevouts: Vec<bitcoin::TxOut>,
    /// The block it confirmed in.
    pub block_hash: BlockHash,
    /// That block's height.
    pub height: u32,
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

// -- "Scan already in progress" --------------------------------------------
//
// bitcoind runs one `scantxoutset` at a time per node and fails a second
// concurrent call at once with RPC error -8 "Scan already in progress". The
// devnet shares one bitcoind among every node, so reference members arming
// on the same equivocation all scan for their replacement collateral within
// the same second: before this retry the losers armed with no collateral,
// which strict cosigners refuse (DEP-03 §"Replacement collateral
// declaration"), stalling the confiscation. Other backends never produce
// this error, so the retry is a no-op for them.

/// Retry schedule for a UTXO scan that bitcoind refused because another scan
/// was running.
#[derive(Clone, Debug)]
pub struct ScanRetry {
    /// Total attempts, the first included.
    pub attempts: u32,
    /// Each wait is uniform in `[min_wait, max_wait]`; the jitter keeps
    /// members that collided once from colliding again in lockstep.
    pub min_wait: std::time::Duration,
    pub max_wait: std::time::Duration,
}

impl Default for ScanRetry {
    /// 12 attempts, 1-5 s apart: at most 55 s (about 33 s expected) before
    /// giving up. A regtest/signet scan takes milliseconds and a mainnet one
    /// seconds, so a dozen other scans can finish in that time.
    fn default() -> Self {
        Self {
            attempts: 12,
            min_wait: std::time::Duration::from_secs(1),
            max_wait: std::time::Duration::from_secs(5),
        }
    }
}

impl ScanRetry {
    /// A short schedule for lookups on a path that must not stall: the
    /// inbound handlers (5 s timeouts), the periodic tasks (10 s) and the
    /// blocking `Wallet::find_utxo_for_script`. 4 attempts, 0.25-1 s apart,
    /// at most 3 s. The dispute arm falls back to the background re-arm
    /// pass, which uses the full [`ScanRetry::default`].
    pub fn quick() -> Self {
        Self {
            attempts: 4,
            min_wait: std::time::Duration::from_millis(250),
            max_wait: std::time::Duration::from_millis(1000),
        }
    }

    /// No waiting between attempts (tests).
    pub fn immediate(attempts: u32) -> Self {
        Self {
            attempts,
            min_wait: std::time::Duration::ZERO,
            max_wait: std::time::Duration::ZERO,
        }
    }

    fn jittered_wait(&self) -> std::time::Duration {
        use rand::Rng;
        if self.max_wait <= self.min_wait {
            return self.min_wait;
        }
        let lo = self.min_wait.as_millis() as u64;
        let hi = self.max_wait.as_millis() as u64;
        std::time::Duration::from_millis(rand::thread_rng().gen_range(lo..=hi))
    }
}

/// Whether `e` is bitcoind refusing a `scantxoutset` because another is
/// running (RPC error -8, "Scan already in progress, use action \"abort\"
/// or \"status\"").
pub fn is_scan_in_progress(e: &Error) -> bool {
    e.to_string().contains("Scan already in progress")
}

/// [`ChainBackend::find_unspent_output_at`], retried per `retry` while the
/// backend reports a scan already in progress. Any other error, and the
/// last "in progress" error once the attempts run out, is returned. The
/// waits are async so a daemon task does not hold a worker thread.
pub async fn find_unspent_output_retrying(
    backend: &dyn ChainBackend,
    script: &Script,
    retry: &ScanRetry,
) -> Result<Option<UnspentOutput>, Error> {
    let mut attempt = 1;
    loop {
        match backend.find_unspent_output_at(script) {
            Err(e) if is_scan_in_progress(&e) && attempt < retry.attempts => {
                let wait = retry.jittered_wait();
                tracing::info!(
                    "UTXO scan: another scan is in progress (attempt {}/{}); retrying in {:?}",
                    attempt,
                    retry.attempts,
                    wait
                );
                tokio::time::sleep(wait).await;
                attempt += 1;
            }
            other => return other,
        }
    }
}

/// Blocking form of [`find_unspent_output_retrying`] for the synchronous
/// callers (`Wallet::find_utxo_for_script`, the CLI). On a multi-threaded
/// tokio runtime the wait goes through `block_in_place`, so the runtime
/// moves its other tasks off this worker meanwhile.
pub fn find_unspent_output_retrying_blocking(
    backend: &dyn ChainBackend,
    script: &Script,
    retry: &ScanRetry,
) -> Result<Option<UnspentOutput>, Error> {
    let mut attempt = 1;
    loop {
        match backend.find_unspent_output_at(script) {
            Err(e) if is_scan_in_progress(&e) && attempt < retry.attempts => {
                let wait = retry.jittered_wait();
                tracing::info!(
                    "UTXO scan: another scan is in progress (attempt {}/{}); retrying in {:?}",
                    attempt,
                    retry.attempts,
                    wait
                );
                sleep_blocking(wait);
                attempt += 1;
            }
            other => return other,
        }
    }
}

fn sleep_blocking(d: std::time::Duration) {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| std::thread::sleep(d))
        }
        _ => std::thread::sleep(d),
    }
}

/// A scripted [`ChainBackend`] for tests: `find_unspent_output_at` returns
/// the queued results in order (then `Ok(None)`); everything else is empty.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::Mutex;

    pub(crate) struct ScriptedScans {
        pub scans: Mutex<std::collections::VecDeque<Result<Option<UnspentOutput>, Error>>>,
        pub calls: std::sync::atomic::AtomicU32,
    }

    impl ScriptedScans {
        pub(crate) fn new(results: Vec<Result<Option<UnspentOutput>, Error>>) -> Self {
            Self {
                scans: Mutex::new(results.into()),
                calls: std::sync::atomic::AtomicU32::new(0),
            }
        }

        pub(crate) fn scan_in_progress() -> Error {
            Error::Wallet(
                "bitcoind scantxoutset error -8: Scan already in progress, use action \
                 \"abort\" or \"status\""
                    .to_string(),
            )
        }

        pub(crate) fn calls(&self) -> u32 {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl ChainBackend for ScriptedScans {
        fn get_tip_height(&self) -> Result<u32, Error> {
            Ok(0)
        }
        fn get_block_hash(&self, _: u32) -> Result<BlockHash, Error> {
            Err(Error::Wallet("fake".into()))
        }
        fn get_block_height_if_in_best_chain(&self, _: &BlockHash) -> Result<Option<u32>, Error> {
            Ok(None)
        }
        fn get_tx(&self, _: &Txid) -> Result<Option<Transaction>, Error> {
            Ok(None)
        }
        fn get_tx_block_height(&self, _: &Txid) -> Result<Option<u32>, Error> {
            Ok(None)
        }
        fn is_output_unspent(&self, _: &Txid, _: u32) -> Result<Option<bool>, Error> {
            Ok(None)
        }
        fn find_unspent_output_at(&self, _: &Script) -> Result<Option<UnspentOutput>, Error> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.scans.lock().unwrap().pop_front().unwrap_or(Ok(None))
        }
        fn find_spending_tx(
            &self,
            _: &OutPoint,
            _: &Script,
            _: u32,
        ) -> Result<Option<Transaction>, Error> {
            Ok(None)
        }
        fn broadcast_tx(&self, _: &Transaction) -> Result<Txid, Error> {
            Err(Error::Wallet("fake".into()))
        }
    }
}
