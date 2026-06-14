//! [`ChainBackend`] impl using esplora HTTP API.
//!
//! Mirrors the per-call `EsploraBuilder::new(&url).build_blocking()` pattern
//! sprinkled throughout `wallet.rs`, ledger_wallet.rs`, and `recovery.rs`,
//! but wraps it behind the neutral trait so swap-in of `BitcoindRpcBackend`
//! / `ElectrumBackend` doesn't require touching the call sites.
//!
//! Construction is cheap (just stores the URL); the underlying
//! `esplora_client::BlockingClient` is built per call to match current
//! behaviour. A future optimization is to cache a single client per
//! backend instance — measure first; the per-call cost is dominated by the
//! HTTP round-trip, not client construction.

use bdk_esplora::esplora_client::Builder as EsploraBuilder;
use bitcoin::{BlockHash, OutPoint, Script, Transaction, Txid};

use crate::chain_backend::{ChainBackend, UnspentOutput};
use crate::Error;

/// Esplora HTTP API impl of [`ChainBackend`]. Backend selection: `CHAIN_BACKEND=esplora`
/// (the default).
#[derive(Clone)]
pub struct EsploraBackend {
    /// Base URL of the esplora server (e.g. `https://blockstream.info/api`
    /// or `http://localhost:3100`).
    pub url: String,
}

impl EsploraBackend {
    pub fn new(url: impl Into<String>) -> Self {
        // Trim trailing slashes: the esplora client appends paths like
        // `/blocks/tip/height`, so a base of `http://host:3100/` would
        // produce `http://host:3100//blocks/tip/height` → 404. The
        // bootstrap's own poll already trims; match it here so the two
        // paths agree and `--esplora http://host:3100/` just works.
        let url = url.into().trim_end_matches('/').to_string();
        Self { url }
    }

    fn client(&self) -> bdk_esplora::esplora_client::BlockingClient {
        EsploraBuilder::new(&self.url).build_blocking()
    }
}

impl ChainBackend for EsploraBackend {
    fn get_tip_height(&self) -> Result<u32, Error> {
        self.client()
            .get_height()
            .map_err(|e| Error::Wallet(format!("esplora get_height: {}", e)))
    }

    fn get_block_hash(&self, height: u32) -> Result<BlockHash, Error> {
        self.client()
            .get_block_hash(height)
            .map_err(|e| Error::Wallet(format!("esplora get_block_hash({}): {}", height, e)))
    }

    fn get_block_height_if_in_best_chain(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<u32>, Error> {
        match self.client().get_block_status(hash) {
            Ok(status) if status.in_best_chain => Ok(status.height),
            Ok(_) => Ok(None),
            Err(e) => Err(Error::Wallet(format!(
                "esplora get_block_status({}): {}",
                hash, e
            ))),
        }
    }

    fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        self.client()
            .get_tx(txid)
            .map_err(|e| Error::Wallet(format!("esplora get_tx({}): {}", txid, e)))
    }

    fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u32>, Error> {
        match self.client().get_tx_status(txid) {
            Ok(status) => Ok(status.block_height),
            Err(e) => Err(Error::Wallet(format!(
                "esplora get_tx_status({}): {}",
                txid, e
            ))),
        }
    }

    fn is_output_unspent(&self, txid: &Txid, vout: u32) -> Result<Option<bool>, Error> {
        match self.client().get_output_status(txid, vout as u64) {
            Ok(Some(status)) => Ok(Some(!status.spent)),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::Wallet(format!(
                "esplora get_output_status({}:{}): {}",
                txid, vout, e
            ))),
        }
    }

    fn find_unspent_output_at(
        &self,
        script: &Script,
    ) -> Result<Option<UnspentOutput>, Error> {
        // Hit /scripthash/<hash>/txs directly. The esplora-client library
        // would auto-format the hash using bitcoin's {:x} (byte-reversed)
        // which is the Blockstream-public-esplora convention; electrs
        // expects the non-reversed SHA256 hash. Bypass the typed client
        // to use the non-reversed form so we work against the electrs
        // every operator runs.
        use bitcoin::hashes::{sha256, Hash as _};

        let script_hash = sha256::Hash::hash(script.as_bytes());
        let script_hash_hex = hex::encode(script_hash.to_byte_array());
        let url = format!("{}/scripthash/{}/txs", self.url, script_hash_hex);

        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Wallet(format!("esplora HTTP client: {}", e)))?;
        let response = http.get(&url).send().map_err(|e| {
            Error::Wallet(format!("esplora GET {}: {}", url, e))
        })?;
        if !response.status().is_success() {
            return Err(Error::Wallet(format!(
                "esplora returned status {} for scripthash scan",
                response.status()
            )));
        }
        let txs: Vec<bdk_esplora::esplora_client::Tx> = response
            .json()
            .map_err(|e| Error::Wallet(format!("esplora parse scripthash response: {}", e)))?;
        let client = self.client();
        for tx in &txs {
            for (vout, output) in tx.vout.iter().enumerate() {
                if output.scriptpubkey.as_script() == script {
                    let status = client
                        .get_output_status(&tx.txid, vout as u64)
                        .map_err(|e| {
                            Error::Wallet(format!(
                                "esplora get_output_status({}:{}): {:?}",
                                tx.txid, vout, e
                            ))
                        })?;
                    if status.map(|s| !s.spent).unwrap_or(true) {
                        return Ok(Some(UnspentOutput {
                            outpoint: OutPoint::new(tx.txid, vout as u32),
                            value_sats: output.value,
                        }));
                    }
                }
            }
        }
        Ok(None)
    }

    fn find_spending_tx(
        &self,
        outpoint: &OutPoint,
        _script: &Script,
        _scan_from_height: u32,
    ) -> Result<Option<Transaction>, Error> {
        // Esplora exposes the spender directly via
        // /tx/{txid}/outspend/{vout} — OutputStatus carries the spending
        // txid (mempool or confirmed). No script or height hint needed.
        match self
            .client()
            .get_output_status(&outpoint.txid, outpoint.vout as u64)
        {
            Ok(Some(status)) if status.spent => match status.txid {
                Some(spender) => self.get_tx(&spender),
                None => Ok(None),
            },
            Ok(_) => Ok(None),
            Err(e) => Err(Error::Wallet(format!(
                "esplora get_output_status({}:{}): {}",
                outpoint.txid, outpoint.vout, e
            ))),
        }
    }

    fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid, Error> {
        self.client()
            .broadcast(tx)
            .map_err(|e| Error::Wallet(format!("esplora broadcast: {}", e)))?;
        Ok(tx.compute_txid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: `EsploraBackend` actually satisfies the
    /// `ChainBackend` trait. If the trait or impl drifts, this fails
    /// to type-check before runtime exercises it.
    #[test]
    fn esplora_backend_implements_chain_backend() {
        fn assert_backend<T: ChainBackend>() {}
        assert_backend::<EsploraBackend>();
    }
}
