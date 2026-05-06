// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! BDK wallet for on-chain reserves management
//!
//! Unlike deposits-ldk which uses Lightning commitment transaction outputs,
//! deposits-node holds reserves as on-chain UTXOs in a BDK wallet.

use bdk_esplora::esplora_client::Builder as EsploraBuilder;
use bdk_esplora::EsploraExt;
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv};
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::script::Builder as ScriptBuilder;
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bdk_wallet::bitcoin::{
    opcodes, Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
};
use bdk_wallet::chain::spk_client::SyncRequest;
use bdk_wallet::{KeychainKind, SignOptions, Wallet as BdkWallet};
use deposits_core::TaprootReservesOutput;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

use crate::Error;

/// BDK-based wallet for reserves management
pub struct Wallet {
    /// The BDK wallet instance
    inner: Mutex<BdkWallet>,

    /// Electrum client URL for chain sync
    electrum_url: String,

    /// Network
    network: Network,

    /// Our operator secret key (for signing reserves)
    operator_secret: SecretKey,

    /// Our operator public key
    operator_pubkey: PublicKey,

    /// Current block height (updated on sync)
    block_height: Mutex<u32>,

    /// Current block hash (updated on sync)
    block_hash: Mutex<[u8; 32]>,

    /// Data directory for persistence
    data_dir: PathBuf,

    /// Last revealed address index (persisted to disk)
    address_index: Mutex<u32>,
}

/// Information about a Taproot reserves output (quorum-based spending)
#[derive(Debug, Clone)]
pub struct TaprootReservesInfo {
    /// The outpoint
    pub outpoint: OutPoint,

    /// Amount in satoshis
    pub amount: u64,

    /// The operator pubkey (tie-breaker)
    pub operator: PublicKey,

    /// Quorum member pubkeys (primary voters)
    pub quorum_members: Vec<PublicKey>,

    /// Minimum quorum member expiration block (first timeout)
    pub quorum_expiry: u32,

    /// The ledger hash committed to in the Taproot tree
    pub ledger_hash: [u8; 32],

    /// The Taproot reserves output (contains spend info)
    pub taproot_output: TaprootReservesOutput,

    /// Whether this output is confirmed
    pub confirmed: bool,
}

impl Wallet {
    /// Create a new wallet from a seed
    pub fn new(
        seed: [u8; 32],
        network: Network,
        data_dir: PathBuf,
        electrum_url: String,
    ) -> Result<Self, Error> {
        let secp = Secp256k1::new();

        // Derive operator key from seed
        let xpriv = Xpriv::new_master(network, &seed)
            .map_err(|e| Error::Wallet(format!("Failed to create master key: {}", e)))?;

        let operator_path = DerivationPath::from_str("m/86'/0'/0'/0/0")
            .map_err(|e| Error::Wallet(format!("Invalid derivation path: {}", e)))?;

        let operator_xpriv = xpriv
            .derive_priv(&secp, &operator_path)
            .map_err(|e| Error::Wallet(format!("Failed to derive operator key: {}", e)))?;

        let operator_secret = operator_xpriv.private_key;
        let operator_pubkey = PublicKey::from_secret_key(&secp, &operator_secret);

        // Use simple wpkh descriptor for the wallet
        // External: m/0/* for receiving addresses
        // Internal: m/1/* for change addresses
        let external_desc = format!("wpkh({}/0/*)", xpriv);
        let internal_desc = format!("wpkh({}/1/*)", xpriv);

        // Ensure data directory exists
        if !data_dir.exists() {
            tracing::info!("Creating data directory: {:?}", data_dir);
            fs::create_dir_all(&data_dir)
                .map_err(|e| Error::Wallet(format!("Failed to create data dir: {}", e)))?;
        }

        // Load persisted address index
        let address_index = Self::load_address_index(&data_dir)?;
        tracing::info!("Loaded address index: {}", address_index);

        // Create wallet (in-memory)
        let mut wallet = BdkWallet::create(external_desc, internal_desc)
            .network(network)
            .create_wallet_no_persist()
            .map_err(|e| Error::Wallet(format!("Failed to create wallet: {}", e)))?;

        // Reveal addresses up to the persisted index to sync state
        for _ in 0..address_index {
            wallet.reveal_next_address(KeychainKind::External);
        }

        Ok(Self {
            inner: Mutex::new(wallet),
            electrum_url,
            network,
            operator_secret,
            operator_pubkey,
            block_height: Mutex::new(0),
            block_hash: Mutex::new([0u8; 32]),
            data_dir,
            address_index: Mutex::new(address_index),
        })
    }

    /// Load address index from disk
    fn load_address_index(data_dir: &PathBuf) -> Result<u32, Error> {
        let index_file = data_dir.join("address_index.txt");
        if !index_file.exists() {
            return Ok(0);
        }
        let content = fs::read_to_string(&index_file)
            .map_err(|e| Error::Wallet(format!("Failed to read address index: {}", e)))?;
        let trimmed = content.trim();
        // Handle race condition where file exists but is empty (during atomic write)
        if trimmed.is_empty() {
            return Ok(0);
        }
        trimmed
            .parse()
            .map_err(|e| Error::Wallet(format!("Failed to parse address index: {}", e)))
    }

    /// Save address index to disk
    fn save_address_index(data_dir: &PathBuf, index: u32) -> Result<(), Error> {
        let index_file = data_dir.join("address_index.txt");
        fs::write(&index_file, index.to_string())
            .map_err(|e| Error::Wallet(format!("Failed to write address index: {}", e)))?;
        Ok(())
    }

    /// Get the operator's public key
    pub fn operator_pubkey(&self) -> PublicKey {
        self.operator_pubkey
    }

    /// Get the operator's secret key
    pub fn operator_secret(&self) -> SecretKey {
        self.operator_secret
    }

    /// Look up an on-chain outpoint and report its value (sats) and
    /// confirmation depth. Returns `Ok(None)` if the tx is known but the
    /// vout is out of range, or if the vout is already spent. Used by
    /// quorum members to verify the reserves UTXO referenced by a first
    /// `QuorumBegin` before co-signing.
    ///
    /// Async path: this is the cosign-handler hot path. A blocking
    /// version of this function held a tokio worker for four serial
    /// HTTP round-trips, which under load (16 daemons all hitting
    /// Phase 4 simultaneously) saturated the runtime worker pool and
    /// caused the 5s cosign deadline to time out across the cluster
    /// — even when the operator's electrs already saw the tx confirmed.
    /// Fetch a transaction from esplora by txid. Returns `None` if the
    /// txid isn't on-chain (or in mempool). Used by fraud-proof verifiers
    /// that need the raw TX bytes (e.g., `WinnerCollateralDeviation`).
    pub async fn get_transaction(
        &self,
        txid: bitcoin::Txid,
    ) -> Result<Option<bitcoin::Transaction>, Error> {
        let client = EsploraBuilder::new(&self.electrum_url)
            .build_async()
            .map_err(|e| Error::Wallet(format!("Failed to build esplora client: {}", e)))?;
        client
            .get_tx(&txid)
            .await
            .map_err(|e| Error::Wallet(format!("Failed to fetch tx: {}", e)))
    }

    pub async fn get_outpoint_value_and_confs(
        &self,
        txid: bitcoin::Txid,
        vout: u32,
    ) -> Result<Option<(u64, u32)>, Error> {
        let client = EsploraBuilder::new(&self.electrum_url)
            .build_async()
            .map_err(|e| Error::Wallet(format!("Failed to build esplora client: {}", e)))?;

        // Transaction lookup — None if the tx doesn't exist on-chain yet.
        let tx = match client
            .get_tx(&txid)
            .await
            .map_err(|e| Error::Wallet(format!("Failed to fetch tx: {}", e)))?
        {
            Some(t) => t,
            None => return Ok(None),
        };

        let output = match tx.output.get(vout as usize) {
            Some(o) => o,
            None => return Ok(None),
        };
        let value_sats = output.value.to_sat();

        // Check unspent.
        let spent = client
            .get_output_status(&txid, vout as u64)
            .await
            .map_err(|e| Error::Wallet(format!("Failed to get output status: {}", e)))?
            .map(|s| s.spent)
            .unwrap_or(false);
        if spent {
            return Ok(None);
        }

        // Confirmation depth. A TxStatus without a block_height means
        // mempool / unconfirmed → 0 confirmations.
        let status = client
            .get_tx_status(&txid)
            .await
            .map_err(|e| Error::Wallet(format!("Failed to get tx status: {}", e)))?;
        let tx_height = match status.block_height {
            Some(h) => h,
            None => return Ok(Some((value_sats, 0))),
        };
        let tip = client
            .get_height()
            .await
            .map_err(|e| Error::Wallet(format!("Failed to get chain tip: {}", e)))?;
        // Tip - tx_height + 1 (a tx in the tip block itself is 1 confirmation).
        let confs = tip.saturating_sub(tx_height).saturating_add(1);
        Ok(Some((value_sats, confs)))
    }

    /// Fetch current block info from esplora and update cache
    pub fn fetch_block_info(&self) -> Result<(u32, [u8; 32]), Error> {
        let client = EsploraBuilder::new(&self.electrum_url).build_blocking();

        let height = client
            .get_height()
            .map_err(|e| Error::Wallet(format!("Failed to get block height: {}", e)))?;

        let hash = client
            .get_block_hash(height)
            .map_err(|e| Error::Wallet(format!("Failed to get block hash: {}", e)))?;

        let hash_bytes: [u8; 32] = *hash.as_ref();

        *self.block_height.lock().unwrap() = height;
        *self.block_hash.lock().unwrap() = hash_bytes;

        Ok((height, hash_bytes))
    }

    /// Get the current block height (fetches from chain if not yet known)
    pub fn get_block_height(&self) -> Result<u32, Error> {
        let cached = *self.block_height.lock().unwrap();
        if cached == 0 {
            // Fetch fresh block info
            let (height, _) = self.fetch_block_info()?;
            Ok(height)
        } else {
            Ok(cached)
        }
    }

    /// Get the current block hash (fetches from chain if not yet known)
    pub fn get_block_hash(&self) -> Result<[u8; 32], Error> {
        let cached = *self.block_hash.lock().unwrap();
        if cached == [0u8; 32] {
            // Fetch fresh block info
            let (_, hash) = self.fetch_block_info()?;
            Ok(hash)
        } else {
            Ok(cached)
        }
    }

    /// Resolve an arbitrary block hash against the verifier's confirmed
    /// chain. Returns `Some(height)` iff the block is in our best
    /// chain; `None` if unknown / not confirmed / network error.
    /// Network errors map to `None` deliberately — fraud-proof verifiers
    /// reject on `None`, so the conservative failure mode is "not
    /// confirmed" rather than crashing the verifier.
    pub fn confirms_block(&self, block_hash: &[u8; 32]) -> Option<u32> {
        let client = EsploraBuilder::new(&self.electrum_url).build_blocking();
        let bh = bitcoin::BlockHash::from_byte_array(*block_hash);
        match client.get_block_status(&bh) {
            Ok(status) if status.in_best_chain => status.height,
            _ => None,
        }
    }

    /// Get the wallet balance (non-reserves funds)
    pub fn get_wallet_balance(&self) -> Result<u64, Error> {
        let wallet = self.inner.lock().unwrap();
        let balance = wallet.balance();
        Ok(balance.total().to_sat())
    }

    /// Get the network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get a new receiving address
    pub fn get_new_address(&self) -> Result<Address, Error> {
        let mut wallet = self.inner.lock().unwrap();

        // Reload address index from disk in case another process updated it
        let disk_index = Self::load_address_index(&self.data_dir)?;
        let mut index = self.address_index.lock().unwrap();

        // If disk has a higher index, catch up by revealing more addresses
        while *index < disk_index {
            wallet.reveal_next_address(KeychainKind::External);
            *index += 1;
        }

        // Now reveal the next address
        let addr = wallet.reveal_next_address(KeychainKind::External);

        // Increment and persist address index
        *index += 1;
        Self::save_address_index(&self.data_dir, *index)?;

        Ok(addr.address)
    }

    /// Lightweight sync: just update block height and hash (2 HTTP requests).
    /// Call this frequently (e.g. every 5s) to keep block info fresh.
    pub fn sync_block_height(&self) -> Result<(), Error> {
        let client = EsploraBuilder::new(&self.electrum_url).build_blocking();

        let height = client
            .get_height()
            .map_err(|e| Error::Wallet(format!("Failed to get block height: {}", e)))?;

        *self.block_height.lock().unwrap() = height;

        if let Ok(hash) = client.get_block_hash(height) {
            *self.block_hash.lock().unwrap() = *hash.as_ref();
        }

        tracing::debug!("Block height synced: {}", height);
        Ok(())
    }

    /// Full wallet sync: update block height, hash, and all script pubkeys.
    /// Expensive (~40 HTTP requests). Call infrequently (e.g. every 30–60s).
    pub fn sync(&self) -> Result<(), Error> {
        // First update block info
        self.sync_block_height()?;

        let client = EsploraBuilder::new(&self.electrum_url).build_blocking();
        let height = *self.block_height.lock().unwrap();

        // Sync all wallet script pubkeys
        let mut wallet = self.inner.lock().unwrap();

        let spks: Vec<ScriptBuf> = wallet
            .all_unbounded_spk_iters()
            .into_iter()
            .flat_map(|(_, iter)| iter.take(20).map(|(_, spk)| spk))
            .collect();

        if !spks.is_empty() {
            let request = SyncRequest::builder().spks(spks).build();

            let update = client
                .sync(request, 5)
                .map_err(|e| Error::Wallet(format!("Sync failed: {}", e)))?;

            wallet
                .apply_update(update)
                .map_err(|e| Error::Wallet(format!("Failed to apply update: {}", e)))?;
        }

        tracing::info!("Wallet synced at height {}", height);
        Ok(())
    }

    /// Build a reserves redeem script
    ///
    /// Structure:
    /// ```text
    /// OP_IF
    ///     <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
    ///     <operator_pubkey> OP_CHECKSIG
    /// OP_ELSE
    ///     <threshold> <partner1> ... <partnerN> <N> OP_CHECKMULTISIG
    /// OP_ENDIF
    /// ```
    /// Create a Taproot reserves output with quorum-based spending
    ///
    /// This creates a P2TR output with tiered spending policies:
    /// - Tier 0: Majority of quorum + operator (immediate)
    /// - Tier 1: Operator only after first quorum member expires
    /// - Tier 2+: Degraded tiers with longer timelocks
    ///
    /// # Arguments
    /// * `amount_sats` - Amount in satoshis for the reserves
    /// * `quorum_members` - The quorum member pubkeys (will be voters)
    /// * `member_expiries` - Block heights when each quorum member expires (parallel to quorum_members)
    /// * `ledger_hash` - The current ledger hash to commit to in the Taproot tree
    ///
    /// # Returns
    /// A `TaprootReservesCreateResult` with the transaction and reserves info
    /// Broadcast a transaction.
    ///
    /// After a successful broadcast, the tx is folded into BDK's
    /// in-memory mempool view via `apply_unconfirmed_txs` so the next
    /// coin-selection call doesn't re-pick the same input. Without this,
    /// rapid back-to-back broadcasts (e.g. setup.sh creating multiple
    /// reserves UTXOs in a tight loop) race against esplora indexing +
    /// BDK sync — `wallet.create_tx` selects an input that's already
    /// pending in mempool, bitcoind rejects with
    /// `bad-txns-inputs-missingorspent`. Telling BDK directly avoids
    /// the round-trip entirely.
    ///
    /// `last_seen` is the unix timestamp at which we observed this tx.
    /// BDK uses it to order conflicting unconfirmed txs (later-seen
    /// wins). Real wall-clock now() is the right value here.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, Error> {
        let client = EsploraBuilder::new(&self.electrum_url).build_blocking();

        client
            .broadcast(tx)
            .map_err(|e| Error::Wallet(format!("Broadcast failed: {}", e)))?;

        let txid = tx.compute_txid();
        tracing::info!("Broadcast tx: {}", txid);

        // Stamp the tx into BDK's mempool view immediately. The lock is
        // already exclusively held by us (every other wallet caller goes
        // through this Mutex), so this is contention-free.
        let last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut wallet = self
            .inner
            .lock()
            .map_err(|e| Error::Wallet(format!("BDK wallet mutex poisoned: {}", e)))?;
        wallet.apply_unconfirmed_txs(std::iter::once((tx.clone(), last_seen)));

        Ok(txid)
    }

    /// Find an unspent UTXO for a given script pubkey
    ///
    /// Returns (OutPoint, amount) if found, None if no unspent output exists.
    pub fn find_utxo_for_script(
        &self,
        script: &bitcoin::ScriptBuf,
    ) -> Result<Option<(OutPoint, u64)>, Error> {
        use bitcoin::hashes::{sha256, Hash};

        // Compute the scripthash in non-reversed format for esplora API.
        // The esplora-client library's scripthash_txs uses bitcoin's {:x}
        // format which is byte-reversed, but electrs expects the non-reversed
        // SHA256 hash.  Query the API directly instead.
        let script_hash = sha256::Hash::hash(script.as_bytes());
        let script_hash_hex = hex::encode(script_hash.to_byte_array());

        let url = format!("{}/scripthash/{}/txs", self.electrum_url, script_hash_hex);

        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Wallet(format!("Failed to create HTTP client: {}", e)))?;

        let response = http
            .get(&url)
            .send()
            .map_err(|e| Error::Wallet(format!("Failed to query esplora: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Wallet(format!(
                "Esplora returned status {}: {}",
                response.status(),
                response
                    .text()
                    .unwrap_or_else(|_| "unknown error".to_string())
            )));
        }

        let txs: Vec<bdk_esplora::esplora_client::Tx> = response
            .json()
            .map_err(|e| Error::Wallet(format!("Failed to parse esplora response: {}", e)))?;

        let esplora = EsploraBuilder::new(&self.electrum_url).build_blocking();

        for tx in &txs {
            for (vout, output) in tx.vout.iter().enumerate() {
                if &output.scriptpubkey == script {
                    let outpoint = OutPoint::new(tx.txid, vout as u32);
                    let status = esplora
                        .get_output_status(&tx.txid, vout as u64)
                        .map_err(|e| Error::Wallet(format!("Failed to check output: {:?}", e)))?;
                    if status.map(|s| !s.spent).unwrap_or(true) {
                        return Ok(Some((outpoint, output.value)));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Send an on-chain withdrawal with OP_RETURN commitment
    ///
    /// Builds and broadcasts a transaction that:
    /// 1. Sends the specified amount to the destination address
    /// 2. Includes an OP_RETURN output with the withdrawal_id commitment
    pub fn send_withdrawal(
        &self,
        withdrawal: &deposits_core::types::OnChainWithdrawal,
    ) -> Result<String, Error> {
        // Parse the destination address
        let dest_address = withdrawal
            .destination_address
            .parse::<Address<_>>()
            .map_err(|e| Error::Wallet(format!("Invalid destination address: {}", e)))?
            .require_network(self.network)
            .map_err(|e| Error::Wallet(format!("Address network mismatch: {}", e)))?;

        // Build OP_RETURN script with withdrawal commitment
        let op_return_data = withdrawal.op_return_data();
        let op_return_script = ScriptBuilder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(op_return_data)
            .into_script();

        // Build the transaction
        let mut wallet = self.inner.lock().unwrap();

        let mut psbt = {
            let mut builder = wallet.build_tx();
            builder
                // Main payment output
                .add_recipient(
                    dest_address.script_pubkey(),
                    Amount::from_sat(withdrawal.amount_sats),
                )
                // OP_RETURN commitment output (0 value)
                .add_recipient(op_return_script, Amount::ZERO)
                .fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
            builder
                .finish()
                .map_err(|e| Error::Wallet(format!("Failed to build withdrawal tx: {}", e)))?
        };

        // Sign the transaction
        wallet
            .sign(&mut psbt, SignOptions::default())
            .map_err(|e| Error::Wallet(format!("Failed to sign withdrawal tx: {}", e)))?;

        let tx = psbt
            .extract_tx()
            .map_err(|e| Error::Wallet(format!("Failed to extract withdrawal tx: {}", e)))?;

        // Release wallet lock before broadcast
        drop(wallet);

        // Broadcast the transaction
        let client = EsploraBuilder::new(&self.electrum_url).build_blocking();

        client
            .broadcast(&tx)
            .map_err(|e| Error::Wallet(format!("Failed to broadcast withdrawal: {}", e)))?;

        let txid = tx.compute_txid();
        tracing::info!(
            "Broadcast withdrawal tx: {} (amount: {} sats, op_return: {})",
            txid,
            withdrawal.amount_sats,
            hex::encode(&withdrawal.withdrawal_id[..8])
        );

        Ok(txid.to_string())
    }

    /// Check if an address has received funds
    ///
    /// Returns Some((txid, amount_sats)) for the first unspent transaction to this address,
    /// or None if no funds have been received.
    pub fn check_address_received(
        &self,
        address: &Address<bitcoin::address::NetworkUnchecked>,
    ) -> Result<Option<(String, u64)>, Error> {
        use bitcoin::hashes::{sha256, Hash};

        // Get the script pubkey for this address
        // Use assume_checked() since we trust addresses from our deposit offers
        let address_checked = address.clone().assume_checked();
        let script_pubkey = address_checked.script_pubkey();

        // Compute the scripthash in non-reversed format for esplora API
        // Note: The esplora-client library uses bitcoin's {:x} format which is byte-reversed,
        // but electrs expects the non-reversed SHA256 hash.
        let script_hash = sha256::Hash::hash(script_pubkey.as_bytes());
        let hash_bytes = script_hash.to_byte_array();
        let script_hash_hex = hex::encode(hash_bytes);

        // Query esplora directly with correct hash format
        let url = format!("{}/scripthash/{}/txs", self.electrum_url, script_hash_hex);

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Wallet(format!("Failed to create HTTP client: {}", e)))?;

        let response = client
            .get(&url)
            .send()
            .map_err(|e| Error::Wallet(format!("Failed to query esplora: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Wallet(format!(
                "Esplora returned status {}: {}",
                response.status(),
                response
                    .text()
                    .unwrap_or_else(|_| "unknown error".to_string())
            )));
        }

        // Parse the JSON response
        let txs: Vec<bdk_esplora::esplora_client::Tx> = response
            .json()
            .map_err(|e| Error::Wallet(format!("Failed to parse esplora response: {}", e)))?;

        // Look for confirmed transactions that have outputs to this address
        for tx in txs {
            // Find outputs that match our address
            for (vout, output) in tx.vout.iter().enumerate() {
                if output.scriptpubkey == script_pubkey {
                    // Found a matching output
                    tracing::info!(
                        "Found funding tx {} vout {} with {} sats",
                        tx.txid,
                        vout,
                        output.value
                    );
                    return Ok(Some((tx.txid.to_string(), output.value)));
                }
            }
        }

        Ok(None)
    }

    /// Create a mock wallet for testing
    #[cfg(test)]
    pub fn new_mock(data_dir: PathBuf) -> Self {
        let secp = Secp256k1::new();
        let operator_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let operator_pubkey = PublicKey::from_secret_key(&secp, &operator_secret);

        // Create a minimal wallet with a simple descriptor
        let desc = "wpkh(tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF/84'/1'/0'/0/*)";
        let change_desc = "wpkh(tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF/84'/1'/0'/1/*)";

        let wallet = BdkWallet::create(desc, change_desc)
            .network(Network::Signet)
            .create_wallet_no_persist()
            .expect("Failed to create mock wallet");

        Self {
            inner: Mutex::new(wallet),
            electrum_url: "".to_string(),
            network: Network::Signet,
            operator_secret,
            operator_pubkey,
            block_height: Mutex::new(800_000),
            block_hash: Mutex::new([0u8; 32]),
            data_dir,
            address_index: Mutex::new(0),
        }
    }
}

/// Output of building a Taproot Q=N activation tx (used by
/// `LedgerWallet::build_activation_tx`). Stays in this module because
/// it embeds `TaprootReservesOutput` which is shared between the
/// wallet and ledger-wallet code paths.
#[derive(Debug, Clone)]
pub struct TaprootReservesCreateResult {
    /// The outpoint (valid after broadcast)
    pub outpoint: OutPoint,

    /// The P2TR address
    pub address: Address,

    /// Amount in satoshis
    pub amount: u64,

    /// The signed transaction
    pub tx: Transaction,

    /// The Taproot reserves output (contains spend info)
    pub taproot_output: TaprootReservesOutput,

    /// Block height when first quorum member expires (operator-only spend unlocks)
    pub quorum_expiry: u32,

    /// The ledger hash committed to in the Taproot tree
    pub ledger_hash: [u8; 32],
}
