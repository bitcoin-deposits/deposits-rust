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

    /// Our operator public key (cached from `signer.pubkey()` at
    /// construction). The corresponding secret never lives in the
    /// daemon — production signs route through the signer.
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

    /// Name of the protocol ruleset that this UTXO was built under.
    /// The reconstruction path looks this up via
    /// `deposits_core::ruleset::lookup` to recover the exact tier
    /// shape encoded in the on-chain script. Defaults to `"legacy"`
    /// when missing from persisted JSON — that's the on-chain shape
    /// for every pre-versioned QuorumBegin.
    pub ruleset_name: String,

    /// Whether this output is confirmed
    pub confirmed: bool,
}

impl Wallet {
    /// Create a new node-level wallet from a signer-issued master xpub.
    ///
    /// **Watch-only:** the descriptor is `wpkh(master_xpub/0/*)` +
    /// `wpkh(master_xpub/1/*)` — the daemon never holds the master
    /// xpriv. Signing on this wallet's UTXOs routes back through the
    /// signer via [`KeyPath::NodeWallet`]. The receive addresses match
    /// what the legacy seed-embedded `wpkh(xpriv/0/*)` produced — same
    /// `m/0/*` and `m/1/*` derivation, just sourced via `xpub_at_master`.
    pub fn new(
        signer: &dyn deposits_signer_api::Signer,
        network: Network,
        data_dir: PathBuf,
        electrum_url: String,
    ) -> Result<Self, Error> {
        let operator_pubkey = signer.pubkey();

        let master_xpub = signer
            .master_xpub()
            .map_err(|e| Error::Wallet(format!("master_xpub: {}", e)))?;

        let external_desc = format!("wpkh({}/0/*)", master_xpub);
        let internal_desc = format!("wpkh({}/1/*)", master_xpub);

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
    /// Fetch a transaction from the chain backend by txid. Returns `None` if
    /// the txid isn't on-chain (or in mempool). Used by fraud-proof verifiers
    /// that need the raw TX bytes (e.g., `WinnerCollateralDeviation`).
    ///
    /// Was async (used `build_async`) before the ChainBackend migration;
    /// now sync because the trait is sync (every backend impl blocks on
    /// HTTP/RPC anyway). Callers that were awaiting can drop `.await`.
    pub fn get_transaction(
        &self,
        txid: bitcoin::Txid,
    ) -> Result<Option<bitcoin::Transaction>, Error> {
        crate::chain_backend::from_env(&self.electrum_url).get_tx(&txid)
    }

    pub fn get_outpoint_value_and_confs(
        &self,
        txid: bitcoin::Txid,
        vout: u32,
    ) -> Result<Option<(u64, u32)>, Error> {
        let backend = crate::chain_backend::from_env(&self.electrum_url);

        // Transaction lookup — None if the tx doesn't exist on-chain yet.
        let tx = match backend.get_tx(&txid)? {
            Some(t) => t,
            None => return Ok(None),
        };

        let output = match tx.output.get(vout as usize) {
            Some(o) => o,
            None => return Ok(None),
        };
        let value_sats = output.value.to_sat();

        // Check unspent. is_output_unspent returns Some(true) for unspent,
        // Some(false) for spent, None for unknown (treat as unspent — the
        // tx exists per the get_tx above, so the output exists too).
        let unspent = backend
            .is_output_unspent(&txid, vout)?
            .unwrap_or(true);
        if !unspent {
            return Ok(None);
        }

        // Confirmation depth. None block height means mempool / unconfirmed
        // → 0 confirmations.
        let tx_height = match backend.get_tx_block_height(&txid)? {
            Some(h) => h,
            None => return Ok(Some((value_sats, 0))),
        };
        let tip = backend.get_tip_height()?;
        // Tip - tx_height + 1 (a tx in the tip block itself is 1 confirmation).
        let confs = tip.saturating_sub(tx_height).saturating_add(1);
        Ok(Some((value_sats, confs)))
    }

    /// Fetch current block info from esplora and update cache
    pub fn fetch_block_info(&self) -> Result<(u32, [u8; 32]), Error> {
        let backend = crate::chain_backend::from_env(&self.electrum_url);
        let height = backend.get_tip_height()?;
        let hash = backend.get_block_hash(height)?;
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
        let bh = bitcoin::BlockHash::from_byte_array(*block_hash);
        crate::chain_backend::from_env(&self.electrum_url)
            .get_block_height_if_in_best_chain(&bh)
            .ok()
            .flatten()
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

    /// Get the configured Esplora/Electrs URL. Exposed so CLI
    /// helpers can issue ad-hoc chain queries against the same
    /// endpoint the wallet uses (e.g. `disputes` checking the
    /// reserves address's funded/spent stats).
    pub fn electrum_url(&self) -> &str {
        &self.electrum_url
    }

    /// Return the lowest-indexed address that hasn't received funds.
    /// Doesn't burn through the address index — repeated calls without
    /// a receive return the same address. Used by the hub's status
    /// push to show a stable funding address per node without rolling
    /// it every 30s.
    pub fn peek_unused_address(&self) -> Result<Address, Error> {
        let mut wallet = self.inner.lock().unwrap();
        let info = wallet.next_unused_address(bdk_wallet::KeychainKind::External);
        Ok(info.address)
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
        let backend = crate::chain_backend::from_env(&self.electrum_url);
        let height = backend.get_tip_height()?;
        *self.block_height.lock().unwrap() = height;
        if let Ok(hash) = backend.get_block_hash(height) {
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
        let txid = crate::chain_backend::from_env(&self.electrum_url).broadcast_tx(tx)?;
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
        let utxo = crate::chain_backend::from_env(&self.electrum_url)
            .find_unspent_output_at(script.as_script())?;
        Ok(utxo.map(|u| (u.outpoint, u.value_sats)))
    }

    /// Send an on-chain withdrawal with OP_RETURN commitment
    ///
    /// Builds and broadcasts a transaction that:
    /// 1. Sends the specified amount to the destination address
    /// 2. Includes an OP_RETURN output with the withdrawal_id commitment
    pub fn send_withdrawal(
        &self,
        signer: &dyn deposits_signer_api::Signer,
        withdrawal: &deposits_core::types::OnChainWithdrawal,
    ) -> Result<String, Error> {
        use bdk_wallet::bitcoin::ecdsa::Signature as BtcEcdsaSignature;
        use bdk_wallet::bitcoin::hashes::Hash as _;
        use bdk_wallet::bitcoin::sighash::{EcdsaSighashType, SighashCache};
        use bdk_wallet::bitcoin::Witness;
        use deposits_signer_api::{KeyPath, SigPurpose, SigRole, SignContext};

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

        // Build the PSBT (no sign).
        let mut psbt = {
            let mut wallet = self.inner.lock().unwrap();
            let mut builder = wallet.build_tx();
            builder
                .add_recipient(
                    dest_address.script_pubkey(),
                    Amount::from_sat(withdrawal.amount_sats),
                )
                .add_recipient(op_return_script, Amount::ZERO)
                .fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
            builder
                .finish()
                .map_err(|e| Error::Wallet(format!("Failed to build withdrawal tx: {}", e)))?
        };

        // Per-input sighash signing routed through the signer. The
        // node-level wallet uses `wpkh(master_xpub/<change>/*)`, so
        // BDK's `bip32_derivation` records `[change, index]` relative
        // to master. Same shape as `LedgerWallet::build_activation_tx`,
        // just KeyPath::NodeWallet instead of KeyPath::Wallet.
        let unsigned_tx_clone = psbt.unsigned_tx.clone();
        let mut sighash_cache = SighashCache::new(&unsigned_tx_clone);
        let input_count = psbt.inputs.len();
        for input_index in 0..input_count {
            let (script_pubkey, amount, leaf_pubkey, change, leaf_index) = {
                let input = &psbt.inputs[input_index];
                let utxo = input.witness_utxo.as_ref().ok_or_else(|| {
                    Error::Wallet(format!(
                        "withdrawal PSBT input {} missing witness_utxo",
                        input_index
                    ))
                })?;
                let (pk, (_fp, path)) = input.bip32_derivation.iter().next().ok_or_else(|| {
                    Error::Wallet(format!(
                        "withdrawal PSBT input {} has no bip32_derivation entry",
                        input_index
                    ))
                })?;
                let comps: Vec<u32> = path.into_iter().map(|c| (*c).into()).collect();
                if comps.len() != 2 {
                    return Err(Error::Wallet(format!(
                        "withdrawal input {} bip32 path length {} != 2",
                        input_index,
                        comps.len()
                    )));
                }
                if comps[0] > 1 {
                    return Err(Error::Wallet(format!(
                        "withdrawal input {} change={} (must be 0 or 1)",
                        input_index, comps[0]
                    )));
                }
                (
                    utxo.script_pubkey.clone(),
                    utxo.value,
                    *pk,
                    comps[0] as u8,
                    comps[1],
                )
            };

            let sighash = sighash_cache
                .p2wpkh_signature_hash(input_index, &script_pubkey, amount, EcdsaSighashType::All)
                .map_err(|e| {
                    Error::Wallet(format!(
                        "withdrawal sighash for input {}: {:?}",
                        input_index, e
                    ))
                })?;

            let ctx = SignContext {
                role: SigRole::NoLedger,
                purpose: SigPurpose::OnchainSighash,
                key: KeyPath::NodeWallet {
                    change,
                    index: leaf_index,
                },
            };
            let sig = signer
                .ecdsa_sign_sighash(&ctx, sighash.as_byte_array())
                .map_err(|e| {
                    Error::Wallet(format!(
                        "withdrawal signer sign input {} (change={}, index={}): {}",
                        input_index, change, leaf_index, e
                    ))
                })?;

            let btc_sig = BtcEcdsaSignature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            };
            let mut witness = Witness::new();
            witness.push(btc_sig.serialize());
            witness.push(leaf_pubkey.serialize());
            psbt.inputs[input_index].final_script_witness = Some(witness);
            psbt.inputs[input_index].partial_sigs.clear();
            psbt.inputs[input_index].bip32_derivation.clear();
        }

        let tx = psbt
            .extract_tx()
            .map_err(|e| Error::Wallet(format!("Failed to extract withdrawal tx: {}", e)))?;

        // Broadcast the transaction
        let txid = crate::chain_backend::from_env(&self.electrum_url).broadcast_tx(&tx)?;
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
        let address_checked = address.clone().assume_checked();
        let script_pubkey = address_checked.script_pubkey();
        let utxo = crate::chain_backend::from_env(&self.electrum_url)
            .find_unspent_output_at(script_pubkey.as_script())?;
        Ok(utxo.map(|u| {
            tracing::info!(
                "Found funding tx {} vout {} with {} sats",
                u.outpoint.txid,
                u.outpoint.vout,
                u.value_sats
            );
            (u.outpoint.txid.to_string(), u.value_sats)
        }))
    }

    /// Create a mock wallet for testing. Used by both in-crate unit
    /// tests and the `actor_paths` integration test in
    /// `deposits-node/tests/`, so the cfg gate spans `test` (cargo
    /// test for the lib crate) and `not(test)` consumers must still
    /// see it for the integration-test target — leave it
    /// unconditionally-public; the body has no production callers.
    pub fn new_mock(data_dir: PathBuf) -> Self {
        let secp = Secp256k1::new();
        let operator_pubkey =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());

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
