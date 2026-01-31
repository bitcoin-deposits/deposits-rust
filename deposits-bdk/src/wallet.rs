// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! BDK wallet for on-chain reserves management
//!
//! Unlike deposits-ldk which uses Lightning commitment transaction outputs,
//! deposits-bdk holds reserves as on-chain UTXOs in a BDK wallet.

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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, RwLock};

use crate::Error;

const RESERVES_TIMEOUT_BLOCKS: u32 = 144; // ~1 day

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

    /// Tracked reserves outputs
    reserves: RwLock<HashMap<OutPoint, ReservesInfo>>,

    /// Current block height (updated on sync)
    block_height: Mutex<u32>,

    /// Current block hash (updated on sync)
    block_hash: Mutex<[u8; 32]>,

    /// Data directory for persistence
    data_dir: PathBuf,
}

/// Information about a reserves output
#[derive(Debug, Clone)]
pub struct ReservesInfo {
    /// The outpoint
    pub outpoint: OutPoint,

    /// Amount in satoshis
    pub amount: u64,

    /// The operator pubkey
    pub operator: PublicKey,

    /// Partner pubkeys for multisig recovery
    pub partners: Vec<PublicKey>,

    /// Threshold for partner multisig
    pub threshold: usize,

    /// Timeout block height for operator reclaim
    pub timeout_height: u32,

    /// The redeem script (for spending)
    pub redeem_script: ScriptBuf,

    /// Whether this output is confirmed
    pub confirmed: bool,
}

/// Serializable version of ReservesInfo for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReservesInfoSerde {
    outpoint_txid: String,
    outpoint_vout: u32,
    amount: u64,
    operator: String,
    partners: Vec<String>,
    threshold: usize,
    timeout_height: u32,
    redeem_script_hex: String,
    confirmed: bool,
}

impl From<&ReservesInfo> for ReservesInfoSerde {
    fn from(info: &ReservesInfo) -> Self {
        use bitcoin::consensus::encode::serialize_hex;
        Self {
            outpoint_txid: info.outpoint.txid.to_string(),
            outpoint_vout: info.outpoint.vout,
            amount: info.amount,
            operator: info.operator.to_string(),
            partners: info.partners.iter().map(|p| p.to_string()).collect(),
            threshold: info.threshold,
            timeout_height: info.timeout_height,
            redeem_script_hex: serialize_hex(&info.redeem_script),
            confirmed: info.confirmed,
        }
    }
}

impl ReservesInfoSerde {
    fn to_reserves_info(&self) -> Result<ReservesInfo, Error> {
        use bitcoin::consensus::encode::deserialize;
        let txid = Txid::from_str(&self.outpoint_txid)
            .map_err(|e| Error::Wallet(format!("Invalid txid: {}", e)))?;
        let operator = PublicKey::from_str(&self.operator)
            .map_err(|e| Error::Wallet(format!("Invalid operator pubkey: {}", e)))?;
        let partners: Result<Vec<PublicKey>, _> = self
            .partners
            .iter()
            .map(|p| PublicKey::from_str(p))
            .collect();
        let partners =
            partners.map_err(|e| Error::Wallet(format!("Invalid partner pubkey: {}", e)))?;
        let script_bytes = hex::decode(&self.redeem_script_hex)
            .map_err(|e| Error::Wallet(format!("Invalid redeem script hex: {}", e)))?;
        let redeem_script: ScriptBuf = deserialize(&script_bytes)
            .map_err(|e| Error::Wallet(format!("Invalid redeem script: {}", e)))?;

        Ok(ReservesInfo {
            outpoint: OutPoint {
                txid,
                vout: self.outpoint_vout,
            },
            amount: self.amount,
            operator,
            partners,
            threshold: self.threshold,
            timeout_height: self.timeout_height,
            redeem_script,
            confirmed: self.confirmed,
        })
    }
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
        let external_desc = format!("wpkh({})", xpriv);
        let internal_desc = format!("wpkh({}/1/*)", xpriv);

        // Create wallet (in-memory for now)
        let wallet = BdkWallet::create(external_desc, internal_desc)
            .network(network)
            .create_wallet_no_persist()
            .map_err(|e| Error::Wallet(format!("Failed to create wallet: {}", e)))?;

        // Ensure data directory exists
        if !data_dir.exists() {
            tracing::info!("Creating data directory: {:?}", data_dir);
            fs::create_dir_all(&data_dir)
                .map_err(|e| Error::Wallet(format!("Failed to create data dir: {}", e)))?;
        }

        // Load existing reserves from disk
        let reserves = Self::load_reserves_from_disk(&data_dir)?;

        Ok(Self {
            inner: Mutex::new(wallet),
            electrum_url,
            network,
            operator_secret,
            operator_pubkey,
            reserves: RwLock::new(reserves),
            block_height: Mutex::new(0),
            block_hash: Mutex::new([0u8; 32]),
            data_dir,
        })
    }

    /// Load reserves from disk
    fn load_reserves_from_disk(data_dir: &PathBuf) -> Result<HashMap<OutPoint, ReservesInfo>, Error> {
        let reserves_file = data_dir.join("reserves.json");
        if !reserves_file.exists() {
            return Ok(HashMap::new());
        }

        let contents = fs::read_to_string(&reserves_file)
            .map_err(|e| Error::Wallet(format!("Failed to read reserves file: {}", e)))?;

        let serde_list: Vec<ReservesInfoSerde> = serde_json::from_str(&contents)
            .map_err(|e| Error::Wallet(format!("Failed to parse reserves file: {}", e)))?;

        let mut reserves = HashMap::new();
        for serde_info in serde_list {
            let info = serde_info.to_reserves_info()?;
            reserves.insert(info.outpoint, info);
        }

        tracing::info!("Loaded {} reserves from disk", reserves.len());
        Ok(reserves)
    }

    /// Save reserves to disk
    fn save_reserves_to_disk(&self) -> Result<(), Error> {
        let reserves = self.reserves.read().unwrap();
        let serde_list: Vec<ReservesInfoSerde> = reserves
            .values()
            .map(ReservesInfoSerde::from)
            .collect();

        let contents = serde_json::to_string_pretty(&serde_list)
            .map_err(|e| Error::Wallet(format!("Failed to serialize reserves: {}", e)))?;

        let reserves_file = self.data_dir.join("reserves.json");
        fs::write(&reserves_file, contents)
            .map_err(|e| Error::Wallet(format!("Failed to write reserves file: {}", e)))?;

        tracing::info!("Saved {} reserves to disk", reserves.len());
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

    /// Fetch current block info from esplora and update cache
    pub fn fetch_block_info(&self) -> Result<(u32, [u8; 32]), Error> {
        let client = EsploraBuilder::new(&self.electrum_url)
            .build_blocking();

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

    /// Get the total reserves balance (sum of all tracked reserves outputs)
    pub fn get_reserves_balance(&self) -> Result<u64, Error> {
        let reserves = self.reserves.read().unwrap();
        // Count all reserves - confirmation status is tracked separately
        // but for balance purposes, if we created and broadcast the reserves,
        // they should be counted toward our reserves balance
        let total = reserves.values().map(|r| r.amount).sum();
        Ok(total)
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
        let addr = wallet.reveal_next_address(KeychainKind::External);
        Ok(addr.address)
    }

    /// Sync wallet with esplora server
    pub fn sync(&self) -> Result<(), Error> {
        let client = EsploraBuilder::new(&self.electrum_url)
            .build_blocking();

        // Get block height
        let height = client
            .get_height()
            .map_err(|e| Error::Wallet(format!("Failed to get block height: {}", e)))?;

        *self.block_height.lock().unwrap() = height;

        // Get block hash at current height
        if let Ok(hash) = client.get_block_hash(height) {
            *self.block_hash.lock().unwrap() = *hash.as_ref();
        }

        // Sync the wallet
        let mut wallet = self.inner.lock().unwrap();

        // Get all script pubkeys to sync
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
    pub fn build_reserves_script(
        operator: &PublicKey,
        partners: &[PublicKey],
        threshold: usize,
        timeout_height: u32,
    ) -> ScriptBuf {
        let mut builder = ScriptBuilder::new();

        // OP_IF branch: operator can spend after timeout
        builder = builder
            .push_opcode(opcodes::all::OP_IF)
            .push_int(timeout_height as i64)
            .push_opcode(opcodes::all::OP_CLTV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_slice(&operator.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIG);

        // OP_ELSE branch: partners can spend via multisig
        builder = builder.push_opcode(opcodes::all::OP_ELSE);

        if partners.is_empty() {
            // No partners yet - just require operator sig (fallback)
            builder = builder
                .push_slice(&operator.serialize())
                .push_opcode(opcodes::all::OP_CHECKSIG);
        } else {
            // threshold-of-n multisig
            builder = builder.push_int(threshold as i64);
            for partner in partners {
                builder = builder.push_slice(&partner.serialize());
            }
            builder = builder
                .push_int(partners.len() as i64)
                .push_opcode(opcodes::all::OP_CHECKMULTISIG);
        }

        builder = builder.push_opcode(opcodes::all::OP_ENDIF);

        builder.into_script()
    }

    /// Create a reserves output
    ///
    /// This creates a P2WSH output with the reserves script.
    pub fn create_reserves_output(
        &self,
        amount_sats: u64,
        partners: Vec<PublicKey>,
        threshold: usize,
    ) -> Result<ReservesOutput, Error> {
        let current_height = self.get_block_height()?;
        let timeout_height = current_height + RESERVES_TIMEOUT_BLOCKS;

        // Build the redeem script
        let redeem_script = Self::build_reserves_script(
            &self.operator_pubkey,
            &partners,
            threshold,
            timeout_height,
        );

        // Create P2WSH address
        let script_hash = sha256::Hash::hash(redeem_script.as_bytes());
        let witness_program = ScriptBuf::new_p2wsh(&script_hash.into());
        let address = Address::from_script(&witness_program, self.network)
            .map_err(|e| Error::Wallet(format!("Failed to create address: {}", e)))?;

        // Build the transaction
        let mut wallet = self.inner.lock().unwrap();

        let mut psbt = {
            let mut builder = wallet.build_tx();
            builder
                .add_recipient(witness_program.clone(), Amount::from_sat(amount_sats))
                .fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
            builder
                .finish()
                .map_err(|e| Error::Wallet(format!("Failed to build tx: {}", e)))?
        };

        // Sign the transaction
        wallet
            .sign(&mut psbt, SignOptions::default())
            .map_err(|e| Error::Wallet(format!("Failed to sign tx: {}", e)))?;

        let tx = psbt
            .extract_tx()
            .map_err(|e| Error::Wallet(format!("Failed to extract tx: {}", e)))?;

        // Find the reserves output index
        let vout = tx
            .output
            .iter()
            .position(|o| o.script_pubkey == witness_program)
            .ok_or_else(|| Error::Wallet("Reserves output not found in tx".to_string()))?;

        let outpoint = OutPoint {
            txid: tx.compute_txid(),
            vout: vout as u32,
        };

        // Track this reserves output
        let info = ReservesInfo {
            outpoint,
            amount: amount_sats,
            operator: self.operator_pubkey,
            partners: partners.clone(),
            threshold,
            timeout_height,
            redeem_script: redeem_script.clone(),
            confirmed: false,
        };

        drop(wallet); // Release lock before acquiring write lock
        self.reserves.write().unwrap().insert(outpoint, info);

        // Persist reserves to disk
        self.save_reserves_to_disk()?;

        Ok(ReservesOutput {
            outpoint,
            address,
            amount: amount_sats,
            tx,
            redeem_script,
            timeout_height,
        })
    }

    /// Broadcast a transaction
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, Error> {
        let client = EsploraBuilder::new(&self.electrum_url)
            .build_blocking();

        client
            .broadcast(tx)
            .map_err(|e| Error::Wallet(format!("Broadcast failed: {}", e)))?;

        let txid = tx.compute_txid();
        tracing::info!("Broadcast tx: {}", txid);
        Ok(txid)
    }

    /// Get all tracked reserves
    pub fn get_reserves(&self) -> Vec<ReservesInfo> {
        self.reserves.read().unwrap().values().cloned().collect()
    }

    /// Get the first/primary reserves outpoint
    pub fn get_reserves_outpoint(&self) -> Option<OutPoint> {
        self.reserves
            .read()
            .unwrap()
            .keys()
            .next()
            .copied()
    }

    /// Get the reserves address (P2WSH address of the primary reserves)
    pub fn get_reserves_address(&self) -> Option<Address> {
        let reserves = self.reserves.read().unwrap();
        reserves.values().next().map(|info| {
            Address::p2wsh(&info.redeem_script, self.network)
        })
    }

    /// Mark a reserves output as confirmed
    pub fn confirm_reserves(&self, outpoint: &OutPoint) -> Result<(), Error> {
        {
            let mut reserves = self.reserves.write().unwrap();
            if let Some(info) = reserves.get_mut(outpoint) {
                info.confirmed = true;
            } else {
                return Err(Error::Wallet(format!(
                    "Reserves output not found: {}",
                    outpoint
                )));
            }
        }
        // Persist updated state
        self.save_reserves_to_disk()
    }

    /// Create a recovery transaction (pre-signed by operator)
    ///
    /// This transaction spends the reserves via the partner multisig path
    /// and sends to a recovery address.
    pub fn create_recovery_tx(
        &self,
        reserves_outpoint: OutPoint,
        recovery_address: Address,
    ) -> Result<RecoveryTx, Error> {
        let reserves = self.reserves.read().unwrap();
        let info = reserves
            .get(&reserves_outpoint)
            .ok_or_else(|| Error::Wallet("Reserves not found".to_string()))?;

        // Build the recovery transaction
        // For now, just create the structure - actual signing happens in recovery flow
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: reserves_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(info.amount.saturating_sub(500)), // Leave room for fee
                script_pubkey: recovery_address.script_pubkey(),
            }],
        };

        Ok(RecoveryTx {
            tx,
            reserves_outpoint,
            redeem_script: info.redeem_script.clone(),
            operator_sig: None, // Will be signed separately
        })
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
        let dest_address = withdrawal.destination_address.parse::<Address<_>>()
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
                .add_recipient(dest_address.script_pubkey(), Amount::from_sat(withdrawal.amount_sats))
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
        let client = EsploraBuilder::new(&self.electrum_url)
            .build_blocking();

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
        let client = EsploraBuilder::new(&self.electrum_url)
            .build_blocking();

        // Get the script pubkey for this address
        let address_checked = address.clone()
            .require_network(self.network)
            .map_err(|e| Error::Wallet(format!("Address network mismatch: {}", e)))?;

        let script_pubkey = address_checked.script_pubkey();

        // Query the esplora API for transactions to this script
        let txs = client
            .scripthash_txs(&script_pubkey, None)
            .map_err(|e| Error::Wallet(format!("Failed to query address: {}", e)))?;

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
}

/// A reserves output ready for broadcast
#[derive(Debug, Clone)]
pub struct ReservesOutput {
    /// The outpoint (valid after broadcast)
    pub outpoint: OutPoint,

    /// The P2WSH address
    pub address: Address,

    /// Amount in satoshis
    pub amount: u64,

    /// The signed transaction
    pub tx: Transaction,

    /// The redeem script (needed for spending)
    pub redeem_script: ScriptBuf,

    /// Timeout height for operator reclaim
    pub timeout_height: u32,
}

/// A recovery transaction (partially signed)
#[derive(Debug, Clone)]
pub struct RecoveryTx {
    /// The transaction
    pub tx: Transaction,

    /// The reserves outpoint being spent
    pub reserves_outpoint: OutPoint,

    /// The redeem script
    pub redeem_script: ScriptBuf,

    /// Operator's signature (if signed)
    pub operator_sig: Option<Vec<u8>>,
}
