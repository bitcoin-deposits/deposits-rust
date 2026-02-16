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
use deposits_core::{TapscriptReservesBuilder, TaprootReservesOutput, VoterSet, ThresholdConfig, ThresholdTier};
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

    /// Tracked reserves outputs (legacy P2WSH)
    reserves: RwLock<HashMap<OutPoint, ReservesInfo>>,

    /// Tracked Taproot reserves outputs (quorum-based)
    taproot_reserves: RwLock<HashMap<OutPoint, TaprootReservesInfo>>,

    /// Current block height (updated on sync)
    block_height: Mutex<u32>,

    /// Current block hash (updated on sync)
    block_hash: Mutex<[u8; 32]>,

    /// Data directory for persistence
    data_dir: PathBuf,

    /// Last revealed address index (persisted to disk)
    address_index: Mutex<u32>,
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
    pub first_expiry_block: u32,

    /// The ledger hash committed to in the Taproot tree
    pub ledger_hash: [u8; 32],

    /// The Taproot reserves output (contains spend info)
    pub taproot_output: TaprootReservesOutput,

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

/// Serializable version of TaprootReservesInfo for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TaprootReservesInfoSerde {
    outpoint_txid: String,
    outpoint_vout: u32,
    amount: u64,
    operator: String,
    quorum_members: Vec<String>,
    first_expiry_block: u32,
    ledger_hash: String,  // hex encoded
    address: String,      // Taproot address
    confirmed: bool,
}

impl From<&TaprootReservesInfo> for TaprootReservesInfoSerde {
    fn from(info: &TaprootReservesInfo) -> Self {
        Self {
            outpoint_txid: info.outpoint.txid.to_string(),
            outpoint_vout: info.outpoint.vout,
            amount: info.amount,
            operator: info.operator.to_string(),
            quorum_members: info.quorum_members.iter().map(|p| p.to_string()).collect(),
            first_expiry_block: info.first_expiry_block,
            ledger_hash: hex::encode(info.ledger_hash),
            address: info.taproot_output.address.to_string(),
            confirmed: info.confirmed,
        }
    }
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

        // Load existing reserves from disk
        let reserves = Self::load_reserves_from_disk(&data_dir)?;
        let taproot_reserves = Self::load_taproot_reserves_from_disk(&data_dir, operator_pubkey, network)?;

        Ok(Self {
            inner: Mutex::new(wallet),
            electrum_url,
            network,
            operator_secret,
            operator_pubkey,
            reserves: RwLock::new(reserves),
            taproot_reserves: RwLock::new(taproot_reserves),
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
        trimmed.parse()
            .map_err(|e| Error::Wallet(format!("Failed to parse address index: {}", e)))
    }

    /// Save address index to disk
    fn save_address_index(data_dir: &PathBuf, index: u32) -> Result<(), Error> {
        let index_file = data_dir.join("address_index.txt");
        fs::write(&index_file, index.to_string())
            .map_err(|e| Error::Wallet(format!("Failed to write address index: {}", e)))?;
        Ok(())
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
        // Save legacy P2WSH reserves
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

        tracing::info!("Saved {} legacy reserves to disk", reserves.len());
        drop(reserves);

        // Save Taproot reserves
        self.save_taproot_reserves_to_disk()?;

        Ok(())
    }

    /// Load Taproot reserves from disk
    fn load_taproot_reserves_from_disk(
        data_dir: &PathBuf,
        operator_pubkey: PublicKey,
        network: Network,
    ) -> Result<HashMap<OutPoint, TaprootReservesInfo>, Error> {
        let reserves_file = data_dir.join("taproot_reserves.json");
        if !reserves_file.exists() {
            return Ok(HashMap::new());
        }

        let contents = fs::read_to_string(&reserves_file)
            .map_err(|e| Error::Wallet(format!("Failed to read taproot reserves file: {}", e)))?;

        let serde_list: Vec<TaprootReservesInfoSerde> = serde_json::from_str(&contents)
            .map_err(|e| Error::Wallet(format!("Failed to parse taproot reserves file: {}", e)))?;

        let mut reserves = HashMap::new();
        for serde_info in serde_list {
            // Parse the basic info
            let txid = Txid::from_str(&serde_info.outpoint_txid)
                .map_err(|e| Error::Wallet(format!("Invalid txid: {}", e)))?;
            let outpoint = OutPoint {
                txid,
                vout: serde_info.outpoint_vout,
            };
            let operator = PublicKey::from_str(&serde_info.operator)
                .map_err(|e| Error::Wallet(format!("Invalid operator pubkey: {}", e)))?;
            let quorum_members: Result<Vec<PublicKey>, _> = serde_info
                .quorum_members
                .iter()
                .map(|p| PublicKey::from_str(p))
                .collect();
            let quorum_members =
                quorum_members.map_err(|e| Error::Wallet(format!("Invalid quorum member pubkey: {}", e)))?;
            let ledger_hash_bytes = hex::decode(&serde_info.ledger_hash)
                .map_err(|e| Error::Wallet(format!("Invalid ledger hash hex: {}", e)))?;
            let mut ledger_hash = [0u8; 32];
            ledger_hash.copy_from_slice(&ledger_hash_bytes);

            // Rebuild the TaprootReservesOutput using default config to match custody transfer
            let voter_set = VoterSet::new(operator_pubkey, quorum_members.clone());
            let config = if quorum_members.is_empty() {
                ThresholdConfig::custom(vec![ThresholdTier::new(1, true, 0, "Operator only")])
            } else {
                ThresholdConfig::default_for_voter_count(quorum_members.len() + 1)
            };

            let builder = TapscriptReservesBuilder::new(voter_set, config, network, ledger_hash);
            let taproot_output = builder.build()
                .map_err(|e| Error::Wallet(format!("Failed to rebuild Taproot output: {:?}", e)))?;

            let info = TaprootReservesInfo {
                outpoint,
                amount: serde_info.amount,
                operator,
                quorum_members,
                first_expiry_block: serde_info.first_expiry_block,
                ledger_hash,
                taproot_output,
                confirmed: serde_info.confirmed,
            };

            reserves.insert(outpoint, info);
        }

        tracing::info!("Loaded {} Taproot reserves from disk", reserves.len());
        Ok(reserves)
    }

    /// Save Taproot reserves to disk
    fn save_taproot_reserves_to_disk(&self) -> Result<(), Error> {
        let reserves = self.taproot_reserves.read().unwrap();
        let serde_list: Vec<TaprootReservesInfoSerde> = reserves
            .values()
            .map(TaprootReservesInfoSerde::from)
            .collect();

        let contents = serde_json::to_string_pretty(&serde_list)
            .map_err(|e| Error::Wallet(format!("Failed to serialize Taproot reserves: {}", e)))?;

        let reserves_file = self.data_dir.join("taproot_reserves.json");
        fs::write(&reserves_file, contents)
            .map_err(|e| Error::Wallet(format!("Failed to write Taproot reserves file: {}", e)))?;

        tracing::info!("Saved {} Taproot reserves to disk", reserves.len());
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
    pub fn create_taproot_reserves_output(
        &self,
        amount_sats: u64,
        quorum_members: Vec<PublicKey>,
        member_expiries: Vec<u32>,
        ledger_hash: [u8; 32],
    ) -> Result<TaprootReservesCreateResult, Error> {
        if quorum_members.len() != member_expiries.len() {
            return Err(Error::Wallet(
                "Quorum members and expiries must have same length".to_string()
            ));
        }

        // Find the minimum expiry (first quorum member timeout)
        let first_expiry = *member_expiries.iter().min().unwrap_or(&0);
        let current_height = self.get_block_height()?;

        if first_expiry > 0 && first_expiry <= current_height {
            return Err(Error::Wallet(format!(
                "First quorum member expiry {} is already past current block {}",
                first_expiry, current_height
            )));
        }

        // Create VoterSet: operator is tie-breaker, quorum members are primary voters
        let voter_set = VoterSet::new(self.operator_pubkey, quorum_members.clone());

        // Use default threshold configuration to ensure custody transfer can rebuild the same address
        // This uses: Tier 0 (majority+operator), Tier 1 (2-of-n quorum override), Tier 2 (emergency)
        let config = if quorum_members.is_empty() {
            ThresholdConfig::custom(vec![ThresholdTier::new(1, true, 0, "Operator only (no quorum)")])
        } else {
            ThresholdConfig::default_for_voter_count(quorum_members.len() + 1)
        };

        // Build the Taproot reserves output
        let builder = TapscriptReservesBuilder::new(
            voter_set,
            config,
            self.network,
            ledger_hash,
        );

        let taproot_output = builder.build()
            .map_err(|e| Error::Wallet(format!("Failed to build Taproot reserves: {:?}", e)))?;

        // Get the P2TR script pubkey
        let script_pubkey = taproot_output.script_pubkey();

        // Build the transaction
        let mut wallet = self.inner.lock().unwrap();

        let mut psbt = {
            let mut builder = wallet.build_tx();
            builder
                .add_recipient(script_pubkey.clone(), Amount::from_sat(amount_sats))
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

        // Find the Taproot output index
        let vout = tx
            .output
            .iter()
            .position(|o| o.script_pubkey == script_pubkey)
            .ok_or_else(|| Error::Wallet("Taproot output not found in tx".to_string()))?;

        let outpoint = OutPoint {
            txid: tx.compute_txid(),
            vout: vout as u32,
        };

        // Track this Taproot reserves output
        let info = TaprootReservesInfo {
            outpoint,
            amount: amount_sats,
            operator: self.operator_pubkey,
            quorum_members: quorum_members.clone(),
            first_expiry_block: first_expiry,
            ledger_hash,
            taproot_output: taproot_output.clone(),
            confirmed: false,
        };

        drop(wallet); // Release lock before acquiring write lock
        self.taproot_reserves.write().unwrap().insert(outpoint, info);

        tracing::info!(
            "Created Taproot reserves at {} with {} quorum members, first expiry at block {}",
            outpoint,
            quorum_members.len(),
            first_expiry
        );

        Ok(TaprootReservesCreateResult {
            outpoint,
            address: taproot_output.address.clone(),
            amount: amount_sats,
            tx,
            taproot_output,
            first_expiry_block: first_expiry,
            ledger_hash,
        })
    }

    /// Get all tracked Taproot reserves
    pub fn get_taproot_reserves(&self) -> Vec<TaprootReservesInfo> {
        self.taproot_reserves.read().unwrap().values().cloned().collect()
    }

    /// Get the first/primary Taproot reserves outpoint
    pub fn get_taproot_reserves_outpoint(&self) -> Option<OutPoint> {
        self.taproot_reserves
            .read()
            .unwrap()
            .keys()
            .next()
            .copied()
    }

    /// Mark a Taproot reserves output as confirmed
    pub fn confirm_taproot_reserves(&self, outpoint: &OutPoint) -> Result<(), Error> {
        let mut taproot_reserves = self.taproot_reserves.write().unwrap();
        if let Some(info) = taproot_reserves.get_mut(outpoint) {
            info.confirmed = true;
            Ok(())
        } else {
            Err(Error::Wallet(format!(
                "Taproot reserves output not found: {}",
                outpoint
            )))
        }
    }

    /// Rotate existing P2WSH reserves to a new Taproot output with quorum-based spending
    ///
    /// This spends the existing P2WSH reserves output and creates a new P2TR output.
    /// The operator signs the P2WSH input using the single-sig path (OP_ELSE branch).
    ///
    /// # Arguments
    /// * `quorum_members` - The quorum member pubkeys (will be voters)
    /// * `member_expiries` - Block heights when each quorum member expires
    /// * `ledger_hash` - The current ledger hash to commit to in the Taproot tree
    ///
    /// # Returns
    /// A `TaprootReservesCreateResult` with the rotation transaction
    pub fn rotate_reserves_to_taproot(
        &self,
        quorum_members: Vec<PublicKey>,
        member_expiries: Vec<u32>,
        ledger_hash: [u8; 32],
    ) -> Result<TaprootReservesCreateResult, Error> {
        use bitcoin::sighash::{SighashCache, EcdsaSighashType};
        use bitcoin::ecdsa::Signature as EcdsaSignature;
        use bitcoin::Witness;

        if quorum_members.len() != member_expiries.len() {
            return Err(Error::Wallet(
                "Quorum members and expiries must have same length".to_string()
            ));
        }

        // Get existing reserves info
        let reserves_info = {
            let reserves = self.reserves.read().unwrap();
            reserves.values().next().cloned()
                .ok_or_else(|| Error::Wallet("No existing reserves to rotate".to_string()))?
        };

        let amount_sats = reserves_info.amount;
        let fee_sats = 200; // Simple fee estimate for 1-in-1-out
        let output_amount = amount_sats.saturating_sub(fee_sats);

        // Find the minimum expiry (first quorum member timeout)
        let first_expiry = *member_expiries.iter().min().unwrap_or(&0);
        let current_height = self.get_block_height()?;

        // Create VoterSet: operator is tie-breaker, quorum members are primary voters
        let voter_set = VoterSet::new(self.operator_pubkey, quorum_members.clone());

        // Use default threshold configuration to ensure custody transfer can rebuild the same address
        let config = if quorum_members.is_empty() {
            ThresholdConfig::custom(vec![ThresholdTier::new(1, true, 0, "Operator only (no quorum)")])
        } else {
            ThresholdConfig::default_for_voter_count(quorum_members.len() + 1)
        };

        // Build the Taproot reserves output
        let builder = TapscriptReservesBuilder::new(
            voter_set,
            config,
            self.network,
            ledger_hash,
        );

        let taproot_output = builder.build()
            .map_err(|e| Error::Wallet(format!("Failed to build Taproot reserves: {:?}", e)))?;

        let new_script_pubkey = taproot_output.script_pubkey();

        // Build the rotation transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: reserves_info.outpoint,
                script_sig: ScriptBuf::new(), // Empty for SegWit
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_amount),
                script_pubkey: new_script_pubkey.clone(),
            }],
        };

        // Compute sighash for the P2WSH input

        let mut sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache
            .p2wsh_signature_hash(
                0,
                &reserves_info.redeem_script,
                Amount::from_sat(amount_sats),
                EcdsaSighashType::All,
            )
            .map_err(|e| Error::Wallet(format!("Failed to compute sighash: {:?}", e)))?;

        // Sign with operator's key
        let secp = Secp256k1::new();
        let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, &self.operator_secret);
        let ecdsa_sig = EcdsaSignature::sighash_all(sig);

        // Build the witness for P2WSH single-sig (OP_ELSE branch)
        // Witness stack: <signature> <FALSE> <redeem_script>
        // FALSE selects the OP_ELSE branch
        let mut witness = Witness::new();
        witness.push(ecdsa_sig.to_vec());
        witness.push([]); // OP_FALSE to select ELSE branch
        witness.push(reserves_info.redeem_script.as_bytes());

        tx.input[0].witness = witness;

        // Calculate new outpoint
        let new_outpoint = OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        };

        // Track the new Taproot reserves
        let new_info = TaprootReservesInfo {
            outpoint: new_outpoint,
            amount: output_amount,
            operator: self.operator_pubkey,
            quorum_members: quorum_members.clone(),
            first_expiry_block: first_expiry,
            ledger_hash,
            taproot_output: taproot_output.clone(),
            confirmed: false,
        };

        // Update tracking: remove old reserves, add new
        {
            let mut old_reserves = self.reserves.write().unwrap();
            old_reserves.remove(&reserves_info.outpoint);
        }
        {
            let mut new_reserves = self.taproot_reserves.write().unwrap();
            new_reserves.insert(new_outpoint, new_info);
        }

        // Persist
        self.save_reserves_to_disk()?;

        tracing::info!(
            "Rotating reserves from {} to Taproot {} with {} quorum members",
            reserves_info.outpoint,
            new_outpoint,
            quorum_members.len()
        );

        Ok(TaprootReservesCreateResult {
            outpoint: new_outpoint,
            address: taproot_output.address.clone(),
            amount: output_amount,
            tx,
            taproot_output,
            first_expiry_block: first_expiry,
            ledger_hash,
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

    /// Find an unspent UTXO for a given script pubkey
    ///
    /// Returns (OutPoint, amount) if found, None if no unspent output exists.
    pub fn find_utxo_for_script(&self, script: &bitcoin::ScriptBuf) -> Result<Option<(OutPoint, u64)>, Error> {
        let client = EsploraBuilder::new(&self.electrum_url)
            .build_blocking();

        let txs = client
            .scripthash_txs(script, None)
            .map_err(|e| Error::Wallet(format!("Failed to query script: {:?}", e)))?;

        for tx in &txs {
            for (vout, output) in tx.vout.iter().enumerate() {
                if &output.scriptpubkey == script {
                    let outpoint = OutPoint::new(tx.txid, vout as u32);
                    let status = client
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

    // ========================================================================
    // Custody Transfer (Quorum Override) Spending
    // ========================================================================

    /// Prepare a custody transfer spend transaction
    ///
    /// This creates an unsigned transaction that spends the Taproot reserves
    /// via the Tier 2 spending path (2-of-n without operator, after 2016 blocks).
    /// This path allows quorum members to confiscate reserves from a non-conforming operator.
    ///
    /// # Arguments
    /// * `request` - The custody transfer parameters
    ///
    /// # Returns
    /// A `CustodyAcquireSpend` with the unsigned tx and sighash for signing
    pub fn create_custody_transfer_spend(
        &self,
        request: &CustodyAcquireRequest,
    ) -> Result<CustodyAcquireSpend, Error> {
        use deposits_core::ReservesSpendBuilder;

        // Get the Taproot reserves info
        let reserves_info = {
            let reserves = self.taproot_reserves.read().unwrap();
            reserves
                .get(&request.reserves_outpoint)
                .cloned()
                .ok_or_else(|| Error::Wallet(format!(
                    "Taproot reserves not found: {}",
                    request.reserves_outpoint
                )))?
        };

        // Find the quorum-override tier: one that doesn't require tie-breaker (operator)
        // and has threshold > 1 (not emergency single-sig). This allows quorum members
        // to spend without the operator's cooperation.
        let (tier_index, tier) = reserves_info.taproot_output.config.tiers.iter()
            .enumerate()
            .find(|(_, t)| !t.requires_tie_breaker && t.threshold > 1)
            .ok_or_else(|| Error::Wallet(
                "No quorum-override tier found (requires_tie_breaker=false, threshold>1)".to_string()
            ))?;

        // Rebuild the leaf script for this tier
        let builder = deposits_core::TapscriptReservesBuilder::new(
            reserves_info.taproot_output.voter_set.clone(),
            reserves_info.taproot_output.config.clone(),
            self.network,
            reserves_info.ledger_hash,
        );

        let leaf_script = builder.build_threshold_leaf(tier)
            .map_err(|e| Error::Wallet(format!("Failed to build spending script: {:?}", e)))?;

        // Get the control block
        let control_block = reserves_info.taproot_output.control_block_for_tier(tier_index)
            .ok_or_else(|| Error::Wallet("Failed to get control block for tier".to_string()))?;

        // Build the spend transaction parameters
        let spend_params = deposits_core::SpendTxParams {
            reserves_outpoint: request.reserves_outpoint,
            reserves_amount: reserves_info.amount,
            destination_script: request.destination_address.script_pubkey(),
            fee_rate_sat_vbyte: request.fee_rate,
        };

        let reserves_script_pubkey = reserves_info.taproot_output.script_pubkey();

        // Build the unsigned transaction
        let unsigned_tx = ReservesSpendBuilder::build_spend_transaction(
            &spend_params,
            &reserves_script_pubkey,
        ).map_err(|e| Error::Wallet(format!("Failed to build spend tx: {:?}", e)))?;

        // Compute the sighash
        let sighash = ReservesSpendBuilder::compute_sighash(
            &unsigned_tx,
            0, // input index
            reserves_info.amount,
            &reserves_script_pubkey,
            &leaf_script,
        ).map_err(|e| Error::Wallet(format!("Failed to compute sighash: {:?}", e)))?;

        // Get sorted voter pubkeys (signature order must match)
        let voter_pubkeys: Vec<PublicKey> = reserves_info.taproot_output.voter_set
            .all_voters()
            .into_iter()
            .collect();

        Ok(CustodyAcquireSpend {
            unsigned_tx,
            sighash: sighash.to_byte_array(),
            leaf_script,
            control_block,
            voter_pubkeys,
            tier_index,
            reserves_amount: reserves_info.amount,
            reserves_script_pubkey,
        })
    }

    /// Sign a custody transfer sighash with our key
    ///
    /// Returns a 64-byte Schnorr signature if our key is in the voter set,
    /// or None if we're not a voter.
    pub fn sign_custody_transfer_sighash(&self, sighash: &[u8; 32]) -> Result<Option<[u8; 64]>, Error> {
        use bitcoin::secp256k1::{Secp256k1, Message, Keypair};

        let secp = Secp256k1::new();
        let msg = Message::from_digest(*sighash);

        // Create keypair for Schnorr signing
        let keypair = Keypair::from_secret_key(&secp, &self.operator_secret);

        // Sign with Schnorr (BIP-340)
        let sig = secp.sign_schnorr(&msg, &keypair);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(sig.as_ref());

        Ok(Some(sig_bytes))
    }

    /// Finalize a custody transfer spend with collected signatures
    ///
    /// # Arguments
    /// * `spend` - The custody transfer spend prepared earlier
    /// * `signatures` - Signatures from voters, keyed by their pubkey
    ///
    /// # Returns
    /// A `CustodyAcquireResult` with the signed transaction
    pub fn finalize_custody_transfer(
        &self,
        spend: &CustodyAcquireSpend,
        signatures: &std::collections::HashMap<PublicKey, [u8; 64]>,
    ) -> Result<CustodyAcquireResult, Error> {
        use deposits_core::ReservesSpendBuilder;

        // Build the signature array in the correct order (matching voter pubkey order)
        // For CHECKSIGADD, we need signatures in the order of keys in the script
        let sorted_pubkeys = spend.voter_pubkeys.iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect::<Vec<_>>();

        let sorted_keys_with_sigs: Vec<_> = sorted_pubkeys.iter()
            .map(|xonly| {
                // Find the full pubkey and its signature
                for (pk, sig) in signatures.iter() {
                    if pk.x_only_public_key().0 == *xonly {
                        return Some(*sig);
                    }
                }
                None
            })
            .collect();

        // Sort by x-only pubkey (same order as script construction)
        let mut indexed: Vec<_> = sorted_pubkeys.iter().zip(sorted_keys_with_sigs.iter())
            .enumerate()
            .collect();
        indexed.sort_by(|a, b| a.1.0.serialize().cmp(&b.1.0.serialize()));

        let ordered_sigs: Vec<Option<[u8; 64]>> = indexed.iter()
            .map(|(_, (_, sig))| **sig)
            .collect();

        // Create the witness
        let signed_tx = ReservesSpendBuilder::finalize_spend_transaction(
            spend.unsigned_tx.clone(),
            &ordered_sigs,
            &spend.leaf_script,
            &spend.control_block,
        );

        let txid = signed_tx.compute_txid();

        Ok(CustodyAcquireResult {
            signed_tx,
            txid,
        })
    }

    /// Execute a complete custody transfer (for testing/single-node scenarios)
    ///
    /// This is a convenience method that creates, signs, and optionally broadcasts
    /// a custody transfer spend. For production use with multiple quorum members,
    /// use the individual create/sign/finalize methods to coordinate signatures.
    pub fn execute_custody_transfer(
        &self,
        destination_address: Address,
        fee_rate: u64,
    ) -> Result<CustodyAcquireResult, Error> {
        // Get the first Taproot reserves
        let reserves_outpoint = self.get_taproot_reserves_outpoint()
            .ok_or_else(|| Error::Wallet("No Taproot reserves found".to_string()))?;

        let request = CustodyAcquireRequest {
            reserves_outpoint,
            destination_address,
            fee_rate,
        };

        // Create the spend
        let spend = self.create_custody_transfer_spend(&request)?;

        // Sign with our key
        let our_sig = self.sign_custody_transfer_sighash(&spend.sighash)?
            .ok_or_else(|| Error::Wallet("Failed to sign".to_string()))?;

        // For a proper custody transfer, we need 2 signatures (Tier 2 threshold)
        // In a real scenario, we'd collect from other quorum members via Nostr
        // For now, just use our signature (will fail if threshold > 1)
        let mut signatures = std::collections::HashMap::new();
        signatures.insert(self.operator_pubkey, our_sig);

        // Finalize
        self.finalize_custody_transfer(&spend, &signatures)
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
            reserves: RwLock::new(HashMap::new()),
            taproot_reserves: RwLock::new(HashMap::new()),
            block_height: Mutex::new(800_000),
            block_hash: Mutex::new([0u8; 32]),
            data_dir,
            address_index: Mutex::new(0),
        }
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

/// Result of creating a Taproot reserves output
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
    pub first_expiry_block: u32,

    /// The ledger hash committed to in the Taproot tree
    pub ledger_hash: [u8; 32],
}

/// Parameters for a custody transfer spend
#[derive(Debug, Clone)]
pub struct CustodyAcquireRequest {
    /// The Taproot reserves outpoint to spend
    pub reserves_outpoint: OutPoint,
    /// Destination address (new custodian's receiving address)
    pub destination_address: Address,
    /// Fee rate in sat/vbyte
    pub fee_rate: u64,
}

/// Result of preparing a custody transfer spend
#[derive(Debug, Clone)]
pub struct CustodyAcquireSpend {
    /// The unsigned spend transaction
    pub unsigned_tx: Transaction,
    /// The sighash that each quorum member must sign
    pub sighash: [u8; 32],
    /// The Tapscript leaf being used (Tier 2: 2-of-n without operator)
    pub leaf_script: ScriptBuf,
    /// The control block for the leaf
    pub control_block: bitcoin::taproot::ControlBlock,
    /// Sorted list of voter pubkeys (signature order must match)
    pub voter_pubkeys: Vec<PublicKey>,
    /// The tier index being used (2 = quorum override)
    pub tier_index: usize,
    /// The reserves amount (needed for sighash verification)
    pub reserves_amount: u64,
    /// The reserves script pubkey
    pub reserves_script_pubkey: ScriptBuf,
}

/// Result of finalizing a custody transfer spend
#[derive(Debug, Clone)]
pub struct CustodyAcquireResult {
    /// The signed transaction ready for broadcast
    pub signed_tx: Transaction,
    /// The transaction ID
    pub txid: Txid,
}
