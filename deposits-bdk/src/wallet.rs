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

use bdk_electrum::electrum_client::{self, ElectrumApi};
use bdk_electrum::BdkElectrumClient;
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv};
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::script::Builder as ScriptBuilder;
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bdk_wallet::bitcoin::{
    opcodes, Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
};
use bdk_wallet::chain::spk_client::SyncRequest;
use bdk_wallet::{KeychainKind, SignOptions, Wallet as BdkWallet};
use std::collections::HashMap;
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

impl Wallet {
    /// Create a new wallet from a seed
    pub fn new(
        seed: [u8; 32],
        network: Network,
        _db_path: PathBuf,
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

        Ok(Self {
            inner: Mutex::new(wallet),
            electrum_url,
            network,
            operator_secret,
            operator_pubkey,
            reserves: RwLock::new(HashMap::new()),
            block_height: Mutex::new(0),
        })
    }

    /// Get the operator's public key
    pub fn operator_pubkey(&self) -> PublicKey {
        self.operator_pubkey
    }

    /// Get the operator's secret key
    pub fn operator_secret(&self) -> SecretKey {
        self.operator_secret
    }

    /// Get the current block height
    pub fn get_block_height(&self) -> Result<u32, Error> {
        Ok(*self.block_height.lock().unwrap())
    }

    /// Get the total reserves balance (sum of all tracked reserves outputs)
    pub fn get_reserves_balance(&self) -> Result<u64, Error> {
        let reserves = self.reserves.read().unwrap();
        let total = reserves
            .values()
            .filter(|r| r.confirmed)
            .map(|r| r.amount)
            .sum();
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

    /// Sync wallet with electrum server
    pub fn sync(&self) -> Result<(), Error> {
        let client = electrum_client::Client::new(&self.electrum_url)
            .map_err(|e| Error::Wallet(format!("Failed to connect to electrum: {}", e)))?;

        let electrum = BdkElectrumClient::new(client);

        // Get block height
        let height = electrum
            .inner
            .block_headers_subscribe()
            .map_err(|e| Error::Wallet(format!("Failed to get block height: {}", e)))?
            .height as u32;

        *self.block_height.lock().unwrap() = height;

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

            let update = electrum
                .sync(request, 5, true)
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
        let client = electrum_client::Client::new(&self.electrum_url)
            .map_err(|e| Error::Wallet(format!("Failed to connect to electrum: {}", e)))?;

        let txid = client
            .transaction_broadcast(tx)
            .map_err(|e| Error::Wallet(format!("Broadcast failed: {}", e)))?;

        tracing::info!("Broadcast tx: {}", txid);
        Ok(txid)
    }

    /// Get all tracked reserves
    pub fn get_reserves(&self) -> Vec<ReservesInfo> {
        self.reserves.read().unwrap().values().cloned().collect()
    }

    /// Mark a reserves output as confirmed
    pub fn confirm_reserves(&self, outpoint: &OutPoint) -> Result<(), Error> {
        let mut reserves = self.reserves.write().unwrap();
        if let Some(info) = reserves.get_mut(outpoint) {
            info.confirmed = true;
            Ok(())
        } else {
            Err(Error::Wallet(format!(
                "Reserves output not found: {}",
                outpoint
            )))
        }
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
