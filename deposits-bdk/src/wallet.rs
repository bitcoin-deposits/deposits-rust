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

use bitcoin::secp256k1::PublicKey;
use std::sync::Mutex;

use crate::Error;

/// BDK-based wallet for reserves management
pub struct Wallet {
    /// Current block height (synced from electrum)
    block_height: Mutex<u32>,

    /// Network (mainnet, testnet, regtest, signet)
    network: bitcoin::Network,

    /// Reserves balance in satoshis
    reserves_balance: Mutex<u64>,
}

impl Wallet {
    /// Create a new wallet
    pub fn new(network: bitcoin::Network) -> Result<Self, Error> {
        Ok(Self {
            block_height: Mutex::new(0),
            network,
            reserves_balance: Mutex::new(0),
        })
    }

    /// Get the current block height
    pub fn get_block_height(&self) -> Result<u32, Error> {
        Ok(*self.block_height.lock().unwrap())
    }

    /// Get the reserves balance
    pub fn get_reserves_balance(&self) -> Result<u64, Error> {
        Ok(*self.reserves_balance.lock().unwrap())
    }

    /// Get the network
    pub fn network(&self) -> bitcoin::Network {
        self.network
    }

    /// Sync with electrum server
    pub async fn sync(&self, _electrum_url: &str) -> Result<(), Error> {
        // TODO: Implement BDK sync
        //
        // 1. Create BDK electrum client
        // 2. Sync wallet
        // 3. Update block_height
        // 4. Update reserves_balance

        tracing::info!("Syncing wallet...");
        Ok(())
    }

    /// Create a reserves output
    ///
    /// This creates a taproot output with the reserves script (similar to
    /// what deposits-ldk does in commitment transactions, but on-chain).
    pub fn create_reserves_output(
        &self,
        _amount: u64,
        _operator: PublicKey,
        _partner: PublicKey,
        _collateral_partners: Vec<PublicKey>,
    ) -> Result<ReservesOutput, Error> {
        // TODO: Implement reserves output creation
        //
        // 1. Build taproot script tree with:
        //    - Operator can spend after timelock
        //    - Partner can claim with fraud proof
        //    - Collateral partners can vote
        // 2. Create PSBT
        // 3. Return unsigned output for signing

        Err(Error::Wallet("Not implemented".to_string()))
    }

    /// Spend a reserves output
    pub fn spend_reserves(
        &self,
        _outpoint: bitcoin::OutPoint,
        _destination: bitcoin::Address,
        _signatures: Vec<(PublicKey, [u8; 64])>,
    ) -> Result<bitcoin::Transaction, Error> {
        // TODO: Implement reserves spending
        //
        // 1. Build spend transaction
        // 2. Add signatures
        // 3. Finalize and return

        Err(Error::Wallet("Not implemented".to_string()))
    }
}

/// A reserves output ready for signing
#[derive(Debug, Clone)]
pub struct ReservesOutput {
    /// The outpoint once confirmed
    pub outpoint: Option<bitcoin::OutPoint>,

    /// The taproot address
    pub address: bitcoin::Address,

    /// Amount in satoshis
    pub amount: u64,

    /// The unsigned PSBT
    pub psbt: Vec<u8>,
}
