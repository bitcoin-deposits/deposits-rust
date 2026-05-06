// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Per-ledger BDK wallet.
//!
//! Each ledger gets its own BDK `Wallet` rooted at a distinct BIP-32
//! account so the per-ledger UTXO sets are disjoint. The activation tx
//! that builds the Q=N Taproot vault draws inputs only from the ledger's
//! own wallet — eliminating the multi-ledger UTXO race the shared
//! [`crate::wallet::Wallet`] suffered when several `quorum begin` calls
//! ran concurrently against the same UTXO pool.
//!
//! Storage layout:
//!
//! ```text
//! <data_dir>/wallet/ledgers/<ledger_id>/
//!   account_index.txt    # the BIP-32 account integer assigned at ledger open
//!   address_index.txt    # last-revealed external-keychain index
//! ```
//!
//! Phase 1b is purely additive: `LedgerWallet` is defined and tested but
//! not wired into [`Node`] yet; phase 1c does the wiring, phase 1d swaps
//! the activation path over.

use bdk_esplora::esplora_client::Builder as EsploraBuilder;
use bdk_esplora::EsploraExt;
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::{Address, Network, Transaction, Txid};
use bdk_wallet::chain::spk_client::SyncRequest;
use bdk_wallet::{KeychainKind, Wallet as BdkWallet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::Error;

/// Per-ledger BDK wallet. One instance per `ledger_id`.
///
/// The wallet's keys derive from the operator's master seed under
/// `m/86'/0'/<account_index>'/<change>/*`, where `<account_index>` is
/// assigned sequentially at `ledger open` time and persisted in the
/// ledger's own data dir. That's how distinct ledgers get distinct UTXO
/// sets while sharing a single seed.
pub struct LedgerWallet {
    inner: Mutex<BdkWallet>,
    network: Network,
    electrum_url: String,
    data_dir: PathBuf,
    ledger_id: String,
    account_index: u32,
    address_index: Mutex<u32>,
}

impl LedgerWallet {
    /// Create a new per-ledger wallet at the given account index.
    ///
    /// Fails if the ledger's data dir already exists with an
    /// `account_index.txt` (callers should use [`LedgerWallet::load`]
    /// for that case). The check guards against silently re-creating a
    /// wallet at a different account than the one a ledger was opened
    /// with.
    pub fn create(
        seed: &[u8; 32],
        network: Network,
        account_index: u32,
        ledger_id: &str,
        data_dir_root: &Path,
        electrum_url: String,
    ) -> Result<Self, Error> {
        let dir = Self::ledger_dir(data_dir_root, ledger_id);
        let account_file = dir.join("account_index.txt");
        if account_file.exists() {
            return Err(Error::Wallet(format!(
                "ledger wallet already exists at {} (use LedgerWallet::load)",
                dir.display()
            )));
        }
        fs::create_dir_all(&dir)
            .map_err(|e| Error::Wallet(format!("create ledger wallet dir {:?}: {}", dir, e)))?;
        fs::write(&account_file, account_index.to_string())
            .map_err(|e| Error::Wallet(format!("write account_index.txt: {}", e)))?;

        Self::open(seed, network, account_index, ledger_id, dir, electrum_url, 0)
    }

    /// Load an existing per-ledger wallet from disk.
    ///
    /// Reads `account_index.txt` and `address_index.txt` from the
    /// ledger's data dir; rebuilds the BDK wallet from the seed at the
    /// recorded account.
    pub fn load(
        seed: &[u8; 32],
        network: Network,
        ledger_id: &str,
        data_dir_root: &Path,
        electrum_url: String,
    ) -> Result<Self, Error> {
        let dir = Self::ledger_dir(data_dir_root, ledger_id);
        let account_file = dir.join("account_index.txt");
        let account_index: u32 = fs::read_to_string(&account_file)
            .map_err(|e| {
                Error::Wallet(format!(
                    "ledger wallet not initialized at {}: {}",
                    dir.display(),
                    e
                ))
            })?
            .trim()
            .parse()
            .map_err(|e| Error::Wallet(format!("parse account_index.txt: {}", e)))?;
        let address_index = Self::load_address_index(&dir)?;
        Self::open(
            seed,
            network,
            account_index,
            ledger_id,
            dir,
            electrum_url,
            address_index,
        )
    }

    fn open(
        seed: &[u8; 32],
        network: Network,
        account_index: u32,
        ledger_id: &str,
        dir: PathBuf,
        electrum_url: String,
        address_index: u32,
    ) -> Result<Self, Error> {
        let xpriv = Xpriv::new_master(network, seed)
            .map_err(|e| Error::Wallet(format!("Xpriv::new_master: {}", e)))?;

        // wpkh descriptors with a per-ledger BIP-32 account. The
        // hardened-account number in the descriptor isolates this
        // ledger's UTXO set from every other ledger and from the
        // legacy node-level wallet's `m/0/*`/`m/1/*`.
        let external_desc = format!("wpkh({}/86'/0'/{}'/0/*)", xpriv, account_index);
        let internal_desc = format!("wpkh({}/86'/0'/{}'/1/*)", xpriv, account_index);

        let mut wallet = BdkWallet::create(external_desc, internal_desc)
            .network(network)
            .create_wallet_no_persist()
            .map_err(|e| Error::Wallet(format!("BdkWallet::create: {}", e)))?;

        for _ in 0..address_index {
            wallet.reveal_next_address(KeychainKind::External);
        }

        Ok(Self {
            inner: Mutex::new(wallet),
            network,
            electrum_url,
            data_dir: dir,
            ledger_id: ledger_id.to_string(),
            account_index,
            address_index: Mutex::new(address_index),
        })
    }

    /// Path to a ledger's per-ledger wallet directory.
    pub fn ledger_dir(data_dir_root: &Path, ledger_id: &str) -> PathBuf {
        data_dir_root.join("wallet").join("ledgers").join(ledger_id)
    }

    pub fn ledger_id(&self) -> &str {
        &self.ledger_id
    }

    pub fn account_index(&self) -> u32 {
        self.account_index
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Reveal a fresh receive address (external keychain). Persists the
    /// new address index to disk.
    pub fn get_new_address(&self) -> Result<Address, Error> {
        let mut wallet = self.inner.lock().unwrap();
        let mut index = self.address_index.lock().unwrap();
        let addr = wallet.reveal_next_address(KeychainKind::External);
        *index += 1;
        Self::save_address_index(&self.data_dir, *index)?;
        Ok(addr.address)
    }

    /// Confirmed + trusted-unconfirmed sat balance, summed across both
    /// keychains.
    pub fn balance_sats(&self) -> Result<u64, Error> {
        let wallet = self.inner.lock().unwrap();
        let bal = wallet.balance();
        Ok(bal.confirmed.to_sat() + bal.trusted_pending.to_sat())
    }

    /// Full sync via Esplora. Calls every revealed script-pubkey on
    /// both keychains; ~40 HTTP requests for a fresh wallet, scales
    /// linearly with revealed addresses afterward.
    pub fn sync(&self) -> Result<(), Error> {
        let client = EsploraBuilder::new(&self.electrum_url).build_blocking();

        let mut wallet = self.inner.lock().unwrap();
        let spks: Vec<_> = wallet
            .all_unbounded_spk_iters()
            .into_iter()
            .flat_map(|(_, iter)| iter.take(20).map(|(_, spk)| spk))
            .collect();
        if spks.is_empty() {
            return Ok(());
        }
        let request = SyncRequest::builder().spks(spks).build();
        let update = client
            .sync(request, 5)
            .map_err(|e| Error::Wallet(format!("ledger wallet sync: {}", e)))?;
        wallet
            .apply_update(update)
            .map_err(|e| Error::Wallet(format!("ledger wallet apply_update: {}", e)))?;
        Ok(())
    }

    /// Broadcast a tx and stamp it into BDK's mempool view so a
    /// subsequent build_tx on this wallet won't re-pick the same
    /// inputs.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, Error> {
        let client = EsploraBuilder::new(&self.electrum_url).build_blocking();
        client
            .broadcast(tx)
            .map_err(|e| Error::Wallet(format!("ledger wallet broadcast: {}", e)))?;
        let txid = tx.compute_txid();

        let last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut wallet = self.inner.lock().unwrap();
        wallet.apply_unconfirmed_txs(std::iter::once((tx.clone(), last_seen)));
        tracing::info!(
            "LedgerWallet[{}] broadcast {} (account {})",
            &self.ledger_id[..16.min(self.ledger_id.len())],
            txid,
            self.account_index,
        );
        Ok(txid)
    }

    fn load_address_index(dir: &Path) -> Result<u32, Error> {
        let f = dir.join("address_index.txt");
        if !f.exists() {
            return Ok(0);
        }
        let s = fs::read_to_string(&f)
            .map_err(|e| Error::Wallet(format!("read address_index.txt: {}", e)))?;
        let s = s.trim();
        if s.is_empty() {
            return Ok(0);
        }
        s.parse()
            .map_err(|e| Error::Wallet(format!("parse address_index.txt: {}", e)))
    }

    fn save_address_index(dir: &Path, index: u32) -> Result<(), Error> {
        let f = dir.join("address_index.txt");
        fs::write(&f, index.to_string())
            .map_err(|e| Error::Wallet(format!("write address_index.txt: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const SEED: [u8; 32] = [42u8; 32];

    fn open(account: u32, ledger_id: &str, root: &Path) -> LedgerWallet {
        LedgerWallet::create(
            &SEED,
            Network::Regtest,
            account,
            ledger_id,
            root,
            "http://localhost:0".to_string(),
        )
        .expect("create LedgerWallet")
    }

    #[test]
    fn distinct_accounts_yield_distinct_first_addresses() {
        let tmp = TempDir::new().unwrap();
        let w0 = open(0, "ledger_a", tmp.path());
        let w1 = open(1, "ledger_b", tmp.path());
        let a0 = w0.get_new_address().unwrap();
        let a1 = w1.get_new_address().unwrap();
        assert_ne!(
            a0, a1,
            "different accounts must produce different first addresses"
        );
    }

    #[test]
    fn create_then_load_recovers_same_state() {
        let tmp = TempDir::new().unwrap();
        let first_addr = {
            let w = open(7, "ledger_x", tmp.path());
            assert_eq!(w.account_index(), 7);
            w.get_new_address().unwrap()
        };

        // Reload — should re-produce the same first address (because
        // the next reveal is index 1, not 0; we already revealed 0
        // above and persisted address_index=1).
        let w2 = LedgerWallet::load(
            &SEED,
            Network::Regtest,
            "ledger_x",
            tmp.path(),
            "http://localhost:0".to_string(),
        )
        .unwrap();
        assert_eq!(w2.account_index(), 7);
        let next = w2.get_new_address().unwrap();
        assert_ne!(next, first_addr);

        // Open a *fresh* wallet at the same account in a separate
        // temp dir and check its first address matches `first_addr`
        // — proves derivation is stable for (seed, account).
        let tmp2 = TempDir::new().unwrap();
        let w3 = open(7, "ledger_x_fresh", tmp2.path());
        let fresh_first = w3.get_new_address().unwrap();
        assert_eq!(fresh_first, first_addr);
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let tmp = TempDir::new().unwrap();
        let _w = open(0, "ledger_dup", tmp.path());
        match LedgerWallet::create(
            &SEED,
            Network::Regtest,
            1, // different account — but the dir exists
            "ledger_dup",
            tmp.path(),
            "http://localhost:0".to_string(),
        ) {
            Err(e) => assert!(format!("{:?}", e).contains("already exists")),
            Ok(_) => panic!("expected create to refuse overwrite"),
        }
    }

    #[test]
    fn load_fails_when_uninitialized() {
        let tmp = TempDir::new().unwrap();
        match LedgerWallet::load(
            &SEED,
            Network::Regtest,
            "ledger_missing",
            tmp.path(),
            "http://localhost:0".to_string(),
        ) {
            Err(e) => assert!(format!("{:?}", e).contains("not initialized")),
            Ok(_) => panic!("expected load to fail on uninitialized dir"),
        }
    }
}
