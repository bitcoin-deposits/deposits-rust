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
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Transaction, Txid};
use bdk_wallet::{KeychainKind, SignOptions, Wallet as BdkWallet};
use deposits_core::{
    TapscriptReservesBuilder, ThresholdConfig, ThresholdTier, VoterSet,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, RwLock};

use crate::wallet::{TaprootReservesCreateResult, TaprootReservesInfo};
use crate::Error;
use deposits_signer_api::Signer;

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
    /// Operator's protocol-level pubkey (`m/86'/0'/0'/0/0` against the
    /// master seed). Same across all of an operator's ledgers; used in
    /// `VoterSet::new` and to rebuild the Taproot output on
    /// taproot-reserves load.
    operator_pubkey: PublicKey,
    /// Active Taproot reserves vault for this ledger (at most one).
    /// Populated by `commit_taproot_reserves` after `quorum begin`'s
    /// activation tx confirms; loaded from
    /// `<ledger_dir>/taproot_reserves.json` at startup.
    taproot_reserves: RwLock<Option<TaprootReservesInfo>>,
}

impl LedgerWallet {
    /// Create a new per-ledger wallet at the given account index.
    ///
    /// Fails if the ledger's data dir already exists with an
    /// `account_index.txt` (callers should use [`LedgerWallet::load`]
    /// for that case). The check guards against silently re-creating a
    /// wallet at a different account than the one a ledger was opened
    /// with.
    ///
    /// `signer` is used twice: to fetch the BIP-32 xpub at
    /// `m/86'/0'/<account>'` (used to build the *watch-only* BDK
    /// descriptor) and to read the operator's protocol pubkey
    /// (cached for taproot-reserves rebuilds). Neither call needs the
    /// seed — the daemon never sees it.
    pub fn create(
        signer: &dyn Signer,
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

        Self::open(
            signer,
            network,
            account_index,
            ledger_id,
            dir,
            electrum_url,
            0,
        )
    }

    /// Load an existing per-ledger wallet from disk.
    ///
    /// Reads `account_index.txt` and `address_index.txt` from the
    /// ledger's data dir; asks the signer for the watch-only xpub
    /// at the recorded account and rebuilds the BDK wallet from it.
    pub fn load(
        signer: &dyn Signer,
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
            signer,
            network,
            account_index,
            ledger_id,
            dir,
            electrum_url,
            address_index,
        )
    }

    fn open(
        signer: &dyn Signer,
        network: Network,
        account_index: u32,
        ledger_id: &str,
        dir: PathBuf,
        electrum_url: String,
        address_index: u32,
    ) -> Result<Self, Error> {
        // Watch-only descriptor: ask the signer for the xpub at
        // `m/86'/0'/<account>'`, then build `wpkh(account_xpub/0/*)`
        // / `wpkh(account_xpub/1/*)` from it. BDK can derive every
        // child key publicly (the unhardened `0/*`/`1/*` tail is
        // beyond the last hardened step), but it has no secrets —
        // signing routes back to the signer per input via
        // KeyPath::Wallet.
        let account_xpub = signer.wallet_account_xpub(account_index).map_err(|e| {
            Error::Wallet(format!(
                "wallet_account_xpub(account={}): {}",
                account_index, e
            ))
        })?;
        let operator_pubkey = signer.pubkey();

        let external_desc = format!("wpkh({}/0/*)", account_xpub);
        let internal_desc = format!("wpkh({}/1/*)", account_xpub);

        let mut wallet = BdkWallet::create(external_desc, internal_desc)
            .network(network)
            .create_wallet_no_persist()
            .map_err(|e| Error::Wallet(format!("BdkWallet::create: {}", e)))?;

        for _ in 0..address_index {
            wallet.reveal_next_address(KeychainKind::External);
        }

        let taproot_reserves =
            Self::load_taproot_reserves(&dir, operator_pubkey, network)?;

        Ok(Self {
            inner: Mutex::new(wallet),
            network,
            electrum_url,
            data_dir: dir,
            ledger_id: ledger_id.to_string(),
            account_index,
            address_index: Mutex::new(address_index),
            operator_pubkey,
            taproot_reserves: RwLock::new(taproot_reserves),
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

    /// Full descriptor-scan via Esplora. Walks both keychains from
    /// index 0 with a stop-gap of `SCAN_GAP` so externally-funded
    /// UTXOs (faucet → `ledger address` output) get picked up even
    /// when this process has never revealed any addresses itself.
    ///
    /// Uses BDK's `start_full_scan` rather than `start_sync` —
    /// full_scan registers each scanned spk in the wallet's index
    /// before checking it, so apply_update will recognize matching
    /// txs as wallet-owned. A plain SyncRequest only checks already-
    /// indexed scripts, which gives back-to-back zero-balance reads
    /// when (as in our flow) the daemon's per-ledger BDK wallet has
    /// never had `reveal_next_address` called on it.
    pub fn sync(&self) -> Result<(), Error> {
        const SCAN_GAP: usize = 20;
        let client = EsploraBuilder::new(&self.electrum_url).build_blocking();

        let mut wallet = self.inner.lock().unwrap();
        let request = wallet.start_full_scan();
        let update = client
            .full_scan(request, SCAN_GAP, 5)
            .map_err(|e| Error::Wallet(format!("ledger wallet full_scan: {}", e)))?;
        wallet
            .apply_update(update)
            .map_err(|e| Error::Wallet(format!("ledger wallet apply_update: {}", e)))?;
        let bal = wallet.balance();
        tracing::debug!(
            "LedgerWallet[{} acct={}] sync done: confirmed={}sat pending={}sat utxos={}",
            &self.ledger_id[..16.min(self.ledger_id.len())],
            self.account_index,
            bal.confirmed.to_sat(),
            bal.trusted_pending.to_sat() + bal.untrusted_pending.to_sat(),
            wallet.list_unspent().count(),
        );
        Ok(())
    }

    pub fn operator_pubkey(&self) -> PublicKey {
        self.operator_pubkey
    }

    /// Currently-active Taproot reserves vault for this ledger, if any.
    pub fn taproot_reserves(&self) -> Option<TaprootReservesInfo> {
        self.taproot_reserves.read().unwrap().clone()
    }

    /// Build (but do NOT broadcast) the Q=N Taproot activation tx for
    /// this ledger. Inputs are selected from the ledger's own UTXO set
    /// only — no shared pool with other ledgers, so concurrent
    /// `quorum begin` calls across ledgers can't race.
    ///
    /// **Watch-only signing:** the BDK wallet holds an xpub-only
    /// descriptor; we ask `signer` to ECDSA-sign each input's segwit-v0
    /// sighash via [`KeyPath::Wallet { account, change, index }`]. The
    /// daemon never holds the per-input private key.
    ///
    /// Caller drives broadcast → confs → cosign+commit, then invokes
    /// [`commit_taproot_reserves`] to persist the entry.
    pub fn build_activation_tx(
        &self,
        signer: &dyn Signer,
        quorum_members: Vec<PublicKey>,
        member_expiries: Vec<u32>,
        ledger_hash: [u8; 32],
        amount_sats: u64,
        fee_rate_sat_per_vb: f32,
        // Name of the protocol ruleset the new UTXO commits to. Same
        // value that the QuorumBegin operation will record. Caller's
        // policy decision: rotating an existing legacy ledger usually
        // wants to flip to "cltv-offset-v2"; bootstrapping a new
        // ledger picks whatever the deployer's default is.
        ruleset_name: &str,
    ) -> Result<(TaprootReservesCreateResult, TaprootReservesInfo), Error> {
        use bdk_wallet::bitcoin::ecdsa::Signature as BtcEcdsaSignature;
        use bdk_wallet::bitcoin::hashes::Hash as _;
        use bdk_wallet::bitcoin::sighash::{EcdsaSighashType, SighashCache};
        use bdk_wallet::bitcoin::Witness;
        use deposits_signer_api::{KeyPath, SigPurpose, SigRole, SignContext};

        if quorum_members.len() != member_expiries.len() {
            return Err(Error::Wallet(
                "Quorum members and expiries must have same length".to_string(),
            ));
        }
        let first_expiry = *member_expiries.iter().min().unwrap_or(&0);

        let voter_set = VoterSet::new(self.operator_pubkey, quorum_members.clone());
        // Look up the named ruleset and run its tier_config_factory.
        // The factory takes `quorum_expiry` so cltv-offset-v2 can bake
        // `quorum_expiry + offset` into the leaf scripts; legacy
        // ignores it and returns plain literals.
        let config = if quorum_members.is_empty() {
            ThresholdConfig::custom(vec![ThresholdTier::new(
                1,
                true,
                0,
                "Operator only (no quorum)",
            )])
        } else {
            let ruleset = deposits_core::ruleset::resolve_or_legacy(Some(ruleset_name));
            (ruleset.tier_config_factory)(quorum_members.len() + 1, first_expiry)
        };
        let builder = TapscriptReservesBuilder::new(
            voter_set,
            config,
            self.network,
            ledger_hash,
        );
        let taproot_output = builder
            .build()
            .map_err(|e| Error::Wallet(format!("build taproot reserves: {:?}", e)))?;
        let new_script_pubkey = taproot_output.script_pubkey();

        // Build the PSBT (no sign yet). Drop the BDK lock as soon as we
        // have the PSBT — manual per-input signing only needs the PSBT
        // itself, not the wallet.
        let mut psbt = {
            let mut wallet = self.inner.lock().unwrap();
            let mut tx_builder = wallet.build_tx();
            tx_builder
                .add_recipient(new_script_pubkey.clone(), Amount::from_sat(amount_sats))
                .fee_rate(FeeRate::from_sat_per_vb_unchecked(
                    fee_rate_sat_per_vb.max(1.0) as u64,
                ));
            tx_builder
                .finish()
                .map_err(|e| Error::Wallet(format!("build activation tx: {}", e)))?
        };

        // Manually sign every input by walking the PSBT's bip32_derivation
        // hints (BDK fills these in based on which descriptor leaf each
        // selected UTXO belongs to). We compute the segwit-v0 sighash
        // ourselves and route it through `signer.ecdsa_sign_sighash`.
        // For the descriptor `wpkh(account_xpub/<change>/*)`, BDK records
        // the path *relative* to the xpub root: a 2-element [change,
        // index] derivation list. The xpub corresponds to BIP-32 account
        // `self.account_index`; the daemon sends that account along to
        // the signer via `KeyPath::Wallet`.
        let unsigned_tx_clone = psbt.unsigned_tx.clone();
        let mut sighash_cache = SighashCache::new(&unsigned_tx_clone);
        let input_count = psbt.inputs.len();
        for input_index in 0..input_count {
            let (script_pubkey, amount, leaf_pubkey, change, leaf_index) = {
                let input = &psbt.inputs[input_index];
                let utxo = input.witness_utxo.as_ref().ok_or_else(|| {
                    Error::Wallet(format!(
                        "PSBT input {} missing witness_utxo (BDK should have populated this)",
                        input_index
                    ))
                })?;
                let (pk, (_fp, path)) = input.bip32_derivation.iter().next().ok_or_else(|| {
                    Error::Wallet(format!(
                        "PSBT input {} has no bip32_derivation entry",
                        input_index
                    ))
                })?;
                let comps: Vec<u32> = path.into_iter().map(|c| (*c).into()).collect();
                if comps.len() != 2 {
                    return Err(Error::Wallet(format!(
                        "PSBT input {} bip32 path length {} != 2 (expected [change, index] \
                         relative to descriptor xpub)",
                        input_index,
                        comps.len()
                    )));
                }
                if comps[0] > 1 {
                    return Err(Error::Wallet(format!(
                        "PSBT input {} change={} (must be 0 or 1)",
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

            // BDK's `p2wpkh_signature_hash` wants the *prevout's*
            // scriptPubKey (the P2WPKH `OP_0 <pkh>` form). It builds
            // the BIP-143 script_code internally.
            let sighash = sighash_cache
                .p2wpkh_signature_hash(input_index, &script_pubkey, amount, EcdsaSighashType::All)
                .map_err(|e| {
                    Error::Wallet(format!(
                        "compute p2wpkh sighash for input {}: {:?}",
                        input_index, e
                    ))
                })?;

            let ctx = SignContext {
                role: SigRole::NoLedger,
                purpose: SigPurpose::OnchainSighash,
                key: KeyPath::Wallet {
                    account: self.account_index,
                    change,
                    index: leaf_index,
                },
            };
            let sig = signer
                .ecdsa_sign_sighash(&ctx, sighash.as_byte_array())
                .map_err(|e| {
                    Error::Wallet(format!(
                        "signer ECDSA sign for input {} (account={}, change={}, index={}): {}",
                        input_index, self.account_index, change, leaf_index, e
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
            // Wipe the partial fields BDK populated; finalization just
            // needs `final_script_witness`.
            psbt.inputs[input_index].partial_sigs.clear();
            psbt.inputs[input_index].bip32_derivation.clear();
        }

        let tx = psbt
            .extract_tx()
            .map_err(|e| Error::Wallet(format!("extract activation tx: {}", e)))?;

        let vout = tx
            .output
            .iter()
            .position(|o| o.script_pubkey == new_script_pubkey)
            .ok_or_else(|| {
                Error::Wallet("Taproot reserves output not in activation tx".to_string())
            })? as u32;
        let new_outpoint = OutPoint {
            txid: tx.compute_txid(),
            vout,
        };
        let new_info = TaprootReservesInfo {
            outpoint: new_outpoint,
            amount: amount_sats,
            operator: self.operator_pubkey,
            quorum_members: quorum_members.clone(),
            quorum_expiry: first_expiry,
            ledger_hash,
            taproot_output: taproot_output.clone(),
            ruleset_name: ruleset_name.to_string(),
            confirmed: false,
        };
        tracing::info!(
            "LedgerWallet[{}] built activation tx: {}sat → {}, Q={}, expiry block {}",
            &self.ledger_id[..16.min(self.ledger_id.len())],
            amount_sats,
            new_outpoint,
            quorum_members.len(),
            first_expiry,
        );
        let result = TaprootReservesCreateResult {
            outpoint: new_outpoint,
            address: taproot_output.address.clone(),
            amount: amount_sats,
            tx,
            taproot_output,
            quorum_expiry: first_expiry,
            ledger_hash,
        };
        Ok((result, new_info))
    }

    /// Persist the Taproot reserves entry. Call after the activation tx
    /// has been broadcast AND the QuorumBegin ledger op has committed.
    ///
    /// Before persisting, verifies the snapshot's `script_pubkey` matches
    /// the actual scriptpubkey at the broadcast outpoint via esplora. This
    /// catches "build path produced a different script than what we
    /// broadcast" — the inverse of the overwrite bug
    /// [`save_taproot_reserves`] guards against. With both checks in
    /// place, every recoverability path is covered: initial write must
    /// match chain, subsequent writes can't disagree with the locked
    /// script.
    ///
    /// Fail-close on script mismatch; fail-open with a warning on esplora
    /// fetch failure (3 retries with exponential backoff) so a transient
    /// outage doesn't block legitimate rotations.
    pub fn commit_taproot_reserves(&self, info: TaprootReservesInfo) -> Result<(), Error> {
        let outpoint = info.outpoint;
        let member_count = info.quorum_members.len();

        let snapshot_script = info.taproot_output.script_pubkey();
        match Self::fetch_outpoint_script_with_retry(&self.electrum_url, &outpoint) {
            Ok(Some(on_chain)) => {
                if on_chain != snapshot_script {
                    return Err(Error::Wallet(format!(
                        "refusing to commit taproot reserves at {}: snapshot \
                         script_pubkey={} differs from on-chain script_pubkey={}. \
                         The build path computed a different script than what was \
                         broadcast — recoverability would be lost. Investigate the \
                         build inputs before retrying.",
                        outpoint,
                        hex::encode(snapshot_script.as_bytes()),
                        hex::encode(on_chain.as_bytes()),
                    )));
                }
            }
            Ok(None) => {
                tracing::warn!(
                    "LedgerWallet[{}] outpoint {} not visible on chain or mempool yet — \
                     skipping verify-against-chain. Snapshot will be persisted; subsequent \
                     overwrites are still blocked by save_taproot_reserves guard.",
                    &self.ledger_id[..16.min(self.ledger_id.len())],
                    outpoint,
                );
            }
            Err(e) => {
                tracing::warn!(
                    "LedgerWallet[{}] verify-against-chain failed for {} after retries: {} — \
                     proceeding with persist; if the snapshot is wrong it will be caught at \
                     spend time, but not before then",
                    &self.ledger_id[..16.min(self.ledger_id.len())],
                    outpoint,
                    e,
                );
            }
        }

        Self::save_taproot_reserves(&self.data_dir, &info)?;
        *self.taproot_reserves.write().unwrap() = Some(info);
        tracing::info!(
            "LedgerWallet[{}] committed taproot reserves {} (Q={})",
            &self.ledger_id[..16.min(self.ledger_id.len())],
            outpoint,
            member_count,
        );
        Ok(())
    }

    /// Adopt an on-chain Q=N taproot vault into this wallet's local state.
    ///
    /// Recovery path for when `quorum begin` broadcast the activation tx but
    /// never persisted the taproot record — e.g. a daemon timeout/restart
    /// during the post-broadcast confirmation wait, the failure mode the
    /// persist-after-broadcast fix closes going forward. The funds are sitting
    /// in the vault on-chain; this re-derives the local view so `quorum begin`
    /// hits its `pending_resume` path and completes.
    ///
    /// Correctness is verified, not assumed: for each candidate `quorum_expiry`
    /// it rebuilds the vault output with the exact same builder the activation
    /// used (`VoterSet` + ruleset tier factory) and keeps the one whose
    /// scriptPubKey matches `onchain_script`. A mismatch on every candidate is
    /// an error rather than a guess, so we never persist a record the daemon
    /// would later fail to spend. Persistence goes through the normal
    /// [`commit_taproot_reserves`] path (verify-against-chain + full serde),
    /// making the written record byte-identical to a healthy run's.
    ///
    /// Caller must stop the daemon first (this instantiates a wallet that would
    /// otherwise contend with the running one).
    pub fn adopt_taproot_from_chain(
        &self,
        vault_outpoint: OutPoint,
        onchain_script: bdk_wallet::bitcoin::ScriptBuf,
        amount: u64,
        quorum_members: Vec<PublicKey>,
        ledger_hash: [u8; 32],
        ruleset_name: &str,
        candidate_expiries: &[u32],
    ) -> Result<TaprootReservesInfo, Error> {
        let ruleset = deposits_core::ruleset::resolve_or_legacy(Some(ruleset_name));
        for &expiry in candidate_expiries {
            let voter_set = VoterSet::new(self.operator_pubkey, quorum_members.clone());
            // Mirror build_activation_tx exactly: factory takes the full voter
            // count (members + operator) and the first expiry.
            let config = (ruleset.tier_config_factory)(quorum_members.len() + 1, expiry);
            let taproot_output =
                TapscriptReservesBuilder::new(voter_set, config, self.network, ledger_hash)
                    .build()
                    .map_err(|e| Error::Wallet(format!("rebuild taproot output: {:?}", e)))?;
            if taproot_output.script_pubkey() == onchain_script {
                let info = TaprootReservesInfo {
                    outpoint: vault_outpoint,
                    amount,
                    operator: self.operator_pubkey,
                    quorum_members,
                    quorum_expiry: expiry,
                    ledger_hash,
                    taproot_output,
                    ruleset_name: ruleset_name.to_string(),
                    confirmed: true,
                };
                self.commit_taproot_reserves(info.clone())?;
                return Ok(info);
            }
        }
        Err(Error::Wallet(format!(
            "could not reconstruct the vault at {}: no expiry in the searched window \
             reproduced the on-chain scriptPubKey under ruleset '{}' with {} quorum \
             members. The members, ledger hash, or ruleset likely differ from what the \
             activation tx was built with — widen --expiry-search or pass --quorum-expiry / \
             --protocol-version explicitly.",
            vault_outpoint,
            ruleset_name,
            quorum_members.len()
        )))
    }

    /// Fetch the scriptpubkey at the given outpoint via esplora, with 3
    /// retries on transient errors (exponential backoff: 500ms, 1s, 2s).
    /// Returns Ok(None) if the tx is genuinely not found (404) — the tx
    /// may not have propagated yet. Returns Err only on persistent
    /// transport/parse errors.
    fn fetch_outpoint_script_with_retry(
        esplora_url: &str,
        outpoint: &OutPoint,
    ) -> Result<Option<bdk_wallet::bitcoin::ScriptBuf>, String> {
        let backend = crate::chain_backend::from_env(esplora_url);
        let mut last_err: Option<String> = None;
        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(500 << (attempt - 1)));
            }
            match backend.get_tx(&outpoint.txid) {
                Ok(Some(tx)) => {
                    let vout = outpoint.vout as usize;
                    match tx.output.get(vout) {
                        Some(o) => return Ok(Some(o.script_pubkey.clone())),
                        None => {
                            return Err(format!(
                                "tx {} has only {} outputs, requested vout {}",
                                outpoint.txid,
                                tx.output.len(),
                                outpoint.vout
                            ))
                        }
                    }
                }
                Ok(None) => return Ok(None),
                Err(e) => last_err = Some(format!("{}", e)),
            }
        }
        Err(last_err.unwrap_or_else(|| "unknown error".to_string()))
    }

    /// Mark the Taproot reserves UTXO as confirmed on-chain.
    pub fn confirm_taproot_reserves(&self, outpoint: &OutPoint) -> Result<(), Error> {
        let mut guard = self.taproot_reserves.write().unwrap();
        let info = guard.as_mut().ok_or_else(|| {
            Error::Wallet(format!(
                "no taproot reserves tracked for ledger {}",
                self.ledger_id,
            ))
        })?;
        if info.outpoint != *outpoint {
            return Err(Error::Wallet(format!(
                "outpoint mismatch: tracked {} != requested {}",
                info.outpoint, outpoint
            )));
        }
        info.confirmed = true;
        let snapshot = info.clone();
        drop(guard);
        Self::save_taproot_reserves(&self.data_dir, &snapshot)
    }

    /// Broadcast a tx and stamp it into BDK's mempool view so a
    /// subsequent build_tx on this wallet won't re-pick the same
    /// inputs.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, Error> {
        let txid = crate::chain_backend::from_env(&self.electrum_url).broadcast_tx(tx)?;

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

    fn taproot_reserves_path(dir: &Path) -> PathBuf {
        dir.join("taproot_reserves.json")
    }

    fn load_taproot_reserves(
        dir: &Path,
        operator_pubkey: PublicKey,
        network: Network,
    ) -> Result<Option<TaprootReservesInfo>, Error> {
        use bdk_wallet::bitcoin::Txid;

        let path = Self::taproot_reserves_path(dir);
        if !path.exists() {
            return Ok(None);
        }
        let contents = fs::read_to_string(&path)
            .map_err(|e| Error::Wallet(format!("read taproot_reserves.json: {}", e)))?;
        let serde_info: TaprootReservesInfoSerde = serde_json::from_str(&contents)
            .map_err(|e| Error::Wallet(format!("parse taproot_reserves.json: {}", e)))?;

        let txid = Txid::from_str(&serde_info.outpoint_txid)
            .map_err(|e| Error::Wallet(format!("invalid txid: {}", e)))?;
        let outpoint = OutPoint {
            txid,
            vout: serde_info.outpoint_vout,
        };
        let operator = PublicKey::from_str(&serde_info.operator)
            .map_err(|e| Error::Wallet(format!("invalid operator pubkey: {}", e)))?;
        let quorum_members: Result<Vec<PublicKey>, _> = serde_info
            .quorum_members
            .iter()
            .map(|p| PublicKey::from_str(p))
            .collect();
        let quorum_members = quorum_members
            .map_err(|e| Error::Wallet(format!("invalid quorum member pubkey: {}", e)))?;
        let ledger_hash_bytes = hex::decode(&serde_info.ledger_hash)
            .map_err(|e| Error::Wallet(format!("invalid ledger hash hex: {}", e)))?;
        if ledger_hash_bytes.len() != 32 {
            return Err(Error::Wallet("ledger hash != 32 bytes".to_string()));
        }
        let mut ledger_hash = [0u8; 32];
        ledger_hash.copy_from_slice(&ledger_hash_bytes);

        let voter_set = VoterSet::new(operator_pubkey, quorum_members.clone());
        // Look up the persisted ruleset and run its tier_config_factory
        // so the rebuilt script matches the on-chain UTXO. Pre-versioned
        // files lack `ruleset_name`; serde defaults that to "legacy".
        let config = if quorum_members.is_empty() {
            ThresholdConfig::custom(vec![ThresholdTier::new(1, true, 0, "Operator only")])
        } else {
            let ruleset =
                deposits_core::ruleset::resolve_or_legacy(Some(&serde_info.ruleset_name));
            (ruleset.tier_config_factory)(
                quorum_members.len() + 1,
                serde_info.quorum_expiry,
            )
        };
        let taproot_output = TapscriptReservesBuilder::new(
            voter_set,
            config,
            network,
            ledger_hash,
        )
        .build()
        .map_err(|e| Error::Wallet(format!("rebuild taproot output: {:?}", e)))?;

        Ok(Some(TaprootReservesInfo {
            outpoint,
            amount: serde_info.amount,
            operator,
            quorum_members,
            quorum_expiry: serde_info.quorum_expiry,
            ledger_hash,
            taproot_output,
            ruleset_name: serde_info.ruleset_name,
            confirmed: serde_info.confirmed,
        }))
    }

    /// Persist the taproot reserves snapshot, refusing to silently overwrite
    /// a snapshot whose `script_pubkey` doesn't match `info`'s. This is the
    /// guard that prevents the historical "metadata-write path used stale
    /// inputs, produced a different scriptPubKey than the on-chain reality,
    /// silently overwrote the correct snapshot" bug class (see commits
    /// 61b375c5 / 830a3a24 / e52e5cd4 for the production case that motivated
    /// this).
    ///
    /// Mutating only the `confirmed` flag (same outpoint, same script) is
    /// allowed; everything else is rejected with a loud error so the operator
    /// notices instead of losing recoverability silently.
    fn save_taproot_reserves(dir: &Path, info: &TaprootReservesInfo) -> Result<(), Error> {
        let path = Self::taproot_reserves_path(dir);
        if path.exists() {
            if let Ok(raw) = fs::read_to_string(&path) {
                if let Ok(existing) = serde_json::from_str::<TaprootReservesInfoSerde>(&raw) {
                    // The pre-Phase-1 format lacks `script_pubkey`; in that case
                    // we can't compare, so allow the write (the next write will
                    // populate the field and lock in the guard).
                    let new_spk = hex::encode(info.taproot_output.script_pubkey().as_bytes());
                    if let Some(ref existing_spk) = existing.script_pubkey {
                        // Allow overwrite when the outpoint differs — that's a
                        // genuine rotation moving to a new UTXO. The script
                        // is expected to change with each rotation (new
                        // quorum_expiry / members produce a different vault
                        // address). The bug class this guard targets is the
                        // metadata-write path producing a different script
                        // for the *same* outpoint — i.e., the in-memory
                        // snapshot disagrees with the existing UTXO's actual
                        // script. Only refuse when outpoint matches but
                        // script doesn't.
                        let existing_txid = existing
                            .outpoint_txid
                            .parse::<bdk_wallet::bitcoin::Txid>()
                            .ok();
                        let same_outpoint = existing_txid
                            .map(|t| t == info.outpoint.txid && existing.outpoint_vout == info.outpoint.vout)
                            .unwrap_or(true);
                        if same_outpoint && existing_spk != &new_spk {
                            return Err(Error::Wallet(format!(
                                "refusing to overwrite taproot snapshot at {}: same outpoint \
                                 {} but existing script_pubkey={} differs from new {}. This \
                                 indicates the build path computed a different script than \
                                 what was committed at this outpoint — would lose the ability \
                                 to spend the on-chain UTXO. Investigate the build inputs \
                                 before retrying.",
                                path.display(),
                                info.outpoint,
                                existing_spk,
                                new_spk,
                            )));
                        }
                    }
                }
            }
        }
        Self::save_taproot_reserves_unchecked(dir, info)
    }

    fn save_taproot_reserves_unchecked(
        dir: &Path,
        info: &TaprootReservesInfo,
    ) -> Result<(), Error> {
        // Capture the on-chain scriptPubKey + internal key + per-tier control
        // blocks. With these in the snapshot, recovery doesn't need to
        // rebuild the script tree from inputs — it can sign with the
        // persisted leaves directly, immune to future builder code drift.
        let script_pubkey = Some(hex::encode(info.taproot_output.script_pubkey().as_bytes()));
        let internal_key = Some(hex::encode(info.taproot_output.internal_key().serialize()));
        let mut tier_leaves: Vec<TierLeafSerde> = Vec::new();
        for (tier_index, tier) in info.taproot_output.config.tiers.iter().enumerate() {
            use deposits_core::TapscriptReservesBuilder;
            let builder = TapscriptReservesBuilder::new(
                info.taproot_output.voter_set.clone(),
                info.taproot_output.config.clone(),
                info.taproot_output.network,
                info.taproot_output.ledger_hash,
            );
            let leaf_script = match builder.build_threshold_leaf(tier) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "save_taproot_reserves: tier {} leaf rebuild failed: {:?}",
                        tier_index,
                        e
                    );
                    continue;
                }
            };
            let control_block = match info.taproot_output.control_block_for_tier(tier_index) {
                Some(cb) => cb,
                None => {
                    tracing::warn!(
                        "save_taproot_reserves: tier {} control block missing",
                        tier_index
                    );
                    continue;
                }
            };
            tier_leaves.push(TierLeafSerde {
                tier_index: tier_index as u32,
                script_hex: hex::encode(leaf_script.as_bytes()),
                control_block_hex: hex::encode(control_block.serialize()),
            });
        }

        let serde = TaprootReservesInfoSerde {
            outpoint_txid: info.outpoint.txid.to_string(),
            outpoint_vout: info.outpoint.vout,
            amount: info.amount,
            operator: info.operator.to_string(),
            quorum_members: info.quorum_members.iter().map(|p| p.to_string()).collect(),
            quorum_expiry: info.quorum_expiry,
            ledger_hash: hex::encode(info.ledger_hash),
            address: info.taproot_output.address.to_string(),
            confirmed: info.confirmed,
            ruleset_name: info.ruleset_name.clone(),
            script_pubkey,
            internal_key,
            tier_leaves,
        };
        let json = serde_json::to_string_pretty(&serde)
            .map_err(|e| Error::Wallet(format!("serialize taproot_reserves: {}", e)))?;
        fs::write(Self::taproot_reserves_path(dir), json)
            .map_err(|e| Error::Wallet(format!("write taproot_reserves.json: {}", e)))?;
        Ok(())
    }
}

/// Per-ledger persistence shape for `taproot_reserves.json`. One entry
/// per file (each ledger has at most one active vault).
#[derive(serde::Serialize, serde::Deserialize)]
struct TaprootReservesInfoSerde {
    outpoint_txid: String,
    outpoint_vout: u32,
    amount: u64,
    operator: String,
    quorum_members: Vec<String>,
    quorum_expiry: u32,
    ledger_hash: String, // hex
    address: String,
    confirmed: bool,
    /// Pre-existing files don't have this; serde default fills in
    /// `"legacy"` so the reconstruction path stays consistent with
    /// the on-chain UTXO that file describes.
    #[serde(default = "default_ruleset_name")]
    ruleset_name: String,

    // ------------------------------------------------------------------
    // Self-describing tree snapshot (added 2026-05-29). Sweep / recovery
    // paths prefer these over rebuilding from (operator, members,
    // ledger_hash, expiry, ruleset_name) so future builder changes can't
    // make an old vault unspendable.
    //
    // Old JSONs predate these fields; `#[serde(default)]` makes them
    // backward-compatible — readers fall back to current-code rebuild.
    // ------------------------------------------------------------------
    /// Hex-encoded on-chain `scriptPubKey` of the vault output. Sanity
    /// check: if a reader's rebuild produces a different script than this,
    /// they MUST trust the persisted leaves / control blocks below over
    /// their own rebuild.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    script_pubkey: Option<String>,
    /// Hex of the 32-byte x-only Taproot internal key the tree was built
    /// against. Lets a reader rebuild the spend_info from the persisted
    /// leaves without re-running the build pipeline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    internal_key: Option<String>,
    /// One entry per tier of the tier-config used at build time, in tier
    /// order (tier_0 = majority-immediate first). Each carries enough to
    /// spend that leaf without rebuilding: the leaf script bytes and the
    /// pre-computed control block (encodes internal key + merkle path).
    #[serde(default)]
    tier_leaves: Vec<TierLeafSerde>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct TierLeafSerde {
    /// Zero-based tier index (0 = tier-0 majority-immediate, etc.).
    tier_index: u32,
    /// Hex of the tapscript leaf bytes (what goes into the witness).
    script_hex: String,
    /// Hex of the control block (what goes into the witness alongside the
    /// leaf script). 33 + 32×n bytes where n is the merkle path length.
    control_block_hex: String,
}

fn default_ruleset_name() -> String {
    "legacy".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use deposits_signer_api::LocalSigner;
    use tempfile::TempDir;

    const SEED: [u8; 32] = [42u8; 32];

    fn signer() -> LocalSigner {
        let xpriv = bdk_wallet::bitcoin::bip32::Xpriv::new_master(Network::Regtest, &SEED)
            .expect("xpriv from seed");
        LocalSigner::from_xpriv(xpriv).expect("from_xpriv")
    }

    fn open(account: u32, ledger_id: &str, root: &Path) -> LedgerWallet {
        LedgerWallet::create(
            &signer(),
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
            &signer(),
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
            &signer(),
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

    /// Recovery: `adopt_taproot_from_chain` must reconstruct the exact
    /// `quorum_expiry` from the on-chain vault scriptPubKey by brute-force, and
    /// refuse (not guess) when the searched window misses it. This is the
    /// correctness backstop for the stranded-vault recovery path: the activation
    /// tx's P2TR commits to the expiry (cltv-offset-v2 bakes it into the leaf
    /// CLTVs), so the scriptPubKey uniquely identifies it.
    #[test]
    fn adopt_vault_bruteforces_correct_expiry() {
        use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};
        let tmp = TempDir::new().unwrap();
        let w = open(3, "ledger_adopt", tmp.path());

        let secp = Secp256k1::new();
        let members: Vec<PublicKey> = (1u8..=3)
            .map(|i| PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[i; 32]).unwrap()))
            .collect();
        let ledger_hash = [9u8; 32];
        let ruleset_name = "cltv-offset-v2";
        let expiry_true: u32 = 100_000;

        // Build the vault scriptPubKey exactly as build_activation_tx would, for
        // a given expiry. This is the "on-chain" output the recovery sees.
        let build_spk = |expiry: u32| {
            let voter_set = VoterSet::new(w.operator_pubkey(), members.clone());
            let ruleset = deposits_core::ruleset::resolve_or_legacy(Some(ruleset_name));
            let config = (ruleset.tier_config_factory)(members.len() + 1, expiry);
            TapscriptReservesBuilder::new(voter_set, config, Network::Regtest, ledger_hash)
                .build()
                .unwrap()
                .script_pubkey()
        };
        let true_spk = build_spk(expiry_true);
        // Neighbouring expiries produce different scripts — so the match is
        // unambiguous and a wide search window stays safe.
        assert_ne!(build_spk(expiry_true - 1), true_spk);
        assert_ne!(build_spk(expiry_true + 1), true_spk);

        // Window straddling the true expiry → adopts it.
        let candidates: Vec<u32> = (expiry_true - 2..=expiry_true + 2).collect();
        let info = w
            .adopt_taproot_from_chain(
                OutPoint::null(),
                true_spk.clone(),
                39_000,
                members.clone(),
                ledger_hash,
                ruleset_name,
                &candidates,
            )
            .expect("adopt should reconstruct the vault");
        assert_eq!(info.quorum_expiry, expiry_true);
        assert_eq!(info.amount, 39_000);
        assert_eq!(info.taproot_output.script_pubkey(), true_spk);

        // Window that misses the true expiry → error, never a wrong guess.
        let bad: Vec<u32> = (expiry_true + 10..=expiry_true + 12).collect();
        assert!(w
            .adopt_taproot_from_chain(
                OutPoint::null(),
                true_spk,
                39_000,
                members,
                ledger_hash,
                ruleset_name,
                &bad,
            )
            .is_err());
    }

    /// Three sibling per-ledger wallets at accounts 0/1/2 must keep
    /// their UTXO sets disjoint — receiving funds at one account's
    /// address must NOT show up in the other two wallets' balances.
    /// Reproduces the cluster-level "4 BTC available" misread by
    /// stripping Esplora out of the loop and feeding txs directly via
    /// BDK's mempool API.
    #[test]
    fn sibling_accounts_do_not_share_utxos() {
        use bdk_wallet::bitcoin::{
            absolute::LockTime, transaction::Version, Amount, OutPoint, Sequence, Transaction,
            TxIn, TxOut, Witness,
        };

        let tmp = TempDir::new().unwrap();
        let w0 = open(0, "L0", tmp.path());
        let w1 = open(1, "L1", tmp.path());
        let w2 = open(2, "L2", tmp.path());

        // Reveal the first address on each wallet to mirror the
        // production flow (CLI calls `ledger address` once before
        // pre-funding).
        let a0 = w0.get_new_address().unwrap();
        let a1 = w1.get_new_address().unwrap();
        let a2 = w2.get_new_address().unwrap();
        assert_ne!(a0, a1);
        assert_ne!(a1, a2);
        assert_ne!(a0, a2);

        // Build a synthetic funding tx that pays 1 BTC to each of the
        // three addresses. Inputs are bogus (we're injecting it via
        // `apply_unconfirmed_txs` which doesn't validate them).
        let funding_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Default::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000_000),
                    script_pubkey: a0.script_pubkey(),
                },
                TxOut {
                    value: Amount::from_sat(100_000_000),
                    script_pubkey: a1.script_pubkey(),
                },
                TxOut {
                    value: Amount::from_sat(100_000_000),
                    script_pubkey: a2.script_pubkey(),
                },
            ],
        };

        // Apply to each wallet — same tx, same time. BDK should fold
        // only the spk-matching outputs into each wallet's UTXO set.
        let now = 1_700_000_000u64;
        for w in [&w0, &w1, &w2] {
            let mut inner = w.inner.lock().unwrap();
            inner.apply_unconfirmed_txs(std::iter::once((funding_tx.clone(), now)));
        }

        // Each wallet should see exactly 1 BTC trusted-pending — its
        // own output. Untrusted-pending should be zero (BDK trusts
        // unconfirmed payments to its own descriptors by default).
        for (i, w) in [&w0, &w1, &w2].iter().enumerate() {
            let inner = w.inner.lock().unwrap();
            let bal = inner.balance();
            let total = bal.confirmed.to_sat()
                + bal.trusted_pending.to_sat()
                + bal.untrusted_pending.to_sat();
            assert_eq!(
                total, 100_000_000,
                "wallet at account {} saw {} sats (confirmed={}, trusted={}, untrusted={}); \
                 expected 100_000_000 — sibling-account UTXO leak?",
                i,
                total,
                bal.confirmed.to_sat(),
                bal.trusted_pending.to_sat(),
                bal.untrusted_pending.to_sat(),
            );
        }
    }

    /// Regression test for the silent-overwrite bug: once a snapshot has been
    /// persisted with a script_pubkey (Phase 1+ format), any subsequent save
    /// with a DIFFERENT script_pubkey must be rejected. This is the structural
    /// guard against the historical d269a384-era "metadata-write path used
    /// stale inputs, overwrote the correct snapshot with a wrong one" bug.
    #[test]
    fn save_taproot_reserves_refuses_to_overwrite_different_script() {
        use deposits_core::tapscript_reserves::{
            TapscriptReservesBuilder, ThresholdConfig, VoterSet,
        };
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

        let tmp = TempDir::new().unwrap();
        let secp = Secp256k1::new();

        // Build two TaprootReservesInfo with the SAME operator/members but
        // DIFFERENT ledger_hashes (mirrors the production drift pattern).
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let operator = PublicKey::from_secret_key(&secp, &sk);
        let other_sk = SecretKey::from_slice(&[11u8; 32]).unwrap();
        let member = PublicKey::from_secret_key(&secp, &other_sk);
        let voter_set = VoterSet::new(operator, vec![member]);
        let config = ThresholdConfig::default_for_voter_count(2);

        let h_correct: [u8; 32] = [0xaa; 32];
        let h_wrong: [u8; 32] = [0xbb; 32];

        let make = |h: [u8; 32]| -> TaprootReservesInfo {
            let builder = TapscriptReservesBuilder::new(
                voter_set.clone(),
                config.clone(),
                Network::Regtest,
                h,
            );
            let taproot_output = builder.build().expect("build");
            TaprootReservesInfo {
                outpoint: OutPoint {
                    txid: Txid::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000001",
                    )
                    .unwrap(),
                    vout: 0,
                },
                amount: 100_000,
                operator,
                quorum_members: vec![member],
                quorum_expiry: 1000,
                ledger_hash: h,
                taproot_output,
                ruleset_name: "legacy".to_string(),
                confirmed: false,
            }
        };

        let correct = make(h_correct);
        let wrong = make(h_wrong);

        // Sanity: they produce different scripts (otherwise this test is moot)
        assert_ne!(
            correct.taproot_output.script_pubkey(),
            wrong.taproot_output.script_pubkey(),
            "different ledger_hashes must produce different scriptpubkeys for this test to mean anything",
        );

        // First write succeeds.
        LedgerWallet::save_taproot_reserves(tmp.path(), &correct).expect("first save");

        // Same script — confirmed flag flip — allowed.
        let mut still_correct = correct.clone();
        still_correct.confirmed = true;
        LedgerWallet::save_taproot_reserves(tmp.path(), &still_correct)
            .expect("same-script re-save should succeed");

        // Different script — rejected with a loud error.
        let err = LedgerWallet::save_taproot_reserves(tmp.path(), &wrong)
            .expect_err("different-script save MUST be rejected");
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("refusing to overwrite"),
            "error should explain the refusal, got: {}",
            msg
        );
    }

    #[test]
    fn load_fails_when_uninitialized() {
        let tmp = TempDir::new().unwrap();
        match LedgerWallet::load(
            &signer(),
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
