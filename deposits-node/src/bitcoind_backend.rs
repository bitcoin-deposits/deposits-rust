//! [`ChainBackend`] impl talking directly to a bitcoind node via JSON-RPC.
//!
//! The audience payoff is biggest here:
//! every Umbrel/Start9/self-host operator already has a `bitcoind`
//! running, so this backend lets them skip electrs/esplora entirely.
//!
//! ## Auth
//!
//! HTTP basic auth using either an explicit `rpcuser:rpcpassword`
//! (env: `BITCOIND_RPC_USER` + `BITCOIND_RPC_PASS`) or a cookie file
//! (env: `BITCOIND_COOKIE_FILE`). The cookie file is bitcoind's preferred
//! mechanism — auto-generated on each restart at
//! `~/.bitcoin/<network>/.cookie`, contains `__cookie__:<random>` in
//! cleartext, and rotates on every bitcoind restart so we re-read it
//! each call rather than caching.
//!
//! ## Required bitcoind config
//!
//! - `-server=1` (RPC enabled)
//! - `-txindex=1` for `get_tx` on arbitrary txids. Without `txindex`,
//!   `getrawtransaction` only finds wallet-owned txs, which won't cover
//!   fraud-proof verification. Document this requirement in the operator
//!   deployment docs.
//!
//! No ZMQ required for the trait's surface — that's only useful for
//! sub-second mempool notifications, which we don't currently need.
//!
//! ## `find_unspent_output_at`
//!
//! Uses `scantxoutset` with a `raw(<scriptpubkey-hex>)` descriptor. The
//! command rescans the entire UTXO set each call — order of seconds on a
//! mainnet node, milliseconds on regtest. Not on the hot path; called for
//! reserves discovery and recovery flows, both human-driven. If a future
//! caller wants address scanning on the hot path, the right answer is to
//! import the address as watch-only into bitcoind's wallet and use
//! `listunspent`; for now `scantxoutset` is simpler.

use serde::Deserialize;
use std::time::Duration;

use crate::chain_backend::{ChainBackend, UnspentOutput};
use crate::Error;

/// bitcoind JSON-RPC impl of [`ChainBackend`]. Backend selection:
/// `CHAIN_BACKEND=bitcoind`.
pub struct BitcoindRpcBackend {
    /// Base URL of the RPC endpoint, e.g. `http://127.0.0.1:8332`.
    /// Note: bitcoind's RPC port differs from its P2P port; mainnet
    /// default is 8332.
    url: String,
    /// HTTP basic auth source. The cookie path reloads on every call so
    /// bitcoind restarts (which rotate the cookie) don't lock us out.
    auth: AuthSource,
    client: reqwest::blocking::Client,
}

enum AuthSource {
    /// Explicit `rpcuser:rpcpassword` pair, loaded once.
    UserPass { user: String, pass: String },
    /// Path to bitcoind's `.cookie` file; read on every request.
    CookieFile(std::path::PathBuf),
}

impl BitcoindRpcBackend {
    /// Build from explicit config. See [`Self::from_env`] for env-driven
    /// construction.
    pub fn new(
        url: impl Into<String>,
        user: impl Into<String>,
        pass: impl Into<String>,
    ) -> Result<Self, Error> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Wallet(format!("build bitcoind http client: {}", e)))?;
        Ok(Self {
            url: url.into(),
            auth: AuthSource::UserPass {
                user: user.into(),
                pass: pass.into(),
            },
            client,
        })
    }

    /// Build from a cookie file (bitcoind's auto-rotated auth file).
    pub fn from_cookie(
        url: impl Into<String>,
        cookie_file: impl Into<std::path::PathBuf>,
    ) -> Result<Self, Error> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Wallet(format!("build bitcoind http client: {}", e)))?;
        Ok(Self {
            url: url.into(),
            auth: AuthSource::CookieFile(cookie_file.into()),
            client,
        })
    }

    /// Build from environment:
    /// - `BITCOIND_RPC_URL`     (default `http://127.0.0.1:8332`)
    /// - `BITCOIND_RPC_USER` + `BITCOIND_RPC_PASS`, OR
    /// - `BITCOIND_COOKIE_FILE` (path to `.cookie` file)
    pub fn from_env() -> Result<Self, Error> {
        let url = std::env::var("BITCOIND_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8332".to_string());
        match (
            std::env::var("BITCOIND_RPC_USER"),
            std::env::var("BITCOIND_RPC_PASS"),
            std::env::var("BITCOIND_COOKIE_FILE"),
        ) {
            (Ok(u), Ok(p), _) => Self::new(url, u, p),
            (_, _, Ok(c)) => Self::from_cookie(url, c),
            _ => Err(Error::Wallet(
                "BitcoindRpcBackend: must set either BITCOIND_RPC_USER+BITCOIND_RPC_PASS \
                 or BITCOIND_COOKIE_FILE"
                    .to_string(),
            )),
        }
    }

    fn current_auth(&self) -> Result<(String, String), Error> {
        match &self.auth {
            AuthSource::UserPass { user, pass } => Ok((user.clone(), pass.clone())),
            AuthSource::CookieFile(path) => {
                let s = std::fs::read_to_string(path).map_err(|e| {
                    Error::Wallet(format!("read bitcoind cookie {}: {}", path.display(), e))
                })?;
                let (u, p) = s.trim_end().split_once(':').ok_or_else(|| {
                    Error::Wallet(format!(
                        "bitcoind cookie {} not in user:pass form",
                        path.display()
                    ))
                })?;
                Ok((u.to_string(), p.to_string()))
            }
        }
    }

    /// Issue a single JSON-RPC call. Returns the parsed `result` field or
    /// surfaces the bitcoind error.
    fn call<P: serde::Serialize, R: for<'de> serde::Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, Error> {
        let (user, pass) = self.current_auth()?;
        let req = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "deposits-node",
            "method": method,
            "params": params,
        });
        let resp = self
            .client
            .post(&self.url)
            .basic_auth(user, Some(pass))
            .json(&req)
            .send()
            .map_err(|e| Error::Wallet(format!("bitcoind {}: {}", method, e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(Error::Wallet(format!(
                "bitcoind {} returned {}: {}",
                method, status, body
            )));
        }
        let envelope: BitcoindRpcResponse<R> = resp
            .json()
            .map_err(|e| Error::Wallet(format!("bitcoind parse {}: {}", method, e)))?;
        decode_envelope(method, envelope)
    }
}

/// The `result` of a JSON-RPC envelope, or the error bitcoind reported.
fn decode_envelope<R: for<'de> serde::Deserialize<'de>>(
    method: &str,
    envelope: BitcoindRpcResponse<R>,
) -> Result<R, Error> {
    if let Some(err) = envelope.error {
        return Err(Error::Wallet(format!(
            "bitcoind {} error {}: {}",
            method, err.code, err.message
        )));
    }
    // `"result": null` is a real answer for some calls (gettxout on a spent or unknown
    // output): serde folds it into the envelope's `None`, so give it to R as null, which
    // succeeds when R is an Option and fails as before otherwise.
    match envelope.result {
        Some(r) => Ok(r),
        None => serde_json::from_value(serde_json::Value::Null).map_err(|_| {
            Error::Wallet(format!(
                "bitcoind {}: response had neither result nor error",
                method
            ))
        }),
    }
}

// -- JSON-RPC framing ------------------------------------------------------

#[derive(Deserialize)]
struct BitcoindRpcResponse<T> {
    result: Option<T>,
    error: Option<BitcoindRpcError>,
}

#[derive(Deserialize)]
struct BitcoindRpcError {
    code: i64,
    message: String,
}

// -- Method response types -------------------------------------------------

#[derive(Deserialize)]
struct GetBlockVerbose1 {
    /// Number of confirmations; negative when the block is on a stale fork,
    /// 0 when in mempool (n/a for blocks), positive when in best chain.
    confirmations: i64,
    height: u32,
}

#[derive(Deserialize)]
struct GetRawTransactionVerbose {
    #[serde(default)]
    blockhash: Option<String>,
    /// `getrawtransaction` with verbosity=1 returns confirmations as a
    /// distinct field. Used for `get_tx_block_height` confirmation.
    #[serde(default)]
    confirmations: Option<i64>,
}

#[derive(Deserialize)]
struct GetTxOut {
    /// Value in BTC. Multiply by 100_000_000 to get sats.
    value: f64,
}

#[derive(Deserialize)]
struct ScanTxOutSetResult {
    success: bool,
    #[serde(default)]
    unspents: Vec<ScanTxOutUnspent>,
}

#[derive(Deserialize)]
struct ScanTxOutUnspent {
    txid: String,
    vout: u32,
    /// BTC; convert to sats.
    amount: f64,
}

// -- ChainBackend impl -----------------------------------------------------

impl ChainBackend for BitcoindRpcBackend {
    fn get_tip_height(&self) -> Result<u32, Error> {
        self.call("getblockcount", serde_json::json!([]))
    }

    fn get_block_hash(&self, height: u32) -> Result<bitcoin::BlockHash, Error> {
        let s: String = self.call("getblockhash", serde_json::json!([height]))?;
        s.parse()
            .map_err(|e| Error::Wallet(format!("bitcoind getblockhash parse: {}", e)))
    }

    fn get_block_height_if_in_best_chain(
        &self,
        hash: &bitcoin::BlockHash,
    ) -> Result<Option<u32>, Error> {
        // verbosity=1 returns the header summary including confirmations.
        // confirmations > 0 → in best chain at the returned height.
        // confirmations < 0 → known but on a stale fork.
        // RPC error -5 → unknown block → map to Ok(None).
        let result: Result<GetBlockVerbose1, Error> =
            self.call("getblock", serde_json::json!([hash.to_string(), 1]));
        match result {
            Ok(b) => {
                if b.confirmations > 0 {
                    Ok(Some(b.height))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("error -5") || msg.contains("Block not found") {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>, Error> {
        // verbosity=0 returns serialized hex (matches what we want to decode).
        // RPC error -5 → unknown txid → Ok(None). Requires -txindex=1 for
        // unrelated txs; without it bitcoind only knows its own wallet txs.
        let result: Result<String, Error> = self.call(
            "getrawtransaction",
            serde_json::json!([txid.to_string(), 0]),
        );
        match result {
            Ok(hex_str) => {
                use bitcoin::consensus::deserialize;
                let bytes = hex::decode(&hex_str)
                    .map_err(|e| Error::Wallet(format!("bitcoind tx hex: {}", e)))?;
                let tx: bitcoin::Transaction = deserialize(&bytes)
                    .map_err(|e| Error::Wallet(format!("bitcoind tx consensus decode: {}", e)))?;
                Ok(Some(tx))
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("error -5")
                    || msg.contains("No such mempool or blockchain transaction")
                {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn get_tx_block_height(&self, txid: &bitcoin::Txid) -> Result<Option<u32>, Error> {
        // verbose=true (or verbosity=1) returns the JSON header. Look up
        // the blockhash + walk into getblock for the height. If
        // confirmations is None or 0, it's mempool / not confirmed.
        let result: Result<GetRawTransactionVerbose, Error> = self.call(
            "getrawtransaction",
            serde_json::json!([txid.to_string(), true]),
        );
        let info = match result {
            Ok(i) => i,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("error -5") {
                    return Ok(None);
                }
                return Err(e);
            }
        };
        match (info.blockhash, info.confirmations) {
            (Some(h), Some(c)) if c > 0 => {
                let bh: bitcoin::BlockHash = h
                    .parse()
                    .map_err(|e| Error::Wallet(format!("blockhash parse: {}", e)))?;
                self.get_block_height_if_in_best_chain(&bh)
            }
            _ => Ok(None),
        }
    }

    fn is_output_unspent(&self, txid: &bitcoin::Txid, vout: u32) -> Result<Option<bool>, Error> {
        // gettxout: include_mempool=true (third positional arg).
        // Returns null when the output is spent OR doesn't exist; we
        // distinguish those two cases by following up with get_tx if needed.
        let result: Result<Option<GetTxOut>, Error> = self.call(
            "gettxout",
            serde_json::json!([txid.to_string(), vout, true]),
        );
        match result {
            Ok(Some(_)) => Ok(Some(true)),
            Ok(None) => {
                // Distinguish spent (Some(false)) from unknown (None) by
                // checking whether the tx exists at all. If it doesn't,
                // the output is "unknown" — None. If it does, the output
                // exists but is spent — Some(false).
                match self.get_tx(txid)? {
                    Some(tx) => {
                        if (vout as usize) < tx.output.len() {
                            Ok(Some(false))
                        } else {
                            Ok(None)
                        }
                    }
                    None => Ok(None),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn find_unspent_output_at(
        &self,
        script: &bitcoin::Script,
    ) -> Result<Option<UnspentOutput>, Error> {
        // scantxoutset start [{"desc":"raw(<hex>)"}] rescans the UTXO set
        // for outputs matching the descriptor. Expensive (seconds on mainnet,
        // ms on regtest) but doesn't require -txindex and doesn't need the
        // address to be in bitcoind's wallet.
        let desc = format!("raw({})", hex::encode(script.as_bytes()));
        let result: ScanTxOutSetResult = self.call(
            "scantxoutset",
            serde_json::json!(["start", [{ "desc": desc }]]),
        )?;
        if !result.success {
            return Err(Error::Wallet(
                "bitcoind scantxoutset returned success=false".to_string(),
            ));
        }
        let first = match result.unspents.into_iter().next() {
            Some(u) => u,
            None => return Ok(None),
        };
        let txid: bitcoin::Txid = first
            .txid
            .parse()
            .map_err(|e| Error::Wallet(format!("scantxoutset txid parse: {}", e)))?;
        // Convert BTC → sats with rounding to avoid f64 representation drift.
        let value_sats = (first.amount * 100_000_000.0).round() as u64;
        Ok(Some(UnspentOutput {
            outpoint: bitcoin::OutPoint::new(txid, first.vout),
            value_sats,
        }))
    }

    fn find_spending_tx(
        &self,
        outpoint: &bitcoin::OutPoint,
        _script: &bitcoin::Script,
        scan_from_height: u32,
    ) -> Result<Option<bitcoin::Transaction>, Error> {
        // bitcoind has no spent-output index, so walk raw blocks from
        // `scan_from_height` (the funding TX's confirmation height, per
        // the trait contract) up to the tip and scan every tx's inputs.
        // getblock verbosity=0 returns consensus-serialized hex, which
        // avoids depending on the verbose JSON's field shapes.
        //
        // Mempool-only spends are NOT found (we don't trawl getrawmempool
        // — unbounded on mainnet). For the forfeit-sweep caller this is
        // fine: the claim TX it hunts for is necessarily older than the
        // CSV delay, hence confirmed.
        const MAX_SCAN_BLOCKS: u32 = 4320; // ~30 days; unbounded walks are operator error
        let tip = self.get_tip_height()?;
        let start = scan_from_height.min(tip);
        if tip - start > MAX_SCAN_BLOCKS {
            return Err(Error::Wallet(format!(
                "bitcoind find_spending_tx: scan range {}..={} exceeds {} blocks; \
                 pass a tighter scan_from_height or use an esplora/electrum backend",
                start, tip, MAX_SCAN_BLOCKS
            )));
        }
        for height in start..=tip {
            let hash = self.get_block_hash(height)?;
            let block_hex: String =
                self.call("getblock", serde_json::json!([hash.to_string(), 0]))?;
            let block_bytes = hex::decode(&block_hex)
                .map_err(|e| Error::Wallet(format!("bitcoind block hex: {}", e)))?;
            let block: bitcoin::Block = bitcoin::consensus::deserialize(&block_bytes)
                .map_err(|e| Error::Wallet(format!("bitcoind block consensus decode: {}", e)))?;
            for tx in block.txdata {
                if tx.input.iter().any(|i| i.previous_output == *outpoint) {
                    return Ok(Some(tx));
                }
            }
        }
        Ok(None)
    }

    fn confirmed_spend(
        &self,
        outpoint: &bitcoin::OutPoint,
        script: &bitcoin::Script,
        scan_from: u32,
    ) -> Result<crate::chain_backend::ConfirmedSpend, Error> {
        use crate::chain_backend::ConfirmedSpend;
        // include_mempool=false: null means spent on the confirmed chain (the
        // caller has already checked the output exists).
        let confirmed: Option<GetTxOut> = self.call(
            "gettxout",
            serde_json::json!([outpoint.txid.to_string(), outpoint.vout, false]),
        )?;
        if confirmed.is_some() {
            return Ok(ConfirmedSpend::Unspent);
        }
        match self.find_spending_tx(outpoint, script, scan_from)? {
            Some(tx) => match self.get_tx_block_height(&tx.compute_txid())? {
                Some(h) => Ok(ConfirmedSpend::SpentAt(h)),
                None => Ok(ConfirmedSpend::SpentBefore(scan_from)),
            },
            None => Ok(ConfirmedSpend::SpentBefore(scan_from)),
        }
    }

    fn scan_outpoint_spends(
        &self,
        from: u32,
        to: u32,
        watched: &std::collections::HashSet<bitcoin::OutPoint>,
    ) -> Result<Vec<crate::chain_backend::ScannedSpend>, Error> {
        let mut out = Vec::new();
        for height in from..=to {
            let hash = self.get_block_hash(height)?;
            // Verbosity 3 is the one that carries each input's `prevout`.
            let block: serde_json::Value =
                self.call("getblock", serde_json::json!([hash.to_string(), 3]))?;
            let txs = block["tx"].as_array().cloned().unwrap_or_default();
            for t in txs {
                let vin = t["vin"].as_array().cloned().unwrap_or_default();
                let spends: Vec<bitcoin::OutPoint> = vin
                    .iter()
                    .filter_map(|i| {
                        Some(bitcoin::OutPoint::new(
                            i["txid"].as_str()?.parse().ok()?,
                            i["vout"].as_u64()? as u32,
                        ))
                    })
                    .collect();
                if !spends.iter().any(|o| watched.contains(o)) {
                    continue;
                }
                let tx_hex = t["hex"]
                    .as_str()
                    .ok_or_else(|| Error::Wallet("getblock 3: tx without hex".into()))?;
                let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
                    &hex::decode(tx_hex)
                        .map_err(|e| Error::Wallet(format!("getblock 3: tx hex: {}", e)))?,
                )
                .map_err(|e| Error::Wallet(format!("getblock 3: tx decode: {}", e)))?;
                let prevouts = vin
                    .iter()
                    .map(|i| {
                        let p = &i["prevout"];
                        let sats = (p["value"].as_f64().ok_or("no prevout value")? * 100_000_000.0)
                            .round() as u64;
                        let spk = hex::decode(
                            p["scriptPubKey"]["hex"]
                                .as_str()
                                .ok_or("no prevout script")?,
                        )
                        .map_err(|_| "prevout script hex")?;
                        Ok(bitcoin::TxOut {
                            value: bitcoin::Amount::from_sat(sats),
                            script_pubkey: bitcoin::ScriptBuf::from_bytes(spk),
                        })
                    })
                    .collect::<Result<Vec<_>, &str>>()
                    .map_err(|e| Error::Wallet(format!("getblock 3: {}", e)))?;
                for outpoint in spends.into_iter().filter(|o| watched.contains(o)) {
                    out.push(crate::chain_backend::ScannedSpend {
                        outpoint,
                        tx: tx.clone(),
                        prevouts: prevouts.clone(),
                        block_hash: hash,
                        height,
                    });
                }
            }
        }
        Ok(out)
    }

    fn broadcast_tx(&self, tx: &bitcoin::Transaction) -> Result<bitcoin::Txid, Error> {
        use bitcoin::consensus::serialize;
        let hex_str = hex::encode(serialize(tx));
        let _accepted_txid: String =
            self.call("sendrawtransaction", serde_json::json!([hex_str]))?;
        Ok(tx.compute_txid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: `BitcoindRpcBackend` satisfies `ChainBackend`.
    #[test]
    fn bitcoind_backend_implements_chain_backend() {
        fn assert_backend<T: ChainBackend>() {}
        assert_backend::<BitcoindRpcBackend>();
    }

    /// `getblock <hash> 1` returns a confirmations field that distinguishes
    /// best-chain blocks (positive) from stale-fork blocks (negative).
    #[test]
    fn parses_getblock_verbose1() {
        let json = r#"{
            "hash":"0000000000000000000000000000000000000000000000000000000000000001",
            "confirmations":42,"height":850000,"size":1234,"strippedsize":1234,
            "weight":4936,"version":536870912,"versionHex":"20000000",
            "merkleroot":"abc","tx":[],"time":1700000000,"mediantime":1699999000,
            "nonce":0,"bits":"1d00ffff","difficulty":1,"chainwork":"abc",
            "nTx":0,"previousblockhash":"abc"
        }"#;
        let b: GetBlockVerbose1 = serde_json::from_str(json).unwrap();
        assert_eq!(b.confirmations, 42);
        assert_eq!(b.height, 850_000);
    }

    /// `getrawtransaction <txid> 1` carries blockhash + confirmations when
    /// the tx is confirmed; both are absent for mempool entries.
    #[test]
    fn parses_getrawtransaction_verbose() {
        let confirmed = r#"{
            "txid":"abc","hash":"abc","size":100,"vsize":100,"weight":400,
            "version":2,"locktime":0,"vin":[],"vout":[],
            "blockhash":"0000abc","confirmations":7,"time":1700,"blocktime":1700
        }"#;
        let v: GetRawTransactionVerbose = serde_json::from_str(confirmed).unwrap();
        assert_eq!(v.blockhash.as_deref(), Some("0000abc"));
        assert_eq!(v.confirmations, Some(7));

        let mempool = r#"{
            "txid":"abc","hash":"abc","size":100,"vsize":100,"weight":400,
            "version":2,"locktime":0,"vin":[],"vout":[]
        }"#;
        let v: GetRawTransactionVerbose = serde_json::from_str(mempool).unwrap();
        assert!(v.blockhash.is_none());
        assert!(v.confirmations.is_none());
    }

    /// scantxoutset returns BTC amounts as floats — common bitcoind
    /// gotcha. Verify the round-to-sats conversion handles realistic
    /// gettxout on a spent or unknown output answers `"result": null`; that is `None`, not
    /// an error, for a caller asking for an `Option`.
    #[test]
    fn null_result_is_none_for_an_option() {
        let env: BitcoindRpcResponse<Option<GetTxOut>> =
            serde_json::from_str(r#"{"result":null,"error":null,"id":"x"}"#).unwrap();
        assert!(decode_envelope("gettxout", env).unwrap().is_none());
        let env: BitcoindRpcResponse<u32> =
            serde_json::from_str(r#"{"result":null,"error":null,"id":"x"}"#).unwrap();
        assert!(decode_envelope("getblockcount", env).is_err());
        let env: BitcoindRpcResponse<Option<GetTxOut>> =
            serde_json::from_str(r#"{"result":null,"error":{"code":-8,"message":"bad"},"id":"x"}"#)
                .unwrap();
        assert!(decode_envelope("gettxout", env).is_err());
    }

    /// precision (1 sat = 0.00000001 BTC).
    #[test]
    fn scantxoutset_amount_round_trip() {
        let amount_btc = 0.42_f64;
        let sats = (amount_btc * 100_000_000.0).round() as u64;
        assert_eq!(sats, 42_000_000);
        // Edge case: 1 sat.
        let one_sat = (0.00000001_f64 * 100_000_000.0).round() as u64;
        assert_eq!(one_sat, 1);
    }

    /// Cookie file format: `__cookie__:<random hex>`. Splitter must
    /// handle that AND `user:pass` form (some operators put a real
    /// rpcuser in bitcoin.conf and ignore the cookie).
    #[test]
    fn cookie_split() {
        let cookie = "__cookie__:abcdef1234567890\n";
        let (u, p) = cookie.trim_end().split_once(':').unwrap();
        assert_eq!(u, "__cookie__");
        assert_eq!(p, "abcdef1234567890");
    }
}
