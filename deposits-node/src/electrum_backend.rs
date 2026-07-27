//! [`ChainBackend`] impl talking to an Electrum server (electrs / fulcrum /
//! ElectrumX) over its plain-TCP JSON-RPC protocol.
//!
//! Covers operators who already run electrs
//! (or fulcrum) for other apps and don't want to also expose bitcoind RPC.
//!
//! ## Protocol
//!
//! Newline-delimited JSON-RPC 2.0 over TCP. Standard ports: 50001 (plain)
//! and 50002 (TLS). This impl supports plain TCP only for v1 — TLS adds
//! cert-pinning complexity that's not worth it when most operators run
//! their electrs on localhost. A future enhancement can add TLS.
//!
//! ## Mapping notes
//!
//! - **`get_block_height_if_in_best_chain`**: electrum has no direct
//!   block-by-hash lookup. We batch-fetch the last 2016 headers (~2 weeks
//!   of confirmations) via `blockchain.block.headers(start, count)`,
//!   double-SHA256 each header, compare to the candidate. Within the
//!   window: returns Some(height). Outside: returns Ok(None). Callers
//!   needing deeper confirmation (cold fraud-proof verification) should
//!   use bitcoind or esplora.
//!
//! - **`is_output_unspent`**: electrum keys outputs by scripthash, not
//!   outpoint. Two round-trips: fetch the tx (`blockchain.transaction.get`)
//!   to learn the output's scriptpubkey, hash it, then check
//!   `blockchain.scripthash.listunspent` for an entry matching
//!   (txid, vout).

use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::chain_backend::{ChainBackend, UnspentOutput};
use crate::Error;

/// Electrum protocol impl of [`ChainBackend`]. Backend selection:
/// `CHAIN_BACKEND=electrum`.
pub struct ElectrumBackend {
    addr: String,
    timeout: Duration,
    /// Monotonic JSON-RPC id, in case the server cares about uniqueness.
    next_id: AtomicU64,
    /// Persistent connection. Electrum servers are happy with long-lived
    /// connections and we save the connect cost per call. Mutex serializes
    /// concurrent calls (electrum is request/response; out-of-order replies
    /// would need a correlation table we don't have).
    conn: Mutex<Option<TcpStream>>,
}

impl ElectrumBackend {
    pub fn new(host: impl AsRef<str>, port: u16) -> Self {
        Self {
            addr: format!("{}:{}", host.as_ref(), port),
            timeout: Duration::from_secs(30),
            next_id: AtomicU64::new(1),
            conn: Mutex::new(None),
        }
    }

    /// Build from environment:
    /// - `ELECTRUM_HOST` (default `127.0.0.1`)
    /// - `ELECTRUM_PORT` (default `50001`)
    pub fn from_env() -> Result<Self, Error> {
        let host = std::env::var("ELECTRUM_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = std::env::var("ELECTRUM_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50001_u16);
        Ok(Self::new(host, port))
    }

    fn call<P: serde::Serialize, R: for<'de> serde::Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, Error> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| Error::Wallet("electrum conn mutex poisoned".to_string()))?;
        // Connect lazily; reconnect on EOF (server dropped us, common on idle).
        if guard.is_none() {
            let stream = TcpStream::connect(&self.addr)
                .map_err(|e| Error::Wallet(format!("electrum connect {}: {}", self.addr, e)))?;
            stream
                .set_read_timeout(Some(self.timeout))
                .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
                .map_err(|e| Error::Wallet(format!("electrum socket timeout: {}", e)))?;
            *guard = Some(stream);
        }

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let mut req_bytes = serde_json::to_vec(&req)
            .map_err(|e| Error::Wallet(format!("electrum serialize {}: {}", method, e)))?;
        req_bytes.push(b'\n');

        let stream = guard.as_mut().expect("just connected above");
        let mut try_call = || -> Result<String, Error> {
            stream
                .write_all(&req_bytes)
                .map_err(|e| Error::Wallet(format!("electrum write {}: {}", method, e)))?;
            stream
                .flush()
                .map_err(|e| Error::Wallet(format!("electrum flush {}: {}", method, e)))?;
            let mut reader = BufReader::new(
                stream
                    .try_clone()
                    .map_err(|e| Error::Wallet(format!("electrum stream clone: {}", e)))?,
            );
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|e| Error::Wallet(format!("electrum read {}: {}", method, e)))?;
            if line.is_empty() {
                return Err(Error::Wallet(format!(
                    "electrum {}: empty response (socket closed?)",
                    method
                )));
            }
            Ok(line)
        };

        // One retry on connection-level error — common after idle.
        let line = match try_call() {
            Ok(l) => l,
            Err(_first_err) => {
                // Drop the connection, reconnect once.
                *guard = None;
                let stream = TcpStream::connect(&self.addr)
                    .map_err(|e| Error::Wallet(format!("electrum reconnect: {}", e)))?;
                stream
                    .set_read_timeout(Some(self.timeout))
                    .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
                    .map_err(|e| Error::Wallet(format!("electrum socket timeout: {}", e)))?;
                *guard = Some(stream);
                let stream = guard.as_mut().expect("just reconnected");
                stream
                    .write_all(&req_bytes)
                    .map_err(|e| Error::Wallet(format!("electrum write {}: {}", method, e)))?;
                stream
                    .flush()
                    .map_err(|e| Error::Wallet(format!("electrum flush {}: {}", method, e)))?;
                let mut reader = BufReader::new(stream.try_clone().map_err(|e| {
                    Error::Wallet(format!("electrum stream clone after reconnect: {}", e))
                })?);
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .map_err(|e| Error::Wallet(format!("electrum read after reconnect: {}", e)))?;
                line
            }
        };

        let resp: ElectrumRpcResponse<R> = serde_json::from_str(&line).map_err(|e| {
            Error::Wallet(format!(
                "electrum parse {}: {} (raw: {})",
                method,
                e,
                line.trim()
            ))
        })?;
        if let Some(err) = resp.error {
            return Err(Error::Wallet(format!("electrum {} error: {}", method, err)));
        }
        resp.result.ok_or_else(|| {
            Error::Wallet(format!(
                "electrum {}: response had neither result nor error",
                method
            ))
        })
    }
}

// -- JSON-RPC framing ------------------------------------------------------

#[derive(Deserialize)]
struct ElectrumRpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

// -- Method response types -------------------------------------------------

#[derive(Deserialize)]
struct HeadersSubscribe {
    height: u32,
    // Other fields like `hex` exist; we don't read them.
}

#[derive(Deserialize)]
struct BlockHeaders {
    count: usize,
    hex: String,
    // `max` field optional, ignored.
}

#[derive(Deserialize)]
struct TxGetVerbose {
    hex: String,
    #[serde(default)]
    confirmations: Option<u64>,
    #[serde(default)]
    blockhash: Option<String>,
}

#[derive(Deserialize)]
struct ScripthashUnspent {
    tx_hash: String,
    tx_pos: u32,
    value: u64,
    // height: u32 — emitted by electrum but we don't currently surface it.
}

#[derive(Deserialize)]
struct ScripthashHistoryItem {
    tx_hash: String,
    // height: i64 — 0/-1 for mempool entries; not currently surfaced.
}

// -- ChainBackend impl -----------------------------------------------------

impl ChainBackend for ElectrumBackend {
    fn get_tip_height(&self) -> Result<u32, Error> {
        let r: HeadersSubscribe =
            self.call("blockchain.headers.subscribe", serde_json::json!([]))?;
        Ok(r.height)
    }

    fn get_block_hash(&self, height: u32) -> Result<bitcoin::BlockHash, Error> {
        let hex_str: String = self.call("blockchain.block.header", serde_json::json!([height]))?;
        block_hash_from_header_hex(&hex_str)
    }

    fn get_block_height_if_in_best_chain(
        &self,
        hash: &bitcoin::BlockHash,
    ) -> Result<Option<u32>, Error> {
        // Walk the last `WINDOW` blocks via batched header fetches; hash each
        // and compare. Outside the window: return Ok(None).
        const WINDOW: u32 = 2016; // ~2 weeks
        const BATCH: u32 = 256;
        let tip = self.get_tip_height()?;
        let start_floor = tip.saturating_sub(WINDOW);
        // Iterate from tip backwards in BATCH-sized chunks. Each batch is
        // returned as concatenated 80-byte headers in hex.
        let mut high = tip;
        while high >= start_floor {
            let batch_start = high.saturating_sub(BATCH - 1).max(start_floor);
            let count = (high - batch_start + 1) as usize;
            let batch: BlockHeaders = self.call(
                "blockchain.block.headers",
                serde_json::json!([batch_start, count]),
            )?;
            if batch.count != count {
                // Server gave us fewer headers than requested — probably
                // means we walked past genesis. Stop.
                break;
            }
            let bytes = hex::decode(&batch.hex)
                .map_err(|e| Error::Wallet(format!("electrum headers hex: {}", e)))?;
            if bytes.len() != 80 * count {
                return Err(Error::Wallet(format!(
                    "electrum headers length mismatch: {} bytes for {} headers",
                    bytes.len(),
                    count
                )));
            }
            for i in 0..count {
                let header = &bytes[80 * i..80 * (i + 1)];
                let h = header_hash(header);
                if &h == hash {
                    return Ok(Some(batch_start + i as u32));
                }
            }
            if batch_start == 0 {
                break;
            }
            high = batch_start - 1;
        }
        Ok(None)
    }

    fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>, Error> {
        // verbose=false returns raw hex. Map known "not found" error to None;
        // surface other errors.
        let result: Result<String, Error> = self.call(
            "blockchain.transaction.get",
            serde_json::json!([txid.to_string(), false]),
        );
        match result {
            Ok(hex_str) => {
                use bitcoin::consensus::deserialize;
                let bytes = hex::decode(&hex_str)
                    .map_err(|e| Error::Wallet(format!("electrum tx hex: {}", e)))?;
                let tx: bitcoin::Transaction = deserialize(&bytes)
                    .map_err(|e| Error::Wallet(format!("electrum tx consensus decode: {}", e)))?;
                Ok(Some(tx))
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("missing transaction") || msg.contains("No such mempool") {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn get_tx_block_height(&self, txid: &bitcoin::Txid) -> Result<Option<u32>, Error> {
        // verbose=true returns a JSON object with `confirmations` and
        // `blockhash`. Mempool: no blockhash, confirmations=0 or absent.
        let result: Result<TxGetVerbose, Error> = self.call(
            "blockchain.transaction.get",
            serde_json::json!([txid.to_string(), true]),
        );
        let verbose = match result {
            Ok(v) => v,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("missing transaction") {
                    return Ok(None);
                }
                return Err(e);
            }
        };
        let _ = verbose.hex; // unused; the trait only wants the block height.
        let confs = verbose.confirmations.unwrap_or(0);
        if confs == 0 {
            return Ok(None);
        }
        let bh: bitcoin::BlockHash = match verbose.blockhash {
            Some(h) => h
                .parse()
                .map_err(|e| Error::Wallet(format!("electrum blockhash parse: {}", e)))?,
            None => return Ok(None),
        };
        self.get_block_height_if_in_best_chain(&bh)
    }

    fn is_output_unspent(&self, txid: &bitcoin::Txid, vout: u32) -> Result<Option<bool>, Error> {
        // Electrum keys outputs by scripthash, not outpoint. Two round
        // trips: fetch the tx to learn the output's scriptpubkey, then
        // look it up in the script's listunspent.
        let tx = match self.get_tx(txid)? {
            Some(t) => t,
            None => return Ok(None),
        };
        let output = match tx.output.get(vout as usize) {
            Some(o) => o,
            None => return Ok(None),
        };
        let sh = scripthash_hex(&output.script_pubkey);
        let unspents: Vec<ScripthashUnspent> =
            self.call("blockchain.scripthash.listunspent", serde_json::json!([sh]))?;
        let txid_hex = txid.to_string();
        let is_unspent = unspents
            .iter()
            .any(|u| u.tx_hash == txid_hex && u.tx_pos == vout);
        Ok(Some(is_unspent))
    }

    fn find_unspent_output_at(
        &self,
        script: &bitcoin::Script,
    ) -> Result<Option<UnspentOutput>, Error> {
        let sh = scripthash_hex(script);
        let unspents: Vec<ScripthashUnspent> =
            self.call("blockchain.scripthash.listunspent", serde_json::json!([sh]))?;
        let first = match unspents.into_iter().next() {
            Some(u) => u,
            None => return Ok(None),
        };
        let txid: bitcoin::Txid = first
            .tx_hash
            .parse()
            .map_err(|e| Error::Wallet(format!("electrum tx_hash parse: {}", e)))?;
        Ok(Some(UnspentOutput {
            outpoint: bitcoin::OutPoint::new(txid, first.tx_pos),
            value_sats: first.value,
        }))
    }

    fn find_spending_tx(
        &self,
        outpoint: &bitcoin::OutPoint,
        script: &bitcoin::Script,
        _scan_from_height: u32,
    ) -> Result<Option<bitcoin::Transaction>, Error> {
        // Electrum keys everything by scripthash. The spender of an
        // outpoint necessarily appears in the script's history (it
        // touches the script by consuming the output), so walk the
        // history and find the tx whose inputs include the outpoint.
        let sh = scripthash_hex(script);
        let history: Vec<ScripthashHistoryItem> =
            self.call("blockchain.scripthash.get_history", serde_json::json!([sh]))?;
        let funding_txid_hex = outpoint.txid.to_string();
        for item in history {
            // Skip the funding tx itself — it pays TO the script, it
            // doesn't spend from it.
            if item.tx_hash == funding_txid_hex {
                continue;
            }
            let txid: bitcoin::Txid = item
                .tx_hash
                .parse()
                .map_err(|e| Error::Wallet(format!("electrum tx_hash parse: {}", e)))?;
            if let Some(tx) = self.get_tx(&txid)? {
                if tx.input.iter().any(|i| i.previous_output == *outpoint) {
                    return Ok(Some(tx));
                }
            }
        }
        Ok(None)
    }

    fn broadcast_tx(&self, tx: &bitcoin::Transaction) -> Result<bitcoin::Txid, Error> {
        use bitcoin::consensus::serialize;
        let hex_str = hex::encode(serialize(tx));
        let _accepted_txid: String = self.call(
            "blockchain.transaction.broadcast",
            serde_json::json!([hex_str]),
        )?;
        Ok(tx.compute_txid())
    }
}

// -- Hash helpers ----------------------------------------------------------

/// Double-SHA256 a serialized block header and wrap in a BlockHash.
fn header_hash(header: &[u8]) -> bitcoin::BlockHash {
    use bitcoin::hashes::Hash as _;
    bitcoin::BlockHash::hash(header)
}

fn block_hash_from_header_hex(hex_str: &str) -> Result<bitcoin::BlockHash, Error> {
    let bytes =
        hex::decode(hex_str).map_err(|e| Error::Wallet(format!("electrum header hex: {}", e)))?;
    if bytes.len() != 80 {
        return Err(Error::Wallet(format!(
            "electrum header length {} != 80",
            bytes.len()
        )));
    }
    Ok(header_hash(&bytes))
}

/// Electrum's scripthash convention: SHA256(scriptpubkey), then BIG-ENDIAN hex
/// (i.e., reverse the bytes before display). This is the inverse of bitcoin's
/// normal little-endian hash display.
fn scripthash_hex(script: &bitcoin::Script) -> String {
    use bitcoin::hashes::{sha256, Hash as _};
    let h = sha256::Hash::hash(script.as_bytes());
    // Reverse: electrum_scripthash is big-endian hex of the raw SHA256.
    let mut bytes = h.to_byte_array();
    bytes.reverse();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: `ElectrumBackend` satisfies `ChainBackend`.
    #[test]
    fn electrum_backend_implements_chain_backend() {
        fn assert_backend<T: ChainBackend>() {}
        assert_backend::<ElectrumBackend>();
    }

    /// Bitcoin block 0 (genesis) header — sanity-check that we hash the
    /// header the same way bitcoind does. Genesis hash on mainnet is
    /// 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.
    #[test]
    fn header_hash_matches_genesis() {
        // 160 hex chars = 80 bytes. Concatenated without whitespace.
        let genesis_header_hex = concat!(
            "010000000000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49",
            "ffff001d",
            "1dac2b7c",
        );
        let h = block_hash_from_header_hex(genesis_header_hex).unwrap();
        assert_eq!(
            h.to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    /// Electrum's scripthash is SHA256(scriptpubkey), bytes REVERSED for
    /// display. Spot-check against a known fixture: an empty script → its
    /// scripthash is sha256(empty) reversed.
    #[test]
    fn scripthash_byte_order_matches_electrum_convention() {
        let empty = bitcoin::ScriptBuf::new();
        let sh = scripthash_hex(empty.as_script());
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // electrum reverses it before hex:
        //                = 55b85278 1b9995a4 4c939b64 e441ae27 24b96f99 c8f4fb9a 141cfc98 42c4b0e3
        assert_eq!(
            sh,
            "55b852781b9995a44c939b64e441ae2724b96f99c8f4fb9a141cfc9842c4b0e3"
        );
    }

    /// Verify the JSON-RPC envelope shape we expect from electrum servers.
    #[test]
    fn parses_envelope_with_result() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":42}"#;
        let r: ElectrumRpcResponse<u32> = serde_json::from_str(json).unwrap();
        assert_eq!(r.result, Some(42));
        assert!(r.error.is_none());
    }

    #[test]
    fn parses_envelope_with_error() {
        let json = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad"}}"#;
        let r: ElectrumRpcResponse<u32> = serde_json::from_str(json).unwrap();
        assert!(r.result.is_none());
        assert!(r.error.is_some());
    }
}
