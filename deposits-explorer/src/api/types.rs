use serde::{Deserialize, Serialize};

/// Block summary from electrs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSummary {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub tx_count: usize,
    #[serde(default)]
    pub txids: Vec<String>,
    pub size: u64,
    pub weight: u64,
}

/// Full block info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub id: String,
    pub height: u64,
    pub version: u32,
    pub timestamp: u64,
    pub tx_count: usize,
    pub size: u64,
    pub weight: u64,
    pub merkle_root: String,
    pub previousblockhash: Option<String>,
    pub nonce: u64,
    pub bits: u64,
}

/// Transaction input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    pub txid: String,
    pub vout: u32,
    #[serde(default)]
    pub prevout: Option<TxOutput>,
    pub scriptsig: String,
    #[serde(default)]
    pub witness: Vec<String>,
    pub sequence: u32,
    #[serde(default)]
    pub is_coinbase: bool,
}

/// Transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    #[serde(default)]
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
    /// Set after fetching outspends
    #[serde(skip)]
    pub spending_txid: Option<String>,
    #[serde(skip)]
    pub spending_vin: Option<u32>,
}

/// Transaction info from electrs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub txid: String,
    pub version: u32,
    pub locktime: u32,
    #[serde(rename = "vin")]
    pub inputs: Vec<TxInput>,
    #[serde(rename = "vout")]
    pub outputs: Vec<TxOutput>,
    pub size: u64,
    pub weight: u64,
    pub fee: u64,
    #[serde(default)]
    pub status: TxStatus,
}

/// Transaction confirmation status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TxStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub block_hash: Option<String>,
    #[serde(default)]
    pub block_time: Option<u64>,
}

/// Output spend info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutSpend {
    pub spent: bool,
    #[serde(default)]
    pub txid: Option<String>,
    #[serde(default)]
    pub vin: Option<u32>,
    #[serde(default)]
    pub status: Option<TxStatus>,
}

/// Address info from electrs
#[derive(Debug, Clone)]
pub struct AddressInfo {
    pub address: String,
    pub script_type: String,
    pub funded_txo_count: u64,
    pub funded_txo_sum: u64,
    pub spent_txo_count: u64,
    pub spent_txo_sum: u64,
    pub utxos: Vec<Utxo>,
    pub txs: Vec<TransactionInfo>,
}

/// Address stats from electrs API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressStats {
    pub address: String,
    pub chain_stats: ChainStats,
    pub mempool_stats: ChainStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStats {
    pub funded_txo_count: u64,
    pub funded_txo_sum: u64,
    pub spent_txo_count: u64,
    pub spent_txo_sum: u64,
    pub tx_count: u64,
}

/// UTXO info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: TxStatus,
}

impl TransactionInfo {
    /// Calculate fee rate in sat/vB
    pub fn fee_rate(&self) -> f64 {
        let vsize = (self.weight as f64) / 4.0;
        if vsize > 0.0 {
            self.fee as f64 / vsize
        } else {
            0.0
        }
    }

    /// Get total input value (sum of prevouts)
    pub fn input_value(&self) -> u64 {
        self.inputs
            .iter()
            .filter_map(|i| i.prevout.as_ref().map(|p| p.value))
            .sum()
    }

    /// Get total output value
    pub fn output_value(&self) -> u64 {
        self.outputs.iter().map(|o| o.value).sum()
    }

    /// Check if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].is_coinbase
    }

    /// Get the virtual size (vsize) in vbytes
    pub fn vsize(&self) -> u64 {
        (self.weight + 3) / 4
    }
}

impl AddressInfo {
    /// Get current balance
    pub fn balance(&self) -> u64 {
        self.funded_txo_sum.saturating_sub(self.spent_txo_sum)
    }

    /// Get UTXO count
    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_block_summary() {
        let json = r#"{
            "hash": "0000000000000000000123456789abcdef",
            "height": 800000,
            "timestamp": 1700000000,
            "tx_count": 3500,
            "txids": [],
            "size": 1500000,
            "weight": 4000000
        }"#;

        let block: BlockSummary = serde_json::from_str(json).unwrap();
        assert_eq!(block.height, 800000);
        assert_eq!(block.tx_count, 3500);
        assert_eq!(block.timestamp, 1700000000);
    }

    #[test]
    fn test_parse_transaction() {
        let json = r#"{
            "txid": "abc123def456",
            "version": 2,
            "locktime": 0,
            "vin": [{
                "txid": "prev123",
                "vout": 0,
                "scriptsig": "",
                "witness": [],
                "sequence": 4294967295
            }],
            "vout": [{
                "scriptpubkey": "0014abc123",
                "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 abc123",
                "scriptpubkey_type": "v0_p2wpkh",
                "scriptpubkey_address": "bc1qtest",
                "value": 50000
            }],
            "size": 250,
            "weight": 750,
            "fee": 500,
            "status": {
                "confirmed": true,
                "block_height": 800000
            }
        }"#;

        let tx: TransactionInfo = serde_json::from_str(json).unwrap();
        assert_eq!(tx.txid, "abc123def456");
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 50000);
        assert!(tx.status.confirmed);
        assert_eq!(tx.vsize(), 188); // (750 + 3) / 4
    }

    #[test]
    fn test_transaction_fee_rate() {
        let tx = TransactionInfo {
            txid: "test".to_string(),
            version: 2,
            locktime: 0,
            inputs: vec![],
            outputs: vec![],
            size: 250,
            weight: 1000,
            fee: 500,
            status: TxStatus::default(),
        };

        // vsize = 1000/4 = 250, fee_rate = 500/250 = 2.0 sat/vB
        assert!((tx.fee_rate() - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_parse_utxo() {
        let json = r#"{
            "txid": "abc123",
            "vout": 0,
            "value": 100000,
            "status": {
                "confirmed": true,
                "block_height": 800000
            }
        }"#;

        let utxo: Utxo = serde_json::from_str(json).unwrap();
        assert_eq!(utxo.txid, "abc123");
        assert_eq!(utxo.value, 100000);
        assert!(utxo.status.confirmed);
    }

    #[test]
    fn test_parse_outspend() {
        let json = r#"{
            "spent": true,
            "txid": "spending123",
            "vin": 0
        }"#;

        let outspend: OutSpend = serde_json::from_str(json).unwrap();
        assert!(outspend.spent);
        assert_eq!(outspend.txid, Some("spending123".to_string()));
    }

    #[test]
    fn test_address_balance() {
        let addr = AddressInfo {
            address: "bc1qtest".to_string(),
            script_type: "v0_p2wpkh".to_string(),
            funded_txo_count: 5,
            funded_txo_sum: 1_000_000,
            spent_txo_count: 3,
            spent_txo_sum: 400_000,
            utxos: vec![],
            txs: vec![],
        };

        assert_eq!(addr.balance(), 600_000);
        assert_eq!(addr.utxo_count(), 0);
    }
}
