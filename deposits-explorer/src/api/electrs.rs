use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::Deserialize;

use super::types::*;

/// Electrs REST API client
pub struct ElectrsClient {
    base_url: String,
    client: Client,
}

impl ElectrsClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
        }
    }

    /// Get recent blocks (from tip)
    pub async fn get_blocks(&self) -> Result<Vec<BlockSummary>> {
        let url = format!("{}/blocks", self.base_url);
        self.fetch_blocks_from_url(&url).await
    }

    /// Get blocks starting from a specific height (for pagination)
    pub async fn get_blocks_from_height(&self, start_height: u64) -> Result<Vec<BlockSummary>> {
        let url = format!("{}/blocks/{}", self.base_url, start_height);
        self.fetch_blocks_from_url(&url).await
    }

    async fn fetch_blocks_from_url(&self, url: &str) -> Result<Vec<BlockSummary>> {
        let response: Vec<BlockApiResponse> = self.client.get(url).send().await?.json().await?;

        let mut blocks = Vec::with_capacity(response.len());
        for b in response {
            blocks.push(BlockSummary {
                hash: b.id,
                height: b.height,
                timestamp: b.timestamp,
                tx_count: b.tx_count,
                txids: Vec::new(), // Fetched separately if needed
                size: b.size,
                weight: b.weight,
            });
        }

        Ok(blocks)
    }

    /// Get block by hash
    pub async fn get_block(&self, hash: &str) -> Result<BlockInfo> {
        let url = format!("{}/block/{}", self.base_url, hash);
        let response = self.client.get(&url).send().await?.json().await?;
        Ok(response)
    }

    /// Get block hash by height
    pub async fn get_block_hash(&self, height: u64) -> Result<String> {
        let url = format!("{}/block-height/{}", self.base_url, height);
        let hash = self.client.get(&url).send().await?.text().await?;
        Ok(hash)
    }

    /// Get transactions in a block
    pub async fn get_block_txids(&self, hash: &str) -> Result<Vec<String>> {
        let url = format!("{}/block/{}/txids", self.base_url, hash);
        let txids = self.client.get(&url).send().await?.json().await?;
        Ok(txids)
    }

    /// Get transaction by txid
    pub async fn get_transaction(&self, txid: &str) -> Result<TransactionInfo> {
        let url = format!("{}/tx/{}", self.base_url, txid);
        let mut tx: TransactionInfo = self.client.get(&url).send().await?.json().await?;

        // Check if inputs are coinbase
        if tx.inputs.len() == 1 {
            let input = &tx.inputs[0];
            // Coinbase has all-zero txid
            if input.txid == "0000000000000000000000000000000000000000000000000000000000000000" {
                tx.inputs[0].is_coinbase = true;
            }
        }

        // Fetch outspends to know which outputs are spent
        if let Ok(outspends) = self.get_outspends(txid).await {
            for (i, outspend) in outspends.into_iter().enumerate() {
                if i < tx.outputs.len() && outspend.spent {
                    tx.outputs[i].spending_txid = outspend.txid;
                    tx.outputs[i].spending_vin = outspend.vin;
                }
            }
        }

        Ok(tx)
    }

    /// Get raw transaction hex
    pub async fn get_transaction_hex(&self, txid: &str) -> Result<String> {
        let url = format!("{}/tx/{}/hex", self.base_url, txid);
        let hex = self.client.get(&url).send().await?.text().await?;
        Ok(hex)
    }

    /// Get which outputs of a transaction are spent
    pub async fn get_outspends(&self, txid: &str) -> Result<Vec<OutSpend>> {
        let url = format!("{}/tx/{}/outspends", self.base_url, txid);
        let outspends = self.client.get(&url).send().await?.json().await?;
        Ok(outspends)
    }

    /// Get address info
    pub async fn get_address(&self, address: &str) -> Result<AddressInfo> {
        // Get address stats
        let stats_url = format!("{}/address/{}", self.base_url, address);
        let stats: AddressStats = self.client.get(&stats_url).send().await?.json().await?;

        // Get UTXOs
        let utxo_url = format!("{}/address/{}/utxo", self.base_url, address);
        let utxos: Vec<Utxo> = self.client.get(&utxo_url).send().await?.json().await?;

        // Get recent transactions (limit to 25)
        let txs_url = format!("{}/address/{}/txs", self.base_url, address);
        let txs: Vec<TransactionInfo> = self.client.get(&txs_url).send().await?.json().await?;

        // Determine script type from first UTXO or transaction
        let script_type = if let Some(utxo) = utxos.first() {
            if let Ok(tx) = self.get_transaction(&utxo.txid).await {
                if let Some(output) = tx.outputs.get(utxo.vout as usize) {
                    output.scriptpubkey_type.clone()
                } else {
                    "unknown".to_string()
                }
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        };

        Ok(AddressInfo {
            address: address.to_string(),
            script_type,
            funded_txo_count: stats.chain_stats.funded_txo_count,
            funded_txo_sum: stats.chain_stats.funded_txo_sum,
            spent_txo_count: stats.chain_stats.spent_txo_count,
            spent_txo_sum: stats.chain_stats.spent_txo_sum,
            utxos,
            txs,
        })
    }

    /// Get current chain tip height
    pub async fn get_tip_height(&self) -> Result<u64> {
        let url = format!("{}/blocks/tip/height", self.base_url);
        let height: u64 = self.client.get(&url).send().await?.json().await?;
        Ok(height)
    }

    /// Get current chain tip hash
    pub async fn get_tip_hash(&self) -> Result<String> {
        let url = format!("{}/blocks/tip/hash", self.base_url);
        let hash = self.client.get(&url).send().await?.text().await?;
        Ok(hash)
    }
}

/// Block response from electrs API
#[derive(Debug, Deserialize)]
struct BlockApiResponse {
    id: String,
    height: u64,
    timestamp: u64,
    tx_count: usize,
    size: u64,
    weight: u64,
}
