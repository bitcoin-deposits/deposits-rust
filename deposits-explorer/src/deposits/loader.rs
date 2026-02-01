use anyhow::{anyhow, Result};
use bitcoin::secp256k1::PublicKey;
use deposits_core::Ledger;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use super::types::{LedgerInfo, OperationInfo};

/// Loader for deposits-bdk data directory
pub struct DepositsLoader {
    pub data_dir: PathBuf,
}

/// Serialized ledger entry (matches deposits-bdk format)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerEntry {
    operator: String,
    reserves_id: String,
    ledger: Ledger,
}

impl DepositsLoader {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    /// Load all ledgers from the data directory
    pub fn load_ledgers(&self) -> Result<Vec<LedgerInfo>> {
        let ledgers_file = self.data_dir.join("ledgers.json");

        if !ledgers_file.exists() {
            return Err(anyhow!("ledgers.json not found"));
        }

        let contents = fs::read_to_string(&ledgers_file)?;
        let entries: Vec<LedgerEntry> = serde_json::from_str(&contents)?;

        let mut ledgers = Vec::with_capacity(entries.len());

        for entry in entries {
            let operator: PublicKey = entry
                .operator
                .parse()
                .map_err(|e| anyhow!("Invalid operator pubkey: {}", e))?;

            // Parse operations from history
            let operations: Vec<OperationInfo> = entry
                .ledger
                .history
                .iter()
                .map(|signed_update| OperationInfo::from_signed_update(signed_update))
                .collect();

            ledgers.push(LedgerInfo {
                operator,
                reserves_id: entry.reserves_id,
                ledger: entry.ledger,
                operations,
            });
        }

        // Sort by operator pubkey for consistent display
        ledgers.sort_by(|a, b| a.operator.to_string().cmp(&b.operator.to_string()));

        Ok(ledgers)
    }

    /// Reload a single ledger
    pub fn reload_ledger(&self, operator: &PublicKey, reserves_id: &str) -> Result<LedgerInfo> {
        let ledgers = self.load_ledgers()?;
        ledgers
            .into_iter()
            .find(|l| l.operator == *operator && l.reserves_id == reserves_id)
            .ok_or_else(|| anyhow!("Ledger not found"))
    }

    /// Check if data directory exists and has ledgers
    pub fn has_data(&self) -> bool {
        self.data_dir.join("ledgers.json").exists()
    }
}
