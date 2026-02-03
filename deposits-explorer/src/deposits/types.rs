use deposits_core::{Ledger, Deposit, SignedLedgerUpdate};
use bitcoin::secp256k1::PublicKey;

/// Ledger info for display
#[derive(Debug, Clone)]
pub struct LedgerInfo {
    /// Operator pubkey
    pub operator: PublicKey,
    /// Reserves ID (partner pubkey as string)
    pub reserves_id: String,
    /// The full ledger
    pub ledger: Ledger,
    /// Parsed operations for display
    pub operations: Vec<OperationInfo>,
}

/// Operation info for display
#[derive(Debug, Clone)]
pub struct OperationInfo {
    /// Sequence number
    pub sequence: u64,
    /// Operation type (from message_type)
    pub op_type: String,
    /// Timestamp
    pub timestamp: u64,
    /// Block height
    pub block_height: u32,
    /// Previous hash (hex, truncated)
    pub prev_hash: String,
    /// Current hash (hex, truncated)
    pub curr_hash: String,
}

impl LedgerInfo {
    /// Get operator short name (first 8 chars of hex pubkey)
    pub fn operator_short(&self) -> String {
        let hex = self.operator.to_string();
        format!("{}...", &hex[..8.min(hex.len())])
    }

    /// Get reserves ID short (first 8 chars)
    pub fn reserves_id_short(&self) -> String {
        if self.reserves_id.len() > 8 {
            format!("{}...", &self.reserves_id[..8])
        } else {
            self.reserves_id.clone()
        }
    }

    /// Get current sequence number
    pub fn sequence(&self) -> u64 {
        self.ledger.state.sequence
    }

    /// Get current ledger hash (hex, truncated)
    pub fn hash_short(&self) -> String {
        let hex = hex::encode(self.ledger.state.hash);
        format!("{}...", &hex[..8.min(hex.len())])
    }

    /// Get total reserves amount
    pub fn reserves_amount(&self) -> u64 {
        self.ledger.state.reserves.amount
    }

    /// Get deposits count
    pub fn deposits_count(&self) -> usize {
        self.ledger.state.deposits.len()
    }

    /// Get quorum members count
    pub fn quorum_count(&self) -> usize {
        self.ledger.state.quorum_members.len()
    }

    /// Get all deposits
    pub fn deposits(&self) -> Vec<(&PublicKey, &Deposit)> {
        self.ledger.state.deposits.iter().collect()
    }
}

impl OperationInfo {
    pub fn from_signed_update(update: &SignedLedgerUpdate) -> Self {
        let op_type = message_type_name(update.message_type);

        Self {
            sequence: update.sequence_number,
            op_type,
            timestamp: update.timestamp,
            block_height: update.block_height,
            prev_hash: hex::encode(&update.previous_hash[..4]),
            curr_hash: hex::encode(&update.current_hash[..4]),
        }
    }
}

/// Convert message type to human-readable name
fn message_type_name(msg_type: u16) -> String {
    match msg_type {
        // Based on LedgerOperation discriminant values
        1 => "LedgerOpen".to_string(),
        2 => "ReservesAdd".to_string(),
        3 => "ReservesInc".to_string(),
        4 => "ReservesDec".to_string(),
        10 => "DepositOpen".to_string(),
        11 => "DepositClose".to_string(),
        12 => "DepositUpdate".to_string(),
        20 => "InvoiceCredit".to_string(),
        21 => "InvoiceLock".to_string(),
        22 => "InvoiceFulfill".to_string(),
        23 => "InvoiceFail".to_string(),
        30 => "OnchainCredit".to_string(),
        31 => "OnchainDebit".to_string(),
        32 => "OnchainLock".to_string(),
        37 => "OnchainFail".to_string(),
        38 => "OnchainFulfill".to_string(),
        40 => "CollateralInc".to_string(),
        41 => "CollateralDec".to_string(),
        42 => "CollateralAttest".to_string(),
        43 => "QuorumAdd".to_string(),
        44 => "QuorumRemove".to_string(),
        45 => "CollateralLock".to_string(),
        46 => "QuorumJoin".to_string(),
        50 => "FeeCollect".to_string(),
        60 => "LedgerClose".to_string(),
        61 => "Tombstone".to_string(),
        _ => format!("Type({})", msg_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_names() {
        assert_eq!(message_type_name(1), "LedgerOpen");
        assert_eq!(message_type_name(3), "ReservesInc");
        assert_eq!(message_type_name(10), "DepositOpen");
        assert_eq!(message_type_name(20), "InvoiceCredit");
        assert_eq!(message_type_name(50), "FeeCollect");
        assert_eq!(message_type_name(999), "Type(999)");
    }

    #[test]
    fn test_operation_info_from_signed_update() {
        // Use a valid secp256k1 public key (this is the generator point G)
        let valid_pubkey: PublicKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".parse().unwrap();

        let update = SignedLedgerUpdate {
            message: vec![],
            message_type: 10, // DepositOpen
            operator_id: valid_pubkey,
            ledger_id: [0u8; 32],
            sequence_number: 42,
            previous_hash: [0u8; 32],
            current_hash: [1u8; 32],
            timestamp: 1700000000,
            block_height: 800000,
            block_hash: [0u8; 32],
            partner_signature: [0u8; 64],
            operator_signature: [0u8; 64],
        };

        let op_info = OperationInfo::from_signed_update(&update);
        assert_eq!(op_info.sequence, 42);
        assert_eq!(op_info.op_type, "DepositOpen");
        assert_eq!(op_info.timestamp, 1700000000);
        assert_eq!(op_info.block_height, 800000);
        assert_eq!(op_info.prev_hash, "00000000");
        assert_eq!(op_info.curr_hash, "01010101");
    }
}
