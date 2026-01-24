// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Reserves Output Proposal Types
//!
//! This module contains the core data structures for reserves output proposals
//! that are used in Lightning commitment transactions for the Bitcoin Deposits protocol.
//!
//! These types are independent of any Lightning implementation and can be used
//! by any adapter layer.

use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use crate::error::{DepositsError, DepositsResult};

/// Serde helper for large arrays (64-byte signatures)
pub mod serde_arrays {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(array) => array.as_slice().serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match opt {
            Some(vec) => {
                if vec.len() == 64 {
                    let mut array = [0u8; 64];
                    array.copy_from_slice(&vec);
                    Ok(Some(array))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "Expected 64 bytes, got {}",
                        vec.len()
                    )))
                }
            }
            None => Ok(None),
        }
    }
}

/// Represents a proposed ReservesOutput for inclusion in commitment transactions
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservesOutputProposal {
    /// Unique identifier for this proposal
    pub proposal_id: [u8; 32],
    /// Amount to be held in reserves (in satoshis)
    pub amount: u64,
    /// The Lightning partner this reserves output is shared with
    pub partner_pubkey: PublicKey,
    /// Ledger ID that disambiguates multiple ledgers
    pub ledger_id: u16,
    /// Taproot address where funds will be sent (as string)
    pub reserves_address: String,
    /// Spending conditions for the reserves output
    pub spending_policy: SpendingPolicy,
    /// Timeout block height for emergency recovery
    pub emergency_timeout: u32,
    /// Operator signature over proposal parameters
    #[serde(with = "serde_arrays")]
    pub operator_signature: Option<[u8; 64]>,
    /// Ledger hash to embed in the Taproot output
    pub ledger_hash: [u8; 32],
}

impl ReservesOutputProposal {
    /// Check if emergency timeout has been reached
    pub fn is_emergency_timeout_reached(&self, current_height: u32) -> bool {
        current_height >= self.emergency_timeout
    }

    /// Validate the proposal's basic parameters
    pub fn validate(&self) -> DepositsResult<()> {
        // Validate amount is reasonable (minimum 1000 sats, maximum 100M sats)
        if self.amount < 1000 || self.amount > 100_000_000 {
            return Err(DepositsError::InvalidAmount(
                "Reserves amount out of acceptable range (1000 - 100M sats)".to_string(),
            ));
        }

        // Validate timeout is reasonable (minimum 144 blocks = 1 day)
        if self.emergency_timeout < 144 {
            return Err(DepositsError::InvalidTimeout(
                "Emergency timeout too short (minimum 144 blocks)".to_string(),
            ));
        }

        // Validate spending policy
        self.spending_policy.validate()?;

        Ok(())
    }
}

/// Defines who can spend from the reserves output under what conditions
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingPolicy {
    /// Normal cooperative spending (both parties sign)
    pub cooperative_spending: bool,
    /// Partner can unilaterally spend after timeout (in blocks)
    pub partner_unilateral_timeout: u32,
    /// Operator can unilaterally spend for valid deposits only
    pub operator_deposit_spending: bool,
    /// Emergency recovery conditions
    pub emergency_recovery: EmergencyRecovery,
}

impl SpendingPolicy {
    /// Create a default spending policy with the given emergency timeout
    pub fn default_with_timeout(emergency_timeout: u32) -> Self {
        Self {
            cooperative_spending: true,
            partner_unilateral_timeout: emergency_timeout + 144, // +1 day
            operator_deposit_spending: true,
            emergency_recovery: EmergencyRecovery::default_with_timeout(emergency_timeout),
        }
    }

    /// Validate spending policy parameters
    pub fn validate(&self) -> DepositsResult<()> {
        // Partner timeout must be reasonable (minimum 144 blocks = 1 day)
        if self.partner_unilateral_timeout < 144 {
            return Err(DepositsError::InvalidTimeout(
                "Partner unilateral timeout too short (minimum 144 blocks)".to_string(),
            ));
        }

        // Emergency recovery timeout must be longer than partner timeout
        if self.emergency_recovery.partner_timeout <= self.partner_unilateral_timeout {
            return Err(DepositsError::InvalidTimeout(
                "Emergency recovery timeout must be longer than partner timeout".to_string(),
            ));
        }

        Ok(())
    }
}

/// Emergency recovery spending conditions
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyRecovery {
    /// Partner can recover after this timeout (blocks)
    pub partner_timeout: u32,
    /// Operator's emergency key for recovery
    pub operator_emergency_key: PublicKey,
    /// Additional recovery conditions
    pub require_proof_of_reserves: bool,
}

impl EmergencyRecovery {
    /// Create default emergency recovery with the given base timeout
    ///
    /// Note: `operator_emergency_key` must be set by the caller after construction
    pub fn default_with_timeout(emergency_timeout: u32) -> Self {
        // Use a dummy key - caller must set the real one
        let dummy_key = PublicKey::from_slice(&[
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01,
        ])
        .expect("valid dummy pubkey");

        Self {
            partner_timeout: emergency_timeout + 1008, // +1 week
            operator_emergency_key: dummy_key,
            require_proof_of_reserves: true,
        }
    }
}

/// Current status of a reserves output proposal
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalStatus {
    /// Proposal created but not yet sent
    Draft,
    /// Proposal sent to partner, awaiting response
    Pending,
    /// Partner accepted the proposal
    Accepted,
    /// Partner rejected the proposal
    Rejected(String),
    /// Proposal timed out
    TimedOut,
    /// Reserves output created and added to commitment transaction
    Active,
    /// Reserves output spent/removed
    Closed,
}

impl ProposalStatus {
    /// Check if the proposal is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ProposalStatus::Rejected(_) | ProposalStatus::TimedOut | ProposalStatus::Closed
        )
    }

    /// Check if the proposal can be activated
    pub fn can_activate(&self) -> bool {
        matches!(self, ProposalStatus::Accepted)
    }

    /// Check if the proposal is still pending a response
    pub fn is_pending(&self) -> bool {
        matches!(self, ProposalStatus::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn create_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [seed; 32];
        if seed == 0 {
            bytes[0] = 1;
        }
        let secret = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    #[test]
    fn test_spending_policy_validation() {
        let mut policy = SpendingPolicy::default_with_timeout(1000);
        assert!(policy.validate().is_ok());

        // Too short partner timeout
        policy.partner_unilateral_timeout = 100;
        assert!(policy.validate().is_err());

        // Reset and test emergency timeout
        policy.partner_unilateral_timeout = 200;
        policy.emergency_recovery.partner_timeout = 150; // Less than partner timeout
        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_proposal_validation() {
        let partner = create_test_pubkey(1);
        let operator_key = create_test_pubkey(2);

        let mut proposal = ReservesOutputProposal {
            proposal_id: [0u8; 32],
            amount: 50000,
            partner_pubkey: partner,
            ledger_id: 0,
            reserves_address: "tb1qtest".to_string(),
            spending_policy: SpendingPolicy {
                cooperative_spending: true,
                partner_unilateral_timeout: 200,
                operator_deposit_spending: true,
                emergency_recovery: EmergencyRecovery {
                    partner_timeout: 1000,
                    operator_emergency_key: operator_key,
                    require_proof_of_reserves: true,
                },
            },
            emergency_timeout: 1000,
            operator_signature: None,
            ledger_hash: [0u8; 32],
        };

        assert!(proposal.validate().is_ok());

        // Amount too small
        proposal.amount = 500;
        assert!(proposal.validate().is_err());

        // Amount too large
        proposal.amount = 200_000_000;
        assert!(proposal.validate().is_err());

        // Reset amount, test timeout
        proposal.amount = 50000;
        proposal.emergency_timeout = 50;
        assert!(proposal.validate().is_err());
    }

    #[test]
    fn test_proposal_status() {
        assert!(!ProposalStatus::Draft.is_terminal());
        assert!(!ProposalStatus::Pending.is_terminal());
        assert!(!ProposalStatus::Accepted.is_terminal());
        assert!(ProposalStatus::Rejected("test".to_string()).is_terminal());
        assert!(ProposalStatus::TimedOut.is_terminal());
        assert!(ProposalStatus::Closed.is_terminal());

        assert!(ProposalStatus::Accepted.can_activate());
        assert!(!ProposalStatus::Draft.can_activate());

        assert!(ProposalStatus::Pending.is_pending());
        assert!(!ProposalStatus::Draft.is_pending());
    }

    #[test]
    fn test_emergency_timeout_check() {
        let partner = create_test_pubkey(1);
        let proposal = ReservesOutputProposal {
            proposal_id: [0u8; 32],
            amount: 50000,
            partner_pubkey: partner,
            ledger_id: 0,
            reserves_address: "tb1qtest".to_string(),
            spending_policy: SpendingPolicy::default_with_timeout(1000),
            emergency_timeout: 1000,
            operator_signature: None,
            ledger_hash: [0u8; 32],
        };

        assert!(!proposal.is_emergency_timeout_reached(500));
        assert!(!proposal.is_emergency_timeout_reached(999));
        assert!(proposal.is_emergency_timeout_reached(1000));
        assert!(proposal.is_emergency_timeout_reached(1500));
    }
}
