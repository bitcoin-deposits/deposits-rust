//! Recovery Claim Execution
//!
//! This module handles the actual on-chain claim of reserves when an operator
//! is deemed non-compliant. It bridges the recovery state machine with the
//! tapscript spending infrastructure.
//!
//! ## Claim Flow
//!
//! 1. RecoveryManager determines operator is non-compliant
//! 2. ClaimEligibility is computed based on blocks elapsed
//! 3. Eligible claimant(s) build a deterministic claim transaction
//! 4. Signatures are collected from eligible parties
//! 5. Transaction is finalized and broadcast
//!
//! ## Deterministic Transaction Building
//!
//! All eligible claimants independently build the same transaction:
//! - Same destination (derived from claimant pubkeys)
//! - Same fee rate (protocol-specified or from mempool)
//! - Same tier selection based on eligibility
//!
//! This enables signature aggregation without coordination on tx details.

use bitcoin::{
    secp256k1::{schnorr::Signature, Message, PublicKey, Secp256k1, SecretKey},
    Address, Network, OutPoint, ScriptBuf, Transaction, Txid,
};
use std::collections::HashMap;

use crate::error::{DepositsError, DepositsResult};
use crate::recovery::{ClaimEligibility, RecoveryPhase, RecoveryState};
use crate::tapscript_reserves::{
    ReservesSpendBuilder, SpendTxParams, TapscriptReservesBuilder, ThresholdConfig, VoterSet,
};
use crate::traits::Broadcaster;

/// Default fee rate for claim transactions (sat/vbyte)
pub const DEFAULT_CLAIM_FEE_RATE: u64 = 10;

/// Configuration for a claim attempt
#[derive(Clone, Debug)]
pub struct ClaimConfig {
    /// Fee rate in sat/vbyte
    pub fee_rate_sat_vbyte: u64,
    /// Network for address derivation
    pub network: Network,
}

impl Default for ClaimConfig {
    fn default() -> Self {
        Self {
            fee_rate_sat_vbyte: DEFAULT_CLAIM_FEE_RATE,
            network: Network::Regtest,
        }
    }
}

/// Information about the reserves output being claimed
#[derive(Clone, Debug)]
pub struct ClaimableReserves {
    /// The on-chain outpoint of the reserves
    pub outpoint: OutPoint,
    /// Amount in the reserves (satoshis)
    pub amount_sats: u64,
    /// The script pubkey of the reserves output
    pub script_pubkey: ScriptBuf,
    /// Voter set for the reserves multisig
    pub voter_set: VoterSet,
    /// Threshold configuration
    pub threshold_config: ThresholdConfig,
    /// Network
    pub network: Network,
    /// The ledger hash committed to in this reserves output
    pub ledger_hash: [u8; 32],
}

/// A claim attempt with collected signatures
#[derive(Clone, Debug)]
pub struct ClaimAttempt {
    /// The claimants (pubkeys of those claiming)
    pub claimants: Vec<PublicKey>,
    /// The eligibility tier being used
    pub eligibility: ClaimEligibility,
    /// The tier index in the threshold config
    pub tier_index: usize,
    /// The destination address for the claim
    pub destination: Address,
    /// The unsigned transaction
    pub unsigned_tx: Transaction,
    /// Collected signatures (indexed by voter position in sorted order)
    pub signatures: HashMap<usize, [u8; 64]>,
    /// The leaf script for this tier
    pub leaf_script: ScriptBuf,
    /// The reserves being claimed
    pub reserves: ClaimableReserves,
}

impl ClaimAttempt {
    /// Create a new claim attempt
    pub fn new(
        claimants: Vec<PublicKey>,
        eligibility: ClaimEligibility,
        reserves: ClaimableReserves,
        config: &ClaimConfig,
    ) -> DepositsResult<Self> {
        // Determine which tier to use based on eligibility
        let tier_index = match &eligibility {
            ClaimEligibility::SelectedPartnerOnly { .. } => 0, // majority
            ClaimEligibility::AnyThreePartners => 1,           // minority
            ClaimEligibility::AnySinglePartner => 2,           // single partner (operator tier)
            ClaimEligibility::CommunityFallback => {
                // emergency (last tier)
                reserves.threshold_config.tiers.len().saturating_sub(1)
            }
        };

        if tier_index >= reserves.threshold_config.tiers.len() {
            return Err(DepositsError::InvalidState(format!(
                "No tier available for eligibility {:?}",
                eligibility
            )));
        }

        // Derive destination address from first claimant (deterministic)
        // In production, this would be a taproot address they control
        let destination = derive_claim_destination(&claimants[0], config.network)?;

        // Build the threshold leaf script for this tier
        let builder = TapscriptReservesBuilder::new(
            reserves.voter_set.clone(),
            reserves.threshold_config.clone(),
            config.network,
            reserves.ledger_hash,
        );
        let leaf_script =
            builder.build_threshold_leaf(&reserves.threshold_config.tiers[tier_index])?;

        // Build the spend transaction parameters
        let spend_params = SpendTxParams {
            reserves_outpoint: reserves.outpoint,
            reserves_amount: reserves.amount_sats,
            destination_script: destination.script_pubkey(),
            fee_rate_sat_vbyte: config.fee_rate_sat_vbyte,
        };

        let unsigned_tx =
            ReservesSpendBuilder::build_spend_transaction(&spend_params, &reserves.script_pubkey)?;

        Ok(Self {
            claimants,
            eligibility,
            tier_index,
            destination,
            unsigned_tx,
            signatures: HashMap::new(),
            leaf_script,
            reserves,
        })
    }

    /// Get the sighash that needs to be signed
    pub fn get_sighash(&self) -> DepositsResult<bitcoin::TapSighash> {
        ReservesSpendBuilder::compute_sighash(
            &self.unsigned_tx,
            0,
            self.reserves.amount_sats,
            &self.reserves.script_pubkey,
            &self.leaf_script,
        )
    }

    /// Add a signature from a voter
    ///
    /// The voter_index is their position in the sorted voter list
    pub fn add_signature(&mut self, voter_index: usize, signature: [u8; 64]) {
        self.signatures.insert(voter_index, signature);
    }

    /// Check if we have enough signatures to finalize
    pub fn has_sufficient_signatures(&self) -> bool {
        let required = self.reserves.threshold_config.tiers[self.tier_index].threshold;
        self.signatures.len() >= required
    }

    /// Get the number of required signatures for this tier
    pub fn required_signatures(&self) -> usize {
        self.reserves.threshold_config.tiers[self.tier_index].threshold
    }

    /// Finalize the transaction with collected signatures
    pub fn finalize(&self) -> DepositsResult<Transaction> {
        if !self.has_sufficient_signatures() {
            return Err(DepositsError::InvalidState(format!(
                "Not enough signatures: have {}, need {}",
                self.signatures.len(),
                self.required_signatures()
            )));
        }

        // Get control block for this tier
        let taproot_output = TapscriptReservesBuilder::new(
            self.reserves.voter_set.clone(),
            self.reserves.threshold_config.clone(),
            self.reserves.network,
            self.reserves.ledger_hash,
        )
        .build()?;

        let control_block = taproot_output
            .control_block_for_tier(self.tier_index)
            .ok_or_else(|| {
                DepositsError::InvalidState("Failed to get control block for tier".to_string())
            })?;

        // Build signature array in correct order
        let voter_count = self.reserves.voter_set.total_count();
        let mut sig_array: Vec<Option<[u8; 64]>> = vec![None; voter_count];

        for (&idx, &sig) in &self.signatures {
            if idx < voter_count {
                sig_array[idx] = Some(sig);
            }
        }

        let finalized_tx = ReservesSpendBuilder::finalize_spend_transaction(
            self.unsigned_tx.clone(),
            &sig_array,
            &self.leaf_script,
            &control_block,
        );

        Ok(finalized_tx)
    }

    /// Get the transaction ID (useful for tracking even before broadcast)
    pub fn txid(&self) -> Txid {
        self.unsigned_tx.compute_txid()
    }
}

/// Derive a deterministic destination address from a claimant's pubkey
fn derive_claim_destination(claimant: &PublicKey, network: Network) -> DepositsResult<Address> {
    let secp = Secp256k1::new();
    let x_only = claimant.x_only_public_key().0;

    // Create a P2TR address with the claimant as internal key (no script path)
    Ok(Address::p2tr(&secp, x_only, None, network))
}

/// Manager for coordinating claim attempts
pub struct ClaimManager {
    /// Active claim attempts by (operator, partner) ledger ID
    active_claims: HashMap<(PublicKey, PublicKey), ClaimAttempt>,
    /// Our node's secret key for signing
    our_secret_key: Option<SecretKey>,
    /// Our node's public key
    our_pubkey: PublicKey,
    /// Default claim configuration
    config: ClaimConfig,
}

impl ClaimManager {
    /// Create a new claim manager
    pub fn new(
        our_pubkey: PublicKey,
        our_secret_key: Option<SecretKey>,
        config: ClaimConfig,
    ) -> Self {
        Self {
            active_claims: HashMap::new(),
            our_secret_key,
            our_pubkey,
            config,
        }
    }

    /// Initiate a claim for a non-compliant recovery
    pub fn initiate_claim(
        &mut self,
        ledger_id: (PublicKey, PublicKey),
        claimants: Vec<PublicKey>,
        eligibility: ClaimEligibility,
        reserves: ClaimableReserves,
    ) -> DepositsResult<&ClaimAttempt> {
        let attempt = ClaimAttempt::new(claimants, eligibility, reserves, &self.config)?;

        self.active_claims.insert(ledger_id, attempt);
        Ok(self.active_claims.get(&ledger_id).unwrap())
    }

    /// Sign a claim with our key
    pub fn sign_claim(&mut self, ledger_id: &(PublicKey, PublicKey)) -> DepositsResult<[u8; 64]> {
        let secret_key = self.our_secret_key.ok_or_else(|| {
            DepositsError::InvalidState("No secret key configured for signing".to_string())
        })?;

        let attempt = self.active_claims.get(ledger_id).ok_or_else(|| {
            DepositsError::InvalidState("No active claim for this ledger".to_string())
        })?;

        let sighash = attempt.get_sighash()?;

        // Find our position in the sorted voter list
        let sorted_keys = attempt.reserves.voter_set.sorted_x_only_pubkeys();
        let our_x_only = self.our_pubkey.x_only_public_key().0;

        let our_index = sorted_keys
            .iter()
            .position(|k| *k == our_x_only)
            .ok_or_else(|| {
                DepositsError::InvalidState("We are not in the voter set".to_string())
            })?;

        // Create Schnorr signature
        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let msg = Message::from_digest(*sighash.as_ref());
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        let sig_bytes: [u8; 64] = sig.serialize();

        // Add signature to the attempt
        if let Some(attempt) = self.active_claims.get_mut(ledger_id) {
            attempt.add_signature(our_index, sig_bytes);
        }

        Ok(sig_bytes)
    }

    /// Add a signature from another party
    pub fn add_peer_signature(
        &mut self,
        ledger_id: &(PublicKey, PublicKey),
        voter_pubkey: &PublicKey,
        signature: [u8; 64],
    ) -> DepositsResult<bool> {
        let attempt = self.active_claims.get_mut(ledger_id).ok_or_else(|| {
            DepositsError::InvalidState("No active claim for this ledger".to_string())
        })?;

        // Find the voter's position
        let sorted_keys = attempt.reserves.voter_set.sorted_x_only_pubkeys();
        let voter_x_only = voter_pubkey.x_only_public_key().0;

        let voter_index = sorted_keys
            .iter()
            .position(|k| *k == voter_x_only)
            .ok_or_else(|| {
                DepositsError::InvalidState("Voter is not in the voter set".to_string())
            })?;

        // Verify signature before adding
        let sighash = attempt.get_sighash()?;
        let secp = Secp256k1::new();
        let msg = Message::from_digest(*sighash.as_ref());
        let sig = Signature::from_slice(&signature).map_err(|e| {
            DepositsError::InvalidState(format!("Invalid signature format: {:?}", e))
        })?;

        secp.verify_schnorr(&sig, &msg, &voter_x_only)
            .map_err(|e| {
                DepositsError::InvalidState(format!("Signature verification failed: {:?}", e))
            })?;

        attempt.add_signature(voter_index, signature);

        Ok(attempt.has_sufficient_signatures())
    }

    /// Finalize and return the claim transaction
    pub fn finalize_claim(
        &self,
        ledger_id: &(PublicKey, PublicKey),
    ) -> DepositsResult<Transaction> {
        let attempt = self.active_claims.get(ledger_id).ok_or_else(|| {
            DepositsError::InvalidState("No active claim for this ledger".to_string())
        })?;

        attempt.finalize()
    }

    /// Get an active claim attempt
    pub fn get_claim(&self, ledger_id: &(PublicKey, PublicKey)) -> Option<&ClaimAttempt> {
        self.active_claims.get(ledger_id)
    }

    /// Remove a completed or abandoned claim
    pub fn remove_claim(&mut self, ledger_id: &(PublicKey, PublicKey)) -> Option<ClaimAttempt> {
        self.active_claims.remove(ledger_id)
    }

    /// Finalize and broadcast a claim transaction
    ///
    /// This is the final step in the claim process:
    /// 1. Verifies sufficient signatures have been collected
    /// 2. Finalizes the transaction with collected signatures
    /// 3. Broadcasts to the Bitcoin network
    /// 4. Removes the claim from active claims
    ///
    /// Returns a `BroadcastResult` with the transaction details on success.
    pub fn broadcast_claim<B: Broadcaster>(
        &mut self,
        ledger_id: &(PublicKey, PublicKey),
        broadcaster: &B,
    ) -> DepositsResult<BroadcastResult> {
        // Check if claim exists
        let attempt = self.active_claims.get(ledger_id).ok_or_else(|| {
            DepositsError::InvalidState("No active claim for this ledger".to_string())
        })?;

        // Verify we have enough signatures
        if !attempt.has_sufficient_signatures() {
            return Err(DepositsError::InvalidState(format!(
                "Not enough signatures to broadcast: have {}, need {}",
                attempt.signatures.len(),
                attempt.required_signatures()
            )));
        }

        // Finalize the transaction
        let finalized_tx = attempt.finalize()?;
        let txid = finalized_tx.compute_txid();
        let destination = attempt.destination.clone();
        let amount_claimed = attempt.reserves.amount_sats;
        let claimants = attempt.claimants.clone();

        // Broadcast the transaction
        broadcaster
            .broadcast_transaction(&finalized_tx)
            .map_err(|e| DepositsError::BroadcastFailed(format!("{:?}", e)))?;

        // Remove from active claims now that it's broadcast
        self.active_claims.remove(ledger_id);

        Ok(BroadcastResult {
            txid,
            transaction: finalized_tx,
            destination,
            amount_claimed,
            claimants,
        })
    }

    /// Check if a claim is ready to broadcast (has sufficient signatures)
    pub fn is_ready_to_broadcast(&self, ledger_id: &(PublicKey, PublicKey)) -> bool {
        self.active_claims
            .get(ledger_id)
            .map(|a| a.has_sufficient_signatures())
            .unwrap_or(false)
    }
}

/// Result of broadcasting a claim transaction
#[derive(Clone, Debug)]
pub struct BroadcastResult {
    /// The transaction ID of the broadcast claim
    pub txid: Txid,
    /// The full finalized transaction
    pub transaction: Transaction,
    /// The destination address where funds were sent
    pub destination: Address,
    /// The amount claimed (in satoshis)
    pub amount_claimed: u64,
    /// The claimants who received the funds
    pub claimants: Vec<PublicKey>,
}

impl BroadcastResult {
    /// Get a human-readable summary of the broadcast
    pub fn summary(&self) -> String {
        format!(
            "Claim broadcast: txid={}, amount={} sats, destination={}",
            self.txid, self.amount_claimed, self.destination
        )
    }
}

/// Build a claim from recovery state
///
/// This is the main entry point for creating a claim after recovery
/// determines the operator is non-compliant.
pub fn build_claim_from_recovery(
    recovery_state: &RecoveryState,
    reserves_outpoint: OutPoint,
    reserves_amount: u64,
    reserves_script_pubkey: ScriptBuf,
    voter_set: VoterSet,
    threshold_config: ThresholdConfig,
    claimants: Vec<PublicKey>,
    config: &ClaimConfig,
) -> DepositsResult<ClaimAttempt> {
    let (eligibility, _) = match &recovery_state.phase {
        RecoveryPhase::NonCompliantRecovery {
            current_eligibility,
            recovery_pool,
            ..
        } => (current_eligibility.clone(), recovery_pool.clone()),
        _ => {
            return Err(DepositsError::InvalidState(
                "Recovery is not in NonCompliantRecovery phase".to_string(),
            ));
        }
    };

    let reserves = ClaimableReserves {
        outpoint: reserves_outpoint,
        amount_sats: reserves_amount,
        script_pubkey: reserves_script_pubkey,
        voter_set,
        threshold_config,
        network: config.network,
        ledger_hash: [0u8; 32], // TODO: Extract ledger_hash from on-chain reserves output
    };

    ClaimAttempt::new(claimants, eligibility, reserves, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    /// Mock broadcaster that captures broadcast transactions for testing
    struct MockBroadcaster {
        broadcast_count: AtomicUsize,
        broadcast_txs: StdMutex<Vec<Transaction>>,
    }

    impl MockBroadcaster {
        fn new() -> Self {
            Self {
                broadcast_count: AtomicUsize::new(0),
                broadcast_txs: StdMutex::new(Vec::new()),
            }
        }

        fn get_broadcast_count(&self) -> usize {
            self.broadcast_count.load(Ordering::SeqCst)
        }

        fn get_broadcast_txs(&self) -> Vec<Transaction> {
            self.broadcast_txs.lock().unwrap().clone()
        }
    }

    impl Broadcaster for MockBroadcaster {
        fn broadcast_transaction(
            &self,
            tx: &Transaction,
        ) -> Result<(), crate::traits::BroadcastError> {
            self.broadcast_count.fetch_add(1, Ordering::SeqCst);
            let mut stored = self.broadcast_txs.lock().unwrap();
            stored.push(tx.clone());
            Ok(())
        }
    }

    fn generate_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[31] = seed;
        let sk = SecretKey::from_slice(&secret).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn generate_test_keypair(seed: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[31] = seed;
        let sk = SecretKey::from_slice(&secret).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    fn create_test_reserves(voter_set: VoterSet) -> ClaimableReserves {
        let test_ledger_hash = [0xAA; 32];
        let builder = TapscriptReservesBuilder::with_defaults(
            voter_set.clone(),
            Network::Regtest,
            test_ledger_hash,
        );
        let output = builder.build().unwrap();

        ClaimableReserves {
            outpoint: OutPoint {
                txid: Txid::from_slice(&[0xAB; 32]).unwrap(),
                vout: 0,
            },
            amount_sats: 100_000,
            script_pubkey: output.script_pubkey(),
            voter_set,
            threshold_config: ThresholdConfig::default_for_voter_count(3),
            network: Network::Regtest,
            ledger_hash: test_ledger_hash,
        }
    }

    #[test]
    fn test_derive_claim_destination() {
        let pubkey = generate_test_pubkey(1);
        let addr = derive_claim_destination(&pubkey, Network::Regtest).unwrap();

        assert!(addr.script_pubkey().is_p2tr());
    }

    #[test]
    fn test_claim_attempt_creation() {
        let tie_breaker = generate_test_pubkey(1);
        let voter2 = generate_test_pubkey(2);
        let voter3 = generate_test_pubkey(3);

        let voter_set = VoterSet::new(tie_breaker, vec![voter2, voter3]);
        let reserves = create_test_reserves(voter_set);

        let config = ClaimConfig::default();
        let eligibility = ClaimEligibility::SelectedPartnerOnly {
            partner: tie_breaker,
        };

        let attempt = ClaimAttempt::new(vec![tie_breaker], eligibility, reserves, &config)
            .expect("Should create claim attempt");

        assert_eq!(attempt.claimants.len(), 1);
        assert_eq!(attempt.tier_index, 0);
        assert!(!attempt.has_sufficient_signatures());
    }

    #[test]
    fn test_claim_sighash_computation() {
        let tie_breaker = generate_test_pubkey(1);
        let voter2 = generate_test_pubkey(2);

        let voter_set = VoterSet::new(tie_breaker, vec![voter2]);
        let reserves = create_test_reserves(voter_set);

        let config = ClaimConfig::default();
        let eligibility = ClaimEligibility::SelectedPartnerOnly {
            partner: tie_breaker,
        };

        let attempt = ClaimAttempt::new(vec![tie_breaker], eligibility, reserves, &config)
            .expect("Should create claim attempt");

        let sighash = attempt.get_sighash().expect("Should compute sighash");
        assert_ne!(sighash.to_byte_array(), [0u8; 32]);
    }

    #[test]
    fn test_claim_signature_collection() {
        let (sk1, pk1) = generate_test_keypair(1);
        let (sk2, pk2) = generate_test_keypair(2);

        let voter_set = VoterSet::new(pk1, vec![pk2]);
        let reserves = create_test_reserves(voter_set);

        let config = ClaimConfig::default();
        let eligibility = ClaimEligibility::SelectedPartnerOnly { partner: pk1 };

        let mut attempt =
            ClaimAttempt::new(vec![pk1], eligibility.clone(), reserves.clone(), &config)
                .expect("Should create claim attempt");

        // Sign with the tie-breaker (should be sufficient for tier 0)
        let sighash = attempt.get_sighash().unwrap();
        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk1);
        let msg = Message::from_digest(*sighash.as_ref());
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        // Find pk1's position in sorted order
        let sorted = attempt.reserves.voter_set.sorted_x_only_pubkeys();
        let pk1_x = pk1.x_only_public_key().0;
        let idx = sorted.iter().position(|k| *k == pk1_x).unwrap();

        attempt.add_signature(idx, sig.serialize());

        // For a 2-party setup with tier 0 requiring 2 sigs, we need both
        // Actually the default for 2 voters is "both required" so we need both
        // Let's check what threshold is actually set
        let required = attempt.required_signatures();
        println!("Required signatures: {}", required);

        // For 2-party, tier 0 requires both signatures
        if required > 1 {
            // Add second signature
            let keypair2 = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk2);
            let sig2 = secp.sign_schnorr_no_aux_rand(&msg, &keypair2);
            let pk2_x = pk2.x_only_public_key().0;
            let idx2 = sorted.iter().position(|k| *k == pk2_x).unwrap();
            attempt.add_signature(idx2, sig2.serialize());
        }

        assert!(attempt.has_sufficient_signatures());
    }

    #[test]
    fn test_claim_manager_workflow() {
        let (sk1, pk1) = generate_test_keypair(1);
        let pk2 = generate_test_pubkey(2);

        let voter_set = VoterSet::new(pk1, vec![pk2]);
        let reserves = create_test_reserves(voter_set);

        let config = ClaimConfig::default();
        let mut manager = ClaimManager::new(pk1, Some(sk1), config);

        let ledger_id = (pk1, pk2);
        let eligibility = ClaimEligibility::AnySinglePartner;

        manager
            .initiate_claim(ledger_id, vec![pk1], eligibility, reserves)
            .expect("Should initiate claim");

        // Sign with our key
        let _sig = manager.sign_claim(&ledger_id).expect("Should sign");

        // Verify claim exists
        assert!(manager.get_claim(&ledger_id).is_some());
    }

    #[test]
    fn test_eligibility_tier_mapping() {
        let pk1 = generate_test_pubkey(1);
        let pk2 = generate_test_pubkey(2);
        let pk3 = generate_test_pubkey(3);
        let pk4 = generate_test_pubkey(4);

        // Multi-party setup (4 voters -> 4 tiers)
        // Tier 0: Majority of quorum (no operator, immediate)
        // Tier 1: Minority of quorum (no operator, 1008 blocks)
        // Tier 2: Operator only (2016 blocks)
        // Tier 3: Emergency (1-of-n, 4032 blocks)
        let voter_set = VoterSet::new(pk1, vec![pk2, pk3, pk4]);
        let reserves = create_test_reserves(voter_set);

        let config = ClaimConfig::default();

        // Test tier mapping for different eligibilities
        let test_cases = vec![
            (ClaimEligibility::SelectedPartnerOnly { partner: pk1 }, 0), // majority
            (ClaimEligibility::AnyThreePartners, 1),                     // minority
            (ClaimEligibility::AnySinglePartner, 2),                     // single partner
            (ClaimEligibility::CommunityFallback, 3),                    // emergency (last)
        ];

        for (eligibility, expected_tier) in test_cases {
            let attempt =
                ClaimAttempt::new(vec![pk1], eligibility.clone(), reserves.clone(), &config)
                    .expect("Should create claim");

            assert_eq!(
                attempt.tier_index, expected_tier,
                "Eligibility {:?} should map to tier {}",
                eligibility, expected_tier
            );
        }
    }

    #[test]
    fn test_is_ready_to_broadcast_without_signatures() {
        let (sk1, pk1) = generate_test_keypair(1);
        let pk2 = generate_test_pubkey(2);

        let voter_set = VoterSet::new(pk1, vec![pk2]);
        let reserves = create_test_reserves(voter_set);

        let config = ClaimConfig::default();
        let mut manager = ClaimManager::new(pk1, Some(sk1), config);

        let ledger_id = (pk1, pk2);
        let eligibility = ClaimEligibility::AnySinglePartner;

        manager
            .initiate_claim(ledger_id, vec![pk1], eligibility, reserves)
            .expect("Should initiate claim");

        // Without signatures, should not be ready
        assert!(!manager.is_ready_to_broadcast(&ledger_id));
    }

    #[test]
    fn test_is_ready_to_broadcast_nonexistent_ledger() {
        let pk1 = generate_test_pubkey(1);
        let pk2 = generate_test_pubkey(2);

        let config = ClaimConfig::default();
        let manager = ClaimManager::new(pk1, None, config);

        let ledger_id = (pk1, pk2);

        // Nonexistent ledger should return false, not panic
        assert!(!manager.is_ready_to_broadcast(&ledger_id));
    }

    #[test]
    fn test_broadcast_claim_insufficient_signatures() {
        let (sk1, pk1) = generate_test_keypair(1);
        let pk2 = generate_test_pubkey(2);

        let voter_set = VoterSet::new(pk1, vec![pk2]);
        let reserves = create_test_reserves(voter_set);

        let config = ClaimConfig::default();
        let mut manager = ClaimManager::new(pk1, Some(sk1), config);

        let ledger_id = (pk1, pk2);
        let eligibility = ClaimEligibility::AnySinglePartner;

        manager
            .initiate_claim(ledger_id, vec![pk1], eligibility, reserves)
            .expect("Should initiate claim");

        let broadcaster = MockBroadcaster::new();

        // Should fail because no signatures collected
        let result = manager.broadcast_claim(&ledger_id, &broadcaster);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Not enough signatures"));
        assert_eq!(broadcaster.get_broadcast_count(), 0);
    }

    #[test]
    fn test_broadcast_claim_no_active_claim() {
        let pk1 = generate_test_pubkey(1);
        let pk2 = generate_test_pubkey(2);

        let config = ClaimConfig::default();
        let mut manager = ClaimManager::new(pk1, None, config);

        let ledger_id = (pk1, pk2);
        let broadcaster = MockBroadcaster::new();

        // Should fail because no active claim
        let result = manager.broadcast_claim(&ledger_id, &broadcaster);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No active claim"));
        assert_eq!(broadcaster.get_broadcast_count(), 0);
    }

    #[test]
    fn test_broadcast_claim_success_single_signer() {
        // This test verifies the full workflow with a single-signature tier
        // We'll use AnySinglePartner eligibility which maps to tier 2
        // For a 2-party setup, this should require only 1 signature

        let (sk1, pk1) = generate_test_keypair(1);
        let (sk2, pk2) = generate_test_keypair(2);

        let voter_set = VoterSet::new(pk1, vec![pk2]);
        let reserves = create_test_reserves(voter_set);

        let config = ClaimConfig::default();
        let mut manager = ClaimManager::new(pk1, Some(sk1), config);

        let ledger_id = (pk1, pk2);
        // Use AnySinglePartner - for 2 voters this should be tier 2 with threshold 1
        let eligibility = ClaimEligibility::AnySinglePartner;

        manager
            .initiate_claim(ledger_id, vec![pk1], eligibility, reserves)
            .expect("Should initiate claim");

        // Sign with our key
        manager.sign_claim(&ledger_id).expect("Should sign");

        // Check if ready (depends on threshold for AnySinglePartner tier)
        let attempt = manager.get_claim(&ledger_id).unwrap();
        let required = attempt.required_signatures();

        // If we need more signatures, add the second one
        if required > 1 {
            // Get sighash and sign with sk2
            let sighash = attempt.get_sighash().unwrap();
            let secp = Secp256k1::new();
            let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk2);
            let msg = Message::from_digest(*sighash.as_ref());
            let sig2 = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

            manager
                .add_peer_signature(&ledger_id, &pk2, sig2.serialize())
                .expect("Should add peer signature");
        }

        assert!(manager.is_ready_to_broadcast(&ledger_id));

        let broadcaster = MockBroadcaster::new();
        let result = manager.broadcast_claim(&ledger_id, &broadcaster);

        assert!(result.is_ok());
        let broadcast_result = result.unwrap();

        // Verify broadcast happened
        assert_eq!(broadcaster.get_broadcast_count(), 1);
        let broadcast_txs = broadcaster.get_broadcast_txs();
        assert_eq!(broadcast_txs.len(), 1);

        // Verify the transaction matches
        assert_eq!(broadcast_txs[0].compute_txid(), broadcast_result.txid);

        // Verify the claim was removed from active claims
        assert!(manager.get_claim(&ledger_id).is_none());
        assert!(!manager.is_ready_to_broadcast(&ledger_id));
    }

    #[test]
    fn test_broadcast_result_summary() {
        let pk1 = generate_test_pubkey(1);

        let result = BroadcastResult {
            txid: Txid::from_slice(&[0xAB; 32]).unwrap(),
            transaction: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            destination: derive_claim_destination(&pk1, Network::Regtest).unwrap(),
            amount_claimed: 100_000,
            claimants: vec![pk1],
        };

        let summary = result.summary();
        assert!(summary.contains("Claim broadcast:"));
        assert!(summary.contains("100000 sats"));
    }
}
