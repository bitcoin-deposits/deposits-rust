//! Integration test harness for the Bitcoin Deposits protocol.
//!
//! Simulates multi-operator interactions using the core protocol stack
//! without external services (no Nostr relays, no Bitcoin network).

pub mod adversarial;
pub mod docker;
pub mod regtest;

use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use deposits_core::descriptor::CoreWitnessVerifier;
use deposits_core::ledger::{Ledger, LedgerRole};
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::{
    compute_deposit_id, DepositId, DescriptorWitness, FeeStructure, LedgerState,
    TransferFeeSchedule,
};

/// A simulated operator with a keypair and ledger.
pub struct Operator {
    pub name: String,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub ledger: Ledger,
}

/// A simulated depositor (customer) with a keypair.
pub struct Depositor {
    pub name: String,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

/// Test network with multiple operators.
pub struct TestNetwork {
    pub operators: Vec<Operator>,
    pub secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl TestNetwork {
    /// Create a test network with N operators, each with reserves.
    pub fn new(names: &[&str], reserves_amount: u64) -> Self {
        let secp = Secp256k1::new();
        let operators: Vec<Operator> = names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let mut seed = [0u8; 32];
                seed[0] = (i + 1) as u8;
                seed[31] = 0x42;
                let sk = SecretKey::from_slice(&seed).unwrap();
                let pk = PublicKey::from_secret_key(&secp, &sk);
                let reserves_key = format!("bcrt1q{}reserves", name);

                let mut ledger = Ledger::new_as_operator(pk, reserves_key, 0);

                // Apply LedgerOpen to set reserves
                let open_op = LedgerOperation::LedgerOpen {
                    operator_id: pk,
                    reserves_id: format!("bcrt1q{}reserves", name),
                    genesis_block: 0,
                    reserves_amount,
                    collateral_amount: reserves_amount, // 50/50 split
                };
                ledger.append_operation(open_op).unwrap();

                Operator {
                    name: name.to_string(),
                    secret_key: sk,
                    public_key: pk,
                    ledger,
                }
            })
            .collect();

        Self { operators, secp }
    }

    /// Get an operator by name.
    pub fn op(&self, name: &str) -> &Operator {
        self.operators
            .iter()
            .find(|o| o.name == name)
            .unwrap_or_else(|| panic!("operator '{}' not found", name))
    }

    /// Get a mutable operator by name.
    pub fn op_mut(&mut self, name: &str) -> &mut Operator {
        self.operators
            .iter_mut()
            .find(|o| o.name == name)
            .unwrap_or_else(|| panic!("operator '{}' not found", name))
    }

    /// Create a depositor with a deterministic keypair.
    pub fn create_depositor(&self, name: &str, seed: u8) -> Depositor {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[0] = seed;
        seed_bytes[31] = 0xDD;
        let sk = SecretKey::from_slice(&seed_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&self.secp, &sk);
        Depositor {
            name: name.to_string(),
            secret_key: sk,
            public_key: pk,
        }
    }

    /// Create a watcher (partner) copy of an operator's ledger.
    pub fn create_watcher(&self, operator_name: &str) -> Ledger {
        let op = self.op(operator_name);
        Ledger::new_as_partner(
            op.public_key,
            op.ledger.state.reserves_key.clone(),
            op.ledger.state.genesis_block,
        )
    }
}

impl Operator {
    /// Open a deposit on this operator's ledger.
    pub fn open_deposit(&mut self, depositor: &Depositor) -> DepositId {
        let descriptor = format!("pk({})", hex::encode(depositor.public_key.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);
        let op = LedgerOperation::DepositOpen {
            deposit_id,
            descriptor,
            fees: Some(FeeStructure::default()),
            transfer_fees: Some(TransferFeeSchedule::default()),
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        };
        self.ledger.append_operation(op).unwrap();
        deposit_id
    }

    /// Credit a deposit via invoice payment.
    pub fn credit_deposit(&mut self, deposit_id: DepositId, amount: u64, payment_hash: [u8; 32]) {
        let op = LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id,
            amount,
            invoice_id: hex::encode(&payment_hash[..8]),
            sequence_number: self.ledger.state.sequence + 1,
        };
        self.ledger.append_operation(op).unwrap();
    }

    /// Lock an invoice payment (requires depositor signature).
    pub fn lock_invoice(
        &mut self,
        depositor: &Depositor,
        deposit_id: DepositId,
        amount: u64,
        payment_id: [u8; 32],
    ) {
        let secp = Secp256k1::new();
        let msg_hash =
            deposits_protocol::invoice_lock_signing_message(&deposit_id, &payment_id, amount);
        let keypair = Keypair::from_secret_key(&secp, &depositor.secret_key);
        let msg = Message::from_digest(msg_hash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        let op = LedgerOperation::InvoiceLock {
            deposit_id,
            amount,
            payment_id,
            sequence_number: self.ledger.state.sequence + 1,
            witness: DescriptorWitness {
                stack: vec![sig.serialize().to_vec()],
            },
        };
        self.ledger.append_operation(op).unwrap();
    }

    /// Fulfill an invoice payment (with preimage).
    pub fn fulfill_invoice(
        &mut self,
        depositor: &Depositor,
        deposit_id: DepositId,
        amount: u64,
        payment_id: [u8; 32],
        preimage: [u8; 32],
    ) {
        let secp = Secp256k1::new();
        let msg_hash =
            deposits_protocol::invoice_lock_signing_message(&deposit_id, &payment_id, amount);
        let keypair = Keypair::from_secret_key(&secp, &depositor.secret_key);
        let msg = Message::from_digest(msg_hash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        let op = LedgerOperation::InvoiceFulfill {
            deposit_id,
            amount,
            payment_id,
            sequence_number: self.ledger.state.sequence + 1,
            witness: DescriptorWitness {
                stack: vec![sig.serialize().to_vec()],
            },
            preimage,
        };
        self.ledger.append_operation(op).unwrap();
    }

    /// Add a quorum member to this operator's ledger.
    pub fn add_quorum_member(&mut self, member: &Operator, member_ledger_id: &str) {
        let op = LedgerOperation::QuorumAddMember {
            quorum_member: member.public_key,
            member_ledger_id: member_ledger_id.to_string(),
            quorum_member_signature: [0xAB; 64],
            min_fee_bps: Some(50),
            min_fee_fixed: Some(100),
            max_fee_period: Some(2016),
            membership_until: Some(900_000),
            dispute_response_blocks: None,
            dispute_arm_blocks: None,
            service_response_blocks: None,
            max_transfer_timeout_blocks: None,
            max_descriptor_bytes: None,
            compensation_bps: None,
            compensation_deposit_id: None,
            compensation_frequency_blocks: None,
        };
        self.ledger.append_operation(op).unwrap();
    }

    /// Begin quorum (promotes pending members to active).
    ///
    /// Pads the cosigner list with synthetic deterministic keys up to
    /// `MIN_VALID_Q = 3` if the test set up fewer real members. Each
    /// padded key is also staged via a synthetic QuorumAddMember op so
    /// the new "members ⊆ next_quorum_members" validation passes. Tests
    /// that exercise specific cosigner-set behavior (e.g., adversarial
    /// consent paths) should add three real members explicitly via
    /// `add_quorum_member`.
    pub fn begin_quorum(&mut self, new_reserves_amount: u64) {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        const MIN_VALID_Q: usize = 3;
        let real_count = self.ledger.state.next_quorum_members.len();
        if real_count < MIN_VALID_Q {
            // Generate deterministic synthetic keys with high seeds so
            // they don't collide with real test operators (which tend to
            // use low byte values). Stage each via a real QuorumAddMember
            // op so the staged set actually contains them.
            let secp = Secp256k1::new();
            let mut filler: u8 = 0xF0;
            while self.ledger.state.next_quorum_members.len() < MIN_VALID_Q {
                let mut bytes = [0u8; 32];
                bytes[31] = filler;
                let sk = SecretKey::from_slice(&bytes).unwrap();
                let pk = PublicKey::from_secret_key(&secp, &sk);
                let already_staged = self
                    .ledger
                    .state
                    .next_quorum_members
                    .iter()
                    .any(|m| m.pubkey == pk);
                if !already_staged {
                    self.ledger
                        .append_operation(LedgerOperation::QuorumAddMember {
                            quorum_member: pk,
                            member_ledger_id: format!("synthetic_pad_{:02x}", filler),
                            quorum_member_signature: [0xCD; 64],
                            min_fee_bps: Some(50),
                            min_fee_fixed: Some(100),
                            max_fee_period: Some(2016),
                            membership_until: Some(900_000),
                            dispute_response_blocks: None,
                            dispute_arm_blocks: None,
                            service_response_blocks: None,
                            max_transfer_timeout_blocks: None,
                            max_descriptor_bytes: None,
                            compensation_bps: None,
                            compensation_deposit_id: None,
                            compensation_frequency_blocks: None,
                        })
                        .unwrap();
                }
                filler = filler.wrapping_add(1);
            }
        }
        let members: Vec<deposits_core::messages::QuorumMemberRef> = self
            .ledger
            .state
            .next_quorum_members
            .iter()
            .map(|m| deposits_core::messages::QuorumMemberRef::pubkey_only(m.pubkey))
            .collect();
        // Bind expiry to the MIN of staged members' membership_until per
        // protocol rule (operator can shorten but not extend any member's
        // commitment). Falls back to a sentinel only if no member set one.
        let quorum_expiry: u32 = self
            .ledger
            .state
            .next_quorum_members
            .iter()
            .filter_map(|m| m.membership_until)
            .min()
            .unwrap_or(900_000);
        let op = LedgerOperation::QuorumBegin {
            reserves_id: format!("{}_rotated", self.ledger.state.reserves_key),
            spending_txid: [0x11; 32],
            new_outpoint_txid: [0x22; 32],
            new_outpoint_vout: 0,
            amount: new_reserves_amount,
            quorum_expiry,
            ledger_hash: self.ledger.state.chain_tip_hash,
            quorum_members: members,
            collateral_amount: 50_000,
            protocol_version: None,
        };
        self.ledger.append_operation(op).unwrap();
    }

    /// Replay all operations from this ledger onto another ledger (watcher sync).
    pub fn sync_to(&self, watcher: &mut Ledger) {
        for update in &self.ledger.history {
            if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                watcher.apply_state_changes(&op).unwrap_or_else(|e| {
                    panic!("sync failed at seq {}: {}", update.sequence_number, e)
                });
                watcher.state.sequence = update.sequence_number;
                watcher.state.chain_tip_hash = update.chain_hash();
                watcher.history.push(update.clone());
            }
        }
    }

    /// Replay operations with conformance checking (returns violations).
    pub fn sync_to_checked(
        &self,
        watcher: &mut Ledger,
    ) -> Vec<deposits_protocol::ConformanceViolation> {
        let mut all_violations = Vec::new();
        for update in &self.ledger.history {
            if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                if let Ok(violations) = watcher.apply_and_check(&op, &CoreWitnessVerifier) {
                    all_violations.extend(violations);
                }
                watcher.state.sequence = update.sequence_number;
                watcher.state.chain_tip_hash = update.chain_hash();
                watcher.history.push(update.clone());
            }
        }
        all_violations
    }
}

use deposits_protocol::TlvDecode;
