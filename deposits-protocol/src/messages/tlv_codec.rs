use super::types::*;
use super::wire_types::*;
use super::*;

use crate::tlv::{TlvBuilder, TlvDecode, TlvEncode, TlvError, TlvReader, TlvResult};

/// TLV field type constants for LedgerOperation
mod ledger_op_tlv {
    pub const DISCRIMINANT: u64 = 0;
    pub const AMOUNT: u64 = 2;
    // 4 was SPEND_TO (unused; declare freed)
    pub const QUORUM_MEMBERS: u64 = 6;
    /// Parallel array to QUORUM_MEMBERS — one ledger_id string per
    /// member, length-prefixed (u8). Empty when constructed by older
    /// callers; new producers populate from QuorumAddMember.member_ledger_id.
    pub const QUORUM_MEMBER_LEDGER_IDS: u64 = 276;
    pub const FEES: u64 = 12;
    pub const PAYMENT_HASH: u64 = 14;
    pub const INVOICE: u64 = 16;
    pub const COSIGNER_SIG: u64 = 18;
    pub const NEW_FEES: u64 = 20;
    // 24 reserved (was DEPOSIT_PUBKEY on legacy wire — never emitted
    // by current code, dropped post-Wave-1 since identity is the
    // miniscript descriptor, not a single pubkey)
    pub const INVOICE_ID: u64 = 26;
    pub const SEQUENCE_NUMBER: u64 = 28;
    pub const PAYMENT_ID: u64 = 30;
    pub const PREIMAGE: u64 = 34;
    pub const BLOCK_HEIGHT: u64 = 36;
    // 38 was COLLATERAL_OPERATOR (removed with collateral-in-UTXO migration)
    // 40 was SIGNATURE (unused; declare freed)
    pub const LEDGER_HASH: u64 = 42;
    pub const QUORUM_MEMBER: u64 = 44;
    pub const QUORUM_MEMBER_SIG: u64 = 46;
    pub const OPERATOR_SIG: u64 = 48;
    // LedgerOpen fields
    pub const OPERATOR_ID: u64 = 56;
    pub const RESERVES_ID: u64 = 58;
    pub const RESERVES_AMOUNT: u64 = 62;
    // 64 was collateral_enforcement_block (removed)
    pub const GENESIS_BLOCK: u64 = 96;
    // Onchain operation fields
    pub const TXID: u64 = 66;
    pub const VOUT: u64 = 68;
    pub const DESTINATION_ADDRESS: u64 = 70;
    pub const WITHDRAWAL_ID: u64 = 72;
    pub const FUNDING_ADDRESS: u64 = 74;
    // 76 was LOCK_UNTIL_BLOCK (removed with collateral-in-UTXO migration)
    // QuorumJoin fields
    pub const MEMBERSHIP_EXPIRES: u64 = 82;
    // QuorumBegin fields
    pub const SPENDING_TXID: u64 = 90;
    pub const NEW_OUTPOINT_TXID: u64 = 84;
    pub const NEW_OUTPOINT_VOUT: u64 = 92;
    pub const QUORUM_EXPIRY: u64 = 86;
    pub const TOTAL_COLLATERAL: u64 = 88;
    // Dispute fields
    pub const REASON: u64 = 100;
    pub const LAST_VALID_SEQUENCE: u64 = 102;
    pub const NEW_CUSTODIAN: u64 = 108;
    pub const ARMED_BLOCK: u64 = 118;
    pub const CLAIM_TXID: u64 = 110;
    pub const NEW_RESERVES_ADDRESS: u64 = 120;
    // DisputeArmed lottery fields
    pub const COMMITMENT_HASH: u64 = 112;
    pub const TARGET_RESERVES: u64 = 122;
    /// DisputeArmed replacement-collateral declaration (DEP-03 §"Replacement
    /// collateral declaration"). All three are written when a producer
    /// pledges replacement collateral; absent on legacy events.
    pub const REPLACEMENT_COLLATERAL_TXID: u64 = 280; // [u8; 32]
    pub const REPLACEMENT_COLLATERAL_VOUT: u64 = 282; // u32
    pub const REPLACEMENT_COLLATERAL_AMOUNT: u64 = 284; // u64 sats
    // Quorum/Collateral ledger binding fields
    pub const MEMBER_LEDGER_ID: u64 = 114;
    // 124 was COLLATERAL_LEDGER_ID (removed with collateral-in-UTXO migration)
    // Descriptor-based deposit fields
    pub const DEPOSIT_ID: u64 = 200; // 16-byte deposit identifier
    pub const DESCRIPTOR: u64 = 202; // Variable-length string
    pub const WITNESS: u64 = 204; // Nested TLV with stack elements
    pub const WITNESS_ELEMENT: u64 = 206; // Single stack element (bytes)
    pub const NEW_DESCRIPTOR: u64 = 208; // New descriptor for key rotation

    // Transfer operation fields
    pub const NONCE: u64 = 210;
    pub const SOURCE_DEPOSIT_ID: u64 = 212;
    pub const DESTINATION_DEPOSIT_ID: u64 = 214;
    pub const COMPLETION_SCRIPT: u64 = 216;
    pub const TIMEOUT_HEIGHT: u64 = 218;
    pub const TRANSFER_ID: u64 = 220;
    pub const BLOCK_HASH: u64 = 222;
    pub const SCRIPT_WITNESS: u64 = 224;
    pub const TRANSFER_FEES: u64 = 226;
    pub const FAIL_REASON: u64 = 228; // u8 (0 = timeout)
    pub const RECEIVE_REQUIRES_SIG: u64 = 232; // u8 (0 or 1)
                                               // Quorum member fee limits (on QuorumAddMember)
    pub const MIN_FEE_BPS: u64 = 234; // u16
    pub const MIN_FEE_FIXED: u64 = 236; // u64 (msats/year)
    pub const MAX_FEE_PERIOD: u64 = 238; // u32 (blocks)
    pub const FEE_CHANGE_AFTER: u64 = 244; // u32 (blocks after open)
    pub const FEE_CHANGE_NOTICE: u64 = 246; // u32 (notice blocks)
    pub const FEE_CHANGE_LIMIT_BPS: u64 = 248; // u16 (default 1000 = 10%)
    pub const EFFECTIVE_BLOCK: u64 = 250; // u32 (on FeeChange)
                                          // 240 was COLLATERAL_LOCK_AMOUNT (removed with collateral-in-UTXO migration)
    pub const MEMBERSHIP_UNTIL: u64 = 242; // u32 (block height) — on QuorumAddMember

    // Per-quorum timing parameters (on QuorumAddMember)
    pub const DISPUTE_RESPONSE_BLOCKS: u64 = 252; // u32
    pub const DISPUTE_ARM_BLOCKS: u64 = 254; // u32
    pub const SERVICE_RESPONSE_BLOCKS: u64 = 256; // u32
    pub const MAX_TRANSFER_TIMEOUT_BLOCKS: u64 = 258; // u32
    pub const MAX_DESCRIPTOR_BYTES: u64 = 262; // u32

    // Member compensation negotiated at quorum formation.
    // `compensation_bps` is the portion of *collected* fees the operator
    // commits to pay this member (300 = 3%). The payout lands in the
    // member's chosen deposit on the operator's ledger at the member's
    // chosen cadence.
    pub const COMPENSATION_BPS: u64 = 264; // u16
    pub const COMPENSATION_DEPOSIT_ID: u64 = 266; // [u8; 16]
    pub const COMPENSATION_FREQUENCY_BLOCKS: u64 = 268; // u32

    // Delivery operation fields
    pub const REQUEST_HASH: u64 = 270; // [u8; 32]
    pub const TARGET_LEDGER_ID: u64 = 272; // [u8; 32]
    pub const TARGET_OPERATOR: u64 = 274; // pubkey (33 bytes)
}

impl TlvEncode for LedgerOperation {
    fn tlv_encode(&self) -> Vec<u8> {
        use ledger_op_tlv::*;

        let mut builder = TlvBuilder::new().u8_field(DISCRIMINANT, self.discriminant());

        match self {
            Self::LedgerOpen {
                operator_id,
                reserves_id,
                genesis_block,
                reserves_amount,
                collateral_amount,
            } => {
                builder = builder
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .u32_field(GENESIS_BLOCK, *genesis_block)
                    .u64_field(RESERVES_AMOUNT, *reserves_amount)
                    .u64_field(TOTAL_COLLATERAL, *collateral_amount);
            }
            Self::QuorumBegin {
                reserves_id,
                spending_txid,
                new_outpoint_txid,
                new_outpoint_vout,
                amount,
                quorum_expiry,
                ledger_hash,
                quorum_members,
                collateral_amount,
            } => {
                // Pubkeys: concat of 33-byte compressed pubkeys (existing
                // shape — kept for backwards compatibility).
                let mut members_bytes = Vec::new();
                for m in quorum_members {
                    members_bytes.extend_from_slice(&m.pubkey.serialize());
                }
                // Member ledger_ids: parallel array, each entry is
                // `u8 len || ledger_id_bytes`. Skipped entirely if all
                // entries are empty (older producers / legacy callers).
                let any_lids = quorum_members.iter().any(|m| !m.member_ledger_id.is_empty());
                let mut lids_bytes = Vec::new();
                if any_lids {
                    for m in quorum_members {
                        let lid = m.member_ledger_id.as_bytes();
                        lids_bytes.push(lid.len() as u8);
                        lids_bytes.extend_from_slice(lid);
                    }
                }
                builder = builder
                    .string_field(RESERVES_ID, reserves_id)
                    .bytes_field(SPENDING_TXID, spending_txid)
                    .bytes_field(NEW_OUTPOINT_TXID, new_outpoint_txid)
                    .u32_field(NEW_OUTPOINT_VOUT, *new_outpoint_vout)
                    .u64_field(AMOUNT, *amount)
                    .u32_field(QUORUM_EXPIRY, *quorum_expiry)
                    .bytes_field(LEDGER_HASH, ledger_hash)
                    .bytes_field(QUORUM_MEMBERS, &members_bytes)
                    .u64_field(TOTAL_COLLATERAL, *collateral_amount);
                if any_lids {
                    builder = builder.bytes_field(QUORUM_MEMBER_LEDGER_IDS, &lids_bytes);
                }
            }
            Self::DepositOpen {
                deposit_id,
                descriptor,
                fees,
                transfer_fees,
                payment_hash,
                invoice,
                cosigner_guarantee_signature,
                receive_requires_sig,
                fee_change_after_blocks,
                fee_change_notice_blocks,
                fee_change_limit_bps,
            } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .string_field(DESCRIPTOR, descriptor);
                if let Some(f) = fees {
                    builder = builder.nested(FEES, f);
                }
                if let Some(tf) = transfer_fees {
                    builder = builder.nested(TRANSFER_FEES, tf);
                }
                if let Some(h) = payment_hash {
                    builder = builder.bytes_field(PAYMENT_HASH, h);
                }
                if let Some(inv) = invoice {
                    builder = builder.string_field(INVOICE, inv);
                }
                if let Some(sig) = cosigner_guarantee_signature {
                    builder = builder.bytes_field(COSIGNER_SIG, sig);
                }
                if *receive_requires_sig {
                    builder = builder.u8_field(RECEIVE_REQUIRES_SIG, 1);
                }
                if let Some(v) = fee_change_after_blocks {
                    builder = builder.u32_field(FEE_CHANGE_AFTER, *v);
                }
                if let Some(v) = fee_change_notice_blocks {
                    builder = builder.u32_field(FEE_CHANGE_NOTICE, *v);
                }
                if let Some(v) = fee_change_limit_bps {
                    builder = builder.u16_field(FEE_CHANGE_LIMIT_BPS, *v);
                }
            }
            Self::DepositClose { deposit_id } => {
                builder = builder.deposit_id_field(DEPOSIT_ID, deposit_id);
            }
            Self::FeeChange {
                deposit_id,
                new_fees,
                effective_block,
            } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .nested(NEW_FEES, new_fees)
                    .u32_field(EFFECTIVE_BLOCK, *effective_block);
            }
            Self::DepositKeyRotate {
                deposit_id,
                new_descriptor,
                witness,
            } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .string_field(NEW_DESCRIPTOR, new_descriptor)
                    .witness_field(WITNESS, witness);
            }
            Self::InvoiceCredit {
                payment_hash,
                deposit_id,
                amount,
                invoice_id,
                sequence_number,
            } => {
                builder = builder
                    .bytes_field(PAYMENT_HASH, payment_hash)
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .string_field(INVOICE_ID, invoice_id)
                    .u64_field(SEQUENCE_NUMBER, *sequence_number);
            }
            Self::InvoiceLock {
                deposit_id,
                amount,
                payment_id,
                sequence_number,
                witness,
            } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .bytes_field(PAYMENT_ID, payment_id)
                    .u64_field(SEQUENCE_NUMBER, *sequence_number)
                    .witness_field(WITNESS, witness);
            }
            Self::InvoiceFail {
                deposit_id,
                amount,
                payment_id,
                sequence_number,
            } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .bytes_field(PAYMENT_ID, payment_id)
                    .u64_field(SEQUENCE_NUMBER, *sequence_number);
            }
            Self::InvoiceFulfill {
                deposit_id,
                amount,
                payment_id,
                sequence_number,
                witness,
                preimage,
            } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .bytes_field(PAYMENT_ID, payment_id)
                    .u64_field(SEQUENCE_NUMBER, *sequence_number)
                    .witness_field(WITNESS, witness)
                    .bytes_field(PREIMAGE, preimage);
            }
            Self::OnchainCredit {
                txid,
                vout,
                deposit_id,
                amount,
                funding_address,
            } => {
                builder = builder
                    .bytes_field(TXID, txid)
                    .u32_field(VOUT, *vout)
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .string_field(FUNDING_ADDRESS, funding_address);
            }
            Self::OnchainLock {
                deposit_id,
                amount,
                fee_sats,
                destination_address,
                withdrawal_id,
                witness,
            } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .u64_field(FEES, *fee_sats)
                    .string_field(DESTINATION_ADDRESS, destination_address)
                    .bytes_field(WITHDRAWAL_ID, withdrawal_id)
                    .witness_field(WITNESS, witness);
            }
            Self::OnchainFail {
                deposit_id,
                withdrawal_id,
            } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .bytes_field(WITHDRAWAL_ID, withdrawal_id);
            }
            Self::OnchainFulfill {
                deposit_id,
                withdrawal_id,
                amount,
                txid,
                destination_address,
            } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .bytes_field(WITHDRAWAL_ID, withdrawal_id)
                    .u64_field(AMOUNT, *amount)
                    .bytes_field(TXID, txid)
                    .string_field(DESTINATION_ADDRESS, destination_address);
            }
            Self::TransferLock {
                nonce,
                source_deposit_id,
                destination_deposit_id,
                amount,
                fee,
                completion_script,
                timeout_height,
                transfer_id,
                witness,
            } => {
                builder = builder
                    .bytes_field(NONCE, nonce)
                    .deposit_id_field(SOURCE_DEPOSIT_ID, source_deposit_id)
                    .deposit_id_field(DESTINATION_DEPOSIT_ID, destination_deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .u64_field(FEES, *fee)
                    .string_field(COMPLETION_SCRIPT, completion_script)
                    .u32_field(TIMEOUT_HEIGHT, *timeout_height)
                    .bytes_field(TRANSFER_ID, transfer_id)
                    .witness_field(WITNESS, witness);
            }
            Self::TransferComplete {
                transfer_id,
                script_witness,
            } => {
                builder = builder
                    .bytes_field(TRANSFER_ID, transfer_id)
                    .witness_field(SCRIPT_WITNESS, script_witness);
            }
            Self::TransferFail {
                transfer_id,
                block_hash,
                reason,
            } => {
                builder = builder
                    .bytes_field(TRANSFER_ID, transfer_id)
                    .bytes_field(BLOCK_HASH, block_hash)
                    .u8_field(FAIL_REASON, *reason);
            }
            Self::QuorumAddMember {
                quorum_member,
                quorum_member_signature,
                member_ledger_id,
                min_fee_bps,
                min_fee_fixed,
                max_fee_period,
                membership_until,
                dispute_response_blocks,
                dispute_arm_blocks,
                service_response_blocks,
                max_transfer_timeout_blocks,
                max_descriptor_bytes,
                compensation_bps,
                compensation_deposit_id,
                compensation_frequency_blocks,
            } => {
                builder = builder
                    .pubkey_field(QUORUM_MEMBER, quorum_member)
                    .bytes_field(QUORUM_MEMBER_SIG, quorum_member_signature)
                    .string_field(MEMBER_LEDGER_ID, member_ledger_id);
                if let Some(bps) = min_fee_bps {
                    builder = builder.u16_field(MIN_FEE_BPS, *bps);
                }
                if let Some(fixed) = min_fee_fixed {
                    builder = builder.u64_field(MIN_FEE_FIXED, *fixed);
                }
                if let Some(period) = max_fee_period {
                    builder = builder.u32_field(MAX_FEE_PERIOD, *period);
                }
                if let Some(until) = membership_until {
                    builder = builder.u32_field(MEMBERSHIP_UNTIL, *until);
                }
                if let Some(v) = dispute_response_blocks {
                    builder = builder.u32_field(DISPUTE_RESPONSE_BLOCKS, *v);
                }
                if let Some(v) = dispute_arm_blocks {
                    builder = builder.u32_field(DISPUTE_ARM_BLOCKS, *v);
                }
                if let Some(v) = service_response_blocks {
                    builder = builder.u32_field(SERVICE_RESPONSE_BLOCKS, *v);
                }
                if let Some(v) = max_transfer_timeout_blocks {
                    builder = builder.u32_field(MAX_TRANSFER_TIMEOUT_BLOCKS, *v);
                }
                if let Some(v) = max_descriptor_bytes {
                    builder = builder.u32_field(MAX_DESCRIPTOR_BYTES, *v);
                }
                if let Some(v) = compensation_bps {
                    builder = builder.u16_field(COMPENSATION_BPS, *v);
                }
                if let Some(v) = compensation_deposit_id {
                    builder = builder.deposit_id_field(COMPENSATION_DEPOSIT_ID, v);
                }
                if let Some(v) = compensation_frequency_blocks {
                    builder = builder.u32_field(COMPENSATION_FREQUENCY_BLOCKS, *v);
                }
            }
            Self::QuorumRemoveMember {
                quorum_member,
                operator_signature,
            } => {
                builder = builder
                    .pubkey_field(QUORUM_MEMBER, quorum_member)
                    .bytes_field(OPERATOR_SIG, operator_signature);
            }
            Self::QuorumJoin {
                operator_id,
                ledger_id,
                membership_expires,
            } => {
                // Note: TLV field ID is RESERVES_ID (58) for wire compatibility,
                // even though the Rust field is now named ledger_id
                builder = builder
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, ledger_id)
                    .u32_field(MEMBERSHIP_EXPIRES, *membership_expires);
            }
            Self::FeeCollect {
                deposit_id,
                amount,
                block_height,
            } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .u32_field(BLOCK_HEIGHT, *block_height);
            }
            Self::DisputeEnter {
                last_valid_sequence,
                reason,
            } => {
                builder = builder
                    .u64_field(LAST_VALID_SEQUENCE, *last_valid_sequence)
                    .string_field(REASON, reason);
            }
            Self::DisputeArmed {
                armed_block,
                commitment_hash,
                target_reserves,
                replacement_collateral,
            } => {
                builder = builder
                    .u32_field(ARMED_BLOCK, *armed_block)
                    .bytes_field(COMMITMENT_HASH, commitment_hash)
                    .string_field(TARGET_RESERVES, target_reserves);
                if let Some(rc) = replacement_collateral {
                    builder = builder
                        .bytes_field(REPLACEMENT_COLLATERAL_TXID, &rc.txid)
                        .u32_field(REPLACEMENT_COLLATERAL_VOUT, rc.vout)
                        .u64_field(REPLACEMENT_COLLATERAL_AMOUNT, rc.amount);
                }
            }
            Self::DisputeAcquire {
                new_custodian,
                claim_txid,
                new_reserves_address,
            } => {
                builder = builder
                    .pubkey_field(NEW_CUSTODIAN, new_custodian)
                    .bytes_field(CLAIM_TXID, claim_txid)
                    .string_field(NEW_RESERVES_ADDRESS, new_reserves_address);
            }
            Self::DeliveryEmbed {
                request_hash,
                target_ledger_id,
                target_operator,
            } => {
                builder = builder
                    .bytes_field(REQUEST_HASH, request_hash)
                    .bytes_field(TARGET_LEDGER_ID, target_ledger_id)
                    .pubkey_field(TARGET_OPERATOR, target_operator);
            }
            Self::DisputeYield => {}
            Self::LedgerClose => {}
        }

        builder.build()
    }
}

impl TlvDecode for LedgerOperation {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use ledger_op_tlv::*;

        let reader = TlvReader::new(data)?;
        let discriminant = reader.read_u8(DISCRIMINANT)?;

        match discriminant {
            1 => Ok(Self::LedgerOpen {
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                genesis_block: reader.read_u32_opt(GENESIS_BLOCK)?.unwrap_or(0),
                reserves_amount: reader.read_u64_opt(RESERVES_AMOUNT)?.unwrap_or(0),
                collateral_amount: reader.read_u64_opt(TOTAL_COLLATERAL)?.unwrap_or(0),
            }),
            12 => {
                let members_bytes = reader.read_raw_opt(QUORUM_MEMBERS).unwrap_or(&[]);
                let mut pubkeys = Vec::new();
                let mut off = 0;
                while off + 33 <= members_bytes.len() {
                    if let Ok(pk) =
                        bitcoin::secp256k1::PublicKey::from_slice(&members_bytes[off..off + 33])
                    {
                        pubkeys.push(pk);
                    }
                    off += 33;
                }
                // Parallel ledger_id list. New field; absent in older
                // events. Each entry is `u8 len || ledger_id_bytes`.
                let lids_bytes = reader.read_raw_opt(QUORUM_MEMBER_LEDGER_IDS).unwrap_or(&[]);
                let mut ledger_ids: Vec<String> = Vec::new();
                let mut loff = 0;
                while loff < lids_bytes.len() {
                    let len = lids_bytes[loff] as usize;
                    loff += 1;
                    if loff + len > lids_bytes.len() {
                        break;
                    }
                    ledger_ids.push(
                        String::from_utf8_lossy(&lids_bytes[loff..loff + len]).into_owned()
                    );
                    loff += len;
                }
                let quorum_members: Vec<QuorumMemberRef> = pubkeys
                    .into_iter()
                    .enumerate()
                    .map(|(i, pk)| QuorumMemberRef {
                        pubkey: pk,
                        member_ledger_id: ledger_ids.get(i).cloned().unwrap_or_default(),
                    })
                    .collect();
                Ok(Self::QuorumBegin {
                    reserves_id: reader.read_string(RESERVES_ID)?,
                    spending_txid: reader.read_bytes(SPENDING_TXID)?,
                    new_outpoint_txid: reader.read_bytes(NEW_OUTPOINT_TXID)?,
                    new_outpoint_vout: reader.read_u32(NEW_OUTPOINT_VOUT)?,
                    amount: reader.read_u64(AMOUNT)?,
                    quorum_expiry: reader.read_u32(QUORUM_EXPIRY)?,
                    ledger_hash: reader.read_bytes(LEDGER_HASH)?,
                    quorum_members,
                    collateral_amount: reader.read_u64(TOTAL_COLLATERAL)?,
                })
            }
            20 => Ok(Self::DepositOpen {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                descriptor: reader.read_string(DESCRIPTOR)?,
                fees: reader.read_nested_opt(FEES)?,
                transfer_fees: reader.read_nested_opt(TRANSFER_FEES)?,
                payment_hash: reader.read_bytes_opt(PAYMENT_HASH)?,
                invoice: reader.read_string_opt(INVOICE)?,
                cosigner_guarantee_signature: reader.read_bytes_opt(COSIGNER_SIG)?,
                receive_requires_sig: reader.read_u8(RECEIVE_REQUIRES_SIG).unwrap_or(0) != 0,
                fee_change_after_blocks: reader.read_u32_opt(FEE_CHANGE_AFTER)?,
                fee_change_notice_blocks: reader.read_u32_opt(FEE_CHANGE_NOTICE)?,
                fee_change_limit_bps: reader.read_u16_opt(FEE_CHANGE_LIMIT_BPS)?,
            }),
            21 => Ok(Self::DepositClose {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
            }),
            22 => Ok(Self::FeeChange {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                new_fees: reader.read_nested(NEW_FEES)?,
                effective_block: reader.read_u32_opt(EFFECTIVE_BLOCK)?.unwrap_or(0),
            }),
            23 => Ok(Self::DepositKeyRotate {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                new_descriptor: reader.read_string(NEW_DESCRIPTOR)?,
                witness: reader.read_witness(WITNESS)?,
            }),
            30 => Ok(Self::InvoiceCredit {
                payment_hash: reader.read_bytes(PAYMENT_HASH)?,
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                invoice_id: reader.read_string(INVOICE_ID)?,
                sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
            }),
            31 => Ok(Self::InvoiceLock {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                payment_id: reader.read_bytes(PAYMENT_ID)?,
                sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
                witness: reader.read_witness(WITNESS)?,
            }),
            32 => Ok(Self::InvoiceFail {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                payment_id: reader.read_bytes(PAYMENT_ID)?,
                sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
            }),
            33 => Ok(Self::InvoiceFulfill {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                payment_id: reader.read_bytes(PAYMENT_ID)?,
                sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
                witness: reader.read_witness(WITNESS)?,
                preimage: reader.read_bytes(PREIMAGE)?,
            }),
            35 => Ok(Self::OnchainCredit {
                txid: reader.read_bytes(TXID)?,
                vout: reader.read_u32(VOUT)?,
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                funding_address: reader.read_string(FUNDING_ADDRESS)?,
            }),
            36 => Ok(Self::OnchainLock {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                fee_sats: reader.read_u64(FEES)?,
                destination_address: reader.read_string(DESTINATION_ADDRESS)?,
                withdrawal_id: reader.read_bytes(WITHDRAWAL_ID)?,
                witness: reader.read_witness(WITNESS)?,
            }),
            37 => Ok(Self::OnchainFail {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                withdrawal_id: reader.read_bytes(WITHDRAWAL_ID)?,
            }),
            38 => Ok(Self::OnchainFulfill {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                withdrawal_id: reader.read_bytes(WITHDRAWAL_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                txid: reader.read_bytes(TXID)?,
                destination_address: reader.read_string(DESTINATION_ADDRESS)?,
            }),
            70 => Ok(Self::TransferLock {
                nonce: reader.read_bytes(NONCE)?,
                source_deposit_id: reader.read_deposit_id(SOURCE_DEPOSIT_ID)?,
                destination_deposit_id: reader.read_deposit_id(DESTINATION_DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                fee: reader.read_u64(FEES)?,
                completion_script: reader.read_string(COMPLETION_SCRIPT)?,
                timeout_height: reader.read_u32(TIMEOUT_HEIGHT)?,
                transfer_id: reader.read_bytes(TRANSFER_ID)?,
                witness: reader.read_witness(WITNESS)?,
            }),
            71 => Ok(Self::TransferComplete {
                transfer_id: reader.read_bytes(TRANSFER_ID)?,
                script_witness: reader.read_witness(SCRIPT_WITNESS)?,
            }),
            72 => Ok(Self::TransferFail {
                transfer_id: reader.read_bytes(TRANSFER_ID)?,
                block_hash: reader.read_bytes(BLOCK_HASH)?,
                reason: reader.read_u8(FAIL_REASON).unwrap_or(1),
            }),
            43 => Ok(Self::QuorumAddMember {
                quorum_member: reader.read_pubkey(QUORUM_MEMBER)?,
                quorum_member_signature: reader.read_bytes(QUORUM_MEMBER_SIG)?,
                member_ledger_id: reader.read_string(MEMBER_LEDGER_ID)?,
                min_fee_bps: reader.read_u16_opt(MIN_FEE_BPS)?,
                min_fee_fixed: reader.read_u64_opt(MIN_FEE_FIXED)?,
                max_fee_period: reader.read_u32_opt(MAX_FEE_PERIOD)?,
                membership_until: reader.read_u32_opt(MEMBERSHIP_UNTIL)?,
                dispute_response_blocks: reader.read_u32_opt(DISPUTE_RESPONSE_BLOCKS)?,
                dispute_arm_blocks: reader.read_u32_opt(DISPUTE_ARM_BLOCKS)?,
                service_response_blocks: reader.read_u32_opt(SERVICE_RESPONSE_BLOCKS)?,
                max_transfer_timeout_blocks: reader.read_u32_opt(MAX_TRANSFER_TIMEOUT_BLOCKS)?,
                max_descriptor_bytes: reader.read_u32_opt(MAX_DESCRIPTOR_BYTES)?,
                compensation_bps: reader.read_u16_opt(COMPENSATION_BPS)?,
                compensation_deposit_id: reader.read_deposit_id_opt(COMPENSATION_DEPOSIT_ID)?,
                compensation_frequency_blocks: reader.read_u32_opt(COMPENSATION_FREQUENCY_BLOCKS)?,
            }),
            44 => Ok(Self::QuorumRemoveMember {
                quorum_member: reader.read_pubkey(QUORUM_MEMBER)?,
                operator_signature: reader.read_bytes(OPERATOR_SIG)?,
            }),
            46 => Ok(Self::QuorumJoin {
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                // Note: TLV field ID is RESERVES_ID (58) for wire compatibility
                ledger_id: reader.read_string(RESERVES_ID)?,
                membership_expires: reader.read_u32(MEMBERSHIP_EXPIRES)?,
            }),
            50 => Ok(Self::FeeCollect {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                block_height: reader.read_u32(BLOCK_HEIGHT)?,
            }),
            54 => Ok(Self::DisputeEnter {
                last_valid_sequence: reader.read_u64(LAST_VALID_SEQUENCE)?,
                reason: reader.read_string(REASON)?,
            }),
            55 => Ok(Self::DisputeAcquire {
                new_custodian: reader.read_pubkey(NEW_CUSTODIAN)?,
                claim_txid: reader.read_bytes(CLAIM_TXID)?,
                new_reserves_address: reader.read_string(NEW_RESERVES_ADDRESS)?,
            }),
            56 => Ok(Self::DisputeYield),
            57 => {
                let armed_block = reader.read_u32(ARMED_BLOCK)?;
                let commitment_hash = reader.read_bytes(COMMITMENT_HASH)?;
                let target_reserves = reader.read_string(TARGET_RESERVES)?;
                // Replacement collateral: optional, all-or-nothing. New
                // producers emit all three fields; legacy events omit them.
                // Partial presence (some fields, not all) is a malformed
                // event and falls through to MissingRequiredField.
                let rc_txid = reader.read_bytes_opt::<32>(REPLACEMENT_COLLATERAL_TXID)?;
                let rc_vout = reader.read_u32_opt(REPLACEMENT_COLLATERAL_VOUT)?;
                let rc_amount = reader.read_u64_opt(REPLACEMENT_COLLATERAL_AMOUNT)?;
                let replacement_collateral = match (rc_txid, rc_vout, rc_amount) {
                    (Some(txid), Some(vout), Some(amount)) => {
                        Some(ReplacementCollateral { txid, vout, amount })
                    }
                    (None, None, None) => None,
                    _ => return Err(TlvError::InvalidFieldValue {
                        field_type: REPLACEMENT_COLLATERAL_TXID,
                        reason: "DisputeArmed replacement_collateral fields must be all present or all absent".into(),
                    }),
                };
                Ok(Self::DisputeArmed {
                    armed_block,
                    commitment_hash,
                    target_reserves,
                    replacement_collateral,
                })
            },
            80 => Ok(Self::DeliveryEmbed {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
                target_ledger_id: reader.read_bytes(TARGET_LEDGER_ID)?,
                target_operator: reader.read_pubkey(TARGET_OPERATOR)?,
            }),
            60 => Ok(Self::LedgerClose),
            d => Err(TlvError::InvalidFieldValue {
                field_type: DISCRIMINANT,
                reason: format!("unknown LedgerOperation discriminant: {}", d),
            }),
        }
    }
}

/// TLV field type constants for LedgerUpdateMsg
mod ledger_update_tlv {
    pub const OPERATOR_ID: u64 = 0;
    pub const RESERVES_ID: u64 = 2;
    pub const OPERATION: u64 = 4;
    pub const SEQUENCE_NUMBER: u64 = 6;
    pub const PREVIOUS_HASH: u64 = 8;
    pub const CURRENT_HASH: u64 = 10;
    pub const OPERATOR_SIGNATURE: u64 = 12;
}

impl TlvEncode for LedgerUpdateMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use ledger_update_tlv::*;
        TlvBuilder::new()
            .pubkey_field(OPERATOR_ID, &self.operator_id)
            .string_field(RESERVES_ID, &self.reserves_id)
            .nested(OPERATION, &self.operation)
            .u64_field(SEQUENCE_NUMBER, self.sequence_number)
            .bytes_field(PREVIOUS_HASH, &self.previous_hash)
            .bytes_field(CURRENT_HASH, &self.content_hash)
            .bytes_field(OPERATOR_SIGNATURE, &self.operator_signature)
            .build()
    }
}

impl TlvDecode for LedgerUpdateMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use ledger_update_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            operator_id: reader.read_pubkey(OPERATOR_ID)?,
            reserves_id: reader.read_string(RESERVES_ID)?,
            operation: reader.read_nested(OPERATION)?,
            sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
            previous_hash: reader.read_bytes(PREVIOUS_HASH)?,
            content_hash: reader.read_bytes(CURRENT_HASH)?,
            operator_signature: reader.read_bytes(OPERATOR_SIGNATURE)?,
        })
    }
}

/// TLV field type constants for LedgerUpdateResponseMsg
mod ledger_response_tlv {
    pub const OPERATOR_ID: u64 = 0;
    pub const RESERVES_ID: u64 = 2;
    pub const REQUEST_HASH: u64 = 4;
    pub const ACCEPTED: u64 = 6;
    pub const ERROR: u64 = 8;
    pub const COSIGN_SIGNATURE: u64 = 10;
    pub const CONFIRMED_SEQUENCE: u64 = 12;
    pub const CONFIRMED_HASH: u64 = 14;
}

impl TlvEncode for LedgerUpdateResponseMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use ledger_response_tlv::*;
        let mut builder = TlvBuilder::new()
            .pubkey_field(OPERATOR_ID, &self.operator_id)
            .string_field(RESERVES_ID, &self.reserves_id)
            .bytes_field(REQUEST_HASH, &self.request_hash)
            .u8_field(ACCEPTED, if self.accepted { 1 } else { 0 });

        if let Some(ref err) = self.error {
            builder = builder.string_field(ERROR, err);
        }
        if let Some(ref sig) = self.cosign_signature {
            builder = builder.bytes_field(COSIGN_SIGNATURE, sig);
        }

        builder
            .u64_field(CONFIRMED_SEQUENCE, self.confirmed_sequence)
            .bytes_field(CONFIRMED_HASH, &self.confirmed_hash)
            .build()
    }
}

impl TlvDecode for LedgerUpdateResponseMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use ledger_response_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            operator_id: reader.read_pubkey(OPERATOR_ID)?,
            reserves_id: reader.read_string(RESERVES_ID)?,
            request_hash: reader.read_bytes(REQUEST_HASH)?,
            accepted: reader.read_u8(ACCEPTED)? != 0,
            error: reader.read_string_opt(ERROR)?,
            cosign_signature: reader.read_bytes_opt(COSIGN_SIGNATURE)?,
            confirmed_sequence: reader.read_u64(CONFIRMED_SEQUENCE)?,
            confirmed_hash: reader.read_bytes(CONFIRMED_HASH)?,
        })
    }
}

/// TLV field type constants for HandshakeMsg
mod handshake_tlv {
    pub const PROTOCOL_VERSION: u64 = 0;
    pub const MIN_PROTOCOL_VERSION: u64 = 2;
    pub const FEATURES: u64 = 4;
    pub const OPERATOR_PUBKEY: u64 = 6;
    pub const PARTNER_PUBKEY: u64 = 8;
    pub const FUNDING_TXID: u64 = 10;
    pub const FUNDING_VOUT: u64 = 12;
    // 14 was COLLATERAL_ENFORCEMENT_BLOCK (removed)
}

impl TlvEncode for HandshakeMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use handshake_tlv::*;
        TlvBuilder::new()
            .u16_field(PROTOCOL_VERSION, self.protocol_version)
            .u16_field(MIN_PROTOCOL_VERSION, self.min_protocol_version)
            .u32_field(FEATURES, self.features)
            .pubkey_field(OPERATOR_PUBKEY, &self.operator_id)
            .string_field(PARTNER_PUBKEY, &self.reserves_id)
            .bytes_field(FUNDING_TXID, &self.funding_txid)
            .u16_field(FUNDING_VOUT, self.funding_vout)
            .build()
    }
}

impl TlvDecode for HandshakeMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use handshake_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            protocol_version: reader.read_u16(PROTOCOL_VERSION)?,
            min_protocol_version: reader.read_u16(MIN_PROTOCOL_VERSION)?,
            features: reader.read_u32(FEATURES)?,
            operator_id: reader.read_pubkey(OPERATOR_PUBKEY)?,
            reserves_id: reader.read_string(PARTNER_PUBKEY)?,
            funding_txid: reader.read_bytes(FUNDING_TXID)?,
            funding_vout: reader.read_u16(FUNDING_VOUT)?,
        })
    }
}

/// TLV field type constants for HandshakeResponseMsg
mod handshake_response_tlv {
    pub const REQUEST_HASH: u64 = 0;
    pub const PROTOCOL_VERSION: u64 = 2;
    pub const ACCEPTED: u64 = 4;
    pub const ERROR: u64 = 6;
    pub const PARTNER_PUBKEY: u64 = 8;
}

impl TlvEncode for HandshakeResponseMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use handshake_response_tlv::*;
        let mut builder = TlvBuilder::new()
            .bytes_field(REQUEST_HASH, &self.request_hash)
            .u16_field(PROTOCOL_VERSION, self.protocol_version)
            .u8_field(ACCEPTED, if self.accepted { 1 } else { 0 });

        if let Some(ref err) = self.error {
            builder = builder.string_field(ERROR, err);
        }

        builder
            .string_field(PARTNER_PUBKEY, &self.reserves_id)
            .build()
    }
}

impl TlvDecode for HandshakeResponseMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use handshake_response_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            request_hash: reader.read_bytes(REQUEST_HASH)?,
            protocol_version: reader.read_u16(PROTOCOL_VERSION)?,
            accepted: reader.read_u8(ACCEPTED)? != 0,
            error: reader.read_string_opt(ERROR)?,
            reserves_id: reader.read_string(PARTNER_PUBKEY)?,
        })
    }
}

// NOTE: TlvEncode/TlvDecode for SignedLedgerUpdate are implemented in types.rs

/// TLV for SyncMsg
mod sync_msg_tlv {
    pub const LEDGER_ID: u64 = 0;
    pub const LAST_KNOWN_SEQUENCE: u64 = 2;
    pub const LAST_KNOWN_HASH: u64 = 4;
}

impl TlvEncode for SyncMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use sync_msg_tlv::*;
        TlvBuilder::new()
            .bytes_field(LEDGER_ID, &self.ledger_id)
            .u64_field(LAST_KNOWN_SEQUENCE, self.last_known_sequence)
            .bytes_field(LAST_KNOWN_HASH, &self.last_known_hash)
            .build()
    }
}

impl TlvDecode for SyncMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use sync_msg_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            ledger_id: reader.read_bytes(LEDGER_ID)?,
            last_known_sequence: reader.read_u64(LAST_KNOWN_SEQUENCE)?,
            last_known_hash: reader.read_bytes(LAST_KNOWN_HASH)?,
        })
    }
}

/// TLV for SyncResponseMsg
mod sync_response_tlv {
    pub const LEDGER_ID: u64 = 0;
    pub const REQUEST_HASH: u64 = 2;
    pub const UPDATES: u64 = 4;
    pub const CURRENT_SEQUENCE: u64 = 6;
    pub const CURRENT_HASH: u64 = 8;
}

impl TlvEncode for SyncResponseMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use sync_response_tlv::*;
        TlvBuilder::new()
            .bytes_field(LEDGER_ID, &self.ledger_id)
            .bytes_field(REQUEST_HASH, &self.request_hash)
            .vec_field(UPDATES, &self.updates)
            .u64_field(CURRENT_SEQUENCE, self.current_sequence)
            .bytes_field(CURRENT_HASH, &self.content_hash)
            .build()
    }
}

impl TlvDecode for SyncResponseMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use sync_response_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            ledger_id: reader.read_bytes(LEDGER_ID)?,
            request_hash: reader.read_bytes(REQUEST_HASH)?,
            updates: reader.read_vec(UPDATES)?,
            current_sequence: reader.read_u64(CURRENT_SEQUENCE)?,
            content_hash: reader.read_bytes(CURRENT_HASH)?,
        })
    }
}


// ============================================================================
// TLV Encoding for Coordination Messages
// ============================================================================

mod coordination_tlv {
    pub const DISCRIMINANT: u64 = 0;
    pub const OPERATOR_ID: u64 = 2;
    pub const RESERVES_ID: u64 = 4;
    pub const AMOUNT: u64 = 6;
    pub const PAYMENT_HASH: u64 = 8;
    pub const EXPIRES: u64 = 10;
    pub const ASSIGNED_DEPOSIT: u64 = 12;
    pub const INVOICE_ID: u64 = 14;
    pub const BOLT11_INVOICE: u64 = 16;
    pub const OPERATOR_SIGNATURE: u64 = 18;
    pub const REQUESTER_PUBKEY: u64 = 20;
    pub const PROTOCOL_VERSION: u64 = 22;
    pub const TIMESTAMP: u64 = 24;
    pub const SIGNATURE: u64 = 26;
    pub const VOTE_ROUND_ID: u64 = 28;
    pub const SEQUENCE_NUMBER: u64 = 30;
    pub const STATE_HASH: u64 = 32;
    pub const CLAIMED_RESERVES: u64 = 34;
    pub const COLLATERAL_AMOUNTS: u64 = 36;
    pub const RESERVES_OUTPOINT: u64 = 38;
    pub const DESTINATION_SCRIPT: u64 = 40;
    pub const FEE_RATE_SAT_VBYTE: u64 = 42;
    pub const VOTER_PUBKEY: u64 = 44;
    pub const VOTE: u64 = 46;
    pub const VOTER_SEQUENCE: u64 = 48;
    pub const VOTER_STATE_HASH: u64 = 50;
    pub const EVIDENCE: u64 = 52;
    pub const SPEND_SIGNATURE: u64 = 54;
    // UpdateReserves fields
    pub const CHANNEL_ID: u64 = 56;
    pub const RESERVES_SATS: u64 = 58;
    pub const SCRIPT_PUBKEY: u64 = 60;
    pub const LEDGER_HASH: u64 = 62;
    pub const REMOTE_LEDGER_HASH: u64 = 64;
    // QuorumJoinRequest compensation proposal
    pub const COMPENSATION_BPS: u64 = 66;
    pub const COMPENSATION_DEPOSIT_ID: u64 = 68;
    pub const COMPENSATION_FREQUENCY_BLOCKS: u64 = 70;
}

impl TlvEncode for CoordinationMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use coordination_tlv::*;
        match self {
            Self::CosignInvoice {
                operator_id,
                reserves_id,
                amount,
                payment_hash,
                expires,
                assigned_deposit,
                invoice_id,
                bolt11_invoice,
            } => TlvBuilder::new()
                .u8_field(DISCRIMINANT, 0)
                .pubkey_field(OPERATOR_ID, operator_id)
                .string_field(RESERVES_ID, reserves_id)
                .u64_field(AMOUNT, *amount)
                .bytes_field(PAYMENT_HASH, payment_hash)
                .u64_field(EXPIRES, *expires)
                .pubkey_field(ASSIGNED_DEPOSIT, assigned_deposit)
                .string_field(INVOICE_ID, invoice_id)
                .string_field(BOLT11_INVOICE, bolt11_invoice)
                .build(),
            Self::CollateralConsentRequest {
                operator_id,
                reserves_id,
                operator_signature,
            } => TlvBuilder::new()
                .u8_field(DISCRIMINANT, 1)
                .pubkey_field(OPERATOR_ID, operator_id)
                .string_field(RESERVES_ID, reserves_id)
                .bytes_field(OPERATOR_SIGNATURE, operator_signature)
                .build(),
            Self::QuorumJoinRequest {
                requester_pubkey,
                operator_id,
                reserves_id,
                protocol_version,
                timestamp,
                signature,
                compensation_bps,
                compensation_deposit_id,
                compensation_frequency_blocks,
            } => {
                let mut b = TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 2)
                    .pubkey_field(REQUESTER_PUBKEY, requester_pubkey)
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .u16_field(PROTOCOL_VERSION, *protocol_version)
                    .u64_field(TIMESTAMP, *timestamp)
                    .bytes_field(SIGNATURE, signature);
                if let Some(v) = compensation_bps {
                    b = b.u16_field(COMPENSATION_BPS, *v);
                }
                if let Some(v) = compensation_deposit_id {
                    b = b.deposit_id_field(COMPENSATION_DEPOSIT_ID, v);
                }
                if let Some(v) = compensation_frequency_blocks {
                    b = b.u32_field(COMPENSATION_FREQUENCY_BLOCKS, *v);
                }
                b.build()
            }
            Self::QuorumVoteRequest {
                vote_round_id,
                operator_id,
                reserves_id,
                sequence_number,
                state_hash,
                claimed_reserves,
                collateral_amounts,
                reserves_outpoint,
                destination_script,
                fee_rate_sat_vbyte,
                timestamp,
            } => {
                // Encode Vec<u64> as concatenated big-endian bytes
                let collateral_bytes: Vec<u8> = collateral_amounts
                    .iter()
                    .flat_map(|v| v.to_be_bytes())
                    .collect();
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 3)
                    .bytes_field(VOTE_ROUND_ID, vote_round_id)
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .u64_field(SEQUENCE_NUMBER, *sequence_number)
                    .bytes_field(STATE_HASH, state_hash)
                    .u64_field(CLAIMED_RESERVES, *claimed_reserves)
                    .bytes_field(COLLATERAL_AMOUNTS, &collateral_bytes)
                    .bytes_field(RESERVES_OUTPOINT, reserves_outpoint)
                    .bytes_field(DESTINATION_SCRIPT, destination_script)
                    .u64_field(FEE_RATE_SAT_VBYTE, *fee_rate_sat_vbyte)
                    .u64_field(TIMESTAMP, *timestamp)
                    .build()
            }
            Self::QuorumVote {
                vote_round_id,
                voter_pubkey,
                vote,
                voter_sequence,
                voter_state_hash,
                evidence,
                signature,
                spend_signature,
            } => {
                let mut builder = TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 4)
                    .bytes_field(VOTE_ROUND_ID, vote_round_id)
                    .pubkey_field(VOTER_PUBKEY, voter_pubkey)
                    .u8_field(VOTE, if *vote { 1 } else { 0 })
                    .u64_field(VOTER_SEQUENCE, *voter_sequence)
                    .bytes_field(VOTER_STATE_HASH, voter_state_hash);
                if let Some(ev) = evidence {
                    builder = builder.bytes_field(EVIDENCE, ev);
                }
                builder = builder.bytes_field(SIGNATURE, signature);
                if let Some(spend_sig) = spend_signature {
                    builder = builder.bytes_field(SPEND_SIGNATURE, spend_sig);
                }
                builder.build()
            }
            Self::UpdateReserves {
                channel_id,
                reserves_sats,
                script_pubkey,
                ledger_hash,
                remote_ledger_hash,
            } => TlvBuilder::new()
                .u8_field(DISCRIMINANT, 5)
                .bytes_field(CHANNEL_ID, channel_id)
                .u64_field(RESERVES_SATS, *reserves_sats)
                .bytes_field(SCRIPT_PUBKEY, script_pubkey)
                .bytes_field(LEDGER_HASH, ledger_hash)
                .bytes_field(REMOTE_LEDGER_HASH, remote_ledger_hash)
                .build(),
        }
    }
}

impl TlvDecode for CoordinationMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use coordination_tlv::*;
        let reader = TlvReader::new(data)?;
        let discriminant = reader.read_u8(DISCRIMINANT)?;
        match discriminant {
            0 => Ok(Self::CosignInvoice {
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                payment_hash: reader.read_bytes(PAYMENT_HASH)?,
                expires: reader.read_u64(EXPIRES)?,
                assigned_deposit: reader.read_pubkey(ASSIGNED_DEPOSIT)?,
                invoice_id: reader.read_string(INVOICE_ID)?,
                bolt11_invoice: reader.read_string(BOLT11_INVOICE)?,
            }),
            1 => Ok(Self::CollateralConsentRequest {
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                operator_signature: reader.read_bytes(OPERATOR_SIGNATURE)?,
            }),
            2 => Ok(Self::QuorumJoinRequest {
                requester_pubkey: reader.read_pubkey(REQUESTER_PUBKEY)?,
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                protocol_version: reader.read_u16(PROTOCOL_VERSION)?,
                timestamp: reader.read_u64(TIMESTAMP)?,
                signature: reader.read_bytes(SIGNATURE)?,
                compensation_bps: reader.read_u16_opt(COMPENSATION_BPS)?,
                compensation_deposit_id: reader.read_deposit_id_opt(COMPENSATION_DEPOSIT_ID)?,
                compensation_frequency_blocks: reader.read_u32_opt(COMPENSATION_FREQUENCY_BLOCKS)?,
            }),
            3 => {
                // Decode Vec<u64> from concatenated big-endian bytes
                let collateral_raw = reader.read_raw(COLLATERAL_AMOUNTS)?;
                let collateral_amounts: Vec<u64> = collateral_raw
                    .chunks_exact(8)
                    .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
                    .collect();
                Ok(Self::QuorumVoteRequest {
                    vote_round_id: reader.read_bytes(VOTE_ROUND_ID)?,
                    operator_id: reader.read_pubkey(OPERATOR_ID)?,
                    reserves_id: reader.read_string(RESERVES_ID)?,
                    sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
                    state_hash: reader.read_bytes(STATE_HASH)?,
                    claimed_reserves: reader.read_u64(CLAIMED_RESERVES)?,
                    collateral_amounts,
                    reserves_outpoint: reader.read_raw(RESERVES_OUTPOINT)?.to_vec(),
                    destination_script: reader.read_raw(DESTINATION_SCRIPT)?.to_vec(),
                    fee_rate_sat_vbyte: reader.read_u64(FEE_RATE_SAT_VBYTE)?,
                    timestamp: reader.read_u64(TIMESTAMP)?,
                })
            }
            4 => Ok(Self::QuorumVote {
                vote_round_id: reader.read_bytes(VOTE_ROUND_ID)?,
                voter_pubkey: reader.read_pubkey(VOTER_PUBKEY)?,
                vote: reader.read_u8(VOTE)? != 0,
                voter_sequence: reader.read_u64(VOTER_SEQUENCE)?,
                voter_state_hash: reader.read_bytes(VOTER_STATE_HASH)?,
                evidence: reader.read_raw_opt(EVIDENCE).map(|b| b.to_vec()),
                signature: reader.read_bytes(SIGNATURE)?,
                spend_signature: reader.read_bytes_opt(SPEND_SIGNATURE)?,
            }),
            5 => Ok(Self::UpdateReserves {
                channel_id: reader.read_bytes(CHANNEL_ID)?,
                reserves_sats: reader.read_u64(RESERVES_SATS)?,
                script_pubkey: reader.read_raw(SCRIPT_PUBKEY)?.to_vec(),
                ledger_hash: reader.read_bytes(LEDGER_HASH)?,
                remote_ledger_hash: reader.read_bytes(REMOTE_LEDGER_HASH)?,
            }),
            d => Err(TlvError::InvalidFieldValue {
                field_type: DISCRIMINANT,
                reason: format!("unknown CoordinationMsg discriminant: {}", d),
            }),
        }
    }
}

mod coordination_response_tlv {
    pub const DISCRIMINANT: u64 = 0;
    pub const REQUEST_HASH: u64 = 2;
    pub const COSIGNATURE: u64 = 4;
    pub const OPERATOR_ID: u64 = 6;
    pub const RESERVES_ID: u64 = 8;
    pub const CONSENT_GRANTED: u64 = 10;
    pub const QUORUM_MEMBER_SIGNATURE: u64 = 12;
    pub const ACCEPTED: u64 = 14;
    pub const MEMBERS: u64 = 16;
    pub const THRESHOLD: u64 = 18;
    pub const LAST_SEQUENCE: u64 = 20;
    pub const CURRENT_STATE_HASH: u64 = 22;
    pub const REJECTION_REASON: u64 = 24;
    pub const UPDATES: u64 = 26;
    pub const START_SEQUENCE: u64 = 28;
    pub const IS_FINAL: u64 = 30;
    pub const CHANGE_TYPE: u64 = 32;
    pub const MEMBER_PUBKEY: u64 = 34;
    pub const NEW_MEMBERS: u64 = 36;
    pub const NEW_THRESHOLD: u64 = 38;
    pub const TIMESTAMP: u64 = 40;
    pub const OPERATOR_SIGNATURE: u64 = 42;
    // AcceptReserves fields
    pub const CHANNEL_ID: u64 = 44;
}

impl TlvEncode for CoordinationResponseMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use coordination_response_tlv::*;
        match self {
            Self::InvoiceCosigned {
                request_hash,
                cosignature,
            } => TlvBuilder::new()
                .u8_field(DISCRIMINANT, 0)
                .bytes_field(REQUEST_HASH, request_hash)
                .bytes_field(COSIGNATURE, cosignature)
                .build(),
            Self::CollateralConsentResponse {
                request_hash,
                operator_id,
                reserves_id,
                consent_granted,
                quorum_member_signature,
            } => TlvBuilder::new()
                .u8_field(DISCRIMINANT, 1)
                .bytes_field(REQUEST_HASH, request_hash)
                .pubkey_field(OPERATOR_ID, operator_id)
                .string_field(RESERVES_ID, reserves_id)
                .u8_field(CONSENT_GRANTED, if *consent_granted { 1 } else { 0 })
                .bytes_field(QUORUM_MEMBER_SIGNATURE, quorum_member_signature)
                .build(),
            Self::QuorumJoinResponse {
                request_hash,
                accepted,
                members,
                threshold,
                last_sequence,
                content_hash,
                rejection_reason,
            } => {
                // Encode Vec<PublicKey> as concatenated compressed pubkey bytes (33 bytes each)
                let members_bytes: Vec<u8> = members.iter().flat_map(|pk| pk.serialize()).collect();
                let mut builder = TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 2)
                    .bytes_field(REQUEST_HASH, request_hash)
                    .u8_field(ACCEPTED, if *accepted { 1 } else { 0 })
                    .bytes_field(MEMBERS, &members_bytes)
                    .u16_field(THRESHOLD, *threshold)
                    .u64_field(LAST_SEQUENCE, *last_sequence)
                    .bytes_field(CURRENT_STATE_HASH, content_hash);
                if let Some(reason) = rejection_reason {
                    builder = builder.string_field(REJECTION_REASON, reason);
                }
                builder.build()
            }
            Self::QuorumStateSync {
                request_hash,
                operator_id,
                reserves_id,
                updates,
                start_sequence,
                is_final,
            } => TlvBuilder::new()
                .u8_field(DISCRIMINANT, 3)
                .bytes_field(REQUEST_HASH, request_hash)
                .pubkey_field(OPERATOR_ID, operator_id)
                .string_field(RESERVES_ID, reserves_id)
                .vec_field(UPDATES, updates)
                .u64_field(START_SEQUENCE, *start_sequence)
                .u8_field(IS_FINAL, if *is_final { 1 } else { 0 })
                .build(),
            Self::QuorumMembershipChange {
                request_hash,
                operator_id,
                reserves_id,
                change_type,
                member_pubkey,
                new_members,
                new_threshold,
                timestamp,
                operator_signature,
            } => {
                // Encode Vec<PublicKey> as concatenated compressed pubkey bytes (33 bytes each)
                let new_members_bytes: Vec<u8> =
                    new_members.iter().flat_map(|pk| pk.serialize()).collect();
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 4)
                    .bytes_field(REQUEST_HASH, request_hash)
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .string_field(CHANGE_TYPE, change_type)
                    .pubkey_field(MEMBER_PUBKEY, member_pubkey)
                    .bytes_field(NEW_MEMBERS, &new_members_bytes)
                    .u16_field(NEW_THRESHOLD, *new_threshold)
                    .u64_field(TIMESTAMP, *timestamp)
                    .bytes_field(OPERATOR_SIGNATURE, operator_signature)
                    .build()
            }
            Self::AcceptReserves { channel_id } => TlvBuilder::new()
                .u8_field(DISCRIMINANT, 5)
                .bytes_field(CHANNEL_ID, channel_id)
                .build(),
        }
    }
}

impl TlvDecode for CoordinationResponseMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use coordination_response_tlv::*;
        let reader = TlvReader::new(data)?;
        let discriminant = reader.read_u8(DISCRIMINANT)?;
        match discriminant {
            0 => Ok(Self::InvoiceCosigned {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
                cosignature: reader.read_bytes(COSIGNATURE)?,
            }),
            1 => Ok(Self::CollateralConsentResponse {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                consent_granted: reader.read_u8(CONSENT_GRANTED)? != 0,
                quorum_member_signature: reader.read_bytes(QUORUM_MEMBER_SIGNATURE)?,
            }),
            2 => {
                // Decode Vec<PublicKey> from concatenated 33-byte compressed pubkeys
                let members_raw = reader.read_raw(MEMBERS)?;
                let members: Result<Vec<PublicKey>, _> = members_raw
                    .chunks_exact(33)
                    .map(PublicKey::from_slice)
                    .collect();
                let members = members.map_err(|e| TlvError::InvalidFieldValue {
                    field_type: MEMBERS,
                    reason: format!("invalid pubkey: {}", e),
                })?;
                Ok(Self::QuorumJoinResponse {
                    request_hash: reader.read_bytes(REQUEST_HASH)?,
                    accepted: reader.read_u8(ACCEPTED)? != 0,
                    members,
                    threshold: reader.read_u16(THRESHOLD)?,
                    last_sequence: reader.read_u64(LAST_SEQUENCE)?,
                    content_hash: reader.read_bytes(CURRENT_STATE_HASH)?,
                    rejection_reason: reader.read_string_opt(REJECTION_REASON)?,
                })
            }
            3 => Ok(Self::QuorumStateSync {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                updates: reader.read_vec(UPDATES)?,
                start_sequence: reader.read_u64(START_SEQUENCE)?,
                is_final: reader.read_u8(IS_FINAL)? != 0,
            }),
            4 => {
                // Decode Vec<PublicKey> from concatenated 33-byte compressed pubkeys
                let new_members_raw = reader.read_raw(NEW_MEMBERS)?;
                let new_members: Result<Vec<PublicKey>, _> = new_members_raw
                    .chunks_exact(33)
                    .map(PublicKey::from_slice)
                    .collect();
                let new_members = new_members.map_err(|e| TlvError::InvalidFieldValue {
                    field_type: NEW_MEMBERS,
                    reason: format!("invalid pubkey: {}", e),
                })?;
                Ok(Self::QuorumMembershipChange {
                    request_hash: reader.read_bytes(REQUEST_HASH)?,
                    operator_id: reader.read_pubkey(OPERATOR_ID)?,
                    reserves_id: reader.read_string(RESERVES_ID)?,
                    change_type: reader.read_string(CHANGE_TYPE)?,
                    member_pubkey: reader.read_pubkey(MEMBER_PUBKEY)?,
                    new_members,
                    new_threshold: reader.read_u16(NEW_THRESHOLD)?,
                    timestamp: reader.read_u64(TIMESTAMP)?,
                    operator_signature: reader.read_bytes(OPERATOR_SIGNATURE)?,
                })
            }
            5 => Ok(Self::AcceptReserves {
                channel_id: reader.read_bytes(CHANNEL_ID)?,
            }),
            d => Err(TlvError::InvalidFieldValue {
                field_type: DISCRIMINANT,
                reason: format!("unknown CoordinationResponseMsg discriminant: {}", d),
            }),
        }
    }
}

// ============================================================================
// TLV Encoding for ReservesAddOutputMsg
// ============================================================================

mod reserves_add_output_tlv {
    pub const INITIAL_AMOUNT: u64 = 0;
    pub const SPEND_TO: u64 = 2;
    pub const RESERVES_ID: u64 = 4;
    pub const QUORUM_MEMBERS: u64 = 6;
}

impl TlvEncode for crate::wire_messages::ReservesAddOutputMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use reserves_add_output_tlv::*;
        // Encode Vec<PublicKey> as concatenated compressed pubkey bytes (33 bytes each)
        let partners_bytes: Vec<u8> = self
            .quorum_members
            .iter()
            .flat_map(|pk| pk.serialize())
            .collect();
        TlvBuilder::new()
            .u64_field(INITIAL_AMOUNT, self.initial_amount)
            .pubkey_field(SPEND_TO, &self.spend_to)
            .string_field(RESERVES_ID, &self.reserves_id)
            .bytes_field(QUORUM_MEMBERS, &partners_bytes)
            .build()
    }
}

impl TlvDecode for crate::wire_messages::ReservesAddOutputMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use reserves_add_output_tlv::*;
        let reader = TlvReader::new(data)?;
        // Decode Vec<PublicKey> from concatenated 33-byte compressed pubkeys
        let partners_raw = reader.read_raw(QUORUM_MEMBERS)?;
        let quorum_members: Result<Vec<bitcoin::secp256k1::PublicKey>, _> = partners_raw
            .chunks(33)
            .map(bitcoin::secp256k1::PublicKey::from_slice)
            .collect();
        let quorum_members = quorum_members.map_err(|e| TlvError::InvalidFieldValue {
            field_type: QUORUM_MEMBERS,
            reason: format!("invalid pubkey: {}", e),
        })?;
        Ok(Self {
            initial_amount: reader.read_u64(INITIAL_AMOUNT)?,
            spend_to: reader.read_pubkey(SPEND_TO)?,
            reserves_id: reader.read_string(RESERVES_ID)?,
            quorum_members,
        })
    }
}

// ============================================================================
// TLV Encoding for ReservesRemoveOutputMsg
// ============================================================================

mod reserves_remove_output_tlv {
    pub const RESERVES_ID: u64 = 0;
    pub const REMOVE_ALL: u64 = 2;
}

impl TlvEncode for crate::wire_messages::ReservesRemoveOutputMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use reserves_remove_output_tlv::*;
        TlvBuilder::new()
            .string_field(RESERVES_ID, &self.reserves_id)
            .u8_field(REMOVE_ALL, if self.remove_all { 1 } else { 0 })
            .build()
    }
}

impl TlvDecode for crate::wire_messages::ReservesRemoveOutputMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use reserves_remove_output_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            reserves_id: reader.read_string(RESERVES_ID)?,
            remove_all: reader.read_u8(REMOVE_ALL)? != 0,
        })
    }
}

// ============================================================================
// TLV Encoding for DepositsMessage (main enum)
// ============================================================================

mod message_v2_tlv {
    pub const MESSAGE_TYPE: u64 = 0;
    pub const MESSAGE_BODY: u64 = 2;
}

impl DepositsMessage {
    /// Encode this message to TLV wire format
    pub fn tlv_encode(&self) -> Vec<u8> {
        use message_v2_tlv::*;
        let (msg_type, body) = match self {
            Self::LedgerUpdate(msg) => (LEDGER_UPDATE, msg.tlv_encode()),
            Self::LedgerUpdateResponse(msg) => (LEDGER_UPDATE_RESPONSE, msg.tlv_encode()),
            Self::Handshake(msg) => (HANDSHAKE, msg.tlv_encode()),
            Self::HandshakeResponse(msg) => (HANDSHAKE_RESPONSE, msg.tlv_encode()),
            Self::Sync(msg) => (SYNC, msg.tlv_encode()),
            Self::SyncResponse(msg) => (SYNC_RESPONSE, msg.tlv_encode()),
            Self::Coordination(msg) => (COORDINATION, msg.tlv_encode()),
            Self::CoordinationResponse(msg) => (COORDINATION_RESPONSE, msg.tlv_encode()),
            Self::ReservesAddOutput(msg) => (RESERVES_ADD_OUTPUT, msg.tlv_encode()),
            Self::ReservesRemoveOutput(msg) => (RESERVES_REMOVE_OUTPUT, msg.tlv_encode()),
        };
        TlvBuilder::new()
            .u16_field(MESSAGE_TYPE, msg_type)
            .bytes_field(MESSAGE_BODY, &body)
            .build()
    }

    /// Decode this message from TLV wire format
    pub fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use message_v2_tlv::*;
        let reader = TlvReader::new(data)?;
        let msg_type = reader.read_u16(MESSAGE_TYPE)?;
        let body = reader.read_raw(MESSAGE_BODY)?;
        match msg_type {
            LEDGER_UPDATE => Ok(Self::LedgerUpdate(LedgerUpdateMsg::tlv_decode(body)?)),
            LEDGER_UPDATE_RESPONSE => Ok(Self::LedgerUpdateResponse(
                LedgerUpdateResponseMsg::tlv_decode(body)?,
            )),
            HANDSHAKE => Ok(Self::Handshake(HandshakeMsg::tlv_decode(body)?)),
            HANDSHAKE_RESPONSE => Ok(Self::HandshakeResponse(HandshakeResponseMsg::tlv_decode(
                body,
            )?)),
            SYNC => Ok(Self::Sync(SyncMsg::tlv_decode(body)?)),
            SYNC_RESPONSE => Ok(Self::SyncResponse(SyncResponseMsg::tlv_decode(body)?)),
            COORDINATION => Ok(Self::Coordination(CoordinationMsg::tlv_decode(body)?)),
            COORDINATION_RESPONSE => Ok(Self::CoordinationResponse(
                CoordinationResponseMsg::tlv_decode(body)?,
            )),
            RESERVES_ADD_OUTPUT => Ok(Self::ReservesAddOutput(
                crate::wire_messages::ReservesAddOutputMsg::tlv_decode(body)?,
            )),
            RESERVES_REMOVE_OUTPUT => Ok(Self::ReservesRemoveOutput(
                crate::wire_messages::ReservesRemoveOutputMsg::tlv_decode(body)?,
            )),
            _ => Err(TlvError::InvalidFieldValue {
                field_type: MESSAGE_TYPE,
                reason: format!("unknown message type: 0x{:04X}", msg_type),
            }),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_message_type_constants() {
        // All message types should be odd per BOLT 1
        assert_eq!(LEDGER_UPDATE & 1, 1);
        assert_eq!(LEDGER_UPDATE_RESPONSE & 1, 1);
        assert_eq!(HANDSHAKE & 1, 1);
        assert_eq!(HANDSHAKE_RESPONSE & 1, 1);
        assert_eq!(SYNC & 1, 1);
        assert_eq!(SYNC_RESPONSE & 1, 1);
        assert_eq!(COORDINATION & 1, 1);
        assert_eq!(COORDINATION_RESPONSE & 1, 1);
    }

    #[test]
    fn test_ledger_operation_roundtrip() {
        // Test non-deposit operations that fully round-trip with BinaryCodec
        let ops = vec![LedgerOperation::FeeCollect {
            deposit_id: crate::types::compute_deposit_id("pk(test)"),
            amount: 500,
            block_height: 800000,
        }];

        for op in ops {
            let mut bytes = Vec::new();
            op.write_to(&mut bytes).unwrap();
            let decoded = LedgerOperation::read_from(&mut &bytes[..]).unwrap();
            assert_eq!(op, decoded);
        }

        // Test DepositOpen separately - BinaryCodec is a legacy format that uses 33-byte
        // legacy pubkey encoding for deposit_id and doesn't preserve the descriptor.
        // The descriptor becomes "legacy(<hex_deposit_id>)" on decode.
        let deposit_id = crate::types::compute_deposit_id("pk(test)");
        let deposit_open = LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: "pk(test)".to_string(),
            fees: Some(FeeStructure {
                annualized_msats: 1000,
                annualized_bps: 50,
                frequency_blocks: 144,
            }),
            transfer_fees: None,
            payment_hash: Some([0xAB; 32]),
            invoice: Some("lnbc...".to_string()),
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        };

        let mut bytes = Vec::new();
        deposit_open.write_to(&mut bytes).unwrap();
        let decoded = LedgerOperation::read_from(&mut &bytes[..]).unwrap();

        // Verify deposit_id is preserved, descriptor becomes legacy format
        if let LedgerOperation::DepositOpen {
            deposit_id: decoded_id,
            descriptor,
            ..
        } = decoded
        {
            assert_eq!(decoded_id, deposit_id);
            assert_eq!(descriptor, format!("legacy({})", hex::encode(deposit_id)));
        } else {
            panic!("Expected DepositOpen");
        }
    }

    #[test]
    fn test_ledger_update_message_roundtrip() {
        let msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg {
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            operation: LedgerOperation::FeeCollect {
                deposit_id: crate::types::compute_deposit_id("pk(test)"),
                amount: 500,
                block_height: 800000,
            },
            sequence_number: 1,
            previous_hash: [0u8; 32],
            content_hash: [0xAB; 32],
            operator_signature: [0xCD; 64],
        });

        let encoded = msg.encode();
        let decoded = DepositsMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
        assert_eq!(decoded.message_type(), LEDGER_UPDATE);
    }

    #[test]
    fn test_handshake_roundtrip() {
        let msg = DepositsMessage::Handshake(HandshakeMsg {
            protocol_version: PROTOCOL_VERSION,
            min_protocol_version: MIN_PROTOCOL_VERSION,
            features: 0,
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            funding_txid: [0x11; 32],
            funding_vout: 0,
        });

        let encoded = msg.encode();
        let decoded = DepositsMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_coordination_message_roundtrip() {
        let msg = DepositsMessage::Coordination(CoordinationMsg::CosignInvoice {
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            amount: 50000,
            payment_hash: [0x11; 32],
            expires: 1234567890,
            assigned_deposit: test_pubkey(),
            invoice_id: "inv123".to_string(),
            bolt11_invoice: "lnbc...".to_string(),
        });

        let encoded = msg.encode();
        let decoded = DepositsMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_all_message_types_are_odd() {
        // Per BOLT 1: odd types MAY be ignored if not understood
        let types = [
            LEDGER_UPDATE,
            LEDGER_UPDATE_RESPONSE,
            HANDSHAKE,
            HANDSHAKE_RESPONSE,
            SYNC,
            SYNC_RESPONSE,
            COORDINATION,
            COORDINATION_RESPONSE,
        ];
        for t in types {
            assert!(t & 1 == 1, "Message type 0x{:04X} is not odd", t);
        }
    }

    // ========================================================================
    // TLV Roundtrip Tests
    // ========================================================================

    #[test]
    fn test_ledger_operation_tlv_roundtrip() {
        use crate::tlv::{TlvDecode, TlvEncode};

        let ops = vec![
            LedgerOperation::DepositOpen {
                deposit_id: crate::types::compute_deposit_id("pk(test)"),
                descriptor: "pk(test)".to_string(),
                fees: Some(FeeStructure::new(100, 10, 144)),
                transfer_fees: None,
                payment_hash: Some([0xAA; 32]),
                invoice: Some("lnbc...".to_string()),
                cosigner_guarantee_signature: None,
                receive_requires_sig: false,
                fee_change_after_blocks: Some(52560),
                fee_change_notice_blocks: Some(2016),
                fee_change_limit_bps: Some(1000),
            },
            LedgerOperation::DepositClose {
                deposit_id: crate::types::compute_deposit_id("pk(test)"),
            },
            LedgerOperation::InvoiceCredit {
                payment_hash: [0xBB; 32],
                deposit_id: crate::types::compute_deposit_id("pk(test)"),
                amount: 50000,
                invoice_id: "inv123".to_string(),
                sequence_number: 1,
            },
            LedgerOperation::LedgerClose,
        ];

        for op in ops {
            let encoded = op.tlv_encode();
            let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();
            assert_eq!(op, decoded, "TLV roundtrip failed for {:?}", op);
        }
    }

    #[test]
    fn test_ledger_update_msg_tlv_roundtrip() {
        use crate::tlv::{TlvDecode, TlvEncode};

        let msg = LedgerUpdateMsg {
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            operation: LedgerOperation::FeeCollect {
                deposit_id: crate::types::compute_deposit_id("pk(test)"),
                amount: 500,
                block_height: 800000,
            },
            sequence_number: 1,
            previous_hash: [0u8; 32],
            content_hash: [0xAB; 32],
            operator_signature: [0xCD; 64],
        };

        let encoded = msg.tlv_encode();
        let decoded = LedgerUpdateMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_ledger_update_response_msg_tlv_roundtrip() {
        use crate::tlv::{TlvDecode, TlvEncode};

        let msg = LedgerUpdateResponseMsg {
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            request_hash: [0xAA; 32],
            accepted: true,
            error: None,
            cosign_signature: Some([0xBB; 64]),
            confirmed_sequence: 5,
            confirmed_hash: [0xCC; 32],
        };

        let encoded = msg.tlv_encode();
        let decoded = LedgerUpdateResponseMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_handshake_msg_tlv_roundtrip() {
        use crate::tlv::{TlvDecode, TlvEncode};

        let msg = HandshakeMsg {
            protocol_version: PROTOCOL_VERSION,
            min_protocol_version: MIN_PROTOCOL_VERSION,
            features: 0,
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            funding_txid: [0x11; 32],
            funding_vout: 0,
        };

        let encoded = msg.tlv_encode();
        let decoded = HandshakeMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_handshake_response_msg_tlv_roundtrip() {
        use crate::tlv::{TlvDecode, TlvEncode};

        let msg = HandshakeResponseMsg {
            request_hash: [0xAA; 32],
            protocol_version: PROTOCOL_VERSION,
            accepted: true,
            error: None,
            reserves_id: test_pubkey().to_string(),
        };

        let encoded = msg.tlv_encode();
        let decoded = HandshakeResponseMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_sync_msg_tlv_roundtrip() {
        use crate::tlv::{TlvDecode, TlvEncode};

        let msg = SyncMsg {
            ledger_id: [0x12; 32],
            last_known_sequence: 5,
            last_known_hash: [0xAA; 32],
        };

        let encoded = msg.tlv_encode();
        let decoded = SyncMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_sync_response_msg_tlv_roundtrip() {
        use crate::tlv::{TlvDecode, TlvEncode};

        let mut update = SignedLedgerUpdate {
            // Valid TLV: tag=0 (discriminant), len=1, value=60 (LedgerClose)
            message: vec![0x00, 0x01, 60],
            message_type: LEDGER_CLOSE,
            operator_id: test_pubkey(),
            ledger_id: [0x12; 32],
            sequence_number: 1,
            previous_hash: [0xCC; 32],
            content_hash: [0u8; 32], // will be computed
            block_height: 12345,
            block_hash: [0x11; 32],
            cosign_signature: [0xFF; 64],
            operator_signature: [0xEE; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
        };
        update.content_hash = update.compute_hash();

        let msg = SyncResponseMsg {
            ledger_id: [0x12; 32],
            request_hash: [0xAA; 32],
            updates: vec![update],
            current_sequence: 10,
            content_hash: [0xBB; 32],
        };

        let encoded = msg.tlv_encode();
        let decoded = SyncResponseMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_coordination_msg_tlv_roundtrip() {
        use crate::tlv::{TlvDecode, TlvEncode};

        let msgs = vec![
            CoordinationMsg::CosignInvoice {
                operator_id: test_pubkey(),
                reserves_id: test_pubkey().to_string(),
                amount: 100000,
                payment_hash: [0xAA; 32],
                expires: 1234567890,
                assigned_deposit: test_pubkey(),
                invoice_id: "inv123".to_string(),
                bolt11_invoice: "lnbc100...".to_string(),
            },
            CoordinationMsg::CollateralConsentRequest {
                operator_id: test_pubkey(),
                reserves_id: test_pubkey().to_string(),
                operator_signature: [0xBB; 64],
            },
            CoordinationMsg::QuorumVoteRequest {
                vote_round_id: [0xCC; 32],
                operator_id: test_pubkey(),
                reserves_id: test_pubkey().to_string(),
                sequence_number: 50,
                state_hash: [0xDD; 32],
                claimed_reserves: 500000,
                collateral_amounts: vec![100000, 200000, 150000],
                reserves_outpoint: vec![0xEE; 36],
                destination_script: vec![0xFF; 25],
                fee_rate_sat_vbyte: 5,
                timestamp: 1234567890,
            },
        ];

        for msg in msgs {
            let encoded = msg.tlv_encode();
            let decoded = CoordinationMsg::tlv_decode(&encoded).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_coordination_response_msg_tlv_roundtrip() {
        use crate::tlv::{TlvDecode, TlvEncode};

        let msgs = vec![
            CoordinationResponseMsg::InvoiceCosigned {
                request_hash: [0xAA; 32],
                cosignature: [0xBB; 64],
            },
            CoordinationResponseMsg::QuorumJoinResponse {
                request_hash: [0xCC; 32],
                accepted: true,
                members: vec![test_pubkey(), test_pubkey()],
                threshold: 2,
                last_sequence: 100,
                content_hash: [0xDD; 32],
                rejection_reason: None,
            },
        ];

        for msg in msgs {
            let encoded = msg.tlv_encode();
            let decoded = CoordinationResponseMsg::tlv_decode(&encoded).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_deposits_message_v2_tlv_roundtrip() {
        let messages = vec![
            DepositsMessage::LedgerUpdate(LedgerUpdateMsg {
                operator_id: test_pubkey(),
                reserves_id: test_pubkey().to_string(),
                operation: LedgerOperation::InvoiceCredit {
                    payment_hash: [0xAA; 32],
                    deposit_id: crate::types::compute_deposit_id("pk(test)"),
                    amount: 100000,
                    invoice_id: "inv123".to_string(),
                    sequence_number: 1,
                },
                sequence_number: 1,
                previous_hash: [0xBB; 32],
                content_hash: [0xCC; 32],
                operator_signature: [0xDD; 64],
            }),
            DepositsMessage::Handshake(HandshakeMsg {
                protocol_version: PROTOCOL_VERSION,
                min_protocol_version: 1,
                features: 0,
                operator_id: test_pubkey(),
                reserves_id: test_pubkey().to_string(),
                funding_txid: [0xEE; 32],
                funding_vout: 0,
            }),
            DepositsMessage::Sync(SyncMsg {
                ledger_id: [0x12; 32],
                last_known_sequence: 5,
                last_known_hash: [0xFF; 32],
            }),
        ];

        for msg in messages {
            let encoded = msg.tlv_encode();
            let decoded = DepositsMessage::tlv_decode(&encoded).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_transfer_lock_wire_roundtrip() {
        let source_id = crate::types::compute_deposit_id("pk(alice)");
        let dest_id = crate::types::compute_deposit_id("pk(bob)");

        let op = LedgerOperation::TransferLock {
            nonce: [0x42u8; 32],
            source_deposit_id: source_id,
            destination_deposit_id: dest_id,
            amount: 100_000,
            fee: 1_000,
            completion_script:
                "sha256(deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567)"
                    .to_string(),
            timeout_height: 850_000,
            transfer_id: [0xABu8; 32],
            witness: DescriptorWitness {
                stack: vec![[0x11u8; 64].to_vec()],
            },
        };

        let mut bytes = Vec::new();
        op.write_to(&mut bytes).unwrap();
        let decoded = LedgerOperation::read_from(&mut &bytes[..]).unwrap();

        // Wire encoding preserves source and dest deposit IDs
        if let LedgerOperation::TransferLock {
            nonce,
            source_deposit_id,
            destination_deposit_id,
            amount,
            fee,
            completion_script,
            timeout_height,
            transfer_id,
            witness,
        } = decoded
        {
            assert_eq!(nonce, [0x42u8; 32]);
            assert_eq!(source_deposit_id, source_id);
            assert_eq!(destination_deposit_id, dest_id);
            assert_eq!(amount, 100_000);
            assert_eq!(fee, 1_000);
            assert_eq!(
                completion_script,
                "sha256(deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567)"
            );
            assert_eq!(timeout_height, 850_000);
            assert_eq!(transfer_id, [0xABu8; 32]);
            assert_eq!(witness.stack.len(), 1);
            assert_eq!(witness.stack[0].len(), 64);
        } else {
            panic!("Expected TransferLock");
        }
    }

    #[test]
    fn test_transfer_complete_wire_roundtrip() {
        let op = LedgerOperation::TransferComplete {
            transfer_id: [0xCDu8; 32],
            script_witness: DescriptorWitness {
                stack: vec![
                    [0x11u8; 32].to_vec(), // preimage
                ],
            },
        };

        let mut bytes = Vec::new();
        op.write_to(&mut bytes).unwrap();
        let decoded = LedgerOperation::read_from(&mut &bytes[..]).unwrap();

        if let LedgerOperation::TransferComplete {
            transfer_id,
            script_witness,
        } = decoded
        {
            assert_eq!(transfer_id, [0xCDu8; 32]);
            assert_eq!(script_witness.stack.len(), 1);
            assert_eq!(script_witness.stack[0], [0x11u8; 32].to_vec());
        } else {
            panic!("Expected TransferComplete");
        }
    }

    #[test]
    fn test_transfer_fail_wire_roundtrip() {
        let op = LedgerOperation::TransferFail {
            transfer_id: [0xEFu8; 32],
            block_hash: [0x99u8; 32],
            reason: 1,
        };

        let mut bytes = Vec::new();
        op.write_to(&mut bytes).unwrap();
        let decoded = LedgerOperation::read_from(&mut &bytes[..]).unwrap();

        assert_eq!(op, decoded);
    }

    #[test]
    fn test_transfer_lock_tlv_roundtrip() {
        let source_id = crate::types::compute_deposit_id("pk(source_key)");
        let dest_id = crate::types::compute_deposit_id("pk(dest_key)");

        let op = LedgerOperation::TransferLock {
            nonce: [0x55u8; 32],
            source_deposit_id: source_id,
            destination_deposit_id: dest_id,
            amount: 250_000,
            fee: 2_500,
            completion_script: "sha256(cafebabe)".to_string(),
            timeout_height: 900_000,
            transfer_id: [0x77u8; 32],
            witness: DescriptorWitness {
                stack: vec![[0x88u8; 64].to_vec()],
            },
        };

        let encoded = op.tlv_encode();
        let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

        if let LedgerOperation::TransferLock {
            nonce,
            source_deposit_id,
            destination_deposit_id,
            amount,
            fee,
            completion_script,
            timeout_height,
            transfer_id,
            witness,
        } = decoded
        {
            assert_eq!(nonce, [0x55u8; 32]);
            assert_eq!(source_deposit_id, source_id);
            assert_eq!(destination_deposit_id, dest_id);
            assert_eq!(amount, 250_000);
            assert_eq!(fee, 2_500);
            assert_eq!(completion_script, "sha256(cafebabe)");
            assert_eq!(timeout_height, 900_000);
            assert_eq!(transfer_id, [0x77u8; 32]);
            assert_eq!(witness.stack.len(), 1);
        } else {
            panic!("Expected TransferLock");
        }
    }

    #[test]
    fn test_transfer_complete_tlv_roundtrip() {
        let op = LedgerOperation::TransferComplete {
            transfer_id: [0xAAu8; 32],
            script_witness: DescriptorWitness {
                stack: vec![
                    vec![1, 2, 3, 4], // arbitrary witness data
                    vec![5, 6, 7, 8],
                ],
            },
        };

        let encoded = op.tlv_encode();
        let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

        if let LedgerOperation::TransferComplete {
            transfer_id,
            script_witness,
        } = decoded
        {
            assert_eq!(transfer_id, [0xAAu8; 32]);
            assert_eq!(script_witness.stack.len(), 2);
            assert_eq!(script_witness.stack[0], vec![1, 2, 3, 4]);
            assert_eq!(script_witness.stack[1], vec![5, 6, 7, 8]);
        } else {
            panic!("Expected TransferComplete");
        }
    }

    #[test]
    fn test_transfer_fail_tlv_roundtrip() {
        let op = LedgerOperation::TransferFail {
            transfer_id: [0xBBu8; 32],
            block_hash: [0xCCu8; 32],
            reason: 1,
        };

        let encoded = op.tlv_encode();
        let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

        assert_eq!(op, decoded);
    }

    #[test]
    fn test_transfer_discriminants() {
        let source_id = crate::types::compute_deposit_id("pk(test)");
        let dest_id = crate::types::compute_deposit_id("pk(test2)");

        let lock = LedgerOperation::TransferLock {
            nonce: [0u8; 32],
            source_deposit_id: source_id,
            destination_deposit_id: dest_id,
            amount: 1000,
            fee: 10,
            completion_script: "sha256(00)".to_string(),
            timeout_height: 100,
            transfer_id: [0u8; 32],
            witness: DescriptorWitness { stack: vec![] },
        };

        let complete = LedgerOperation::TransferComplete {
            transfer_id: [0u8; 32],
            script_witness: DescriptorWitness { stack: vec![] },
        };

        let timeout = LedgerOperation::TransferFail {
            transfer_id: [0u8; 32],
            block_hash: [0u8; 32],
            reason: 1,
        };

        assert_eq!(lock.discriminant(), 70);
        assert_eq!(complete.discriminant(), 71);
        assert_eq!(timeout.discriminant(), 72);
    }
}
