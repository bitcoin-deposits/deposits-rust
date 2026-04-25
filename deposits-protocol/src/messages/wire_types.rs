use super::types::*;
use super::*;

// ============================================================================
// Handshake Messages (0x8005 / 0x8007)
// ============================================================================

/// Protocol handshake to establish a ledger connection
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeMsg {
    /// Protocol version
    pub protocol_version: u16,
    /// Minimum supported version
    pub min_protocol_version: u16,
    /// Feature flags
    pub features: u32,
    /// Operator's public key
    pub operator_id: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK)
    pub reserves_id: String,
    /// Funding transaction ID (reserves UTXO)
    pub funding_txid: [u8; 32],
    /// Funding output index
    pub funding_vout: u16,
}

/// Response to handshake
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeResponseMsg {
    /// Hash of the request being responded to
    pub request_hash: [u8; 32],
    /// Negotiated protocol version
    pub protocol_version: u16,
    /// Whether handshake was accepted
    pub accepted: bool,
    /// Error reason if rejected
    pub error: Option<String>,
    /// Reserves identifier
    pub reserves_id: String,
}

// ============================================================================
// Sync Messages (0x8009 / 0x800B)
// ============================================================================

/// Request to synchronize ledger state
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncMsg {
    pub ledger_id: [u8; 32],
    pub last_known_sequence: u64,
    pub last_known_hash: [u8; 32],
}

/// Response with missing updates
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncResponseMsg {
    pub ledger_id: [u8; 32],
    pub request_hash: [u8; 32],
    /// Signed updates since last_known_sequence
    pub updates: Vec<SignedLedgerUpdate>,
    pub current_sequence: u64,
    pub content_hash: [u8; 32],
}

// ============================================================================
// Coordination Messages (0x8011 / 0x8013)
// ============================================================================

/// Coordination messages for non-ledger-modifying operations
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoordinationMsg {
    /// Request partner to cosign an invoice
    CosignInvoice {
        operator_id: PublicKey,
        reserves_id: String,
        /// Invoice details for cosigning
        amount: u64,
        payment_hash: [u8; 32],
        expires: u64,
        assigned_deposit: PublicKey,
        invoice_id: String,
        bolt11_invoice: String,
    },
    /// Request consent for collateral registration
    CollateralConsentRequest {
        operator_id: PublicKey,
        reserves_id: String,
        operator_signature: [u8; 64],
    },
    /// Quorum join request.
    ///
    /// `compensation_*` fields are the member's *proposal* for co-signing
    /// compensation — the operator either accepts (echoing them back on
    /// the on-ledger QuorumAddMember) or rejects the request. See
    /// `DEFAULT_COMPENSATION_BPS`.
    QuorumJoinRequest {
        requester_pubkey: PublicKey,
        operator_id: PublicKey,
        reserves_id: String,
        protocol_version: u16,
        timestamp: u64,
        signature: [u8; 64],
        compensation_bps: Option<u16>,
        compensation_deposit_id: Option<[u8; 16]>,
        compensation_frequency_blocks: Option<u32>,
    },
    /// Quorum vote request
    QuorumVoteRequest {
        vote_round_id: [u8; 32],
        operator_id: PublicKey,
        reserves_id: String,
        sequence_number: u64,
        state_hash: [u8; 32],
        claimed_reserves: u64,
        collateral_amounts: Vec<u64>,
        reserves_outpoint: Vec<u8>,
        destination_script: Vec<u8>,
        fee_rate_sat_vbyte: u64,
        timestamp: u64,
    },
    /// Quorum vote submission
    QuorumVote {
        vote_round_id: [u8; 32],
        voter_pubkey: PublicKey,
        vote: bool,
        voter_sequence: u64,
        voter_state_hash: [u8; 32],
        evidence: Option<Vec<u8>>,
        signature: [u8; 64],
        spend_signature: Option<[u8; 64]>,
    },
    /// Propose extra outputs for reserves commitment
    UpdateReserves {
        channel_id: [u8; 32],
        reserves_sats: u64,
        script_pubkey: Vec<u8>,
        ledger_hash: [u8; 32],
        remote_ledger_hash: [u8; 32],
    },
}

impl CoordinationMsg {
    pub fn reserves_id(&self) -> Option<String> {
        match self {
            Self::CosignInvoice { reserves_id, .. } => Some(reserves_id.clone()),
            Self::CollateralConsentRequest { reserves_id, .. } => Some(reserves_id.clone()),
            Self::QuorumJoinRequest { reserves_id, .. } => Some(reserves_id.clone()),
            Self::QuorumVoteRequest { reserves_id, .. } => Some(reserves_id.clone()),
            Self::QuorumVote { .. } => None,
            Self::UpdateReserves { .. } => None, // Channel-level, not ledger-level
        }
    }
}

/// Response to coordination messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoordinationResponseMsg {
    /// Invoice cosigned
    InvoiceCosigned {
        request_hash: [u8; 32],
        cosignature: [u8; 64],
    },
    /// Collateral consent granted/denied
    CollateralConsentResponse {
        request_hash: [u8; 32],
        operator_id: PublicKey,
        reserves_id: String,
        consent_granted: bool,
        quorum_member_signature: [u8; 64],
    },
    /// Quorum join accepted/rejected
    QuorumJoinResponse {
        request_hash: [u8; 32],
        accepted: bool,
        members: Vec<PublicKey>,
        threshold: u16,
        last_sequence: u64,
        content_hash: [u8; 32],
        rejection_reason: Option<String>,
    },
    /// Quorum state sync
    QuorumStateSync {
        request_hash: [u8; 32],
        operator_id: PublicKey,
        reserves_id: String,
        updates: Vec<SignedLedgerUpdate>,
        start_sequence: u64,
        is_final: bool,
    },
    /// Quorum membership change announcement
    QuorumMembershipChange {
        request_hash: [u8; 32],
        operator_id: PublicKey,
        reserves_id: String,
        change_type: String,
        member_pubkey: PublicKey,
        new_members: Vec<PublicKey>,
        new_threshold: u16,
        timestamp: u64,
        operator_signature: [u8; 64],
    },
    /// Accept proposed reserves commitment
    AcceptReserves { channel_id: [u8; 32] },
}

impl CoordinationResponseMsg {
    pub fn reserves_id(&self) -> Option<String> {
        match self {
            Self::InvoiceCosigned { .. } => None,
            Self::CollateralConsentResponse { reserves_id, .. } => Some(reserves_id.clone()),
            Self::QuorumJoinResponse { .. } => None,
            Self::QuorumStateSync { reserves_id, .. } => Some(reserves_id.clone()),
            Self::QuorumMembershipChange { reserves_id, .. } => Some(reserves_id.clone()),
            Self::AcceptReserves { .. } => None, // Channel-level, not ledger-level
        }
    }
}

// Implement write_payload and read_payload for DepositsMessage
impl DepositsMessage {
    pub(super) fn write_payload<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        match self {
            Self::LedgerUpdate(m) => {
                write_pubkey(w, &m.operator_id)?;
                write_string(w, &m.reserves_id)?;
                m.operation.write_to(w)?;
                write_u64(w, m.sequence_number)?;
                write_32(w, &m.previous_hash)?;
                write_32(w, &m.content_hash)?;
                write_64(w, &m.operator_signature)?;
            }
            Self::LedgerUpdateResponse(m) => {
                write_pubkey(w, &m.operator_id)?;
                write_string(w, &m.reserves_id)?;
                write_32(w, &m.request_hash)?;
                write_bool(w, m.accepted)?;
                write_option(w, &m.error, |w, s| write_string(w, s))?;
                write_option(w, &m.cosign_signature, |w, s| write_64(w, s))?;
                write_u64(w, m.confirmed_sequence)?;
                write_32(w, &m.confirmed_hash)?;
            }
            Self::Handshake(m) => {
                write_u16(w, m.protocol_version)?;
                write_u16(w, m.min_protocol_version)?;
                write_u32(w, m.features)?;
                write_pubkey(w, &m.operator_id)?;
                write_string(w, &m.reserves_id)?;
                write_32(w, &m.funding_txid)?;
                write_u16(w, m.funding_vout)?;
                write_u32(w, 0)?; // reserved (was collateral_enforcement_block)
            }
            Self::HandshakeResponse(m) => {
                write_32(w, &m.request_hash)?;
                write_u16(w, m.protocol_version)?;
                write_bool(w, m.accepted)?;
                write_option(w, &m.error, |w, s| write_string(w, s))?;
                write_string(w, &m.reserves_id)?;
            }
            Self::Sync(m) => {
                write_32(w, &m.ledger_id)?;
                write_u64(w, m.last_known_sequence)?;
                write_32(w, &m.last_known_hash)?;
            }
            Self::SyncResponse(m) => {
                write_32(w, &m.ledger_id)?;
                write_32(w, &m.request_hash)?;
                write_vec(w, &m.updates, |w, u| u.write_to(w))?;
                write_u64(w, m.current_sequence)?;
                write_32(w, &m.content_hash)?;
            }
            Self::Coordination(m) => m.write_to(w)?,
            Self::CoordinationResponse(m) => m.write_to(w)?,
            Self::ReservesAddOutput(m) => {
                write_u64(w, m.initial_amount)?;
                write_pubkey(w, &m.spend_to)?;
                write_string(w, &m.reserves_id)?;
                write_u16(w, m.quorum_members.len() as u16)?;
                for pk in &m.quorum_members {
                    write_pubkey(w, pk)?;
                }
            }
            Self::ReservesRemoveOutput(m) => {
                write_string(w, &m.reserves_id)?;
                write_bool(w, m.remove_all)?;
            }
        }
        Ok(())
    }

    pub(super) fn read_payload<R: Read>(message_type: u16, r: &mut R) -> Result<Self, CodecError> {
        match message_type {
            LEDGER_UPDATE => Ok(Self::LedgerUpdate(LedgerUpdateMsg {
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                operation: LedgerOperation::read_from(r)?,
                sequence_number: read_u64(r)?,
                previous_hash: read_32(r)?,
                content_hash: read_32(r)?,
                operator_signature: read_64(r)?,
            })),
            LEDGER_UPDATE_RESPONSE => Ok(Self::LedgerUpdateResponse(LedgerUpdateResponseMsg {
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                request_hash: read_32(r)?,
                accepted: read_bool(r)?,
                error: read_option(r, read_string)?,
                cosign_signature: read_option(r, read_64)?,
                confirmed_sequence: read_u64(r)?,
                confirmed_hash: read_32(r)?,
            })),
            HANDSHAKE => {
                let protocol_version = read_u16(r)?;
                let min_protocol_version = read_u16(r)?;
                let features = read_u32(r)?;
                let operator_id = read_pubkey(r)?;
                let reserves_id = read_string(r)?;
                let funding_txid = read_32(r)?;
                let funding_vout = read_u16(r)?;
                let _reserved = read_u32(r)?; // was collateral_enforcement_block
                Ok(Self::Handshake(HandshakeMsg {
                    protocol_version,
                    min_protocol_version,
                    features,
                    operator_id,
                    reserves_id,
                    funding_txid,
                    funding_vout,
                }))
            }
            HANDSHAKE_RESPONSE => Ok(Self::HandshakeResponse(HandshakeResponseMsg {
                request_hash: read_32(r)?,
                protocol_version: read_u16(r)?,
                accepted: read_bool(r)?,
                error: read_option(r, read_string)?,
                reserves_id: read_string(r)?,
            })),
            SYNC => Ok(Self::Sync(SyncMsg {
                ledger_id: read_32(r)?,
                last_known_sequence: read_u64(r)?,
                last_known_hash: read_32(r)?,
            })),
            SYNC_RESPONSE => Ok(Self::SyncResponse(SyncResponseMsg {
                ledger_id: read_32(r)?,
                request_hash: read_32(r)?,
                updates: read_vec(r, SignedLedgerUpdate::read_from)?,
                current_sequence: read_u64(r)?,
                content_hash: read_32(r)?,
            })),
            COORDINATION => Ok(Self::Coordination(CoordinationMsg::read_from(r)?)),
            COORDINATION_RESPONSE => Ok(Self::CoordinationResponse(
                CoordinationResponseMsg::read_from(r)?,
            )),
            RESERVES_ADD_OUTPUT => {
                let initial_amount = read_u64(r)?;
                let spend_to = read_pubkey(r)?;
                let reserves_id = read_string(r)?;
                let count = read_u16(r)? as usize;
                let mut quorum_members = Vec::with_capacity(count);
                for _ in 0..count {
                    quorum_members.push(read_pubkey(r)?);
                }
                Ok(Self::ReservesAddOutput(
                    crate::wire_messages::ReservesAddOutputMsg {
                        initial_amount,
                        spend_to,
                        reserves_id,
                        quorum_members,
                    },
                ))
            }
            RESERVES_REMOVE_OUTPUT => {
                let reserves_id = read_string(r)?;
                let remove_all = read_bool(r)?;
                Ok(Self::ReservesRemoveOutput(
                    crate::wire_messages::ReservesRemoveOutputMsg {
                        reserves_id,
                        remove_all,
                    },
                ))
            }
            _ => Err(CodecError::InvalidMessageType(message_type)),
        }
    }
}


// CoordinationMsg codec
impl BinaryCodec for CoordinationMsg {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
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
            } => {
                write_u8(w, 0)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_u64(w, *amount)?;
                write_32(w, payment_hash)?;
                write_u64(w, *expires)?;
                write_pubkey(w, assigned_deposit)?;
                write_string(w, invoice_id)?;
                write_string(w, bolt11_invoice)?;
            }
            Self::CollateralConsentRequest {
                operator_id,
                reserves_id,
                operator_signature,
            } => {
                write_u8(w, 1)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_64(w, operator_signature)?;
            }
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
                write_u8(w, 2)?;
                write_pubkey(w, requester_pubkey)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_u16(w, *protocol_version)?;
                write_u64(w, *timestamp)?;
                write_64(w, signature)?;
                write_option(w, compensation_bps, |w, v| write_u16(w, *v))?;
                write_option(w, compensation_deposit_id, |w, v| write_16(w, v))?;
                write_option(w, compensation_frequency_blocks, |w, v| write_u32(w, *v))?;
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
                write_u8(w, 3)?;
                write_32(w, vote_round_id)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_u64(w, *sequence_number)?;
                write_32(w, state_hash)?;
                write_u64(w, *claimed_reserves)?;
                write_vec(w, collateral_amounts, |w, a| write_u64(w, *a))?;
                write_bytes(w, reserves_outpoint)?;
                write_bytes(w, destination_script)?;
                write_u64(w, *fee_rate_sat_vbyte)?;
                write_u64(w, *timestamp)?;
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
                write_u8(w, 4)?;
                write_32(w, vote_round_id)?;
                write_pubkey(w, voter_pubkey)?;
                write_bool(w, *vote)?;
                write_u64(w, *voter_sequence)?;
                write_32(w, voter_state_hash)?;
                write_option(w, evidence, |w, e| write_bytes(w, e))?;
                write_64(w, signature)?;
                write_option(w, spend_signature, |w, s| write_64(w, s))?;
            }
            Self::UpdateReserves {
                channel_id,
                reserves_sats,
                script_pubkey,
                ledger_hash,
                remote_ledger_hash,
            } => {
                write_u8(w, 5)?;
                write_32(w, channel_id)?;
                write_u64(w, *reserves_sats)?;
                write_bytes(w, script_pubkey)?;
                write_32(w, ledger_hash)?;
                write_32(w, remote_ledger_hash)?;
            }
        }
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        match read_u8(r)? {
            0 => Ok(Self::CosignInvoice {
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                amount: read_u64(r)?,
                payment_hash: read_32(r)?,
                expires: read_u64(r)?,
                assigned_deposit: read_pubkey(r)?,
                invoice_id: read_string(r)?,
                bolt11_invoice: read_string(r)?,
            }),
            1 => Ok(Self::CollateralConsentRequest {
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                operator_signature: read_64(r)?,
            }),
            2 => Ok(Self::QuorumJoinRequest {
                requester_pubkey: read_pubkey(r)?,
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                protocol_version: read_u16(r)?,
                timestamp: read_u64(r)?,
                signature: read_64(r)?,
                compensation_bps: read_option(r, read_u16)?,
                compensation_deposit_id: read_option(r, read_16)?,
                compensation_frequency_blocks: read_option(r, read_u32)?,
            }),
            3 => Ok(Self::QuorumVoteRequest {
                vote_round_id: read_32(r)?,
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                sequence_number: read_u64(r)?,
                state_hash: read_32(r)?,
                claimed_reserves: read_u64(r)?,
                collateral_amounts: read_vec(r, read_u64)?,
                reserves_outpoint: read_bytes(r)?,
                destination_script: read_bytes(r)?,
                fee_rate_sat_vbyte: read_u64(r)?,
                timestamp: read_u64(r)?,
            }),
            4 => Ok(Self::QuorumVote {
                vote_round_id: read_32(r)?,
                voter_pubkey: read_pubkey(r)?,
                vote: read_bool(r)?,
                voter_sequence: read_u64(r)?,
                voter_state_hash: read_32(r)?,
                evidence: read_option(r, read_bytes)?,
                signature: read_64(r)?,
                spend_signature: read_option(r, read_64)?,
            }),
            5 => Ok(Self::UpdateReserves {
                channel_id: read_32(r)?,
                reserves_sats: read_u64(r)?,
                script_pubkey: read_bytes(r)?,
                ledger_hash: read_32(r)?,
                remote_ledger_hash: read_32(r)?,
            }),
            d => Err(CodecError::InvalidDiscriminant(d)),
        }
    }
}

// CoordinationResponseMsg codec
impl BinaryCodec for CoordinationResponseMsg {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        match self {
            Self::InvoiceCosigned {
                request_hash,
                cosignature,
            } => {
                write_u8(w, 0)?;
                write_32(w, request_hash)?;
                write_64(w, cosignature)?;
            }
            Self::CollateralConsentResponse {
                request_hash,
                operator_id,
                reserves_id,
                consent_granted,
                quorum_member_signature,
            } => {
                write_u8(w, 1)?;
                write_32(w, request_hash)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_bool(w, *consent_granted)?;
                write_64(w, quorum_member_signature)?;
            }
            Self::QuorumJoinResponse {
                request_hash,
                accepted,
                members,
                threshold,
                last_sequence,
                content_hash,
                rejection_reason,
            } => {
                write_u8(w, 2)?;
                write_32(w, request_hash)?;
                write_bool(w, *accepted)?;
                write_vec(w, members, |w, pk| write_pubkey(w, pk))?;
                write_u16(w, *threshold)?;
                write_u64(w, *last_sequence)?;
                write_32(w, content_hash)?;
                write_option(w, rejection_reason, |w, s| write_string(w, s))?;
            }
            Self::QuorumStateSync {
                request_hash,
                operator_id,
                reserves_id,
                updates,
                start_sequence,
                is_final,
            } => {
                write_u8(w, 3)?;
                write_32(w, request_hash)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_vec(w, updates, |w, u| u.write_to(w))?;
                write_u64(w, *start_sequence)?;
                write_bool(w, *is_final)?;
            }
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
                write_u8(w, 4)?;
                write_32(w, request_hash)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_string(w, change_type)?;
                write_pubkey(w, member_pubkey)?;
                write_vec(w, new_members, |w, pk| write_pubkey(w, pk))?;
                write_u16(w, *new_threshold)?;
                write_u64(w, *timestamp)?;
                write_64(w, operator_signature)?;
            }
            Self::AcceptReserves { channel_id } => {
                write_u8(w, 5)?;
                write_32(w, channel_id)?;
            }
        }
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        match read_u8(r)? {
            0 => Ok(Self::InvoiceCosigned {
                request_hash: read_32(r)?,
                cosignature: read_64(r)?,
            }),
            1 => Ok(Self::CollateralConsentResponse {
                request_hash: read_32(r)?,
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                consent_granted: read_bool(r)?,
                quorum_member_signature: read_64(r)?,
            }),
            2 => Ok(Self::QuorumJoinResponse {
                request_hash: read_32(r)?,
                accepted: read_bool(r)?,
                members: read_vec(r, read_pubkey)?,
                threshold: read_u16(r)?,
                last_sequence: read_u64(r)?,
                content_hash: read_32(r)?,
                rejection_reason: read_option(r, read_string)?,
            }),
            3 => Ok(Self::QuorumStateSync {
                request_hash: read_32(r)?,
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                updates: read_vec(r, SignedLedgerUpdate::read_from)?,
                start_sequence: read_u64(r)?,
                is_final: read_bool(r)?,
            }),
            4 => Ok(Self::QuorumMembershipChange {
                request_hash: read_32(r)?,
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                change_type: read_string(r)?,
                member_pubkey: read_pubkey(r)?,
                new_members: read_vec(r, read_pubkey)?,
                new_threshold: read_u16(r)?,
                timestamp: read_u64(r)?,
                operator_signature: read_64(r)?,
            }),
            5 => Ok(Self::AcceptReserves {
                channel_id: read_32(r)?,
            }),
            d => Err(CodecError::InvalidDiscriminant(d)),
        }
    }
}
