meta:
  id: deposits_protocol
  title: Bitcoin Deposits Protocol
  license: MIT
  endian: be
  file-extension: tlv

doc: |
  Bitcoin Deposits Protocol wire format. All structures use TLV (Type-Length-Value)
  encoding with BigEndian varints, compatible with Lightning Network TLV format.

  All current field types are even. Odd types are reserved for future
  forward-compatible extensions that unknown implementations may safely ignore.

types:
  varint:
    doc: BigEndian varint (1/3/5/9 byte encoding, Lightning-compatible)
    seq:
      - id: first_byte
        type: u1
      - id: value_2
        type: u2be
        if: first_byte == 0xfd
      - id: value_4
        type: u4be
        if: first_byte == 0xfe
      - id: value_8
        type: u8be
        if: first_byte == 0xff
    instances:
      value:
        value: |
          first_byte == 0xff ? value_8 :
          first_byte == 0xfe ? value_4 :
          first_byte == 0xfd ? value_2 :
          first_byte

  tlv_record:
    doc: A single TLV record (type, length, value)
    seq:
      - id: type
        type: varint
      - id: length
        type: varint
      - id: value
        size: length.value

  tlv_stream:
    doc: A sequence of TLV records, ordered by type
    seq:
      - id: records
        type: tlv_record
        repeat: eos

  signed_ledger_update:
    doc: |
      A signed ledger update, broadcast as Kind 9100 Nostr events.

      Multi-cosig format (tag 22 present):
        content_hash = SHA256(seq || prev_hash || message || for each sorted entry: member_hash || cosig)
      Legacy single-cosig format (tag 22 absent):
        content_hash = SHA256(seq || prev_hash || message [|| member_ledger_hash] [|| cosign_signature])
      chain_hash   = SHA256(content_hash || operator_signature)
      next update's previous_hash = chain_hash

      content_hash is NOT on the wire -- it is derived by the receiver.
      message_type is NOT on the wire -- it is derived from the operation discriminant.

      Layout: identity -> chain -> payload -> context -> cosign -> signatures
        type 0  = operator_id        (33-byte pubkey)
        type 2  = ledger_id          (32-byte hash)
        type 4  = sequence_number    (u64)
        type 6  = previous_hash      (32-byte hash)
        type 8  = message            (variable, inner LedgerOperation TLV)
        type 10 = block_height       (u32, optional)
        type 12 = block_hash         (32-byte hash, optional)
        type 14 = cosigner_pubkey    (33-byte pubkey, deprecated — legacy single-cosig)
        type 16 = member_ledger_hash (32-byte hash, deprecated — legacy single-cosig)
        type 18 = cosign_signature   (64-byte sig, deprecated — legacy single-cosig)
        type 20 = operator_signature (64-byte sig)
        type 22 = cosignatures       (variable, length-prefixed entries — majority cosig)

      Tag 22 contains N entries, each: u16_be(129) || pubkey(33) || sig(64) || hash(32).
      Entries sorted by pubkey. After QuorumBegin, floor(n/2)+1 entries required.

      Co-signing: SHA256(tag || tag || cosign_data || member_ledger_hash)
      where tag = SHA256("deposits/cosign") and cosign_data =
      sequence || previous_hash || message.
      Each quorum member signs independently with their own member_ledger_hash.
    seq:
      - id: records
        type: tlv_record
        repeat: eos
    instances:
      operator_id:
        doc: "Operator's 33-byte compressed secp256k1 pubkey (type 0)"
        value: "records[0].value"
      ledger_id:
        doc: "32-byte ledger identifier hash (type 2)"
        value: "records[1].value"
      sequence_number:
        doc: "Monotonically increasing sequence number (type 4, u64)"
        value: "records[2].value"
      previous_hash:
        doc: "32-byte chain hash of the previous update (type 6)"
        value: "records[3].value"
      message:
        doc: "Inner LedgerOperation TLV bytes (type 8)"
        value: "records[4].value"
      block_height:
        doc: "Block height when update was created (type 10, u32, optional)"
        value: "records[5].value"
      block_hash:
        doc: "32-byte block hash at time of creation (type 12, optional)"
        value: "records[6].value"
      cosigner_pubkey:
        doc: "DEPRECATED: 33-byte pubkey of single co-signer (type 14). Use cosignatures (type 22) for majority cosig."
        value: "records[7].value"
      member_ledger_hash:
        doc: "DEPRECATED: 32-byte tip hash of single co-signer's ledger (type 16). Use cosignatures (type 22)."
        value: "records[8].value"
      cosign_signature:
        doc: "DEPRECATED: 64-byte single co-signature (type 18). Use cosignatures (type 22)."
        value: "records[9].value"
      operator_signature:
        doc: "64-byte Schnorr signature from operator (type 20)"
        value: "records[10].value"
      cosignatures:
        doc: "Majority cosignature list (type 22). N entries: u16_be(129) || pubkey(33) || sig(64) || hash(32), sorted by pubkey."
        value: "records[11].value"

  ledger_operation:
    doc: |
      A ledger operation -- the inner message of a SignedLedgerUpdate.
      First field (type 0) is always the discriminant byte identifying the operation type.

      Discriminant values:
        1  = LedgerOpen
        12 = QuorumBegin
        20 = DepositOpen
        21 = DepositClose
        22 = FeeChange
        23 = DepositKeyRotate
        30 = InvoiceCredit
        31 = InvoiceLock
        32 = InvoiceFail
        33 = InvoiceFulfill
        35 = OnchainCredit
        36 = OnchainLock
        37 = OnchainFail
        38 = OnchainFulfill
        43 = QuorumAddMember
        44 = QuorumRemoveMember
        46 = QuorumJoin
        50 = FeeCollect
        54 = DisputeEnter
        55 = DisputeAcquire
        56 = DisputeYield
        57 = DisputeArmed
        60 = LedgerClose
        70 = TransferLock
        71 = TransferComplete
        72 = TransferFail
        80 = DeliveryEmbed
    seq:
      - id: records
        type: tlv_record
        repeat: eos
    instances:
      discriminant:
        doc: "Operation type (type 0, 1 byte)"
        value: "records[0].value[0]"

  # ================================================================
  # TLV field type reference for LedgerOperation
  # ================================================================
  #
  # Common:
  #   0   = discriminant (u8)
  #   2   = amount (u64, msats)
  #   36  = block_height (u32)
  #
  # Ledger:
  #   6   = quorum_members (N*33 concatenated compressed pubkeys, QuorumBegin)
  #         Pair with field 276 (quorum_member_ledger_ids, optional) for
  #         the per-member ledger_id pairing.
  #   56  = operator_id (33 bytes, LedgerOpen)
  #   58  = reserves_id (string, LedgerOpen/QuorumBegin/QuorumJoin)
  #   62  = reserves_amount (u64, msats, LedgerOpen/QuorumBegin)
  #   64  = (reserved, was collateral_enforcement_block)
  #   96  = genesis_block (u32, LedgerOpen)
  #
  # Deposits:
  #   18  = cosigner_sig (64 bytes, DepositOpen co-signer guarantee, optional)
  #   24  = deposit_pubkey (33 bytes, DepositOpen)
  #   200 = deposit_id (16 bytes)
  #   202 = descriptor (string, miniscript)
  #   204 = witness (nested TLV)
  #   206 = witness_element (bytes, sub-TLV inside type 204)
  #   208 = new_descriptor (string)
  #   232 = receive_requires_sig (u8, 0 or 1)
  #
  # Fees:
  #   12  = fees (nested TLV: FeeStructure)
  #   20  = new_fees (nested TLV: FeeStructure)
  #   226 = transfer_fees (nested TLV: TransferFeeSchedule)
  #   244 = fee_change_after_blocks (u32)
  #   246 = fee_change_notice_blocks (u32)
  #   248 = fee_change_limit_bps (u16)
  #   250 = effective_block (u32, FeeChange)
  #
  # Lightning/On-chain:
  #   14  = payment_hash (32 bytes)
  #   16  = invoice (string, BOLT11)
  #   26  = invoice_id (string)
  #   28  = sequence_number (u64, InvoiceCredit/Lock/Fail/Fulfill)
  #   30  = payment_id (32 bytes, InvoiceLock/Fail/Fulfill)
  #   34  = preimage (32 bytes)
  #   66  = txid (32 bytes)
  #   68  = vout (u32)
  #   70  = destination_address (string)
  #   72  = withdrawal_id (32 bytes)
  #   74  = funding_address (string, OnchainCredit)
  #
  # Transfers:
  #   210 = nonce (32 bytes, TransferLock)
  #   212 = source_deposit_id (16 bytes)
  #   214 = destination_deposit_id (16 bytes)
  #   216 = completion_script (string, miniscript)
  #   218 = timeout_height (u32)
  #   220 = transfer_id (32 bytes)
  #   222 = block_hash (32 bytes, TransferFail)
  #   224 = script_witness (nested TLV, TransferComplete)
  #   228 = fail_reason (u8, 1=timeout, 0=reserved)
  #
  # Quorum/Collateral:
  #   38  = reserved (was collateral_operator)
  #   42  = ledger_hash (32 bytes, QuorumBegin)
  #   44  = quorum_member (33 bytes)
  #   46  = quorum_member_sig (64 bytes, QuorumAddMember)
  #   48  = operator_sig (64 bytes, QuorumRemoveMember)
  #   76  = reserved (was lock_until_block)
  #   82  = membership_expires (u32, QuorumJoin)
  #   114 = member_ledger_id (string)
  #   124 = reserved (was collateral_ledger_id)
  #   234 = min_fee_bps (u16, QuorumAddMember)
  #   236 = min_fee_fixed (u64, QuorumAddMember)
  #   238 = max_fee_period (u32, QuorumAddMember)
  #   240 = reserved (was collateral_lock_amount)
  #   242 = membership_until (u32, QuorumAddMember)
  #   252 = dispute_response_blocks (u32, QuorumAddMember)
  #   254 = dispute_arm_blocks (u32, QuorumAddMember)
  #   256 = service_response_blocks (u32, QuorumAddMember)
  #   258 = max_transfer_timeout_blocks (u32, QuorumAddMember)
  #   262 = max_descriptor_bytes (u32, QuorumAddMember)
  #   264 = compensation_bps (u16, QuorumAddMember — bips of collected fees
  #                           paid to this member)
  #   266 = compensation_deposit_id (16 bytes, QuorumAddMember — deposit on
  #                                  operator's ledger where payout lands)
  #   268 = compensation_frequency_blocks (u32, QuorumAddMember — payout cadence)
  #
  # Delivery:
  #   270 = request_hash (32 bytes, DeliveryEmbed)
  #   272 = target_ledger_id (32 bytes, DeliveryEmbed)
  #   274 = target_operator (33 bytes, DeliveryEmbed)
  #
  # QuorumBegin:
  #   84  = new_outpoint_txid (32 bytes)
  #   86  = quorum_expiry (u32)
  #   88  = collateral_amount_msats (u64, msats, collateral portion of UTXO)
  #   90  = spending_txid (32 bytes)
  #   92  = new_outpoint_vout (u32)
  #   276 = quorum_member_ledger_ids (parallel array to quorum_members:
  #         each entry is `u8 len || ledger_id_bytes`. Ledger IDs are
  #         64-char hex (so `len` is always 64 today, but the encoding
  #         is varlen for forward compat). Index i in this list is the
  #         ledger_id for quorum_members[i]. Optional — older
  #         QuorumBegin events omit it; decoders MUST treat the
  #         per-member ledger_id as empty in that case and may fall
  #         back to deriving the mapping from prior QuorumAddMember
  #         operations on the same ledger.
  #
  # Dispute:
  #   100 = reason (string, DisputeEnter)
  #   102 = last_valid_sequence (u64, DisputeEnter)
  #   108 = new_custodian (33 bytes, DisputeAcquire)
  #   110 = claim_txid (32 bytes, DisputeAcquire)
  #   118 = armed_block (u32, DisputeArmed)
  #   120 = new_reserves_address (string, DisputeAcquire)
  #   112 = commitment_hash (20 bytes HASH160, DisputeArmed)
  #   122 = target_reserves (string, DisputeArmed)
  #   280 = replacement_collateral_txid (32 bytes, DisputeArmed,
  #         optional — emitted by new producers since 2026-05; old armed
  #         events omit fields 280/282/284 entirely. See DEP-03
  #         §"Replacement collateral declaration".)
  #   282 = replacement_collateral_vout (u32, DisputeArmed, optional)
  #   284 = replacement_collateral_amount (u64 sats, DisputeArmed,
  #         optional — sats pledged from the declared UTXO toward the
  #         post-takeover vault. Cosigners enforce
  #         `amount ≥ obligations × collateral_ratio + fee_estimate`
  #         at confiscation cosign time.)
  # Note: 106 and 116 (entropy_block_hash, entropy_block_height) were
  # used by the pre-lottery DisputeAcquire shape and are now retired.

  fee_structure:
    doc: |
      Nested TLV for fee structure (annualized).
      Field types:
        0 = annualized_msats (u64, msat/year)
        2 = annualized_bps (u16, basis points/year)
        4 = frequency_blocks (u32, collection period)
    seq:
      - id: records
        type: tlv_record
        repeat: eos

  transfer_fee_schedule:
    doc: |
      Nested TLV for per-transfer fee schedule.
      Field types:
        0 = fixed_msats (u64)
        2 = rate_bps (u16)
    seq:
      - id: records
        type: tlv_record
        repeat: eos

seq:
  - id: body
    type: signed_ledger_update
