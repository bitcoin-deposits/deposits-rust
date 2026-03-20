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

      current_hash = SHA256(seq || prev_hash || message [|| member_ledger_hash] [|| cosign_signature])
      chain_hash   = SHA256(current_hash || operator_signature)
      next update's previous_hash = chain_hash

      current_hash is NOT on the wire -- it is derived by the receiver.
      Type 12 is reserved.

      Co-signing: SHA256(tag || tag || cosign_data || member_ledger_hash)
      where tag = SHA256("deposits/cosign") and cosign_data =
      message || message_type || sequence || previous_hash.
    seq:
      - id: records
        type: tlv_record
        repeat: eos
    instances:
      message:
        doc: "Inner LedgerOperation TLV bytes (type 0)"
        value: "records[0].value"
      message_type:
        doc: "Operation type constant for fast filtering (type 2, u16)"
        value: "records[1].value"
      operator_id:
        doc: "Operator's 33-byte compressed secp256k1 pubkey (type 4)"
        value: "records[2].value"
      ledger_id:
        doc: "32-byte ledger identifier hash (type 6)"
        value: "records[3].value"
      sequence_number:
        doc: "Monotonically increasing sequence number (type 8, u64)"
        value: "records[4].value"
      previous_hash:
        doc: "32-byte chain hash of the previous update (type 10)"
        value: "records[5].value"
      cosign_signature:
        doc: "64-byte Schnorr co-signature from quorum member (type 16)"
        value: "records[6].value"
      operator_signature:
        doc: "64-byte Schnorr signature from operator (type 18)"
        value: "records[7].value"
      block_height:
        doc: "Block height when update was created (type 20, u32)"
        value: "records[8].value"
      block_hash:
        doc: "32-byte block hash at time of creation (type 22)"
        value: "records[9].value"
      cosigner_pubkey:
        doc: "33-byte compressed pubkey of the co-signing quorum member (type 24)"
        value: "records[10].value"
      member_ledger_hash:
        doc: "32-byte tip hash of the co-signer's own ledger (type 26). Included in derived current_hash for causal ordering."
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
        42 = CollateralAttestation
        43 = QuorumAddMember
        44 = QuorumRemoveMember
        45 = CollateralLock
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
  #   56  = operator_id (33 bytes, LedgerOpen)
  #   58  = reserves_id (string, LedgerOpen/QuorumBegin/QuorumJoin)
  #   62  = reserves_amount (u64, msats, LedgerOpen/QuorumBegin)
  #   64  = (reserved, was collateral_enforcement_block)
  #   96  = genesis_block (u32, LedgerOpen)
  #
  # Deposits:
  #   18  = cosigner_guarantee_sig (64 bytes, DepositOpen)
  #   200 = deposit_id (16 bytes)
  #   202 = descriptor (string, miniscript)
  #   204 = witness (nested TLV)
  #   208 = new_descriptor (string)
  #   230 = is_collateral (u8, 0 or 1)
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
  #   38  = collateral_operator (33 bytes)
  #   40  = signature (64 bytes, CollateralAttestation)
  #   42  = ledger_hash (32 bytes, QuorumBegin/CollateralAttestation)
  #   44  = quorum_member (33 bytes)
  #   46  = quorum_member_sig (64 bytes, QuorumAddMember)
  #   48  = operator_sig (64 bytes, QuorumRemoveMember)
  #   76  = lock_until_block (u32)
  #   80  = our_signature (64 bytes, QuorumJoin)
  #   82  = membership_expires (u32, QuorumJoin)
  #   114 = member_ledger_id (string)
  #   124 = collateral_ledger_id (string)
  #   234 = min_fee_bps (u16, QuorumAddMember)
  #   236 = min_fee_fixed (u64, QuorumAddMember)
  #   238 = max_fee_period (u32, QuorumAddMember)
  #   240 = collateral_lock_amount (u64, QuorumAddMember)
  #   242 = collateral_lock_until (u32, QuorumAddMember)
  #
  # QuorumBegin:
  #   90  = spending_txid (32 bytes)
  #   84  = new_outpoint_txid (32 bytes)
  #   92  = new_outpoint_vout (u32)
  #   86  = first_expiry_block (u32)
  #
  # Dispute:
  #   100 = reason (string, DisputeEnter)
  #   102 = last_valid_sequence (u64, DisputeEnter)
  #   116 = entropy_block_height (u32, DisputeAcquire)
  #   106 = entropy_block_hash (32 bytes, DisputeAcquire)
  #   108 = new_custodian (33 bytes, DisputeAcquire)
  #   118 = armed_block (u32, DisputeArmed)
  #   110 = spend_txid (32 bytes, DisputeAcquire)
  #   120 = new_reserves_address (string, DisputeAcquire)
  #   112 = commitment_hash (20 bytes HASH160, DisputeArmed)
  #   122 = target_reserves (string, DisputeArmed)

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
