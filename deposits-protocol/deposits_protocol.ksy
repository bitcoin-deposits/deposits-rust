meta:
  id: deposits_protocol
  title: Bitcoin Deposits Protocol
  license: MIT
  endian: be
  file-extension: tlv

doc: |
  Bitcoin Deposits Protocol wire format. All structures use TLV (Type-Length-Value)
  encoding with BigEndian varints, compatible with Lightning Network TLV format.

  Fields are ordered by type number. Even types are required, odd are optional.
  Unknown fields are preserved for forward compatibility.

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
      Contains the inner operation (as TLV bytes), metadata, and signatures.
    seq:
      - id: records
        type: tlv_record
        repeat: eos
    instances:
      message:
        doc: "Inner LedgerOperation TLV bytes (type 0)"
        value: "records[0].value"
      message_type:
        doc: "Protocol message type constant (type 2)"
        value: "records[1].value"
      operator_id:
        doc: "Operator's 33-byte compressed secp256k1 pubkey (type 4)"
        value: "records[2].value"
      ledger_id:
        doc: "32-byte ledger identifier hash (type 6)"
        value: "records[3].value"
      sequence_number:
        doc: "Monotonically increasing sequence number (type 8)"
        value: "records[4].value"
      previous_hash:
        doc: "32-byte hash of the previous update (type 10)"
        value: "records[5].value"
      current_hash:
        doc: "32-byte hash of this update (type 12)"
        value: "records[6].value"
      timestamp:
        doc: "Unix timestamp in seconds (type 14)"
        value: "records[7].value"
      partner_signature:
        doc: "64-byte ECDSA signature from co-signing partner (type 16)"
        value: "records[8].value"
      operator_signature:
        doc: "64-byte Schnorr signature from operator (type 18)"
        value: "records[9].value"

  ledger_operation:
    doc: |
      A ledger operation — the inner message of a SignedLedgerUpdate.
      First field (type 0) is always the discriminant byte identifying the operation type.

      Discriminant values:
        1  = LedgerOpen
        10 = ReservesIncrease
        11 = ReservesDecrease
        12 = ReservesRotate
        20 = DepositOpen
        21 = DepositClose
        22 = DepositUpdate
        23 = DepositKeyRotate
        30 = InvoiceCredit
        31 = InvoiceLock
        32 = InvoiceFail
        33 = InvoiceFulfill
        35 = OnchainCredit
        36 = OnchainLock
        37 = OnchainFail
        38 = OnchainFulfill
        40 = CollateralIncrease
        41 = CollateralDecrease
        42 = CollateralAttestation
        43 = QuorumAddMember
        44 = QuorumRemoveMember
        45 = CollateralLock
        46 = QuorumJoin
        50 = FeeCollect
        54 = CustodyDispute
        55 = CustodyAcquire
        56 = CustodyYield
        57 = CustodyArmed
        60 = LedgerClose
        61 = Tombstone
        70 = TransferLock
        71 = TransferComplete
        72 = TransferTimeout
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
  # Common fields:
  #   0   = discriminant (u8)
  #   2   = amount (u64)
  #   8   = new_amount (u64)
  #   10  = pubkey (33 bytes, compressed secp256k1)
  #   14  = payment_hash (32 bytes)
  #   30  = payment_id (32 bytes)
  #   34  = preimage (32 bytes)
  #   42  = ledger_hash (32 bytes)
  #   54  = timestamp (u64)
  #
  # Ledger fields:
  #   56  = operator_id (33 bytes)
  #   58  = reserves_id (string)
  #   60  = ledger_address (string)
  #   62  = reserves_amount (u64)
  #   64  = enforcement_block (u64)
  #   96  = genesis_block (u32)
  #
  # Deposit fields:
  #   200 = deposit_id (16 bytes)
  #   202 = descriptor (string)
  #   204 = witness (nested TLV)
  #   206 = witness_element (bytes)
  #   208 = new_descriptor (string)
  #
  # Fee fields:
  #   12  = fees (nested TLV: FeeStructure in DepositOpen; u64 fee_sats in OnchainLock/TransferLock)
  #   226 = transfer_fees (nested TLV: TransferFeeSchedule)
  #   20  = new_fees (nested TLV: FeeStructure)
  #
  # Invoice/Payment fields:
  #   16  = invoice (string)
  #   18  = cosigner_sig (64 bytes)
  #   26  = invoice_id (string)
  #   28  = sequence_number (u64)
  #
  # Transfer fields:
  #   210 = nonce (32 bytes)
  #   212 = source_deposit_id (16 bytes)
  #   214 = destination_deposit_id (16 bytes)
  #   216 = completion_script (string)
  #   218 = timeout_height (u32)
  #   220 = transfer_id (32 bytes)
  #   222 = block_hash (32 bytes)
  #   224 = script_witness (nested TLV)
  #
  # On-chain fields:
  #   66  = txid (32 bytes)
  #   68  = vout (u32)
  #   70  = destination_address (string)
  #   72  = withdrawal_id (32 bytes)
  #   74  = funding_address (string)
  #
  # Reserves rotation fields:
  #   90  = spending_txid (32 bytes)
  #   91  = new_outpoint_txid (32 bytes)
  #   92  = new_outpoint_vout (u32)
  #   93  = quorum_threshold (u8)
  #   94  = quorum_size (u8)
  #   95  = first_expiry_block (u32)
  #
  # Collateral fields:
  #   38  = collateral_operator (33 bytes)
  #   40  = signature (64 bytes)
  #   44  = quorum_member (33 bytes)
  #   76  = lock_until_block (u32)
  #   78  = deposit_holder_sig (64 bytes)
  #   80  = our_signature (64 bytes)
  #   82  = membership_expires (u64)
  #   114 = member_ledger_id (string)
  #   115 = collateral_ledger_id (string)
  #
  # Custody dispute fields:
  #   100 = reason (string)
  #   101 = last_valid_hash (32 bytes)
  #   102 = last_valid_sequence (u64)
  #   103 = evidence_hash (32 bytes)
  #   104 = initiation_block (u32)
  #   105 = entropy_block_height (u32)
  #   106 = entropy_block_hash (32 bytes)
  #   108 = new_custodian (33 bytes)
  #   109 = armed_block (u32)
  #   110 = spend_txid (32 bytes)
  #   111 = new_reserves_address (string)
  #   112 = commitment_hash (32 bytes)
  #   113 = target_reserves (string)

  fee_structure:
    doc: |
      Nested TLV for fee structure (annualized).
      Field types:
        0 = annualized_fixed (u64, msat/year)
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
        0 = fixed_sats (u64)
        2 = rate_bps (u16)
    seq:
      - id: records
        type: tlv_record
        repeat: eos

seq:
  - id: body
    type: signed_ledger_update
