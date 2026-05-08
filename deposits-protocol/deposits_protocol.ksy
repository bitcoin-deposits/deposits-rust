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

  Each TLV layer (outer SignedLedgerUpdate, inner LedgerOperation, nested
  FeeStructure / TransferFeeSchedule) has its own typed record (`outer_record`,
  `op_record`, `fee_record`, `transfer_fee_record`) that switch-decodes `value`
  bytes into the protocol type for that layer. The legacy untyped `tlv_record`
  is retained for downstream consumers that want to walk records with raw
  `value` bytes.

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

  # ============================================================
  # Untyped TLV record (back-compat). Prefer the layer-specific
  # typed records below for new code paths.
  # ============================================================
  tlv_record:
    doc: A single TLV record (type, length, raw value bytes).
    seq:
      - id: type
        type: varint
      - id: length
        type: varint
      - id: value
        size: length.value

  tlv_stream:
    doc: A sequence of TLV records, ordered by type.
    seq:
      - id: records
        type: tlv_record
        repeat: eos

  # ============================================================
  # Helper / nested types — referenced by the typed records.
  # ============================================================
  pubkey:
    doc: 33-byte compressed secp256k1 public key.
    seq:
      - id: data
        size: 33

  hash32:
    doc: 32-byte hash (SHA-256, txid, block hash, ledger id, …).
    seq:
      - id: data
        size: 32

  hash20:
    doc: 20-byte hash (HASH160 commitment).
    seq:
      - id: data
        size: 20

  sig64:
    doc: 64-byte BIP-340 Schnorr signature.
    seq:
      - id: data
        size: 64

  deposit_id_bytes:
    doc: 16-byte deposit identifier (fingerprint of the descriptor).
    seq:
      - id: data
        size: 16

  pubkey_concat:
    doc: |
      Concatenated 33-byte compressed secp256k1 pubkeys (e.g. the
      `quorum_members` field on QuorumBegin). Length is the field's
      TLV length (a multiple of 33).
    seq:
      - id: members
        type: pubkey
        repeat: eos

  cosignature_list:
    doc: |
      List of cosignature entries. Each entry encoded as
      u16_be(129) || pubkey(33) || sig(64) || hash(32). Entries are
      sorted by pubkey ascending. After QuorumBegin, floor(n/2)+1
      entries are required to validate.
    seq:
      - id: entries
        type: cosignature_entry
        repeat: eos

  cosignature_entry:
    seq:
      - id: entry_len
        type: u2
        doc: Always 129 (= 33 + 64 + 32). On the wire for forward compat.
      - id: pubkey
        size: 33
      - id: signature
        size: 64
      - id: member_ledger_hash
        size: 32

  descriptor_witness:
    doc: |
      Witness encoding (TLV types 204 and 224).
      Layout: varint(count) || (varint(len) || element)*
      `element` is a raw script/sig push (max 520 bytes per Bitcoin's
      MAX_SCRIPT_ELEMENT_SIZE; max 1000 elements per stack).
    seq:
      - id: count
        type: varint
      - id: stack
        type: descriptor_witness_element
        repeat: expr
        repeat-expr: count.value

  descriptor_witness_element:
    seq:
      - id: len
        type: varint
      - id: data
        size: len.value

  quorum_member_ledger_id_list:
    doc: |
      Parallel array to QuorumBegin.quorum_members (TLV type 276).
      Each entry: u8 length || ledger_id_bytes (ASCII hex). Entries
      align positionally with the pubkey list. Optional — older
      QuorumBegin events omit it; decoders MUST treat the per-member
      ledger_id as empty in that case and may fall back to deriving
      the mapping from prior QuorumAddMember operations on the same
      ledger.
    seq:
      - id: entries
        type: quorum_member_ledger_id_entry
        repeat: eos

  quorum_member_ledger_id_entry:
    seq:
      - id: len
        type: u1
      - id: ledger_id
        size: len
        type: str
        encoding: ASCII

  # ============================================================
  # Outer SignedLedgerUpdate
  # ============================================================
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
        type: outer_record
        repeat: eos

  outer_record:
    doc: A typed TLV record inside signed_ledger_update.
    seq:
      - id: type
        type: varint
      - id: length
        type: varint
      - id: value
        size: length.value
        type:
          switch-on: type.value
          cases:
            0:  pubkey            # operator_id
            2:  hash32            # ledger_id
            4:  u8be              # sequence_number
            6:  hash32            # previous_hash
            8:  ledger_operation  # message (nested)
            10: u4be              # block_height
            12: hash32            # block_hash
            14: pubkey            # cosigner_pubkey (deprecated)
            16: hash32            # member_ledger_hash (deprecated)
            18: sig64             # cosign_signature (deprecated)
            20: sig64             # operator_signature
            22: cosignature_list

  # ============================================================
  # Inner LedgerOperation
  # ============================================================
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
        type: op_record
        repeat: eos

  op_record:
    doc: |
      A typed TLV record inside ledger_operation. The switch-decode
      below mirrors the field-type catalog comment block in this file
      (kept for backwards compatibility with `gen-tlv-catalog.sh` and
      human reference). Unknown / odd field types fall through to raw
      bytes — implementations MUST ignore them per forward-compat
      convention.
    seq:
      - id: type
        type: varint
      - id: length
        type: varint
      - id: value
        size: length.value
        type:
          switch-on: type.value
          cases:
            0:   u1                            # discriminant
            2:   u8be                          # amount (msats)
            6:   pubkey_concat                 # quorum_members
            12:  fee_structure                 # fees (nested)
            14:  hash32                        # payment_hash
            16:  str                           # invoice (BOLT11)
            18:  sig64                         # cosigner_sig (DepositOpen)
            20:  fee_structure                 # new_fees (nested)
            26:  str                           # invoice_id
            28:  u8be                          # sequence_number
            30:  hash32                        # payment_id
            34:  hash32                        # preimage
            36:  u4be                          # block_height
            42:  hash32                        # ledger_hash
            44:  pubkey                        # quorum_member
            46:  sig64                         # quorum_member_sig
            48:  sig64                         # operator_sig
            56:  pubkey                        # operator_id
            58:  str                           # reserves_id
            62:  u8be                          # reserves_amount (msats)
            66:  hash32                        # txid
            68:  u4be                          # vout
            70:  str                           # destination_address
            72:  hash32                        # withdrawal_id
            74:  str                           # funding_address
            82:  u4be                          # membership_expires
            84:  hash32                        # new_outpoint_txid
            86:  u4be                          # quorum_expiry
            88:  u8be                          # collateral_amount_msats
            90:  hash32                        # spending_txid
            92:  u4be                          # new_outpoint_vout
            96:  u4be                          # genesis_block
            100: str                           # reason
            102: u8be                          # last_valid_sequence
            108: pubkey                        # new_custodian
            110: hash32                        # claim_txid
            112: hash20                        # commitment_hash (HASH160)
            114: str                           # member_ledger_id
            118: u4be                          # armed_block
            120: str                           # new_reserves_address
            122: str                           # target_reserves
            200: deposit_id_bytes              # deposit_id
            202: str                           # descriptor (miniscript)
            204: descriptor_witness            # witness (nested)
            208: str                           # new_descriptor
            210: hash32                        # nonce
            212: deposit_id_bytes              # source_deposit_id
            214: deposit_id_bytes              # destination_deposit_id
            216: str                           # completion_script (miniscript)
            218: u4be                          # timeout_height
            220: hash32                        # transfer_id
            222: hash32                        # block_hash (TransferFail)
            224: descriptor_witness            # script_witness (nested)
            226: transfer_fee_schedule         # transfer_fees (nested)
            228: u1                            # fail_reason
            232: u1                            # receive_requires_sig
            234: u2be                          # min_fee_bps
            236: u8be                          # min_fee_fixed
            238: u4be                          # max_fee_period
            242: u4be                          # membership_until
            244: u4be                          # fee_change_after_blocks
            246: u4be                          # fee_change_notice_blocks
            248: u2be                          # fee_change_limit_bps
            250: u4be                          # effective_block
            252: u4be                          # dispute_response_blocks
            254: u4be                          # dispute_arm_blocks
            256: u4be                          # service_response_blocks
            258: u4be                          # max_transfer_timeout_blocks
            262: u4be                          # max_descriptor_bytes
            264: u2be                          # compensation_bps
            266: deposit_id_bytes              # compensation_deposit_id
            268: u4be                          # compensation_frequency_blocks
            270: hash32                        # request_hash
            272: hash32                        # target_ledger_id
            274: pubkey                        # target_operator
            276: quorum_member_ledger_id_list  # quorum_member_ledger_ids
            280: hash32                        # replacement_collateral_txid
            282: u4be                          # replacement_collateral_vout
            284: u8be                          # replacement_collateral_amount

  # ================================================================
  # TLV field type reference for LedgerOperation
  # ================================================================
  #
  # Mirrored by the `op_record.value` switch-on above; this comment
  # block remains the human-facing source of truth and is consumed by
  # `deposits-tools/bin/gen-tlv-catalog.sh` to populate the wallet's
  # `tlv-catalog.js`.
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
  #   24  = reserved (was deposit_pubkey — descriptor-based identity post-Wave-1)
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

  # ============================================================
  # Nested fee structures
  # ============================================================
  fee_structure:
    doc: |
      Nested TLV for fee structure (annualized).
      Field types:
        0 = annualized_msats (u64, msat/year)
        2 = annualized_bps (u16, basis points/year)
        4 = frequency_blocks (u32, collection period)
    seq:
      - id: records
        type: fee_record
        repeat: eos

  fee_record:
    seq:
      - id: type
        type: varint
      - id: length
        type: varint
      - id: value
        size: length.value
        type:
          switch-on: type.value
          cases:
            0: u8be   # annualized_msats
            2: u2be   # annualized_bps
            4: u4be   # frequency_blocks

  transfer_fee_schedule:
    doc: |
      Nested TLV for per-transfer fee schedule.
      Field types:
        0 = fixed_msats (u64)
        2 = rate_bps (u16)
    seq:
      - id: records
        type: transfer_fee_record
        repeat: eos

  transfer_fee_record:
    seq:
      - id: type
        type: varint
      - id: length
        type: varint
      - id: value
        size: length.value
        type:
          switch-on: type.value
          cases:
            0: u8be   # fixed_msats
            2: u2be   # rate_bps

seq:
  - id: body
    type: signed_ledger_update
