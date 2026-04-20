# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 11):
    raise Exception("Incompatible Kaitai Struct Python API: 0.11 or later is required, but you have %s" % (kaitaistruct.__version__))

class DepositsProtocol(KaitaiStruct):
    """Bitcoin Deposits Protocol wire format. All structures use TLV (Type-Length-Value)
    encoding with BigEndian varints, compatible with Lightning Network TLV format.
    
    Fields are ordered by type number. Even types are required, odd are optional.
    Unknown fields are preserved for forward compatibility.
    """
    def __init__(self, _io, _parent=None, _root=None):
        super(DepositsProtocol, self).__init__(_io)
        self._parent = _parent
        self._root = _root or self
        self._read()

    def _read(self):
        self.body = DepositsProtocol.SignedLedgerUpdate(self._io, self, self._root)


    def _fetch_instances(self):
        pass
        self.body._fetch_instances()

    class FeeStructure(KaitaiStruct):
        """Nested TLV for fee structure (annualized).
        Field types:
          0 = annualized_msats (u64, msat/year)
          2 = annualized_bps (u16, basis points/year)
          4 = frequency_blocks (u32, collection period)
        """
        def __init__(self, _io, _parent=None, _root=None):
            super(DepositsProtocol.FeeStructure, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.records = []
            i = 0
            while not self._io.is_eof():
                self.records.append(DepositsProtocol.TlvRecord(self._io, self, self._root))
                i += 1



        def _fetch_instances(self):
            pass
            for i in range(len(self.records)):
                pass
                self.records[i]._fetch_instances()



    class LedgerOperation(KaitaiStruct):
        """A ledger operation — the inner message of a SignedLedgerUpdate.
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
          43 = QuorumAddMember
          44 = QuorumRemoveMember
          46 = QuorumJoin
          50 = FeeCollect
          54 = DisputeEnter
          55 = DisputeAcquire
          56 = DisputeYield
          57 = DisputeArmed
          60 = LedgerClose
          61 = Tombstone
          70 = TransferLock
          71 = TransferComplete
          72 = TransferFail
        """
        def __init__(self, _io, _parent=None, _root=None):
            super(DepositsProtocol.LedgerOperation, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.records = []
            i = 0
            while not self._io.is_eof():
                self.records.append(DepositsProtocol.TlvRecord(self._io, self, self._root))
                i += 1



        def _fetch_instances(self):
            pass
            for i in range(len(self.records)):
                pass
                self.records[i]._fetch_instances()


        @property
        def discriminant(self):
            """Operation type (type 0, 1 byte)."""
            if hasattr(self, '_m_discriminant'):
                return self._m_discriminant

            self._m_discriminant = KaitaiStream.byte_array_index(self.records[0].value, 0)
            return getattr(self, '_m_discriminant', None)


    class SignedLedgerUpdate(KaitaiStruct):
        """A signed ledger update, broadcast as Kind 9100 Nostr events.
        Contains the inner operation (as TLV bytes), metadata, and signatures.
        """
        def __init__(self, _io, _parent=None, _root=None):
            super(DepositsProtocol.SignedLedgerUpdate, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.records = []
            i = 0
            while not self._io.is_eof():
                self.records.append(DepositsProtocol.TlvRecord(self._io, self, self._root))
                i += 1



        def _fetch_instances(self):
            pass
            for i in range(len(self.records)):
                pass
                self.records[i]._fetch_instances()


        @property
        def current_hash(self):
            """32-byte hash of this update (type 12)."""
            if hasattr(self, '_m_current_hash'):
                return self._m_current_hash

            self._m_current_hash = self.records[6].value
            return getattr(self, '_m_current_hash', None)

        @property
        def ledger_id(self):
            """32-byte ledger identifier hash (type 6)."""
            if hasattr(self, '_m_ledger_id'):
                return self._m_ledger_id

            self._m_ledger_id = self.records[3].value
            return getattr(self, '_m_ledger_id', None)

        @property
        def message(self):
            """Inner LedgerOperation TLV bytes (type 0)."""
            if hasattr(self, '_m_message'):
                return self._m_message

            self._m_message = self.records[0].value
            return getattr(self, '_m_message', None)

        @property
        def message_type(self):
            """Protocol message type constant (type 2)."""
            if hasattr(self, '_m_message_type'):
                return self._m_message_type

            self._m_message_type = self.records[1].value
            return getattr(self, '_m_message_type', None)

        @property
        def operator_id(self):
            """Operator's 33-byte compressed secp256k1 pubkey (type 4)."""
            if hasattr(self, '_m_operator_id'):
                return self._m_operator_id

            self._m_operator_id = self.records[2].value
            return getattr(self, '_m_operator_id', None)

        @property
        def operator_signature(self):
            """64-byte Schnorr signature from operator (type 18)."""
            if hasattr(self, '_m_operator_signature'):
                return self._m_operator_signature

            self._m_operator_signature = self.records[9].value
            return getattr(self, '_m_operator_signature', None)

        @property
        def cosign_signature(self):
            """64-byte ECDSA signature from co-signing partner (type 16)."""
            if hasattr(self, '_m_cosign_signature'):
                return self._m_cosign_signature

            self._m_cosign_signature = self.records[8].value
            return getattr(self, '_m_cosign_signature', None)

        @property
        def previous_hash(self):
            """32-byte hash of the previous update (type 10)."""
            if hasattr(self, '_m_previous_hash'):
                return self._m_previous_hash

            self._m_previous_hash = self.records[5].value
            return getattr(self, '_m_previous_hash', None)

        @property
        def sequence_number(self):
            """Monotonically increasing sequence number (type 8)."""
            if hasattr(self, '_m_sequence_number'):
                return self._m_sequence_number

            self._m_sequence_number = self.records[4].value
            return getattr(self, '_m_sequence_number', None)

        @property
        def timestamp(self):
            """Unix timestamp in seconds (type 14)."""
            if hasattr(self, '_m_timestamp'):
                return self._m_timestamp

            self._m_timestamp = self.records[7].value
            return getattr(self, '_m_timestamp', None)


    class TlvRecord(KaitaiStruct):
        """A single TLV record (type, length, value)."""
        def __init__(self, _io, _parent=None, _root=None):
            super(DepositsProtocol.TlvRecord, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.type = DepositsProtocol.Varint(self._io, self, self._root)
            self.length = DepositsProtocol.Varint(self._io, self, self._root)
            self.value = self._io.read_bytes(self.length.value)


        def _fetch_instances(self):
            pass
            self.type._fetch_instances()
            self.length._fetch_instances()


    class TlvStream(KaitaiStruct):
        """A sequence of TLV records, ordered by type."""
        def __init__(self, _io, _parent=None, _root=None):
            super(DepositsProtocol.TlvStream, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.records = []
            i = 0
            while not self._io.is_eof():
                self.records.append(DepositsProtocol.TlvRecord(self._io, self, self._root))
                i += 1



        def _fetch_instances(self):
            pass
            for i in range(len(self.records)):
                pass
                self.records[i]._fetch_instances()



    class TransferFeeSchedule(KaitaiStruct):
        """Nested TLV for per-transfer fee schedule.
        Field types:
          0 = fixed_msats (u64)
          2 = rate_bps (u16)
        """
        def __init__(self, _io, _parent=None, _root=None):
            super(DepositsProtocol.TransferFeeSchedule, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.records = []
            i = 0
            while not self._io.is_eof():
                self.records.append(DepositsProtocol.TlvRecord(self._io, self, self._root))
                i += 1



        def _fetch_instances(self):
            pass
            for i in range(len(self.records)):
                pass
                self.records[i]._fetch_instances()



    class Varint(KaitaiStruct):
        """BigEndian varint (1/3/5/9 byte encoding, Lightning-compatible)."""
        def __init__(self, _io, _parent=None, _root=None):
            super(DepositsProtocol.Varint, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.first_byte = self._io.read_u1()
            if self.first_byte == 253:
                pass
                self.value_2 = self._io.read_u2be()

            if self.first_byte == 254:
                pass
                self.value_4 = self._io.read_u4be()

            if self.first_byte == 255:
                pass
                self.value_8 = self._io.read_u8be()



        def _fetch_instances(self):
            pass
            if self.first_byte == 253:
                pass

            if self.first_byte == 254:
                pass

            if self.first_byte == 255:
                pass


        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value

            self._m_value = (self.value_8 if self.first_byte == 255 else (self.value_4 if self.first_byte == 254 else (self.value_2 if self.first_byte == 253 else self.first_byte)))
            return getattr(self, '_m_value', None)



