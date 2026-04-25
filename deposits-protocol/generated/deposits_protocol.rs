// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(irrefutable_let_patterns)]
#![allow(unused_comparisons)]

extern crate kaitai;
use kaitai::*;
use std::cell::{Cell, Ref, RefCell};
use std::convert::{TryFrom, TryInto};
use std::rc::{Rc, Weak};

/**
 * Bitcoin Deposits Protocol wire format. All structures use TLV (Type-Length-Value)
 * encoding with BigEndian varints, compatible with Lightning Network TLV format.
 *
 * Fields are ordered by type number. Even types are required, odd are optional.
 * Unknown fields are preserved for forward compatibility.
 */

#[derive(Default, Debug, Clone)]
pub struct DepositsProtocol {
    pub _root: SharedType<DepositsProtocol>,
    pub _parent: SharedType<DepositsProtocol>,
    pub _self: SharedType<Self>,
    body: RefCell<OptRc<DepositsProtocol_SignedLedgerUpdate>>,
    _io: RefCell<BytesReader>,
}
impl KStruct for DepositsProtocol {
    type Root = DepositsProtocol;
    type Parent = DepositsProtocol;

    fn read<S: KStream>(
        self_rc: &OptRc<Self>,
        _io: &S,
        _root: SharedType<Self::Root>,
        _parent: SharedType<Self::Parent>,
    ) -> KResult<()> {
        *self_rc._io.borrow_mut() = _io.clone();
        self_rc._root.set(_root.get());
        self_rc._parent.set(_parent.get());
        self_rc._self.set(Ok(self_rc.clone()));
        let _rrc = self_rc._root.get_value().borrow().upgrade();
        let _prc = self_rc._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        let t = Self::read_into::<_, DepositsProtocol_SignedLedgerUpdate>(
            _io,
            Some(self_rc._root.clone()),
            Some(self_rc._self.clone()),
        )?;
        *self_rc.body.borrow_mut() = t;
        Ok(())
    }
}
impl DepositsProtocol {}
impl DepositsProtocol {
    pub fn body(&self) -> Ref<'_, OptRc<DepositsProtocol_SignedLedgerUpdate>> {
        self.body.borrow()
    }
}
impl DepositsProtocol {
    pub fn _io(&self) -> Ref<'_, BytesReader> {
        self._io.borrow()
    }
}

/**
 * Nested TLV for fee structure (annualized).
 * Field types:
 *   0 = annualized_msats (u64, msat/year)
 *   2 = annualized_bps (u16, basis points/year)
 *   4 = frequency_blocks (u32, collection period)
 */

#[derive(Default, Debug, Clone)]
pub struct DepositsProtocol_FeeStructure {
    pub _root: SharedType<DepositsProtocol>,
    pub _parent: SharedType<KStructUnit>,
    pub _self: SharedType<Self>,
    records: RefCell<Vec<OptRc<DepositsProtocol_TlvRecord>>>,
    _io: RefCell<BytesReader>,
}
impl KStruct for DepositsProtocol_FeeStructure {
    type Root = DepositsProtocol;
    type Parent = KStructUnit;

    fn read<S: KStream>(
        self_rc: &OptRc<Self>,
        _io: &S,
        _root: SharedType<Self::Root>,
        _parent: SharedType<Self::Parent>,
    ) -> KResult<()> {
        *self_rc._io.borrow_mut() = _io.clone();
        self_rc._root.set(_root.get());
        self_rc._parent.set(_parent.get());
        self_rc._self.set(Ok(self_rc.clone()));
        let _rrc = self_rc._root.get_value().borrow().upgrade();
        let _prc = self_rc._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        *self_rc.records.borrow_mut() = Vec::new();
        {
            let mut _i = 0;
            while !_io.is_eof() {
                let t = Self::read_into::<_, DepositsProtocol_TlvRecord>(
                    _io,
                    Some(self_rc._root.clone()),
                    None,
                )?;
                self_rc.records.borrow_mut().push(t);
                _i += 1;
            }
        }
        Ok(())
    }
}
impl DepositsProtocol_FeeStructure {}
impl DepositsProtocol_FeeStructure {
    pub fn records(&self) -> Ref<'_, Vec<OptRc<DepositsProtocol_TlvRecord>>> {
        self.records.borrow()
    }
}
impl DepositsProtocol_FeeStructure {
    pub fn _io(&self) -> Ref<'_, BytesReader> {
        self._io.borrow()
    }
}

/**
 * A ledger operation — the inner message of a SignedLedgerUpdate.
 * First field (type 0) is always the discriminant byte identifying the operation type.
 *
 * Discriminant values:
 *   1  = LedgerOpen
 *   10 = ReservesIncrease
 *   11 = ReservesDecrease
 *   12 = ReservesRotate
 *   20 = DepositOpen
 *   21 = DepositClose
 *   22 = DepositUpdate
 *   23 = DepositKeyRotate
 *   30 = InvoiceCredit
 *   31 = InvoiceLock
 *   32 = InvoiceFail
 *   33 = InvoiceFulfill
 *   35 = OnchainCredit
 *   36 = OnchainLock
 *   37 = OnchainFail
 *   38 = OnchainFulfill
 *   40 = CollateralIncrease
 *   41 = CollateralDecrease
 *   43 = QuorumAddMember
 *   44 = QuorumRemoveMember
 *   46 = QuorumJoin
 *   50 = FeeCollect
 *   54 = DisputeEnter
 *   55 = DisputeAcquire
 *   56 = DisputeYield
 *   57 = DisputeArmed
 *   60 = LedgerClose
 *   61 = Tombstone
 *   70 = TransferLock
 *   71 = TransferComplete
 *   72 = TransferFail
 */

#[derive(Default, Debug, Clone)]
pub struct DepositsProtocol_LedgerOperation {
    pub _root: SharedType<DepositsProtocol>,
    pub _parent: SharedType<KStructUnit>,
    pub _self: SharedType<Self>,
    records: RefCell<Vec<OptRc<DepositsProtocol_TlvRecord>>>,
    _io: RefCell<BytesReader>,
    f_discriminant: Cell<bool>,
    discriminant: RefCell<u8>,
}
impl KStruct for DepositsProtocol_LedgerOperation {
    type Root = DepositsProtocol;
    type Parent = KStructUnit;

    fn read<S: KStream>(
        self_rc: &OptRc<Self>,
        _io: &S,
        _root: SharedType<Self::Root>,
        _parent: SharedType<Self::Parent>,
    ) -> KResult<()> {
        *self_rc._io.borrow_mut() = _io.clone();
        self_rc._root.set(_root.get());
        self_rc._parent.set(_parent.get());
        self_rc._self.set(Ok(self_rc.clone()));
        let _rrc = self_rc._root.get_value().borrow().upgrade();
        let _prc = self_rc._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        *self_rc.records.borrow_mut() = Vec::new();
        {
            let mut _i = 0;
            while !_io.is_eof() {
                let t = Self::read_into::<_, DepositsProtocol_TlvRecord>(
                    _io,
                    Some(self_rc._root.clone()),
                    None,
                )?;
                self_rc.records.borrow_mut().push(t);
                _i += 1;
            }
        }
        Ok(())
    }
}
impl DepositsProtocol_LedgerOperation {
    /**
     * Operation type (type 0, 1 byte)
     */
    pub fn discriminant(&self) -> KResult<Ref<'_, u8>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_discriminant.get() {
            return Ok(self.discriminant.borrow());
        }
        self.f_discriminant.set(true);
        *self.discriminant.borrow_mut() = (self.records()[0_usize].value()[0_usize]);
        Ok(self.discriminant.borrow())
    }
}
impl DepositsProtocol_LedgerOperation {
    pub fn records(&self) -> Ref<'_, Vec<OptRc<DepositsProtocol_TlvRecord>>> {
        self.records.borrow()
    }
}
impl DepositsProtocol_LedgerOperation {
    pub fn _io(&self) -> Ref<'_, BytesReader> {
        self._io.borrow()
    }
}

/**
 * A signed ledger update, broadcast as Kind 9100 Nostr events.
 * Contains the inner operation (as TLV bytes), metadata, and signatures.
 */

#[derive(Default, Debug, Clone)]
pub struct DepositsProtocol_SignedLedgerUpdate {
    pub _root: SharedType<DepositsProtocol>,
    pub _parent: SharedType<DepositsProtocol>,
    pub _self: SharedType<Self>,
    records: RefCell<Vec<OptRc<DepositsProtocol_TlvRecord>>>,
    _io: RefCell<BytesReader>,
    f_content_hash: Cell<bool>,
    content_hash: RefCell<Vec<u8>>,
    f_ledger_id: Cell<bool>,
    ledger_id: RefCell<Vec<u8>>,
    f_message: Cell<bool>,
    message: RefCell<Vec<u8>>,
    f_message_type: Cell<bool>,
    message_type: RefCell<Vec<u8>>,
    f_operator_id: Cell<bool>,
    operator_id: RefCell<Vec<u8>>,
    f_operator_signature: Cell<bool>,
    operator_signature: RefCell<Vec<u8>>,
    f_cosign_signature: Cell<bool>,
    cosign_signature: RefCell<Vec<u8>>,
    f_previous_hash: Cell<bool>,
    previous_hash: RefCell<Vec<u8>>,
    f_sequence_number: Cell<bool>,
    sequence_number: RefCell<Vec<u8>>,
    f_timestamp: Cell<bool>,
    timestamp: RefCell<Vec<u8>>,
}
impl KStruct for DepositsProtocol_SignedLedgerUpdate {
    type Root = DepositsProtocol;
    type Parent = DepositsProtocol;

    fn read<S: KStream>(
        self_rc: &OptRc<Self>,
        _io: &S,
        _root: SharedType<Self::Root>,
        _parent: SharedType<Self::Parent>,
    ) -> KResult<()> {
        *self_rc._io.borrow_mut() = _io.clone();
        self_rc._root.set(_root.get());
        self_rc._parent.set(_parent.get());
        self_rc._self.set(Ok(self_rc.clone()));
        let _rrc = self_rc._root.get_value().borrow().upgrade();
        let _prc = self_rc._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        *self_rc.records.borrow_mut() = Vec::new();
        {
            let mut _i = 0;
            while !_io.is_eof() {
                let t = Self::read_into::<_, DepositsProtocol_TlvRecord>(
                    _io,
                    Some(self_rc._root.clone()),
                    None,
                )?;
                self_rc.records.borrow_mut().push(t);
                _i += 1;
            }
        }
        Ok(())
    }
}
impl DepositsProtocol_SignedLedgerUpdate {
    /**
     * 32-byte hash of this update (type 12)
     */
    pub fn content_hash(&self) -> KResult<Ref<'_, Vec<u8>>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_content_hash.get() {
            return Ok(self.content_hash.borrow());
        }
        self.f_content_hash.set(true);
        *self.content_hash.borrow_mut() = self.records()[6_usize].value().to_vec();
        Ok(self.content_hash.borrow())
    }

    /**
     * 32-byte ledger identifier hash (type 6)
     */
    pub fn ledger_id(&self) -> KResult<Ref<'_, Vec<u8>>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_ledger_id.get() {
            return Ok(self.ledger_id.borrow());
        }
        self.f_ledger_id.set(true);
        *self.ledger_id.borrow_mut() = self.records()[3_usize].value().to_vec();
        Ok(self.ledger_id.borrow())
    }

    /**
     * Inner LedgerOperation TLV bytes (type 0)
     */
    pub fn message(&self) -> KResult<Ref<'_, Vec<u8>>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_message.get() {
            return Ok(self.message.borrow());
        }
        self.f_message.set(true);
        *self.message.borrow_mut() = self.records()[0_usize].value().to_vec();
        Ok(self.message.borrow())
    }

    /**
     * Protocol message type constant (type 2)
     */
    pub fn message_type(&self) -> KResult<Ref<'_, Vec<u8>>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_message_type.get() {
            return Ok(self.message_type.borrow());
        }
        self.f_message_type.set(true);
        *self.message_type.borrow_mut() = self.records()[1_usize].value().to_vec();
        Ok(self.message_type.borrow())
    }

    /**
     * Operator's 33-byte compressed secp256k1 pubkey (type 4)
     */
    pub fn operator_id(&self) -> KResult<Ref<'_, Vec<u8>>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_operator_id.get() {
            return Ok(self.operator_id.borrow());
        }
        self.f_operator_id.set(true);
        *self.operator_id.borrow_mut() = self.records()[2_usize].value().to_vec();
        Ok(self.operator_id.borrow())
    }

    /**
     * 64-byte Schnorr signature from operator (type 18)
     */
    pub fn operator_signature(&self) -> KResult<Ref<'_, Vec<u8>>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_operator_signature.get() {
            return Ok(self.operator_signature.borrow());
        }
        self.f_operator_signature.set(true);
        *self.operator_signature.borrow_mut() = self.records()[9_usize].value().to_vec();
        Ok(self.operator_signature.borrow())
    }

    /**
     * 64-byte ECDSA signature from co-signing partner (type 16)
     */
    pub fn cosign_signature(&self) -> KResult<Ref<'_, Vec<u8>>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_cosign_signature.get() {
            return Ok(self.cosign_signature.borrow());
        }
        self.f_cosign_signature.set(true);
        *self.cosign_signature.borrow_mut() = self.records()[8_usize].value().to_vec();
        Ok(self.cosign_signature.borrow())
    }

    /**
     * 32-byte hash of the previous update (type 10)
     */
    pub fn previous_hash(&self) -> KResult<Ref<'_, Vec<u8>>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_previous_hash.get() {
            return Ok(self.previous_hash.borrow());
        }
        self.f_previous_hash.set(true);
        *self.previous_hash.borrow_mut() = self.records()[5_usize].value().to_vec();
        Ok(self.previous_hash.borrow())
    }

    /**
     * Monotonically increasing sequence number (type 8)
     */
    pub fn sequence_number(&self) -> KResult<Ref<'_, Vec<u8>>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_sequence_number.get() {
            return Ok(self.sequence_number.borrow());
        }
        self.f_sequence_number.set(true);
        *self.sequence_number.borrow_mut() = self.records()[4_usize].value().to_vec();
        Ok(self.sequence_number.borrow())
    }

    /**
     * Unix timestamp in seconds (type 14)
     */
    pub fn timestamp(&self) -> KResult<Ref<'_, Vec<u8>>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_timestamp.get() {
            return Ok(self.timestamp.borrow());
        }
        self.f_timestamp.set(true);
        *self.timestamp.borrow_mut() = self.records()[7_usize].value().to_vec();
        Ok(self.timestamp.borrow())
    }
}
impl DepositsProtocol_SignedLedgerUpdate {
    pub fn records(&self) -> Ref<'_, Vec<OptRc<DepositsProtocol_TlvRecord>>> {
        self.records.borrow()
    }
}
impl DepositsProtocol_SignedLedgerUpdate {
    pub fn _io(&self) -> Ref<'_, BytesReader> {
        self._io.borrow()
    }
}

/**
 * A single TLV record (type, length, value)
 */

#[derive(Default, Debug, Clone)]
pub struct DepositsProtocol_TlvRecord {
    pub _root: SharedType<DepositsProtocol>,
    pub _parent: SharedType<KStructUnit>,
    pub _self: SharedType<Self>,
    record_type: RefCell<OptRc<DepositsProtocol_Varint>>,
    length: RefCell<OptRc<DepositsProtocol_Varint>>,
    value: RefCell<Vec<u8>>,
    _io: RefCell<BytesReader>,
}
impl KStruct for DepositsProtocol_TlvRecord {
    type Root = DepositsProtocol;
    type Parent = KStructUnit;

    fn read<S: KStream>(
        self_rc: &OptRc<Self>,
        _io: &S,
        _root: SharedType<Self::Root>,
        _parent: SharedType<Self::Parent>,
    ) -> KResult<()> {
        *self_rc._io.borrow_mut() = _io.clone();
        self_rc._root.set(_root.get());
        self_rc._parent.set(_parent.get());
        self_rc._self.set(Ok(self_rc.clone()));
        let _rrc = self_rc._root.get_value().borrow().upgrade();
        let _prc = self_rc._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        let t = Self::read_into::<_, DepositsProtocol_Varint>(
            _io,
            Some(self_rc._root.clone()),
            Some(self_rc._self.clone()),
        )?;
        *self_rc.record_type.borrow_mut() = t;
        let t = Self::read_into::<_, DepositsProtocol_Varint>(
            _io,
            Some(self_rc._root.clone()),
            Some(self_rc._self.clone()),
        )?;
        *self_rc.length.borrow_mut() = t;
        *self_rc.value.borrow_mut() = _io.read_bytes(*self_rc.length().value()? as usize)?;
        Ok(())
    }
}
impl DepositsProtocol_TlvRecord {}
impl DepositsProtocol_TlvRecord {
    pub fn record_type(&self) -> Ref<'_, OptRc<DepositsProtocol_Varint>> {
        self.record_type.borrow()
    }
}
impl DepositsProtocol_TlvRecord {
    pub fn length(&self) -> Ref<'_, OptRc<DepositsProtocol_Varint>> {
        self.length.borrow()
    }
}
impl DepositsProtocol_TlvRecord {
    pub fn value(&self) -> Ref<'_, Vec<u8>> {
        self.value.borrow()
    }
}
impl DepositsProtocol_TlvRecord {
    pub fn _io(&self) -> Ref<'_, BytesReader> {
        self._io.borrow()
    }
}

/**
 * A sequence of TLV records, ordered by type
 */

#[derive(Default, Debug, Clone)]
pub struct DepositsProtocol_TlvStream {
    pub _root: SharedType<DepositsProtocol>,
    pub _parent: SharedType<KStructUnit>,
    pub _self: SharedType<Self>,
    records: RefCell<Vec<OptRc<DepositsProtocol_TlvRecord>>>,
    _io: RefCell<BytesReader>,
}
impl KStruct for DepositsProtocol_TlvStream {
    type Root = DepositsProtocol;
    type Parent = KStructUnit;

    fn read<S: KStream>(
        self_rc: &OptRc<Self>,
        _io: &S,
        _root: SharedType<Self::Root>,
        _parent: SharedType<Self::Parent>,
    ) -> KResult<()> {
        *self_rc._io.borrow_mut() = _io.clone();
        self_rc._root.set(_root.get());
        self_rc._parent.set(_parent.get());
        self_rc._self.set(Ok(self_rc.clone()));
        let _rrc = self_rc._root.get_value().borrow().upgrade();
        let _prc = self_rc._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        *self_rc.records.borrow_mut() = Vec::new();
        {
            let mut _i = 0;
            while !_io.is_eof() {
                let t = Self::read_into::<_, DepositsProtocol_TlvRecord>(
                    _io,
                    Some(self_rc._root.clone()),
                    None,
                )?;
                self_rc.records.borrow_mut().push(t);
                _i += 1;
            }
        }
        Ok(())
    }
}
impl DepositsProtocol_TlvStream {}
impl DepositsProtocol_TlvStream {
    pub fn records(&self) -> Ref<'_, Vec<OptRc<DepositsProtocol_TlvRecord>>> {
        self.records.borrow()
    }
}
impl DepositsProtocol_TlvStream {
    pub fn _io(&self) -> Ref<'_, BytesReader> {
        self._io.borrow()
    }
}

/**
 * Nested TLV for per-transfer fee schedule.
 * Field types:
 *   0 = fixed_msats (u64)
 *   2 = rate_bps (u16)
 */

#[derive(Default, Debug, Clone)]
pub struct DepositsProtocol_TransferFeeSchedule {
    pub _root: SharedType<DepositsProtocol>,
    pub _parent: SharedType<KStructUnit>,
    pub _self: SharedType<Self>,
    records: RefCell<Vec<OptRc<DepositsProtocol_TlvRecord>>>,
    _io: RefCell<BytesReader>,
}
impl KStruct for DepositsProtocol_TransferFeeSchedule {
    type Root = DepositsProtocol;
    type Parent = KStructUnit;

    fn read<S: KStream>(
        self_rc: &OptRc<Self>,
        _io: &S,
        _root: SharedType<Self::Root>,
        _parent: SharedType<Self::Parent>,
    ) -> KResult<()> {
        *self_rc._io.borrow_mut() = _io.clone();
        self_rc._root.set(_root.get());
        self_rc._parent.set(_parent.get());
        self_rc._self.set(Ok(self_rc.clone()));
        let _rrc = self_rc._root.get_value().borrow().upgrade();
        let _prc = self_rc._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        *self_rc.records.borrow_mut() = Vec::new();
        {
            let mut _i = 0;
            while !_io.is_eof() {
                let t = Self::read_into::<_, DepositsProtocol_TlvRecord>(
                    _io,
                    Some(self_rc._root.clone()),
                    None,
                )?;
                self_rc.records.borrow_mut().push(t);
                _i += 1;
            }
        }
        Ok(())
    }
}
impl DepositsProtocol_TransferFeeSchedule {}
impl DepositsProtocol_TransferFeeSchedule {
    pub fn records(&self) -> Ref<'_, Vec<OptRc<DepositsProtocol_TlvRecord>>> {
        self.records.borrow()
    }
}
impl DepositsProtocol_TransferFeeSchedule {
    pub fn _io(&self) -> Ref<'_, BytesReader> {
        self._io.borrow()
    }
}

/**
 * BigEndian varint (1/3/5/9 byte encoding, Lightning-compatible)
 */

#[derive(Default, Debug, Clone)]
pub struct DepositsProtocol_Varint {
    pub _root: SharedType<DepositsProtocol>,
    pub _parent: SharedType<DepositsProtocol_TlvRecord>,
    pub _self: SharedType<Self>,
    first_byte: RefCell<u8>,
    value_2: RefCell<u16>,
    value_4: RefCell<u32>,
    value_8: RefCell<u64>,
    _io: RefCell<BytesReader>,
    f_value: Cell<bool>,
    value: RefCell<u64>,
}
impl KStruct for DepositsProtocol_Varint {
    type Root = DepositsProtocol;
    type Parent = DepositsProtocol_TlvRecord;

    fn read<S: KStream>(
        self_rc: &OptRc<Self>,
        _io: &S,
        _root: SharedType<Self::Root>,
        _parent: SharedType<Self::Parent>,
    ) -> KResult<()> {
        *self_rc._io.borrow_mut() = _io.clone();
        self_rc._root.set(_root.get());
        self_rc._parent.set(_parent.get());
        self_rc._self.set(Ok(self_rc.clone()));
        let _rrc = self_rc._root.get_value().borrow().upgrade();
        let _prc = self_rc._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        *self_rc.first_byte.borrow_mut() = _io.read_u1()?;
        if *self_rc.first_byte() == 253 {
            *self_rc.value_2.borrow_mut() = _io.read_u2be()?;
        }
        if *self_rc.first_byte() == 254 {
            *self_rc.value_4.borrow_mut() = _io.read_u4be()?;
        }
        if *self_rc.first_byte() == 255 {
            *self_rc.value_8.borrow_mut() = _io.read_u8be()?;
        }
        Ok(())
    }
}
impl DepositsProtocol_Varint {
    pub fn value(&self) -> KResult<Ref<'_, u64>> {
        let _io = self._io.borrow();
        let _rrc = self._root.get_value().borrow().upgrade();
        let _prc = self._parent.get_value().borrow().upgrade();
        let _r = _rrc.as_ref().unwrap();
        if self.f_value.get() {
            return Ok(self.value.borrow());
        }
        self.f_value.set(true);
        *self.value.borrow_mut() = if *self.first_byte() == 255 {
            *self.value_8()
        } else if *self.first_byte() == 254 {
            *self.value_4() as u64
        } else if *self.first_byte() == 253 {
            *self.value_2() as u64
        } else {
            *self.first_byte() as u64
        };
        Ok(self.value.borrow())
    }
}
impl DepositsProtocol_Varint {
    pub fn first_byte(&self) -> Ref<'_, u8> {
        self.first_byte.borrow()
    }
}
impl DepositsProtocol_Varint {
    pub fn value_2(&self) -> Ref<'_, u16> {
        self.value_2.borrow()
    }
}
impl DepositsProtocol_Varint {
    pub fn value_4(&self) -> Ref<'_, u32> {
        self.value_4.borrow()
    }
}
impl DepositsProtocol_Varint {
    pub fn value_8(&self) -> Ref<'_, u64> {
        self.value_8.borrow()
    }
}
impl DepositsProtocol_Varint {
    pub fn _io(&self) -> Ref<'_, BytesReader> {
        self._io.borrow()
    }
}
