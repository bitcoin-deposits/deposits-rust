// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['exports', 'kaitai-struct/KaitaiStream'], factory);
  } else if (typeof exports === 'object' && exports !== null && typeof exports.nodeType !== 'number') {
    factory(exports, require('kaitai-struct/KaitaiStream'));
  } else {
    factory(root.DepositsProtocol || (root.DepositsProtocol = {}), root.KaitaiStream);
  }
})(typeof self !== 'undefined' ? self : this, function (DepositsProtocol_, KaitaiStream) {
/**
 * Bitcoin Deposits Protocol wire format. All structures use TLV (Type-Length-Value)
 * encoding with BigEndian varints, compatible with Lightning Network TLV format.
 * 
 * Fields are ordered by type number. Even types are required, odd are optional.
 * Unknown fields are preserved for forward compatibility.
 */

var DepositsProtocol = (function() {
  function DepositsProtocol(_io, _parent, _root) {
    this._io = _io;
    this._parent = _parent;
    this._root = _root || this;

    this._read();
  }
  DepositsProtocol.prototype._read = function() {
    this.body = new SignedLedgerUpdate(this._io, this, this._root);
  }

  /**
   * Nested TLV for fee structure (annualized).
   * Field types:
   *   0 = annualized_fixed (u64, msat/year)
   *   2 = annualized_bps (u16, basis points/year)
   *   4 = frequency_blocks (u32, collection period)
   */

  var FeeStructure = DepositsProtocol.FeeStructure = (function() {
    function FeeStructure(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root;

      this._read();
    }
    FeeStructure.prototype._read = function() {
      this.records = [];
      var i = 0;
      while (!this._io.isEof()) {
        this.records.push(new TlvRecord(this._io, this, this._root));
        i++;
      }
    }

    return FeeStructure;
  })();

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
   *   42 = CollateralAttestation
   *   43 = QuorumAddMember
   *   44 = QuorumRemoveMember
   *   45 = CollateralLock
   *   46 = QuorumJoin
   *   50 = FeeCollect
   *   54 = CustodyDispute
   *   55 = CustodyAcquire
   *   56 = CustodyYield
   *   57 = CustodyArmed
   *   60 = LedgerClose
   *   61 = Tombstone
   *   70 = TransferLock
   *   71 = TransferComplete
   *   72 = TransferTimeout
   */

  var LedgerOperation = DepositsProtocol.LedgerOperation = (function() {
    function LedgerOperation(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root;

      this._read();
    }
    LedgerOperation.prototype._read = function() {
      this.records = [];
      var i = 0;
      while (!this._io.isEof()) {
        this.records.push(new TlvRecord(this._io, this, this._root));
        i++;
      }
    }

    /**
     * Operation type (type 0, 1 byte)
     */
    Object.defineProperty(LedgerOperation.prototype, 'discriminant', {
      get: function() {
        if (this._m_discriminant !== undefined)
          return this._m_discriminant;
        this._m_discriminant = this.records[0].value[0];
        return this._m_discriminant;
      }
    });

    return LedgerOperation;
  })();

  /**
   * A signed ledger update, broadcast as Kind 9100 Nostr events.
   * Contains the inner operation (as TLV bytes), metadata, and signatures.
   */

  var SignedLedgerUpdate = DepositsProtocol.SignedLedgerUpdate = (function() {
    function SignedLedgerUpdate(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root;

      this._read();
    }
    SignedLedgerUpdate.prototype._read = function() {
      this.records = [];
      var i = 0;
      while (!this._io.isEof()) {
        this.records.push(new TlvRecord(this._io, this, this._root));
        i++;
      }
    }

    /**
     * 32-byte hash of this update (type 12)
     */
    Object.defineProperty(SignedLedgerUpdate.prototype, 'currentHash', {
      get: function() {
        if (this._m_currentHash !== undefined)
          return this._m_currentHash;
        this._m_currentHash = this.records[6].value;
        return this._m_currentHash;
      }
    });

    /**
     * 32-byte ledger identifier hash (type 6)
     */
    Object.defineProperty(SignedLedgerUpdate.prototype, 'ledgerId', {
      get: function() {
        if (this._m_ledgerId !== undefined)
          return this._m_ledgerId;
        this._m_ledgerId = this.records[3].value;
        return this._m_ledgerId;
      }
    });

    /**
     * Inner LedgerOperation TLV bytes (type 0)
     */
    Object.defineProperty(SignedLedgerUpdate.prototype, 'message', {
      get: function() {
        if (this._m_message !== undefined)
          return this._m_message;
        this._m_message = this.records[0].value;
        return this._m_message;
      }
    });

    /**
     * Protocol message type constant (type 2)
     */
    Object.defineProperty(SignedLedgerUpdate.prototype, 'messageType', {
      get: function() {
        if (this._m_messageType !== undefined)
          return this._m_messageType;
        this._m_messageType = this.records[1].value;
        return this._m_messageType;
      }
    });

    /**
     * Operator's 33-byte compressed secp256k1 pubkey (type 4)
     */
    Object.defineProperty(SignedLedgerUpdate.prototype, 'operatorId', {
      get: function() {
        if (this._m_operatorId !== undefined)
          return this._m_operatorId;
        this._m_operatorId = this.records[2].value;
        return this._m_operatorId;
      }
    });

    /**
     * 64-byte Schnorr signature from operator (type 18)
     */
    Object.defineProperty(SignedLedgerUpdate.prototype, 'operatorSignature', {
      get: function() {
        if (this._m_operatorSignature !== undefined)
          return this._m_operatorSignature;
        this._m_operatorSignature = this.records[9].value;
        return this._m_operatorSignature;
      }
    });

    /**
     * 64-byte ECDSA signature from co-signing partner (type 16)
     */
    Object.defineProperty(SignedLedgerUpdate.prototype, 'partnerSignature', {
      get: function() {
        if (this._m_partnerSignature !== undefined)
          return this._m_partnerSignature;
        this._m_partnerSignature = this.records[8].value;
        return this._m_partnerSignature;
      }
    });

    /**
     * 32-byte hash of the previous update (type 10)
     */
    Object.defineProperty(SignedLedgerUpdate.prototype, 'previousHash', {
      get: function() {
        if (this._m_previousHash !== undefined)
          return this._m_previousHash;
        this._m_previousHash = this.records[5].value;
        return this._m_previousHash;
      }
    });

    /**
     * Monotonically increasing sequence number (type 8)
     */
    Object.defineProperty(SignedLedgerUpdate.prototype, 'sequenceNumber', {
      get: function() {
        if (this._m_sequenceNumber !== undefined)
          return this._m_sequenceNumber;
        this._m_sequenceNumber = this.records[4].value;
        return this._m_sequenceNumber;
      }
    });

    /**
     * Unix timestamp in seconds (type 14)
     */
    Object.defineProperty(SignedLedgerUpdate.prototype, 'timestamp', {
      get: function() {
        if (this._m_timestamp !== undefined)
          return this._m_timestamp;
        this._m_timestamp = this.records[7].value;
        return this._m_timestamp;
      }
    });

    return SignedLedgerUpdate;
  })();

  /**
   * A single TLV record (type, length, value)
   */

  var TlvRecord = DepositsProtocol.TlvRecord = (function() {
    function TlvRecord(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root;

      this._read();
    }
    TlvRecord.prototype._read = function() {
      this.type = new Varint(this._io, this, this._root);
      this.length = new Varint(this._io, this, this._root);
      this.value = this._io.readBytes(this.length.value);
    }

    return TlvRecord;
  })();

  /**
   * A sequence of TLV records, ordered by type
   */

  var TlvStream = DepositsProtocol.TlvStream = (function() {
    function TlvStream(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root;

      this._read();
    }
    TlvStream.prototype._read = function() {
      this.records = [];
      var i = 0;
      while (!this._io.isEof()) {
        this.records.push(new TlvRecord(this._io, this, this._root));
        i++;
      }
    }

    return TlvStream;
  })();

  /**
   * Nested TLV for per-transfer fee schedule.
   * Field types:
   *   0 = fixed_sats (u64)
   *   2 = rate_bps (u16)
   */

  var TransferFeeSchedule = DepositsProtocol.TransferFeeSchedule = (function() {
    function TransferFeeSchedule(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root;

      this._read();
    }
    TransferFeeSchedule.prototype._read = function() {
      this.records = [];
      var i = 0;
      while (!this._io.isEof()) {
        this.records.push(new TlvRecord(this._io, this, this._root));
        i++;
      }
    }

    return TransferFeeSchedule;
  })();

  /**
   * BigEndian varint (1/3/5/9 byte encoding, Lightning-compatible)
   */

  var Varint = DepositsProtocol.Varint = (function() {
    function Varint(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root;

      this._read();
    }
    Varint.prototype._read = function() {
      this.firstByte = this._io.readU1();
      if (this.firstByte == 253) {
        this.value2 = this._io.readU2be();
      }
      if (this.firstByte == 254) {
        this.value4 = this._io.readU4be();
      }
      if (this.firstByte == 255) {
        this.value8 = this._io.readU8be();
      }
    }
    Object.defineProperty(Varint.prototype, 'value', {
      get: function() {
        if (this._m_value !== undefined)
          return this._m_value;
        this._m_value = (this.firstByte == 255 ? this.value8 : (this.firstByte == 254 ? this.value4 : (this.firstByte == 253 ? this.value2 : this.firstByte)));
        return this._m_value;
      }
    });

    return Varint;
  })();

  return DepositsProtocol;
})();
DepositsProtocol_.DepositsProtocol = DepositsProtocol;
});
