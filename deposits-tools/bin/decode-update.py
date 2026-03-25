#!/usr/bin/env python3
"""Decode and annotate a SignedLedgerUpdate TLV blob.

Reads raw bytes from stdin (pipe from base64 -d) or a base64 string,
and prints an annotated hexdump explaining every byte.

Tag definitions, discriminants, and message_type constants are loaded at
runtime from deposits-protocol/deposits_protocol.ksy (the Kaitai schema),
so this tool stays in sync automatically.

Usage:
  nak req ws://localhost:7779 | tail -n1 | jq -r .content | base64 -d | python3 bin/decode-update.py
  echo <base64> | python3 bin/decode-update.py --base64
  python3 bin/decode-update.py --relay ws://localhost:7779 [--filter '{"kinds":[30078]}'] [--last]
"""

import sys
import os
import re
import struct
import hashlib
import base64
import argparse
from collections import OrderedDict

# ── Color helpers ──────────────────────────────────────────────────────────────

USE_COLOR = sys.stdout.isatty()

def c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def dim(t):    return c("2", t)
def bold(t):   return c("1", t)
def cyan(t):   return c("36", t)
def green(t):  return c("32", t)
def yellow(t): return c("33", t)
def red(t):    return c("31", t)
def mag(t):    return c("35", t)

# ── BigEndian varint (Lightning TLV) ──────────────────────────────────────────

def read_varint(data, offset):
    """Read a BigEndian varint. Returns (value, bytes_consumed)."""
    if offset >= len(data):
        raise ValueError(f"EOF reading varint at offset {offset}")
    b = data[offset]
    if b < 0xFD:
        return b, 1
    elif b == 0xFD:
        return struct.unpack(">H", data[offset+1:offset+3])[0], 3
    elif b == 0xFE:
        return struct.unpack(">I", data[offset+1:offset+5])[0], 5
    else:
        return struct.unpack(">Q", data[offset+1:offset+9])[0], 9

# ── Load mappings from Kaitai schema ─────────────────────────────────────────

def _find_ksy():
    """Locate deposits_protocol.ksy relative to this script."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "../../deposits-protocol/deposits_protocol.ksy"),
        os.path.join(here, "../deposits-protocol/deposits_protocol.ksy"),
    ]
    for p in candidates:
        rp = os.path.realpath(p)
        if os.path.isfile(rp):
            return rp
    return None

def _infer_encoding(type_hint, field_name=""):
    """Map a .ksy type hint string to our internal encoding name."""
    t = type_hint.strip().lower()
    # Check the first token (before comma) for exact primitive types
    first = t.split(",")[0].strip()
    if first in ("u8", "u16", "u32", "u64"):
        return first
    if "witness" in field_name:
        return "witness"
    if "nested" in t:
        return "nested"
    if "string" in t or "bolt11" in t:
        return "string"
    if "16 bytes" in t:
        return "deposit_id"
    if "n*33" in t:
        return "pubkeys"
    if "33 bytes" in t or "33-byte" in t or "pubkey" in t:
        return "pubkey"
    if "64 bytes" in t or "64-byte" in t or "signature" in t:
        return "sig"
    if "32 bytes" in t or "32-byte" in t or "hash" in t or "20 bytes" in t:
        return "hash"
    return "bytes"

def _load_ksy_mappings(path):
    """Parse the .ksy raw text and extract all mappings."""
    with open(path) as f:
        text = f.read()

    # ── Discriminants: lines like "        1  = LedgerOpen" in ledger_operation doc
    op_discriminants = {}
    in_disc = False
    for line in text.split('\n'):
        if 'Discriminant values:' in line:
            in_disc = True
            continue
        if in_disc:
            m = re.match(r'\s+(\d+)\s*=\s*(\w+)', line)
            if m:
                op_discriminants[int(m.group(1))] = m.group(2)
            elif line.strip() and not re.match(r'\s+\d', line):
                in_disc = False

    # ── message_type constants: lines like "        0x8001 = LEDGER_UPDATE"
    msg_types = {}
    in_mt = False
    for line in text.split('\n'):
        if 'message_type constants' in line:
            in_mt = True
            continue
        if in_mt:
            m = re.match(r'\s+(0x[0-9a-fA-F]+)\s*=\s*(\w+)', line)
            if m:
                msg_types[int(m.group(1), 16)] = m.group(2)
            elif line.strip() and not re.match(r'\s+0x', line):
                in_mt = False

    # ── OP_TAGS from comment block: lines like "#   0   = discriminant (u8)"
    op_tags = {}
    for line in text.split('\n'):
        m = re.match(r'\s*#\s+(\d+)\s*=\s*(\w+)\s*\(([^)]+)\)', line)
        if m:
            tag = int(m.group(1))
            name = m.group(2)
            encoding = _infer_encoding(m.group(3), field_name=name)
            op_tags[tag] = (name, encoding)

    # ── SLU_TAGS from signed_ledger_update instances docs
    # Each instance has a doc like: "32-byte ledger identifier hash (type 6)"
    slu_tags = {}
    in_slu_type = False
    in_slu_instances = False
    current_name = None
    for line in text.split('\n'):
        # Detect entry into signed_ledger_update type definition
        if re.match(r'  signed_ledger_update:', line):
            in_slu_type = True
            continue
        # Detect exit (next type definition at same indent)
        if in_slu_type and re.match(r'  \w', line) and not re.match(r'  signed_ledger_update', line):
            if not re.match(r'\s', line) or re.match(r'  [a-z].*:', line):
                in_slu_type = False
                in_slu_instances = False
                continue
        if in_slu_type and re.match(r'\s+instances:', line):
            in_slu_instances = True
            continue
        if in_slu_instances:
            # Instance name line: "      message:"
            m = re.match(r'^\s{6}(\w+):\s*$', line)
            if m:
                current_name = m.group(1)
                continue
            # Doc line: '        doc: "... (type N)"'
            if current_name:
                m = re.search(r'\(type\s+(\d+)', line)
                if m:
                    tag = int(m.group(1))
                    # Infer encoding from name and doc
                    doc = line.lower()
                    if "tlv bytes" in doc or current_name == "message":
                        enc = "bytes"
                    elif "u16" in doc:
                        enc = "u16"
                    elif "u32" in doc:
                        enc = "u32"
                    elif "u64" in doc:
                        enc = "u64"
                    elif "pubkey" in doc or "33-byte" in doc:
                        enc = "pubkey"
                    elif "signature" in doc or "64-byte" in doc:
                        enc = "sig"
                    elif "32-byte" in doc or "hash" in doc:
                        enc = "hash"
                    else:
                        enc = "bytes"
                    slu_tags[tag] = (current_name, enc)
                    current_name = None

    # ── Fee tags from fee_structure doc: "  0 = annualized_msats (u64, ...)"
    fee_tags = {}
    in_fee = False
    for line in text.split('\n'):
        if re.match(r'\s+fee_structure:', line):
            in_fee = True
            continue
        if in_fee:
            m = re.match(r'\s+(\d+)\s*=\s*(\w+)\s*\(([^)]+)\)', line)
            if m:
                fee_tags[int(m.group(1))] = (m.group(2), _infer_encoding(m.group(3), m.group(2)))
            elif re.match(r'\s+seq:', line):
                in_fee = False

    # ── Transfer fee tags from transfer_fee_schedule doc
    xfer_fee_tags = {}
    in_xfee = False
    for line in text.split('\n'):
        if re.match(r'\s+transfer_fee_schedule:', line):
            in_xfee = True
            continue
        if in_xfee:
            m = re.match(r'\s+(\d+)\s*=\s*(\w+)\s*\(([^)]+)\)', line)
            if m:
                xfer_fee_tags[int(m.group(1))] = (m.group(2), _infer_encoding(m.group(3), m.group(2)))
            elif re.match(r'\s+seq:', line):
                in_xfee = False

    return slu_tags, msg_types, op_discriminants, op_tags, fee_tags, xfer_fee_tags

# ── Load from .ksy or fall back to minimal builtins ──────────────────────────

_ksy_path = _find_ksy()
if _ksy_path:
    SLU_TAGS, MSG_TYPES, OP_DISCRIMINANTS, OP_TAGS, FEE_TAGS, XFER_FEE_TAGS = \
        _load_ksy_mappings(_ksy_path)
else:
    print("warning: deposits_protocol.ksy not found, using minimal builtins",
          file=sys.stderr)
    SLU_TAGS = {
        0: ("operator_id", "pubkey"), 2: ("ledger_id", "hash"),
        4: ("sequence_number", "u64"), 6: ("previous_hash", "hash"),
        8: ("message", "bytes"),
        10: ("block_height", "u32"), 12: ("block_hash", "hash"),
        14: ("cosigner_pubkey", "pubkey"), 16: ("member_ledger_hash", "hash"),
        18: ("cosign_signature", "sig"), 20: ("operator_signature", "sig"),
    }
    MSG_TYPES = {}
    OP_DISCRIMINANTS = {}
    OP_TAGS = {0: ("discriminant", "u8")}
    FEE_TAGS = {}
    XFER_FEE_TAGS = {}

# ── Annotation engine ─────────────────────────────────────────────────────────

class Annotation:
    """A range of bytes with a label."""
    __slots__ = ("start", "end", "label", "depth")
    def __init__(self, start, end, label, depth=0):
        self.start = start
        self.end = end
        self.label = label
        self.depth = depth

class Decoder:
    def __init__(self, data, base_offset=0):
        self.data = data
        self.base = base_offset
        self.annotations = []

    def ann(self, start, end, label, depth=0):
        self.annotations.append(Annotation(self.base + start, self.base + end, label, depth))

    def format_value(self, val_bytes, encoding):
        """Format a value for display."""
        if encoding == "u8":
            return str(val_bytes[0]) if val_bytes else "0"
        elif encoding == "u16":
            v = int.from_bytes(val_bytes, "big") if val_bytes else 0
            return str(v)
        elif encoding == "u32":
            v = int.from_bytes(val_bytes, "big") if val_bytes else 0
            return f"{v} (0x{v:x})"
        elif encoding == "u64":
            v = int.from_bytes(val_bytes, "big") if val_bytes else 0
            if v < 100_000:
                return str(v)
            elif v < 100_000_000_000:  # < 1000 BTC in msats
                sats = v // 1000 if v > 100_000_000 else v
                return f"{v} ({sats:,} {'msats' if v > 100_000_000 else 'sats'})"
            return str(v)
        elif encoding == "pubkey":
            return val_bytes.hex()
        elif encoding in ("hash", "sig"):
            h = val_bytes.hex()
            if all(b == 0 for b in val_bytes):
                return "(zero)"
            return h[:16] + "..." if len(h) > 20 else h
        elif encoding == "deposit_id":
            return val_bytes.hex()
        elif encoding == "string":
            try:
                return repr(val_bytes.decode("utf-8"))
            except:
                return val_bytes.hex()
        return val_bytes.hex()

    def decode_tlv_stream(self, start, end, tag_map, depth=0, label_prefix=""):
        """Decode a TLV stream and annotate each record."""
        offset = start
        fields = OrderedDict()

        while offset < end:
            # Read tag
            tag, tag_size = read_varint(self.data, offset)
            tag_start = offset
            offset += tag_size

            # Read length
            length, len_size = read_varint(self.data, offset)
            offset += len_size

            # Value
            val_start = offset
            val_end = offset + length
            val_bytes = self.data[val_start:val_end]
            offset = val_end

            # Look up tag
            if tag in tag_map:
                name, encoding = tag_map[tag]
            else:
                name, encoding = f"unknown_{tag}", "bytes"

            # Format the value
            display = self.format_value(val_bytes, encoding)

            # Special: message_type lookup
            if name == "message_type" and encoding == "u16":
                mt = int.from_bytes(val_bytes, "big") if val_bytes else 0
                mt_name = MSG_TYPES.get(mt, f"0x{mt:04x}")
                display = f"0x{mt:04x} = {mt_name}"

            # Special: discriminant lookup
            if name == "discriminant" and encoding == "u8":
                d = val_bytes[0]
                d_name = OP_DISCRIMINANTS.get(d, f"unknown({d})")
                display = f"{d} = {d_name}"

            full_name = f"{label_prefix}{name}" if label_prefix else name

            # Annotate tag+length header
            self.ann(tag_start, val_start,
                     f"{cyan(f'tag={tag}')} {dim(f'len={length}')}  {bold(full_name)}",
                     depth)

            # Annotate value
            if encoding == "nested":
                self.ann(val_start, val_end,
                         f"{green(full_name)} {dim('(nested TLV)')}", depth)
                # Determine which tag map to use for nested content
                if name in ("fees", "new_fees"):
                    nested_tags = FEE_TAGS
                elif name == "transfer_fees":
                    nested_tags = XFER_FEE_TAGS
                else:
                    nested_tags = OP_TAGS
                self.decode_tlv_stream(val_start, val_end, nested_tags, depth + 1, f"{name}.")
            elif encoding == "bytes" and name == "message":
                self.ann(val_start, val_end,
                         f"{green('message')} {dim(f'({length} bytes, inner TLV)')}", depth)
                # Decode inner message as LedgerOperation TLV
                self.decode_tlv_stream(val_start, val_end, OP_TAGS, depth + 1, "op.")
            elif encoding == "witness":
                self.decode_witness(val_start, val_end, full_name, depth)
            elif encoding == "pubkeys":
                # Concatenated 33-byte pubkeys
                n = length // 33
                self.ann(val_start, val_end,
                         f"{yellow(display)}  {dim(f'({n} pubkeys)')}", depth)
            else:
                self.ann(val_start, val_end, f"{yellow(display)}", depth)

            fields[name] = val_bytes

        return fields

    def decode_witness(self, start, end, name, depth):
        """Decode a witness field: varint(count) || (varint(len) || bytes)*"""
        offset = start
        count, sz = read_varint(self.data, offset)
        self.ann(offset, offset + sz, f"{name}: {count} element(s)", depth)
        offset += sz
        for i in range(count):
            elem_len, sz = read_varint(self.data, offset)
            self.ann(offset, offset + sz, dim(f"  elem[{i}] len={elem_len}"), depth)
            offset += sz
            elem_hex = self.data[offset:offset+elem_len].hex()
            display = elem_hex[:32] + "..." if len(elem_hex) > 36 else elem_hex
            self.ann(offset, offset + elem_len, f"  {yellow(display)}", depth)
            offset += elem_len

    def decode_signed_ledger_update(self):
        """Top-level decode."""
        fields = self.decode_tlv_stream(0, len(self.data), SLU_TAGS, depth=0)

        # Compute current_hash (not on wire)
        seq_bytes = fields.get("sequence_number", b"\x00" * 8)
        prev_hash = fields.get("previous_hash", b"\x00" * 32)
        message = fields.get("message", b"")
        member_hash = fields.get("member_ledger_hash")
        cosign_sig = fields.get("cosign_signature")

        seq_le = struct.pack("<Q", struct.unpack(">Q", seq_bytes)[0])
        h_input = seq_le + prev_hash + message
        if member_hash:
            h_input += member_hash
        if cosign_sig and any(b != 0 for b in cosign_sig):
            h_input += cosign_sig
        current_hash = hashlib.sha256(h_input).digest()

        # Compute chain_hash
        op_sig = fields.get("operator_signature", b"\x00" * 64)
        chain_hash = hashlib.sha256(current_hash + op_sig).digest()

        return fields, current_hash, chain_hash

    def print_annotated(self):
        """Print the annotated hexdump."""
        # Sort annotations by start position
        self.annotations.sort(key=lambda a: (a.start, -a.depth))

        # Build annotation index: for each byte offset, the annotation(s) covering it
        # We'll print one annotation line per annotation range
        printed = set()
        lines = []

        for ann in self.annotations:
            if ann.start in printed:
                continue
            printed.add(ann.start)

            start = ann.start
            end = ann.end
            chunk = self.data[start:end]
            indent = "  " * ann.depth

            # Format hex bytes (max ~24 bytes per line for readability)
            hex_parts = []
            for i in range(0, len(chunk), 16):
                hex_parts.append(" ".join(f"{b:02x}" for b in chunk[i:i+16]))

            offset_str = f"{start:04x}"

            if len(chunk) <= 16:
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                lines.append(f"  {dim(offset_str)}  {hex_str:<48s}  {indent}{ann.label}")
            else:
                # First line with annotation
                first = " ".join(f"{b:02x}" for b in chunk[:16])
                lines.append(f"  {dim(offset_str)}  {first:<48s}  {indent}{ann.label}")
                # Continuation lines
                for i in range(16, len(chunk), 16):
                    cont_hex = " ".join(f"{b:02x}" for b in chunk[i:i+16])
                    cont_off = f"{start+i:04x}"
                    lines.append(f"  {dim(cont_off)}  {cont_hex}")

        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Decode and annotate a SignedLedgerUpdate TLV blob",
        epilog="Examples:\n"
               "  nak req ws://localhost:7779 | tail -n1 | jq -r .content | base64 -d | %(prog)s\n"
               "  echo <base64> | %(prog)s --base64\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--base64", "-b", action="store_true",
                        help="Input is base64-encoded (not raw bytes)")
    parser.add_argument("--hex", action="store_true",
                        help="Input is hex-encoded")
    parser.add_argument("--dump-maps", action="store_true",
                        help="Print loaded mappings and exit (for debugging)")
    parser.add_argument("file", nargs="?", default="-",
                        help="File to read (default: stdin)")
    args = parser.parse_args()

    if args.dump_maps:
        print(f"ksy: {_ksy_path or '(not found)'}")
        print(f"\nSLU_TAGS ({len(SLU_TAGS)}):")
        for k, v in sorted(SLU_TAGS.items()):
            print(f"  {k:>3}: {v}")
        print(f"\nMSG_TYPES ({len(MSG_TYPES)}):")
        for k, v in sorted(MSG_TYPES.items()):
            print(f"  0x{k:04x}: {v}")
        print(f"\nOP_DISCRIMINANTS ({len(OP_DISCRIMINANTS)}):")
        for k, v in sorted(OP_DISCRIMINANTS.items()):
            print(f"  {k:>3}: {v}")
        print(f"\nOP_TAGS ({len(OP_TAGS)}):")
        for k, v in sorted(OP_TAGS.items()):
            print(f"  {k:>3}: {v}")
        print(f"\nFEE_TAGS ({len(FEE_TAGS)}):")
        for k, v in sorted(FEE_TAGS.items()):
            print(f"  {k:>3}: {v}")
        print(f"\nXFER_FEE_TAGS ({len(XFER_FEE_TAGS)}):")
        for k, v in sorted(XFER_FEE_TAGS.items()):
            print(f"  {k:>3}: {v}")
        return

    # Read input
    if args.file == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(args.file, "rb") as f:
            data = f.read()

    if args.base64 or (not args.hex and all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r\t " for c in data) and len(data) > 20):
        data = base64.b64decode(data)
    elif args.hex:
        data = bytes.fromhex(data.decode().strip())

    if not data:
        print("No input data", file=sys.stderr)
        sys.exit(1)

    print(f"\n{bold('SignedLedgerUpdate')} ({len(data)} bytes)\n")

    dec = Decoder(data)
    fields, current_hash, chain_hash = dec.decode_signed_ledger_update()
    print(dec.print_annotated())

    # Summary
    print(f"\n{bold('--- Derived ---')}")
    print(f"  current_hash:  {current_hash.hex()[:16]}...")
    print(f"  chain_hash:    {chain_hash.hex()[:16]}...")

    seq = struct.unpack(">Q", fields.get("sequence_number", b"\x00"*8))[0]
    # Derive message type from inner operation discriminant
    message = fields.get("message", b"")
    if len(message) >= 3 and message[0] == 0 and message[1] == 1:
        disc = message[2]
        disc_name = OP_DISCRIMINANTS.get(disc, f"disc={disc}")
    else:
        disc_name = "unknown"
    lid = fields.get("ledger_id", b"").hex()
    print(f"  seq={seq}  type={disc_name}  ledger={lid[:16]}...")
    print()


if __name__ == "__main__":
    main()
