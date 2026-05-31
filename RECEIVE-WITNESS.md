# Receive-witness wire format

Authorization shape for inbound credits to a deposit whose
`receive_requires_sig = true`. Two call sites consume this format:

- `make_invoice` and `make_offer` (invoice / on-chain offer creation against
  a deposit that gates receives)
- transfer-release (destination side, when the receiving deposit gates
  receives)

This is what wallets MUST produce in the `receive_witness` request
parameter. The matching node-side verification lives in
`deposits_core::dep16::Dep16Authorizer::authorize_receive`.

## JSON shape

```json
{
  "nonce":   <u64>,
  "expiry":  <u32>,
  "signatures": {
    "<33-byte compressed pubkey, hex>": "<64-byte ECDSA compact sig, hex>",
    ...
  }
}
```

- **`nonce`** — per-deposit replay counter. The wallet chooses; the node
  binds it into the signed preimage. Future phase 3 will reject
  `nonce ≤ last_seen` for the deposit.
- **`expiry`** — absolute block height after which the signature is no
  longer accepted. The node rejects if `expiry < current_chain_tip`.
- **`signatures`** — one entry per signing key the descriptor needs.
  Single-key descriptors carry one; threshold descriptors carry one
  per signing participant. Keys not present in the descriptor are
  ignored. Order is irrelevant (the node treats it as a set).

The hex values are lowercase, no `0x` prefix, no length prefix beyond
hex's implicit one. Signatures are the 64-byte compact ECDSA encoding
(libsecp256k1's `serialize_compact`), low-s normalized as libsecp256k1
produces by default. Schnorr signatures are NOT accepted at this site;
the dep-16 receive path is ECDSA-only as of phase 5.

## What gets signed

The signature is over the BIP-340 tagged hash of the **receive operation
preimage**:

```
sighash = SHA256( SHA256("dep17/operation") ||
                  SHA256("dep17/operation") ||
                  preimage_bytes )
```

The preimage construction is deterministic and version-tagged. To produce
it, build the following bytes in order (all big-endian):

```
1 byte:    0x01                     // version
32 bytes:  deposit_id || zeros      // zero-extended from 16-byte protocol id
4 bytes:   u32 BE: length of "receive"
7 bytes:   ASCII "receive"          // op_type symbol
4 bytes:   u32 BE: args count
            // For invoice / make_offer (no transfer): args count = 0
            // For transfer-release receive: args count = 1, with:
            //   4 bytes: u32 BE: length of "transfer_id" = 11
            //   11 bytes: ASCII "transfer_id"
            //   1 byte: 0x03   (value tag: Bytes)
            //   4 bytes: u32 BE: length of transfer_id bytes
            //   N bytes: transfer_id bytes (32 in the current protocol)
8 bytes:   u64 BE: nonce
4 bytes:   u32 BE: expiry
```

Then `sighash = tagged_hash("dep17/operation", preimage_bytes)`.

The wallet signs `sighash` with libsecp256k1 ECDSA, serializes to
64-byte compact form, hex-encodes, and puts it in `signatures` keyed by
the compressed public key (33 bytes hex).

The reference implementation is `deposits_core::dep16::operations::receive_op`
plus `miniscript::calculus::operation_preimage` + `operation_sighash` —
this spec is just those functions written out.

## Multi-signer descriptors

`pk_threshold(k, [K1, K2, ..., Kn])` and `pk_any([K1, ..., Kn])` need
multiple signatures. The wallet collects them out-of-band (signers each
produce a sig over the same preimage), then assembles `signatures` with
one entry per signing participant. The node accepts iff the descriptor's
threshold can be satisfied by the entries' keys.

A signature whose key isn't referenced by the descriptor is silently
ignored (not a failure mode). A `signatures` value with malformed key or
sig hex causes the entire witness to be rejected.

## Failure modes (node-side)

The node returns a request error in these cases. The error string is
indicative — wallets should NOT parse the string for control flow; treat
any non-empty error from the request handler as "receive witness was
rejected" and surface to the user.

- `receive_witness` parameter missing
- JSON shape doesn't match (missing field, wrong type)
- `expiry < current_chain_tip` (signature has aged out)
- A signature hex is not 64 bytes after decode
- A key hex is not 33 bytes after decode
- No combination of provided signatures satisfies the descriptor's
  threshold (ECDSA verify failed against the preimage, or the descriptor
  needed more signers than were provided)

## End-to-end example

Inputs:
- `deposit_id` = `0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC` (16 bytes)
- Descriptor: `wsh(prove(pk(<K>)))` where K = single owner key
- `nonce` = 1
- `expiry` = `0xFFFFFFFF` (effectively never expires)
- Not a transfer-release (so `transfer_id` arg absent)

Preimage bytes (89 bytes total):

```
01                                                                    // version
CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC                      // deposit_id (16 bytes)
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00                      // zero-padding to 32 bytes
00 00 00 07                                                          // op_type length = 7
72 65 63 65 69 76 65                                                 // "receive"
00 00 00 00                                                          // args count = 0
00 00 00 00 00 00 00 01                                              // nonce = 1
FF FF FF FF                                                          // expiry
```

`sighash = tagged_hash("dep17/operation", preimage_bytes)`, where
`tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)`.

Wallet signs `sighash` with libsecp256k1 ECDSA, gets a 64-byte compact
signature. Wraps in:

```json
{
  "nonce": 1,
  "expiry": 4294967295,
  "signatures": {
    "02xxxxxxxx...": "yyyyyyyy..."
  }
}
```

Sends as the `receive_witness` field of the make_invoice / make_offer
request params.

## Transfer-release variant

When the request is a transfer release (NOT make_invoice / make_offer),
the receive op carries `transfer_id` in args. Same preimage construction
except the args section is:

```
00 00 00 01                                  // args count = 1
00 00 00 0B                                  // arg name length = 11
74 72 61 6E 73 66 65 72 5F 69 64             // "transfer_id"
03                                           // value tag: Bytes
00 00 00 20                                  // bytes length = 32 (current protocol)
<32 bytes>                                   // transfer_id
```

`transfer_id` length is whatever the transfer protocol uses (32 bytes
today, but the encoding is length-prefixed so a future change doesn't
break this format). The wallet receives `transfer_id` from the transfer
release context; it's not chosen by the wallet.

## Reference implementations

Node-side verification:
- `deposits_core::dep16::Dep16Authorizer::authorize_receive`
- `deposits_core::dep16::operations::receive_op`
- `deposits_core::dep16::operations::receive_op_sighash`

Underlying calculus:
- `miniscript::calculus::operation_preimage` (preimage encoding)
- `miniscript::calculus::operation_sighash` (tagged hash)

A worked example using these functions is in
`deposits-core/examples/receive_auth.rs`.
