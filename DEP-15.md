# DEP-15: Anonymous Web-of-Trust Ring Signatures

## Abstract

This document specifies a ring-signature scheme over secp256k1 that lets a wallet prove membership in a verifier-published "cover" of trusted public keys without revealing which member it is, then bind a fresh per-attestation pseudonym to the proof so subsequent requests authenticate by the bound key alone. This is the cryptographic core of the `ringsig` verification method in DEP-14: an operator can require that `deposit_open` requesters be inside the verifier's social graph, while learning nothing about *which* graph member each requester is.

The protocol guarantees exactly one cryptographic property: a valid signature was produced over a specified set of Nostr public keys. Policy decisions — which sets are acceptable, how pseudonyms accumulate reputation, when to rotate a cover — are verifier-side and out of scope.

## Motivation

DEP-14 specifies attestation methods that all link an npub to some externally-observable identity (a lightning address, a manually-allowlisted vouching account). For deployments where the *anonymity set* is itself the access criterion — "anyone the operator's social graph trusts, but we don't need to know who" — those methods leak too much. A ring signature over a cover of follow lists provides exactly that property: a wallet proves it controls at least one of `n` public keys without revealing which, the verifier issues an attestation pinned to a bound-pubkey pseudonym, and the operator never sees the underlying ring-member identity.

## Terminology

- **Anchor** — the verifier's xonly public key, used as the root of the web-of-trust closure.
- **`F_0`** — the set of public keys the anchor follows, per the anchor's most recent `kind:3` event at or before a pinned timestamp.
- **`R_max`** — the depth-2 closure of follows from the anchor, excluding the anchor itself.
- **Cover** — a published collection of subsets `{S_1, ..., S_m}` with each `S_i ⊆ R_max`. The verifier publishes the cover; requesters sign over one `S_i`.
- **Ring** — the specific `S_i` chosen for a given signature.
- **Key image** `I` — the bLSAG linkability handle, deterministic in `(sk, P_π)` where `P_π` is the signer's ring-member pubkey and `sk` its secret. 33-byte compressed encoding.
- **Nullifier** — a 32-byte hash derived from `I` and a per-cover context separator. Used as a wire-format / index handle; **linkability lives on `I`**, not on this hash.
- **Bound pubkey** `P` — a fresh secp256k1 pubkey declared at first contact, cryptographically tied to the same `sk` that produced the ring signature. Subsequent requests from the same pseudonym are signed by `P`.

## Cryptographic Primitives

All primitives operate over secp256k1, the curve underlying BIP-340 Schnorr signatures in Nostr. Every Nostr `npub` is directly usable as a ring member without conversion.

### Tagged Hashes

All domain-separated hashes follow the BIP-340 tagged-hash construction:

```
H_τ(data) = SHA256(SHA256(τ) || SHA256(τ) || data)
```

The tags used in this DEP are:

- `"DepositsRingSig/v1/hash-to-curve"`
- `"DepositsRingSig/v1/challenge"`
- `"DepositsRingSig/v1/nullifier"`
- `"DepositsRingSig/v1/binding"`

### Hash-to-Curve

`H_p` maps a byte string to a secp256k1 point. Implementations SHOULD use try-and-increment seeded by the tagged hash:

```
H_p(input):
    for counter in 0, 1, 2, ...:
        x = H_τ("DepositsRingSig/v1/hash-to-curve", input || u32_le(counter))
        if x is a valid affine x-coordinate on secp256k1:
            return lift_x(x)              # even-y, per BIP-340
```

Try-and-increment's variable timing is acceptable here because the input is exclusively public — a ring member's public key — so timing leaks no secret.

### Ring Signature Scheme

Senders produce ring signatures using **bLSAG** (Back-linkable Linkable Spontaneous Anonymous Group signatures) adapted to secp256k1. The scheme provides:

- Signer anonymity within the ring (unconditional).
- A key image `I` deterministic in `(sk, P_π)`.
- Linear signature size: approximately `32·(n+1)` bytes for a ring of size `n`.

The challenge chain is computed with the tagged hash `"DepositsRingSig/v1/challenge"` over `(L_i || R_i || message_digest)` at each ring index, in standard bLSAG fashion.

Implementations MAY substitute a logarithmic-size alternative (e.g. Groth–Kohlweiss) provided the key-image and verification semantics are preserved.

### Key Image and Nullifier

The bLSAG key image is the linkability mechanism:

```
I = sk · H_p(encode(P_π))
```

where `encode(P)` is the 33-byte compressed encoding of `P`. `I` is itself encoded as 33 bytes compressed for transit, hashing, and storage. **All linkability checks are performed on `I`** — recomputed by the verifier during signature verification, then matched against state.

The 32-byte `nullifier` carried in event tags is a *presentation derivation* of `I`:

```
nullifier = H_τ("DepositsRingSig/v1/nullifier", encode(I) || ctx)
```

with `ctx` defined under "Domain Separator for Nullifier" below. This hash is a wire-format convenience: 32 bytes is the size Nostr clients expect, and it lets the verifier index continuation events without re-running the ring-signature check. Linkability authority remains on `I`.

A verifier MUST reject a first-contact event whose recomputed `I` is already bound (under the same `(anchor, cover)` pair) to a different bound pubkey, regardless of whether the published `nullifier` happens to match.

### Bound Pubkey

At first contact the signer declares a fresh secp256k1 public key `P` and proves, as part of the same signature ceremony, that `P` is controlled by the same `sk` that produced the ring signature and key image. Subsequent requests under the same pseudonym are signed under `P` as ordinary BIP-340 events; no further ring signature is required.

The binding proof and ring signature are combined into a single zero-knowledge statement so that `P` itself reveals no information about which ring member the signer is. The challenge for the binding proof uses the tag `"DepositsRingSig/v1/binding"`.

## Event Kinds

The kind numbers below sit alongside the Kind 25500/25501 verify pair and Kind 55502 durable attestation defined in DEP-14:

| Kind  | Class                       | Direction              | Purpose                                       |
|-------|-----------------------------|------------------------|-----------------------------------------------|
| 25502 | ephemeral                   | requester → verifier   | Ringsig request (first-contact OR continuation) |
| 25503 | ephemeral                   | verifier → requester   | Ringsig response (correlated via `e` tag)     |
| 35500 | parameterized replaceable   | verifier published     | Cover                                         |
| 55502 | durable                     | verifier published     | Attestation (DEP-14, with `method: "ringsig"`) |

### Kind 35500 — Cover Publication

Published by the verifier; replaceable by a later event with the same `d` tag. Advertises the currently-acceptable rings.

```json
{
  "kind": 35500,
  "pubkey": "<verifier xonly>",
  "created_at": <unix ts>,
  "tags": [
    ["d", "<cover-version-id>"],
    ["snapshot", "<unix ts T>"],
    ["k_min", "<minimum ring size>"],
    ["ring", "<ring-id-1>", "<pk_1>", "<pk_2>", "..."],
    ["ring", "<ring-id-2>", "<pk_1>", "<pk_3>", "..."]
  ],
  "content": "<optional human-readable description>"
}
```

- `d` distinguishes concurrent covers (e.g. for different request contexts) from the same anchor.
- `snapshot` pins the timestamp `T` against which each follower's `kind:3` was evaluated.
- `k_min` is the minimum acceptable ring size. Clients SHOULD reject any ring smaller regardless of cover contents.
- Each `ring` tag enumerates one `S_i`: a ring identifier followed by hex public keys. Members MUST be sorted lexicographically and deduplicated.

A verifier with no published cover cannot accept ringsig requests. Implementations MAY provide a default cover-generation policy; see "Cover Construction" below.

### Kind 25502 — Ringsig Request

Published by the requester. The `action` field on the rumor (carried as JSON in `content`) selects the path:

#### `action: "first_contact"`

Establishes a pseudonym. Carries the ring signature and binding proof; signed by the *bound* pubkey `P`.

```json
{
  "kind": 25502,
  "pubkey": "<bound pubkey P>",
  "created_at": <unix ts>,
  "tags": [
    ["anchor", "<verifier xonly>"],
    ["cover", "<cover d-tag>", "<cover event id>"],
    ["ring", "<ring-id>"],
    ["nullifier", "<32-byte hex>"],
    ["ringsig", "<hex-encoded ring signature>"],
    ["binding", "<hex-encoded bound-pubkey proof>"]
  ],
  "content": "{\"action\":\"first_contact\", ...}",
  "sig": "<BIP-340 sig by P over the event id>"
}
```

- `pubkey` is the bound pubkey `P`, *not* the signer's underlying Nostr identity.
- `anchor` names the verifier whose cover is in use.
- `cover` references the cover event by `d`-tag and event id.
- `ring` identifies which `S_i` was signed over.
- `nullifier` is the 32-byte presentation hash.
- `ringsig` is the bLSAG signature: 33-byte `I` || 32-byte `c_0` || `n` × 32-byte responses, all hex.
- `binding` is the bound-pubkey proof: 33-byte `R` || 32-byte `s`, all hex.
- `sig` is an ordinary BIP-340 signature by `P` as with any Nostr event.

#### `action: "continuation"`

Authenticated solely by `P`; carries no ring signature. The verifier looks up `nullifier` in local state and confirms the event's `pubkey` matches the recorded `P`.

```json
{
  "kind": 25502,
  "pubkey": "<bound pubkey P>",
  "tags": [
    ["anchor", "<verifier xonly>"],
    ["nullifier", "<32-byte hex>"]
  ],
  "content": "{\"action\":\"continuation\", ...}"
}
```

### Kind 25503 — Ringsig Response

Published by the verifier in reply to a 25502, correlated via the `e` tag (event id of the request). Routed to the requester via the `#p` tag carrying the bound pubkey.

```json
{
  "kind": 25503,
  "pubkey": "<verifier xonly>",
  "tags": [
    ["e", "<request event id>"],
    ["p", "<bound pubkey P>"]
  ],
  "content": "{\"status\":\"accepted\"|\"rejected\", ...}"
}
```

The body schema is verifier-policy-specific. Implementations SHOULD include at least:

- `status`: `"accepted"` or `"rejected"`.
- For accepted first-contact: an `attestation_event_id` (Kind 55502, see DEP-14) the verifier published, so the wallet can avoid re-fetching.
- For rejected: a `code` and `message` describing the failure.

## Canonicalization

### Ring Member Ordering

Within any `ring` tag of a Kind 35500 cover, public keys MUST be sorted lexicographically as 32-byte hex strings and deduplicated. The cover publication is authoritative; requesters MUST NOT reconstruct the ring independently.

### Self-Exclusion

`R_max` MUST exclude the anchor itself. A verifier cannot sign a request to themselves under this scheme.

### Digest for Ring Signature

The ring signature covers a canonical digest computed as SHA-256 of the JSON serialization:

```
[
  0,
  <bound pubkey P, hex>,
  <created_at>,
  <kind>,
  <tags array, with the "ringsig" and "binding" tags removed>,
  <content>
]
```

serialized as compact JSON per NIP-01's event-id construction, with the two noted omissions. Implementations MUST NOT include `ringsig` or `binding` tags in the digest — signatures produced by one implementation will fail to verify under another.

### Domain Separator for Nullifier

```
ctx = utf8(<anchor xonly, lowercase hex>) || 0x2f || utf8(<cover d-tag>)
```

(i.e. `<anchor>/<d-tag>` in ASCII). The version and namespace are already encoded in the surrounding tagged-hash tag (`"DepositsRingSig/v1/nullifier"`), so they are not repeated.

This separator gives unlinkability of the *published* 32-byte nullifier across `(anchor, cover)` pairs. The underlying `I = sk · H_p(P_π)` does not include `ctx` and is not unlinkable across rings sharing `P_π`. See "Privacy Considerations".

## Verification Procedure

A verifier processing a Kind 25502 with `action: "first_contact"` MUST:

1. Fetch the cover event referenced by the `cover` tag. Reject if missing, expired per local policy, or not authored by the `anchor`.
2. Locate the `ring` entry matching the event's `ring` tag. Reject if absent.
3. Confirm `|ring| ≥ k_min`.
4. Compute the canonical digest as specified above.
5. Verify the ring signature against the ring's member list and the digest. Verification recovers `I` (33 bytes compressed) and simultaneously validates the binding proof — that the declared bound pubkey `P` is controlled by the same `sk` that produced `I`.
6. Recompute `nullifier = H_τ("DepositsRingSig/v1/nullifier", encode(I) || ctx)` and confirm it equals the event's `nullifier` tag. (Bookkeeping; `I` is the authoritative handle.)
7. Verify the BIP-340 `sig` under `P` as with any Nostr event.
8. Consult local state keyed by `I` (not by the hashed nullifier): reject if `I` is already bound to a different `P` for this `(anchor, cover)`.
9. If all checks pass, record `(I, P, ring-id, cover-id)` and pass the event to policy evaluation.

A verifier processing a Kind 25502 with `action: "continuation"` MUST:

1. Look up the event's `nullifier` tag in local state — a fast presentation-layer index into the `(I, P)` records.
2. Confirm the event's `pubkey` matches the recorded `P`.
3. Verify the BIP-340 `sig`.
4. Pass the event to policy evaluation.

## Cover Construction

Cover construction is verifier-side and not normative. The following is RECOMMENDED as a default:

**Trust-topology cover.** For each `f ∈ F_0`, define `S_f = ({f} ∪ follows(f, T)) ∩ R_max`. The cover is `{S_f : f ∈ F_0, |S_f| ≥ k_min}`. This yields one ring per direct follow, naturally sized and semantically meaningful: a signer's choice of ring signals which of the anchor's direct follows they are socially adjacent to, without revealing identity.

Alternative constructions (random subsets, balanced incomplete block designs, reputation-weighted covers) are permitted. Verifiers SHOULD publish covers infrequently enough that pseudonyms accumulate meaningfully under each ring; frequent rotation fragments the anonymity set.

The reference verifier rebuilds the cover every `VERIFY_COVER_REFRESH_SECS` seconds; production deployments SHOULD set this to one hour or more.

## Pseudonym Semantics

A nullifier is an identifier, not a bearer credential. Possession of a nullifier alone authorizes nothing; only a signature under the bound pubkey `P` proves control of the pseudonym. Nullifiers MAY therefore be transmitted in the clear, logged, or used as correlation keys in public indices.

A signer MAY establish distinct pseudonyms under distinct covers (including distinct `d`-tagged covers from the same anchor) without cross-linkage. A signer MUST NOT attempt to establish two distinct bound pubkeys under the same `(anchor, cover)` pair; the deterministic nullifier derivation prevents this, and verifiers will reject the second attempt at step 8 of first-contact verification.

Key rotation of the bound pubkey is not defined in this version of the DEP. A future revision MAY define a rotation event that re-anchors an existing nullifier to a new bound pubkey via a fresh proof of equivalent `sk`.

## Privacy Considerations

**Ring size floor.** The anonymity set for a given pseudonym is bounded above by ring size at first contact. Verifiers SHOULD set `k_min` high enough that individual signers are not trivially identifiable. Values below 10 are strongly discouraged.

**Cover stability.** As long as a cover remains published, new pseudonyms continue to pool within its rings. Frequent cover rotation fragments anonymity sets. Verifiers SHOULD rotate covers only when `R_max` has changed substantially.

**Published nullifier vs. underlying key image.** The 32-byte `nullifier` carried in event tags includes the per-`(anchor, cover)` `ctx` separator, so the *published* nullifiers a signer produces under different anchors or different covers are unlinkable to anyone observing only the wire. **The underlying `I` is not.** Since `I = sk · H_p(P_π)`, two `I` values produced by the same signer in two rings that contain the same `P_π` are bitwise-equal; anyone able to recompute them — for example a verifier whose ring intersects another verifier's ring — sees correlation. Verifiers SHOULD treat `I` as sensitive operational state and not republish it; cross-verifier correlation requires explicit `I` sharing.

**Nullifier collision across verifiers.** Building on the above: the *published* nullifier at verifier A is unlinkable to the *published* nullifier at verifier B even when both verifiers' covers include overlapping rings. Cross-verifier correlation requires sharing `I` values explicitly.

**Timing and metadata.** This DEP does not protect against timing analysis, relay-level metadata correlation, or stylometric deanonymization. Signers concerned with these vectors should layer additional mitigations at the transport and application layers.

**Compromise of a ring member's secret key** allows the attacker to forge signatures attributable to the original holder's ring memberships. This is inherent to any ring signature scheme. Nullifier-based linkability bounds the scope of forged continuation requests to the compromised pseudonym.

## Security Considerations

**Canonical digest omissions.** The `ringsig` and `binding` tags are excluded from the digest. Implementations MUST NOT include them, or signatures produced by one implementation will fail to verify under another.

**Cover authenticity.** Verifiers MUST confirm that a referenced cover event is authored by the `anchor`. A forged cover would permit arbitrary ring acceptance.

**Replay of continuation requests.** The `created_at` field is included in the BIP-340-signed event id and serves as the replay-protection nonce. Verifiers SHOULD reject continuation events whose `created_at` falls outside an acceptable window.

**BIP-340 parity normalization.** Cover members are stored as 32-byte xonly pubkeys; lifting them to a curve point assumes even-y. A signer whose seed-derived secret produces an odd-y pubkey MUST negate `sk` once at the start of the signing ceremony so the lifted point matches the actual pubkey used in the bLSAG ring. Implementations MUST do this normalization client-side; the wire format carries only the (parity-agnostic) xonly.

## Out of Scope

The following are deliberately not specified:

- Policy for accepting or rejecting requests beyond the cryptographic checks above.
- Reputation, rate-limiting, or trust-scoring applied to pseudonyms.
- Cover-construction algorithms beyond the recommended default.
- Relay-level routing, transport encryption, or metadata minimization.
- Bound-pubkey rotation and pseudonym portability.

These are verifier-local or deployment-specific and are expected to evolve independently of the wire protocol.

## Related DEPs

- [DEP-04](DEP-04.md): Peer messaging (relays, advertisement format)
- [DEP-14](DEP-14.md): Attestation verification service (the `ringsig` method's place in the verifier framework)

## References

- BIP-340: Schnorr Signatures for secp256k1 (tagged-hash construction, xonly encoding)
- bLSAG: Back-linkable Linkable Spontaneous Anonymous Group signatures (CryptoNote specification, §4)
- Groth, Kohlweiss: "One-Out-of-Many Proofs: Or How to Leak a Secret and Spend a Coin" (EUROCRYPT 2015) — referenced for log-size alternative
