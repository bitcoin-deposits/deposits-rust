# NIP-XX

## Anonymous Web-of-Trust Requests

`draft` `optional`

This NIP defines a mechanism by which a request can be authenticated as having originated from within a verifier's web of trust — specifically, from someone the verifier directly or transitively follows — without revealing which specific member of that web of trust sent it. It further defines a pseudonymous identity construction that allows a blessed sender to authenticate subsequent requests without re-establishing ring membership.

The protocol guarantees exactly one property: that a valid signature was produced over a specified set of Nostr public keys. All decisions about which sets are acceptable, how pseudonyms are treated, and how reputation is accumulated are verifier-side policy and are explicitly out of scope.

## Motivation

A Nostr user wishes to receive requests from members of their extended social graph while preserving the sender's anonymity within that graph. Existing primitives (plain Schnorr signatures on BIP-340) identify the sender uniquely; this NIP provides a wire format and verification procedure for requests that prove web-of-trust membership without identifying the specific member.

## Terminology

- **Verifier** — the Nostr identity to whom requests are addressed.
- **Anchor** — the verifier's public key, used as the root of the web-of-trust closure.
- **`F_0`** — the set of public keys the anchor follows, per the anchor's most recent `kind:3` event at or before a pinned timestamp.
- **`R_max`** — the depth-2 closure of follows from the anchor: `F_0 ∪ (⋃_{p ∈ F_0} follows(p, T)) \ {anchor}`.
- **Cover** — a published collection of subsets `{S_1, ..., S_m}` with each `S_i ⊆ R_max`. The verifier publishes a cover; requesters sign over one `S_i`.
- **Ring** — the specific `S_i` used for a given signature.
- **Nullifier** — a deterministic value derived from the signer's secret key, serving as a pseudonymous identifier across requests.
- **Bound pubkey** — a fresh secp256k1 public key declared at first contact, cryptographically tied to the same secret that produced the nullifier, used to authenticate subsequent requests from the same pseudonym.

## Cryptographic Primitives

All primitives operate over secp256k1, the curve used by BIP-340 Schnorr signatures in Nostr. Every Nostr `npub` is directly usable as a ring member without conversion.

### Tagged Hashes

All domain-separated hashes follow the BIP-340 tagged-hash construction:

```
H_τ(data) = SHA256(SHA256(τ) || SHA256(τ) || data)
```

with tag `τ` chosen per purpose. The tags used in this NIP are:

- `"DepositsRingSig/v1/hash-to-curve"`
- `"DepositsRingSig/v1/challenge"`
- `"DepositsRingSig/v1/nullifier"`
- `"DepositsRingSig/v1/binding"`

### Hash-to-Curve

`H_p` maps an arbitrary byte string to a secp256k1 point. Implementations SHOULD use try-and-increment seeded by the tagged hash:

```
H_p(input):
    for counter in 0, 1, 2, ...:
        x = H_τ("DepositsRingSig/v1/hash-to-curve", input || u32_le(counter))
        if x is a valid affine x-coordinate on secp256k1:
            return lift_x(x)              # even-y, per BIP-340
```

Try-and-increment's variable timing is acceptable: the input is exclusively public (a ring member's public key), so timing leaks no secret information.

### Ring Signature Scheme

Senders produce ring signatures using **bLSAG** (Back-linkable Linkable Spontaneous Anonymous Group signatures) adapted to secp256k1. The scheme provides:

- Signer anonymity within the ring (unconditional).
- A key image `I` that is deterministic in `(sk, P_π)`, where `P_π` is the signer's public key and `sk` is its secret.
- Linear signature size in the ring: approximately `32·(n+1)` bytes for a ring of size `n`.

The challenge chain is computed with the tagged hash `"DepositsRingSig/v1/challenge"` over `(L_i || R_i || message_digest)` at each ring index, in standard bLSAG fashion.

Implementations MAY substitute a logarithmic-size alternative (e.g., Groth–Kohlweiss) provided the key image and verification semantics are preserved.

### Key Image and Nullifier

The bLSAG key image is the cryptographic linkability mechanism:

```
I = sk · H_p(encode(P_π))
```

where `encode(P)` is the 33-byte compressed encoding of `P` and the resulting `I` is itself encoded as 33 bytes compressed for transit, hashing, and storage. **All linkability checks are performed on `I`** — recomputed by the verifier during ring-signature verification, then matched against state.

The 32-byte `nullifier` published in event tags is a **presentation derivation** of `I`:

```
nullifier = H_τ("DepositsRingSig/v1/nullifier", encode(I) || ctx)
```

where `ctx` is the domain separator for the event kind (see Domain Separator for Nullifier below). The hash is a wire-format / indexing convenience: 32 bytes is what Nostr clients are used to handling, and it allows verifiers to correlate continuation events without re-running ring-signature verification. **Linkability lives on `I`, not on the hash.**

A verifier MUST reject a first-contact event (kind 25502 with `action: "first_contact"`) whose recomputed `I` is already bound (under the same `(anchor, cover)` pair) to a different bound pubkey, regardless of whether the published `nullifier` happens to match.

### Bound Pubkey

At first contact, the signer declares a fresh secp256k1 public key `P` and proves, as part of the ring signature ceremony, that `P` is controlled by the same `sk` that produced the ring signature and key image. Subsequent requests from the same pseudonym are signed under `P` as ordinary BIP-340 Schnorr signatures.

The binding proof and ring signature are combined into a single zero-knowledge statement during first contact, so that `P` itself reveals no information about which ring member the signer is. The challenge for the binding proof uses the tag `"DepositsRingSig/v1/binding"`.

## Event Kinds

The kind numbers below sit alongside the lightning-verify pair (25500/25501) and durable attestation (55502) used by the same verifier service:

| Kind  | Class                       | Direction              | Purpose                                  |
|-------|-----------------------------|------------------------|------------------------------------------|
| 25502 | ephemeral                   | requester → verifier   | Ringsig request (first-contact OR continuation) |
| 25503 | ephemeral                   | verifier → requester   | Ringsig response (correlated via `e` tag) |
| 35500 | parameterized replaceable   | verifier published     | Cover                                    |
| 55502 | durable                     | verifier published     | Attestation (extended with `method: "ringsig"`) |

### `kind:35500` — Cover Publication (parameterized replaceable)

Published by the verifier. Advertises the currently acceptable cover of rings. Replaceable by the author with a later event carrying the same `d` tag.

```json
{
  "kind": 35500,
  "pubkey": "<verifier pubkey>",
  "created_at": <unix timestamp>,
  "tags": [
    ["d", "<cover-version-id>"],
    ["snapshot", "<unix timestamp T>"],
    ["k_min", "<minimum ring size>"],
    ["ring", "<ring-id-1>", "<pk_1>", "<pk_2>", "..."],
    ["ring", "<ring-id-2>", "<pk_1>", "<pk_3>", "..."]
  ],
  "content": "<optional human-readable description>"
}
```

- `d` is the cover version identifier. A verifier MAY publish multiple concurrent covers (e.g., for different request contexts) distinguished by `d`.
- `snapshot` is the Unix timestamp `T` such that the cover was computed against each follower's latest `kind:3` event at or before `T`.
- `k_min` is the minimum acceptable ring size. Clients SHOULD reject any ring smaller than this regardless of the cover's contents.
- Each `ring` tag enumerates one `S_i`: a ring identifier followed by the hex public keys of its members. Members MUST be sorted lexicographically and deduplicated.

A verifier with no published cover cannot receive requests under this NIP. Implementations MAY provide a default cover-generation policy (e.g., "trust-topology cover: one ring per direct follow, containing that follow's follow list").

### `kind:25502` — Ringsig Request (ephemeral)

Published by the requester. The `action` field on the request payload (in `content`) selects the processing path: `"first_contact"` or `"continuation"`. Verifiers MUST dispatch on this discriminator and MUST reject any other value.

#### First contact

Establishes a pseudonym. Carries a ring signature that proves membership in one of the cover's published rings, plus a binding proof that ties a fresh bound pubkey `P` to the signer.

```json
{
  "kind": 25502,
  "pubkey": "<bound pubkey P>",
  "created_at": <unix timestamp>,
  "tags": [
    ["anchor", "<verifier pubkey>"],
    ["cover", "<cover d-tag>", "<cover event id>"],
    ["ring", "<ring-id>"],
    ["nullifier", "<32-byte hex>"],
    ["ringsig", "<hex-encoded ring signature>"],
    ["binding", "<hex-encoded bound-pubkey proof>"]
  ],
  "content": "{\"action\":\"first_contact\", ...request-specific fields}",
  "sig": "<BIP-340 signature by P over the event>"
}
```

- `pubkey` is the bound pubkey `P`, not the signer's underlying Nostr identity.
- `anchor` names the verifier whose cover is being used.
- `cover` references the cover publication event that defines the acceptable rings.
- `ring` identifies which `S_i` from that cover was signed over.
- `nullifier` is the 32-byte presentation hash (see Key Image and Nullifier above).
- `ringsig` is the bLSAG signature over the canonical digest, encoded as 33-byte `I` followed by 32-byte `c_0` followed by `n` × 32-byte responses, all hex.
- `binding` is the bound-pubkey proof, encoded as 33-byte `R` followed by 32-byte `s`, hex.
- `sig` is an ordinary BIP-340 signature by `P`, as with any Nostr event.

#### Continuation

Authenticated solely by `P`. Carries no ring signature.

```json
{
  "kind": 25502,
  "pubkey": "<bound pubkey P>",
  "created_at": <unix timestamp>,
  "tags": [
    ["anchor", "<verifier pubkey>"],
    ["nullifier", "<32-byte hex>"]
  ],
  "content": "{\"action\":\"continuation\", ...request-specific fields}",
  "sig": "<BIP-340 signature by P>"
}
```

The verifier looks up `nullifier` in its local state, confirms the event's `pubkey` matches the `P` recorded at first contact, and accepts or rejects per policy.

### `kind:25503` — Ringsig Response (ephemeral)

Published by the verifier in reply to a 25502 request. The response is correlated with its request via the `e` tag (event id of the request). Same pattern the lightning-verify path uses for `kind:25501`.

```json
{
  "kind": 25503,
  "pubkey": "<verifier pubkey>",
  "created_at": <unix timestamp>,
  "tags": [
    ["e", "<request event id>"],
    ["p", "<bound pubkey P>"]
  ],
  "content": "{\"status\":\"accepted\"|\"rejected\", ...response-specific fields}",
  "sig": "<BIP-340 signature by the verifier>"
}
```

The schema of the response body is verifier-policy-specific. Implementations SHOULD include at least:

- `status`: `"accepted"` on success, `"rejected"` with a `reason` on failure.
- For accepted first-contact: an `attestation_event_id` (kind 55502) the verifier published, so the wallet can avoid re-fetching the attestation from a different relay.

## Canonicalization

### Ring Member Ordering

Within any `ring` tag of a cover publication, public keys MUST be sorted lexicographically as 32-byte hex strings and deduplicated. The verifier's cover publication is authoritative; requesters do not reconstruct the ring independently.

### Self-Exclusion

`R_max` MUST exclude the anchor itself. A verifier cannot sign a request to themselves under this scheme.

### Digest for Ring Signature

The ring signature covers a canonical digest of the event computed as SHA-256 of the serialization:

```
[
  0,
  <bound pubkey P, hex>,
  <created_at>,
  <kind>,
  <tags array, with "ringsig" and "sig" tags removed>,
  <content>
]
```

serialized as compact JSON per NIP-01's event ID computation, with the two noted omissions. This digest is the message input to the ring signature scheme.

### Domain Separator for Nullifier

`ctx` is constructed as:

```
ctx = utf8(<anchor pubkey, lowercase hex>) || 0x2f || utf8(<cover d-tag>)
```

(i.e. `<anchor>/<d-tag>`, ASCII). The version and namespace are already encoded in the tag of the surrounding tagged hash (`"DepositsRingSig/v1/nullifier"`), so they are not repeated inside `ctx`.

Per "Published nullifier vs. underlying key image" in Privacy Considerations, this separator gives unlinkability *of the published 32-byte handle* across (anchor, cover) pairs. The underlying key image `I = sk · H_p(P_π)` does not include `ctx` and is not unlinkable across rings that share `P_π`.

## Verification Procedure

A verifier processing a `kind:25502` event with `action: "first_contact"` MUST:

1. Fetch the cover event referenced by the `cover` tag. Reject if missing, expired per local policy, or not authored by the `anchor`.
2. Locate the `ring` entry in the cover matching the event's `ring` tag. Reject if absent.
3. Confirm `|ring| ≥ k_min`.
4. Compute the canonical digest as specified above.
5. Verify the ring signature against the ring's member list and the digest. The verification procedure recovers the key image `I` (33 bytes compressed) and simultaneously validates that the declared bound pubkey `P` is controlled by the same `sk` that produced `I`.
6. Recompute the presentation nullifier `H_τ("DepositsRingSig/v1/nullifier", encode(I) || ctx)` and confirm it equals the event's `nullifier` tag. (This is bookkeeping; `I` is the authoritative handle.)
7. Verify the BIP-340 `sig` under `P` as with any Nostr event.
8. Consult local state keyed by `I` (not by the hashed nullifier): reject if `I` is already bound to a different `P` for this `(anchor, cover)`.
9. If all checks pass, record `(I, P, ring-id, cover-id)` in local state and pass the event to policy evaluation.

A verifier processing a `kind:25502` event with `action: "continuation"` MUST:

1. Look up the event's `nullifier` tag in local state — this is a fast presentation-layer index into the verifier's `(I, P)` records. Reject if absent.
2. Confirm the event's `pubkey` matches the `P` recorded for that nullifier (and therefore for the underlying `I`).
3. Verify the BIP-340 `sig`.
4. Pass the event to policy evaluation.

## Cover Construction

Cover construction is a verifier-side concern and is not normative. The following construction is RECOMMENDED as a default:

**Trust-topology cover.** For each `f ∈ F_0`, define `S_f = ({f} ∪ follows(f, T)) ∩ R_max`. The cover is `{S_f : f ∈ F_0, |S_f| ≥ k_min}`. This yields one ring per direct follow, naturally sized and semantically meaningful: a signer's choice of ring signals which of the anchor's direct follows they are socially adjacent to, without revealing identity.

Alternative constructions (random subsets, balanced incomplete block designs, reputation-weighted covers) are permitted. Verifiers SHOULD publish covers infrequently enough that pseudonyms accumulate meaningfully under each ring.

## Pseudonym Semantics

A nullifier is an identifier, not a bearer credential. Possession of a nullifier alone authorizes nothing; only a signature under the bound pubkey `P` proves control of the pseudonym. Nullifiers MAY therefore be transmitted in the clear, logged, or used as correlation keys in public indices.

A signer MAY establish distinct pseudonyms under distinct covers (including distinct `d`-tagged covers from the same anchor) without cross-linkage. A signer MUST NOT attempt to establish two distinct bound pubkeys under the same `(anchor, cover)` pair; the deterministic nullifier derivation prevents this, and verifiers will reject the second attempt in step 7 of first-contact verification.

Key rotation of the bound pubkey is not defined in this version of the NIP. A future version MAY define a rotation event that re-anchors an existing nullifier to a new bound pubkey via a fresh proof of equivalent `sk`.

## Privacy Considerations

**Ring size floor.** The anonymity set for a given pseudonym is bounded above by the ring size at first contact. Verifiers SHOULD set `k_min` high enough that individual signers are not trivially identifiable. Values below 10 are strongly discouraged.

**Cover stability.** As long as a cover remains published, new pseudonyms continue to pool within its rings. Frequent cover rotation fragments anonymity sets. Verifiers SHOULD rotate covers only when `R_max` has changed substantially.

**Published nullifier vs. underlying key image.** The 32-byte `nullifier` carried in event tags is a hash that includes the per-(anchor, cover) `ctx` separator, so the *published* nullifiers a signer produces under different anchors or different covers are unlinkable to anyone observing only the wire. **The underlying `I` is not.** Since `I = sk · H_p(P_π)`, two `I` values produced by the same signer in two rings that contain the same `P_π` are bitwise-equal; anyone able to recompute them (e.g. a verifier whose ring intersects another verifier's ring) sees correlation. Verifiers SHOULD treat `I` as sensitive operational state and not republish it; correlation between verifiers is in scope only insofar as `I` values are exchanged between them.

**Nullifier collision across verifiers.** Building on the above: the *published* nullifier at verifier A is unlinkable to the *published* nullifier at verifier B, even if both verifiers' covers include overlapping rings. Cross-verifier correlation requires sharing `I` values explicitly.

**Timing and metadata.** This NIP does not protect against timing analysis, relay-level metadata correlation, or stylometric deanonymization. Signers concerned with these attack vectors should use additional mitigations at the transport and application layers.

**Compromise of a ring member's secret key** allows the attacker to forge signatures attributable to the original holder's ring memberships. This is inherent to any ring signature scheme. Nullifier-based linkability means that forged continuation requests are bounded in scope to the compromised pseudonym.

## Security Considerations

**Canonical digest omissions.** The `ringsig` and `sig` tags are excluded from the digest. Implementations MUST NOT include them, or ring signatures produced by one implementation will fail to verify under another.

**Cover authenticity.** Verifiers MUST confirm that a referenced cover event is authored by the `anchor`. A forged cover would permit arbitrary ring acceptance.

**Replay of continuation requests.** The `created_at` field is included in the BIP-340-signed event id and serves as the replay-protection nonce. Verifiers SHOULD reject continuation events with `created_at` values outside an acceptable window.

## Out of Scope

The following are deliberately not specified:

- Policy for accepting or rejecting requests beyond the cryptographic checks enumerated above.
- Reputation, rate-limiting, or trust-scoring mechanisms applied to pseudonyms.
- Cover-construction algorithms (a default is recommended but not mandated).
- Relay-level routing, transport encryption, or metadata minimization.
- Key rotation and pseudonym portability.

These are verifier-local or deployment-specific concerns and are expected to evolve independently of the wire protocol.
