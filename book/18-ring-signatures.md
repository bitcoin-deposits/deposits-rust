# Chapter 18: Anonymous WoT Ring Signatures

> **Audience**: developers, integrators, advanced wallet users
> **Prereqs**: chapters 2, 6, 17
> **DEPs**: DEP-15

There are interactions in this protocol that need authentication but not identification. A wallet asking a courier for a quote needs to convince the courier it is a real, vouched-for participant in the network — not a bot, not a probe — without telling the courier *which* participant. A wallet subscribing to a member's ledger feed wants its query throttled by per-requester limits, but doesn't want to advertise that this particular requester is the same one that holds deposits with operator X. A wallet submitting a fraud proof wants the proof on chain but doesn't necessarily want its wallet identity tied to the dispute that follows.

The web of trust solves discovery. The attestation service ([Chapter 17](17-attestation-service.md)) solves identity. Neither one solves the problem of *authenticating without identifying*. That gap is where ring signatures fit.

This chapter is the cryptographic core of the `ringsig` attestation method. It is denser than most chapters in the book — readers are likely developers, and the wire format is load-bearing — but the mechanics are not as forbidding as they look once the goal is clear. We motivate the construction, walk through bLSAG, explain what each piece of the wire format buys, and close with a worked example.

## What ring signatures buy

A ring signature is a signature produced by *one* secret key but verifiable against *any one of n* public keys. The verifier learns: somebody who controls one of these `n` keys signed this message. They do not learn which one. The set of `n` public keys is the *ring*.

Three properties matter for our use case:

1. **Spontaneity.** The ring is constructed at sign time. The other ring members do not have to consent, do not have to be online, and do not even have to know they are in the ring. (They are, after all, just public keys.) This is what makes ring signatures usable for ad-hoc privacy: you can pick a ring of "five plausibly-similar wallets" each time you sign without any coordination.

2. **Anonymity within the ring.** Information-theoretically — not just computationally — the verifier cannot tell which member signed. The signer's anonymity set is exactly the ring.

3. **Linkability.** The variant we use, **bLSAG** (Backwards Linkable Spontaneous Anonymous Group), exposes a deterministic *key image* `I` that is the same every time a particular signer produces a signature for a particular ring-member identity. Two signatures from the same secret key produce the same key image, so verifiers can detect re-presentation without breaking anonymity. Anonymity *across* signatures from the same signer is gone; anonymity *of which ring member* the signer is remains.

Linkability is unusual to ask for in an anonymity primitive. The reason we want it: the attacks ring signatures defend against here are mostly about resource exhaustion and Sybil amplification, not about state surveillance. A courier that accepts an anonymous quote-request needs to be able to count distinct anonymous requesters and rate-limit each one. A verifier issuing a one-shot bounty needs to detect a second claim by the same wallet. Without linkability, "ring signatures from a trusted set" devolves into "every signature is from a fresh new identity," which defeats every kind of throttling.

So bLSAG is the sweet spot: spontaneous, anonymous within the ring, linkable enough to stop double-claims.

### Why not other primitives

Three alternatives were considered and rejected:

- **zk-SNARKs / zk-STARKs.** Constant-size proofs, fast verification, mature tooling. But: trusted setup (for SNARKs) or large proof size (for STARKs), prover complexity orders of magnitude beyond a wallet's signing path, and a curve mismatch — Nostr keys are secp256k1, almost no SNARK ecosystem is. The protocol-native curve buys integration simplicity that a SNARK library would burn.

- **Anonymous credentials** (BBS+, U-Prove, etc.). Issuer-bound: somebody has to issue the credential, and the issuer's signing key is itself a trust assumption. The whole point of the WoT cover here is that the verifier's *follow graph* — public, observable on Nostr — is the access criterion. There is no issuer to delegate to.

- **Rotating keys with no proof of membership.** A wallet could just sign each request with a fresh key. But then the verifier has no way to limit access to "wallets in my web of trust," because every fresh key is by construction outside the trust graph. The anonymity is real but the authentication is gone.

bLSAG over secp256k1 is what falls out: native curve, native key format, no setup, no issuer, ~32·(n+1) bytes per signature for ring size `n`, linkable enough to throttle. The cost is linear-in-ring-size verification; with `n ≤ 1000`-ish rings and millisecond-scale verification per ring member, that is comfortably within request-handling budgets.

## The protocol's role for ring signatures

Three deployment patterns are envisioned, all built on the same primitive:

**Anonymous courier rate-limiting.** Couriers ([Chapter 16](16-couriers.md)) are economic intermediaries that bridge transfers between ledgers. Their per-quote work is small but their attack surface is large — a fleet of bots can ask for thousands of quotes per second to map liquidity, probe pricing, or just deny service. A courier publishes a cover ring of "wallets I have served before, plus N WoT anchors," accepts anonymous quote-requests via ring signature against that cover, and rate-limits each unique key image. A bot that compromised one wallet's key gets one wallet's rate. A bot with no key gets zero rate. Identity of any specific requester is never exposed to the courier or to anyone else watching the relay.

**Anonymous member-ledger queries.** A wallet that holds deposits with operator A may want to inspect operator B's ledger history before deciding whether to bridge to it via a courier. It does not want to broadcast "wallet 0xabc... is researching operator B" because that reveals its trade pattern to any observer. Wrapping the query in a ring signature against {wallets I trust} removes the link.

**Anonymous fraud-proof submission.** A wallet that paid a Lightning invoice the operator failed to deliver has the cryptographic evidence to fire a fraud proof. The proof is broadcast publicly ([Chapter 11](11-fraud-proofs.md)) and lives forever on the relay. By default, the wallet's identity is on the proof. With ring signatures, a wallet can submit the proof through the courier or escalation path under a ring-signed pseudonym instead, getting the slashing it wants without making itself the one who triggered it.

In every case, the protocol primitive is the same: a wallet proves membership in a publicly-published ring, the verifier learns nothing about which member, and the verifier can rate-limit or throttle by key image.

## bLSAG, the algorithm

bLSAG is a chain-style ring signature. The structure is identical to the original LSAG of Liu-Wei-Wong (2004) with a small modification — the responses cycle back to the signer at the end rather than starting from them — that gives backwards linkability without any size or speed cost. It is what Monero used until 2017 and what many privacy-focused secp256k1 protocols still use when they want a ring signature.

The signing algorithm at index `π` in a ring `[P_0, …, P_{n-1}]` with secret `sk` and message `m`:

```
1. Compute key image I = sk · H_p(encode(P_π)).
2. Pick fresh α and one s_i per non-signer index i ≠ π.
3. Set L_π = α·G,  R_π = α·H_p(encode(P_π)).
4. For i = π+1, π+2, … (mod n) until we wrap back to π:
       c_i  = H_τ(L_{i-1} || R_{i-1} || m)
       L_i  = s_i·G            + c_i·P_i
       R_i  = s_i·H_p(P_i)     + c_i·I
5. Once c_π is fixed by the chain, close it: s_π = α − c_π·sk.
6. Output (I, c_0, s_0, …, s_{n-1}).
```

Verification is the forward walk only — no closing — and the test is whether `c_n` (computed from `(L_{n-1}, R_{n-1}, m)`) equals `c_0`. If the chain closes, somebody who knew one of the `n` secrets must have produced it. If it doesn't, the signature is forged.

Two facts to keep in mind:

- The challenge chain `c_i = H_τ(L_{i-1} || R_{i-1} || m)` is a SHA-256 with a per-purpose tag (`"DepositsRingSig/v1/challenge"`). The hash includes the message, so the same ring under a different message gives totally different `c_i` and anyone who tampers with `m` invalidates the closure.
- The key image `I = sk · H_p(P_π)` does not depend on the ring composition or the message. It depends only on `sk` and on `P_π`, the ring member identity the signer is using. Two signatures from the same `sk` against rings that both contain the same `P_π` produce bitwise-equal `I`. This is the linkability property.

The Rust implementation of `sign` and `verify` is in `deposits-ringsig/src/blsag.rs`, with detailed comments explaining each step. It has unit tests for honest round-trip, modified-message rejection, modified-ring rejection, modified-response rejection, key-image determinism across ring shuffles, and key-image distinctness across signers.

### Hash-to-curve

The construction needs a way to map an arbitrary byte string to a point on secp256k1, written `H_p(x)`. We need this for the `I = sk · H_p(P_π)` step, for `R_π = α · H_p(P_π)`, and for the verifier's recomputation of each `R_i`. The implementation lives in `deposits-ringsig/src/hash_to_curve.rs` and uses **try-and-increment**:

```
H_p(input):
    for counter in 0, 1, 2, ...:
        x = H_τ("DepositsRingSig/v1/hash-to-curve", input || u32_le(counter))
        if x is a valid affine x-coordinate on secp256k1:
            return lift_x(x)              # even-y, per BIP-340
```

About half of all 32-byte values are valid x-coordinates on secp256k1, so the expected iteration count is two and you almost never see more than four or five. The reference implementation caps at 256 attempts as a defense-in-depth panic — if 256 candidates miss the curve, something is structurally wrong, and silently looping forever would be worse than crashing.

Try-and-increment has variable timing: each call takes a different number of iterations depending on the input. That would be a serious problem if the input were a secret. Here it is a public ring-member key, so the timing leaks nothing about anybody's `sk`. The comment at `deposits-ringsig/src/hash_to_curve.rs:7` notes this explicitly: do not reuse this primitive in contexts where the input is secret without re-evaluating that assumption.

### Tagged hashes

Every hash in the construction is *tagged*, in the BIP-340 sense:

```
H_τ(data) = SHA256(SHA256(τ) || SHA256(τ) || data)
```

where `τ` is a per-purpose ASCII string. The tags used by this scheme, all defined in `deposits-ringsig/src/tagged.rs`:

- `"DepositsRingSig/v1/hash-to-curve"` — the seed for try-and-increment.
- `"DepositsRingSig/v1/challenge"` — the bLSAG chain hash `c_i`.
- `"DepositsRingSig/v1/nullifier"` — the published 32-byte nullifier (more on this below).
- `"DepositsRingSig/v1/binding"` — the bound-pubkey proof's Fiat-Shamir challenge.

Why per-purpose tags matter is straightforward: without them, an output of one hash construction can be coerced to look like an output of another. With them, even if two hashes happen to take similar-looking input bytes, the prefixed double-SHA-256 of the tag ensures the inner SHA-256 block is fully consumed by the tag before any data lands. The tag namespace is namespaced (`DepositsRingSig/v1/...`) so a future v2 of the scheme cannot collide with v1, and so a different protocol that happens to use the same construction style cannot accidentally produce an output that we accept.

This is the same trick BIP-340 uses for Schnorr signatures, and the same trick the deposits ledger update digest uses to keep update bytes from being mistaken for raw block-hash bytes.

## Key images, nullifiers, and what's actually linkable

The two terms tend to blur together. They are not the same thing.

- **Key image `I`.** A 33-byte compressed secp256k1 point. Defined as `I = sk · H_p(encode(P_π))`. Recoverable by the verifier as a side-effect of verifying the ring signature. Authoritative: linkability checks are performed on `I`, not on anything derived from it.

- **Presentation nullifier.** A 32-byte hash. Defined as
  ```
  nullifier = H_τ("DepositsRingSig/v1/nullifier", encode(I) || ctx)
  ```
  where `ctx = "<anchor_pubkey_hex>/<cover_d_tag>"`. It is a *presentation derivation* of `I` for use as a Nostr tag. Nostr clients are used to handling 32-byte event-id-shaped values; 33-byte compressed pubkeys would be awkward in the existing tooling.

The key fact the spec is careful about: **linkability lives on `I`**, the key image. The published nullifier is unlinkable across `(anchor, cover)` pairs because `ctx` differs, but the underlying `I` is not — two signatures from the same `sk` against rings that both contain the same `P_π` have equal `I`, regardless of ctx. Anyone who can reconstruct `I` (any verifier who runs the ring-signature verification path) sees the link. So:

- Verifiers MUST treat `I` as sensitive operational state. Don't republish it.
- Cross-verifier correlation requires explicit `I` sharing, not just observation of public nullifier tags.

The reference verifier indexes its pseudonym table by `I`, with the published nullifier as a fast-lookup secondary index. When a continuation request comes in carrying a nullifier, the verifier does the lookup, recovers the `(I, P)` record, and accepts the request iff `P` matches the bound pubkey on file. The nullifier alone authorizes nothing — only a Schnorr signature under `P` does — so leaking nullifiers (logging, public indexing, sharing across services) is fine. Leaking `I` is not.

## The bound-pubkey trick

A pure ring signature is expensive to produce and not much cheaper to verify. If a wallet sent ring-signed requests *every* time it talked to a verifier, every request would carry `~32·(n+1)` bytes of signature material and the verifier would do `n` curve operations for each. For a cover with `n=20` rings, every quote request would carry ~672 bytes of signature and ~20 ms of verification. Workable, not great.

The protocol's solution: ring-sign once at *first contact*, declare a fresh secp256k1 pubkey `P` as part of that ceremony, and prove that the same `sk` controls both the ring-signature key image and `P`. Subsequent requests under the same pseudonym are signed by `P` directly with an ordinary BIP-340 signature. The verifier maintains state mapping `I → P`, so when a continuation comes in signed under `P`, it knows the requester is the same anonymous party that authenticated earlier.

This is the bound-pubkey protocol. The proof — a Schnorr Σ-protocol "I know `sk_P` such that `P = sk_P·G`" made non-interactive via Fiat-Shamir — lives in `deposits-ringsig/src/binding.rs`. Its Fiat-Shamir challenge folds in the surrounding ring signature's `c_0` and `I`:

```
c_bind = H_τ("DepositsRingSig/v1/binding", encode(P) || encode(R) || c_0 || encode(I))
```

The fold is what *binds* the binding proof to the ring signature: an attacker can't grab somebody else's `(R, s)` from a different first-contact event, glue it onto their own ring signature, and pass off `P_victim` as their bound pubkey. The challenge would not match. The test in `deposits-ringsig/src/binding.rs` named `rejects_replay_across_ring_sigs` exercises exactly this attack.

(There is a subtlety: the binding proof and the ring signature use *different* secrets — `sk_P` for the binding, `sk` for the ring sig, where `sk_P` belongs to the freshly-declared bound key and `sk` is a ring member's secret. The two secrets are different by construction. The honest signer happens to know both; the binding proof is purely about `sk_P → P`, not about any equivalence between `sk_P` and `sk`.)

## The wire format

DEP-15 specifies four Nostr event kinds. They sit alongside the lightning-verify pair `25500/25501` and the durable attestation kind `55502` defined in DEP-14:

| Kind  | Class                       | Direction              | Purpose                                       |
|-------|-----------------------------|------------------------|-----------------------------------------------|
| 25502 | ephemeral                   | requester → verifier   | Ringsig request (first-contact OR continuation) |
| 25503 | ephemeral                   | verifier → requester   | Ringsig response (correlated via `e` tag)     |
| 35500 | parameterized replaceable   | verifier published     | Cover                                         |
| 55502 | durable                     | verifier published     | Attestation (DEP-14, with `method: "ringsig"`) |

### Cover (kind 35500)

The cover is the verifier's authoritative declaration of which rings they will accept. It is a parameterized replaceable event — the verifier can publish a new version with the same `d` tag and relays will replace the old one. Wallets MUST use the cover the verifier published; they do not get to invent rings on the fly. (This is the "cover authenticity" requirement in DEP-15: a forged cover would let an attacker construct a ring of pubkeys they know the secrets for and produce arbitrary "valid" ring signatures.)

A cover carries:

- `d` — version identifier.
- `snapshot` — Unix timestamp the verifier used when reading each follower's `kind:3` follow list.
- `k_min` — minimum acceptable ring size; verifiers reject requests targeting smaller rings.
- One `ring` tag per available ring: ring id followed by the lexicographically-sorted, deduplicated list of member pubkeys.

The reference cover-construction default — *trust-topology cover* — generates one ring per direct follow `f ∈ F_0`, with each ring containing `{f} ∪ follows(f, T)` intersected with `R_max`, the depth-2 closure. This makes ring choice semantically meaningful: a signer's choice of ring identifies which of the verifier's direct follows they are socially adjacent to, without revealing which.

### First-contact request (kind 25502, action `first_contact`)

Establishes a pseudonym. Carries the ring signature, the binding proof, the freshly-declared bound pubkey `P`, and the actual application payload.

```json
{
  "kind": 25502,
  "pubkey": "<bound pubkey P, hex>",
  "created_at": <unix ts>,
  "tags": [
    ["anchor", "<verifier pubkey, hex>"],
    ["cover", "<cover d-tag>", "<cover event id>"],
    ["ring", "<ring-id>"],
    ["nullifier", "<32-byte hex>"],
    ["ringsig", "<hex: 33-byte I || 32-byte c_0 || n × 32-byte responses>"],
    ["binding", "<hex: 33-byte R || 32-byte s>"]
  ],
  "content": "{\"action\":\"first_contact\",\"payload\":{...}}",
  "sig": "<BIP-340 signature by P over the event id>"
}
```

A few things to notice:

- `pubkey` is `P`, the bound pubkey, *not* the signer's underlying Nostr identity. Nothing on the wire reveals which ring member produced this.
- `ringsig` and `binding` are tags on the event, but they are excluded from the digest the ring signature itself covers (otherwise the event would be self-referential). The ordinary Nostr `sig` over the event id, computed *with* those tags, is produced afterwards.
- The `e`-tag-correlated response (kind 25503) is routed back to the requester via a `#p` filter on `P`. Standard Nostr request/response pattern, indistinguishable from the lightning-verify pair.

### Continuation request (kind 25502, action `continuation`)

Subsequent requests under the same pseudonym. Authenticated solely by `P`.

```json
{
  "kind": 25502,
  "pubkey": "<bound pubkey P>",
  "tags": [
    ["anchor", "<verifier pubkey>"],
    ["nullifier", "<32-byte hex>"]
  ],
  "content": "{\"action\":\"continuation\",\"payload\":{...}}"
}
```

The verifier looks up `nullifier` in its local state (constant-time lookup), confirms `pubkey` matches the recorded `P`, verifies the ordinary BIP-340 `sig`, and dispatches to policy. No ring signature, no binding proof, no `n`-step verification. About the same cost as any other Nostr event.

### Verifier's first-contact verification

The verifier does, in order:

1. Fetch the cover by `cover` tag. Reject if missing, expired by local policy, or not authored by the named `anchor`.
2. Find the ring with id matching the event's `ring` tag. Reject if absent, or if `|ring| < k_min`.
3. Compute the canonical event digest — NIP-01 style, with the `ringsig` and `binding` tags omitted.
4. Verify the ring signature against the ring's members and that digest. Recovers `I`.
5. Verify the binding proof `(R, s)` against `(P, ring_signature)`.
6. Recompute `nullifier = H_τ("DepositsRingSig/v1/nullifier", encode(I) || ctx)` and confirm it matches the published tag (bookkeeping check).
7. Verify the BIP-340 `sig` under `P` as with any Nostr event.
8. Check local state keyed by `I`: reject if `I` is already bound (under this `(anchor, cover)`) to a different `P`. This is the linkability check — somebody trying to register a second pseudonym from the same ring-member identity gets rejected.
9. If all checks pass, record `(I, P, ring-id, cover-id)` and pass the event to policy.

The keying-by-`I` step is the part the spec is most insistent on. The published nullifier is a presentation handle; `I` is the authoritative identifier. A verifier that keyed only by nullifier could be tricked by the (theoretical) collision into accepting a duplicate registration; keying by `I` is collision-free because `I` is a curve point.

## A worked example: anonymous courier quote-request

Concrete walk-through of the courier-rate-limiting use case.

**Setup.** Cassie runs a courier service that bridges deposits between five operators. She wants to accept anonymous `quote_request` calls — "I want to bridge `X` from ledger A to ledger B, what's your fee?" — but not from bots. Her policy: requests must come from one of {wallets she has served before} ∪ {wallets in her web of trust}, rate-limited to 60 requests per hour per unique pseudonym.

Cassie publishes a kind-35500 cover at her npub:

```
d = "couriers-2026-04"
snapshot = 1714000000
k_min = 12
ring "regulars": [pk_alice, pk_bob, pk_carol, ..., pk_irma]   (her past customers)
ring "wot-1":    [pk_dave, pk_emma, pk_frank, ..., pk_zoe]    (one direct follow's follows)
ring "wot-2":    [pk_george, pk_helen, ..., pk_yusuf]         (another direct follow's follows)
```

Three rings, each big enough to comfortably exceed `k_min = 12`. The "regulars" ring has 30 members, the WoT rings have ~50 each.

**Wallet sign.** Wesley (a wallet) wants a quote and is in the "regulars" ring at index 7. His wallet:

1. Fetches the latest 35500 cover at Cassie's npub. Confirms the cover is signed by Cassie (anchor authenticity).
2. Picks ring "regulars" (the smaller, more semantically meaningful ring is fine — `k_min = 12 < 30`).
3. Generates a fresh `sk_P`, computes `P = sk_P · G`. This is his pseudonym.
4. Builds the canonical event digest over `(0, P_hex, created_at, 25502, tags_without_ringsig_and_binding, content)` where `content` is the JSON `{"action":"first_contact","payload":{"from":"ledgerA","to":"ledgerB","amount_msat":1000000}}`.
5. Calls `deposits_ringsig::sign(secp, &cover.regulars.members, 7, &wesley_sk, &digest, rng)` — produces `RingSignature { I, c_0, responses }`. Key image `I` is now fixed at `wesley_sk · H_p(encode(P_7))`.
6. Calls `deposits_ringsig::binding::prove(secp, &sk_P, &ring_sig, rng)` — produces `BoundPubkeyProof { R, s }`.
7. Computes `nullifier = H_τ(NULLIFIER_TAG, encode(I) || "<cassie_pubkey_hex>/couriers-2026-04")`.
8. Hex-encodes both proofs (`ringsig_to_hex`, `binding_to_hex`), appends the `ringsig` and `binding` tags, computes the BIP-340 event id over the now-complete event, and signs the event id with `sk_P`.
9. Publishes the event to Cassie's relay set.

Total wire size: ~600 bytes for ring signature (33 + 32 + 32·30), 65 bytes for binding, plus envelope. Computation: one `hash_to_curve` per ring member, one curve mult per ring member, one signing `α`, plus the binding proof. On a laptop, well under 50 ms.

**Cassie verifies.** Her verifier:

1. Pulls the event off the relay subscription. Filters events with `["#p", cassie_npub]` — standard Nostr addressing.
2. Fetches the cover; confirms the `cover` tag's event id matches her own `couriers-2026-04` publication.
3. Finds ring "regulars" in the cover.
4. `|regulars| = 30 ≥ k_min = 12`. OK.
5. Computes the canonical digest, omitting `ringsig` and `binding` tags.
6. `deposits_ringsig::verify(secp, &regulars.members, &digest, &ring_sig)` — closes the chain. Recovers `I`.
7. `deposits_ringsig::binding::verify(secp, &P, &ring_sig, &binding_proof)` — equation `s·G = R + c·P` holds.
8. Recomputes the nullifier, confirms it matches the tag (bookkeeping).
9. Verifies the BIP-340 `sig` under `P` over the full event id.
10. Looks up `I` in her pseudonym table. New entry — record `(I, P, "regulars", couriers-2026-04)`.
11. Passes the event to policy: extract the quote-request payload, run her quoting logic, publish a kind-25503 response correlated by `e`-tag and routed by `#p P`.

**Subsequent requests.** Wesley wants another quote five minutes later. His wallet builds a continuation request: the same `nullifier` tag, no `ringsig`, no `binding`, content `{"action":"continuation","payload":{...new request...}}`, signed with `sk_P` only. Cassie's verifier looks up the nullifier, confirms `pubkey` matches the stored `P`, verifies the BIP-340 `sig`, and rate-limits him by his pseudonym (`I`). After 60 requests in this hour from this `I`, she 429s him.

Wesley cannot escape the rate limit by re-doing first-contact: the ring-member pubkey he'd be signing as is the same `P_7`, so the recovered `I` is the same, so step 8 of first-contact verification rejects the duplicate. He can rotate to a *different* ring (say "wot-1" if he has a key there too) but each ring-member identity gets one pseudonym per cover.

That is the entire flow. Cassie has rate-limited an anonymous request from a wallet in her trust set without ever learning which wallet.

## What this primitive does not do

The boundary cases are worth being explicit about.

**Anonymity is bounded by ring size.** A ring of size 12 means 12-way anonymity — fine for "is this a real wallet?" use cases, possibly insufficient for "this wallet is the whistleblower exposing operator X." DEP-15 strongly discourages `k_min` below 10, and recommends covers be rotated infrequently so that pseudonyms accumulate density within rings.

**Anonymity is bounded by side channels.** The protocol does not protect against timing analysis (when did this wallet send its request?), relay-level correlation (which IP did this event come from?), or stylometry (what does the request payload's free-text fields look like?). Wallets concerned about these should layer Tor, request-batching, or formatted-payload mitigations on top.

**Anonymity is fragile under key compromise.** If the attacker steals a ring member's `sk`, they can forge ring signatures attributable to that member's ring memberships. This is unavoidable in any ring scheme. The linkability property bounds the damage: forged continuations from a stolen pseudonym remain bounded to that pseudonym's quota.

**This isn't a fraud-proof primitive.** Ring signatures don't replace [fraud proofs](11-fraud-proofs.md) or [attestations](17-attestation-service.md). They authenticate request-time interactions; they don't make claims about ledger state. A ring-signed message saying "the operator stole my deposit" is no more weight than a plain-signed message of the same — only a fraud proof, with cryptographic evidence, slashes anybody.

**This is a request-time primitive.** It does not anonymize on-chain transactions, ledger updates, or anything else that lives in the durable layer. The protocol's durable surface is fundamentally public ([Chapter 1](01-introduction.md) names this as an explicit non-goal). What ring signatures protect is the *meta* layer: who is asking, who is querying, who is rate-limited.

## Where this leads

This chapter closes Part IV. The protocol is now fully on the table — the ledger model, the on-chain anchor, the messaging substrate, the quorum, the operations, the fee model, the fraud pipeline, the recovery lottery, the equivocation defense, the privacy and identity layer. What remains is the implementation.

[Chapter 19](19-architecture-tour.md) opens Part V with a tour of the nine Rust crates that make up the reference daemon, wallet, and supporting tools. It is the map you need before the rest of Part V — daemon internals, wallet internals, testing infrastructure, and operations — makes sense in context.
