# DEP-14: Attestation Verification Service

## Abstract

This document specifies an optional opt-in verifier role that issues durable Nostr attestations linking a public key to one of several externally-attestable identities — a lightning-address domain (NIP-05, lightning-challenge), a manual proclamation by an already-trusted account, or anonymous web-of-trust ring-signature membership (DEP-15). Operators MAY require a valid attestation to authorize `deposit_open` (DEP-08), enabling per-domain or per-graph access control without the operator itself running any non-Nostr infrastructure.

The protocol is deliberately scoped: a verifier issues *cryptographically-signed claims about identity*, and an operator decides what to do with them. Reputation, rate-limiting, and policy live with the operator and are out of scope here.

## Motivation

DEP-08 defines the deposit lifecycle and references "access control" without specifying how an operator decides whether a `deposit_open` request comes from a trustworthy sender. Three concrete signals are relevant:

1. **Pubkey allowlist** — a static list of npubs the operator manually trusts. Already specified in DEP-08; needs no protocol surface.
2. **Subkey delegation** — DEP-04 already lets an allowlisted account delegate its trust to an ephemeral key.
3. **External identity attestation** — the operator wants evidence that the requester controls a particular lightning address, has been vouched for by an allowlisted account, or is a member of a curated social graph. This is the gap DEP-14 closes.

A verifier is run as a separate service (the reference implementation is `lnaddr-attest` in this repository). Operators publish a single environment variable — `ATTESTATION_VERIFIER_PUBKEY` — pointing at the verifier they trust; the verifier's signed attestations then become the access-control credential.

## Roles

- **Verifier** — a Nostr identity that issues attestations. Holds a long-term BIP-340 keypair; signs both ephemeral verify responses (Kind 25501) and durable attestations (Kind 55502). Connected to the durable ledgers relay and the ephemeral messaging relay (DEP-04).
- **Subject** — the npub the attestation describes. Often the same key that originated the verification request, except in the `proclaim` flow.
- **Requester** — the npub that signs the verification request. Equal to the subject in all flows except `proclaim`.
- **Operator** — the deposits-node operator whose `deposit_open` is being gated. Configures `ATTESTATION_VERIFIER_PUBKEY` and access lists; calls `check_attestation` on each request.

## Verification Methods

A verifier MUST implement at least one method and MAY implement any subset of those listed below. Each method produces an attestation distinguishable by the `method` field on the Kind 55502 content (see "Attestation Event").

### 1. NIP-05 Domain Attestation

The subject claims a lightning-address `<user>@<domain>`. The verifier:

1. Fetches `https://<domain>/.well-known/nostr.json?name=<user>` (NIP-05).
2. Confirms the resulting `pubkey` field equals the subject's xonly hex.
3. Issues a Kind 55502 attestation carrying `method: "nip05"`, `lightning_address: "<user>@<domain>"`.

The verifier SHOULD cache `nostr.json` per-domain with a short TTL (default 5–60 seconds for tests, longer for production). Operators consuming this attestation match `<domain>` against their `deposit_domain_allowlist.txt`.

### 2. Lightning Challenge Attestation

The subject claims a lightning-address `<user>@<domain>`. The verifier:

1. On request `action: "link"`: emits a BOLT-11 invoice for `challenge_sats + num_payments × fee_fallback_sats`, returns `{ session_id, invoice, amount_sats }`.
2. On request `action: "challenge"` (after the user pays the invoice): pays `num_payments` random amounts summing to `challenge_sats` *to* the subject's lightning address.
3. On request `action: "verify"` carrying the list of amounts the subject observed: confirms the amounts match (set equality) and issues a Kind 55502 attestation with `method: "challenge"`, `lightning_address: "<user>@<domain>"`.

A verifier MUST reject `verify` events submitted outside `timeout_secs` of session creation, MUST reject more than `max_attempts` `verify` failures per session, and SHOULD reject any `challenge` request whose paid invoice the verifier did not previously emit.

The challenge flow is sound under the assumption that an attacker cannot intercept lightning payments to the claimed address. A subject who genuinely controls the address sees the random amounts; an impostor does not.

### 3. Proclaim Attestation

An already-trusted requester (one whose xonly appears in the verifier's `VERIFY_ALLOWLIST_FILE`, typically a bind-mount of the operator's `deposit_allowlist.txt`) vouches for an arbitrary subject by submitting `action: "proclaim", attest_pubkey: "<subject xonly>"`. The verifier:

1. Reads `VERIFY_ALLOWLIST_FILE` fresh each request.
2. Rejects if the requester's xonly is not present.
3. Issues a Kind 55502 attestation tagged `#p` with the *subject*'s xonly, content carrying `method: "proclaim"`, `allowlist_npub: "<requester xonly>"`.

This lets a manually-allowlisted account onboard an ephemeral key for one-shot operations — for example, a user holding a hardware wallet may proclaim their daily-driver phone key without copying the hardware key onto the phone.

### 4. Ring-Signature Attestation

The subject proves membership in one of the verifier's published anonymity rings, without revealing which ring member they are, by submitting a Kind 25502 first-contact event. The wire format and verification procedure are specified in DEP-15. On a valid first-contact event, the verifier issues a Kind 55502 attestation tagged `#p` with the subject's *bound* pubkey (not their underlying ring-member key), content carrying `method: "ringsig"`, `nullifier: "<32-byte hex>"`.

A wallet using ringsig attestation MUST sign subsequent `deposit_open` requests under the bound pubkey, since that is the npub the operator's `check_attestation` will look up. The attestation does not record `lightning_address` or `allowlist_npub` — anonymity-set membership *is* the access criterion.

## Wire Format

### Kind 25500 — Verify Request (ephemeral, gift-wrapped)

Wallets MUST send verify requests as NIP-59 gift-wraps. The wrap envelope is:

- Outer event: `kind: 1059`, encrypted with NIP-44 to the verifier's pubkey, `pubkey` set to a one-shot ephemeral key.
- Seal: `kind: 13`, encrypted with NIP-44 by the wallet's real signing key.
- Rumor: `kind: 25500`, content is a JSON object with at least an `action` field selecting the method.

The rumor schema is method-specific; the union accepted by the reference verifier is:

```json
{
  "action": "link" | "challenge" | "verify" | "nip05" | "proclaim",
  "lightning_address": "user@domain",     // link / challenge / verify / nip05
  "session_id": "...",                    // challenge / verify
  "amounts": [123, 456, 421],             // verify
  "attest_pubkey": "<xonly hex>"          // proclaim (subject npub)
}
```

A verifier MUST reject any rumor whose `action` is not on its supported-methods list, and SHOULD reject any field combination not consistent with the specified action.

### Kind 25501 — Verify Response (ephemeral, gift-wrapped)

The verifier replies by gift-wrapping a Kind 25501 rumor back to the original requester, addressed via the `#p` tag on the outer wrap. The rumor body is:

```json
{ "status": "verified" | "rejected" | "challenge_pending" | "invoice",
  "method": "nip05" | "challenge" | "proclaim",
  "attestation_event_id": "<hex>",         // verified
  "lightning_address": "user@domain",      // verified (nip05/challenge)
  "allowlist_npub": "<xonly hex>",         // verified (proclaim)
  "invoice": "lnbc...",                    // invoice
  "session_id": "...",                     // challenge_pending / invoice
  "message": "..." }                       // rejected
```

The response is correlated with the request via the gift-wrap envelope's outer `#p` and the rumor's `session_id` (when relevant). The 25501 reply is for synchronous UX feedback only — the durable record is the Kind 55502 below.

### Kind 25502 / 25503 — Ringsig Request / Response (ephemeral, plain-signed)

Specified in DEP-15. Unlike Kind 25500, ringsig events are not gift-wrapped: the bound pubkey is the *purpose* of the event and is signed in the clear.

### Kind 55502 — Attestation (durable, replaceable)

The persistent record. Published by the verifier on the durable ledgers relay; consumed by the operator's `check_attestation` (see below).

```json
{
  "kind": 55502,
  "pubkey": "<verifier xonly>",
  "tags": [
    ["p", "<subject xonly>"],          // the npub being attested for
    ["d", "<subject xonly>:<method>"]  // recommended uniqueness key
  ],
  "content": "{...AttestationContent...}",
  "sig": "<verifier BIP-340 sig>"
}
```

The `#p` tag is the index operators query on. The recommended `#d` tag combines subject and method so a subject can hold concurrent attestations for multiple methods without one replacing another.

`AttestationContent`:

```json
{
  "npub": "<subject xonly>",
  "method": "nip05" | "challenge" | "proclaim" | "ringsig",
  "verified_at": "<ISO-8601 timestamp>",
  "lightning_address": "user@domain",   // nip05 / challenge only
  "allowlist_npub": "<xonly hex>",      // proclaim only
  "nullifier": "<32-byte hex>"          // ringsig only, diagnostic
}
```

A consumer MUST verify the event signature against the configured verifier xonly, MUST confirm the `#p` tag matches the subject of interest, MAY consult `verified_at` for staleness checks, and MUST dispatch on `method` to apply the matching access-control rule.

## Operator-Side Consumption

An operator opts in by setting:

- `ATTESTATION_VERIFIER_PUBKEY` — the verifier xonly to trust. Without this, attestation lookup is disabled and the operator falls back to pubkey-allowlist-only access control (DEP-08).
- `deposit_allowlist.txt` — npubs accepted unconditionally, also used for the `proclaim` path.
- `deposit_domain_allowlist.txt` — domains whose lightning-address attestations are accepted.

On each `deposit_open` request the operator computes the *effective sender* (subject account after DEP-04 subkey resolution) and checks, in order:

1. Effective sender ∈ `deposit_allowlist` ⇒ accept.
2. Otherwise, fetch Kind 55502 events authored by the configured verifier and tagged `#p` with the effective sender. For each:
   - `method = "nip05"` or `"challenge"` and `lightning_address`'s domain ∈ `deposit_domain_allowlist` ⇒ accept.
   - `method = "proclaim"` and `allowlist_npub` ∈ `deposit_allowlist` ⇒ accept.
   - `method = "ringsig"` ⇒ accept (anonymity-set membership is the criterion; the operator trusts the verifier's signature).
3. No matching attestation ⇒ reject with `code: "not_authorized"`. The reject MAY carry `attestation_required: true` to nudge the wallet to initiate verification.

The operator MUST NOT re-verify the cryptographic content of an attestation beyond the BIP-340 signature on the Kind 55502 event itself. The verifier is the trust anchor by configuration; second-guessing its decisions defeats the abstraction.

## Verifier Configuration

The reference verifier reads its configuration from environment variables (and `_FILE` indirections for secrets):

| Variable | Purpose |
|---|---|
| `VERIFY_NSEC_FILE` | Path to the verifier's secret key (hex or nsec1) |
| `VERIFY_RELAYS` | Comma-separated relay URLs (durable + messaging) |
| `VERIFY_CHALLENGE_SATS` | Default challenge amount (default 1000) |
| `VERIFY_NUM_PAYMENTS` | Number of random payments per challenge (default 3) |
| `VERIFY_TIMEOUT_SECS` | Session timeout (default 600) |
| `VERIFY_FEE_FALLBACK_SATS` | Per-payment fee budget when probing (default 10) |
| `VERIFY_NIP05_CACHE_SECS` | Per-domain `nostr.json` TTL |
| `VERIFY_COVER_REFRESH_SECS` | Ringsig cover republish cadence (DEP-15) |
| `VERIFY_ALLOWLIST_FILE` | Path to the allowlist consulted by `proclaim` |
| `VERIFY_CA_CERT` | Optional custom CA bundle for HTTPS probes |

A verifier MAY support additional methods or configuration; it MUST NOT issue an attestation whose `method` field is not specified in this DEP or a successor.

## Security Considerations

**Verifier trust.** The verifier is fully trusted by every operator who configures it. A compromised verifier can issue attestations for any subject, bypassing access control on every operator that trusts it. Operators SHOULD review the verifier's behavior and SHOULD treat verifier compromise the way they treat root CA compromise.

**Attestation longevity.** Kind 55502 events persist on the durable relay until garbage-collected by the operator's relay policy. An attestation issued today and trusted today might still be on-relay months later. Verifiers SHOULD consider issuing short-lived attestations (small `verified_at`-relative TTL embedded in policy) or rotating their signing key to bound exposure.

**Domain-allowlist scope.** A `nip05` or `challenge` attestation only proves control of a *specific* lightning address. An operator that allowlists `example.com` must trust that *every* `*@example.com` is appropriate to onboard. This is the same trust assumption as TLS certificate authority: scope the allowlist to domains whose user-vetting policy you trust.

**Lightning-challenge soundness.** The challenge flow is sound only if the verifier's lightning payments succeed — a verifier with a flaky lightning node may produce false negatives but cannot produce false positives. The verifier SHOULD use a reliable LN node and SHOULD cache fee estimates so transient fee spikes don't fail otherwise-valid verifications.

**Proclaim authority.** A proclaim request lets a single allowlisted account vouch for an arbitrary npub. Operators SHOULD audit `deposit_allowlist.txt` regularly; an allowlisted key whose private material has leaked can be used to onboard arbitrary other identities. The proclaim flow does NOT support quorum-vouching in this version of the DEP.

## Privacy Considerations

The Kind 25500 verify request is gift-wrapped (NIP-59), so a relay observer cannot link the requester's npub to the lightning address being attested. The Kind 55502 attestation, however, is a public claim by definition — it's the durable record an operator looks up — and so links the subject npub to whichever identifier (`lightning_address`, `allowlist_npub`) the method emits.

Operators wishing to gate access without correlating identities to deposits SHOULD use the ringsig method (DEP-15), which records only an opaque pseudonym (`nullifier`) and the subject's bound pubkey, never the underlying ring-member key.

## Related DEPs

- [DEP-04](DEP-04.md): Peer messaging (gift-wrap envelope, advertisement format)
- [DEP-08](DEP-08.md): Deposits (where `check_attestation` is invoked)
- [DEP-15](DEP-15.md): Anonymous web-of-trust ring signatures (the `ringsig` method)

## References

- NIP-05: Mapping Nostr keys to DNS-based identifiers
- NIP-44: Versioned encryption
- NIP-59: Gift Wrap
- LUD-06 / LUD-16: lnurl-pay over lightning addresses
- BOLT #11: Invoice format
