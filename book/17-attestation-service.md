# Chapter 17: Attestation Service

> **Audience**: integrators (especially), wallet users, operators
> **Prereqs**: chapters 2, 6
> **DEPs**: DEP-14

## What problem this solves

The default operator identity in this protocol is an npub. That is by design — the protocol does not require operators to dox themselves to participate, and a wallet that wants to evaluate operators can do so entirely on the basis of measurable on-chain and on-relay properties: how much collateral is locked, how the quorum is shaped, how the operator has historically behaved on conformance checks, what fees they charge.

But discovery isn't just measurement. A wallet browsing operator advertisements on the relay sees a list of pseudonyms, each with their own quorum graph and fee schedule. The information is there to make a decision; the *anchor* a human reviewer would normally use to ground that decision — "this is the npub of `alice@example.com`, and `example.com` is a name I recognize" — is not. Pseudonymous-by-default is the right floor for the protocol; it is the wrong ceiling for a discovery experience that will reach normal users.

The attestation service is the protocol's lightest-touch concession to that gap. It is an opt-in role that issues *signed claims about identity* — "the holder of this npub controls `example.com`," or "the holder of this npub has been vouched for by an account on the operator's allowlist" — without itself running any deposits-protocol infrastructure. Operators that want to be discoverable as `alice@example.com` get their pseudonym attested; operators that prefer to stay nameless do nothing. Wallets consume attestations from verifiers they trust and ignore the rest.

DEP-14 names this role the *verifier*, the npub being attested as the *subject*, and the operator that consumes attestations on `deposit_open` as the *operator*. Three things matter about the design before the wire format:

- **The verifier issues claims, not endorsements.** A `nip05` attestation says "this npub controls this domain." It does not say "this operator is honest." Reputation, rate-limiting, abuse-handling, and policy live with the operator that consumes the attestation, not with the verifier that issues it. The verifier is not in the trust graph for slashing; it is in the trust graph for *access control*.
- **Self-attestation proves nothing.** An operator can put any string they like in their advertisement. The verifier exists because *somebody else* has to actually run the verification — fetch the DNS record, send the challenge invoice, pay the LNURL probe — and sign the result. Decoupling who-verifies from who-claims is the entire point.
- **Verifier compromise is bounded.** A compromised verifier can issue false attestations against any subject, but only on behalf of operators that explicitly configured that verifier. There is no protocol-level "root verifier" — every operator picks their own. New verifiers can launch without coordination, compete on freshness and identifier coverage, and be retired without protocol-level fallout.

The rest of this chapter walks the wire format, the four verification methods DEP-14 specifies, and the operator + wallet consumption paths.

## What an attestation is, on the wire

The durable record is a Nostr `Kind: 55502` event published by the verifier and pinned to the relay the protocol uses. Every consumer queries the same shape:

```json
{
  "kind": 55502,
  "pubkey": "<verifier xonly hex>",
  "tags": [
    ["p", "<subject xonly hex>"],
    ["d", "<subject xonly hex>:<method>"]
  ],
  "content": "{...AttestationContent JSON...}",
  "sig": "<verifier BIP-340 signature>"
}
```

The `#p` tag is the index. Operators and wallets fetch attestations for a specific subject by `kind: 55502, author: <verifier>, #p: <subject>`. The recommended `#d` tag, combining subject and method, lets the same subject hold concurrent attestations under different verification methods (a `nip05` and a `challenge` simultaneously, say) without one replacing the other under Nostr's replaceable-event semantics.

The `content` payload is the `AttestationContent` JSON:

```json
{
  "npub": "<subject xonly hex>",
  "method": "nip05" | "challenge" | "proclaim" | "ringsig",
  "verified_at": "<ISO-8601 timestamp>",
  "lightning_address": "user@domain",
  "allowlist_npub": "<xonly hex>",
  "nullifier": "<32-byte hex>"
}
```

The `method` field selects which trailing field is populated. `nip05` and `challenge` set `lightning_address`. `proclaim` sets `allowlist_npub`. `ringsig` sets `nullifier` (diagnostic only). `verified_at` is informational — the receiver decides what TTL to apply.

Two ephemeral kinds round out the protocol surface, used only during the verification handshake itself and discarded afterward:

- `Kind: 25500` — the verify request, sent by a wallet to a verifier as a NIP-59 gift-wrap so a relay observer can't link the requester npub to the address being verified.
- `Kind: 25501` — the verifier's reply with the immediate status (`verified`, `rejected`, `challenge_pending`, `invoice`), correlated to the request via the gift-wrap envelope.

The 25501 reply is for synchronous UX feedback — "your verification finished, here's the durable event ID." The Kind 55502 attestation is the durable record everyone consumes after the fact.

## The four verification methods

A verifier MUST implement at least one method and MAY implement any subset of the four. Each method emits a Kind 55502 event distinguishable by the `method` field.

### NIP-05 domain attestation

The subject claims a lightning-address `<user>@<domain>` and asks the verifier to confirm it. The verifier:

1. Fetches `https://<domain>/.well-known/nostr.json?name=<user>` (NIP-05).
2. Confirms the resulting `pubkey` field equals the subject's xonly hex.
3. Issues a Kind 55502 with `method: "nip05"`, `lightning_address: "<user>@<domain>"`.

This is the cheapest method. It runs purely on a single HTTPS GET. No on-chain or off-chain payment moves. It is also the strongest, in the sense that the domain operator has to actively cooperate (publish the right `nostr.json`) for the attestation to succeed — there is no "pay the address" attack surface.

The verifier caches `nostr.json` per-domain with a short TTL (default 5–60 seconds for tests, longer for production). The `VERIFY_NIP05_CACHE_SECS` environment variable controls the TTL.

### Lightning challenge attestation

The subject claims a lightning-address `<user>@<domain>` but the domain doesn't expose a NIP-05 record (or exposes one for a different key). The verifier falls back to a challenge-response over Lightning payments:

1. **Link.** On `action: "link"`, the verifier resolves the LNURL-pay endpoint for the address, estimates routing fees from the BOLT-11 route hints, generates a BOLT-11 invoice for `challenge_sats + num_payments × fee_fallback_sats` sats, and returns `{ session_id, invoice, amount_sats }`.
2. **Challenge.** After the user pays the invoice, the wallet sends `action: "challenge"`. The verifier confirms the payment landed, generates `num_payments` random positive integers summing to `challenge_sats`, and pays each amount in turn to the subject's lightning address.
3. **Verify.** The subject observes the amounts that arrived, sums them up, and submits `action: "verify"` carrying the list. The verifier compares against the amounts it actually paid (set equality), and on a match issues the Kind 55502 with `method: "challenge"`, `lightning_address: "<user>@<domain>"`.

The soundness argument: an attacker who doesn't control the address can't observe the random amounts. With the default `challenge_sats=1000` and `num_payments=3`, a stars-and-bars enumeration gives roughly C(999, 2) = 498,501 equally-likely outcomes. An impostor who has to guess the amounts within `timeout_secs=600` of session creation has a probability of success around 2 × 10⁻⁶ per attempt; the verifier rejects after `max_attempts` failures.

The challenge flow is "sound under the assumption that an attacker cannot intercept lightning payments to the claimed address." A flaky LN node on the verifier side can cause false negatives (paid invoice, payment fails to route) but cannot cause false positives. The verifier SHOULD use a reliable LN node and SHOULD cache fee estimates so transient fee spikes don't fail otherwise-valid verifications.

### Proclaim attestation

A separate path for the case where the subject can't run a NIP-05 endpoint or accept Lightning at the address being attested. An already-trusted requester — one whose xonly is in the verifier's `VERIFY_ALLOWLIST_FILE`, which is typically a bind-mount of the operator's `deposit_allowlist.txt` — vouches for an arbitrary subject by submitting `action: "proclaim", attest_pubkey: "<subject xonly>"`. The verifier:

1. Reads `VERIFY_ALLOWLIST_FILE` fresh each request (so adds and removes take effect immediately).
2. Rejects if the requester's xonly is not present.
3. Issues a Kind 55502 tagged `#p` with the *subject*'s xonly, content `method: "proclaim"`, `allowlist_npub: "<requester xonly>"`.

This is how a user with a hardware wallet (the long-term allowlisted account) onboards an ephemeral phone key (the subject) without copying private material onto the phone. The hardware key signs a single proclaim request. The phone receives an attestation it can present to the operator's `check_attestation`. The operator sees `allowlist_npub` matching its `deposit_allowlist`, accepts the deposit_open, and the phone never has to be on the static allowlist.

Note that proclaim only authorizes a single allowlisted account to vouch for one ephemeral subject at a time. Quorum-vouching ("two of these three trusted accounts authorize this key") is not in this version of the DEP.

### Ring-signature attestation

A wallet that wants to gain access without revealing which member of a curated anonymity set it is uses a ring signature instead. The wire format is specified separately in DEP-15 and contextualized in [Chapter 18](18-ring-signatures.md); for this chapter what matters is the *output*: on a valid ring-signature first-contact event, the verifier issues a Kind 55502 with `method: "ringsig"` tagged `#p` with the subject's *bound* pubkey (not the underlying ring-member key). Content is just `{npub, method, verified_at, nullifier}`. There is no `lightning_address` and no `allowlist_npub` — anonymity-set membership *is* the access criterion. The operator that trusts the verifier accepts on the strength of the verifier's signature alone.

## How the verifier signs

The verifier is a long-term BIP-340 keypair on the durable relay. The reference implementation (`deposits-attestation/src/bin/deposits-attest.rs`) uses a single `Keys` instance loaded from `VERIFY_NSEC` (or `VERIFY_NSEC_FILE`) and signs every Kind 55502 event with that key directly. Compromise of that key compromises every attestation the verifier has ever issued or ever will issue, until the verifier rotates and operators reconfigure.

The crate's `subkey.rs` module (`deposits-attestation/src/subkey.rs:1`) implements a separate, unrelated mechanism — NIP-style subkey delegation, where a long-term *account* key authorizes ephemeral *subkey*s to publish on its behalf, and revocation lives in a Kind 10301 replaceable event. This is a general-purpose Nostr building block usable by any client that wants to keep its long-term key in cold storage and post day-to-day with hot keys; the deposits-attest binary itself does not currently use it for issuing attestations. (The architectural question of whether attestations *should* be issued under per-purpose subkeys, with a Kind 10301 control plane to revoke compromised subkeys without moving the verifier root, is open. The hooks are in the codebase.)

The signing-message inside `publish_attestation` (`deposits-attestation/src/bin/deposits-attest.rs:1109`) also produces a *standalone* schnorr signature over `SHA256("LIGHTNING_VERIFY:<npub>:<detail>:<verified_at>:<verifier_pubkey>")` and returns it in the Kind 25501 reply. That signature is for out-of-band consumers — a web UI that wants to display a "verified by alice-attestor" badge without speaking Nostr can verify it directly. The durable Kind 55502 event is the canonical record; the standalone signature is a convenience.

## Operator-side consumption

An operator opts into attestation-gated `deposit_open` by setting one environment variable:

```
ATTESTATION_VERIFIER_PUBKEY=<verifier xonly hex or npub>
```

Without it, attestation lookup is disabled and the operator falls back to pubkey-allowlist-only access control (see DEP-08). With it set, every `deposit_open` request runs through `check_attestation` (`deposits-node/src/node/ledger_queries.rs:1251`):

```
1. Compute effective sender. After DEP-04 subkey resolution, this is the
   long-term account npub the request is operating under.
2. If effective_sender ∈ deposit_allowlist  →  accept.
3. Else fetch Kind 55502 events authored by ATTESTATION_VERIFIER_PUBKEY
   and tagged #p with effective_sender. For each:
     method = "nip05" or "challenge":
       if lightning_address's domain ∈ deposit_domain_allowlist  →  accept.
     method = "proclaim":
       if allowlist_npub ∈ deposit_allowlist  →  accept.
     method = "ringsig":
       accept (ring-membership IS the criterion; the verifier's
       signature is sufficient because the verifier already
       checked ring + binding proof).
4. No matching attestation  →  reject with code: "not_authorized".
```

The reject MAY carry `attestation_required: true` so the wallet knows to initiate verification before retrying. The operator MUST NOT re-verify the cryptographic content of an attestation beyond the BIP-340 signature on the Kind 55502 event itself — the verifier *is* the trust anchor by configuration; second-guessing its decisions defeats the abstraction. (The operator does, however, transitively trust the relay's claim that it served a real Kind 55502; the standard Nostr filter+author+sig path covers that.)

The implementation today supports a single configured verifier per operator. The DEP allows multiple, and the wire format is unchanged — a future extension just stores a set of trusted verifier pubkeys instead of one — but until that lands, an operator picks one verifier whose policy and uptime they can live with.

The supporting allowlists are file-backed and reloaded fresh on each request:

- `deposit_allowlist.txt` — npubs accepted unconditionally. Also the source `proclaim` references.
- `deposit_domain_allowlist.txt` — domains whose lightning-address attestations are accepted.

The reload-fresh property matters: an operator who removes a compromised npub from `deposit_allowlist.txt` sees the change reflected on the next `deposit_open` request without restarting the daemon. Verifier-issued attestations, however, persist on the relay until garbage-collected — see "Security considerations" below.

## Wallet-side verification

A wallet receiving an attestation runs three mandatory checks and one optional one:

1. **Verifier signature.** The Kind 55502 event's `sig` MUST be a valid BIP-340 signature over the canonical event-id by the `pubkey` (the verifier xonly). This is the standard Nostr event-validity check; any Nostr client library does it. Then: `pubkey` must be on the wallet's configured trusted-verifier set. If the wallet only trusts `verifier_X` and the event is signed by `verifier_Y`, the attestation is ignored regardless of validity.
2. **Subject match.** The `#p` tag and the `npub` field inside `content` must both equal the subject the wallet is evaluating. (A verifier that conforms to the DEP always sets these consistently, but the wallet checks anyway — defense in depth.)
3. **Freshness.** The wallet decides what TTL is acceptable. `verified_at` is ISO-8601, easy to compare. The DEP doesn't mandate a specific ceiling — discovery UI might accept attestations issued in the last 90 days; an operator whose attestation is two years old probably should not be displayed as "verified."
4. **Optional re-verification.** A paranoid wallet that wants stronger evidence than the verifier's signature can re-run the underlying check itself: fetch the NIP-05 record for a `nip05` attestation, ping the LNURL endpoint for a `challenge` attestation, look up the proclaim's `allowlist_npub` to see if it's still on a known allowlist. None of these are required by the protocol — they are a wallet-side hardening choice. The price is the bandwidth and time the verifier was supposed to amortize for everyone.

If all checks pass, the wallet displays the verified identifier alongside the operator's npub: "alice@example.com (verified)." If the verifier signature fails, or the verifier isn't on the wallet's trust list, or the attestation is expired, the wallet ignores it and the operator is shown as anonymous. *Ignored* is the right default — silent fallback to anonymous is much better UX than a "verification failed" warning that could be triggered by transient relay weirdness.

## Multiple verifiers, no coordination

There is no protocol-level registry of verifiers. A new verifier launches by:

1. Generating a long-term keypair.
2. Standing up the `deposits-attest` binary (or any compatible implementation) configured with the relays it will publish to.
3. Telling potential consumers — wallet developers, operators — its pubkey.

That's the whole onboarding. Wallets that decide to trust the new verifier add its pubkey to their trusted-verifier set. Operators that decide to consume its attestations set `ATTESTATION_VERIFIER_PUBKEY` to its hex.

This is deliberately reminiscent of certificate authorities, with one important difference: there is no protocol pressure toward consolidation. A wallet that trusts only one CA is exposed to that CA's compromise; a wallet that trusts the union of N CAs is exposed to *any* of their compromises. Verifiers compete on freshness, identifier coverage, fee policy, and the perceived rigor of their verification — but the wallet that trusts all of them is taking on more risk, not less. The natural equilibrium for a careful wallet is "the smallest set of verifiers that covers the operators I want to evaluate."

The protocol leaves *which* verifiers to trust as a wallet decision. Some wallets may ship with a curated default list. Others may expose it as a per-user setting. Either is fine; nothing in DEP-14 prescribes the UX.

## Discovery interaction

The discovery model in this protocol is operator-published advertisements on the relay (DEP-04, [Chapter 6](06-peer-messaging.md)). An operator publishes their advert; the advert may reference one or more attestations by event ID. A wallet doing discovery:

1. Subscribes to advert events on the relays it knows.
2. For each advert, extracts the referenced attestation event IDs (or queries directly on `kind: 55502, #p: <operator npub>`).
3. Filters those attestations through its trusted-verifier set.
4. Applies the per-attestation checks above.
5. Renders each operator with their verified identifier(s), if any, plus their quorum graph and fee schedule.

Operators with no attestation render as anonymous — pubkey-only. They are still selectable; the wallet just has less to go on. Operators with stale-or-untrusted attestations *also* render as anonymous, by the silent-fallback rule. The wallet might log a tooltip — "this operator has an attestation from a verifier you don't trust" — but the surface should not nag.

## A worked example

Alice runs a deposits node. She owns `example.com` and would like wallets browsing the relay to recognize her advert as `alice@example.com (verified)` instead of `npub1xz…`.

1. Alice picks a verifier she trusts — say `verifier-pubkey-V`. She has done due diligence on V's operator and is comfortable with V issuing attestations under her npub.
2. Alice sets up a NIP-05 record on `example.com`. She publishes `https://example.com/.well-known/nostr.json` with `{ "names": { "alice": "<alice xonly hex>" } }`.
3. Alice's wallet sends a Kind 25500 verify request to V, gift-wrapped, with `{ "action": "link", "lightning_address": "alice@example.com" }`.
4. V receives the wrap, decrypts to find the rumor. V's `handle_link` (`deposits-attestation/src/bin/deposits-attest.rs:697`) extracts the address, runs `check_nip05`, fetches `https://example.com/.well-known/nostr.json?name=alice`, sees `pubkey = <alice xonly>`, and routes to the NIP-05 fast path.
5. V's `publish_attestation` (`deposits-attest.rs:1059`) builds an `AttestationContent { npub: <alice npub>, method: "nip05", verified_at: <now>, lightning_address: "alice@example.com" }`, signs it with V's keypair, publishes Kind 55502 to the relay, and returns the event ID via Kind 25501.
6. Alice updates her operator advert to reference the attestation event ID.
7. Bob's wallet, running discovery, subscribes to operator adverts. Bob's wallet trusts V. It sees Alice's advert, fetches the referenced Kind 55502, verifies V's signature, sees `lightning_address: alice@example.com`, sees that `verified_at` is recent. Bob's UI renders: `alice@example.com (verified by verifier-V)`.
8. Bob picks Alice. His first `deposit_open` request goes through. Alice's daemon, consuming the same attestation via `check_attestation`, sees `domain=example.com` matches `deposit_domain_allowlist.txt`, and accepts.

If `example.com` doesn't have a NIP-05 record but does run a Lightning address, V routes to the challenge flow instead — invoice, payment, three random sats, verify, attestation. The wire shape consumers see is identical; only the `method` field changes from `nip05` to `challenge`.

If Alice can't run either, but she's already been onboarded onto Bob's operator's `deposit_allowlist`, she can still get a Kind 55502 by having an allowlisted account proclaim her npub. The attestation now has `method: "proclaim"`, `allowlist_npub: <vouching key>`, no `lightning_address`. Operators that consume it match `allowlist_npub` against their own `deposit_allowlist.txt`.

If Alice wants to participate without revealing her identifier at all — a wallet user picking from an anonymity ring — she goes through the ringsig flow described in DEP-15. The Kind 55502 has `method: "ringsig"` and a `nullifier`. Ringsig and `nip05`/`challenge` are not mutually exclusive; the same npub can hold one of each, since the recommended `#d` tag combines subject and method.

## What this doesn't prove

Identity binding is not endorsement, and a verifier is not the protocol's slashing engine. Three failure modes are explicit in the design:

- **Verifier compromise.** A verifier whose signing key has been stolen can issue arbitrary attestations against arbitrary subjects, on behalf of every operator and wallet that trusts that verifier. This is exactly the trust posture of a TLS root CA: the operator and wallet SHOULD treat verifier compromise the way they treat root-CA compromise. Operators rotate `ATTESTATION_VERIFIER_PUBKEY`; wallets rotate their trusted-verifier set. Compromised attestations may persist on relays until garbage-collected, so verifiers SHOULD consider issuing short-lived attestations and rotating signing keys on a schedule even in the absence of an incident.

- **Domain-allowlist scope.** A `nip05` or `challenge` attestation only proves control of a *specific* lightning address. An operator that allowlists `example.com` is implicitly trusting that *every* `*@example.com` is appropriate to onboard. This is the same trust posture as TLS — scope your domain allowlist to domains whose user-vetting policy you trust, not to domains that just happen to sound respectable.

- **Proclaim authority.** A proclaim request lets a single allowlisted account vouch for an arbitrary npub. An allowlisted key whose private material has leaked can be used to proclaim arbitrary identities into the operator's access set. Operators SHOULD audit `deposit_allowlist.txt` regularly.

The complement to all three of these is the ring-signature web of trust, [Chapter 18](18-ring-signatures.md). Ring signatures don't replace attestations — they answer a different question. An attestation says "this npub controls this real-world identifier." A ring signature says "this npub is one of these N accounts I trust, and I'm not telling you which." Wallets that want strong identity bindings use attestations. Wallets that want anonymity-preserving access control use rings. The mature deployment has both, and operators that consume both broaden their access surface without weakening either.

## The relay role

Attestation events live on the same Nostr relays the protocol uses for ledger updates and peer messaging. The verifier publishes Kind 55502 to the relays in `VERIFY_RELAYS` (or `VERIFY_ATTESTATION_RELAYS` for a separate publishing set). Operators query the same relays via `nostr.client().fetch_events()` filtered on `kind: 55502, author: <verifier>, #p: <subject>`. Wallets subscribe to verifier pubkeys for live updates, or query on demand.

Two minor relay considerations worth knowing:

- **Replaceable-event semantics.** Kind 55502 is in the regular range, not the replaceable range. The recommended `#d` tag combining subject and method gives the verifier a uniqueness key it can use for soft-replacement (re-publish under the same `#d` to supersede), but the relay won't enforce uniqueness. A subject can hold multiple co-existing attestations under the same method if a verifier issues them carelessly; consumers query by `#p` and pick the freshest.
- **Garbage collection.** Relays decide their own retention. An operator running their own relay can purge attestations older than some threshold; a verifier that wants its attestations to live longer should publish to relays with longer retention. The DEP does not mandate a TTL — short-lived attestations are a verifier-side hardening choice, not a protocol invariant.

## What stays in your head

- An attestation is a Kind 55502 Nostr event published by a verifier, binding an npub to either a domain (via NIP-05 or Lightning challenge), an allowlisted-account vouch (proclaim), or a ring-signature anonymity set.
- Operators consume attestations by setting `ATTESTATION_VERIFIER_PUBKEY` and consulting `check_attestation` on every `deposit_open`. Wallets consume them by filtering through a trusted-verifier set on discovery.
- The verifier is fully trusted by every consumer that configures it. Compromise has the same blast radius as a compromised TLS root CA. Protect verifier keys accordingly; rotate on a schedule; consider issuing short-lived attestations.
- Attestations bind identifiers, not endorse behavior. Slashing, fraud-proof handling, fee policy — all of those are still on the operator's quorum, with collateral as the enforcement.
- Multiple verifiers can co-exist with no coordination. The wallet picks whom to trust. The operator picks one (today; multiple in a future revision).

## Where this leads

The next chapter, [Chapter 18: Anonymous WoT Ring Signatures](18-ring-signatures.md), covers the complementary identity primitive — anonymity-set membership without doxxing. Ring signatures fit the same `check_attestation` slot, with `method: "ringsig"` in the Kind 55502 payload, but they answer the discovery question "should this npub be allowed in" without ever telling the operator who the underlying member is. Used together with the attestation flows in this chapter, they cover both ends of the identity spectrum: explicit "I am alice@example.com" on one side, "I am one of the people you've already decided to trust" on the other.
