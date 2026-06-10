# dep-17: canonical encodings

## abstract

dep-16 evaluates a descriptor against an operation, a ledger-state snapshot, and a witness, and relies on a fraud-proof mechanism that replays that evaluation. correctness of the fraud proof requires that every implementation agree, bit for bit, on three things: what a signature over an operation commits to, what a state predicate reads, and what the descriptor's own structure is when it is hashed or compared. this dep fixes those three encodings — operations, state snapshots, and descriptors — together with the value encoding they share, the domain-separation tags, the primitive-id registry, and the versioning rule. it specifies what dep-16 treats as opaque: `Operation::signing_message`, the descriptor commitment, and the bytes a snapshot reduces to.

## motivation

dep-16's determinism argument (its §3.3) is conditional: replay yields a fixed verdict *given* protocol-fixed canonical encodings. an evaluator is a pure function of `(T, w, s, m)`, but `T`, `w`, and `s` are abstract objects until serialized, and three operations cross that boundary:

- **signature verification** checks a signature against the canonical bytes of the operation. two implementations that encode an operation differently will disagree on whether a signature is valid, and therefore on the verdict.
- **state predicates** read fields of the snapshot. two implementations that disagree on what the snapshot contains, or how an absent field is represented, will disagree on a guard.
- **ast operations** (`ast_ref`, `ast_shape_at`, `subtree_at`) and the descriptor commitment compare or hash subterms. two implementations with different term encodings will disagree on structural equality and on the descriptor's identity.

a single dep fixing all three keeps the fraud-proof shape singular (dep-16's §fraud-proofs): one preimage discipline, one determinism argument.

## design principles

1. **canonical**: every object has exactly one valid encoding. decoders reject non-canonical input — non-canonical sort order, duplicate entries where uniqueness is required, unknown tags, or trailing bytes after the declared structure. this is stronger than "deterministic encoder": it closes the door on an adversary presenting a second encoding of the "same" object to a verifier. each top-level object — descriptor, operation preimage, snapshot — must consume its entire input; bytes left over after the declared structure are a parse error, not someone else's data.
2. **tagged and length-prefixed**: every composite is a 1-byte type tag followed by length- or count-prefixed contents, so a decoder never guesses boundaries.
3. **domain-separated**: every hash is a tagged hash (below), so a preimage valid in one role can never be reinterpreted in another.
4. **versioned**: each top-level object's leading byte is its format discriminator, so a decoder always knows which rules to apply before reading anything else. operations and snapshots have no wrapper notion, so their leading byte is a plain version byte and this dep fixes it at `0x01`. descriptors *do* have a wrapper notion — the scheme tag (`wsh`, `tr`) plays the discriminator role, in the spirit of bitcoin's witness versions: `OP_0` and `OP_1` distinguish p2wsh from p2tr without a separate format-version byte, and BIP-380 mints a new wrapper name (`tr`) for a new format rather than bumping an existing one. dep-17 follows the same pattern. future revisions either assign a new scheme tag or — for revisions that do not change the descriptor's leading discriminator — bump a version byte placed after the scheme tag.
5. **fixed-width integers**: ledger integers are 16-byte big-endian two's complement (matching dep-16's `i128` value width); counts and lengths are 4-byte big-endian unsigned; nonces are 8-byte; block heights are 4-byte. no variable-length integers, so there is no minimality rule to get wrong.

### tagged hashing

all hashing in this dep uses the BIP-340 tagged-hash construction to enforce domain separation:

```
tagged_hash(tag, m) = SHA256( SHA256(tag) || SHA256(tag) || m )
```

with the ASCII tags `dep17/value`, `dep17/descriptor`, `dep17/operation`, and `dep17/snapshot`. a 32-byte digest results in each case.

## primitive encodings

| primitive | encoding |
|---|---|
| `u32` (count, length, height) | 4 bytes, big-endian |
| `u64` (nonce) | 8 bytes, big-endian |
| `int` (ledger integer) | 16 bytes, big-endian two's complement |
| `bytes` | `u32` length, then that many bytes |
| `list<T>` | `u32` count, then each `T` in order |
| `bool` | one byte, `0x00` or `0x01`; any other byte is non-canonical |
| `symbol` | `bytes` of its UTF-8 form (operation-type tags, branch tags, argument names) |

## the primitive-id registry

the calculus's combinators are named in source but encoded by stable numeric id. the registry below is normative; ids are never reused — a removed primitive's id is retired, not reallocated — and new entries append. an implementation rejects an id it does not know (which, combined with dep-16's capability check, means an undeclared primitive cannot even be decoded).

the registry splits along one line: **capability-gated extension axes are `u16`; fixed language-structural tags are `u8`.** the extension axes are what operators advertise and what grows over the protocol's life; the structural tags are bounded by the calculus's fixed shape.

capability-gated, `u16`:

- **value functions**: the dep-16 value signature, assigned in declaration order (`add=0x0000` … `path=0x0013`).
- **state predicates**: assigned likewise.
- **obligation forms**: `pk=0x0000`, `pk_h=0x0001`, `pk_any=0x0002`, `pk_threshold=0x0003`, `hashlock=0x0004`, `attest=0x0005`. `pk_h`'s id is reserved whether or not a given operator implements it.
- **schema kinds**: `price_within_bps=0x0000`. attestation schemas are an extension axis operators advertise, so they are registered and capability-gated like any other primitive rather than encoded ad hoc.

fixed structural, `u8`:

- **scheme tags** (descriptor wrapper): `wsh=0x01`, `tr=0x02`. these play the role of bitcoin's witness versions: the leading byte of a descriptor encoding selects its layout (see *descriptor encoding* below). a new wrapper takes a new tag; tags are never reused.
- **comparison ops**: `eq=0x00`, `lt=0x01`, `le=0x02`, `gt=0x03`, `ge=0x04`.
- **node tags** (term encoding): `const=0x00`, `and=0x01`, `or=0x02`, `thresh=0x03`, `not=0x04`, `if=0x05`, `match=0x06`, `cmp=0x07`, `state=0x08`, `prove=0x09`.
- **value-term tags**: `lit=0x00`, `var=0x01`, `op=0x02`.
- **value tags**: `int=0x00`, `key=0x01`, `hash=0x02`, `bytes=0x03`, `path=0x04`, `list=0x05`, `symbol=0x06`, `subtree=0x07`.
- **hash-function tags**: `sha256=0x00`, `hash256=0x01`, `ripemd160=0x02`, `hash160=0x03`.
- **rolling-window fields**: `amount_out=0x00`, `amount_in=0x01`, `transfer_count=0x02`.

the authoritative numeric tables for the `u16` axes live alongside the registry in the dep-16 reference implementation; this dep fixes the widths, the split, and the append-only / retire-never rule.

## value encoding

values (dep-16 sort `V`) appear in operation arguments, descriptor literals, and reified subtrees, so they have one encoding shared everywhere. a value is its value tag followed by its payload:

```
int     -> 0x00, int(16)
key     -> 0x01, bytes        -- the key type's canonical serialization (e.g. 33-byte compressed secp pubkey)
hash    -> 0x02, hashfn(1), digest        -- 32 bytes for sha256/hash256, 20 for ripemd160/hash160
bytes   -> 0x03, bytes
path    -> 0x04, list<u32>
list    -> 0x05, list<value>
symbol  -> 0x06, symbol
subtree -> 0x07, term         -- a descriptor term, encoded as below
```

the `subtree` kind wraps a full term encoding (below) under the subtree tag; it is the exact inverse of reifying a subterm via `ast_ref`. the key serialization is the only place the encoding depends on the key type; the protocol fixes it per supported key type (compressed secp256k1 for v1). deposit ids and destinations are not a distinct kind — a deposit id is a 32-byte identifier carried as a `hash` (or, where it is opaque, `bytes`); dep-16 has no separate "deposit-id" value.

## descriptor encoding

a descriptor's leading byte is a *scheme tag* (registry above) that selects which wrapper, and therefore which layout, follows. dep-17 v1 defines two:

```
wsh descriptor -> 0x01 (scheme=wsh)
                  list< (symbol name, value) > constants     -- sorted by name
                  term                                        -- the body

tr  descriptor -> 0x02 (scheme=tr)
                  bytes internal_key                          -- per the key serialization rules
                  list< (symbol name, value) > constants     -- sorted by name
                  bool body_present
                  term                                        -- present iff body_present=0x01
```

a `wsh(...)` descriptor authorizes operations by evaluating its body; this is the unadorned form and what bare top-level bodies parse to in a forgiving source surface. a `tr(K)` descriptor authorizes any operation by a signature under `K`, with no body to consult; a `tr(K, BODY)` descriptor is semantically `or(prove(pk(K)), BODY)`, evaluated with key-path tried first as an optimization. the scheme tag is part of the descriptor commitment preimage, so a `wsh(BODY)` and a `tr(K, BODY)` over the same body produce distinct `descriptor_id`s — a fraud proof cannot be replayed across schemes. constants are encoded sorted by name so the encoding is independent of source order; a name matches `[a-z_][a-z0-9_]*`, and any other name (or a duplicate name) is non-canonical. a *term* (`B`) is a node tag and its children:

```
const  -> 0x00, bool
and    -> 0x01, list<term>
or     -> 0x02, list<term>
thresh -> 0x03, u32 k, list<term>
not    -> 0x04, term
if     -> 0x05, term, term, term
match  -> 0x06, vterm scrutinee, list< (symbol tag, term) > arms, term default
cmp    -> 0x07, cmpop(1), vterm, vterm
state  -> 0x08, statepred(2), list<vterm>
prove  -> 0x09, obligation
```

a *value term* (`V`):

```
lit -> 0x00, value
var -> 0x01, symbol            -- a constant reference, by name
op  -> 0x02, valuefn(2), list<vterm>
```

an *obligation* (`O`) is a `u16` form id followed by its payload:

```
pk           -> 0x0000, vterm
pk_h         -> 0x0001, vterm
pk_any       -> 0x0002, vterm
pk_threshold -> 0x0003, u32 k, vterm
hashlock     -> 0x0004, vterm
attest       -> 0x0005, vterm, schema
```

a *schema* is a `u16` kind id (registered above) followed by its payload; `price_within_bps` (`0x0000`) carries `u32 tolerance_bps`.

the *term* encoding is what `ast_ref` reifies, what `subtree_at` compares against, and what `ast_shape_at` reads the leading node tag of. ast operations navigate paths into the body term; the scheme wrapper (and a `tr` descriptor's internal key) is structural and is not addressed by any path. the *full descriptor* encoding — scheme tag and all — is what the descriptor commitment hashes.

### descriptor commitment

```
descriptor_id = tagged_hash("dep17/descriptor", descriptor_encoding)
```

a 32-byte identifier for the descriptor in effect. fraud proofs carry the descriptor; a verifier recomputes `descriptor_id` to confirm it is the one the deposit was bound to. note this is distinct from the *deposit* id (assigned at deposit-open), which identifies the account across descriptor modifications.

## operation encoding

an operation's canonical bytes are what a signature commits to and what fraud-proof replay verifies against. they bind the deposit, the operation, replay protection, and an expiry:

```
operation_preimage -> 0x01 (version)
                      deposit_id(32)             -- domain separator; not replayable across deposits
                      symbol op_type
                      list< (symbol name, value) > args     -- sorted by name
                      u64 nonce
                      u32 expiry                  -- block height after which the signature is invalid
```

the message a signature is computed over is

```
operation_sighash = tagged_hash("dep17/operation", operation_preimage)
```

this is dep-16's `Operation::signing_message` (more precisely, its digest): `pk(K)` verifies a signature by `K` over `operation_sighash`. because `deposit_id` is inside the preimage and the tag is operation-specific, a signature is not replayable across deposits, operation types, argument sets, nonces, or roles.

### nonce and expiry

`nonce` and `expiry` are replay protection enforced by the **protocol**, not by the descriptor's predicates:

- the protocol maintains a per-deposit nonce and rejects an operation whose nonce is not strictly greater than the last accepted one (the exact monotonicity rule is the deposit dep's; this dep only fixes that the nonce is the 8 bytes above).
- the protocol rejects an operation once the current height exceeds `expiry`.

both checks sit outside the evaluator: the descriptor authorizes the operation's *content*, while nonce and expiry bound *when and how often* a given signature can be used. an evaluator therefore does not read them, and they are not part of the dep-16 predicate or value vocabulary. (a future dep may expose `nonce`/`expiry` as state values if a use case needs to gate on them; this dep only fixes their position in the preimage.)

## state-snapshot encoding

a state snapshot is the ledger state a descriptor reads through dep-16's state predicates and ledger value functions. its canonical encoding is what fraud-proof replay reproduces, so that a state predicate reads identical bytes at the operator and at a verifier. the snapshot is the committed object the state-commitment dep proves against; this dep fixes its layout.

```
snapshot -> 0x01 (version)
            int balance
            u32 blocks_since_activity
            u32 blocks_since_open
            u32 height                              -- current block height
            list< (rwfield(1) field, u32 period, int amount) > rolling_windows
            list< (path, int) > cumulative_spent_via
```

rolling-window fields are encoded by their `u8` registry id, not as text. the `rolling_windows` and `cumulative_spent_via` lists are sorted (by `(field, period)` and by `path` respectively) and contain exactly the entries the descriptor references; a read of an absent entry is defined to yield `0`, so the snapshot need only carry non-zero, referenced values, and two snapshots that agree on all referenced entries encode identically. a snapshot commitment, when needed, is `tagged_hash("dep17/snapshot", snapshot_encoding)`.

the relationship to the state-commitment dep is one of layering: that dep specifies how an operator commits to evolving ledger state and how a verifier obtains an authenticated snapshot; this dep specifies the byte layout of the snapshot once obtained.

## interaction with dep-16

dep-16 names three opaque objects; this dep defines them:

- `Operation::signing_message` is `operation_sighash` (or its preimage, with the verifier hashing); the dep-16 reference `EcdsaVerifier` signs and verifies over it.
- the descriptor a fraud proof carries is the descriptor encoding above (scheme tag, then scheme-specific payload); `descriptor_id` is its commitment. `ast_ref` / `subtree_at` / `ast_shape_at` navigate paths into the body term, not the wrapper.
- the `s` a fraud proof carries is the snapshot encoding above; dep-16's state predicates and ledger value functions read its fields.

nothing in dep-16's evaluation algorithm changes; this dep only removes the "treated as opaque bytes" caveats from its determinism and signature claims.

## open questions

- **key serialization across schemes.** v1 fixes 33-byte compressed secp256k1 for ECDSA contexts and 32-byte BIP-340 x-only for Schnorr / `tr` internal-key contexts; the spec defers selection to "the key type's canonical serialization." if dep-16 admits other key types (e.g. for non-bitcoin signing), each needs a fixed serialization, and a per-scheme rule may be needed to fix which is used where.
- **descriptor encoding size bound.** the cost cap is an operator-local policy (dep-16); whether the canonical encoding should additionally bound nesting depth or total size at the protocol level, to bound `subtree_at` comparison cost during replay, is unsettled.
- **snapshot field set.** the snapshot layout enumerates the v1 ledger reads; it must grow in lockstep with the dep-16 ledger value-function and state-predicate vocabulary, and the versioning rule is the mechanism for that.
- **exposing nonce/expiry to the evaluator.** deferred; noted above.
- **canonical encoding of attestation payloads — deferred to a substantive separate dep, not a footnote.** this dep encodes the `schema` (its registered kind id and payload), but not the attestation itself. an attestation is a signed oracle message, and its canonical encoding determines what the oracle signs and therefore what `attest(K, schema)` verifies against; it carries its own canonicalization surface — the oracle message format, the rule pairing a schema with a conforming payload, and how a multi-field schema's fields combine into the signed message. that is the subject of the attestation/oracle dep; until it lands, `attest` is specified here only down to the schema, and the dep-16 reference implementation treats attestation discharge as attestor presence.

## summary

dep-17 fixes the four encodings dep-16 leaves opaque — values, descriptors, operations, and state snapshots — under one set of principles: canonical (decoders reject non-canonical input), tagged and length-prefixed, domain-separated via BIP-340 tagged hashes, versioned, and fixed-width-integer. operations encode to a signing preimage that binds the deposit, type, arguments, nonce, and expiry; descriptors encode to the bytes that ast operations compare and the commitment hashes; snapshots encode to the bytes state predicates read. with these fixed, dep-16's determinism and signature-binding claims become unconditional, and the single fraud-proof shape replays identically across implementations.
