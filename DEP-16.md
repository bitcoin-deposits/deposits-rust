# dep-16: self-modifying ledger-aware descriptors

## abstract

deposit authorization is generalized from spending-only miniscript to a small term calculus in which every deposit operation — spending, modification of the authorization term, accepting incoming payments, updating metadata — is authorized by evaluating a closed term against the operation, a ledger-state snapshot, and a witness. existing miniscript syntax is preserved as a sublanguage with unchanged semantics. extensions add ledger-state predicates, operation introspection, structural inspection of the term itself, and operation-level signatures. one language, one evaluator, one admission discipline, one fraud-proof shape.

formal semantics, the monotonicity theorem, and the modification invariant are in calculus.md. this dep specifies the implementation: concrete grammar, operation encodings, witness format, admission checks, evaluation algorithm, cost model, fraud proofs, capability declarations, and integration with existing deps.

## background

deposits are currently locked by miniscript expressions evaluated against spending witnesses. operations beyond spending — rotating a key, accepting a payment under conditions, repairing a descriptor, transferring authority to recovery guardians — have had no native expression. encoding them as spends adds vestigial semantics; carrying a separate authorization sublanguage per operation multiplies fraud-proof variants and admission rules.

this dep takes a third path. the descriptor language is extended with combinators that introspect the operation, the ledger state, and the term itself; modification is an operation under the same authorization regime; everything is verified by one evaluator. the formal properties relied on — witness-monotonicity under a static polarity rule, total deterministic evaluation, system-level well-formedness across modifications — are proved in calculus.md.

## descriptor structure

a descriptor is a closed term with a top-level constant environment, wrapped in a scheme tag that selects the commitment shape and authorization paths above the body.

```
descriptor ::= wsh(body)
            |  tr(K)
            |  tr(K, body)
            |  body                          -- sugar for wsh(body)

body       ::= with(name = literal, ..., in expression)
            |  expression
```

`wsh(body)` is the default scheme: authorization is whatever the body evaluates to. `tr(K)` authorizes any operation by a signature under the internal key `K` and has no body to consult — it is the calculus's pk(K) at the top level. `tr(K, body)` is semantically `or(prove(pk(K)), body)`: either a signature by `K` or any path through `body` authorizes. the scheme tag is part of the descriptor commitment specified in dep-17, so a `wsh(BODY)` and a `tr(K, BODY)` over the same body are distinct descriptors with distinct commitments; the scheme also distinguishes which encoding rules dep-17 applies. bare body without an explicit wrapper is sugar for `wsh(body)` and provided so existing source compiles unchanged.

the choice of scheme is a security decision distinct from the body's contents. `tr`'s internal key holds an unconditional authorization path over every operation, including modifications, and its custody discipline must match. this mirrors bitcoin p2tr.

ast paths address positions in the *descriptor*, with the scheme wrapper as the root. `wsh(body)` has one child — the body root — at path `[0]`; deeper positions in the body extend the path (`[0, i]` is the body's i-th child, and so on). `tr(K)` has one child — the internal key — at path `[0]`. `tr(K, body)` has two: the internal key at `[0]` and the body root at `[1]`. the path origin is uniform across schemes, so every modifiable position — including the internal key of a `tr` descriptor — is reachable by a path of the same shape.

names in `with(...)` are bound once at deposit-open and resolved by name in the body. names that do not resolve cause admission to fail.

the expression language has three sorts: `B` for booleans (the sort of authorization decisions and of the descriptor body), `V` for values (integers, public keys, hashes, paths, subterms-as-data, operation arguments), and `O` for proof obligations, injected into `B` via the coercion `prove(O) : B`.

```
B ::=  <bool>                      true or false
    |  and(B, B, ...)
    |  or(B, B, ...)
    |  thresh(k, B, B, ...)
    |  not(B)
    |  if(B, B, B)
    |  match(V, branch(V, B), ..., branch(else, B))
    |  cmp(<op>, V, V)             where <op> in {=, <, <=, >, >=}
    |  state(<predicate>, V, ..., V)
    |  prove(O)

V ::=  <literal>                   integers, keys, hashes, bytes, symbols
    |  [V, V, ...]                 list
    |  <varref>                    resolved against the with(...) environment
    |  <op>(V, ..., V)             from the value function signature

O ::=  pk(V)
    |  pk_any(V)                   V is a list of keys
    |  pk_threshold(k, V)          V is a list of keys
    |  hashlock(V)                 V is a hash; the function is encoded in the hash's type
    |  attest(V, V)                first V is an oracle key; second is a schema
```

every `match` must include an `else` branch. this is grammatical, not a runtime check; the parser rejects `match` without `else`.

value literals include integers, public keys, hashes, byte strings, and symbols. byte strings are used for opaque payloads such as the `completion_script` argument of a spend operation. symbols are atomic identifiers used as operation-type tags (`spend`, `insert`, `replace`, `delete`, `accept`, `update_metadata`), branch tags in `match`, and schema kinds. paths are constructed by the `path(...)` value function rather than written as literals. deposit ids and destinations are not a distinct literal kind — they are 32-byte identifiers carried as hashes. lists are written `[v, v, ...]` and are used wherever a collection of values of the same kind is needed; predicates that take lists treat them as sets (order does not matter, and duplicates are folded for purposes like `pk_threshold`'s distinct-key requirement).

existing miniscript fragments are accepted as parse-time aliases and desugar to the n-ary `and`, `or`, `thresh` above; the wrappers (`a:`, `s:`, `c:`, `v:`, `t:`, `d:`, `j:`, `n:`, `l:`, `u:`) desugar to no-ops. the miniscript combinators `pk`, `older`, `after`, `sha256`, `hash256`, `ripemd160`, `hash160` retain their meaning; their semantic content in the calculus is `prove(pk(...))`, `prove(hashlock(...))`, `state(older, ...)`, `state(after, ...)`. miniscript's `pk_h` is not provided — the witness is keyed by key, not by hash-of-key, so the hash-then-reveal discharge pattern does not fit. wallets that want a hash-protected reference should use `hashlock` directly.

## value functions

the value signature is fixed at the protocol level. an operator advertises which subset it implements via capability declaration; descriptors may use only what their operator implements.

every value function is a total deterministic function of `(w, s)` and constant in `m`. arithmetic operates on the ledger's native integer width. addition, subtraction, and multiplication saturate at the range's endpoints on overflow; division by zero yields zero. these choices preserve totality and remove implementation-defined behavior across implementations.

arithmetic: `add(a, b)`, `sub(a, b)`, `mul(a, b)`, `div(a, b)`, `min(a, b)`, `max(a, b)`. `pct(n, p)` is `div(mul(n, p), 100)`. `bps(n, bp)` is `div(mul(n, bp), 10000)`. percentages and basis points are integers, not decimals; the language has no floating point.

operation introspection: `operation_type()` returns an identifier (`spend`, `accept`, `insert`, `replace`, `delete`, `update_metadata`). `operation_arg(name)` returns a named argument of the operation. `operation_path()` returns the ast path targeted by a modification operation. `operation_subtree()` returns the subtree being introduced (for `insert` and `replace`).

ledger state: `blocks_since_activity()` is blocks since the deposit's last authorized operation. `blocks_since_open()` is blocks since the deposit was opened. `deposit_balance()` is the current balance. `rolling_window(field, period)` is the cumulative `field` (`amount_out`, `amount_in`, or `transfer_count`) over the last `period` blocks. `cumulative_spent_via(path)` is the lifetime spend authorized via the descriptor path identified by `path`.

ast inspection: `ast_ref(p)` returns the subtree at path `p`. `ast_shape_at(p)` returns the head constructor at path `p`. `path(i, i, ...)` constructs a path value from a sequence of indices.

## state predicates

state predicates are total deterministic boolean-valued functions of `(w, s)`, constant in `m`. they may appear freely under negation and as conditions of `if` — they cannot be exploited by withholding because they do not depend on the witness.

miniscript-compatible: `older(n)`, `after(n)`. amount-based: `amount_at_most(n)`, `amount_in_range(low, high)`, `amount_at_most_pct(p)`. destination-based: `destination_is(id)`, `destination_in(set)`. balance-based: `balance_at_least(n)`, `balance_at_most(n)`. time-based: `blocks_since_activity_at_least(n)`, `blocks_since_open_below(n)`. rolling-window: `rolling_amount_below(n, period)`, `rolling_amount_below_pct(p, period)`. structural: `subtree_at(c, p)` is structural equality of value `c` with the subtree at path `p`.

each parameterized predicate desugars to a comparison plus a base value function. wallets and operators may extend the predicate set; extensions are advertised via capability declaration. the protocol does not fix a closed set, but it does fix the desugaring rules for the predicates above.

## proof obligations

proof obligations are the only constructs whose evaluation depends on `m`. each is satisfied by an entry the witness supplies under the appropriate key. `pk(K)` is satisfied iff `m` contains a valid signature by `K` over the canonical encoding of the operation, under the deposit's domain separator. `pk_any(keys)` is satisfied iff `m` contains a valid signature from at least one key in `keys`. `pk_threshold(k, keys)` is satisfied iff `m` contains valid signatures from at least `k` distinct keys in `keys`. `hashlock(H)` is satisfied iff `m` contains a value whose hash matches `H` under the function encoded in `H`'s type. `attest(K, schema)` is satisfied iff `m` contains a signed attestation by `K` whose payload satisfies `schema`.

the `schema` argument of `attest` is a V value identifying a schema kind. each schema kind has a protocol-defined satisfaction relation between attestation payloads and the schema's parameters. the v1 vocabulary of schema kinds is deferred to a future dep; this dep specifies the discharge mechanism (an attestation entry in `m`, signed by the oracle, whose payload matches the schema) but not the specific kinds an operator must support. operators advertise the schema kinds they implement via capabilities.

a single signature by `K` discharges every occurrence of `pk(K)` in the descriptor. the signature commits to the operation, not to a particular branch, so any branch whose `prove(pk(K))` leaves resolve to this signature is satisfied. branch-disjointness, when desired, must come from the surrounding guards (state predicates that select which branch's other conditions hold).

## witness format

the witness is a keyed bundle, not a positional stack:

```
witness ::= {
  signatures:   { key -> signature, ... },
  preimages:    { hash -> bytes, ... },
  attestations: { oracle_key -> attestation, ... }
}
```

proof obligations are discharged by lookup. there is no branch-selector data and no positional consumption. the evaluator does not need to be told which branch was intended; a branch is open iff its leaves find their witness items and its state predicates evaluate to true.

## operations

every action against a deposit is an operation. each has a canonical encoding under which signatures are computed; the encoding commits to the deposit id, the operation type, the canonical serialization of arguments, a per-deposit monotonically increasing nonce, and an expiry block height. signatures are not replayable across deposits, operation types, or nonces, and become invalid after expiry.

v1 operation types: `spend` carries `destination`, `amount`, `completion_script`, `timeout`, `fee`. `accept` carries `source`, `amount`, `conditions`. `insert` carries `path`, `subtree`. `replace` carries `path`, `subtree`. `delete` carries `path`. `update_metadata` carries `field`, `new_value`.

the canonical encoding for each operation type is specified in dep-17.

## evaluation

evaluation takes `(D, w, s, m)` and produces accept or reject. it first dispatches on the descriptor's scheme, then folds the body. the structural definition:

```
eval(D, w, s, m) =
  case D of
    wsh(body)             -> eval_b(body, w, s, m)
    tr(K)                 -> verify(pk(K), m, w, s)
    tr(K, body)           -> verify(pk(K), m, w, s) || eval_b(body, w, s, m)

eval_b(T, w, s, m) =
  case T of
    and(b1, ..., bn)      -> all (\b -> eval_b(b, w, s, m)) [b1, ..., bn]
    or(b1, ..., bn)       -> any (\b -> eval_b(b, w, s, m)) [b1, ..., bn]
    thresh(k, b1, ..., bn)-> count (\b -> eval_b(b, w, s, m)) [...] >= k
    not(b)                -> not eval_b(b, w, s, m)
    if(c, t, e)           -> if eval_b(c, w, s, m) then eval_b(t, w, s, m)
                                                    else eval_b(e, w, s, m)
    match(v, branches)    -> eval_b(select_branch(eval_v(v, w, s), branches),
                                    w, s, m)
    cmp(op, a, b)         -> op(eval_v(a, w, s), eval_v(b, w, s))
    state(p, vs)          -> p(eval_v(vs, w, s)..., w, s)
    prove(o)              -> verify(o, m, w, s)
```

implementations may evaluate `tr(K, body)` by trying the key-path before reifying the body; the verdict is unchanged because `or` is symmetric and `verify(pk(K), …)` is m-monotone like every other proof obligation.

`select_branch` returns the branch whose tag equals the scrutinee, falling through to the `else` branch if none matches.

evaluation is strict, total, and structural. there is no recursion, iteration, search, or fixpoint; the witness is supplied, not computed. cost is polynomial in `|T|`, `|w|`, and the snapshot data the term references. most node types contribute constant work per evaluation, but `subtree_at` and `cmp` over reflective values (`ast_ref`, `operation_subtree`) cost time proportional to operand size. the worst-case bound is `O(|T| · (|T| + |w|))` for terms heavy in reflective comparisons; for terms without them it is `O(|T|)`.

## admission

a descriptor is admitted at deposit-open and re-admitted as part of every modification operation that produces a new descriptor. admission runs two checks; failure of either rejects the candidate. both are syntactic, depend on no operation or witness or state, and run in time linear in the descriptor.

**polarity.** every occurrence of `prove(o)` in the body must be in positive position. positive position is defined inductively: the body's root is positive; a `B`-subterm directly under `and`, `or`, `thresh`, or in a branch body of `if(_, B, B)` or `match(_, branch(_, B), ...)` inherits the polarity of its enclosing context; a `B`-subterm under `not(_)` or in the condition slot of `if(B, _, _)` is non-positive. `V`-positions cannot contain `prove(o)` by sort discipline and need not be checked. the scheme wrapper contributes no proof obligations of its own — `tr(K, body)` is `or(prove(pk(K)), body)` semantically, and the synthesized `prove(pk(K))` arm is in positive position by construction — so polarity is a single check on the body regardless of scheme.

the polarity check rejects `prove` under `not` absolutely, not relative to parity. parity-flipping (under which `not(not(prove(o)))` would be admitted) would break the m-constancy invariant the witness-monotonicity proof depends on; acceptance of double-negated proof obligations is structurally lost, with no practical cost. see calculus.md §2.4 for the justification.

**capability.** every combinator, value function, state predicate, proof-obligation form, and operation type used in the descriptor must appear in the operator's advertised capability set.

a descriptor that passes admission is well-formed in the sense the system invariant requires. every descriptor against which the protocol evaluates an operation has passed admission.

operators may impose additional operational limits — maximum descriptor size, maximum nesting depth, maximum operation argument size — as a matter of local policy. these are not protocol-level checks; they are how an operator manages its own resources and need no admission machinery.

## modification

modification operations (`insert`, `replace`, `delete`) target ast paths into the descriptor and produce a candidate descriptor `D'` from the current descriptor `D` and the operation's arguments. the operator computes `D'`, runs admission against it, and binds the deposit to `D'` only if both checks pass. a candidate that fails either is rejected — the modification operation as a whole is rejected, even though `D` authorized the underlying request.

paths are rooted at the descriptor (see §descriptor structure), so every modifiable position is in the path space. for `wsh(body)`, all modifiable positions live under `[0, …]` (inside the body). for `tr(K, body)`, the internal key is at `[0]` and the body's positions are under `[1, …]`. internal-key rotation is therefore a `replace` operation at path `[0]` of a `tr` descriptor, authorized by whatever the descriptor's current authorization paths admit — typically the existing K signing — and subject to admission like any other modification. the scheme tag itself is the descriptor's root identity and is not addressable by any path; a modification cannot rewrite a `wsh` descriptor into a `tr` descriptor or vice versa. modifications against `tr(K)` (no body) accept path `[0]` to rotate the internal key and reject any other path with no addressable position.

this preserves the system invariant inductively. deposit-open establishes admission; each modification preserves it by re-check. modifications may expand, narrow, or rearrange authority — the calculus does not constrain the relationship between `D` and `D'` beyond well-formedness. this is deliberate: recovery use cases require expansion (a quorum of guardians installing a new principal key), and a narrowing-only discipline would foreclose them. see calculus.md §3.4.

paths in v1 are positional. a modification produces a new descriptor in which subtrees may have shifted to new positional addresses. descriptors whose guards depend on stable cross-modification references should encode the relevant structure into operation argument shape rather than positional paths; named-slot extensions are deferred to a future dep.

## fraud proofs

every operation produces a fraud-proof input of the shape

```
(T, w, s_t, m, verdict, ledger_update)
```

where `T` is the descriptor in effect at time `t`, `w` is the operation, `s_t` is the ledger-state snapshot at `t`, `m` is the witness, `verdict` is the operator's accept/reject, and `ledger_update` is what the operator wrote to the ledger. a verifier replays `eval(T, w, s_t, m)`, compares to `verdict`, and checks that the ledger update is consistent with the verdict. mismatch on either is a provable operator fault.

determinism of replay holds given protocol-fixed canonical encodings of operations, state snapshots, and descriptors. the encodings are specified in dep-17.

this fraud-proof shape covers all operation types. there is no per-operation variant — `spend`, modification, `accept`, and `update_metadata` all reduce to the same shape. per-operation variants previously planned are replaced by this.

## capability declarations

an operator declares its capability set in metadata accessible to wallets at deposit-open. the set lists supported value functions, supported state predicates, supported operation types, supported proof-obligation forms, and supported scheme tags. for proof-obligation forms parameterized by hash type or schema kind, the granularity is per type: an operator may declare `hashlock` for sha256 without declaring it for ripemd160, and may declare `attest` with one schema kind without declaring it with another. for schemes the granularity is per tag: an operator may declare `wsh` without declaring `tr`, e.g., to defer Schnorr / x-only key support until it is ready.

the boolean connectives — `and`, `or`, `not`, `thresh`, `if`, `match`, `cmp` — and the sort/coercion machinery (`prove`, the `with` binder, `branch`) are part of the language core and always available. capabilities apply only to the five gated categories above.

a deposit may open against an operator only if every primitive in its descriptor appears in the operator's set. the protocol fixes a minimum capability set every operator must implement: as proof-obligation forms, `pk`, `pk_threshold`, and `hashlock` with all four hash types (sha256, hash256, ripemd160, hash160); as state predicates, `older` and `after`; as operation types, `spend`; as scheme tags, `wsh`. `tr` is opt-in beyond the minimum. beyond the minimum, capability sets vary across operators.

cosigning quorum members must implement every primitive their operator declares — quorum members verify the operator's evaluations and must run the same evaluator. quorum formation rejects members whose declared implementation does not cover the operator's declared set.

the capability mechanism is the protocol's primary lever for evolving the language. new predicates, operation types, proof-obligation forms, and schema kinds can be introduced by operators advertising them, without consensus changes. wallets that recognize a new capability can use it; deposits using it work only against operators that advertise it. operators that drop a capability force open deposits using it to either close, migrate to another operator, or wait for the capability's return.

## canonical encodings

three encodings are fixed at the protocol level and required for cross-implementation determinism. the operation encoding determines what signatures over operations commit to and is what fraud-proof replay verifies signatures against. the state-snapshot encoding determines what state predicates read and what fraud-proof replay reproduces. the descriptor encoding determines what `ast_ref`, `subtree_at`, and structural comparisons compute against, and what the descriptor commits to when its root hash is recorded.

all three are specified in dep-17. implementations that do not honor them produce divergent fraud proofs and cannot participate in the protocol.

## error semantics

admission errors are returned to the wallet with a structured reason: which check failed (polarity or capability), and which subterm or primitive triggered the failure. the descriptor does not take effect.

evaluation does not produce errors in the conventional sense. saturation and division by zero are total functions and return values, not faults. lookup failure on a proof obligation evaluates that obligation to false. unmatched scrutinee is impossible in an admitted descriptor because `else` is grammatically required.

modification errors — candidate `T'` fails admission — return to the wallet with the failed check identified. the descriptor remains `T`.

operators that fail to run the evaluator correctly produce verdicts that disagree with replay and are detected by fraud proof.

## integration with existing deps

this dep modifies or supersedes parts of:

- **dep-01 (deposits):** the descriptor field of a deposit is generalized from a miniscript expression to a term in this calculus. existing miniscript descriptors continue to validate as a sublanguage.
- **dep-02 (transfers):** the `spend` operation's authorization is evaluated against the deposit's descriptor as a term in this calculus, not as a bitcoin script. transferlock and transfercomplete shapes are unchanged.
- **dep-08 (cosigning):** cosigners run the evaluator described here. quorum admission references the capability declaration mechanism.
- **dep-12 (fraud proofs):** the shape above is the canonical fraud proof for all operation types. per-operation variants are dropped.

it depends on:

- **dep-17 (canonical encodings):** operations, state snapshots, and descriptors.
- **dep-N (state commitments):** operator commitments to ledger state, against which fraud proofs verify.

it does not affect:

- reserves utxos (dep-04): on-chain enforcement uses plain tapscript. this language is off-chain only.
- deposit open and close protocol (dep-01) beyond the descriptor field generalization.
- cosigning quorum economics (dep-08).

## examples

delegate with allowance and recovery, under the default scheme:

```
wsh(with(
  user = K1,
  delegate = K2,
  guardians = [K3, K4, K5],
  recovery_to = D1,
  in match(operation_type(),
    branch(spend,
      or(
        prove(pk(user)),
        and(
          prove(pk(delegate)),
          state(amount_at_most_pct, 10),
          state(rolling_amount_below_pct, 30, 4320)
        ),
        and(
          prove(pk_threshold(2, guardians)),
          state(blocks_since_activity_at_least, 4320),
          state(destination_is, recovery_to)
        )
      )
    ),
    branch(insert, prove(pk(user))),
    branch(replace, prove(pk(user))),
    branch(delete, prove(pk(user))),
    branch(else, false)
  )
))
```

user spends without limit. delegate spends up to 10% of balance per operation with a rolling 30-day cap of 30% of balance. a 2-of-3 guardian quorum sends to `recovery_to` after roughly 30 days of inactivity. modifications require the user's signature; other operation types are denied.

bare authorization:

```
prove(pk(user_key))
```

`user_key` authorizes any operation presented. `pk` semantics commit to the operation, so a signature over a spend does not authorize a modification; both are permitted only if signed separately. the descriptor's author has chosen not to differentiate by operation type.

synthetic position bound by oracle attestation:

```
with(
  user = K1,
  rebalancer = K2,
  oracle = K3,
  counterparty = D1,
  in match(operation_type(),
    branch(spend,
      or(
        prove(pk(user)),
        and(
          prove(pk(rebalancer)),
          state(destination_is, counterparty),
          prove(attest(oracle, price_schema(50)))
        )
      )
    ),
    branch(else, false)
  )
)
```

the rebalancer may send to the counterparty only if an oracle attestation by `oracle` matches the operation's amount within 50 basis points (the schema's tolerance). user retains unilateral spending authority. modifications and other operation types are denied. `price_schema` here is a schema kind whose exact form is deferred to a future dep; this example illustrates the discharge shape, not the concrete schema vocabulary.

guardian-driven principal-key rotation (implicit `wsh`):

```
with(
  user = K1,
  guardians = [G1, G2, G3, G4],
  in match(operation_type(),
    branch(spend, prove(pk(user))),
    branch(replace,
      or(
        prove(pk(user)),
        and(
          prove(pk_threshold(3, guardians)),
          state(blocks_since_activity_at_least, 8640),
          cmp(=, operation_path(), path(0, 0))
        )
      )
    ),
    branch(else, false)
  )
)
```

user spends and modifies freely. a 3-of-4 guardian quorum may replace the subtree at path `[0, 0]` — `[0]` into the body, then `[0]` into the body's match, addressing the spend branch body (the user's clause) — after roughly 60 days of inactivity. this is the recovery path that requires expansion of authority and that capability-narrowing systems cannot express.

internal-key bypass over the same policy:

```
tr(K_super, with(
  user = K1,
  guardians = [G1, G2, G3, G4],
  in match(operation_type(),
    branch(spend, prove(pk(user))),
    branch(replace,
      or(
        prove(pk(user)),
        and(
          prove(pk_threshold(3, guardians)),
          state(blocks_since_activity_at_least, 8640),
          cmp(=, operation_path(), path(1, 0))
        )
      )
    ),
    branch(else, false)
  )
))
```

semantically `or(prove(pk(K_super)), body)`. `K_super` authorizes any operation, including modifications, regardless of the body — the calculus's structural analog of bitcoin p2tr's key-path. all guard and recovery semantics of the body are preserved when `K_super` does not sign; when it does, the body is bypassed. choosing the internal key is a security decision distinct from choosing the script-path keys, and its custody discipline must reflect that.

note the path shift: under `tr`, the body root is at `[1]` (with `[0]` reserved for the internal key), so the spend branch body is at `[1, 0]` rather than the `[0, 0]` of the `wsh` form. an authorized `replace` operation at path `[0]` of this descriptor rotates `K_super` itself.

## open questions

several details are deferred to subsequent deps or to v2:

- **named slots for stable cross-modification references.** v1 uses positional paths.
- **predicate vocabulary.** the set in this dep is a starting point; the protocol-fixed set will grow or contract empirically as wallets and operators converge on common templates.
- **descriptor canonicalization.** dep-17 fixes the exact canonical encoding; the boundary between protocol-fixed and implementation-chosen encoding details may need refinement.
- **migration of capability sets.** what happens to deposits using a primitive an operator subsequently drops is sketched above (close, migrate, wait) but not specified in detail.
