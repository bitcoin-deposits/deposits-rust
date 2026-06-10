# A monotone term calculus for ledger-based deposit authorization

## Abstract

We describe a small term calculus for authorizing operations on accounts in a ledger-based system. A deposit's authorization condition is a closed term in this calculus, evaluated against an operation, a ledger-state snapshot, and a witness, to produce accept or reject. The calculus is strict, total, and statically checked against a single placement rule that guarantees authorization is monotone in the witness. The same calculus authorizes modification of the term itself, so capability attenuation and related policy disciplines are expressible within the language rather than enforced by a separate relation. The design recombines elements from miniscript's implicit positive-position discipline, the capability-attenuation tradition, and the bounded-policy-language tradition of macaroons and Cedar.

The calculus is not a programming language and not a smart-contract platform. It governs no UTXOs. It authorizes operations within a single ledger account, and only that.

## 1. Proposal

A *deposit* is an account in a ledger. Each deposit carries an *authorization term* in the calculus described below. *Operations* on the deposit — spending, modifying the authorization term, receiving funds under specified conditions, updating metadata — are presented to the term for authorization. Authorization succeeds iff the term evaluates to `true` against the operation, the current ledger state, and a witness supplied with the operation.

The calculus is intended to satisfy four requirements:

1. Evaluation is strict, total, deterministic, and linear in term size.
2. Authorization is monotone in the witness: acquiring additional capabilities — signatures, preimages, attestations — cannot revoke authority. This is enforced statically.
3. The authorization term is data addressable by the calculus, so modification of the term is an operation like any other, and attenuation disciplines are expressed as guards on modification rather than enforced as a separate relation.
4. The calculus is small enough that conforming implementations of evaluation are straightforwardly verifiable for cross-implementation equivalence.

## 2. The calculus

### 2.1 Sorts

The calculus has three sorts:

- **B**, the sort of authorization decisions. A closed term of sort `B` is an authorization condition.
- **V**, the sort of values. Inhabitants include integers, public keys, hashes, paths into terms, subterms reified as data, and structured payloads such as operation arguments and attestation contents.
- **O**, the sort of *proof obligations*. A leaf of sort `O` denotes a fact that must be discharged by the witness. Proof obligations are injected into `B` by a coercion `prove : O → B`.

The distinction between leaves of `B` introduced via `prove` and leaves of `B` drawn from closed-world data is load-bearing.

### 2.2 Syntax

```
B ::=  and(B, ..., B)
    |  or(B, ..., B)
    |  thresh(k, B, ..., B)
    |  not(B)
    |  if(B, B, B)
    |  match(V, branch(V, B), ..., branch(else, B))
    |  cmp(@, V, V)               -- @ in {=, <, <=, >, >=}
    |  state(p, V, ..., V)        -- state predicate p applied to values
    |  prove(O)

V ::=  literal | varref | op(V, ..., V)
    -- op is drawn from a fixed signature of total functions

O ::=  pk(V)                       -- signature by a key
    |  hashlock(V)                 -- preimage of a hash
    |  attest(V, V)                -- oracle attestation matching a schema
```

The protocol fixes finite signatures of state predicates `p` (e.g., `blocks_since_open`, `deposit_balance`, `operation_arg(_)`) and value functions `op` (arithmetic, comparison, AST inspection). These signatures are the only avenue by which the calculus accesses the environment.

Closed terms of sort `B` are *authorization terms*.

### 2.3 Evaluation

An *environment* is a triple `(w, s, m)` where `w` is the operation being authorized, `s` is a ledger-state snapshot, and `m` is a *witness* — a finite map from {public keys, hashes, oracle keys} to {signatures, preimages, attestations}.

Evaluation `[[ T ]] (w, s, m)` is a strict, total, structural fold:

- `V`-terms reduce to values by total functions of `(w, s)`.
- `state(p, ...)` and `cmp(...)` reduce to booleans by total functions of `(w, s)`.
- Boolean connectives have standard semantics; `match` selects a branch by equality of scrutinee with branch tag, or `else`.
- `prove(o)` evaluates to `true` iff `m` contains a discharging entry for `o` that verifies against `(w, s)`. The witness is queried by *lookup*: `pk(K)` asks `m` for a signature under key `K` over the canonical encoding of `w`; `hashlock(H)` asks `m` for a preimage of `H`. There is no positional consumption of the witness and no branch-selector data.

There is no recursion, iteration, or search. The witness is supplied, not synthesized. Evaluation terminates in `O(|T|)`.

### 2.4 The polarity rule

Define the *positive-position* judgment P inductively on contexts. The root of a term is in positive position. A subterm directly under `and(...)`, `or(...)`, `thresh(k, ...)`, or in a branch body of `if(_, B, B)` or `match(_, branch(_, B), ...)` is in positive position iff the enclosing context is. A subterm under `not(_)`, in the *condition* slot of `if(B, _, _)`, or in the *scrutinee* slot of `match(V, _, ...)` is not in positive position.

The polarity rule is:

> **Every occurrence of `prove(o)` in an authorization term must lie in positive position.**

The rule is checked once, statically, when a term is admitted to the protocol. Terms that violate it are rejected. The rule applies only to `prove`; `state(...)`, `cmp(...)`, and `V`-expressions are unconstrained and may appear freely under negation, as conditions, or as scrutinees.

## 3. Properties

### 3.1 Witness-monotonicity

Define a partial order on witnesses: `m <= m'` iff every entry in `m` is present in `m'` and verifies identically. Intuitively, `m'` represents at least as much capability as `m`.

**Theorem (witness-monotonicity).** *For every authorization term T satisfying the polarity rule, every operation w, every state s, and witnesses m <= m', if `[[ T ]] (w, s, m) = true` then `[[ T ]] (w, s, m') = true`.*

*Proof sketch.* By structural induction on `T`, tracking polarity. The induction is on a pair: the term and the parity of the enclosing context. At a `prove(o)` node, polarity is positive, so a transition `false -> true` as `m` grows is preserved upward through monotone connectives. At `state(...)`, `cmp(...)`, and `V`-expressions, the evaluation does not depend on `m`, so the value is unchanged. The polarity rule excludes the contexts in which a false-to-true transition at a leaf could flip a gate from true to false: `not` flips polarity, and the condition of `if` and the scrutinee of `match` discard the polarity of their operand by introducing case analysis. The rule thus admits exactly those positions where leaf monotonicity propagates upward. ∎

Witness-monotonicity is the security property the calculus is engineered to guarantee. A party that holds a key cannot fabricate authority by pretending not to hold it: no well-formed term has a branch gated on key-absence, so no branch is unlocked by withholding.

### 3.2 State predicates carry no monotonicity burden

State predicates depend on `(w, s)` and not on `m`. Their truth values are fixed by the environment, and an adversary cannot withhold the operation's arguments or the ledger state. Closed-world expressivity — negation, disjunction, comparison, dispatch — is therefore admissible at state predicates without endangering the monotonicity theorem.

This is what distinguishes the calculus from a pure capability calculus, in which all leaves are proof obligations and negation is therefore inadmissible everywhere, and from a general policy language, in which negation is admitted over all data and monotonicity is forfeited.

### 3.3 Determinism

The value functions and state predicates are specified as total functions of `(w, s)`. Witness lookup is deterministic given `(o, w, s, m)`: the predicate either finds a verifying entry or does not. Evaluation contains no search. It follows that for fixed `(T, w, s, m)`, evaluation yields a fixed verdict in every conforming implementation. This property is required for the calculus to underpin a fraud-proof mechanism: a verifier replays `[[ T ]] (w, s, m)` and either confirms or contradicts the operator's verdict, with no ambiguity to adjudicate.

### 3.4 Reflexivity

A term `T` is data. The value signature includes total functions that read `T` as structured data:

```
ast_ref(p)       : V    -- subterm at path p
ast_shape_at(p)  : V    -- head constructor at path p
subtree_at(c, p) : V    -- structural equality of c with the subtree at p
```

The protocol's operation set includes ast-modifying operations `insert(p, s)`, `replace(p, s)`, `delete(p)`. When such an operation is authorized by the current term `T`, the protocol computes the resulting term `T'` and binds the deposit to `T'`; subsequent operations are authorized by `T'`.

Because modification is an operation, its authorization condition is an expression in `T`. The set of `(m, s)` pairs accepted by `T'` for a fixed operation `w` may be a subset, a superset, or neither, of the set accepted by `T`; the relationship is whatever the modification guards in `T` produce. The protocol enforces what the guards say. Attenuation, in the sense of the capability-security literature, is a property a well-written `T` may have; the calculus does not require it.

## 4. Precedent

The calculus draws on four bodies of prior work.

**Bitcoin miniscript** (Wuille, Poelstra, Russell, et al.) implements a monotone authorization calculus by construction. Its leaves are proof obligations on a spending witness, and its expression grammar admits no boolean negation, so the positive-position discipline holds implicitly. Miniscript has no closed-world state predicates beyond the timelocks `older` and `after`, and no notion of self-modification. The present calculus generalizes miniscript along both axes while retaining its monotonicity property; the polarity rule of §2.4 is the discipline miniscript enforces grammatically, made explicit.

**The capability-security tradition** (Dennis and Van Horn 1966; the KeyKOS, EROS, and Coyotos lineage of capability operating systems; Miller's E language; Pony's reference capabilities; and more recently the ERC-7579 / Rhinestone Smart Sessions work in the Ethereum account-abstraction stack) studies authority as a delegable, attenuable resource. The property that a holder of an authority may mint a strictly weaker sub-authority is the property the present calculus expresses via modification guards. The capability-attenuation literature typically presumes either a fixed operation set with attenuation as a relation on policies, or general reflection with soundness becoming nontrivial. The present calculus sits between these: the operation set is finite and the predicate signature is fixed, but the term is reflective in the limited sense that ast operations are part of the value signature.

**Macaroons** (Birgisson, Beresford, Erlingsson, Pihur, et al., 2014) demonstrate that a sufficiently restricted caveat language with conjunction-only composition supports usable reasoning about delegation chains. Macaroons restrict caveats to closed-world predicates and avoid the negation problem by avoiding negation entirely. The present calculus admits negation on closed-world predicates while excluding it on proof obligations, which yields strictly more expressive policies than macaroons admit, at the cost of an explicit polarity check.

**Cedar** (Cutler, Schäf, Schlaipfer, et al., 2024) and the broader decidable-policy-language tradition (Datalog with stratified negation; XACML; OPA/Rego with bounded recursion) are policy languages designed for static analyzability over structured authorization data. Cedar's design choice to bound expressivity in service of analyzability is the same choice the present calculus makes; the differences are that Cedar does not have proof obligations in the present sense — it is a policy-evaluation engine over named principals and resources — and that Cedar does not admit reflection.

We are not aware of prior systems that combine (a) a monotone authorization calculus in the miniscript sense, (b) closed-world state predicates with full boolean expressivity, and (c) reflexive self-modification authorized within the same calculus, into a single decidable, deterministic term language. The combination is what the calculus contributes; the individual elements are not novel.

## 5. Why it works

Three observations underpin the design.

**Witness-monotonicity, not stack-discipline, is what makes miniscript safe.** Miniscript's stack-typed grammar is a means to an end: it admits only positive-position uses of proof obligations because Bitcoin script provides no usable boolean negation. The stack discipline is incidental to the safety property; the positive-position invariant is essential. Replacing the implicit grammatical discipline with an explicit polarity check on a richer term language preserves the safety property while freeing the language from Bitcoin script's stack semantics.

**Closed-world predicates do not threaten monotonicity.** The risk in admitting negation into an authorization language is that an adversary may reach a branch gated on absence by withholding capability. Closed-world predicates depend on data the adversary does not control: the operation arguments are committed to by the witness's signatures, the ledger state is global. There is nothing to withhold. The polarity rule formalizes the distinction: it constrains exactly the leaves whose truth depends on the witness, and nothing else. The expressivity gain over miniscript — negation, dispatch, comparison over operation arguments and ledger state — comes without cost to monotonicity.

**Self-modification can be made safe by treating it as an operation under the same calculus.** Attenuation in the capability-security tradition is a relation between policies, expressed in a separate metalanguage. By making the authorization term itself addressable as data, and modification an operation authorized by the term, the relation collapses into the calculus: a modification guard is a term, evaluated under the same semantics as a spending guard. The protocol does not enforce attenuation; the guards do, or do not, as their authors write them. This places the responsibility for safe modification on the author of the term. We take this to be acceptable in the deposit context, where authority over a deposit is exercised by its creator and the consequences of unsafe terms are borne by the same party.

These three observations together yield the calculus: a strict total term language, with two sorts of leaves and a single polarity rule, that authorizes its own modification and admits closed-world predicates without forfeiting the monotonicity that makes it safe.
