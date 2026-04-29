# CLI cleanup — known TODOs

Tracking the deferred items from the CLI audit. Substantive fixes
(stale examples, wrong subcommand summaries, missing top-level
commands, and the `min_fee_sats` → `annualized_fixed_msats` rename
including the per-period-sats → annualized-msats semantic fix) have
already landed. What's below is doc-completeness and structural
items that are real but lower-priority.

## Subcommand documentation gaps

`deposits-node --help` lists the subcommand groups in the COMMANDS
section, but the per-section blocks below document only a subset of
each group's actual subcommands. The gaps:

### `quorum`
- `quorum remove <…>` — exists in code (`quorum.rs:26`), undocumented in help.

### `ledger`
- `ledger import <…>` — exists, undocumented.
- `ledger advertise [reserves_id] [options]` — exists with its own
  flag set (`--annual-fee-bps`, `--annual-fee-fixed-msats`,
  `--deposit-fee-bps`, `--withdrawal-fee-bps`, `--invoice-fee-bps`,
  `--max-deposit`, `--min-deposit`, `--name`, `--description`,
  `--advertise-relay`, `--fee-period-blocks`). Undocumented.
- `ledger republish <…>` — exists, undocumented.
- `ledger discover [options]` — exists, undocumented.
- `ledger health [reserves_id]` — exists, undocumented.

### `deposit`
- `deposit address <…>` — undocumented.
- `deposit invoice <…>` — undocumented.
- `deposit pending <…>` — undocumented.
- `deposit verify-custodian <…>` — undocumented.
- `deposit collect-fees <…>` — undocumented.

### `lightning`
- `lightning locks` — exists, undocumented.
- `lightning send <…>` — exists, undocumented.

### `nostr`
- `nostr events <…>` — exists, undocumented.
- `nostr request deposit_withdraw <…>` — third action verb supported
  by `nostr request` but not in the help.

### `recovery`
The help block lists 5 subcommands; the dispatch table has 18
(`embed-hash`, `publish-fraud-broadcast`, `dispute`, `rebuild`,
`arm`, `claim`, `continue`, `spend`, `status`, `confiscate`,
`reveal`, `lottery-claim`, `rotate-to-quorum`, `start`, `agree`,
`prepare`, `release`, plus the `rebuild quorum-add` sub-sub).
The help is missing 13.

### `bootstrap`
Top-level command exists; subcommand help is empty. Subcommands:
`init`, `reserves`, `quorum`.

### `admin`
Top-level command exists; subcommand help is empty. Subcommands:
`buffer {open, fill, drain, list}`.

### `health`
Top-level command exists; subcommand help is empty. Subcommands:
`ping`, `chains`, `relays`.

### `danger` (only with `--features dangerous-testing`)
The conditional help block lists 4 violation types; code dispatches
3 top-level subcommands (`publish-invalid`, `forge-stale-cosig`,
`fork-update`) and additional violation types inside
`publish-invalid`. The match between help and code should be made
exhaustive while still gating the whole block on the feature flag.

## Fix shape

Each section's help block should list every dispatched subcommand
with: positional args (name and meaning), flag args (one line per
flag with type + purpose), and a one-sentence "what it does."
Cross-link to the relevant book chapter where the protocol-level
concept is taught.

## Structural cleanups (separate from doc completeness)

These are substantive but require scope decisions, so they're
deferred to a focused pass:

### Three fee-flag vocabularies

`ledger open`, `ledger advertise`, and `nostr request deposit_open`
each use a different flag/positional vocabulary for the same
underlying `FeeStructure`. Pick one canonical naming and apply it
everywhere. Likely candidate, matching the current `ledger open`
shape:
- `--annual-fee-bps`
- `--annual-fee-fixed-msats`
- `--fee-period-blocks`
- `--transfer-fee-fixed-msats`
- `--transfer-fee-rate-bps`

`ledger advertise`'s additional flags (`--deposit-fee-bps`,
`--withdrawal-fee-bps`, `--invoice-fee-bps`, `--max-deposit`,
`--min-deposit`) should also be available on `ledger open` (or the
two should explicitly diverge with documented rationale).

### ID-type confusion

Several positional args take "an identifier" without specifying
which kind. Three IDs in circulation:
- `reserves_id` — Bitcoin address string (`bcrt1q…`/`bc1q…`)
- `ledger_id` — 64-char hex SHA256 hash
- `partner_id` — used only by `withdraw` subcommands; semantically
  identical to `ledger_id`.

Fix shape: most "identifier" positional args should accept either
form and disambiguate by prefix (32-byte hex starting with `[0-9a-f]`
without an `bcrt`/`bc` prefix → ledger_id; address-shaped → reserves_id).
Drop `partner_id` in favor of `ledger_id` everywhere.

### Duplicate-named subcommands

`deposit list` lists offers; `deposit ls` lists deposits-in-a-ledger.
Visually identical commands with materially different behavior.
Either rename one (e.g. `deposit offers list` and `deposit list`),
or merge their code paths.

### Pair semantics not documented

The `withdraw request` vs `withdraw lock` and `deposit credit` vs
`deposit complete` pairs have overlapping behavior. The help should
explicitly say "use `request` for the common case; use `lock` when
you have a pre-signed request from another tool" (or whatever the
correct guidance is — the codebase intent isn't fully clear from
the help).

### `run`-flag documentation

`--metrics-port` is in OPTIONS at the bottom; `--fast-poll` and
several other `run` flags are dispatched in code but not documented.
Audit the run-time-only flag set and document under a `run` section.

### Subcommand alias `nostr broadcast` doesn't exist

The previous summary blurb claimed it did. Now corrected, but the
broader implication: a CI check that diffs documented subcommands
against `match` arms in the dispatch tables would prevent this
class of drift. (Probably overengineered for now; noted as a
future possibility.)
