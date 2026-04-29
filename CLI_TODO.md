# CLI cleanup — known TODOs

Tracking the deferred items from the CLI audit. Substantive fixes
(stale examples, wrong subcommand summaries, missing top-level
commands, the `min_fee_sats` → `annualized_fixed_msats` rename, and
the per-subcommand documentation gaps for every group) have all
landed. What remains are the structural items that require scope
decisions.

## Structural cleanups

These are substantive but require scope decisions, so they're
deferred until they're picked up explicitly:

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

### Subcommand-doc CI check

The doc-completeness work covered all known gaps as of this commit,
but nothing prevents drift the next time someone adds a subcommand.
A small CI script that diffs documented subcommands against the
`match` arms in each dispatch table would lock this in. Probably a
test in `deposits-node/tests/` that calls a function which extracts
the help text and walks the dispatch source. Not urgent.
