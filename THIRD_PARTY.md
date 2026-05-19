# Third-party code

Forked dependencies vendored under `third_party/`.

| Path                              | Upstream                                          | Imported at                              | License |
|-----------------------------------|---------------------------------------------------|------------------------------------------|---------|
| `third_party/rust-miniscript/`    | https://github.com/rust-bitcoin/rust-miniscript   | tag `miniscript-12.3.6` (2026-05-19)     | CC0-1.0 |

Dependents declare upstream versions (e.g. `miniscript = "12"`); Cargo
redirects resolution to the vendored copy via `[patch.crates-io]` in
the workspace root `Cargo.toml`.

## Importing

Initial import uses `git subtree add` so the upstream history is
squashed into a single merge commit in this repo (no submodules; one
`git clone` brings everything).

```sh
git subtree add --prefix=third_party/<name> <url> <tag-or-commit> --squash
```

## Pulling upstream

```sh
git subtree pull --prefix=third_party/<name> <url> <tag-or-commit> --squash
```

Resolve merge conflicts against any local patches. The squashed commit
records the upstream tag/commit; the subtree commit history under
`third_party/<name>/` is the local diff against that.

## Exporting local patches upstream

```sh
git format-patch -- third_party/<name>/
```

Drop the `third_party/<name>/` prefix from the resulting patches and
submit upstream.

## Adding a new vendored fork

1. `git subtree add` as above.
2. If the upstream package declares its own `[workspace]`, leave it in
   place — do NOT add to our workspace `members`. The `[patch.crates-io]`
   redirect resolves the dependency without making it a workspace member,
   which keeps the upstream manifest pristine for future subtree pulls.
3. Add a `[patch.crates-io]` entry in this repo's root `Cargo.toml`.
4. Run `cargo update -p <name>` to materialize the patch in `Cargo.lock`.
5. Append a row to the table at the top of this file.
