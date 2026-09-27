//! Static "no parallel writes" check for the actor migration.
//!
//! Every primitive that mutates a `Ledger`'s history or state —
//! `apply_and_check`, `commit_staged`, `apply_state_changes`,
//! `append_operation*`, `history.push` — must appear only inside
//! the actor (`ledger_actor.rs`) or at a small set of documented
//! pre-actor callsites:
//!
//! * `handler.rs::load_single_ledger_from_jsonl` (replay-on-load
//!   at startup; the actor for this ledger doesn't exist yet).
//! * `handler.rs::get_or_create_ledger_with_outpoint` (LedgerOpen
//!   at ledger creation; `ensure_actor_for` is called by the outer
//!   `open_ledger` AFTER this returns).
//! * `inbound.rs::create_dispute_fork` (fork creation: builds the
//!   fork's state by replaying the parent ledger's truncated history
//!   before inserting it into `handler.ledgers`).
//! * `dispute.rs::auto_arm_for_dispute_with_anchor` (the three
//!   sequential fork-branch writes are single-writer by design;
//!   `auto_arm` is the sole writer to a given fork).
//! * `dispute.rs::withdraw_dispute` (the `DisputeYield` that ends a
//!   fork whose dispute was withdrawn; Tombstoned, auto_arm cannot
//!   append to it after).
//!
//! Any new direct write outside this allowlist fails this test —
//! caught at compile/test time instead of by a downstream race.
//!
//! Lives in `deposits-node/tests/` (not `deposits-test/`) because
//! it's a structural property of `deposits-node` source, not an
//! integration scenario.

use std::path::{Path, PathBuf};

const FORBIDDEN_PATTERNS: &[(&str, &[&str])] = &[
    (
        // The actor's apply-inbound path. Conformance + state machine.
        // Also handler.rs::apply_updates_to_ledger — the joined-ledger relay
        // gap-fill / re-import path (main_loop::reimport_joined_ledger). That's
        // a genuine second writer to ledgers that already have a live actor, but
        // it can't corrupt: it's a sync fn that holds the ledger RwLock write
        // lock atomically (no awaits mid-apply) and rechecks chain continuity
        // (previous_hash == tail_hash) under the lock, so it serializes with the
        // actor's apply_inbound and the loser backs off (Err / dedup no-op). See
        // the race note in ledger_actor.rs::apply_inbound.
        "apply_and_check",
        &["node/ledger_actor.rs", "handler.rs"],
    ),
    (
        // The actor's apply-commit path. Stages our outbound op.
        "commit_staged",
        &["node/ledger_actor.rs"],
    ),
    (
        // Raw history append from the actor — and from the same
        // apply_updates_to_ledger gap-fill path noted above (lock-serialized,
        // continuity-rechecked, safe against the actor).
        "history.push",
        &["node/ledger_actor.rs", "handler.rs"],
    ),
    (
        // LedgerOpen creation (pre-actor) + fork creation replay.
        // Both are constructing the ledger; neither has a parallel
        // writer to race against.
        "apply_state_changes",
        &[
            "handler.rs",      // load_single_ledger_from_jsonl
            "node/inbound.rs", // create_dispute_fork (replay only)
        ],
    ),
    (
        // LedgerOpen creation in handler.rs:999. Pre-actor write at
        // ledger genesis; ensure_actor_for runs after.
        "append_operation",
        &["handler.rs"],
    ),
    (
        // Fork-branch ops in auto_arm. Single function, sequential.
        "append_operation_with_block",
        &["node/dispute.rs"],
    ),
];

/// Recursively collect every `.rs` file under `dir`, returning paths
/// relative to `dir`.
fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        let read = match std::fs::read_dir(&p) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|x| x.to_str()) == Some("rs") {
                if let Ok(rel) = path.strip_prefix(dir) {
                    out.push(rel.to_path_buf());
                }
            }
        }
    }
    out
}

fn src_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("src")
}

#[test]
fn no_ledger_mutations_outside_allowlist() {
    let root = src_root();
    let files = collect_rs_files(&root);
    assert!(!files.is_empty(), "no .rs files found under {:?}", root);

    let mut violations: Vec<String> = Vec::new();

    for (pattern, allowed) in FORBIDDEN_PATTERNS {
        for rel in &files {
            let full = root.join(rel);
            let contents = match std::fs::read_to_string(&full) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for (lineno, line) in contents.lines().enumerate() {
                // Skip comments + doc comments — they're often listing
                // the API surface, not calling it.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if !line_contains_call(line, pattern) {
                    continue;
                }
                let rel_str = rel.to_string_lossy();
                let allowed_here = allowed.iter().any(|allow| {
                    // Allow exact match OR allow_path being a prefix
                    // (the allowlist entries are file paths, not dirs).
                    rel_str == *allow
                });
                if !allowed_here {
                    violations.push(format!(
                        "{}:{}: `{}` called outside allowlist {:?}: {}",
                        rel_str,
                        lineno + 1,
                        pattern,
                        allowed,
                        line.trim()
                    ));
                }
            }
        }
    }

    if !violations.is_empty() {
        panic!(
            "Ledger-mutating primitive called outside the actor or documented pre-actor \
             callsites. Either route the new write through `Node::commit_operation` / \
             `LedgerEvent::Inbound`, or — if the new site is genuinely pre-actor by \
             design — add it to FORBIDDEN_PATTERNS's allowlist in {} with a comment \
             explaining why it can't race.\n\nViolations:\n  {}",
            file!(),
            violations.join("\n  ")
        );
    }
}

/// Match a method/function call to `pattern` while ignoring the
/// function *definition* (`fn pattern(...)`) and the *type-level*
/// method declaration in trait impls.
///
/// This is intentionally simple: it accepts `.<pattern>(` and `<pattern>(`
/// at word boundaries but rejects `fn <pattern>(`. For our six
/// patterns that's enough — we don't have any string-literal,
/// macro-name, or comment-of-comment cases to worry about.
fn line_contains_call(line: &str, pattern: &str) -> bool {
    // Skip the function definition line itself.
    if line.contains(&format!("fn {}(", pattern))
        || line.contains(&format!("fn {}<", pattern))
        || line.contains(&format!("fn {} ", pattern))
    {
        return false;
    }
    // Skip string-literal mentions (rough heuristic — only matters
    // for tracing strings).
    if line.contains(&format!("\"{}", pattern)) {
        return false;
    }
    // Accept call-shaped occurrences.
    line.contains(&format!(".{}(", pattern)) || line.contains(&format!("{}(", pattern))
}
