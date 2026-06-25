//! Browser wasm wrapper around `deposits-audit`.
//!
//! The explorer already fetches the base64-encoded TLV update blobs for a
//! ledger from the Nostr relay. It passes them here as a JSON array of strings;
//! we decode + replay through the canonical `LedgerState` and return the
//! `AuditReport` as JSON. Same code path as the `replay-ledger` CLI, so the
//! explorer's solvency numbers can never disagree with the command line.

use wasm_bindgen::prelude::*;

/// Audit a ledger from its base64 TLV update blobs.
///
/// `updates_b64_json` is a JSON array of base64 strings (the `content` field of
/// each kind:9100 event). Returns the `AuditReport` serialized as JSON. On
/// malformed input returns a JSON object with an `error` field.
#[wasm_bindgen]
pub fn audit(updates_b64_json: &str) -> String {
    let blobs: Vec<String> = match serde_json::from_str(updates_b64_json) {
        Ok(v) => v,
        Err(e) => {
            return format!("{{\"error\":\"bad input: {}\"}}", e.to_string().replace('"', "'"))
        }
    };
    let report = deposits_audit::audit_base64(&blobs);
    serde_json::to_string(&report).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
}

/// Version marker so the explorer can confirm the wasm module loaded.
#[wasm_bindgen]
pub fn audit_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
