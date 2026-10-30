// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! DEP-16 §Descriptor validity: whether a descriptor may enter a ledger
//! (`DepositOpen`, `DepositKeyRotate`). Pinned by the shared vector
//! `deposits-protocol/tests/vectors/descriptor_validity.json`, which cl-deposits
//! passes too.
//!
//! Valid means: the text is in the descriptor character set, every 66-hex-digit
//! word is a compressed secp256k1 key and no word is 130 hex digits (an
//! uncompressed key), it parses, no `with(...)` name is bound twice, it passes
//! admission (polarity, every name resolves, depth), and every `thresh(k, ...)`
//! has `1 <= k <= n`. Capability is not part of validity: it is the operator's
//! own advertisement, which a judge of the ledger cannot see.

use core::str::FromStr;

use bitcoin::PublicKey;
use miniscript::calculus::ast::BTerm;
use miniscript::calculus::{admit, parse, AdmissionError, CapabilitySet};

fn is_ws(c: u8) -> bool {
    c == b' ' || (0x09..=0x0d).contains(&c)
}

fn is_word(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

/// `None` if `text` is a valid descriptor, else the reason it is not.
pub fn descriptor_violation(text: &str) -> Option<String> {
    let b = text.as_bytes();
    if let Some(&c) = b
        .iter()
        .find(|&&c| !(is_ws(c) || (0x21..=0x7e).contains(&c)))
    {
        return Some(format!(
            "byte 0x{:02x} is outside the descriptor character set",
            c
        ));
    }
    // Words: keys must be compressed points, and count `name =` bindings.
    let mut bindings = 0usize;
    let mut i = 0;
    while i < b.len() {
        if !is_word(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_word(b[i]) {
            i += 1;
        }
        let w = &text[start..i];
        let hex = w.bytes().all(|c| c.is_ascii_hexdigit());
        if hex && w.len() == 130 {
            return Some(format!("`{}…` is an uncompressed key", &w[..8]));
        }
        if hex && w.len() == 66 {
            match PublicKey::from_str(w) {
                Ok(k) if k.compressed => {}
                _ => return Some(format!("`{}…` is not a compressed secp256k1 key", &w[..8])),
            }
        }
        let mut j = i;
        while j < b.len() && is_ws(b[j]) {
            j += 1;
        }
        if j < b.len() && b[j] == b'=' {
            bindings += 1;
        }
    }
    let d = match parse::<PublicKey>(text) {
        Ok(d) => d,
        Err(e) => return Some(e.to_string()),
    };
    if d.constants.len() != bindings {
        return Some("a with(...) name is bound twice".to_string());
    }
    if let Err(e) = admit(&d, &CapabilitySet::everything()) {
        return Some(match e {
            AdmissionError::NegativeProof => {
                "a proof obligation is in negative position".to_string()
            }
            AdmissionError::UnresolvedVar(n) => format!("name `{}` does not resolve", n),
            AdmissionError::TooDeep => "nesting too deep".to_string(),
            other => format!("{:?}", other),
        });
    }
    if let Some(body) = d.body() {
        if let Some(why) = thresh_violation(body) {
            return Some(why);
        }
    }
    None
}

fn thresh_violation<Pk: miniscript::MiniscriptKey>(t: &BTerm<Pk>) -> Option<String> {
    if let BTerm::Thresh(k, bs) = t {
        if *k < 1 || *k > bs.len() {
            return Some(format!("thresh needs 1 <= k <= {}", bs.len()));
        }
    }
    t.children().into_iter().find_map(thresh_violation)
}
