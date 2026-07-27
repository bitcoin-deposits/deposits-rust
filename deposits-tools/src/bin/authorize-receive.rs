//! Thin CLI wrapper around [`Dep16Authorizer::authorize_receive`] for the
//! round-trip cross-implementation test in
//! `deposits-web/wallet/tests/round-trip-receive.test.mjs`.
//!
//! Usage:
//!   authorize-receive --descriptor <desc> --deposit-id <hex16>
//!                     [--transfer-id <hex32>] <<< '<ReceiveWitness JSON>'
//!
//! Reads a `ReceiveWitness` JSON object from stdin, runs
//! `Dep16Authorizer::authorize_receive`, and exits:
//!   0 — authorized
//!   1 — rejected
//!   2 — usage / parse error (bad args, malformed JSON, etc.)
//!
//! No stdout output on success or rejection. Errors go to stderr.

use deposits_core::dep16::{Dep16Authorizer, ReceiveWitness};
use std::io::Read;

fn parse_hex_bytes(s: &str, expected_len: usize, name: &str) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(s).map_err(|e| format!("--{} hex decode: {}", name, e))?;
    if bytes.len() != expected_len {
        return Err(format!(
            "--{}: expected {} bytes, got {}",
            name,
            expected_len,
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn main() {
    let mut descriptor: Option<String> = None;
    let mut deposit_id_hex: Option<String> = None;
    let mut transfer_id_hex: Option<String> = None;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--descriptor" if i + 1 < args.len() => {
                descriptor = Some(args[i + 1].clone());
                i += 2;
            }
            "--deposit-id" if i + 1 < args.len() => {
                deposit_id_hex = Some(args[i + 1].clone());
                i += 2;
            }
            "--transfer-id" if i + 1 < args.len() => {
                transfer_id_hex = Some(args[i + 1].clone());
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: authorize-receive --descriptor <desc> --deposit-id <hex16> \
                     [--transfer-id <hex>] <<< '<ReceiveWitness JSON>'"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown arg: {}", other);
                std::process::exit(2);
            }
        }
    }

    let descriptor = match descriptor {
        Some(d) => d,
        None => {
            eprintln!("missing --descriptor");
            std::process::exit(2);
        }
    };
    let deposit_id_bytes = match deposit_id_hex
        .as_deref()
        .map(|s| parse_hex_bytes(s, 16, "deposit-id"))
    {
        Some(Ok(b)) => b,
        Some(Err(e)) => {
            eprintln!("{}", e);
            std::process::exit(2);
        }
        None => {
            eprintln!("missing --deposit-id");
            std::process::exit(2);
        }
    };
    let mut deposit_id = [0u8; 16];
    deposit_id.copy_from_slice(&deposit_id_bytes);

    let transfer_id_bytes: Option<Vec<u8>> = match transfer_id_hex.as_deref() {
        Some(s) => match hex::decode(s) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("--transfer-id hex decode: {}", e);
                std::process::exit(2);
            }
        },
        None => None,
    };

    let mut stdin_buf = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut stdin_buf) {
        eprintln!("stdin read: {}", e);
        std::process::exit(2);
    }
    let witness: ReceiveWitness = match serde_json::from_str(&stdin_buf) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("receive_witness JSON parse: {}", e);
            std::process::exit(2);
        }
    };

    let authorizer = Dep16Authorizer::new();
    let verdict = authorizer.authorize_receive(
        &descriptor,
        &deposit_id,
        transfer_id_bytes.as_deref(),
        &witness,
    );
    std::process::exit(if verdict { 0 } else { 1 });
}
