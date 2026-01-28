// Binary to decode SignedLedgerUpdateLog entries from SQLite database
//
// Usage:
//   # Single record (hex)
//   sqlite3 db.sqlite "select hex(value) from ldk_node_data where secondary_namespace = 'signed_ledger_updates' limit 1" | decode-updates
//
//   # Multiple records (one hex per line)
//   sqlite3 db.sqlite "select hex(value) from ldk_node_data where secondary_namespace = 'signed_ledger_updates'" | decode-updates
//
//   # Single record (base64)
//   sqlite3 db.sqlite "select base64(value) from ldk_node_data where secondary_namespace = 'signed_ledger_updates' limit 1" | decode-updates --base64
//
//   # Multiple records (one base64 per line)
//   sqlite3 db.sqlite "select base64(value) from ldk_node_data where secondary_namespace = 'signed_ledger_updates'" | decode-updates --base64
//
//   # Raw binary from stdin
//   cat raw_bytes.bin | decode-updates --raw
//
//   # Hex from command line
//   decode-updates --hex <hex_string>

use std::io::{self, BufRead, Read, Cursor};
// Use library types directly
use deposits_core::{SignedLedgerUpdate, SignedLedgerUpdateLog};
use deposits_ldk::handler::messages::{DepositsMessage, type_id_to_const_name};
use lightning::util::ser::Readable;
use bitcoin::secp256k1::PublicKey;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

fn format_pubkey(pubkey: &PublicKey) -> String {
    let s = pubkey.to_string();
    if s.len() > 16 {
        format!("{}...", &s[..16])
    } else {
        s
    }
}

fn format_hash(hash: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}...", hash[0], hash[1], hash[2], hash[3])
}

fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "0".to_string();
    }

    use std::time::{UNIX_EPOCH, Duration};
    let d = UNIX_EPOCH + Duration::from_secs(ts);

    // Format as ISO-8601 datetime
    let datetime: chrono::DateTime<chrono::Utc> = d.into();
    datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Decode message bytes using DepositsMessage::read (same as SignedLedgerUpdate::get_message)
/// Returns formatted string describing the message content
fn decode_message_content(_message_type: u16, message_bytes: &[u8]) -> String {
    let mut cursor = Cursor::new(message_bytes);
    match DepositsMessage::read(&mut cursor) {
        Ok(msg) => format!("{:?}", msg),
        Err(e) => format!("Decode error: {:?}", e),
    }
}

fn print_update(idx: usize, update: &SignedLedgerUpdate) {
    let msg_type_name = type_id_to_const_name(update.message_type);

    println!("  [{}] seq={} type=0x{:04x} ({})",
        idx,
        update.sequence_number,
        update.message_type,
        msg_type_name
    );
    println!("      operator: {}", format_pubkey(&update.operator_id));
    println!("      partner:  {}", format_pubkey(&update.partner_id));
    println!("      prev_hash: {}", format_hash(&update.previous_hash));
    println!("      curr_hash: {}", format_hash(&update.current_hash));
    println!("      timestamp: {} ({})", update.timestamp, format_timestamp(update.timestamp));
    println!("      signature: {:02x}{:02x}{:02x}{:02x}...",
        update.operator_signature[0],
        update.operator_signature[1],
        update.operator_signature[2],
        update.operator_signature[3]
    );
    // Decode and display the message content
    let content = decode_message_content(update.message_type, &update.message);
    println!("      message: {}", content);
}

fn decode_and_print(data: &[u8], record_num: usize) {
    if record_num > 0 {
        println!();
        println!("================================================================================");
    }
    println!("Record #{} ({} bytes)", record_num + 1, data.len());
    println!();

    // Try to deserialize as SignedLedgerUpdateLog
    match bincode::deserialize::<SignedLedgerUpdateLog>(data) {
        Ok(log) => {
            println!("=== SignedLedgerUpdateLog ===");
            println!("operator_id: {}", format_pubkey(&log.operator_id));
            println!("partner_id:  {}", format_pubkey(&log.partner_id));
            println!("next_sequence: {}", log.next_sequence);
            println!("updates: {} entries", log.updates.len());
            println!("pending_updates: {} entries", log.pending_updates.len());
            println!();

            if !log.updates.is_empty() {
                println!("--- Updates (committed) ---");
                for (idx, update) in log.updates.iter().enumerate() {
                    print_update(idx, update);
                }
                println!();
            }

            if !log.pending_updates.is_empty() {
                println!("--- Pending Updates (buffered) ---");
                let mut pending: Vec<_> = log.pending_updates.iter().collect();
                pending.sort_by_key(|(seq, _)| *seq);
                for (seq, update) in pending {
                    println!("  [pending seq={}]", seq);
                    print_update(*seq as usize, update);
                }
            }

            // Print hash chain summary
            if log.updates.len() > 1 {
                println!();
                println!("--- Hash Chain Summary ---");
                for (idx, update) in log.updates.iter().enumerate() {
                    if idx == 0 {
                        println!("  {} -> {}", format_hash(&update.previous_hash), format_hash(&update.current_hash));
                    } else {
                        let prev = &log.updates[idx - 1];
                        let chain_ok = update.previous_hash == prev.current_hash;
                        let status = if chain_ok { "OK" } else { "BROKEN!" };
                        println!("  {} -> {} [{}]", format_hash(&update.previous_hash), format_hash(&update.current_hash), status);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to deserialize as SignedLedgerUpdateLog: {}", e);
            eprintln!();
            eprintln!("First 64 bytes (hex): {}", hex::encode(&data[..std::cmp::min(64, data.len())]));
        }
    }
}

fn print_help() {
    eprintln!("Usage: decode-updates [OPTIONS]");
    eprintln!();
    eprintln!("Decodes SignedLedgerUpdateLog entries from SQLite database.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --hex <string>   Decode a single hex string from command line");
    eprintln!("  --base64         Read base64-encoded lines from stdin (one per line)");
    eprintln!("  --raw            Read raw binary from stdin (single record)");
    eprintln!("  --help           Show this help message");
    eprintln!();
    eprintln!("Default: Read hex-encoded lines from stdin (one per line)");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  # Decode all signed_ledger_updates (hex, default)");
    eprintln!("  sqlite3 db.sqlite \"select hex(value) from ldk_node_data \\");
    eprintln!("    where secondary_namespace = 'signed_ledger_updates'\" | decode-updates");
    eprintln!();
    eprintln!("  # Decode all signed_ledger_updates (base64)");
    eprintln!("  sqlite3 db.sqlite \"select base64(value) from ldk_node_data \\");
    eprintln!("    where secondary_namespace = 'signed_ledger_updates'\" | decode-updates --base64");
    eprintln!();
    eprintln!("  # Decode single hex string");
    eprintln!("  decode-updates --hex <hex_string>");
    eprintln!();
    eprintln!("  # Decode raw binary file");
    eprintln!("  cat raw_bytes.bin | decode-updates --raw");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Check for --help
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    // Check for --hex <string>
    if let Some(pos) = args.iter().position(|a| a == "--hex") {
        if pos + 1 < args.len() {
            let hex_str = &args[pos + 1];
            match hex::decode(hex_str) {
                Ok(data) => decode_and_print(&data, 0),
                Err(e) => {
                    eprintln!("Error: Invalid hex string: {}", e);
                    std::process::exit(1);
                }
            }
            return;
        } else {
            eprintln!("Error: --hex requires a hex string argument");
            std::process::exit(1);
        }
    }

    // Check for --raw (raw binary from stdin)
    if args.iter().any(|a| a == "--raw") {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer).expect("Failed to read from stdin");
        if buffer.is_empty() {
            eprintln!("Error: No data provided");
            std::process::exit(1);
        }
        decode_and_print(&buffer, 0);
        return;
    }

    // Check for --base64 (base64 from stdin - handles multi-line base64 per record)
    let use_base64 = args.iter().any(|a| a == "--base64");

    // Read lines from stdin
    let stdin = io::stdin();
    let mut record_count = 0;

    if use_base64 {
        // For base64: SQLite's base64() outputs multi-line base64 with blank lines between records
        // Accumulate lines until we hit a blank line, then decode the accumulated base64
        let mut accumulated = String::new();

        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Error reading line: {}", e);
                    continue;
                }
            };

            let trimmed = line.trim();

            if trimmed.is_empty() {
                // End of a record - decode accumulated base64
                if !accumulated.is_empty() {
                    match BASE64.decode(&accumulated) {
                        Ok(data) => {
                            decode_and_print(&data, record_count);
                            record_count += 1;
                        }
                        Err(e) => {
                            eprintln!("Error decoding base64 record {}: {}", record_count + 1, e);
                        }
                    }
                    accumulated.clear();
                }
            } else {
                // Accumulate base64 content (remove any whitespace)
                accumulated.push_str(trimmed);
            }
        }

        // Handle last record if there's no trailing blank line
        if !accumulated.is_empty() {
            match BASE64.decode(&accumulated) {
                Ok(data) => {
                    decode_and_print(&data, record_count);
                    record_count += 1;
                }
                Err(e) => {
                    eprintln!("Error decoding base64 record {}: {}", record_count + 1, e);
                }
            }
        }
    } else {
        // For hex: one record per line (sqlite hex() outputs single line)
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Error reading line: {}", e);
                    continue;
                }
            };

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            match hex::decode(line) {
                Ok(data) => {
                    decode_and_print(&data, record_count);
                    record_count += 1;
                }
                Err(e) => {
                    eprintln!("Error decoding hex on line {}: {}", record_count + 1, e);
                }
            }
        }
    }

    if record_count == 0 {
        eprintln!("Error: No valid records found");
        std::process::exit(1);
    }

    println!();
    println!("================================================================================");
    println!("Total: {} record(s) decoded", record_count);
}
