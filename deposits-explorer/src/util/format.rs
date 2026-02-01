use ratatui::style::Color;
use std::time::{SystemTime, UNIX_EPOCH};

/// Format satoshis as BTC with appropriate precision
pub fn format_btc(sats: u64) -> String {
    let btc = sats as f64 / 100_000_000.0;
    if sats >= 100_000_000 {
        format!("{:.8} BTC", btc)
    } else if sats >= 1_000_000 {
        format!("{:.8} BTC", btc)
    } else if sats >= 1_000 {
        format!("{} sats", sats)
    } else {
        format!("{} sats", sats)
    }
}

/// Format a signed amount with color
pub fn format_amount(amount: i64) -> (String, Color) {
    let sats = amount.unsigned_abs();
    let formatted = if sats >= 100_000_000 {
        let btc = sats as f64 / 100_000_000.0;
        format!("{:.8} BTC", btc)
    } else {
        format!("{} sats", sats)
    };

    if amount > 0 {
        (format!("+{}", formatted), Color::Green)
    } else if amount < 0 {
        (format!("-{}", formatted), Color::Red)
    } else {
        (formatted, Color::White)
    }
}

/// Format a timestamp as "X ago"
pub fn format_time_ago(timestamp: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(timestamp);

    let diff = now.saturating_sub(timestamp);

    if diff < 60 {
        format!("{}s", diff)
    } else if diff < 3600 {
        format!("{}m", diff / 60)
    } else if diff < 86400 {
        format!("{}h", diff / 3600)
    } else {
        format!("{}d", diff / 86400)
    }
}

/// Truncate a hash/address for display
pub fn short_hash(s: &str, len: usize) -> String {
    if s.len() <= len {
        s.to_string()
    } else {
        format!("{}...", &s[..len])
    }
}

/// Format bytes as hex
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Format bytes as hex, truncated
pub fn short_hex(bytes: &[u8], len: usize) -> String {
    let hex = hex::encode(bytes);
    short_hash(&hex, len)
}
