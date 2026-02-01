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
#[allow(dead_code)]
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Format bytes as hex, truncated
#[allow(dead_code)]
pub fn short_hex(bytes: &[u8], len: usize) -> String {
    let hex = hex::encode(bytes);
    short_hash(&hex, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_btc() {
        assert_eq!(format_btc(100_000_000), "1.00000000 BTC");
        assert_eq!(format_btc(50_000_000), "0.50000000 BTC");
        assert_eq!(format_btc(1_000_000), "0.01000000 BTC");
        assert_eq!(format_btc(10_000), "10000 sats");
        assert_eq!(format_btc(1_000), "1000 sats");
        assert_eq!(format_btc(100), "100 sats");
        assert_eq!(format_btc(1), "1 sats");
        assert_eq!(format_btc(0), "0 sats");
    }

    #[test]
    fn test_format_amount() {
        let (text, color) = format_amount(100_000_000);
        assert_eq!(text, "+1.00000000 BTC");
        assert_eq!(color, Color::Green);

        let (text, color) = format_amount(-50_000);
        assert_eq!(text, "-50000 sats");
        assert_eq!(color, Color::Red);

        let (text, color) = format_amount(0);
        assert_eq!(text, "0 sats");
        assert_eq!(color, Color::White);
    }

    #[test]
    fn test_short_hash() {
        let hash = "7f41c1c04e23ba7cde206aa7d4b55c8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d";
        assert_eq!(short_hash(hash, 8), "7f41c1c0...");
        assert_eq!(short_hash(hash, 64), hash); // No truncation needed
        assert_eq!(short_hash("short", 10), "short"); // Already short enough
    }

    #[test]
    fn test_short_hex() {
        let bytes = [0x7f, 0x41, 0xc1, 0xc0, 0x4e, 0x23, 0xba, 0x7c];
        assert_eq!(short_hex(&bytes, 8), "7f41c1c0...");
        assert_eq!(short_hex(&bytes, 16), "7f41c1c04e23ba7c");
    }

    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(to_hex(&[]), "");
    }
}
