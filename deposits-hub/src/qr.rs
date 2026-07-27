//! Terminal QR rendering using Unicode half-blocks.
//!
//! One terminal cell encodes **two** QR modules (one row in the top
//! half, one in the bottom). That keeps the QR roughly square in
//! typical terminal fonts where character cells are ~2:1 tall.
//!
//! Charset:
//!   * `' '` — both halves off
//!   * `'▀'` — top half on, bottom off  (U+2580 UPPER HALF BLOCK)
//!   * `'▄'` — top off, bottom on       (U+2584 LOWER HALF BLOCK)
//!   * `'█'` — both halves on           (U+2588 FULL BLOCK)
//!
//! A two-module light "quiet zone" border is included by default — the
//! QR spec wants four; we use two to save terminal real estate and
//! still scan reliably on phone cameras under normal lighting.

use qrcode::{EcLevel, QrCode};

/// Render `data` as a QR code using Unicode half-blocks. Returns the
/// full block of text including a trailing newline; print it directly.
///
/// Uses error-correction level **M** (15% recovery) — a sane default
/// for short payloads like nostr pubkeys (66 hex chars). Bumps to L if
/// the payload is too long for M at any supported version.
pub fn render(data: &str) -> String {
    let qr = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M)
        .or_else(|_| QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L))
        .expect("payloads under several KB fit in any QR version");
    render_qr(&qr, 2)
}

fn render_qr(qr: &QrCode, quiet_modules: usize) -> String {
    let w = qr.width();
    let total = w + 2 * quiet_modules;
    let modules = qr.to_colors();

    // Sample a module at logical (x, y) — coordinates include the
    // quiet zone, so anything outside the QR proper is "light" (off).
    let on = |x: usize, y: usize| -> bool {
        if x < quiet_modules
            || y < quiet_modules
            || x >= w + quiet_modules
            || y >= w + quiet_modules
        {
            return false;
        }
        let qx = x - quiet_modules;
        let qy = y - quiet_modules;
        // qrcode::Color::Dark == module on.
        modules[qy * w + qx] == qrcode::Color::Dark
    };

    let mut out = String::with_capacity(total * (total / 2 + 1) * 4);
    // Process two QR rows at a time. If `total` is odd we pad the final
    // row with an implicit "off" bottom half.
    let mut y = 0;
    while y < total {
        for x in 0..total {
            let top = on(x, y);
            let bot = if y + 1 < total { on(x, y + 1) } else { false };
            out.push(match (top, bot) {
                (false, false) => ' ',
                (true, false) => '▀',
                (false, true) => '▄',
                (true, true) => '█',
            });
        }
        out.push('\n');
        y += 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_emits_quiet_zone_and_terminator() {
        let s = render("hello");
        // Last column of the first line should be a space (quiet zone).
        let first_line = s.lines().next().unwrap();
        assert!(
            first_line.chars().all(|c| c == ' '),
            "first line should be all quiet-zone whitespace, got {:?}",
            first_line
        );
        // Trailing newline.
        assert!(s.ends_with('\n'));
        // Contains at least one filled block somewhere (sanity: the
        // finder patterns are dense enough that something must be on).
        assert!(s.chars().any(|c| matches!(c, '█' | '▀' | '▄')));
    }

    #[test]
    fn larger_payload_still_renders() {
        // A 66-char hex pubkey is the canonical operator artifact.
        let pk = "0".repeat(66);
        let s = render(&pk);
        assert!(s.lines().count() > 10);
    }
}
