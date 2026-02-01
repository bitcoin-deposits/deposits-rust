use ratatui::{prelude::*, widgets::*};

use crate::app::App;

pub fn draw(f: &mut Frame, _app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help ")
        .title_style(Style::default().bold());

    let text = vec![
        Line::from(Span::styled(
            "Deposits Explorer - Keyboard Shortcuts",
            Style::default().bold().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(Span::styled("Global", Style::default().bold())),
        Line::from("  q          Quit"),
        Line::from("  B          Go to Blocks view"),
        Line::from("  L          Go to Ledgers view"),
        Line::from("  /          Search (txid, address, block height, ledger)"),
        Line::from("  R          Refresh current view"),
        Line::from("  ?          Show this help"),
        Line::from("  Esc        Go back / close modal"),
        Line::from(""),
        Line::from(Span::styled("Navigation", Style::default().bold())),
        Line::from("  j / Down   Move down"),
        Line::from("  k / Up     Move up"),
        Line::from("  g          Go to top"),
        Line::from("  G          Go to bottom"),
        Line::from("  Enter      Select / drill down"),
        Line::from("  Tab        Switch panel focus (in Transaction view)"),
        Line::from(""),
        Line::from(Span::styled("Ledgers View", Style::default().bold())),
        Line::from("  O          View operations for selected ledger"),
        Line::from("  S          View reserves for selected ledger"),
        Line::from("  Enter      Same as O (view operations)"),
        Line::from(""),
        Line::from(Span::styled("Transaction View", Style::default().bold())),
        Line::from("  Tab        Switch between inputs and outputs"),
        Line::from("  Enter      Navigate to selected input's prev tx"),
        Line::from("             or output's spending tx"),
        Line::from(""),
        Line::from(Span::styled("Search", Style::default().bold())),
        Line::from("  Auto-detects query type:"),
        Line::from("  - 64 hex chars: txid or block hash"),
        Line::from("  - bc1/bcrt1/tb1 prefix: address"),
        Line::from("  - Numeric: block height"),
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "Press any key to close",
            Style::default().fg(Color::DarkGray).italic(),
        )),
    ];

    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}
