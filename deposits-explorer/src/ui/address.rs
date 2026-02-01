use ratatui::{prelude::*, widgets::*};

use crate::app::App;
use crate::util::format::{format_btc, short_hash};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Address ")
        .title_style(Style::default().bold());

    if let Some(ref addr) = app.current_address {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6), // Header
                Constraint::Min(5),    // UTXOs
            ])
            .split(area);

        // Header
        draw_address_header(f, addr, chunks[0]);

        // UTXOs
        draw_utxos(f, addr, chunks[1]);
    } else {
        let paragraph = Paragraph::new("No address loaded")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
    }
}

fn draw_address_header(f: &mut Frame, addr: &crate::api::AddressInfo, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Address ")
        .title_style(Style::default().bold());

    let text = vec![
        Line::from(vec![
            Span::styled(&addr.address, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("Type: ", Style::default().fg(Color::Gray)),
            Span::raw(&addr.script_type),
        ]),
        Line::from(vec![
            Span::styled("Balance: ", Style::default().fg(Color::Gray)),
            Span::styled(format_btc(addr.balance()), Style::default().fg(Color::Green).bold()),
            Span::raw(format!(" ({} UTXOs)", addr.utxo_count())),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, area);
}

fn draw_utxos(f: &mut Frame, addr: &crate::api::AddressInfo, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" UTXOs ({}) ", addr.utxos.len()))
        .title_style(Style::default().bold());

    let items: Vec<ListItem> = addr
        .utxos
        .iter()
        .map(|utxo| {
            let confirmed = if utxo.status.confirmed {
                utxo.status
                    .block_height
                    .map(|h| format!("Block #{}", h))
                    .unwrap_or_else(|| "confirmed".to_string())
            } else {
                "unconfirmed".to_string()
            };

            let content = Line::from(vec![
                Span::raw(format!("{}:{} ", short_hash(&utxo.txid, 12), utxo.vout)),
                Span::styled(format_btc(utxo.value), Style::default().fg(Color::Green)),
                Span::raw(format!("  {}", confirmed)),
            ]);

            ListItem::new(content)
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}
