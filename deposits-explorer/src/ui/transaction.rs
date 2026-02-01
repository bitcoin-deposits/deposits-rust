use ratatui::{prelude::*, widgets::*};

use crate::app::App;
use crate::util::format::{format_btc, short_hash};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Transaction ")
        .title_style(Style::default().bold());

    if let Some(ref tx) = app.current_tx {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5), // Header
                Constraint::Min(5),    // Inputs/Outputs
            ])
            .split(area);

        // Header
        draw_tx_header(f, tx, chunks[0]);

        // Inputs and outputs
        draw_tx_io(f, app, tx, chunks[1]);
    } else {
        let paragraph = Paragraph::new("No transaction loaded")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
    }
}

fn draw_tx_header(f: &mut Frame, tx: &crate::api::TransactionInfo, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Transaction ")
        .title_style(Style::default().bold());

    let confirmations = if tx.status.confirmed {
        tx.status
            .block_height
            .map(|h| format!("{} confirmations", h))
            .unwrap_or_else(|| "confirmed".to_string())
    } else {
        "unconfirmed".to_string()
    };

    let fee_rate = tx.fee_rate();

    let text = vec![
        Line::from(vec![
            Span::styled("TxID: ", Style::default().fg(Color::Gray)),
            Span::styled(&tx.txid, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::Gray)),
            Span::raw(&confirmations),
            Span::raw("  "),
            Span::styled("Size: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{} vB", tx.vsize())),
            Span::raw("  "),
            Span::styled("Fee: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{} sats ({:.2} sat/vB)", tx.fee, fee_rate)),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, area);
}

fn draw_tx_io(f: &mut Frame, app: &App, tx: &crate::api::TransactionInfo, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    draw_inputs(f, app, tx, chunks[0]);
    draw_outputs(f, app, tx, chunks[1]);
}

fn draw_inputs(f: &mut Frame, app: &App, tx: &crate::api::TransactionInfo, area: Rect) {
    let title = format!(" Inputs ({}) ", tx.inputs.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(if app.tx_viewing_inputs {
            Style::default().bold().fg(Color::Yellow)
        } else {
            Style::default().bold()
        });

    let items: Vec<ListItem> = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let style = if app.tx_viewing_inputs && i == app.tx_io_index {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            let content = if input.is_coinbase {
                Line::from(vec![
                    Span::styled(format!("#{:<2} ", i), Style::default().fg(Color::DarkGray)),
                    Span::styled("COINBASE", Style::default().fg(Color::Yellow).bold()),
                ])
            } else {
                let value = input
                    .prevout
                    .as_ref()
                    .map(|p| format_btc(p.value))
                    .unwrap_or_else(|| "?".to_string());

                let addr = input
                    .prevout
                    .as_ref()
                    .and_then(|p| p.scriptpubkey_address.as_ref())
                    .map(|a| short_hash(a, 16))
                    .unwrap_or_else(|| "unknown".to_string());

                Line::from(vec![
                    Span::styled(format!("#{:<2} ", i), Style::default().fg(Color::DarkGray)),
                    Span::raw(format!("{}:{} ", short_hash(&input.txid, 8), input.vout)),
                    Span::styled(value, Style::default().fg(Color::Green)),
                    Span::raw(format!(" {}", addr)),
                ])
            };

            ListItem::new(content).style(style)
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

fn draw_outputs(f: &mut Frame, app: &App, tx: &crate::api::TransactionInfo, area: Rect) {
    let title = format!(" Outputs ({}) ", tx.outputs.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(if !app.tx_viewing_inputs {
            Style::default().bold().fg(Color::Yellow)
        } else {
            Style::default().bold()
        });

    let items: Vec<ListItem> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(i, output)| {
            let style = if !app.tx_viewing_inputs && i == app.tx_io_index {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            let addr = output
                .scriptpubkey_address
                .as_ref()
                .map(|a| short_hash(a, 20))
                .unwrap_or_else(|| output.scriptpubkey_type.clone());

            let spent_indicator = if output.spending_txid.is_some() {
                Span::styled(" SPENT", Style::default().fg(Color::Red))
            } else {
                Span::styled(" UNSPENT", Style::default().fg(Color::Green))
            };

            let content = Line::from(vec![
                Span::styled(format!("#{:<2} ", i), Style::default().fg(Color::DarkGray)),
                Span::styled(format_btc(output.value), Style::default().fg(Color::Green)),
                Span::raw(format!(" {} ", addr)),
                spent_indicator,
            ]);

            ListItem::new(content).style(style)
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}
