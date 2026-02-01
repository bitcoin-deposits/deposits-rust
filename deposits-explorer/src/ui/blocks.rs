use ratatui::{prelude::*, widgets::*};

use crate::app::App;
use crate::util::format::{format_btc, format_time_ago, short_hash};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    // If we have a transaction loaded, show split view
    if app.current_tx.is_some() {
        // Top 1/3: blocks, Bottom 2/3: transaction
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(33), Constraint::Percentage(67)])
            .split(area);

        draw_block_list_horizontal(f, app, chunks[0]);
        draw_transaction_detail(f, app, chunks[1]);
    } else {
        // No transaction: show block list left, details right
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        draw_block_list(f, app, chunks[0]);
        draw_block_details(f, app, chunks[1]);
    }
}

fn draw_block_list(f: &mut Frame, app: &App, area: Rect) {
    let title = if app.loading {
        " Blocks (loading...) "
    } else if app.blocks.is_empty() {
        " Blocks (none) "
    } else {
        " Blocks "
    };

    let block_widget = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(Style::default().bold());

    if app.blocks.is_empty() {
        let paragraph = Paragraph::new("No blocks loaded")
            .block(block_widget)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
        return;
    }

    let visible_height = area.height.saturating_sub(2) as usize; // Account for borders
    let block_index = app.block_index.min(app.blocks.len().saturating_sub(1));
    let start = block_index.saturating_sub(visible_height / 2);

    let items: Vec<ListItem> = app
        .blocks
        .iter()
        .enumerate()
        .skip(start)
        .take(visible_height)
        .map(|(i, block)| {
            let style = if i == block_index {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            let time_ago = format_time_ago(block.timestamp);
            let content = format!(
                "{:>6}  {}  {:>3} tx  {:>6}",
                block.height,
                short_hash(&block.hash, 8),
                block.tx_count,
                time_ago,
            );

            ListItem::new(Line::from(content)).style(style)
        })
        .collect();

    let list = List::new(items).block(block_widget);
    f.render_widget(list, area);
}

fn draw_block_list_horizontal(f: &mut Frame, app: &App, area: Rect) {
    let border_style = if !app.detail_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let block_widget = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Blocks ")
        .title_style(Style::default().bold());

    if app.blocks.is_empty() {
        let paragraph = Paragraph::new("No blocks")
            .block(block_widget)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
        return;
    }

    let visible_height = area.height.saturating_sub(2) as usize;
    let block_index = app.block_index.min(app.blocks.len().saturating_sub(1));
    let start = block_index.saturating_sub(visible_height / 2);

    let items: Vec<ListItem> = app
        .blocks
        .iter()
        .enumerate()
        .skip(start)
        .take(visible_height)
        .map(|(i, block)| {
            let is_selected = i == block_index;
            let style = if is_selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            let indicator = if is_selected { ">" } else { " " };
            let content = format!(
                "{} {:>6}  {}  {:>3} tx  {}",
                indicator,
                block.height,
                short_hash(&block.hash, 8),
                block.tx_count,
                format_time_ago(block.timestamp),
            );

            ListItem::new(Line::from(content)).style(style)
        })
        .collect();

    let list = List::new(items).block(block_widget);
    f.render_widget(list, area);
}

fn draw_block_details(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Block Details ")
        .title_style(Style::default().bold());

    if let Some(b) = app.blocks.get(app.block_index) {
        let text = vec![
            Line::from(vec![
                Span::styled("Height: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}", b.height), Style::default().bold()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Hash: ", Style::default().fg(Color::Gray)),
                Span::raw(&b.hash),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Time: ", Style::default().fg(Color::Gray)),
                Span::raw(format_timestamp(b.timestamp)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Transactions: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{}", b.tx_count)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Size: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{} bytes", b.size)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Weight: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{} WU", b.weight)),
            ]),
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "Press Enter to view transactions",
                Style::default().fg(Color::DarkGray).italic(),
            )),
        ];

        let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
        f.render_widget(paragraph, area);
    } else {
        let paragraph = Paragraph::new("No block selected")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
    }
}

fn draw_transaction_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some(ref tx) = app.current_tx else {
        return;
    };

    let border_style = if app.detail_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    // Split into header and inputs/outputs
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(5)])
        .split(area);

    // Header
    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Transaction ")
        .title_style(Style::default().bold());

    let confirmations = if tx.status.confirmed {
        tx.status
            .block_height
            .map(|h| format!("Block #{}", h))
            .unwrap_or_else(|| "confirmed".to_string())
    } else {
        "unconfirmed".to_string()
    };

    let header_text = vec![
        Line::from(vec![
            Span::styled("TxID: ", Style::default().fg(Color::Gray)),
            Span::styled(&tx.txid, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw(format!("{}  ", confirmations)),
            Span::styled("Size: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{} vB  ", tx.vsize())),
            Span::styled("Fee: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{} sats ({:.1} sat/vB)", tx.fee, tx.fee_rate())),
        ]),
    ];

    let header = Paragraph::new(header_text).block(header_block);
    f.render_widget(header, chunks[0]);

    // Inputs and Outputs side by side
    let io_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    draw_inputs(f, app, tx, io_chunks[0]);
    draw_outputs(f, app, tx, io_chunks[1]);
}

fn draw_inputs(f: &mut Frame, app: &App, tx: &crate::api::TransactionInfo, area: Rect) {
    let title = format!(" Inputs ({}) ", tx.inputs.len());
    let border_style = if app.detail_focused && app.tx_viewing_inputs {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title)
        .title_style(Style::default().bold());

    let items: Vec<ListItem> = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let style = if app.detail_focused && app.tx_viewing_inputs && i == app.tx_io_index {
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

                Line::from(vec![
                    Span::styled(format!("#{:<2} ", i), Style::default().fg(Color::DarkGray)),
                    Span::styled(value, Style::default().fg(Color::Green)),
                    Span::raw(format!(" {}:{}", short_hash(&input.txid, 8), input.vout)),
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
    let border_style = if app.detail_focused && !app.tx_viewing_inputs {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title)
        .title_style(Style::default().bold());

    let items: Vec<ListItem> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(i, output)| {
            let style = if app.detail_focused && !app.tx_viewing_inputs && i == app.tx_io_index {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            let addr = output
                .scriptpubkey_address
                .as_ref()
                .map(|a| short_hash(a, 16))
                .unwrap_or_else(|| output.scriptpubkey_type.clone());

            let spent_indicator = if output.spending_txid.is_some() {
                Span::styled(" SPENT", Style::default().fg(Color::Red))
            } else {
                Span::styled("", Style::default())
            };

            let content = Line::from(vec![
                Span::styled(format!("#{:<2} ", i), Style::default().fg(Color::DarkGray)),
                Span::styled(format_btc(output.value), Style::default().fg(Color::Green)),
                Span::raw(format!(" {}", addr)),
                spent_indicator,
            ]);

            ListItem::new(content).style(style)
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

fn format_timestamp(ts: u64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(ts as i64, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("{}", ts))
}
