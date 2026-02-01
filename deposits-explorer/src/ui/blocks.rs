use ratatui::{prelude::*, widgets::*};

use crate::app::App;
use crate::util::format::{format_btc, format_time_ago, short_hash};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    // Split into left (block list) and right (details) panels
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    draw_block_list(f, app, chunks[0]);
    draw_block_details(f, app, chunks[1]);
}

fn draw_block_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .blocks
        .iter()
        .enumerate()
        .map(|(i, block)| {
            let style = if i == app.block_index {
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

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Blocks ")
                .title_style(Style::default().bold()),
        )
        .highlight_style(Style::default().bg(Color::DarkGray));

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

fn format_timestamp(ts: u64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(ts as i64, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("{}", ts))
}
