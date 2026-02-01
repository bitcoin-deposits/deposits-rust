use ratatui::{prelude::*, widgets::*};

use crate::app::App;
use crate::util::format::format_btc;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    // Split into left (ledger list) and right (details) panels
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    draw_ledger_list(f, app, chunks[0]);
    draw_ledger_details(f, app, chunks[1]);
}

fn draw_ledger_list(f: &mut Frame, app: &App, area: Rect) {
    if app.ledgers.is_empty() {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Ledgers ")
            .title_style(Style::default().bold());

        let paragraph = Paragraph::new("No ledgers found.\nCheck --data-dir path.")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
        return;
    }

    let items: Vec<ListItem> = app
        .ledgers
        .iter()
        .enumerate()
        .map(|(i, ledger)| {
            let style = if i == app.ledger_index {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            let content = format!(
                "{} → {} seq:{}",
                ledger.operator_short(),
                ledger.reserves_id_short(),
                ledger.sequence(),
            );

            ListItem::new(Line::from(content)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Ledgers ({}) ", app.ledgers.len()))
                .title_style(Style::default().bold()),
        )
        .highlight_style(Style::default().bg(Color::DarkGray));

    f.render_widget(list, area);
}

fn draw_ledger_details(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Ledger Details ")
        .title_style(Style::default().bold());

    if let Some(ledger) = app.ledgers.get(app.ledger_index) {
        let text = vec![
            Line::from(vec![
                Span::styled("Operator: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    ledger.operator.to_string(),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Reserves ID: ", Style::default().fg(Color::Gray)),
                Span::raw(&ledger.reserves_id),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Sequence: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{}", ledger.sequence()),
                    Style::default().bold(),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Ledger Hash: ", Style::default().fg(Color::Gray)),
                Span::raw(ledger.hash_short()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Role: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{:?}", ledger.ledger.role)),
            ]),
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "─ Reserves ",
                Style::default().fg(Color::Yellow).bold(),
            )),
            Line::from(vec![
                Span::styled("Amount: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format_btc(ledger.reserves_amount()),
                    Style::default().fg(Color::Green).bold(),
                ),
            ]),
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "─ State ",
                Style::default().fg(Color::Yellow).bold(),
            )),
            Line::from(vec![
                Span::styled("Deposits: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{}", ledger.deposits_count())),
            ]),
            Line::from(vec![
                Span::styled("Quorum Members: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{}", ledger.quorum_count())),
            ]),
            Line::from(vec![
                Span::styled("Operations: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{}", ledger.operations.len())),
            ]),
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "[O]perations  [S]Reserves  [Enter] Operations",
                Style::default().fg(Color::DarkGray).italic(),
            )),
        ];

        let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
        f.render_widget(paragraph, area);
    } else {
        let paragraph = Paragraph::new("No ledger selected")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
    }
}
