use ratatui::{prelude::*, widgets::*};

use crate::app::App;
use crate::util::format::format_btc;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let Some(ledger) = app.ledgers.get(app.ledger_index) else {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Reserves ")
            .title_style(Style::default().bold());
        let paragraph = Paragraph::new("No ledger selected")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
        return;
    };

    let title = format!(" Reserves: {} ", ledger.operator_short());

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(Style::default().bold());

    let reserves = &ledger.ledger.state.reserves;

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Amount: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_btc(reserves.amount),
                Style::default().fg(Color::Green).bold(),
            ),
            Span::raw(format!(" ({} sats)", reserves.amount)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Spend To: ", Style::default().fg(Color::Gray)),
            Span::styled(
                reserves.spend_to.to_string(),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Channel ID: ", Style::default().fg(Color::Gray)),
            Span::raw(hex::encode(reserves.channel_id)),
        ]),
        Line::from(""),
        Line::from(""),
    ];

    // Quorum members section
    lines.push(Line::from(Span::styled(
        format!("─ Quorum Members ({}) ", ledger.quorum_count()),
        Style::default().fg(Color::Yellow).bold(),
    )));
    lines.push(Line::from(""));

    if ledger.ledger.state.quorum_members.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No quorum members",
            Style::default().fg(Color::DarkGray).italic(),
        )));
    } else {
        for member in &ledger.ledger.state.quorum_members {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(member.to_string(), Style::default().fg(Color::Cyan)),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(""));

    // Deposits summary section
    lines.push(Line::from(Span::styled(
        format!("─ Deposits ({}) ", ledger.deposits_count()),
        Style::default().fg(Color::Yellow).bold(),
    )));
    lines.push(Line::from(""));

    let deposits: Vec<_> = ledger.deposits();
    if deposits.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No deposits",
            Style::default().fg(Color::DarkGray).italic(),
        )));
    } else {
        let total_balance: u64 = deposits.iter().map(|(_, d)| d.balance).sum();
        let total_locked: u64 = deposits.iter().map(|(_, d)| d.locked_balance).sum();

        lines.push(Line::from(vec![
            Span::styled("  Total Balance: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_btc(total_balance),
                Style::default().fg(Color::Green),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Total Locked: ", Style::default().fg(Color::Gray)),
            Span::styled(format_btc(total_locked), Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::from(""));

        // List individual deposits (truncated if too many)
        for (i, (pubkey, deposit)) in deposits.iter().enumerate().take(10) {
            let short_pk = {
                let s = pubkey.to_string();
                format!("{}...", &s[..12.min(s.len())])
            };
            lines.push(Line::from(vec![
                Span::raw(format!("  {}: ", i)),
                Span::styled(short_pk, Style::default().fg(Color::Cyan)),
                Span::raw(format!(
                    " bal:{} lock:{}",
                    format_btc(deposit.balance),
                    format_btc(deposit.locked_balance)
                )),
            ]));
        }
        if deposits.len() > 10 {
            lines.push(Line::from(Span::styled(
                format!("  ... and {} more", deposits.len() - 10),
                Style::default().fg(Color::DarkGray).italic(),
            )));
        }
    }

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}
