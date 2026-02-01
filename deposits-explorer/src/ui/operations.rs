use ratatui::{prelude::*, widgets::*};

use crate::app::App;
use crate::util::format::format_time_ago;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let Some(ledger) = app.ledgers.get(app.ledger_index) else {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Operations ")
            .title_style(Style::default().bold());
        let paragraph = Paragraph::new("No ledger selected")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
        return;
    };

    let title = format!(
        " Operations: {} ({}) ",
        ledger.operator_short(),
        ledger.operations.len()
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(Style::default().bold());

    if ledger.operations.is_empty() {
        let paragraph = Paragraph::new("No operations recorded")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
        return;
    }

    // Create table rows
    let rows: Vec<Row> = ledger
        .operations
        .iter()
        .rev() // Show most recent first
        .enumerate()
        .map(|(display_idx, op)| {
            // The actual index in the operations vec (reversed)
            let actual_idx = ledger.operations.len() - 1 - display_idx;
            let is_selected = actual_idx == app.operation_index;

            let style = if is_selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            let time_str = if op.timestamp > 0 {
                format_time_ago(op.timestamp)
            } else {
                "-".to_string()
            };

            let block_str = if op.block_height > 0 {
                format!("#{}", op.block_height)
            } else {
                "-".to_string()
            };

            Row::new(vec![
                Cell::from(format!("{:>4}", op.sequence)),
                Cell::from(op.op_type.clone()).style(Style::default().fg(Color::Cyan)),
                Cell::from(time_str),
                Cell::from(block_str),
                Cell::from(format!("{}→{}", op.prev_hash, op.curr_hash))
                    .style(Style::default().fg(Color::DarkGray)),
            ])
            .style(style)
        })
        .collect();

    let header = Row::new(vec![
        Cell::from("Seq").style(Style::default().bold()),
        Cell::from("Type").style(Style::default().bold()),
        Cell::from("Time").style(Style::default().bold()),
        Cell::from("Block").style(Style::default().bold()),
        Cell::from("Hash").style(Style::default().bold()),
    ])
    .style(Style::default().fg(Color::Yellow));

    let widths = [
        Constraint::Length(5),
        Constraint::Length(15),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(18),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    f.render_widget(table, area);
}
