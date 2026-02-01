use ratatui::{prelude::*, widgets::*};

use crate::app::{App, View};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let view_name = match app.view {
        View::Blocks => "Blocks",
        View::Transaction => "Transaction",
        View::Address => "Address",
        View::Ledgers => "Ledgers",
        View::Operations => "Operations",
        View::Reserves => "Reserves",
        View::Help => "Help",
    };

    let mut spans = vec![
        Span::styled(" [B]", Style::default().fg(Color::Yellow)),
        Span::raw("locks "),
        Span::styled("[L]", Style::default().fg(Color::Yellow)),
        Span::raw("edgers "),
        Span::styled("[/]", Style::default().fg(Color::Yellow)),
        Span::raw("Search "),
        Span::styled("[R]", Style::default().fg(Color::Yellow)),
        Span::raw("efresh "),
        Span::styled("[?]", Style::default().fg(Color::Yellow)),
        Span::raw("Help "),
        Span::styled("[Q]", Style::default().fg(Color::Yellow)),
        Span::raw("uit"),
    ];

    // Add loading indicator
    if app.loading {
        spans.push(Span::raw(" "));
        spans.push(Span::styled("Loading...", Style::default().fg(Color::Yellow)));
    }

    // Add status message
    if !app.status.is_empty() {
        spans.push(Span::raw(" │ "));
        spans.push(Span::styled(&app.status, Style::default().fg(Color::Cyan)));
    }

    // Right side: current view and position
    let right_info = match app.view {
        View::Blocks if !app.blocks.is_empty() => {
            format!(
                "{} │ Block {}/{}",
                view_name,
                app.block_index + 1,
                app.blocks.len()
            )
        }
        View::Ledgers if !app.ledgers.is_empty() => {
            format!(
                "{} │ Ledger {}/{}",
                view_name,
                app.ledger_index + 1,
                app.ledgers.len()
            )
        }
        View::Operations => {
            if let Some(ledger) = app.ledgers.get(app.ledger_index) {
                format!(
                    "{} │ Op {}/{}",
                    view_name,
                    app.operation_index + 1,
                    ledger.operations.len()
                )
            } else {
                view_name.to_string()
            }
        }
        _ => view_name.to_string(),
    };

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line).style(Style::default().bg(Color::DarkGray));

    // Calculate right padding
    let right_span = Span::styled(
        format!(" {} ", right_info),
        Style::default().bg(Color::DarkGray).fg(Color::White),
    );

    f.render_widget(paragraph, area);

    // Render right-aligned info
    let right_width = right_info.len() as u16 + 2;
    if area.width > right_width {
        let right_area = Rect {
            x: area.x + area.width - right_width,
            y: area.y,
            width: right_width,
            height: 1,
        };
        f.render_widget(Paragraph::new(right_span), right_area);
    }
}
