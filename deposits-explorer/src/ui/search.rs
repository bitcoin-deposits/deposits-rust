use ratatui::{prelude::*, widgets::*};

use crate::app::App;

pub fn draw(f: &mut Frame, app: &App) {
    // Center the search modal
    let area = centered_rect(60, 3, f.area());

    // Clear the area behind the modal
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Search (txid, address, block height) ")
        .title_style(Style::default().bold())
        .border_style(Style::default().fg(Color::Yellow));

    let input = Paragraph::new(app.search_input.as_str())
        .block(block)
        .style(Style::default().fg(Color::White));

    f.render_widget(input, area);

    // Show cursor at end of input
    f.set_cursor_position(Position::new(
        area.x + app.search_input.len() as u16 + 1,
        area.y + 1,
    ));
}

/// Helper function to create a centered rect
fn centered_rect(percent_x: u16, height: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((r.height.saturating_sub(height)) / 2),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
