mod blocks;
mod transaction;
mod address;
mod ledgers;
mod operations;
mod reserves;
mod status;
mod help;
mod search;

use ratatui::prelude::*;

use crate::app::{App, View};

/// Main draw function
pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // Main content
            Constraint::Length(1), // Status bar
        ])
        .split(f.area());

    // Draw main content based on current view
    match app.view {
        View::Blocks => blocks::draw(f, app, chunks[0]),
        View::Transaction => transaction::draw(f, app, chunks[0]),
        View::Address => address::draw(f, app, chunks[0]),
        View::Ledgers => ledgers::draw(f, app, chunks[0]),
        View::Operations => operations::draw(f, app, chunks[0]),
        View::Reserves => reserves::draw(f, app, chunks[0]),
        View::Help => help::draw(f, app, chunks[0]),
    }

    // Draw status bar
    status::draw(f, app, chunks[1]);

    // Draw search modal if open
    if app.search_open {
        search::draw(f, app);
    }
}
