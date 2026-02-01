use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{prelude::*, widgets::*};
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::api::{ElectrsClient, BlockSummary, TransactionInfo, AddressInfo};
use crate::deposits::{DepositsLoader, LedgerInfo};
use crate::ui;

/// Which view is currently active
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Blocks,
    Transaction,
    Address,
    Ledgers,
    Operations,
    Reserves,
    Help,
}

/// Navigation history for back functionality
#[derive(Debug, Clone)]
pub enum HistoryEntry {
    Blocks,
    Transaction(String),
    Address(String),
    Ledgers,
    Operations(usize),
    Reserves(usize),
}

/// Application state
pub struct App {
    /// Current view
    pub view: View,
    /// Navigation history
    pub history: Vec<HistoryEntry>,

    /// Electrs API client
    pub electrs: ElectrsClient,
    /// Deposits data loader
    pub deposits: DepositsLoader,

    /// Blocks list
    pub blocks: Vec<BlockSummary>,
    /// Selected block index
    pub block_index: usize,
    /// Block list scroll offset
    pub block_scroll: usize,

    /// Current transaction (shown in detail panel)
    pub current_tx: Option<TransactionInfo>,
    /// Selected input/output index in transaction view
    pub tx_io_index: usize,
    /// Whether viewing inputs (true) or outputs (false)
    pub tx_viewing_inputs: bool,
    /// Whether the detail panel is focused (vs the list)
    pub detail_focused: bool,

    /// Current address (when in Address view)
    pub current_address: Option<AddressInfo>,

    /// Loaded ledgers
    pub ledgers: Vec<LedgerInfo>,
    /// Selected ledger index
    pub ledger_index: usize,
    /// Ledger list scroll offset
    pub ledger_scroll: usize,

    /// Selected operation index (when in Operations view)
    pub operation_index: usize,
    /// Operation list scroll offset
    pub operation_scroll: usize,

    /// Search input buffer
    pub search_input: String,
    /// Whether search modal is open
    pub search_open: bool,

    /// Status message (shown in status bar)
    pub status: String,
    /// Whether we're currently loading
    pub loading: bool,

    /// Last refresh time
    pub last_refresh: Instant,
    /// Refresh interval
    pub refresh_interval: Duration,

    /// Whether to quit
    pub should_quit: bool,

    /// Whether we've loaded all available blocks
    pub blocks_exhausted: bool,
}

impl App {
    pub fn new(electrs_url: String, data_dir: PathBuf, refresh_secs: u64) -> Self {
        Self {
            view: View::Blocks,
            history: Vec::new(),

            electrs: ElectrsClient::new(electrs_url),
            deposits: DepositsLoader::new(data_dir),

            blocks: Vec::new(),
            block_index: 0,
            block_scroll: 0,

            current_tx: None,
            tx_io_index: 0,
            tx_viewing_inputs: true,
            detail_focused: false,

            current_address: None,

            ledgers: Vec::new(),
            ledger_index: 0,
            ledger_scroll: 0,

            operation_index: 0,
            operation_scroll: 0,

            search_input: String::new(),
            search_open: false,

            status: String::new(),
            loading: false,

            last_refresh: Instant::now(),
            refresh_interval: Duration::from_secs(refresh_secs),

            should_quit: false,
            blocks_exhausted: false,
        }
    }

    /// Load initial data
    pub async fn load_initial(&mut self) {
        self.loading = true;
        self.status = "Loading blocks...".to_string();

        // Load blocks
        match self.electrs.get_blocks().await {
            Ok(blocks) => {
                self.blocks = blocks;
                self.status = format!("Loaded {} blocks", self.blocks.len());
            }
            Err(e) => {
                self.status = format!("Failed to load blocks: {}", e);
            }
        }

        // Load ledgers
        match self.deposits.load_ledgers() {
            Ok(ledgers) => {
                self.ledgers = ledgers;
                if !self.ledgers.is_empty() {
                    self.status = format!(
                        "{} | {} ledgers",
                        self.status,
                        self.ledgers.len()
                    );
                }
            }
            Err(e) => {
                // Not an error if no data dir - just no deposits data
                if self.deposits.data_dir.exists() {
                    self.status = format!("{} | Deposits: {}", self.status, e);
                }
            }
        }

        self.loading = false;
        self.last_refresh = Instant::now();
    }

    /// Refresh current view data
    pub async fn refresh(&mut self) {
        match self.view {
            View::Blocks => {
                // Only fetch new blocks at the tip, don't replace everything
                if let Ok(new_blocks) = self.electrs.get_blocks().await {
                    if self.blocks.is_empty() {
                        self.blocks = new_blocks;
                    } else {
                        // Prepend any new blocks we don't have yet
                        let our_tip = self.blocks.first().map(|b| b.height).unwrap_or(0);
                        let fresh: Vec<_> = new_blocks
                            .into_iter()
                            .filter(|b| b.height > our_tip)
                            .collect();
                        if !fresh.is_empty() {
                            let count = fresh.len();
                            // Prepend new blocks
                            self.blocks.splice(0..0, fresh);
                            // Adjust block_index to keep same block selected
                            self.block_index += count;
                            self.status = format!("{} new blocks", count);
                        }
                    }
                }
            }
            View::Ledgers => {
                if let Ok(ledgers) = self.deposits.load_ledgers() {
                    self.ledgers = ledgers;
                }
            }
            _ => {}
        }
        // Ensure indices are valid
        self.clamp_indices();
        self.last_refresh = Instant::now();
    }

    /// Ensure all indices are within valid bounds
    fn clamp_indices(&mut self) {
        if !self.blocks.is_empty() {
            self.block_index = self.block_index.min(self.blocks.len() - 1);
        } else {
            self.block_index = 0;
        }
        if !self.ledgers.is_empty() {
            self.ledger_index = self.ledger_index.min(self.ledgers.len() - 1);
        } else {
            self.ledger_index = 0;
        }
    }

    /// Navigate to a transaction by txid
    pub async fn goto_transaction(&mut self, txid: &str) {
        self.loading = true;
        self.status = format!("Loading tx {}...", &txid[..8.min(txid.len())]);

        match self.electrs.get_transaction(txid).await {
            Ok(tx) => {
                self.history.push(match self.view {
                    View::Blocks => HistoryEntry::Blocks,
                    View::Transaction => {
                        if let Some(ref t) = self.current_tx {
                            HistoryEntry::Transaction(t.txid.clone())
                        } else {
                            HistoryEntry::Blocks
                        }
                    }
                    View::Address => {
                        if let Some(ref a) = self.current_address {
                            HistoryEntry::Address(a.address.clone())
                        } else {
                            HistoryEntry::Blocks
                        }
                    }
                    View::Ledgers => HistoryEntry::Ledgers,
                    View::Operations => HistoryEntry::Operations(self.ledger_index),
                    View::Reserves => HistoryEntry::Reserves(self.ledger_index),
                    View::Help => HistoryEntry::Blocks,
                });
                self.current_tx = Some(tx);
                self.tx_io_index = 0;
                self.tx_viewing_inputs = true;
                self.view = View::Transaction;
                self.status = String::new();
            }
            Err(e) => {
                self.status = format!("Failed to load tx: {}", e);
            }
        }
        self.loading = false;
    }

    /// Navigate to an address
    pub async fn goto_address(&mut self, address: &str) {
        self.loading = true;
        self.status = format!("Loading address {}...", &address[..12.min(address.len())]);

        match self.electrs.get_address(address).await {
            Ok(addr) => {
                self.history.push(match self.view {
                    View::Blocks => HistoryEntry::Blocks,
                    View::Transaction => {
                        if let Some(ref t) = self.current_tx {
                            HistoryEntry::Transaction(t.txid.clone())
                        } else {
                            HistoryEntry::Blocks
                        }
                    }
                    View::Address => {
                        if let Some(ref a) = self.current_address {
                            HistoryEntry::Address(a.address.clone())
                        } else {
                            HistoryEntry::Blocks
                        }
                    }
                    View::Ledgers => HistoryEntry::Ledgers,
                    View::Operations => HistoryEntry::Operations(self.ledger_index),
                    View::Reserves => HistoryEntry::Reserves(self.ledger_index),
                    View::Help => HistoryEntry::Blocks,
                });
                self.current_address = Some(addr);
                self.view = View::Address;
                self.status = String::new();
            }
            Err(e) => {
                self.status = format!("Failed to load address: {}", e);
            }
        }
        self.loading = false;
    }

    /// Go back in history
    pub async fn go_back(&mut self) {
        if let Some(entry) = self.history.pop() {
            match entry {
                HistoryEntry::Blocks => {
                    self.view = View::Blocks;
                }
                HistoryEntry::Transaction(txid) => {
                    if let Ok(tx) = self.electrs.get_transaction(&txid).await {
                        self.current_tx = Some(tx);
                        self.view = View::Transaction;
                    }
                }
                HistoryEntry::Address(addr) => {
                    if let Ok(a) = self.electrs.get_address(&addr).await {
                        self.current_address = Some(a);
                        self.view = View::Address;
                    }
                }
                HistoryEntry::Ledgers => {
                    self.view = View::Ledgers;
                }
                HistoryEntry::Operations(idx) => {
                    self.ledger_index = idx;
                    self.view = View::Operations;
                }
                HistoryEntry::Reserves(idx) => {
                    self.ledger_index = idx;
                    self.view = View::Reserves;
                }
            }
        } else {
            // No history, go to blocks
            self.view = View::Blocks;
        }
    }

    /// Handle search input
    pub fn handle_search(&mut self) -> Option<String> {
        let query = self.search_input.trim().to_string();
        self.search_input.clear();
        self.search_open = false;

        if query.is_empty() {
            return None;
        }

        Some(query)
    }

    /// Detect search query type and navigate
    pub async fn execute_search(&mut self, query: &str) {
        let query = query.trim();

        // 64 hex chars = txid or block hash
        if query.len() == 64 && query.chars().all(|c| c.is_ascii_hexdigit()) {
            // Try as txid first
            self.goto_transaction(query).await;
            return;
        }

        // Starts with bc1/bcrt1/tb1 = address
        if query.starts_with("bc1")
            || query.starts_with("bcrt1")
            || query.starts_with("tb1")
        {
            self.goto_address(query).await;
            return;
        }

        // Pure numeric = block height
        if query.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(height) = query.parse::<u64>() {
                self.goto_block_height(height).await;
            }
            return;
        }

        self.status = format!("Unknown search query: {}", query);
    }

    /// Enter a block - fetch txids and load first transaction into detail panel
    pub async fn enter_block(&mut self) {
        let block_hash = match self.blocks.get(self.block_index) {
            Some(b) => b.hash.clone(),
            None => return,
        };

        // Fetch txids if not already loaded
        if self.blocks.get(self.block_index).map(|b| b.txids.is_empty()).unwrap_or(true) {
            self.loading = true;
            self.status = "Loading transactions...".to_string();

            match self.electrs.get_block_txids(&block_hash).await {
                Ok(txids) => {
                    if let Some(block) = self.blocks.get_mut(self.block_index) {
                        block.txids = txids;
                    }
                }
                Err(e) => {
                    self.status = format!("Failed to load txids: {}", e);
                    self.loading = false;
                    return;
                }
            }
            self.loading = false;
        }

        // Load first transaction into detail panel (don't change view)
        let txid = self.blocks.get(self.block_index)
            .and_then(|b| b.txids.first().cloned());

        if let Some(txid) = txid {
            self.loading = true;
            match self.electrs.get_transaction(&txid).await {
                Ok(tx) => {
                    self.current_tx = Some(tx);
                    self.tx_io_index = 0;
                    self.tx_viewing_inputs = true;
                    self.detail_focused = true;
                    self.status = String::new();
                }
                Err(e) => {
                    self.status = format!("Failed to load tx: {}", e);
                }
            }
            self.loading = false;
        } else {
            self.status = "No transactions in block".to_string();
        }
    }

    /// Load more blocks when cursor is near the bottom
    pub async fn maybe_load_more_blocks(&mut self) {
        // Don't load if already exhausted or loading
        if self.blocks_exhausted || self.loading || self.blocks.is_empty() {
            return;
        }

        // Load more when within 5 blocks of the end
        let threshold = 5;
        let remaining = self.blocks.len().saturating_sub(self.block_index + 1);
        if remaining > threshold {
            return;
        }

        // Get the height of the last block to paginate from
        let last_height = match self.blocks.last() {
            Some(b) => b.height,
            None => return,
        };

        // Check we're not at genesis (height 0)
        if last_height == 0 {
            self.blocks_exhausted = true;
            return;
        }

        // Request blocks starting from one before our last
        let start_height = last_height.saturating_sub(1);

        self.loading = true;
        self.status = "Loading more blocks...".to_string();

        match self.electrs.get_blocks_from_height(start_height).await {
            Ok(new_blocks) => {
                // Skip blocks we already have (by height)
                let fresh_blocks: Vec<_> = new_blocks
                    .into_iter()
                    .filter(|b| b.height < last_height)
                    .collect();

                if fresh_blocks.is_empty() {
                    self.blocks_exhausted = true;
                    self.status = "Reached genesis".to_string();
                } else {
                    self.status = format!("Loaded {} more blocks", fresh_blocks.len());
                    self.blocks.extend(fresh_blocks);
                }
            }
            Err(e) => {
                self.status = format!("Failed to load more blocks: {}", e);
            }
        }

        self.clamp_indices();
        self.loading = false;
    }

    /// Jump to a specific block height
    pub async fn goto_block_height(&mut self, target_height: u64) {
        // First check if we already have this block loaded
        if let Some(idx) = self.blocks.iter().position(|b| b.height == target_height) {
            self.block_index = idx;
            self.view = View::Blocks;
            self.status = format!("Jumped to block {}", target_height);
            return;
        }

        // Not loaded - need to fetch blocks around this height
        self.loading = true;
        self.status = format!("Loading block {}...", target_height);

        match self.electrs.get_blocks_from_height(target_height).await {
            Ok(new_blocks) => {
                if new_blocks.is_empty() {
                    self.status = format!("Block {} not found", target_height);
                    self.loading = false;
                    return;
                }

                // Find if target height is in the fetched blocks
                let target_in_new = new_blocks.iter().position(|b| b.height == target_height);

                if self.blocks.is_empty() {
                    // No existing blocks, just use the new ones
                    self.blocks = new_blocks;
                    self.block_index = target_in_new.unwrap_or(0);
                } else {
                    // We have existing blocks - need to merge or replace
                    let our_tip = self.blocks.first().map(|b| b.height).unwrap_or(0);
                    let our_bottom = self.blocks.last().map(|b| b.height).unwrap_or(0);

                    if target_height > our_tip {
                        // Target is above our tip - prepend new blocks
                        let fresh: Vec<_> = new_blocks
                            .into_iter()
                            .filter(|b| b.height > our_tip)
                            .collect();
                        let count = fresh.len();
                        self.blocks.splice(0..0, fresh);
                        // Find the target in our updated list
                        if let Some(idx) = self.blocks.iter().position(|b| b.height == target_height) {
                            self.block_index = idx;
                        } else {
                            self.block_index = 0;
                        }
                    } else if target_height < our_bottom {
                        // Target is below our bottom - append new blocks
                        let fresh: Vec<_> = new_blocks
                            .into_iter()
                            .filter(|b| b.height < our_bottom)
                            .collect();
                        let old_len = self.blocks.len();
                        self.blocks.extend(fresh);
                        // Find the target in our updated list
                        if let Some(idx) = self.blocks.iter().position(|b| b.height == target_height) {
                            self.block_index = idx;
                        } else {
                            self.block_index = old_len;
                        }
                    } else {
                        // Target should be in our range but wasn't found - scroll to closest
                        if let Some(idx) = self.blocks.iter().position(|b| b.height <= target_height) {
                            self.block_index = idx;
                        }
                    }
                }

                self.view = View::Blocks;
                self.status = format!("Jumped to block {}", target_height);
                self.blocks_exhausted = false; // Reset since we may have jumped
            }
            Err(e) => {
                self.status = format!("Failed to load block {}: {}", target_height, e);
            }
        }

        self.clamp_indices();
        self.loading = false;
    }
}

/// Run the TUI application
pub async fn run(electrs_url: String, data_dir: PathBuf, refresh_secs: u64) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and load initial data
    let mut app = App::new(electrs_url, data_dir, refresh_secs);
    app.load_initial().await;

    // Main loop
    let result = run_loop(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
) -> Result<()> {
    let tick_rate = Duration::from_millis(100);

    loop {
        // Draw UI
        terminal.draw(|f| ui::draw(f, app))?;

        // Handle events with timeout
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                // Handle search input mode
                if app.search_open {
                    match key.code {
                        KeyCode::Esc => {
                            app.search_open = false;
                            app.search_input.clear();
                        }
                        KeyCode::Enter => {
                            if let Some(query) = app.handle_search() {
                                app.execute_search(&query).await;
                            }
                        }
                        KeyCode::Backspace => {
                            app.search_input.pop();
                        }
                        KeyCode::Char(c) => {
                            app.search_input.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                // Global keys
                match key.code {
                    KeyCode::Char('q') => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('/') => {
                        app.search_open = true;
                    }
                    KeyCode::Char('?') => {
                        if app.view != View::Help {
                            app.history.push(HistoryEntry::Blocks);
                            app.view = View::Help;
                        }
                    }
                    KeyCode::Char('b') | KeyCode::Char('B') => {
                        app.view = View::Blocks;
                    }
                    KeyCode::Char('l') | KeyCode::Char('L') => {
                        app.view = View::Ledgers;
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        app.refresh().await;
                    }
                    KeyCode::Esc => {
                        // If viewing transaction detail, close it first
                        if app.view == View::Blocks && app.current_tx.is_some() {
                            app.current_tx = None;
                            app.detail_focused = false;
                        } else {
                            app.go_back().await;
                        }
                    }
                    KeyCode::Tab => {
                        // Toggle focus between list and detail
                        if app.current_tx.is_some() {
                            app.detail_focused = !app.detail_focused;
                        }
                    }
                    _ => {
                        // View-specific keys
                        handle_view_keys(app, key.code).await;
                    }
                }
            }
        }

        // Auto-refresh
        if app.refresh_interval > Duration::ZERO
            && app.last_refresh.elapsed() >= app.refresh_interval
        {
            app.refresh().await;
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

async fn handle_view_keys(app: &mut App, key: KeyCode) {
    match app.view {
        View::Blocks => {
            // If detail is focused, handle navigation within transaction
            if app.detail_focused && app.current_tx.is_some() {
                match key {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.tx_io_index > 0 {
                            app.tx_io_index -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if let Some(ref tx) = app.current_tx {
                            let max = if app.tx_viewing_inputs {
                                tx.inputs.len()
                            } else {
                                tx.outputs.len()
                            };
                            if app.tx_io_index < max.saturating_sub(1) {
                                app.tx_io_index += 1;
                            }
                        }
                    }
                    KeyCode::Left | KeyCode::Char('h') => {
                        if !app.tx_viewing_inputs {
                            app.tx_viewing_inputs = true;
                            app.tx_io_index = 0;
                        }
                    }
                    KeyCode::Right | KeyCode::Char('l') => {
                        if app.tx_viewing_inputs {
                            app.tx_viewing_inputs = false;
                            app.tx_io_index = 0;
                        }
                    }
                    KeyCode::Enter => {
                        // Navigate to selected input's prev tx or output's spending tx
                        if let Some(ref tx) = app.current_tx {
                            if app.tx_viewing_inputs {
                                if let Some(input) = tx.inputs.get(app.tx_io_index) {
                                    if !input.is_coinbase {
                                        let txid = input.txid.clone();
                                        app.loading = true;
                                        if let Ok(new_tx) = app.electrs.get_transaction(&txid).await {
                                            app.current_tx = Some(new_tx);
                                            app.tx_io_index = 0;
                                        }
                                        app.loading = false;
                                    }
                                }
                            } else if let Some(output) = tx.outputs.get(app.tx_io_index) {
                                if let Some(ref spending_txid) = output.spending_txid {
                                    let txid = spending_txid.clone();
                                    app.loading = true;
                                    if let Ok(new_tx) = app.electrs.get_transaction(&txid).await {
                                        app.current_tx = Some(new_tx);
                                        app.tx_io_index = 0;
                                    }
                                    app.loading = false;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                // Block list is focused
                match key {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.block_index > 0 {
                            app.block_index -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.block_index < app.blocks.len().saturating_sub(1) {
                            app.block_index += 1;
                            // Lazy load more blocks when near the bottom
                            app.maybe_load_more_blocks().await;
                        }
                    }
                    KeyCode::Char('g') => {
                        app.block_index = 0;
                    }
                    KeyCode::Char('G') => {
                        app.block_index = app.blocks.len().saturating_sub(1);
                        // Load more blocks when jumping to bottom
                        app.maybe_load_more_blocks().await;
                    }
                    KeyCode::Enter => {
                        // Enter block: fetch txids and show first transaction
                        app.enter_block().await;
                    }
                    _ => {}
                }
            }
        }
        View::Transaction => {
            match key {
                KeyCode::Up | KeyCode::Char('k') => {
                    if app.tx_io_index > 0 {
                        app.tx_io_index -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if let Some(ref tx) = app.current_tx {
                        let max = if app.tx_viewing_inputs {
                            tx.inputs.len()
                        } else {
                            tx.outputs.len()
                        };
                        if app.tx_io_index < max.saturating_sub(1) {
                            app.tx_io_index += 1;
                        }
                    }
                }
                KeyCode::Tab => {
                    app.tx_viewing_inputs = !app.tx_viewing_inputs;
                    app.tx_io_index = 0;
                }
                KeyCode::Enter => {
                    // Navigate to selected input's prev tx or output's spending tx
                    if let Some(ref tx) = app.current_tx {
                        if app.tx_viewing_inputs {
                            if let Some(input) = tx.inputs.get(app.tx_io_index) {
                                let txid = input.txid.clone();
                                app.goto_transaction(&txid).await;
                            }
                        } else if let Some(output) = tx.outputs.get(app.tx_io_index) {
                            if let Some(ref spending_txid) = output.spending_txid {
                                let txid = spending_txid.clone();
                                app.goto_transaction(&txid).await;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        View::Ledgers => {
            match key {
                KeyCode::Up | KeyCode::Char('k') => {
                    if app.ledger_index > 0 {
                        app.ledger_index -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if app.ledger_index < app.ledgers.len().saturating_sub(1) {
                        app.ledger_index += 1;
                    }
                }
                KeyCode::Char('o') | KeyCode::Char('O') => {
                    if !app.ledgers.is_empty() {
                        app.operation_index = 0;
                        app.view = View::Operations;
                    }
                }
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    if !app.ledgers.is_empty() {
                        app.view = View::Reserves;
                    }
                }
                KeyCode::Enter => {
                    if !app.ledgers.is_empty() {
                        app.operation_index = 0;
                        app.view = View::Operations;
                    }
                }
                _ => {}
            }
        }
        View::Operations => {
            match key {
                KeyCode::Up | KeyCode::Char('k') => {
                    if app.operation_index > 0 {
                        app.operation_index -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if let Some(ledger) = app.ledgers.get(app.ledger_index) {
                        if app.operation_index < ledger.operations.len().saturating_sub(1) {
                            app.operation_index += 1;
                        }
                    }
                }
                KeyCode::Char('g') => {
                    app.operation_index = 0;
                }
                KeyCode::Char('G') => {
                    if let Some(ledger) = app.ledgers.get(app.ledger_index) {
                        app.operation_index = ledger.operations.len().saturating_sub(1);
                    }
                }
                _ => {}
            }
        }
        View::Reserves => {
            // Reserves view is mostly informational
            match key {
                KeyCode::Enter => {
                    // TODO: Navigate to reserves UTXO transaction
                }
                _ => {}
            }
        }
        View::Address => {
            // TODO: Navigate address UTXOs and history
        }
        View::Help => {
            // Any key exits help
            app.go_back().await;
        }
    }
}
