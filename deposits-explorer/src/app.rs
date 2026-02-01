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

    /// Current transaction (when in Transaction view)
    pub current_tx: Option<TransactionInfo>,
    /// Selected input/output index in transaction view
    pub tx_io_index: usize,
    /// Whether viewing inputs (true) or outputs (false)
    pub tx_viewing_inputs: bool,

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
                if let Ok(blocks) = self.electrs.get_blocks().await {
                    self.blocks = blocks;
                }
            }
            View::Ledgers => {
                if let Ok(ledgers) = self.deposits.load_ledgers() {
                    self.ledgers = ledgers;
                }
            }
            _ => {}
        }
        self.last_refresh = Instant::now();
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
                self.loading = true;
                if let Ok(hash) = self.electrs.get_block_hash(height).await {
                    // Find block in our list or fetch it
                    if let Some(idx) = self.blocks.iter().position(|b| b.hash == hash) {
                        self.block_index = idx;
                        self.view = View::Blocks;
                    }
                }
                self.loading = false;
            }
            return;
        }

        self.status = format!("Unknown search query: {}", query);
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
                        app.go_back().await;
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
            match key {
                KeyCode::Up | KeyCode::Char('k') => {
                    if app.block_index > 0 {
                        app.block_index -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if app.block_index < app.blocks.len().saturating_sub(1) {
                        app.block_index += 1;
                    }
                }
                KeyCode::Char('g') => {
                    app.block_index = 0;
                }
                KeyCode::Char('G') => {
                    app.block_index = app.blocks.len().saturating_sub(1);
                }
                KeyCode::Enter => {
                    // Enter block: show first transaction
                    let txid = app.blocks.get(app.block_index)
                        .and_then(|b| b.txids.first().cloned());
                    if let Some(txid) = txid {
                        app.goto_transaction(&txid).await;
                    }
                }
                _ => {}
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
