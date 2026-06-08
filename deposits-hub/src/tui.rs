//! TUI shell for the operator.
//!
//! Two tabs today:
//!
//!   * **Dashboard** — approved signers + nodes, with last-heartbeat age
//!     (live-updated from the nostr inbox).
//!   * **Pending**   — Register requests the hub has parked. Operator
//!     approves with `a`, rejects with `x`. Approval moves the entry
//!     from `state.pending` into `state.signers` / `state.nodes`;
//!     rejection sends a `RegisterAck { next_action: Shutdown }` so the
//!     peer stops trying.
//!
//! All mutations go through `state.save()` — the JSON inventory on disk
//! is the source of truth across restarts.

use crate::nostr::{HubTransport, Inbound};
use crate::proto::{HubMessage, NodeStats, Role};
use crate::state::HubState;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs};
use ratatui::Terminal;
use std::collections::HashMap;
use std::io::Stdout;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dashboard,
    Pending,
    Setup,
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Pending => "Pending",
            Tab::Setup => "Setup",
        }
    }
}

/// Bootstrap-wizard stages. Persisted in `wizard.json` so the
/// operator can pause and resume without losing progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WizardStage {
    /// Pick cosigner operators from the discovered Kind 39100 ads.
    PickPeers,
    /// Tune the liquidity-drip parameters (rate, decrement, fuzz).
    TuneDrip,
    /// Display the Docker invocation; wait for the signer + daemon to
    /// register with the hub.
    SpawnSigner,
    /// Display the next-step CLI for opening a ledger.
    OpenLedger,
    /// Display the funding QR for the ledger; wait for it to be funded.
    FundLedger,
    /// Display the next-step CLI for adding quorum members + begin.
    ActivateQuorum,
    /// Wizard complete — show summary.
    Done,
}

impl WizardStage {
    /// Display label for the wizard's breadcrumb strip.
    fn label(self) -> &'static str {
        match self {
            WizardStage::PickPeers => "1. peers",
            WizardStage::TuneDrip => "2. drip",
            WizardStage::SpawnSigner => "3. signer",
            WizardStage::OpenLedger => "4. ledger",
            WizardStage::FundLedger => "5. fund",
            WizardStage::ActivateQuorum => "6. quorum",
            WizardStage::Done => "✓ done",
        }
    }

    fn next(self) -> Self {
        match self {
            WizardStage::PickPeers => WizardStage::TuneDrip,
            WizardStage::TuneDrip => WizardStage::SpawnSigner,
            WizardStage::SpawnSigner => WizardStage::OpenLedger,
            WizardStage::OpenLedger => WizardStage::FundLedger,
            WizardStage::FundLedger => WizardStage::ActivateQuorum,
            WizardStage::ActivateQuorum => WizardStage::Done,
            WizardStage::Done => WizardStage::Done,
        }
    }

    fn prev(self) -> Self {
        match self {
            WizardStage::PickPeers => WizardStage::PickPeers,
            WizardStage::TuneDrip => WizardStage::PickPeers,
            WizardStage::SpawnSigner => WizardStage::TuneDrip,
            WizardStage::OpenLedger => WizardStage::SpawnSigner,
            WizardStage::FundLedger => WizardStage::OpenLedger,
            WizardStage::ActivateQuorum => WizardStage::FundLedger,
            WizardStage::Done => WizardStage::ActivateQuorum,
        }
    }
}

/// Persisted wizard state. Lives in `<data_dir>/wizard.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WizardState {
    pub stage: WizardStage,
    /// Operator pubkeys (hex) the user multiselected as cosigner
    /// candidates. Empty until stage 1 commits.
    #[serde(default)]
    pub selected_peer_pubkeys: Vec<String>,
    /// Drip-rate parameters chosen at stage 2.
    #[serde(default)]
    pub drip_decrement_sats: u64,
    #[serde(default)]
    pub drip_interval_sec: u64,
    #[serde(default)]
    pub drip_fuzz_sec: u64,
    /// Signer name picked at stage 3 (default "vault").
    #[serde(default)]
    pub signer_name: String,
}

impl Default for WizardState {
    fn default() -> Self {
        Self {
            stage: WizardStage::PickPeers,
            selected_peer_pubkeys: Vec::new(),
            drip_decrement_sats: 100_000,
            drip_interval_sec: 600,
            drip_fuzz_sec: 60,
            signer_name: "vault".into(),
        }
    }
}

impl WizardState {
    pub fn path(dir: &std::path::Path) -> PathBuf {
        dir.join("wizard.json")
    }

    pub fn load(dir: &std::path::Path) -> Self {
        let path = Self::path(dir);
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let raw = serde_json::to_string_pretty(self).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        std::fs::write(Self::path(dir), raw)
    }
}

pub struct App {
    data_dir: PathBuf,
    state: Arc<Mutex<HubState>>,
    transport: HubTransport,
    /// pubkey hex → last unix-seconds we heard from this peer. Lives
    /// in memory only — heartbeats restart at each launch.
    last_heartbeat: HashMap<String, u64>,
    /// Node pubkey hex → most recent NodeStats snapshot. Daemons push
    /// these every 30s via unsolicited StatusResp. Memory-only; rebuilt
    /// from inbound after restart.
    node_stats: HashMap<String, NodeStats>,
    /// When `Some`, the dashboard is overlaid with a fullscreen QR of
    /// the indexed node's funding address. j/k cycles through nodes,
    /// Esc/a/q exits. Index is into the label-sorted node list.
    address_view_idx: Option<usize>,
    tab: Tab,
    pending_cursor: ListState,
    /// Transient status line (e.g., "approved", "rejected", error
    /// messages). Cleared after a few render ticks.
    flash: Option<String>,
    flash_ttl: u8,
    /// First-launch view: shows the BIP-39 mnemonic of `hub-master-seed`
    /// and blocks all other input until the operator presses Enter to
    /// acknowledge. Sourced from the on-disk seed at startup; cleared
    /// once `state.mnemonic_acknowledged == true`. Errors during seed
    /// load surface as an inline message inside the overlay (still
    /// blocks the rest of the UI — operator should not proceed without
    /// a backup).
    mnemonic_overlay: Option<Result<String, String>>,
    /// Persisted bootstrap-wizard state — survives restarts so the
    /// operator can pause and resume.
    wizard: WizardState,
    /// Discovered peers from the most recent `peers::discover_peers`
    /// fetch. `None` until the operator first opens the Setup tab.
    /// Refreshed via the [r]efresh keybinding inside the wizard.
    discovered_peers: Option<Vec<crate::peers::PeerInfo>>,
    /// Whether a discovery fetch is currently in flight. Renders a
    /// "discovering…" placeholder until the result lands.
    discovering: bool,
    /// Cursor position in the peer multiselect list (PickPeers stage).
    peer_cursor: usize,
    /// Network the wizard targets (passed to discovery). For now
    /// hardcoded to the hub's launch-time argument; future: TUI toggle.
    wizard_network: String,
}

impl App {
    pub fn new(
        data_dir: PathBuf,
        state: Arc<Mutex<HubState>>,
        transport: HubTransport,
    ) -> Self {
        let mut cursor = ListState::default();
        cursor.select(Some(0));
        // Decide up front whether to show the mnemonic overlay. If the
        // operator has already acknowledged, skip — re-prompting after
        // the fact buys nothing. Otherwise compute the phrase (or
        // capture the error to surface in the overlay).
        let mnemonic_overlay = {
            let already_ack = state
                .try_lock()
                .ok()
                .map(|s| s.mnemonic_acknowledged)
                .unwrap_or(false);
            if already_ack {
                None
            } else {
                Some(HubState::master_seed_mnemonic(&data_dir).map_err(|e| e.to_string()))
            }
        };
        let wizard = WizardState::load(&data_dir);
        Self {
            data_dir,
            state,
            transport,
            last_heartbeat: HashMap::new(),
            node_stats: HashMap::new(),
            address_view_idx: None,
            tab: Tab::Dashboard,
            pending_cursor: cursor,
            flash: None,
            flash_ttl: 0,
            mnemonic_overlay,
            wizard,
            discovered_peers: None,
            discovering: false,
            peer_cursor: 0,
            wizard_network: "regtest".into(),
        }
    }

    /// Entry point — owns the terminal for the duration of the run.
    /// Returns on `q` or Ctrl-C; restores the terminal on the way out
    /// regardless of how we exit (panic path also handled via the RAII
    /// `TermGuard`).
    pub async fn run(mut self, mut inbox: mpsc::Receiver<Inbound>) -> Result<(), String> {
        let _guard = TermGuard::enter().map_err(|e| format!("enter tty: {}", e))?;
        let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))
            .map_err(|e| format!("terminal: {}", e))?;
        // EnterAlternateScreen sends ESC[?1049h, but real terminals
        // (especially over SSH/tmux/mosh) switch buffers asynchronously
        // — if our clear() lands before the swap takes effect, we end
        // up clearing the primary screen while subsequent draws hit
        // the alt buffer with whatever stale content was already there
        // (typically a previous TUI's last frame, which the alt buffer
        // is not blanked between sessions). 50ms is enough margin for
        // any sane terminal; invisible to the operator.
        tokio::time::sleep(Duration::from_millis(50)).await;
        terminal
            .clear()
            .map_err(|e| format!("terminal clear: {}", e))?;

        let mut events = EventStream::new();
        let mut ticker = tokio::time::interval(Duration::from_millis(500));
        ticker.tick().await;

        loop {
            // Render
            terminal
                .draw(|f| self.render(f.area(), f))
                .map_err(|e| format!("draw: {}", e))?;

            tokio::select! {
                _ = ticker.tick() => {
                    if self.flash_ttl > 0 {
                        self.flash_ttl -= 1;
                        if self.flash_ttl == 0 { self.flash = None; }
                    }
                }
                maybe_evt = events.next() => {
                    match maybe_evt {
                        Some(Ok(Event::Key(k))) if k.kind == KeyEventKind::Press => {
                            // Ctrl-L: force-redraw escape hatch. Same
                            // semantics as in vim/less/htop — operator
                            // can rescue a garbled screen without
                            // having to drag the window border.
                            if k.code == KeyCode::Char('l') && k.modifiers == KeyModifiers::CONTROL {
                                let _ = terminal.clear();
                                continue;
                            }
                            if self.handle_key(k).await {
                                return Ok(());
                            }
                        }
                        Some(Ok(Event::Resize(_, _))) => {
                            // Drop the cached buffer so the next draw
                            // computes the layout against the new size
                            // from scratch. ratatui's autoresize handles
                            // the size change on its own, but without a
                            // clear the previous frame's chrome can
                            // bleed through cells that the new layout
                            // no longer covers.
                            let _ = terminal.clear();
                        }
                        Some(Err(e)) => {
                            return Err(format!("terminal event: {}", e));
                        }
                        None => return Ok(()), // stream closed
                        _ => {}
                    }
                }
                maybe_in = inbox.recv() => {
                    let Some(inbound) = maybe_in else {
                        // Nostr pump died — surface and exit so the
                        // operator notices instead of staring at a
                        // stale dashboard.
                        return Err("nostr inbox closed".to_string());
                    };
                    self.absorb_inbound(inbound).await;
                }
            }
        }
    }

    /// Handle a keypress. Returns `true` if the app should exit.
    async fn handle_key(&mut self, k: KeyEvent) -> bool {
        // Mnemonic overlay pre-empts everything else. Only Enter
        // (acknowledge) and q/Ctrl-C (quit) get through — the
        // operator must explicitly confirm they've backed up the
        // seed before the rest of the UI is reachable.
        if self.mnemonic_overlay.is_some() {
            match (k.code, k.modifiers) {
                (KeyCode::Enter, _) => {
                    // Persist the ack before clearing the overlay so a
                    // crash mid-confirmation doesn't re-prompt forever.
                    let save_err = {
                        let mut st = self.state.lock().await;
                        st.acknowledge_mnemonic();
                        st.save(&self.data_dir).err()
                    };
                    if let Some(e) = save_err {
                        tracing::warn!("persist mnemonic ack: {}", e);
                        self.flash(format!("save failed: {}", e));
                        return false;
                    }
                    self.mnemonic_overlay = None;
                    self.flash("mnemonic acknowledged".to_string());
                    return false;
                }
                (KeyCode::Char('q'), _) => return true,
                (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => return true,
                _ => return false,
            }
        }
        // Address overlay swallows its own keys when active. q/Esc/a
        // exits; j/k cycles through nodes. Anything else is no-op so
        // operators don't accidentally trigger underlying-tab actions.
        if self.address_view_idx.is_some() {
            match (k.code, k.modifiers) {
                (KeyCode::Esc, _)
                | (KeyCode::Char('a'), _)
                | (KeyCode::Char('q'), _) => {
                    self.address_view_idx = None;
                }
                (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                    self.address_cycle(1).await;
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                    self.address_cycle(-1).await;
                }
                _ => {}
            }
            return false;
        }

        match (k.code, k.modifiers) {
            (KeyCode::Char('q'), _) => return true,
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => return true,
            (KeyCode::Tab, _) | (KeyCode::Char('\t'), _) => {
                self.tab = match self.tab {
                    Tab::Dashboard => Tab::Pending,
                    Tab::Pending => Tab::Setup,
                    Tab::Setup => Tab::Dashboard,
                };
            }
            (KeyCode::Char('1'), _) => self.tab = Tab::Dashboard,
            (KeyCode::Char('2'), _) => self.tab = Tab::Pending,
            (KeyCode::Char('3'), _) => self.tab = Tab::Setup,
            (KeyCode::Char('a'), _) if self.tab == Tab::Dashboard => {
                // Enter address-view mode if there's at least one node.
                let n = self.state.lock().await.nodes.len();
                if n > 0 {
                    self.address_view_idx = Some(0);
                } else {
                    self.flash("no nodes to show addresses for".to_string());
                }
            }
            (KeyCode::Down, _) | (KeyCode::Char('j'), _) if self.tab == Tab::Pending => {
                self.cursor_step(1).await;
            }
            (KeyCode::Up, _) | (KeyCode::Char('k'), _) if self.tab == Tab::Pending => {
                self.cursor_step(-1).await;
            }
            (KeyCode::Char('a'), _) | (KeyCode::Enter, _) if self.tab == Tab::Pending => {
                if let Err(e) = self.approve_selected().await {
                    self.flash(format!("approve: {}", e));
                }
            }
            // ── Setup wizard keys ──
            (KeyCode::Char('r'), _) if self.tab == Tab::Setup => {
                self.refresh_discovered_peers().await;
            }
            (KeyCode::Char('n'), _) if self.tab == Tab::Setup => {
                self.wizard.stage = self.wizard.stage.next();
                let _ = self.wizard.save(&self.data_dir);
                return false;
            }
            (KeyCode::Char('p'), _) if self.tab == Tab::Setup => {
                self.wizard.stage = self.wizard.stage.prev();
                let _ = self.wizard.save(&self.data_dir);
                return false;
            }
            (KeyCode::Down, _) | (KeyCode::Char('j'), _)
                if self.tab == Tab::Setup
                    && self.wizard.stage == WizardStage::PickPeers =>
            {
                let n = self.discovered_peers.as_ref().map(|p| p.len()).unwrap_or(0);
                if n > 0 {
                    self.peer_cursor = (self.peer_cursor + 1).min(n - 1);
                }
                return false;
            }
            (KeyCode::Up, _) | (KeyCode::Char('k'), _)
                if self.tab == Tab::Setup
                    && self.wizard.stage == WizardStage::PickPeers =>
            {
                self.peer_cursor = self.peer_cursor.saturating_sub(1);
                return false;
            }
            (KeyCode::Char(' '), _)
                if self.tab == Tab::Setup
                    && self.wizard.stage == WizardStage::PickPeers =>
            {
                if let Some(peers) = self.discovered_peers.as_ref() {
                    if let Some(peer) = peers.get(self.peer_cursor) {
                        let pk = peer.operator_pubkey.clone();
                        if let Some(pos) =
                            self.wizard.selected_peer_pubkeys.iter().position(|p| *p == pk)
                        {
                            self.wizard.selected_peer_pubkeys.remove(pos);
                        } else {
                            self.wizard.selected_peer_pubkeys.push(pk);
                        }
                        let _ = self.wizard.save(&self.data_dir);
                    }
                }
                return false;
            }
            (KeyCode::Char('x'), _) if self.tab == Tab::Pending => {
                if let Err(e) = self.reject_selected().await {
                    self.flash(format!("reject: {}", e));
                }
            }
            _ => {}
        }
        false
    }

    /// Move through the label-sorted node list in the address overlay.
    async fn address_cycle(&mut self, delta: i32) {
        let n = self.state.lock().await.nodes.len();
        if n == 0 {
            self.address_view_idx = None;
            return;
        }
        let cur = self.address_view_idx.unwrap_or(0) as i32;
        let next = (cur + delta).rem_euclid(n as i32) as usize;
        self.address_view_idx = Some(next);
    }

    /// Look up the (label, NodeStats) for the cursor in the address
    /// overlay. None if the cursor's stale (node removed mid-view) or
    /// there's no stats push yet.
    async fn address_target(&self, idx: usize) -> Option<(String, Option<NodeStats>, String)> {
        let st = self.state.lock().await;
        let mut entries: Vec<(&String, &crate::state::NodeRecord)> = st.nodes.iter().collect();
        entries.sort_by(|a, b| a.1.label.cmp(&b.1.label));
        let (pk, rec) = entries.get(idx)?;
        let stats = self.node_stats.get(*pk).cloned();
        Some(((*rec).label.clone(), stats, (*pk).clone()))
    }

    async fn cursor_step(&mut self, delta: i32) {
        let st = self.state.lock().await;
        let len = st.pending.len();
        drop(st);
        if len == 0 {
            self.pending_cursor.select(None);
            return;
        }
        let cur = self.pending_cursor.selected().unwrap_or(0) as i32;
        let next = (cur + delta).rem_euclid(len as i32) as usize;
        self.pending_cursor.select(Some(next));
    }

    async fn approve_selected(&mut self) -> Result<(), String> {
        let cur = self.pending_cursor.selected().ok_or("no selection")?;
        let sender_pk = self.nth_pending_pubkey(cur).await?;
        let mut st = self.state.lock().await;
        let label = crate::control::approve(&mut st, &self.data_dir, &sender_pk, None)?;
        let snapshot = st.clone();
        drop(st);
        crate::control::send_accept_ack(&self.transport, &sender_pk, &label).await;
        crate::control::publish_backup(&self.transport, &snapshot, &self.data_dir).await;
        self.flash(format!("approved {}", short_pk(&sender_pk)));
        self.fix_cursor_after_shrink(cur).await;
        Ok(())
    }

    async fn reject_selected(&mut self) -> Result<(), String> {
        let cur = self.pending_cursor.selected().ok_or("no selection")?;
        let sender_pk = self.nth_pending_pubkey(cur).await?;
        let mut st = self.state.lock().await;
        crate::control::reject(&mut st, &self.data_dir, &sender_pk)?;
        let snapshot = st.clone();
        drop(st);
        crate::control::send_reject_ack(&self.transport, &sender_pk).await;
        crate::control::publish_backup(&self.transport, &snapshot, &self.data_dir).await;
        self.flash(format!("rejected {}", short_pk(&sender_pk)));
        self.fix_cursor_after_shrink(cur).await;
        Ok(())
    }

    /// Look up the pubkey at the cursor's position in the sorted
    /// pending list. The TUI displays pending sorted by first_seen, so
    /// the cursor's index has the same ordering.
    async fn nth_pending_pubkey(&self, idx: usize) -> Result<String, String> {
        let st = self.state.lock().await;
        let mut entries: Vec<_> = st.pending.iter().collect();
        entries.sort_by_key(|(_, v)| v.first_seen);
        entries
            .get(idx)
            .map(|(k, _)| (*k).clone())
            .ok_or_else(|| format!("no pending entry at index {}", idx))
    }

    async fn fix_cursor_after_shrink(&mut self, prev_idx: usize) {
        let new_len = self.state.lock().await.pending.len();
        if new_len == 0 {
            self.pending_cursor.select(None);
        } else if prev_idx >= new_len {
            self.pending_cursor.select(Some(new_len - 1));
        }
    }

    async fn absorb_inbound(&mut self, inbound: Inbound) {
        let from = inbound.from.to_hex();
        match inbound.msg {
            HubMessage::Register {
                role,
                identity_pubkey,
                version,
                label,
                signer_pubkey,
            } => {
                let mut st = self.state.lock().await;
                let already = match crate::control::ingest_register(
                    &mut st,
                    &self.data_dir,
                    &from,
                    role,
                    identity_pubkey,
                    version,
                    label,
                    signer_pubkey,
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::warn!("ingest register from {}: {}", from, e);
                        return;
                    }
                };
                let snapshot = st.clone();
                drop(st);
                if already {
                    crate::control::send_already_approved_ack(&self.transport, &from).await;
                } else {
                    crate::control::send_waiting_ack(&self.transport, &from).await;
                }
                crate::control::publish_backup(&self.transport, &snapshot, &self.data_dir).await;
            }
            HubMessage::Heartbeat { ts, .. } => {
                self.last_heartbeat.insert(from, ts);
            }
            HubMessage::StatusResp { node_stats, .. } => {
                // Status pushes carry liveness too — refresh hb so a
                // node sending status but not heartbeats (because of a
                // scheduler hiccup) still looks alive.
                self.last_heartbeat.insert(from.clone(), unix_secs());
                if let Some(stats) = node_stats {
                    self.node_stats.insert(from, stats);
                }
            }
            HubMessage::RegisterAck { .. } | HubMessage::StatusReq => {
                // Hub doesn't expect these inbound.
            }
        }
    }

    fn flash(&mut self, s: String) {
        self.flash = Some(s);
        // 6 ticks × 500ms = 3 seconds visible.
        self.flash_ttl = 6;
    }

    /// Re-run peer discovery against the configured network. Synchronous
    /// from the key-handler caller's perspective — we await the fetch.
    /// 10s timeout inside `discover_peers` keeps the worst case bounded.
    async fn refresh_discovered_peers(&mut self) {
        self.discovering = true;
        match crate::peers::discover_peers(&self.transport, &self.wizard_network).await {
            Ok(peers) => {
                self.discovered_peers = Some(peers);
                self.flash("refreshed peer list".into());
            }
            Err(e) => {
                self.flash(format!("discover failed: {}", e));
            }
        }
        self.discovering = false;
        self.peer_cursor = 0;
    }

    fn render(&mut self, area: Rect, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // tabs + hub pk header
                Constraint::Min(0),    // body
                Constraint::Length(1), // status line
            ])
            .split(area);

        // Header: tab strip
        let titles: Vec<Line> = [Tab::Dashboard, Tab::Pending, Tab::Setup]
            .iter()
            .map(|t| Line::from(t.title()))
            .collect();
        let selected = match self.tab {
            Tab::Dashboard => 0,
            Tab::Pending => 1,
            Tab::Setup => 2,
        };
        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL).title(" deposits-hub "))
            .select(selected)
            .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
        f.render_widget(tabs, chunks[0]);

        // Body — clone the inventory under a brief lock so we can hand
        // out &mut self to the per-tab renderers without overlapping
        // borrows. The state is small (10s of entries); the clone is
        // cheap compared to a frame's render budget.
        let snapshot = match self.state.try_lock() {
            Ok(st) => Some(st.clone()),
            Err(_) => None,
        };
        match snapshot.as_ref() {
            Some(st) => match self.tab {
                Tab::Dashboard => self.render_dashboard(st, chunks[1], f),
                Tab::Pending => self.render_pending(st, chunks[1], f),
                Tab::Setup => self.render_setup(st, chunks[1], f),
            },
            None => {
                let p = Paragraph::new("...");
                f.render_widget(p, chunks[1]);
            }
        }

        // Address overlay sits on top of the dashboard body. Centered,
        // takes ~70% of the inner area, falls back gracefully if the
        // terminal is too small for the QR.
        if let Some(idx) = self.address_view_idx {
            if let Some(st) = snapshot.as_ref() {
                self.render_address_overlay(st, idx, chunks[1], f);
            }
        }

        // Mnemonic overlay pre-empts everything else on first launch.
        // Rendered last so it sits on top of any other UI.
        if self.mnemonic_overlay.is_some() {
            self.render_mnemonic_overlay(chunks[1], f);
        }

        // Status line
        let hint = if self.mnemonic_overlay.is_some() {
            "[Enter] I've written these down  [q] quit"
        } else if self.address_view_idx.is_some() {
            "[j/k] cycle  [Esc/a/q] close"
        } else {
            match self.tab {
                Tab::Dashboard => "[a] address  [1]ashboard  [2]ending  [3]etup  [Tab] switch  [q] quit",
                Tab::Pending => "[a] approve  [x] reject  [j/k] move  [Tab] switch  [q] quit",
                Tab::Setup => match self.wizard.stage {
                    WizardStage::PickPeers => "[j/k] move  [space] toggle  [r] refresh  [n] next  [Tab] switch  [q] quit",
                    _ => "[n] next  [p] prev  [Tab] switch  [q] quit",
                },
            }
        };
        let body = match &self.flash {
            Some(msg) => format!("{}    │    {}", msg, hint),
            None => hint.to_string(),
        };
        let status = Paragraph::new(body).style(Style::default().fg(Color::DarkGray));
        f.render_widget(status, chunks[2]);
    }

    /// Fullscreen-ish QR popup for one node's funding address. Draws
    /// over the dashboard body. If the focused node has no NodeStats
    /// yet (just registered, hasn't pushed status), shows a placeholder.
    fn render_address_overlay(
        &self,
        st: &HubState,
        idx: usize,
        area: Rect,
        f: &mut ratatui::Frame,
    ) {
        // Look up the node at idx (label-sorted).
        let mut entries: Vec<(&String, &crate::state::NodeRecord)> = st.nodes.iter().collect();
        entries.sort_by(|a, b| a.1.label.cmp(&b.1.label));
        let n = entries.len();
        let (pk, rec) = match entries.get(idx) {
            Some(e) => *e,
            None => return,
        };
        let stats = self.node_stats.get(pk);

        // Center an inner area at ~80% of the body. The QR's natural
        // size depends on the address — a P2TR mainnet address is 62
        // chars; QR fits in ~33 modules across at EC=M. Each terminal
        // cell encodes 2 modules horizontally and 2 vertically per row
        // (Unicode half-blocks), so the QR is ~33 cols × ~17 rows.
        let inner = center_rect(area, 80, 80);
        f.render_widget(Clear, inner);

        let title = format!(" {} of {} — {} ", idx + 1, n, rec.label);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .style(Style::default().fg(Color::Yellow));
        let block_inner = block.inner(inner);
        f.render_widget(block, inner);

        let mut lines: Vec<Line> = Vec::new();
        match stats.and_then(|s| s.next_address.as_deref()) {
            Some(addr) => {
                // Render the QR first as a single text block, then
                // the address line beneath. If the inner area is too
                // small for the QR we fall back to address-only.
                let qr = crate::qr::render(addr);
                let qr_lines: Vec<&str> = qr.lines().collect();
                let qr_h = qr_lines.len() as u16;
                let qr_w = qr_lines
                    .iter()
                    .map(|l| l.chars().count() as u16)
                    .max()
                    .unwrap_or(0);
                if qr_h + 4 <= block_inner.height && qr_w <= block_inner.width {
                    // Pad each line to center horizontally.
                    let pad = (block_inner.width.saturating_sub(qr_w)) / 2;
                    let pad_str: String = std::iter::repeat(' ').take(pad as usize).collect();
                    for l in &qr_lines {
                        lines.push(Line::from(format!("{}{}", pad_str, l)));
                    }
                    lines.push(Line::from(""));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    addr.to_string(),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                )));
                if let Some(s) = stats {
                    lines.push(Line::from(""));
                    lines.push(Line::from(format!(
                        "wallet: {:.4} BTC   ledgers: {}   quorums: {}",
                        (s.wallet_balance_sats as f64) / 100_000_000.0,
                        s.ledger_count,
                        s.quorum_member_count,
                    )));
                }
            }
            None => {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "(awaiting status from this node — addresses arrive on the next 30s push)",
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }

        let p = Paragraph::new(lines).alignment(ratatui::layout::Alignment::Center);
        f.render_widget(p, block_inner);
    }

    /// First-launch view: the BIP-39 mnemonic of `hub-master-seed`,
    /// laid out 4-per-row, framed in a fixed-color border, with a
    /// terse "write this down, then press Enter" prompt. Pre-empts
    /// every other UI element.
    fn render_mnemonic_overlay(&self, area: Rect, f: &mut ratatui::Frame) {
        let inner = center_rect(area, 90, 80);
        f.render_widget(Clear, inner);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" back up your hub seed ")
            .style(Style::default().fg(Color::Yellow));
        let block_inner = block.inner(inner);
        f.render_widget(block, inner);

        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "These 24 words derive every signer this hub will ever spawn.",
            Style::default().fg(Color::White),
        )));
        lines.push(Line::from(Span::styled(
            "Lose them and you lose every signer's private key.",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Write the words on paper. Store offline. Do not screenshot.",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(""));

        match &self.mnemonic_overlay {
            Some(Ok(phrase)) => {
                // Lay out 4 per row, numbered, monospace-friendly.
                // BIP-39 24-word phrase → 6 rows of 4.
                let words: Vec<&str> = phrase.split_whitespace().collect();
                for chunk in words.chunks(4) {
                    let chunk_start = words
                        .iter()
                        .position(|w| std::ptr::eq(*w, chunk[0]))
                        .unwrap_or(0);
                    let mut spans: Vec<Span> = Vec::new();
                    for (offset, w) in chunk.iter().enumerate() {
                        let idx = chunk_start + offset + 1;
                        spans.push(Span::styled(
                            format!("{:>2}. ", idx),
                            Style::default().fg(Color::DarkGray),
                        ));
                        spans.push(Span::styled(
                            format!("{:<10}", w),
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ));
                        spans.push(Span::raw("  "));
                    }
                    lines.push(Line::from(spans));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "After you've written them down, press [Enter] to continue.",
                    Style::default().fg(Color::Green),
                )));
            }
            Some(Err(e)) => {
                lines.push(Line::from(Span::styled(
                    format!("error loading seed: {}", e),
                    Style::default().fg(Color::Red),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "[q] quit  — investigate the data dir and retry.",
                    Style::default().fg(Color::DarkGray),
                )));
            }
            None => {}
        }

        let p = Paragraph::new(lines).alignment(ratatui::layout::Alignment::Center);
        f.render_widget(p, block_inner);
    }

    /// Setup wizard tab. Renders a breadcrumb strip across the top,
    /// then delegates to a per-stage view in the body.
    fn render_setup(&self, _st: &HubState, area: Rect, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);

        // Breadcrumb strip
        let stages = [
            WizardStage::PickPeers,
            WizardStage::TuneDrip,
            WizardStage::SpawnSigner,
            WizardStage::OpenLedger,
            WizardStage::FundLedger,
            WizardStage::ActivateQuorum,
            WizardStage::Done,
        ];
        let breadcrumb: Vec<Span> = stages
            .iter()
            .flat_map(|s| {
                let label = s.label();
                let style = if *s == self.wizard.stage {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                vec![
                    Span::styled(label.to_string(), style),
                    Span::raw("  "),
                ]
            })
            .collect();
        let crumbs = Paragraph::new(Line::from(breadcrumb))
            .block(Block::default().borders(Borders::ALL).title(" bootstrap "));
        f.render_widget(crumbs, chunks[0]);

        // Body — per-stage view
        match self.wizard.stage {
            WizardStage::PickPeers => self.render_stage_pick_peers(chunks[1], f),
            WizardStage::TuneDrip => self.render_stage_tune_drip(chunks[1], f),
            WizardStage::SpawnSigner => self.render_stage_spawn_signer(chunks[1], f),
            WizardStage::OpenLedger => self.render_stage_open_ledger(chunks[1], f),
            WizardStage::FundLedger => self.render_stage_fund_ledger(chunks[1], f),
            WizardStage::ActivateQuorum => self.render_stage_activate_quorum(chunks[1], f),
            WizardStage::Done => self.render_stage_done(chunks[1], f),
        }
    }

    fn render_stage_pick_peers(&self, area: Rect, f: &mut ratatui::Frame) {
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            format!(
                "select cosigner peers from the {} relay",
                self.wizard_network
            ),
            Style::default().fg(Color::White),
        )));
        lines.push(Line::from(""));
        match (&self.discovered_peers, self.discovering) {
            (_, true) => {
                lines.push(Line::from(Span::styled(
                    "discovering…",
                    Style::default().fg(Color::DarkGray),
                )));
            }
            (None, false) => {
                lines.push(Line::from(Span::styled(
                    "press [r] to fetch the peer directory",
                    Style::default().fg(Color::DarkGray),
                )));
            }
            (Some(peers), false) if peers.is_empty() => {
                lines.push(Line::from(Span::styled(
                    "no peers found on this network — check relay connectivity",
                    Style::default().fg(Color::Red),
                )));
            }
            (Some(peers), false) => {
                for (i, p) in peers.iter().enumerate() {
                    let selected =
                        self.wizard.selected_peer_pubkeys.contains(&p.operator_pubkey);
                    let marker = if selected { "[x]" } else { "[ ]" };
                    let cursor = if i == self.peer_cursor { ">" } else { " " };
                    let name = p
                        .operator_name
                        .clone()
                        .unwrap_or_else(|| format!("op-{}…", &p.operator_pubkey[..8]));
                    let short_name = if name.len() > 24 {
                        format!("{}…", &name[..23])
                    } else {
                        name.clone()
                    };
                    let row = format!(
                        "{} {} {:<24}  {} ledgers   fee {:.2}%   {}…",
                        cursor,
                        marker,
                        short_name,
                        p.ledger_count,
                        p.annual_fee_bps.unwrap_or(0) as f64 / 100.0,
                        &p.operator_pubkey[..16.min(p.operator_pubkey.len())],
                    );
                    let style = if selected {
                        Style::default().fg(Color::Green)
                    } else if i == self.peer_cursor {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(Span::styled(row, style)));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!(
                        "{} selected — when ready, [n] continues to drip tuning",
                        self.wizard.selected_peer_pubkeys.len()
                    ),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
        let p = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" peers "));
        f.render_widget(p, area);
    }

    fn render_stage_tune_drip(&self, area: Rect, f: &mut ratatui::Frame) {
        let lines = vec![
            Line::from(Span::styled(
                "liquidity drip — how fast does your reserve un-lock?",
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from(format!(
                "  decrement_sats:    {}",
                self.wizard.drip_decrement_sats
            )),
            Line::from(format!(
                "  interval_sec:      {}",
                self.wizard.drip_interval_sec
            )),
            Line::from(format!(
                "  interval_fuzz_sec: ±{}",
                self.wizard.drip_fuzz_sec
            )),
            Line::from(""),
            Line::from(Span::styled(
                "(in-tab edit not implemented — set via `deposits-node liquidity drip-create` after bootstrap)",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "[n] continue   [p] back",
                Style::default().fg(Color::DarkGray),
            )),
        ];
        let p = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" drip "));
        f.render_widget(p, area);
    }

    fn render_stage_spawn_signer(&self, area: Rect, f: &mut ratatui::Frame) {
        let lines = vec![
            Line::from(Span::styled(
                "spawn the signer subprocess",
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from("Run this on the host that should hold the signer keys:"),
            Line::from(""),
            Line::from(Span::styled(
                format!(
                    "  deposits-hub spawn-line --name {} --relay <hub-relay-url> --docker",
                    self.wizard.signer_name
                ),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "(or omit --docker for a bash launch line)",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(
                "When the signer registers with the hub, accept it on the Pending tab.",
            ),
            Line::from(""),
            Line::from(Span::styled(
                "[n] continue once accepted   [p] back",
                Style::default().fg(Color::DarkGray),
            )),
        ];
        let p = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" signer "));
        f.render_widget(p, area);
    }

    fn render_stage_open_ledger(&self, area: Rect, f: &mut ratatui::Frame) {
        let lines = vec![
            Line::from(Span::styled(
                "open the operator's first ledger",
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from("On the daemon's host:"),
            Line::from(""),
            Line::from(Span::styled(
                "  deposits-node ledger open",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(
                "The daemon's NodeStats push will reflect the new ledger on the dashboard.",
            ),
            Line::from(""),
            Line::from(Span::styled(
                "[n] continue when the ledger appears   [p] back",
                Style::default().fg(Color::DarkGray),
            )),
        ];
        let p = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" ledger "));
        f.render_widget(p, area);
    }

    fn render_stage_fund_ledger(&self, area: Rect, f: &mut ratatui::Frame) {
        let lines = vec![
            Line::from(Span::styled(
                "fund the ledger",
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from(
                "Switch to the Dashboard tab and press [a] to display the funding address QR for your new ledger.",
            ),
            Line::from(""),
            Line::from("Pay the QR with any Bitcoin wallet."),
            Line::from(""),
            Line::from(Span::styled(
                "[n] continue when paid   [p] back",
                Style::default().fg(Color::DarkGray),
            )),
        ];
        let p = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" fund "));
        f.render_widget(p, area);
    }

    fn render_stage_activate_quorum(&self, area: Rect, f: &mut ratatui::Frame) {
        let mut lines = vec![
            Line::from(Span::styled(
                "activate the quorum",
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from(format!(
                "{} peers selected. On the daemon's host, run:",
                self.wizard.selected_peer_pubkeys.len()
            )),
            Line::from(""),
        ];
        for pk in &self.wizard.selected_peer_pubkeys {
            lines.push(Line::from(Span::styled(
                format!(
                    "  deposits-node quorum add <ledger> {} <their_ledger>",
                    &pk[..16.min(pk.len())]
                ),
                Style::default().fg(Color::Yellow),
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  deposits-node quorum begin <ledger> --amount-sats <N> \\",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            "      --collateral-ratio 0.6 --protocol-version cltv-offset-v2",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "[n] mark done   [p] back",
            Style::default().fg(Color::DarkGray),
        )));
        let p = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" quorum "));
        f.render_widget(p, area);
    }

    fn render_stage_done(&self, area: Rect, f: &mut ratatui::Frame) {
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "✓ bootstrap complete",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(
                "Your hub is paired with a signer, your daemon owns at least one ledger,",
            ),
            Line::from("and your quorum is activating on-chain."),
            Line::from(""),
            Line::from(Span::styled(
                "Switch to the Dashboard tab to watch the lifecycle.",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Set up a liquidity-drip plan with:",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                format!(
                    "  deposits-node liquidity drip-create <alias> <ledger> \\\n      --initial-sats <N> --decrement-sats {} --interval-sec {} --interval-fuzz-sec {}",
                    self.wizard.drip_decrement_sats,
                    self.wizard.drip_interval_sec,
                    self.wizard.drip_fuzz_sec,
                ),
                Style::default().fg(Color::Yellow),
            )),
        ];
        let p = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" done "));
        f.render_widget(p, area);
    }

    fn render_dashboard(&self, st: &HubState, area: Rect, f: &mut ratatui::Frame) {
        let now = unix_secs();
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            format!("hub pubkey: {}", st.hub_pubkey),
            Style::default().fg(Color::Cyan),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("Signers ({})", st.signers.len()),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        if st.signers.is_empty() {
            lines.push(Line::from("  (none — pending tab shows requests)"));
        } else {
            let mut entries: Vec<_> = st.signers.iter().collect();
            entries.sort_by(|a, b| a.1.label.cmp(&b.1.label));
            for (pk, rec) in entries {
                let hb = self
                    .last_heartbeat
                    .get(pk)
                    .map(|ts| format!("hb {}s ago", now.saturating_sub(*ts)))
                    .unwrap_or_else(|| "(no heartbeat yet)".to_string());
                lines.push(Line::from(format!(
                    "  {:<24} {}  v{}  {}",
                    rec.label,
                    short_pk(pk),
                    rec.last_version,
                    hb
                )));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("Nodes ({})", st.nodes.len()),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        if st.nodes.is_empty() {
            lines.push(Line::from("  (none)"));
        } else {
            let mut entries: Vec<_> = st.nodes.iter().collect();
            entries.sort_by(|a, b| a.1.label.cmp(&b.1.label));
            for (pk, rec) in entries {
                let hb = self
                    .last_heartbeat
                    .get(pk)
                    .map(|ts| format!("hb {}s ago", now.saturating_sub(*ts)))
                    .unwrap_or_else(|| "(no heartbeat yet)".to_string());
                let signer = match rec.signer_pubkey.as_deref() {
                    None => "local".to_string(),
                    Some(sig_pk) => {
                        // Resolve transport pk → signer label by scanning
                        // the signers map. ~10s of entries, render is
                        // not hot, no need to build an index.
                        st.signers
                            .values()
                            .find(|s| s.transport_pubkey == sig_pk)
                            .map(|s| s.label.clone())
                            .unwrap_or_else(|| short_pk(sig_pk))
                    }
                };
                let stats = self
                    .node_stats
                    .get(pk)
                    .map(|s| {
                        // Only show `active=N` parenthetical when not
                        // everything's active — keeps the row terse
                        // for the steady state.
                        let active_note = if s.active_ledger_count == s.ledger_count {
                            String::new()
                        } else {
                            format!(" (active={})", s.active_ledger_count)
                        };
                        format!(
                            "wallet={:.4}BTC  ledgers={}{}  quorums={}  tip={}",
                            (s.wallet_balance_sats as f64) / 100_000_000.0,
                            s.ledger_count,
                            active_note,
                            s.quorum_member_count,
                            s.chain_tip
                        )
                    })
                    .unwrap_or_else(|| "(awaiting status)".to_string());
                lines.push(Line::from(format!(
                    "  {:<10} {}  v{}  signer={}  {}",
                    rec.label,
                    short_pk(pk),
                    rec.last_version,
                    signer,
                    hb
                )));
                lines.push(Line::from(format!("    {}", stats)));
            }
        }
        // Clear first — Paragraph renders top-down without blanking
        // trailing cells, so a frame with fewer lines than a previous
        // frame leaves stale text below. (Observed: when a node
        // disappeared, its old "signer=…  hb …" tail showed through
        // the new shorter "Nodes (0)" line.)
        f.render_widget(Clear, area);
        let p = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" inventory "));
        f.render_widget(p, area);
    }

    fn render_pending(&mut self, st: &HubState, area: Rect, f: &mut ratatui::Frame) {
        let mut entries: Vec<_> = st.pending.iter().collect();
        entries.sort_by_key(|(_, v)| v.first_seen);

        if entries.is_empty() {
            f.render_widget(Clear, area);
            let p = Paragraph::new("(no pending registrations — peers waiting for approval show up here)")
                .block(Block::default().borders(Borders::ALL).title(" pending "));
            f.render_widget(p, area);
            self.pending_cursor.select(None);
            return;
        }

        // Make sure cursor is in-bounds.
        if self.pending_cursor.selected().is_none() {
            self.pending_cursor.select(Some(0));
        }

        let now = unix_secs();
        let items: Vec<ListItem> = entries
            .iter()
            .map(|(pending_key, e)| {
                let waiting = now.saturating_sub(e.first_seen);
                let role = match e.role {
                    Role::Signer => "signer",
                    Role::Node => "node",
                };
                let label = e.suggested_label.as_deref().unwrap_or("(unnamed)");
                // pending_key is "<role>:<pk>" — strip the role prefix
                // for display since the role is already shown next to it.
                let pk_only =
                    pending_key.splitn(2, ':').nth(1).unwrap_or(pending_key.as_str());
                ListItem::new(format!(
                    "{:<6} {:<24} from {}  v{}  waiting {}s",
                    role,
                    label,
                    short_pk(pk_only),
                    e.version,
                    waiting,
                ))
            })
            .collect();
        f.render_widget(Clear, area);
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" pending "))
            .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");
        f.render_stateful_widget(list, area, &mut self.pending_cursor);
    }
}

/// Restore the terminal on drop — covers normal exit and panic.
struct TermGuard;

impl TermGuard {
    fn enter() -> std::io::Result<Self> {
        enable_raw_mode()?;
        execute!(std::io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    }
}

#[allow(dead_code)]
fn _silence_stdout(_: &Stdout) {}

/// Center a rect within `area`, taking `pct_x`/`pct_y` percent of each
/// dimension. Used by the address overlay; standard ratatui popup
/// pattern.
fn center_rect(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let popup_w = area.width * pct_x / 100;
    let popup_h = area.height * pct_y / 100;
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    Rect {
        x,
        y,
        width: popup_w,
        height: popup_h,
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn short_pk(pk: &str) -> String {
    if pk.len() > 12 {
        format!("{}…{}", &pk[..6], &pk[pk.len() - 4..])
    } else {
        pk.to_string()
    }
}
