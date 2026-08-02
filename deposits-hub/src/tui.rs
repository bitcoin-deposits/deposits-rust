//! TUI shell for the operator.
//!
//! Screen map (Tab cycles tabs; 1/2/3 jump directly):
//!
//! ```text
//! deposits-hub TUI
//! ├── Dashboard  [1]              needs-attention panel + signers/nodes
//! │   ├── needs attention         per-ledger concerns, worst deadline first
//! │   ├── node details  [Enter]   per-node ledgers/liabilities/quorum +
//! │   │                           "serving on" partner quorums; j/k node, Esc back
//! │   └── address overlay  [a]    funding-address QR; j/k cycle, Esc close
//! ├── Pending    [2]              parked Register requests
//! │       approve [a/Enter] · reject [x] · move [j/k]
//! └── Setup      [3]              bootstrap wizard  (next [n] / prev [p])
//!     ├── 1. peers       pick cosigners; [r] refresh, [space] toggle
//!     ├── 2. drip        liquidity-drip tuning
//!     ├── 3. signer      spawn locally [s] or copy the docker line
//!     ├── 4. ledger      open via admin RPC [o]
//!     ├── 5. fund        funding QR (via the Dashboard address overlay)
//!     ├── 6. quorum      quorum add + begin
//!     └── ✓ done         summary
//!
//! first launch: a mnemonic overlay gates every screen until the
//!               operator acknowledges the hub seed with [Enter]
//! ```
//!
//! Behavior notes:
//!
//!   * **Dashboard** — approved signers + nodes, with last-heartbeat age
//!     (live-updated from the nostr inbox).
//!   * **Pending**   — Register requests the hub has parked. Operator
//!     approves with `a`, rejects with `x`. Approval moves the entry
//!     from `state.pending` into `state.signers` / `state.nodes`;
//!     rejection sends a `RegisterAck { next_action: Shutdown }` so the
//!     peer stops trying.
//!   * **Setup**     — the bootstrap wizard. Stage is persisted to
//!     `wizard.json` so the operator can pause and resume across runs.
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
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Tabs, Wrap,
};
use ratatui::Terminal;
use std::collections::HashMap;
use std::io::Stdout;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
        let raw = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(Self::path(dir), raw)
    }
}

pub struct App {
    data_dir: PathBuf,
    state: Arc<Mutex<HubState>>,
    /// Nostr transport for hub→signer/daemon messaging. `None` only in
    /// unit tests, where the App is driven offline to exercise the
    /// input→state logic and rendering without a relay connection; the
    /// action paths (approve/reject/discover/inbound) skip their network
    /// sends when it's absent but still mutate + persist local state.
    transport: Option<HubTransport>,
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
    /// Live spawned-signer handles. Each `[s]` press on the wizard's
    /// signer stage appends one. Dropped when the App drops
    /// (kill_on_drop is set on the underlying Command), so closing the
    /// TUI cleans up child processes automatically.
    spawned_signers: Vec<crate::spawn::SpawnHandle>,
    /// Relays the hub was launched with — passed to the Spawner so the
    /// spawned signer knows where to find the hub.
    hub_relays: Vec<String>,
    /// Cursor into the label-sorted node list on the Dashboard (which
    /// node a `[Enter]` drills into).
    dashboard_cursor: usize,
    /// When `Some(pubkey)`, the Dashboard body is replaced by the
    /// node-details pane for that node. Esc returns to the inventory.
    details_node: Option<String>,
}

/// Severity of a standing operator concern, worst first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Severity {
    Critical,
    Warn,
}

/// One thing that needs the operator's attention, surfaced in the
/// Dashboard's "needs attention" section. Derived each frame from the
/// per-node `NodeStats` (which carry per-ledger health as of the last
/// 30s push) plus heartbeat ages — never persisted.
struct Concern {
    severity: Severity,
    /// Short operator-facing concern label, e.g. "quorum expiry".
    kind: &'static str,
    /// Node label this concern belongs to.
    node: String,
    /// Ledger tag (truncated) or empty when node-scoped (e.g. offline).
    scope: String,
    /// Human detail, e.g. "EXPIRED 2d ago" / "refresh in 920 blk (~6d)".
    detail: String,
    /// Blocks until the deadline; `Some(<0)` is overdue, `None` is not a
    /// block-clock concern (reserves ratio, offline). Drives the sort so
    /// the soonest deadline floats to the top.
    blocks_left: Option<i64>,
}

// Block-clock thresholds (blocks). ~144 blocks ≈ 1 day.
const EXPIRY_CRIT_BLOCKS: i64 = 144;
const EXPIRY_WARN_BLOCKS: i64 = 1008;
// Heartbeat staleness (seconds). Status/heartbeat cadence is ~30s.
const HB_WARN_SECS: u64 = 120;
const HB_CRIT_SECS: u64 = 300;

impl App {
    pub fn new(data_dir: PathBuf, state: Arc<Mutex<HubState>>, transport: HubTransport) -> Self {
        Self::new_with_relays(data_dir, state, transport, Vec::new())
    }

    /// Same as [`new`], plus the relay URLs the hub was launched with.
    /// The wizard's signer-spawn flow needs these so the spawned signer
    /// knows where to talk to the hub.
    pub fn new_with_relays(
        data_dir: PathBuf,
        state: Arc<Mutex<HubState>>,
        transport: HubTransport,
        hub_relays: Vec<String>,
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
            transport: Some(transport),
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
            spawned_signers: Vec::new(),
            hub_relays,
            dashboard_cursor: 0,
            details_node: None,
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
                (KeyCode::Esc, _) | (KeyCode::Char('a'), _) | (KeyCode::Char('q'), _) => {
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

        // Node-details pane swallows its own keys: Esc/Left/h/b returns
        // to the inventory; j/k drill into the prev/next node's details
        // so the operator can scan the fleet without backing out.
        if self.details_node.is_some() {
            match (k.code, k.modifiers) {
                (KeyCode::Char('q'), _) => return true,
                (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => return true,
                (KeyCode::Esc, _)
                | (KeyCode::Left, _)
                | (KeyCode::Char('h'), _)
                | (KeyCode::Char('b'), _) => {
                    self.details_node = None;
                }
                (KeyCode::Down, _) | (KeyCode::Char('j'), _) => self.details_step(1).await,
                (KeyCode::Up, _) | (KeyCode::Char('k'), _) => self.details_step(-1).await,
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
            (KeyCode::Down, _) | (KeyCode::Char('j'), _) if self.tab == Tab::Dashboard => {
                self.dashboard_step(1).await;
            }
            (KeyCode::Up, _) | (KeyCode::Char('k'), _) if self.tab == Tab::Dashboard => {
                self.dashboard_step(-1).await;
            }
            (KeyCode::Enter, _) if self.tab == Tab::Dashboard => {
                self.open_details().await;
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
            (KeyCode::Char('s'), _)
                if self.tab == Tab::Setup && self.wizard.stage == WizardStage::SpawnSigner =>
            {
                self.spawn_signer_in_process().await;
                return false;
            }
            (KeyCode::Char('o'), _)
                if self.tab == Tab::Setup && self.wizard.stage == WizardStage::OpenLedger =>
            {
                self.admin_ledger_open().await;
                return false;
            }
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
                if self.tab == Tab::Setup && self.wizard.stage == WizardStage::PickPeers =>
            {
                let n = self.discovered_peers.as_ref().map(|p| p.len()).unwrap_or(0);
                if n > 0 {
                    self.peer_cursor = (self.peer_cursor + 1).min(n - 1);
                }
                return false;
            }
            (KeyCode::Up, _) | (KeyCode::Char('k'), _)
                if self.tab == Tab::Setup && self.wizard.stage == WizardStage::PickPeers =>
            {
                self.peer_cursor = self.peer_cursor.saturating_sub(1);
                return false;
            }
            (KeyCode::Char(' '), _)
                if self.tab == Tab::Setup && self.wizard.stage == WizardStage::PickPeers =>
            {
                if let Some(peers) = self.discovered_peers.as_ref() {
                    if let Some(peer) = peers.get(self.peer_cursor) {
                        let pk = peer.operator_pubkey.clone();
                        if let Some(pos) = self
                            .wizard
                            .selected_peer_pubkeys
                            .iter()
                            .position(|p| *p == pk)
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
        Some((rec.label.clone(), stats, (*pk).clone()))
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
        if let Some(t) = &self.transport {
            crate::control::send_accept_ack(t, &sender_pk, &label).await;
            crate::control::publish_backup(t, &snapshot, &self.data_dir).await;
        }
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
        if let Some(t) = &self.transport {
            crate::control::send_reject_ack(t, &sender_pk).await;
            crate::control::publish_backup(t, &snapshot, &self.data_dir).await;
        }
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
                if let Some(t) = &self.transport {
                    if already {
                        crate::control::send_already_approved_ack(t, &from).await;
                    } else {
                        crate::control::send_waiting_ack(t, &from).await;
                    }
                    crate::control::publish_backup(t, &snapshot, &self.data_dir).await;
                }
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

    /// Auto-spawn the wizard's signer in-process via the existing
    /// `Spawner`. Same flow `deposits-hub spawn` uses from the CLI,
    /// just reachable from the wizard's [s] keybinding so the operator
    /// doesn't need a second terminal.
    ///
    /// The hub seed derives a stable per-name signer index, so re-
    /// spawning the same name re-uses its identity (idempotent).
    /// The child is held in `self.spawned_signers` with `kill_on_drop`,
    /// so closing the TUI cleans up the process.
    async fn spawn_signer_in_process(&mut self) {
        let name = self.wizard.signer_name.clone();
        if self.spawned_signers.iter().any(|h| h.name == name) {
            self.flash(format!("signer '{}' already spawned", name));
            return;
        }
        if self.hub_relays.is_empty() {
            self.flash("can't spawn — hub launched without --relay; restart with one".into());
            return;
        }
        // Look up the hub pubkey for the Spawner config.
        let hub_pubkey_hex = {
            let st = self.state.lock().await;
            st.hub_pubkey.clone()
        };
        let spawner = crate::spawn::Spawner::new(hub_pubkey_hex, self.hub_relays.clone());
        // Stable per-name seed derivation so re-spawn keeps identity.
        // `signer_index_for` persists the new index allocation itself.
        // Hold the lock just long enough to allocate the index, then
        // drop it before any error-path `self.flash(...)` (which would
        // re-borrow self).
        let idx_result = {
            let mut st = self.state.lock().await;
            st.signer_index_for(&name, &self.data_dir)
        };
        let idx = match idx_result {
            Ok(i) => i,
            Err(e) => {
                self.flash(format!("allocate signer index: {}", e));
                return;
            }
        };
        let master = match crate::state::HubState::load_or_init_master_seed(&self.data_dir) {
            Ok(m) => m,
            Err(e) => {
                self.flash(format!("load master seed: {}", e));
                return;
            }
        };
        let seed_opt = match crate::state::derive_signer_seed(&master, idx) {
            Ok(seed) => Some(seed),
            Err(e) => {
                self.flash(format!("derive seed: {}", e));
                return;
            }
        };
        if let Err(e) = spawner
            .ensure_initialized_with_seed(&self.data_dir, &name, seed_opt)
            .await
        {
            self.flash(format!("init signer workspace: {}", e));
            return;
        }
        match spawner.spawn(&self.data_dir, &name).await {
            Ok(handle) => {
                let pk = handle.transport_pubkey_hex.clone();
                self.spawned_signers.push(handle);
                self.flash(format!(
                    "spawned signer '{}' (transport pk {}…)",
                    name,
                    &pk[..16.min(pk.len())]
                ));
            }
            Err(e) => self.flash(format!("spawn failed: {}", e)),
        }
    }

    /// Call the daemon's `ledger_open` admin RPC. Proof-of-concept
    /// for hub → daemon admin actions over Nostr; the same pattern
    /// will drive every other wizard stage once it's plumbed.
    async fn admin_ledger_open(&mut self) {
        let Some((daemon_pk, _label)) = self.first_registered_daemon() else {
            self.flash("no daemon registered yet".into());
            return;
        };
        if self.hub_relays.is_empty() {
            self.flash("hub has no relays — restart with --relay".into());
            return;
        }
        // Hub secret lives next to hub.json at <data_dir>/hub-nostr-secret.
        let secret_path = self.data_dir.join("hub-nostr-secret");
        let secret_hex = match std::fs::read_to_string(&secret_path) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                self.flash(format!("read hub secret: {}", e));
                return;
            }
        };
        self.flash("calling ledger_open on daemon…".into());
        let result = crate::admin_client::send_admin_request(
            &secret_hex,
            &self.hub_relays,
            &daemon_pk,
            &daemon_pk, // non-ledger-scoped — recipient pk is the #l sentinel
            "ledger_open",
            serde_json::json!({}),
            crate::admin_client::DEFAULT_TIMEOUT_MS,
        )
        .await;
        match result {
            Ok(v) => {
                let lid = v
                    .get("ledger_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or("<no ledger_id in result>");
                self.flash(format!("✓ ledger opened: {}…", &lid[..16.min(lid.len())]));
            }
            Err(e) => {
                self.flash(format!("ledger_open failed: {}", e));
            }
        }
    }

    /// Re-run peer discovery against the configured network. Synchronous
    /// from the key-handler caller's perspective — we await the fetch.
    /// 10s timeout inside `discover_peers` keeps the worst case bounded.
    async fn refresh_discovered_peers(&mut self) {
        let Some(t) = &self.transport else {
            self.flash("no transport — discovery unavailable".into());
            return;
        };
        self.discovering = true;
        match crate::peers::discover_peers(t, &self.wizard_network).await {
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
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" deposits-hub "),
            )
            .select(selected)
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
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
                Tab::Dashboard => match &self.details_node {
                    Some(pk) => self.render_node_details(st, pk, chunks[1], f),
                    None => self.render_dashboard(st, chunks[1], f),
                },
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
        } else if self.details_node.is_some() {
            "[j/k] node  [Esc] back  [q] quit"
        } else {
            match self.tab {
                Tab::Dashboard => {
                    "[j/k] select  [Enter] details  [a] address  [1/2/3] tabs  [q] quit"
                }
                Tab::Pending => "[a] approve  [x] reject  [j/k] move  [Tab] switch  [q] quit",
                Tab::Setup => match self.wizard.stage {
                    WizardStage::PickPeers => {
                        "[j/k] move  [space] toggle  [r] refresh  [n] next  [Tab] switch  [q] quit"
                    }
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
                    let pad_str: String = std::iter::repeat_n(' ', pad as usize).collect();
                    for l in &qr_lines {
                        lines.push(Line::from(format!("{}{}", pad_str, l)));
                    }
                    lines.push(Line::from(""));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    addr.to_string(),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
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

        let mut lines: Vec<Line> = vec![Line::from("")];
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
                for (chunk_idx, chunk) in words.chunks(4).enumerate() {
                    let chunk_start = chunk_idx * 4;
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
                vec![Span::styled(label.to_string(), style), Span::raw("  ")]
            })
            .collect();
        let crumbs = Paragraph::new(Line::from(breadcrumb)).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1))
                .title(" bootstrap "),
        );
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
                    let selected = self
                        .wizard
                        .selected_peer_pubkeys
                        .contains(&p.operator_pubkey);
                    let marker = if selected { "[x]" } else { "[ ]" };
                    let cursor = if i == self.peer_cursor { ">" } else { " " };
                    // Self-chosen ad names can collide or impersonate;
                    // the pubkey-derived handle can't. Show the derived
                    // name first, ad name as flavor.
                    let derived = deposits_protocol::display_name::pubkey_display_name_hex(
                        &p.operator_pubkey,
                    );
                    let name = match &p.operator_name {
                        Some(n) => format!("{} ({})", derived, n),
                        None => derived,
                    };
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
        let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1))
                .title(" peers "),
        );
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
        let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1))
                .title(" drip "),
        );
        f.render_widget(p, area);
    }

    fn render_stage_spawn_signer(&self, area: Rect, f: &mut ratatui::Frame) {
        // Usable text width inside the panel = area − borders(2) − padding(2).
        let cw = area.width.saturating_sub(4);
        let mut lines = vec![
            Line::from(Span::styled(
                "spawn the signer subprocess",
                Style::default().fg(Color::White),
            )),
            Line::from(""),
        ];

        // Option A: in-process spawn (local).
        lines.push(Line::from(Span::styled(
            format!(
                "[s] spawn '{}' locally — hub forks the signer as a child process",
                self.wizard.signer_name
            ),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )));
        if let Some(h) = self
            .spawned_signers
            .iter()
            .find(|h| h.name == self.wizard.signer_name)
        {
            lines.push(Line::from(Span::styled(
                format!(
                    "    ✓ running — transport pk {}…  logs at {}",
                    &h.transport_pubkey_hex[..16.min(h.transport_pubkey_hex.len())],
                    h.workspace.root.display()
                ),
                Style::default().fg(Color::Green),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "    (not yet spawned)",
                Style::default().fg(Color::DarkGray),
            )));
        }
        lines.push(Line::from(""));

        // Option B: copy docker invocation (remote host).
        lines.push(Line::from(Span::styled(
            "OR run the signer on a different host:",
            Style::default().fg(Color::White),
        )));
        let relay_for_display = self
            .hub_relays
            .first()
            .map(String::as_str)
            .unwrap_or("<hub-relay-url>");
        lines.extend(command_lines(
            &format!(
                "deposits-hub spawn-line --name {} --relay {} --docker",
                self.wizard.signer_name, relay_for_display
            ),
            cw,
            Style::default().fg(Color::Yellow),
        ));
        lines.push(Line::from(Span::styled(
            "  (run on the signer host; emits a `docker run` invocation)",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(""));

        lines.push(Line::from(
            "When the signer registers, it appears under the Dashboard tab (and Pending if not auto-approved).",
        ));
        lines.push(Line::from(""));

        // ── admin.npub setup — the operator must authorize the hub
        //    on the daemon side before any wizard stage can drive
        //    admin RPCs. We display the hub pubkey here so the
        //    operator can copy it into <daemon-data-dir>/admin.npub.
        lines.push(Line::from(Span::styled(
            "── one-time daemon trust setup ──",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        let hub_pk = self
            .state
            .try_lock()
            .ok()
            .map(|s| s.hub_pubkey.clone())
            .unwrap_or_default();
        lines.push(Line::from(
            "On the daemon host, drop the hub's pubkey into admin.npub:",
        ));
        lines.extend(command_lines(
            &format!("echo {} > <data-dir>/admin.npub", hub_pk),
            cw,
            Style::default().fg(Color::Yellow),
        ));
        lines.push(Line::from(Span::styled(
            "  # then restart the daemon so it picks up the trust",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(
            "Once set, the hub can drive ledger_open / quorum_add / quorum_begin / etc. directly.",
        ));
        lines.push(Line::from(""));

        lines.push(Line::from(Span::styled(
            "[s] spawn locally   [n] continue once registered   [p] back",
            Style::default().fg(Color::DarkGray),
        )));

        let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1))
                .title(" signer "),
        );
        f.render_widget(p, area);
    }

    fn render_stage_open_ledger(&self, area: Rect, f: &mut ratatui::Frame) {
        let registered_daemon = self.first_registered_daemon();
        let mut lines = vec![
            Line::from(Span::styled(
                "open the operator's first ledger",
                Style::default().fg(Color::White),
            )),
            Line::from(""),
        ];
        match registered_daemon {
            Some((pk, label)) => {
                lines.push(Line::from(Span::styled(
                    format!("daemon: {} ({}…)", label, &pk[..16.min(pk.len())]),
                    Style::default().fg(Color::Green),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "[o] call ledger_open on the daemon (hub admin RPC)",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(Span::styled(
                    "    Requires the daemon to trust this hub's pubkey via admin.npub —",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(Span::styled(
                    "    see the signer stage for the one-time setup.",
                    Style::default().fg(Color::DarkGray),
                )));
            }
            None => {
                lines.push(Line::from(Span::styled(
                    "no daemon registered yet — go back to the signer stage",
                    Style::default().fg(Color::Red),
                )));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Alternative: run on the daemon host:",
            Style::default().fg(Color::White),
        )));
        lines.push(Line::from(Span::styled(
            "  deposits-node ledger open",
            Style::default().fg(Color::Yellow),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "[o] open via admin RPC   [n] continue   [p] back",
            Style::default().fg(Color::DarkGray),
        )));
        let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1))
                .title(" ledger "),
        );
        f.render_widget(p, area);
    }

    /// First node registered with the hub, returned as `(operator_pk, label)`.
    /// Used by wizard stages that need a daemon to drive admin RPCs against.
    fn first_registered_daemon(&self) -> Option<(String, String)> {
        let st = self.state.try_lock().ok()?;
        let (pk, rec) = st.nodes.iter().next()?;
        Some((pk.clone(), rec.label.clone()))
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
        let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1))
                .title(" fund "),
        );
        f.render_widget(p, area);
    }

    fn render_stage_activate_quorum(&self, area: Rect, f: &mut ratatui::Frame) {
        let cw = area.width.saturating_sub(4);
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
            lines.extend(command_lines(
                &format!(
                    "deposits-node quorum add <ledger> {} <their_ledger>",
                    &pk[..16.min(pk.len())]
                ),
                cw,
                Style::default().fg(Color::Yellow),
            ));
        }
        lines.push(Line::from(""));
        lines.extend(command_lines(
            "deposits-node quorum begin <ledger> --amount-sats <N> --collateral-ratio 0.6 --protocol-version cltv-offset-v2",
            cw,
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "[n] mark done   [p] back",
            Style::default().fg(Color::DarkGray),
        )));
        let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1))
                .title(" quorum "),
        );
        f.render_widget(p, area);
    }

    fn render_stage_done(&self, area: Rect, f: &mut ratatui::Frame) {
        let cw = area.width.saturating_sub(4);
        let mut lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "✓ bootstrap complete",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Your hub is paired with a signer, your daemon owns at least one ledger,"),
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
        ];
        lines.extend(command_lines(
            &format!(
                "deposits-node liquidity drip-create <alias> <ledger> --initial-sats <N> --decrement-sats {} --interval-sec {} --interval-fuzz-sec {}",
                self.wizard.drip_decrement_sats,
                self.wizard.drip_interval_sec,
                self.wizard.drip_fuzz_sec,
            ),
            cw,
            Style::default().fg(Color::Yellow),
        ));
        let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1))
                .title(" done "),
        );
        f.render_widget(p, area);
    }

    /// Node pubkeys in the same label-sorted order the Dashboard renders,
    /// so `dashboard_cursor` indexes consistently.
    async fn sorted_node_pks(&self) -> Vec<String> {
        let st = self.state.lock().await;
        let mut v: Vec<_> = st.nodes.iter().collect();
        v.sort_by(|a, b| a.1.label.cmp(&b.1.label));
        v.into_iter().map(|(k, _)| k.clone()).collect()
    }

    /// Move the Dashboard node cursor, wrapping. No-op with no nodes.
    async fn dashboard_step(&mut self, delta: i32) {
        let n = self.state.lock().await.nodes.len();
        if n == 0 {
            self.dashboard_cursor = 0;
            return;
        }
        let cur = self.dashboard_cursor.min(n - 1) as i32;
        self.dashboard_cursor = (cur + delta).rem_euclid(n as i32) as usize;
    }

    /// Drill into the node at the cursor.
    async fn open_details(&mut self) {
        let pks = self.sorted_node_pks().await;
        match pks.get(self.dashboard_cursor) {
            Some(pk) => self.details_node = Some(pk.clone()),
            None => self.flash("no node to show details for".to_string()),
        }
    }

    /// While in the details pane, step to the prev/next node's details.
    async fn details_step(&mut self, delta: i32) {
        self.dashboard_step(delta).await;
        let pks = self.sorted_node_pks().await;
        self.details_node = pks.get(self.dashboard_cursor).cloned();
    }

    /// Derive the standing concerns across the fleet from the latest
    /// per-node status push + heartbeat ages. Sorted worst-severity
    /// first, then soonest block deadline, so the top row is always the
    /// most urgent thing. Pure read — never mutates or persists.
    fn collect_concerns(&self, st: &HubState, now: u64) -> Vec<Concern> {
        let mut out: Vec<Concern> = Vec::new();
        for (pk, stats) in &self.node_stats {
            let node = st
                .nodes
                .get(pk)
                .map(|r| r.label.clone())
                .unwrap_or_else(|| short_pk(pk));
            // Lightning backend unreachable — node can't mint/pay invoices.
            if let Some(err) = &stats.ln_error {
                out.push(Concern {
                    severity: Severity::Critical,
                    kind: "lightning offline",
                    node: node.clone(),
                    scope: String::new(),
                    detail: err.lines().next().unwrap_or("unreachable").to_string(),
                    blocks_left: None,
                });
            }
            for lh in &stats.ledgers {
                let scope = short_tag(&lh.ledger_id);
                // Quorum expiry / post-expiry cascade.
                if let Some(b) = lh.blocks_to_expiry {
                    if !lh.value_moving_allowed || b < 0 {
                        out.push(Concern {
                            severity: Severity::Critical,
                            kind: "quorum expiry",
                            node: node.clone(),
                            scope: scope.clone(),
                            detail: format!(
                                "EXPIRED {} ago — tier {} cascade",
                                blocks_eta(-b),
                                lh.tier
                            ),
                            blocks_left: Some(b),
                        });
                    } else {
                        let sev = if b <= EXPIRY_CRIT_BLOCKS {
                            Some(Severity::Critical)
                        } else if b <= EXPIRY_WARN_BLOCKS {
                            Some(Severity::Warn)
                        } else {
                            None
                        };
                        if let Some(severity) = sev {
                            out.push(Concern {
                                severity,
                                kind: "quorum expiry",
                                node: node.clone(),
                                scope: scope.clone(),
                                detail: format!("refresh in {}", blocks_eta(b)),
                                blocks_left: Some(b),
                            });
                        }
                    }
                }
                // Reserves vs. obligations (solvency).
                if lh.obligations_sats > 0 {
                    if lh.obligations_sats >= lh.reserves_sats {
                        out.push(Concern {
                            severity: Severity::Critical,
                            kind: "reserves",
                            node: node.clone(),
                            scope: scope.clone(),
                            detail: format!(
                                "obligations {} ≥ reserves {}",
                                sats_human(lh.obligations_sats),
                                sats_human(lh.reserves_sats)
                            ),
                            blocks_left: None,
                        });
                    } else if lh.obligations_sats.saturating_mul(10)
                        >= lh.reserves_sats.saturating_mul(9)
                    {
                        let pct =
                            (lh.obligations_sats as f64 / lh.reserves_sats as f64 * 100.0) as u64;
                        out.push(Concern {
                            severity: Severity::Warn,
                            kind: "reserves",
                            node: node.clone(),
                            scope: scope.clone(),
                            detail: format!("obligations {}% of reserves", pct),
                            blocks_left: None,
                        });
                    }
                }
                // Open dispute against this ledger.
                if lh.open_disputes > 0 {
                    out.push(Concern {
                        severity: Severity::Critical,
                        kind: "dispute",
                        node: node.clone(),
                        scope: scope.clone(),
                        detail: format!("{} open — respond", lh.open_disputes),
                        blocks_left: lh.blocks_to_dispute_deadline,
                    });
                }
            }
        }
        // Heartbeat staleness for everyone we've heard from at least once.
        for (pk, rec) in st.signers.iter() {
            if let Some(c) = self.heartbeat_concern(pk, &rec.label, now) {
                out.push(c);
            }
        }
        for (pk, rec) in st.nodes.iter() {
            if let Some(c) = self.heartbeat_concern(pk, &rec.label, now) {
                out.push(c);
            }
        }
        out.sort_by(|a, b| {
            a.severity.cmp(&b.severity).then(
                a.blocks_left
                    .unwrap_or(i64::MAX)
                    .cmp(&b.blocks_left.unwrap_or(i64::MAX)),
            )
        });
        out
    }

    fn heartbeat_concern(&self, pk: &str, label: &str, now: u64) -> Option<Concern> {
        let last = self.last_heartbeat.get(pk)?;
        let age = now.saturating_sub(*last);
        let severity = if age > HB_CRIT_SECS {
            Severity::Critical
        } else if age > HB_WARN_SECS {
            Severity::Warn
        } else {
            return None;
        };
        Some(Concern {
            severity,
            kind: "offline",
            node: label.to_string(),
            scope: String::new(),
            detail: format!("no heartbeat for {}", secs_human(age)),
            blocks_left: None,
        })
    }

    /// The "needs attention" panel above the inventory: concerns sorted
    /// worst-first, or a single "all clear" line when the fleet is quiet.
    fn render_attention(&self, concerns: &[Concern], area: Rect, f: &mut ratatui::Frame) {
        const MAX_SHOWN: usize = 8;
        f.render_widget(Clear, area);
        let mut lines: Vec<Line> = Vec::new();
        if concerns.is_empty() {
            lines.push(Line::from(Span::styled(
                "✓ all clear",
                Style::default().fg(Color::Green),
            )));
        } else {
            for c in concerns.iter().take(MAX_SHOWN) {
                let (glyph, color) = match c.severity {
                    Severity::Critical => ("✗", Color::Red),
                    Severity::Warn => ("!", Color::Yellow),
                };
                let scope = if c.scope.is_empty() {
                    String::new()
                } else {
                    format!(" · {}", c.scope)
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{} ", glyph), Style::default().fg(color)),
                    Span::styled(format!("{:<13} ", c.kind), Style::default().fg(color)),
                    Span::styled(
                        format!("{}{}", c.node, scope),
                        Style::default().fg(Color::White),
                    ),
                    Span::raw("  "),
                    Span::styled(c.detail.clone(), Style::default().fg(Color::Gray)),
                ]));
            }
            if concerns.len() > MAX_SHOWN {
                lines.push(Line::from(Span::styled(
                    format!("…and {} more", concerns.len() - MAX_SHOWN),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
        let title = if concerns.is_empty() {
            " needs attention ".to_string()
        } else {
            format!(" needs attention ({}) ", concerns.len())
        };
        let p = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1))
                .title(title),
        );
        f.render_widget(p, area);
    }

    fn render_dashboard(&self, st: &HubState, area: Rect, f: &mut ratatui::Frame) {
        let now = unix_secs();

        // Split the body: "needs attention" on top (sized to its rows,
        // capped so the inventory always stays visible), inventory below.
        let concerns = self.collect_concerns(st, now);
        let shown = concerns.len().min(8);
        let overflow = usize::from(concerns.len() > 8);
        let att_rows = if concerns.is_empty() {
            1
        } else {
            shown + overflow
        } as u16;
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(att_rows + 2), Constraint::Min(0)])
            .split(area);
        self.render_attention(&concerns, chunks[0], f);
        let body = chunks[1];

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
                    "  {:<24} {:<28} {}  v{}  {}",
                    rec.label,
                    deposits_protocol::display_name::pubkey_display_name_hex(pk),
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
            let cursor = self.dashboard_cursor.min(entries.len().saturating_sub(1));
            for (i, (pk, rec)) in entries.into_iter().enumerate() {
                let marker = if i == cursor { "> " } else { "  " };
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
                            "wallet={:.4} BTC  ledgers={}{}  quorums={}  tip={}",
                            (s.wallet_balance_sats as f64) / 100_000_000.0,
                            s.ledger_count,
                            active_note,
                            s.quorum_member_count,
                            s.chain_tip
                        )
                    })
                    .unwrap_or_else(|| "(awaiting status)".to_string());
                lines.push(Line::from(format!(
                    "{}{:<10} {}  v{}  signer={}  {}",
                    marker,
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
        f.render_widget(Clear, body);
        let p = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1))
                .title(" inventory "),
        );
        f.render_widget(p, body);
    }

    /// Drill-in pane for one node: identity + wallet, each own ledger
    /// (length, deposits, liabilities, reserves, quorum + members), and a
    /// "serving on" section for the partner quorums it co-signs. All
    /// read-only, from the latest status push.
    fn render_node_details(&self, st: &HubState, pk: &str, area: Rect, f: &mut ratatui::Frame) {
        let muted = Style::default().fg(Color::DarkGray);
        let head = Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD);
        let accent = Style::default().fg(Color::Cyan);
        let label = st
            .nodes
            .get(pk)
            .map(|r| r.label.clone())
            .unwrap_or_else(|| short_pk(pk));
        let stats = self.node_stats.get(pk);

        // Compact "expires in / EXPIRED" rendering shared by both sections.
        let expiry_str = |bte: Option<i64>, exp: Option<u32>| -> String {
            match (bte, exp) {
                (Some(b), Some(e)) if b < 0 => format!("EXPIRED {} ago (@{})", blocks_eta(-b), e),
                (Some(b), Some(e)) => format!("expires in {} (@{})", blocks_eta(b), e),
                _ => "pre-quorum".to_string(),
            }
        };
        let members_line = |members: &[crate::proto::QuorumMemberInfo]| -> String {
            if members.is_empty() {
                "—".to_string()
            } else {
                members
                    .iter()
                    .map(|m| short_pk(&m.pubkey))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        };

        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(vec![
            Span::styled(format!("{}  ", label), head),
            Span::styled(short_pk(pk), muted),
        ]));
        match stats {
            None => {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "(awaiting status from this node)",
                    muted,
                )));
            }
            Some(s) => {
                lines.push(Line::from(Span::styled(
                    format!(
                        "wallet {}   tip {}   own {}   serving {}",
                        sats_human(s.wallet_balance_sats),
                        s.chain_tip,
                        s.ledgers.len(),
                        s.serving.len()
                    ),
                    accent,
                )));
                // Lightning backend health.
                match &s.ln_error {
                    None => lines.push(Line::from(Span::styled("lightning: OK", muted))),
                    Some(err) => lines.push(Line::from(Span::styled(
                        format!(
                            "lightning: OFFLINE — {}",
                            err.lines().next().unwrap_or("unreachable")
                        ),
                        Style::default().fg(Color::Red),
                    ))),
                }
                lines.push(Line::from(""));

                // ── own ledgers ──
                lines.push(Line::from(Span::styled(
                    format!("own ledgers ({})", s.ledgers.len()),
                    head,
                )));
                if s.ledgers.is_empty() {
                    lines.push(Line::from(Span::styled("  (none)", muted)));
                }
                for lh in &s.ledgers {
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {} ", short_tag(&lh.ledger_id)), accent),
                        Span::styled(
                            format!(
                                "tier {}{}",
                                lh.tier,
                                if lh.value_moving_allowed { "" } else { " ⚠" }
                            ),
                            if lh.value_moving_allowed {
                                muted
                            } else {
                                Style::default().fg(Color::Yellow)
                            },
                        ),
                    ]));
                    lines.push(Line::from(Span::styled(
                        format!(
                            "      len {}  ·  {} deposits  ·  liab {}  ·  reserves {}",
                            lh.sequence,
                            lh.deposit_count,
                            sats_human(lh.obligations_sats),
                            sats_human(lh.reserves_sats),
                        ),
                        Style::default().fg(Color::Gray),
                    )));
                    lines.push(Line::from(Span::styled(
                        format!(
                            "      quorum Q={}  ·  {}",
                            lh.members.len(),
                            expiry_str(lh.blocks_to_expiry, lh.quorum_expiry)
                        ),
                        Style::default().fg(Color::Gray),
                    )));
                    // Begin entry + duration, when the QuorumBegin location
                    // is known (stamped on commit/replay).
                    if let Some(begin) = lh.quorum_begin_block {
                        let dur = lh
                            .quorum_expiry
                            .map(|e| {
                                format!("  ·  duration {}", blocks_eta(e as i64 - begin as i64))
                            })
                            .unwrap_or_default();
                        let seq = lh
                            .quorum_begin_sequence
                            .map(|s| format!("seq {}", s))
                            .unwrap_or_else(|| "seq ?".to_string());
                        let entry = lh
                            .quorum_begin_hash
                            .as_deref()
                            .map(short_tag)
                            .unwrap_or_default();
                        lines.push(Line::from(Span::styled(
                            format!("      began @{}  ·  {}  {}{}", begin, seq, entry, dur),
                            muted,
                        )));
                    }
                    lines.push(Line::from(Span::styled(
                        format!("      members: {}", members_line(&lh.members)),
                        muted,
                    )));
                }
                lines.push(Line::from(""));

                // ── serving on (partner quorums) ──
                lines.push(Line::from(Span::styled(
                    format!("serving on ({})", s.serving.len()),
                    head,
                )));
                if s.serving.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "  (not a quorum member of any other operator's ledger)",
                        muted,
                    )));
                }
                for sv in &s.serving {
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {} ", short_tag(&sv.ledger_id)), accent),
                        Span::styled(format!("op {}  ", short_pk(&sv.operator)), muted),
                        Span::styled(
                            format!("tier {}", sv.tier),
                            Style::default().fg(Color::Gray),
                        ),
                    ]));
                    lines.push(Line::from(Span::styled(
                        format!(
                            "      {} deposits  ·  liab {}  ·  reserves {}  ·  {}",
                            sv.deposit_count,
                            sats_human(sv.obligations_sats),
                            sats_human(sv.reserves_sats),
                            expiry_str(sv.blocks_to_expiry, sv.quorum_expiry),
                        ),
                        Style::default().fg(Color::Gray),
                    )));
                    lines.push(Line::from(Span::styled(
                        format!("      members: {}", members_line(&sv.members)),
                        muted,
                    )));
                }
            }
        }

        f.render_widget(Clear, area);
        let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::horizontal(1))
                .title(format!(" node details · {} ", label)),
        );
        f.render_widget(p, area);
    }

    fn render_pending(&mut self, st: &HubState, area: Rect, f: &mut ratatui::Frame) {
        let mut entries: Vec<_> = st.pending.iter().collect();
        entries.sort_by_key(|(_, v)| v.first_seen);

        if entries.is_empty() {
            f.render_widget(Clear, area);
            let p = Paragraph::new(
                "(no pending registrations — peers waiting for approval show up here)",
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .padding(Padding::horizontal(1))
                    .title(" pending "),
            );
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
                let pk_only = pending_key
                    .split_once(':')
                    .map(|x| x.1)
                    .unwrap_or(pending_key.as_str());
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
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .padding(Padding::horizontal(1))
                    .title(" pending "),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
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

/// First 12 chars of a ledger id (matches the explorer's tag width).
fn short_tag(id: &str) -> String {
    if id.len() > 12 {
        format!("{}…", &id[..12])
    } else {
        id.to_string()
    }
}

/// A block delta as "N blk (~X.Yd)". Caller passes a non-negative count
/// (negate the remaining-blocks value for the "ago" case).
fn blocks_eta(blocks: i64) -> String {
    let b = blocks.max(0);
    format!("{} blk (~{:.1}d)", b, b as f64 / 144.0)
}

/// Compact sats: BTC above 0.01, else plain sats.
fn sats_human(sats: u64) -> String {
    if sats >= 1_000_000 {
        format!("{:.4} BTC", sats as f64 / 100_000_000.0)
    } else {
        format!("{} sat", sats)
    }
}

/// Compact elapsed seconds: "Nh" / "Nm" / "Ns".
fn secs_human(s: u64) -> String {
    if s >= 3600 {
        format!("{}h", s / 3600)
    } else if s >= 60 {
        format!("{}m", s / 60)
    } else {
        format!("{}s", s)
    }
}

/// Lay out a shell command across as many lines as it takes to fit
/// `usable_width` columns, breaking at token boundaries and ending every
/// line but the last in a ` \` continuation so the whole thing stays
/// copy-pasteable. The first line is indented two spaces; continuations
/// hang at six. Tokens longer than the width (e.g. a 64-hex pubkey) sit
/// on their own line and are left to the terminal — we never split a
/// token. Returns owned `Line`s so callers can `extend` their buffer.
fn command_lines(cmd: &str, usable_width: u16, style: Style) -> Vec<Line<'static>> {
    const HEAD: &str = "  ";
    const CONT: &str = "      ";
    // Reserve two columns for the trailing ` \`.
    let limit = (usable_width.max(24) as usize).saturating_sub(2);

    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut cur = String::from(HEAD);
    let mut started = false; // a token already sits on the current line
    for tok in cmd.split_whitespace() {
        let added = if started {
            1 + tok.chars().count()
        } else {
            tok.chars().count()
        };
        if started && cur.chars().count() + added > limit {
            cur.push_str(" \\");
            lines.push(Line::from(Span::styled(std::mem::take(&mut cur), style)));
            cur.push_str(CONT);
            cur.push_str(tok);
        } else {
            if started {
                cur.push(' ');
            }
            cur.push_str(tok);
        }
        started = true;
    }
    lines.push(Line::from(Span::styled(cur, style)));
    lines
}

#[cfg(test)]
mod tests {
    //! Offline tests for the TUI's input→state logic and rendering.
    //!
    //! The `App` is built with `transport: None` (see the field doc) so it
    //! can run without a relay connection: navigation/overlay/wizard
    //! branches of `handle_key` never touch the transport, and the action
    //! branches (approve/reject) still mutate + persist local state, just
    //! skipping the network ack/backup. Rendering is exercised against
    //! ratatui's in-memory `TestBackend` — no TTY required.

    use super::*;
    use crate::peers::PeerInfo;
    use crate::proto::{LedgerHealth, QuorumMemberInfo, ServingLedger};
    use crate::state::NodeRecord;
    use ratatui::backend::TestBackend;
    use std::path::Path;

    // ── fixtures ─────────────────────────────────────────────────────

    /// Build an offline App over the given (writable) data dir and state.
    /// Mnemonic already acknowledged → no first-launch overlay in the way.
    fn test_app(dir: &Path, state: HubState) -> App {
        let mut cursor = ListState::default();
        cursor.select(Some(0));
        App {
            data_dir: dir.to_path_buf(),
            state: Arc::new(Mutex::new(state)),
            transport: None,
            last_heartbeat: HashMap::new(),
            node_stats: HashMap::new(),
            address_view_idx: None,
            tab: Tab::Dashboard,
            pending_cursor: cursor,
            flash: None,
            flash_ttl: 0,
            mnemonic_overlay: None,
            wizard: WizardState::default(),
            discovered_peers: None,
            discovering: false,
            peer_cursor: 0,
            wizard_network: "regtest".into(),
            spawned_signers: Vec::new(),
            hub_relays: Vec::new(),
            dashboard_cursor: 0,
            details_node: None,
        }
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }
    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }
    fn code(kc: KeyCode) -> KeyEvent {
        KeyEvent::new(kc, KeyModifiers::NONE)
    }

    fn pk(n: u8) -> String {
        // 32-byte (64-hex) pubkey-shaped string: byte `n` repeated.
        format!("{:02x}", n).repeat(32)
    }

    /// Insert `n` pending signer registrations into `st` via the real
    /// ingest path so the pending-map keying matches production.
    fn seed_pending_signers(st: &mut HubState, dir: &Path, n: u8) {
        for i in 0..n {
            crate::control::ingest_register(
                st,
                dir,
                &pk(i),
                Role::Signer,
                pk(i),
                "1.2.3".into(),
                Some(format!("vault-{}", i)),
                None,
            )
            .expect("ingest_register");
        }
    }

    fn render_to_string(app: &mut App, w: u16, h: u16) -> String {
        let backend = TestBackend::new(w, h);
        let mut term = Terminal::new(backend).expect("terminal");
        term.draw(|f| app.render(f.area(), f)).expect("draw");
        format!("{}", term.backend())
    }

    fn peer(n: u8) -> PeerInfo {
        PeerInfo {
            operator_pubkey: pk(n),
            operator_name: Some(format!("op-{}", n)),
            ledger_count: 1,
            ledger_ids: vec![pk(100 + n)],
            latest_ad_unix: 1_700_000_000,
            annual_fee_bps: Some(50),
        }
    }

    // ── navigation ───────────────────────────────────────────────────

    #[tokio::test]
    async fn tab_key_cycles_dashboard_pending_setup() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), HubState::default());
        assert_eq!(app.tab, Tab::Dashboard);
        assert!(!app.handle_key(code(KeyCode::Tab)).await);
        assert_eq!(app.tab, Tab::Pending);
        app.handle_key(code(KeyCode::Tab)).await;
        assert_eq!(app.tab, Tab::Setup);
        app.handle_key(code(KeyCode::Tab)).await;
        assert_eq!(app.tab, Tab::Dashboard);
    }

    #[tokio::test]
    async fn number_keys_jump_to_tab() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), HubState::default());
        app.handle_key(key('2')).await;
        assert_eq!(app.tab, Tab::Pending);
        app.handle_key(key('3')).await;
        assert_eq!(app.tab, Tab::Setup);
        app.handle_key(key('1')).await;
        assert_eq!(app.tab, Tab::Dashboard);
    }

    #[tokio::test]
    async fn q_and_ctrl_c_request_quit() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), HubState::default());
        assert!(app.handle_key(key('q')).await, "q should quit");
        assert!(app.handle_key(ctrl('c')).await, "ctrl-c should quit");
        // A no-op key must not quit.
        assert!(!app.handle_key(key('z')).await);
    }

    // ── mnemonic overlay gating ──────────────────────────────────────

    #[tokio::test]
    async fn mnemonic_overlay_blocks_input_until_enter() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), HubState::default());
        app.mnemonic_overlay = Some(Ok("word ".repeat(24).trim().to_string()));

        // Tab/number keys are swallowed while the overlay is up.
        app.handle_key(code(KeyCode::Tab)).await;
        assert_eq!(app.tab, Tab::Dashboard, "overlay must block tab nav");
        assert!(app.mnemonic_overlay.is_some());

        // Enter acknowledges, clears the overlay, and persists the ack.
        assert!(!app.handle_key(code(KeyCode::Enter)).await);
        assert!(app.mnemonic_overlay.is_none());
        assert!(
            app.state.lock().await.mnemonic_acknowledged,
            "ack must persist to state"
        );
    }

    #[tokio::test]
    async fn mnemonic_overlay_still_allows_quit() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), HubState::default());
        app.mnemonic_overlay = Some(Ok("seed".into()));
        assert!(app.handle_key(key('q')).await, "q quits through overlay");
    }

    // ── pending cursor + approve ─────────────────────────────────────

    #[tokio::test]
    async fn pending_cursor_steps_and_wraps() {
        let dir = tempfile::tempdir().unwrap();
        let mut st = HubState::default();
        seed_pending_signers(&mut st, dir.path(), 3);
        let mut app = test_app(dir.path(), st);
        app.tab = Tab::Pending;
        app.pending_cursor.select(Some(0));

        app.handle_key(key('j')).await;
        assert_eq!(app.pending_cursor.selected(), Some(1));
        app.handle_key(key('j')).await;
        assert_eq!(app.pending_cursor.selected(), Some(2));
        app.handle_key(key('j')).await; // wrap
        assert_eq!(app.pending_cursor.selected(), Some(0));
        app.handle_key(key('k')).await; // wrap backwards
        assert_eq!(app.pending_cursor.selected(), Some(2));
    }

    #[tokio::test]
    async fn approve_moves_pending_into_signers_offline() {
        let dir = tempfile::tempdir().unwrap();
        let mut st = HubState::default();
        seed_pending_signers(&mut st, dir.path(), 2);
        let mut app = test_app(dir.path(), st);
        app.tab = Tab::Pending;
        app.pending_cursor.select(Some(0));

        // 'a' on the Pending tab approves the selected entry. transport is
        // None, so the network ack/backup is skipped but the inventory
        // mutation + persistence still runs.
        assert!(!app.handle_key(key('a')).await);

        let st = app.state.lock().await;
        assert_eq!(st.pending.len(), 1, "one entry should remain pending");
        assert_eq!(st.signers.len(), 1, "approved entry moved to signers");
        drop(st);
        // Cursor stays in-bounds for the shrunken list.
        let sel = app.pending_cursor.selected().unwrap();
        assert!(sel < 1, "cursor must remain valid after shrink");
    }

    #[tokio::test]
    async fn reject_drops_pending_offline() {
        let dir = tempfile::tempdir().unwrap();
        let mut st = HubState::default();
        seed_pending_signers(&mut st, dir.path(), 2);
        let mut app = test_app(dir.path(), st);
        app.tab = Tab::Pending;
        app.pending_cursor.select(Some(0));

        assert!(!app.handle_key(key('x')).await);
        let st = app.state.lock().await;
        assert_eq!(st.pending.len(), 1, "rejected entry removed from pending");
        assert_eq!(st.signers.len(), 0, "reject must not approve");
    }

    // ── address overlay ──────────────────────────────────────────────

    #[tokio::test]
    async fn address_overlay_opens_cycles_and_closes() {
        let dir = tempfile::tempdir().unwrap();
        let mut st = HubState::default();
        for i in 0..2u8 {
            st.nodes.insert(
                pk(i),
                NodeRecord {
                    label: format!("node-{}", i),
                    spawned_by_hub: false,
                    registered_at: 0,
                    last_version: "1.0".into(),
                    signer_pubkey: None,
                },
            );
        }
        let mut app = test_app(dir.path(), st);
        app.tab = Tab::Dashboard;

        app.handle_key(key('a')).await;
        assert_eq!(app.address_view_idx, Some(0), "'a' opens address overlay");
        app.handle_key(key('j')).await;
        assert_eq!(app.address_view_idx, Some(1));
        app.handle_key(key('j')).await; // wraps over 2 nodes
        assert_eq!(app.address_view_idx, Some(0));
        app.handle_key(code(KeyCode::Esc)).await;
        assert_eq!(app.address_view_idx, None, "Esc closes overlay");
    }

    #[tokio::test]
    async fn address_overlay_noop_without_nodes() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), HubState::default());
        app.tab = Tab::Dashboard;
        app.handle_key(key('a')).await;
        assert_eq!(app.address_view_idx, None, "no nodes → no overlay");
    }

    // ── wizard ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn wizard_next_prev_navigates_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), HubState::default());
        app.tab = Tab::Setup;
        assert_eq!(app.wizard.stage, WizardStage::PickPeers);

        app.handle_key(key('n')).await;
        assert_eq!(app.wizard.stage, WizardStage::TuneDrip);
        app.handle_key(key('n')).await;
        assert_eq!(app.wizard.stage, WizardStage::SpawnSigner);
        app.handle_key(key('p')).await;
        assert_eq!(app.wizard.stage, WizardStage::TuneDrip);

        // Stage transitions are persisted so the wizard resumes on restart.
        let reloaded = WizardState::load(dir.path());
        assert_eq!(reloaded.stage, WizardStage::TuneDrip);
    }

    #[tokio::test]
    async fn pick_peers_space_toggles_selection() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), HubState::default());
        app.tab = Tab::Setup;
        app.wizard.stage = WizardStage::PickPeers;
        app.discovered_peers = Some(vec![peer(1), peer(2)]);
        app.peer_cursor = 0;

        app.handle_key(key(' ')).await;
        assert_eq!(app.wizard.selected_peer_pubkeys, vec![pk(1)]);
        // j moves cursor, space selects the second peer too.
        app.handle_key(key('j')).await;
        app.handle_key(key(' ')).await;
        assert_eq!(app.wizard.selected_peer_pubkeys, vec![pk(1), pk(2)]);
        // Toggling the same peer off removes it.
        app.handle_key(key(' ')).await;
        assert_eq!(app.wizard.selected_peer_pubkeys, vec![pk(1)]);
    }

    // ── rendering (TestBackend, no TTY) ──────────────────────────────

    #[test]
    fn renders_dashboard_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), HubState::default());
        let out = render_to_string(&mut app, 80, 24);
        assert!(out.contains("deposits-hub"), "header chrome present");
        assert!(out.contains("Dashboard"), "tab strip present");
    }

    #[test]
    fn command_lines_wrap_with_backslash_continuations() {
        let cmd = "deposits-node quorum begin <ledger> --amount-sats <N> \
                   --collateral-ratio 0.6 --protocol-version cltv-offset-v2";
        let width = 60u16;
        let lines = command_lines(cmd, width, Style::default());
        let texts: Vec<String> = lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect();
        assert!(texts.len() > 1, "a long command should wrap: {texts:?}");
        for (i, t) in texts.iter().enumerate() {
            assert!(
                t.chars().count() <= width as usize,
                "line over width: {t:?}"
            );
            if i + 1 == texts.len() {
                assert!(!t.ends_with('\\'), "final line must not continue: {t:?}");
            } else {
                assert!(
                    t.ends_with(" \\"),
                    "non-final line must end in ' \\': {t:?}"
                );
            }
        }
        // Stripping the indents + trailing backslashes recovers the exact
        // token sequence — wrapping is purely cosmetic, never lossy.
        let joined: Vec<String> = texts
            .iter()
            .flat_map(|t| {
                t.trim_end_matches('\\')
                    .split_whitespace()
                    .map(String::from)
            })
            .collect();
        let original: Vec<String> = cmd.split_whitespace().map(String::from).collect();
        assert_eq!(joined, original, "tokens must survive wrapping");
    }

    #[test]
    fn command_lines_single_line_when_it_fits() {
        let lines = command_lines("deposits-node ledger open", 80, Style::default());
        assert_eq!(lines.len(), 1, "short command stays on one line");
        let t: String = lines[0].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(!t.ends_with('\\'), "single line has no continuation: {t:?}");
        assert!(
            t.starts_with("  deposits-node"),
            "two-space head indent: {t:?}"
        );
    }

    // ── needs-attention concerns ─────────────────────────────────────

    fn health(
        b_expiry: Option<i64>,
        value_moving: bool,
        reserves: u64,
        obligations: u64,
        disputes: u32,
    ) -> LedgerHealth {
        LedgerHealth {
            ledger_id: "ab".repeat(32),
            tier: if value_moving { 0 } else { 1 },
            quorum_expiry: Some(1000),
            blocks_to_expiry: b_expiry,
            value_moving_allowed: value_moving,
            open_disputes: disputes,
            blocks_to_dispute_deadline: None,
            reserves_sats: reserves,
            obligations_sats: obligations,
            sequence: 412,
            deposit_count: 12,
            members: vec![QuorumMemberInfo {
                pubkey: "11".repeat(33),
                ledger_id: "cc".repeat(8),
            }],
            quorum_begin_block: Some(100),
            quorum_begin_sequence: Some(5),
            quorum_begin_hash: Some("ab".repeat(32)),
        }
    }

    fn node_state(label: &str) -> HubState {
        let mut st = HubState::default();
        st.nodes.insert(
            pk(1),
            NodeRecord {
                label: label.to_string(),
                spawned_by_hub: false,
                registered_at: 0,
                last_version: "1.0".into(),
                signer_pubkey: None,
            },
        );
        st
    }

    /// Run collect_concerns over a single node carrying `healths`.
    fn concerns_for(healths: Vec<LedgerHealth>) -> Vec<Concern> {
        let dir = tempfile::tempdir().unwrap();
        let st = node_state("node-a");
        let mut app = test_app(dir.path(), st.clone());
        app.node_stats.insert(
            pk(1),
            NodeStats {
                ledgers: healths,
                ..Default::default()
            },
        );
        app.collect_concerns(&st, 0)
    }

    #[test]
    fn healthy_fleet_has_no_concerns() {
        let c = concerns_for(vec![health(Some(5000), true, 100, 10, 0)]);
        assert!(
            c.is_empty(),
            "all-healthy should be quiet: {c:?}",
            c = c.iter().map(|x| x.kind).collect::<Vec<_>>()
        );
    }

    #[test]
    fn quorum_expiry_crosses_warn_then_critical_then_expired() {
        assert!(
            concerns_for(vec![health(Some(2000), true, 100, 10, 0)]).is_empty(),
            ">1wk = quiet"
        );
        let warn = concerns_for(vec![health(Some(500), true, 100, 10, 0)]);
        assert_eq!(
            (warn[0].kind, warn[0].severity),
            ("quorum expiry", Severity::Warn)
        );
        let crit = concerns_for(vec![health(Some(100), true, 100, 10, 0)]);
        assert_eq!(
            (crit[0].kind, crit[0].severity),
            ("quorum expiry", Severity::Critical)
        );
        let expired = concerns_for(vec![health(Some(-288), false, 100, 10, 0)]);
        assert_eq!(expired[0].severity, Severity::Critical);
        assert!(
            expired[0].detail.contains("EXPIRED"),
            "{:?}",
            expired[0].detail
        );
    }

    #[test]
    fn reserves_warn_and_critical() {
        // expiry healthy (>1wk) so the only concern is reserves.
        let crit = concerns_for(vec![health(Some(5000), true, 100, 100, 0)]);
        assert_eq!(
            (crit.len(), crit[0].kind, crit[0].severity),
            (1, "reserves", Severity::Critical)
        );
        let warn = concerns_for(vec![health(Some(5000), true, 100, 95, 0)]);
        assert_eq!(
            (warn[0].kind, warn[0].severity),
            ("reserves", Severity::Warn)
        );
    }

    #[test]
    fn concerns_sorted_worst_then_soonest_then_clockless() {
        // One ledger that is both critically near expiry AND insolvent:
        // critical-with-deadline must precede the clockless reserves crit.
        let c = concerns_for(vec![health(Some(100), true, 100, 100, 0)]);
        assert_eq!(
            c[0].kind,
            "quorum expiry",
            "deadline concern first: {c:?}",
            c = c.iter().map(|x| x.kind).collect::<Vec<_>>()
        );
        assert_eq!(c[1].kind, "reserves", "clockless concern after");
        // Across two ledgers, the soonest critical deadline wins.
        let c = concerns_for(vec![
            health(Some(500), true, 1000, 1, 0), // warn, b=500
            health(Some(50), true, 1000, 1, 0),  // critical, b=50
        ]);
        assert_eq!(
            (c[0].severity, c[0].blocks_left),
            (Severity::Critical, Some(50))
        );
    }

    #[test]
    fn stale_heartbeat_becomes_offline_concern() {
        let dir = tempfile::tempdir().unwrap();
        let st = node_state("node-a");
        let mut app = test_app(dir.path(), st.clone());
        app.last_heartbeat.insert(pk(1), 0); // last seen at epoch
        let c = app.collect_concerns(&st, 1000); // now = 1000s → age > crit
        assert!(
            c.iter()
                .any(|x| x.kind == "offline" && x.severity == Severity::Critical),
            "stale node should be flagged offline: {c:?}",
            c = c.iter().map(|x| x.kind).collect::<Vec<_>>()
        );
    }

    #[test]
    fn dashboard_renders_attention_and_all_clear() {
        // Critical concern shows in the attention panel.
        let dir = tempfile::tempdir().unwrap();
        let st = node_state("node-a");
        let mut app = test_app(dir.path(), st);
        app.node_stats.insert(
            pk(1),
            NodeStats {
                ledgers: vec![health(Some(-288), false, 100, 10, 0)],
                ..Default::default()
            },
        );
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("needs attention"), "panel title: {out}");
        assert!(
            out.contains("quorum expiry") && out.contains("EXPIRED"),
            "concern row: {out}"
        );

        // Quiet fleet collapses to all-clear.
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), node_state("node-a"));
        let out = render_to_string(&mut app, 100, 24);
        assert!(
            out.contains("all clear"),
            "quiet fleet shows all-clear: {out}"
        );
    }

    // ── node details pane ─────────────────────────────────────────────

    fn serving_ledger() -> ServingLedger {
        ServingLedger {
            ledger_id: "cd".repeat(32),
            operator: "ef".repeat(33),
            tier: 0,
            quorum_expiry: Some(2000),
            blocks_to_expiry: Some(1500),
            deposit_count: 7,
            obligations_sats: 250_000_000,
            reserves_sats: 100_000_000,
            members: vec![QuorumMemberInfo {
                pubkey: "22".repeat(33),
                ledger_id: "dd".repeat(8),
            }],
        }
    }

    #[tokio::test]
    async fn enter_opens_details_and_esc_returns() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), node_state("node-a"));
        app.tab = Tab::Dashboard;
        assert!(app.details_node.is_none());
        app.handle_key(code(KeyCode::Enter)).await;
        assert_eq!(
            app.details_node.as_deref(),
            Some(pk(1).as_str()),
            "Enter drills in"
        );
        app.handle_key(code(KeyCode::Esc)).await;
        assert!(app.details_node.is_none(), "Esc returns to inventory");
    }

    #[tokio::test]
    async fn dashboard_jk_moves_node_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let mut st = node_state("node-a");
        st.nodes.insert(
            pk(2),
            NodeRecord {
                label: "node-b".into(),
                spawned_by_hub: false,
                registered_at: 0,
                last_version: "1.0".into(),
                signer_pubkey: None,
            },
        );
        let mut app = test_app(dir.path(), st);
        app.tab = Tab::Dashboard;
        assert_eq!(app.dashboard_cursor, 0);
        app.handle_key(key('j')).await;
        assert_eq!(app.dashboard_cursor, 1);
        app.handle_key(key('j')).await; // wraps over 2 nodes
        assert_eq!(app.dashboard_cursor, 0);
    }

    #[test]
    fn details_pane_renders_own_and_serving() {
        let dir = tempfile::tempdir().unwrap();
        let st = node_state("node-a");
        let mut app = test_app(dir.path(), st);
        app.node_stats.insert(
            pk(1),
            NodeStats {
                wallet_balance_sats: 5_000_000,
                ledger_count: 1,
                serving: vec![serving_ledger()],
                ledgers: vec![health(Some(900), true, 100_000_000, 40_000_000, 0)],
                ..Default::default()
            },
        );
        app.details_node = Some(pk(1));
        let out = render_to_string(&mut app, 100, 30);
        assert!(out.contains("node details"), "title: {out}");
        assert!(out.contains("own ledgers (1)"), "own section: {out}");
        assert!(
            out.contains("len 412") && out.contains("12 deposits"),
            "ledger metrics: {out}"
        );
        assert!(out.contains("serving on (1)"), "serving section: {out}");
        assert!(out.contains("members:"), "members listed: {out}");
        assert!(
            out.contains("began @100") && out.contains("duration"),
            "quorum begin + duration: {out}"
        );
    }

    #[test]
    fn lightning_offline_raises_critical_concern() {
        let dir = tempfile::tempdir().unwrap();
        let st = node_state("node-a");
        let mut app = test_app(dir.path(), st.clone());
        app.node_stats.insert(
            pk(1),
            NodeStats {
                ln_error: Some("Container d62a7753 is restarting".into()),
                ..Default::default()
            },
        );
        let c = app.collect_concerns(&st, 0);
        let ln = c.iter().find(|x| x.kind == "lightning offline");
        assert!(
            ln.is_some(),
            "LN offline must be surfaced: {:?}",
            c.iter().map(|x| x.kind).collect::<Vec<_>>()
        );
        assert_eq!(ln.unwrap().severity, Severity::Critical);
        // Healthy LN (ln_error None) raises nothing.
        let mut app2 = test_app(dir.path(), st.clone());
        app2.node_stats.insert(
            pk(1),
            NodeStats {
                ln_error: None,
                ..Default::default()
            },
        );
        assert!(app2
            .collect_concerns(&st, 0)
            .iter()
            .all(|x| x.kind != "lightning offline"));
    }

    #[test]
    fn dashboard_hint_uses_valid_shortcut_copy() {
        // Regression: the status-line hint once read "[1]ashboard
        // [2]ending [3]etup" — the [key]word form only works when the
        // key is the word's leading letter, so numbered tabs rendered as
        // nonsense ("1ashboard"). They must use the [1/2/3] form instead.
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), HubState::default());
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("[1/2/3]"), "tab jump hint present: {out}");
        for bad in ["]ashboard", "]ending", "]etup"] {
            assert!(!out.contains(bad), "leftover [N]word hint {bad:?}: {out}");
        }
    }

    #[test]
    fn renders_pending_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut st = HubState::default();
        seed_pending_signers(&mut st, dir.path(), 1);
        let mut app = test_app(dir.path(), st);
        app.tab = Tab::Pending;
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("vault-0"), "pending label shown: {out}");
        assert!(out.contains("signer"), "pending role shown");
    }

    #[test]
    fn renders_every_wizard_stage_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        let stages = [
            WizardStage::PickPeers,
            WizardStage::TuneDrip,
            WizardStage::SpawnSigner,
            WizardStage::OpenLedger,
            WizardStage::FundLedger,
            WizardStage::ActivateQuorum,
            WizardStage::Done,
        ];
        for stage in stages {
            let mut app = test_app(dir.path(), HubState::default());
            app.tab = Tab::Setup;
            app.wizard.stage = stage;
            let out = render_to_string(&mut app, 80, 30);
            assert!(!out.trim().is_empty(), "stage {:?} rendered empty", stage);
        }
    }

    #[test]
    fn renders_mnemonic_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), HubState::default());
        app.mnemonic_overlay = Some(Ok("alpha bravo charlie".into()));
        let out = render_to_string(&mut app, 80, 24);
        assert!(
            out.contains("written") || out.contains("Enter"),
            "overlay should prompt for acknowledgement: {out}"
        );
    }
}
