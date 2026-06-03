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
use crate::proto::{HubMessage, NextAction, Role};
use crate::state::{HubState, NodeRecord, SignerRecord};
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
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs};
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
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Pending => "Pending",
        }
    }
}

pub struct App {
    data_dir: PathBuf,
    state: Arc<Mutex<HubState>>,
    transport: HubTransport,
    /// pubkey hex → last unix-seconds we heard from this peer. Lives
    /// in memory only — heartbeats restart at each launch.
    last_heartbeat: HashMap<String, u64>,
    tab: Tab,
    pending_cursor: ListState,
    /// Transient status line (e.g., "approved", "rejected", error
    /// messages). Cleared after a few render ticks.
    flash: Option<String>,
    flash_ttl: u8,
}

impl App {
    pub fn new(
        data_dir: PathBuf,
        state: Arc<Mutex<HubState>>,
        transport: HubTransport,
    ) -> Self {
        let mut cursor = ListState::default();
        cursor.select(Some(0));
        Self {
            data_dir,
            state,
            transport,
            last_heartbeat: HashMap::new(),
            tab: Tab::Dashboard,
            pending_cursor: cursor,
            flash: None,
            flash_ttl: 0,
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
                            if self.handle_key(k).await {
                                return Ok(());
                            }
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
        match (k.code, k.modifiers) {
            (KeyCode::Char('q'), _) => return true,
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => return true,
            (KeyCode::Tab, _) | (KeyCode::Char('\t'), _) => {
                self.tab = match self.tab {
                    Tab::Dashboard => Tab::Pending,
                    Tab::Pending => Tab::Dashboard,
                };
            }
            (KeyCode::Char('1'), _) => self.tab = Tab::Dashboard,
            (KeyCode::Char('2'), _) => self.tab = Tab::Pending,
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
            (KeyCode::Char('x'), _) if self.tab == Tab::Pending => {
                if let Err(e) = self.reject_selected().await {
                    self.flash(format!("reject: {}", e));
                }
            }
            _ => {}
        }
        false
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
        let mut st = self.state.lock().await;
        let mut pending_iter: Vec<_> = st
            .pending
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        pending_iter.sort_by_key(|(_, v)| v.first_seen);
        let (sender_pk, entry) = pending_iter
            .get(cur)
            .cloned()
            .ok_or_else(|| format!("no pending entry at index {}", cur))?;
        let now = unix_secs();
        let label = entry
            .suggested_label
            .clone()
            .unwrap_or_else(|| short_pk(&sender_pk));
        match entry.role {
            Role::Signer => {
                st.signers.insert(
                    sender_pk.clone(),
                    SignerRecord {
                        label: label.clone(),
                        spawned_by_hub: false,
                        registered_at: now,
                        last_version: entry.version.clone(),
                    },
                );
            }
            Role::Node => {
                st.nodes.insert(
                    sender_pk.clone(),
                    NodeRecord {
                        label: label.clone(),
                        spawned_by_hub: false,
                        registered_at: now,
                        last_version: entry.version.clone(),
                        signer_pubkey: None,
                    },
                );
            }
        }
        st.pending.remove(&sender_pk);
        st.save(&self.data_dir).map_err(|e| format!("save: {}", e))?;
        drop(st);
        // Best-effort accept ack — the peer's heartbeat retry will get
        // it anyway, but the immediate ack snaps the peer out of
        // "waiting" state on the very next round-trip.
        let ack = HubMessage::RegisterAck {
            accepted: true,
            message: format!("approved as '{}'", label),
            next_action: NextAction::Heartbeat,
        };
        if let Err(e) = self.transport.send(&sender_pk, ack).await {
            tracing::debug!("approve ack send: {}", e);
        }
        self.flash(format!("approved {}", short_pk(&sender_pk)));
        // Keep cursor sane after the list shrinks.
        let new_len = self.state.lock().await.pending.len();
        if new_len == 0 {
            self.pending_cursor.select(None);
        } else if cur >= new_len {
            self.pending_cursor.select(Some(new_len - 1));
        }
        Ok(())
    }

    async fn reject_selected(&mut self) -> Result<(), String> {
        let cur = self.pending_cursor.selected().ok_or("no selection")?;
        let mut st = self.state.lock().await;
        let mut pending_iter: Vec<_> = st
            .pending
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        pending_iter.sort_by_key(|(_, v)| v.first_seen);
        let (sender_pk, _) = pending_iter
            .get(cur)
            .cloned()
            .ok_or_else(|| format!("no pending entry at index {}", cur))?;
        st.pending.remove(&sender_pk);
        st.save(&self.data_dir).map_err(|e| format!("save: {}", e))?;
        drop(st);
        let ack = HubMessage::RegisterAck {
            accepted: false,
            message: "operator rejected this peer".to_string(),
            next_action: NextAction::Shutdown,
        };
        if let Err(e) = self.transport.send(&sender_pk, ack).await {
            tracing::debug!("reject ack send: {}", e);
        }
        self.flash(format!("rejected {}", short_pk(&sender_pk)));
        let new_len = self.state.lock().await.pending.len();
        if new_len == 0 {
            self.pending_cursor.select(None);
        } else if cur >= new_len {
            self.pending_cursor.select(Some(new_len - 1));
        }
        Ok(())
    }

    async fn absorb_inbound(&mut self, inbound: Inbound) {
        let from = inbound.from.to_hex();
        match inbound.msg {
            HubMessage::Register {
                role,
                identity_pubkey,
                version,
                label,
            } => {
                // Same parking logic as the headless main loop; the TUI
                // owns the state lock so we do it here directly instead
                // of round-tripping through main.
                let mut st = self.state.lock().await;
                if st.signers.contains_key(&from) || st.nodes.contains_key(&from) {
                    let ack = HubMessage::RegisterAck {
                        accepted: true,
                        message: "already approved".to_string(),
                        next_action: NextAction::Heartbeat,
                    };
                    drop(st);
                    let _ = self.transport.send(&from, ack).await;
                    return;
                }
                let now = unix_secs();
                let entry =
                    st.pending
                        .entry(from.clone())
                        .or_insert_with(|| crate::state::PendingRegistration {
                            role,
                            identity_pubkey: identity_pubkey.clone(),
                            suggested_label: label.clone(),
                            version: version.clone(),
                            first_seen: now,
                            last_seen: now,
                        });
                entry.last_seen = now;
                entry.version = version;
                if entry.suggested_label.is_none() {
                    entry.suggested_label = label;
                }
                if let Err(e) = st.save(&self.data_dir) {
                    tracing::warn!("save pending: {}", e);
                }
                drop(st);
                let ack = HubMessage::RegisterAck {
                    accepted: false,
                    message: "waiting for operator approval".to_string(),
                    next_action: NextAction::Retry,
                };
                let _ = self.transport.send(&from, ack).await;
            }
            HubMessage::Heartbeat { ts, .. } => {
                self.last_heartbeat.insert(from, ts);
            }
            HubMessage::StatusResp { ready, summary, .. } => {
                tracing::debug!("status from {}: ready={} summary={:?}", from, ready, summary);
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
        let titles: Vec<Line> = [Tab::Dashboard, Tab::Pending]
            .iter()
            .map(|t| Line::from(t.title()))
            .collect();
        let selected = if self.tab == Tab::Dashboard { 0 } else { 1 };
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
        match snapshot {
            Some(st) => match self.tab {
                Tab::Dashboard => self.render_dashboard(&st, chunks[1], f),
                Tab::Pending => self.render_pending(&st, chunks[1], f),
            },
            None => {
                let p = Paragraph::new("...");
                f.render_widget(p, chunks[1]);
            }
        }

        // Status line
        let hint = match self.tab {
            Tab::Dashboard => "[1]ashboard  [2]ending  [Tab] switch  [q] quit",
            Tab::Pending => "[a] approve  [x] reject  [j/k] move  [Tab] switch  [q] quit",
        };
        let body = match &self.flash {
            Some(msg) => format!("{}    │    {}", msg, hint),
            None => hint.to_string(),
        };
        let status = Paragraph::new(body).style(Style::default().fg(Color::DarkGray));
        f.render_widget(status, chunks[2]);
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
                let signer = rec
                    .signer_pubkey
                    .as_deref()
                    .map(short_pk)
                    .unwrap_or_else(|| "(no signer pinned)".to_string());
                lines.push(Line::from(format!(
                    "  {:<24} {}  v{}  signer={}  {}",
                    rec.label,
                    short_pk(pk),
                    rec.last_version,
                    signer,
                    hb
                )));
            }
        }
        let p = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" inventory "));
        f.render_widget(p, area);
    }

    fn render_pending(&mut self, st: &HubState, area: Rect, f: &mut ratatui::Frame) {
        let mut entries: Vec<_> = st.pending.iter().collect();
        entries.sort_by_key(|(_, v)| v.first_seen);

        if entries.is_empty() {
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
            .map(|(pk, e)| {
                let waiting = now.saturating_sub(e.first_seen);
                let role = match e.role {
                    Role::Signer => "signer",
                    Role::Node => "node",
                };
                let label = e.suggested_label.as_deref().unwrap_or("(unnamed)");
                ListItem::new(format!(
                    "{:<6} {:<24} from {}  v{}  waiting {}s",
                    role,
                    label,
                    short_pk(pk),
                    e.version,
                    waiting,
                ))
            })
            .collect();
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
