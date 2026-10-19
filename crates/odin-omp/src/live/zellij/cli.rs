use async_trait::async_trait;
use odin_domain::huginn::{LiveError, LiveSessionId, SessionEpoch, TerminalCursor, TerminalSeq};
use odin_domain::CommandId;
use parking_lot::RwLock;
use serde::Deserialize;
use std::ffi::OsString;
use std::fs;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::{invalid_terminal, io_error, unavailable, ZellijLiveAdapter, MAX_TERMINAL_BYTES};
use crate::live::target::{
    parse_live_sessions, validate_target_name, TerminalTargetAdmin, TerminalTargetRegistry,
    TerminalTargetSnapshot, TerminalTargetStatus, ATTACH_SESSION_PLACEHOLDER, TERMINAL_TARGET_KIND,
};
use crate::process::OmpWorkerLaunch;

mod action;

use action::{run_zellij, run_zellij_blocking};

#[derive(Clone, Debug)]
pub struct CapturedTerminal {
    pub columns: NonZeroU16,
    pub rows: NonZeroU16,
    pub contents: String,
    pub cursor: TerminalCursor,
}

#[async_trait]
pub trait ZellijPane: Send + Sync {
    async fn capture(&self) -> Result<CapturedTerminal, LiveError>;
    async fn write_input(&self, operation_id: &CommandId, bytes: &[u8]) -> Result<(), LiveError>;
    async fn resize(
        &self,
        operation_id: &CommandId,
        columns: NonZeroU16,
        rows: NonZeroU16,
    ) -> Result<(), LiveError>;
    async fn terminate(&self) -> Result<(), LiveError>;
}

#[derive(Clone)]
pub struct ZellijCliFactory {
    executable: Arc<PathBuf>,
    targets: TerminalTargetRegistry,
    state_root: Arc<PathBuf>,
    command_timeout: StdDuration,
    initial_columns: NonZeroU16,
    initial_rows: NonZeroU16,
    action_lock: Arc<Mutex<()>>,
    /// Set once at daemon shutdown: no workflow starts afterwards, and
    /// started opens cut their ordinary actions and roll back.
    closing: Arc<AtomicBool>,
    /// Records that closed admission has been observed with no active workflow.
    drained: Arc<std::sync::OnceLock<()>>,
    worker: OmpWorkerLaunch,
    /// Governed attach-client argv template for the persistent tab; the
    /// `{session_id}` placeholder is replaced with the dispatched session id.
    attach_command: Option<Arc<Vec<String>>>,
}

const MAX_ATTACH_ARGS: usize = 64;
const MAX_ATTACH_ARG_BYTES: usize = 4096;
/// The plain (non-Odin) tab opened when closing would leave the operator
/// session without any tab.
const KEEP_TAB_NAME: &str = "operator";

impl ZellijCliFactory {
    pub fn open(
        executable: impl AsRef<Path>,
        session_name: impl Into<String>,
        state_root: impl AsRef<Path>,
        command_timeout: StdDuration,
        initial_columns: NonZeroU16,
        initial_rows: NonZeroU16,
        worker: OmpWorkerLaunch,
    ) -> Result<Self, LiveError> {
        if command_timeout.is_zero() {
            return Err(invalid_terminal("zellij command timeout must be positive"));
        }
        let session_name = session_name.into();
        // An empty selector waits for explicit registration; named targets must validate.
        let targets = if session_name.is_empty() {
            TerminalTargetRegistry::new()
        } else {
            validate_target_name(&session_name)
                .map_err(|_| invalid_terminal("zellij session name is invalid"))?;
            TerminalTargetRegistry::with_declared(&session_name)
                .map_err(|_| invalid_terminal("zellij session name is invalid"))?
        };
        let executable = executable.as_ref().to_path_buf();
        if !executable.is_file() {
            return Err(invalid_terminal("zellij executable is not a regular file"));
        }
        fs::create_dir_all(state_root.as_ref()).map_err(io_error)?;
        let state_root = state_root.as_ref().canonicalize().map_err(io_error)?;
        Ok(Self {
            executable: Arc::new(executable),
            targets,
            state_root: Arc::new(state_root),
            command_timeout,
            initial_columns,
            initial_rows,
            action_lock: Arc::new(Mutex::new(())),
            closing: Arc::new(AtomicBool::new(false)),
            drained: Arc::new(std::sync::OnceLock::new()),
            worker,
            attach_command: None,
        })
    }

    /// Closes ordinary admission at the start of daemon shutdown:
    /// queued work refuses before any effect and started opens roll back.
    /// Pane retirement remains admitted until the final drain.
    pub fn close(&self) {
        self.closing.store(true, Ordering::Release);
    }

    /// Seals retirement admission while holding the action lock, after the
    /// session owners have retired their panes. Every started workflow holds
    /// the lock through cleanup; queued callers observe the sealed drain.
    /// Ordinary admission closes immediately.
    /// `false` is an honest miss: started work was still running at the
    /// deadline. One-action reads outside the lock are not covered here.
    pub async fn quiesce_until(&self, deadline: tokio::time::Instant) -> bool {
        self.close();
        if self.drained.get().is_some() {
            return true;
        }
        let lock = Arc::clone(&self.action_lock).lock_owned();
        match tokio::time::timeout_at(deadline, lock).await {
            Ok(guard) => {
                let _ = self.drained.set(());
                drop(guard);
                true
            }
            Err(_) => false,
        }
    }

    /// Declares the governed attach client that every persistent tab runs,
    /// making the visible tab an operator surface over the SAME dispatched
    /// OMP session. The template may carry `{session_id}`; no other
    /// placeholder is accepted.
    pub fn with_attach_command(
        mut self,
        template: impl IntoIterator<Item = String>,
    ) -> Result<Self, LiveError> {
        let template: Vec<String> = template.into_iter().collect();
        if template.is_empty() || template.len() > MAX_ATTACH_ARGS {
            return Err(invalid_terminal(
                "zellij attach command must hold 1..=64 arguments",
            ));
        }
        for argument in &template {
            if argument.is_empty()
                || argument.len() > MAX_ATTACH_ARG_BYTES
                || argument.chars().any(char::is_control)
            {
                return Err(invalid_terminal(
                    "zellij attach command argument is invalid",
                ));
            }
            for candidate in argument.match_indices('{') {
                let rest = &argument[candidate.0..];
                if let Some(end) = rest.find('}') {
                    let placeholder = &rest[..=end];
                    if placeholder != ATTACH_SESSION_PLACEHOLDER {
                        return Err(invalid_terminal(format!(
                            "zellij attach command placeholder {placeholder} is unknown"
                        )));
                    }
                }
            }
        }
        self.attach_command = Some(Arc::new(template));
        Ok(self)
    }

    /// Live Zellij session names as reported by the real zellij CLI.
    async fn live_session_names(&self) -> Result<Vec<String>, LiveError> {
        let output = run_zellij(
            &self.executable,
            &self.worker,
            &self.state_root,
            self.command_timeout,
            vec!["list-sessions".to_owned(), "--no-formatting".to_owned()],
        )
        .await?;
        let text = std::str::from_utf8(&output).map_err(|_| unavailable())?;
        Ok(parse_live_sessions(text))
    }

    async fn verified_target(&self) -> Result<TerminalTargetSnapshot, LiveError> {
        let snapshot = self.targets.resolve()?;
        let live = self.live_session_names().await?;
        if live.iter().any(|name| name == &snapshot.zellij_session) {
            Ok(snapshot)
        } else {
            // Fail closed: a bound-but-dead selector is a typed miss. No
            // fallback to another session, and no session is ever created.
            Err(LiveError::NotFound {
                object_kind: TERMINAL_TARGET_KIND.to_owned(),
                object_id: snapshot.zellij_session,
            })
        }
    }
}

impl ZellijCliFactory {
    fn capture_root(&self) -> PathBuf {
        self.state_root.join("terminal")
    }

    pub async fn open_terminal(
        &self,
        session_id: LiveSessionId,
        epoch: SessionEpoch,
        terminal_head: TerminalSeq,
        cwd: &Path,
        tab_label: &str,
    ) -> Result<Arc<ZellijLiveAdapter>, LiveError> {
        self.open_terminal_with(session_id, epoch, terminal_head, cwd, tab_label, None)
            .await
    }

    /// Uses `attach` instead of the declared attach client when supplied.
    pub async fn open_terminal_with(
        &self,
        session_id: LiveSessionId,
        epoch: SessionEpoch,
        terminal_head: TerminalSeq,
        cwd: &Path,
        tab_label: &str,
        attach: Option<Vec<String>>,
    ) -> Result<Arc<ZellijLiveAdapter>, LiveError> {
        // A closed factory refuses before any action, the listing included.
        if self.closing.load(Ordering::Acquire) {
            return Err(terminals_closed());
        }
        // Resolve and verify the explicit target first: an unbound target, a
        // dead declared selector, or a session that is not currently live is
        // a typed error here. No fallback, no guessing, no creation.
        let target = self.verified_target().await?;
        let template = self
            .attach_command
            .as_ref()
            .ok_or_else(|| LiveError::Unavailable {
                code: "terminal_attach_command_unconfigured".to_owned(),
            })?;
        let session_token = session_id.to_string();
        let attach_command: Vec<String> = attach.unwrap_or_else(|| {
            template
                .iter()
                .map(|argument| argument.replace(ATTACH_SESSION_PLACEHOLDER, &session_token))
                .collect()
        });
        // The tab is named by seat + purpose (the caller's label), not the
        // raw session id — the operator reads WHO/WHAT, not a digest. The
        // label is slugified and bounded; identity stays on the adapter's
        // own session binding.
        let tab_name = format!("odin-{}", slug_label(tab_label));
        // Whichever side decides first wins the handover: the caller taking
        // the adapter, or the workflow refusing it. A caller dropped first
        // (cancelled, or its task dropped by runtime shutdown) refuses it
        // through its claim, which also cuts the open's ordinary actions.
        let handover = Arc::new(AtomicU8::new(HANDOVER_PENDING));
        let claim = HandoverClaim(Arc::clone(&handover));
        let pane = ZellijCliPane {
            executable: Arc::clone(&self.executable),
            session_name: Arc::from(target.zellij_session.as_str()),
            tab_name: Arc::from(tab_name),
            capture_root: Arc::clone(&self.state_root),
            command_timeout: self.command_timeout,
            dimensions: Arc::new(RwLock::new((self.initial_columns, self.initial_rows))),
            action_lock: Arc::clone(&self.action_lock),
            closing: Arc::clone(&self.closing),
            drained: Arc::clone(&self.drained),
            worker: self.worker.clone(),
            attach_command: Arc::new(attach_command),
            target: Arc::new(std::sync::OnceLock::new()),
            opened_tab: Arc::new(std::sync::OnceLock::new()),
            deadline: None,
            handover: Some(Arc::clone(&handover)),
        };
        let cwd = cwd.to_path_buf();
        let capture_root = self.capture_root();
        let (accepted, acceptance) = std::sync::mpsc::channel::<()>();
        // Hold the action lock through completion or rollback, even if the caller leaves.
        let adapter = pane
            .owned(TerminalWork::Ordinary, move |pane, reply| {
                let result = pane.ensure_tab(&cwd).and_then(|()| {
                    ZellijLiveAdapter::open(
                        capture_root,
                        session_id,
                        epoch,
                        terminal_head,
                        Arc::new(ZellijCliPane {
                            deadline: None,
                            handover: None,
                            ..pane.clone()
                        }),
                    )
                    .map(Arc::new)
                });
                let opened = result.is_ok();
                // A value left in an abandoned mailbox is not a handover:
                // the caller acknowledges taking the adapter within what is
                // left of the workflow budget, before the lock is released.
                // Then one refusal attempt settles it: only the caller's own
                // prior decision means taken.
                let delivered = reply.send(result).is_ok();
                let taken = opened && delivered && {
                    let _ = acceptance.recv_timeout(pane.remaining());
                    pane.handover.as_deref().is_some_and(|state| {
                        decide_handover(state, HANDOVER_REFUSED) == Err(HANDOVER_TAKEN)
                    })
                };
                if !taken {
                    // Rollback is never cut and has its own bounded budget:
                    // an abandoned or expired open still closes exactly the
                    // tab it created.
                    if let Err(error) = pane.cleanup().close_opened_tab() {
                        tracing::error!(
                            "odin-omp: zellij could not close unopened tab={}: {error}",
                            pane.tab_name
                        );
                    }
                }
            })
            .await?;
        // Refused only when the workflow stopped waiting and rolled back.
        let taken = decide_handover(&claim.0, HANDOVER_TAKEN).is_ok();
        let _ = accepted.send(());
        drop(claim);
        if taken {
            Ok(adapter)
        } else {
            Err(unavailable())
        }
    }
}

#[async_trait]
impl TerminalTargetAdmin for ZellijCliFactory {
    async fn register_chat_target(
        &self,
        zellij_session: String,
    ) -> Result<TerminalTargetStatus, LiveError> {
        validate_target_name(&zellij_session)?;
        let live = self.live_session_names().await?;
        if !live.iter().any(|name| name == &zellij_session) {
            // Fail closed on registration: a target that does not name a
            // currently live operator session is refused before it can bind.
            return Err(LiveError::NotFound {
                object_kind: TERMINAL_TARGET_KIND.to_owned(),
                object_id: zellij_session,
            });
        }
        self.targets.register_chat(zellij_session)
    }

    async fn clear_chat_target(&self) -> Result<TerminalTargetStatus, LiveError> {
        self.targets.clear_chat()
    }

    async fn terminal_target_status(&self) -> TerminalTargetStatus {
        self.targets.status()
    }

    async fn resolve_target(&self) -> Result<TerminalTargetSnapshot, LiveError> {
        self.verified_target().await
    }

    async fn capture_screen(
        &self,
        session: &str,
        max_bytes: usize,
    ) -> Result<crate::live::target::TerminalScreenCapture, LiveError> {
        if max_bytes == 0 {
            return Err(invalid_terminal(
                "terminal screen capture budget must be positive",
            ));
        }
        // Resolve and verify the governed target first; the requested
        // selector must name exactly that session — no wandering read.
        let target = self.verified_target().await?;
        if session != target.zellij_session {
            return Err(LiveError::NotFound {
                object_kind: TERMINAL_TARGET_KIND.to_owned(),
                object_id: session.to_owned(),
            });
        }
        // Read-only dump of the target session's focused pane through the
        // same registered-service zellij launch as every other action. The
        // capture is the bounded viewport — never an unchecked full
        // scrollback dump: `--full` reads unbounded history and used to
        // fail the whole read at the hard byte cap instead of truncating.
        let path = self
            .state_root
            .join(format!(".terminal-read-{}.txt", Uuid::new_v4()));
        let direct_output = run_zellij(
            &self.executable,
            &self.worker,
            &self.state_root,
            self.command_timeout,
            vec![
                "--session".to_owned(),
                target.zellij_session.clone(),
                "action".to_owned(),
                "dump-screen".to_owned(),
                "--path".to_owned(),
                path.to_string_lossy().into_owned(),
            ],
        )
        .await?;
        let bytes = if path.try_exists().unwrap_or(false) {
            let bytes = fs::read(&path).map_err(io_error)?;
            let _ = fs::remove_file(&path);
            bytes
        } else {
            direct_output
        };
        // Defensive bound for a pathological capture: char-safe truncation
        // at the hard cap, reported through the same `truncated` flag,
        // instead of failing the whole read; the caller's maxBytes budget
        // still applies afterwards.
        let contents =
            String::from_utf8(bytes).map_err(|_| invalid_terminal("non-UTF-8 terminal"))?;
        let hard_truncated = contents.len() > MAX_TERMINAL_BYTES;
        let mut cut = contents.len().min(MAX_TERMINAL_BYTES);
        while cut > 0 && !contents.is_char_boundary(cut) {
            cut -= 1;
        }
        let contents = &contents[..cut];
        let (bounded, truncated) = if contents.len() <= max_bytes {
            (contents.to_owned(), hard_truncated)
        } else {
            let mut cut = max_bytes;
            while cut > 0 && !contents.is_char_boundary(cut) {
                cut -= 1;
            }
            (contents[..cut].to_owned(), true)
        };
        Ok(crate::live::target::TerminalScreenCapture {
            zellij_session: target.zellij_session,
            content: bounded,
            truncated,
        })
    }

    async fn captured_sessions(&self) -> Result<Vec<LiveSessionId>, LiveError> {
        let mut entries = match tokio::fs::read_dir(self.capture_root()).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_error(error)),
        };
        let mut sessions = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(io_error)? {
            if let Some(session) = entry
                .file_name()
                .to_str()
                .and_then(|name| LiveSessionId::parse(name).ok())
            {
                sessions.push(session);
            }
        }
        sessions.sort();
        Ok(sessions)
    }

    async fn remove_session_capture(&self, session: LiveSessionId) -> Result<(), LiveError> {
        match tokio::fs::remove_dir_all(self.capture_root().join(session.to_string())).await {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(io_error(error)),
            _ => Ok(()),
        }
    }
}

/// Clones share one pane: an owned workflow carries its own clone.
#[derive(Clone)]
pub struct ZellijCliPane {
    executable: Arc<PathBuf>,
    session_name: Arc<str>,
    tab_name: Arc<str>,
    capture_root: Arc<PathBuf>,
    command_timeout: StdDuration,
    dimensions: Arc<RwLock<(NonZeroU16, NonZeroU16)>>,
    action_lock: Arc<Mutex<()>>,
    /// The factory's shutdown admission flag.
    closing: Arc<AtomicBool>,
    /// Seals all work after the factory's final drain, including retirement.
    drained: Arc<std::sync::OnceLock<()>>,
    worker: OmpWorkerLaunch,
    /// Concrete governed attach-client argv for this session's tab.
    attach_command: Arc<Vec<String>>,
    /// The tab and pane this session's attach client runs in, set once by
    /// [`Self::ensure_tab`]. Every later action names this pane by id.
    target: Arc<std::sync::OnceLock<PaneTarget>>,
    /// The tab [`Self::open_tab`] created, recorded before its pane exists:
    /// an abandoned or failed open closes only this, never a reused tab.
    opened_tab: Arc<std::sync::OnceLock<u64>>,
    /// The single wall-clock deadline of the workflow this clone runs, set
    /// by [`Self::budgeted`]; every action gets at most what is left.
    deadline: Option<std::time::Instant>,
    /// The handover of the open this clone runs: once its caller refused
    /// it, the open's ordinary actions are cut. `None` for rollback and for
    /// every pane outside an open, which are never cut.
    handover: Option<Arc<AtomicU8>>,
}

#[derive(Clone, Copy)]
enum TerminalWork {
    Ordinary,
    Retirement,
}

/// The open caller's side of the handover: dropped before it took the
/// adapter, it refuses the handover, which marks the open abandoned.
struct HandoverClaim(Arc<AtomicU8>);

impl Drop for HandoverClaim {
    fn drop(&mut self) {
        let _ = decide_handover(&self.0, HANDOVER_REFUSED);
    }
}

/// Stable zellij ids of one session's tab and its attach-client pane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PaneTarget {
    tab_id: u64,
    pane_id: u64,
}

impl PaneTarget {
    fn pane_arg(self) -> OsString {
        OsString::from(format!("terminal_{}", self.pane_id))
    }
}

fn pane_unaddressable() -> LiveError {
    LiveError::Unavailable {
        code: "terminal_pane_unaddressable".to_owned(),
    }
}

impl ZellijCliPane {
    fn admission_closed(&self, work: TerminalWork) -> bool {
        match work {
            TerminalWork::Ordinary => self.closing.load(Ordering::Acquire),
            TerminalWork::Retirement => self.drained.get().is_some(),
        }
    }

    /// Runs blocking work under the action lock through cleanup, even after cancellation.
    /// Queued work does not start if its caller leaves; later mutations cannot overtake it.
    async fn owned<T: Send + 'static>(
        &self,
        admission: TerminalWork,
        work: impl FnOnce(&Self, Reply<T>) + Send + 'static,
    ) -> Result<T, LiveError> {
        if self.admission_closed(admission) {
            return Err(terminals_closed());
        }
        let guard = Arc::clone(&self.action_lock).lock_owned().await;
        if self.admission_closed(admission) {
            return Err(terminals_closed());
        }
        let pane = self.budgeted();
        let (reply, receive) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            // Effects begin here; a caller already gone, or admission closed
            // while this waited for the pool, left nothing to own.
            if pane.admission_closed(admission) {
                let _ = reply.send(Err(terminals_closed()));
            } else if !reply.is_closed() {
                work(&pane, reply);
            }
            drop(guard);
        });
        receive.await.map_err(|_| unavailable())?
    }

    /// A clone whose actions share one `command_timeout` from now: a
    /// started workflow's whole budget, or a rollback's separate one.
    fn budgeted(&self) -> Self {
        let mut pane = self.clone();
        pane.deadline = Some(std::time::Instant::now() + self.command_timeout);
        pane
    }

    /// The open's rollback: its own fresh budget, never cut by abandonment.
    fn cleanup(&self) -> Self {
        let mut pane = self.budgeted();
        pane.handover = None;
        pane
    }

    /// Whether this clone runs an open its caller has abandoned, or one
    /// still running when daemon shutdown closed admission.
    fn abandoned(&self) -> bool {
        self.handover.as_deref().is_some_and(|state| {
            state.load(Ordering::Acquire) == HANDOVER_REFUSED
                || self.closing.load(Ordering::Acquire)
        })
    }

    /// What is left of this clone's workflow budget; outside any workflow,
    /// the per-action bound.
    fn remaining(&self) -> StdDuration {
        self.deadline.map_or(self.command_timeout, |deadline| {
            deadline.saturating_duration_since(std::time::Instant::now())
        })
    }

    /// [`Self::owned`] for a mutation whose result needs no handover.
    async fn owned_mutation<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Self) -> Result<T, LiveError> + Send + 'static,
    ) -> Result<T, LiveError> {
        self.owned(TerminalWork::Ordinary, move |pane, reply| {
            let _ = reply.send(work(pane));
        })
        .await
    }

    /// Caller holds the action lock.
    fn ensure_tab(&self, cwd: &Path) -> Result<(), LiveError> {
        let (tabs, panes) = self.tab_snapshot()?;
        let command = self.attach_command.join(" ");
        let reusable = tabs
            .iter()
            .filter(|tab| tab.name == self.tab_name.as_ref())
            .find_map(|tab| {
                panes
                    .iter()
                    .find(|pane| {
                        pane.tab_id == tab.tab_id
                            && !pane.is_plugin
                            && !pane.exited
                            && pane
                                .terminal_command
                                .as_deref()
                                .is_some_and(|running| running.ends_with(command.as_str()))
                    })
                    .map(|pane| PaneTarget {
                        tab_id: tab.tab_id,
                        pane_id: pane.id,
                    })
            });
        let target = match reusable {
            // This session's attach client still runs there; reuse it
            // instead of spawning a second client for the same session.
            Some(target) => target,
            None => {
                self.warn_unlaid_out();
                let target = self.open_tab(cwd)?;
                tracing::info!(
                    "odin-omp: zellij opened tab={} tab_id={} pane=terminal_{}",
                    self.tab_name,
                    target.tab_id,
                    target.pane_id
                );
                target
            }
        };
        let _ = self.target.set(target);
        // Open before pruning: closing the last tab would end the zellij session.
        self.prune_stale_tabs(target.tab_id);
        Ok(())
    }

    /// zellij 0.45 lays out a tab opened while no client is attached at
    /// 0x0 for good: its panes get a 1x1 pty and capture shows nothing
    /// usable. The authority keeps a hidden client attached
    /// (`odin-operator-zellij-client`); its absence is named here, once per
    /// opened tab, instead of surfacing later as an empty screen.
    fn warn_unlaid_out(&self) {
        match self.invoke(&[OsString::from("list-clients")]) {
            Ok(output) if attached_clients(&output) == 0 => tracing::error!(
                "odin-omp: zellij session={} has no attached client; tab={} opens at 1x1 \
                 and its screen stays unreadable (is odin-operator-zellij-client running?)",
                self.session_name,
                self.tab_name
            ),
            Ok(_) => {}
            Err(error) => tracing::error!("odin-omp: zellij list-clients failed: {error}"),
        }
    }

    /// Opens this session's tab and its attach-client pane, returning both
    /// ids. The client is placed with `new-pane --tab-id`, which answers its
    /// pane id: a command given to `new-tab` itself is never laid out on a
    /// headless session (no pane id, unreachable by id or focus). The tab's
    /// placeholder `true` pane exits at once; when a client is attached it
    /// stays held, so it is closed by id.
    fn open_tab(&self, cwd: &Path) -> Result<PaneTarget, LiveError> {
        if self.abandoned() {
            return Err(open_abandoned());
        }
        // A started `new-tab` is never cut: cutting it could leave a tab
        // whose id was never read, which rollback cannot close by id.
        let uncut = ZellijCliPane {
            handover: None,
            ..self.clone()
        };
        let tab_output = uncut.invoke(&new_tab_arguments(&self.tab_name, cwd))?;
        let tab_id = parse_created_id(&tab_output, "")?;
        let _ = self.opened_tab.set(tab_id);
        let pane_output = self.invoke(&new_pane_arguments(tab_id, cwd, &self.attach_command))?;
        let pane_id = parse_created_id(&pane_output, "terminal_")?;
        let target = PaneTarget { tab_id, pane_id };
        let (_, panes) = self.tab_snapshot()?;
        for placeholder in panes
            .iter()
            .filter(|pane| pane.tab_id == tab_id && !pane.is_plugin && pane.id != pane_id)
        {
            self.invoke(&[
                OsString::from("close-pane"),
                OsString::from("--pane-id"),
                OsString::from(format!("terminal_{}", placeholder.id)),
            ])?;
        }
        Ok(target)
    }

    /// Re-lists panes before acting because zellij reports success for unknown IDs.
    /// Caller holds the action lock.
    fn live_target(&self) -> Result<PaneTarget, LiveError> {
        let target = *self.target.get().ok_or_else(pane_unaddressable)?;
        let panes = self.list_panes()?;
        if panes
            .iter()
            .any(|pane| pane.id == target.pane_id && !pane.is_plugin && !pane.exited)
        {
            Ok(target)
        } else {
            Err(pane_unaddressable())
        }
    }

    /// Runs `verb --pane-id <this session's pane> rest…`. Never focus
    /// relative: `go-to-tab-name` is ignored on a headless session, so a
    /// focused action hit whichever tab was active (another session's).
    async fn pane_action(&self, verb: &str, rest: &[OsString]) -> Result<Vec<u8>, LiveError> {
        let verb = verb.to_owned();
        let rest = rest.to_vec();
        self.owned_mutation(move |pane| pane.pane_action_locked(&verb, &rest))
            .await
    }

    fn pane_action_locked(&self, verb: &str, rest: &[OsString]) -> Result<Vec<u8>, LiveError> {
        let target = self.live_target()?;
        let mut action = Vec::with_capacity(rest.len().saturating_add(3));
        action.push(OsString::from(verb));
        action.push(OsString::from("--pane-id"));
        action.push(target.pane_arg());
        action.extend(rest.iter().cloned());
        self.invoke(&action)
    }

    fn list_panes(&self) -> Result<Vec<ZellijPaneInfo>, LiveError> {
        let panes = self.invoke(&[
            OsString::from("list-panes"),
            OsString::from("--all"),
            OsString::from("--json"),
        ])?;
        parse_zellij_json(&panes)
    }

    /// The operator session's tabs as zellij reports them (`list-tabs` and
    /// `list-panes`, JSON).
    fn tab_snapshot(&self) -> Result<(Vec<ZellijTabInfo>, Vec<ZellijPaneInfo>), LiveError> {
        let tabs = self.invoke(&[OsString::from("list-tabs"), OsString::from("--json")])?;
        Ok((parse_zellij_json(&tabs)?, self.list_panes()?))
    }

    /// Closes stable IDs and re-lists: headless sessions ignore focus-relative actions,
    /// and closing an unknown ID reports success. Returns tabs still present.
    fn close_tabs_by_id(&self, tabs: &[(u64, String)]) -> Result<Vec<(u64, String)>, LiveError> {
        if tabs.is_empty() {
            return Ok(Vec::new());
        }
        // Never close the session's last tab: zellij ends a session whose
        // last tab closes, and the watch unit then resurrects it from its
        // serialized layout. A plain tab keeps the session when nothing
        // else would remain.
        let (before, _) = self.tab_snapshot()?;
        if before
            .iter()
            .all(|tab| tabs.iter().any(|(id, _)| *id == tab.tab_id))
        {
            self.invoke(&[
                OsString::from("new-tab"),
                OsString::from("--name"),
                OsString::from(KEEP_TAB_NAME),
            ])?;
            tracing::info!(
                "odin-omp: zellij session={} kept open with tab={KEEP_TAB_NAME}: every tab was \
                 closing",
                self.session_name
            );
        }
        for (id, _) in tabs {
            self.invoke(&[
                OsString::from("close-tab-by-id"),
                OsString::from(id.to_string()),
            ])?;
        }
        let (after, _) = self.tab_snapshot()?;
        Ok(tabs
            .iter()
            .filter(|(id, _)| after.iter().any(|tab| tab.tab_id == *id))
            .cloned()
            .collect())
    }

    /// Closes the operator session's stale `odin-*` tabs (see
    /// [`stale_odin_tabs`]) exactly once each. Best effort under the action
    /// lock; every outcome is logged.
    fn prune_stale_tabs(&self, keep: u64) {
        let stale = match self.tab_snapshot() {
            Ok((tabs, panes)) => stale_odin_tabs(&tabs, &panes)
                .into_iter()
                .filter(|tab| tab.id != keep)
                .collect::<Vec<_>>(),
            Err(error) => {
                tracing::warn!("odin-omp: zellij tab prune skipped: {error}");
                return;
            }
        };
        let targets: Vec<(u64, String)> =
            stale.iter().map(|tab| (tab.id, tab.name.clone())).collect();
        match self.close_tabs_by_id(&targets) {
            Ok(survivors) => {
                for tab in &stale {
                    if survivors.iter().any(|(id, _)| *id == tab.id) {
                        tracing::error!(
                            "odin-omp: zellij could not close stale tab={} id={}: still listed",
                            tab.name,
                            tab.id
                        );
                    } else {
                        tracing::info!(
                            "odin-omp: zellij closed stale tab={} id={} reason={}",
                            tab.name,
                            tab.id,
                            tab.reason.as_str()
                        );
                    }
                }
            }
            Err(error) => tracing::error!(
                "odin-omp: zellij could not close {} stale tabs: {error}",
                targets.len()
            ),
        }
    }

    /// Runs an action within the remaining workflow budget, stopping it if abandoned.
    fn invoke(&self, action: &[OsString]) -> Result<Vec<u8>, LiveError> {
        let budget = self.remaining().min(self.command_timeout);
        if budget.is_zero() {
            return Err(LiveError::Unavailable {
                code: "zellij_workflow_deadline".to_owned(),
            });
        }
        if self.abandoned() {
            return Err(open_abandoned());
        }
        let mut args: Vec<String> = Vec::with_capacity(action.len().saturating_add(3));
        args.push("--session".to_owned());
        args.push(self.session_name.to_string());
        args.push("action".to_owned());
        args.extend(
            action
                .iter()
                .map(|value| value.to_string_lossy().into_owned()),
        );
        run_zellij_blocking(
            &self.executable,
            &self.worker,
            &self.capture_root,
            budget,
            args,
            &|| self.abandoned(),
        )
    }
}

fn open_abandoned() -> LiveError {
    LiveError::Unavailable {
        code: "zellij_open_abandoned".to_owned(),
    }
}

fn terminals_closed() -> LiveError {
    LiveError::Unavailable {
        code: "zellij_terminals_closed".to_owned(),
    }
}

/// The answer channel of one owned workflow.
type Reply<T> = tokio::sync::oneshot::Sender<Result<T, LiveError>>;

const HANDOVER_PENDING: u8 = 0;
const HANDOVER_TAKEN: u8 = 1;
const HANDOVER_REFUSED: u8 = 2;

/// Settles a pending adapter handover once; `Err` names who settled first.
fn decide_handover(state: &AtomicU8, outcome: u8) -> Result<u8, u8> {
    state.compare_exchange(
        HANDOVER_PENDING,
        outcome,
        Ordering::AcqRel,
        Ordering::Acquire,
    )
}

#[async_trait]
impl ZellijPane for ZellijCliPane {
    async fn capture(&self) -> Result<CapturedTerminal, LiveError> {
        let path = self
            .capture_root
            .join(format!(".terminal-capture-{}.txt", Uuid::new_v4()));
        let direct_output = self
            .pane_action(
                "dump-screen",
                &[
                    OsString::from("--full"),
                    OsString::from("--path"),
                    path.as_os_str().to_owned(),
                ],
            )
            .await?;
        let bytes = if path.try_exists().unwrap_or(false) {
            let bytes = fs::read(&path).map_err(io_error)?;
            let _ = fs::remove_file(&path);
            bytes
        } else {
            direct_output
        };
        let contents = screen_tail(bytes)?;
        let (columns, rows) = *self.dimensions.read();
        let last = contents.lines().next_back().unwrap_or_default();
        let line_count = contents.lines().count().max(1);
        let cursor = TerminalCursor {
            row: u16::try_from(line_count.saturating_sub(1))
                .unwrap_or(u16::MAX)
                .min(rows.get().saturating_sub(1)),
            column: u16::try_from(last.chars().count())
                .unwrap_or(u16::MAX)
                .min(columns.get().saturating_sub(1)),
            visible: true,
        };
        Ok(CapturedTerminal {
            columns,
            rows,
            contents,
            cursor,
        })
    }

    async fn write_input(&self, _operation_id: &CommandId, bytes: &[u8]) -> Result<(), LiveError> {
        let action: Vec<OsString> = bytes
            .iter()
            .map(|byte| OsString::from(byte.to_string()))
            .collect();
        self.pane_action("write", &action).await.map(|_| ())
    }

    async fn resize(
        &self,
        _operation_id: &CommandId,
        columns: NonZeroU16,
        rows: NonZeroU16,
    ) -> Result<(), LiveError> {
        self.owned_mutation(move |pane| pane.resize_locked(columns, rows))
            .await
    }

    /// Closes this session's tab by its stable id: focus-relative
    /// `go-to-tab-name` + `close-pane` is a silent no-op on a headless
    /// session, which left every ended session's tab behind.
    async fn terminate(&self) -> Result<(), LiveError> {
        self.owned(TerminalWork::Retirement, |pane, reply| {
            let result = match pane.target.get().copied() {
                Some(target) => pane.close_tab_locked(target.tab_id),
                None => Ok(()),
            };
            let _ = reply.send(result);
        })
        .await
    }
}

impl ZellijCliPane {
    /// Both axes as one workflow; caller holds the action lock.
    fn resize_locked(&self, columns: NonZeroU16, rows: NonZeroU16) -> Result<(), LiveError> {
        let current = *self.dimensions.read();
        if current.0 != columns {
            let change = if columns > current.0 {
                "increase"
            } else {
                "decrease"
            };
            self.pane_action_locked("resize", &[OsString::from(change), OsString::from("right")])?;
        }
        if current.1 != rows {
            let change = if rows > current.1 {
                "increase"
            } else {
                "decrease"
            };
            self.pane_action_locked("resize", &[OsString::from(change), OsString::from("down")])?;
        }
        *self.dimensions.write() = (columns, rows);
        Ok(())
    }

    /// Closes the tab an abandoned or failed open created, if any; a
    /// reused tab was never recorded and stays. Caller holds the lock.
    fn close_opened_tab(&self) -> Result<(), LiveError> {
        match self.opened_tab.get().copied() {
            Some(tab_id) => self.close_tab_locked(tab_id),
            None => Ok(()),
        }
    }

    /// Closes only a tab still listed under this session; caller holds the action lock.
    fn close_tab_locked(&self, tab_id: u64) -> Result<(), LiveError> {
        let (tabs, _) = self.tab_snapshot()?;
        let own: Vec<(u64, String)> = tabs
            .into_iter()
            .filter(|tab| tab.tab_id == tab_id && tab.name == self.tab_name.as_ref())
            .map(|tab| (tab.tab_id, tab.name))
            .collect();
        let survivors = self.close_tabs_by_id(&own)?;
        if survivors.is_empty() {
            if !own.is_empty() {
                tracing::info!(
                    "odin-omp: zellij closed session tab={} tab_id={tab_id}",
                    self.tab_name
                );
            }
            Ok(())
        } else {
            Err(LiveError::Unavailable {
                code: "terminal_tab_close_failed".to_owned(),
            })
        }
    }
}

/// Bounded, zellij-safe label slug: lowercase alphanumerics and single
/// dashes; everything else collapses to one dash; never empty, never
/// longer than 32 chars.
/// The `new-tab` action of one session's tab: named, in the project cwd,
/// running only a placeholder `true` (see [`ZellijCliPane::open_tab`]); it
/// answers the new tab's stable id.
fn new_tab_arguments(tab_name: &str, cwd: &Path) -> Vec<OsString> {
    vec![
        OsString::from("new-tab"),
        OsString::from("--name"),
        OsString::from(tab_name),
        OsString::from("--cwd"),
        cwd.as_os_str().to_owned(),
        OsString::from("--"),
        OsString::from("true"),
    ]
}

/// Waits for a pane larger than the headless 1x1 placeholder before starting its client.
/// After five seconds the command runs regardless of size.
const AWAIT_REAL_SIZE: &str = "i=0; while [ $i -lt 100 ]; do \
     s=$(stty size 2>/dev/null); r=${s% *}; c=${s#* }; \
     [ \"${r:-0}\" -gt 1 ] 2>/dev/null && [ \"${c:-0}\" -gt 1 ] 2>/dev/null && break; \
     i=$((i+1)); sleep 0.05; done; exec \"$0\" \"$@\"";

fn new_pane_arguments(tab_id: u64, cwd: &Path, attach_command: &[String]) -> Vec<OsString> {
    let mut action = Vec::with_capacity(attach_command.len().saturating_add(10));
    action.extend([
        OsString::from("new-pane"),
        OsString::from("--tab-id"),
        OsString::from(tab_id.to_string()),
        OsString::from("--cwd"),
        cwd.as_os_str().to_owned(),
        OsString::from("--close-on-exit"),
        OsString::from("--"),
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from(AWAIT_REAL_SIZE),
    ]);
    action.extend(attach_command.iter().map(OsString::from));
    action
}

/// The newest [`MAX_TERMINAL_BYTES`] of a `dump-screen --full` capture,
/// cut at a line start. A live pane (now laid out at a real size) keeps
/// growing scrollback; refusing past the bound would blind every reader of
/// a long session, while its tail always holds the current screen.
fn screen_tail(bytes: Vec<u8>) -> Result<String, LiveError> {
    let contents = String::from_utf8(bytes).map_err(|_| invalid_terminal("non-UTF-8 terminal"))?;
    if contents.len() <= MAX_TERMINAL_BYTES {
        return Ok(contents);
    }
    let mut start = contents.len() - MAX_TERMINAL_BYTES;
    while !contents.is_char_boundary(start) {
        start += 1;
    }
    let tail = &contents[start..];
    Ok(match tail.find('\n') {
        Some(newline) if newline + 1 < tail.len() => tail[newline + 1..].to_owned(),
        _ => tail.to_owned(),
    })
}

/// Client rows of `zellij action list-clients` (a header line, then one
/// row per attached client).
fn attached_clients(output: &[u8]) -> usize {
    String::from_utf8_lossy(output)
        .lines()
        .filter(|line| {
            let first = line.split_whitespace().next().unwrap_or_default();
            !first.is_empty() && first.bytes().all(|byte| byte.is_ascii_digit())
        })
        .count()
}

/// The id a creating action prints (`3` for a tab, `terminal_3` for a
/// pane); anything else is a typed refusal, never a guessed target.
fn parse_created_id(output: &[u8], prefix: &str) -> Result<u64, LiveError> {
    std::str::from_utf8(output)
        .ok()
        .map(str::trim)
        .and_then(|text| text.strip_prefix(prefix))
        .and_then(|id| id.parse().ok())
        .ok_or_else(|| {
            invalid_terminal(format!(
                "zellij did not answer a created {} id",
                if prefix.is_empty() { "tab" } else { "pane" }
            ))
        })
}

/// One tab of `zellij action list-tabs --json` (the fields Odin reads).
#[derive(Debug, Deserialize)]
struct ZellijTabInfo {
    tab_id: u64,
    name: String,
}

/// One pane of `zellij action list-panes --all --json`.
#[derive(Debug, Deserialize)]
struct ZellijPaneInfo {
    id: u64,
    tab_id: u64,
    #[serde(default)]
    is_plugin: bool,
    #[serde(default)]
    exited: bool,
    #[serde(default)]
    terminal_command: Option<String>,
}

fn parse_zellij_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<Vec<T>, LiveError> {
    serde_json::from_slice(bytes)
        .map_err(|error| invalid_terminal(format!("zellij JSON listing is malformed: {error}")))
}

/// Why an `odin-*` tab is stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StaleTabReason {
    /// No terminal pane at all: its attach client exited (`--close-on-exit`)
    /// and zellij kept the tab, or it was opened while no client was
    /// attached (a headless session never lays out a new tab's pane).
    NoPane,
    /// Only command-less panes: the bare shells a resurrected serialized
    /// session puts into such tabs, never an Odin attach client.
    NoCommand,
    /// Its command pane exited and is held.
    Exited,
}

impl StaleTabReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::NoPane => "no-pane",
            Self::NoCommand => "no-command",
            Self::Exited => "exited",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct StaleTab {
    id: u64,
    name: String,
    reason: StaleTabReason,
}

/// The `odin-*` tabs that run no live command pane. Every Odin tab is
/// opened running its session's attach client, so a tab without one shows
/// the operator nothing and is closed; tabs that are not Odin's are never
/// touched.
fn stale_odin_tabs(tabs: &[ZellijTabInfo], panes: &[ZellijPaneInfo]) -> Vec<StaleTab> {
    tabs.iter()
        .filter(|tab| tab.name.starts_with("odin-"))
        .filter_map(|tab| {
            let terminals: Vec<&ZellijPaneInfo> = panes
                .iter()
                .filter(|pane| pane.tab_id == tab.tab_id && !pane.is_plugin)
                .collect();
            let reason = if terminals.is_empty() {
                StaleTabReason::NoPane
            } else if terminals.iter().any(|pane| {
                !pane.exited
                    && pane
                        .terminal_command
                        .as_deref()
                        .is_some_and(|command| !command.trim().is_empty())
            }) {
                return None;
            } else if terminals.iter().any(|pane| pane.exited) {
                StaleTabReason::Exited
            } else {
                StaleTabReason::NoCommand
            };
            Some(StaleTab {
                id: tab.tab_id,
                name: tab.name.clone(),
                reason,
            })
        })
        .collect()
}

fn slug_label(label: &str) -> String {
    let mut slug = String::with_capacity(32);
    let mut dash = false;
    for character in label.chars() {
        if character.is_ascii_alphanumeric() {
            if dash && !slug.is_empty() {
                slug.push('-');
            }
            dash = false;
            slug.push(character.to_ascii_lowercase());
            if slug.len() >= 32 {
                break;
            }
        } else {
            dash = true;
        }
    }
    if slug.is_empty() {
        "live".to_owned()
    } else {
        slug
    }
}

#[cfg(test)]
mod slug_tests {
    /// Every `odin-*` tab without a live command pane is stale: no pane (a
    /// headless session, or a client that exited), only bare shells (a
    /// resurrected serialized session), or an exited held command. A tab
    /// running its attach client and every non-Odin tab stay.
    #[test]
    fn only_odin_tabs_without_a_live_command_are_stale() {
        use super::{StaleTab, StaleTabReason, ZellijPaneInfo, ZellijTabInfo};
        let tabs: Vec<ZellijTabInfo> = serde_json::from_str(
            r#"[{"tab_id":0,"name":"Tab #1","position":0},
                {"tab_id":1,"name":"odin-kubert-run-browser-probe-once-an"},
                {"tab_id":2,"name":"odin-kubert-verify-pods-after-mini-re"},
                {"tab_id":3,"name":"odin-kubert-live"},
                {"tab_id":4,"name":"odin-architect-held"},
                {"tab_id":5,"name":"notes"}]"#,
        )
        .expect("tabs");
        let panes: Vec<ZellijPaneInfo> = serde_json::from_str(
            r#"[{"id":0,"is_plugin":true,"tab_id":0,"exited":false,"terminal_command":null},
                {"id":0,"is_plugin":false,"tab_id":0,"exited":false,"terminal_command":null},
                {"id":1,"is_plugin":true,"tab_id":1,"exited":false,"terminal_command":null},
                {"id":2,"is_plugin":false,"tab_id":2,"exited":false,"terminal_command":null},
                {"id":3,"is_plugin":false,"tab_id":3,"exited":false,"terminal_command":"odin-supervisor-attach 1a2b"},
                {"id":4,"is_plugin":false,"tab_id":4,"exited":true,"exit_status":0,"terminal_command":"odin-supervisor-attach 3c4d"}]"#,
        )
        .expect("panes");
        let stale = |id, name: &str, reason| StaleTab {
            id,
            name: name.to_owned(),
            reason,
        };
        assert_eq!(
            super::stale_odin_tabs(&tabs, &panes),
            [
                stale(
                    1,
                    "odin-kubert-run-browser-probe-once-an",
                    StaleTabReason::NoPane
                ),
                stale(
                    2,
                    "odin-kubert-verify-pods-after-mini-re",
                    StaleTabReason::NoCommand
                ),
                stale(4, "odin-architect-held", StaleTabReason::Exited),
            ]
        );
    }

    #[test]
    fn an_ended_sessions_tab_closes_with_its_client() {
        let action = super::new_pane_arguments(
            7,
            std::path::Path::new("/work"),
            &["odin-supervisor-attach".to_owned(), "session-id".to_owned()],
        );
        let action: Vec<String> = action
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        let separator = action
            .iter()
            .position(|a| a == "--")
            .expect("command separator");
        assert!(action[..separator].contains(&"--close-on-exit".to_owned()));
        assert_eq!(
            &action[separator + 1..],
            [
                "/bin/sh",
                "-c",
                super::AWAIT_REAL_SIZE,
                "odin-supervisor-attach",
                "session-id"
            ]
        );
    }

    /// adversarial-d12: the size gate took the headless 1x1 placeholder for
    /// a real size and launched at once. It waits past 0x0 and 1x1 and
    /// runs the command, arguments intact, at the first real size.
    #[test]
    fn the_pane_command_waits_past_both_placeholder_sizes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("odin-await-size-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let count = dir.join("count");
        let stty = dir.join("stty");
        std::fs::write(
            &stty,
            "#!/bin/sh\nn=$(cat \"$COUNT\" 2>/dev/null || echo 0)\necho $((n+1)) > \"$COUNT\"\n\
             case $n in 0) echo '0 0';; 1) echo '1 1';; *) echo '24 80';; esac\n",
        )
        .expect("stty");
        std::fs::set_permissions(&stty, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let path = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let output = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                super::AWAIT_REAL_SIZE,
                "/bin/sh",
                "-c",
                "cat \"$COUNT\"; echo \"$0\"",
            ])
            .arg("ran")
            .env("PATH", path)
            .env("COUNT", &count)
            .output()
            .expect("run");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(String::from_utf8_lossy(&output.stdout), "3\nran\n");
    }

    /// A long session's full capture past the bound keeps its newest lines
    /// (the current screen) instead of refusing the whole capture.
    #[test]
    fn a_long_capture_keeps_its_newest_lines() {
        let mut text = String::new();
        for line in 0..20_000 {
            text.push_str(&format!("line {line} é\n"));
        }
        text.push_str("prompt> ");
        let tail = super::screen_tail(text.into_bytes()).expect("tail");
        assert!(tail.len() <= super::MAX_TERMINAL_BYTES);
        assert!(tail.starts_with("line "), "cut at a line start");
        assert!(tail.ends_with("line 19999 é\nprompt> "));
        assert_eq!(
            super::screen_tail(b"short\n".to_vec()).expect("short"),
            "short\n"
        );
    }

    /// A session without an attached client is told apart from one with
    /// the hidden operator client (real zellij 0.45 output).
    #[test]
    fn attached_clients_counts_client_rows_only() {
        assert_eq!(
            super::attached_clients(b"CLIENT_ID ZELLIJ_PANE_ID RUNNING_COMMAND\n"),
            0
        );
        assert_eq!(
            super::attached_clients(
                b"CLIENT_ID ZELLIJ_PANE_ID RUNNING_COMMAND\n1         terminal_0     N/A\n"
            ),
            1
        );
        assert_eq!(super::attached_clients(b""), 0);
    }

    #[test]
    fn slug_label_names_by_purpose_not_digest() {
        assert_eq!(
            super::slug_label("sinmara-Execute the delegated task"),
            "sinmara-execute-the-delegated-ta"
        );
        assert_eq!(super::slug_label("Skuld -- CFD sweep!!"), "skuld-cfd-sweep");
        assert_eq!(super::slug_label("   "), "live");
        assert!(super::slug_label(&"x".repeat(100)).len() <= 32);
    }
}

/// The pane lifecycle against a scripted zellij with headless semantics
/// (zellij 0.45, no client attached, observed on pc 10-04): focus-relative
/// actions (`go-to-tab-name`, `close-tab`, `close-pane`/`write`/
/// `dump-screen`/`resize` without `--pane-id`) answer success and never
/// reach a session's pane (they land on the active tab), a command given to
/// `new-tab` is never laid out, `new-pane --tab-id` answers a real pane id,
/// and actions by `--pane-id` or tab id reach exactly that pane or tab.
#[cfg(test)]
mod headless_tests {
    use super::ZellijCliFactory;
    use crate::live::target::TerminalTargetAdmin;
    use odin_domain::huginn::{LiveError, LiveSessionId, SessionEpoch, TerminalSeq};
    use odin_domain::CommandId;
    use std::fs;
    use std::num::NonZeroU16;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    /// `tabs` lines are `id|name|kind`, kind one of `none` (no pane),
    /// `shell` (a bare shell, pane id 100+id) or `live` (a running attach
    /// client, pane id 100+id). `panes` lines are `id|tab|command` for panes
    /// placed by `new-pane`. Input written to pane P lands in `input-P`;
    /// focus-relative input lands in `input-focused`. While a `gate-VERB`
    /// file exists, each `VERB` action touches `entered-VERB` and waits;
    /// a `hold-VERB` file holds each `VERB` action for the seconds it names;
    /// every action past its gate and hold appends `verb args…` to `actions`.
    const SCRIPT: &str = r#"#!/bin/sh
root='ROOT'
tabs="$root/tabs"
panes="$root/panes"
if [ -e "$root/dead" ]; then exit 1; fi
if [ "$1" = list-sessions ]; then printf '%s\n' 'odin [Created 1h ago] '; exit 0; fi
shift 3
verb=$1
shift
if [ -e "$root/gate-$verb" ]; then
  touch "$root/entered-$verb"
  while [ -e "$root/gate-$verb" ]; do sleep 0.01; done
fi
if [ -s "$root/hold-$verb" ]; then sleep "$(cat "$root/hold-$verb")"; fi
printf '%s\n' "$verb $*" >> "$root/actions"
pane=focused
if [ "$1" = --pane-id ]; then pane=$2; shift 2; fi
case "$verb" in
query-tab-names) cut -d'|' -f2 "$tabs" ;;
list-tabs) awk -F'|' 'BEGIN { printf "[" } { if (NR > 1) printf ","; printf "{\"tab_id\":%s,\"name\":\"%s\",\"position\":%d}", $1, $2, NR - 1 } END { print "]" }' "$tabs" ;;
list-panes)
  { awk -F'|' '$3 != "none" { printf "%d|%s|%s\n", 100 + $1, $1, ($3 == "live") ? "odin-supervisor-attach s" : "" }' "$tabs"; cat "$panes"; } |
  awk -F'|' 'BEGIN { printf "["; n = 0 } { if (n++) printf ","; c = $3; gsub(/\\/, "\\\\", c); gsub(/"/, "\\\"", c); command = (c == "") ? "null" : "\"" c "\""; printf "{\"id\":%s,\"is_plugin\":false,\"tab_id\":%s,\"exited\":false,\"terminal_command\":%s}", $1, $2, command } END { print "]" }' ;;
close-tab-by-id)
  awk -F'|' -v id="$1" '$1 != id' "$tabs" > "$tabs.next" && mv "$tabs.next" "$tabs"
  awk -F'|' -v id="$1" '$2 != id' "$panes" > "$panes.next" && mv "$panes.next" "$panes"
  if [ ! -s "$tabs" ]; then touch "$root/dead"; fi ;;
new-tab) last=$(awk -F'|' 'BEGIN { m = 0 } $1 > m { m = $1 } END { print m }' "$tabs"); id=$((last + 1)); printf '%s|%s|none\n' "$id" "$2" >> "$tabs"; printf '%s\n' "$id" ;;
new-pane)
  tab=$2
  while [ "$1" != -- ]; do shift; done
  shift
  count=$(wc -l < "$panes")
  id=$((count + 1))
  printf '%s|%s|%s\n' "$id" "$tab" "$*" >> "$panes"
  printf 'terminal_%s\n' "$id" ;;
write) printf '%s\n' "$*" >> "$root/input-$pane" ;;
dump-screen)
  while [ "$1" != --path ]; do shift; done
  { printf 'screen of %s\n' "$pane"; cat "$root/input-$pane" 2>/dev/null; } > "$2" ;;
resize) printf '%s\n' "$*" >> "$root/resize-$pane" ;;
*) : ;;
esac
"#;

    fn scripted_zellij(root: &Path, tabs: &str) -> PathBuf {
        fs::write(root.join("tabs"), tabs).expect("tabs");
        fs::write(root.join("panes"), "").expect("panes");
        let executable = root.join("zellij");
        fs::write(
            &executable,
            SCRIPT.replace("ROOT", &root.display().to_string()),
        )
        .expect("script");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("chmod");
        executable
    }

    fn factory(root: &Path, executable: &Path) -> ZellijCliFactory {
        factory_timed(root, executable, Duration::from_secs(15))
    }

    fn factory_timed(root: &Path, executable: &Path, timeout: Duration) -> ZellijCliFactory {
        ZellijCliFactory::open(
            executable,
            "odin",
            root.join("terminal-state"),
            timeout,
            NonZeroU16::new(80).expect("columns"),
            NonZeroU16::new(24).expect("rows"),
            crate::process::launch_for_fixture(executable),
        )
        .expect("factory")
        .with_attach_command(vec![
            "odin-supervisor-attach".to_owned(),
            "{session_id}".to_owned(),
        ])
        .expect("attach command")
    }

    async fn open(
        factory: &ZellijCliFactory,
        root: &Path,
        label: &str,
    ) -> std::sync::Arc<super::ZellijLiveAdapter> {
        factory
            .open_terminal(
                LiveSessionId::new(uuid::Uuid::new_v4()).expect("session"),
                SessionEpoch::new(1),
                TerminalSeq::new(0),
                root,
                label,
            )
            .await
            .expect("open terminal")
    }

    fn tab_names(root: &Path) -> Vec<String> {
        fs::read_to_string(root.join("tabs"))
            .expect("tabs")
            .lines()
            .filter_map(|line| line.split('|').nth(1).map(str::to_owned))
            .collect()
    }

    /// Waits until the scripted zellij holds a `verb` action at its gate.
    async fn entered(root: &Path, verb: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !root.join(format!("entered-{verb}")).exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the action reached its gate");
    }

    #[tokio::test]
    async fn captures_list_by_session_and_remove_idempotently() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "0|Tab #1|shell\n");
        let factory = factory(&root, &executable);
        assert!(factory.captured_sessions().await.expect("empty").is_empty());
        let session = LiveSessionId::new(uuid::Uuid::new_v4()).expect("session");
        factory
            .open_terminal(
                session,
                SessionEpoch::new(1),
                TerminalSeq::new(0),
                &root,
                "kubert observe",
            )
            .await
            .expect("open terminal");
        fs::create_dir_all(root.join("terminal-state/terminal/not-a-session")).expect("foreign");
        assert_eq!(
            factory.captured_sessions().await.expect("listed"),
            [session]
        );
        factory
            .remove_session_capture(session)
            .await
            .expect("removed");
        assert!(factory
            .captured_sessions()
            .await
            .expect("listed")
            .is_empty());
        factory
            .remove_session_capture(session)
            .await
            .expect("an absent capture is already removed");
    }

    #[tokio::test]
    async fn stale_tabs_close_once_and_an_ended_sessions_tab_closes() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(
            &root,
            "0|Tab #1|shell\n\
             1|odin-kubert-run-browser-probe-once-an|none\n\
             2|odin-kubert-run-browser-probe-once-an|none\n\
             3|odin-kubert-verify-pods-after-mini-re|shell\n\
             4|odin-kubert-live|live\n",
        );
        let factory = factory(&root, &executable);

        let adapter = open(&factory, &root, "kubert-new run").await;
        assert_eq!(
            tab_names(&root),
            ["Tab #1", "odin-kubert-live", "odin-kubert-new-run"],
            "every stale odin tab closes; the live and foreign tabs stay"
        );

        adapter.terminate_pane().await.expect("terminate");
        assert_eq!(
            tab_names(&root),
            ["Tab #1", "odin-kubert-live"],
            "the ended session's own tab closes at teardown"
        );

        open(&factory, &root, "kubert-other").await;
        assert_eq!(
            tab_names(&root),
            ["Tab #1", "odin-kubert-live", "odin-kubert-other"],
            "nothing stale returns and the live tab is never closed"
        );
    }

    #[tokio::test]
    async fn a_listing_past_the_screen_bound_still_opens_a_tab() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let mut tabs = String::from("0|Tab #1|shell\n");
        for id in 1..=700 {
            tabs.push_str(&format!("{id}|odin-live-{id}|live\n"));
        }
        let executable = scripted_zellij(&root, &tabs);
        let factory = factory(&root, &executable);
        open(&factory, &root, "kubert-busy").await;
        let names = tab_names(&root);
        assert_eq!(names.len(), 702);
        assert_eq!(names.last().map(String::as_str), Some("odin-kubert-busy"));
    }

    #[tokio::test]
    async fn the_operator_session_never_loses_its_last_tab() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(
            &root,
            "0|odin-kubert-launch-arxiv-fludyn-diges|shell\n\
             1|odin-kubert-watch-pc-claude-session|shell\n",
        );
        let factory = factory(&root, &executable);
        let adapter = open(&factory, &root, "reginn-observe").await;
        assert!(
            !root.join("dead").exists(),
            "the session survived the prune"
        );
        assert_eq!(tab_names(&root), ["odin-reginn-observe"]);

        adapter
            .terminate_pane()
            .await
            .expect("terminate the last tab");
        assert!(!root.join("dead").exists(), "the session survived teardown");
        assert_eq!(tab_names(&root), ["operator"]);
    }

    #[tokio::test]
    async fn two_sessions_each_reach_only_their_own_pane() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "0|Tab #1|shell\n");
        let factory = factory(&root, &executable);
        let a = open(&factory, &root, "kubert-session a").await;
        let b = open(&factory, &root, "kubert-session b").await;
        let pane_a = a.pane_for_test();
        let pane_b = b.pane_for_test();

        let operation = CommandId::new("op-write-b").expect("operation");
        pane_b
            .write_input(&operation, b"hi")
            .await
            .expect("write to B");
        let resize = CommandId::new("op-resize-b").expect("operation");
        pane_b
            .resize(
                &resize,
                NonZeroU16::new(100).expect("columns"),
                NonZeroU16::new(24).expect("rows"),
            )
            .await
            .expect("resize B");
        let b_input = fs::read_to_string(root.join("input-terminal_2")).expect("B's input");
        assert_eq!(b_input, "104 105\n", "B's pane received B's bytes");
        assert!(
            !root.join("input-terminal_1").exists(),
            "A's pane is untouched"
        );
        assert!(
            !root.join("input-focused").exists(),
            "nothing goes to whichever pane is focused"
        );
        assert!(root.join("resize-terminal_2").exists(), "B resized by id");
        assert!(!root.join("resize-focused").exists(), "no focused resize");

        let captured = pane_b.capture().await.expect("capture B");
        assert!(
            captured.contents.starts_with("screen of terminal_2"),
            "B's capture is B's own screen: {:?}",
            captured.contents
        );

        // B's pane goes away (its client exited); B never falls back to
        // another pane.
        fs::write(
            root.join("panes"),
            fs::read_to_string(root.join("panes"))
                .expect("panes")
                .lines()
                .filter(|line| !line.starts_with("2|"))
                .map(|line| format!("{line}\n"))
                .collect::<String>(),
        )
        .expect("drop B");
        let refused = pane_b
            .write_input(&CommandId::new("op-write-gone").expect("operation"), b"x")
            .await
            .expect_err("a gone pane is refused");
        assert!(
            matches!(&refused, odin_domain::huginn::LiveError::Unavailable { code } if code == "terminal_pane_unaddressable"),
            "{refused:?}"
        );
        assert!(!root.join("input-focused").exists());
        assert!(!root.join("input-terminal_1").exists());
        drop(pane_a);
    }

    /// Z1: an open abandoned while its attach pane is being placed still
    /// owns the tab it created. Its workflow finishes, then closes that tab
    /// before the next open may act: no attach client outlives its caller
    /// and no later mutation overtakes the cleanup.
    #[tokio::test]
    async fn an_abandoned_open_closes_its_tab_before_the_next_mutation() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "0|Tab #1|shell\n");
        let factory = factory(&root, &executable);
        let gate = root.join("gate-new-pane");
        fs::write(&gate, "").expect("gate");
        let abandoned = {
            let (factory, root) = (factory.clone(), root.clone());
            tokio::spawn(async move { open(&factory, &root, "abandoned").await })
        };
        entered(&root, "new-pane").await;
        abandoned.abort();
        assert!(matches!(abandoned.await, Err(error) if error.is_cancelled()));

        let next = {
            let (factory, root) = (factory.clone(), root.clone());
            tokio::spawn(async move { open(&factory, &root, "next").await })
        };
        fs::remove_file(&gate).expect("release new-pane");
        tokio::time::timeout(Duration::from_secs(30), next)
            .await
            .expect("the next open completes")
            .expect("next open task");

        assert_eq!(
            tab_names(&root),
            ["Tab #1", "odin-next"],
            "the abandoned open's tab is closed"
        );
        let panes = fs::read_to_string(root.join("panes")).expect("panes");
        assert_eq!(
            panes.lines().count(),
            1,
            "no abandoned attach client survives: {panes}"
        );
        let actions = fs::read_to_string(root.join("actions")).expect("actions");
        let at = |prefix: &str| actions.lines().position(|line| line.starts_with(prefix));
        let closed = at("close-tab-by-id 1").expect("the abandoned tab is closed by id");
        let reopened = at("new-tab --name odin-next").expect("the next open's tab");
        assert!(
            closed < reopened,
            "cleanup finishes before the next open acts:\n{actions}"
        );
    }

    /// Z1: a two-axis resize abandoned mid-action still applies both axes
    /// before the pane's tab closes, and a write queued behind it, then
    /// abandoned, never reaches the pane.
    #[tokio::test]
    async fn an_abandoned_resize_finishes_both_axes_before_the_next_mutation() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "0|Tab #1|shell\n");
        let factory = factory(&root, &executable);
        let adapter = open(&factory, &root, "resize").await;
        let pane = adapter.pane_for_test();
        let gate = root.join("gate-resize");
        fs::write(&gate, "").expect("gate");
        let resize = {
            let pane = pane.clone();
            tokio::spawn(async move {
                pane.resize(
                    &CommandId::new("op-resize-abandoned").expect("operation"),
                    NonZeroU16::new(120).expect("columns"),
                    NonZeroU16::new(50).expect("rows"),
                )
                .await
            })
        };
        entered(&root, "resize").await;
        resize.abort();
        assert!(matches!(resize.await, Err(error) if error.is_cancelled()));

        // The abandoned resize still holds the action lock, and acquiring
        // it is a write's first await: one pending poll queues the write
        // on the lock, and dropping it leaves that queue before it starts.
        assert!(
            factory.action_lock.try_lock().is_err(),
            "the abandoned resize keeps its workflow"
        );
        let operation = CommandId::new("op-write-queued").expect("operation");
        let mut queued = pane.write_input(&operation, b"q");
        assert!(futures_util::poll!(queued.as_mut()).is_pending());
        drop(queued);

        fs::remove_file(&gate).expect("release resize");
        adapter
            .terminate_pane()
            .await
            .expect("terminate after the resize");
        assert_eq!(
            fs::read_to_string(root.join("resize-terminal_1")).unwrap_or_default(),
            "increase right\nincrease down\n",
            "both axes apply before the tab closes"
        );
        assert!(
            !root.join("input-terminal_1").exists(),
            "the abandoned queued write never ran"
        );
        assert_eq!(tab_names(&root), ["Tab #1"]);
    }

    /// An abandoned open that found its session's attach client already
    /// running reuses that tab and leaves it standing: cleanup closes only
    /// a tab the abandoned open created.
    #[tokio::test]
    async fn an_abandoned_open_keeps_the_tab_it_reused() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "0|Tab #1|shell\n1|odin-reuse|live\n");
        let factory = factory(&root, &executable);
        let gate = root.join("gate-list-tabs");
        fs::write(&gate, "").expect("gate");
        let abandoned = {
            let (factory, root) = (factory.clone(), root.clone());
            tokio::spawn(async move {
                factory
                    .open_terminal_with(
                        LiveSessionId::new(uuid::Uuid::new_v4()).expect("session"),
                        SessionEpoch::new(1),
                        TerminalSeq::new(0),
                        &root,
                        "reuse",
                        // The fixture's live tab runs exactly this client.
                        Some(vec!["odin-supervisor-attach".to_owned(), "s".to_owned()]),
                    )
                    .await
            })
        };
        entered(&root, "list-tabs").await;
        abandoned.abort();
        assert!(matches!(abandoned.await, Err(error) if error.is_cancelled()));
        fs::remove_file(&gate).expect("release list-tabs");

        // The next open queues behind whatever the abandoned one still owns.
        open(&factory, &root, "next").await;
        assert_eq!(tab_names(&root), ["Tab #1", "odin-reuse", "odin-next"]);
    }

    /// Z1: a started open gets one `command_timeout` in all. Its `new-tab`
    /// and `new-pane` are each held two thirds of it, so each fits alone
    /// but not both: `new-pane` is cut at the workflow deadline instead of
    /// receiving a fresh budget, the open is refused, and the tab it
    /// created is still closed under the rollback's own bounded budget.
    #[tokio::test]
    async fn one_budget_spans_every_action_of_a_started_open() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "0|Tab #1|shell\n");
        let factory = factory_timed(&root, &executable, Duration::from_secs(6));
        fs::write(root.join("hold-new-tab"), "4").expect("hold new-tab");
        fs::write(root.join("hold-new-pane"), "4").expect("hold new-pane");
        let refused = factory
            .open_terminal(
                LiveSessionId::new(uuid::Uuid::new_v4()).expect("session"),
                SessionEpoch::new(1),
                TerminalSeq::new(0),
                &root,
                "budget",
            )
            .await;
        assert!(refused.is_err(), "the open overran its single budget");
        // The rollback holds the action lock until its cleanup ends.
        drop(factory.action_lock.lock().await);
        let actions = fs::read_to_string(root.join("actions")).expect("actions");
        let lines: Vec<&str> = actions.lines().collect();
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("new-tab --name odin-budget")),
            "the first held action fit its share:\n{actions}"
        );
        assert!(
            !lines.iter().any(|line| line.starts_with("new-pane")),
            "the second held action was cut, never completed:\n{actions}"
        );
        assert!(
            lines.contains(&"close-tab-by-id 1"),
            "the created tab was closed by its own cleanup:\n{actions}"
        );
        assert_eq!(tab_names(&root), ["Tab #1"]);
    }

    /// Z1: shutdown reaching the terminals with its deadline already spent
    /// gets an immediate honest miss while an open is held at `new-pane`,
    /// admits no new open, and still leaves the started open its owned
    /// rollback while the process lives; a later drain then proves it ended.
    /// The preexisting live tab of another session is never touched.
    #[tokio::test]
    async fn a_spent_shutdown_deadline_misses_honestly_and_rollback_stays_owned() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "0|Tab #1|shell\n1|odin-reuse|live\n");
        let factory = factory(&root, &executable);
        let gate = root.join("gate-new-pane");
        fs::write(&gate, "").expect("gate");
        let started = {
            let (factory, root) = (factory.clone(), root.clone());
            tokio::spawn(async move {
                let session = LiveSessionId::new(uuid::Uuid::new_v4()).expect("session");
                factory
                    .open_terminal(
                        session,
                        SessionEpoch::new(1),
                        TerminalSeq::new(0),
                        &root,
                        "spent",
                    )
                    .await
                    .map(|_| ())
            })
        };
        entered(&root, "new-pane").await;

        let spent = tokio::time::Instant::now() - Duration::from_millis(1);
        assert!(
            !factory.quiesce_until(spent).await,
            "a started workflow at a spent deadline is a miss, never a drain"
        );
        let late = factory
            .open_terminal(
                LiveSessionId::new(uuid::Uuid::new_v4()).expect("session"),
                SessionEpoch::new(1),
                TerminalSeq::new(0),
                &root,
                "late",
            )
            .await;
        assert!(late.is_err(), "a closed factory admits no new open");
        let drain = tokio::time::Instant::now() + Duration::from_secs(30);
        assert!(factory.quiesce_until(drain).await, "the started open ended");
        fs::remove_file(&gate).expect("release new-pane");
        assert!(
            started.await.expect("open task").is_err(),
            "the open rolled back"
        );

        let actions = fs::read_to_string(root.join("actions")).expect("actions");
        assert!(
            !actions.contains("odin-late"),
            "the refused open took no action:\n{actions}"
        );
        assert!(
            actions.lines().any(|line| line == "close-tab-by-id 2"),
            "the started open closed exactly its own tab:\n{actions}"
        );
        assert_eq!(tab_names(&root), ["Tab #1", "odin-reuse"]);
    }

    #[tokio::test]
    async fn shutdown_closes_new_work_but_retires_owned_panes_before_the_final_drain() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "0|Tab #1|shell\n");
        let factory = factory(&root, &executable);
        let adapter = open(&factory, &root, "retiring").await;
        factory.close();
        let refused = factory
            .open_terminal(
                LiveSessionId::new(uuid::Uuid::new_v4()).expect("session"),
                SessionEpoch::new(1),
                TerminalSeq::new(0),
                &root,
                "late",
            )
            .await;
        assert!(refused.is_err());
        adapter
            .terminate_pane()
            .await
            .expect("owned shutdown retirement");
        assert_eq!(tab_names(&root), ["Tab #1"]);
        assert!(
            factory
                .quiesce_until(tokio::time::Instant::now() + Duration::from_secs(10))
                .await
        );
        assert!(adapter.terminate_pane().await.is_err());
        assert_eq!(tab_names(&root), ["Tab #1"]);
    }

    #[tokio::test]
    async fn mutations_after_a_completed_drain_refuse_without_hanging() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "0|Tab #1|shell\n");
        let factory = factory(&root, &executable);
        let adapter = open(&factory, &root, "drained").await;
        let before = fs::read_to_string(root.join("actions")).expect("actions");
        assert!(
            factory
                .quiesce_until(tokio::time::Instant::now() + Duration::from_secs(10))
                .await
        );
        let refusal = tokio::time::timeout(Duration::from_secs(1), adapter.terminate_pane())
            .await
            .expect("a closed terminal mutation must return, not wait on the completed drain");
        assert!(
            matches!(refusal, Err(LiveError::Unavailable { code }) if code == "zellij_terminals_closed")
        );
        assert_eq!(
            fs::read_to_string(root.join("actions")).expect("actions"),
            before
        );
        assert_eq!(tab_names(&root), ["Tab #1", "odin-drained"]);
    }

    const EXIT_CHILD_ROOT: &str = "ODIN_Z1_DAEMON_EXIT_CHILD_ROOT";

    /// Re-entry for [`a_started_open_rolls_back_before_normal_daemon_exit`]:
    /// a no-op unless that test started this harness as its daemon stand-in.
    /// It ends exactly as odind does (`pc_publish::shutdown_for_publication`):
    /// `shutdown_timeout` for the remaining grace, a runtime-thread count, then
    /// a normal process exit, which ends every thread still running.
    #[test]
    fn daemon_exit_child_entry() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let Some(root) = std::env::var_os(EXIT_CHILD_ROOT) else {
            return;
        };
        let root = PathBuf::from(root);
        let factory = factory(&root, &root.join("zellij"));
        let threads = std::sync::Arc::new(AtomicUsize::new(0));
        let (started, stopped) = (threads.clone(), threads.clone());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .on_thread_start(move || {
                started.fetch_add(1, Ordering::SeqCst);
            })
            .on_thread_stop(move || {
                stopped.fetch_sub(1, Ordering::SeqCst);
            })
            .enable_all()
            .build()
            .expect("runtime");
        let _opening = {
            let (factory, root) = (factory.clone(), root.clone());
            runtime.spawn(async move { open(&factory, &root, "exit").await })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !root.join("entered-new-pane").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "open reached new-pane"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        runtime.shutdown_timeout(Duration::from_secs(2));
        let quiescent = threads.load(Ordering::SeqCst) == 0;
        std::process::exit(if quiescent { 0 } else { 3 });
    }

    /// Z1: an open started in a daemon whose graceful shutdown begins while
    /// the open is held at `new-pane` must have closed the tab it created
    /// before that process exits, and the daemon must find itself quiescent.
    /// The fixture's gate is released only after the process is gone, so
    /// nothing outside the exited daemon can finish its cleanup for it.
    #[test]
    fn a_started_open_rolls_back_before_normal_daemon_exit() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        scripted_zellij(&root, "0|Tab #1|shell\n");
        let gate = root.join("gate-new-pane");
        fs::write(&gate, "").expect("gate");
        // The child's registered-worker fixture roots stay in this tempdir.
        let fixture_tmp = root.join("tmp");
        fs::create_dir(&fixture_tmp).expect("child tmp");
        let mut child = std::process::Command::new(std::env::current_exe().expect("harness"))
            .args([
                "--exact",
                "live::zellij::cli::headless_tests::daemon_exit_child_entry",
                "--test-threads",
                "1",
                "--nocapture",
            ])
            .env(EXIT_CHILD_ROOT, &root)
            .env("TMPDIR", &fixture_tmp)
            .spawn()
            .expect("daemon stand-in");
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        let status = loop {
            if let Some(status) = child.try_wait().expect("daemon stand-in wait") {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the daemon stand-in never exited");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        // Observed before the gate opens: only the exited daemon's own work.
        let tabs = tab_names(&root);
        let panes = fs::read_to_string(root.join("panes")).expect("panes");
        fs::remove_file(&gate).expect("release new-pane");
        assert_eq!(
            tabs,
            ["Tab #1"],
            "process exit abandoned the started open's own tab"
        );
        assert_eq!(panes, "", "no attach pane outlived the daemon");
        assert!(
            status.success(),
            "the daemon stand-in exited non-quiescent: {status}"
        );
    }

    /// Z1: runtime shutdown as odind ends (`shutdown_timeout`) drops the
    /// caller of an open held at its `new-pane` action, yet the started
    /// workflow keeps running on its blocking thread: once the fixture
    /// releases, it finishes, closes exactly the tab it created, leaves the
    /// preexisting live tab standing, and only then frees the action lock.
    #[test]
    fn a_started_open_rolls_back_through_runtime_shutdown() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "0|Tab #1|shell\n1|odin-reuse|live\n");
        let factory = factory(&root, &executable);
        let gate = root.join("gate-new-pane");
        fs::write(&gate, "").expect("gate");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let _opening = {
            let (factory, root) = (factory.clone(), root.clone());
            runtime.spawn(async move { open(&factory, &root, "shutdown").await })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(40);
        let wait = |done: &dyn Fn() -> bool, what: &str| {
            while !done() {
                assert!(std::time::Instant::now() < deadline, "{what}");
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        wait(
            &|| root.join("entered-new-pane").exists(),
            "open reached new-pane",
        );
        runtime.shutdown_timeout(Duration::from_millis(100));
        fs::remove_file(&gate).expect("release new-pane");

        wait(
            &|| factory.action_lock.try_lock().is_ok(),
            "the workflow ends",
        );
        assert_eq!(
            tab_names(&root),
            ["Tab #1", "odin-reuse"],
            "only the tab the open created is closed"
        );
        assert_eq!(
            fs::read_to_string(root.join("panes")).expect("panes"),
            "",
            "its attach pane went with it"
        );
    }
}
