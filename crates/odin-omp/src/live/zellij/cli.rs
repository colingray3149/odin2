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
    /// The hub prefix (`hub.<host>`): every seat terminal is its own
    /// session `<hub>.<label>`, which every device's `odin hub` shows.
    hub: Arc<str>,
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
    /// Whether new sessions start in their own user scope (always, outside
    /// tests).
    scoped: bool,
}

const MAX_ATTACH_ARGS: usize = 64;
const MAX_ATTACH_ARG_BYTES: usize = 4096;

impl ZellijCliFactory {
    pub fn open(
        executable: impl AsRef<Path>,
        hub: impl Into<String>,
        state_root: impl AsRef<Path>,
        command_timeout: StdDuration,
        initial_columns: NonZeroU16,
        initial_rows: NonZeroU16,
        worker: OmpWorkerLaunch,
    ) -> Result<Self, LiveError> {
        if command_timeout.is_zero() {
            return Err(invalid_terminal("zellij command timeout must be positive"));
        }
        let hub = hub.into();
        // An empty prefix leaves seat terminals undeclared (refused at open).
        if !hub.is_empty() {
            validate_target_name(&hub).map_err(|error| {
                invalid_terminal(format!("zellij hub prefix is invalid: {error}"))
            })?;
        }
        let executable = executable.as_ref().to_path_buf();
        if !executable.is_file() {
            return Err(invalid_terminal("zellij executable is not a regular file"));
        }
        fs::create_dir_all(state_root.as_ref()).map_err(io_error)?;
        let state_root = state_root.as_ref().canonicalize().map_err(io_error)?;
        Ok(Self {
            executable: Arc::new(executable),
            hub: Arc::from(hub),
            targets: TerminalTargetRegistry::new(),
            state_root: Arc::new(state_root),
            command_timeout,
            initial_columns,
            initial_rows,
            action_lock: Arc::new(Mutex::new(())),
            closing: Arc::new(AtomicBool::new(false)),
            drained: Arc::new(std::sync::OnceLock::new()),
            worker,
            attach_command: None,
            scoped: true,
        })
    }

    /// Tests start their scripted sessions without a systemd scope.
    #[cfg(test)]
    fn unscoped(mut self) -> Self {
        self.scoped = false;
        self
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
        let text = std::str::from_utf8(&output).map_err(|error| {
            unavailable(format!("zellij list-sessions output is not UTF-8: {error}"))
        })?;
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
        if self.hub.is_empty() {
            return Err(LiveError::unavailable(
                "terminal_hub_undeclared",
                "executables.zellij_hub is not declared",
            ));
        }
        let template = self.attach_command.as_ref().ok_or_else(|| {
            LiveError::unavailable(
                "terminal_attach_command_unconfigured",
                "this adapter has no attach command",
            )
        })?;
        let session_token = session_id.to_string();
        let attach_command: Vec<String> = attach.unwrap_or_else(|| {
            template
                .iter()
                .map(|argument| argument.replace(ATTACH_SESSION_PLACEHOLDER, &session_token))
                .collect()
        });
        // The session is named by seat + purpose (the caller's label,
        // slugified and bounded) for the operator, plus the session id's
        // last six characters, so two sessions never share a name; identity
        // stays on the pane's attach command, which carries the session id.
        let short_id = &session_token[session_token.len().saturating_sub(6)..];
        let session_name = format!("{}.{}-{short_id}", self.hub, slug_label(tab_label));
        // Whichever side decides first wins the handover: the caller taking
        // the adapter, or the workflow refusing it. A caller dropped first
        // (cancelled, or its task dropped by runtime shutdown) refuses it
        // through its claim, which also cuts the open's ordinary actions.
        let handover = Arc::new(AtomicU8::new(HANDOVER_PENDING));
        let claim = HandoverClaim(Arc::clone(&handover));
        let pane = ZellijCliPane {
            executable: Arc::clone(&self.executable),
            session_name: Arc::from(session_name),
            capture_root: Arc::clone(&self.state_root),
            command_timeout: self.command_timeout,
            dimensions: Arc::new(RwLock::new((self.initial_columns, self.initial_rows))),
            action_lock: Arc::clone(&self.action_lock),
            closing: Arc::clone(&self.closing),
            drained: Arc::clone(&self.drained),
            worker: self.worker.clone(),
            attach_command: Arc::new(attach_command),
            scoped: self.scoped,
            target: Arc::new(std::sync::OnceLock::new()),
            created: Arc::new(std::sync::OnceLock::new()),
            deadline: None,
            handover: Some(Arc::clone(&handover)),
        };
        let cwd = cwd.to_path_buf();
        let capture_root = self.capture_root();
        let (accepted, acceptance) = std::sync::mpsc::channel::<()>();
        // Hold the action lock through completion or rollback, even if the caller leaves.
        let adapter = pane
            .owned(TerminalWork::Ordinary, move |pane, reply| {
                let result = pane.ensure_session(&cwd).and_then(|()| {
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
                    // an abandoned or expired open still ends exactly the
                    // session it created.
                    if let Err(error) = pane.cleanup().end_created_session() {
                        tracing::error!(
                            "odin-omp: zellij could not end unopened session={}: {error}",
                            pane.session_name
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
            Err(unavailable(
                "the open workflow stopped waiting and rolled back",
            ))
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
        // capture is the bounded viewport: `--full` would read unbounded history.
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
        let bytes = dumped_bytes(&path, direct_output)?;
        // A pathological capture is cut char-safely at the hard cap and reported through
        // the same `truncated` flag; the caller's maxBytes budget applies afterwards.
        let contents = String::from_utf8(bytes)
            .map_err(|error| invalid_terminal(format!("non-UTF-8 terminal: {error}")))?;
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
    /// This pane's own session, `<hub>.<label>`.
    session_name: Arc<str>,
    capture_root: Arc<PathBuf>,
    command_timeout: StdDuration,
    dimensions: Arc<RwLock<(NonZeroU16, NonZeroU16)>>,
    action_lock: Arc<Mutex<()>>,
    /// The factory's shutdown admission flag.
    closing: Arc<AtomicBool>,
    /// Seals all work after the factory's final drain, including retirement.
    drained: Arc<std::sync::OnceLock<()>>,
    worker: OmpWorkerLaunch,
    /// Concrete governed attach-client argv for this session's pane.
    attach_command: Arc<Vec<String>>,
    scoped: bool,
    /// The pane this session's attach client runs in, set once by
    /// [`Self::ensure_session`]. Every later action names this pane by id.
    target: Arc<std::sync::OnceLock<u64>>,
    /// Set when [`Self::create_session`] started the session: an abandoned
    /// or failed open ends only a session it created, never a reused one.
    created: Arc<std::sync::OnceLock<()>>,
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

/// The refusal code of a terminal whose pane is closed or gone.
pub const PANE_UNADDRESSABLE: &str = "terminal_pane_unaddressable";

fn pane_unaddressable() -> LiveError {
    LiveError::unavailable(PANE_UNADDRESSABLE, "the terminal pane is closed or gone")
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
        receive.await.map_err(unavailable)?
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

    /// Reuses this session when its pane still runs this attach client;
    /// otherwise (gone, ended, or an earlier client of this same session,
    /// whose id the name carries, which this open supersedes) starts it
    /// afresh. Caller holds the action lock.
    fn ensure_session(&self, cwd: &Path) -> Result<(), LiveError> {
        let running = if self.session_live()? {
            self.own_pane()?
        } else {
            None
        };
        let pane = match running {
            Some(pane) => pane,
            None => {
                self.end_session()?;
                let pane = self.create_session(cwd)?;
                tracing::info!(
                    "odin-omp: zellij opened session={} pane=terminal_{pane}",
                    self.session_name
                );
                pane
            }
        };
        let _ = self.target.set(pane);
        Ok(())
    }

    fn session_live(&self) -> Result<bool, LiveError> {
        let output = self.run(
            &self.executable,
            vec!["list-sessions".into(), "--no-formatting".into()],
        )?;
        let text = String::from_utf8_lossy(&output);
        Ok(parse_live_sessions(&text)
            .iter()
            .any(|name| name == self.session_name.as_ref()))
    }

    /// The live pane running exactly this session's attach client (its argv
    /// carries the live session id), if any.
    fn own_pane(&self) -> Result<Option<u64>, LiveError> {
        let command = self.attach_command.join(" ");
        Ok(self
            .list_panes()?
            .into_iter()
            .find(|pane| {
                !pane.is_plugin
                    && !pane.exited
                    && pane
                        .terminal_command
                        .as_deref()
                        .is_some_and(|running| running.ends_with(command.as_str()))
            })
            .map(|pane| pane.id))
    }

    /// Starts the session in the background with one pane running the
    /// attach client; the pane closes on exit and so ends the session. The
    /// server runs in its own user scope: each zellij action is a unit that
    /// is stopped when it returns, and would take the server with it.
    fn create_session(&self, cwd: &Path) -> Result<u64, LiveError> {
        if self.abandoned() {
            return Err(open_abandoned());
        }
        let layout = self
            .capture_root
            .join(format!(".layout-{}.kdl", Uuid::new_v4()));
        fs::write(&layout, pane_layout(cwd, &self.attach_command)).map_err(io_error)?;
        // A started create is never cut: rollback must see the session it made.
        let uncut = ZellijCliPane {
            handover: None,
            ..self.clone()
        };
        let _ = self.created.set(());
        let attach = vec![
            "attach".to_owned(),
            "--create-background".to_owned(),
            self.session_name.to_string(),
            "options".to_owned(),
            "--default-layout".to_owned(),
            layout.to_string_lossy().into_owned(),
            "--session-serialization".to_owned(),
            "false".to_owned(),
            "--pane-frames".to_owned(),
            "false".to_owned(),
        ];
        let started = if self.scoped {
            uncut.start_scoped(attach)
        } else {
            uncut.run(&self.executable, attach).map(|_| ())
        };
        let _ = fs::remove_file(&layout);
        started?;
        // The server lays the pane out just after the client returns. A poll never starts on
        // less than one interval of budget, so a spent budget reads as the timeout it is.
        let mut listed = false;
        while self.remaining() > SESSION_POLL {
            let polled = self.session_live().and_then(|live| {
                listed |= live;
                if live {
                    self.own_pane()
                } else {
                    Ok(None)
                }
            });
            match polled {
                Ok(Some(pane)) => return Ok(pane),
                Ok(None) => {}
                // A poll the budget ran out under is the timeout, not its own failure.
                Err(error) if self.remaining() > SESSION_POLL => return Err(error),
                Err(_) => break,
            }
            std::thread::sleep(SESSION_POLL);
        }
        // The pane closes with its client, and the session with the pane: a session that was
        // listed but lost its pane saw the client start and die.
        Err(unavailable(if listed {
            format!(
                "zellij session {} came up but no pane runs its attach client; the client \
                 exited as it started",
                self.session_name
            )
        } else {
            format!(
                "zellij session {} never came up after `attach --create-background`; its \
                 attach client exited at once or the server did not start",
                self.session_name
            )
        }))
    }

    /// Runs `systemd-run --user --scope -- zellij attach …` directly: the
    /// registered action launcher runs only the bound zellij binary, and its
    /// unit is stopped when the action returns, server and all. The scope
    /// keeps the server; the client returns once the session exists.
    fn start_scoped(&self, attach: Vec<String>) -> Result<(), LiveError> {
        let mut child = std::process::Command::new("systemd-run")
            .args(["--user", "--scope", "--quiet", "--collect", "--"])
            .arg(self.executable.as_os_str())
            .args(&attach)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|error| unavailable(format!("systemd-run could not start: {error}")))?;
        let deadline = std::time::Instant::now() + self.remaining();
        loop {
            if let Some(status) = child.try_wait().map_err(io_error)? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(unavailable(format!(
                        "zellij could not start session {}: systemd-run {status}",
                        self.session_name
                    )))
                };
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(unavailable(format!(
                    "zellij did not start session {} within the workflow budget",
                    self.session_name
                )));
            }
            std::thread::sleep(SESSION_POLL);
        }
    }

    /// Ends this session if it is live and clears an ended one, so a new
    /// start never resurrects it.
    fn end_session(&self) -> Result<(), LiveError> {
        if self.session_live()? {
            self.run(
                &self.executable,
                vec!["kill-session".into(), self.session_name.to_string()],
            )?;
        }
        // Absent is the usual answer here, so its refusal says nothing.
        let _ = self.run(
            &self.executable,
            vec!["delete-session".into(), self.session_name.to_string()],
        );
        Ok(())
    }

    /// Re-lists panes before acting because zellij reports success for
    /// unknown IDs; pane ids restart in every session, so the pane must
    /// still run this attach client. Caller holds the action lock.
    fn live_target(&self) -> Result<u64, LiveError> {
        let target = *self.target.get().ok_or_else(pane_unaddressable)?;
        if self.own_pane()? == Some(target) {
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
        action.push(OsString::from(format!("terminal_{target}")));
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

    /// Runs `zellij --session <this session> action …`.
    fn invoke(&self, action: &[OsString]) -> Result<Vec<u8>, LiveError> {
        let mut args: Vec<String> = Vec::with_capacity(action.len().saturating_add(3));
        args.push("--session".to_owned());
        args.push(self.session_name.to_string());
        args.push("action".to_owned());
        args.extend(
            action
                .iter()
                .map(|value| value.to_string_lossy().into_owned()),
        );
        self.run(&self.executable, args)
    }

    /// Runs `program args…` within the remaining workflow budget, stopping
    /// it if abandoned.
    fn run(&self, program: &Path, args: Vec<String>) -> Result<Vec<u8>, LiveError> {
        let budget = self.remaining().min(self.command_timeout);
        if budget.is_zero() {
            return Err(LiveError::unavailable(
                "zellij_workflow_deadline",
                "the workflow budget is spent",
            ));
        }
        if self.abandoned() {
            return Err(open_abandoned());
        }
        run_zellij_blocking(
            program,
            &self.worker,
            &self.capture_root,
            budget,
            args,
            &|| self.abandoned(),
        )
    }
}

fn open_abandoned() -> LiveError {
    LiveError::unavailable("zellij_open_abandoned", "the caller abandoned the open")
}

fn terminals_closed() -> LiveError {
    LiveError::unavailable("zellij_terminals_closed", "this pane admits no more work")
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
        let contents = capture_tail(dumped_bytes(&path, direct_output)?)?;
        let (columns, rows) = *self.dimensions.read();
        // A screen dump carries no cursor; none is claimed.
        let cursor = TerminalCursor {
            row: 0,
            column: 0,
            visible: false,
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

    /// Ends this session while its pane still runs this attach client; a
    /// session a later open took over under the same name stays.
    async fn terminate(&self) -> Result<(), LiveError> {
        self.owned(TerminalWork::Retirement, |pane, reply| {
            let result = match pane.target.get() {
                Some(_) => pane.end_own_session(),
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
            // Each axis is recorded as it lands: a retry after the first must not repeat it.
            self.dimensions.write().0 = columns;
        }
        if current.1 != rows {
            let change = if rows > current.1 {
                "increase"
            } else {
                "decrease"
            };
            self.pane_action_locked("resize", &[OsString::from(change), OsString::from("down")])?;
            self.dimensions.write().1 = rows;
        }
        Ok(())
    }

    /// Ends the session an abandoned or failed open created, if any; a
    /// reused session stays. Caller holds the lock.
    fn end_created_session(&self) -> Result<(), LiveError> {
        if self.created.get().is_some() {
            self.end_session()?;
        }
        Ok(())
    }

    /// Caller holds the action lock.
    fn end_own_session(&self) -> Result<(), LiveError> {
        if self.session_live()? && self.own_pane()?.is_some() {
            self.end_session()?;
            tracing::info!("odin-omp: zellij ended session={}", self.session_name);
        }
        Ok(())
    }
}

/// Polling interval while a new session lays out its pane.
const SESSION_POLL: StdDuration = StdDuration::from_millis(50);

/// The one-pane layout of a seat session: the attach client in `cwd`,
/// closing (and so ending the session) when the client exits.
fn pane_layout(cwd: &Path, attach_command: &[String]) -> String {
    let quote = |value: &str| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""));
    let (program, args) = attach_command
        .split_first()
        .map_or(("", &[][..]), |(p, a)| (p.as_str(), a));
    let args: Vec<String> = args.iter().map(|arg| quote(arg)).collect();
    format!(
        "layout {{\n    pane command={} cwd={} close_on_exit=true {{\n        args {};\n    }}\n}}\n",
        quote(program),
        quote(&cwd.to_string_lossy()),
        args.join(" ")
    )
}

/// What `dump-screen --path` produced: the file it wrote (removed once read), or the
/// action's own output when it wrote none.
fn dumped_bytes(path: &Path, direct_output: Vec<u8>) -> Result<Vec<u8>, LiveError> {
    if !path.try_exists().unwrap_or(false) {
        return Ok(direct_output);
    }
    let bytes = fs::read(path).map_err(io_error)?;
    let _ = fs::remove_file(path);
    Ok(bytes)
}

/// The newest [`MAX_TERMINAL_BYTES`] of a `dump-screen --full` capture,
/// cut at a line start. A live pane (now laid out at a real size) keeps
/// growing scrollback; refusing past the bound would blind every reader of
/// a long session, while its tail always holds the current screen.
fn capture_tail(bytes: Vec<u8>) -> Result<String, LiveError> {
    let contents = String::from_utf8(bytes)
        .map_err(|error| invalid_terminal(format!("non-UTF-8 terminal: {error}")))?;
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

/// One pane of `zellij action list-panes --all --json`.
#[derive(Debug, Deserialize)]
struct ZellijPaneInfo {
    id: u64,
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

/// Longest session-name slug a label contributes.
const SLUG_MAX_CHARS: usize = 32;

/// Bounded, zellij-safe label slug: lowercase alphanumerics and single
/// dashes; everything else collapses to one dash; never empty, never
/// longer than [`SLUG_MAX_CHARS`].
fn slug_label(label: &str) -> String {
    let mut slug = String::with_capacity(SLUG_MAX_CHARS);
    let mut dash = false;
    for character in label.chars() {
        if character.is_ascii_alphanumeric() {
            if dash && !slug.is_empty() {
                slug.push('-');
            }
            dash = false;
            slug.push(character.to_ascii_lowercase());
            if slug.len() >= SLUG_MAX_CHARS {
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
mod slug_tests {}

/// The pane lifecycle against a scripted zellij with per-session semantics
/// (zellij 0.45): `attach --create-background` starts a session whose one
/// pane runs its layout's command, pane ids restart at 0 in every session,
/// and actions by `--session` and `--pane-id` reach exactly that pane.
#[cfg(test)]
mod session_tests {
    use super::ZellijCliFactory;
    use crate::live::target::TerminalTargetAdmin;
    use odin_domain::huginn::{LiveError, LiveSessionId, SessionEpoch, TerminalSeq};
    use odin_domain::CommandId;
    use std::fs;
    use std::num::NonZeroU16;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    /// `sessions` lines are `name|command` (the command of the session's
    /// pane 0). Input written to session S's pane P lands in `input-S-P`.
    /// While a `gate-VERB` file exists, each `VERB` touches `entered-VERB`
    /// and waits; a `hold-VERB` file holds each `VERB` for the seconds it
    /// names; every run past its gate and hold appends `verb args…` to
    /// `actions`.
    const SCRIPT: &str = r#"#!/bin/sh
root='ROOT'
sessions="$root/sessions"
session=
if [ "$1" = --session ]; then session=$2; shift 3; fi
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
list-sessions) cut -d'|' -f1 "$sessions" | sed 's/$/ [Created 1h ago] /' ;;
attach)
  command=$(grep -o '"[^"]*"' "$5" | sed '2d' | tr -d '"' | tr '\n' ' ' | sed 's/ $//')
  printf '%s|%s\n' "$2" "$command" >> "$sessions" ;;
kill-session) awk -F'|' -v s="$1" '$1 != s' "$sessions" > "$sessions.next" && mv "$sessions.next" "$sessions" ;;
list-panes)
  awk -F'|' -v s="$session" 'BEGIN { printf "[" } $1 == s { c = ($2 == "") ? "null" : "\"" $2 "\""; printf "{\"id\":0,\"is_plugin\":false,\"exited\":false,\"terminal_command\":%s}", c } END { print "]" }' "$sessions" ;;
write) printf '%s\n' "$*" >> "$root/input-$session-$pane" ;;
dump-screen)
  while [ "$1" != --path ]; do shift; done
  { printf 'screen of %s %s\n' "$session" "$pane"; cat "$root/input-$session-$pane" 2>/dev/null || true; } > "$2" ;;
resize) printf '%s\n' "$*" >> "$root/resize-$session-$pane" ;;
*) : ;;
esac
"#;

    fn scripted_zellij(root: &Path, sessions: &str) -> PathBuf {
        fs::write(root.join("sessions"), sessions).expect("sessions");
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
            "hub.test",
            root.join("terminal-state"),
            timeout,
            NonZeroU16::new(80).expect("columns"),
            NonZeroU16::new(24).expect("rows"),
            crate::process::launch_for_fixture(executable),
        )
        .expect("factory")
        .unscoped()
        .with_attach_command(vec![
            "odin-supervisor-attach".to_owned(),
            "{session_id}".to_owned(),
        ])
        .expect("attach command")
    }

    /// Session ids ending in these six characters name `<label>-a00001`, `-b00002`.
    const SESSION_A: &str = "8f9c2ee3-85ec-46e9-a43a-a2cd06a00001";
    const SESSION_B: &str = "8f9c2ee3-85ec-46e9-a43a-a2cd06b00002";

    async fn open(
        factory: &ZellijCliFactory,
        root: &Path,
        label: &str,
        session: &str,
    ) -> std::sync::Arc<super::ZellijLiveAdapter> {
        factory
            .open_terminal(
                LiveSessionId::parse(session).expect("session"),
                SessionEpoch::new(1),
                TerminalSeq::new(0),
                root,
                label,
            )
            .await
            .expect("open terminal")
    }

    fn session_names(root: &Path) -> Vec<String> {
        fs::read_to_string(root.join("sessions"))
            .expect("sessions")
            .lines()
            .filter_map(|line| line.split('|').next().map(str::to_owned))
            .collect()
    }

    fn actions(root: &Path) -> String {
        fs::read_to_string(root.join("actions")).unwrap_or_default()
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

    /// The operator's terminal is read only from the registered live session, within the
    /// caller's byte budget, and a dead or foreign selector is a typed miss.
    #[tokio::test]
    async fn the_operator_terminal_screen_is_read_bounded_from_the_registered_session_only() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "operator|\nother|\n");
        let factory = factory(&root, &executable);

        let unbound = factory.capture_screen("operator", 1024).await;
        assert!(matches!(
            unbound,
            Err(LiveError::Unavailable { ref code, .. }) if code == "terminal_target_unbound"
        ));
        factory
            .register_chat_target("operator".to_owned())
            .await
            .expect("register");

        let whole = factory
            .capture_screen("operator", 1024)
            .await
            .expect("whole");
        assert_eq!(whole.content, "screen of operator focused\n");
        assert!(!whole.truncated);
        let cut = factory.capture_screen("operator", 6).await.expect("cut");
        assert_eq!((cut.content.as_str(), cut.truncated), ("screen", true));

        let foreign = factory.capture_screen("other", 1024).await;
        assert!(matches!(foreign, Err(LiveError::NotFound { .. })));
        let no_budget = factory.capture_screen("operator", 0).await;
        assert!(matches!(no_budget, Err(LiveError::InvalidRequest { .. })));

        fs::write(root.join("sessions"), "other|\n").expect("the operator session ends");
        let gone = factory.capture_screen("operator", 1024).await;
        assert!(matches!(gone, Err(LiveError::NotFound { .. })));
    }

    #[tokio::test]
    async fn captures_list_by_session_and_remove_idempotently() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "");
        let factory = factory(&root, &executable);
        assert!(factory.captured_sessions().await.expect("empty").is_empty());
        let session = LiveSessionId::parse(SESSION_B).expect("session");
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

    /// Two sessions with one label each get their own hub session (the name
    /// carries the session id); retiring one leaves the other standing.
    #[tokio::test]
    async fn sessions_sharing_a_label_never_share_a_hub_session() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "");
        let factory = factory(&root, &executable);
        let first = open(&factory, &root, "sinmara", SESSION_A).await;
        let second = open(&factory, &root, "sinmara", SESSION_B).await;
        assert_eq!(
            session_names(&root),
            ["hub.test.sinmara-a00001", "hub.test.sinmara-b00002"]
        );
        first.terminate_pane().await.expect("retire the first");
        assert_eq!(
            session_names(&root),
            ["hub.test.sinmara-b00002"],
            "the other stays"
        );
        second.terminate_pane().await.expect("retire the second");
        assert!(session_names(&root).is_empty());
    }

    #[tokio::test]
    async fn two_sessions_each_reach_only_their_own_pane() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "");
        let factory = factory(&root, &executable);
        let _a = open(&factory, &root, "kubert-session a", SESSION_A).await;
        let b = open(&factory, &root, "kubert-session b", SESSION_B).await;
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
        let b_input =
            fs::read_to_string(root.join("input-hub.test.kubert-session-b-b00002-terminal_0"))
                .expect("B's input");
        assert_eq!(b_input, "104 105\n", "B's pane received B's bytes");
        assert!(
            !root
                .join("input-hub.test.kubert-session-a-a00001-terminal_0")
                .exists(),
            "A's pane is untouched"
        );
        assert!(root
            .join("resize-hub.test.kubert-session-b-b00002-terminal_0")
            .exists());

        let captured = pane_b.capture().await.expect("capture B");
        assert!(
            captured
                .contents
                .starts_with("screen of hub.test.kubert-session-b-b00002 terminal_0"),
            "B's capture is B's own screen: {:?}",
            captured.contents
        );

        // B's session ends (its client exited); B never falls back to
        // another session.
        fs::write(
            root.join("sessions"),
            "hub.test.kubert-session-a-a00001|x\n",
        )
        .expect("drop B");
        let refused = pane_b
            .write_input(&CommandId::new("op-write-gone").expect("operation"), b"x")
            .await
            .expect_err("a gone pane is refused");
        assert!(
            matches!(&refused, LiveError::Unavailable { code, .. } if code == "terminal_pane_unaddressable"),
            "{refused:?}"
        );
    }

    /// An open abandoned while its session is being laid out still owns
    /// the session it created. Its workflow finishes, then ends that
    /// session before the next open may act.
    #[tokio::test]
    async fn an_abandoned_open_ends_its_session_before_the_next_mutation() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "");
        let factory = factory(&root, &executable);
        let gate = root.join("gate-list-panes");
        fs::write(&gate, "").expect("gate");
        let abandoned = {
            let (factory, root) = (factory.clone(), root.clone());
            tokio::spawn(async move { open(&factory, &root, "abandoned", SESSION_A).await })
        };
        entered(&root, "list-panes").await;
        abandoned.abort();
        assert!(matches!(abandoned.await, Err(error) if error.is_cancelled()));

        let next = {
            let (factory, root) = (factory.clone(), root.clone());
            tokio::spawn(async move { open(&factory, &root, "next", SESSION_A).await })
        };
        fs::remove_file(&gate).expect("release list-panes");
        tokio::time::timeout(Duration::from_secs(30), next)
            .await
            .expect("the next open completes")
            .expect("next open task");

        assert_eq!(session_names(&root), ["hub.test.next-a00001"]);
        let actions = actions(&root);
        let at = |prefix: &str| actions.lines().position(|line| line.starts_with(prefix));
        let ended =
            at("kill-session hub.test.abandoned-a00001").expect("the abandoned session ends");
        let started = at("attach --create-background hub.test.next-a00001").expect("the next open");
        assert!(
            ended < started,
            "cleanup finishes before the next open acts:\n{actions}"
        );
    }

    /// An open whose attach client dies names what it saw. `patch` makes the stand-in client die
    /// (the `attach)` arm) or list the session with no pane. The budget is wall-clock, so the
    /// listing case gets enough of it for a loaded machine to reach its first poll.
    async fn dead_attach_client_open(patch: &str, budget: Duration) -> String {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "");
        let script = fs::read_to_string(&executable).expect("script");
        let patched = if patch.starts_with("attach)") {
            script.replacen("attach)\n", patch, 1)
        } else {
            script.replacen(patch, "printf '%s|\\n' \"$2\" >> \"$sessions\"", 1)
        };
        assert_ne!(script, patched, "the stand-in script took the patch");
        fs::write(&executable, patched).expect("patched script");
        factory_timed(&root, &executable, budget)
            .open_terminal(
                LiveSessionId::parse(SESSION_B).expect("session"),
                SessionEpoch::new(1),
                TerminalSeq::new(0),
                &root,
                "dead",
            )
            .await
            .err()
            .expect("a dead attach client refuses the open")
            .to_string()
    }

    #[tokio::test]
    async fn an_attach_client_that_dies_before_the_session_lists_never_came_up() {
        let refused =
            dead_attach_client_open("attach) : ;;\nattach-unused)\n", Duration::from_secs(1)).await;
        assert!(refused.contains("never came up"), "{refused}");
    }

    #[tokio::test]
    async fn an_attach_client_that_dies_after_the_session_lists_leaves_no_pane() {
        let refused = dead_attach_client_open(
            "printf '%s|%s\\n' \"$2\" \"$command\" >> \"$sessions\"",
            Duration::from_secs(3),
        )
        .await;
        assert!(
            refused.contains("no pane runs its attach client"),
            "{refused}"
        );
    }

    /// Shutdown reaching the terminals with its deadline already spent
    /// gets an immediate honest miss while an open is held at its layout
    /// poll, admits no new open, and still leaves the started open its
    /// owned rollback while the process lives; a later drain then proves it
    /// ended. Another live session is never touched.
    #[tokio::test]
    async fn a_spent_shutdown_deadline_misses_honestly_and_rollback_stays_owned() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let executable = scripted_zellij(&root, "hub.test.reuse-b00002|odin-supervisor-attach s\n");
        let factory = factory(&root, &executable);
        let gate = root.join("gate-list-panes");
        fs::write(&gate, "").expect("gate");
        let started = {
            let (factory, root) = (factory.clone(), root.clone());
            tokio::spawn(async move {
                let session = LiveSessionId::parse(SESSION_B).expect("session");
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
        entered(&root, "list-panes").await;

        let spent = tokio::time::Instant::now() - Duration::from_millis(1);
        assert!(
            !factory.quiesce_until(spent).await,
            "a started workflow at a spent deadline is a miss, never a drain"
        );
        let late = factory
            .open_terminal(
                LiveSessionId::parse(SESSION_B).expect("session"),
                SessionEpoch::new(1),
                TerminalSeq::new(0),
                &root,
                "late",
            )
            .await;
        assert!(late.is_err(), "a closed factory admits no new open");
        let drain = tokio::time::Instant::now() + Duration::from_secs(30);
        assert!(factory.quiesce_until(drain).await, "the started open ended");
        fs::remove_file(&gate).expect("release list-panes");
        assert!(
            started.await.expect("open task").is_err(),
            "the open rolled back"
        );

        let actions = actions(&root);
        assert!(
            !actions.contains("hub.test.late-b00002"),
            "the refused open took no action:\n{actions}"
        );
        assert!(
            actions
                .lines()
                .any(|line| line == "kill-session hub.test.spent-b00002"),
            "the started open ended exactly its own session:\n{actions}"
        );
        assert_eq!(session_names(&root), ["hub.test.reuse-b00002"]);
    }

    const EXIT_CHILD_ROOT: &str = "ODIN_DAEMON_EXIT_CHILD_ROOT";

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
            runtime.spawn(async move { open(&factory, &root, "exit", SESSION_A).await })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !root.join("entered-list-panes").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "open reached its layout poll"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        runtime.shutdown_timeout(Duration::from_secs(2));
        let quiescent = threads.load(Ordering::SeqCst) == 0;
        std::process::exit(if quiescent { 0 } else { 3 });
    }

    /// An open started in a daemon whose graceful shutdown begins while
    /// the open is held at its layout poll must have ended the session it
    /// created before that process exits, and the daemon must find itself
    /// quiescent. The fixture's gate is released only after the process is
    /// gone, so nothing outside the exited daemon can finish its cleanup.
    #[test]
    fn a_started_open_rolls_back_before_normal_daemon_exit() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        scripted_zellij(&root, "");
        let gate = root.join("gate-list-panes");
        fs::write(&gate, "").expect("gate");
        // The child's registered-worker fixture roots stay in this tempdir.
        let fixture_tmp = root.join("tmp");
        fs::create_dir(&fixture_tmp).expect("child tmp");
        let mut child = std::process::Command::new(std::env::current_exe().expect("harness"))
            .args([
                "--exact",
                "live::zellij::cli::session_tests::daemon_exit_child_entry",
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
        let sessions = session_names(&root);
        fs::remove_file(&gate).expect("release list-panes");
        assert!(
            sessions.is_empty(),
            "process exit abandoned the started open's own session: {sessions:?}"
        );
        assert!(
            status.success(),
            "the daemon stand-in exited non-quiescent: {status}"
        );
    }
}
