//! Bounded typed-worker event routing and the production session event pump.
//!
//! Every worker event either reaches a typed bounded subsystem — frames,
//! downloads, or the page view — or is retained as bounded redacted
//! protocol evidence. Frames are admitted to the bounded frame stream;
//! download events drive the quarantine/scanner manager; page observations
//! taken after launch, navigation, and text entry build the public session
//! view. Waiting for the next worker event never holds the state guard.

use odin_domain::huginn::browser::{BrowserDownloadStatus, BrowserDownloadView};
use odin_domain::huginn::ids::DownloadId;
use time::OffsetDateTime;

use crate::download::DownloadError;
use crate::stream::IncomingFrame;
use crate::takeover::TakeoverError;
use crate::worker::{
    Ack, CancelDownloadParams, StageDownloadParams, StageDownloadResult, WorkerDownloadState,
    WorkerEvent, WorkerMethod,
};

use super::{BrowserSession, ProtocolObservation, SessionError, SessionEvent, SessionPhase, State};

const MAX_EVENT_REASON_BYTES: usize = 512;

impl BrowserSession {
    /// Takes and routes the next bounded session fact: worker queue loss, an
    /// unreported session view, the retirement of a due takeover control
    /// lease, or the next typed worker event. Queue/view facts are checked
    /// under the state guard, but an idle event wait never holds that guard.
    /// While a control lease is held the pump wakes exactly at its deadline
    /// and retires the due lease itself — expiry is production behavior, not
    /// only an explicit call. Frames are admitted to the bounded frame stream;
    /// download events drive the quarantine manager; page observations build
    /// session views; protocol notices become redacted
    /// [`SessionEvent::Protocol`] evidence. Progress already queued for a
    /// terminal download is consumed without re-projecting its final view.
    /// Returns `None` once the worker channel is gone and queued facts are
    /// drained.
    pub async fn next_event(&mut self) -> Option<SessionEvent> {
        loop {
            {
                let mut state = self.state.lock().await;
                if matches!(state.phase, SessionPhase::Stopped) || state.runtime.is_none() {
                    return None;
                }
                // Expiry has precedence over queued projection facts: deliver
                // any retained cancellation first, then retire a newly due
                // lease before any held view can escape.
                if let Some(expiry) = state.lease_expiry_unreported.take() {
                    return Some(SessionEvent::TakeoverLeaseExpired(expiry));
                }
                if let Err(error) = state
                    .expire_takeover_lease(OffsetDateTime::now_utc(), true)
                    .await
                {
                    return Some(SessionEvent::ControlFailure {
                        code: control_failure_code(&error),
                    });
                }
                if let Some(expiry) = state.lease_expiry_unreported.take() {
                    return Some(SessionEvent::TakeoverLeaseExpired(expiry));
                }
                let dropped = self.events.dropped_events();
                let overflowed = dropped.saturating_sub(self.dropped_seen);
                self.dropped_seen = dropped;
                if overflowed > 0 {
                    return Some(SessionEvent::EventsDropped { count: overflowed });
                }
                if state.view_unreported {
                    state.view_unreported = false;
                    if let Some(view) = state.view.clone() {
                        return Some(SessionEvent::Session(view));
                    }
                }
            }

            // Production lease timer: while a control lease is held, wait for
            // the next worker fact or exactly until the deadline, whichever
            // comes first. A lease released meanwhile costs one harmless
            // spurious wake; the due check above retires nothing then.
            let lease_wake = {
                let state = self.state.lock().await;
                state.takeover.lease_deadline().map(|deadline| {
                    std::time::Duration::try_from(deadline - OffsetDateTime::now_utc())
                        .unwrap_or(std::time::Duration::ZERO)
                })
            };
            let event = match lease_wake {
                Some(delay) => {
                    tokio::select! {
                        event = self.events.next() => event,
                        () = tokio::time::sleep(delay) => continue,
                    }
                }
                None => self.events.next().await,
            }?;
            let routed = {
                let mut state = self.state.lock().await;
                state.route_event(event).await
            };
            if let Some(event) = routed {
                return Some(event);
            }
        }
    }
}

impl State {
    async fn route_event(&mut self, event: WorkerEvent) -> Option<SessionEvent> {
        match event {
            WorkerEvent::Frame {
                captured_at,
                jpeg_base64,
                key_frame,
                masked_runtime_value_regions,
            } => Some(self.route_frame(
                captured_at,
                jpeg_base64,
                key_frame,
                masked_runtime_value_regions,
            )),
            WorkerEvent::DownloadBegin {
                download_id,
                suggested_filename,
                source_url,
                expected_bytes,
            } => Some(
                self.route_download_begin(
                    download_id,
                    suggested_filename,
                    source_url,
                    expected_bytes,
                )
                .await,
            ),
            WorkerEvent::DownloadProgress {
                download_id,
                state,
                received_bytes,
            } => {
                self.route_download_progress(download_id, state, received_bytes)
                    .await
            }
            WorkerEvent::Protocol {
                name,
                session_scoped,
            } => {
                if name == "page-changed" {
                    self.refresh_page_view().await;
                }
                Some(SessionEvent::Protocol(ProtocolObservation {
                    method: bounded_event_reason(name),
                    session_scoped,
                }))
            }
        }
    }

    fn route_frame(
        &self,
        captured_at: u64,
        jpeg_base64: String,
        key_frame: bool,
        masked_runtime_value_regions: u32,
    ) -> SessionEvent {
        match self.frames.offer(IncomingFrame {
            control_revision: self.control_revision,
            captured_at: frame_timestamp(captured_at),
            key_frame,
            masked_runtime_value_regions,
            encoded: jpeg_base64.into_bytes(),
        }) {
            Ok(record) => SessionEvent::Frame(record),
            Err(error) => SessionEvent::FrameRejected {
                reason: bounded_event_reason(error.to_string()),
            },
        }
    }

    async fn route_download_begin(
        &self,
        worker_download_id: String,
        suggested_filename: String,
        source_url: String,
        expected_bytes: Option<u64>,
    ) -> SessionEvent {
        let download_id = match DownloadId::parse(&worker_download_id) {
            Ok(download_id) => download_id,
            Err(_) => {
                let _ = self.cancel_worker_download(&worker_download_id).await;
                return SessionEvent::DownloadRejected {
                    download_id: None,
                    reason: "download begin carried no usable download id".to_owned(),
                };
            }
        };
        let _admitted_view = match self
            .downloads
            .begin(
                download_id,
                &suggested_filename,
                &source_url,
                expected_bytes,
                OffsetDateTime::now_utc(),
            )
            .await
        {
            Ok(view) => view,
            Err(error) => {
                let _ = self.cancel_worker_download(&worker_download_id).await;
                return download_rejection(download_id, error);
            }
        };

        let staged_received_bytes = match self.stage_worker_download(&worker_download_id).await {
            Ok(StageDownloadResult {
                download_id: staged_id,
                received_bytes,
            }) if staged_id == worker_download_id => received_bytes,
            _ => {
                let _ = self.cancel_worker_download(&worker_download_id).await;
                let _ = self
                    .downloads
                    .cancel(download_id, OffsetDateTime::now_utc())
                    .await;
                return SessionEvent::DownloadRejected {
                    download_id: Some(download_id),
                    reason: "download staging could not be confirmed".to_owned(),
                };
            }
        };
        let now = OffsetDateTime::now_utc();
        if let Err(error) = self
            .downloads
            .progress(download_id, staged_received_bytes, now)
            .await
        {
            let _ = self.cancel_worker_download(&worker_download_id).await;
            let _ = self.downloads.cancel(download_id, now).await;
            return download_rejection(download_id, error);
        }

        match self.downloads.complete(download_id, now).await {
            Ok(view) => self.final_download_event(download_id, view),
            Err(error) => {
                if let Some(view) = self.terminal_download_view(download_id) {
                    return self.final_download_event(download_id, view);
                }
                let _ = self.downloads.cancel(download_id, now).await;
                download_rejection(download_id, error)
            }
        }
    }

    async fn route_download_progress(
        &self,
        worker_download_id: String,
        worker_state: WorkerDownloadState,
        received_bytes: u64,
    ) -> Option<SessionEvent> {
        let download_id = match DownloadId::parse(&worker_download_id) {
            Ok(download_id) => download_id,
            Err(_) => {
                let _ = self.cancel_worker_download(&worker_download_id).await;
                return Some(SessionEvent::DownloadRejected {
                    download_id: None,
                    reason: "download progress carried no usable download id".to_owned(),
                });
            }
        };
        if matches!(
            worker_state,
            WorkerDownloadState::InProgress | WorkerDownloadState::Completed
        ) && self.terminal_download_view(download_id).is_some()
        {
            return None;
        }

        let now = OffsetDateTime::now_utc();
        let event = match worker_state {
            WorkerDownloadState::InProgress => {
                match self
                    .downloads
                    .progress(download_id, received_bytes, now)
                    .await
                {
                    Ok(view) if view.status == BrowserDownloadStatus::Rejected => {
                        let _ = self.cancel_worker_download(&worker_download_id).await;
                        SessionEvent::Download(view)
                    }
                    Ok(view) => SessionEvent::Download(view),
                    Err(error) => {
                        let _ = self.cancel_worker_download(&worker_download_id).await;
                        download_rejection(download_id, error)
                    }
                }
            }
            WorkerDownloadState::Completed => {
                match self
                    .downloads
                    .progress(download_id, received_bytes, now)
                    .await
                {
                    Ok(view) if view.status == BrowserDownloadStatus::Rejected => {
                        let _ = self.cancel_worker_download(&worker_download_id).await;
                        return Some(SessionEvent::Download(view));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        let _ = self.cancel_worker_download(&worker_download_id).await;
                        return Some(download_rejection(download_id, error));
                    }
                }
                match self.downloads.complete(download_id, now).await {
                    Ok(view) => self.final_download_event(download_id, view),
                    Err(error) => {
                        if let Some(view) = self.terminal_download_view(download_id) {
                            return Some(self.final_download_event(download_id, view));
                        }
                        let _ = self.downloads.cancel(download_id, now).await;
                        download_rejection(download_id, error)
                    }
                }
            }
            WorkerDownloadState::Cancelled => match self.downloads.cancel(download_id, now).await {
                Ok(view) => SessionEvent::Download(view),
                Err(error) => {
                    let _ = self.cancel_worker_download(&worker_download_id).await;
                    download_rejection(download_id, error)
                }
            },
            WorkerDownloadState::Failed => {
                let _ = self.cancel_worker_download(&worker_download_id).await;
                let _ = self.downloads.cancel(download_id, now).await;
                SessionEvent::DownloadRejected {
                    download_id: Some(download_id),
                    reason: "worker reported download staging failure".to_owned(),
                }
            }
        };
        Some(event)
    }

    fn final_download_event(
        &self,
        download_id: DownloadId,
        view: BrowserDownloadView,
    ) -> SessionEvent {
        if view.status == BrowserDownloadStatus::Rejected {
            if let Some(record) = self
                .downloads
                .quarantine_records()
                .into_iter()
                .rev()
                .find(|record| record.download_id == download_id)
            {
                return SessionEvent::Quarantined(record);
            }
        }
        SessionEvent::Download(view)
    }

    fn terminal_download_view(&self, download_id: DownloadId) -> Option<BrowserDownloadView> {
        self.downloads.view(download_id).filter(|view| {
            matches!(
                view.status,
                BrowserDownloadStatus::Complete
                    | BrowserDownloadStatus::Rejected
                    | BrowserDownloadStatus::Cancelled
                    | BrowserDownloadStatus::Failed
            )
        })
    }

    async fn stage_worker_download(&self, download_id: &str) -> Result<StageDownloadResult, ()> {
        let runtime = self.runtime.as_ref().ok_or(())?;
        runtime
            .client()
            .call::<_, StageDownloadResult>(
                WorkerMethod::StageDownload,
                &StageDownloadParams {
                    download_id: download_id.to_owned(),
                },
                self.worker_command_deadline,
            )
            .await
            .map_err(|_| ())
    }

    async fn cancel_worker_download(&self, download_id: &str) -> bool {
        let Some(runtime) = self.runtime.as_ref() else {
            return false;
        };
        matches!(
            runtime
                .client()
                .call::<_, Ack>(
                    WorkerMethod::CancelDownload,
                    &CancelDownloadParams {
                        download_id: download_id.to_owned(),
                    },
                    self.worker_command_deadline,
                )
                .await,
            Ok(Ack { acknowledged: true })
        )
    }
}

fn download_rejection(download_id: DownloadId, error: DownloadError) -> SessionEvent {
    // Static typed reasons only: download error text can embed staging
    // paths and I/O details that never belong in a public event.
    let reason = match error {
        DownloadError::StagingRoot(_) | DownloadError::StagingIo(_) => {
            "download staging I/O failed".to_owned()
        }
        DownloadError::UnknownDownload(_) => "download event named an unknown download".to_owned(),
        DownloadError::WrongState(_) => "download event arrived in an unexpected state".to_owned(),
        DownloadError::InvalidSourceUrl => "download source URL is unusable".to_owned(),
        DownloadError::ActiveCeiling { .. } => {
            "download refused: active download ceiling reached".to_owned()
        }
        DownloadError::FileCeiling { .. } => {
            "download refused: per-file byte ceiling exceeded".to_owned()
        }
        DownloadError::TotalCeiling { .. } => {
            "download refused: aggregate byte ceiling exceeded".to_owned()
        }
    };
    SessionEvent::DownloadRejected {
        download_id: Some(download_id),
        reason,
    }
}

fn bounded_event_reason(reason: String) -> String {
    if reason.len() <= MAX_EVENT_REASON_BYTES {
        return reason;
    }
    let mut end = MAX_EVENT_REASON_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}

fn control_failure_code(error: &SessionError) -> &'static str {
    match error {
        SessionError::DurableControlUnavailable => "durable-control-unavailable",
        SessionError::DurableControlInvalid => "durable-control-invalid",
        SessionError::DurableControlStale => "durable-control-stale",
        SessionError::ControlRevisionOverflow
        | SessionError::Takeover(TakeoverError::RevisionOverflow) => "control-revision-overflow",
        _ => "takeover-expiry-failed",
    }
}

fn frame_timestamp(epoch_millis: u64) -> OffsetDateTime {
    let epoch_nanos = i128::from(epoch_millis) * 1_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(epoch_nanos)
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
}
