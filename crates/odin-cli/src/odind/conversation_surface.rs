//! Paired Huginn surfaces share the declared conversation with Discord;
//! Hermes mirrors incoming lines to the owner channel before admission.

use std::sync::Arc;

use odin_domain::huginn as live;
use odin_domain::{ProjectId, SeatId};
use odin_huginn::devices::{DeviceTrustStore as _, SqliteDeviceTrustStore};

pub(crate) struct ConversationSurface {
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
    root: Arc<odin_hermes::conversation::ConversationRoot>,
    seat: SeatId,
    project: ProjectId,
    devices: Arc<SqliteDeviceTrustStore>,
    /// One say in intake at a time, held by the intake itself (it outlives
    /// a dropped request): a retry that arrives while its first attempt is
    /// still in intake waits for it and reads its recorded outcome.
    says: Arc<std::sync::Mutex<()>>,
}

impl ConversationSurface {
    pub(crate) fn new(
        runtime: Arc<odin_hermes::runtime::HermesRuntime>,
        root: Arc<odin_hermes::conversation::ConversationRoot>,
        devices: Arc<SqliteDeviceTrustStore>,
    ) -> Result<Self, String> {
        let discord =
            runtime.settings().discord.as_ref().ok_or_else(|| {
                "the conversation root has no declared Discord surface".to_owned()
            })?;
        Ok(Self {
            seat: discord.seat.clone(),
            project: discord.project.clone(),
            runtime,
            root,
            devices,
            says: Arc::default(),
        })
    }

    /// Refuse unsupported continuations before running `decide`; otherwise
    /// return its result unchanged through `ConversationRoot::decide_external`.
    pub(crate) async fn decide(
        &self,
        approval_id: &odin_domain::ApprovalId,
        approved: bool,
        decide: impl std::future::Future<Output = Result<live::HuginnResponse, live::HuginnProtocolError>>
            + Send,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        self.root
            .decide_external(approval_id.as_str(), approved, decide)
            .await
            .unwrap_or_else(|error| {
                tracing::error!(
                    "conversation-surface decision_unowned approval={approval_id} error={error}"
                );
                Err(unavailable("conversationDecision"))
            })
    }

    pub(crate) async fn status(
        &self,
        intake: Option<String>,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let vehicle = self.root.current_vehicle_session().await.map_err(|error| {
            tracing::error!("conversation-surface status_failed error={error:?}");
            unavailable("conversationVehicle")
        })?;
        Ok(live::HuginnResponse::Conversation(live::ConversationView {
            conversation_id: self.root.conversation_id().to_owned(),
            seat_id: self.seat.clone(),
            project_id: self.project.clone(),
            vehicle_session: vehicle,
            intake,
            thread: Vec::new(),
        }))
    }

    pub(crate) async fn thread(
        &self,
        request: live::ConversationThreadRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let thread = self
            .runtime
            .owner_thread(request.after.as_deref())
            .await
            .map_err(|error| {
                tracing::error!("conversation-surface thread_failed error={error}");
                unavailable("conversationThread")
            })?;
        let live::HuginnResponse::Conversation(mut view) = self.status(None).await? else {
            return Err(unavailable("conversationVehicle"));
        };
        view.thread = thread;
        Ok(live::HuginnResponse::Conversation(view))
    }

    pub(crate) async fn say(
        &self,
        device: live::DeviceId,
        request: live::ConversationSayRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let text = request.text.trim().to_owned();
        if text.is_empty() || text.chars().count() > live::CONVERSATION_MESSAGE_MAX_CHARS {
            return Err(live::HuginnProtocolError::InvalidRequest {
                code: "conversationLine".to_owned(),
                message: format!(
                    "an owner line must hold 1 to {} characters",
                    live::CONVERSATION_MESSAGE_MAX_CHARS
                ),
            });
        }
        let surface = match self.devices.get(device).await {
            Ok(Some(record)) => record.label,
            Ok(None) => return Err(live::HuginnProtocolError::Unauthenticated),
            Err(error) => {
                tracing::error!(
                    "conversation-surface device_lookup_failed device={device} error={error}"
                );
                return Err(unavailable("conversationDevice"));
            }
        };
        let runtime = Arc::clone(&self.runtime);
        let label = surface.clone();
        let say = request.command_id.clone();
        let says = Arc::clone(&self.says);
        // Intake blocks (the mirror send, the plain-language decision
        // route): it runs off the async workers.
        let projection = tokio::task::spawn_blocking(move || {
            let _one_say = says.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            runtime.admit_surface_line(&label, &say, &text)
        })
        .await
                .map_err(|error| {
                    tracing::error!("conversation-surface intake_join_failed error={error}");
                    unavailable("conversationIntake")
                })?
                .map_err(|error| {
                    tracing::error!(
                        "conversation-surface say_refused device={device} surface={surface} error={error:?}"
                    );
                    unavailable("conversationIntake")
                })?;
        let intake = projection
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        tracing::info!(
            "conversation-surface say device={device} surface={surface} command={} intake={intake}",
            request.command_id
        );
        if intake == "interrupted" {
            return Err(live::HuginnProtocolError::Conflict {
                code: "conversationInterrupted".to_owned(),
                message: "That line was cut off before Odin knew whether the conversation \
                          got it."
                    .to_owned(),
            });
        }
        self.status(Some(intake)).await
    }

    /// The committed reply texts for one say, or an empty thread when that
    /// delivery is not sent yet. Reads the mirror this say already recorded.
    /// Does not resume or resend delivery.
    pub(crate) fn committed_reply(
        &self,
        say: &odin_domain::CommandId,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let discord = self
            .runtime
            .settings()
            .discord
            .as_ref()
            .ok_or_else(|| unavailable("conversationSurface"))?;
        let mirror = self.runtime.store().surface_mirror(say).map_err(|error| {
            tracing::error!("conversation-surface reply_unreadable say={say} error={error}");
            unavailable("conversationReply")
        })?;
        let Some(mirror) = mirror else {
            return Ok(self.reply_view(None, Vec::new()));
        };
        let key = format!("discord:v1:{}:{mirror}", discord.notify_channel_id);
        let chunks = self.root.committed_reply(&key).map_err(|error| {
            tracing::error!("conversation-surface reply_unreadable say={say} error={error}");
            unavailable("conversationReply")
        })?;
        let Some(chunks) = chunks else {
            return Ok(self.reply_view(None, Vec::new()));
        };
        let thread = chunks
            .into_iter()
            .enumerate()
            .map(|(index, text)| live::ConversationLine {
                id: format!("committed-{index}"),
                from_owner: false,
                text,
                files: Vec::new(),
            })
            .collect();
        Ok(self.reply_view(Some("committed".to_owned()), thread))
    }

    fn reply_view(
        &self,
        intake: Option<String>,
        thread: Vec<live::ConversationLine>,
    ) -> live::HuginnResponse {
        live::HuginnResponse::Conversation(live::ConversationView {
            conversation_id: self.root.conversation_id().to_owned(),
            seat_id: self.seat.clone(),
            project_id: self.project.clone(),
            vehicle_session: None,
            intake,
            thread,
        })
    }
}

fn unavailable(code: &str) -> live::HuginnProtocolError {
    live::HuginnProtocolError::Unavailable {
        code: code.to_owned(),
    }
}
