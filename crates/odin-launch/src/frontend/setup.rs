//! Delay attachment responses until replay validates the session's seat and project.

use super::*;

impl<T: HuginnTransport, K: DeviceCredentialStore> Frontend<T, K> {
    pub(super) async fn handle_initialize(
        &mut self,
        params: Option<&Value>,
    ) -> Result<Value, RpcError> {
        let params: acp::InitializeParams = acp::decode_params(params, "initialize")?;
        if params.protocol_version != ACP_PROTOCOL_VERSION {
            return Err(RpcError::new(
                RpcError::GOVERNED_REFUSAL,
                format!(
                    "unsupported ACP protocol version {}; this frontend speaks version \
                     {ACP_PROTOCOL_VERSION} only",
                    params.protocol_version
                ),
            ));
        }
        self.initialized = true;
        // Client capabilities are diagnostic only; no client-side methods are invoked.
        if let Some(caps) = params.client_capabilities.as_object() {
            let offered: Vec<&str> = caps.keys().map(String::as_str).collect();
            if !offered.is_empty() {
                tracing::info!(
                    capabilities = %offered.join(", "),
                    "client capabilities offered but unused here"
                );
            }
        }
        if let Some(info) = &params.client_info {
            tracing::info!(name = %info.name, version = %info.version, "client");
        }
        let result = acp::InitializeResult {
            protocol_version: ACP_PROTOCOL_VERSION,
            agent_capabilities: acp::AgentCapabilities { load_session: true },
            auth_methods: [],
            agent_info: acp::Implementation {
                name: AGENT_NAME.to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                title: Some(AGENT_TITLE.to_owned()),
            },
        };
        serde_json::to_value(&result)
            .map_err(|error| RpcError::new(RpcError::INTERNAL_ERROR, error.to_string()))
    }

    pub(super) async fn handle_session_new(
        &mut self,
        id: &Value,
        params: Option<&Value>,
    ) -> Result<Handled, RpcError> {
        self.require_initialized()?;
        let params: acp::SessionSetupParams = acp::decode_params(params, "session/new")?;
        self.reject_unsupported_setup(
            params.mcp_servers.len(),
            params.additional_directories.len(),
        )?;
        self.spawn_setup(id.clone(), SetupKind::New, params.cwd.clone(), {
            let opener = Arc::clone(&self.opener);
            Box::pin(async move { opener.prepare_new().await })
        });
        // Wait for ReplayComplete before returning the allocated session identity.
        Ok(Handled::Deferred)
    }

    pub(super) async fn handle_session_load(
        &mut self,
        id: &Value,
        params: Option<&Value>,
    ) -> Result<Handled, RpcError> {
        self.require_initialized()?;
        let params: acp::LoadSessionParams = acp::decode_params(params, "session/load")?;
        self.reject_unsupported_setup(
            params.setup.mcp_servers.len(),
            params.setup.additional_directories.len(),
        )?;
        let live_session = live::LiveSessionId::parse(&params.session_id).map_err(|error| {
            RpcError::new(
                RpcError::INVALID_PARAMS,
                format!("sessionId is not a governed session identity: {error}"),
            )
        })?;
        let session_key = live_session.to_string();
        if self.sessions.contains_key(&session_key) {
            return Err(RpcError::new(
                RpcError::INVALID_REQUEST,
                format!("session {session_key} is already attached to this frontend"),
            ));
        }
        // Controller lookup and durable history checks prevent exposing another session's content.
        let opener = Arc::clone(&self.opener);
        self.spawn_setup(
            id.clone(),
            SetupKind::Load,
            params.setup.cwd.clone(),
            Box::pin(async move { opener.prepare_load(live_session).await }),
        );
        Ok(Handled::Deferred)
    }

    /// Run setup separately so controller delays cannot block the frontend loop.
    fn spawn_setup(
        &mut self,
        request_id: Value,
        kind: SetupKind,
        cwd: String,
        prepare: BoxFuture<'static, Result<PendingSession, String>>,
    ) {
        self.tasks.push(Box::pin(async move {
            let opened = async move {
                let pending = prepare.await.map_err(governed)?;
                require_cwd_binding(&cwd, pending.project_root()).map_err(governed)?;
                pending.commit().await.map_err(governed)
            }
            .await;
            Completion::SetupReady {
                request_id,
                kind,
                opened,
            }
        }));
    }

    pub(super) fn on_setup_ready(
        &mut self,
        request_id: Value,
        kind: SetupKind,
        opened: Result<OpenedSession, RpcError>,
    ) {
        match opened {
            Ok(opened) => {
                let session_key = opened.facts.live_session.to_string();
                if self.sessions.contains_key(&session_key) {
                    self.queue_message(Message::failure(
                        request_id,
                        governed("the session is already attached to this frontend"),
                    ));
                    return;
                }
                tracing::info!(
                    session = %session_key,
                    seat = %opened.facts.seat,
                    project = %opened.facts.project,
                    provider = %opened.facts.provider,
                    model = %opened.facts.model,
                    root = %opened.facts.project_root.display(),
                    "session bound"
                );
                let live_session = opened.facts.live_session;
                let setup = SetupWaiter {
                    acp_request_id: request_id,
                    kind,
                };
                self.sessions
                    .insert(session_key.clone(), Session::from_opened(opened, setup));
                self.order_plane(PlaneOrder::Subscribe {
                    session: live_session,
                    after: live::EventSeq::new(0),
                });
            }
            Err(error) => {
                self.queue_message(Message::failure(request_id, error));
            }
        }
    }
}

/// Canonical paths prevent attaching the client to a different project root.
fn require_cwd_binding(cwd: &str, project_root: &Path) -> Result<(), String> {
    let cwd_canonical = PathBuf::from(cwd)
        .canonicalize()
        .map_err(|error| format!("cwd {cwd:?} is not accessible: {error}"))?;
    let root_canonical = project_root.canonicalize().map_err(|error| {
        format!(
            "the composed project root {} is not accessible: {error}",
            project_root.display()
        )
    })?;
    if cwd_canonical != root_canonical {
        return Err(format!(
            "cwd {cwd:?} does not match the composed project root {}; this frontend \
             binds sessions exactly to their declared project",
            root_canonical.display()
        ));
    }
    Ok(())
}
