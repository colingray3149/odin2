use odin_browser::capability::ActionRequest;
use odin_browser::session::{ConsumedApproval, PreparedActionView, SessionError};
use odin_domain::huginn as live;
use odin_domain::CapabilityId;
use odin_huginn::browser::{BrowserActionOutcome, BrowserActionRecord};
use odin_ledger::command::{AcceptedCommand, CommandSpec, CommandTerminalStatus};
use time::OffsetDateTime;

use super::protocol::{
    accepted_response, action_request, conflict, digest_json, durable_revision,
    execute_action_failure_code, failed_outcome, invalid_request, prepare_action_failure_code,
    unavailable,
};
use super::{ActionAuthorization, BrowserCommandCoordinator, JournalDisposition, COMMAND_TTL};
use crate::browser_runtime::{BROWSER_INTERACT_CAPABILITY, BROWSER_INTERACT_VERSION};

const BROWSER_COMMAND_TARGET_KIND: &str = "browser";

impl BrowserCommandCoordinator {
    pub(super) async fn execute_browser_command(
        &self,
        device: live::DeviceId,
        command: live::BrowserCommand,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        match command {
            live::BrowserCommand::Takeover { context, command } => {
                self.execute_takeover(device, context, command).await
            }
            other => self.execute_action_command(device, other).await,
        }
    }

    async fn execute_takeover(
        &self,
        device: live::DeviceId,
        context: live::BrowserCommandContext,
        command: live::BrowserTakeoverCommand,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        if context.approval_id.is_some() {
            return Err(invalid_request(
                "browserTakeoverApproval",
                "browser takeover does not accept approval authority",
            ));
        }
        let arguments =
            serde_json::to_value((&command, context.session_id, context.expected_revision))
                .map_err(|_| unavailable("browserTakeoverArguments"))?;
        let digest = digest_json(&arguments)?;
        if digest != context.arguments_digest {
            return Err(conflict(
                "browserArgumentsDigest",
                "browser command arguments digest does not match",
            ));
        }
        let expected_revision = durable_revision(context.expected_revision)?;
        let now = OffsetDateTime::now_utc();
        let spec = CommandSpec {
            id: context.command_id.clone(),
            idempotency_key: context.command_id.to_string(),
            correlation_id: context.session_id.to_string(),
            causation_id: None,
            issuer: device.to_string(),
            approval_id: None,
            target_kind: BROWSER_COMMAND_TARGET_KIND.to_owned(),
            target_id: context.session_id.to_string(),
            capability_id: CapabilityId::new(BROWSER_INTERACT_CAPABILITY)
                .map_err(|_| unavailable("browserInteractCapability"))?,
            capability_version: i64::try_from(BROWSER_INTERACT_VERSION)
                .map_err(|_| unavailable("browserInteractCapability"))?,
            arguments_hash: digest,
            arguments,
            expected_desired_revision: Some(expected_revision),
            issued_at: now,
            expires_at: now + COMMAND_TTL,
        };
        if let Some(response) = self.existing_command(&spec)? {
            return Ok(response);
        }
        self.validate_context(&context).await?;
        let accepted = match self.journal(spec)? {
            JournalDisposition::Duplicate(response) => return Ok(response),
            JournalDisposition::Accepted(accepted) => accepted,
        };

        let command_id = context.command_id;
        let result = self.projection.browser().takeover(device, &command).await;
        match result {
            Ok(_) => {
                self.complete_command(
                    &accepted,
                    CommandTerminalStatus::Completed,
                    live::CommandOutcome::Applied {
                        command_id: command_id.clone(),
                    },
                )?;
                Ok(accepted_response(command_id))
            }
            Err(_) => {
                self.complete_command(
                    &accepted,
                    CommandTerminalStatus::Failed,
                    failed_outcome(&command_id, "browserTakeover", "browser takeover failed"),
                )?;
                Err(unavailable("browserTakeover"))
            }
        }
    }

    async fn execute_action_command(
        &self,
        device: live::DeviceId,
        command: live::BrowserCommand,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let (context, request) = action_request(command)?;
        self.execute_action_request(device.to_string(), context, request, None, None)
            .await
    }

    /// `host_consumed` is the approval the kernel authority consumed for
    /// this exact host command, already verified against the durable
    /// records: it authorizes the prepared action in place of a second
    /// consumption. Native browser-session approvals pass `None`.
    pub(super) async fn execute_action_request(
        &self,
        issuer: String,
        context: live::BrowserCommandContext,
        request: ActionRequest,
        expected_capability: Option<(CapabilityId, u64)>,
        host_consumed: Option<odin_ledger::approval::Approval>,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        self.projection
            .browser()
            .validate_outbound(&request)
            .await
            .map_err(|_| {
                invalid_request(
                    "browserOutboundSafety",
                    "browser outbound safety validation failed",
                )
            })?;

        let digest = request.canonical_arguments_digest();
        if digest != context.arguments_digest {
            return Err(conflict(
                "browserArgumentsDigest",
                "browser command arguments digest does not match",
            ));
        }
        let expected_revision = durable_revision(context.expected_revision)?;
        let arguments = serde_json::to_value((&request.action, &request.arguments))
            .map_err(|_| unavailable("browserCommandArguments"))?;
        let target_id = context.session_id.to_string();
        if let Some(response) = self.existing_action_command(
            &context.command_id,
            &digest,
            &target_id,
            expected_revision,
        )? {
            return Ok(response);
        }

        self.validate_context(&context).await?;
        let prepared = self
            .projection
            .browser()
            .prepare_action(request)
            .await
            .map_err(|error| unavailable(prepare_action_failure_code(&error)))?;

        if let Some((capability_id, capability_version)) = &expected_capability {
            if &prepared.rule.capability_id != capability_id
                || prepared.rule.capability_version != *capability_version
            {
                self.abandon_prepared(&prepared).await?;
                return Err(conflict(
                    "browserCapabilityBinding",
                    "browser policy selected a different capability binding",
                ));
            }
        }
        if prepared.control_revision != context.expected_revision
            || prepared.arguments_digest != digest
        {
            self.abandon_prepared(&prepared).await?;
            return Err(conflict(
                "browserBindingChanged",
                "browser command binding changed during preparation",
            ));
        }
        if prepared.rule.approval_required && context.approval_id.is_none() {
            self.abandon_prepared(&prepared).await?;
            return Err(invalid_request(
                "browserApprovalId",
                "browser action requires an explicit approval ID",
            ));
        }

        let policy = self.projection.browser().policy().await;
        if !policy.binding_is_current(&prepared.policy_binding)
            || policy.rule(&prepared.policy_action) != Some(&prepared.rule)
        {
            self.abandon_prepared(&prepared).await?;
            return Err(conflict(
                "browserBindingChanged",
                "browser command binding changed during preparation",
            ));
        }

        let capability_version = match i64::try_from(prepared.rule.capability_version) {
            Ok(version) => version,
            Err(_) => {
                self.abandon_prepared(&prepared).await?;
                return Err(invalid_request(
                    "browserCapabilityVersion",
                    "capability version is out of range",
                ));
            }
        };
        let now = OffsetDateTime::now_utc();
        let spec = CommandSpec {
            id: context.command_id.clone(),
            idempotency_key: context.command_id.to_string(),
            correlation_id: target_id.clone(),
            causation_id: None,
            issuer: issuer.clone(),
            approval_id: context.approval_id.clone(),
            target_kind: BROWSER_COMMAND_TARGET_KIND.to_owned(),
            target_id,
            capability_id: prepared.rule.capability_id.clone(),
            capability_version,
            arguments_hash: digest,
            arguments,
            expected_desired_revision: Some(expected_revision),
            issued_at: now,
            expires_at: now + COMMAND_TTL,
        };
        let accepted = match self.journal(spec) {
            Ok(JournalDisposition::Accepted(accepted)) => accepted,
            Ok(JournalDisposition::Duplicate(response)) => {
                self.abandon_prepared(&prepared).await?;
                return Ok(response);
            }
            Err(error) => {
                let abandon_error = self.abandon_prepared(&prepared).await.err();
                return Err(abandon_error.unwrap_or(error));
            }
        };

        let authorization = match host_consumed {
            // The consumed approval covers exactly these canonical action
            // arguments; the session still re-proves the typed action, its
            // revision and its policy before dispatch.
            Some(approval) if approval.scope.capability_id == prepared.rule.capability_id => {
                Ok(ActionAuthorization::Consumed {
                    evidence: ConsumedApproval {
                        capability_id: approval.scope.capability_id.clone(),
                        arguments_digest: prepared.arguments_digest,
                    },
                    approval,
                })
            }
            Some(_) => Err(conflict(
                "browserCapabilityBinding",
                "the consumed approval names a different capability than the policy rule",
            )),
            None => {
                self.authorize_prepared(&accepted, context.approval_id.as_ref(), &prepared, &issuer)
            }
        };
        let authorization = match authorization {
            Ok(authorization) => authorization,
            Err(error) => {
                self.finish_without_execution(
                    &accepted,
                    &prepared,
                    BrowserActionOutcome::Abandoned,
                    CommandTerminalStatus::Blocked,
                    failed_outcome(
                        &context.command_id,
                        "browserApprovalAuthority",
                        "browser approval authority failed",
                    ),
                )
                .await?;
                return Err(error);
            }
        };

        match authorization {
            ActionAuthorization::NotRequired => {
                self.execute_prepared(&accepted, &prepared, None).await?;
            }
            ActionAuthorization::Consumed { approval, evidence } => {
                let publication_error = self.publish_approval(&approval).err();
                let execution_error = self
                    .execute_prepared(&accepted, &prepared, Some(evidence))
                    .await
                    .err();
                if let Some(error) = execution_error.or(publication_error) {
                    return Err(error);
                }
            }
            ActionAuthorization::Pending(approval) => {
                self.publish_approval(&approval)?;
                return Ok(accepted_response(context.command_id));
            }
            ActionAuthorization::Denied => {
                self.finish_without_execution(
                    &accepted,
                    &prepared,
                    BrowserActionOutcome::Denied,
                    CommandTerminalStatus::Cancelled,
                    live::CommandOutcome::Cancelled {
                        command_id: context.command_id.clone(),
                        reason: "browser approval was denied".to_owned(),
                    },
                )
                .await?;
                return Err(conflict(
                    "browserApprovalDenied",
                    "browser approval was denied",
                ));
            }
            ActionAuthorization::Redirect => {
                self.finish_without_execution(
                    &accepted,
                    &prepared,
                    BrowserActionOutcome::Abandoned,
                    CommandTerminalStatus::Blocked,
                    failed_outcome(
                        &context.command_id,
                        "browserApprovalRedirect",
                        "browser approval did not authorize the command",
                    ),
                )
                .await?;
                return Err(conflict(
                    "browserApprovalRedirect",
                    "browser approval did not authorize the command",
                ));
            }
        }
        Ok(accepted_response(context.command_id))
    }

    async fn validate_context(
        &self,
        context: &live::BrowserCommandContext,
    ) -> Result<(), live::HuginnProtocolError> {
        if context.session_id != self.projection.browser().session_id() {
            return Err(invalid_request(
                "browserSession",
                "browser command targets a different session",
            ));
        }
        let actual = self.projection.browser().control_revision().await;
        if context.expected_revision != actual {
            return Err(live::HuginnProtocolError::RevisionMismatch {
                expected: live::Revision::new(context.expected_revision),
                actual: live::Revision::new(actual),
            });
        }
        Ok(())
    }

    async fn abandon_prepared(
        &self,
        prepared: &PreparedActionView,
    ) -> Result<(), live::HuginnProtocolError> {
        match self
            .projection
            .browser()
            .abandon_action(prepared.action_id)
            .await
        {
            Ok(_) | Err(SessionError::UnknownAction { .. }) => Ok(()),
            Err(_) => Err(unavailable("browserActionAbandon")),
        }
    }

    pub(super) async fn execute_prepared(
        &self,
        accepted: &AcceptedCommand,
        prepared: &PreparedActionView,
        approval: Option<ConsumedApproval>,
    ) -> Result<(), live::HuginnProtocolError> {
        let command_id = accepted.command().id.clone();
        let execution = self
            .projection
            .browser()
            .execute_action(prepared.action_id, approval)
            .await;
        let (timeline_outcome, status, command_outcome, protocol_error) = match execution {
            Ok(_) => (
                BrowserActionOutcome::Applied,
                CommandTerminalStatus::Completed,
                live::CommandOutcome::Applied {
                    command_id: command_id.clone(),
                },
                None,
            ),
            Err(error) => {
                let code = execute_action_failure_code(&error);
                (
                    BrowserActionOutcome::Unknown,
                    CommandTerminalStatus::Failed,
                    failed_outcome(&command_id, code, "browser action result is unknown"),
                    Some(unavailable(code)),
                )
            }
        };
        let projection_error = self
            .projection
            .record_action(BrowserActionRecord::from_prepared(
                command_id,
                prepared,
                timeline_outcome,
                OffsetDateTime::now_utc(),
            ))
            .await
            .err()
            .map(|_| unavailable("browserActionProjection"));
        let completion_error = self
            .complete_command(accepted, status, command_outcome)
            .err();
        if let Some(error) = completion_error.or(projection_error).or(protocol_error) {
            return Err(error);
        }
        Ok(())
    }

    pub(super) async fn finish_without_execution(
        &self,
        accepted: &AcceptedCommand,
        prepared: &PreparedActionView,
        timeline_outcome: BrowserActionOutcome,
        status: CommandTerminalStatus,
        command_outcome: live::CommandOutcome,
    ) -> Result<(), live::HuginnProtocolError> {
        let abandon_error = self
            .projection
            .browser()
            .abandon_action(prepared.action_id)
            .await
            .err()
            .map(|_| unavailable("browserActionAbandon"));
        let projection_error = self
            .projection
            .record_action(BrowserActionRecord::from_prepared(
                accepted.command().id.clone(),
                prepared,
                timeline_outcome,
                OffsetDateTime::now_utc(),
            ))
            .await
            .err()
            .map(|_| unavailable("browserActionProjection"));
        let completion_error = self
            .complete_command(accepted, status, command_outcome)
            .err();
        if let Some(error) = completion_error.or(projection_error).or(abandon_error) {
            return Err(error);
        }
        Ok(())
    }
}
