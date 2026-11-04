//! The durable first-prompt plan gate: the bounded operator prompt file,
//! the gated handoff that durably accepts the exact prompt before any
//! Huginn Prompt command exists, and the explicit local acceptance
//! command for idle and manually composed sessions.

use odin_cli::authority_provision::{SessionComposition, MAX_PROMPT_FILE_BYTES};
use odin_cli::operator_prompt::{self, OperatorPlanReceipt};
use odin_domain::huginn as live;
use odin_huginn::client::{
    RemoteClient, DeviceCredential, EndpointTransport, FileCredentialStore,
};
use odin_huginn::OdindConfig;
use odin_ledger::Ledger;
use std::fs;
use std::io::{Read as _, Write};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

use super::transport::{enrolled_credential, send_prompt};

pub(crate) struct PlanAcceptRequest {
    pub config: PathBuf,
    pub session: String,
    pub expected_revision: Option<i64>,
}

/// Accepts the current plan using this workstation's paired operator device.
pub(crate) fn accept(request: PlanAcceptRequest, output: &mut dyn Write) -> Result<(), String> {
    let config = OdindConfig::load(&request.config).map_err(|error| {
        format!(
            "could not load the controller configuration {}: {error}",
            request.config.display()
        )
    })?;
    let session = live::LiveSessionId::parse(&request.session)
        .map_err(|error| format!("invalid session id {:?}: {error}", request.session))?;
    let run_id = operator_prompt::session_run_id(&session)?;
    let credentials = FileCredentialStore::open(config.paths.state_root.join("huginn"))
        .map_err(|error| error.to_string())?;
    let credential = enrolled_credential(&config, &credentials, "accepting a plan")?;
    let device = credential.device_id().map_err(|error| {
        format!("the enrolled credential has no valid device identity: {error}")
    })?;
    let identity = operator_prompt::operator_identity(&config.paths.state_root, device)?;
    let mut ledger = Ledger::open(config.paths.state_root.join("ledger.sqlite3"))
        .map_err(|error| format!("could not open the session state ledger: {error}"))?;
    let plan = ledger
        .plan(&run_id)
        .map_err(|error| format!("could not read the plan of run {run_id}: {error}"))?
        .ok_or_else(|| format!("run {run_id} has no plan to accept"))?;
    let expected_revision = request.expected_revision.unwrap_or(plan.revision);
    let now = OffsetDateTime::now_utc();
    ledger
        .accept_plan(&run_id, expected_revision, &identity.actor(), now)
        .map_err(|error| {
            format!("could not accept plan {run_id} at revision {expected_revision}: {error}")
        })?;
    let gate = ledger
        .plan_is_accepted(&run_id)
        .map_err(|error| format!("could not verify plan acceptance of {run_id}: {error}"))?;
    let record = ledger
        .plan_acceptance(&run_id)
        .map_err(|error| format!("could not re-read the acceptance record of {run_id}: {error}"))?;
    match (gate, record) {
        (true, Some(record)) => {
            writeln!(
                output,
                "plan accepted: run {run_id} revision {} fingerprint {} as {} (device label \"{}\")",
                record.plan_revision, record.fingerprint, record.actor, identity.label
            )
            .map_err(|error| format!("could not write acceptance report: {error}"))?;
            Ok(())
        }
        (true, None) => Err(format!(
            "the acceptance record of {run_id} disappeared after verification"
        )),
        (false, _) => Err(format!(
            "plan {run_id} was recorded but does not verify as accepted; its structure changed after the record, so it never counts as approved"
        )),
    }
}

/// Accepts the prompt plan before constructing a command for the opened epoch.
pub(super) fn deliver_first_prompt(
    runtime: &tokio::runtime::Runtime,
    client: &RemoteClient<EndpointTransport, FileCredentialStore>,
    config: &OdindConfig,
    composition: &SessionComposition,
    summary: &live::LiveSessionSummary,
    credential: &DeviceCredential,
    prompt_text: Option<String>,
) -> Result<Option<OperatorPlanReceipt>, String> {
    let Some(text) = prompt_text else {
        return Ok(None);
    };
    let device = credential.device_id().map_err(|error| {
        format!("the enrolled credential has no valid device identity: {error}")
    })?;
    let (command, plan) =
        operator_prompt::prepare(config, composition, device, &text, summary.epoch)?.into_parts();
    let proof = &plan;
    let receipt = send_prompt(runtime, client, command).map_err(|error| {
        format!(
            "session {} opened idle, but sending the accepted prompt (command {}) failed: {error}; the plan acceptance for {} remains durably recorded",
            summary.session_id, proof.prompt_command_id, proof.run
        )
    })?;
    if !matches!(receipt, live::CommandReceipt::Accepted { .. }) {
        return Err(format!(
            "session {} opened idle, but the controller refused the accepted prompt \
             (command {}): {receipt:?}; the plan acceptance for {} remains durably \
             recorded",
            summary.session_id, proof.prompt_command_id, proof.run
        ));
    }
    Ok(Some(plan))
}

pub(super) fn prompt_text_from_file(path: &Path) -> Result<String, String> {
    let file = fs::File::open(path)
        .map_err(|error| format!("could not open the prompt file {}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "could not inspect the prompt file {}: {error}",
            path.display()
        )
    })?;
    if metadata.len() > MAX_PROMPT_FILE_BYTES {
        return Err(format!(
            "the prompt file {} holds {} bytes, above the {} byte bound",
            path.display(),
            metadata.len(),
            MAX_PROMPT_FILE_BYTES
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|error| format!("prompt length {} exceeds usize: {error}", metadata.len()))?,
    );
    file.take(MAX_PROMPT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read the prompt file {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PROMPT_FILE_BYTES {
        return Err(format!(
            "the prompt file {} grew beyond the {} byte bound while it was read",
            path.display(),
            MAX_PROMPT_FILE_BYTES
        ));
    }
    let text = String::from_utf8(bytes)
        .map_err(|error| format!("the prompt file {} is not UTF-8: {error}", path.display()))?;
    if text.trim().is_empty() {
        return Err(format!("the prompt file {} is empty", path.display()));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {}
