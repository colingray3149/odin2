//! The frozen draft identity: `email.draft` persists the original intent and
//! the transport receipt privately, and every `email.send` route resolves and
//! dispatches exactly that produced snapshot.

use super::{
    capability, EmailAdapter, EmailDraft, EmailDraftReceipt, EMAIL_DRAFT_OPERATION,
    EMAIL_SEND_OPERATION, MAX_ID_CHARS,
};
use crate::account::{
    completed_effect, fault_into_life, run_ungated_effect, settle_gated_effect, DurableEffect,
    EffectIdentity, EffectIntent, EffectRoute, HostConsumeProof, LifeError, SettledEffect,
    TransportFault,
};
use odin_domain::CommandId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

const MSG_INTENT: &str = "the recorded send intent is missing the draft reference";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducedDraft {
    intent: EmailDraft,
    receipt: EmailDraftReceipt,
}

impl ProducedDraft {
    fn digest(&self) -> Result<String, LifeError> {
        let value = serde_json::to_value(self).map_err(|_| LifeError::Protocol(MSG_INTENT))?;
        let bytes = serde_json::to_vec(&value).map_err(|_| LifeError::Protocol(MSG_INTENT))?;
        Ok(odin_domain::Digest::hash(&bytes).to_string())
    }
}

/// The completed draft one `email.draft` identity names, read from its
/// durable record only: the command id and the recorded intent, which must
/// be the exact intent the provider's draft receipt was produced from.
/// Never issues a lease, contacts the provider, or writes.
pub(crate) fn completed_draft(
    ledger: &parking_lot::Mutex<odin_ledger::Ledger>,
    identity: &EffectIdentity,
) -> Result<(CommandId, EmailDraft), LifeError> {
    let command = completed_effect(ledger, identity, &capability(EMAIL_DRAFT_OPERATION))?;
    let produced: ProducedDraft = serde_json::from_str(
        command
            .terminal_result
            .as_ref()
            .and_then(|result| result.get("draftReceipt"))
            .and_then(Value::as_str)
            .ok_or(LifeError::InvalidInput(
                "the completed draft has no content binding",
            ))?,
    )
    .map_err(|_| LifeError::Protocol(MSG_INTENT))?;
    let intent =
        serde_json::to_value(&produced.intent).map_err(|_| LifeError::Protocol(MSG_INTENT))?;
    if intent != command.arguments {
        return Err(LifeError::Protocol(MSG_INTENT));
    }
    Ok((command.id, produced.intent))
}

impl EmailAdapter {
    /// `email.draft` — the ungated durable draft effect. Replaying the
    /// same identity returns the recorded outcome without a second
    /// dispatch.
    pub fn save_draft(
        &self,
        identity: &EffectIdentity,
        draft: &EmailDraft,
        now: time::OffsetDateTime,
    ) -> Result<SettledEffect, LifeError> {
        draft.validate()?;
        let arguments = serde_json::to_value(draft)
            .map_err(|_| LifeError::InvalidInput("the draft could not be canonicalized"))?;
        let transport = Arc::clone(&self.transport);
        let mut settled = run_ungated_effect(
            DurableEffect {
                ledger: &self.ledger,
                issuer: &self.issuer,
                identity,
            },
            self.leases.as_ref(),
            EffectRoute {
                capability: &capability(EMAIL_DRAFT_OPERATION),
                account: &draft.account,
                result_key: "draftReceipt",
            },
            arguments,
            now,
            move |lease, _arguments| {
                let receipt = transport.save_draft(lease, draft, now)?;
                serde_json::to_string(&ProducedDraft {
                    intent: draft.clone(),
                    receipt,
                })
                .map_err(|_| TransportFault::Protocol(MSG_INTENT))
            },
        )?;
        if settled.status == crate::account::EffectStatus::Completed {
            let produced: ProducedDraft = serde_json::from_str(
                settled
                    .result
                    .get("draftReceipt")
                    .and_then(Value::as_str)
                    .ok_or(LifeError::InvalidInput(
                        "the historical draft has no content binding",
                    ))?,
            )
            .map_err(|_| LifeError::Protocol(MSG_INTENT))?;
            settled.result = serde_json::json!({
                "draftId": produced.receipt.draft_id,
                "draftDigest": produced.digest()?,
            });
        }
        Ok(settled)
    }

    fn produced_draft(
        &self,
        account: &str,
        draft_id: &str,
        draft_digest: &str,
    ) -> Result<ProducedDraft, LifeError> {
        Self::validate_send_facts(account, draft_id)?;
        let ledger = self.ledger.lock();
        // Only this account's completed drafts are read; the receipts are
        // decoded here so one unrelated malformed row cannot fail the query.
        let mut statement = ledger
            .connection()
            .prepare(
                "SELECT terminal_result_json FROM commands
                 WHERE capability_id = ?1 AND target_id = ?2
                   AND terminal_status = 'completed'",
            )
            .map_err(|_| LifeError::Protocol(MSG_INTENT))?;
        let results = statement
            .query_map([EMAIL_DRAFT_OPERATION, account], |row| {
                row.get::<_, Option<String>>(0)
            })
            .map_err(|_| LifeError::Protocol(MSG_INTENT))?;
        for result in results {
            let result = result.map_err(|_| LifeError::Protocol(MSG_INTENT))?;
            // An unrelated undecodable receipt never hides the exact match;
            // a match that cannot be decoded is never proven either.
            let Some(produced) = result
                .and_then(|result| serde_json::from_str::<Value>(&result).ok())
                .and_then(|result| result.get("draftReceipt")?.as_str().map(str::to_owned))
                .and_then(|raw| serde_json::from_str::<ProducedDraft>(&raw).ok())
            else {
                continue;
            };
            if produced.intent.account == account
                && produced.receipt.draft_id == draft_id
                && produced.digest()? == draft_digest
            {
                return Ok(produced);
            }
        }
        Err(LifeError::InvalidInput(
            "no produced draft matches this account, id and content binding",
        ))
    }

    /// Effect-free owner-preview projection from the authoritative durable snapshot.
    pub(crate) fn approved_draft(
        &self,
        account: &str,
        draft_id: &str,
        draft_digest: &str,
    ) -> Result<EmailDraft, LifeError> {
        Ok(self.produced_draft(account, draft_id, draft_digest)?.intent)
    }

    fn validate_send_facts(account: &str, draft_id: &str) -> Result<(), LifeError> {
        Self::validate_send_account(account)?;
        if draft_id.is_empty() || draft_id.chars().count() > MAX_ID_CHARS {
            return Err(LifeError::InvalidInput("the draft id is out of bounds"));
        }
        Ok(())
    }

    /// Records the approved frozen draft without issuing credentials or contacting the provider.
    /// Reusing an identity requires identical effect details.
    pub(crate) fn record_send_intent(
        &self,
        account: &str,
        identity: &EffectIdentity,
        draft_id: &str,
        draft_digest: &str,
        now: time::OffsetDateTime,
    ) -> Result<(), LifeError> {
        let produced = self.produced_draft(account, draft_id, draft_digest)?;
        crate::account::record_dispatch_intent(
            DurableEffect {
                ledger: &self.ledger,
                issuer: &self.issuer,
                identity,
            },
            &capability(EMAIL_SEND_OPERATION),
            EffectIntent {
                target_kind: EMAIL_DRAFT_OPERATION,
                target_id: draft_id,
                arguments: serde_json::json!({ "account": account, "draftId": draft_id, "draftDigest": draft_digest, "producedDraft": produced }),
            },
            now,
        )
    }

    /// Rechecks consumed approval against the ledger without consuming it again; denials have no effect.
    pub fn settle_send(
        &self,
        account: &str,
        identity: &EffectIdentity,
        proof: &HostConsumeProof,
        now: time::OffsetDateTime,
    ) -> Result<SettledEffect, LifeError> {
        self.validate_recorded_send(account, identity)?;
        let transport = Arc::clone(&self.transport);
        settle_gated_effect(
            DurableEffect {
                ledger: &self.ledger,
                issuer: &self.issuer,
                identity,
            },
            self.leases.as_ref(),
            EffectRoute {
                capability: &capability(EMAIL_SEND_OPERATION),
                account,
                result_key: "sentId",
            },
            proof,
            now,
            move |lease, arguments| {
                let produced = Self::send_snapshot(arguments, lease.account())?;
                transport.send_draft(lease, &produced.receipt, now)
            },
        )
    }

    fn validate_recorded_send(
        &self,
        account: &str,
        identity: &EffectIdentity,
    ) -> Result<(), LifeError> {
        Self::validate_send_account(account)?;
        let command = self
            .ledger
            .lock()
            .command(&identity.command_id()?)
            .map_err(|_| LifeError::Protocol(MSG_INTENT))?
            .ok_or(LifeError::InvalidInput(MSG_INTENT))?;
        Self::send_snapshot(&command.arguments, account).map_err(fault_into_life)?;
        Ok(())
    }

    fn send_snapshot(arguments: &Value, account: &str) -> Result<ProducedDraft, TransportFault> {
        let produced: ProducedDraft = serde_json::from_value(arguments["producedDraft"].clone())
            .map_err(|_| TransportFault::Refused(MSG_INTENT))?;
        if arguments["account"].as_str() != Some(account)
            || produced.intent.account != account
            || arguments["draftId"].as_str() != Some(produced.receipt.draft_id.as_str())
            || arguments["draftDigest"].as_str()
                != Some(
                    produced
                        .digest()
                        .map_err(|_| TransportFault::Refused(MSG_INTENT))?
                        .as_str(),
                )
        {
            return Err(TransportFault::Refused(MSG_INTENT));
        }
        Ok(produced)
    }
}
