//! Per-seat `brain://` resolution with scoped provenance and policy-pinned snapshots.

use std::collections::BTreeMap;

use odin_brain::{error::BrainError, index::model::ItemProvenance};
use odin_domain::Scope;
use odin_ledger::lane_run;
use serde_json::{json, Value};

use super::resolvers::{
    json_result, parse_resource_id, scope_denied, scope_shortfall, storage_error,
};
use super::ScopedUriRouter;
use super::{ExecutionBinding, UriContext, UriError, UriRequest, UriResult};

impl ScopedUriRouter {
    /// `brain://` resolution through the injected BrainService. The bare URI returns the
    /// pinned authority snapshot across every composed knowledge source; an identified URI
    /// resolves one knowledge item and proves the caller's bound scope against its Atlas
    /// node provenance. Policy and generation digests are pinned into every snapshot so
    /// consumers can detect authority rotation.
    pub(super) fn resolve_brain(
        &self,
        context: &UriContext,
        request: UriRequest,
    ) -> Result<UriResult, UriError> {
        let url = request.url.clone();
        // Validate captured session state before choosing a service or materializing data.
        let Some(execution) = context.execution.as_ref() else {
            return Err(UriError::ExecutionProof {
                url: url.clone(),
                reason: "brain:// resolves only for a live bound session and the \
                         caller carried no execution proof"
                    .to_owned(),
            });
        };
        self.prove_brain_execution(&context.scope, execution)?;
        // The seat comes from the caller's authenticated session scope —
        // bound host-side at session open from the verified seat token and
        // the ledger session manifest, never from the URI or model input.
        // A seatless scope, or a seat that serves no brain service, refuses
        // brain typed while every other scheme keeps resolving.
        let Some(seat) = context.scope.seat.clone() else {
            return Err(UriError::ConfigurationRejected {
                detail: format!(
                    "{url} is unavailable: the caller scope binds no seat, so no brain \
                     service can be selected while every other scheme resolves"
                ),
            });
        };
        let Some(brain) = self.brains.get(&seat) else {
            return Err(UriError::ConfigurationRejected {
                detail: format!(
                    "{url} is unavailable: seat {seat} serves no brain service, so \
                     brain:// stays typed-unavailable while every other scheme resolves"
                ),
            });
        };
        let policy = brain.policy();
        let Some(id) = request.id.as_deref() else {
            if context.scope.node.is_some() {
                return Err(scope_denied(&url, "node"));
            }
            let serving_scope = policy.project_serving_scope(context.scope.project.as_ref());
            let status = brain.status().map_err(|error| brain_error(&url, error))?;
            let pinned: BTreeMap<&str, String> = status
                .pinned
                .iter()
                .filter(|(source, _)| serving_scope.contains(*source))
                .map(|(source, revision)| (source.as_str(), revision.to_string()))
                .collect();
            let generations: BTreeMap<&str, Value> = status
                .generations
                .iter()
                .filter(|(source, _)| serving_scope.contains(*source))
                .map(|(source, generation)| {
                    (
                        source.as_str(),
                        json!({
                            "id": generation.generation_id.to_string(),
                            "atlasRevision": generation.atlas_revision.to_string(),
                            "manifestDigest": generation.manifest_digest.to_string(),
                            "embeddingModel": generation.embedding_model.to_string(),
                        }),
                    )
                })
                .collect();
            let mut result = json_result(
                request,
                json!({
                    "authority": "brain",
                    "policyDigest": policy.policy_digest.to_string(),
                    "registryRevision": policy.registry_revision,
                    "pinned": &pinned,
                    "generations": &generations,
                }),
            );
            result.notes = vec![format!(
                "pinned to brain policy digest {} at registry revision {} across {} composed sources",
                policy.policy_digest,
                policy.registry_revision,
                pinned.len()
            )];
            return Ok(result);
        };
        let target = super::brain_ids::parse_brain_id(&url, id)?;
        let item_id = target.item;
        let item = brain
            .knowledge_item(&item_id, context.scope.project.as_ref())
            .map_err(|error| brain_error(&url, error))?;
        let object = brain_object_scope(&url, &context.scope, item.provenance.as_ref())?;
        if let Some(dimension) = scope_shortfall(&context.scope, &object) {
            return Err(scope_denied(&url, dimension));
        }
        let generation = &item.generation;
        let page = super::brain_page::page(&url, &target, &item.chunks)?;
        let note = match &item.provenance {
            Some(provenance) => format!(
                "scope proven for atlas node {}; pinned to brain policy digest {}, index \
                 generation {}, atlas revision {}",
                provenance.node_id,
                policy.policy_digest,
                generation.generation_id,
                generation.atlas_revision
            ),
            // Non-Atlas sources carry no node identity. Source authorization
            // was checked by the seat's brain service; they prove no node scope.
            None => format!(
                "knowledge item without Atlas node identity; pinned to brain policy digest {}, \
                 index generation {}, atlas revision {}",
                policy.policy_digest, generation.generation_id, generation.atlas_revision
            ),
        };
        let payload = json!({
                "kind": "knowledge item window",
                "policyDigest": policy.policy_digest.to_string(),
                "registryRevision": policy.registry_revision,
                "generation": {
                    "id": generation.generation_id.to_string(),
                    "atlasId": generation.atlas_id.to_string(),
                    "atlasRevision": generation.atlas_revision.to_string(),
                    "manifestDigest": generation.manifest_digest.to_string(),
                    "chunkerVersion": generation.chunker_version.as_str(),
                    "tokenizer": generation.tokenizer.to_string(),
                    "embeddingModel": generation.embedding_model.to_string(),
                },
                "provenance": item.provenance.as_ref().map(|provenance| json!({
                    "nodeId": provenance.node_id.as_str(),
                    "path": provenance.path.as_str(),
                    "sourceClass": provenance.source_class.as_str(),
                    "scopeTags": &provenance.scope_tags,
                })),
                "itemId": item_id,
                "page": page,
                // Archive-export attribution, present only for items of a
                // published archive source: export account, conversation
                // and message identity, timestamps, declared labels, and
                // rule flags. This is observed record metadata for source
                // attribution — untrusted memory, never prompt authority.
                "archive": item.archive.as_ref().map(|archive| {
                    let mut archive_json = json!({
                    "recordKey": archive.record_key.to_string(),
                    "naturalKey": archive.natural_key.as_str(),
                    "kind": serde_json::to_value(archive.kind).unwrap_or(Value::Null),
                    "namespace": archive.namespace.as_str(),
                    "privacyClass": serde_json::to_value(archive.privacy_class)
                        .unwrap_or(Value::Null),
                    "partIndex": archive.part_index,
                    "partCount": archive.part_count,
                    "exportAccount": archive.export_account.as_deref(),
                    "exportId": archive.export_id.as_deref(),
                    "conversationId": archive.conversation_id.as_deref(),
                    // The operator-declared export root, read from the
                    // persisted declaration: origin members/declaration
                    // paths resolve against it.
                    "exportRoot": archive.export_root.as_deref(),
                    "messageId": archive.message_id.as_deref(),
                    "threadId": archive.thread_id.as_deref(),
                    "createdAt": archive.created_at.map(|created_at| created_at.to_string()),
                    "sentByUser": archive.sent_by_user,
                    "labels": &archive.labels,
                    "ruleFlags": &archive.rule_flags,
                    // Original asset locator when the record carries one
                    // (declaration location and, only when the export
                    // really ships the bytes, the exact member); `null`
                    // otherwise, never a guessed filename.
                        "origin": archive.origin.as_ref().map(|origin| json!({
                            "declaredIn": origin.declared_in.as_deref(),
                            "member": origin.member.as_deref(),
                            "assetId": origin.asset_id.as_deref(),
                            "position": origin.position,
                        })),
                    });
                    // Format-specific export metadata carried verbatim
                    // (Gemini/NotebookLM source names, ChatGPT branch
                    // ancestry); the key stays absent when the record
                    // declares none.
                    if !archive.export_metadata.is_empty() {
                        archive_json["exportMetadata"] = json!(&archive.export_metadata);
                    }
                    archive_json
                }),
        });
        let mut result = json_result(request, payload);
        result.notes = vec![note];
        Ok(result)
    }
}

impl ScopedUriRouter {
    /// Checks captured session/run/lane dimensions and epoch against active ledger state.
    /// Scope dimensions must match exactly; node access is checked at materialization.
    pub fn prove_brain_execution(
        &self,
        scope: &Scope,
        execution: &ExecutionBinding,
    ) -> Result<(), UriError> {
        let session = execution.session_id().to_string();
        let rejected = |reason: String| UriError::ExecutionProof {
            url: format!("brain execution proof for session {session}"),
            reason,
        };
        if scope.session.as_ref() != Some(execution.session_id()) {
            return Err(rejected(
                "the bound scope does not name the proven session".to_owned(),
            ));
        }
        if scope.run.as_ref() != Some(execution.run_id()) {
            return Err(rejected(
                "the bound scope does not name the proven run".to_owned(),
            ));
        }
        if scope.lane.as_ref() != Some(execution.lane_id()) {
            return Err(rejected(
                "the bound scope does not name the proven lane".to_owned(),
            ));
        }
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| storage_error("brain execution ledger lock poisoned"))?;
        let record = ledger
            .live_session(execution.session_id())
            .map_err(storage_error)?;
        if record.epoch != execution.epoch() {
            return Err(rejected(format!(
                "the live session advanced to epoch {}, so the proof's epoch {} is stale",
                record.epoch,
                execution.epoch()
            )));
        }
        if matches!(record.state.as_str(), "ended" | "failed") {
            return Err(rejected("the live session is terminal".to_owned()));
        }
        let (seat, project, lane): (String, String, String) = ledger
            .connection()
            .query_row(
                "SELECT seat_id, project_id, lane_id FROM live_sessions WHERE session_id=?1",
                [execution.session_id().as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(storage_error)?;
        if scope.seat.as_ref().map(|id| id.as_str()) != Some(seat.as_str())
            || scope.project.as_ref().map(|id| id.as_str()) != Some(project.as_str())
            || execution.lane_id().as_str() != lane
        {
            return Err(rejected(
                "the durable session ownership does not match the bound scope".into(),
            ));
        }
        let Some(run) =
            lane_run::read_run(ledger.connection(), execution.run_id()).map_err(storage_error)?
        else {
            return Err(rejected(format!(
                "run {} was not found",
                execution.run_id()
            )));
        };
        if run.lane_id != *execution.lane_id() {
            return Err(rejected(format!(
                "run {} serves lane {}, not the proven lane {}",
                run.run_id,
                run.lane_id,
                execution.lane_id()
            )));
        }
        if run.status.is_terminal() {
            return Err(rejected(format!(
                "run {} is terminal ({:?})",
                run.run_id, run.status
            )));
        }
        if let Some(attempt_id) = &scope.attempt {
            let attempt = lane_run::read_attempt(ledger.connection(), attempt_id)
                .map_err(storage_error)?
                .ok_or_else(|| rejected("the bound attempt does not exist".into()))?;
            if attempt.run_id != run.run_id
                || attempt.attempt_number != run.attempt_number
                || attempt.status.is_terminal()
            {
                return Err(rejected(
                    "the bound attempt is not the run's active attempt".into(),
                ));
            }
        }
        let Some(lane) =
            lane_run::read_lane(ledger.connection(), execution.lane_id()).map_err(storage_error)?
        else {
            return Err(rejected(format!(
                "lane {} was not found",
                execution.lane_id()
            )));
        };
        if lane.status.is_terminal() {
            return Err(rejected(format!(
                "lane {} is terminal ({:?})",
                lane.lane_id, lane.status
            )));
        }
        if scope.seat.as_ref() != Some(&lane.seat_id) {
            return Err(rejected(format!(
                "lane {} belongs to seat {}, not the bound seat",
                lane.lane_id, lane.seat_id
            )));
        }
        if scope.project != lane.project_id {
            return Err(rejected(
                "the bound project does not match the runtime lane".into(),
            ));
        }
        if let Some(serving) = &lane.session_ref {
            if serving != &session {
                return Err(rejected(format!(
                    "lane {session} no longer serves the proven session; it serves {serving}"
                )));
            }
        }
        Ok(())
    }
}

/// Maps a typed brain authority failure onto the URI contract. A missing resource stays a
/// typed miss; a stale authority is operator configuration, not storage.
fn brain_error(url: &str, error: BrainError) -> UriError {
    match error {
        BrainError::NotFound { kind, id } => UriError::UnknownResource {
            url: url.to_owned(),
            kind,
            id,
        },
        BrainError::StaleAuthority { authority, detail } => UriError::ConfigurationRejected {
            detail: format!("brain authority {authority} is stale: {detail}"),
        },
        error => UriError::Storage {
            detail: error.to_string(),
        },
    }
}

/// The scope a resolved knowledge item proves: the caller's bound seat and
/// project, both proven by the resolution itself — the service is selected
/// by the authenticated session seat, and `knowledge_item` serves an item
/// only inside the bound project's declared serving scope, so an item that
/// reaches this point already served under those bindings — plus its Atlas
/// node identity when the source has one. Vault pages carry no node
/// identity and prove no node dimension. Provenance scope tags are
/// source-layer allowlists already enforced when the index was built, not
/// scope dimensions.
fn brain_object_scope(
    url: &str,
    bound: &Scope,
    provenance: Option<&ItemProvenance>,
) -> Result<Scope, UriError> {
    let node = provenance
        .map(|provenance| parse_resource_id(url, &provenance.node_id))
        .transpose()?;
    Ok(Scope {
        seat: bound.seat.clone(),
        project: bound.project.clone(),
        lane: bound.lane.clone(),
        run: bound.run.clone(),
        session: bound.session.clone(),
        attempt: bound.attempt.clone(),
        node,
    })
}
