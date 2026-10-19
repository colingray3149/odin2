//! Governed tools reuse the same seat services and canonical URI authority.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use odin_brain::retrieval::LaneEmbeddingProvider;
use odin_brain::service::{BrainService, RetrievalPosture};
use odin_domain::{Scope, SeatId};
use serde_json::{json, Value};

use odin_brain::index::postgres::{BrainPostgres, RecordFilters, RecordRead};

use crate::host_tools::brain::{
    BrainReadInput, BrainRecordsInput, BrainSearchInput, BrainToolsBackend, RecordOp,
    MAX_RESPONSE_BYTES,
};
use crate::host_tools::operations::LiveSessionBindings;
use crate::host_tools::HostToolError;
use crate::uri::{ExecutionBinding, ScopedUriRouter, UriBody, UriContext};

pub(crate) struct RuntimeBrainTools {
    pub brains: BTreeMap<SeatId, Arc<BrainService>>,
    // The session registry owns operations, which own these tools. Keep
    // this edge weak so stopping the runtime releases the entire graph.
    pub sessions: Weak<LiveSessionBindings>,
    pub router: ScopedUriRouter,
    pub embedding: Option<Arc<dyn LaneEmbeddingProvider>>,
}

fn unavailable(tool: &'static str, error: impl std::fmt::Display) -> HostToolError {
    HostToolError::Unavailable {
        tool,
        reason: error.to_string(),
    }
}

/// The posture a search served under, never silent: `full`, or
/// `lexicalOnly` with why the vector leg did not run.
fn posture_value(posture: RetrievalPosture) -> Value {
    match posture {
        RetrievalPosture::Full => json!({"mode": "full"}),
        RetrievalPosture::LexicalOnly { reason } => {
            let mut value = json!({"mode": "lexicalOnly"});
            value["reason"] = Value::String(reason);
            value
        }
    }
}

fn json_size(value: &Value) -> Result<usize, HostToolError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut size = Counter(0);
    serde_json::to_writer(&mut size, value).map_err(|error| unavailable("brain_search", error))?;
    Ok(size.0)
}

impl RuntimeBrainTools {
    fn service(&self, scope: &Scope) -> Result<&Arc<BrainService>, HostToolError> {
        let denied = || HostToolError::Scope {
            tool: "brain_search",
            reason: "knowledge requires the registered session's exact seat and lane",
        };
        let seat = scope.seat.as_ref().ok_or_else(denied)?;
        let session = scope.session.as_ref().ok_or_else(denied)?;
        let sessions = self
            .sessions
            .upgrade()
            .ok_or_else(|| unavailable("brain_search", "knowledge runtime has stopped"))?;
        let binding = sessions.binding_for(session).ok_or_else(denied)?;
        if &binding.policy.seat_id != seat || scope.lane.as_ref() != Some(&binding.policy.lane_id) {
            return Err(denied());
        }
        let brain = self
            .brains
            .get(seat)
            .ok_or_else(|| unavailable("brain_search", "seat has no composed knowledge service"))?;
        // The brain is composed once, at odind's startup revision; a
        // session bound to another revision is served only when both
        // publications compose identically (a routine in between).
        if !sessions
            .operations()
            .same_composition(brain.policy().registry_revision, binding.served_revision)
        {
            return Err(unavailable(
                "brain_search",
                "knowledge service and session publication revisions differ",
            ));
        }
        Ok(brain)
    }
}

/// A record read as the model sees it: the record, or why not.
fn record_value(read: RecordRead, what: &str) -> Value {
    match read {
        RecordRead::Found(value) => value,
        RecordRead::Withheld(reason) => json!({"refused": reason}),
        RecordRead::Missing => json!({"missing": format!(
            "no {what}; op=search finds ids (filters.kind narrows it)"
        )}),
    }
}

impl RuntimeBrainTools {
    /// The 256-d query embedding of the seat's declared embedding lane, or
    /// why the search runs lexical-only.
    fn query_embedding(
        &self,
        brain: &BrainService,
        scope: &Scope,
        text: &str,
    ) -> (Option<Vec<f32>>, Value) {
        let embedded = (|| {
            let knowledge = brain
                .policy()
                .knowledge
                .as_ref()
                .ok_or("seat has no declared knowledge policy")?;
            let lane = scope.lane.as_ref().ok_or("no bound runtime lane")?;
            let provider = self
                .embedding
                .as_ref()
                .ok_or("no embedding provider is composed")?;
            let embedder = Arc::clone(provider)
                .bind_lane(lane)
                .map_err(|error| format!("embedding lane: {error}"))?;
            let query = knowledge
                .retrieval_query(text.to_owned())
                .map_err(|error| error.to_string())?;
            odin_brain::retrieval::embed_one(embedder.as_ref(), &query.text)
                .map(|vector| vector.dims().to_vec())
                .map_err(|error| error.to_string())
        })();
        match embedded {
            Ok(dims) => (Some(dims), json!({"mode": "hybrid"})),
            Err(reason) => (
                None,
                json!({"mode": "lexicalOnly", "reason": reason.to_string()}),
            ),
        }
    }

    fn store(brain: &BrainService) -> Result<&Arc<BrainPostgres>, HostToolError> {
        brain.config().postgres.as_ref().ok_or_else(|| {
            unavailable(
                "brain",
                "the brain has no Postgres store ([brain] postgres is not configured)",
            )
        })
    }
}

impl BrainToolsBackend for RuntimeBrainTools {
    fn preflight(&self, scope: &Scope) -> Result<(), HostToolError> {
        self.service(scope).map(|_| ())
    }

    fn search(
        &self,
        scope: &Scope,
        execution: &ExecutionBinding,
        input: BrainSearchInput,
    ) -> Result<Value, HostToolError> {
        self.router
            .prove_brain_execution(scope, execution)
            .map_err(HostToolError::from)?;
        let brain = self.service(scope)?;
        let policy = brain.policy();
        let knowledge = policy
            .knowledge
            .as_ref()
            .ok_or_else(|| unavailable("brain_search", "seat has no declared knowledge policy"))?;
        let mut query = knowledge
            .retrieval_query(input.query)
            .map_err(|error| unavailable("brain_search", error))?;
        query.sources = policy.project_serving_scope(scope.project.as_ref());
        // A question that names a source ("what did I talk to Grok about")
        // searches that source alone: its conversations rarely contain the
        // source's own name, so a union search surfaces other sources.
        if let Some(source) = input.source.as_deref() {
            let declared: Vec<String> = query.sources.iter().map(ToString::to_string).collect();
            query.sources.retain(|id| id.as_str() == source);
            if query.sources.is_empty() {
                return Err(HostToolError::Arguments {
                    tool: "brain_search",
                    detail: format!(
                        "source {source:?} is not declared for this session; its sources are: {}",
                        declared.join(", ")
                    ),
                });
            }
        }
        query
            .validate()
            .map_err(|error| unavailable("brain_search", error))?;
        let lane = scope.lane.as_ref().ok_or(HostToolError::Scope {
            tool: "brain_search",
            reason: "a bound runtime lane is required",
        })?;
        let embedder = self
            .embedding
            .as_ref()
            .map(|provider| Arc::clone(provider).bind_lane(lane))
            .transpose()
            .map_err(|error| unavailable("brain_search", format!("embedding lane: {error:?}")))?;
        let started = std::time::Instant::now();
        // The posture travels with the hits: a hybrid search whose lane
        // embedding is typed-unavailable serves its lexical leg and says so;
        // a vector plan or any other retrieval failure refuses here.
        let response = brain
            .retrieve(&query, scope.project.as_ref(), embedder.as_ref())
            .map_err(|error| unavailable("brain_search", error))?;
        let total = started.elapsed();
        if total >= std::time::Duration::from_secs(2) {
            tracing::debug!(
                "odind: brain_search over {} source(s) took {} ms",
                query.sources.len(),
                total.as_millis()
            );
        }
        let context = UriContext::with_execution(scope.clone(), execution.clone());
        let posture = posture_value(response.posture);
        let mut bytes = 1024usize.saturating_add(json_size(&posture)?);
        let mut results = Vec::with_capacity(response.hits.len());
        let mut truncated = false;
        for hit in response.hits {
            let url = format!("brain://{}", hit.item_id);
            // The URI path additionally proves every bound node/run dimension.
            // Do not turn a node-bound search into a seat-only retrieval path.
            self.router
                .resolve(&context, &url)
                .map_err(HostToolError::from)?;
            let value = json!({"url": url, "hit": hit});
            let length = json_size(&value)?;
            if bytes.saturating_add(length).saturating_add(1) > MAX_RESPONSE_BYTES {
                truncated = true;
                break;
            }
            bytes += length + 1;
            results.push(value);
        }
        let mut output = json!({
            "policyDigest": policy.policy_digest,
            "registryRevision": policy.registry_revision,
            "truncated": truncated,
        });
        output["posture"] = posture;
        output["results"] = Value::Array(results);
        Ok(output)
    }

    fn read(
        &self,
        scope: &Scope,
        execution: &ExecutionBinding,
        input: BrainReadInput,
    ) -> Result<Value, HostToolError> {
        self.router
            .prove_brain_execution(scope, execution)
            .map_err(HostToolError::from)?;
        self.service(scope)?;
        // Read never rebuilds first: a citation to a moved head stays a typed miss.
        let result = self
            .router
            .resolve(
                &UriContext::with_execution(scope.clone(), execution.clone()),
                &input.url,
            )
            .map_err(HostToolError::from)?;
        match result.body {
            UriBody::Json(body) => {
                Ok(json!({"url": input.url, "body": body, "notes": result.notes}))
            }
            UriBody::Bytes(_) => Err(unavailable(
                "brain_read",
                "brain URI returned a non-JSON payload",
            )),
        }
    }

    fn records(
        &self,
        scope: &Scope,
        execution: &ExecutionBinding,
        input: BrainRecordsInput,
    ) -> Result<Value, HostToolError> {
        self.router
            .prove_brain_execution(scope, execution)
            .map_err(HostToolError::from)?;
        let brain = self.service(scope)?;
        let store = Self::store(brain)?;
        // Seat sessions run cloud model lanes and may switch between them
        // mid-session, so local_only records are never served here.
        let local = false;
        let failed = |error: odin_brain::error::BrainError| unavailable("brain", error);
        let limit = i64::from(input.limit.unwrap_or(10));
        let query = input.query.as_deref().unwrap_or("").trim();
        let id = input.id.as_deref().unwrap_or("").trim();
        let filters = RecordFilters {
            kind: input.filters.kind,
            person: input.filters.person,
            source: input.filters.source,
            topic: input.filters.topic,
            from: input.filters.from,
            to: input.filters.to,
        };
        let withheld_note =
            "some records matching a query word were withheld (a secret finding or a private \
             path); nothing more about them can be read from this session, so answer from the \
             results above";
        let output = match input.op {
            RecordOp::Search => {
                let (embedding, posture) = self.query_embedding(brain, scope, query);
                let found = store
                    .search_records(query, embedding, &filters, local, limit)
                    .map_err(failed)?;
                let mut output = json!({"results": found.hits, "posture": posture});
                if found.withheld {
                    output["withheld"] = json!(withheld_note);
                }
                output
            }
            RecordOp::Asset => {
                let near = input.filters.near.map(|near| (near.lat, near.lon, near.km));
                let found = store
                    .find_assets(query, &filters, near, local, limit)
                    .map_err(failed)?;
                let mut output = json!({"results": found.hits});
                if found.withheld {
                    output["withheld"] = json!(withheld_note);
                }
                output
            }
            RecordOp::Person => record_value(
                store.read_person(id, local).map_err(failed)?,
                "person matches that id, name, handle, email or phone",
            ),
            RecordOp::Fact => record_value(
                store.read_fact(id, local).map_err(failed)?,
                "fact has that id",
            ),
            RecordOp::Photo => match store.read_asset(id, local).map_err(failed)? {
                RecordRead::Found(asset) if asset["kind"] != "photo" => {
                    json!({"refused": format!("{id} is a {}, not a photo", asset["kind"])})
                }
                // Pixels stay on disk: a seat's context budget counts text
                // only (the extension refuses media as uncountable), and
                // photos carry no OCR secret check yet.
                RecordRead::Found(asset) => json!({
                    "photo": asset,
                    "pixels": "not opened: this session's context budget cannot count images and \
                               photos have no OCR secret check yet; describe it from the metadata \
                               or offer to send Colin the file",
                }),
                other => record_value(other, "photo has that exact path"),
            },
        };
        if json_size(&output)? > MAX_RESPONSE_BYTES {
            return Err(unavailable(
                "brain",
                "brain response exceeds the transport bound; lower the limit",
            ));
        }
        Ok(output)
    }
}
