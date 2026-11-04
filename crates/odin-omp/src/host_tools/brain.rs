//! Model-callable knowledge tools over the runtime's existing scoped services.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, Weak};

use odin_domain::{CapabilityId, Digest, Scope};
use odin_kernel::{CapabilityContract, PreparedEffect};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{
    ConsumedHostCommand, HostInvocation, HostTool, HostToolError, HostToolRegistry,
    InternalBindingKey, RpcHostToolDefinition, ToolLoadMode,
};
use crate::uri::{ExecutionBinding, ScopedUriRouter, UriScheme};

pub const SEARCH_HANDLER: &str = "odin_brain.search";
pub const SEARCH_EVIDENCE: &str = "odin_brain.search_evidence";
pub const READ_HANDLER: &str = "odin_brain.read";
pub const READ_EVIDENCE: &str = "odin_brain.read_evidence";
pub const RECORDS_HANDLER: &str = "odin_brain.records";
pub const RECORDS_EVIDENCE: &str = "odin_brain.records_evidence";
pub const NOTE_HANDLER: &str = "odin_brain.note";
pub const NOTE_EVIDENCE: &str = "odin_brain.note_evidence";
pub const MAX_RESPONSE_BYTES: usize = 262_144;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrainSearchInput {
    pub query: String,
    /// Optionally one of the session's declared sources to search alone.
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrainReadInput {
    pub url: String,
}

/// One note pinned to an open task by the id live memory shows.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskNoteInput {
    pub task: String,
    pub note: String,
}

/// One read of the curated brain records: people, conversation units,
/// facts with evidence, the photo/doc index, and the map of a person,
/// project or Discord place.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecordOp {
    Records,
    Person,
    Fact,
    Asset,
    Photo,
    Project,
    Place,
    Status,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrainRecordsInput {
    pub op: RecordOp,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub filters: RecordFiltersInput,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordFiltersInput {
    pub kind: Option<String>,
    pub person: Option<String>,
    pub source: Option<String>,
    pub topic: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub near: Option<NearInput>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NearInput {
    pub lat: f64,
    pub lon: f64,
    pub km: f64,
}

/// Longest query and record id, in UTF-8 bytes.
const MAX_QUERY_BYTES: usize = 4096;
const MAX_ID_BYTES: usize = 1024;
/// Widest radius a place filter may ask for.
const MAX_NEAR_KM: f64 = 20_000.0;
/// Records a read returns when it names no limit, and the most it may name.
const DEFAULT_RECORD_LIMIT: u32 = 10;
const MAX_RECORD_LIMIT: u32 = 50;

/// `YYYY`, `YYYY-MM` or `YYYY-MM-DD`, widened to the period's first day
/// (`from`) or last day (`to`).
fn date_bound(value: &str, end: bool) -> Option<String> {
    let parts: Vec<&str> = value.split('-').collect();
    let number = |text: &str, width: usize| {
        (text.len() == width && text.bytes().all(|b| b.is_ascii_digit()))
            .then(|| text.parse::<u32>().ok())
            .flatten()
    };
    let year = number(parts.first()?, 4)?;
    let month = match parts.get(1) {
        Some(text) => number(text, 2).filter(|m| (1..=12).contains(m))?,
        None => {
            if end {
                12
            } else {
                1
            }
        }
    };
    let last = match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    let day = match parts.get(2) {
        Some(text) => number(text, 2).filter(|d| (1..=last).contains(d))?,
        None => {
            if end {
                last
            } else {
                1
            }
        }
    };
    (parts.len() <= 3).then(|| format!("{year:04}-{month:02}-{day:02}"))
}

impl BrainRecordsInput {
    fn validate(&mut self) -> Result<(), String> {
        fn text(value: &Option<String>) -> Option<&str> {
            value.as_deref().map(str::trim).filter(|v| !v.is_empty())
        }
        let by_id = matches!(
            self.op,
            RecordOp::Person
                | RecordOp::Fact
                | RecordOp::Photo
                | RecordOp::Project
                | RecordOp::Place
        );
        // A by-name lookup sent as `query` means the same read.
        if by_id && text(&self.id).is_none() {
            self.id = self.query.take();
        }
        match self.op {
            RecordOp::Records if text(&self.query).is_none() => {
                return Err("records needs a query".into())
            }
            _ if by_id && text(&self.id).is_none() => {
                return Err("person, fact, photo, project and place need an id".into())
            }
            RecordOp::Asset
                if text(&self.query).is_none()
                    && text(&self.filters.person).is_none()
                    && self.filters.from.is_none()
                    && self.filters.to.is_none()
                    && self.filters.near.is_none() =>
            {
                return Err("asset needs a query, a person, a date range or a place".into())
            }
            _ => {}
        }
        if self
            .query
            .as_ref()
            .is_some_and(|q| q.len() > MAX_QUERY_BYTES)
            || self.id.as_ref().is_some_and(|q| q.len() > MAX_ID_BYTES)
        {
            return Err(format!(
                "query must fit {MAX_QUERY_BYTES} and id {MAX_ID_BYTES} UTF-8 bytes"
            ));
        }
        for (name, bound, end) in [
            ("from", &mut self.filters.from, false),
            ("to", &mut self.filters.to, true),
        ] {
            if let Some(value) = bound.as_deref() {
                *bound = Some(date_bound(value.trim(), end).ok_or_else(|| {
                    format!("filters.{name} {value:?} is not YYYY, YYYY-MM or YYYY-MM-DD")
                })?);
            }
        }
        if let Some(near) = self.filters.near {
            if !(-90.0..=90.0).contains(&near.lat)
                || !(-180.0..=180.0).contains(&near.lon)
                || !(near.km > 0.0 && near.km <= MAX_NEAR_KM)
            {
                return Err(format!(
                    "filters.near needs lat in [-90, 90], lon in [-180, 180] and 0 < km <= {MAX_NEAR_KM}"
                ));
            }
        }
        self.limit = Some(
            self.limit
                .unwrap_or(DEFAULT_RECORD_LIMIT)
                .clamp(1, MAX_RECORD_LIMIT),
        );
        Ok(())
    }
}

/// Runtime composition binds this slot once, after services and URI routing exist.
pub type BrainToolsSlot = Arc<OnceLock<Arc<dyn BrainToolsBackend>>>;

pub trait BrainToolsBackend: Send + Sync {
    fn source_ids(&self, scope: &Scope) -> Vec<String>;
    fn preflight(&self, scope: &Scope) -> Result<(), HostToolError>;
    fn search(
        &self,
        scope: &Scope,
        execution: &ExecutionBinding,
        input: BrainSearchInput,
    ) -> Result<Value, HostToolError>;
    fn read(
        &self,
        scope: &Scope,
        execution: &ExecutionBinding,
        input: BrainReadInput,
    ) -> Result<Value, HostToolError>;
    fn records(
        &self,
        scope: &Scope,
        execution: &ExecutionBinding,
        input: BrainRecordsInput,
    ) -> Result<Value, HostToolError>;
    fn note(
        &self,
        scope: &Scope,
        execution: &ExecutionBinding,
        input: TaskNoteInput,
    ) -> Result<Value, HostToolError>;
}

#[derive(Clone, Copy)]
enum Operation {
    Search,
    Read,
    Records,
    Note,
}

impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::Search => "brain_search",
            Self::Read => "brain_read",
            Self::Records => "brain",
            Self::Note => "task_note",
        }
    }
    fn handler(self) -> &'static str {
        match self {
            Self::Search => SEARCH_HANDLER,
            Self::Read => READ_HANDLER,
            Self::Records => RECORDS_HANDLER,
            Self::Note => NOTE_HANDLER,
        }
    }
    fn evidence(self) -> &'static str {
        match self {
            Self::Search => SEARCH_EVIDENCE,
            Self::Read => READ_EVIDENCE,
            Self::Records => RECORDS_EVIDENCE,
            Self::Note => NOTE_EVIDENCE,
        }
    }
}

enum Input {
    Search(BrainSearchInput),
    Read(BrainReadInput),
    Records(BrainRecordsInput),
    Note(TaskNoteInput),
}

struct BrainTool {
    operation: Operation,
    // Runtime owns the slot; services may own operation gates which own
    // this registry. A weak edge prevents retaining the runtime in a cycle.
    slot: Weak<OnceLock<Arc<dyn BrainToolsBackend>>>,
    definition: RpcHostToolDefinition,
}

impl BrainTool {
    fn backend(&self) -> Result<Arc<dyn BrainToolsBackend>, HostToolError> {
        self.slot
            .upgrade()
            .and_then(|slot| slot.get().cloned())
            .ok_or_else(|| HostToolError::Unavailable {
                tool: self.operation.name(),
                reason: "brain runtime is not composed or has stopped".into(),
            })
    }

    fn input(&self, arguments: Value) -> Result<Input, HostToolError> {
        let invalid = |detail: String| HostToolError::Arguments {
            tool: self.operation.name(),
            detail,
        };
        match self.operation {
            Operation::Search => {
                let input: BrainSearchInput = serde_json::from_value(arguments)
                    .map_err(|error| invalid(error.to_string()))?;
                if input.query.trim().is_empty() || input.query.len() > MAX_QUERY_BYTES {
                    return Err(invalid(format!(
                        "query must contain text and fit {MAX_QUERY_BYTES} UTF-8 bytes"
                    )));
                }
                Ok(Input::Search(input))
            }
            Operation::Read => {
                let input: BrainReadInput = serde_json::from_value(arguments)
                    .map_err(|error| invalid(error.to_string()))?;
                let request = ScopedUriRouter::parse(&input.url)
                    .map_err(|error| invalid(error.to_string()))?;
                if request.scheme != UriScheme::Brain || request.id.is_none() {
                    return Err(invalid(
                        "read requires an identified canonical brain:// URL".into(),
                    ));
                }
                Ok(Input::Read(input))
            }
            Operation::Records => {
                let mut input: BrainRecordsInput = serde_json::from_value(arguments)
                    .map_err(|error| invalid(error.to_string()))?;
                input.validate().map_err(invalid)?;
                Ok(Input::Records(input))
            }
            Operation::Note => {
                let input: TaskNoteInput = serde_json::from_value(arguments)
                    .map_err(|error| invalid(error.to_string()))?;
                if input.task.trim().is_empty() || input.note.trim().is_empty() {
                    return Err(invalid("task and note must hold text".into()));
                }
                Ok(Input::Note(input))
            }
        }
    }
}

impl HostTool for BrainTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn parameters_for_scope(&self, scope: &Scope) -> Option<Value> {
        if !matches!(self.operation, Operation::Search) {
            return None;
        }
        let values = self
            .backend()
            .map(|backend| backend.source_ids(scope))
            .unwrap_or_default();
        let mut parameters = self.definition.parameters.clone();
        parameters["properties"]["source"]["description"] =
            Value::String("Search only this declared source.".to_owned());
        Some(super::schema_compat::resolve_ids(
            parameters,
            "/properties/source",
            values,
        ))
    }

    fn preflight(
        &self,
        _contract: &CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.input(arguments.clone())?;
        self.backend()?.preflight(scope)
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Scope {
            tool: self.operation.name(),
            reason: "brain tools require governed execution proof",
        })
    }

    fn invoke_execution(
        &self,
        _effect: &PreparedEffect,
        _consumed: &ConsumedHostCommand,
        invocation: HostInvocation,
        execution: Option<&ExecutionBinding>,
    ) -> Result<Value, HostToolError> {
        let execution = execution.ok_or(HostToolError::Scope {
            tool: self.operation.name(),
            reason: "the caller supplied no trusted execution proof",
        })?;
        let input = self.input(invocation.arguments)?;
        let backend = self.backend()?;
        let output = match input {
            Input::Search(input) => backend.search(&invocation.scope, execution, input)?,
            Input::Read(input) => backend.read(&invocation.scope, execution, input)?,
            Input::Records(input) => backend.records(&invocation.scope, execution, input)?,
            Input::Note(input) => backend.note(&invocation.scope, execution, input)?,
        };
        let bytes = serde_json::to_vec(&output).map_err(|error| HostToolError::Response {
            tool: self.operation.name(),
            detail: error.to_string(),
        })?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(HostToolError::Unavailable {
                tool: self.operation.name(),
                reason: "knowledge response exceeds the transport bound".into(),
            });
        }
        Ok(output)
    }

    fn requires_execution_proof(&self) -> bool {
        true
    }
}

struct BrainEvidence {
    definition: RpcHostToolDefinition,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceInput {
    output: Value,
}

impl HostTool for BrainEvidence {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }
    fn preflight(
        &self,
        _contract: &CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Evidence exists only after the governed handler returns.
        Ok(())
    }
    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let input: EvidenceInput =
            serde_json::from_value(invocation.arguments).map_err(|error| {
                HostToolError::Arguments {
                    tool: "brain_evidence",
                    detail: error.to_string(),
                }
            })?;
        let bytes = odin_strict_json::canonicalize(&input.output).map_err(|error| {
            HostToolError::Response {
                tool: "brain_evidence",
                detail: error.to_string(),
            }
        })?;
        Ok(json!({"contentDigest": Digest::hash(&bytes), "byteCount": bytes.len()}))
    }
}

pub fn register(
    registry: &mut HostToolRegistry,
    slot: BrainToolsSlot,
    contracts: &BTreeMap<CapabilityId, CapabilityContract>,
) -> Result<(), HostToolError> {
    for contract in contracts.values() {
        let (operation, parameters) = match contract.id.as_str() {
            "brain.search" => (
                Operation::Search,
                crate::capability_parameters!("brain.search"),
            ),
            "brain.read" => (Operation::Read, crate::capability_parameters!("brain.read")),
            "brain" => (Operation::Records, crate::capability_parameters!("brain")),
            "task.note" => (Operation::Note, crate::capability_parameters!("task.note")),
            _ => continue,
        };
        let tool: Arc<dyn HostTool> = Arc::new(BrainTool {
            operation,
            slot: Arc::downgrade(&slot),
            definition: RpcHostToolDefinition {
                name: contract.tool_name.as_str().to_owned().into(),
                label: contract.id.as_str().to_owned().into(),
                description: contract.description.clone().into(),
                parameters,
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        });
        registry.register(Arc::clone(&tool))?;
        registry.register_internal(
            InternalBindingKey::Builtin(operation.handler().into()),
            tool,
        )?;
        registry.register_internal(InternalBindingKey::Builtin(operation.evidence().into()), Arc::new(BrainEvidence {
            definition: RpcHostToolDefinition {
                name: operation.evidence().into(), label: "Brain evidence".into(),
                description: "Internal content-free digest of a governed knowledge response.".into(),
                parameters: json!({"type":"object","additionalProperties":false,"properties":{"output":{"type":"object"}},"required":["output"]}),
                hidden: true, load_mode: ToolLoadMode::Essential,
            },
        }))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_by_name_lookup_sent_as_query_reads_the_same_record() {
        let mut place: BrainRecordsInput =
            serde_json::from_value(json!({"op":"place","query":"orders"})).unwrap();
        place.validate().unwrap();
        assert_eq!(place.id.as_deref(), Some("orders"));
        let mut bare: BrainRecordsInput = serde_json::from_value(json!({"op":"place"})).unwrap();
        assert!(bare.validate().is_err());
        let mut records: BrainRecordsInput =
            serde_json::from_value(json!({"op":"records","query":"orders"})).unwrap();
        records.validate().unwrap();
        assert_eq!(records.id, None);
    }

    /// A year, month or day widens to the period's first day for `from` and its last for `to`;
    /// leap days are real days, and anything else is refused.
    #[test]
    fn date_filters_widen_to_the_period_and_refuse_nonsense() {
        let widened = |value, end| date_bound(value, end);
        assert_eq!(widened("2024", false).as_deref(), Some("2024-01-01"));
        assert_eq!(widened("2024", true).as_deref(), Some("2024-12-31"));
        assert_eq!(widened("2024-02", true).as_deref(), Some("2024-02-29"));
        assert_eq!(widened("2023-02", true).as_deref(), Some("2023-02-28"));
        assert_eq!(widened("2024-02-29", false).as_deref(), Some("2024-02-29"));
        for refused in ["2023-02-29", "2024-13", "2024-01-01T00", "24", "2024-1", ""] {
            assert_eq!(widened(refused, false), None, "{refused:?}");
        }
    }

    #[test]
    fn a_record_read_is_bounded_in_text_distance_and_count() {
        let validated = |arguments| -> Result<BrainRecordsInput, String> {
            let mut input: BrainRecordsInput = serde_json::from_value(arguments).unwrap();
            input.validate().map(|()| input)
        };
        let long = "q".repeat(MAX_QUERY_BYTES + 1);
        assert!(validated(json!({"op": "records", "query": long})).is_err());
        let far = json!({"op": "asset", "filters": {"near": {"lat": 1.0, "lon": 2.0, "km": MAX_NEAR_KM + 1.0}}});
        assert!(validated(far).is_err());
        let many = validated(json!({"op": "records", "query": "orders", "limit": 500})).unwrap();
        assert_eq!(many.limit, Some(MAX_RECORD_LIMIT));
        let default = validated(json!({"op": "records", "query": "orders"})).unwrap();
        assert_eq!(default.limit, Some(DEFAULT_RECORD_LIMIT));
    }
}
