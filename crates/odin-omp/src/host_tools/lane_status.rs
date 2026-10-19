//! `odin_lane_status` — the durable status snapshot of the bound lane.
//!
//! The tool reads the real `lanes` ledger row for the invocation-bound lane;
//! the model never widens the binding. An unbound seat or lane and a foreign
//! lane id are rejected before the ledger is consulted, and the stored row
//! must prove every bound scope dimension before any field is disclosed.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use odin_domain::{LaneId, LaneStatus, ProjectId, RunId, Scope, SeatId, SessionId};
use odin_ledger::{encode_utc, lane_run, Ledger, LedgerError, LedgerResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::host_tools::{
    lock_ledger, response, HostInvocation, HostTool, HostToolError, RpcHostToolDefinition,
    ToolLoadMode,
};

/// Reports the durable status, revision, and ownership of the bound lane.
pub struct LaneStatusTool {
    ledger: Arc<Mutex<Ledger>>,
    definition: RpcHostToolDefinition,
}

impl LaneStatusTool {
    pub const NAME: &str = "odin_lane_status";

    pub fn new(ledger: Arc<Mutex<Ledger>>) -> Self {
        Self {
            ledger,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(Self::NAME),
                label: Cow::Borrowed("Lane Status"),
                description: Cow::Borrowed(
                    "Report the durable status, revision, and ownership of the lane bound to this session, read directly from the ledger. The requested lane id must equal the bound lane; foreign lanes, unknown fields, and unbound scopes are rejected without disclosure.",
                ),
                parameters: parameters(),
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        }
    }

    fn scope(reason: &'static str) -> HostToolError {
        HostToolError::Scope {
            tool: Self::NAME,
            reason,
        }
    }

    /// Proves one optional scope dimension against the ledger row: a bound
    /// dimension must be present on the row with the exact bound value.
    fn prove<T: PartialEq + ?Sized>(
        bound: Option<&T>,
        recorded: Option<&T>,
        reason: &'static str,
    ) -> Result<(), HostToolError> {
        match (bound, recorded) {
            (None, _) => Ok(()),
            (Some(expected), Some(actual)) if expected == actual => Ok(()),
            (Some(_), _) => Err(Self::scope(reason)),
        }
    }

    /// Shared lane lookup and seat/project/run/session validation for preflight and invocation.
    fn proved_record(
        &self,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<lane_run::LaneRecord, HostToolError> {
        // The scope decides; a foreign lane is denied before the ledger is
        // locked, so another lane's existence is never observable here.
        let bound_seat = scope
            .seat
            .as_ref()
            .ok_or_else(|| Self::scope("the invocation scope is not bound to a seat"))?;
        let bound_lane = scope
            .lane
            .as_ref()
            .ok_or_else(|| Self::scope("the invocation scope is not bound to a lane"))?;

        let arguments: LaneStatusArguments =
            serde_json::from_value(arguments.clone()).map_err(|error| {
                HostToolError::Arguments {
                    tool: Self::NAME,
                    detail: format!("arguments violate the odin_lane_status schema: {error}"),
                }
            })?;
        if arguments.lane_id.as_str() != bound_lane.as_str() {
            return Err(Self::scope(
                "the requested lane is outside the bound lane scope",
            ));
        }

        let record = {
            let ledger = lock_ledger(Self::NAME, &self.ledger)?;
            lane_run::read_lane(ledger.connection(), bound_lane)?.ok_or_else(|| {
                HostToolError::Ledger(LedgerError::NotFound {
                    kind: "lane",
                    id: bound_lane.to_string(),
                })
            })?
        };

        // The stored row must prove the exact bound scope before disclosure.
        Self::prove(
            Some(bound_seat),
            Some(&record.seat_id),
            "the ledger lane does not belong to the bound seat",
        )?;
        Self::prove(
            scope.project.as_ref(),
            record.project_id.as_ref(),
            "the ledger lane does not belong to the bound project",
        )?;
        Self::prove(
            scope.run.as_ref(),
            record.current_run_id.as_ref(),
            "the ledger lane is not running the bound run",
        )?;
        Self::prove(
            scope.session.as_ref().map(SessionId::as_str),
            record.session_ref.as_deref(),
            "the ledger lane session does not match the bound session",
        )?;
        Ok(record)
    }
}

impl HostTool for LaneStatusTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Validate without projecting lane contents; invocation repeats the checks.
        self.proved_record(scope, arguments)?;
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let record = self.proved_record(&invocation.scope, &invocation.arguments)?;
        response(Self::NAME, &LaneStatusView::from_record(&record)?)
    }
}

fn parameters() -> Value {
    json!({
        "type": "object",
        "properties": {
            "laneId": {
                "type": "string",
                "minLength": 1,
                "description": "Lane to report; must equal the lane bound to this invocation."
            }
        },
        "required": ["laneId"],
        "additionalProperties": false
    })
}

/// The durable lane row projected as model-facing camelCase JSON; timestamps are explicit UTC
/// RFC3339 strings.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LaneStatusView {
    lane_id: LaneId,
    seat_id: SeatId,
    project_id: Option<ProjectId>,
    template_id: String,
    backend: String,
    status: LaneStatus,
    revision: i64,
    desired_revision: i64,
    current_run_id: Option<RunId>,
    session_ref: Option<String>,
    provider_lease_id: Option<String>,
    created_by: String,
    created_at: String,
    updated_at: String,
    retained: bool,
}

impl LaneStatusView {
    /// Projects the durable row; encoding the UTC timestamps is fallible.
    fn from_record(record: &lane_run::LaneRecord) -> LedgerResult<Self> {
        Ok(Self {
            lane_id: record.lane_id.clone(),
            seat_id: record.seat_id.clone(),
            project_id: record.project_id.clone(),
            template_id: record.template_id.clone(),
            backend: record.backend.clone(),
            status: record.status,
            revision: record.revision,
            desired_revision: record.desired_revision,
            current_run_id: record.current_run_id.clone(),
            session_ref: record.session_ref.clone(),
            provider_lease_id: record.provider_lease_id.clone(),
            created_by: record.created_by.clone(),
            created_at: encode_utc(record.created_at)?,
            updated_at: encode_utc(record.updated_at)?,
            retained: record.retained,
        })
    }
}

/// Extracts validated evidence from a settled `odin_lane_status` result.
///
/// The authority's executor relays the handler's exact result here; the
/// extractor proves the required lane fields before any digest is settled,
/// and a result that cannot be projected is surfaced as uncertainty rather
/// than silently accepted.
pub struct LaneStatusEvidenceTool {
    definition: RpcHostToolDefinition,
}

impl LaneStatusEvidenceTool {
    /// Internal binding id the admitted capability's evidence extractor
    /// resolves through.
    pub const ID: &str = "odin_lane_status_evidence";

    /// Builds the extractor over no shared state: it validates exactly what
    /// the handler produced.
    pub fn new() -> Self {
        Self {
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(Self::ID),
                label: Cow::Borrowed("Lane Status Evidence"),
                description: Cow::Borrowed(
                    "Extract validated evidence from an odin_lane_status result.",
                ),
                parameters: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "output": {
                            "type": "object",
                            "additionalProperties": true
                        }
                    },
                    "required": ["output"]
                }),
                hidden: true,
                load_mode: ToolLoadMode::Essential,
            },
        }
    }

    fn required_text(output: &Value, field: &str) -> Result<String, HostToolError> {
        let value =
            output
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| HostToolError::Arguments {
                    tool: Self::ID,
                    detail: format!("lane status result has no string {field}"),
                })?;
        if value.is_empty() {
            return Err(HostToolError::Arguments {
                tool: Self::ID,
                detail: format!("lane status result has an empty {field}"),
            });
        }
        Ok(value.to_owned())
    }
}

impl Default for LaneStatusEvidenceTool {
    fn default() -> Self {
        Self::new()
    }
}

impl HostTool for LaneStatusEvidenceTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Explicit no-gate, by construction: an evidence extractor's input
        // is the handler's post-effect output, which cannot exist at
        // dispatch time, so there is no declared readiness to observe
        // pre-consume. Its strict output-field validation is the execution
        // and governs at the permit.
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let arguments: EvidenceArguments =
            serde_json::from_value(invocation.arguments).map_err(|error| {
                HostToolError::Arguments {
                    tool: Self::ID,
                    detail: format!("arguments violate the extractor schema: {error}"),
                }
            })?;
        let output = &arguments.output;
        let lane_id = Self::required_text(output, "laneId")?;
        let status = Self::required_text(output, "status")?;
        let backend = Self::required_text(output, "backend")?;
        let revision = output
            .get("revision")
            .and_then(Value::as_i64)
            .ok_or_else(|| HostToolError::Arguments {
                tool: Self::ID,
                detail: "lane status result has no integer revision".to_owned(),
            })?;
        if revision < 0 {
            return Err(HostToolError::Arguments {
                tool: Self::ID,
                detail: "lane status result has a negative revision".to_owned(),
            });
        }
        Ok(json!({
            "extractedBy": Self::ID,
            "laneId": lane_id,
            "status": status,
            "backend": backend,
            "revision": revision,
        }))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EvidenceArguments {
    output: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LaneStatusArguments {
    lane_id: LaneId,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use odin_domain::Scope;
    use odin_ledger::lane_run::{self, NewLane};
    use odin_ledger::{Ledger, LedgerError};
    use serde_json::json;
    use time::OffsetDateTime;

    use super::LaneStatusTool;
    use crate::host_tools::fixtures::fixture_contract;
    use crate::host_tools::{HostInvocation, HostTool, HostToolError};
    use crate::test_support::ledger;

    const TIMESTAMP_MS: i64 = 1_700_000_000_000;
    const SEAT_ID: &str = "seat:1700000000000:lane-status";
    const LANE_A: &str = "lane:1700000000000:alpha";
    const LANE_B: &str = "lane:1700000000000:beta";

    fn fixed_instant() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(TIMESTAMP_MS / 1_000).expect("fixed instant")
    }

    fn store_lane(guard: &Ledger, lane_id: &str, seat_id: &str) {
        lane_run::create_lane(
            guard.connection(),
            &NewLane {
                lane_id: lane_id.parse().expect("lane id"),
                seat_id: seat_id.parse().expect("seat id"),
                project_id: None,
                template_id: "template:dev".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "operator".to_owned(),
                created_at: fixed_instant(),
                retained: false,
            },
        )
        .expect("lane row");
    }

    fn bound_scope(lane_id: &str) -> Scope {
        Scope {
            seat: Some(SEAT_ID.parse().expect("seat id")),
            lane: Some(lane_id.parse().expect("lane id")),
            ..Scope::default()
        }
    }

    fn invocation(scope: Scope, lane_id: &str) -> HostInvocation {
        HostInvocation {
            scope,
            arguments: json!({ "laneId": lane_id }),
        }
    }

    #[test]
    fn cross_lane_request_is_rejected_without_disclosure() {
        let ledger = ledger();
        {
            let guard = ledger.lock().expect("ledger lock");
            store_lane(&guard, LANE_A, SEAT_ID);
            store_lane(&guard, LANE_B, SEAT_ID);
        }
        let tool = LaneStatusTool::new(Arc::clone(&ledger));

        let error = tool
            .invoke(invocation(bound_scope(LANE_A), LANE_B))
            .expect_err("a foreign lane must be rejected before any read");

        assert!(matches!(
            error,
            HostToolError::Scope {
                tool: LaneStatusTool::NAME,
                ..
            }
        ));
    }

    #[test]
    fn unbound_seat_or_lane_scope_is_rejected_before_disclosure() {
        let ledger = ledger();
        {
            let guard = ledger.lock().expect("ledger lock");
            store_lane(&guard, LANE_A, SEAT_ID);
        }
        let tool = LaneStatusTool::new(Arc::clone(&ledger));

        let unbound = [
            Scope::default(),
            Scope {
                lane: Some(LANE_A.parse().expect("lane id")),
                ..Scope::default()
            },
        ];
        for scope in unbound {
            let error = tool
                .invoke(invocation(scope, LANE_A))
                .expect_err("an unbound seat or lane scope must be rejected");
            assert!(matches!(
                error,
                HostToolError::Scope {
                    tool: LaneStatusTool::NAME,
                    ..
                }
            ));
        }
    }

    #[test]
    fn absent_lane_is_not_found_while_foreign_lane_is_scope_rejected() {
        let ledger = ledger();
        {
            let guard = ledger.lock().expect("ledger lock");
            store_lane(&guard, LANE_A, SEAT_ID);
        }
        let tool = LaneStatusTool::new(Arc::clone(&ledger));

        let absent = tool
            .invoke(invocation(
                bound_scope("lane:1700000000000:absent"),
                "lane:1700000000000:absent",
            ))
            .expect_err("an absent bound lane is a typed not-found");
        assert!(matches!(
            absent,
            HostToolError::Ledger(LedgerError::NotFound { kind: "lane", .. })
        ));

        let foreign = tool
            .invoke(invocation(bound_scope(LANE_A), LANE_B))
            .expect_err("a foreign lane is a scope rejection");
        assert!(matches!(
            foreign,
            HostToolError::Scope {
                tool: LaneStatusTool::NAME,
                ..
            }
        ));
    }

    #[test]
    fn bound_lane_returns_the_durable_ledger_record() {
        let ledger = ledger();
        {
            let guard = ledger.lock().expect("ledger lock");
            store_lane(&guard, LANE_A, SEAT_ID);
        }
        let tool = LaneStatusTool::new(Arc::clone(&ledger));

        let status = tool
            .invoke(invocation(bound_scope(LANE_A), LANE_A))
            .expect("the bound lane reads from the ledger");
        assert_eq!(status["laneId"], LANE_A);
        assert_eq!(status["seatId"], SEAT_ID);
        assert_eq!(status["status"], "desired");
        assert_eq!(status["revision"], 1);
        assert_eq!(status["desiredRevision"], 1);
        assert_eq!(status["templateId"], "template:dev");
        assert_eq!(status["backend"], "local_omp");
        assert!(!status["retained"].as_bool().expect("retained bool"));
        assert!(status["createdAt"]
            .as_str()
            .expect("rfc3339")
            .contains("2023"));

        let repeated = tool
            .invoke(invocation(bound_scope(LANE_A), LANE_A))
            .expect("a repeated read is idempotent");
        assert_eq!(status, repeated);
    }

    #[test]
    fn ledger_row_must_prove_every_bound_dimension() {
        let ledger = ledger();
        {
            let guard = ledger.lock().expect("ledger lock");
            store_lane(&guard, LANE_A, SEAT_ID);
        }
        let tool = LaneStatusTool::new(Arc::clone(&ledger));

        let scope = Scope {
            run: Some("run:1700000000000:other".parse().expect("run id")),
            ..bound_scope(LANE_A)
        };
        let error = tool
            .invoke(invocation(scope, LANE_A))
            .expect_err("a bound run the lane row cannot prove must be rejected");

        assert!(matches!(
            error,
            HostToolError::Scope {
                tool: LaneStatusTool::NAME,
                ..
            }
        ));
    }

    #[test]
    fn unknown_fields_are_rejected_before_disclosure() {
        let ledger = ledger();
        {
            let guard = ledger.lock().expect("ledger lock");
            store_lane(&guard, LANE_A, SEAT_ID);
        }
        let tool = LaneStatusTool::new(Arc::clone(&ledger));

        let mut smuggled = json!({ "laneId": LANE_A });
        smuggled["seat"] = json!(SEAT_ID);
        let error = tool
            .invoke(HostInvocation {
                scope: bound_scope(LANE_A),
                arguments: smuggled,
            })
            .expect_err("unknown fields must never smuggle a seat binding");

        assert!(matches!(
            error,
            HostToolError::Arguments {
                tool: LaneStatusTool::NAME,
                ..
            }
        ));
    }

    #[test]
    fn preflight_refuses_unseeded_and_foreign_lane_read_only() {
        let ledger = ledger();
        let tool = LaneStatusTool::new(ledger.clone());
        let contract = fixture_contract();
        let error = tool
            .preflight(&contract, &bound_scope(LANE_A), &json!({"laneId": LANE_A}))
            .expect_err("a lane the ledger does not hold refuses preflight");
        assert!(matches!(
            error,
            HostToolError::Ledger(odin_ledger::LedgerError::NotFound { .. })
        ));

        // An existing row can still fail the seat-scope check.
        store_lane(
            &ledger.lock().expect("ledger lock"),
            LANE_A,
            "seat:1700000000000:foreign",
        );
        let error = tool
            .preflight(&contract, &bound_scope(LANE_A), &json!({"laneId": LANE_A}))
            .expect_err("a lane row the bound scope cannot prove refuses preflight");
        assert!(matches!(error, HostToolError::Scope { .. }));
    }
}
