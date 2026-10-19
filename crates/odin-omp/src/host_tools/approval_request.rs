//! `odin_approval_request` — durable exact-scope approval requests from the model.
//!
//! The target kind and id must name and equal a dimension bound in the invocation scope, both
//! timestamps are explicit caller values, and the canonical argument JSON is hashed. A retry with
//! the same id, issuer, and scope returns the existing request; any changed target, capability, or
//! arguments conflicts, and a request is never widened.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use odin_domain::{ApprovalId, ApprovalStatus, CapabilityId, Digest, Scope};
use odin_kernel::arguments_digest;
use odin_ledger::approval::{ApprovalScope, NewApproval};
use odin_ledger::Ledger;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::host_tools::{
    bound_scope_dimension, lock_ledger, parse_unix_milliseconds, response, HostInvocation,
    HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode, SCOPE_DIMENSIONS,
};

/// Mints durable, scope-exact approval requests over shared ledger state.
pub struct ApprovalRequestTool {
    ledger: Arc<Mutex<Ledger>>,
    definition: RpcHostToolDefinition,
}

impl ApprovalRequestTool {
    pub const NAME: &str = "odin_approval_request";

    pub fn new(ledger: Arc<Mutex<Ledger>>) -> Self {
        Self {
            ledger,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(Self::NAME),
                label: Cow::Borrowed("Approval Request"),
                description: Cow::Borrowed(
                    "Request an exact-scope approval for one capability invocation \
                     against a target bound to this session's scope. The approval binds the exact \
                     target, capability, and canonical hash of the arguments. Retrying with the \
                     same approval id and identical scope returns the existing request; any change \
                     conflicts. Unknown fields and empty or reversed windows are rejected.",
                ),
                parameters: parameters(),
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        }
    }
}

impl HostTool for ApprovalRequestTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        // The ledger is supplied at construction; invocation checks scope and intervals before writing.
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let arguments: ApprovalRequestArguments = serde_json::from_value(invocation.arguments)
            .map_err(|error| HostToolError::Arguments {
                tool: Self::NAME,
                detail: format!("arguments violate the odin_approval_request schema: {error}"),
            })?;

        // Every bound-scope check below happens before the ledger is touched, so a denied or
        // invalid request never creates durable state.
        let issuer = invocation
            .scope
            .seat
            .as_ref()
            .ok_or_else(|| HostToolError::Scope {
                tool: Self::NAME,
                reason: "the invocation scope is not bound to a seat",
            })?;
        if !SCOPE_DIMENSIONS.contains(&arguments.target_kind.as_str()) {
            return Err(HostToolError::Arguments {
                tool: Self::NAME,
                detail: format!(
                    "unknown target kind {:?}; expected one of {SCOPE_DIMENSIONS:?}",
                    arguments.target_kind
                ),
            });
        }
        let bound =
            bound_scope_dimension(&invocation.scope, &arguments.target_kind).ok_or_else(|| {
                HostToolError::Scope {
                    tool: Self::NAME,
                    reason: "the invocation scope does not bind the requested target kind",
                }
            })?;
        if bound != arguments.target_id {
            return Err(HostToolError::Scope {
                tool: Self::NAME,
                reason: "the requested target id does not match the invocation scope",
            });
        }

        let requested_at = parse_unix_milliseconds(Self::NAME, arguments.requested_at_ms)?;
        let expires_at = parse_unix_milliseconds(Self::NAME, arguments.expires_at_ms)?;
        if expires_at <= requested_at {
            return Err(HostToolError::Arguments {
                tool: Self::NAME,
                detail: "expiresAtMs must be after requestedAtMs".to_owned(),
            });
        }

        let scope = ApprovalScope {
            target_kind: arguments.target_kind,
            target_id: arguments.target_id,
            capability_id: arguments.capability_id,
            arguments_digest: arguments_digest(&arguments.arguments),
        };

        let mut ledger = lock_ledger(Self::NAME, &self.ledger)?;
        if let Some(existing) = ledger.approval(&arguments.approval_id)? {
            // Idempotency is exact: same id, same issuer, same scope. Anything else conflicts,
            // and the stored record is never reinterpreted or widened.
            if existing.scope == scope && existing.issuer == issuer.as_str() {
                return response(Self::NAME, &ApprovalRequestView::new(&existing, false));
            }
            return Err(HostToolError::Arguments {
                tool: Self::NAME,
                detail: format!(
                    "approval {} already exists with a different target, capability, or \
                     arguments; requests are never widened",
                    arguments.approval_id
                ),
            });
        }

        let approval = ledger.request_approval(NewApproval {
            approval_id: arguments.approval_id,
            issuer: issuer.to_string(),
            scope,
            requested_at,
            expires_at,
        })?;
        response(Self::NAME, &ApprovalRequestView::new(&approval, true))
    }
}

/// The durable approval projected as model-facing camelCase JSON.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalRequestView {
    approval_id: ApprovalId,
    status: ApprovalStatus,
    target_kind: String,
    target_id: String,
    capability_id: CapabilityId,
    arguments_digest: Digest,
    requested_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    revision: i64,
    created: bool,
}

impl ApprovalRequestView {
    fn new(approval: &odin_ledger::approval::Approval, created: bool) -> Self {
        Self {
            approval_id: approval.approval_id.clone(),
            status: approval.status,
            target_kind: approval.scope.target_kind.clone(),
            target_id: approval.scope.target_id.clone(),
            capability_id: approval.scope.capability_id.clone(),
            arguments_digest: approval.scope.arguments_digest,
            requested_at: approval.requested_at,
            expires_at: approval.expires_at,
            revision: approval.revision,
            created,
        }
    }
}

/// Model-facing input. The schema and this parser are one contract: unknown fields never pass.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ApprovalRequestArguments {
    approval_id: ApprovalId,
    target_kind: String,
    target_id: String,
    capability_id: CapabilityId,
    requested_at_ms: i64,
    expires_at_ms: i64,
    arguments: Value,
}

fn parameters() -> Value {
    json!({
        "type": "object",
        "properties": {
            "approvalId": {
                "type": "string",
                "minLength": 1,
                "description": "Caller-chosen request identifier; reusing it retries the same request."
            },
            "targetKind": {
                "enum": SCOPE_DIMENSIONS,
                "description": "Scope dimension the approval is bound to."
            },
            "targetId": {
                "type": "string",
                "minLength": 1,
                "description": "Exact bound value of that scope dimension."
            },
            "capabilityId": {
                "type": "string",
                "minLength": 1,
                "description": "Capability the approval will authorize."
            },
            "requestedAtMs": {
                "type": "integer",
                "description": "Explicit request timestamp in Unix milliseconds."
            },
            "expiresAtMs": {
                "type": "integer",
                "description": "Explicit expiry timestamp in Unix milliseconds, after requestedAtMs."
            },
            "arguments": {
                "description": "Exact invocation arguments; their canonical JSON hash is bound to the request."
            }
        },
        "required": [
            "approvalId",
            "targetKind",
            "targetId",
            "capabilityId",
            "requestedAtMs",
            "expiresAtMs",
            "arguments"
        ],
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use odin_domain::LaneId;

    use super::*;

    const REQUESTED_AT_MS: i64 = 1_890_000_000_000;
    const EXPIRES_AT_MS: i64 = REQUESTED_AT_MS + 3_600_000;

    fn scope(seat: &str, lane: &str) -> Scope {
        Scope {
            seat: Some(odin_domain::SeatId::new(seat).expect("seat id")),
            lane: Some(LaneId::new(lane).expect("lane id")),
            ..Scope::default()
        }
    }

    fn arguments(
        approval_id: &str,
        target_kind: &str,
        target_id: &str,
        capability: &str,
        args: Value,
    ) -> Value {
        json!({
            "approvalId": approval_id,
            "targetKind": target_kind,
            "targetId": target_id,
            "capabilityId": capability,
            "requestedAtMs": REQUESTED_AT_MS,
            "expiresAtMs": EXPIRES_AT_MS,
            "arguments": args,
        })
    }

    fn fixture() -> (ApprovalRequestTool, Arc<Mutex<Ledger>>) {
        let ledger = Arc::new(Mutex::new(
            Ledger::open_in_memory().expect("in-memory ledger opens"),
        ));
        (ApprovalRequestTool::new(Arc::clone(&ledger)), ledger)
    }

    #[test]
    fn same_id_same_scope_retry_returns_existing_request() {
        let (tool, ledger) = fixture();
        let first_arguments = arguments(
            "approval:1",
            "lane",
            "lane-a",
            "capability:exec",
            json!({"step": 1}),
        );
        let first = tool
            .invoke(HostInvocation {
                scope: scope("seat-a", "lane-a"),
                arguments: first_arguments.clone(),
            })
            .expect("first request creates a record");
        assert_eq!(first["created"], true);
        assert_eq!(first["status"], "requested");
        assert_eq!(first["revision"], 1);
        assert_eq!(first["targetKind"], "lane");
        assert_eq!(first["targetId"], "lane-a");
        assert_eq!(
            first["argumentsDigest"],
            arguments_digest(&first_arguments["arguments"]).to_string()
        );

        let retry = tool
            .invoke(HostInvocation {
                scope: scope("seat-a", "lane-a"),
                arguments: first_arguments,
            })
            .expect("an exact retry returns the existing request");
        assert_eq!(retry["created"], false);
        assert_eq!(retry["approvalId"], first["approvalId"]);
        assert_eq!(retry["status"], "requested");
        assert_eq!(retry["revision"], 1);
        assert_eq!(retry["argumentsDigest"], first["argumentsDigest"]);

        // Exactly one durable record exists and the retry never modified it.
        let stored = ledger
            .lock()
            .expect("ledger lock")
            .approval(&ApprovalId::new("approval:1").expect("approval id"))
            .expect("approval reads")
            .expect("approval exists");
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.status, ApprovalStatus::Requested);
    }

    #[test]
    fn changed_arguments_or_scope_conflicts() {
        let (tool, ledger) = fixture();
        tool.invoke(HostInvocation {
            scope: scope("seat-a", "lane-a"),
            arguments: arguments(
                "approval:2",
                "lane",
                "lane-a",
                "capability:exec",
                json!({"step": 1}),
            ),
        })
        .expect("base request creates a record");

        let changed_arguments = tool
            .invoke(HostInvocation {
                scope: scope("seat-a", "lane-a"),
                arguments: arguments(
                    "approval:2",
                    "lane",
                    "lane-a",
                    "capability:exec",
                    json!({"step": 2}),
                ),
            })
            .expect_err("changed arguments must conflict");
        assert!(matches!(
            changed_arguments,
            HostToolError::Arguments {
                tool: ApprovalRequestTool::NAME,
                ..
            }
        ));

        // The seat dimension is also bound, so this passes the scope gate and must then
        // conflict on the exact-scope comparison.
        let changed_target = tool
            .invoke(HostInvocation {
                scope: scope("seat-a", "lane-a"),
                arguments: arguments(
                    "approval:2",
                    "seat",
                    "seat-a",
                    "capability:exec",
                    json!({"step": 1}),
                ),
            })
            .expect_err("a changed target must conflict");
        assert!(matches!(
            changed_target,
            HostToolError::Arguments {
                tool: ApprovalRequestTool::NAME,
                ..
            }
        ));

        let changed_capability = tool
            .invoke(HostInvocation {
                scope: scope("seat-a", "lane-a"),
                arguments: arguments(
                    "approval:2",
                    "lane",
                    "lane-a",
                    "capability:write",
                    json!({"step": 1}),
                ),
            })
            .expect_err("a changed capability must conflict");
        assert!(matches!(
            changed_capability,
            HostToolError::Arguments {
                tool: ApprovalRequestTool::NAME,
                ..
            }
        ));

        // A different seat cannot inherit another seat's request id.
        let changed_issuer = tool
            .invoke(HostInvocation {
                scope: scope("seat-b", "lane-a"),
                arguments: arguments(
                    "approval:2",
                    "lane",
                    "lane-a",
                    "capability:exec",
                    json!({"step": 1}),
                ),
            })
            .expect_err("a different issuer must conflict");
        assert!(matches!(
            changed_issuer,
            HostToolError::Arguments {
                tool: ApprovalRequestTool::NAME,
                ..
            }
        ));

        let stored = ledger
            .lock()
            .expect("ledger lock")
            .approval(&ApprovalId::new("approval:2").expect("approval id"))
            .expect("approval reads")
            .expect("approval exists");
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.scope.target_kind, "lane");
        assert_eq!(stored.scope.capability_id.to_string(), "capability:exec");
    }

    #[test]
    fn scope_denials_never_touch_the_ledger() {
        let (tool, ledger) = fixture();
        let approval_id = ApprovalId::new("approval:3").expect("approval id");

        let cross_scope = tool
            .invoke(HostInvocation {
                scope: scope("seat-a", "lane-a"),
                arguments: arguments("approval:3", "lane", "lane-b", "capability:exec", json!({})),
            })
            .expect_err("an unbound target id must be denied");
        assert!(matches!(
            cross_scope,
            HostToolError::Scope {
                tool: ApprovalRequestTool::NAME,
                ..
            }
        ));

        let unbound_dimension = tool
            .invoke(HostInvocation {
                scope: scope("seat-a", "lane-a"),
                arguments: arguments("approval:3", "node", "node-a", "capability:exec", json!({})),
            })
            .expect_err("an unbound target dimension must be denied");
        assert!(matches!(
            unbound_dimension,
            HostToolError::Scope {
                tool: ApprovalRequestTool::NAME,
                ..
            }
        ));

        let no_seat = tool
            .invoke(HostInvocation {
                scope: Scope {
                    lane: Some(LaneId::new("lane-a").expect("lane id")),
                    ..Scope::default()
                },
                arguments: arguments("approval:3", "lane", "lane-a", "capability:exec", json!({})),
            })
            .expect_err("a scope without a bound seat must be denied");
        assert!(matches!(
            no_seat,
            HostToolError::Scope {
                tool: ApprovalRequestTool::NAME,
                ..
            }
        ));

        assert!(
            ledger
                .lock()
                .expect("ledger lock")
                .approval(&approval_id)
                .expect("approval reads")
                .is_none(),
            "a denied request must not create durable state"
        );
    }

    #[test]
    fn invalid_windows_are_rejected() {
        let (tool, ledger) = fixture();
        for (requested, expires) in [
            (REQUESTED_AT_MS, REQUESTED_AT_MS),
            (REQUESTED_AT_MS, REQUESTED_AT_MS - 1),
        ] {
            let result = tool.invoke(HostInvocation {
                scope: scope("seat-a", "lane-a"),
                arguments: json!({
                    "approvalId": "approval:4",
                    "targetKind": "lane",
                    "targetId": "lane-a",
                    "capabilityId": "capability:exec",
                    "requestedAtMs": requested,
                    "expiresAtMs": expires,
                    "arguments": {},
                }),
            });
            assert!(matches!(
                result,
                Err(HostToolError::Arguments {
                    tool: ApprovalRequestTool::NAME,
                    ..
                })
            ));
        }
        assert!(
            ledger
                .lock()
                .expect("ledger lock")
                .approval(&ApprovalId::new("approval:4").expect("approval id"))
                .expect("approval reads")
                .is_none(),
            "an invalid window must not create durable state"
        );
    }

    #[test]
    fn unknown_fields_and_target_kinds_are_rejected() {
        let (tool, _ledger) = fixture();

        let unknown_field = tool.invoke(HostInvocation {
            scope: scope("seat-a", "lane-a"),
            arguments: json!({
                "approvalId": "approval:5",
                "targetKind": "lane",
                "targetId": "lane-a",
                "capabilityId": "capability:exec",
                "requestedAtMs": REQUESTED_AT_MS,
                "expiresAtMs": EXPIRES_AT_MS,
                "arguments": {},
                "approve": true,
            }),
        });
        assert!(matches!(
            unknown_field,
            Err(HostToolError::Arguments {
                tool: ApprovalRequestTool::NAME,
                ..
            })
        ));

        let unknown_kind = tool.invoke(HostInvocation {
            scope: scope("seat-a", "lane-a"),
            arguments: arguments(
                "approval:5",
                "container",
                "container-a",
                "capability:exec",
                json!({}),
            ),
        });
        assert!(matches!(
            unknown_kind,
            Err(HostToolError::Arguments {
                tool: ApprovalRequestTool::NAME,
                ..
            })
        ));
    }
}
