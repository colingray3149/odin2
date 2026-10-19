//! Generated authority wire v2 canonical size preflight and field size accounting; do not edit.

use super::*;

fn add_size_part(total: usize, part: usize) -> Result<usize, ProtocolError> {
    total
        .checked_add(part)
        .ok_or_else(|| ProtocolError::Encode("canonical payload size overflow".to_string()))
}
pub(super) fn canonical_size_quoted(text: &str) -> usize {
    2 + text
        .chars()
        .map(|character| match character {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            character if (character as u32) < 0x20 => 6,
            character if character.is_ascii() => 1,
            character if (character as u32) <= 0xFFFF => 6,
            _ => 12,
        })
        .sum::<usize>()
}
fn canonical_size_digits(magnitude: u64) -> usize {
    let mut magnitude = magnitude;
    let mut digits = 1;
    while magnitude >= 10 {
        magnitude /= 10;
        digits += 1;
    }
    digits
}
fn canonical_size_u64(value: u64) -> usize {
    canonical_size_digits(value)
}
fn canonical_size_i32(value: i64) -> usize {
    canonical_size_digits(value.unsigned_abs()) + usize::from(value < 0)
}
fn canonical_size_u64_wire(value: u64) -> usize {
    2 + canonical_size_digits(value)
}
fn canonical_size_object_parts(parts: &[usize]) -> Result<usize, ProtocolError> {
    let separators = (parts.len() / 3).saturating_sub(1);
    parts
        .iter()
        .copied()
        .try_fold(2usize + separators, add_size_part)
}
fn canonical_size_value(value: &Value, depth: usize) -> Result<usize, ProtocolError> {
    if depth > ARGUMENT_MAX_DEPTH {
        return Err(ProtocolError::Encode(
            "argument nesting exceeds the generated wire depth bound".to_string(),
        ));
    }
    match value {
        Value::Null => Ok(4),
        Value::Bool(true) => Ok(4),
        Value::Bool(false) => Ok(5),
        Value::Int(number) => Ok(canonical_size_i32(*number)),
        Value::UInt(number) => Ok(canonical_size_u64(*number)),
        Value::Float(_) => Err(ProtocolError::Encode(
            "argument numbers must be integers".to_string(),
        )),
        Value::String(text) => Ok(canonical_size_quoted(text)),
        Value::Array(items) => {
            let mut total = 2usize;
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    total = add_size_part(total, 1)?;
                }
                total = add_size_part(total, canonical_size_value(item, depth + 1)?)?;
            }
            Ok(total)
        }
        Value::Object(entries) => {
            let mut total = 2usize;
            for (index, entry) in entries.iter().enumerate() {
                if index > 0 {
                    total = add_size_part(total, 1)?;
                }
                total = add_size_part(total, canonical_size_quoted(&entry.key))?;
                total = add_size_part(total, 1)?;
                total = add_size_part(total, canonical_size_value(&entry.value, depth + 1)?)?;
            }
            Ok(total)
        }
    }
}
fn canonical_size_budget(value: &Budget) -> Result<usize, ProtocolError> {
    canonical_size_object_parts(&[
        canonical_size_quoted("requests"),
        1,
        canonical_size_u64_wire(value.requests.get()),
        canonical_size_quoted("stops"),
        1,
        canonical_size_u64_wire(value.stops.get()),
        canonical_size_quoted("spend"),
        1,
        canonical_size_u64_wire(value.spend.get()),
    ])
}
fn canonical_size_evidence(value: &Evidence) -> Result<usize, ProtocolError> {
    Ok(match value {
        Evidence::Process {
            pid,
            start_time_ticks,
            process_group,
        } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("process"),
            canonical_size_quoted("pid"),
            1,
            canonical_size_i32(i64::from(*pid)),
            canonical_size_quoted("start_time_ticks"),
            1,
            canonical_size_u64_wire(start_time_ticks.get()),
            canonical_size_quoted("process_group"),
            1,
            canonical_size_i32(i64::from(*process_group)),
        ])?,
        Evidence::Unit { unit_name } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("unit"),
            canonical_size_quoted("unit_name"),
            1,
            canonical_size_quoted(unit_name.as_str()),
        ])?,
        Evidence::Cgroup { path, inode } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("cgroup"),
            canonical_size_quoted("path"),
            1,
            canonical_size_quoted(path.as_str()),
            canonical_size_quoted("inode"),
            1,
            canonical_size_u64_wire(inode.get()),
        ])?,
        Evidence::Durable { digest } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("durable"),
            canonical_size_quoted("digest"),
            1,
            canonical_size_quoted(digest.as_str()),
        ])?,
        Evidence::Absent => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("absent"),
        ])?,
    })
}

pub(super) fn canonical_size_request(value: &Request) -> Result<usize, ProtocolError> {
    Ok(match value {
        Request::InvokeCapability {
            wire: _,
            capsule_id,
            correlation_id,
            capability,
            budget,
            arguments,
        } => {
            let arguments_size = canonical_size_value(arguments.as_value(), 0)?;
            canonical_size_object_parts(&[
                canonical_size_quoted("kind"),
                1,
                canonical_size_quoted("invoke_capability"),
                canonical_size_quoted("wire"),
                1,
                canonical_size_u64(u64::from(PROTOCOL_VERSION)),
                canonical_size_quoted("capsule_id"),
                1,
                canonical_size_quoted(capsule_id.as_str()),
                canonical_size_quoted("correlation_id"),
                1,
                canonical_size_quoted(correlation_id.as_str()),
                canonical_size_quoted("capability"),
                1,
                canonical_size_quoted(capability.as_str()),
                canonical_size_quoted("budget"),
                1,
                canonical_size_budget(budget)?,
                canonical_size_quoted("arguments"),
                1,
                arguments_size,
            ])?
        }
        Request::ResumeOperation {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
        } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("resume_operation"),
            canonical_size_quoted("wire"),
            1,
            canonical_size_u64(u64::from(PROTOCOL_VERSION)),
            canonical_size_quoted("capsule_id"),
            1,
            canonical_size_quoted(capsule_id.as_str()),
            canonical_size_quoted("correlation_id"),
            1,
            canonical_size_quoted(correlation_id.as_str()),
            canonical_size_quoted("operation_id"),
            1,
            canonical_size_quoted(operation_id.as_str()),
        ])?,
        Request::ReconcileOperation {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
        } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("reconcile_operation"),
            canonical_size_quoted("wire"),
            1,
            canonical_size_u64(u64::from(PROTOCOL_VERSION)),
            canonical_size_quoted("capsule_id"),
            1,
            canonical_size_quoted(capsule_id.as_str()),
            canonical_size_quoted("correlation_id"),
            1,
            canonical_size_quoted(correlation_id.as_str()),
            canonical_size_quoted("operation_id"),
            1,
            canonical_size_quoted(operation_id.as_str()),
        ])?,
        Request::CloseCapsule {
            wire: _,
            capsule_id,
            correlation_id,
            mode,
        } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("close_capsule"),
            canonical_size_quoted("wire"),
            1,
            canonical_size_u64(u64::from(PROTOCOL_VERSION)),
            canonical_size_quoted("capsule_id"),
            1,
            canonical_size_quoted(capsule_id.as_str()),
            canonical_size_quoted("correlation_id"),
            1,
            canonical_size_quoted(correlation_id.as_str()),
            canonical_size_quoted("mode"),
            1,
            canonical_size_quoted(match mode {
                CloseMode::Drain => "drain",
                CloseMode::Abort => "abort",
            }),
        ])?,
        Request::StopIntent {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
        } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("stop_intent"),
            canonical_size_quoted("wire"),
            1,
            canonical_size_u64(u64::from(PROTOCOL_VERSION)),
            canonical_size_quoted("capsule_id"),
            1,
            canonical_size_quoted(capsule_id.as_str()),
            canonical_size_quoted("correlation_id"),
            1,
            canonical_size_quoted(correlation_id.as_str()),
            canonical_size_quoted("operation_id"),
            1,
            match operation_id {
                Some(operation_id) => canonical_size_quoted(operation_id.as_str()),
                None => 4,
            },
        ])?,
    })
}

pub(super) fn canonical_size_response(value: &Response) -> Result<usize, ProtocolError> {
    Ok(match value {
        Response::CapabilityInvoked {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
            state,
            replay,
        } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("capability_invoked"),
            canonical_size_quoted("wire"),
            1,
            canonical_size_u64(u64::from(PROTOCOL_VERSION)),
            canonical_size_quoted("capsule_id"),
            1,
            canonical_size_quoted(capsule_id.as_str()),
            canonical_size_quoted("correlation_id"),
            1,
            canonical_size_quoted(correlation_id.as_str()),
            canonical_size_quoted("operation_id"),
            1,
            canonical_size_quoted(operation_id.as_str()),
            canonical_size_quoted("state"),
            1,
            canonical_size_quoted(match state {
                OperationState::Prepared => "prepared",
                OperationState::EffectStarted => "effect_started",
                OperationState::Committed => "committed",
                OperationState::Aborted => "aborted",
                OperationState::InDoubt => "in_doubt",
            }),
            canonical_size_quoted("replay"),
            1,
            if *replay { 4 } else { 5 },
        ])?,
        Response::OperationResumed {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
            state,
            replay,
        } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("operation_resumed"),
            canonical_size_quoted("wire"),
            1,
            canonical_size_u64(u64::from(PROTOCOL_VERSION)),
            canonical_size_quoted("capsule_id"),
            1,
            canonical_size_quoted(capsule_id.as_str()),
            canonical_size_quoted("correlation_id"),
            1,
            canonical_size_quoted(correlation_id.as_str()),
            canonical_size_quoted("operation_id"),
            1,
            canonical_size_quoted(operation_id.as_str()),
            canonical_size_quoted("state"),
            1,
            canonical_size_quoted(match state {
                OperationState::Prepared => "prepared",
                OperationState::EffectStarted => "effect_started",
                OperationState::Committed => "committed",
                OperationState::Aborted => "aborted",
                OperationState::InDoubt => "in_doubt",
            }),
            canonical_size_quoted("replay"),
            1,
            if *replay { 4 } else { 5 },
        ])?,
        Response::OperationReconciled {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
            state,
            replay,
            evidence,
        } => {
            let evidence_size = canonical_size_evidence(evidence)?;
            canonical_size_object_parts(&[
                canonical_size_quoted("kind"),
                1,
                canonical_size_quoted("operation_reconciled"),
                canonical_size_quoted("wire"),
                1,
                canonical_size_u64(u64::from(PROTOCOL_VERSION)),
                canonical_size_quoted("capsule_id"),
                1,
                canonical_size_quoted(capsule_id.as_str()),
                canonical_size_quoted("correlation_id"),
                1,
                canonical_size_quoted(correlation_id.as_str()),
                canonical_size_quoted("operation_id"),
                1,
                canonical_size_quoted(operation_id.as_str()),
                canonical_size_quoted("state"),
                1,
                canonical_size_quoted(match state {
                    OperationState::Prepared => "prepared",
                    OperationState::EffectStarted => "effect_started",
                    OperationState::Committed => "committed",
                    OperationState::Aborted => "aborted",
                    OperationState::InDoubt => "in_doubt",
                }),
                canonical_size_quoted("replay"),
                1,
                if *replay { 4 } else { 5 },
                canonical_size_quoted("evidence"),
                1,
                evidence_size,
            ])?
        }
        Response::CapsuleClosed {
            wire: _,
            capsule_id,
            correlation_id,
            drained,
        } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("capsule_closed"),
            canonical_size_quoted("wire"),
            1,
            canonical_size_u64(u64::from(PROTOCOL_VERSION)),
            canonical_size_quoted("capsule_id"),
            1,
            canonical_size_quoted(capsule_id.as_str()),
            canonical_size_quoted("correlation_id"),
            1,
            canonical_size_quoted(correlation_id.as_str()),
            canonical_size_quoted("drained"),
            1,
            canonical_size_u64_wire(drained.get()),
        ])?,
        Response::StopRecorded {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
            state,
            evidence,
        } => {
            let evidence_size = canonical_size_evidence(evidence)?;
            canonical_size_object_parts(&[
                canonical_size_quoted("kind"),
                1,
                canonical_size_quoted("stop_recorded"),
                canonical_size_quoted("wire"),
                1,
                canonical_size_u64(u64::from(PROTOCOL_VERSION)),
                canonical_size_quoted("capsule_id"),
                1,
                canonical_size_quoted(capsule_id.as_str()),
                canonical_size_quoted("correlation_id"),
                1,
                canonical_size_quoted(correlation_id.as_str()),
                canonical_size_quoted("operation_id"),
                1,
                match operation_id {
                    Some(operation_id) => canonical_size_quoted(operation_id.as_str()),
                    None => 4,
                },
                canonical_size_quoted("state"),
                1,
                canonical_size_quoted(match state {
                    StopState::Requested => "requested",
                    StopState::Stopped => "stopped",
                    StopState::Failed => "failed",
                }),
                canonical_size_quoted("evidence"),
                1,
                evidence_size,
            ])?
        }
        Response::Rejected {
            wire: _,
            code,
            detail,
        } => canonical_size_object_parts(&[
            canonical_size_quoted("kind"),
            1,
            canonical_size_quoted("rejected"),
            canonical_size_quoted("wire"),
            1,
            canonical_size_u64(u64::from(PROTOCOL_VERSION)),
            canonical_size_quoted("code"),
            1,
            canonical_size_quoted(code.as_str()),
            canonical_size_quoted("detail"),
            1,
            canonical_size_quoted(detail.as_str()),
        ])?,
    })
}

#[cfg(test)]
pub(crate) fn canonical_size_request_field_sizes(
    value: &Request,
) -> Result<Vec<(&'static str, usize)>, ProtocolError> {
    Ok(match value {
        Request::InvokeCapability {
            wire: _,
            capsule_id,
            correlation_id,
            capability,
            budget,
            arguments,
        } => {
            let arguments_size = canonical_size_value(arguments.as_value(), 0)?;
            vec![
                ("kind", canonical_size_quoted("invoke_capability")),
                ("wire", canonical_size_u64(u64::from(PROTOCOL_VERSION))),
                ("capsule_id", canonical_size_quoted(capsule_id.as_str())),
                (
                    "correlation_id",
                    canonical_size_quoted(correlation_id.as_str()),
                ),
                ("capability", canonical_size_quoted(capability.as_str())),
                ("budget", canonical_size_budget(budget)?),
                ("arguments", arguments_size),
            ]
        }
        Request::ResumeOperation {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
        } => {
            vec![
                ("kind", canonical_size_quoted("resume_operation")),
                ("wire", canonical_size_u64(u64::from(PROTOCOL_VERSION))),
                ("capsule_id", canonical_size_quoted(capsule_id.as_str())),
                (
                    "correlation_id",
                    canonical_size_quoted(correlation_id.as_str()),
                ),
                ("operation_id", canonical_size_quoted(operation_id.as_str())),
            ]
        }
        Request::ReconcileOperation {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
        } => {
            vec![
                ("kind", canonical_size_quoted("reconcile_operation")),
                ("wire", canonical_size_u64(u64::from(PROTOCOL_VERSION))),
                ("capsule_id", canonical_size_quoted(capsule_id.as_str())),
                (
                    "correlation_id",
                    canonical_size_quoted(correlation_id.as_str()),
                ),
                ("operation_id", canonical_size_quoted(operation_id.as_str())),
            ]
        }
        Request::CloseCapsule {
            wire: _,
            capsule_id,
            correlation_id,
            mode,
        } => {
            vec![
                ("kind", canonical_size_quoted("close_capsule")),
                ("wire", canonical_size_u64(u64::from(PROTOCOL_VERSION))),
                ("capsule_id", canonical_size_quoted(capsule_id.as_str())),
                (
                    "correlation_id",
                    canonical_size_quoted(correlation_id.as_str()),
                ),
                (
                    "mode",
                    canonical_size_quoted(match mode {
                        CloseMode::Drain => "drain",
                        CloseMode::Abort => "abort",
                    }),
                ),
            ]
        }
        Request::StopIntent {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
        } => {
            vec![
                ("kind", canonical_size_quoted("stop_intent")),
                ("wire", canonical_size_u64(u64::from(PROTOCOL_VERSION))),
                ("capsule_id", canonical_size_quoted(capsule_id.as_str())),
                (
                    "correlation_id",
                    canonical_size_quoted(correlation_id.as_str()),
                ),
                (
                    "operation_id",
                    match operation_id {
                        Some(operation_id) => canonical_size_quoted(operation_id.as_str()),
                        None => 4,
                    },
                ),
            ]
        }
    })
}

#[cfg(test)]
pub(crate) fn canonical_size_response_field_sizes(
    value: &Response,
) -> Result<Vec<(&'static str, usize)>, ProtocolError> {
    Ok(match value {
        Response::CapabilityInvoked {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
            state,
            replay,
        } => {
            vec![
                ("kind", canonical_size_quoted("capability_invoked")),
                ("wire", canonical_size_u64(u64::from(PROTOCOL_VERSION))),
                ("capsule_id", canonical_size_quoted(capsule_id.as_str())),
                (
                    "correlation_id",
                    canonical_size_quoted(correlation_id.as_str()),
                ),
                ("operation_id", canonical_size_quoted(operation_id.as_str())),
                (
                    "state",
                    canonical_size_quoted(match state {
                        OperationState::Prepared => "prepared",
                        OperationState::EffectStarted => "effect_started",
                        OperationState::Committed => "committed",
                        OperationState::Aborted => "aborted",
                        OperationState::InDoubt => "in_doubt",
                    }),
                ),
                ("replay", if *replay { 4 } else { 5 }),
            ]
        }
        Response::OperationResumed {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
            state,
            replay,
        } => {
            vec![
                ("kind", canonical_size_quoted("operation_resumed")),
                ("wire", canonical_size_u64(u64::from(PROTOCOL_VERSION))),
                ("capsule_id", canonical_size_quoted(capsule_id.as_str())),
                (
                    "correlation_id",
                    canonical_size_quoted(correlation_id.as_str()),
                ),
                ("operation_id", canonical_size_quoted(operation_id.as_str())),
                (
                    "state",
                    canonical_size_quoted(match state {
                        OperationState::Prepared => "prepared",
                        OperationState::EffectStarted => "effect_started",
                        OperationState::Committed => "committed",
                        OperationState::Aborted => "aborted",
                        OperationState::InDoubt => "in_doubt",
                    }),
                ),
                ("replay", if *replay { 4 } else { 5 }),
            ]
        }
        Response::OperationReconciled {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
            state,
            replay,
            evidence,
        } => {
            let evidence_size = canonical_size_evidence(evidence)?;
            vec![
                ("kind", canonical_size_quoted("operation_reconciled")),
                ("wire", canonical_size_u64(u64::from(PROTOCOL_VERSION))),
                ("capsule_id", canonical_size_quoted(capsule_id.as_str())),
                (
                    "correlation_id",
                    canonical_size_quoted(correlation_id.as_str()),
                ),
                ("operation_id", canonical_size_quoted(operation_id.as_str())),
                (
                    "state",
                    canonical_size_quoted(match state {
                        OperationState::Prepared => "prepared",
                        OperationState::EffectStarted => "effect_started",
                        OperationState::Committed => "committed",
                        OperationState::Aborted => "aborted",
                        OperationState::InDoubt => "in_doubt",
                    }),
                ),
                ("replay", if *replay { 4 } else { 5 }),
                ("evidence", evidence_size),
            ]
        }
        Response::CapsuleClosed {
            wire: _,
            capsule_id,
            correlation_id,
            drained,
        } => {
            vec![
                ("kind", canonical_size_quoted("capsule_closed")),
                ("wire", canonical_size_u64(u64::from(PROTOCOL_VERSION))),
                ("capsule_id", canonical_size_quoted(capsule_id.as_str())),
                (
                    "correlation_id",
                    canonical_size_quoted(correlation_id.as_str()),
                ),
                ("drained", canonical_size_u64_wire(drained.get())),
            ]
        }
        Response::StopRecorded {
            wire: _,
            capsule_id,
            correlation_id,
            operation_id,
            state,
            evidence,
        } => {
            let evidence_size = canonical_size_evidence(evidence)?;
            vec![
                ("kind", canonical_size_quoted("stop_recorded")),
                ("wire", canonical_size_u64(u64::from(PROTOCOL_VERSION))),
                ("capsule_id", canonical_size_quoted(capsule_id.as_str())),
                (
                    "correlation_id",
                    canonical_size_quoted(correlation_id.as_str()),
                ),
                (
                    "operation_id",
                    match operation_id {
                        Some(operation_id) => canonical_size_quoted(operation_id.as_str()),
                        None => 4,
                    },
                ),
                (
                    "state",
                    canonical_size_quoted(match state {
                        StopState::Requested => "requested",
                        StopState::Stopped => "stopped",
                        StopState::Failed => "failed",
                    }),
                ),
                ("evidence", evidence_size),
            ]
        }
        Response::Rejected {
            wire: _,
            code,
            detail,
        } => {
            vec![
                ("kind", canonical_size_quoted("rejected")),
                ("wire", canonical_size_u64(u64::from(PROTOCOL_VERSION))),
                ("code", canonical_size_quoted(code.as_str())),
                ("detail", canonical_size_quoted(detail.as_str())),
            ]
        }
    })
}
