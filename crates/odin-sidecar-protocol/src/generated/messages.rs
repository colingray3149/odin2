//! Generated authority wire v2 message accessors and exact echo semantics; do not edit.

use super::*;

impl Request {
    pub const fn capsule_id(&self) -> &CapsuleId {
        match self {
            Self::InvokeCapability { capsule_id, .. } => capsule_id,
            Self::ResumeOperation { capsule_id, .. } => capsule_id,
            Self::ReconcileOperation { capsule_id, .. } => capsule_id,
            Self::CloseCapsule { capsule_id, .. } => capsule_id,
            Self::StopIntent { capsule_id, .. } => capsule_id,
        }
    }

    pub const fn correlation_id(&self) -> &CorrelationId {
        match self {
            Self::InvokeCapability { correlation_id, .. } => correlation_id,
            Self::ResumeOperation { correlation_id, .. } => correlation_id,
            Self::ReconcileOperation { correlation_id, .. } => correlation_id,
            Self::CloseCapsule { correlation_id, .. } => correlation_id,
            Self::StopIntent { correlation_id, .. } => correlation_id,
        }
    }

    pub const fn operation_id(&self) -> Option<&OperationId> {
        match self {
            Self::InvokeCapability { .. } => None,
            Self::ResumeOperation { operation_id, .. } => Some(operation_id),
            Self::ReconcileOperation { operation_id, .. } => Some(operation_id),
            Self::CloseCapsule { .. } => None,
            Self::StopIntent { operation_id, .. } => operation_id.as_ref(),
        }
    }
}

impl Response {
    pub const fn correlation_id(&self) -> Option<&CorrelationId> {
        match self {
            Self::CapabilityInvoked { correlation_id, .. } => Some(correlation_id),
            Self::OperationResumed { correlation_id, .. } => Some(correlation_id),
            Self::OperationReconciled { correlation_id, .. } => Some(correlation_id),
            Self::CapsuleClosed { correlation_id, .. } => Some(correlation_id),
            Self::StopRecorded { correlation_id, .. } => Some(correlation_id),
            Self::Rejected { .. } => None,
        }
    }
}

/// Returns true only when kind matches and every caller-supplied ID is echoed byte-for-byte.
pub fn echoes(response: &Response, request: &Request) -> bool {
    match (response, request) {
        (
            Response::CapabilityInvoked {
                capsule_id: response_capsule_id,
                correlation_id: response_correlation_id,
                ..
            },
            Request::InvokeCapability {
                capsule_id: request_capsule_id,
                correlation_id: request_correlation_id,
                ..
            },
        ) => {
            response_capsule_id == request_capsule_id
                && response_correlation_id == request_correlation_id
        }
        (
            Response::OperationResumed {
                capsule_id: response_capsule_id,
                correlation_id: response_correlation_id,
                operation_id: response_operation_id,
                ..
            },
            Request::ResumeOperation {
                capsule_id: request_capsule_id,
                correlation_id: request_correlation_id,
                operation_id: request_operation_id,
                ..
            },
        ) => {
            response_capsule_id == request_capsule_id
                && response_correlation_id == request_correlation_id
                && response_operation_id == request_operation_id
        }
        (
            Response::OperationReconciled {
                capsule_id: response_capsule_id,
                correlation_id: response_correlation_id,
                operation_id: response_operation_id,
                ..
            },
            Request::ReconcileOperation {
                capsule_id: request_capsule_id,
                correlation_id: request_correlation_id,
                operation_id: request_operation_id,
                ..
            },
        ) => {
            response_capsule_id == request_capsule_id
                && response_correlation_id == request_correlation_id
                && response_operation_id == request_operation_id
        }
        (
            Response::CapsuleClosed {
                capsule_id: response_capsule_id,
                correlation_id: response_correlation_id,
                ..
            },
            Request::CloseCapsule {
                capsule_id: request_capsule_id,
                correlation_id: request_correlation_id,
                ..
            },
        ) => {
            response_capsule_id == request_capsule_id
                && response_correlation_id == request_correlation_id
        }
        (
            Response::StopRecorded {
                capsule_id: response_capsule_id,
                correlation_id: response_correlation_id,
                operation_id: response_operation_id,
                ..
            },
            Request::StopIntent {
                capsule_id: request_capsule_id,
                correlation_id: request_correlation_id,
                operation_id: request_operation_id,
                ..
            },
        ) => {
            response_capsule_id == request_capsule_id
                && response_correlation_id == request_correlation_id
                && response_operation_id == request_operation_id
        }
        _ => false,
    }
}
