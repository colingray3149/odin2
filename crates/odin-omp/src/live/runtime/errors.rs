use odin_domain::huginn::LiveError;

pub(super) fn invalid(message: impl Into<String>) -> LiveError {
    LiveError::InvalidRequest {
        code: "production_live_runtime".to_owned(),
        message: message.into(),
    }
}

pub(super) fn conflict(message: impl Into<String>) -> LiveError {
    LiveError::Conflict {
        code: "production_live_runtime".to_owned(),
        message: message.into(),
    }
}

#[track_caller]
pub(super) fn io_error(error: std::io::Error) -> LiveError {
    let location = std::panic::Location::caller();
    LiveError::unavailable(
        "production_live_filesystem",
        format!("at {}:{}: {error}", location.file(), location.line()),
    )
}

/// A session-listing refusal carries only its non-secret kind — ids and
/// states, never token bytes — so it stays diagnosable from the daemon log.
pub(super) fn listing_refusal(
    error: &crate::host_tools::operations::HostToolOperationError,
) -> LiveError {
    use crate::host_tools::operations::HostToolOperationError as Error;
    let kind = match error {
        Error::Token(_) | Error::PublishedAuthorityUnavailable { .. } => "seat_token",
        Error::Generation { .. } => "generation",
        Error::Authority(_) => "operation_authority",
        Error::Kernel(_) => "kernel_policy",
        Error::Ledger(_) => "ledger",
        _ => "session_listing",
    };
    LiveError::unavailable("published_operation_authority", kind)
}
