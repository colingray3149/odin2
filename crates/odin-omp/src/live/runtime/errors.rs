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
    LiveError::Unavailable {
        code: format!(
            "production_live_filesystem at {}:{}: {error}",
            location.file(),
            location.line()
        ),
    }
}

pub(super) fn unavailable(code: &str) -> LiveError {
    LiveError::Unavailable {
        code: code.to_owned(),
    }
}
