use super::*;

#[test]
fn sidecar_failure_preserves_cause_and_uncertainty() {
    use odin_sidecar::SidecarErrorCode::{Remote, Unanswered};
    for (code, message, uncertain) in [
        (
            Remote,
            "executor.uncertain: compiled effector closed without a response",
            true,
        ),
        (Remote, "executor.rejected: preimage hash mismatch", false),
        (Unanswered, "server closed without a response", true),
    ] {
        let error = odin_sidecar::SidecarError::new(code, message);
        let fault = invoke_wire_fault(&error);
        match fault {
            HostToolError::Uncertain { detail, .. } => {
                assert!(uncertain);
                assert!(detail.contains(message));
            }
            HostToolError::Arguments { detail, .. } => {
                assert!(!uncertain);
                assert!(detail.contains(message));
            }
            other => panic!("unexpected sidecar error: {other:?}"),
        }
    }
}
