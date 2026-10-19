use super::*;

#[test]
fn sidecar_failure_preserves_cause_and_uncertainty() {
    for (message, uncertain) in [
        (
            "executor.uncertain: compiled effector closed without a response",
            true,
        ),
        ("executor.rejected: preimage hash mismatch", false),
    ] {
        let error =
            odin_sidecar::SidecarError::new(odin_sidecar::SidecarErrorCode::Remote, message);
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
