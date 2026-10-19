use super::StopAuthority;

pub(super) async fn terminal_lifecycle_guard<'a>(
    stops: &StopAuthority,
    lifecycle: &'a tokio::sync::Mutex<bool>,
) -> Result<tokio::sync::MutexGuard<'a, bool>, odin_kernel::stop::StopAuthorityError> {
    odin_kube::terminal_pod::pod_lifecycle_guard(stops, lifecycle).await
}

#[cfg(test)]
mod terminal_custody_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use odin_ledger::Ledger;

    #[tokio::test]
    async fn startup_cleanup_runs_once_and_guard_serializes_new_launches() {
        let directory = tempfile::tempdir().expect("ledger directory");
        let authority = StopAuthority::new(
            Arc::new(Mutex::new(
                Ledger::open(directory.path().join("pod.sqlite3")).expect("ledger"),
            )),
            odin_kernel::recovery_worker_channel("unix:path=/run/user/0/bus").expect("channel"),
        );
        let lifecycle = tokio::sync::Mutex::new(false);
        let first = terminal_lifecycle_guard(&authority, &lifecycle)
            .await
            .expect("first recovery");
        assert!(*first);
        assert!(lifecycle.try_lock().is_err());
        let worker = odin_kernel::stop::mint_worker_id().expect("worker");
        let correlation = odin_kernel::stop::CorrelationId::new("0f1e2d3c000040008000000000000003")
            .expect("correlation");
        authority
            .register_pod_worker(
                &worker,
                &odin_kernel::stop::PodWorkerIdentity {
                    cluster: "cluster".to_owned(),
                    namespace: "namespace".to_owned(),
                    pod_name: "terminal".to_owned(),
                    pod_uid: None,
                    policy_name: "policy".to_owned(),
                    policy_uid: None,
                    secret_name: None,
                    secret_uid: None,
                    correlation_id: correlation.as_str().to_owned(),
                },
                &correlation,
            )
            .expect("new launch");
        drop(first);
        let _next = terminal_lifecycle_guard(&authority, &lifecycle)
            .await
            .expect("next lock");
        let (_, _, state) = authority
            .pod_worker_for_correlation(&correlation)
            .expect("lookup")
            .expect("worker");
        assert_eq!(
            state, "registered",
            "startup cleanup must not run again on a new launch"
        );
    }
}
