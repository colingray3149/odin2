use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_adapter_core::dispatch::{AdapterBackends, AdapterExecutor, AdapterResultSink};
use odin_adapter_core::evidence::LedgerEffectReceiptSink;
use odin_kernel::{Clock, OperationExecutor, SchemaCatalog};
use odin_ledger::Ledger;

use crate::host_tools::adapter::DeclaredAdapterBackends;
use crate::host_tools::executor::HostToolExecutor;
use crate::host_tools::operations::{HostAdapterStatus, SupervisedAdapterStatus};

/// The composed adapter stack the live runtime assembles: one assembly,
/// never two.
pub(in crate::live) struct AdapterStack {
    /// The executor behind the operation authority: the adapter dispatcher
    /// over the declared backends, falling back to the concrete host
    /// executor for every non-adapter permit.
    pub(in crate::live) executor: Arc<dyn OperationExecutor>,
    /// The live Ready-only adapter-health source over the same backends.
    pub(in crate::live) status: Arc<dyn HostAdapterStatus>,
}

/// The declared adapter backends and the status freshness bound.
pub(in crate::live) struct AdapterStackConfig {
    pub adapters: Arc<DeclaredAdapterBackends>,
    pub status_ttl: Duration,
}

/// The single adapter-stack assembly. The dispatcher is always composed —
/// with no backend configured every adapter capability is refused as a typed
/// unavailable instead of reaching a HostTool.
pub(in crate::live) fn compose_adapter_stack(
    config: AdapterStackConfig,
    fallback: Arc<HostToolExecutor>,
    schemas: Arc<dyn SchemaCatalog + Send + Sync>,
    ledger: &Arc<Mutex<Ledger>>,
    operation_clock: &Clock,
) -> Result<AdapterStack, String> {
    let AdapterStackConfig {
        adapters,
        status_ttl,
    } = config;
    let configured: BTreeSet<String> = adapters.ids().map(str::to_owned).collect();
    let status: Arc<dyn HostAdapterStatus> = Arc::new(SupervisedAdapterStatus::new(
        Arc::clone(&adapters) as Arc<dyn crate::host_tools::operations::HostAdapterStatusTransport>,
        configured,
        status_ttl,
    ));
    let receipt_clock: Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync> = {
        let clock = Arc::clone(operation_clock);
        Arc::new(move || {
            let now_ms = i64::try_from(clock()).expect("wall clock out of range");
            time::OffsetDateTime::from_unix_timestamp_nanos(
                i128::from(now_ms)
                    .checked_mul(1_000_000)
                    .expect("wall clock out of range"),
            )
            .expect("wall clock out of range")
        })
    };
    let fallback_executor: Arc<dyn OperationExecutor> =
        Arc::clone(&fallback) as Arc<dyn OperationExecutor>;
    let results: Arc<dyn AdapterResultSink> = fallback;
    let composed = AdapterExecutor::new(
        adapters as Arc<dyn AdapterBackends>,
        fallback_executor,
        schemas,
        Arc::new(LedgerEffectReceiptSink::new(
            Arc::clone(ledger),
            Arc::clone(&receipt_clock),
        )),
        results,
        receipt_clock,
    );
    Ok(AdapterStack {
        executor: Arc::new(composed),
        status,
    })
}
