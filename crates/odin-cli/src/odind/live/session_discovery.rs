//! Adapts the live ledger's durable changes to feed startup discovery.

use std::sync::Arc;

use odin_domain::huginn as live;

/// Binds the daemon's real live ledger to the durable-feeds pump's one-time
/// startup discovery: the bounded durable session listing (id + event head)
/// that lets terminal sessions finish draining after a restart.
pub(super) struct LiveLedgerSessionDiscovery {
    pub(super) ledger: Arc<dyn odin_omp::live::ledger::LiveLedger>,
}

#[async_trait::async_trait]
impl odin_huginn::feed::DurableSessionDiscovery for LiveLedgerSessionDiscovery {
    async fn changes_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<odin_huginn::feed::SessionChange>, live::LiveError> {
        self.ledger
            .changes_after(after, limit)
            .await
            .map_err(odin_omp::live::ledger::live_error)
            .map(|changes| {
                changes
                    .into_iter()
                    .map(|change| odin_huginn::feed::SessionChange {
                        position: change.position,
                        session_id: change.session_id,
                        head: change.head.get(),
                    })
                    .collect()
            })
    }
}
