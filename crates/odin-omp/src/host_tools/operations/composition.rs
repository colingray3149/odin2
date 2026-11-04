//! Validates and assembles the host-tool operation stack before serving dispatches.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use odin_domain::CapabilityId;
use odin_kernel::{CapabilityContract, OperationAuthority, OperationExecutor};

use super::catalog::declared_narrowing_schema;
use super::{HostToolOperationError, HostToolOperations};

impl HostToolOperations {
    /// Validates catalog bindings and recovers orphaned journal entries to `in_doubt` before serving.
    pub fn new(
        inputs: super::OperationStackInputs,
        contracts: BTreeMap<CapabilityId, CapabilityContract>,
        authority_provider: Arc<super::ProvisionedFreshAuthorityProvider>,
    ) -> Result<Self, HostToolOperationError> {
        let super::OperationStackInputs {
            catalog,
            schemas,
            executor,
            adapter_executor,
            adapter_status,
            limits,
            clock,
            ledger,
            revisions,
            workload_drafts,
        } = inputs;
        let mut tool_index = BTreeMap::new();
        for (id, contract) in &contracts {
            let Some(admitted) = catalog.admitted(id) else {
                if catalog.is_operator_owned(id) {
                    // Operator CLI capabilities have no model-dispatch route.
                    continue;
                }
                return Err(HostToolOperationError::Composition {
                    detail: format!("contract {id} is not admitted by the operation catalog"),
                });
            };
            if admitted.contract != *contract {
                return Err(HostToolOperationError::Composition {
                    detail: format!(
                        "catalog admission for {id} does not match the declared contract"
                    ),
                });
            }
            if !catalog.resolves(&contract.handler)
                || !catalog.resolves(&contract.evidence_extractor)
            {
                return Err(HostToolOperationError::Composition {
                    detail: format!("contract {id} handler or evidence extractor does not resolve"),
                });
            }
            if let Some(existing) =
                tool_index.insert(contract.tool_name.as_ref().to_owned(), id.clone())
            {
                return Err(HostToolOperationError::Composition {
                    detail: format!(
                        "tool {} is bound by both {} and {}",
                        contract.tool_name, existing, id
                    ),
                });
            }
        }
        let contract_adapters: BTreeSet<String> = contracts
            .values()
            .filter_map(|contract| contract.adapter.clone())
            .collect();
        // The declared argument narrowing is compiled exactly once from
        // the immutable registered model surfaces: `HostToolRegistry`
        // takes `&mut` only before it is `Arc`-wrapped for this executor,
        // so the definition set compiled here is the definition set the
        // model was listed with and the executor serves, for the
        // registry's whole lifetime. A definition that does not compile
        // into a schema fails composition instead of silently dropping a
        // declared constraint.
        let mut narrowing_schemas = BTreeMap::new();
        for definition in executor.definitions() {
            let narrowing = declared_narrowing_schema(&definition.name, definition.parameters)?;
            narrowing_schemas.insert(definition.name.into_owned(), narrowing);
        }
        let authority = Arc::new(OperationAuthority::new(
            Arc::clone(&catalog),
            Arc::clone(&schemas),
            Arc::clone(&adapter_executor) as Arc<dyn OperationExecutor>,
            limits,
            Arc::clone(&clock),
            Arc::clone(&ledger),
        ));
        authority.recover()?;
        let toolset_routes = Arc::new(super::toolsets::routes(
            contracts.values(),
            schemas.as_ref(),
        )?);
        Ok(Self {
            authority,
            contracts: Arc::new(contracts),
            tool_index: Arc::new(tool_index),
            toolset_routes,
            toolsets: Arc::new(BTreeMap::new()),
            projection_memo: Arc::new(Mutex::new(BTreeMap::new())),
            contract_adapters: Arc::new(contract_adapters),
            narrowing_schemas: Arc::new(narrowing_schemas),
            schemas,
            executor,
            adapter_status,
            authority_provider,
            revisions,
            workload_drafts,
            task_grants: None,
            approved_calls: None,
            jobs: None,
            delivery_acknowledger: None,
            result_transformer: None,
            material_memo: Arc::new(Mutex::new(BTreeMap::new())),
            clock,
            ledger,
        })
    }
}
