//! The daemon half of non-OMP harnesses: the routes
//! every declared harness launch option resolves to (harness + environment
//! from the published registry), the session workspace (a fresh clone of
//! the project on `seat/<seat>/<session>`, on the environment's machine)
//! and its hand-back (each turn's changes committed and the branch pushed
//! into the project's own repository — the session's seat branch, or the
//! exact seat branch the agent moved the workspace to), and the session's
//! Zellij tab.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use odin_domain::huginn::{LiveError, SessionManifest};
use odin_omp::live::harness::{HarnessRoute, HarnessTerminals, ProjectAccounts};
use odin_omp::live::runtime::ProductionBridgeRuntimeFactory;
use odin_omp::live::zellij::ZellijLiveAdapter;
use odin_registry::{ObjectConfig, RegistryObject};

#[path = "harness/workspace.rs"]
pub(crate) mod workspace;

/// Every harness route the seats' declared launch options name, resolved
/// against the published registry. A launch option naming an undeclared or
/// disabled harness or environment fails composition: the seat would
/// otherwise be offered a launch that can never open.
pub(crate) fn harness_routes(
    seats: &[odin_huginn::config::OdindSeatBinding],
    objects: &[RegistryObject],
) -> Result<Vec<HarnessRoute>, String> {
    let wanted: BTreeSet<(String, String)> = seats
        .iter()
        .flat_map(|seat| seat.launch_options.iter())
        .filter_map(|option| option.harness.as_ref())
        .map(|binding| (binding.harness.clone(), binding.environment.clone()))
        .collect();
    let mut harnesses = BTreeMap::new();
    let mut environments = BTreeMap::new();
    for object in objects {
        match &object.config {
            ObjectConfig::Harness(harness) if harness.enabled => {
                harnesses.insert(object.id.clone(), harness.as_ref().clone());
            }
            ObjectConfig::Environment(environment) if environment.enabled => {
                environments.insert(object.id.clone(), environment.as_ref().clone());
            }
            _ => {}
        }
    }
    wanted
        .into_iter()
        .map(|(harness_id, environment_id)| {
            let harness = harnesses.get(&harness_id).cloned().ok_or_else(|| {
                format!("launch harness {harness_id} is not an enabled registry harness")
            })?;
            let environment = environments.get(&environment_id).cloned().ok_or_else(|| {
                format!(
                    "launch environment {environment_id} is not an enabled registry environment"
                )
            })?;
            Ok(HarnessRoute {
                harness_id,
                harness,
                environment_id,
                environment,
                account: None,
            })
        })
        .collect()
}

/// The account each enabled registry project's agents sign in with, by kind.
pub(crate) fn project_accounts(objects: &[RegistryObject]) -> ProjectAccounts {
    objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Project(project) if project.enabled && !project.accounts.is_empty() => {
                Some((object.id.clone(), project.accounts.clone()))
            }
            _ => None,
        })
        .collect()
}

pub(crate) struct FactoryHarnessTerminals(pub(crate) Arc<ProductionBridgeRuntimeFactory>);

#[async_trait]
impl HarnessTerminals for FactoryHarnessTerminals {
    async fn open(
        &self,
        manifest: &SessionManifest,
        cwd: &Path,
    ) -> Result<Option<Arc<ZellijLiveAdapter>>, LiveError> {
        // A remote workspace path does not exist here: the tab opens in the
        // project root instead (it shows the session journal either way).
        let local = if cwd.is_absolute() && cwd.is_dir() {
            cwd.to_path_buf()
        } else {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
        };
        self.0.open_session_terminal(manifest, &local).await
    }

    async fn open_attached(
        &self,
        manifest: &SessionManifest,
        cwd: &Path,
        attach: Vec<String>,
    ) -> Result<Option<Arc<ZellijLiveAdapter>>, LiveError> {
        self.0
            .open_session_terminal_attached(manifest, cwd, Some(attach))
            .await
    }
}

/// Watchdog hits on terminal sessions raise incidents through the desk.
pub(crate) struct DeskIncidentSink(pub(crate) Arc<crate::incidents::IncidentDesk>);

impl odin_omp::live::harness::HarnessIncidentSink for DeskIncidentSink {
    fn raise(&self, environment: &str, watchdog: &str, summary: &str, detail: &str) {
        let receipt = self.0.raise(crate::incidents::RaisedIncident {
            source: format!("watchdog:{environment}/{watchdog}"),
            severity: odin_huginn::incidents::IncidentSeverityView::Warning,
            summary: summary.to_owned(),
            detail: detail.chars().take(1_000).collect(),
            affected: vec![format!("environment:{environment}")],
            signature: format!("watchdog:{environment}:{watchdog}"),
        });
        tracing::info!(
            "watchdog incident environment={environment} watchdog={watchdog} \
             incident={} published={} phone={} woken={} summary={summary:?}",
            receipt.incident_id,
            receipt.published,
            receipt.phone_alerted,
            receipt.conversation_woken
        );
    }
}
