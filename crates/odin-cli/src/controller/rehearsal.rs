use std::path::Path;
use std::sync::Arc;

use odin_registry::Snapshot;

use super::state::Controller;
#[cfg(test)]
use super::types::CheckRequest;
use super::types::{CheckReport, ControllerError};

#[cfg(test)]
pub fn check(request: &CheckRequest) -> Result<CheckReport, ControllerError> {
    let mut controller = Controller::open_published(
        &request.state_root,
        &request.registry_snapshot,
        &request.node,
    )?;
    controller.startup()
}

/// Validates controller startup against the exact snapshot Arc the daemon
/// will use for runtime composition. The open posture is decided by the
/// kernel-verified snapshot relation alone: the authoritative node opens
/// strictly; any other enabled node opens as a read-only follower whose
/// kernel authority mutations are refused before any audit write.
pub fn check_snapshot(
    state_root: &Path,
    snapshot: Arc<Snapshot>,
    node: &str,
) -> Result<CheckReport, ControllerError> {
    let mut controller = match Controller::open_snapshot(state_root, Arc::clone(&snapshot), node) {
        Ok(controller) => controller,
        Err(ControllerError::AuthorityMismatch { .. }) => {
            Controller::open_snapshot_follower(state_root, snapshot, node)?
        }
        Err(error) => return Err(error),
    };
    controller.startup()
}

/// Validates controller startup for a strict-config constructor: authority
/// and refreshes resolve only against the active published registry snapshot.
pub fn check_from_config(
    config: &odin_huginn::OdindConfig,
) -> Result<CheckReport, ControllerError> {
    let mut controller = Controller::open_published(
        &config.paths.state_root,
        &config.paths.registry_snapshot,
        &config.identity.node,
    )?;
    controller.startup()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;
    use crate::test_support::{commit_all, git};

    #[test]
    fn check_reports_the_started_controller_state() {
        let fixture = PublishedFixture::new("check-control");
        let report = check(&CheckRequest {
            registry_snapshot: fixture.snapshot_path.clone(),
            state_root: fixture.state_root.clone(),
            node: "check-control".to_owned(),
        })
        .expect("start controller check");

        assert_eq!(report.schema, "odin.controller-check.v1");
        assert_eq!(report.node, "check-control");
        assert_eq!(report.authoritative_node, "check-control");
        assert_eq!(report.restart_count, 1);
        assert!(!report.stopped);
        assert_eq!(
            report.ledger_path,
            fixture.state_root.join("ledger.sqlite3")
        );
    }

    #[test]
    fn check_rejects_a_store_that_is_not_a_published_snapshot() {
        let fixture = PublishedFixture::new("check-control");
        let raw_store = fixture.temporary.path().join("raw-registry/snapshot.json");
        std::fs::create_dir_all(raw_store.parent().expect("raw parent")).expect("raw directory");
        std::fs::write(&raw_store, b"{ not a publication }").expect("write raw snapshot");

        let error = check(&CheckRequest {
            registry_snapshot: raw_store,
            state_root: fixture.state_root.clone(),
            node: "check-control".to_owned(),
        })
        .expect_err("raw snapshot must fail controller startup");

        assert!(matches!(error, ControllerError::Registry(_)));
    }

    fn write_node(root: &Path, id: &str, authoritative_state: bool) {
        let host_directory = root.join("hosts").join(format!("{id}-host"));
        fs::create_dir(&host_directory).expect("create host directory");
        fs::write(
            host_directory.join("host.toml"),
            format!(
                "schema = \"odin.registry.v1\"\n\
                 kind = \"host\"\n\
                 enabled = true\n\
                 description = \"controller rehearsal fixture host\"\n\
                 hardware = \"fixture\"\n\
                 role = \"control\"\n\
                 tailscale = \"{id}-host\"\n\
                 enrolled = true\n"
            ),
        )
        .expect("write host config");
        let directory = root.join("nodes").join(id);
        fs::create_dir(&directory).expect("create node directory");
        fs::write(
            directory.join("node.toml"),
            format!(
                "schema = \"odin.registry.v1\"\n\
                 kind = \"node\"\n\
                 enabled = true\n\
                 description = \"controller rehearsal fixture\"\n\
                 host = \"{id}-host\"\n\
                 role = \"control\"\n\
                 capabilities = []\n\
                 allow_workloads = false\n\
                 authoritative_state = {authoritative_state}\n"
            ),
        )
        .expect("write node config");
    }

    /// A controller check fixture whose registry source is a real published
    /// `SnapshotStore`: a committed authoring worktree published through the
    /// same `publish_committed` path production uses.
    struct PublishedFixture {
        temporary: TempDir,
        snapshot_path: std::path::PathBuf,
        state_root: std::path::PathBuf,
    }

    impl PublishedFixture {
        fn new(authority: &str) -> Self {
            let temporary = TempDir::new().expect("create temporary fixture");
            let worktree = temporary.path().join("authoring");
            fs::create_dir(&worktree).expect("create authoring worktree");
            git(&worktree, &["-c", "init.defaultBranch=main", "init"]);
            let registry = worktree.join("registry");
            for directory in
                odin_registry::RegistryKind::ALL.map(odin_registry::RegistryKind::directory)
            {
                fs::create_dir_all(registry.join(directory)).expect("create kind directory");
                fs::write(registry.join(directory).join(".gitkeep"), b"")
                    .expect("write kind placeholder");
            }
            write_node(&registry, authority, true);
            fs::create_dir_all(worktree.join("schemas")).expect("create schemas root");
            fs::write(worktree.join("schemas/.gitkeep"), b"").expect("write schemas placeholder");
            let commit = commit_all(&worktree, "controller check fixture");
            let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
                &worktree,
                &commit,
                Vec::<odin_registry::relational::AdmittedBinding>::new(),
            )
            .expect("committed check fixture candidate");
            let snapshot_path = temporary.path().join("state/registry/snapshot.json");
            odin_registry::SnapshotStore::new(&snapshot_path)
                .publish_committed(&candidate, 1)
                .expect("publish check fixture");
            let state_root = temporary.path().join("controller-state");
            fs::create_dir(&state_root).expect("create controller state root");
            Self {
                temporary,
                snapshot_path,
                state_root,
            }
        }
    }
}
