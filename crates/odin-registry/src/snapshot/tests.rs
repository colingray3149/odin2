use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use super::store::{versioned_receipt_path, versioned_snapshot_path};
use crate::relational::AdmittedBinding;
use crate::schema::RegistryKind;
use crate::snapshot::{SnapshotStore, ValidatedSnapshotCandidate};

mod committed;
mod conversation;
mod handle;
mod migration;
mod races;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "odin-registry-snapshot-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn node_toml(id: &str, authoritative: bool) -> String {
    format!(
        "schema = \"odin.registry.v1\"\n\
         kind = \"node\"\n\
         enabled = true\n\
         description = \"committed publisher fixture\"\n\
         host = \"{id}-host\"\n\
         role = \"control\"\n\
         capabilities = []\n\
         allow_workloads = false\n\
         authoritative_state = {authoritative}\n"
    )
}

fn host_toml(id: &str) -> String {
    format!(
        "schema = \"odin.registry.v1\"\n\
         kind = \"host\"\n\
         enabled = true\n\
         description = \"committed publisher fixture host\"\n\
         hardware = \"fixture\"\n\
         role = \"control\"\n\
         tailscale = \"{id}-host\"\n\
         enrolled = true\n"
    )
}

fn git(worktree: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git output is UTF-8")
        .trim_end()
        .to_owned()
}

fn write_fixture_registry(worktree: &Path, nodes: &[(&str, bool)]) {
    let registry = worktree.join("registry");
    for kind in RegistryKind::ALL {
        let directory = registry.join(kind.directory());
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(".gitkeep"), b"").unwrap();
    }
    for (id, authoritative) in nodes {
        let directory = registry.join("nodes").join(id);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("node.toml"), node_toml(id, *authoritative)).unwrap();
        let host_directory = registry.join("hosts").join(format!("{id}-host"));
        fs::create_dir_all(&host_directory).unwrap();
        fs::write(host_directory.join("host.toml"), host_toml(id)).unwrap();
    }
    fs::create_dir_all(worktree.join("schemas")).unwrap();
    fs::write(worktree.join("schemas/.gitkeep"), b"").unwrap();
}

fn commit_all(worktree: &Path, message: &str) -> String {
    git(worktree, &["add", "-A"]);
    git(
        worktree,
        &[
            "-c",
            "user.name=Odin Test",
            "-c",
            "user.email=odin-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            message,
        ],
    );
    git(worktree, &["rev-parse", "HEAD"])
}

fn commit_empty(worktree: &Path, message: &str) -> String {
    git(
        worktree,
        &[
            "-c",
            "user.name=Odin Test",
            "-c",
            "user.email=odin-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-m",
            message,
        ],
    );
    git(worktree, &["rev-parse", "HEAD"])
}

struct CommittedFixture {
    _directory: TestDirectory,
    worktree: PathBuf,
    store: SnapshotStore,
}

impl CommittedFixture {
    fn new(nodes: &[(&str, bool)]) -> (Self, String) {
        let directory = TestDirectory::new();
        let worktree = directory.0.join("worktree");
        fs::create_dir_all(&worktree).unwrap();
        git(&worktree, &["-c", "init.defaultBranch=main", "init"]);
        write_fixture_registry(&worktree, nodes);
        let commit = commit_all(&worktree, "fixture registry");
        let store = SnapshotStore::new(directory.0.join("state/registry/snapshot.json"));
        (
            Self {
                _directory: directory,
                worktree,
                store,
            },
            commit,
        )
    }

    fn candidate(&self, commit: &str) -> ValidatedSnapshotCandidate {
        ValidatedSnapshotCandidate::from_committed_worktree(
            &self.worktree,
            commit,
            Vec::<AdmittedBinding>::new(),
        )
        .expect("committed candidate")
    }

    fn runtime_candidate(&self, commit: &str) -> ValidatedSnapshotCandidate {
        self.store
            .runtime_candidate(&self.worktree, commit, Vec::<AdmittedBinding>::new())
            .expect("isolated runtime candidate")
    }

    fn unpublished_change(&self) -> String {
        fs::write(
            self.worktree.join("registry/nodes/beta/node.toml"),
            node_toml("beta", false).replace("committed publisher fixture", "pending deployment"),
        )
        .unwrap();
        fs::write(
            self.worktree.join("schemas/pending.json"),
            b"{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\"}\n",
        )
        .unwrap();
        commit_all(&self.worktree, "unpublished registry and schema change")
    }

    fn runtime_change(&self, description: &str) -> String {
        fs::write(
            self.worktree.join("registry/nodes/alpha/node.toml"),
            node_toml("alpha", true).replace("committed publisher fixture", description),
        )
        .unwrap();
        commit_all(&self.worktree, description)
    }

    fn versioned_snapshot(&self, revision: u64) -> PathBuf {
        versioned_snapshot_path(self.store.path(), revision)
    }

    fn versioned_receipt(&self, revision: u64) -> PathBuf {
        versioned_receipt_path(self.store.path(), revision)
    }
}
