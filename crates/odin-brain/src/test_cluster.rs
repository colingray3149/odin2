//! A throwaway PostgreSQL cluster for one test (the dev shell's
//! postgresql_17 with pgvector and pg_search, which the server preloads):
//! initialized in a temporary directory, served on a private socket only,
//! stopped on drop. Other crates' tests reach it through the `test-cluster`
//! feature.

use std::process::Command;

pub struct TestCluster {
    dir: tempfile::TempDir,
    pub conninfo: String,
}

fn run(command: &mut Command) {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{command:?} (postgres from the dev shell): {error}"));
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

impl TestCluster {
    pub fn start() -> Self {
        let dir = tempfile::tempdir().expect("cluster directory");
        let data = dir.path().join("data");
        run(Command::new("initdb")
            .args(["--auth=trust", "--username=odin", "--no-sync", "--pgdata"])
            .arg(&data));
        let settings = format!(
            "-k {} -c listen_addresses='' -c fsync=off -c full_page_writes=off \
             -c shared_preload_libraries=pg_search",
            dir.path().display()
        );
        run(Command::new("pg_ctl")
            .args(["--wait", "--pgdata"])
            .arg(&data)
            .args(["--log"])
            .arg(dir.path().join("log"))
            .args(["--options", &settings, "start"]));
        let conninfo = format!("host={} dbname=postgres user=odin", dir.path().display());
        Self { dir, conninfo }
    }

    /// Runs `sql` through psql, panicking with its error on failure; the
    /// trimmed output.
    pub fn sql(&self, sql: &str) -> String {
        let output = Command::new("psql")
            .args([&self.conninfo, "-X", "-v", "ON_ERROR_STOP=1", "-tAc", sql])
            .output()
            .expect("psql (from the dev shell)");
        assert!(
            output.status.success(),
            "{sql}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// A store root beside the cluster, gone with it.
    pub fn path(&self) -> std::path::PathBuf {
        let root = self.dir.path().join("store");
        std::fs::create_dir_all(&root).expect("store root");
        root
    }

    /// The brain store over this cluster, migrated.
    pub fn store(&self) -> std::sync::Arc<crate::index::postgres::BrainPostgres> {
        std::sync::Arc::new(
            crate::index::postgres::BrainPostgres::connect(&self.conninfo)
                .expect("the test cluster's brain store"),
        )
    }
}

thread_local! {
    /// The cluster of [`TestCluster::thread_store`], stopped when the test's
    /// thread ends.
    static THREAD_CLUSTER: std::cell::OnceCell<TestCluster> = const { std::cell::OnceCell::new() };
}

impl TestCluster {
    /// One brain store for the calling test thread, for fixtures that hand
    /// out a service without a place to keep its cluster.
    pub fn thread_store() -> std::sync::Arc<crate::index::postgres::BrainPostgres> {
        THREAD_CLUSTER.with(|cluster| cluster.get_or_init(TestCluster::start).store())
    }
}

impl Drop for TestCluster {
    fn drop(&mut self) {
        let _ = Command::new("pg_ctl")
            .args(["--mode=immediate", "--pgdata"])
            .arg(self.dir.path().join("data"))
            .arg("stop")
            .output();
    }
}
