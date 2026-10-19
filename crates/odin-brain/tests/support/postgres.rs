//! A throwaway PostgreSQL cluster with pgvector for one test (the dev
//! shell's postgresql_17 with pgvector): initialized in a temporary
//! directory, served on a private socket only, stopped on drop.

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
            "-k {} -c listen_addresses='' -c fsync=off -c full_page_writes=off",
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
