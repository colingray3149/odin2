//! Behavior tests for the bounded git helpers in [`super`]. Every fixture
//! is a throwaway tree under the temp dir, removed on drop; nothing reads
//! source files or asserts against this repository. The hostile fixtures
//! (refusing hooks, fsmonitor hooks, rewrite rules, a hanging git) exist
//! to prove the hardened spawn contains them.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::{bounded_git_in, git_bound, git_program, set_git_program_for_tests};

const GIT_BOUND: Duration = Duration::from_secs(30);

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One throwaway fixture tree, removed on drop.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "odin-capsule-git-test-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("fixture root created");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Runs raw git for fixture setup only: the trusted test builds the world,
/// then the hardened helpers must survive it.
fn setup_git(directory: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@invalid")
        .env("GIT_COMMITTER_NAME", "fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@invalid")
        .output()
        .expect("fixture git runs");
    assert!(
        output.status.success(),
        "fixture git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn write_script(path: &Path, body: &str) {
    fs::write(path, body).expect("script written");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("script executable");
}

fn repo_with_commit(directory: &Path, message: &str) -> String {
    fs::create_dir_all(directory).expect("repo directory created");
    setup_git(directory, &["init", "--quiet"]);
    fs::write(directory.join("file.txt"), format!("{message}\n")).expect("fixture file written");
    setup_git(directory, &["add", "."]);
    setup_git(directory, &["commit", "--quiet", "--message", message]);
    setup_git(directory, &["rev-parse", "HEAD"])
        .trim()
        .to_owned()
}

/// The fsmonitor integration is repo-local config, which env nulling
/// cannot silence. A hostile fsmonitor hook must never be spawned by an
/// audit: it would leave a side-effect marker and hang the call.
#[test]
fn repo_local_fsmonitor_is_never_spawned() {
    let fixture = Fixture::new("fsmonitor");
    let repo = fixture.path("repo");
    let head = repo_with_commit(&repo, "fsmonitor fixture");
    let marker = fixture.path("fsmonitor-marker");
    let hook = fixture.path("fsmonitor-hook");
    write_script(
        &hook,
        &format!(
            "#!/bin/sh\nprintf x >> {}\nexec sleep 300\n",
            marker.display()
        ),
    );
    setup_git(
        &repo,
        &["config", "core.fsmonitor", &hook.display().to_string()],
    );
    let status =
        bounded_git_in(&repo, &["status", "--porcelain"], GIT_BOUND).expect("status readable");
    assert!(status.trim().is_empty(), "clean tree expected: {status:?}");
    assert!(!marker.exists(), "the fsmonitor hook ran");
    assert_eq!(setup_git(&repo, &["rev-parse", "HEAD"]).trim(), head);
}

/// A hanging git and its descendant are killed at the bound.
#[test]
fn the_bound_kills_the_whole_process_group() {
    let fixture = Fixture::new("timeout");
    let repo = fixture.path("repo");
    repo_with_commit(&repo, "timeout fixture");
    let leader = fixture.path("leader-pid");
    let descendant = fixture.path("descendant-pid");
    // The fixture program delegates to the real git for every other
    // invocation so concurrent tests are unaffected, and hangs (with a
    // descendant) only for the sentinel subcommand.
    let real = git_program();
    let fake = fixture.path("fake-git");
    write_script(
        &fake,
        &format!(
            "#!/bin/sh\ncase \" $* \" in\n  *\" hang-around \"*)\n    echo $$ > {}\n    sh -c 'exec sleep 300' &\n    echo $! > {}\n    exec sleep 300\n    ;;\n  *)\n    exec {} \"$@\"\n    ;;\nesac\n",
            leader.display(),
            descendant.display(),
            real.display(),
        ),
    );
    set_git_program_for_tests(Some(fake));
    let bound = Duration::from_secs(1);
    let started = Instant::now();
    let error = git_bound(Some(&repo), &["hang-around"], bound)
        .expect_err("the hanging git is killed at the bound");
    assert!(error.contains("exceeded its 1s bound"), "{error:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the bound took {:?}",
        started.elapsed()
    );
    for pid_file in [&leader, &descendant] {
        let pid = fs::read_to_string(pid_file)
            .expect("the pid was recorded")
            .trim()
            .to_owned();
        assert_process_gone(&pid);
    }
    set_git_program_for_tests(None);
}

/// A git that exits while a descendant keeps its output pipe open fails the call, and the
/// descendant does not outlive it.
#[test]
fn a_descendant_holding_the_output_pipe_is_killed_when_the_drain_stalls() {
    let fixture = Fixture::new("stalled-drain");
    let repo = fixture.path("repo");
    repo_with_commit(&repo, "stalled drain fixture");
    let descendant = fixture.path("descendant-pid");
    let real = git_program();
    let fake = fixture.path("fake-git");
    write_script(
        &fake,
        &format!(
            "#!/bin/sh\ncase \" $* \" in\n  *\" hold-pipe \"*)\n    sh -c 'exec sleep 300' &\n    echo $! > {}\n    exit 0\n    ;;\n  *)\n    exec {} \"$@\"\n    ;;\nesac\n",
            descendant.display(),
            real.display(),
        ),
    );
    set_git_program_for_tests(Some(fake));
    let error = git_bound(Some(&repo), &["hold-pipe"], GIT_BOUND)
        .expect_err("a pipe held past exit fails the call");
    set_git_program_for_tests(None);
    assert!(!error.is_empty());
    let pid = fs::read_to_string(&descendant)
        .expect("the descendant was recorded")
        .trim()
        .to_owned();
    assert_process_gone(&pid);
}

fn assert_process_gone(pid: &str) {
    let process = format!("/proc/{pid}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !Path::new(&process).exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("pid {pid} survived the process group kill");
}
