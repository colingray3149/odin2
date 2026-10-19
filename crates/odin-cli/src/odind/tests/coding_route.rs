use std::collections::BTreeMap;
use std::sync::Arc;

use odin_domain::Scope;
use odin_hermes::runtime::coding::{
    ArtifactSource, CodingRoute, NixVerb, ProposalFailure, TestSelection,
};
use odin_kernel::operation::PreparedEffect;

use super::{valid_attr, valid_test_path, DaemonCodingRoute, MergeLock, MERGE_LOCK_BOUND};
use crate::test_support::{commit_all, git};

#[path = "scoped_test_fixture.rs"]
mod scoped_test_fixture;

#[test]
fn merge_cleanup_never_deletes_a_foreign_administrative_directory() {
    let root = tempfile::tempdir().unwrap();
    let worktree = root.path().join("owned-merge");
    let foreign = root.path().join("foreign/worktrees/owner");
    // The admitted project's common directory, holding no such worktree.
    let admitted = root.path().join("admitted/.git");
    std::fs::create_dir_all(admitted.join("worktrees")).unwrap();
    std::fs::create_dir_all(&worktree).unwrap();
    std::fs::create_dir_all(&foreign).unwrap();
    std::fs::write(worktree.join("owned"), b"merge evidence").unwrap();
    std::fs::write(foreign.join("keep"), b"foreign evidence").unwrap();
    std::fs::write(
        worktree.join(".git"),
        format!("gitdir: {}\n", foreign.display()),
    )
    .unwrap();

    assert!(super::remove_merge_worktree(&worktree, &admitted).is_err());
    assert_eq!(
        std::fs::read(foreign.join("keep")).unwrap(),
        b"foreign evidence"
    );
    assert_eq!(
        std::fs::read(worktree.join("owned")).unwrap(),
        b"merge evidence"
    );
}

/// Incomplete worktree metadata cannot establish which repository may remove it.
#[test]
fn merge_cleanup_removes_only_a_reciprocally_bound_worktree() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    std::fs::create_dir(&project).unwrap();
    git(&project, &["init", "-q"]);
    std::fs::write(project.join("base.txt"), "base\n").unwrap();
    commit_all(&project, "base");
    let common = project.join(".git");
    let bound = root.path().join("merge-worktrees/bound");
    git(
        &project,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            bound.to_str().unwrap(),
            "HEAD",
        ],
    );
    super::remove_merge_worktree(&bound, &common).unwrap();
    assert!(!bound.exists(), "the bound worktree was removed");
    assert!(
        !common.join("worktrees/bound").exists(),
        "and its administration"
    );

    let residue = root.path().join("merge-worktrees/residue");
    std::fs::create_dir_all(&residue).unwrap();
    std::fs::create_dir_all(common.join("worktrees/residue")).unwrap();
    assert!(super::remove_merge_worktree(&residue, &common).is_err());
    assert!(residue.exists() && common.join("worktrees/residue").exists());
}

/// Record a passing log without executing a build; lifecycle tests cover execution.
fn tested(route: &DaemonCodingRoute, scope: &Scope) {
    let selection = TestSelection::Attr(None);
    let registered = route.registered(scope, &super::Unowned).unwrap();
    let run = route.begin_test_run(&registered, &selection).unwrap();
    let log = odin_hermes::runtime::coding::NixLog {
        ok: true,
        log: "test result: ok. 1 passed; 0 failed; 0 ignored".to_owned(),
        seconds: 0,
    };
    route.finish_test_run(run, &selection, log).unwrap();
}

/// A declared project repository and one session's capsule cloned from it,
/// laid out exactly where `live_authority` provisions capsules.
fn session_capsule() -> (
    tempfile::TempDir,
    DaemonCodingRoute,
    Scope,
    std::path::PathBuf,
) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("valhalla/surtr");
    std::fs::create_dir_all(&root).unwrap();
    git(&root, &["-c", "init.defaultBranch=main", "init", "--quiet"]);
    git(&root, &["config", "user.name", "Odin Test"]);
    git(
        &root,
        &["config", "user.email", "odin-test@example.invalid"],
    );
    git(&root, &["config", "commit.gpgsign", "false"]);
    std::fs::write(root.join("README.md"), "surtr\n").unwrap();
    // The declared check the gate runs on every merged HEAD: a real
    // derivation that builds offline from the sandbox's own /bin/sh.
    std::fs::write(
        root.join("flake.nix"),
        "{ outputs = _: { checks.x86_64-linux.smoke = derivation { name = \
         \"odin-merge-gate-smoke\"; system = \"x86_64-linux\"; builder = \"/bin/sh\"; args = \
         [ \"-c\" \"echo smoke > $out\" ]; }; }; }\n",
    )
    .unwrap();
    commit_all(&root, "start");
    let session: odin_domain::SessionId = "0e0c5a8e-1111-4222-8333-444455556666".parse().unwrap();
    let state = dir.path().join("state");
    let capsule = state
        .join("session-authorities")
        .join(format!("capsule-capsule-{session}"))
        .join("capsule");
    std::fs::create_dir_all(&capsule).unwrap();
    git(
        &capsule,
        &["clone", "--quiet", root.to_str().unwrap(), "project"],
    );
    let route = DaemonCodingRoute {
        state_root: state,
        session_pool: None,
        supervisor: Default::default(),
        projects: BTreeMap::from([("surtr".to_owned(), root.clone())]),
        registry: Some(super::review_registry()),
    };
    let scope = Scope {
        seat: Some("gungnir".parse().unwrap()),
        project: Some("surtr".parse().unwrap()),
        session: Some(session),
        ..Scope::default()
    };
    (dir, route, scope, root)
}

fn admitted<V: Send + 'static, E: Send + 'static>(
    scope: &Scope,
    work: impl Fn(&PreparedEffect) -> Result<V, E> + Send + Sync + 'static,
) -> Result<V, E> {
    scoped_test_fixture::dispatch_with(scope.clone(), serde_json::json!({}), None, work)
}

fn merge(
    route: &Arc<DaemonCodingRoute>,
    scope: &Scope,
    branch: &str,
    base: &str,
    head: &str,
) -> Result<serde_json::Value, ProposalFailure> {
    let (route, owner) = (Arc::clone(route), scope.clone());
    let (branch, base, head) = (branch.to_owned(), base.to_owned(), head.to_owned());
    admitted(scope, move |effect| {
        route.merge(effect, &owner, "surtr", &branch, &base, &head)
    })
}

fn propose(
    route: &Arc<DaemonCodingRoute>,
    scope: &Scope,
    summary: &str,
    branch: Option<&str>,
) -> Result<serde_json::Value, ProposalFailure> {
    let (route, owner) = (Arc::clone(route), scope.clone());
    let (summary, branch) = (summary.to_owned(), branch.map(str::to_owned));
    admitted(scope, move |effect| {
        route.propose(effect, &owner, summary.clone(), branch.clone())
    })
}

fn propose_reviewed(
    route: &Arc<DaemonCodingRoute>,
    scope: &Scope,
    summary: &str,
    branch: Option<&str>,
) -> Result<serde_json::Value, ProposalFailure> {
    let (route, owner) = (Arc::clone(route), scope.clone());
    let (summary, branch) = (summary.to_owned(), branch.map(str::to_owned));
    admitted(scope, move |effect| {
        route.propose_reviewed(effect, &owner, summary.clone(), branch.clone())
    })
}

fn request_review(
    route: &Arc<DaemonCodingRoute>,
    scope: &Scope,
    reviewer: &str,
) -> Result<serde_json::Value, String> {
    let (route, owner, reviewer) = (Arc::clone(route), scope.clone(), reviewer.to_owned());
    admitted(scope, move |effect| {
        route.request_review(effect, &owner, reviewer.clone())
    })
}

fn merge_current(
    route: &Arc<DaemonCodingRoute>,
    scope: &Scope,
    branch: &str,
) -> Result<serde_json::Value, ProposalFailure> {
    let root = &route.projects["surtr"];
    let origin = git(root, &["remote", "get-url", "--push", "origin"]);
    let base = git(std::path::Path::new(&origin), &["rev-parse", "main"]);
    let head = git(root, &["rev-parse", branch]);
    merge(route, scope, branch, &base, &head)
}

#[test]
fn work_is_handed_back_as_the_session_branch() {
    let (_dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("engine.py"), "print('thrust')\n").unwrap();
    let handed = propose(&route, &scope, "first engine sketch", None).unwrap();
    assert_eq!(handed["changed"], true);
    assert_eq!(
        handed["branch"],
        "seat/gungnir/0e0c5a8e-1111-4222-8333-444455556666"
    );
    assert_eq!(handed["files"][0], "engine.py");
    let branch = git(
        &root,
        &[
            "show",
            "seat/gungnir/0e0c5a8e-1111-4222-8333-444455556666:engine.py",
        ],
    );
    assert_eq!(branch, "print('thrust')");
    assert!(git(&root, &["ls-tree", "--name-only", "main"])
        .lines()
        .all(|file| file != "engine.py"));
    let again = propose(&route, &scope, "nothing new", None).unwrap();
    assert_eq!(again["changed"], false);
}

#[test]
fn a_hand_back_may_name_its_exact_branch() {
    let (_dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("engine.py"), "print('thrust')\n").unwrap();
    let named = Some("seat/acceptance/a1t4188a");
    let handed = propose(&route, &scope, "first engine sketch", named).unwrap();
    assert_eq!(handed["changed"], true);
    assert_eq!(handed["branch"], "seat/acceptance/a1t4188a");
    assert_eq!(
        git(&root, &["show", "seat/acceptance/a1t4188a:engine.py"]),
        "print('thrust')"
    );
    assert!(
        !git(
            &root,
            &["for-each-ref", "--format=%(refname:short)", "refs/heads"],
        )
        .lines()
        .any(|name| name == "seat/gungnir/0e0c5a8e-1111-4222-8333-444455556666"),
        "the session branch was never published"
    );
    assert!(git(&root, &["ls-tree", "--name-only", "main"])
        .lines()
        .all(|file| file != "engine.py"));
    // Nothing new to commit: the named branch is offered again, unchanged.
    let again = propose(&route, &scope, "nothing new", named).unwrap();
    assert_eq!(again["changed"], false);
}

#[test]
fn two_active_tasks_cannot_claim_one_branch_even_when_the_second_is_a_fast_forward() {
    let (_dir, mut route, first, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &first, &root);
    let route = Arc::new(route);
    let second = Scope {
        session: Some("0e0c5a8e-2222-4222-8333-444455556666".parse().unwrap()),
        ..first.clone()
    };
    scoped_test_fixture::open(&route, &second, &root);
    let first_capsule = route.capsule(&first).unwrap().path;
    let second_capsule = route.capsule(&second).unwrap().path;
    let main = git(&root, &["rev-parse", "main"]);
    let shared = "seat/acceptance/shared-work";
    std::fs::write(first_capsule.join("first.txt"), "first task\n").unwrap();
    let published = propose(&route, &first, "first", Some(shared)).unwrap();
    let first_commit = published["commit"].as_str().unwrap();
    git(
        &second_capsule,
        &["fetch", "--quiet", root.to_str().unwrap(), shared],
    );
    git(
        &second_capsule,
        &["checkout", "--quiet", "--detach", first_commit],
    );
    std::fs::write(second_capsule.join("second.txt"), "second task\n").unwrap();
    let refused = propose(&route, &second, "second", Some(shared));
    assert!(
        refused.is_err(),
        "a live task owns the ref even when Git would permit the update: {refused:?}"
    );
    assert_eq!(git(&root, &["rev-parse", shared]), first_commit);
    assert_eq!(git(&second_capsule, &["rev-parse", "HEAD"]), first_commit);
    assert_eq!(
        std::fs::read_to_string(second_capsule.join("second.txt")).unwrap(),
        "second task\n"
    );
    let disjoint = propose(
        &route,
        &second,
        "second",
        Some("seat/acceptance/second-work"),
    )
    .unwrap();
    assert_eq!(
        git(&root, &["show", "seat/acceptance/second-work:second.txt"]),
        "second task"
    );
    assert_eq!(git(&root, &["rev-parse", shared]), first_commit);
    assert_ne!(disjoint["commit"], first_commit);
    assert_eq!(git(&root, &["rev-parse", "main"]), main);
}

/// A named hand-back is one seat branch — never a protected or foreign
/// ref, and never a name that already holds different work.
#[test]
fn a_named_hand_back_is_refused_for_unsafe_or_taken_names() {
    let (_dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("engine.py"), "print('thrust')\n").unwrap();
    for unsafe_name in [
        "main",
        "refs/heads/main",
        "seat/main",
        "seat/acceptance/x/y",
        "seat/Acceptance/x",
        "seat/acceptance/x_y",
    ] {
        propose(&route, &scope, "x", Some(unsafe_name)).unwrap_err();
    }
    assert_eq!(
        git(
            &root,
            &["for-each-ref", "--format=%(refname:short)", "refs/heads"]
        ),
        "main",
        "no branch was created for a refused name"
    );
    // A name that already holds diverged work is never overwritten.
    git(
        &root,
        &["checkout", "--quiet", "-b", "seat/acceptance/a1t4188a"],
    );
    std::fs::write(root.join("other.py"), "other = 1\n").unwrap();
    commit_all(&root, "other work");
    git(&root, &["checkout", "--quiet", "main"]);
    propose(&route, &scope, "engine", Some("seat/acceptance/a1t4188a")).unwrap_err();
    assert_eq!(
        git(&root, &["show", "seat/acceptance/a1t4188a:other.py"]),
        "other = 1",
        "the taken branch keeps its own work"
    );
    // The refusal happened before anything was committed, so choosing a
    // new name publishes the same pending work on the first try.
    let offered = propose(&route, &scope, "engine", Some("seat/acceptance/a1t4188b")).unwrap();
    assert_eq!(offered["changed"], true, "{offered}");
    assert_eq!(offered["branch"], "seat/acceptance/a1t4188b");
    assert_eq!(
        git(&root, &["show", "seat/acceptance/a1t4188b:engine.py"]),
        "print('thrust')"
    );
}

#[test]
fn a_reviewed_hand_back_may_name_its_exact_branch() {
    let (dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let origin = dir.path().join("origin.git");
    git(
        dir.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            root.to_str().unwrap(),
            origin.to_str().unwrap(),
        ],
    );
    git(
        &root,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&root, &["fetch", "--quiet", "origin"]);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("thruster.py"), "thrust = 42\n").unwrap();
    tested(&route, &scope);
    let requested = request_review(&route, &scope, "forseti").unwrap();
    let forseti = Scope {
        seat: Some("forseti".parse().unwrap()),
        ..scope.clone()
    };
    route
        .record_verdict(
            &forseti,
            requested["diffDigest"].as_str().unwrap().to_owned(),
            true,
            "ship it".to_owned(),
        )
        .unwrap();
    propose_reviewed(&route, &scope, "thruster", Some("main")).unwrap_err();
    let named = Some("seat/acceptance/a1t4188a");
    let proposed = propose_reviewed(&route, &scope, "thruster", named).unwrap();
    assert_eq!(proposed["branch"], "seat/acceptance/a1t4188a", "{proposed}");
    assert_eq!(proposed["review"]["reviewer"], "forseti", "{proposed}");
    // The approving review follows the change onto the named branch: the
    // merge gate accepts exactly that name at the reviewed commit.
    let merged = merge_current(&route, &scope, "seat/acceptance/a1t4188a").unwrap();
    assert_eq!(merged["rootFastForwarded"], true);
    assert_eq!(
        git(&root, &["rev-parse", "HEAD"]),
        merged["mergeCommit"].as_str().unwrap()
    );
    assert_eq!(git(&origin, &["show", "main:thruster.py"]), "thrust = 42");
    assert_eq!(
        git(&origin, &["rev-parse", "main"]),
        merged["mergeCommit"].as_str().unwrap()
    );
}

/// Rollover must transfer approval explicitly; matching bytes alone do not authorize a successor.
#[test]
fn a_successor_session_offers_and_merges_the_approved_work() {
    let (dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let origin = dir.path().join("origin.git");
    git(
        dir.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            root.to_str().unwrap(),
            origin.to_str().unwrap(),
        ],
    );
    git(
        &root,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&root, &["fetch", "--quiet", "origin"]);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("thruster.py"), "thrust = 42\n").unwrap();
    tested(&route, &scope);
    let requested = request_review(&route, &scope, "forseti").unwrap();
    let forseti = Scope {
        seat: Some("forseti".parse().unwrap()),
        ..scope.clone()
    };
    route
        .record_verdict(
            &forseti,
            requested["diffDigest"].as_str().unwrap().to_owned(),
            true,
            "ship it".to_owned(),
        )
        .unwrap();
    let predecessor = propose_reviewed(&route, &scope, "thruster", None).unwrap();
    assert_eq!(
        predecessor["branch"],
        "seat/gungnir/0e0c5a8e-1111-4222-8333-444455556666"
    );

    // Another registered session of the same seat: a fresh capsule at the
    // same base holding the exact approved change.
    let session_at = |id: &str| {
        let session: odin_domain::SessionId = id.parse().unwrap();
        let capsule = dir
            .path()
            .join("state")
            .join("session-authorities")
            .join(format!("capsule-capsule-{session}"))
            .join("capsule");
        std::fs::create_dir_all(&capsule).unwrap();
        git(
            &capsule,
            &["clone", "--quiet", root.to_str().unwrap(), "project"],
        );
        std::fs::write(capsule.join("project/thruster.py"), "thrust = 42\n").unwrap();
        let scope = Scope {
            session: Some(session),
            ..scope.clone()
        };
        scoped_test_fixture::open(&route, &scope, &root);
        scope
    };
    let unrelated = session_at("5a1e5a1e-8888-4222-8333-444455556666");
    propose_reviewed(&route, &unrelated, "the same bytes", None).unwrap_err();
    let successor_scope = session_at("7f3d9c2a-8888-4222-8333-444455556666");
    route
        .carry_review_evidence(
            scope.session.as_ref().unwrap(),
            successor_scope.session.as_ref().unwrap(),
        )
        .unwrap();
    let successor =
        propose_reviewed(&route, &successor_scope, "the reviewed thruster", None).unwrap();
    assert!(propose_reviewed(&route, &unrelated, "still not carried", None).is_err());
    assert_eq!(
        successor["branch"], "seat/gungnir/7f3d9c2a-8888-4222-8333-444455556666",
        "{successor}"
    );
    assert_eq!(successor["review"]["reviewer"], "forseti", "{successor}");

    // The re-offer moved the record: the successor's branch merges, the
    // predecessor's no longer matches its head.
    let refused = merge_current(&route, &scope, SESSION_BRANCH).unwrap_err();
    assert!(matches!(refused, ProposalFailure::Refused(_)));
    let successor_branch = "seat/gungnir/7f3d9c2a-8888-4222-8333-444455556666";
    let merged = merge_current(&route, &scope, successor_branch)
        .expect("the successor's branch carries the approving review");
    assert_eq!(git(&origin, &["show", "main:thruster.py"]), "thrust = 42");
    assert_eq!(
        git(&origin, &["rev-parse", "main"]),
        merged["mergeCommit"].as_str().unwrap()
    );
}

/// A named hand-back whose remote publish fails (the remote already holds
/// a diverged branch of the same name) commits and lands in the project
/// repository, and the approval is not stranded: re-offering the committed
/// head under a new name rebinds the review and publishes it.
#[test]
fn a_failed_remote_publish_does_not_strand_the_approval() {
    let (dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let origin = dir.path().join("origin.git");
    git(
        dir.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            root.to_str().unwrap(),
            origin.to_str().unwrap(),
        ],
    );
    git(
        &root,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&root, &["fetch", "--quiet", "origin"]);
    // The remote already holds diverged work under the exact name.
    git(
        &root,
        &["checkout", "--quiet", "-b", "seat/acceptance/a1t4188a"],
    );
    std::fs::write(root.join("other.py"), "other = 1\n").unwrap();
    commit_all(&root, "other work");
    git(
        &root,
        &["push", "--quiet", "origin", "seat/acceptance/a1t4188a"],
    );
    git(&root, &["checkout", "--quiet", "main"]);
    git(&root, &["branch", "-D", "seat/acceptance/a1t4188a"]);

    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("thruster.py"), "thrust = 42\n").unwrap();
    tested(&route, &scope);
    let requested = request_review(&route, &scope, "forseti").unwrap();
    let forseti = Scope {
        seat: Some("forseti".parse().unwrap()),
        ..scope.clone()
    };
    route
        .record_verdict(
            &forseti,
            requested["diffDigest"].as_str().unwrap().to_owned(),
            true,
            "ship it".to_owned(),
        )
        .unwrap();
    let named = Some("seat/acceptance/a1t4188a");
    let landed = propose_reviewed(&route, &scope, "thruster", named).unwrap();
    assert_eq!(landed["branch"], "seat/acceptance/a1t4188a", "{landed}");
    assert_eq!(
        landed["remote"]["pushed"], false,
        "the diverged remote branch rejects the publish"
    );
    assert_eq!(
        git(&root, &["show", "seat/acceptance/a1t4188a:thruster.py"]),
        "thrust = 42",
        "the work is safe in the project repository"
    );

    // Nothing new to commit: a new exact name re-offers the approved head,
    // rebinds the review and publishes it to the remote.
    let renamed = Some("seat/acceptance/a1t4188b");
    let retry = propose_reviewed(&route, &scope, "thruster", renamed).unwrap();
    assert_eq!(retry["branch"], "seat/acceptance/a1t4188b", "{retry}");
    assert_eq!(retry["changed"], false, "{retry}");
    assert_eq!(retry["remote"]["pushed"], true, "{retry}");
    let merged = merge_current(&route, &scope, "seat/acceptance/a1t4188b")
        .expect("the rebinding makes the approval deliverable");
    assert_eq!(git(&origin, &["show", "main:thruster.py"]), "thrust = 42");
    assert_eq!(
        git(&origin, &["rev-parse", "main"]),
        merged["mergeCommit"].as_str().unwrap()
    );
}

/// A rename the guard refuses (the new name already holds diverged work)
/// leaves the approving record bound to the old name — the rejected
/// rename never breaks the merge path the approval already had.
#[test]
fn a_rejected_rename_keeps_the_old_name_mergeable() {
    let (dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let origin = dir.path().join("origin.git");
    git(
        dir.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            root.to_str().unwrap(),
            origin.to_str().unwrap(),
        ],
    );
    git(
        &root,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&root, &["fetch", "--quiet", "origin"]);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("thruster.py"), "thrust = 42\n").unwrap();
    tested(&route, &scope);
    let requested = request_review(&route, &scope, "forseti").unwrap();
    let forseti = Scope {
        seat: Some("forseti".parse().unwrap()),
        ..scope.clone()
    };
    route
        .record_verdict(
            &forseti,
            requested["diffDigest"].as_str().unwrap().to_owned(),
            true,
            "ship it".to_owned(),
        )
        .unwrap();
    let named = Some("seat/acceptance/a1t4188a");
    let landed = propose_reviewed(&route, &scope, "thruster", named).unwrap();
    assert_eq!(landed["branch"], "seat/acceptance/a1t4188a", "{landed}");

    // The rename target already holds diverged work.
    git(
        &root,
        &["checkout", "--quiet", "-b", "seat/acceptance/a1t4188b"],
    );
    std::fs::write(root.join("other.py"), "other = 1\n").unwrap();
    commit_all(&root, "other work");
    git(&root, &["checkout", "--quiet", "main"]);
    propose_reviewed(&route, &scope, "thruster", Some("seat/acceptance/a1t4188b")).unwrap_err();

    // The record still vouches for the name the approval actually landed
    // on: the old branch merges exactly as before the refused rename.
    let merged = merge_current(&route, &scope, "seat/acceptance/a1t4188a")
        .expect("the rejected rename leaves the old binding mergeable");
    assert_eq!(git(&origin, &["show", "main:thruster.py"]), "thrust = 42");
    assert_eq!(
        git(&origin, &["rev-parse", "main"]),
        merged["mergeCommit"].as_str().unwrap()
    );
}

#[test]
fn flake_output_names_are_plain() {
    assert!(valid_attr("packages.x86_64-linux.default"));
    for bad in ["", "../etc", "a b", "x;rm", "--option", "#x"] {
        assert!(!valid_attr(bad), "{bad}");
    }
}

/// A scoped run reads only the capsule's own files: plain relative paths
/// only — no traversal, no absolute root, no control bytes, no component
/// that could read as a pytest option.
#[test]
fn scoped_test_paths_stay_inside_the_capsule() {
    for good in ["test_x.py", "tools/test_engine.py", "deep/dir/test_a.py"] {
        assert!(valid_test_path(good), "{good}");
    }
    for bad in [
        "",
        "/etc/passwd",
        "../outside.py",
        "a/../b.py",
        "a//b.py",
        "trailing/",
        "./x.py",
        "a b.py",
        "a\nb.py",
        "a\x01b.py",
        "-p",
        "-weird.py",
        "--co",
        "--ignore=tests/test_real.py",
        "tools/-dash.py",
    ] {
        assert!(!valid_test_path(bad), "{bad:?}");
    }
    assert!(!valid_test_path(&"x".repeat(201)));
}

/// The actual scoped route must run only the selected file, return its
/// pytest summary, and keep test code away from other tasks and daemon state.
#[test]
fn scoped_test_execution_cannot_write_another_task_or_daemon_state() {
    let (_dir, mut route, scope, root) = session_capsule();
    let capsule = route.capsule(&scope).unwrap().path;
    let other = route.state_root.join("other-task/project");
    std::fs::create_dir_all(&other).unwrap();
    let sentinels = [
        other.join("owned.txt"),
        route.state_root.join("daemon-owned.txt"),
    ];
    for sentinel in &sentinels {
        std::fs::write(sentinel, "unchanged\n").unwrap();
    }
    pin_nixpkgs(&capsule);
    std::fs::write(
        capsule.join("flake.nix"),
        r#"{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { nixpkgs, ... }: {
    devShells.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.mkShell {
      packages = [ nixpkgs.legacyPackages.x86_64-linux.python3Packages.pytest ];
      shellHook = "test \"$HOME\" = /tmp || exit 8; if [ -e .hook-ran ]; then exit 9; fi; printf once > .hook-ran || exit 7";
    };
  };
}
"#,
    )
    .unwrap();
    std::fs::write(
        capsule.join("test_selected.py"),
        format!(
            "from pathlib import Path\n\ndef test_selected():\n    assert Path('.hook-ran').read_text() == 'once'\n    for name in {}:\n        try:\n            Path(name).write_text('test work escaped\\n')\n        except OSError:\n            pass\n",
            serde_json::to_string(&sentinels).unwrap()
        ),
    )
    .unwrap();
    std::fs::write(
        capsule.join("test_unselected.py"),
        "def test_must_not_run():\n    assert False\n",
    )
    .unwrap();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = std::sync::Arc::new(route);
    let selected = TestSelection::Paths(vec!["test_selected.py".into()]);
    let report = scoped_test_fixture::dispatch(
        std::sync::Arc::clone(&route),
        scope.clone(),
        selected.clone(),
        None,
    )
    .unwrap();
    assert_eq!(report["ok"], true, "{report}");
    assert_eq!(report["passed"], 1, "{report}");
    assert_eq!(report["failed"], 0, "{report}");
    for sentinel in &sentinels {
        assert_eq!(
            std::fs::read_to_string(sentinel).unwrap(),
            "unchanged\n",
            "scoped test modified {}",
            sentinel.display()
        );
    }
    for paths in [vec!["../surtr-everything.py".into()], Vec::new()] {
        assert!(scoped_test_fixture::dispatch(
            std::sync::Arc::clone(&route),
            scope.clone(),
            TestSelection::Paths(paths),
            None,
        )
        .is_err());
    }
    std::fs::write(capsule.join("test_output.py"),
        "import os\ndef test_output():\n    for _ in range(1100):\n        os.write(1, b'x' * 8192)\n    assert False\n").unwrap();
    assert!(scoped_test_fixture::dispatch(
        std::sync::Arc::clone(&route),
        scope.clone(),
        TestSelection::Paths(vec!["test_output.py".into()]),
        None
    )
    .is_err());
    // An independently sessioned descendant must be gone before either a
    // completed test or a cancelled operation reports completion.
    for mode in ["complete", "cancel", "retire"] {
        let marker = format!("odin-c1-child-{}-{mode}", uuid::Uuid::new_v4());
        std::fs::write(capsule.join("test_child.py"), format!(
            "import subprocess, sys, time\ndef test_child():\n    subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(90)', {marker:?}], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n    time.sleep({})\n", if mode == "complete" { 1 } else { 90 }
        )).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let owned_route = std::sync::Arc::clone(&route);
        let owned_scope = scope.clone();
        let run = std::thread::spawn(move || {
            scoped_test_fixture::dispatch(
                owned_route,
                owned_scope,
                TestSelection::Paths(vec!["test_child.py".into()]),
                Some(sender),
            )
        });
        let stop = receiver
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let child = loop {
            let found = std::fs::read_dir("/proc")
                .unwrap()
                .filter_map(Result::ok)
                .find_map(|entry| {
                    let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
                    let command = std::fs::read(entry.path().join("cmdline")).ok()?;
                    command
                        .split(|byte| *byte == 0)
                        .any(|argument| argument == marker.as_bytes())
                        .then_some(pid)
                });
            if let Some(pid) = found {
                break pid;
            }
            assert!(
                !run.is_finished(),
                "test finished before its descendant started"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "descendant did not start"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            stop.registered_process().is_some(),
            "the genuine permit owns its running worker"
        );
        if mode == "cancel" {
            stop.cancel();
        }
        if mode == "retire" {
            let capsule_id = odin_omp::host_tools::operations::session_capsule_id(
                scope.session.as_ref().unwrap(),
            )
            .unwrap();
            // Daemon shutdown closes fresh authority admission before the
            // parent bridge retires its already-owned scoped test children.
            route.session_pool.as_ref().unwrap().close();
            assert!(route
                .session_pool
                .as_ref()
                .unwrap()
                .retire_session(&capsule_id)
                .unwrap());
        }
        let result = run.join().unwrap();
        if mode == "complete" {
            assert_eq!(result.unwrap()["ok"], true);
        } else {
            assert!(
                result.is_err(),
                "cancelled or retired work reported success"
            );
        }
        let stat = std::fs::read_to_string(format!("/proc/{child}/stat"));
        assert!(
            stat.is_err()
                || stat
                    .unwrap()
                    .rsplit(')')
                    .next()
                    .unwrap()
                    .trim_start()
                    .starts_with('Z'),
            "task descendant survived completion"
        );
    }
    assert!(scoped_test_fixture::dispatch(route, scope, selected, None).is_err());
}

/// The repository's own pinned nixpkgs as a capsule flake's only locked
/// input.
fn pin_nixpkgs(capsule: &std::path::Path) {
    let lock: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../flake.lock"
    )))
    .unwrap();
    std::fs::write(
        capsule.join("flake.lock"),
        serde_json::to_vec(&serde_json::json!({
            "nodes": {
                "root": {"inputs": {"nixpkgs": "nixpkgs"}},
                "nixpkgs": lock["nodes"]["nixpkgs"],
            },
            "root": "root",
            "version": 7,
        }))
        .unwrap(),
    )
    .unwrap();
}

/// Live (non-zombie) processes with an argument containing `needle`.
fn live_processes_naming(needle: &str) -> Vec<u32> {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
            let command = std::fs::read(entry.path().join("cmdline")).ok()?;
            let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            let zombie = stat.rsplit(')').next()?.trim_start().starts_with('Z');
            let named = command
                .split(|byte| *byte == 0)
                .any(|argument| String::from_utf8_lossy(argument).contains(needle));
            (named && !zombie).then_some(pid)
        })
        .collect()
}

/// Cancellation must join the build before returning and must not publish a test report.
#[test]
fn a_cancelled_attr_test_run_stops_its_nix_and_records_no_report() {
    let (_dir, mut route, scope, root) = session_capsule();
    let capsule = route.capsule(&scope).unwrap().path;
    pin_nixpkgs(&capsule);
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    // Every Nix process of a run names the frozen snapshot of exactly this
    // registered capsule.
    let registered = route
        .session_pool
        .as_ref()
        .unwrap()
        .registered_code_capsule(scope.session.as_ref().unwrap())
        .unwrap()
        .unwrap()
        .capsule_project
        .display()
        .to_string();
    let route = std::sync::Arc::new(route);
    for mode in ["cancel", "retire"] {
        // Join even a failing-before raw Nix run before fixture state is removed.
        std::thread::scope(|threads| {
            // A fresh derivation per mode, so no run is ever a cached output.
            let marker = format!("odin-t6-attr-{}-{mode}", uuid::Uuid::new_v4().simple());
            std::fs::write(
            capsule.join("flake.nix"),
            format!(
                r#"{{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = {{ nixpkgs, ... }}: {{
    checks.x86_64-linux.slow = derivation {{
      name = "odin-t6-slow";
      system = "x86_64-linux";
      builder = "/bin/sh";
      args = [ "-c" "${{nixpkgs.legacyPackages.x86_64-linux.coreutils}}/bin/sleep 90; echo {marker} > $out" ];
    }};
  }};
}}
"#
            ),
        )
        .unwrap();
            let (sender, receiver) = std::sync::mpsc::channel();
            let run = {
                let (route, scope) = (std::sync::Arc::clone(&route), scope.clone());
                let selection = TestSelection::Attr(Some("checks.x86_64-linux.slow".to_owned()));
                threads.spawn(move || {
                    scoped_test_fixture::dispatch(route, scope, selection, Some(sender))
                })
            };
            let stop = receiver
                .recv_timeout(std::time::Duration::from_secs(30))
                .unwrap();
            // The sandboxed builder runs: the run is past evaluation.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            while live_processes_naming(&marker).is_empty() {
                assert!(
                    !run.is_finished(),
                    "the attr run finished before its build started"
                );
                assert!(
                    std::time::Instant::now() < deadline,
                    "the attr build did not start"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(
                !live_processes_naming(&registered).is_empty(),
                "the run's own Nix names its frozen snapshot"
            );
            assert!(
                stop.registered_process().is_some(),
                "the genuine permit owns its running Nix worker"
            );
            if mode == "cancel" {
                stop.cancel();
            } else {
                let capsule_id = odin_omp::host_tools::operations::session_capsule_id(
                    scope.session.as_ref().unwrap(),
                )
                .unwrap();
                // Daemon shutdown closes fresh admission, then the parent bridge
                // retires the session's already-owned children.
                route.session_pool.as_ref().unwrap().close();
                assert!(route
                    .session_pool
                    .as_ref()
                    .unwrap()
                    .retire_session(&capsule_id)
                    .unwrap());
            }
            // The stop answers long before the build's own 90 seconds end.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !run.is_finished() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the {mode} left the attr run's Nix running"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(
                run.join().unwrap().is_err(),
                "cancelled or retired work reported success"
            );
            assert_eq!(
                live_processes_naming(&registered),
                Vec::<u32>::new(),
                "the run's Nix outlived its proven stop"
            );
            // The build itself is the Nix daemon's; it abandons the build once
            // the run's own client is gone.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !live_processes_naming(&marker).is_empty() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the build of the {mode} run kept running"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
    }
    let runs = route.state_root.join("reviews").join("runs");
    let mut records = Vec::new();
    for entry in std::fs::read_dir(runs).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|kind| kind == "json") {
            let bytes = std::fs::read(path).unwrap();
            let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            records.push(record);
        }
    }
    assert_eq!(records.len(), 2, "{records:?}");
    for record in &records {
        assert!(
            record.get("outcome").is_none(),
            "an unfinished run recorded a report: {record}"
        );
    }
}

#[test]
fn an_unproved_worker_stop_does_not_detach_output_readers() {
    use odin_cli::live_authority::{OwnedProgram, OwnedStep};
    use std::time::{Duration, Instant};

    let (_dir, mut route, scope, root) = session_capsule();
    let (_config, worker) = scoped_test_fixture::compose_with_worker(
        &mut route,
        &scope,
        &root,
        odin_process::test_support::RegisteredWorkerFixture::new().unwrap(),
    );
    let pool = Arc::clone(route.session_pool.as_ref().unwrap());
    let capsule = route.capsule(&scope).unwrap().path;
    let capsule_id =
        odin_omp::host_tools::operations::session_capsule_id(scope.session.as_ref().unwrap())
            .unwrap();
    let store = route
        .state_root
        .join("session-authorities")
        .join(format!("capsule-{}", capsule_id.as_str().replace(':', "-")))
        .join("scoped-tests/worker-authority/ledger.sqlite3");
    let ready = capsule.join("owned-reader-ready");
    let args = vec![
        "-c".to_owned(),
        format!(
            "alias.reader-probe=!echo ready > owned-reader-ready; exec {} 90",
            scoped_test_fixture::find("sleep").display()
        ),
        "reader-probe".to_owned(),
    ];
    let observed = std::thread::scope(|threads| {
        let run_pool = Arc::clone(&pool);
        let owner = scope.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let run = threads.spawn(move || {
            scoped_test_fixture::dispatch_with(
                scope.clone(),
                serde_json::json!({}),
                Some(send),
                move |effect| {
                    run_pool.run_owned_step(
                        effect,
                        &owner,
                        OwnedStep {
                            program: OwnedProgram::Git,
                            args: args.clone(),
                            environment: Vec::new(),
                            current_dir: &capsule,
                            capture: Default::default(),
                        },
                        Instant::now() + Duration::from_secs(120),
                    )
                },
            )
        });
        // Always restore the private manager and prove retirement before
        // asserting, including when an observation itself panics.
        let observation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let stop = receive.recv_timeout(Duration::from_secs(30)).unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !ready.exists() {
                assert!(
                    !run.is_finished(),
                    "the worker did not reach its ready marker"
                );
                assert!(Instant::now() < deadline, "the worker did not start");
                std::thread::sleep(Duration::from_millis(10));
            }
            let ledger = odin_ledger::Ledger::open(&store).unwrap();
            let rows = odin_ledger::worker::nonterminal_rows(ledger.connection(), None).unwrap();
            assert_eq!(rows.len(), 1);
            let pid = rows[0].leader_pid.unwrap();
            let pipe = std::fs::read_link(format!("/proc/{pid}/fd/1")).unwrap();
            assert!(pipe.to_string_lossy().starts_with("pipe:["));
            let holds_pipe = || {
                std::fs::read_dir("/proc/self/fd").unwrap().any(|entry| {
                    match std::fs::read_link(entry.unwrap().path()) {
                        Ok(target) => target == pipe,
                        Err(error) => {
                            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
                            false
                        }
                    }
                })
            };
            assert!(holds_pipe(), "the run must own the actual worker output");
            worker.refuse_queries(true);
            stop.cancel();
            let deadline = Instant::now() + Duration::from_secs(15);
            while !run.is_finished() {
                assert!(Instant::now() < deadline, "unproved stop did not return");
                std::thread::sleep(Duration::from_millis(10));
            }
            let result = run.join().unwrap();
            (result, holds_pipe())
        }));
        worker.refuse_queries(false);
        let retired = pool.retire_session(&capsule_id);
        let observation = observation.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        assert_eq!(
            retired,
            Ok(true),
            "the exact retained worker must finally retire"
        );
        observation
    });
    assert!(observed.0.is_err(), "an unproved stop is not success");
    assert!(
        !observed.1,
        "the returned operation detached a blocking output reader"
    );
}

const SESSION_BRANCH: &str = "seat/gungnir/0e0c5a8e-1111-4222-8333-444455556666";

/// The project's origin behind Git's `ext::` transport and a server script,
/// so a merge's fetch (`fetch.armed`, after its `ls-remote`) or an armed
/// origin hook stalls at an exact step. Returns the origin and the stall
/// directory, where the stalled process writes `stall.pid`, then `stalled`,
/// and each hook logs every receive in `<hook>.log`.
fn stallable_origin(dir: &std::path::Path, root: &std::path::Path) -> [std::path::PathBuf; 2] {
    use std::os::unix::fs::PermissionsExt;
    let origin = dir.join("origin.git");
    let (root_text, origin_text) = (root.to_str().unwrap(), origin.to_str().unwrap());
    git(dir, &["clone", "-q", "--bare", root_text, origin_text]);
    let stall = dir.join("stall");
    std::fs::create_dir(&stall).unwrap();
    let (s, git_path) = (stall.display(), scoped_test_fixture::find("git"));
    let sleep = scoped_test_fixture::find("sleep");
    let server = dir.join("git-server");
    std::fs::write(
        &server,
        format!(
            "#!/bin/sh\nunset GIT_CONFIG_PARAMETERS\nexport GIT_CONFIG_COUNT=0\n\
             if [ \"$1\" = upload-pack ] && [ -e {s}/fetch.armed ]; then\n\
             if [ -s {s}/fetch.armed ]; then : > {s}/fetch.armed; else rm {s}/fetch.armed; \
             echo $$ > {s}/stall.pid; : > {s}/stalled; {} 45; fi\nfi\n\
             exec {} \"$1\" \"$2\"\n",
            sleep.display(),
            git_path.display()
        ),
    )
    .unwrap();
    for hook in ["pre-receive", "post-receive"] {
        let path = origin.join("hooks").join(hook);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\necho received >> {s}/{hook}.log\n\
                 [ -e {s}/{hook}.armed ] || exit 0\nrm {s}/{hook}.armed\n\
                 echo $$ > {s}/stall.pid; : > {s}/stalled; exec {} 45\n",
                sleep.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::set_permissions(&server, std::fs::Permissions::from_mode(0o700)).unwrap();
    git(root, &["config", "protocol.ext.allow", "always"]);
    let escape = |path: &str| path.replace('%', "%%").replace(' ', "% ");
    let server_text = escape(server.to_str().unwrap());
    let url = format!("ext::{server_text} %s {}", escape(origin_text));
    git(root, &["remote", "add", "origin", &url]);
    [origin, stall]
}

/// The session's current change tested, approved by another seat and
/// offered on its session branch: (origin main, offered head).
fn reviewed_offer(
    route: &Arc<DaemonCodingRoute>,
    scope: &Scope,
    origin: &std::path::Path,
) -> (String, String) {
    tested(route, scope);
    let requested = request_review(route, scope, "forseti").unwrap();
    let forseti = Scope {
        seat: Some("forseti".parse().unwrap()),
        ..scope.clone()
    };
    let digest = requested["diffDigest"].as_str().unwrap().to_owned();
    route
        .record_verdict(&forseti, digest, true, "ship it".to_owned())
        .unwrap();
    let offered = propose_reviewed(route, scope, "reviewed", None).unwrap();
    assert_eq!(offered["remote"]["pushed"], true, "{offered}");
    let head = offered["commit"].as_str().unwrap().to_owned();
    (git(origin, &["rev-parse", "main"]), head)
}

#[test]
fn a_published_merge_with_unproved_cleanup_never_reports_complete() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let [origin, _stall] = stallable_origin(dir.path(), &root);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(
        capsule.join("flake.nix"),
        "{ outputs = _: { checks.x86_64-linux.smoke = derivation { \
         name = \"odin-cleanup-smoke\"; system = \"x86_64-linux\"; \
         builder = \"/bin/sh\"; args = [ \"-c\" \"echo ok > $out\" ]; }; }; }",
    )
    .unwrap();
    let route = Arc::new(route);
    let (start, head) = reviewed_offer(&route, &scope, &origin);
    let foreign = dir.path().join("foreign");
    std::fs::create_dir(&foreign).unwrap();
    std::fs::write(foreign.join("keep"), b"owner work").unwrap();
    let hook = origin.join("hooks/post-receive");
    std::fs::write(
        &hook,
        format!(
            "#!{}\nfrom pathlib import Path\n\
             for marker in Path({}).glob('*/gitdir'):\n    marker.write_text({})\n",
            scoped_test_fixture::find("python3").display(),
            serde_json::to_string(&root.join(".git/worktrees")).unwrap(),
            serde_json::to_string(&foreign.join(".git").display().to_string()).unwrap(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
    let outcome = merge(&route, &scope, SESSION_BRANCH, &start, &head);
    assert!(
        matches!(outcome, Err(ProposalFailure::Uncertain(_))),
        "{outcome:?}"
    );
    assert_eq!(git(&origin, &["merge-base", "main", &head]), head);
    assert_ne!(git(&origin, &["rev-parse", "main"]), start);
    assert_eq!(std::fs::read(foreign.join("keep")).unwrap(), b"owner work");
    let retained: Vec<_> = std::fs::read_dir(route.state_root.join("merge-worktrees"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(retained.len(), 1);
    assert!(
        retained[0].join(".git").is_file(),
        "unproved custody keeps its evidence"
    );
}

/// Runs `work` under a real permit of `scope`'s session and cancels that
/// permit once `stalled` holds. Work that ignores its cancellation fails the
/// bound here and is still joined — its raw children finish their bounded
/// stall — before any fixture state is removed.
fn cancelled<V: Send + 'static, E: Send + 'static>(
    what: &str,
    scope: &Scope,
    stalled: impl Fn() -> bool,
    work: impl Fn(&PreparedEffect) -> Result<V, E> + Send + Sync + 'static,
) -> Result<V, E> {
    std::thread::scope(|threads| {
        let (sender, receiver) = std::sync::mpsc::channel();
        let arguments = serde_json::json!({});
        let run = threads.spawn(move || {
            scoped_test_fixture::dispatch_with(scope.clone(), arguments, Some(sender), work)
        });
        let stop = receiver
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while !stalled() {
            assert!(!run.is_finished(), "the {what} finished before it stalled");
            assert!(
                std::time::Instant::now() < deadline,
                "the {what} never stalled"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        stop.cancel();
        // The stall itself lasts 45 seconds.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !run.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "the cancelled {what} kept its children running"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        run.join().unwrap()
    })
}

/// One merge of the session branch, cancelled once `stalled` holds.
fn cancelled_merge(
    route: &Arc<DaemonCodingRoute>,
    scope: &Scope,
    (base, head): (&str, &str),
    stalled: impl Fn() -> bool,
) -> Result<serde_json::Value, ProposalFailure> {
    let (route, owner) = (Arc::clone(route), scope.clone());
    let (base, head) = (base.to_owned(), head.to_owned());
    cancelled("merge", scope, stalled, move |effect| {
        route.merge(effect, &owner, "surtr", SESSION_BRANCH, &base, &head)
    })
}

/// Whether the fixture process that recorded its pid in `file` is gone.
fn exited(file: &std::path::Path) -> bool {
    let pid = std::fs::read_to_string(file).unwrap();
    match std::fs::read_to_string(format!("/proc/{}/stat", pid.trim())) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit(')')
            .next()
            .unwrap()
            .trim_start()
            .starts_with('Z'),
    }
}

#[test]
fn a_cancelled_merge_fetch_or_check_stops_its_children_and_never_pushes_main() {
    let (dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let [origin, stall] = stallable_origin(dir.path(), &root);
    let capsule = route.capsule(&scope).unwrap().path;
    pin_nixpkgs(&capsule);
    let marker = format!("odin-t6-merge-check-{}", uuid::Uuid::new_v4().simple());
    std::fs::write(
        capsule.join("flake.nix"),
        format!(
            r#"{{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = {{ nixpkgs, ... }}: {{
    checks.x86_64-linux.slow = derivation {{
      name = "odin-t6-merge-check";
      system = "x86_64-linux";
      builder = "/bin/sh";
      args = [ "-c" "${{nixpkgs.legacyPackages.x86_64-linux.coreutils}}/bin/sleep 45; echo {marker} > $out" ];
    }};
  }};
}}
"#
        ),
    )
    .unwrap();
    let route = Arc::new(route);
    let (previous, head) = reviewed_offer(&route, &scope, &origin);
    // Git can skip the transport when every requested object is local.
    // Advance only the private origin so the cancelled fetch must connect.
    let tree = git(&origin, &["rev-parse", "main^{tree}"]);
    let start = git(
        &origin,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit-tree",
            &tree,
            "-p",
            &previous,
            "-m",
            "remote-only merge base",
        ],
    );
    git(
        &origin,
        &["update-ref", "refs/heads/main", &start, &previous],
    );
    let worktrees = route.state_root.join("merge-worktrees");
    let worktree_text = worktrees.display().to_string();
    // The fetch stalls in the origin's server; then a fresh attempt stalls
    // in the sandboxed check build.
    std::fs::write(stall.join("fetch.armed"), "after ls-remote").unwrap();
    let merged = cancelled_merge(&route, &scope, (&start, &head), || {
        stall.join("stalled").exists()
    });
    assert!(
        matches!(merged, Err(ProposalFailure::Refused(_))),
        "{merged:?}"
    );
    assert!(
        exited(&stall.join("stall.pid")),
        "the fetch outlived its stop"
    );
    let merged = cancelled_merge(&route, &scope, (&start, &head), || {
        !live_processes_naming(&marker).is_empty()
    });
    assert!(
        matches!(merged, Err(ProposalFailure::Refused(_))),
        "{merged:?}"
    );
    assert_eq!(
        live_processes_naming(&worktree_text),
        Vec::<u32>::new(),
        "the check's Nix outlived its stop"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !live_processes_naming(&marker).is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the Nix daemon kept the cancelled check building"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(git(&origin, &["rev-parse", "main"]), start, "main holds");
    let left = std::fs::read_dir(&worktrees).unwrap().count();
    assert_eq!(left, 0, "a cancelled merge left its worktree");
    MergeLock::acquire(
        &route.state_root,
        "surtr",
        std::time::Duration::ZERO,
        || false,
    )
    .expect("a cancelled merge released the project lock");
}

/// A lost push reply is uncertain; retries must inspect the remote before pushing again.
#[test]
fn a_merge_push_cancelled_around_remote_acceptance_stays_uncertain_and_a_retry_recovers() {
    let (dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let [origin, stall] = stallable_origin(dir.path(), &root);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("thruster.py"), "thrust = 42\n").unwrap();
    let route = Arc::new(route);
    let (start, head) = reviewed_offer(&route, &scope, &origin);
    for hook in ["pre-receive", "post-receive"] {
        std::fs::write(stall.join(format!("{hook}.armed")), "").unwrap();
        let merged = cancelled_merge(&route, &scope, (&start, &head), || {
            stall.join("stalled").exists()
        });
        assert!(
            matches!(merged, Err(ProposalFailure::Uncertain(_))),
            "a push cancelled in {hook}: {merged:?}"
        );
        assert!(
            exited(&stall.join("stall.pid")),
            "the {hook} stall outlived the stop"
        );
        let main = git(&origin, &["rev-parse", "main"]);
        let retained = git(
            &root,
            &[
                "for-each-ref",
                "--format=%(objectname)",
                "refs/odin/merge-publications",
            ],
        );
        if hook == "pre-receive" {
            assert_eq!(main, start, "a push stopped before acceptance moved main");
        } else {
            assert!(
                retained.lines().any(|commit| commit == main),
                "the accepted merge is retained: {retained}"
            );
        }
        std::fs::remove_file(stall.join("stalled")).unwrap();
    }
    let landed = git(&origin, &["rev-parse", "main"]);
    // A fresh admitted retry reads the landed merge back; it pushes nothing.
    let retried = merge(&route, &scope, SESSION_BRANCH, &start, &head).unwrap();
    assert_eq!(retried["alreadyMerged"], true, "{retried}");
    assert_eq!(retried["mergeCommit"], landed.as_str());
    assert_eq!(git(&origin, &["rev-parse", "main"]), landed);
}

#[test]
fn a_cancelled_build_or_diagnostics_run_stops_its_nix() {
    let (_dir, mut route, scope, root) = session_capsule();
    let capsule = route.capsule(&scope).unwrap().path;
    pin_nixpkgs(&capsule);
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let capsule_text = capsule.display().to_string();
    for tool in ["build", "diagnostics"] {
        // A fresh derivation per run, so neither is a cached output.
        let marker = format!("odin-t6-{tool}-{}", uuid::Uuid::new_v4().simple());
        std::fs::write(
            capsule.join("flake.nix"),
            format!(
                r#"{{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = {{ nixpkgs, ... }}: {{
    checks.x86_64-linux.slow = derivation {{
      name = "odin-t6-{tool}";
      system = "x86_64-linux";
      builder = "/bin/sh";
      args = [ "-c" "${{nixpkgs.legacyPackages.x86_64-linux.coreutils}}/bin/sleep 45; echo {marker} > $out" ];
    }};
  }};
}}
"#
            ),
        )
        .unwrap();
        let attr = Some("checks.x86_64-linux.slow".to_owned());
        let stalled = || !live_processes_naming(&marker).is_empty();
        let (running, owner) = (Arc::clone(&route), scope.clone());
        let ran = if tool == "build" {
            cancelled(tool, &scope, stalled, move |effect| {
                running.nix(effect, &owner, NixVerb::Build, attr.clone())
            })
        } else {
            cancelled(tool, &scope, stalled, move |effect| {
                running
                    .nix_log(effect, &owner, NixVerb::Build, attr.clone())
                    .map(|log| serde_json::json!({ "ok": log.ok }))
            })
        };
        assert!(ran.is_err(), "a cancelled {tool} run answered: {ran:?}");
        assert_eq!(
            live_processes_naming(&capsule_text),
            Vec::<u32>::new(),
            "the {tool} run's Nix outlived its stop"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !live_processes_naming(&marker).is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "the Nix daemon kept the cancelled {tool} building"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// Diagnostic tails retain failures and summaries when the full log exceeds the capture limit.
#[test]
fn a_diagnostics_log_over_the_capture_bound_keeps_its_final_summary() {
    let (_dir, mut route, scope, root) = session_capsule();
    let capsule = route.capsule(&scope).unwrap().path;
    let unique = uuid::Uuid::new_v4().simple().to_string();
    // A fresh derivation, so its log is printed rather than read from cache.
    std::fs::write(
        capsule.join("flake.nix"),
        format!(
            "{{ outputs = _: {{ checks.x86_64-linux.loud = derivation {{ \
             name = \"odin-f2-{unique}\"; system = \"x86_64-linux\"; \
             builder = \"/bin/sh\"; args = [ \"-c\" \
             \"i=0; while [ $i -lt 120000 ]; do echo odin-f2-padding-$i-{}; \
             i=$((i+1)); done; echo odin-f2-final-summary:3-passed; echo ok > $out\" ]; \
             }}; }}; }}\n",
            "x".repeat(80)
        ),
    )
    .unwrap();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let (running, owner) = (Arc::clone(&route), scope.clone());
    let attr = Some("checks.x86_64-linux.loud".to_owned());
    let log = admitted(&scope, move |effect| {
        running.nix_log(effect, &owner, NixVerb::Build, attr.clone())
    })
    .expect("a finite build log over the capture bound aborted the diagnostics run");
    assert!(log.ok, "the build itself succeeded");
    assert!(
        log.log.contains("odin-f2-final-summary:3-passed"),
        "the log's final summary was lost"
    );
    assert!(log.log.len() <= 8 * 1024 * 1024, "the kept log is bounded");
}

#[test]
fn frozen_attr_tests_keep_large_fresh_and_cached_diagnostic_tails() {
    let (_dir, mut route, scope, root) = session_capsule();
    let capsule = route.capsule(&scope).unwrap().path;
    let unique = uuid::Uuid::new_v4().simple().to_string();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    for (phase, attr) in [
        ("build", Some("checks.x86_64-linux.loud")),
        ("cached", Some("checks.x86_64-linux.loud")),
        ("check", None),
    ] {
        if phase != "cached" {
            // Distinct fresh builders cover both argv paths. The intervening
            // unchanged build must recover its summary from `nix log` stdout.
            std::fs::write(
                capsule.join("flake.nix"),
                format!(
                    "{{ outputs = _: {{ checks.x86_64-linux.loud = derivation {{ \
                     name = \"odin-attr-tail-{unique}-{phase}\"; system = \"x86_64-linux\"; \
                     builder = \"/bin/sh\"; args = [ \"-c\" \
                     \"i=0; while [ $i -lt 120000 ]; do echo padding-$i-{}; \
                     i=$((i+1)); done; echo '=== 3 passed in 0.01s ==='; echo ok > $out\" ]; \
                     }}; }}; }}\n",
                    "x".repeat(80)
                ),
            )
            .unwrap();
        }
        let report = scoped_test_fixture::dispatch(
            Arc::clone(&route),
            scope.clone(),
            TestSelection::Attr(attr.map(str::to_owned)),
            None,
        )
        .unwrap_or_else(|error| panic!("{phase} lost the frozen run's diagnostic tail: {error}"));
        assert_eq!(report["ok"], true, "{phase}: {report}");
        assert_eq!(report["passed"], 3, "{phase}: {report}");
        assert_eq!(report["failed"], 0, "{phase}: {report}");
        assert!(
            live_processes_naming(&capsule.display().to_string()).is_empty(),
            "{phase} left its Nix process alive"
        );
    }
}

#[test]
fn a_code_search_with_excess_output_keeps_its_requested_leading_matches() {
    use std::fmt::Write as _;

    let (_dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let capsule = route.capsule(&scope).unwrap().path;
    let symbol = format!("needle_{}", uuid::Uuid::new_v4().simple());
    let padding = "x".repeat(80);
    let mut broad = String::new();
    for line in 1..=90_000 {
        writeln!(&mut broad, "let {symbol} = {line}; // {padding}").unwrap();
    }
    std::fs::write(capsule.join("broad.rs"), broad).unwrap();
    let (running, owner) = (Arc::clone(&route), scope.clone());
    let query = symbol.clone();
    let found = admitted(&scope, move |effect| {
        running.search_code(
            effect,
            &owner,
            odin_hermes::runtime::coding::CodeQuery::References(query.clone()),
            3,
        )
    })
    .expect("later excess grep output failed a search that only wanted three matches");
    let lines: Vec<u64> = found["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["line"].as_u64().unwrap())
        .collect();
    assert_eq!(lines, [1, 2, 3]);
    assert_eq!(found["truncated"], true);
    assert_eq!(
        live_processes_naming(&symbol),
        Vec::<u32>::new(),
        "the search's git grep outlived its answer"
    );
}

/// A match longer than the byte bound still has a known file/line and a
/// useful bounded excerpt. Dropping its unterminated retained prefix would
/// incorrectly report no matches.
#[test]
fn a_code_search_with_one_oversized_line_keeps_its_match_and_reports_the_cut() {
    use std::io::Write;

    let (_dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let capsule = route.capsule(&scope).unwrap().path;
    let symbol = format!("needle_{}", uuid::Uuid::new_v4().simple());
    let mut source = std::fs::File::create(capsule.join("long.rs")).unwrap();
    write!(source, "let {symbol} = 1; // ").unwrap();
    let padding = [b'x'; 8192];
    for _ in 0..1200 {
        source.write_all(&padding).unwrap();
    }
    writeln!(source).unwrap();
    drop(source);
    let (running, owner) = (Arc::clone(&route), scope.clone());
    let found = admitted(&scope, move |effect| {
        running.search_code(
            effect,
            &owner,
            odin_hermes::runtime::coding::CodeQuery::References(symbol.clone()),
            3,
        )
    })
    .unwrap();
    let matches = found["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["file"], "long.rs");
    assert_eq!(matches[0]["line"], 1);
    assert_eq!(found["truncated"], true);
}

/// Without an explicit retention policy, oversized output must be refused rather than truncated.
#[test]
fn an_owned_step_over_the_capture_bound_is_refused_whole() {
    use odin_cli::live_authority::{OwnedProgram, OwnedStep};
    use std::time::{Duration, Instant};

    let (_dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let pool = Arc::clone(route.session_pool.as_ref().unwrap());
    let capsule = route.capsule(&scope).unwrap().path;
    let flood = vec![
        "-c".to_owned(),
        format!(
            "alias.flood=!{} -c 9437184 /dev/zero",
            scoped_test_fixture::find("head").display()
        ),
        "flood".to_owned(),
    ];
    let owner = scope.clone();
    let (flood_refused, later_ran) = admitted(&scope, move |effect| {
        let step = |args: Vec<String>| OwnedStep {
            program: OwnedProgram::Git,
            args,
            environment: Vec::new(),
            current_dir: &capsule,
            capture: Default::default(),
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        let flooded = pool.run_owned_step(effect, &owner, step(flood.clone()), deadline);
        let version = step(vec!["--version".to_owned()]);
        let later = pool.run_owned_step(effect, &owner, version, deadline);
        let later_ran = later.is_ok_and(|captured| captured.output.status.success());
        Ok::<_, String>((flooded.is_err(), later_ran))
    })
    .unwrap();
    assert!(
        flood_refused,
        "output over the bound was returned as complete"
    );
    assert!(later_ran, "the refusal stranded the session's worker owner");
}

#[test]
fn a_hand_back_push_cancelled_around_remote_acceptance_stays_uncertain() {
    let (dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let [origin, stall] = stallable_origin(dir.path(), &root);
    let route = Arc::new(route);
    let capsule = route.capsule(&scope).unwrap().path;
    let remote_branch = format!("refs/heads/{SESSION_BRANCH}");
    let pushes = || {
        std::fs::read_to_string(stall.join("pre-receive.log"))
            .unwrap_or_default()
            .lines()
            .count()
    };
    let hand_back = || {
        let (route, owner) = (Arc::clone(&route), scope.clone());
        move |effect: &PreparedEffect| route.propose(effect, &owner, "work".to_owned(), None)
    };
    for hook in ["pre-receive", "post-receive"] {
        std::fs::write(capsule.join(format!("{hook}.py")), "work = 1\n").unwrap();
        std::fs::write(stall.join(format!("{hook}.armed")), "").unwrap();
        let handed = cancelled(
            "hand-back",
            &scope,
            || stall.join("stalled").exists(),
            hand_back(),
        );
        assert!(
            matches!(handed, Err(ProposalFailure::Uncertain(_))),
            "a push cancelled in {hook}: {handed:?}"
        );
        assert!(
            exited(&stall.join("stall.pid")),
            "the {hook} stall outlived the stop"
        );
        let committed = git(&root, &["rev-parse", SESSION_BRANCH]);
        let remote = git(
            &origin,
            &["for-each-ref", "--format=%(objectname)", &remote_branch],
        );
        if hook == "pre-receive" {
            assert_ne!(remote, committed, "a stopped push landed");
        } else {
            assert_eq!(remote, committed, "the origin accepted the push");
        }
        std::fs::remove_file(stall.join("stalled")).unwrap();
        let before = pushes();
        let retried = admitted(&scope, hand_back()).unwrap();
        assert_eq!(retried["remote"]["pushed"], true, "{retried}");
        assert_eq!(git(&origin, &["rev-parse", &remote_branch]), committed);
        if hook == "post-receive" {
            assert_eq!(pushes(), before, "the accepted commit was pushed again");
        }
    }
}

#[test]
fn tests_and_reviews_refuse_a_capsule_that_is_not_the_registration() {
    let (dir, mut route, scope, _root) = session_capsule();
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("thruster.py"), "thrust = 42\n").unwrap();
    let unregistered = {
        let bare = Arc::new(DaemonCodingRoute {
            state_root: route.state_root.clone(),
            session_pool: None,
            supervisor: Default::default(),
            registry: None,
            projects: route.projects.clone(),
        });
        request_review(&bare, &scope, "forseti").unwrap_err()
    };
    assert!(
        unregistered.contains("no registered code capsule"),
        "{unregistered}"
    );
    let knowledge = dir.path().join("knowledge");
    std::fs::create_dir_all(&knowledge).unwrap();
    std::fs::write(knowledge.join("notes.md"), "# notes\n").unwrap();
    let _registration = scoped_test_fixture::register(&mut route, &scope, &knowledge);
    let route = std::sync::Arc::new(route);
    let refused = scoped_test_fixture::dispatch(
        std::sync::Arc::clone(&route),
        scope.clone(),
        TestSelection::Attr(None),
        None,
    )
    .unwrap_err();
    assert!(refused.contains("knowledge root"), "{refused}");
    assert!(request_review(&route, &scope, "forseti")
        .unwrap_err()
        .contains("knowledge root"));
    assert!(
        git(&capsule, &["for-each-ref", "refs/odin"]).is_empty(),
        "nothing was frozen or run"
    );
}

/// Review and test results must describe the frozen tree, including earlier unreviewed changes.
#[test]
fn a_reviewed_seat_branch_merges_into_main_after_the_declared_check() {
    let (dir, mut route, scope, root) = session_capsule();
    // The attr run and every merge step execute as the session's
    // registered workers.
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = std::sync::Arc::new(route);
    let origin = dir.path().join("origin.git");
    git(
        dir.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            root.to_str().unwrap(),
            origin.to_str().unwrap(),
        ],
    );
    git(
        &root,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&root, &["fetch", "--quiet", "origin"]);
    let start = git(&origin, &["rev-parse", "main"]);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("nozzle.py"), "area = 0.12\n").unwrap();
    let handed = propose(&route, &scope, "nozzle area", None).unwrap();
    assert_eq!(handed["remote"]["pushed"], true, "{handed}");
    assert_eq!(
        git(
            &origin,
            &[
                "show",
                "seat/gungnir/0e0c5a8e-1111-4222-8333-444455556666:nozzle.py"
            ]
        ),
        "area = 0.12"
    );
    assert!(git(&origin, &["ls-tree", "--name-only", "main"])
        .lines()
        .all(|file| file != "nozzle.py"));

    let refused = merge(&route, &scope, "main", &start, &start).unwrap_err();
    assert!(matches!(refused, ProposalFailure::Refused(_)));
    // Fail closed: the branch has no approving review bound to its head.
    let unreviewed = merge_current(&route, &scope, SESSION_BRANCH).unwrap_err();
    assert!(matches!(unreviewed, ProposalFailure::Refused(_)));
    assert_eq!(git(&origin, &["rev-parse", "main"]), start);

    // The review lane: an executed test run, an independent Forseti
    // verdict, then the reviewed proposal that binds the verdict to the
    // exact commit. The check reads the tree it was built from, so its log
    // names exactly what ran.
    let marker = uuid::Uuid::new_v4().simple().to_string();
    std::fs::write(capsule.join("thruster.py"), "thrust = 42\n").unwrap();
    std::fs::write(
        capsule.join("flake.nix"),
        format!(
            "{{ outputs = _: let check = name: script: derivation {{ inherit name; system = \
             \"x86_64-linux\"; builder = \"/bin/sh\"; args = [ \"-c\" script ]; }}; in {{ \
             checks.x86_64-linux.smoke = check \"odin-merge-gate-smoke\" \"echo smoke > $out\"; \
             checks.x86_64-linux.tests = check \"odin-c2-tests\" \"echo 'tested {marker}: \
             ${{builtins.readFile ./thruster.py}}'; echo 'test result: ok. 1 passed; 0 failed; \
             0 ignored'; echo ok > $out\"; }}; }}\n"
        ),
    )
    .unwrap();
    let running = {
        let (route, scope) = (route.clone(), scope.clone());
        let selection = TestSelection::Attr(Some("checks.x86_64-linux.tests".to_owned()));
        std::thread::spawn(move || scoped_test_fixture::dispatch(route, scope, selection, None))
    };
    // Once the run froze its snapshot, the working tree changes under it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while git(&capsule, &["for-each-ref", "refs/odin/test-runs"]).is_empty() {
        assert!(std::time::Instant::now() < deadline, "the run never froze");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    std::fs::write(capsule.join("thruster.py"), "thrust = 43\n").unwrap();
    let report = running.join().unwrap().unwrap();
    assert_eq!(report["ok"], true, "{report}");
    assert!(
        report["logTail"]
            .as_str()
            .unwrap()
            .contains(&format!("tested {marker}: thrust = 42")),
        "the run executed the frozen tree: {report}"
    );
    let snapshot = git(
        &capsule,
        &[
            "for-each-ref",
            "--format=%(objectname)",
            "refs/odin/test-runs",
        ],
    );
    let tested_tree = git(&capsule, &["rev-parse", &format!("{snapshot}^{{tree}}")]);
    let mutated = request_review(&route, &scope, "forseti").unwrap_err();
    assert!(mutated.contains("another tree"), "{mutated}");
    std::fs::write(capsule.join("thruster.py"), "thrust = 42\n").unwrap();
    let requested = request_review(&route, &scope, "forseti").unwrap();
    let forseti = Scope {
        seat: Some("forseti".parse().unwrap()),
        ..scope.clone()
    };
    // The approval lands everything between the capsule's base and the
    // offered tree, so that is what the reviewer reads — never only the
    // pending diff on top of an unreviewed ancestor.
    let artifact = route
        .read_artifact(
            &forseti,
            requested["artifactId"].as_str().unwrap().to_owned(),
        )
        .unwrap();
    let document = artifact["text"].as_str().unwrap();
    assert!(
        document.contains("nozzle.py") && document.contains("area = 0.12"),
        "the earlier unreviewed commit is part of the reviewed delta:\n{document}"
    );
    assert!(
        document.contains("thruster.py") && document.contains("thrust = 42"),
        "{document}"
    );
    assert!(
        document.contains(&start),
        "the review names its exact base {start}:\n{document}"
    );
    route
        .record_verdict(
            &forseti,
            requested["diffDigest"].as_str().unwrap().to_owned(),
            true,
            "ship it".to_owned(),
        )
        .unwrap();
    // An edit after the approval is another tree: never offered as this
    // review, and never committed behind it.
    std::fs::write(capsule.join("late.py"), "unreviewed = True\n").unwrap();
    assert!(propose_reviewed(&route, &scope, "thruster", None).is_err());
    std::fs::remove_file(capsule.join("late.py")).unwrap();
    let proposed = propose_reviewed(&route, &scope, "thruster", None).unwrap();
    assert_eq!(proposed["review"]["reviewer"], "forseti", "{proposed}");
    let commit = proposed["commit"].as_str().unwrap();
    assert_eq!(
        git(&root, &["rev-parse", &format!("{commit}^{{tree}}")]),
        tested_tree,
        "the offer is exactly the tested and reviewed tree"
    );
    let branch = SESSION_BRANCH;
    assert!(matches!(
        merge(&route, &scope, branch, &start, &start),
        Err(ProposalFailure::Refused(_))
    ));
    assert_eq!(git(&origin, &["rev-parse", "main"]), start);
    // Another actor advances main after the caller observed its base.
    let foreign = tempfile::tempdir().unwrap();
    git(
        foreign.path(),
        &["clone", "--quiet", origin.to_str().unwrap(), "project"],
    );
    let foreign_root = foreign.path().join("project");
    std::fs::write(foreign_root.join("owner.txt"), "other owner's work\n").unwrap();
    let advanced = commit_all(&foreign_root, "independent main update");
    git(
        &foreign_root,
        &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
    );
    assert!(matches!(
        merge(&route, &scope, branch, &start, commit),
        Err(ProposalFailure::Refused(_))
    ));
    assert_eq!(git(&origin, &["rev-parse", "main"]), advanced);
    assert_eq!(git(&root, &["rev-parse", branch]), commit);
    // A clean Git status must not authorize overwriting ignored owner bytes.
    std::fs::write(root.join(".git/info/exclude"), "nozzle.py\n").unwrap();
    std::fs::write(root.join("nozzle.py"), "owner's ignored experiment\n").unwrap();
    assert!(git(&root, &["status", "--porcelain"]).is_empty());

    let merged = merge(&route, &scope, branch, &advanced, commit).unwrap();
    assert_eq!(git(&origin, &["show", "main:thruster.py"]), "thrust = 42");
    assert_eq!(git(&origin, &["show", "main:nozzle.py"]), "area = 0.12");
    assert!(git(&origin, &["ls-tree", "--name-only", "main"])
        .lines()
        .all(|file| file != "late.py"));
    assert_eq!(
        git(&origin, &["rev-parse", "main"]),
        merged["mergeCommit"].as_str().unwrap()
    );
    assert_eq!(
        git(&origin, &["show", "main:owner.txt"]),
        "other owner's work"
    );
    assert_eq!(merged["rootFastForwarded"], false);
    assert_eq!(git(&root, &["rev-parse", "HEAD"]), start);
    assert_eq!(
        std::fs::read_to_string(root.join("nozzle.py")).unwrap(),
        "owner's ignored experiment\n"
    );
    // A retried merge of the landed tip is done already: no second check.
    let again = merge(&route, &scope, SESSION_BRANCH, &start, commit).unwrap();
    assert_eq!(again["alreadyMerged"], true, "{again}");
    assert_eq!(again["mergeCommit"], merged["mergeCommit"]);
}

#[test]
fn a_branch_that_moves_after_its_review_is_not_merged() {
    let (dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let origin = dir.path().join("origin.git");
    git(
        dir.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            root.to_str().unwrap(),
            origin.to_str().unwrap(),
        ],
    );
    git(
        &root,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&root, &["fetch", "--quiet", "origin"]);
    let start = git(&origin, &["rev-parse", "main"]);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("thruster.py"), "thrust = 42\n").unwrap();
    tested(&route, &scope);
    let requested = request_review(&route, &scope, "forseti").unwrap();
    let forseti = Scope {
        seat: Some("forseti".parse().unwrap()),
        ..scope.clone()
    };
    route
        .record_verdict(
            &forseti,
            requested["diffDigest"].as_str().unwrap().to_owned(),
            true,
            "ship it".to_owned(),
        )
        .unwrap();
    propose_reviewed(&route, &scope, "thruster", None).unwrap();

    // The branch moves on WITHOUT a review (the plain hand-back lane).
    std::fs::write(capsule.join("thruster.py"), "thrust = 43\n").unwrap();
    propose(&route, &scope, "unreviewed tweak", None).unwrap();

    let refused = merge_current(&route, &scope, SESSION_BRANCH).unwrap_err();
    assert!(matches!(refused, ProposalFailure::Refused(_)));
    assert_eq!(git(&origin, &["rev-parse", "main"]), start, "main holds");
}

#[test]
fn a_merge_that_fails_its_declared_check_never_pushes_main() {
    let (dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let origin = dir.path().join("origin.git");
    git(
        dir.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            root.to_str().unwrap(),
            origin.to_str().unwrap(),
        ],
    );
    git(
        &root,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&root, &["fetch", "--quiet", "origin"]);
    let start = git(&origin, &["rev-parse", "main"]);
    let capsule = route.capsule(&scope).unwrap().path;
    // The change itself breaks the declared check on the merged tree.
    std::fs::write(
        capsule.join("flake.nix"),
        "{ outputs = _: { checks.x86_64-linux.fail = builtins.throw \"gate\"; }; }\n",
    )
    .unwrap();
    tested(&route, &scope);
    let requested = request_review(&route, &scope, "forseti").unwrap();
    let forseti = Scope {
        seat: Some("forseti".parse().unwrap()),
        ..scope.clone()
    };
    route
        .record_verdict(
            &forseti,
            requested["diffDigest"].as_str().unwrap().to_owned(),
            true,
            "reviewed, but the gate decides".to_owned(),
        )
        .unwrap();
    propose_reviewed(&route, &scope, "breaking check", None).unwrap();

    let refused = merge_current(&route, &scope, SESSION_BRANCH).unwrap_err();
    assert!(matches!(refused, ProposalFailure::Refused(_)));
    assert_eq!(git(&origin, &["rev-parse", "main"]), start, "main holds");
    // The seat branch survives: the seat can fix and re-review.
    assert_eq!(
        git(
            &origin,
            &[
                "show",
                "seat/gungnir/0e0c5a8e-1111-4222-8333-444455556666:flake.nix"
            ]
        ),
        "{ outputs = _: { checks.x86_64-linux.fail = builtins.throw \"gate\"; }; }"
    );
}

#[test]
fn a_merge_without_declared_checks_is_refused() {
    let (dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let origin = dir.path().join("origin.git");
    git(
        dir.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            root.to_str().unwrap(),
            origin.to_str().unwrap(),
        ],
    );
    git(
        &root,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&root, &["fetch", "--quiet", "origin"]);
    let start = git(&origin, &["rev-parse", "main"]);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(
        capsule.join("flake.nix"),
        "{ outputs = _: { checks = { }; }; }\n",
    )
    .unwrap();
    tested(&route, &scope);
    let requested = request_review(&route, &scope, "forseti").unwrap();
    let forseti = Scope {
        seat: Some("forseti".parse().unwrap()),
        ..scope.clone()
    };
    route
        .record_verdict(
            &forseti,
            requested["diffDigest"].as_str().unwrap().to_owned(),
            true,
            "reviewed, but the gate needs a check to run".to_owned(),
        )
        .unwrap();
    propose_reviewed(&route, &scope, "empty checks", None).unwrap();

    let refused = merge_current(&route, &scope, SESSION_BRANCH).unwrap_err();
    assert!(matches!(refused, ProposalFailure::Refused(_)));
    assert_eq!(git(&origin, &["rev-parse", "main"]), start, "main holds");
}

#[test]
fn merges_of_one_project_serialize_on_the_merge_lock() {
    let (_dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let origin_dir = tempfile::tempdir().unwrap();
    git(
        origin_dir.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            root.to_str().unwrap(),
            "origin.git",
        ],
    );
    let origin = origin_dir.path().join("origin.git");
    git(
        &root,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    let start = git(&root, &["rev-parse", "HEAD"]);
    let branch = SESSION_BRANCH;
    git(
        &root,
        &["update-ref", &format!("refs/heads/{branch}"), &start],
    );
    git(
        &origin,
        &["update-ref", &format!("refs/heads/{branch}"), &start],
    );
    let held = MergeLock::acquire(&route.state_root, "surtr", MERGE_LOCK_BOUND, || false).unwrap();
    assert!(matches!(
        merge(&route, &scope, branch, &start, &start),
        Err(ProposalFailure::Refused(_))
    ));
    assert_eq!(git(&origin, &["rev-parse", "main"]), start);
    drop(held);
    let completed = merge(&route, &scope, branch, &start, &start).unwrap();
    assert_eq!(completed["alreadyMerged"], true);
    assert_eq!(completed["mergeCommit"], start);
    assert_eq!(git(&origin, &["rev-parse", "main"]), start);
}

/// an artifact is readable exactly where it was shared —
/// the writer's seat and project, and the seats it names — and a write can
/// never reach outside the session's workspace.
#[test]
fn an_artifact_is_readable_only_where_it_was_shared() {
    let (_dir, route, scope, _root) = session_capsule();
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("report.md"), "# residual 1e-6\n").unwrap();
    let written = route
        .write_artifact(
            &scope,
            ArtifactSource::File("report.md".to_owned()),
            None,
            vec!["sinmara".to_owned()],
        )
        .expect("the workspace file becomes an artifact");
    let id = written["artifactId"].as_str().unwrap().to_owned();
    assert_eq!(written["mediaType"], "text/markdown");

    let read = route
        .read_artifact(&scope, id.clone())
        .expect("the writer reads it");
    assert_eq!(read["text"], "# residual 1e-6\n");
    let sinmara = Scope {
        seat: Some("sinmara".parse().unwrap()),
        project: Some("life".parse().unwrap()),
        ..Scope::default()
    };
    assert!(
        route.read_artifact(&sinmara, id.clone()).is_ok(),
        "shared with sinmara"
    );
    let kubert = Scope {
        seat: Some("kubert".parse().unwrap()),
        project: Some("odin".parse().unwrap()),
        ..Scope::default()
    };
    assert!(
        route.read_artifact(&kubert, id).is_err(),
        "never shared with kubert"
    );

    for outside in ["../../ledger.sqlite3", "/etc/hostname"] {
        assert!(
            route
                .write_artifact(
                    &scope,
                    ArtifactSource::File(outside.to_owned()),
                    None,
                    Vec::new()
                )
                .is_err(),
            "{outside} is outside the workspace"
        );
    }
}

#[test]
fn text_given_inline_becomes_an_artifact_a_pod_can_take() {
    let (_dir, route, scope, _root) = session_capsule();
    let written = route
        .write_artifact(
            &scope,
            ArtifactSource::Text("Summarize arXiv 2101.04749 in five lines.".to_owned()),
            None,
            vec!["kubert".to_owned()],
        )
        .expect("inline text becomes an artifact");
    assert_eq!(written["mediaType"], "text/plain");
    let kubert = Scope {
        seat: Some("kubert".parse().unwrap()),
        project: Some("odin".parse().unwrap()),
        ..Scope::default()
    };
    let read = route
        .read_artifact(&kubert, written["artifactId"].as_str().unwrap().to_owned())
        .expect("shared with kubert");
    assert_eq!(read["text"], "Summarize arXiv 2101.04749 in five lines.");
}

#[test]
fn eval_scratch_is_never_part_of_the_reviewed_or_proposed_change() {
    let (_dir, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let capsule = route.capsule(&scope).unwrap().path;
    std::fs::write(capsule.join("engine.py"), "print('thrust')\n").unwrap();
    std::fs::create_dir_all(capsule.join(".odin-eval")).unwrap();
    std::fs::write(capsule.join(".odin-eval/runner.py"), "print(1)\n").unwrap();
    let offered = || {
        super::stage_change(&super::Unowned, &capsule).unwrap();
        git(&capsule, &["write-tree"])
    };
    let tree = offered();
    let files = git(&capsule, &["ls-tree", "-r", "--name-only", &tree]);
    assert!(!files.contains(".odin-eval"), "{files}");
    std::fs::write(capsule.join(".odin-eval/smoke.py"), "print(2)\n").unwrap();
    assert_eq!(offered(), tree);
    let handed = propose(&route, &scope, "engine", None).unwrap();
    assert_eq!(handed["files"], serde_json::json!(["engine.py"]));
    assert!(git(
        &root,
        &[
            "ls-tree",
            "-r",
            "--name-only",
            "seat/gungnir/0e0c5a8e-1111-4222-8333-444455556666"
        ]
    )
    .lines()
    .all(|file| !file.starts_with(".odin-eval")));
}

#[test]
fn parallel_stagings_of_one_capsule_never_collide_on_the_index_lock() {
    let (_dir, route, scope, _root) = session_capsule();
    let capsule = route.capsule(&scope).unwrap().path;
    let failures: Vec<String> = std::thread::scope(|threads| {
        let workers: Vec<_> = (0..6)
            .map(|worker| {
                let capsule = capsule.clone();
                threads.spawn(move || {
                    (0..15)
                        .filter_map(|round| {
                            std::fs::write(
                                capsule.join(format!("w{worker}.py")),
                                format!("ROUND = {round}\n"),
                            )
                            .unwrap();
                            super::stage_change(&super::Unowned, &capsule).err()
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect()
    });
    assert!(failures.is_empty(), "{failures:?}");
}

#[test]
fn publication_keeps_the_captured_commit_when_the_local_ref_advances() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    let origin = directory.path().join("origin.git");
    std::fs::create_dir(&project).unwrap();
    git(&project, &["init", "-q"]);
    git(
        directory.path(),
        &["init", "--bare", "-q", origin.to_str().unwrap()],
    );
    git(
        &project,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    std::fs::write(project.join("reviewed.txt"), "the reviewed bytes\n").unwrap();
    let captured = commit_all(&project, "reviewed commit");
    let branch = "seat/gungnir/captured";
    let reference = format!("refs/heads/{branch}");
    git(&project, &["update-ref", &reference, &captured]);
    std::fs::write(project.join("later.txt"), "later owner work\n").unwrap();
    let later = commit_all(&project, "later work");
    git(&project, &["update-ref", &reference, &later]);
    let result = super::publication::publish_destination(
        &super::Unowned,
        &project,
        branch,
        &captured,
        Some(origin.to_str().unwrap()),
    )
    .report;
    assert_eq!(result["pushed"], true, "{result}");
    assert_eq!(
        git(&origin, &["rev-parse", &reference]),
        captured,
        "publication must not substitute the later unreviewed local tip"
    );
    assert_eq!(git(&project, &["rev-parse", &reference]), later);
    assert_eq!(
        std::fs::read_to_string(project.join("later.txt")).unwrap(),
        "later owner work\n"
    );
}

#[test]
fn checked_merge_refuses_a_changed_advertisement_and_retains_an_unknown_result() {
    use std::os::unix::fs::PermissionsExt;
    let (_session, mut route, scope, root) = session_capsule();
    let (_config, _worker) = scoped_test_fixture::compose(&mut route, &scope, &root);
    let route = Arc::new(route);
    let fixture = tempfile::tempdir().unwrap();
    let project = fixture.path().join("project");
    let origin = fixture.path().join("origin.git");
    std::fs::create_dir(&project).unwrap();
    git(&project, &["init", "-q", "-b", "main"]);
    std::fs::write(project.join("base.txt"), "base\n").unwrap();
    let base = commit_all(&project, "base");
    git(
        fixture.path(),
        &[
            "clone",
            "-q",
            "--bare",
            project.to_str().unwrap(),
            origin.to_str().unwrap(),
        ],
    );
    // An actual Git server over private pipes, with its own hook config.
    // Client command-scope hook settings must not suppress the receiver fixture.
    let server = fixture.path().join("git-server");
    std::fs::write(&server, "#!/bin/sh\nunset GIT_CONFIG_PARAMETERS\nexport GIT_CONFIG_COUNT=0\nexec git \"$1\" \"$2\"\n").unwrap();
    std::fs::set_permissions(&server, std::fs::Permissions::from_mode(0o700)).unwrap();
    git(&project, &["config", "protocol.ext.allow", "always"]);
    let escape =
        |path: &std::path::Path| path.to_str().unwrap().replace('%', "%%").replace(' ', "% ");
    let target = format!("ext::{} %s {}", escape(&server), escape(&origin));
    std::fs::write(project.join("topic.txt"), "reviewed topic\n").unwrap();
    let head = commit_all(&project, "topic");
    git(&project, &["checkout", "-q", "--detach", &base]);
    git(
        &project,
        &[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "merge",
            "--no-ff",
            "-qm",
            "checked merge",
            &head,
        ],
    );
    let merged = git(&project, &["rev-parse", "HEAD"]);
    git(
        &project,
        &[
            "push",
            "-q",
            origin.to_str().unwrap(),
            &format!("{head}:refs/heads/main"),
        ],
    );
    let push_merged = |base: &str, commit: &str| {
        let (route, owner) = (Arc::clone(&route), scope.clone());
        let (project, target) = (project.clone(), target.clone());
        let (base, commit) = (base.to_owned(), commit.to_owned());
        admitted(&scope, move |effect| {
            let bound = std::time::Duration::from_secs(120);
            let owned = super::Owned::new(&route, effect, &owner, bound)?;
            super::publication::push_merged(&owned, &project, &target, &base, &commit)
        })
    };
    // This is still a fast-forward to `merged`; a plain push would
    // succeed. The expected-base predicate must nevertheless refuse.
    assert!(matches!(
        push_merged(&base, &merged),
        Err(ProposalFailure::Refused(_))
    ));
    assert_eq!(git(&origin, &["rev-parse", "main"]), head);
    push_merged(&head, &merged).unwrap();
    assert_eq!(git(&origin, &["rev-parse", "main"]), merged);

    std::fs::write(project.join("later.txt"), "later checked work\n").unwrap();
    let later = commit_all(&project, "later merge");
    let hook = origin.join("hooks/post-receive");
    std::fs::write(
        &hook,
        "#!/bin/sh\nset -e\ndirectory=$(pwd -P)\nmv -- \"$directory\" \"$directory.unavailable\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        push_merged(&merged, &later),
        Err(ProposalFailure::Uncertain(_))
    ));
    let unavailable = fixture.path().join("origin.git.unavailable");
    assert_eq!(git(&unavailable, &["rev-parse", "main"]), later);
    assert!(git(
        &project,
        &[
            "for-each-ref",
            "--format=%(objectname)",
            "refs/odin/merge-publications"
        ]
    )
    .lines()
    .any(|commit| commit == later));
    assert_eq!(
        std::fs::read_to_string(project.join("topic.txt")).unwrap(),
        "reviewed topic\n"
    );
}
