use super::*;

use crate::probe::PINNED_OMP_SOURCE_REVISION;
fn spec_with(cwd: PathBuf, home: &str) -> OmpProcessSpec {
    OmpProcessSpec {
        executable: PathBuf::from("/omp"),
        cwd,
        explicit_args: Vec::new(),
        explicit_env: vec![("HOME".to_owned(), home.to_owned())],
        expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
        startup_timeout: Duration::from_secs(10),
        drain_timeout: Duration::from_secs(1),
        kill_timeout: Duration::from_secs(1),
    }
}

#[test]
fn names_the_newest_transcript_of_the_exact_launch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let session = "28b3fc48-21e3-4e56-a0df-547737cdef65";
    let launch = "e690e7ac-2038-4dc5-be98-14fa142f0558";
    let cwd = temp
        .path()
        .join("state/huginn/harness")
        .join(session)
        .join(launch);
    std::fs::create_dir_all(&cwd).expect("harness cwd");
    let home = temp.path().join("home");
    let project = home.join(".omp/agent/sessions").join(format!(
        "-.local-state-odin-huginn-harness-{session}-{launch}"
    ));
    std::fs::create_dir_all(&project).expect("sessions project dir");
    std::fs::write(project.join("2026-09-16T23-07-09-803Z_a.jsonl"), b"{}")
        .expect("older transcript");
    std::fs::write(project.join("2026-09-16T23-07-37-242Z_b.jsonl"), b"{}")
        .expect("newer transcript");
    std::fs::write(project.join("notes.txt"), b"not a transcript").expect("non-transcript file");
    // An unrelated session's transcript must never be picked.
    let other = home
        .join(".omp/agent/sessions")
        .join("-.tmp-unrelated")
        .join("2026-09-17T00-00-00-000Z_other.jsonl");
    std::fs::create_dir_all(other.parent().expect("other parent")).expect("other dir");
    std::fs::write(&other, b"{}").expect("unrelated transcript");

    let picked = resumable_transcript(&spec_with(cwd, home.to_str().expect("utf8 home")))
        .expect("the launch's transcript is named");
    assert_eq!(
        picked,
        Some(project.join("2026-09-16T23-07-37-242Z_b.jsonl")),
        "the newest transcript of the exact launch wins"
    );
}

#[test]
fn a_fresh_daemon_launch_resumes_the_previous_launch_transcript() {
    // A daemon restart mints a NEW launch directory for the SAME
    // session; the conversation lives in the previous launch's
    // transcript. The selector must cross launches inside the session.
    let temp = tempfile::tempdir().expect("tempdir");
    let session = "28b3fc48-21e3-4e56-a0df-547737cdef65";
    let old_launch = "e690e7ac-2038-4dc5-be98-14fa142f0558";
    let new_launch = "7c9c1bd2-1111-4222-8333-444555666777";
    let home = temp.path().join("home");
    let sessions = home.join(".omp/agent/sessions");
    let old_project = sessions.join(format!(
        "-.local-state-odin-huginn-harness-{session}-{old_launch}"
    ));
    let new_cwd = temp
        .path()
        .join("state/huginn/harness")
        .join(session)
        .join(new_launch);
    std::fs::create_dir_all(&new_cwd).expect("fresh harness cwd");
    std::fs::create_dir_all(&old_project).expect("old project dir");
    std::fs::write(
        old_project.join("2026-09-16T23-07-09-803Z_epoch1.jsonl"),
        b"{}",
    )
    .expect("epoch one transcript");

    let picked = resumable_transcript(&spec_with(new_cwd, home.to_str().expect("utf8 home")))
        .expect("the previous launch's transcript is named");
    assert_eq!(
        picked,
        Some(old_project.join("2026-09-16T23-07-09-803Z_epoch1.jsonl"))
    );
}

#[test]
fn no_transcript_yet_names_nothing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let cwd = temp
        .path()
        .join("state/huginn/harness")
        .join("28b3fc48-21e3-4e56-a0df-547737cdef65")
        .join("e690e7ac-2038-4dc5-be98-14fa142f0558");
    std::fs::create_dir_all(&cwd).expect("harness cwd");
    let home = temp.path().join("home");
    std::fs::create_dir_all(home.join(".omp/agent/sessions")).expect("sessions root");
    assert!(
        resumable_transcript(&spec_with(cwd, home.to_str().expect("utf8 home")))
            .expect("selector succeeds")
            .is_none(),
        "no transcript yet is a legitimate fresh conversation"
    );
}

#[test]
fn foreign_project_directories_are_never_named() {
    let temp = tempfile::tempdir().expect("tempdir");
    let cwd = temp
        .path()
        .join("state/huginn/harness")
        .join("28b3fc48-21e3-4e56-a0df-547737cdef65")
        .join("e690e7ac-2038-4dc5-be98-14fa142f0558");
    std::fs::create_dir_all(&cwd).expect("harness cwd");
    let home = temp.path().join("home");
    // A directory whose name merely CONTAINS the session id without the
    // surrounding dashes is a different project: never picked.
    let impostor = home
        .join(".omp/agent/sessions")
        .join("-harness-28b3fc48-21e3-4e56-a0df-547737cdef65");
    std::fs::create_dir_all(&impostor).expect("impostor dir");
    std::fs::write(impostor.join("2026-09-16T23-07-09-803Z_x.jsonl"), b"{}")
        .expect("impostor transcript");
    assert!(
        resumable_transcript(&spec_with(cwd, home.to_str().expect("utf8 home")))
            .expect("selector succeeds")
            .is_none(),
        "a foreign project directory is never a resume source"
    );
}

#[cfg(unix)]
#[test]
fn unreadable_transcript_continuity_fails_typed_never_fresh() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().expect("tempdir");
    let session = "28b3fc48-21e3-4e56-a0df-547737cdef65";
    let launch = "e690e7ac-2038-4dc5-be98-14fa142f0558";
    let cwd = temp
        .path()
        .join("state/huginn/harness")
        .join(session)
        .join(launch);
    std::fs::create_dir_all(&cwd).expect("harness cwd");
    let home = temp.path().join("home");
    let project = home.join(".omp/agent/sessions").join(format!(
        "-.local-state-odin-huginn-harness-{session}-{launch}"
    ));
    std::fs::create_dir_all(&project).expect("project dir");
    std::fs::write(project.join("2026-09-16T23-07-09-803Z_a.jsonl"), b"{}").expect("transcript");
    // The transcript for this session EXISTS but its directory is
    // unreadable: recovery must fail typed, never silently start a new
    // empty conversation.
    std::fs::set_permissions(&project, std::fs::Permissions::from_mode(0o000))
        .expect("chmod project");
    let error = resumable_transcript(&spec_with(cwd, home.to_str().expect("utf8 home")))
        .expect_err("unreadable continuity is a typed failure");
    std::fs::set_permissions(&project, std::fs::Permissions::from_mode(0o755))
        .expect("restore permissions for cleanup");
    assert!(
        error.contains("unreadable"),
        "the failure must name the unreadable seam: {error}"
    );
}
