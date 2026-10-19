use std::io::Read;
use std::path::{Component, Path, PathBuf};

use odin_cli::live_authority::{Capture, Retention};
use odin_domain::Scope;
use odin_hermes::runtime::coding::CheckoutQuery;
use odin_omp::host_tools::delegation::TaskBranchReport;
use serde_json::{json, Value};

use super::{DaemonCodingRoute, GitRunner};

const MAX_READ_BYTES: usize = 1 << 20;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

impl DaemonCodingRoute {
    pub(super) fn readable_project(&self, scope: &Scope, project: &str) -> Result<PathBuf, String> {
        let seat = scope.seat.as_ref().ok_or("checkout read requires a seat")?;
        let registry = self
            .registry
            .as_ref()
            .ok_or("checkout read requires the registry")?;
        let snapshot = registry.current();
        let allowed = snapshot
            .object(odin_registry::RegistryKind::Seat, seat.as_str())
            .is_some_and(|object| {
                matches!(&object.config, odin_registry::ObjectConfig::Seat(config)
                if config.enabled && config.project_scope.iter()
                    .chain(&config.read_project_scope)
                    .any(|id| id.as_str() == project))
            });
        let enabled = snapshot
            .object(odin_registry::RegistryKind::Project, project)
            .is_some_and(|object| {
                matches!(&object.config, odin_registry::ObjectConfig::Project(config)
                if config.enabled)
            });
        if !allowed || !enabled {
            return Err(format!(
                "seat {seat} cannot read project {project}: disabled or outside project_scope and read_project_scope"
            ));
        }
        self.projects
            .get(project)
            .cloned()
            .ok_or_else(|| format!("project {project} has no declared checkout"))
    }
}

fn bounded_text(mut text: String, truncated: bool) -> (String, bool) {
    if text.len() <= MAX_OUTPUT_BYTES {
        return (text, truncated);
    }
    let mut end = MAX_OUTPUT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str(&format!("\n[truncated at {MAX_OUTPUT_BYTES} bytes]"));
    (text, true)
}

fn relative_path(path: &str) -> Result<&Path, String> {
    let relative = Path::new(path);
    if path.is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return Err("checkout path must be relative without '..'".to_owned());
    }
    Ok(relative)
}

/// One read-only git command's stdout; `ok_codes` beyond 0 count as success.
fn git_stdout(
    runner: &dyn GitRunner,
    root: &Path,
    mode: &str,
    command: &[&str],
    ok_codes: &[i32],
) -> Result<(String, bool), String> {
    let mut args = vec!["--no-pager", "-c", "core.fsmonitor=false"];
    args.extend_from_slice(command);
    let captured = runner.run_git_captured(
        root,
        &args,
        None,
        false,
        Capture {
            stdout: Retention::Head,
            stderr: Retention::Complete,
        },
    )?;
    let status = captured.output.status;
    if !status.success() && !status.code().is_some_and(|code| ok_codes.contains(&code)) {
        return Err(format!(
            "checkout git {mode} failed ({status}): {}",
            String::from_utf8_lossy(&captured.output.stderr).trim()
        ));
    }
    Ok((
        String::from_utf8_lossy(&captured.output.stdout).into_owned(),
        captured.stdout_cut,
    ))
}

/// A worker capsule's change since `base`: `git diff --stat` and the bounded diff.
pub(crate) fn branch_diff(
    runner: &dyn GitRunner,
    root: &Path,
    branch: &str,
    base: &str,
) -> Result<TaskBranchReport, String> {
    validate_revision(base)?;
    let (stat, stat_cut) = git_stdout(
        runner,
        root,
        "diff --stat",
        &["diff", "--stat", base, "--"],
        &[],
    )?;
    let (diff, diff_cut) = git_stdout(
        runner,
        root,
        "diff",
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            base,
            "--",
        ],
        &[],
    )?;
    let (stat, stat_cut) = bounded_text(stat, stat_cut);
    let (diff, diff_cut) = bounded_text(diff, diff_cut);
    Ok(TaskBranchReport {
        branch: branch.to_owned(),
        base: base.to_owned(),
        stat,
        diff,
        truncated: stat_cut || diff_cut,
    })
}

pub(super) fn inspect_checkout(
    runner: &dyn GitRunner,
    root: &Path,
    query: &CheckoutQuery,
    limit: usize,
) -> Result<Value, String> {
    if let CheckoutQuery::Read { path, start_line } = query {
        let relative = relative_path(path)?;
        let capability = odin_confined_fs::Capability::seal(root)
            .map_err(|error| format!("open checkout {}: {error}", root.display()))?;
        let file = capability
            .open_read(relative)
            .map_err(|error| format!("read checkout file {path}: {error}"))?;
        if !file
            .metadata()
            .map_err(|error| format!("inspect checkout file {path}: {error}"))?
            .is_file()
        {
            return Err(format!("checkout file {path} is not a regular file"));
        }
        let mut bytes = Vec::new();
        file.take((MAX_READ_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read checkout file {path}: {error}"))?;
        let input_cut = bytes.len() > MAX_READ_BYTES;
        if input_cut {
            bytes.truncate(MAX_READ_BYTES);
            while std::str::from_utf8(&bytes).is_err_and(|error| error.error_len().is_none()) {
                bytes.pop();
            }
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|error| format!("decode checkout file {path} as UTF-8: {error}"))?;
        let mut lines = text.lines().skip(start_line.saturating_sub(1));
        let selected = lines.by_ref().take(limit).collect::<Vec<_>>().join("\n");
        let more = lines.next().is_some();
        let (mut text, truncated) = bounded_text(selected, input_cut || more);
        if input_cut && !more {
            text.push_str(&format!("\n[truncated at {MAX_READ_BYTES} bytes]"));
        }
        return Ok(
            json!({"mode": "read", "path": path, "startLine": start_line,
            "text": text, "truncated": truncated, "maxBytes": MAX_OUTPUT_BYTES,
            "scannedBytes": bytes.len()}),
        );
    }
    let limit_arg = format!("-{limit}");
    let (mode, command, ok_codes): (&str, Vec<&str>, &[i32]) = match query {
        CheckoutQuery::List(path) => {
            relative_path(path)?;
            let (output, cut) = git_stdout(
                runner,
                root,
                "list",
                &[
                    "ls-files",
                    "-z",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                    "--",
                    path,
                ],
                &[],
            )?;
            return Ok(list_entries(path, &output, cut, limit));
        }
        CheckoutQuery::Search(pattern) => (
            "search",
            vec![
                "grep",
                "-n",
                "-I",
                "--untracked",
                "--full-name",
                "-F",
                "-e",
                pattern.as_str(),
                "--",
            ],
            &[1],
        ),
        CheckoutQuery::Log => (
            "log",
            vec![
                "log",
                "--no-decorate",
                "--format=%h %ad %s",
                "--date=iso-strict",
                &limit_arg,
                "--",
            ],
            &[],
        ),
        CheckoutQuery::Diff(revision) => {
            let mut command = vec!["diff", "--no-ext-diff", "--no-textconv", "--no-color"];
            if let Some(revision) = revision {
                validate_revision(revision)?;
                command.push(revision.as_str());
            }
            command.push("--");
            ("diff", command, &[])
        }
        CheckoutQuery::Show(revision) => {
            validate_revision(revision)?;
            (
                "show",
                vec![
                    "show",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-color",
                    revision.as_str(),
                    "--",
                ],
                &[],
            )
        }
        CheckoutQuery::Read { .. } | CheckoutQuery::Code(_) => {
            return Err("checkout read or symbol search was not resolved".to_owned())
        }
    };
    let (output, cut) = git_stdout(runner, root, mode, &command, ok_codes)?;
    if mode == "search" {
        let (matches, truncated) = super::engineering::parse_matches(&output, limit);
        return Ok(json!({"mode": mode, "matches": matches, "truncated": truncated || cut}));
    }
    let (text, truncated) = bounded_text(output, cut);
    Ok(json!({"mode": mode, "text": text, "truncated": truncated, "maxBytes": MAX_OUTPUT_BYTES}))
}

/// The immediate children of `path` among the listed files; directories end in `/`.
fn list_entries(path: &str, output: &str, cut: bool, limit: usize) -> Value {
    let prefix = Path::new(path)
        .components()
        .filter(|part| matches!(part, Component::Normal(_)))
        .map(|part| format!("{}/", part.as_os_str().to_string_lossy()))
        .collect::<String>();
    let mut listed = output
        .split('\0')
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    if cut {
        // The last name may be cut mid-way.
        listed.pop();
    }
    let mut entries = std::collections::BTreeSet::new();
    for name in listed {
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        entries.insert(match rest.split_once('/') {
            Some((dir, _)) => format!("{dir}/"),
            None => rest.to_owned(),
        });
    }
    let truncated = cut || entries.len() > limit;
    let entries: Vec<_> = entries.into_iter().take(limit).collect();
    json!({"mode": "list", "path": path, "entries": entries, "truncated": truncated})
}

fn validate_revision(revision: &str) -> Result<(), String> {
    if revision.is_empty() || revision.starts_with('-') || revision.chars().any(char::is_control) {
        return Err(
            "revision must be nonempty, not start with '-' or contain control characters"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn checkout_reads_searches_and_git_history_without_writes_or_path_escape() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for args in [
            &["init", "-q"][..],
            &["config", "user.email", "test@example.com"],
            &["config", "user.name", "Test"],
        ] {
            assert!(Command::new("git")
                .args(args)
                .current_dir(root)
                .status()
                .unwrap()
                .success());
        }
        std::fs::write(root.join("note.txt"), "first line\nneedle\n").unwrap();
        for args in [&["add", "."][..], &["commit", "-qm", "initial"]] {
            assert!(Command::new("git")
                .args(args)
                .current_dir(root)
                .status()
                .unwrap()
                .success());
        }
        let runner = &super::super::Unowned;
        let read = inspect_checkout(
            runner,
            root,
            &CheckoutQuery::Read {
                path: "note.txt".into(),
                start_line: 1,
            },
            1,
        )
        .unwrap();
        assert_eq!(read["text"], "first line");
        assert_eq!(read["truncated"], true);
        let found =
            inspect_checkout(runner, root, &CheckoutQuery::Search("needle".into()), 10).unwrap();
        assert_eq!(found["matches"][0]["line"], 2);
        assert!(
            inspect_checkout(runner, root, &CheckoutQuery::Log, 10).unwrap()["text"]
                .as_str()
                .unwrap()
                .contains("initial")
        );
        assert!(inspect_checkout(
            runner,
            root,
            &CheckoutQuery::Show("HEAD:note.txt".into()),
            10
        )
        .unwrap()["text"]
            .as_str()
            .unwrap()
            .contains("needle"));
        std::fs::write(root.join("note.txt"), "changed\n").unwrap();
        assert!(
            inspect_checkout(runner, root, &CheckoutQuery::Diff(None), 10).unwrap()["text"]
                .as_str()
                .unwrap()
                .contains("+changed")
        );
        std::os::unix::fs::symlink("/etc/passwd", root.join("escape")).unwrap();
        for path in ["../outside", "/etc/passwd", "escape"] {
            assert!(inspect_checkout(
                runner,
                root,
                &CheckoutQuery::Read {
                    path: path.into(),
                    start_line: 1
                },
                10
            )
            .is_err());
        }
        assert!(inspect_checkout(
            runner,
            root,
            &CheckoutQuery::Show("--output=bad".into()),
            10
        )
        .is_err());
        assert_eq!(
            std::fs::read_to_string(root.join("note.txt")).unwrap(),
            "changed\n"
        );
        std::fs::create_dir(root.join("docs")).unwrap();
        std::fs::write(root.join("docs/guide.md"), "guide\n").unwrap();
        let listed = inspect_checkout(runner, root, &CheckoutQuery::List(".".into()), 10).unwrap();
        assert_eq!(listed["entries"], json!(["docs/", "escape", "note.txt"]));
        let base = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root)
            .output()
            .unwrap();
        let base = String::from_utf8(base.stdout).unwrap();
        let change = branch_diff(runner, root, "seat/gungnir/1", base.trim()).unwrap();
        assert!(change.stat.contains("note.txt"));
        assert!(change.diff.contains("+changed"));
    }

    #[test]
    fn sinmara_reads_the_odin_readme_through_her_read_scope() {
        let dir = tempfile::tempdir().unwrap();
        let checkout = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let route = DaemonCodingRoute {
            state_root: dir.path().to_path_buf(),
            session_pool: None,
            supervisor: Default::default(),
            projects: [("odin".to_owned(), checkout.clone())].into(),
            registry: Some(crate::claude_sessions::tests::registry_pin(dir.path())),
        };
        let scope = Scope {
            seat: Some("sinmara".parse().unwrap()),
            ..Scope::default()
        };
        let root = route.readable_project(&scope, "odin").unwrap();
        let read = inspect_checkout(
            &super::super::Unowned,
            &root,
            &CheckoutQuery::Read {
                path: "README.md".into(),
                start_line: 1,
            },
            1,
        )
        .unwrap();
        let readme = std::fs::read_to_string(checkout.join("README.md")).unwrap();
        assert_eq!(read["text"], readme.lines().next().unwrap());
    }
}
