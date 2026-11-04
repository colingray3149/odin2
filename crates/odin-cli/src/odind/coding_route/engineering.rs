//! Gungnir's engineering toolset over the session capsule: code navigation
//! (definitions and references by `git grep`, any
//! language, uncommitted edits included) and logged Nix runs whose full
//! build log the Hermes side parses into diagnostics and test results.

use std::path::Path;
use std::time::{Duration, Instant};

use odin_cli::live_authority::{Capture, Retention, ScopedTestInput};
use odin_hermes::runtime::coding::{CodeQuery, NixLog, NixVerb, TestSelection};
use serde_json::{json, Value};

use super::{
    capsule_flake, nix_flake_argv,
    sphere::{BUILD_CAPTURE, STORED_LOG_CAPTURE},
    stage_change, valid_attr, DaemonCodingRoute, GitRunner, Owned,
};

/// The most of a build log kept for parsing (its END: failures and the
/// test summaries come last).
const MAX_PARSED_LOG_BYTES: usize = 8 * 1024 * 1024;
const MAX_MATCH_TEXT_BYTES: usize = 240;

/// Declaration keywords across the languages the owner's projects use (Rust,
/// Python, TypeScript/JavaScript, Go, Nix-free shells), so "where is X
/// defined" works without a language server.
const DEFINITION_KEYWORDS: &str = "fn|struct|enum|trait|type|union|mod|const|static|macro_rules!|\
                                   impl|def|class|function|interface|func|let|var";

/// Bounded tail of a log at a char boundary.
fn log_tail(text: &str, bytes: usize) -> String {
    let start = text.len().saturating_sub(bytes);
    let start = (start..=text.len())
        .find(|index| text.is_char_boundary(*index))
        .unwrap_or(text.len());
    text[start..].to_owned()
}

/// The `git grep` argv for one query. The symbol was validated as an
/// identifier, so it is safe inside the extended regex.
pub(super) fn grep_args(query: &CodeQuery) -> Vec<String> {
    let mut args: Vec<String> = ["grep", "-n", "-I", "--untracked", "--full-name"]
        .map(str::to_owned)
        .to_vec();
    match query {
        CodeQuery::Definition(symbol) => {
            args.push("-E".to_owned());
            args.push("-e".to_owned());
            args.push(format!(
                "(^|[^A-Za-z0-9_])({DEFINITION_KEYWORDS})[[:space:]]+(\\(.*\\)[[:space:]]+)?{symbol}([^A-Za-z0-9_]|$)"
            ));
        }
        CodeQuery::References(symbol) => {
            args.extend(["-w", "-F", "-e"].map(str::to_owned));
            args.push(symbol.clone());
        }
    }
    args
}

/// Parses `path:line:text` grep output into bounded matches.
pub(super) fn parse_matches(output: &str, limit: usize) -> (Vec<Value>, bool) {
    let mut matches = Vec::new();
    let mut truncated = false;
    for line in output.lines() {
        let mut parts = line.splitn(3, ':');
        let (Some(file), Some(number), Some(text)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let Ok(number) = number.parse::<u64>() else {
            continue;
        };
        if matches.len() == limit {
            truncated = true;
            break;
        }
        let text = text.trim();
        let mut end = text.len().min(MAX_MATCH_TEXT_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        matches.push(json!({ "file": file, "line": number, "text": &text[..end] }));
    }
    (matches, truncated)
}

impl DaemonCodingRoute {
    pub(super) fn search_code_blocking(
        &self,
        runner: &dyn GitRunner,
        workspace: &Path,
        query: &CodeQuery,
        limit: usize,
    ) -> Result<Value, String> {
        let args = grep_args(query);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        // Only the matches' beginning is wanted; the rest of a finite output
        // is drained and dropped, never an error.
        let captured = runner.run_git_captured(
            workspace,
            &args,
            None,
            false,
            Capture {
                stdout: Retention::Head,
                stderr: Retention::Complete,
            },
        )?;
        let output = captured.output;
        // git grep exits 1 for "no match": an empty result, not a failure.
        match output.status.code() {
            Some(0) | Some(1) => {}
            _ => {
                return Err(format!(
                    "git grep failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let (matches, parsed_truncated) = parse_matches(&text, limit);
        let truncated = parsed_truncated || captured.stdout_cut;
        Ok(json!({
            "mode": match query {
                CodeQuery::Definition(_) => "definition",
                CodeQuery::References(_) => "references",
            },
            "symbol": query.symbol(),
            "matches": matches,
            "truncated": truncated,
        }))
    }

    /// Runs one Nix verb over the capsule with `--print-build-logs` and
    /// returns the bounded END of the full log. When a named output built
    /// from cache (no log printed), its stored build log is read with
    /// `nix log`, so a cached passing check still reports its tests.
    /// Staging, execution, and stored-log reads share one deadline and cancellation.
    pub(super) fn nix_log_blocking(
        &self,
        owned: &Owned<'_>,
        capsule: &Path,
        verb: NixVerb,
        attr: Option<&str>,
        environment: Vec<(String, String)>,
    ) -> Result<NixLog, String> {
        stage_change(owned, capsule)?;
        let started = Instant::now();
        let flake = capsule_flake(capsule);
        let mut argv = nix_flake_argv(&flake, verb, attr);
        argv.push("--print-build-logs".to_owned());
        let output =
            self.nix_in_capsule(owned, capsule, argv, environment.clone(), BUILD_CAPTURE)?;
        let mut log = String::from_utf8_lossy(&output.stderr).into_owned();
        let cached = output.status.success() && !printed_build_output(&log);
        if let Some(attr) = attr.filter(|_| cached && verb == NixVerb::Build) {
            let stored = self.nix_in_capsule(
                owned,
                capsule,
                stored_log_argv(&flake, attr),
                environment,
                STORED_LOG_CAPTURE,
            )?;
            if stored.status.success() {
                log.push('\n');
                log.push_str(&String::from_utf8_lossy(&stored.stdout));
            }
        }
        Ok(NixLog {
            ok: output.status.success(),
            log: log_tail(&log, MAX_PARSED_LOG_BYTES),
            seconds: started.elapsed().as_secs(),
        })
    }

    /// Run the frozen snapshot inside the lane bubble. The host Nix binary
    /// is not executed: the same confined store as `build.run` realizes the
    /// output, and a cached build's stored log is read the same way.
    pub(super) fn attr_log(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: &odin_domain::Scope,
        input: &ScopedTestInput<'_>,
        attr: Option<&str>,
    ) -> Result<NixLog, String> {
        if let Some(attr) = attr {
            if !valid_attr(attr) {
                return Err(format!("{attr:?} is not a flake output name"));
            }
        }
        let _slot = self.hold_lane_build_slot(scope)?;
        let owned = Owned::new(self, effect, scope, Duration::from_secs(super::NIX_SECONDS))?;
        let capsule = input.capsule_project;
        let flake = format!(
            "git+file://{}?ref={}&rev={}",
            capsule.display(),
            input.reference,
            input.revision
        );
        let started = Instant::now();
        let verb = if attr.is_some() {
            NixVerb::Build
        } else {
            NixVerb::Check
        };
        let mut argv = nix_flake_argv(&flake, verb, attr);
        argv.push("--print-build-logs".to_owned());
        let output = self.nix_in_capsule(
            &owned,
            capsule,
            argv,
            self.lane_slot_env(scope)?,
            BUILD_CAPTURE,
        )?;
        let mut log = String::from_utf8_lossy(&output.stderr).into_owned();
        let cached = output.status.success() && !printed_build_output(&log);
        if let Some(attr) = attr.filter(|_| cached) {
            let stored = self.nix_in_capsule(
                &owned,
                capsule,
                stored_log_argv(&flake, attr),
                self.lane_slot_env(scope)?,
                STORED_LOG_CAPTURE,
            )?;
            if stored.status.success() {
                log.push('\n');
                log.push_str(&String::from_utf8_lossy(&stored.stdout));
            }
        }
        Ok(NixLog {
            ok: output.status.success(),
            log: log_tail(&log, MAX_PARSED_LOG_BYTES),
            seconds: started.elapsed().as_secs(),
        })
    }
}

/// `nix log` of a built output, read from the local store only.
fn stored_log_argv(flake: &str, attr: &str) -> Vec<String> {
    [
        "--extra-experimental-features",
        "nix-command flakes",
        "log",
        "--option",
        "accept-flake-config",
        "false",
        "--option",
        "substituters",
        "",
        &format!("{flake}#{attr}"),
    ]
    .map(str::to_owned)
    .to_vec()
}

/// Whether a `--print-build-logs` log carries a build's own output
/// (`drv-name> …` lines): then the stored log of that build is the same
/// lines again, and appending it would count every test twice.
fn printed_build_output(log: &str) -> bool {
    log.lines().any(|line| {
        line.split_once("> ").is_some_and(|(prefix, _)| {
            !prefix.is_empty()
                && prefix
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
        })
    })
}

/// The most capsule-relative test files one scoped `test_run` names
/// (mirrors the Hermes-side schema bound).
const MAX_TEST_PATHS: usize = 8;

/// Refuses a test selection whose names could read as options or leave the
/// capsule, before anything runs.
pub(super) fn check_selection(selection: &TestSelection) -> Result<(), String> {
    match selection {
        TestSelection::Paths(paths) => {
            if paths.is_empty() || paths.len() > MAX_TEST_PATHS {
                return Err(format!(
                    "paths must name 1 to {MAX_TEST_PATHS} capsule-relative .py files for pytest"
                ));
            }
            if let Some(path) = paths.iter().find(|path| !valid_test_path(path)) {
                return Err(format!(
                    "paths: {path:?} is not a capsule-relative .py test file for pytest"
                ));
            }
        }
        TestSelection::Cargo(cargo) => {
            let names = [Some(&cargo.package), cargo.test.as_ref()];
            if let Some(name) = names
                .into_iter()
                .flatten()
                .find(|name| !valid_cargo_name(name))
            {
                return Err(format!(
                    "cargo: {name:?} is not a Cargo package or target name"
                ));
            }
            if let Some(filter) = cargo
                .filter
                .as_ref()
                .filter(|filter| !valid_test_filter(filter))
            {
                return Err(format!("cargo: {filter:?} is not a test-name filter"));
            }
        }
        TestSelection::Attr(Some(attr)) if !valid_attr(attr) => {
            return Err(format!("{attr:?} is not a flake output name"));
        }
        TestSelection::Attr(_) => {}
    }
    Ok(())
}

pub(super) fn valid_test_path(path: &str) -> bool {
    (1..=200).contains(&path.len())
        && path.ends_with(".py")
        && !path.starts_with('/')
        && !path.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.starts_with('-'))
}

/// A Cargo package or target name; never an option.
fn valid_cargo_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

/// A test-name substring (`module::test`); never an option.
fn valid_test_filter(filter: &str) -> bool {
    (1..=200).contains(&filter.len())
        && filter.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && filter
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cargo_selection_cannot_smuggle_an_option_or_a_second_argument() {
        let selection = |package: &str, test: Option<&str>, filter: Option<&str>| {
            TestSelection::Cargo(odin_hermes::runtime::coding::CargoTests {
                package: package.to_owned(),
                test: test.map(str::to_owned),
                filter: filter.map(str::to_owned),
            })
        };
        assert!(
            check_selection(&selection("odin-cli", Some("lib"), Some("coding::tests"))).is_ok()
        );
        for bad in [
            selection("--manifest-path=x", None, None),
            selection("odin-cli", Some("a b"), None),
            selection("odin-cli", None, Some("x;y")),
            selection("odin-cli", None, Some("-- --ignored")),
        ] {
            assert!(check_selection(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_definition_regex_finds_definitions_in_a_real_repository() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("a.rs"),
            "pub fn parse_tests() {}\nlet x = parse_tests();\n",
        )
        .unwrap();
        std::fs::write(
            root.join("b.py"),
            "class parse_tests_helper:\n    pass\ndef parse_tests():\n    pass\n",
        )
        .unwrap();
        std::process::Command::new(super::super::program("git"))
            .args(["init", "-q"])
            .current_dir(root)
            .status()
            .unwrap();
        let route = DaemonCodingRoute {
            state_root: root.to_owned(),
            session_pool: None,
            supervisor: Default::default(),
            registry: None,
            projects: Default::default(),
            manifest: None,
            merge_lock_bound: crate::coding_route::MERGE_LOCK_BOUND,
        };
        // The search itself, below the pool that owns it in production.
        let runner = &super::super::Unowned;
        let definition = CodeQuery::Definition("parse_tests".to_owned());
        let found = route
            .search_code_blocking(runner, root, &definition, 10)
            .unwrap();
        let files: Vec<(&str, u64)> = found["matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| (m["file"].as_str().unwrap(), m["line"].as_u64().unwrap()))
            .collect();
        assert_eq!(files, vec![("a.rs", 1), ("b.py", 3)]);
        let references = CodeQuery::References("parse_tests".to_owned());
        let references = route
            .search_code_blocking(runner, root, &references, 10)
            .unwrap();
        assert_eq!(references["matches"].as_array().unwrap().len(), 3);
    }
}
