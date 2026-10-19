//! Parses diagnostics and test results from Nix `--print-build-logs` output.
//! Unrecognized output yields an empty report, never an inferred pass.

use serde::Serialize;

/// Most diagnostics or failures one report carries.
pub const MAX_REPORT_ITEMS: usize = 100;
const MAX_MESSAGE_BYTES: usize = 400;

/// One compiler, linter or type-checker finding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    pub severity: Severity,
    pub file: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

/// Every diagnostic found (bounded) and the full counts.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsReport {
    pub errors: usize,
    pub warnings: usize,
    pub diagnostics: Vec<Diagnostic>,
    pub truncated: bool,
}

/// One failed test, with its failure message when the log shows one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestFailure {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// The test totals across every suite the log reports.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestReport {
    /// The harness formats recognized (`libtest`, `nextest`, `pytest`).
    /// Empty means no test output was recognized — not that tests passed.
    pub frameworks: Vec<&'static str>,
    pub passed: u64,
    pub failed: u64,
    pub ignored: u64,
    pub failures: Vec<TestFailure>,
}

/// Strips Nix's `--print-build-logs` line prefix (`drv-name> `) and the
/// sandbox source root, so paths read as repository paths.
fn clean(line: &str) -> &str {
    let line = match line.split_once("> ") {
        Some((prefix, rest))
            if !prefix.is_empty()
                && prefix
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-')) =>
        {
            rest
        }
        _ => line,
    };
    line.trim_end()
}

fn repo_path(path: &str) -> String {
    let path = path.trim();
    if let Some(rest) = path.strip_prefix("/build/") {
        // `/build/source/src/x.rs` or `/build/<unpacked-name>/src/x.rs`.
        if let Some((_, inner)) = rest.split_once('/') {
            return inner.to_owned();
        }
    }
    path.to_owned()
}

fn bounded(message: &str) -> String {
    let message = message.trim();
    if message.len() <= MAX_MESSAGE_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &message[..end])
}

/// `path:line[:col]` → parts, when `path` looks like a source file.
fn location(text: &str) -> Option<(String, u32, Option<u32>)> {
    let mut parts = text.trim().rsplitn(3, ':');
    let last = parts.next()?;
    let middle = parts.next()?;
    match parts.next() {
        Some(path) => {
            let line = middle.parse().ok()?;
            let column = last.parse().ok()?;
            source_path(path).then(|| (repo_path(path), line, Some(column)))
        }
        None => {
            let line = last.parse().ok()?;
            source_path(middle).then(|| (repo_path(middle), line, None))
        }
    }
}

fn source_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(char::is_whitespace)
        && path
            .rsplit_once('.')
            .is_some_and(|(_, extension)| (1..=5).contains(&extension.len()))
}

/// Parses compiler diagnostics: rustc/clippy (`error[E0308]: …` then
/// `--> path:line:col`), the common `path:line:col: severity: message`
/// form (gcc, clang, mypy, eslint's unix formatter) and tsc's
/// `path(line,col): error TS2304: message`.
pub fn parse_diagnostics(log: &str) -> DiagnosticsReport {
    let mut report = DiagnosticsReport::default();
    let mut seen = std::collections::BTreeSet::new();
    let mut pending: Option<(Severity, Option<String>, String)> = None;
    for raw in log.lines() {
        let line = clean(raw);
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("--> ") {
            if let (Some((severity, code, message)), Some((file, number, column))) =
                (pending.take(), location(rest))
            {
                push(
                    &mut report,
                    &mut seen,
                    Diagnostic {
                        severity,
                        file,
                        line: number,
                        column,
                        code,
                        message,
                    },
                );
            }
            continue;
        }
        if let Some(header) = rustc_header(trimmed) {
            pending = Some(header);
            continue;
        }
        if let Some(diagnostic) = tsc_line(trimmed).or_else(|| colon_line(trimmed)) {
            push(&mut report, &mut seen, diagnostic);
        }
    }
    report
}

fn push(
    report: &mut DiagnosticsReport,
    seen: &mut std::collections::BTreeSet<(String, u32, Option<u32>, String)>,
    diagnostic: Diagnostic,
) {
    // The same finding is printed once per build that compiles the crate
    // (check, clippy, test); count it once.
    let key = (
        diagnostic.file.clone(),
        diagnostic.line,
        diagnostic.column,
        diagnostic.message.clone(),
    );
    if !seen.insert(key) {
        return;
    }
    match diagnostic.severity {
        Severity::Error => report.errors += 1,
        Severity::Warning => report.warnings += 1,
    }
    if report.diagnostics.len() < MAX_REPORT_ITEMS {
        report.diagnostics.push(diagnostic);
    } else {
        report.truncated = true;
    }
}

/// `error[E0308]: mismatched types`, `warning: unused variable: x`.
fn rustc_header(line: &str) -> Option<(Severity, Option<String>, String)> {
    let (severity, rest) = match line.strip_prefix("error") {
        Some(rest) => (Severity::Error, rest),
        None => (Severity::Warning, line.strip_prefix("warning")?),
    };
    let (code, message) = if let Some(rest) = rest.strip_prefix('[') {
        let (code, message) = rest.split_once("]: ")?;
        (Some(code.to_owned()), message)
    } else {
        (None, rest.strip_prefix(": ")?)
    };
    // Summary lines (`error: could not compile …`, `warning: 3 warnings
    // emitted`) carry no location and never get one.
    Some((severity, code, bounded(message)))
}

/// `src/a.ts(3,7): error TS2304: Cannot find name 'x'.`
fn tsc_line(line: &str) -> Option<Diagnostic> {
    let (path, rest) = line.split_once('(')?;
    let (position, rest) = rest.split_once("): ")?;
    let (row, column) = position.split_once(',')?;
    if !source_path(path) {
        return None;
    }
    let (severity, rest) = severity_word(rest)?;
    let (code, message) = match rest.split_once(": ") {
        Some((code, message)) if code.starts_with("TS") => (Some(code.to_owned()), message),
        _ => (None, rest),
    };
    Some(Diagnostic {
        severity,
        file: repo_path(path),
        line: row.parse().ok()?,
        column: column.parse().ok(),
        code,
        message: bounded(message),
    })
}

/// `path:line:col: error: message` / `path:line: warning: message`.
fn colon_line(line: &str) -> Option<Diagnostic> {
    let (head, rest) = line.split_once(": ")?;
    let (file, number, column) = location(head)?;
    let (severity, rest) = severity_word(rest)?;
    let message = rest.strip_prefix(": ").unwrap_or(rest);
    Some(Diagnostic {
        severity,
        file,
        line: number,
        column,
        code: None,
        message: bounded(message),
    })
}

fn severity_word(text: &str) -> Option<(Severity, &str)> {
    if let Some(rest) = text.strip_prefix("error") {
        Some((Severity::Error, rest.trim_start_matches(':').trim_start()))
    } else if let Some(rest) = text.strip_prefix("warning") {
        Some((Severity::Warning, rest.trim_start_matches(':').trim_start()))
    } else {
        None
    }
}

/// Parses test results: libtest (`cargo test`), nextest and pytest
/// summaries plus their named failures and failure messages.
pub fn parse_tests(log: &str) -> TestReport {
    let mut report = TestReport::default();
    let recognize = |report: &mut TestReport, framework: &'static str| {
        if !report.frameworks.contains(&framework) {
            report.frameworks.push(framework);
        }
    };
    let mut panics: Vec<(String, String)> = Vec::new();
    let lines: Vec<&str> = log.lines().map(clean).collect();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("test result: ") {
            recognize(&mut report, "libtest");
            report.passed += count_before(rest, " passed");
            report.failed += count_before(rest, " failed");
            report.ignored += count_before(rest, " ignored");
        } else if let Some(name) = trimmed
            .strip_prefix("test ")
            .and_then(|rest| rest.strip_suffix(" ... FAILED"))
        {
            add_failure(&mut report, name);
        } else if let Some(rest) = trimmed.strip_prefix("thread '") {
            // `thread 'a::b' panicked at src/x.rs:3:5:` then the message.
            if let Some((name, _)) = rest.split_once("' panicked at") {
                if let Some(message) = lines.get(index + 1) {
                    panics.push((name.to_owned(), bounded(message)));
                }
            }
        } else if trimmed.starts_with("Summary [") && trimmed.contains(" tests run: ") {
            recognize(&mut report, "nextest");
            if let Some((_, counts)) = trimmed.split_once(" tests run: ") {
                report.passed += count_before(counts, " passed");
                report.failed += count_before(counts, " failed");
                report.ignored += count_before(counts, " skipped");
            }
        } else if let Some(rest) = trimmed.strip_prefix("FAIL [") {
            if let Some((_, name)) = rest.split_once("] ") {
                add_failure(&mut report, name.trim());
            }
        } else if let Some(summary) = pytest_summary(trimmed) {
            recognize(&mut report, "pytest");
            report.passed += count_before(summary, " passed");
            report.failed += count_before(summary, " failed") + count_before(summary, " error");
            report.ignored += count_before(summary, " skipped");
        } else if let Some(rest) = trimmed.strip_prefix("FAILED ") {
            let (name, message) = match rest.split_once(" - ") {
                Some((name, message)) => (name, Some(bounded(message))),
                None => (rest, None),
            };
            add_failure(&mut report, name.trim());
            if let (Some(message), Some(failure)) = (message, report.failures.last_mut()) {
                failure.message.get_or_insert(message);
            }
        }
    }
    for (name, message) in panics {
        if let Some(failure) = report.failures.iter_mut().find(|f| f.name == name) {
            failure.message.get_or_insert(message);
        }
    }
    report
}

fn add_failure(report: &mut TestReport, name: &str) {
    if report.failures.iter().any(|failure| failure.name == name) {
        return;
    }
    if report.failures.len() < MAX_REPORT_ITEMS {
        report.failures.push(TestFailure {
            name: name.to_owned(),
            message: None,
        });
    }
}

/// `===== 1 failed, 3 passed, 1 skipped in 0.12s =====` → the counts part.
fn pytest_summary(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('=')?.trim_matches('=').trim();
    let (counts, _) = inner.rsplit_once(" in ")?;
    (counts.contains(" passed") || counts.contains(" failed") || counts.contains(" error"))
        .then_some(counts)
}

/// The integer right before `label` (`"9 passed; 0 failed"`, " failed" → 0).
fn count_before(text: &str, label: &str) -> u64 {
    let Some(position) = text.find(label) else {
        return 0;
    };
    text[..position]
        .rsplit(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUST_LOG: &str = "\
odin-clippy> error[E0308]: mismatched types
odin-clippy>    --> /build/source/crates/odin-cli/src/checkout.rs:306:27
odin-clippy>     |
odin-clippy> 306 |             causation_id: causation,
odin-clippy> warning: unused variable: `x`
odin-clippy>   --> crates/odin-hermes/src/lib.rs:3:9
odin-clippy> error: could not compile `odin-cli` (lib) due to 1 previous error
odin-test> error[E0308]: mismatched types
odin-test>    --> /build/source/crates/odin-cli/src/checkout.rs:306:27
";

    #[test]
    fn rustc_and_clippy_diagnostics_are_located_and_deduplicated() {
        let report = parse_diagnostics(RUST_LOG);
        assert_eq!((report.errors, report.warnings), (1, 1));
        assert_eq!(
            report.diagnostics[0],
            Diagnostic {
                severity: Severity::Error,
                file: "crates/odin-cli/src/checkout.rs".to_owned(),
                line: 306,
                column: Some(27),
                code: Some("E0308".to_owned()),
                message: "mismatched types".to_owned(),
            }
        );
        assert_eq!(report.diagnostics[1].file, "crates/odin-hermes/src/lib.rs");
    }

    #[test]
    fn common_and_tsc_formats_are_recognized() {
        let report = parse_diagnostics(
            "src/main.c:12:5: error: implicit declaration of function 'f'\n\
             app/models.py:40: error: Incompatible return value  [return-value]\n\
             src/a.ts(3,7): error TS2304: Cannot find name 'x'.\n\
             note: this line is noise\n",
        );
        assert_eq!(report.errors, 3);
        assert_eq!(report.diagnostics[1].column, None);
        assert_eq!(report.diagnostics[2].code.as_deref(), Some("TS2304"));
        assert_eq!(report.diagnostics[2].line, 3);
    }

    #[test]
    fn a_log_without_findings_is_an_empty_report() {
        let report = parse_diagnostics("building '/nix/store/abc.drv'...\nok\n");
        assert_eq!(report, DiagnosticsReport::default());
    }

    #[test]
    fn libtest_totals_and_failures_with_panic_messages() {
        let report = parse_tests(
            "odin-test> test a::passes ... ok\n\
             odin-test> test a::breaks ... FAILED\n\
             odin-test> thread 'a::breaks' panicked at src/a.rs:9:5:\n\
             odin-test> assertion `left == right` failed\n\
             odin-test> test result: FAILED. 9 passed; 1 failed; 2 ignored; 0 measured; 0 filtered out\n\
             odin-test> test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
        );
        assert_eq!(report.frameworks, vec!["libtest"]);
        assert_eq!((report.passed, report.failed, report.ignored), (13, 1, 2));
        assert_eq!(
            report.failures,
            vec![TestFailure {
                name: "a::breaks".to_owned(),
                message: Some("assertion `left == right` failed".to_owned()),
            }]
        );
    }

    #[test]
    fn pytest_and_nextest_summaries() {
        let pytest = parse_tests(
            "FAILED tests/test_x.py::test_y - AssertionError: 2 != 3\n\
             ========= 1 failed, 10 passed, 1 skipped in 0.42s =========\n",
        );
        assert_eq!(pytest.frameworks, vec!["pytest"]);
        assert_eq!((pytest.passed, pytest.failed, pytest.ignored), (10, 1, 1));
        assert_eq!(
            pytest.failures[0].message.as_deref(),
            Some("AssertionError: 2 != 3")
        );
        let nextest = parse_tests(
            "        FAIL [   0.004s] odin-hermes purchase::tests::breaks\n\
             Summary [   1.204s] 12 tests run: 11 passed, 1 failed, 3 skipped\n",
        );
        assert_eq!(nextest.frameworks, vec!["nextest"]);
        assert_eq!(
            (nextest.passed, nextest.failed, nextest.ignored),
            (11, 1, 3)
        );
        assert_eq!(
            nextest.failures[0].name,
            "odin-hermes purchase::tests::breaks"
        );
    }

    #[test]
    fn unrecognized_output_never_reads_as_a_pass() {
        let report = parse_tests("all good!\n");
        assert!(report.frameworks.is_empty());
        assert_eq!((report.passed, report.failed), (0, 0));
    }
}
