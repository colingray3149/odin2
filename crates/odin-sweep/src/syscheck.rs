//! Retired check IDs remain unused so existing IDs stay stable.
//! Checks read actual runtime state; missing prerequisites cannot pass.
//! Disposable state stays under SystemContext::scratch_root without changing live services or credentials.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use odin_huginn::{OdindConfig, RuntimeManifest};
#[cfg(test)]
use odin_ledger::Ledger;
use odin_process::BusAddress;
use odin_registry::GatewayProjectionManifest;
use rusqlite::{Connection, OpenFlags};
#[cfg(test)]
use serde_json::json;
use serde_json::Value as JsonValue;
use walkdir::WalkDir;

use crate::report::{repository_build_contract, CheckResult, CheckStatus};
use crate::runner;

const SYSTEM_DEFINITIONS: [(&str, &str, u64); 11] = [
    ("SYS-01", "Self/config/schema integrity", 60),
    ("SYS-02", "Source/runtime pin integrity", 60),
    ("SYS-03", "Private/loopback listener policy", 30),
    ("SYS-04", "Secrets hygiene", 300),
    ("SYS-05", "Free-space thresholds", 120),
    ("SYS-06", "Activation drift", 300),
    ("SYS-07", "Configured service health", 60),
    ("SYS-08", "Ledger integrity", 120),
    ("SYS-09", "Gateway consistency", 30),
    ("SYS-11", "last backup on pc younger than 30 h", 60),
    ("SYS-12", "Workspace hygiene", 60),
];

/// Hard free-space floor on any distinct backing filesystem.
const MIN_FREE_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// Advisory free-space floor: between this and the hard floor only flags.
const CLEAR_FREE_BYTES: u64 = 20 * 1024 * 1024 * 1024;
const INPUT_FILE_CAP_BYTES: u64 = 8 * 1024 * 1024;
const EXECUTABLE_CAP_BYTES: u64 = 512 * 1024 * 1024;
const OUTPUT_CAP_BYTES: usize = 256 * 1024;
const WALK_ENTRY_CAP: usize = 4_096;
const TRACKED_ROW_CAP: usize = 32_768;

const PACKAGE_BUILD_SCHEMA: &str = "odin.package-build-identity.v1";

#[derive(Clone, Debug)]
pub struct SystemContext {
    pub odin_root: PathBuf,
    pub dotfiles_root: PathBuf,
    pub runtime_manifest: Option<PathBuf>,
    pub scratch_root: PathBuf,
}

/// Dotfiles-root precedence: an explicit caller override (`--dotfiles-root`
/// or `DOTFILES_ROOT`) beats the declared host-facts `dotfilesRoot`, which
/// beats the `~/dotfiles` default. The declared path is the checkout the
/// dotfiles generation deployed; the explicit override exists for
/// out-of-band runs against a different checkout.
pub fn resolve_dotfiles_root(explicit: Option<PathBuf>, declared: Option<PathBuf>) -> PathBuf {
    explicit.or(declared).unwrap_or_else(default_dotfiles_root)
}

/// The dotfiles checkout declared by the host facts, when the facts are
/// present, readable, and carry `dotfilesRoot`. A failed facts load is
/// deliberately not surfaced here — every facts-consuming check loads the
/// facts itself and type-fails loudly; this resolution only picks the
/// root the checks read.
pub fn declared_dotfiles_root() -> Option<PathBuf> {
    load_host_facts()
        .ok()
        .flatten()
        .and_then(|facts| facts.dotfiles_root)
}

fn default_dotfiles_root() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join("dotfiles")
}

/// Checks that verify the authority's Odin composition (runtime manifest,
/// odind, ledger, backups). A follower carries none of it, so there they
/// are N/A instead of BLOCKED/FAIL; secrets, disk, activation drift,
/// gateway and workspace hygiene run on every host.
const AUTHORITY_ONLY_CHECKS: [&str; 6] =
    ["SYS-01", "SYS-02", "SYS-03", "SYS-07", "SYS-08", "SYS-11"];

/// True only when the host facts explicitly declare a follower; missing or
/// unreadable facts keep the full authority set (the facts-consuming checks
/// report the facts failure themselves).
fn declared_follower() -> bool {
    matches!(
        load_host_facts(),
        Ok(Some(HostFacts {
            odin_authority: Some(false),
            ..
        }))
    )
}

/// Runs exactly one check per registered id against the real runtime.
///
/// A panicking check body still yields an explicit FAIL result so the sweep
/// always emits every registered result.
pub fn run_all_system_checks(context: &SystemContext) -> Vec<CheckResult> {
    let follower = declared_follower();
    SYSTEM_DEFINITIONS
        .iter()
        .map(|(id, name, timeout_seconds)| {
            if follower && AUTHORITY_ONLY_CHECKS.contains(id) {
                return bake_result(
                    id,
                    name,
                    Instant::now(),
                    CheckStatus::NotApplicable,
                    "authority-only; the host facts declare this host an Odin follower".to_owned(),
                    None,
                    Vec::new(),
                );
            }
            let deadline = check_deadline(Instant::now(), *timeout_seconds);
            let body = || match *id {
                "SYS-01" => run_sys_01(context, deadline),
                "SYS-02" => run_sys_02(context, deadline),
                "SYS-03" => run_sys_03(context, deadline),
                "SYS-04" => run_sys_04(context, deadline),
                "SYS-05" => run_sys_05(context, deadline),
                "SYS-06" => run_sys_06(context, deadline),
                "SYS-07" => run_sys_07(context, deadline),
                "SYS-08" => run_sys_08(context, deadline),
                "SYS-09" => run_sys_09(context, deadline),
                "SYS-11" => run_sys_11(context, deadline),
                "SYS-12" => run_sys_12(context, deadline),
                other => {
                    unreachable!("SYSTEM_DEFINITIONS contains only registered ids, got {other}")
                }
            };
            match catch_unwind(AssertUnwindSafe(body)) {
                Ok(result) => result,
                Err(_) => bake_result(
                    id,
                    name,
                    Instant::now(),
                    CheckStatus::Fail,
                    format!("{id} panicked while checking the live system"),
                    Some("internal-panic".to_owned()),
                    Vec::new(),
                ),
            }
        })
        .collect()
}

/// A checked condition that ends the check early with a non-Pass verdict.
#[derive(Debug, Clone)]
struct CheckFailure {
    status: CheckStatus,
    summary: String,
    reason: String,
    evidence: Vec<String>,
}

impl CheckFailure {
    fn fail(reason: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Fail,
            summary: summary.into(),
            reason: reason.into(),
            evidence: Vec::new(),
        }
    }

    fn blocked(reason: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Blocked,
            summary: summary.into(),
            reason: reason.into(),
            evidence: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct CheckOutcome {
    status: CheckStatus,
    summary: String,
    reason: Option<String>,
    evidence: Vec<String>,
}

impl CheckOutcome {
    fn pass(summary: impl Into<String>, evidence: Vec<String>) -> Result<Self, CheckFailure> {
        Ok(Self {
            status: CheckStatus::Pass,
            summary: summary.into(),
            reason: None,
            evidence,
        })
    }

    fn flagged(
        reason: impl Into<String>,
        summary: impl Into<String>,
        evidence: Vec<String>,
    ) -> Result<Self, CheckFailure> {
        Ok(Self {
            status: CheckStatus::Flag,
            summary: summary.into(),
            reason: Some(reason.into()),
            evidence,
        })
    }
}

type Outcome = Result<CheckOutcome, CheckFailure>;

fn check_deadline(started: Instant, timeout_seconds: u64) -> Instant {
    started
        .checked_add(Duration::from_secs(timeout_seconds.min(300)))
        .unwrap_or(started)
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn bake_result(
    id: &str,
    name: &str,
    started: Instant,
    status: CheckStatus,
    summary: String,
    reason: Option<String>,
    evidence: Vec<String>,
) -> CheckResult {
    let mut result = CheckResult::new(id, name, status, elapsed_millis(started), summary, evidence);
    if let Some(reason) = reason {
        result = result.with_reason(reason);
    }
    result
}

fn run_check(
    id: &'static str,
    body: fn(&SystemContext, Instant) -> Outcome,
    context: &SystemContext,
    deadline: Instant,
) -> CheckResult {
    let started = Instant::now();
    bake(id, check_name(id), started, body(context, deadline))
}

/// Display name registered for `id`. A missing registration is a programming
/// error: every check stamps the name from [`SYSTEM_DEFINITIONS`], never a
/// positional index that drifts when a retired id is removed.
fn check_name(id: &str) -> &'static str {
    SYSTEM_DEFINITIONS
        .iter()
        .find(|(registered, _, _)| *registered == id)
        .map(|(_, name, _)| *name)
        .unwrap_or_else(|| panic!("SYSTEM_DEFINITIONS has no {id}"))
}

fn bake(id: &str, name: &str, started: Instant, outcome: Outcome) -> CheckResult {
    match outcome {
        Ok(outcome) => bake_result(
            id,
            name,
            started,
            outcome.status,
            outcome.summary,
            outcome.reason,
            outcome.evidence,
        ),
        Err(failure) => bake_result(
            id,
            name,
            started,
            failure.status,
            failure.summary,
            Some(failure.reason),
            failure.evidence,
        ),
    }
}

fn note_evidence(evidence: &mut Vec<String>, note: impl Into<String>) {
    if evidence.len() < 8 {
        let note = note.into();
        evidence.push(note.chars().take(200).collect());
    }
}

pub(crate) mod probe;
use probe::*;
mod sys_01;
use sys_01::run_sys_01;
mod sys_02;
use sys_02::run_sys_02;
mod sys_03;
use sys_03::run_sys_03;
mod sys_04;
use sys_04::run_sys_04;
mod sys_05;
use sys_05::run_sys_05;
mod sys_06;
use sys_06::run_sys_06;
mod sys_07;
use sys_07::run_sys_07;
mod sys_08;
use sys_08::run_sys_08;
mod sys_09;
use sys_09::run_sys_09;
mod sys_11;
use sys_11::run_sys_11;
mod sys_12;
use sys_12::run_sys_12;

// behavior tests: result invariants and pure predicates only.
// These never touch the live system.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_endpoint_parsing_rejects_malformed_authorities() {
        assert_eq!(
            parse_listener_endpoint("127.0.0.1:8082"),
            Some(("127.0.0.1".to_owned(), 8082))
        );
        assert_eq!(
            parse_listener_endpoint("[::1]:4000"),
            Some(("::1".to_owned(), 4000))
        );
        assert_eq!(
            parse_listener_endpoint("fe80::1%25:9999"),
            Some(("fe80::1".to_owned(), 9999))
        );
        assert_eq!(parse_listener_endpoint("127.0.0.1:http"), None);
        assert_eq!(parse_listener_endpoint("no-port"), None);
    }

    #[test]
    fn private_binding_policy_never_admits_wildcards_or_foreign_hosts() {
        assert!(host_allowed("127.0.0.1", "127.0.0.1"));
        assert!(host_allowed("127.0.0.1", "127.0.0.2"));
        assert!(host_allowed("127.0.0.1", "::1"));
        assert!(!host_allowed("127.0.0.1", "0.0.0.0"));
        assert!(!host_allowed("127.0.0.1", "*"));
        assert!(!host_allowed("127.0.0.1", "::"));
        assert!(!host_allowed("127.0.0.1", "192.168.7.41"));
        assert!(!host_allowed("100.64.0.1", "127.0.0.1"));
    }

    #[test]
    fn listener_owner_parsing_requires_an_explicit_pid() {
        let line = "LISTEN 0 128 127.0.0.1:8082 0.0.0.0:* users:((\"zellij\",pid=1234,fd=9))";
        assert_eq!(listener_owner_pid(line), Some(1234));
        assert_eq!(listener_owner_pid("LISTEN 0 128 *:22 0.0.0.0:*"), None);
    }

    #[test]
    fn flake_revision_extraction_rejects_absent_pins() {
        let lock = json!({
            "nodes": {
                "root": {"inputs": {"odin": "odin-node", "omp": "omp-node"}},
                "odin-node": {"locked": {"rev": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
                "omp-node": {"locked": {}}
            }
        });
        assert_eq!(
            flake_locked_revision(&lock, "odin"),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned())
        );
        assert_eq!(flake_locked_revision(&lock, "omp"), None);
        assert_eq!(flake_locked_revision(&lock, "nixpkgs"), None);
    }

    #[test]
    fn pin_revision_shape_requires_lowercase_40_hex() {
        assert!(lower_hex(&"a".repeat(40), 40));
        assert!(!lower_hex(&"A".repeat(40), 40));
        assert!(!lower_hex("abc", 40));
    }

    #[test]
    fn package_build_metadata_lookup_namespaces_by_cargo_package() {
        let store_root = Path::new("/nix/store/aaa-odin-sweep");
        assert_eq!(
            package_build_metadata_path(store_root, "odin-sweep"),
            PathBuf::from("/nix/store/aaa-odin-sweep/share/odin/odin-sweep/package-build.json")
        );
        // Distinct first-party cargo packages never resolve to one shared
        // metadata path, so coinstalled packages cannot collide in a profile.
        assert_ne!(
            package_build_metadata_path(store_root, "odin-sweep"),
            package_build_metadata_path(store_root, "odin-launch")
        );
    }

    #[test]
    fn credential_path_detection_flags_names_and_spares_sops_declarations() {
        assert!(is_credential_shaped_path(".env"));
        assert!(is_credential_shaped_path("deploy/.env.production"));
        assert!(is_credential_shaped_path("server.pem"));
        assert!(is_credential_shaped_path("keys/host.key"));
        assert!(is_credential_shaped_path("id_ed25519"));
        assert!(is_credential_shaped_path(".netrc"));
        assert!(!is_credential_shaped_path("modules/secrets.yaml"));
        assert!(!is_credential_shaped_path("src/syscheck.rs"));
        assert!(!is_credential_shaped_path("README.md"));
    }

    #[test]
    fn gitignore_contract_requires_the_full_rule_set() {
        let complete = "/target/\n/state/\n/artifacts/\n/result\n/result-*\n.direnv/\n";
        assert!(gitignore_missing_rules(complete).is_empty());
        let missing = gitignore_missing_rules("/target/\n# comment\n");
        assert_eq!(
            missing,
            vec!["/state/", "/artifacts/", "/result", "/result-*", ".direnv/"]
        );
    }

    #[test]
    fn tracked_hygiene_flags_runtime_and_result_content() {
        let root = Path::new("/");
        assert_eq!(
            tracked_hygiene_violation("state/ledger.sqlite3", root),
            Some("tracked-runtime-content")
        );
        assert_eq!(
            tracked_hygiene_violation("nested/target/debug", root),
            Some("tracked-runtime-content")
        );
        assert_eq!(
            tracked_hygiene_violation("config/.env.local", root),
            Some("tracked-dotenv")
        );
        assert_eq!(tracked_hygiene_violation("src/main.rs", root), None);
        assert_eq!(
            tracked_hygiene_violation("artifacts/run.json", root),
            Some("tracked-runtime-content")
        );
        assert_eq!(
            tracked_hygiene_violation("crates/odin-brain/src/source/state/live.rs", root),
            None,
            "a source module named after state is not runtime content"
        );
    }

    #[test]
    fn budget_decimal_shape_rejects_leading_zeros_and_overflow() {
        assert!(decimal_budget_ok("30"));
        assert!(decimal_budget_ok("0.5"));
        assert!(decimal_budget_ok("12.34"));
        assert!(!decimal_budget_ok(""));
        assert!(!decimal_budget_ok("030"));
        assert!(!decimal_budget_ok("1234567890123"));
        assert!(!decimal_budget_ok("-30"));
        assert!(!decimal_budget_ok("1.234"));
        assert!(!decimal_budget_ok("abc"));
    }

    #[test]
    fn yaml_model_extraction_rejects_duplicates_and_bad_ids() {
        let valid = serde_yaml::from_str::<serde_yaml::Value>(
            "model_list:\n  - model_name: lane-a\n  - model_name: lane-b\n",
        )
        .unwrap();
        let names = yaml_model_names(&valid, &["model_list"], "model_name").unwrap();
        assert_eq!(names.len(), 2);
        let duplicated = serde_yaml::from_str::<serde_yaml::Value>(
            "model_list:\n  - model_name: lane-a\n  - model_name: lane-a\n",
        )
        .unwrap();
        assert!(yaml_model_names(&duplicated, &["model_list"], "model_name").is_none());
        let numeric =
            serde_yaml::from_str::<serde_yaml::Value>("model_list:\n  - model_name: 7\n").unwrap();
        assert!(yaml_model_names(&numeric, &["model_list"], "model_name").is_none());
        let empty = serde_yaml::from_str::<serde_yaml::Value>("model_list: []\n").unwrap();
        assert!(yaml_model_names(&empty, &["model_list"], "model_name").is_none());
    }

    #[test]
    fn budget_scalar_equality_compares_like_scalars_only() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>("30").unwrap();
        assert!(yaml_json_scalar_equal(Some(&yaml), Some(&json!("30"))));
        assert!(!yaml_json_scalar_equal(Some(&yaml), Some(&json!("31"))));
        assert!(!yaml_json_scalar_equal(None, Some(&json!("30"))));
        assert!(!yaml_json_scalar_equal(Some(&yaml), None));
        let fractional = serde_yaml::from_str::<serde_yaml::Value>("30.0").unwrap();
        assert!(yaml_json_scalar_equal(
            Some(&fractional),
            Some(&json!("30.00"))
        ));
        assert!(!yaml_json_scalar_equal(
            Some(&fractional),
            Some(&json!("30.01"))
        ));
        assert!(!yaml_json_scalar_equal(Some(&yaml), Some(&json!(true))));
    }

    #[test]
    fn safe_identifiers_reject_paths_and_empty_names() {
        assert!(is_safe_identifier("laptop"));
        assert!(is_safe_identifier("hermes-agent.service"));
        assert!(!is_safe_identifier(""));
        assert!(!is_safe_identifier("../../etc"));
        assert!(!is_safe_identifier("host name"));
    }

    #[test]
    fn df_output_parser_takes_the_final_measurement() {
        assert_eq!(parse_last_u64(b"Avail\n499122176000\n"), Some(499122176000));
        assert_eq!(parse_last_u64(b""), None);
        assert_eq!(parse_last_u64(b"Avail\n"), None);
    }

    #[test]
    fn endpoint_url_parsing_accepts_only_host_port_authorities() {
        assert_eq!(
            endpoint_host_port("http://127.0.0.1:4000/v1"),
            Some(("127.0.0.1".to_owned(), 4000))
        );
        assert_eq!(endpoint_host_port("http://127.0.0.1/v1"), None);
        assert_eq!(endpoint_host_port("ftp://127.0.0.1:4000"), None);
    }

    #[test]
    fn dotfiles_root_precedence_is_explicit_then_declared_then_default() {
        let explicit = PathBuf::from("/explicit/dotfiles");
        let declared = PathBuf::from("/declared/dotfiles");
        // The explicit --dotfiles-root/DOTFILES_ROOT override beats the
        // declared facts root...
        assert_eq!(
            resolve_dotfiles_root(Some(explicit.clone()), Some(declared.clone())),
            explicit
        );
        // ...the declared facts root beats the ~/dotfiles default...
        assert_eq!(
            resolve_dotfiles_root(None, Some(declared.clone())),
            declared
        );
        // ...and an explicit override stands alone.
        assert_eq!(
            resolve_dotfiles_root(Some(explicit.clone()), None),
            explicit
        );
    }

    #[test]
    fn declared_facts_dotfiles_root_wins_without_an_explicit_override() {
        let body = r#"{"schema":"odin.sweep-host-facts.v1","host":"pc","candidateRevision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bootloader":"other","zellijWeb":{"enabled":false,"ip":"127.0.0.1","port":1},"sopsRenderedDirs":[],"dotfilesRoot":"/declared/by-facts"}"#;
        let root = tempfile::tempdir().expect("facts fixture root is creatable");
        let path = root.path().join("host-facts.json");
        std::fs::write(&path, body).expect("facts fixture is writable");
        let declared = load_host_facts_from(Some(&path))
            .expect("the declared facts parse")
            .expect("present")
            .dotfiles_root
            .expect("the facts carry dotfilesRoot");
        assert_eq!(
            resolve_dotfiles_root(None, Some(declared)),
            PathBuf::from("/declared/by-facts")
        );
    }

    #[test]
    fn facts_without_dotfiles_root_keep_the_legacy_default_behavior() {
        let body = r#"{"schema":"odin.sweep-host-facts.v1","host":"pc","candidateRevision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bootloader":"other","zellijWeb":{"enabled":false,"ip":"127.0.0.1","port":1},"sopsRenderedDirs":[]}"#;
        let root = tempfile::tempdir().expect("facts fixture root is creatable");
        let path = root.path().join("host-facts.json");
        std::fs::write(&path, body).expect("facts fixture is writable");
        let declared = load_host_facts_from(Some(&path))
            .expect("the declared facts parse")
            .expect("present")
            .dotfiles_root;
        assert_eq!(declared, None);
    }
}
