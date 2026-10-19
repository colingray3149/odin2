//! Vault integration tests for `odin_hermes::vault`.
//!
//! Offline layer (always runs, no services):
//! 1. retrieval scope and exclusions — the pure policy admits only
//!    configured general namespaces and the generated namespace, never any
//!    page carrying an excluded (private) segment at any depth;
//! 2. generated-only machine writes — exact confined bytes beneath the
//!    generated namespace, with traversal, namespace escapes, symlinked
//!    components, and non-generated content untouched or refused;
//! 3. typed unavailability — a missing vault root, an unprotected root, a
//!    missing SilverBullet configuration, and a dead loopback service all
//!    fail typed, never as fake successes.
//!
//! `live_loopback_smoke` (`#[ignore]`) is the later real-service check: it
//! pins the scoped vault from the actual SilverBullet server, asserts the
//! private exclusions hold against the real listing, writes exactly one
//! disposable page inside the generated namespace, reads those exact bytes
//! back over the loopback API, and removes it. It never reads private
//! personal content (listing names only) and never mutates anything outside
//! the generated namespace.
//!
//! ```text
//! cargo test -p odin-hermes --test vault
//! cargo test -p odin-hermes --test vault -- --ignored
//! ```

use std::fs::Permissions;
use std::net::TcpListener;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use odin_brain::error::BrainError;
use odin_confined_fs::ConfinedError;
use odin_domain::Digest;
use odin_hermes::vault::{
    SilverBulletConfig, VaultBridge, VaultConfig, VaultError, VaultSearchInput,
    VaultWriteGeneratedInput,
};

const GENERATED_NAMESPACE: &str = "generated";
const GENERAL_NAMESPACES: &[&str] = &["knowledge"];
const EXCLUDED_NAMESPACES: &[&str] = &["finance", "credentials", "communications"];
const SOURCE_ID: &str = "atlas.personal";

/// A validated configuration over a temporary vault root, private 0700 as
/// the deployment creates it.
fn test_config(vault_root: &Path) -> VaultConfig {
    VaultConfig {
        vault_root: vault_root.to_path_buf(),
        source_id: SOURCE_ID.to_owned(),
        silverbullet: None,
        general_namespaces: GENERAL_NAMESPACES
            .iter()
            .map(|name| name.to_string())
            .collect(),
        generated_namespace: GENERATED_NAMESPACE.to_owned(),
        excluded_namespaces: EXCLUDED_NAMESPACES
            .iter()
            .map(|name| name.to_string())
            .collect(),
        max_pages: 100,
        max_page_bytes: 64 * 1024,
        timeout_ms: 1_000,
    }
}

/// Creates a 0700 vault root, as the deployment's service does when absent.
fn private_vault_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("odin-hermes-vault-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("vault root created");
    std::fs::set_permissions(&root, Permissions::from_mode(0o700)).expect("vault root private");
    root
}

/// One free loopback port, observed by actually binding it and then
/// releasing it: the subsequent connection is genuinely refused.
fn dead_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    port
}

/// The scope policy admits general-namespace and generated pages and
/// refuses everything else: private classes at any depth, out-of-scope
/// namespaces, non-Markdown entries, and malformed or escaping paths.
#[test]
fn scope_admits_general_and_generated_and_excludes_private_namespaces() {
    let root = private_vault_root("scope");
    let bridge = VaultBridge::new(test_config(&root)).expect("valid configuration");
    std::fs::remove_dir_all(&root).ok();

    let admitted = [
        "knowledge/notes.md",
        "knowledge/deep/page.md",
        "generated/summaries/2026-09-13.md",
        "generated/page.md",
    ];
    for name in admitted {
        assert!(
            bridge.page_scoped(name),
            "{name} must be retrieval-eligible"
        );
    }

    let refused = [
        // The configured private classes, at the top level…
        "finance/q3-summary.md",
        "credentials/tokens.md",
        "communications/email-dump.md",
        // …and shadowed inside a general namespace.
        "knowledge/finance/note.md",
        "knowledge/credentials/leaked.md",
        "knowledge/communications/raw.md",
        // Outside every general namespace: invisible by default.
        "personal/journal.md",
        "money.md",
        // Namespace names are exact, never case-folded.
        "Knowledge/notes.md",
        "Generated/page.md",
        // Only Markdown is ever eligible.
        "knowledge/attachment.png",
        // Malformed or escaping paths are not pages at all.
        "knowledge//double-slash.md",
        "knowledge/../finance/escape.md",
        "knowledge/./dot.md",
        "/etc/passwd.md",
        "generated/../../outside.md",
    ];
    for name in refused {
        assert!(
            !bridge.page_scoped(name),
            "{name} must never be retrieval-eligible"
        );
    }
}

/// Scoped listing projection preserves the listing order and drops exactly
/// the out-of-scope entries.
#[test]
fn scoped_page_names_filter_a_listing_in_order() {
    let root = private_vault_root("listing");
    let bridge = VaultBridge::new(test_config(&root)).expect("valid configuration");
    std::fs::remove_dir_all(&root).ok();

    let listed = vec![
        "finance/q3.md".to_owned(),
        "knowledge/alpha.md".to_owned(),
        "knowledge/credentials/leaked.md".to_owned(),
        "generated/summary.md".to_owned(),
        "scratch/notes.md".to_owned(),
        "knowledge/beta.md".to_owned(),
    ];
    let scoped = bridge.scoped_page_names(&listed);
    assert_eq!(
        scoped,
        vec![
            "knowledge/alpha.md",
            "generated/summary.md",
            "knowledge/beta.md"
        ]
    );
}

/// Configuration validation fails closed on every violated deployment fact.
#[test]
fn config_validation_rejects_invalid_deployment_facts() {
    let root = private_vault_root("config");
    let config = test_config(&root);

    let mut relative = config.clone();
    relative.vault_root = PathBuf::from("vault");
    assert!(
        relative.validate().is_err(),
        "relative roots must be refused"
    );

    let mut source = config.clone();
    source.source_id = "not a source id!".to_owned();
    assert!(
        source.validate().is_err(),
        "invalid source identities must be refused"
    );

    let mut clash = config.clone();
    clash.excluded_namespaces = vec!["finance".to_owned(), "knowledge".to_owned()];
    assert!(
        clash.validate().is_err(),
        "a namespace both general and excluded must be refused"
    );

    let mut generated_excluded = config.clone();
    generated_excluded.generated_namespace = "finance/generated".to_owned();
    assert!(
        generated_excluded.validate().is_err(),
        "a generated namespace inside an excluded class must be refused"
    );

    let mut escaping = config.clone();
    escaping.generated_namespace = "../generated".to_owned();
    assert!(
        escaping.validate().is_err(),
        "escaping namespace paths must be refused"
    );

    let mut port = config.clone();
    port.silverbullet = Some(SilverBulletConfig {
        port: 0,
        expected_space_root: None,
    });
    assert!(port.validate().is_err(), "port 0 must be refused");

    let mut bounds = config.clone();
    bounds.max_pages = 0;
    assert!(
        bounds.validate().is_err(),
        "a zero page bound must be refused"
    );

    let mut byte_bound = config.clone();
    byte_bound.max_page_bytes = 0;
    assert!(
        byte_bound.validate().is_err(),
        "a zero byte bound must be refused"
    );

    std::fs::remove_dir_all(&root).ok();
}

/// A generated write lands at exactly the requested path with exactly the
/// requested bytes, and every non-generated or escaping name is refused
/// before any byte moves.
#[test]
fn generated_writes_land_only_beneath_the_generated_namespace() {
    let root = private_vault_root("write");
    let bridge = VaultBridge::new(test_config(&root)).expect("valid configuration");

    // Pre-existing non-generated content that must survive every refusal.
    std::fs::create_dir_all(root.join("finance")).expect("finance namespace");
    std::fs::write(root.join("finance/human.md"), "human record\n").expect("human page");

    let content = "# Machine summary\n\nGenerated by Odin.\n";
    let written = bridge
        .write_generated(&VaultWriteGeneratedInput {
            page_name: "generated/summaries/2026-09-13.md".to_owned(),
            content: content.to_owned(),
        })
        .expect("generated write succeeds");
    assert_eq!(written.page_name, "generated/summaries/2026-09-13.md");
    assert_eq!(written.byte_count, content.len());
    assert_eq!(
        written.content_digest,
        Digest::hash(content.as_bytes()).to_string()
    );

    let path = root.join("generated/summaries/2026-09-13.md");
    assert_eq!(
        std::fs::read(&path).expect("written bytes"),
        content.as_bytes()
    );
    let mode = std::fs::metadata(&path)
        .expect("written metadata")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o644,
        "generated pages are user-readable Markdown"
    );

    let refused = [
        // Outside the generated namespace…
        "knowledge/machine.md",
        "finance/machine.md",
        // …traversal and escaping shapes…
        "../outside.md",
        "generated/../finance/escape.md",
        "generated/sub/../../escape.md",
        "/etc/passwd.md",
        "generated/./dot.md",
        // …namespace itself is not a page…
        "generated",
        "generated/",
        // …and non-Markdown.
        "generated/blob.bin",
    ];
    for name in refused {
        let outcome = bridge.write_generated(&VaultWriteGeneratedInput {
            page_name: name.to_owned(),
            content: "x".to_owned(),
        });
        assert!(
            matches!(outcome, Err(VaultError::Refused(_))),
            "{name} must be refused"
        );
    }

    // Empty content is a parameter failure; over-bound content is refused.
    assert!(matches!(
        bridge.write_generated(&VaultWriteGeneratedInput {
            page_name: "generated/empty.md".to_owned(),
            content: String::new(),
        }),
        Err(VaultError::Params(_))
    ));
    let oversized = "x".repeat(64 * 1024 + 1);
    assert!(matches!(
        bridge.write_generated(&VaultWriteGeneratedInput {
            page_name: "generated/big.md".to_owned(),
            content: oversized,
        }),
        Err(VaultError::Refused(_))
    ));

    // The human page is byte-identical to before every refused attempt.
    assert_eq!(
        std::fs::read(root.join("finance/human.md")).expect("human page intact"),
        b"human record\n"
    );
    std::fs::remove_dir_all(&root).ok();
}

/// Symlinked components inside the generated namespace are refusals, and a
/// symlinked leaf is replaced in place without ever following it: the
/// symlink target outside the vault is untouched.
#[test]
fn generated_writes_never_traverse_symlinks() {
    let root = private_vault_root("symlink");
    let outside =
        std::env::temp_dir().join(format!("odin-hermes-vault-outside-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).expect("outside directory");
    std::fs::write(outside.join("secret.md"), "outside\n").expect("outside page");

    let bridge = VaultBridge::new(test_config(&root)).expect("valid configuration");
    std::fs::create_dir_all(root.join(GENERATED_NAMESPACE)).expect("generated namespace");

    // A symlinked directory component: refused, never traversed.
    symlink(&outside, root.join("generated/sub")).expect("component symlink");
    let outcome = bridge.write_generated(&VaultWriteGeneratedInput {
        page_name: "generated/sub/page.md".to_owned(),
        content: "escape\n".to_owned(),
    });
    assert!(matches!(outcome, Err(VaultError::Refused(_))));
    assert!(
        !outside.join("page.md").exists(),
        "nothing may be written through a symlinked directory component"
    );

    // A symlinked leaf: replaced inside the namespace; the target outside
    // the vault is never followed and never mutated.
    symlink(outside.join("secret.md"), root.join("generated/leaf.md")).expect("leaf symlink");
    let content = "machine leaf\n".to_owned();
    let written = bridge
        .write_generated(&VaultWriteGeneratedInput {
            page_name: "generated/leaf.md".to_owned(),
            content: content.clone(),
        })
        .expect("leaf replacement succeeds inside the namespace");
    assert_eq!(
        written.content_digest,
        Digest::hash(content.as_bytes()).to_string()
    );
    assert_eq!(
        std::fs::read(root.join("generated/leaf.md")).expect("replaced leaf"),
        content.as_bytes()
    );
    assert_eq!(
        std::fs::read(outside.join("secret.md")).expect("outside page intact"),
        b"outside\n",
        "non-generated content outside the vault must never be mutated"
    );

    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&outside).ok();
}

/// A missing vault root, and a root that is not a private 0700 directory,
/// are typed unavailability — never a fallback, never a fake success.
#[test]
fn generated_writes_fail_typed_when_the_vault_root_is_missing_or_unprotected() {
    let missing =
        std::env::temp_dir().join(format!("odin-hermes-vault-absent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&missing);
    let bridge = VaultBridge::new(test_config(&missing)).expect("valid configuration");
    let outcome = bridge.write_generated(&VaultWriteGeneratedInput {
        page_name: "generated/page.md".to_owned(),
        content: "x\n".to_owned(),
    });
    match outcome {
        Err(VaultError::Unavailable { component, .. }) => {
            assert_eq!(component, "vault", "the absent fact is the vault root");
        }
        other => panic!("a missing vault root must be typed unavailable, got {other:?}"),
    }

    let unprotected = private_vault_root("unprotected");
    std::fs::set_permissions(&unprotected, Permissions::from_mode(0o755))
        .expect("unprotected mode");
    let bridge = VaultBridge::new(test_config(&unprotected)).expect("valid configuration");
    let outcome = bridge.write_generated(&VaultWriteGeneratedInput {
        page_name: "generated/page.md".to_owned(),
        content: "x\n".to_owned(),
    });
    assert!(matches!(outcome, Err(VaultError::Unavailable { .. })));
    assert!(
        !unprotected.join("generated").exists(),
        "no namespace may be created in an unprotected root"
    );
    std::fs::remove_dir_all(&unprotected).ok();
}

/// With no SilverBullet deployment configured, scoped pinning is typed
/// unavailable — the optional default UI is absent, and nothing is faked.
#[test]
fn scoped_pinning_fails_typed_without_a_silverbullet_deployment() {
    let root = private_vault_root("unconfigured");
    let bridge = VaultBridge::new(test_config(&root)).expect("valid configuration");
    std::fs::remove_dir_all(&root).ok();
    let outcome = bridge.pin_scoped_vault();
    match outcome {
        Err(BrainError::Unavailable { component, .. }) => {
            assert_eq!(component, "silverbullet");
        }
        other => panic!("an unconfigured SilverBullet must be typed unavailable, got {other:?}"),
    }
    // The operation surface carries the same typed unavailability.
    assert!(matches!(
        bridge.search(&VaultSearchInput { max_pages: None }),
        Err(VaultError::Unavailable {
            component: "silverbullet",
            ..
        })
    ));
}

/// A configured but absent SilverBullet service is typed unavailable: the
/// real loopback connection is attempted and genuinely refused.
#[test]
fn scoped_pinning_fails_typed_when_the_service_is_absent() {
    let root = private_vault_root("absent-service");
    let mut config = test_config(&root);
    config.silverbullet = Some(SilverBulletConfig {
        port: dead_loopback_port(),
        expected_space_root: None,
    });
    let bridge = VaultBridge::new(config).expect("valid configuration");
    std::fs::remove_dir_all(&root).ok();
    let started = std::time::Instant::now();
    let outcome = bridge.pin_scoped_vault();
    match outcome {
        Err(BrainError::Unavailable { component, .. }) => {
            assert_eq!(component, "silverbullet");
        }
        other => panic!("a dead SilverBullet service must be typed unavailable, got {other:?}"),
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the refused connection must fail on its deadline, not hang"
    );
}

/// The operation inputs keep their schema shape: unknown fields are
/// refused, so a drifted caller cannot smuggle policy through params.
#[test]
fn operation_inputs_reject_unknown_fields() {
    assert!(serde_json::from_str::<VaultSearchInput>("{\"max_pages\": 5}").is_ok());
    assert!(
        serde_json::from_str::<VaultSearchInput>("{\"max_pages\": 5, \"query\": \"scope\"}")
            .is_err()
    );
    assert!(serde_json::from_str::<VaultSearchInput>("{}").is_ok());
    assert!(serde_json::from_str::<VaultWriteGeneratedInput>(
        "{\"page_name\": \"generated/x.md\", \"content\": \"x\", \"mode\": 644}"
    )
    .is_err());
}

/// Confined filesystem failures keep their typed class end to end.
#[test]
fn confined_failures_remain_typed() {
    let error = VaultError::from(ConfinedError::DotDotSegment);
    assert!(matches!(error, VaultError::Confined(_)));
}

/// Reject unaddressable names so one page cannot invalidate a scoped pin.
#[test]
fn unaddressable_names_are_refused_and_never_scoped() {
    let root = private_vault_root("addressability");
    let bridge = VaultBridge::new(test_config(&root)).expect("valid configuration");

    let unaddressable = [
        "generated/café.md",    // non-ASCII
        "generated/what?.md",   // URL metacharacter
        "generated/a#b.md",     // fragment metacharacter
        "generated/a\\b.md",    // backslash
        "generated/.hidden.md", // leading-dot segment
        "knowledge/café.md",    // legal shape, unaddressable name
    ];
    for name in unaddressable {
        assert!(!bridge.page_scoped(name), "{name} must never be scoped");
        let outcome = bridge.write_generated(&VaultWriteGeneratedInput {
            page_name: name.to_owned(),
            content: "x\n".to_owned(),
        });
        assert!(
            matches!(outcome, Err(VaultError::Refused(_))),
            "{name} must be refused"
        );
    }

    // Admitted writes must remain addressable and readable within the same scope.
    let legal = "generated/summaries/day-1.md";
    bridge
        .write_generated(&VaultWriteGeneratedInput {
            page_name: legal.to_owned(),
            content: "ok\n".to_owned(),
        })
        .expect("legal generated write succeeds");
    assert!(bridge.page_scoped(legal));
    assert!(odin_brain::source::silverbullet::encode_page_path(legal).is_ok());
    std::fs::remove_dir_all(&root).ok();
}

/// LIVE SMOKE — the real SilverBullet service path, run explicitly during
/// serial verification:
///
/// ```text
/// cargo test -p odin-hermes --test vault -- --ignored
/// ```
///
/// Prerequisite: the real SilverBullet 2.x server serving
/// `/home/colin/vault` on `127.0.0.1:3000` (dotfiles `odin-foundations.nix`).
///
/// For isolated verification without the personal deployment root, set
/// `ODIN_SMOKE_VAULT_ROOT` to a disposable 0700 directory and
/// `ODIN_SMOKE_SB_PORT` to a fresh loopback port served by a private
/// SilverBullet instance; the defaults stay the real deployment facts.
///
/// Reads only names outside a unique disposable namespace; page contents stay confined to its probe.
/// Cleanup removes only the probe and its empty namespace, never preexisting pages.
#[test]
#[ignore = "requires the real SilverBullet server on 127.0.0.1:3000 serving /home/colin/vault"]
fn live_loopback_smoke() {
    let vault_root =
        std::env::var("ODIN_SMOKE_VAULT_ROOT").unwrap_or_else(|_| "/home/colin/vault".to_owned());
    let port: u16 = std::env::var("ODIN_SMOKE_SB_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3000);

    // One unique top-level namespace, so the configured scope admits
    // exactly the probe page and nothing else in the vault.
    let unique = format!(
        "odin-hermes-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock advances")
            .as_millis()
    );
    let probe_name = format!("{unique}/probe.md");
    let probe_text = "Odin Hermes vault probe (disposable, generated namespace).\n";

    let config_general = vec![unique.clone()];
    let config_generated = unique.clone();
    let config_excluded: Vec<String> = EXCLUDED_NAMESPACES
        .iter()
        .map(|name| name.to_string())
        .collect();
    let mut config = test_config(Path::new(&vault_root));
    config.timeout_ms = 10_000;
    config.general_namespaces = config_general.clone();
    config.generated_namespace = config_generated.clone();
    config.excluded_namespaces = config_excluded.clone();
    config.silverbullet = Some(SilverBulletConfig {
        port,
        expected_space_root: Some(vault_root.clone()),
    });
    let bridge = VaultBridge::new(config).expect("valid configuration");
    assert!(bridge.page_scoped(&probe_name));

    // Check scope using names without reading personal page contents.
    let source = odin_brain::source::silverbullet::SilverBulletSource::new(
        odin_domain::knowledge::ids::AtlasId::new(SOURCE_ID.to_owned()).expect("source id"),
        port,
        odin_brain::source::silverbullet::VaultScope::new(
            &config_general,
            &config_generated,
            &config_excluded,
        )
        .expect("smoke scope"),
    );
    for page in source.list_pages().expect("the real space lists") {
        for excluded in EXCLUDED_NAMESPACES {
            assert!(
                !(bridge.page_scoped(&page.name)
                    && page.name.split('/').any(|segment| segment == *excluded)),
                "private namespace {excluded} admitted by the scope via {:?}",
                page.name
            );
        }
    }

    // The confined generated write lands the unique probe page.
    let written = bridge
        .write_generated(&VaultWriteGeneratedInput {
            page_name: probe_name.clone(),
            content: probe_text.to_owned(),
        })
        .expect("the generated probe page writes");
    assert_eq!(
        written.content_digest,
        Digest::hash(probe_text.as_bytes()).to_string()
    );

    // Scoped retrieval must read only the probe with its exact bytes and digest.
    let retrieval = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let pinned = bridge.pin_scoped_vault().expect("the scoped vault pins");
        let pages = pinned.pages();
        assert_eq!(
            pages.len(),
            1,
            "the probe-only scope must pin exactly one page"
        );
        assert_eq!(pages[0].meta.name, probe_name);
        assert_eq!(
            pages[0].text, probe_text,
            "retrieved bytes are the written bytes"
        );
        let digest = Digest::parse(&written.content_digest).expect("digest wire form parses");
        assert_eq!(pages[0].digest.as_bytes(), digest.as_bytes());
    }));

    // An outside-the-namespace write is refused by the real bridge; the
    // private namespace stays untouched (refusal happens before any I/O).
    let refusal = bridge.write_generated(&VaultWriteGeneratedInput {
        page_name: "finance/odin-hermes-probe.md".to_owned(),
        content: "must never land\n".to_owned(),
    });
    assert!(
        matches!(refusal, Err(VaultError::Refused(_))),
        "an outside-namespace write must be refused, got {refusal:?}"
    );

    // Unconditional cleanup: only the exact probe file, then the now-empty
    // unique namespace directory. Absence is already clean.
    let probe_path = Path::new(&vault_root).join(&probe_name);
    let removal = std::fs::remove_file(&probe_path);
    let namespace_dir = Path::new(&vault_root).join(&unique);
    let _ = std::fs::remove_dir(&namespace_dir);
    let removed = matches!(&removal, Ok(())) || std::fs::metadata(&probe_path).is_err();
    assert!(
        retrieval.is_ok(),
        "the live scoped-retrieval assertions hold"
    );
    assert!(removed, "the probe page must be removed after the smoke");
}
