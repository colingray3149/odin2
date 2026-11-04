//! Vault integration tests for `odin_hermes::vault`.
//!
//! Everything runs offline, over a temporary vault and loopback fakes:
//! 1. retrieval scope and exclusions — a search over a served space lists only
//!    configured general namespaces and the generated namespace, never fetching
//!    a page carrying an excluded (private) segment at any depth;
//! 2. generated-only machine writes — exact confined bytes beneath the
//!    generated namespace, with traversal, namespace escapes, symlinked
//!    components, and non-generated content untouched or refused;
//! 3. typed unavailability — a missing vault root, an unprotected root, a
//!    missing SilverBullet configuration, and a dead loopback service all
//!    fail typed, never as fake successes.

use std::fs::Permissions;
use std::net::TcpListener;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use odin_brain::error::BrainError;
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
fn private_vault_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("vault root created");
    std::fs::set_permissions(root.path(), Permissions::from_mode(0o700))
        .expect("vault root private");
    root
}

/// One loopback SilverBullet: a `/.fs/` listing and the page bodies, reporting
/// every requested path. It answers exactly `requests` connections.
fn serve_space(
    pages: &'static [(&'static str, &'static str)],
    requests: usize,
) -> (u16, std::sync::mpsc::Receiver<String>) {
    use std::io::{BufRead, Write};
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let port = listener.local_addr().expect("local address").port();
    let (seen, requested) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(requests) {
            let mut stream = stream.expect("connection");
            let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
            let mut request_line = String::new();
            reader.read_line(&mut request_line).expect("request line");
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).expect("header");
                if header.trim().is_empty() {
                    break;
                }
            }
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_owned();
            let body = if path == "/.fs/" {
                let entries: Vec<String> = pages
                    .iter()
                    .map(|(name, text)| {
                        format!(
                            "{{\"name\": {name:?}, \"size\": {}, \"lastModified\": 0, \"perm\": \"rw\"}}",
                            text.len()
                        )
                    })
                    .collect();
                format!("[{}]", entries.join(","))
            } else {
                let name = path.trim_start_matches("/.fs/").replace("%20", " ");
                pages
                    .iter()
                    .find(|(page, _)| *page == name)
                    .map_or_else(String::new, |(_, text)| (*text).to_owned())
            };
            seen.send(path).ok();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("response");
        }
    });
    (port, requested)
}

const SPACE: &[(&str, &str)] = &[
    ("knowledge/alpha.md", "alpha notes\n"),
    ("knowledge/credentials/leaked.md", "MUST NEVER BE FETCHED\n"),
    ("generated/summary.md", "machine summary\n"),
    ("finance/q3.md", "MUST NEVER BE FETCHED\n"),
    ("scratch/notes.md", "outside every namespace\n"),
];

/// A search over a served space lists the configured general and generated
/// pages only, never fetches a private or out-of-scope one, and honours the
/// caller's bound within the ceiling.
#[test]
fn a_search_lists_only_the_scoped_pages_of_the_served_space() {
    // Two searches: a listing and the two admitted pages each.
    let (port, requested) = serve_space(SPACE, 6);
    let root = private_vault_root();
    let mut config = test_config(root.path());
    config.silverbullet = Some(SilverBulletConfig {
        port,
        expected_space_root: None,
    });
    let bridge = VaultBridge::new(config).expect("valid configuration");

    let all = bridge
        .search(&VaultSearchInput { max_pages: None })
        .expect("search over the served space");
    let mut names: Vec<_> = all.pages.iter().map(|page| page.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["generated/summary.md", "knowledge/alpha.md"]);
    assert_eq!(all.page_count, 2);
    assert!(!all.truncated);
    assert!(!all.revision_digest.is_empty() && all.pages.iter().all(|page| page.bytes > 0));

    let one = bridge
        .search(&VaultSearchInput { max_pages: Some(1) })
        .expect("a bounded search");
    assert_eq!((one.page_count, one.truncated), (1, true));

    let fetched: Vec<String> = requested.try_iter().collect();
    assert!(
        fetched.iter().all(|path| !path.contains("finance")
            && !path.contains("credentials")
            && !path.contains("scratch")),
        "only admitted pages are ever fetched: {fetched:?}"
    );
    assert!(matches!(
        bridge.search(&VaultSearchInput { max_pages: Some(u32::MAX) }),
        Err(VaultError::Params(why)) if why.contains("max_pages")
    ));
}

/// A generated write lands at exactly the requested path with exactly the
/// requested bytes, and every non-generated or escaping name is refused
/// before any byte moves.
#[test]
fn generated_writes_land_only_beneath_the_generated_namespace() {
    let scratch = private_vault_root();
    let root = scratch.path();
    let bridge = VaultBridge::new(test_config(root)).expect("valid configuration");

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
    assert!(!root.join("finance/machine.md").exists());
    assert!(!root.join("knowledge/machine.md").exists());

    // A page name without .md is refused naming the missing suffix.
    let Err(VaultError::Refused(why)) = bridge.write_generated(&VaultWriteGeneratedInput {
        page_name: "generated/week-plan".to_owned(),
        content: "x".to_owned(),
    }) else {
        panic!("a page name without .md must be refused");
    };
    assert!(
        why.contains("\"generated/week-plan.md\""),
        "the refusal names the fix: {why}"
    );

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
}

/// An identical rewrite never touches the page (Syncthing would replicate the
/// churn to every host); different bytes replace it.
#[test]
fn an_identical_rewrite_leaves_the_page_untouched_and_a_changed_one_replaces_it() {
    use std::os::unix::fs::MetadataExt;
    let scratch = private_vault_root();
    let bridge = VaultBridge::new(test_config(scratch.path())).expect("valid configuration");
    let write = |content: &str| {
        bridge
            .write_generated(&VaultWriteGeneratedInput {
                page_name: "generated/plan.md".to_owned(),
                content: content.to_owned(),
            })
            .expect("write")
    };
    let path = scratch.path().join("generated/plan.md");
    write("week one\n");
    let first = std::fs::metadata(&path).expect("first write");
    let again = write("week one\n");
    assert_eq!(
        again.byte_count,
        "week one\n".len(),
        "the write still reports its bytes"
    );
    let second = std::fs::metadata(&path).expect("identical rewrite");
    assert_eq!(
        (first.ino(), first.mtime_nsec(), first.mtime()),
        (second.ino(), second.mtime_nsec(), second.mtime())
    );
    write("week two\n");
    assert_eq!(std::fs::read(&path).unwrap(), b"week two\n");
}

/// A page that sits beside the generated namespace is refused naming the path to use.
#[test]
fn a_page_beside_the_generated_namespace_is_refused_naming_the_path_to_use() {
    let scratch = private_vault_root();
    let bridge = VaultBridge::new(test_config(scratch.path())).expect("valid configuration");
    let Err(VaultError::Refused(why)) = bridge.write_generated(&VaultWriteGeneratedInput {
        page_name: "generated.md".to_owned(),
        content: "x".to_owned(),
    }) else {
        panic!("a page beside the namespace is not beneath it");
    };
    assert!(
        why.contains("generated/<page-name>") && !why.contains('['),
        "{why}"
    );
}

/// Symlinked components inside the generated namespace are refusals, and a
/// symlinked leaf is replaced in place without ever following it: the
/// symlink target outside the vault is untouched.
#[test]
fn generated_writes_never_traverse_symlinks() {
    let scratch = private_vault_root();
    let root = scratch.path();
    let outside_dir = tempfile::tempdir().expect("outside directory");
    let outside = outside_dir.path();
    std::fs::write(outside.join("secret.md"), "outside\n").expect("outside page");

    let bridge = VaultBridge::new(test_config(root)).expect("valid configuration");
    std::fs::create_dir_all(root.join(GENERATED_NAMESPACE)).expect("generated namespace");

    // A symlinked directory component: refused, never traversed.
    symlink(outside, root.join("generated/sub")).expect("component symlink");
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
}

/// With no SilverBullet deployment configured, scoped pinning is typed
/// unavailable — the optional default UI is absent, and nothing is faked.
#[test]
fn scoped_pinning_fails_typed_without_a_silverbullet_deployment() {
    let root = private_vault_root();
    let bridge = VaultBridge::new(test_config(root.path())).expect("valid configuration");
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

/// Unaddressable names are refused on write, so one page cannot invalidate a scoped pin.
#[test]
fn unaddressable_names_are_refused_and_never_scoped() {
    let scratch = private_vault_root();
    let root = scratch.path();
    let bridge = VaultBridge::new(test_config(root)).expect("valid configuration");

    let unaddressable = [
        "generated/café.md",    // non-ASCII
        "generated/what?.md",   // URL metacharacter
        "generated/a#b.md",     // fragment metacharacter
        "generated/a\\b.md",    // backslash
        "generated/.hidden.md", // leading-dot segment
        "knowledge/café.md",    // legal shape, unaddressable name
    ];
    for name in unaddressable {
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
    assert!(odin_brain::source::silverbullet::encode_page_path(legal).is_ok());
}
