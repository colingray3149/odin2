//! Vault source integration tests.
//!
//! Two layers:
//!
//! 1. The real Atlas AST path through the public API over a temporary
//!    fixture source repo, plus source pin rejection for an invalid root.
//!    These run in the normal suite (no network, no services).
//!
//! 2. `live_loopback_smoke` (`#[ignore]`): the actual SilverBullet HTTP
//!    path. Retrieval is never simulated and never filesystem-based —
//!    every byte moves over the loopback `/.fs/` API of a real server.
//!    The test writes exactly one runtime-owned disposable probe page —
//!    beneath a unique, run-local generated namespace — via the documented
//!    `PUT /.fs/<path>` write endpoint, retrieves it through the mandatory
//!    vault scope (`pin_scoped` must pin exactly the probe and nothing
//!    else), and deletes its own page, asserting the deletion took effect.
//!    No page outside the probe scope is ever read, no pre-existing vault
//!    content is ever overwritten, and an excluded name is refused typed
//!    before any fetch.
//!
//! Prerequisites for the ignored test: a running SilverBullet 2.x server
//! serving the vault at `/home/colin/vault` on `127.0.0.1:3000`. With the
//! server absent the test fails loudly (typed unavailable error) — it can
//! never fake a successful network exchange.
//!
//! ```text
//! cargo test -p odin-brain --test vault_source            # offline layer
//! cargo test -p odin-brain --test vault_source -- --ignored
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use odin_atlas::{AtlasScope, SourceClass};
use odin_brain::error::{BrainError, BrainResult};
use odin_brain::source::atlas::{validate_root, AtlasSource};
use odin_brain::source::silverbullet::{
    encode_page_path, SilverBulletSource, VaultScope, SILVERBULLET_PORT,
};
use odin_domain::knowledge::ids::AtlasId;
use odin_domain::knowledge::retrieval::TrustClass;

const PROBE_TEXT: &str = "Brain M11 vault probe (disposable, generated namespace).\n";
const VAULT_SPACE_ROOT: &str = "/home/colin/vault";

/// A unique, run-local generated namespace: the probe page lives strictly
/// beneath it, so the mandatory vault scope admits exactly this probe —
/// nothing else in the real vault, private or otherwise, is ever eligible.
/// Collisions across concurrent or crashed runs are impossible by
/// construction, so no fixed name is ever overwritten or deleted.
fn probe_namespace() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("generated/brain-m11-probe-{}-{millis}", std::process::id())
}

/// The probe page: one Markdown page strictly beneath the namespace.
fn probe_page_name(namespace: &str) -> String {
    format!("{namespace}/probe.md")
}

/// Admit only the unique generated probe namespace; exclude `finance`
/// to check rejection before any live fetch.
fn probe_scope(namespace: &str) -> VaultScope {
    VaultScope::new(
        &[format!("brain-m11-probe-none-{}", std::process::id())],
        namespace,
        &["finance".to_owned()],
    )
    .expect("probe scope must validate")
}

/// Builds a temporary fixture source repo for the real Atlas build.
fn fixture_root(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "odin-brain-vault-fixture-{tag}-{}",
        std::process::id()
    ));
    let src = dir.join("crates").join("demo").join("src");
    std::fs::create_dir_all(&src).unwrap();
    // The real odin-atlas root layout: all four source-class directories
    // must exist for the resolver; empty ones contribute no nodes.
    std::fs::create_dir_all(dir.join("extension")).unwrap();
    std::fs::create_dir_all(dir.join("registry")).unwrap();
    std::fs::create_dir_all(dir.join("skeletons")).unwrap();
    std::fs::write(
        src.join("lib.rs"),
        "//! Demo crate.\n\n/// Adds one.\npub fn add_one(value: u64) -> u64 { value + 1 }\n",
    )
    .unwrap();
    dir
}

/// The real Atlas AST index over a real (temporary) source repo, through
/// the public `AtlasSource` API only: pin, scope query, item projection,
/// provenance and trust stamped exactly as citations will see them.
#[test]
fn atlas_fixture_pins_through_public_api() {
    let root = fixture_root("pin");
    let atlas_id = AtlasId::new("atlas:fixture").unwrap();
    let pinned = AtlasSource::new(&root, atlas_id.clone()).pin().unwrap();

    let items = pinned
        .items(&AtlasScope::source(SourceClass::Rust))
        .unwrap();
    assert!(!items.is_empty(), "rust scope must project fixture nodes");
    for item in &items {
        assert_eq!(item.source, atlas_id);
        assert_eq!(item.source_revision, pinned.revision());
        assert_eq!(item.trust, TrustClass::Curated);
        assert!(item.text.contains("add_one"));
    }

    // Scope projection is exact: a scope matching nothing yields nothing.
    let empty = pinned
        .items(&AtlasScope::paths(["nonexistent-prefix".to_owned()]).unwrap())
        .unwrap();
    assert!(empty.is_empty());

    std::fs::remove_dir_all(&root).ok();
}

/// Source pin rejection: an invalid root fails typed before Atlas is ever
/// invoked, and a file (not directory) is rejected the same way.
#[test]
fn atlas_pin_rejects_invalid_root() {
    let missing =
        std::env::temp_dir().join(format!("odin-brain-vault-missing-{}", std::process::id()));
    let error = AtlasSource::new(&missing, AtlasId::new("atlas:fixture").unwrap())
        .pin()
        .unwrap_err();
    assert!(
        matches!(error, BrainError::InvalidRequest(_)),
        "expected typed InvalidRequest for a missing root, got {error:?}"
    );
    assert!(matches!(
        validate_root(&missing),
        Err(BrainError::InvalidRequest(_))
    ));

    let file = missing.with_extension("file");
    std::fs::write(&file, b"not a directory").unwrap();
    assert!(matches!(
        validate_root(&file),
        Err(BrainError::InvalidRequest(_))
    ));
    std::fs::remove_file(&file).ok();
}

/// LIVE SMOKE — the user-required actual loopback SilverBullet API path,
/// run explicitly during the serial verification grant:
///
/// ```text
/// cargo test -p odin-brain --test vault_source -- --ignored
/// ```
///
/// Evidence chain, entirely inside a unique run-local generated namespace:
/// PUT probe page → `pin_scoped` over the real API pins exactly the probe
/// (the scope admits nothing else in the vault) → exact byte and digest
/// round trip → typed scope refusal for an excluded page with no fetch, and
/// typed unavailability for an unknown in-scope page → DELETE of its own
/// unique page → listing proves the probe is gone. No other page's content
/// is ever read; cleanup runs even when assertions fail.
#[test]
#[ignore = "requires the real SilverBullet server on 127.0.0.1:3000 serving /home/colin/vault"]
fn live_loopback_smoke() {
    let namespace = probe_namespace();
    let probe_page = probe_page_name(&namespace);
    let source = SilverBulletSource::new(
        AtlasId::new("vault:silverbullet").unwrap(),
        SILVERBULLET_PORT,
        probe_scope(&namespace),
    )
    .with_expected_space_root(VAULT_SPACE_ROOT);

    // Honest prerequisite check: with the server down this fails here,
    // loudly, instead of anywhere downstream. Metadata only — no content
    // bytes move in a listing.
    let initial_listing = source
        .list_pages()
        .expect("SilverBullet must be serving the vault on 127.0.0.1:3000");

    // Refuse an existing probe page rather than overwrite vault content.
    assert!(
        !initial_listing.iter().any(|meta| meta.name == probe_page),
        "probe page {probe_page:?} already exists; refusing to overwrite vault content"
    );
    probe_write_page(&probe_page, PROBE_TEXT).unwrap();

    let result: BrainResult<()> = (|| {
        // Scoped live pin over the whole real vault: the only admitted page
        // is the probe — byte-exact, over HTTP, not from any local fallback.
        let vault = source.pin_scoped()?;
        assert_eq!(
            vault.pages().len(),
            1,
            "the probe scope must admit exactly the probe page"
        );
        assert_eq!(vault.pages()[0].meta.name, probe_page);
        assert_eq!(vault.pages()[0].text, PROBE_TEXT);
        assert_eq!(
            vault.atlas_id(),
            &AtlasId::new("vault:silverbullet").unwrap()
        );

        // Retrieval evidence: a second independent read returns the exact
        // same bytes and digest.
        let reread = source.read_page(&probe_page)?;
        assert_eq!(reread.text, PROBE_TEXT);
        assert_eq!(reread.digest, vault.pages()[0].digest);

        // Items inherit the pinned revision and observed trust class.
        let items = vault.items()?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].source_revision, vault.revision());
        assert_eq!(items[0].trust, TrustClass::Observed);

        // Excluded names must be rejected before fetching any bytes.
        let error = source.read_page("finance/no-such-ledger.md").unwrap_err();
        assert!(
            matches!(error, BrainError::InvalidRequest(_)),
            "excluded pages must be refused by the scope gate, not looked up: {error:?}"
        );

        // An unknown but in-scope name still fails typed-unavailable on the
        // existence check — the gate orders scope before lookup, and lookup
        // stays honest.
        let missing = format!("{namespace}/missing.md");
        let error = source.read_page(&missing).unwrap_err();
        assert!(
            matches!(
                &error,
                BrainError::Unavailable { component, .. } if *component == "silverbullet"
            ),
            "an unknown in-scope page must fail typed-unavailable: {error:?}"
        );
        Ok(())
    })();

    // Idempotent cleanup of its own unique page, then verify it took effect.
    probe_delete_page(&probe_page).unwrap();
    let listing = source.list_pages().unwrap();
    assert!(
        !listing.iter().any(|meta| meta.name == probe_page),
        "probe page must be gone after cleanup"
    );
    result.unwrap();
}

/// Integration-only disposable page writes for the live smoke.
///
/// The library client is deliberately read-only over `/.fs/`; creating and
/// deleting the runtime-owned probe page is smoke behavior and lives here,
/// in this test binary, not in the product. Confined exactly like reads:
/// loopback only, the page name validated by the same [`encode_page_path`]
/// the client uses, one connection per request, redirects refused.
fn probe_write_page(page_name: &str, content: &str) -> BrainResult<()> {
    let status = probe_request("PUT", page_name, Some(content.as_bytes()))?;
    ensure_probe_status(status, "write")
}

/// Integration-only idempotent cleanup: an already-absent page is clean.
fn probe_delete_page(page_name: &str) -> BrainResult<()> {
    let status = probe_request("DELETE", page_name, None)?;
    if status == 404 {
        return Ok(());
    }
    ensure_probe_status(status, "delete")
}

/// One raw loopback `/.fs/` write or delete; returns the HTTP status.
fn probe_request(method: &str, page_name: &str, body: Option<&[u8]>) -> BrainResult<u16> {
    let path = format!("/.fs/{}", encode_page_path(page_name)?);
    let body = body.unwrap_or(b"");
    let transport = |step: &str, error: std::io::Error| BrainError::Unavailable {
        component: "silverbullet",
        reason: format!("probe {step}: {error}"),
    };
    let mut stream = TcpStream::connect(("127.0.0.1", SILVERBULLET_PORT))
        .map_err(|error| transport("connect failed", error))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| transport("timeout setup failed", error))?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len(),
        port = SILVERBULLET_PORT
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| transport("request write failed", error))?;
    stream
        .write_all(body)
        .map_err(|error| transport("body write failed", error))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| transport("response read failed", error))?;
    let text = String::from_utf8_lossy(&response);
    let status_line = text.split("\r\n").next().unwrap_or_default();
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| BrainError::Unavailable {
            component: "silverbullet",
            reason: format!("probe got a malformed status line {status_line:?}"),
        })
}

/// Refuses redirects (never honored) and non-2xx probe outcomes.
fn ensure_probe_status(status: u16, step: &str) -> BrainResult<()> {
    if (300..400).contains(&status) {
        return Err(BrainError::Unavailable {
            component: "silverbullet",
            reason: format!("probe {step} got redirect {status}; redirects are never followed"),
        });
    }
    if !(200..300).contains(&status) {
        return Err(BrainError::Unavailable {
            component: "silverbullet",
            reason: format!("probe {step} got HTTP {status}"),
        });
    }
    Ok(())
}
