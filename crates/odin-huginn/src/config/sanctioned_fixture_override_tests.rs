use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

fn fixture_config() -> OdindConfig {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8420);
    OdindConfig {
        schema: ODIND_CONFIG_SCHEMA.to_owned(),
        revision: 2,
        identity: OdindIdentityConfig {
            node: "laptop".to_owned(),
        },
        paths: OdindPathsConfig {
            registry_root: PathBuf::from("/srv/odin/registry"),
            state_root: PathBuf::from("/srv/odin/state"),
            registry_snapshot: PathBuf::from("/srv/odin/registry/snapshot.json"),
            authority_token_root: PathBuf::from("/srv/odin/state/authority/tokens"),
            authority_verification_key_file: PathBuf::from("/srv/odin/authority/verification.key"),
            operator_context_root: None,
            cargo_registry_cache: None,
            cargo_git_cache: None,
            nix_daemon_socket: None,
            nix_config_root: None,
            authoring_repository: None,
            authoring_worktree: None,
        },
        listener: OdindListenerConfig {
            address,
            tls_cert: None,
            tls_key: None,
        },
        executables: OdindExecutablesConfig {
            omp_bin: PathBuf::from("/nix/store/omp/bin/omp"),
            omp_revision: "a".repeat(40),
            extension: PathBuf::from("/nix/store/extension/index.ts"),
            zellij_bin: PathBuf::from("/nix/store/zellij/bin/zellij"),
            zellij_session: "odin".to_owned(),
            attach_command: Vec::new(),
            browser: Some(OdindBrowserConfig {
                chromium: PathBuf::from("/nix/store/chromium"),
                profile_root: PathBuf::from("/srv/odin/state/browser/profiles"),
                policy: PathBuf::from("/nix/store/policy.json"),
                protected_values: PathBuf::from("/nix/store/values.json"),
                scanner: PathBuf::from("/nix/store/scanner"),
                scanner_args: Vec::new(),
                stream: "0f0e0d0c-0b0a-4948-8765-432109876543".to_owned(),
                display: OdindDisplayConfig {
                    source: BrowserDisplaySource::Xvfb,
                    xvfb_binary: Some(PathBuf::from("/nix/store/xvfb")),
                    display: None,
                },
            }),
        },
        catalogs: OdindCatalogsConfig {
            gateway_projection: PathDigestRef {
                path: PathBuf::from("/nix/store/gateway.json"),
                digest: format!("blake3:{}", "a".repeat(64)),
            },
        },
        projects: BTreeMap::from([(
            "atlas".to_owned(),
            OdindProjectConfig {
                root: PathBuf::from("/srv/atlas"),
                runtime: false,
            },
        )]),
        lane_bindings: Vec::new(),
        seats: Vec::new(),
        file_roots: Vec::new(),
        tailnet_peers: BTreeMap::new(),
        publish: OdindPublishConfig {
            render_session: "live-1".to_owned(),
            file_lane: "lane-file".to_owned(),
            render_lane: "lane-render".to_owned(),
        },
        worker_bus: "unix:path=/run/odin/worker-bus.sock".to_owned(),
        capacity: HuginnLimits::default(),
        delegation: None,
        kube: None,
        adapter_backends: Default::default(),
        gateway_host_credentials: std::collections::BTreeMap::new(),
        brain: None,
        hermes: Some(fixture_hermes_config(PathBuf::from(
            "/srv/odin/state/hermes",
        ))),
        alerts: None,
    }
}

fn fixture_hermes_config(state_dir: PathBuf) -> OdindHermesConfig {
    OdindHermesConfig {
        state_dir,
        discord: Some(OdindHermesDiscordConfig {
            seat: "coordinator".to_owned(),
            project: "research".to_owned(),
            owner_user_id: "owner".to_owned(),
            notify_channel_id: "paired-channel".to_owned(),
            capability: "discord.intake".to_owned(),
            egress_capacity: 8,
            gateway_intents: 1,
            bot_token_handle: "cred:discord.bot".to_owned(),
            scrub_tokens: BTreeSet::new(),
            ttl_seconds: 300,
        }),
        vault: None,
        finance: None,
        accounts: Vec::new(),
        review_gateway: None,
        immich: None,
        brain_raw_root: None,
    }
}

#[test]
fn sanctioned_fixture_overrides_accept_confined_derivation() {
    let packaged = fixture_config();
    let overrides = OdindFixtureOverrides {
        state_root: Some(PathBuf::from("/tmp/tx/state")),
        registry_root: Some(PathBuf::from("/tmp/tx/registry")),
        registry_snapshot: Some(PathBuf::from("/tmp/tx/registry/snapshot.json")),
        listener_address: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19122)),
        project_roots: BTreeMap::from([("atlas".to_owned(), PathBuf::from("/tmp/tx/atlas"))]),
        authority_token_root: Some(PathBuf::from("/tmp/tx/state/authority/tokens")),
        browser_profile_root: Some(PathBuf::from("/tmp/tx/state/browser/profiles")),
        hermes_state_dir: Some(PathBuf::from("/tmp/tx/state/hermes")),
        display: Some(OdindFixtureDisplay::Existing {
            display: ":9".to_owned(),
        }),
        gateway_projection: None,
        ..Default::default()
    };
    let derived = packaged.derive_fixture(&overrides).expect("derives");
    validate_sanctioned_fixture_overrides(&packaged, &derived, Path::new("/tmp/tx"))
        .expect("confined derivation accepted");
}

#[test]
fn sanctioned_fixture_overrides_reject_escape_and_pinned_changes() {
    let packaged = fixture_config();
    // Keep the other state paths confined so the browser profile triggers the refusal.
    let overrides = OdindFixtureOverrides {
        state_root: Some(PathBuf::from("/tmp/tx/state")),
        authority_token_root: Some(PathBuf::from("/tmp/tx/state/authority/tokens")),
        hermes_state_dir: Some(PathBuf::from("/tmp/tx/state/hermes")),
        browser_profile_root: Some(PathBuf::from("/tmp/tx/browser")),
        ..Default::default()
    };
    assert!(matches!(
        packaged.derive_fixture(&overrides),
        Err(ConfigError::StatePathOutsideStateRoot { key, .. })
            if key == "executables.browser.profile_root"
    ));

    // A pinned identity change (worker_bus) is rejected outright.
    let mut tampered = packaged.clone();
    tampered.worker_bus = "unix:path=/run/other.sock".to_owned();
    assert!(
        validate_sanctioned_fixture_overrides(&packaged, &tampered, Path::new("/tmp/tx")).is_err()
    );

    // A pinned browser policy file change is rejected.
    let mut policy_swap = packaged.clone();
    if let Some(browser) = policy_swap.executables.browser.as_mut() {
        browser.policy = PathBuf::from("/tmp/tx/policy.json");
    }
    assert!(
        validate_sanctioned_fixture_overrides(&packaged, &policy_swap, Path::new("/tmp/tx"))
            .is_err()
    );
    // Move all state paths together to isolate the fixture-root containment check.
    let overrides = OdindFixtureOverrides {
        state_root: Some(PathBuf::from("/elsewhere/state")),
        authority_token_root: Some(PathBuf::from("/elsewhere/state/authority/tokens")),
        hermes_state_dir: Some(PathBuf::from("/elsewhere/state/hermes")),
        browser_profile_root: Some(PathBuf::from("/elsewhere/state/browser/profiles")),
        ..Default::default()
    };
    let derived = packaged.derive_fixture(&overrides).expect("derives");
    assert!(
        validate_sanctioned_fixture_overrides(&packaged, &derived, Path::new("/tmp/tx")).is_err()
    );

    // Keep the relocated state inside its root so only the policy change triggers refusal.
    let overrides = OdindFixtureOverrides {
        hermes_state_dir: Some(PathBuf::from("/srv/odin/state/tx-hermes")),
        ..Default::default()
    };
    let mut tampered = packaged.derive_fixture(&overrides).expect("derives");
    if let Some(hermes) = tampered.hermes.as_mut() {
        if let Some(discord) = hermes.discord.as_mut() {
            discord.seat = "someone-else".to_owned();
        }
    }
    assert!(
        validate_sanctioned_fixture_overrides(&packaged, &tampered, Path::new("/tmp/tx")).is_err()
    );
}
fn fixture_config_with_file_root() -> OdindConfig {
    let mut config = fixture_config();
    config.file_roots = vec![odin_domain::huginn::FileRoot {
        root_id: odin_domain::huginn::FileRootId::parse("atlas-root").expect("root id"),
        display_name: "Atlas".to_owned(),
        canonical_path: PathBuf::from("/srv/atlas"),
        access: odin_domain::huginn::FileRootAccess::ReadWrite,
        media_policy: odin_domain::huginn::FileMediaPolicy {
            allowed_media_types: vec!["text/plain".to_owned()],
        },
        max_object_bytes: NonZeroU64::new(4096).expect("nonzero"),
        watch_policy: odin_domain::huginn::FileWatchPolicy::Recursive,
        allowed_seats: vec![odin_domain::SeatId::new("colin").expect("seat id")],
    }];
    config
}

#[test]
fn sanctioned_fixture_overrides_move_file_roots_within_policy() {
    let packaged = fixture_config_with_file_root();
    let overrides = OdindFixtureOverrides {
        file_roots: BTreeMap::from([(
            "atlas-root".to_owned(),
            PathBuf::from("/tmp/tx/files/atlas"),
        )]),
        ..Default::default()
    };
    let derived = packaged.derive_fixture(&overrides).expect("derives");
    assert_eq!(
        derived.file_roots[0].canonical_path,
        PathBuf::from("/tmp/tx/files/atlas")
    );
    assert_eq!(derived.file_roots[0].access, packaged.file_roots[0].access);
    assert_eq!(
        derived.file_roots[0].max_object_bytes,
        packaged.file_roots[0].max_object_bytes
    );
    validate_sanctioned_fixture_overrides(&packaged, &derived, Path::new("/tmp/tx"))
        .expect("confined file root derivation accepted");
}

#[test]
fn sanctioned_fixture_overrides_reject_file_root_faults() {
    let packaged = fixture_config_with_file_root();
    // An undeclared file root id is rejected.
    let unknown = OdindFixtureOverrides {
        file_roots: BTreeMap::from([(
            "ghost-root".to_owned(),
            PathBuf::from("/tmp/tx/files/ghost"),
        )]),
        ..Default::default()
    };
    assert!(packaged.derive_fixture(&unknown).is_err());
    // A moved file root outside the fixture root is rejected.
    let escape = packaged
        .derive_fixture(&OdindFixtureOverrides {
            file_roots: BTreeMap::from([(
                "atlas-root".to_owned(),
                PathBuf::from("/elsewhere/atlas"),
            )]),
            ..Default::default()
        })
        .expect("derives");
    assert!(
        validate_sanctioned_fixture_overrides(&packaged, &escape, Path::new("/tmp/tx")).is_err()
    );
    // A mutated right or ceiling behind a moved root is rejected.
    let mut tampered = packaged
        .derive_fixture(&OdindFixtureOverrides {
            file_roots: BTreeMap::from([(
                "atlas-root".to_owned(),
                PathBuf::from("/tmp/tx/files/atlas"),
            )]),
            ..Default::default()
        })
        .expect("derives");
    tampered.file_roots[0].max_object_bytes = NonZeroU64::new(99_999).expect("nonzero");
    assert!(
        validate_sanctioned_fixture_overrides(&packaged, &tampered, Path::new("/tmp/tx")).is_err()
    );
    // Removing a declared file root is rejected.
    let mut removed = packaged.clone();
    removed.file_roots.clear();
    assert!(
        validate_sanctioned_fixture_overrides(&packaged, &removed, Path::new("/tmp/tx")).is_err()
    );
}
