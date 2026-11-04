use super::*;
use crate::schema::object::parse_object_toml;

const NORMAL_HOST: &str =
    include_str!("../../../../../registry/workloads/claude-code-host-pc/profile.toml");

fn normal_declarations() -> Vec<RegistryObject> {
    let mut objects = declarations();
    for (kind, id, source) in [
        (
            RegistryKind::Host,
            "pc",
            include_str!("../../../../../registry/hosts/pc/host.toml"),
        ),
        (
            RegistryKind::Environment,
            "claude-host-pc",
            include_str!("../../../../../registry/environments/claude-host-pc/environment.toml"),
        ),
        (RegistryKind::Workload, "claude-code-host-pc", NORMAL_HOST),
    ] {
        objects.push(parse_object_toml(kind, id, format!("fixture/{id}.toml"), source).unwrap());
    }
    objects
}

#[test]
fn summoned_sessions_and_presets_cannot_disable_remote_control() {
    let mut pod = profile();
    pod.remote_control = false;
    assert_refused(&pod, &declarations(), "require Remote Control");
    let mut host: ClaudeCodeToml = toml::from_str(NORMAL_HOST).unwrap();
    host.presets.get_mut("normal").unwrap().remote_control = false;
    assert_refused(&host, &normal_declarations(), "requires Remote Control");
}

#[test]
fn normal_preset_name_is_unique_across_enabled_workloads() {
    let profile: ClaudeCodeToml = toml::from_str(NORMAL_HOST).unwrap();
    let mut objects = normal_declarations();
    objects.push(
        parse_object_toml(
            RegistryKind::Workload,
            "duplicate",
            "fixture/duplicate.toml",
            NORMAL_HOST,
        )
        .unwrap(),
    );
    assert_refused(&profile, &objects, "declared by multiple enabled workloads");
    let ObjectConfig::ClaudeCode(duplicate) = &mut objects.last_mut().unwrap().config else {
        panic!("Claude fixture")
    };
    duplicate.enabled = false;
    assert_valid(&profile, &objects);
}

const BASELINE: &str = r#"
schema = "odin.registry.v1"
kind = "workload"
enabled = true
description = "Claude driver contract fixture."
harness = "claude-code"
account_kind = "claude-code"
accounts = "discovered"
environment = "pod-authority"
[image]
reference = "platform"

[resources]
cpu_request = "250m"
cpu_limit = "2"
memory_request = "512Mi"
memory_limit = "2Gi"
storage_limit = "4Gi"
"#;

fn profile() -> ClaudeCodeToml {
    toml::from_str(BASELINE).expect("parse Claude fixture")
}

fn declarations() -> Vec<RegistryObject> {
    [
        (
            RegistryKind::Project,
            "odin",
            include_str!("../../../../../registry/projects/odin/project.toml"),
        ),
        (
            RegistryKind::Environment,
            "pod-authority",
            include_str!("../../../../../registry/environments/pod-authority/environment.toml"),
        ),
        (
            RegistryKind::Environment,
            "sandbox-authority",
            include_str!("../../../../../registry/environments/sandbox-authority/environment.toml"),
        ),
        (
            RegistryKind::Host,
            "mini",
            include_str!("../../../../../registry/hosts/mini/host.toml"),
        ),
    ]
    .into_iter()
    .map(|(kind, id, source)| {
        parse_object_toml(kind, id, format!("fixture/{id}.toml"), source)
            .expect("parse declared authority fixture")
    })
    .collect()
}

fn assert_valid(profile: &ClaudeCodeToml, objects: &[RegistryObject]) {
    let errors = profile.validate(objects);
    assert!(
        errors.is_empty(),
        "unexpected validation errors: {errors:?}"
    );
}

fn assert_refused(profile: &ClaudeCodeToml, objects: &[RegistryObject], reason: &str) {
    let errors = profile.validate(objects);
    assert!(
        errors.iter().any(|error| error.contains(reason)),
        "expected {reason:?}, got {errors:?}"
    );
}

fn host_profile() -> ClaudeCodeToml {
    let mut profile = profile();
    profile.placement = ClaudePlacement::HostTab;
    profile.host = Some("mini".into());
    profile.environment = Some("sandbox-authority".into());
    profile
}

#[test]
fn host_tab_requires_colin_and_a_matching_declared_host_environment() {
    let objects = declarations();
    let mut profile = host_profile();
    assert_eq!(profile.driver(), ClaudeDriver::Owner);
    assert_eq!(profile.environment().unwrap(), "sandbox-authority");
    assert_valid(&profile, &objects);
    profile.environment = None;
    assert!(profile.environment().unwrap_err().contains("must declare"));
    profile.environment = Some("sandbox-authority".into());
    profile.driver = Some(ClaudeDriver::Owner);
    assert_valid(&profile, &objects);
    profile.driver = Some(ClaudeDriver::Sinmara);
    assert_valid(&profile, &objects);
    profile.driver = None;
    profile.host = None;
    assert_refused(
        &profile,
        &objects,
        "host-tab requires an enabled declared host",
    );
    profile.host = Some("undeclared".into());
    assert_refused(
        &profile,
        &objects,
        "host-tab requires an enabled declared host",
    );
    profile.host = Some("mini".into());
    profile.environment = Some("pod-authority".into());
    assert_refused(
        &profile,
        &objects,
        "host-tab environment must name the selected fleet host",
    );
}

#[test]
fn skip_permissions_defaults_by_placement_and_honors_explicit_overrides() {
    let objects = declarations();
    let host = host_profile();
    assert_eq!(host.skip_permissions, None);
    assert!(!host.skip_permissions());
    assert_valid(&host, &objects);
    for placement in [ClaudePlacement::Pod, ClaudePlacement::HostTab] {
        for enabled in [true, false] {
            let mut profile: ClaudeCodeToml =
                toml::from_str(&format!("skip_permissions = {enabled}\n{BASELINE}")).unwrap();
            profile.placement = placement;
            if placement == ClaudePlacement::HostTab {
                profile.host = Some("mini".into());
                profile.environment = Some("sandbox-authority".into());
            }
            assert_eq!(profile.skip_permissions, Some(enabled));
            assert_eq!(profile.skip_permissions(), enabled);
            assert_valid(&profile, &objects);
        }
    }
}

fn mcp_profile() -> ClaudeCodeToml {
    toml::from_str(&format!(
        "mcp = [\"files\"]\n{BASELINE}\n{}",
        r#"
[mcp_servers.files]
command = "/odin/bin/mcp-server-filesystem"
args = ["{worktree}"]
scope = "worktree"

[mcp_servers.browser]
command = "/usr/bin/browser-mcp"
args = ["--index={worktree}/index"]
env = { INDEX_ROOT = "{worktree}/index" }
scope = "browser"
"#
    ))
    .expect("parse MCP fixture")
}

#[test]
fn mcp_selection_rejects_undeclared_unadmitted_and_duplicate_servers() {
    let objects = declarations();
    let mut profile = mcp_profile();
    assert_valid(&profile, &objects);
    for selection in [
        vec!["missing".into()],
        vec!["browser".into()],
        vec!["files".into(), "files".into()],
    ] {
        assert!(
            profile.mcp_config(&selection, CLAUDE_WORKTREE).is_err(),
            "accepted {selection:?}"
        );
    }
    profile.mcp.push("missing".into());
    assert_refused(&profile, &objects, "MCP missing is repeated or undeclared");
    profile.mcp = vec!["files".into(), "files".into()];
    assert_refused(&profile, &objects, "MCP files is repeated or undeclared");
}

#[test]
fn worktree_mcp_cannot_add_roots_or_network_egress() {
    let objects = declarations();
    for args in [
        vec![],
        vec!["/".into()],
        vec!["{worktree}".into(), "/".into()],
        vec!["{worktree}".into(), "--index={worktree}/index".into()],
    ] {
        let mut profile = mcp_profile();
        profile.mcp_servers.get_mut("files").unwrap().args = args;
        assert_refused(
            &profile,
            &objects,
            "worktree scope requires the official placement-specific filesystem server",
        );
    }
    let mut profile = mcp_profile();
    profile.mcp_servers.get_mut("files").unwrap().allow_hosts = vec!["api.anthropic.com".into()];
    assert_refused(
        &profile,
        &objects,
        "worktree scope requires the official placement-specific filesystem server",
    );
}

#[test]
fn mcp_config_expands_only_selected_servers_into_owned_worktree() {
    let profile = mcp_profile();
    let worktree = "/workspace/owned-clone";
    assert_eq!(
        profile.mcp_config(&["files".into()], worktree).unwrap(),
        serde_json::json!({
            "mcpServers": {
                "files": {
                    "type": "stdio",
                    "command": "/odin/bin/mcp-server-filesystem",
                    "args": ["/workspace/owned-clone"],
                    "env": {}
                }
            }
        })
    );
    assert_eq!(
        profile.mcp_config(&[], worktree).unwrap(),
        serde_json::json!({"mcpServers": {}})
    );
    assert!(profile
        .mcp_config(&["files".into()], "relative/worktree")
        .is_err());
}

#[test]
fn worktree_mcp_requires_official_executable_and_no_environment_overrides() {
    let objects = declarations();
    for (placement, official, other) in [
        (
            ClaudePlacement::Pod,
            "/odin/bin/mcp-server-filesystem",
            "/etc/profiles/per-user/owner/bin/mcp-server-filesystem",
        ),
        (
            ClaudePlacement::HostTab,
            "/etc/profiles/per-user/owner/bin/mcp-server-filesystem",
            "/odin/bin/mcp-server-filesystem",
        ),
    ] {
        let mut profile = mcp_profile();
        profile.placement = placement;
        if placement == ClaudePlacement::HostTab {
            profile.host = Some("mini".into());
            profile.environment = Some("sandbox-authority".into());
        }
        profile.mcp_servers.get_mut("files").unwrap().command = official.into();
        assert_valid(&profile, &objects);
        for command in [
            "/bin/sh",
            other,
            "/etc/profiles/per-user/owner/bin/sh",
            "/etc/profiles/per-user/../bin/mcp-server-filesystem",
        ] {
            profile.mcp_servers.get_mut("files").unwrap().command = command.into();
            assert_refused(
                &profile,
                &objects,
                "worktree scope requires the official placement-specific filesystem server",
            );
        }
        profile.mcp_servers.get_mut("files").unwrap().command = official.into();
        if placement == ClaudePlacement::HostTab {
            // Whichever user the host runs as, the filesystem server is that user's own profile binary.
            profile.mcp_servers.get_mut("files").unwrap().command =
                "/etc/profiles/per-user/other/bin/mcp-server-filesystem".into();
            assert_valid(&profile, &objects);
            profile.mcp_servers.get_mut("files").unwrap().command = official.into();
        }
        for (key, value) in [
            ("NODE_OPTIONS", "--require=/tmp/inject.js"),
            ("LANG", "en_US.UTF-8"),
        ] {
            profile.mcp_servers.get_mut("files").unwrap().env =
                BTreeMap::from([(key.into(), value.into())]);
            assert_refused(
                &profile,
                &objects,
                "worktree scope requires the official placement-specific filesystem server",
            );
        }
    }
}

#[test]
fn arbitrary_seat_memory_and_commands_are_not_workload_authority() {
    for field in [
        "seat = \"gungnir\"",
        "memory = \"atlas.code\"",
        "command = \"/bin/sh\"",
        "seat = { seat = \"gungnir\" }",
        "memory = { namespace = \"atlas.code\" }",
    ] {
        let source = format!("{field}\n{BASELINE}");
        let error = toml::from_str::<ClaudeCodeToml>(&source)
            .expect_err("unknown authority field accepted");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
    for field in [
        "command = \"/bin/sh\"",
        "memory = \"atlas.code\"",
        "seat = \"gungnir\"",
    ] {
        let source = format!("{BASELINE}\n{field}");
        let error =
            toml::from_str::<ClaudeCodeToml>(&source).expect_err("unknown resource field accepted");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
    let source = format!("{BASELINE}\n[mcp_servers.files]\ncommand = \"/bin/files\"\nscope = \"worktree\"\nargs = [\"{{worktree}}\"]\nseat = \"gungnir\"\n");
    let error = toml::from_str::<ClaudeCodeToml>(&source)
        .expect_err("unknown MCP authority field accepted");
    assert!(error.to_string().contains("unknown field"), "{error}");
}
