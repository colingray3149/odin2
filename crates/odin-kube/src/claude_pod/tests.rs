use super::*;

fn plan() -> ClaudePodPlan {
    ClaudePodPlan {
        run_id: RunId::new("run:live:0f1e2d3c-0000-4000-8000-000000000001").unwrap(),
        session: "0f1e2d3c-0000-4000-8000-000000000001".into(),
        image: format!("registry/claude@sha256:{}", "a".repeat(64)),
        clone_url: "git://10.77.0.11:9418/odin.git".into(),
        revision: "main".into(),
        branch: "claude/test".into(),
        account_files: BTreeMap::from([
            (".credentials.json".into(), b"secret-login".to_vec()),
            (".claude.json".into(), b"secret-account".to_vec()),
        ]),
        mcp_config: serde_json::json!({"mcpServers": {}}),
        supervisor_script: b"# trusted supervisor\n".to_vec(),
        git_helper_script: b"# trusted git helper\n".to_vec(),
        allow_hosts: vec![],
        egress_targets: vec![],
        cpu_request: "250m".into(),
        cpu_limit: "2".into(),
        memory_request: "512Mi".into(),
        memory_limit: "4Gi".into(),
        storage_limit: "8Gi".into(),
    }
}

#[test]
fn manifest_has_no_host_mounts_or_ambient_credentials() {
    let plan = plan();
    let pod = desired_pod(&plan).unwrap();
    let json = serde_json::to_string(&pod).unwrap();
    assert!(!json.contains("hostPath"));
    assert!(!json.contains("secret-login"));
    assert!(!json.contains("secret-account"));
    let spec = pod.spec.unwrap();
    assert_eq!(spec.automount_service_account_token, Some(false));
    assert_eq!(spec.enable_service_links, Some(false));
    assert!(spec.scheduling_gates.is_none());
    assert_eq!(spec.restart_policy.as_deref(), Some("Never"));
    let volumes = spec.volumes.unwrap();
    assert_eq!(volumes.len(), 5);
    assert_eq!(volumes.iter().filter(|v| v.empty_dir.is_some()).count(), 4);
    let secret = volumes.iter().find_map(|v| v.secret.as_ref()).unwrap();
    assert_eq!(
        secret.secret_name.as_deref(),
        Some(format!("{}-material", pod_name(&plan.run_id)).as_str())
    );
    assert_eq!(secret.default_mode, Some(0o440));
    let items = secret.items.as_ref().unwrap();
    assert_eq!(
        items
            .iter()
            .map(|item| item.key.as_str())
            .collect::<Vec<_>>(),
        [
            ".credentials.json",
            ".claude.json",
            "mcp.json",
            "supervisor.py",
            "publication.json",
            "git-remote-odin"
        ]
    );
    assert!(items.iter().all(|item| item.mode
        == Some(if item.key == "git-remote-odin" {
            0o550
        } else {
            0o440
        })));
    let security = spec.security_context.unwrap();
    assert_eq!(security.run_as_non_root, Some(true));
    assert_eq!(security.fs_group, Some(1000));
    assert_eq!(security.seccomp_profile.unwrap().type_, "RuntimeDefault");
    for container in spec
        .containers
        .iter()
        .chain(spec.init_containers.as_ref().unwrap())
    {
        let resources = container.resources.as_ref().unwrap();
        assert_eq!(resources.limits.as_ref().unwrap()["cpu"].0, "2");
        assert_eq!(resources.limits.as_ref().unwrap()["memory"].0, "4Gi");
        assert_eq!(
            resources.limits.as_ref().unwrap()["ephemeral-storage"].0,
            "8Gi"
        );
        let security = container.security_context.as_ref().unwrap();
        assert_eq!(security.read_only_root_filesystem, Some(true));
        assert_eq!(security.allow_privilege_escalation, Some(false));
        assert_eq!(
            security
                .capabilities
                .as_ref()
                .unwrap()
                .drop
                .as_ref()
                .unwrap(),
            &["ALL"]
        );
    }
    let supervisor = &spec.containers[0];
    assert_eq!(
        supervisor.command.as_ref().unwrap(),
        &[
            "/bin/python3",
            "-I",
            "/run/odin-material/supervisor.py",
            "serve"
        ]
    );
    assert_eq!(
        supervisor.working_dir.as_deref(),
        Some("/run/odin-supervisor")
    );
    let security = supervisor.security_context.as_ref().unwrap();
    assert_eq!(security.run_as_user, Some(0));
    assert_eq!(security.run_as_group, Some(0));
    assert_eq!(security.run_as_non_root, Some(false));
    assert_eq!(
        security
            .capabilities
            .as_ref()
            .unwrap()
            .add
            .as_ref()
            .unwrap(),
        &["SETUID", "SETGID", "KILL"]
    );
    assert!(supervisor
        .volume_mounts
        .as_ref()
        .unwrap()
        .iter()
        .any(
            |mount| mount.name == "supervisor-state" && mount.mount_path == "/run/odin-supervisor"
        ));
    let init = &spec.init_containers.as_ref().unwrap()[0];
    assert_eq!(
        init.security_context.as_ref().unwrap().run_as_non_root,
        Some(true)
    );
    assert!(init
        .security_context
        .as_ref()
        .unwrap()
        .capabilities
        .as_ref()
        .unwrap()
        .add
        .is_none());
    assert!(!init
        .volume_mounts
        .as_ref()
        .unwrap()
        .iter()
        .any(|mount| mount.name == "supervisor-state"));
}

#[test]
fn admission_rejects_foreign_material_and_publish_credentials() {
    let mut plan = plan();
    plan.account_files
        .insert("foreign/.credentials.json".into(), vec![1]);
    assert!(desired_pod(&plan).is_err());
    plan.account_files.remove("foreign/.credentials.json");
    plan.account_files.remove(".claude.json");
    assert!(desired_pod(&plan).is_err());
    plan.account_files.insert(".claude.json".into(), vec![1]);
    plan.clone_url = "https://token@example.com/repo".into();
    assert!(desired_pod(&plan).is_err());
    plan.clone_url = "git://mirror/repo".into();
    for branch in [
        "main",
        "claude/../main",
        "claude/a/b",
        "claude/-bad;echo",
        "claude/",
    ] {
        plan.branch = branch.into();
        assert!(desired_pod(&plan).is_err(), "{branch}");
    }
}

#[test]
fn clone_parameters_are_not_interpolated_into_shell_source() {
    let mut plan = plan();
    plan.revision = "refs/heads/feature;touch_/tmp/escape".into();
    let pod = desired_pod(&plan).unwrap();
    let spec = pod.spec.unwrap();
    let argv = spec.init_containers.unwrap().remove(0).command.unwrap();
    assert!(!argv[2].contains(&plan.revision));
    assert_eq!(argv[5], plan.revision);
    assert!(argv[2].contains("git checkout --no-track -b \"$3\" \"$2\""));
    assert!(argv[2].contains("git remote set-url --push origin odin::"));
}

#[test]
fn presence_rejects_replacement_and_annotation_mismatch() {
    let plan = plan();
    let mut pod = desired_pod(&plan).unwrap();
    let worker = WorkerId::new("claude-worker").unwrap();
    let correlation = crate::terminal_pod::terminal_correlation(&plan.session).unwrap();
    bind(&mut pod.metadata, &worker, &correlation);
    pod.metadata.uid = Some("pod-uid".into());
    pod.status = Some(PodStatus {
        phase: Some("Running".into()),
        ..Default::default()
    });
    let handle = ClaudePodReceipt {
        worker: worker.as_str().into(),
        branch: plan.branch,
        policy_spec: None,
        identity: PodWorkerIdentity {
            cluster: "test".into(),
            namespace: "odin".into(),
            pod_name: pod.metadata.name.clone().unwrap(),
            pod_uid: Some("pod-uid".into()),
            policy_name: "policy".into(),
            policy_uid: Some("policy-uid".into()),
            secret_name: Some("material".into()),
            secret_uid: Some("secret-uid".into()),
            correlation_id: correlation.as_str().into(),
        },
    };
    assert_eq!(presence(&pod, &handle).unwrap(), ClaudePodPresence::Running);
    pod.metadata.uid = Some("replacement".into());
    assert!(presence(&pod, &handle).is_err());
    pod.metadata.uid = handle.identity.pod_uid.clone();
    pod.metadata
        .annotations
        .as_mut()
        .unwrap()
        .insert(WORKER.into(), "foreign-worker".into());
    assert!(presence(&pod, &handle).is_err());
}

#[test]
fn egress_policy_selects_claude_pod() {
    let plan = plan();
    let resolved = crate::workload::ResolvedEgress {
        sites: BTreeMap::new(),
        pinned: vec![],
    };
    let policy = crate::workload::desired_egress_policy(&plan.run_id, &resolved);
    let spec = policy.spec.unwrap();
    assert_eq!(spec.policy_types.unwrap(), ["Egress"]);
    let labels = desired_pod(&plan).unwrap().metadata.labels.unwrap();
    assert!(spec
        .pod_selector
        .unwrap()
        .match_labels
        .unwrap()
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value)));
}
