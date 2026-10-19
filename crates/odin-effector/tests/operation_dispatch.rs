#[cfg(test)]
mod effector_operation_dispatch {
    //! Full authority round trips through the real compiled effector: the
    //! fixture host drives the sidecar's EffectorExecutor, which launches
    //! THIS crate's binary through StopAuthority as a registered worker,
    //! and effects land in the sealed capsule of a real throwaway git repo.
    //! No mocks, no literal verdicts, no direct spawn.

    use odin_domain::operation::Limits;
    use odin_domain::SessionId;
    use odin_kernel::token::{MintRequest, TokenIssuer};
    use odin_process::test_support::RegisteredWorkerFixture;
    use odin_process::WorkerChannel;
    use odin_sidecar::{
        effect_receipt_at, AuthorityConfig, EffectorExecutor, EffectorSandboxBinding, Provisioning,
        Sidecar, SidecarErrorCode, TransportProjection,
    };
    use odin_sidecar_protocol::{
        echoes, Arguments, Budget, CloseMode, Request, Response, U64Wire, Version,
        EFFECT_MAX_REQUEST_BYTES,
    };
    use odin_types::{CapsuleId, CorrelationId, OperationId, ToolId};
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command as StdCommand;
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const SIGNING_KEY: &[u8] = b"wp07 effector round trip signing key";
    const EXECUTE_HELPER_MARKER: &str = "execute-helper-started.json";
    const EXECUTE_HELPER_MARKER_VAR: &str = "ODIN_EFFECTOR_TEST_EXECUTE_HELPER_MARKER";
    const EXECUTE_HELPER_ARGS: [&str; 5] = [
        "--exact",
        "effector_operation_dispatch::execute_fixture_helper",
        "--test-threads",
        "1",
        "--nocapture",
    ];
    static FIXTURE_GIT_BIN: std::sync::LazyLock<PathBuf> =
        std::sync::LazyLock::new(|| store_tool("git", "ODIN_SWEEP_GIT_BIN"));
    static FIXTURE_UNSHARE_BIN: std::sync::LazyLock<PathBuf> =
        std::sync::LazyLock::new(|| absolute_tool("unshare", "ODIN_TEST_WORKER_UNSHARE"));
    static FIXTURE_BWRAP_BIN: std::sync::LazyLock<PathBuf> =
        std::sync::LazyLock::new(|| store_tool("bwrap", "ODIN_SWEEP_BWRAP"));

    #[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureProcessIdentity {
        pid: i32,
        start_time_ticks: u64,
        process_group: i32,
    }

    /// Keeps the real sidecar authority ahead of its isolated manager guard
    /// in drop order, so every worker is retired before the fixture socket
    /// and cgroup observations are removed.
    struct FixtureHost {
        sidecar: Arc<Sidecar>,
        _worker_fixture: Arc<RegisteredWorkerFixture>,
    }

    impl std::ops::Deref for FixtureHost {
        type Target = Sidecar;

        fn deref(&self) -> &Self::Target {
            self.sidecar.as_ref()
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Resolves one test tool exactly once to the explicit executable already
    /// provisioned by the suite, following the shared env-then-PATH fixture
    /// convention. A bare command name is never retained in the binding.
    fn absolute_tool(name: &str, env_key: &str) -> PathBuf {
        if let Some(value) = std::env::var_os(env_key) {
            let path = PathBuf::from(value);
            assert!(path.is_absolute(), "{env_key} must be an absolute path");
            assert!(path.is_file(), "{env_key} must name a file");
            return path;
        }
        let path_var = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path_var)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_absolute() && candidate.is_file())
            .unwrap_or_else(|| panic!("no absolute {name} found on PATH"))
    }

    /// Canonicalizes one discovered tool to its real executable and requires
    /// the Nix store path production manifests always provision: the git
    /// observation sandbox execs git inside a sealed mount namespace where
    /// only /nix/store, /proc, and /dev exist, so a profile-symlink tool
    /// path would be invisible there.
    fn store_tool(name: &str, env_key: &str) -> PathBuf {
        let path = std::fs::canonicalize(absolute_tool(name, env_key))
            .expect("discovered tool resolves to a real file");
        assert!(
            path.starts_with("/nix/store/"),
            "{env_key} must resolve to a Nix store path for the sealed sandbox; got {}",
            path.display()
        );
        path
    }

    fn fixture_git_bin() -> &'static Path {
        FIXTURE_GIT_BIN.as_path()
    }

    fn effector_bin() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_odin-effector"))
    }

    fn git(args: &[&str], cwd: &Path) -> String {
        let fixture_root = cwd.parent().expect("capsule fixture parent");
        let home = fixture_root.join("git-home");
        let xdg = fixture_root.join("git-xdg");
        std::fs::create_dir_all(&home).expect("fixture git home");
        std::fs::create_dir_all(&xdg).expect("fixture git XDG root");
        let output = StdCommand::new(fixture_git_bin())
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &xdg)
            .env("XDG_STATE_HOME", &xdg)
            .env("XDG_CACHE_HOME", &xdg)
            .env(
                "XDG_RUNTIME_DIR",
                std::env::var_os("XDG_RUNTIME_DIR").expect("disposable runtime root"),
            )
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("LC_ALL", "C")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git output utf-8")
            .trim()
            .to_owned()
    }

    fn fixture_process_identity(pid: i32) -> Result<FixtureProcessIdentity, String> {
        if pid <= 0 {
            return Err(format!("helper reported invalid pid {pid}"));
        }
        let raw = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|error| format!("could not read helper /proc identity: {error}"))?;
        let suffix = raw
            .rsplit_once(')')
            .map(|(_, suffix)| suffix)
            .ok_or_else(|| "helper /proc identity omitted the command terminator".to_owned())?;
        let mut fields = suffix.split_whitespace();
        let process_group = fields
            .nth(2)
            .ok_or_else(|| "helper /proc identity omitted the process group".to_owned())?
            .parse::<i32>()
            .map_err(|error| format!("helper process group was malformed: {error}"))?;
        let start_time_ticks = fields
            .nth(16)
            .ok_or_else(|| "helper /proc identity omitted start time".to_owned())?
            .parse::<u64>()
            .map_err(|error| format!("helper start time was malformed: {error}"))?;
        Ok(FixtureProcessIdentity {
            pid,
            start_time_ticks,
            process_group,
        })
    }

    fn publish_started_helper(marker: &Path) {
        let pid = i32::try_from(std::process::id()).expect("helper pid fits i32");
        let identity = fixture_process_identity(pid).expect("live helper identity");
        let encoded = serde_json::to_vec(&identity).expect("helper identity JSON");
        let staging = marker.with_extension(format!("tmp-{pid}"));
        std::fs::write(&staging, encoded).expect("stage helper identity");
        std::fs::rename(&staging, marker).expect("publish helper identity");
    }

    fn wait_for_started_helper<T>(
        marker: &Path,
        invoker: &std::thread::JoinHandle<T>,
        timeout: Duration,
    ) -> Result<FixtureProcessIdentity, String> {
        let deadline = Instant::now() + timeout;
        loop {
            match std::fs::read(marker) {
                Ok(bytes) => {
                    let reported: FixtureProcessIdentity =
                        serde_json::from_slice(&bytes).map_err(|error| {
                            format!("helper identity marker was malformed: {error}")
                        })?;
                    let live = fixture_process_identity(reported.pid).map_err(|error| {
                        format!("reported helper identity {reported:?} was not live: {error}")
                    })?;
                    if live != reported {
                        return Err(format!(
                            "reported helper identity {reported:?} changed to {live:?}"
                        ));
                    }
                    return Ok(reported);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!("helper identity marker could not be read: {error}"));
                }
            }
            if invoker.is_finished() {
                return Err("invoke finished before the execute helper started".to_owned());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "execute helper did not report its identity within {} ms",
                    timeout.as_millis()
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A real sealed capsule: a throwaway git repo pinned to one commit.
    fn capsule_fixture(root: &Path) -> (PathBuf, String) {
        let capsule = root.join("capsule");
        std::fs::create_dir_all(&capsule).expect("capsule dir");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&capsule, std::fs::Permissions::from_mode(0o700))
            .expect("protect capsule root");
        git(&["init", "-q"], &capsule);
        git(&["config", "user.email", "wp07@odin"], &capsule);
        git(&["config", "user.name", "wp07"], &capsule);
        git(&["config", "commit.gpgsign", "false"], &capsule);
        std::fs::write(capsule.join("README"), "wp07\n").expect("seed file");
        git(&["add", "."], &capsule);
        git(&["commit", "-q", "-m", "wp07"], &capsule);
        let commit = git(&["rev-parse", "HEAD"], &capsule);
        (capsule, commit)
    }

    fn strict_arguments(value: &serde_json::Value) -> Arguments {
        let bytes = serde_json::to_vec(value).expect("arguments bytes");
        Arguments::new(
            odin_strict_json::decode(&bytes, EFFECT_MAX_REQUEST_BYTES).expect("strict arguments"),
        )
        .expect("arguments")
    }

    fn projection_bytes(effector: &Path) -> Vec<u8> {
        let digest_of = |seed: &str| format!("blake3:{}", blake3::hash(seed.as_bytes()).to_hex());
        serde_json::json!({
            "schema": "OdinTransportProjection/v1",
            "snapshot_revision": 7,
            "snapshot_digest": digest_of("capability policy"),
            "expected": {
                "seat": "seat.wp07",
                "slice": "slice.wp07",
                "lane": "lane.wp07",
                "session": "00000000-0000-4000-8000-000000000707",
                "seat_revision": digest_of("seat revision"),
                "slice_revision": digest_of("slice revision"),
                "capability_policy_digest": digest_of("capability policy"),
                "context_policy_digest": digest_of("context policy")
            },
            "plan": { "gate": "accepted", "plan_id": "plan-wp07" },
            "policy": {
                "seat_tool_refs": ["capsule.write", "capsule.run"],
                "slice_capabilities": ["capsule.write", "capsule.run"],
                "project_capabilities": ["capsule.write", "capsule.run"],
                "lane_capabilities": ["capsule.write", "capsule.run"],
                "seat_categories": ["builder"]
            },
            "capabilities": [
                {
                    "id": "capsule.write",
                    "version": 1,
                    "tool_name": "capsule_write",
                    "description": "write one capsule file",
                    "handler": {
                        "kind": "exec",
                        "executable": effector.display().to_string(),
                        "argv": ["write"]
                    },
                    "evidence_extractor": { "kind": "builtin", "name": "effector_evidence" },
                    "input_schema_ref": "schemas/write.json",
                    "output_schema_ref": "schemas/out.json",
                    "effect_class": "R1",
                    "seat_tags": ["builder"],
                    "timeout_seconds": 20,
                    "idempotency": "required",
                    "retry_max_attempts": 1,
                    "approval": "none"
                },
                {
                    "id": "capsule.run",
                    "version": 1,
                    "tool_name": "capsule_run",
                    "description": "run one supervised command",
                    "handler": {
                        "kind": "exec",
                        "executable": effector.display().to_string(),
                        "argv": ["execute"]
                    },
                    "evidence_extractor": { "kind": "builtin", "name": "effector_evidence" },
                    "input_schema_ref": "schemas/run.json",
                    "output_schema_ref": "schemas/out.json",
                    "effect_class": "R1",
                    "seat_tags": ["builder"],
                    "timeout_seconds": 30,
                    "idempotency": "required",
                    "retry_max_attempts": 1,
                    "approval": "none"
                }
            ],
            "schemas": {
                "schemas/write.json": {
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string" },
                        "content_hex": { "type": "string" },
                        "old_hex": { "type": "string" },
                        "new_hex": { "type": "string" },
                        "preimage_sha256": { "type": "string" }
                    },
                    "additionalProperties": false
                },
                "schemas/run.json": {
                    "type": "object",
                    "required": ["argv", "current_dir", "timeout_ms", "term_grace_ms",
                                 "max_stdout_bytes", "max_stderr_bytes"],
                    "properties": {
                        "argv": { "type": "array", "items": { "type": "string" } },
                        "environment": {
                            "type": "object",
                            "additionalProperties": { "type": "string" }
                        },
                        "current_dir": { "type": "string" },
                        "timeout_ms": { "type": "integer" },
                        "term_grace_ms": { "type": "integer" },
                        "max_stdout_bytes": { "type": "integer" },
                        "max_stderr_bytes": { "type": "integer" }
                    },
                    "additionalProperties": false
                },
                "schemas/out.json": { "type": "object" }
            },
            "builtins": ["effector_evidence"]
        })
        .to_string()
        .into_bytes()
    }

    fn fixture_channel(fixture: &RegisteredWorkerFixture) -> WorkerChannel {
        let harness = std::env::current_exe().expect("test harness path");
        fixture
            .channel_for_harness(
                &harness,
                "effector_operation_dispatch::worker_bootstrap_fixture_entry",
                FIXTURE_UNSHARE_BIN.as_path(),
            )
            .expect("isolated registered worker channel")
    }

    /// Pin the immutable test binary once; real launches still verify its identity.
    static FIXTURE_EFFECTOR_BINDING_DIGEST: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| {
            let bytes = std::fs::read(effector_bin()).expect("compiled effector bytes");
            blake3::hash(&bytes).to_hex().to_string()
        });

    /// Uses bubblewrap with private eval caches and only git's directory on PATH;
    /// no host context, cargo cache, or Nix configuration is admitted.
    fn fixture_sandbox_binding(root: &Path) -> EffectorSandboxBinding {
        let bwrap = FIXTURE_BWRAP_BIN.clone();
        // The sandbox execs git by its absolute store path; the sandbox PATH
        // stays minimal — exactly that tool's own directory.
        let git_dir = fixture_git_bin()
            .parent()
            .expect("git tool parent directory")
            .to_path_buf();
        let tool_path = std::env::join_paths([git_dir])
            .expect("tool directory joins into a PATH")
            .into_string()
            .expect("tool directory is UTF-8");
        let cache_root = root.join("sandbox");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::create_dir_all(&cache_root).expect("sandbox cache root");
        std::fs::set_permissions(&cache_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect sandbox cache root");
        for directory in ["cargo-home", "target", "home"] {
            let path = cache_root.join(directory);
            std::fs::create_dir_all(&path).expect("sandbox cache directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("protect sandbox cache directory");
        }
        EffectorSandboxBinding::new(bwrap, cache_root, tool_path, None, None, None, None)
            .expect("fixture sandbox binding")
    }

    fn fixture_host(root: &Path, clock: odin_sidecar::Clock) -> FixtureHost {
        let worker_fixture = Arc::new(
            RegisteredWorkerFixture::new_delegated().expect("delegated registered worker fixture"),
        );
        let (capsule_root, source_commit) = capsule_fixture(root);
        let now = now_ms();
        let issuer = TokenIssuer::new(SIGNING_KEY.to_vec()).expect("issuer");
        let token = issuer
            .mint(MintRequest {
                seat: odin_domain::SeatId::parse("seat.wp07").expect("seat"),
                slice: odin_domain::SliceId::parse("slice.wp07").expect("slice"),
                lane: odin_domain::LaneId::parse("lane.wp07").expect("lane"),
                session: SessionId::parse("00000000-0000-4000-8000-000000000707").expect("session"),
                seat_revision: odin_domain::Digest::hash(b"seat revision"),
                slice_revision: odin_domain::Digest::hash(b"slice revision"),
                capability_policy_digest: odin_domain::Digest::hash(b"capability policy"),
                context_policy_digest: odin_domain::Digest::hash(b"context policy"),
                issued_at_ms: now,
                expires_at_ms: now + 600_000,
                entropy: b"wp07-entropy",
            })
            .expect("token");

        let program = effector_bin();
        let projection =
            TransportProjection::from_bytes(&projection_bytes(&program)).expect("projection");

        let executor = EffectorExecutor::new(
            program.clone(),
            FIXTURE_EFFECTOR_BINDING_DIGEST.as_str(),
            odin_sidecar_protocol::CapsuleBinding {
                capsule_id: "capsule-wp07".to_owned(),
                root: capsule_root.display().to_string(),
                source_commit,
                source_kind: "git-commit".to_owned(),
                git_bin: fixture_git_bin()
                    .to_str()
                    .expect("fixture git path is UTF-8")
                    .to_owned(),
            },
            clock,
            fixture_channel(&worker_fixture),
        )
        .expect("executor")
        .with_sandbox(fixture_sandbox_binding(root));
        let config =
            AuthorityConfig::new(Limits::new(256, 32, 0), 262_144, executor).expect("config");
        let provisioning = Provisioning::new(token, SIGNING_KEY.to_vec()).expect("provisioning");
        let sidecar =
            Sidecar::create_or_open(&root.join("state"), config, projection, provisioning)
                .expect("host");
        FixtureHost {
            sidecar: Arc::new(sidecar),
            _worker_fixture: worker_fixture,
        }
    }

    fn invoke_request(
        correlation: &str,
        capability: ToolId,
        arguments: serde_json::Value,
    ) -> Request {
        Request::InvokeCapability {
            wire: Version,
            capsule_id: CapsuleId::new("capsule-wp07").expect("capsule id"),
            correlation_id: CorrelationId::new(correlation).expect("correlation id"),
            capability,
            budget: Budget {
                requests: U64Wire::new(1),
                stops: U64Wire::new(0),
                spend: U64Wire::new(0),
            },
            arguments: strict_arguments(&arguments),
        }
    }

    fn try_durable_row(
        root: &Path,
        correlation: &str,
    ) -> odin_ledger::LedgerResult<Option<odin_ledger::operation::OperationRow>> {
        let ledger = odin_ledger::Ledger::open(root.join("state").join("authority-ledger.db"))?;
        odin_ledger::operation::operation_row(ledger.connection(), correlation)
    }

    fn durable_row(root: &Path, correlation: &str) -> odin_ledger::operation::OperationRow {
        try_durable_row(root, correlation)
            .expect("row query")
            .expect("durable row")
    }

    /// The libtest entry used when this harness stands in for the packaged
    /// worker bootstrap. The ordinary outer test run is a no-op.
    #[test]
    fn worker_bootstrap_fixture_entry() {
        odin_process::test_support::run_bootstrap_if_active();
    }

    /// The single libtest entry re-executed as the real blocking payload. It
    /// is a no-op in the outer suite; payload mode publishes a live `/proc`
    /// identity only after the execute request reached this process.
    #[test]
    fn execute_fixture_helper() {
        let Some(marker) = std::env::var_os(EXECUTE_HELPER_MARKER_VAR) else {
            return;
        };
        publish_started_helper(Path::new(&marker));
        loop {
            std::thread::park();
        }
    }

    #[test]
    fn expired_deadlines_never_dispatch_an_effect_request() {
        use std::sync::atomic::{AtomicU64, Ordering};
        for (stage, after_launch) in [("before-setup", false), ("before-send", true)] {
            let root = std::env::temp_dir().join(format!(
                "odin-effector-expired-{stage}-{}-{}",
                std::process::id(),
                now_ms()
            ));
            std::fs::create_dir_all(&root).expect("fixture root");
            let ledger_path = root.join("state/authority-ledger.db");
            let observed_ledger = ledger_path.clone();
            let elapsed = AtomicU64::new(0);
            let clock = Arc::new(move || {
                let now = now_ms();
                if !after_launch {
                    // Model expiry between deadline capture and setup, not a frozen clock.
                    return now + elapsed.fetch_add(60_000, Ordering::SeqCst);
                }
                let running = observed_ledger.is_file()
                    && odin_ledger::Ledger::open(&observed_ledger).expect("clock ledger")
                        .connection().query_row(
                            "SELECT EXISTS(SELECT 1 FROM worker_registry WHERE state = 'payload_running')",
                            [], |row| row.get::<_, bool>(0),
                        ).expect("worker launch observation");
                if running {
                    now + 60_000
                } else {
                    now
                }
            });
            let host = fixture_host(&root, clock);
            std::fs::create_dir(root.join("capsule/notes")).expect("write parent");
            let correlation = "abcdef0123456789abcdef0123456789";
            let rejected = host.transport(invoke_request(
                correlation, ToolId::new("capsule.write").expect("tool"),
                serde_json::json!({"path":"notes/never.txt","content_hex":odin_types::hash::hex_encode(b"must not land")}),
            )).expect_err("expired work cannot dispatch");
            assert_eq!(
                rejected.code, "executor.rejected",
                "pre-send outcome remains known"
            );
            assert!(!root.join("capsule/notes/never.txt").exists());
            assert!(try_durable_row(&root, correlation)
                .expect("operation query")
                .is_none());
            let ledger = odin_ledger::Ledger::open(&ledger_path).expect("worker ledger");
            let (workers, unstopped): (u64, u64) = ledger
                .connection()
                .query_row(
                    "SELECT COUNT(*), COALESCE(SUM(state != 'stopped'), 0) FROM worker_registry",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("durable worker outcomes");
            assert_eq!(
                workers,
                u64::from(after_launch),
                "no unexpected worker was launched"
            );
            assert_eq!(unstopped, 0, "an idle pre-send worker must be retired");
            drop(ledger);
            drop(host);
            std::fs::remove_dir_all(root).expect("fixture cleanup");
        }
    }

    #[test]
    fn invoke_effect_commits_replays_and_echoes_exact_ids() {
        let root = std::env::temp_dir().join(format!(
            "odin-effector-commit-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&root).expect("fixture root");
        let host = fixture_host(&root, odin_sidecar::system_clock());
        // Atomic file creation requires an existing, confined parent.
        std::fs::create_dir(root.join("capsule/notes")).expect("nested write parent");

        let request = invoke_request(
            "00112233445566778899aabbccddeeff",
            ToolId::new("capsule.write").expect("tool id"),
            serde_json::json!({
                "path": "notes/a.txt",
                "content_hex": odin_types::hash::hex_encode(b"hello wp07")
            }),
        );
        let response = host.transport(request.clone()).expect("first invoke");
        let Response::CapabilityInvoked {
            wire,
            operation_id,
            state,
            replay,
            ..
        } = &response
        else {
            panic!("expected CapabilityInvoked, got {response:?}");
        };
        assert_eq!(*wire, Version);
        assert_eq!(state, &odin_sidecar_protocol::OperationState::Committed);
        assert!(!replay);
        assert!(operation_id.as_str().starts_with("op-"), "kernel-minted id");
        assert!(echoes(&response, &request), "exact caller IDs echoed");
        // The effect really landed inside the sealed capsule.
        let landed =
            std::fs::read(root.join("capsule").join("notes").join("a.txt")).expect("effected file");
        assert_eq!(landed, b"hello wp07");
        let correlation_id =
            CorrelationId::new("00112233445566778899aabbccddeeff").expect("correlation");
        let receipt = host
            .effect_receipt(&correlation_id)
            .expect("measured receipt is journal-bound");
        assert_eq!(receipt.schema, "OdinEffectReceipt/v1");
        assert_eq!(receipt.operation_id, operation_id.as_str());
        assert_eq!(receipt.capability, "capsule.write");
        assert_eq!(receipt.outcome, "completed");
        assert!(receipt.worker_stopped);
        assert_eq!(receipt.residual_workers, 0);
        assert!(receipt.events.iter().all(|event| {
            event.at_ms > 0 && !event.name.is_empty() && !event.detail.is_empty()
        }));
        assert!(receipt
            .filesystem_changes
            .iter()
            .any(|change| change.path.ends_with("/notes/a.txt")));
        let bound_row = durable_row(&root, correlation_id.as_str());
        assert_eq!(
            bound_row.evidence_digest.as_deref(),
            Some(receipt.evidence_digest.as_str())
        );

        // Retry with the same idempotency key: kernel replay, same
        // operation id, no second effect.
        let replayed = host.transport(request.clone()).expect("replay invoke");
        let Response::CapabilityInvoked {
            operation_id: replay_id,
            replay: is_replay,
            ..
        } = &replayed
        else {
            panic!("expected CapabilityInvoked, got {replayed:?}");
        };
        assert!(is_replay, "duplicate correlation must replay");
        assert_eq!(replay_id, operation_id, "operation id is stable");
        assert!(echoes(&replayed, &request));
        assert_eq!(
            host.effect_receipt(&correlation_id)
                .expect("replay receipt"),
            receipt,
            "duplicate invoke reads the original insert-only receipt"
        );

        // Resume replays the terminal row with the exact caller IDs.
        let resume = Request::ResumeOperation {
            wire: Version,
            capsule_id: CapsuleId::new("capsule-wp07").expect("capsule id"),
            correlation_id: CorrelationId::new("00112233445566778899aabbccddeeff")
                .expect("correlation id"),
            operation_id: operation_id.clone(),
        };
        let resumed = host.transport(resume.clone()).expect("resume");
        let Response::OperationResumed { state, replay, .. } = &resumed else {
            panic!("expected OperationResumed, got {resumed:?}");
        };
        assert_eq!(state, &odin_sidecar_protocol::OperationState::Committed);
        assert!(replay);
        assert!(echoes(&resumed, &resume));

        // Reconcile reports the durable observation as discriminated
        // evidence and replays the committed state.
        let reconcile = Request::ReconcileOperation {
            wire: Version,
            capsule_id: CapsuleId::new("capsule-wp07").expect("capsule id"),
            correlation_id: CorrelationId::new("00112233445566778899aabbccddeeff")
                .expect("correlation id"),
            operation_id: operation_id.clone(),
        };
        let reconciled = host.transport(reconcile.clone()).expect("reconcile");
        let Response::OperationReconciled {
            state, evidence, ..
        } = &reconciled
        else {
            panic!("expected OperationReconciled, got {reconciled:?}");
        };
        assert_eq!(state, &odin_sidecar_protocol::OperationState::Committed);
        assert!(
            matches!(evidence, odin_sidecar_protocol::Evidence::Durable { .. }),
            "the observed world digest is durable evidence: {evidence:?}"
        );
        assert!(echoes(&reconciled, &reconcile));

        // Stop intent for the settled operation records durably and
        // echoes the caller IDs.
        let stop = Request::StopIntent {
            wire: Version,
            capsule_id: CapsuleId::new("capsule-wp07").expect("capsule id"),
            correlation_id: CorrelationId::new("00112233445566778899aabbccddeeff")
                .expect("correlation id"),
            operation_id: Some(operation_id.clone()),
        };
        let recorded = host.transport(stop.clone()).expect("stop intent");
        let Response::StopRecorded {
            state, evidence, ..
        } = &recorded
        else {
            panic!("expected StopRecorded, got {recorded:?}");
        };
        assert_eq!(state, &odin_sidecar_protocol::StopState::Requested);
        assert!(matches!(evidence, odin_sidecar_protocol::Evidence::Absent));
        assert!(echoes(&recorded, &stop));

        // Capsule close (drain) answers with the drained count and echoes.
        let close = Request::CloseCapsule {
            wire: Version,
            capsule_id: CapsuleId::new("capsule-wp07").expect("capsule id"),
            correlation_id: CorrelationId::new("00112233445566778899aabbccddeeff")
                .expect("correlation id"),
            mode: CloseMode::Drain,
        };
        let closed = host.transport(close.clone()).expect("close");
        let Response::CapsuleClosed { drained, .. } = &closed else {
            panic!("expected CapsuleClosed, got {closed:?}");
        };
        assert_eq!(drained.get(), 0, "nothing nonterminal needed draining");
        assert!(echoes(&closed, &close));

        // Durable journal check through the real store: exactly the
        // kernel-minted committed operation.
        let row = durable_row(&root, correlation_id.as_str());
        assert_eq!(row.operation_id, operation_id.as_str());
        assert_eq!(row.effect_state.as_str(), "committed");
        assert_eq!(
            row.evidence_digest.as_deref(),
            Some(receipt.evidence_digest.as_str())
        );
        drop(host);
        assert_eq!(
            effect_receipt_at(&root.join("state"), &correlation_id)
                .expect("receipt after ledger reopen"),
            receipt,
            "reopen returns the persisted actual receipt"
        );
    }

    #[test]
    fn persisted_receipt_digest_tamper_fails_honestly() {
        let root = std::env::temp_dir().join(format!(
            "odin-effector-receipt-tamper-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&root).expect("fixture root");
        let host = fixture_host(&root, odin_sidecar::system_clock());
        let correlation =
            CorrelationId::new("11223344556677889900aabbccddeeff").expect("correlation");
        host.transport(invoke_request(
            correlation.as_str(),
            ToolId::new("capsule.write").expect("tool id"),
            serde_json::json!({
                "path": "tamper.txt",
                "content_hex": odin_types::hash::hex_encode(b"real output")
            }),
        ))
        .expect("real effect");
        let receipt = host.effect_receipt(&correlation).expect("real receipt");
        let ledger = odin_ledger::Ledger::open(root.join("state").join("authority-ledger.db"))
            .expect("ledger reopen");
        ledger
            .connection()
            .execute(
                "UPDATE effect_receipts SET receipt_digest = ?1 WHERE correlation_id = ?2",
                (
                    "blake3:0000000000000000000000000000000000000000000000000000000000000000",
                    correlation.as_str(),
                ),
            )
            .expect("tamper receipt index");
        let error = host
            .effect_receipt(&correlation)
            .expect_err("tampered receipt must fail");
        assert_eq!(error.code(), SidecarErrorCode::ReceiptMismatch);
        assert!(!receipt.evidence_digest.is_empty(), "real digest existed");
    }

    #[test]
    fn an_exact_replacement_lands_once_and_ambiguous_old_text_is_refused() {
        let root = std::env::temp_dir().join(format!(
            "odin-effector-replace-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&root).expect("fixture root");
        let host = fixture_host(&root, odin_sidecar::system_clock());
        let hex = |text: &str| odin_types::hash::hex_encode(text.as_bytes());
        let write = |correlation: &str, arguments: serde_json::Value| {
            host.transport(invoke_request(
                correlation,
                ToolId::new("capsule.write").expect("tool id"),
                arguments,
            ))
        };
        write(
            "21223344556677889900aabbccddeeff",
            serde_json::json!({"path": "lib.py", "content_hex": hex("a = 1\nb = 2\na = 1\n")}),
        )
        .expect("file created");
        write(
            "31223344556677889900aabbccddeeff",
            serde_json::json!({"path": "lib.py", "old_hex": hex("b = 2"), "new_hex": hex("b = 3")}),
        )
        .expect("exact replacement");
        let landed = || std::fs::read_to_string(root.join("capsule/lib.py")).expect("file");
        assert_eq!(landed(), "a = 1\nb = 3\na = 1\n");
        let refused = write(
            "41223344556677889900aabbccddeeff",
            serde_json::json!({"path": "lib.py", "old_hex": hex("a = 1"), "new_hex": hex("a = 9")}),
        )
        .expect_err("ambiguous old text is refused");
        assert_eq!(refused.code, "executor.rejected");
        assert!(
            format!("{refused:?}").contains("occurs 2 times"),
            "{refused:?}"
        );
        assert_eq!(landed(), "a = 1\nb = 3\na = 1\n");
        drop(host);
        std::fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn stop_intent_during_execute_cancels_into_in_doubt() {
        let root = std::env::temp_dir().join(format!(
            "odin-effector-stop-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&root).expect("fixture root");
        let host = fixture_host(&root, odin_sidecar::system_clock());

        let correlation = "99887766554433221100ffeeddccbbaa";
        let helper_marker = root.join(EXECUTE_HELPER_MARKER);
        let helper_bin = std::env::current_exe().expect("execute helper executable");
        assert!(helper_bin.is_absolute(), "execute helper must be absolute");
        assert!(helper_bin.is_file(), "execute helper must be a file");
        let helper_program = helper_bin
            .to_str()
            .expect("execute helper path is UTF-8")
            .to_owned();
        let helper_argv = std::iter::once(helper_program)
            .chain(
                EXECUTE_HELPER_ARGS
                    .iter()
                    .map(|argument| (*argument).to_owned()),
            )
            .collect::<Vec<_>>();
        let helper_environment = BTreeMap::from([(
            EXECUTE_HELPER_MARKER_VAR.to_owned(),
            helper_marker
                .to_str()
                .expect("execute helper marker path is UTF-8")
                .to_owned(),
        )]);
        let request = invoke_request(
            correlation,
            ToolId::new("capsule.run").expect("tool id"),
            serde_json::json!({
                "argv": helper_argv,
                "environment": helper_environment,
                "current_dir": root.join("capsule").display().to_string(),
                "timeout_ms": 20_000,
                "term_grace_ms": 1_000,
                "max_stdout_bytes": 4_096,
                "max_stderr_bytes": 4_096
            }),
        );

        let host_for_invoke = Arc::clone(&host.sidecar);
        let worker_fixture_for_invoke = Arc::clone(&host._worker_fixture);
        let invoker = std::thread::spawn(move || {
            let _worker_fixture = worker_fixture_for_invoke;
            host_for_invoke.transport(request)
        });

        // Wait for the durable row to exist so the stop intent can bind to
        // the kernel-minted operation id. The row is durable before executor
        // dispatch, but only after the kernel's declare round trip: under
        // load this wait bounds a real launch, not a local write.
        let operation_id = {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Some(row) = try_durable_row(&root, correlation).expect("row query") {
                    break OperationId::new(&row.operation_id).expect("operation id");
                }
                if invoker.is_finished() {
                    // The invoke is gone and no durable row exists: a
                    // permanent rejection, not something more polling fixes.
                    // Checked before the deadline so an invoke that finished
                    // reports its real outcome instead of a timeout: the
                    // durable row only appears after the kernel's declare
                    // round trip, so a loaded launch can outlive 20 s while
                    // the invoke is still legitimately in flight.
                    match invoker.join() {
                        Ok(Ok(_)) => panic!("invoke returned without a durable row"),
                        Ok(Err(rejection)) => panic!(
                            "invoke permanently rejected before a durable row: {rejection:?}"
                        ),
                        Err(_) => panic!("invoke thread panicked before a durable row"),
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "no durable operation row appeared within 20 s while the \
                     invoke was still in flight"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
        };

        // The row is durable before executor launch, so it is not a start
        // barrier. The payload marker can only be published after the outer
        // effector helper was launched, registered on the stop handle, and
        // received the execute request.
        let started_helper =
            match wait_for_started_helper(&helper_marker, &invoker, Duration::from_secs(20)) {
                Ok(identity) => identity,
                Err(wait_error) => match invoker.join() {
                    Ok(outcome) => {
                        panic!("{wait_error}; invoke completed with {outcome:?}")
                    }
                    Err(_) => panic!("{wait_error}; invoke thread panicked"),
                },
            };
        let active = durable_row(&root, correlation);
        assert_eq!(active.operation_id, operation_id.as_str());
        assert_eq!(
            active.effect_state.as_str(),
            "effect_started",
            "the real helper is blocked inside the durable execute phase: {started_helper:?}"
        );

        // The concurrent stop intent lands while the effect is in flight.
        let stop = Request::StopIntent {
            wire: Version,
            capsule_id: CapsuleId::new("capsule-wp07").expect("capsule id"),
            correlation_id: CorrelationId::new(correlation).expect("correlation id"),
            operation_id: Some(operation_id.clone()),
        };
        let recorded = host.transport(stop.clone()).expect("concurrent stop");
        let Response::StopRecorded {
            state, evidence, ..
        } = &recorded
        else {
            panic!("expected StopRecorded, got {recorded:?}");
        };
        assert_eq!(state, &odin_sidecar_protocol::StopState::Requested);
        assert!(
            matches!(evidence, odin_sidecar_protocol::Evidence::Process { .. }),
            "the in-flight helper identity is reported: {evidence:?}"
        );
        assert!(echoes(&recorded, &stop));

        // The execute path observes the cancellation and reports
        // uncertainty: the authority records in_doubt, never a settlement.
        let outcome = invoker
            .join()
            .expect("invoke thread")
            .expect_err("cancelled effect");
        assert_eq!(outcome.code, "executor.uncertain", "{outcome:?}");

        let row = durable_row(&root, correlation);
        assert_eq!(row.effect_state.as_str(), "in_doubt");

        // Reconcile keeps the blocking nonterminal and reports evidence.
        let reconcile = Request::ReconcileOperation {
            wire: Version,
            capsule_id: CapsuleId::new("capsule-wp07").expect("capsule id"),
            correlation_id: CorrelationId::new(correlation).expect("correlation id"),
            operation_id,
        };
        let reconciled = host.transport(reconcile).expect("reconcile");
        let Response::OperationReconciled { state, .. } = &reconciled else {
            panic!("expected OperationReconciled, got {reconciled:?}");
        };
        assert_eq!(state, &odin_sidecar_protocol::OperationState::InDoubt);

        // The blocking nonterminal keeps the capsule open under abort.
        let close = Request::CloseCapsule {
            wire: Version,
            capsule_id: CapsuleId::new("capsule-wp07").expect("capsule id"),
            correlation_id: CorrelationId::new(correlation).expect("correlation id"),
            mode: CloseMode::Abort,
        };
        let blocked = host
            .transport(close)
            .expect_err("abort blocked by in_doubt");
        assert_eq!(blocked.code, "authority.capsule_blocked", "{blocked:?}");
    }
}
