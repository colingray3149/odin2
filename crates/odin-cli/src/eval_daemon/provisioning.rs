//! Declared provisioning for the live session authority: the verified-snapshot
//! projection with seat-token minting, the extension policy, and the
//! private-state file helpers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use odin_domain::extension_policy::{
    ExtensionArtifactPolicy, ExtensionPolicyBinding, ExtensionPolicyV1, SidecarOperationalPolicy,
    EXTENSION_POLICY_SCHEMA, EXTENSION_POLICY_VERSION,
};
use odin_domain::knowledge::ResourceConstraint;
use odin_domain::{CapabilityId, Digest, SeatToken};
use odin_huginn::OdindConfig;
use odin_kernel::{CapabilityContract, MintRequest, TokenIssuer};
use odin_registry::relational::AdmittedBinding;
use odin_registry::{ObjectConfig, Snapshot};
use odin_types::CapsuleId;

use super::path_text;

/// The registered capsule git runner: runs git with its first argument as
/// the working directory and the rest as arguments, returning trimmed
/// stdout. Implemented by the live session pool's manifest-pinned
/// environment-free git.
pub(crate) type RegisteredGit<'a> = &'a mut dyn FnMut(&Path, &[&str]) -> Result<String, String>;

/// Clones absent capsules privately and verifies existing capsules in place.
/// `--no-hardlinks --dissociate` keeps Git objects inside the capsule;
/// a retained commit mismatch is refused without modifying or removing it.
pub(crate) fn verify_or_clone_capsule_project(
    registered_git: RegisteredGit<'_>,
    capsule_parent: &Path,
    source: &Path,
    source_commit: &str,
) -> Result<PathBuf, String> {
    let capsule_project = capsule_parent.join("project");
    if !capsule_project.exists() {
        registered_git(
            capsule_parent,
            &[
                "clone",
                "--quiet",
                "--no-hardlinks",
                "--dissociate",
                &path_text(source)?,
                "project",
            ],
        )?;
        fs::set_permissions(&capsule_project, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("could not protect capsule project: {error}"))?;
    }
    let scratch_root = capsule_project.join(".odin-eval");
    create_private_dir(&scratch_root)?;
    let capsule_head = registered_git(&capsule_project, &["rev-parse", "HEAD"])?;
    if capsule_head != source_commit {
        return Err(format!(
            "durable capsule project {} does not match its source commit {source_commit}",
            capsule_project.display()
        ));
    }
    // Reapply local merge configuration so retained capsules use the current driver.
    apply_capsule_mergiraf(registered_git, &capsule_project)?;
    Ok(capsule_project)
}

/// The mergiraf executable: the system profile copy first (the daemon and
/// seat workers run with a minimal PATH), else PATH discovery — the same
/// resolution odind applies to git, nix and timeout.
pub fn mergiraf_program() -> PathBuf {
    let system = Path::new("/run/current-system/sw/bin").join("mergiraf");
    if system.exists() {
        system
    } else {
        PathBuf::from("mergiraf")
    }
}

/// The official merge driver registration
/// (mergiraf.org/usage.html#registration-as-a-git-merge-driver).
pub fn mergiraf_driver() -> String {
    format!(
        "{} merge --git %O %A %B -s %S -x %X -y %Y -p %P -l %L",
        mergiraf_program().display()
    )
}

/// Ensures the repository's LOCAL `info/attributes` routes every path
/// through mergiraf (`* merge=mergiraf`; mergiraf detects the language from
/// `-p %P` and falls back to Git's merge for what it does not know). For a
/// linked worktree the path resolves to the common Git directory, so the
/// declared root and every worktree created from it are covered. An
/// existing file is appended to, never replaced; an unreadable file is an
/// error, never silently truncated.
pub fn apply_mergiraf_attributes(git_attributes_path: &Path) -> Result<(), String> {
    const LINE: &str = "* merge=mergiraf";
    let existing = match std::fs::read_to_string(git_attributes_path) {
        Ok(existing) => existing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(format!(
                "could not read {}: {error}",
                git_attributes_path.display()
            ));
        }
    };
    if existing.lines().any(|line| line.trim() == LINE) {
        return Ok(());
    }
    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(LINE);
    content.push('\n');
    if let Some(parent) = git_attributes_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    std::fs::write(git_attributes_path, content)
        .map_err(|error| format!("could not write {}: {error}", git_attributes_path.display()))
}

fn apply_capsule_mergiraf(
    registered_git: RegisteredGit<'_>,
    capsule_project: &Path,
) -> Result<(), String> {
    for (key, value) in [
        ("merge.mergiraf.name", "mergiraf"),
        ("merge.mergiraf.driver", &mergiraf_driver()),
        // mergiraf requires the diff3 conflict style.
        ("merge.conflictstyle", "diff3"),
    ] {
        registered_git(capsule_project, &["config", key, value])?;
    }
    apply_mergiraf_attributes(&capsule_project.join(".git").join("info").join("attributes"))
}

pub(crate) struct SeatTokenIssuance<'a> {
    pub session: odin_domain::SessionId,
    pub signing_key: &'a [u8],
    pub provided_token: Option<&'a SeatToken>,
    pub plan_accepted: bool,
}

pub(crate) fn projection_and_token_session(
    config: &OdindConfig,
    snapshot: &Snapshot,
    seat_binding: &odin_huginn::OdindSeatBinding,
    lane: &odin_domain::LaneId,
    capsule_id: &CapsuleId,
    capsule_project: &Path,
    issuance: SeatTokenIssuance<'_>,
) -> Result<(Vec<u8>, SeatToken, String), String> {
    let SeatTokenIssuance {
        session,
        signing_key,
        provided_token,
        plan_accepted,
    } = issuance;
    let seat_object = object(
        snapshot,
        odin_registry::RegistryKind::Seat,
        seat_binding.seat.as_str(),
    )?;
    let slice_object = object(
        snapshot,
        odin_registry::RegistryKind::Slice,
        seat_binding.slice.as_str(),
    )?;
    let eval_object = object(
        snapshot,
        odin_registry::RegistryKind::Capability,
        "capsule.eval.run",
    )?;
    let edit_object = object(
        snapshot,
        odin_registry::RegistryKind::Capability,
        "capsule.file.edit",
    )?;
    let ObjectConfig::Seat(seat) = &seat_object.config else {
        unreachable!()
    };
    let ObjectConfig::Slice(slice) = &slice_object.config else {
        unreachable!()
    };
    if !seat.enabled || !slice.enabled {
        return Err(format!(
            "{} seat or slice is disabled in the verified snapshot",
            seat_binding.seat.as_str()
        ));
    }
    let mut contracts = Vec::new();
    for (capability_object, label) in [
        (&eval_object, "capsule.eval.run"),
        (&edit_object, "capsule.file.edit"),
    ] {
        let ObjectConfig::Capability(capability) = &capability_object.config else {
            unreachable!()
        };
        let capability_id = CapabilityId::parse(label).map_err(|error| error.to_string())?;
        if !seat.tool_refs.contains(&capability_id) || !slice.capabilities.contains(&capability_id)
        {
            return Err(format!(
                "{label} is absent from the effective {} seat/slice listing",
                seat_binding.seat.as_str()
            ));
        }
        let declared = AdmittedBinding {
            version: capability.version,
            input_schema: capability
                .input_schema
                .clone()
                .ok_or_else(|| format!("{label} input schema missing"))?,
            output_schema: capability
                .output_schema
                .clone()
                .ok_or_else(|| format!("{label} output schema missing"))?,
            handler: capability
                .handler
                .clone()
                .ok_or_else(|| format!("{label} handler missing"))?,
            evidence_extractor: capability
                .evidence_extractor
                .clone()
                .ok_or_else(|| format!("{label} extractor missing"))?,
        };
        let admitted = odin_omp::host_tools::production_bindings()
            .iter()
            .map(|binding| binding.to_admitted_binding())
            .find(|binding| binding == &declared)
            .ok_or_else(|| {
                format!("{label} declaration is not in the compiled admission catalog")
            })?;
        let contract = CapabilityContract::try_from_registry(capability_object, &admitted)
            .map_err(|error| format!("{label} capability contract rejected: {error}"))?;
        contracts.push(contract);
    }

    let schema_root = config
        .paths
        .registry_root
        .parent()
        .ok_or_else(|| "registry root has no schema parent".to_owned())?;
    let mut schemas = BTreeMap::new();
    for contract in &contracts {
        for reference in [&contract.input_schema_ref, &contract.output_schema_ref] {
            let path = schema_root.join(reference);
            let bytes = fs::read(&path).map_err(|error| {
                format!(
                    "could not read canonical schema {}: {error}",
                    path.display()
                )
            })?;
            if bytes.len() > 1_048_576 {
                return Err(format!(
                    "canonical schema {} exceeds byte bound",
                    path.display()
                ));
            }
            let value: serde_json::Value =
                odin_strict_json::decode(&bytes, 1_048_576).map_err(|error| {
                    format!("canonical schema {} rejected: {error}", path.display())
                })?;
            odin_domain::knowledge::ToolSchema::from_value(value.clone()).map_err(|error| {
                format!("canonical schema {} rejected: {error}", path.display())
            })?;
            schemas.insert((*reference).clone(), value);
        }
    }

    let seat_revision = Digest::hash(
        &seat_object
            .canonical_bytes()
            .map_err(|error| format!("seat revision encoding failed: {error}"))?,
    );
    let slice_revision = Digest::hash(
        &slice_object
            .canonical_bytes()
            .map_err(|error| format!("slice revision encoding failed: {error}"))?,
    );
    // The admission digest over the enabled contract set — the same value
    // HostToolOperations and the operator token verify — not the raw
    // snapshot hash.
    let all_contracts = crate::runtime_bindings::operation_contracts(&snapshot.objects)?;
    let snapshot_revision =
        i64::try_from(snapshot.revision).map_err(|_| "snapshot revision exceeds i64".to_owned())?;
    let snapshot_digest =
        odin_omp::host_tools::operations::admission_digest(&all_contracts, snapshot_revision)
            .map_err(|error| error.to_string())?;
    let context_digest = odin_omp::host_tools::operations::context_policy_digest(
        seat_binding.seat.as_str(),
        seat_binding.slice.as_str(),
        lane.as_str(),
        seat_revision,
        slice_revision,
    );
    let effective = seat
        .tool_refs
        .intersection(&slice.capabilities)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut capabilities_json = Vec::with_capacity(contracts.len());
    let mut resource_constraints = serde_json::Map::new();
    for contract in &contracts {
        let handler = serde_json::to_value(&contract.handler)
            .map_err(|error| format!("{} handler encoding failed: {error}", contract.id))?;
        let extractor = serde_json::to_value(&contract.evidence_extractor)
            .map_err(|error| format!("{} extractor encoding failed: {error}", contract.id))?;
        let constraint = match contract.id.as_str() {
            "capsule.eval.run" => ResourceConstraint::Named {
                kind: "capsule".to_owned(),
                value: capsule_id.as_str().to_owned(),
            },
            "capsule.file.edit" => ResourceConstraint::FilesystemBeneath {
                root: capsule_project.to_path_buf(),
            },
            other => return Err(format!("unexpected admitted capability {other:?}")),
        };
        let rendered = serde_json::to_value([constraint])
            .map_err(|error| format!("{} constraint encoding failed: {error}", contract.id))?;
        resource_constraints.insert(contract.id.as_str().to_owned(), rendered);
        capabilities_json.push(serde_json::json!({
            "id": contract.id,
            "version": contract.version,
            "tool_name": contract.tool_name,
            "description": contract.description,
            "handler": handler,
            "evidence_extractor": extractor,
            "input_schema_ref": contract.input_schema_ref,
            "output_schema_ref": contract.output_schema_ref,
            "effect_class": contract.effect_class,
            "seat_tags": contract.seat_tags,
            "timeout_seconds": contract.timeout_seconds.get(),
            "idempotency": contract.idempotency,
            "retry_max_attempts": contract.retry.max_attempts,
            "approval": contract.approval,
            "adapter": contract.adapter,
            "delegate_to": contract.delegate_to,
        }));
    }
    let projection = serde_json::json!({
        "schema": "OdinTransportProjection/v1",
        "snapshot_revision": i64::try_from(snapshot.revision).map_err(|_| "snapshot revision exceeds i64")?,
        "snapshot_digest": snapshot_digest,
        "expected": {
            "seat": seat_binding.seat.clone(),
            "slice": seat_binding.slice.clone(),
            "lane": lane.clone(),
            "session": session.clone(),
            "seat_revision": seat_revision,
            "slice_revision": slice_revision,
            "capability_policy_digest": snapshot_digest,
            "context_policy_digest": context_digest,
        },
        "plan": {
            "gate": if plan_accepted { "accepted" } else { "draft" },
            "plan_id": format!("plan:operator:{}", session.as_str()),
        },
        "policy": {
            "seat_tool_refs": seat.tool_refs.clone(),
            "slice_capabilities": slice.capabilities.clone(),
            "project_capabilities": effective.clone(),
            "lane_capabilities": effective,
            "denied_capabilities": [],
            "denied_tools": seat.tools.as_ref().map(|tools| tools.deny.clone()).unwrap_or_default(),
            "seat_categories": seat.categories,
            "adapter_health": {},
            "resource_constraints": resource_constraints,
            "seat_hints": {},
        },
        "capabilities": capabilities_json,
        "schemas": schemas,
        "builtins": [
            "odin_eval.run",
            "odin_eval.run_evidence",
            "odin_file.edit",
            "odin_file.edit_evidence",
        ],
    });
    let projection = odin_strict_json::canonicalize(&projection)
        .map_err(|error| format!("eval projection encoding failed: {error}"))?;
    odin_sidecar::TransportProjection::from_bytes(&projection)
        .map_err(|error| format!("eval projection rejected: {error}"))?;

    // Align the capsule token lifetime with the operator-provisioned
    // host-tool token for this exact session, when one is provisioned, so
    // sidecar authority never outlives host authority.
    let operator_expiry: Option<u64> = {
        let token_path = config
            .paths
            .authority_token_root
            .join(format!("{}.json", session.as_str()));
        fs::read(&token_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| {
                value
                    .get("expiresAtMs")
                    .and_then(|expiry| expiry.as_u64())
                    .or_else(|| {
                        value
                            .get("expires_at_ms")
                            .and_then(|expiry| expiry.as_u64())
                    })
            })
    };
    let now = unix_millis()?;
    let token = match provided_token {
        Some(token) => token.clone(),
        None => {
            let entropy =
                Digest::hash(format!("eval-token\0{}\0{}", snapshot.hash, capsule_id).as_bytes());
            TokenIssuer::new(signing_key.to_vec())
                .map_err(|error| format!("eval token issuer rejected: {error}"))?
                .mint(MintRequest {
                    seat: seat_binding.seat.clone(),
                    slice: seat_binding.slice.clone(),
                    lane: lane.clone(),
                    session: session.clone(),
                    seat_revision,
                    slice_revision,
                    capability_policy_digest: snapshot_digest,
                    context_policy_digest: context_digest,
                    issued_at_ms: now,
                    expires_at_ms: operator_expiry.unwrap_or_else(|| {
                        now.saturating_add(
                            config
                                .delegation
                                .as_ref()
                                .map(|d| d.child_token_ttl_seconds.get().saturating_mul(1_000))
                                .unwrap_or(3_600_000),
                        )
                    }),
                    entropy: entropy.as_bytes(),
                })
                .map_err(|error| format!("eval seat token mint failed: {error}"))?
        }
    };
    Ok((projection, token, seat_binding.seat.as_str().to_owned()))
}

fn object<'a>(
    snapshot: &'a Snapshot,
    kind: odin_registry::RegistryKind,
    id: &str,
) -> Result<&'a odin_registry::RegistryObject, String> {
    snapshot
        .objects
        .iter()
        .find(|object| object.kind() == kind && object.id == id && object.enters_listing())
        .ok_or_else(|| format!("verified registry snapshot has no listed {kind} {id:?}"))
}

pub(super) fn extension_policy(
    config: &OdindConfig,
    snapshot: &Snapshot,
    authority_root: &Path,
) -> Result<ExtensionPolicyBinding, String> {
    let extension = config
        .executables
        .extension
        .canonicalize()
        .map_err(|error| format!("could not resolve extension artifact: {error}"))?;
    let extension_bytes = fs::read(&extension)
        .map_err(|error| format!("could not read extension artifact: {error}"))?;
    let policy = ExtensionPolicyV1 {
        schema: EXTENSION_POLICY_SCHEMA.to_owned(),
        version: EXTENSION_POLICY_VERSION,
        snapshot_revision: snapshot.revision,
        config_revision: config.revision,
        extension: ExtensionArtifactPolicy {
            path: extension,
            digest: ExtensionPolicyV1::digest_bytes(&extension_bytes),
        },
        sidecar: SidecarOperationalPolicy::compiled_default(),
    };
    let directory = authority_root.join("extension-policy");
    create_private_dir(&directory)?;
    let bytes = serde_json::to_vec(&policy)
        .map_err(|error| format!("extension policy encoding failed: {error}"))?;
    let digest = ExtensionPolicyV1::digest_bytes(&bytes);
    let name = digest
        .strip_prefix("blake3:")
        .ok_or_else(|| "extension policy digest is not BLAKE3".to_owned())?;
    let path = directory.join(format!(
        "r{}-c{}-{name}.json",
        snapshot.revision, config.revision
    ));
    let binding = if path.exists() {
        ExtensionPolicyBinding::new(path, digest)
    } else {
        ExtensionPolicyV1::publish(&path, &policy)
            .map_err(|error| format!("could not publish extension policy: {error}"))?
    };
    binding
        .load()
        .map_err(|error| format!("extension policy verification failed: {error}"))?;
    Ok(binding)
}

pub fn publish_exact(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    if path.exists() {
        let existing = fs::read(path)
            .map_err(|error| format!("could not read existing {}: {error}", path.display()))?;
        if existing != bytes {
            return Err(format!("existing {} has different bytes", path.display()));
        }
        return Ok(());
    }
    fs::write(path, bytes)
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("could not protect {}: {error}", path.display()))
}

pub fn create_private_dir(path: &Path) -> Result<(), String> {
    if let Ok(existing) = fs::metadata(path) {
        // Idempotent re-registration: an already-private directory is
        // accepted WITHOUT a modifying chmod, so re-opening a capsule whose
        // root sits on a read-only mount (the live daemon sandbox mounts
        // every non-whitelisted path read-only) cannot fail with EROFS on a
        // directory that already satisfies the invariant. Anything else
        // falls through to the creating path, which fails closed with the
        // typed divergence.
        if !existing.is_dir() {
            return Err(format!("{} exists and is not a directory", path.display()));
        }
        if existing.permissions().mode() & 0o7777 == 0o700 {
            return Ok(());
        }
    }
    fs::create_dir_all(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not protect {}: {error}", path.display()))
}

fn unix_millis() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| "system time does not fit u64 milliseconds".to_owned())
}

#[cfg(test)]
mod private_dir_tests {
    use super::create_private_dir;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;
    use std::time::Duration;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o7777
    }

    #[test]
    fn existing_private_directory_is_accepted_without_a_chmod() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let dir = root.path().join("capsule-root");
        fs::create_dir(&dir).expect("create dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("protect dir");
        // Separate the setup chmod from anything the call might do so a
        // coarse ctime clock cannot mask a forbidden second chmod.
        std::thread::sleep(Duration::from_millis(20));
        let ctime_before = fs::metadata(&dir).expect("metadata").ctime();

        create_private_dir(&dir).expect("already-private directory is accepted");

        let after = fs::metadata(&dir).expect("metadata");
        assert_eq!(
            after.ctime(),
            ctime_before,
            "an already-private directory must not be chmod-ed again: a read-only \
             mount would turn that into EROFS and fail the whole session open"
        );
        assert_eq!(after.permissions().mode() & 0o7777, 0o700);
    }

    #[test]
    fn loose_existing_directory_is_tightened() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let dir = root.path().join("loose");
        fs::create_dir(&dir).expect("create dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("loosen dir");

        create_private_dir(&dir).expect("loose directory is tightened");

        assert_eq!(mode_of(&dir), 0o700);
    }

    #[test]
    fn missing_nested_directory_is_created_private() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let dir = root.path().join("state/capsules/one");

        create_private_dir(&dir).expect("nested directory is created");

        assert!(dir.is_dir());
        assert_eq!(mode_of(&dir), 0o700);
    }

    #[test]
    fn existing_non_directory_fails_typed() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let file = root.path().join("not-a-dir");
        fs::write(&file, b"bytes").expect("write file");

        let error = create_private_dir(&file).expect_err("non-directory fails");

        assert!(
            error.contains("exists and is not a directory"),
            "typed divergence expected, got: {error}"
        );
    }
}
