//! Prepares the in-pod agent configuration before replacing this process with its launcher.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use odin_confined_fs::{Capability, PrivateCapability};

use odin_domain::extension_policy::{ExtensionPolicyBinding, ExtensionPolicyV1};

pub(crate) struct WorkloadExecInput {
    /// Absolute in-pod path of the staged, read-only policy document.
    pub extension_policy: PathBuf,
    /// The policy binding digest (`blake3:<64 hex>`) the launch journaled.
    pub extension_policy_digest: String,
    /// Absolute in-image path of the declared extension entrypoint.
    pub trusted_extension: PathBuf,
    /// Absolute in-pod path of the staged, read-only models document.
    pub models_config: PathBuf,
    /// The models document digest (`blake3:<64 hex>`) the launch journaled.
    pub models_config_digest: String,
    /// Used as PI_CODING_AGENT_DIR so runs do not share agent settings.
    pub agent_dir: PathBuf,
    /// Restricts agent configuration writes to the state mount.
    pub state_mount: PathBuf,
    /// Resolves the models document's apiKey reference through the environment.
    pub credential_env: String,
    pub working_dir: PathBuf,
    pub launcher_argv: Vec<String>,
}

// These flags would replace the extension or settings chosen for this workload.
const FORBIDDEN_LAUNCHER_FLAG_NAMES: [&str; 5] =
    ["extension", "e", "hook", "config", "session-dir"];

fn validate_launcher_argv(argv: &[String], trusted_extension: &str) -> Result<(), String> {
    // Match the launcher's option syntax before allowing its extension selection.
    let mut selections = 0usize;
    let mut arguments = argv.iter().peekable();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            return Err(
                "launcher argv carries an option terminator (`--`) before the verified                  extension selection"
                    .to_owned(),
            );
        }
        let (name, value): (&str, Option<&str>) = match argument.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (&name[2..], Some(value)),
            _ if argument.starts_with("--") => (&argument[2..], None),
            _ if argument.starts_with('-') && argument.len() > 1 => {
                // Short cluster: `-eVALUE` normalizes to (`e`, Some("VALUE")).
                (&argument[1..2], Some(&argument[2..]))
            }
            _ => continue,
        };
        let is_trusted = name == "trusted-extension";
        if is_trusted {
            selections += 1;
            let selected = match value {
                Some(value) => value,
                None => arguments
                    .next()
                    .map(String::as_str)
                    .ok_or_else(|| "launcher argv ends with --trusted-extension".to_owned())?,
            };
            if selected != trusted_extension {
                return Err(format!(
                    "launcher argv selects extension {selected:?} but the policy verifies \
                     {trusted_extension:?}"
                ));
            }
        } else if FORBIDDEN_LAUNCHER_FLAG_NAMES.contains(&name) {
            return Err(format!(
                "launcher argv carries the forbidden override flag {argument:?}"
            ));
        }
    }
    if selections != 1 {
        return Err(format!(
            "launcher argv must carry exactly one --trusted-extension, found {selections}"
        ));
    }
    Ok(())
}

/// Runs the full verifier pair with the production credential lookup: the
/// declared env NAME resolves from this process environment.
pub(crate) fn verify(input: &WorkloadExecInput) -> Result<ExtensionPolicyV1, String> {
    verify_with_env(input, &|name| std::env::var(name).ok())
}

/// Verify the policy digest with injected credential lookup; errors must prevent exec.
pub(crate) fn verify_with_env(
    input: &WorkloadExecInput,
    credential: &dyn Fn(&str) -> Option<String>,
) -> Result<ExtensionPolicyV1, String> {
    let launcher = input
        .launcher_argv
        .first()
        .ok_or_else(|| "workload-exec requires a launcher argv".to_owned())?;
    if !Path::new(launcher).is_absolute() {
        return Err(format!(
            "workload-exec launcher path {launcher:?} must be absolute"
        ));
    }
    if !input.extension_policy.is_absolute() {
        return Err(format!(
            "workload-exec policy path {:?} must be absolute",
            input.extension_policy
        ));
    }
    if !input.trusted_extension.is_absolute() {
        return Err(format!(
            "workload-exec extension path {:?} must be absolute",
            input.trusted_extension
        ));
    }
    if !input.models_config.is_absolute() {
        return Err(format!(
            "workload-exec models config path {:?} must be absolute",
            input.models_config
        ));
    }
    if !input.agent_dir.is_absolute() {
        return Err(format!(
            "workload-exec agent dir {:?} must be absolute",
            input.agent_dir
        ));
    }
    if !input.working_dir.is_absolute() {
        return Err(format!(
            "workload-exec working dir {:?} must be absolute",
            input.working_dir
        ));
    }
    if !input.state_mount.is_absolute() {
        return Err(format!(
            "workload-exec state mount {:?} must be absolute",
            input.state_mount
        ));
    }
    odin_domain::extension_policy::validate_digest(&input.models_config_digest)
        .map_err(|error| format!("the models config digest is malformed: {error}"))?;
    // A missing value would make the launcher send the environment variable name as a key.
    match credential(&input.credential_env) {
        Some(value) if !value.trim().is_empty() => {}
        Some(_) => {
            return Err(format!(
                "credential env {} is empty; the launcher refuses to exec without the \
                 declared gateway credential",
                input.credential_env
            ))
        }
        None => {
            return Err(format!(
                "credential env {} is absent; the launcher refuses to exec without the \
                 declared gateway credential",
                input.credential_env
            ))
        }
    }
    let trusted = input.trusted_extension.to_string_lossy().into_owned();
    validate_launcher_argv(&input.launcher_argv, &trusted)?;
    let binding = ExtensionPolicyBinding::new(
        input.extension_policy.clone(),
        input.extension_policy_digest.clone(),
    );
    let policy = binding
        .load()
        .map_err(|error| format!("extension policy verification failed: {error}"))?;
    policy
        .verify_extension_artifact(&input.trusted_extension)
        .map_err(|error| format!("extension artifact verification failed: {error}"))?;
    Ok(policy)
}

const MODELS_CONFIG_MAX_BYTES: u64 = 1024 * 1024;

// ConfigMap generation symlinks must resolve without escaping the staging root.
fn read_staged_models_config(staged: &Path) -> Result<Vec<u8>, String> {
    let root = staged
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            format!(
                "the staged models config {:?} has no staging root",
                staged.display()
            )
        })?;
    let leaf = staged
        .file_name()
        .ok_or_else(|| format!("the staged models config {:?} has no leaf name", staged))?;
    let capability = Capability::seal_mount(root).map_err(|error| {
        format!(
            "the staging root {:?} could not be sealed: {error}",
            root.display()
        )
    })?;
    let file = capability
        .open_read_beneath(Path::new(leaf))
        .map_err(|error| {
            format!("the staged models config {leaf:?} could not be opened confined: {error}")
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("the staged models config {leaf:?} is unstattable: {error}"))?;
    if !metadata.permissions().readonly() {
        return Err(format!(
            "the staged models config {leaf:?} is writable; a staged document must be \
             read-only"
        ));
    }
    let mut bytes = Vec::new();
    file.take(MODELS_CONFIG_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("the staged models config {leaf:?} is unreadable: {error}"))?;
    if bytes.len() as u64 > MODELS_CONFIG_MAX_BYTES {
        return Err(format!(
            "the staged models config {leaf:?} exceeds the bounded document read"
        ));
    }
    Ok(bytes)
}

// Replace the per-run config from the staged source on each launch.
fn materialize_models_config(input: &WorkloadExecInput) -> Result<PathBuf, String> {
    let staged = read_staged_models_config(&input.models_config)?;
    let digest = odin_domain::Digest::hash(&staged).to_string();
    if digest != input.models_config_digest {
        return Err(format!(
            "the staged models config digests to {digest}, but the launch journaled {}",
            input.models_config_digest
        ));
    }
    let relative = agent_dir_relative(input)?;
    let agent = PrivateCapability::ensure_dir(&input.state_mount, &relative).map_err(|error| {
        format!(
            "the agent dir {:?} could not be created and sealed under {:?}: {error}",
            input.agent_dir, input.state_mount
        )
    })?;
    agent
        .write_atomic(Path::new("models.yml"), &staged, 0o444)
        .map_err(|error| format!("write agent models configuration failed: {error}"))?;
    Ok(input.agent_dir.join("models.yml"))
}

fn agent_dir_relative(input: &WorkloadExecInput) -> Result<PathBuf, String> {
    input
        .agent_dir
        .strip_prefix(&input.state_mount)
        .map(Path::to_path_buf)
        .map_err(|error| {
            format!(
                "resolve agent directory {:?} beneath state mount {:?} failed: {error}",
                input.agent_dir, input.state_mount
            )
        })
}

pub(crate) fn exec(input: &WorkloadExecInput) -> ! {
    if let Err(reason) = verify(input) {
        tracing::error!("workload-exec: {reason}");
        std::process::exit(1);
    }
    if let Err(reason) = materialize_models_config(input) {
        tracing::error!("workload-exec: {reason}");
        std::process::exit(1);
    }
    let mut command = std::process::Command::new(&input.launcher_argv[0]);
    command.args(&input.launcher_argv[1..]);
    command.current_dir(&input.working_dir);
    command.env("PI_CODING_AGENT_DIR", &input.agent_dir);
    let error = std::os::unix::process::CommandExt::exec(&mut command);
    tracing::error!("workload-exec: launcher exec failed: {error}");
    std::process::exit(126);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn policy_bytes(trusted_extension: &Path) -> Vec<u8> {
        let policy = ExtensionPolicyV1 {
            schema: odin_domain::extension_policy::EXTENSION_POLICY_SCHEMA.to_owned(),
            version: odin_domain::extension_policy::EXTENSION_POLICY_VERSION,
            snapshot_revision: 3,
            config_revision: 1,
            extension: odin_domain::extension_policy::ExtensionArtifactPolicy {
                path: trusted_extension.to_path_buf(),
                digest: ExtensionPolicyV1::digest_bytes(b"extension-bytes"),
            },
            sidecar: odin_domain::extension_policy::SidecarOperationalPolicy::compiled_default(),
        };
        serde_json::to_vec(&policy).expect("policy serializes")
    }

    fn staged_policy(directory: &Path, bytes: &[u8], mode: u32) -> PathBuf {
        let path = directory.join("staged-policy.json");
        std::fs::write(&path, bytes).expect("policy bytes written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("policy permissions set");
        path
    }

    /// The real kube ConfigMap volume layout: every key is a relative
    /// symlink through the `..data` generation symlink into the generation
    /// directory, and the transport is read-only (default_mode 0444). The
    /// state mount is a plain directory; the agent dir beneath it is
    /// created and sealed by the code under test.
    fn models_fixture(root: &Path) -> (PathBuf, String, PathBuf, PathBuf) {
        let staging = root.join("staging");
        let generation_name = "..2026_09_24_00_00_00.000000000";
        let generation = staging.join(generation_name);
        std::fs::create_dir_all(&generation).expect("generation dir");
        let bytes = b"{\"providers\":{\"gateway\":{\"api\":\"openai-completions\"}}}";
        let key = generation.join("input-1");
        // Re-seeding over an earlier seed must stay idempotent: a 0444 key
        // file and existing links are removed before recreation.
        let _ = std::fs::remove_file(&key);
        std::fs::write(&key, bytes).expect("staged models bytes");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o444))
            .expect("staged models mode");
        // The real kube ConfigMap volume layout: `..data` targets the
        // generation DIRECTORY (never itself), and every key is a relative
        // symlink through `..data`.
        for (name, target) in [("..data", generation_name), ("input-1", "..data/input-1")] {
            let link = staging.join(name);
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(target, &link).expect("staged key link");
        }
        let digest = odin_domain::Digest::hash(bytes).to_string();
        let state_mount = root.join("state");
        std::fs::create_dir_all(&state_mount).expect("state mount");
        let agent_dir = state_mount.join(".omp-agent").join("run-1");
        (staging.join("input-1"), digest, agent_dir, state_mount)
    }

    /// Injected credential lookups: production resolves the env NAME from
    /// this process environment; tests inject the lookup, so no test ever
    /// mutates global process state.
    fn granted(name: &str) -> Option<String> {
        Some(format!("resolved-{name}"))
    }

    fn absent(_name: &str) -> Option<String> {
        None
    }

    fn blank(_name: &str) -> Option<String> {
        Some(String::new())
    }

    fn input(policy: &Path, digest: &str, trusted_extension: &Path) -> WorkloadExecInput {
        let root = policy
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        let (models_config, models_config_digest, agent_dir, state_mount) = models_fixture(&root);
        WorkloadExecInput {
            extension_policy: policy.to_path_buf(),
            extension_policy_digest: digest.to_owned(),
            models_config,
            models_config_digest,
            agent_dir,
            state_mount,
            credential_env: "ODIN_GATEWAY_KEY".to_owned(),
            working_dir: root.join("cwd"),
            trusted_extension: trusted_extension.to_path_buf(),
            launcher_argv: vec![
                "/odin/bin/omp".to_owned(),
                "--trusted-extension".to_owned(),
                trusted_extension.to_string_lossy().into_owned(),
            ],
        }
    }

    #[test]
    fn accepts_exact_staged_policy_and_matching_extension_bytes() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let trusted = root.path().join("extension").join("index.ts");
        std::fs::create_dir_all(trusted.parent().expect("extension parent"))
            .expect("extension directory");
        std::fs::write(&trusted, b"extension-bytes").expect("extension bytes");
        let bytes = policy_bytes(&trusted);
        let digest = ExtensionPolicyV1::digest_bytes(&bytes);
        let policy = staged_policy(root.path(), &bytes, 0o444);
        let outcome = verify_with_env(&input(&policy, &digest, &trusted), &granted);
        assert!(
            outcome.is_ok(),
            "exact staged policy must verify: {outcome:?}"
        );
    }

    #[test]
    fn refuses_a_substituted_policy_document() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let trusted = root.path().join("extension").join("index.ts");
        std::fs::create_dir_all(trusted.parent().expect("extension parent"))
            .expect("extension directory");
        std::fs::write(&trusted, b"extension-bytes").expect("extension bytes");
        let bytes = policy_bytes(&trusted);
        let digest = ExtensionPolicyV1::digest_bytes(&bytes);
        let mut substituted = bytes.clone();
        substituted[0] ^= 0x20;
        let policy = staged_policy(root.path(), &substituted, 0o444);
        assert!(
            verify_with_env(&input(&policy, &digest, &trusted), &granted).is_err(),
            "a flipped policy byte must fail the digest proof"
        );
    }

    #[test]
    fn refuses_extension_bytes_outside_the_policy_digest() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let trusted = root.path().join("extension").join("index.ts");
        std::fs::create_dir_all(trusted.parent().expect("extension parent"))
            .expect("extension directory");
        std::fs::write(&trusted, b"tampered").expect("extension bytes");
        let bytes = policy_bytes(&trusted);
        let digest = ExtensionPolicyV1::digest_bytes(&bytes);
        let policy = staged_policy(root.path(), &bytes, 0o444);
        assert!(
            verify_with_env(&input(&policy, &digest, &trusted), &granted).is_err(),
            "extension bytes that differ from the policy digest must refuse"
        );
    }

    #[test]
    fn refuses_launcher_argv_selecting_a_second_extension() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let trusted = root.path().join("extension").join("index.ts");
        std::fs::create_dir_all(trusted.parent().expect("extension parent"))
            .expect("extension directory");
        std::fs::write(&trusted, b"extension-bytes").expect("extension bytes");
        let bytes = policy_bytes(&trusted);
        let digest = ExtensionPolicyV1::digest_bytes(&bytes);
        let policy = staged_policy(root.path(), &bytes, 0o444);
        let mut bypass = input(&policy, &digest, &trusted);
        bypass.launcher_argv = vec![
            "/odin/bin/omp".to_owned(),
            "--trusted-extension".to_owned(),
            trusted.to_string_lossy().into_owned(),
            "--trusted-extension".to_owned(),
            "/odin/lib/other-extension/index.ts".to_owned(),
        ];
        assert!(
            verify_with_env(&bypass, &granted).is_err(),
            "a second --trusted-extension must refuse before any exec"
        );
    }

    #[test]
    fn refuses_launcher_argv_carrying_override_flags() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let trusted = root.path().join("extension").join("index.ts");
        std::fs::create_dir_all(trusted.parent().expect("extension parent"))
            .expect("extension directory");
        std::fs::write(&trusted, b"extension-bytes").expect("extension bytes");
        let bytes = policy_bytes(&trusted);
        let digest = ExtensionPolicyV1::digest_bytes(&bytes);
        let policy = staged_policy(root.path(), &bytes, 0o444);
        for forbidden in [
            vec![
                "/odin/bin/omp".to_owned(),
                "--trusted-extension".to_owned(),
                trusted.to_string_lossy().into_owned(),
                "--config".to_owned(),
                "/tmp/override.toml".to_owned(),
            ],
            vec![
                "/odin/bin/omp".to_owned(),
                "-e".to_owned(),
                "/odin/lib/other/index.ts".to_owned(),
                "--trusted-extension".to_owned(),
                trusted.to_string_lossy().into_owned(),
            ],
        ] {
            let mut bypass = input(&policy, &digest, &trusted);
            bypass.launcher_argv = forbidden;
            assert!(
                verify_with_env(&bypass, &granted).is_err(),
                "override flags must refuse before any exec"
            );
        }
    }

    #[test]
    fn refuses_missing_or_empty_credential_env_before_any_exec() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let trusted = root.path().join("extension").join("index.ts");
        std::fs::create_dir_all(trusted.parent().expect("extension parent"))
            .expect("extension directory");
        std::fs::write(&trusted, b"extension-bytes").expect("extension bytes");
        let bytes = policy_bytes(&trusted);
        let digest = ExtensionPolicyV1::digest_bytes(&bytes);
        let policy = staged_policy(root.path(), &bytes, 0o444);
        let mut input = input(&policy, &digest, &trusted);
        input.credential_env = "ODIN_TEST_ABSENT_CREDENTIAL".to_owned();
        let missing = verify_with_env(&input, &absent);
        assert!(
            missing.is_err(),
            "a missing credential lookup must refuse before any exec"
        );
        let empty = verify_with_env(&input, &blank);
        assert!(
            empty.is_err(),
            "an empty credential lookup must refuse before any exec"
        );
        let resolved = verify_with_env(&input, &granted);
        assert!(
            resolved.is_ok(),
            "a resolved credential must verify: {resolved:?}"
        );
    }

    #[test]
    fn materializes_models_config_on_each_launch() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let trusted = root.path().join("extension").join("index.ts");
        std::fs::create_dir_all(trusted.parent().expect("extension parent"))
            .expect("extension directory");
        std::fs::write(&trusted, b"extension-bytes").expect("extension bytes");
        let bytes = policy_bytes(&trusted);
        let digest = ExtensionPolicyV1::digest_bytes(&bytes);
        let policy = staged_policy(root.path(), &bytes, 0o444);
        let input = input(&policy, &digest, &trusted);
        let staged = std::fs::read(&input.models_config).expect("staged models");
        let target = materialize_models_config(&input).expect("first launch");
        std::fs::remove_file(&target).expect("remove old config");
        std::fs::write(&target, b"old config").expect("old config");

        assert_eq!(
            materialize_models_config(&input).expect("next launch"),
            target
        );
        assert_eq!(std::fs::read(&target).expect("models config"), staged);
        assert!(std::fs::metadata(&target)
            .expect("models metadata")
            .permissions()
            .readonly());
    }

    #[test]
    fn refuses_a_staged_symlink_escaping_the_staging_root() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let trusted = root.path().join("extension").join("index.ts");
        std::fs::create_dir_all(trusted.parent().expect("extension parent"))
            .expect("extension directory");
        std::fs::write(&trusted, b"extension-bytes").expect("extension bytes");
        let bytes = policy_bytes(&trusted);
        let digest = ExtensionPolicyV1::digest_bytes(&bytes);
        let policy = staged_policy(root.path(), &bytes, 0o444);
        let mut escape = input(&policy, &digest, &trusted);
        let staging = escape
            .models_config
            .parent()
            .expect("staging root")
            .to_path_buf();

        // An absolute escape link refuses the confined read.
        let absolute = staging.join("escape-abs");
        std::os::unix::fs::symlink("/etc/passwd", &absolute).expect("absolute escape link");
        escape.models_config = absolute;
        assert!(
            materialize_models_config(&escape).is_err(),
            "an absolute escape link must refuse"
        );

        // A relative escape that climbs above the staging root refuses too.
        let climbing = staging.join("escape-rel");
        std::os::unix::fs::symlink("../../outside", &climbing).expect("relative escape link");
        escape.models_config = climbing;
        assert!(
            materialize_models_config(&escape).is_err(),
            "a relative escape link must refuse"
        );
    }

    #[test]
    fn refuses_a_writable_staged_models_document() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let trusted = root.path().join("extension").join("index.ts");
        std::fs::create_dir_all(trusted.parent().expect("extension parent"))
            .expect("extension directory");
        std::fs::write(&trusted, b"extension-bytes").expect("extension bytes");
        let bytes = policy_bytes(&trusted);
        let digest = ExtensionPolicyV1::digest_bytes(&bytes);
        let policy = staged_policy(root.path(), &bytes, 0o444);
        let mut writable = input(&policy, &digest, &trusted);
        let staging = writable
            .models_config
            .parent()
            .expect("staging root")
            .to_path_buf();
        let path = staging.join("writable.yml");
        // std::fs::write creates the file world-writable-group-writable by
        // umask: a writable mode proves this is not the journaled staged
        // transport document.
        std::fs::write(&path, b"{\"providers\":{}}").expect("writable staged bytes");
        writable.models_config = path;
        assert!(
            materialize_models_config(&writable).is_err(),
            "a writable staged document must refuse"
        );
    }

    #[test]
    fn refuses_an_oversized_staged_models_document() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let trusted = root.path().join("extension").join("index.ts");
        std::fs::create_dir_all(trusted.parent().expect("extension parent"))
            .expect("extension directory");
        std::fs::write(&trusted, b"extension-bytes").expect("extension bytes");
        let bytes = policy_bytes(&trusted);
        let digest = ExtensionPolicyV1::digest_bytes(&bytes);
        let policy = staged_policy(root.path(), &bytes, 0o444);
        let mut oversized = input(&policy, &digest, &trusted);
        let staging = oversized
            .models_config
            .parent()
            .expect("staging root")
            .to_path_buf();
        let path = staging.join("oversized.yml");
        std::fs::write(&path, vec![b'x'; MODELS_CONFIG_MAX_BYTES as usize + 1])
            .expect("oversized staged bytes");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))
            .expect("oversized mode");
        oversized.models_config = path;
        assert!(
            materialize_models_config(&oversized).is_err(),
            "an oversized staged document must refuse"
        );
    }

    #[test]
    fn refuses_a_writable_policy_document_before_any_exec() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let trusted = root.path().join("extension").join("index.ts");
        std::fs::create_dir_all(trusted.parent().expect("extension parent"))
            .expect("extension directory");
        std::fs::write(&trusted, b"extension-bytes").expect("extension bytes");
        let bytes = policy_bytes(&trusted);
        let digest = ExtensionPolicyV1::digest_bytes(&bytes);
        let policy = staged_policy(root.path(), &bytes, 0o644);
        assert!(
            verify_with_env(&input(&policy, &digest, &trusted), &granted).is_err(),
            "a writable staged policy must refuse exactly as bind_file does"
        );
    }
}
