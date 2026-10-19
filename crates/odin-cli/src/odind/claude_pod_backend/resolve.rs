use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use odin_hermes::runtime::claude::{ClaudeOpenRequest, ClaudePlacement as RequestedPlacement};
use odin_kube::workload::WorkloadGatewayTarget;
use odin_registry::schema::{ClaudeCodeToml, ClaudePlacement, ObjectConfig};
use odin_registry::SnapshotHandle;

pub(super) struct ResolvedPlan {
    pub workload: String,
    pub profile: ClaudeCodeToml,
    pub project_root: PathBuf,
    pub clone_url: String,
    pub revision: String,
    pub branch: String,
    pub allow_hosts: Vec<String>,
    pub egress_targets: Vec<WorkloadGatewayTarget>,
}

pub(super) fn resolve(
    pin: &SnapshotHandle,
    projects: &BTreeMap<String, PathBuf>,
    cell: &crate::kube::KubeRuntimeCell,
    request: &ClaudeOpenRequest,
    session: &str,
) -> Result<ResolvedPlan, String> {
    if request.placement.unwrap_or_default() != RequestedPlacement::Pod || request.host.is_some() {
        return Err("Claude pod admission requires pod placement and no host selector".into());
    }
    let session = uuid::Uuid::parse_str(session)
        .map_err(|error| format!("Claude session must be a UUID: {error}"))?;
    let branch =
        match request.name.as_deref() {
            Some(name) if safe_slug(name) => format!("claude/{name}"),
            Some(_) => return Err(
                "Claude name must be a 1..=80 character alphanumeric slug with internal '-' or '_'"
                    .into(),
            ),
            None => format!("claude/{session}"),
        };
    let snapshot = pin.current();
    let mut candidates = snapshot
        .objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::ClaudeCode(profile)
                if profile.enabled
                    && profile.placement == ClaudePlacement::Pod
                    && profile.host.is_none() =>
            {
                Some((object.id.as_str(), profile.as_ref()))
            }
            _ => None,
        });
    let (workload, declared) = candidates
        .next()
        .ok_or("no enabled Claude pod workload template is declared")?;
    if candidates.next().is_some() {
        return Err(
            "multiple enabled Claude pod workload templates are declared; admission is ambiguous"
                .into(),
        );
    }
    let errors = declared.validate(&snapshot.objects);
    if !errors.is_empty() {
        return Err(format!("Claude workload {workload}: {}", errors.join("; ")));
    }
    if !declared.admits_project(&snapshot.objects, &request.project) {
        return Err(format!(
            "Claude workload {workload} does not admit project {}",
            request.project
        ));
    }
    if !odin_registry::schema::valid_account_name(&request.account) {
        return Err("Claude account must be a valid Q33 account handle".into());
    }
    declared.mcp_config(&request.mcp, odin_registry::schema::CLAUDE_WORKTREE)?;
    let environment_id = declared.environment()?;
    let mut environments = snapshot
        .objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Environment(environment)
                if object.id == environment_id && environment.enabled =>
            {
                Some(environment.as_ref())
            }
            _ => None,
        });
    let environment = environments
        .next()
        .ok_or_else(|| format!("Claude environment {environment_id} is not enabled"))?;
    if environments.next().is_some() {
        return Err(format!("Claude environment {environment_id} is ambiguous"));
    }
    let errors = environment.check();
    if !errors.is_empty() {
        return Err(format!(
            "Claude environment {environment_id}: {}",
            errors.join("; ")
        ));
    }
    let pod = environment
        .pod
        .as_ref()
        .ok_or("Claude environment has no pod authority")?;
    let mirror = environment
        .git_mirror
        .as_deref()
        .ok_or("Claude pod environment must declare its read-only git mirror")?;
    let project_root = projects
        .get(&request.project)
        .ok_or_else(|| {
            format!(
                "Claude project {} has no configured physical root",
                request.project
            )
        })?
        .canonicalize()
        .map_err(|error| format!("Claude project {} root: {error}", request.project))?;
    let reference = format!("refs/heads/{branch}");
    if !read_git(
        &project_root,
        &["for-each-ref", "--format=%(objectname)", &reference],
    )?
    .is_empty()
    {
        return Err(format!(
            "Claude branch {branch} already exists in the configured project root"
        ));
    }
    let origin = read_git(&project_root, &["remote", "get-url", "origin"])?;
    let clone_url = mirror_origin(&origin, mirror).ok_or_else(|| {
        format!(
            "Claude project {} origin has no declared read-only mirror mapping",
            request.project
        )
    })?;
    let revision = read_git(&project_root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if !matches!(revision.len(), 40 | 64) || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Claude project HEAD did not resolve to a full commit object ID".into());
    }
    let mut profile = declared.clone();
    if profile.image.reference == odin_registry::schema::PLATFORM_IMAGE {
        profile.image.reference = cell.workload_identity().deployment.image_reference.clone();
        if profile.image.reference == odin_registry::schema::PLATFORM_IMAGE {
            return Err("Claude platform image binding is unresolved".into());
        }
        let errors = profile.validate(&snapshot.objects);
        if !errors.is_empty() {
            return Err(format!(
                "Claude platform image binding: {}",
                errors.join("; ")
            ));
        }
    }
    Ok(ResolvedPlan {
        workload: workload.to_owned(),
        profile,
        project_root,
        clone_url,
        revision,
        branch,
        allow_hosts: pod.allow_hosts.clone(),
        egress_targets: vec![WorkloadGatewayTarget {
            host: mirror.to_owned(),
            port: odin_registry::GIT_MIRROR_PORT,
        }],
    })
}

fn safe_slug(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

// Match the authority mirror's GitHub owner/repository layout, never the
// registry project ID or a caller-supplied URL.
fn mirror_origin(origin: &str, mirror: &str) -> Option<String> {
    let path = [
        "git@github.com:",
        "ssh://git@github.com/",
        "https://github.com/",
    ]
    .iter()
    .find_map(|prefix| origin.strip_prefix(prefix))?;
    let (owner, repo) = path.strip_suffix(".git").unwrap_or(path).split_once('/')?;
    let component = |value: &str| {
        !value.is_empty()
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    (component(owner) && component(repo)).then(|| format!("git://{mirror}/{owner}/{repo}.git"))
}

fn read_git(root: &Path, args: &[&str]) -> Result<String, String> {
    super::publication::read_only_git(root, args)
        .map_err(|error| format!("Claude project git read: {error}"))
}
