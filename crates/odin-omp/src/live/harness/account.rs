//! The session's account, resolved at launch (its launch option's, else its project's, else `default`) and folded
//! into the route the session runs under: its login joins the harness's state paths, a named account's directory is
//! handed to the agent by its variable, and `{account}` in the transcripts template names that directory.

use std::collections::BTreeMap;
use std::path::Path;

use odin_domain::huginn::{LiveError, SessionManifest};
use odin_registry::{valid_account_name, AccountKind, DEFAULT_ACCOUNT};

use super::HarnessRoute;

/// Project id → the account each kind signs in with there (the registry project's `[accounts]`).
pub type ProjectAccounts = BTreeMap<String, BTreeMap<AccountKind, String>>;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccountRefusal {
    #[error("account {name:?} is not an account handle (lowercase letters, digits, inner dashes)")]
    InvalidHandle { name: String },
    #[error("the {kind} account {name} is not signed in on this host; sign in with: {hint}")]
    NotSignedIn {
        kind: &'static str,
        name: String,
        hint: String,
    },
}

impl AccountRefusal {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidHandle { .. } => "harness_account_invalid",
            Self::NotSignedIn { .. } => "harness_account_signed_out",
        }
    }
}

impl From<AccountRefusal> for LiveError {
    fn from(refusal: AccountRefusal) -> Self {
        LiveError::Conflict {
            code: refusal.code().to_owned(),
            message: refusal.to_string(),
        }
    }
}

pub fn session_account(
    manifest: &SessionManifest,
    kind: AccountKind,
    projects: &ProjectAccounts,
) -> String {
    manifest
        .harness
        .as_ref()
        .and_then(|binding| binding.account.clone())
        .or_else(|| {
            projects
                .get(manifest.project_id.as_str())
                .and_then(|accounts| accounts.get(&kind))
                .cloned()
        })
        .unwrap_or_else(|| DEFAULT_ACCOUNT.to_owned())
}

/// `route` running on account `name`. `local`: the agent runs on this host (or a pod on it), so the sign-in is
/// checked here before anything starts.
pub fn with_account(
    mut route: HarnessRoute,
    name: String,
    home: &Path,
    local: bool,
) -> Result<HarnessRoute, AccountRefusal> {
    let Some(kind) = route.harness.account else {
        return Ok(route);
    };
    if !valid_account_name(&name) {
        return Err(AccountRefusal::InvalidHandle { name });
    }
    if local && !kind.signed_in(home, &name) {
        return Err(AccountRefusal::NotSignedIn {
            kind: kind.as_str(),
            hint: kind.sign_in_hint(&name),
            name,
        });
    }
    let layout = kind.layout(&name);
    let dir = home.join(&layout.dir).to_string_lossy().into_owned();
    route.harness.state_paths.extend(layout.paths);
    if let Some(var) = layout.env {
        route
            .harness
            .command
            .splice(0..0, ["env".to_owned(), format!("{var}={dir}")]);
    }
    if let Some(transcripts) = &mut route.harness.transcripts {
        *transcripts = transcripts.replace("{account}", &dir);
    }
    route.account = Some(name);
    Ok(route)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terminal() -> HarnessRoute {
        HarnessRoute {
            harness_id: "fixture-terminal".to_owned(),
            harness: super::super::tests::terminal_fixture(),
            environment_id: "sandbox-authority".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../../registry/environments/sandbox-authority/environment.toml"
            ))
            .expect("sandbox-authority"),
            account: None,
        }
    }

    fn signed_in(home: &Path, dir: &str) {
        std::fs::create_dir_all(home.join(dir)).expect("dir");
        std::fs::write(home.join(dir).join("auth.json"), "{}").expect("sign-in");
    }

    /// CODEX_HOME selects the named account's state and transcripts; default uses ~/.codex.
    #[test]
    fn the_session_runs_on_its_account() {
        let home = tempfile::tempdir().expect("home");
        signed_in(home.path(), ".codex-accounts/school");
        signed_in(home.path(), ".codex");
        let root = home.path().display().to_string();
        let school =
            with_account(terminal(), "school".to_owned(), home.path(), true).expect("school");
        assert_eq!(school.harness.state_paths, [".codex-accounts/school"]);
        assert_eq!(
            school.harness.command[..3],
            [
                "env".to_owned(),
                format!("CODEX_HOME={root}/.codex-accounts/school"),
                "fixture-agent".to_owned()
            ]
        );
        assert_eq!(
            school.harness.transcripts.as_deref(),
            Some(format!("{root}/.codex-accounts/school/projects/{{workspace_slug}}").as_str())
        );
        assert_eq!(school.account.as_deref(), Some("school"));
        let default = with_account(terminal(), DEFAULT_ACCOUNT.to_owned(), home.path(), true)
            .expect("default");
        assert_eq!(default.harness.state_paths, [".codex"]);
        assert_eq!(default.harness.command[0], "fixture-agent");
        assert_eq!(
            default.harness.transcripts.as_deref(),
            Some(format!("{root}/.codex/projects/{{workspace_slug}}").as_str())
        );
    }

    #[test]
    fn a_signed_out_or_invalid_account_is_refused_before_launch() {
        let home = tempfile::tempdir().expect("home");
        let refused =
            with_account(terminal(), "club".to_owned(), home.path(), true).expect_err("club");
        assert_eq!(refused.code(), "harness_account_signed_out");
        assert!(refused
            .to_string()
            .contains("CODEX_HOME=~/.codex-accounts/club codex login"));
        let remote =
            with_account(terminal(), "club".to_owned(), home.path(), false).expect("remote");
        assert_eq!(remote.account.as_deref(), Some("club"));
        assert_eq!(
            with_account(terminal(), "../x".to_owned(), home.path(), false)
                .expect_err("traversal")
                .code(),
            "harness_account_invalid"
        );
    }

    #[test]
    fn the_launch_option_beats_the_project_which_beats_default() {
        use odin_domain::huginn::{LiveSessionId, ModelName, ProviderName};
        use odin_domain::{NodeId, ProjectId, SeatId, SliceId};
        let mut manifest = SessionManifest {
            session_id: LiveSessionId::new(uuid::Uuid::new_v4()).expect("session id"),
            seat_id: SeatId::new("gungnir").expect("seat id"),
            slice_id: SliceId::new("gungnir-build").expect("slice id"),
            project_id: ProjectId::new("weno5").expect("project id"),
            provider: ProviderName::new("fixture-terminal").expect("provider"),
            model: ModelName::new("opus").expect("model"),
            title: None,
            target_node: NodeId::new("mini").expect("node id"),
            open_tab: false,
            workload: None,
            served_revision: None,
            harness: None,
        };
        let projects: ProjectAccounts = BTreeMap::from([(
            manifest.project_id.to_string(),
            BTreeMap::from([(AccountKind::ClaudeCode, "school".to_owned())]),
        )]);
        assert_eq!(
            session_account(&manifest, AccountKind::Codex, &projects),
            "default"
        );
        assert_eq!(
            session_account(&manifest, AccountKind::ClaudeCode, &projects),
            "school"
        );
        manifest.harness = Some(odin_domain::huginn::HarnessBinding {
            harness: "fixture-terminal".to_owned(),
            environment: "sandbox-authority".to_owned(),
            account: Some("club".to_owned()),
        });
        assert_eq!(
            session_account(&manifest, AccountKind::ClaudeCode, &projects),
            "club"
        );
    }
}
