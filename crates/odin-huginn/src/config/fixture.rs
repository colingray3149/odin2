//! Sanctioned fixture derivation: the transaction-private override set, the
//! derivation entry point, and the one shared reproducibility checker for
//! derived fixture configurations.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use super::huginn::{BindScope, ConfigError, HuginnBindConfig};
use super::manifest::PathDigestRef;
use super::odind::{BrowserDisplaySource, OdindConfig, OdindDisplayConfig};

/// The only sanctioned transaction-private substitutions for a derived
/// fixture configuration. Everything not named here — pinned executables,
/// OMP revision, extension identity, catalog digests, seats, lanes, capacity,
/// publish lanes — is preserved verbatim from the packaged configuration.
/// An xauthority path is deliberately not representable: it travels only
/// through the existing explicit parent→child `ODIN_BROWSER_EXISTING_XAUTHORITY`
/// channel and never enters a serialized configuration.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OdindFixtureOverrides {
    pub state_root: Option<PathBuf>,
    pub registry_root: Option<PathBuf>,
    pub registry_snapshot: Option<PathBuf>,
    pub authority_token_root: Option<PathBuf>,
    pub authority_verification_key_file: Option<PathBuf>,
    /// Replacement private listener; must be a loopback address with an
    /// explicit port for the lifetime of the transaction.
    pub listener_address: Option<SocketAddr>,
    /// Replacement roots for already-declared projects only.
    pub project_roots: BTreeMap<String, PathBuf>,
    /// Replacement private tree roots for already-declared file roots only,
    /// keyed by the existing `file_roots[].root_id`. Rights, media policy,
    /// ceilings, watch policy, and allowed seats are preserved verbatim; only
    /// the confined canonical path moves.
    pub file_roots: BTreeMap<String, PathBuf>,
    /// Deterministic local gateway fixture routes manifest.
    pub gateway_projection: Option<PathDigestRef>,
    /// Typed display mode for the derived browser configuration; `None`
    /// preserves the packaged browser configuration untouched.
    pub display: Option<OdindFixtureDisplay>,
    /// Transaction-private browser profile root; `None` preserves the
    /// packaged profile root. Policy and protected-values files are pinned
    /// canonical bytes and are never overridable.
    pub browser_profile_root: Option<PathBuf>,
    /// Transaction-private relocation of a declared hermes state directory
    /// beneath the derived state root; `None` preserves the packaged value.
    pub hermes_state_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OdindFixtureDisplay {
    Virtual {
        xvfb_binary: PathBuf,
    },
    /// The borrowed display name only; the xauthority file, when any, is
    /// supplied per-run through the sanctioned environment channel.
    Existing {
        display: String,
    },
}

impl OdindConfig {
    /// Derives a transaction-private fixture configuration by substituting
    /// only the allowed overrides; every pinned identity is preserved and the
    /// result is validated through the same strict rules as production.
    pub fn derive_fixture(&self, overrides: &OdindFixtureOverrides) -> Result<Self, ConfigError> {
        for (field, value) in [
            ("state_root", &overrides.state_root),
            ("registry_root", &overrides.registry_root),
            ("registry_snapshot", &overrides.registry_snapshot),
            ("authority_token_root", &overrides.authority_token_root),
            (
                "authority_verification_key_file",
                &overrides.authority_verification_key_file,
            ),
        ] {
            if let Some(path) = value {
                if !path.is_absolute() {
                    return Err(ConfigError::Invalid(format!(
                        "fixture {field} must be absolute"
                    )));
                }
            }
        }
        if let Some(address) = overrides.listener_address {
            let validated = HuginnBindConfig::new(address).validate()?;
            if validated.scope() != BindScope::Loopback {
                return Err(ConfigError::Invalid(
                    "fixture listeners must bind a loopback address".to_owned(),
                ));
            }
        }
        for id in overrides.project_roots.keys() {
            if !self.projects.contains_key(id) {
                return Err(ConfigError::Invalid(format!(
                    "fixture override names undeclared project {id:?}"
                )));
            }
        }
        for id in overrides.file_roots.keys() {
            if !self
                .file_roots
                .iter()
                .any(|root| root.root_id.as_str() == id)
            {
                return Err(ConfigError::Invalid(format!(
                    "fixture override names undeclared file root {id:?}"
                )));
            }
            if let Some(path) = overrides.file_roots.get(id) {
                if !path.is_absolute() {
                    return Err(ConfigError::Invalid(format!(
                        "fixture file root {id:?} must be absolute"
                    )));
                }
            }
        }
        let mut derived = self.clone();
        if let Some(state_root) = &overrides.state_root {
            derived.paths.state_root = state_root.clone();
        }
        if let Some(registry_root) = &overrides.registry_root {
            derived.paths.registry_root = registry_root.clone();
        }
        if let Some(registry_snapshot) = &overrides.registry_snapshot {
            derived.paths.registry_snapshot = registry_snapshot.clone();
        }
        if let Some(authority_token_root) = &overrides.authority_token_root {
            derived.paths.authority_token_root = authority_token_root.clone();
        }
        if let Some(authority_verification_key_file) = &overrides.authority_verification_key_file {
            derived.paths.authority_verification_key_file = authority_verification_key_file.clone();
        }
        if let Some(address) = overrides.listener_address {
            derived.listener.address = address;
        }
        if let Some(profile_root) = &overrides.browser_profile_root {
            if !profile_root.is_absolute() {
                return Err(ConfigError::Invalid(
                    "fixture browser profile root must be absolute".to_owned(),
                ));
            }
            let browser = derived.executables.browser.as_mut().ok_or_else(|| {
                ConfigError::Invalid(
                    "fixture browser profile root override requires a declared browser configuration"
                        .to_owned(),
                )
            })?;
            browser.profile_root = profile_root.clone();
        }
        if let Some(state_dir) = &overrides.hermes_state_dir {
            if !state_dir.is_absolute() {
                return Err(ConfigError::Invalid(
                    "fixture hermes state dir must be absolute".to_owned(),
                ));
            }
            let hermes = derived.hermes.as_mut().ok_or_else(|| {
                ConfigError::Invalid(
                    "fixture hermes state dir override requires a declared hermes configuration"
                        .to_owned(),
                )
            })?;
            hermes.state_dir = state_dir.clone();
        }
        if let Some(gateway) = &overrides.gateway_projection {
            derived.catalogs.gateway_projection = gateway.clone();
        }
        for (id, root) in &overrides.project_roots {
            if let Some(project) = derived.projects.get_mut(id) {
                project.root = root.clone();
            }
        }
        for root in &mut derived.file_roots {
            if let Some(path) = overrides.file_roots.get(root.root_id.as_str()) {
                root.canonical_path = path.clone();
            }
        }
        if let Some(display) = &overrides.display {
            let browser = derived.executables.browser.as_mut().ok_or_else(|| {
                ConfigError::Invalid(
                    "fixture display override requires a declared browser configuration".to_owned(),
                )
            })?;
            browser.display = match display {
                OdindFixtureDisplay::Virtual { xvfb_binary } => {
                    if !xvfb_binary.is_absolute() {
                        return Err(ConfigError::Invalid(
                            "fixture xvfb binary must be absolute".to_owned(),
                        ));
                    }
                    OdindDisplayConfig {
                        source: BrowserDisplaySource::Xvfb,
                        xvfb_binary: Some(xvfb_binary.clone()),
                        display: None,
                    }
                }
                OdindFixtureDisplay::Existing { display } => {
                    if display.trim().is_empty() {
                        return Err(ConfigError::Invalid(
                            "fixture borrowed display name is required".to_owned(),
                        ));
                    }
                    OdindDisplayConfig {
                        source: BrowserDisplaySource::Existing,
                        xvfb_binary: None,
                        display: Some(display.clone()),
                    }
                }
            };
        }
        derived.validate()?;
        Ok(derived)
    }
}

/// Requires exact reproduction by `derive_fixture` and confines moved locations to `fixture_root`.
/// Mutable state must also resolve beneath the derived state root; all other fields stay unchanged.
pub fn validate_sanctioned_fixture_overrides(
    packaged: &OdindConfig,
    derived: &OdindConfig,
    fixture_root: &Path,
) -> Result<(), ConfigError> {
    if !fixture_root.is_absolute() {
        return Err(ConfigError::Invalid(
            "fixture root must be absolute".to_owned(),
        ));
    }
    derived.validate()?;

    let confined = |field: &str, path: &Path| -> Result<(), ConfigError> {
        if path.is_absolute() && path.starts_with(fixture_root) {
            Ok(())
        } else {
            Err(ConfigError::Invalid(format!(
                "fixture override {field} must stay beneath the fixture root {}",
                fixture_root.display()
            )))
        }
    };

    // Reproduce the exact derived value from the minimal sanctioned override
    // set implied by the diff; any unexplained difference fails.
    let mut overrides = OdindFixtureOverrides::default();
    let mut override_paths: Vec<(String, PathBuf)> = Vec::new();
    if derived.paths.state_root != packaged.paths.state_root {
        overrides.state_root = Some(derived.paths.state_root.clone());
        override_paths.push(("state_root".to_owned(), derived.paths.state_root.clone()));
    }
    if derived.paths.registry_root != packaged.paths.registry_root {
        overrides.registry_root = Some(derived.paths.registry_root.clone());
        override_paths.push((
            "registry_root".to_owned(),
            derived.paths.registry_root.clone(),
        ));
    }
    if derived.paths.registry_snapshot != packaged.paths.registry_snapshot {
        overrides.registry_snapshot = Some(derived.paths.registry_snapshot.clone());
        override_paths.push((
            "registry_snapshot".to_owned(),
            derived.paths.registry_snapshot.clone(),
        ));
    }
    if derived.paths.authority_token_root != packaged.paths.authority_token_root {
        overrides.authority_token_root = Some(derived.paths.authority_token_root.clone());
        override_paths.push((
            "authority_token_root".to_owned(),
            derived.paths.authority_token_root.clone(),
        ));
    }
    if derived.paths.authority_verification_key_file
        != packaged.paths.authority_verification_key_file
    {
        overrides.authority_verification_key_file =
            Some(derived.paths.authority_verification_key_file.clone());
        override_paths.push((
            "authority_verification_key_file".to_owned(),
            derived.paths.authority_verification_key_file.clone(),
        ));
    }
    if derived.listener.address != packaged.listener.address {
        overrides.listener_address = Some(derived.listener.address);
    }
    for (id, project) in &derived.projects {
        match packaged.projects.get(id) {
            None => {
                return Err(ConfigError::Invalid(format!(
                    "fixture derivation introduced undeclared project {id:?}"
                )));
            }
            Some(packaged_project) if packaged_project.root != project.root => {
                override_paths.push((format!("projects.{id}.root"), project.root.clone()));
                overrides
                    .project_roots
                    .insert(id.clone(), project.root.clone());
            }
            Some(_) => {}
        }
    }
    for root in &derived.file_roots {
        let Some(packaged_root) = packaged
            .file_roots
            .iter()
            .find(|candidate| candidate.root_id == root.root_id)
        else {
            return Err(ConfigError::Invalid(format!(
                "fixture derivation introduced undeclared file root {:?}",
                root.root_id.as_str()
            )));
        };
        if root.display_name != packaged_root.display_name
            || root.access != packaged_root.access
            || root.media_policy != packaged_root.media_policy
            || root.max_object_bytes != packaged_root.max_object_bytes
            || root.watch_policy != packaged_root.watch_policy
            || root.allowed_seats != packaged_root.allowed_seats
        {
            return Err(ConfigError::Invalid(format!(
                "fixture derivation must not change file root {} policy, rights, or ceilings",
                root.root_id.as_str()
            )));
        }
        if packaged_root.canonical_path != root.canonical_path {
            overrides
                .file_roots
                .insert(root.root_id.to_string(), root.canonical_path.clone());
            override_paths.push((
                format!("file_roots.{}.canonical_path", root.root_id.as_str()),
                root.canonical_path.clone(),
            ));
        }
    }
    for packaged_root in &packaged.file_roots {
        if !derived
            .file_roots
            .iter()
            .any(|candidate| candidate.root_id == packaged_root.root_id)
        {
            return Err(ConfigError::Invalid(format!(
                "fixture derivation removed declared file root {:?}",
                packaged_root.root_id.as_str()
            )));
        }
    }
    if derived.catalogs.gateway_projection != packaged.catalogs.gateway_projection {
        override_paths.push((
            "catalogs.gateway_projection.path".to_owned(),
            derived.catalogs.gateway_projection.path.clone(),
        ));
        overrides.gateway_projection = Some(derived.catalogs.gateway_projection.clone());
    }
    if derived.executables.browser != packaged.executables.browser {
        let (Some(derived_browser), Some(packaged_browser)) =
            (&derived.executables.browser, &packaged.executables.browser)
        else {
            return Err(ConfigError::Invalid(
                "fixture derivation must not add or remove a browser configuration".to_owned(),
            ));
        };
        if derived_browser.display != packaged_browser.display {
            overrides.display = Some(match derived_browser.display.source {
                BrowserDisplaySource::Xvfb => OdindFixtureDisplay::Virtual {
                    xvfb_binary: derived_browser.display.xvfb_binary.clone().ok_or_else(|| {
                        ConfigError::Invalid(
                            "derived xvfb display is missing xvfb_binary".to_owned(),
                        )
                    })?,
                },
                BrowserDisplaySource::Existing => OdindFixtureDisplay::Existing {
                    display: derived_browser.display.display.clone().ok_or_else(|| {
                        ConfigError::Invalid(
                            "derived existing display is missing the display name".to_owned(),
                        )
                    })?,
                },
            });
        }
        if derived_browser.profile_root != packaged_browser.profile_root {
            overrides.browser_profile_root = Some(derived_browser.profile_root.clone());
            override_paths.push((
                "browser.profile_root".to_owned(),
                derived_browser.profile_root.clone(),
            ));
        }
        // Pinned browser files are never overridable.
        for (field, derived_value, packaged_value) in [
            (
                "chromium",
                &derived_browser.chromium,
                &packaged_browser.chromium,
            ),
            ("policy", &derived_browser.policy, &packaged_browser.policy),
            (
                "protected_values",
                &derived_browser.protected_values,
                &packaged_browser.protected_values,
            ),
            (
                "scanner",
                &derived_browser.scanner,
                &packaged_browser.scanner,
            ),
        ] {
            if derived_value != packaged_value {
                return Err(ConfigError::Invalid(format!(
                    "fixture derivation must not change executables.browser.{field}"
                )));
            }
        }
    }
    match (&derived.hermes, &packaged.hermes) {
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            return Err(ConfigError::Invalid(
                "fixture derivation must not add or remove a hermes configuration".to_owned(),
            ));
        }
        (Some(derived_hermes), Some(packaged_hermes)) => {
            // Every hermes policy section is pinned; only the state
            // directory relocates, through its sanctioned override.
            let mut policy = derived_hermes.clone();
            policy.state_dir = packaged_hermes.state_dir.clone();
            if policy != *packaged_hermes {
                return Err(ConfigError::Invalid(
                    "fixture derivation must not change a hermes policy section".to_owned(),
                ));
            }
            if derived_hermes.state_dir != packaged_hermes.state_dir {
                overrides.hermes_state_dir = Some(derived_hermes.state_dir.clone());
                override_paths.push((
                    "hermes.state_dir".to_owned(),
                    derived_hermes.state_dir.clone(),
                ));
            }
        }
    }
    // The pinned executable/catalog/worker identity group is preserved by
    // construction of derive_fixture; verify explicitly for defense in depth.
    if derived.executables.omp_bin != packaged.executables.omp_bin
        || derived.executables.omp_revision != packaged.executables.omp_revision
        || derived.executables.extension != packaged.executables.extension
        || derived.executables.zellij_bin != packaged.executables.zellij_bin
        || derived.executables.zellij_session != packaged.executables.zellij_session
        || derived.executables.attach_command != packaged.executables.attach_command
        || derived.worker_bus != packaged.worker_bus
        || derived.capacity != packaged.capacity
        || derived.delegation != packaged.delegation
        || derived.seats != packaged.seats
        || derived.lane_bindings != packaged.lane_bindings
        || derived.tailnet_peers != packaged.tailnet_peers
        || derived.publish != packaged.publish
        || derived.identity != packaged.identity
        || derived.revision != packaged.revision
    {
        return Err(ConfigError::Invalid(
            "fixture derivation changed a pinned identity outside the sanctioned override set"
                .to_owned(),
        ));
    }

    // Resolve relocated mutable state beneath the derived state root, not just the fixture root.
    let resolved_state_root = super::validate::resolve_state_prefix(&derived.paths.state_root)
        .map_err(|reason| ConfigError::Invalid(format!("paths.state_root: {reason}")))?;
    for (field, path) in [
        (
            "paths.authority_token_root",
            overrides.authority_token_root.as_ref(),
        ),
        ("hermes.state_dir", overrides.hermes_state_dir.as_ref()),
        (
            "browser.profile_root",
            overrides.browser_profile_root.as_ref(),
        ),
    ] {
        if let Some(path) = path {
            let resolved = super::validate::resolve_state_prefix(path).map_err(|reason| {
                ConfigError::Invalid(format!("fixture override {field}: {reason}"))
            })?;
            if !resolved.starts_with(&resolved_state_root) {
                return Err(ConfigError::Invalid(format!(
                    "fixture override {field} must stay beneath the derived state root {}",
                    derived.paths.state_root.display()
                )));
            }
        }
    }

    for (field, path) in override_paths {
        confined(&field, &path)?;
    }

    let reproduced = packaged.derive_fixture(&overrides)?;
    if reproduced != *derived {
        return Err(ConfigError::Invalid(
            "fixture derivation is not reproducible through the sanctioned override API".to_owned(),
        ));
    }
    Ok(())
}
