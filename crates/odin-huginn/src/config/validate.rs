//! Semantic validation for the strict controller configuration and every
//! declared section: bounds, listener scope, path shapes, adapter identity
//! grammar, and browser coherence.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use odin_domain::knowledge::AtlasId;

use super::huginn::{range, ConfigError};
use super::odind::{
    BrowserDisplaySource, OdindBrainConfig, OdindBrainEmbeddingConfig, OdindBrainSourceConfig,
    OdindConfig, OdindDelegationConfig, OdindDisplayConfig, OdindHermesAccountConfig,
    OdindHermesConfig, OdindHermesDiscordConfig, OdindHermesFinanceConfig,
    OdindHermesProviderConfig, OdindHermesVaultConfig, OdindKubeConfig, ODIND_CONFIG_SCHEMA,
};

/// Keep these limits aligned with `ZellijCliFactory::with_attach_command`.
const MAX_ZELLIJ_SESSION_NAME_BYTES: usize = 128;
const MAX_ATTACH_COMMAND_ARGS: usize = 64;
const MAX_ATTACH_COMMAND_ARG_BYTES: usize = 4096;
/// The only placeholder an attach-command template may carry; the daemon
/// replaces it with the dispatched live session id at tab creation.
const ATTACH_COMMAND_SESSION_PLACEHOLDER: &str = "{session_id}";
/// Longest account selector the Hermes composition accepts, mirroring
/// `odin_hermes::account::MAX_ACCOUNT_CHARS`.
const MAX_HERMES_ACCOUNT_CHARS: usize = 128;

/// Lexical check mirroring the canonical adapter wire-ID grammar
/// (`schemas/control/adapter-descriptor.schema.json` `$defs.id`: 1..=192
/// bytes, ASCII alphanumeric first, `._:-` after). Values are additionally
/// tied to the compiled catalog at startup; this check only rejects
/// lexically impossible configuration before admission ever runs.
fn invalid_adapter_id_reason(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return Some("must not be empty");
    }
    if value.len() > 192 {
        return Some("must not exceed 192 bytes");
    }
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        return Some("must start with an ASCII alphanumeric character");
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Some("must contain only ASCII alphanumeric characters or '.', '_', ':', '-'");
    }
    None
}

impl OdindConfig {
    /// Validates bounds, listener scope, path shapes, and browser coherence.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema != ODIND_CONFIG_SCHEMA {
            return Err(ConfigError::Invalid(format!(
                "schema must be {ODIND_CONFIG_SCHEMA:?}, found {:?}",
                self.schema
            )));
        }
        if self.revision == 0 {
            return Err(ConfigError::Invalid(
                "revision must be a positive configuration revision".to_owned(),
            ));
        }
        if self.identity.node.trim().is_empty() {
            return Err(ConfigError::Invalid("identity.node is required".to_owned()));
        }
        for (field, path) in [
            ("paths.registry_root", &self.paths.registry_root),
            ("paths.state_root", &self.paths.state_root),
            ("paths.registry_snapshot", &self.paths.registry_snapshot),
            (
                "paths.authority_token_root",
                &self.paths.authority_token_root,
            ),
            (
                "paths.authority_verification_key_file",
                &self.paths.authority_verification_key_file,
            ),
        ] {
            if !path.is_absolute() {
                return Err(ConfigError::Invalid(format!("{field} must be absolute")));
            }
        }
        self.listener_address().validate()?;
        for (field, path) in [
            ("listener.tls_cert", &self.listener.tls_cert),
            ("listener.tls_key", &self.listener.tls_key),
            (
                "paths.operator_context_root",
                &self.paths.operator_context_root,
            ),
            (
                "paths.cargo_registry_cache",
                &self.paths.cargo_registry_cache,
            ),
            ("paths.cargo_git_cache", &self.paths.cargo_git_cache),
            ("paths.nix_daemon_socket", &self.paths.nix_daemon_socket),
            ("paths.nix_config_root", &self.paths.nix_config_root),
            (
                "paths.authoring_repository",
                &self.paths.authoring_repository,
            ),
            ("paths.authoring_worktree", &self.paths.authoring_worktree),
        ] {
            if let Some(path) = path {
                if !path.is_absolute() {
                    return Err(ConfigError::Invalid(format!("{field} must be absolute")));
                }
            }
        }
        // Reject relative projection paths and malformed digests before startup reads them.
        self.catalogs
            .gateway_projection
            .validate()
            .map_err(|error| {
                ConfigError::Invalid(format!("catalogs.gateway_projection: {error}"))
            })?;
        if self.paths.authoring_repository.is_some() != self.paths.authoring_worktree.is_some() {
            return Err(ConfigError::Invalid(
                "paths.authoring_repository and paths.authoring_worktree are declared together"
                    .to_owned(),
            ));
        }
        self.validate_executables()?;
        self.validate_projects()?;
        self.validate_seats()?;
        self.validate_publish()?;
        if self.worker_bus.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "worker_bus must be an explicit non-secret registered endpoint".to_owned(),
            ));
        }
        if let Some(delegation) = &self.delegation {
            delegation.validate()?;
        }
        if let Some(kube) = &self.kube {
            kube.validate()?;
            // Reject lanes that no configured seat can launch.
            if let Some(lane) = &kube.agent_lane {
                let launched = self.seats.iter().any(|seat| {
                    seat.launch_options.iter().any(|option| {
                        option.provider.as_str() == "gateway" && option.model.as_str() == lane
                    })
                });
                if !launched {
                    return Err(ConfigError::Invalid(format!(
                        "kube.agent_lane {lane:?} is not a gateway launch option of any seat"
                    )));
                }
            }
        }
        for (id, backend) in &self.adapter_backends {
            if let Some(reason) = invalid_adapter_id_reason(id) {
                return Err(ConfigError::Invalid(format!(
                    "adapter_backends.{id}: adapter ID {reason}"
                )));
            }
            if backend
                .argv
                .iter()
                .any(|argument| argument.is_empty() || argument.contains('\0'))
            {
                return Err(ConfigError::Invalid(format!(
                    "adapter_backends.{id}.argv: every argument must be non-empty without NUL"
                )));
            }
        }
        if let Some(brain) = &self.brain {
            brain.validate(&self.tailnet_peers)?;
        }
        if let Some(hermes) = &self.hermes {
            hermes.validate()?;
        }
        // Validate all mutable state paths before any consumer can write them.
        self.validate_state_confinement()?;
        self.capacity.validate()?;
        Ok(())
    }

    /// Resolves declared mutable state beneath `paths.state_root` without creating anything.
    /// Parent components are rejected because lexical and symlink resolution can disagree.
    /// Dangling targets are checked at their resolved location; errors other than absence reject.
    fn validate_state_confinement(&self) -> Result<(), ConfigError> {
        let root = &self.paths.state_root;
        ban_parent_components("paths.state_root", root)?;
        let resolved_root = resolve_state_prefix(root)
            .map_err(|reason| ConfigError::Invalid(format!("paths.state_root: {reason}")))?;
        let declared = [
            Some((
                "paths.authority_token_root",
                self.paths.authority_token_root.as_path(),
            )),
            self.hermes
                .as_ref()
                .map(|hermes| ("hermes.state_dir", hermes.state_dir.as_path())),
            self.executables.browser.as_ref().map(|browser| {
                (
                    "executables.browser.profile_root",
                    browser.profile_root.as_path(),
                )
            }),
        ];
        for (key, path) in declared.into_iter().flatten() {
            ban_parent_components(key, path)?;
            let resolved = resolve_state_prefix(path)
                .map_err(|reason| ConfigError::Invalid(format!("{key}: {reason}")))?;
            if !resolved.starts_with(&resolved_root) {
                return Err(ConfigError::StatePathOutsideStateRoot {
                    key: key.to_owned(),
                    path: path.to_path_buf(),
                    root: root.clone(),
                });
            }
        }
        Ok(())
    }

    fn validate_executables(&self) -> Result<(), ConfigError> {
        let executables = &self.executables;
        for (field, path) in [
            ("executables.omp_bin", &executables.omp_bin),
            ("executables.extension", &executables.extension),
            ("executables.zellij_bin", &executables.zellij_bin),
        ] {
            if !path.is_absolute() {
                return Err(ConfigError::Invalid(format!("{field} must be absolute")));
            }
        }
        let revision_ok = executables.omp_revision.len() == 40
            && executables
                .omp_revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !revision_ok {
            return Err(ConfigError::Invalid(
                "executables.omp_revision must be a 40-character lowercase hexadecimal commit id"
                    .to_owned(),
            ));
        }
        // An empty selector leaves the session unspecified; names must satisfy supervisor checks.
        if !executables.zellij_session.is_empty()
            && (executables.zellij_session.len() > MAX_ZELLIJ_SESSION_NAME_BYTES
                || executables.zellij_session.chars().any(char::is_control))
        {
            return Err(ConfigError::Invalid(
                "executables.zellij_session is not a valid zellij session name".to_owned(),
            ));
        }
        // Match `with_attach_command` limits; absence is reported at dispatch.
        if !executables.attach_command.is_empty() {
            if executables.attach_command.len() > MAX_ATTACH_COMMAND_ARGS {
                return Err(ConfigError::Invalid(
                    "executables.attach_command must hold 1..=64 arguments".to_owned(),
                ));
            }
            for argument in &executables.attach_command {
                if argument.is_empty()
                    || argument.len() > MAX_ATTACH_COMMAND_ARG_BYTES
                    || argument.chars().any(char::is_control)
                {
                    return Err(ConfigError::Invalid(
                        "executables.attach_command argument is invalid".to_owned(),
                    ));
                }
                for candidate in argument.match_indices('{') {
                    let rest = &argument[candidate.0..];
                    if let Some(end) = rest.find('}') {
                        let placeholder = &rest[..=end];
                        if placeholder != ATTACH_COMMAND_SESSION_PLACEHOLDER {
                            return Err(ConfigError::Invalid(format!(
                                "executables.attach_command placeholder {placeholder} is unknown"
                            )));
                        }
                    }
                }
            }
        }
        if let Some(browser) = &executables.browser {
            for (field, path) in [
                ("browser.chromium", &browser.chromium),
                ("browser.profile_root", &browser.profile_root),
                ("browser.policy", &browser.policy),
                ("browser.protected_values", &browser.protected_values),
                ("browser.scanner", &browser.scanner),
            ] {
                if !path.is_absolute() {
                    return Err(ConfigError::Invalid(format!(
                        "executables.{field} must be absolute"
                    )));
                }
            }
            if browser.stream.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "executables.browser.stream is required".to_owned(),
                ));
            }
            browser.display.validate()?;
        }
        Ok(())
    }

    fn validate_projects(&self) -> Result<(), ConfigError> {
        for (id, project) in &self.projects {
            if id.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "projects keys must be non-empty project ids".to_owned(),
                ));
            }
            if !project.root.is_absolute() {
                return Err(ConfigError::Invalid(format!(
                    "projects.{id}.root must be absolute"
                )));
            }
        }
        Ok(())
    }

    fn validate_seats(&self) -> Result<(), ConfigError> {
        for binding in &self.seats {
            if binding.display_name.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "seats[{}].display_name is required",
                    binding.seat
                )));
            }
            if binding.max_sessions == 0 {
                return Err(ConfigError::Invalid(format!(
                    "seats[{}].max_sessions must be positive",
                    binding.seat
                )));
            }
            if binding.launch_options.is_empty() || binding.allowed_nodes.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "seats[{}] requires launch options and allowed nodes",
                    binding.seat
                )));
            }
        }
        Ok(())
    }

    fn validate_publish(&self) -> Result<(), ConfigError> {
        for field in [
            ("publish.render_session", &self.publish.render_session),
            ("publish.file_lane", &self.publish.file_lane),
            ("publish.render_lane", &self.publish.render_lane),
        ] {
            if field.1.trim().is_empty() {
                return Err(ConfigError::Invalid(format!("{} is required", field.0)));
            }
        }
        Ok(())
    }
}

impl OdindBrainEmbeddingConfig {
    fn validate(&self, tailnet_peers: &BTreeMap<String, String>) -> Result<(), ConfigError> {
        if self.provider.trim().is_empty() || self.provider.trim() != self.provider {
            return Err(ConfigError::Invalid(
                "brain.embedding.provider must be a non-empty, trimmed registry provider id"
                    .to_owned(),
            ));
        }
        self.validate_endpoint(tailnet_peers)
    }

    /// Allows only loopback or declared tailnet IP literals, without DNS resolution.
    /// The transport checks resolved addresses again at construction.
    fn validate_endpoint(
        &self,
        tailnet_peers: &BTreeMap<String, String>,
    ) -> Result<(), ConfigError> {
        let loopback = "http://127.0.0.1:";
        if let Some(loopback_port) = self.endpoint.strip_prefix(loopback) {
            if loopback_port.bytes().all(|byte| byte.is_ascii_digit())
                && loopback_port.parse::<u16>().is_ok_and(|port| port != 0)
            {
                return Ok(());
            }
        }
        let invalid = || {
            ConfigError::Invalid(format!(
                "brain.embedding.endpoint {:?} must be a loopback URL of the form \
                 http://127.0.0.1:<port> or name a declared [tailnet_peers] address of the \
                 form http://<peer-ip>:<port>",
                self.endpoint
            ))
        };
        let authority = self.endpoint.strip_prefix("http://").ok_or_else(invalid)?;
        let (host, port) = authority.rsplit_once(':').ok_or_else(invalid)?;
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let port: u16 = port.parse().map_err(|_| invalid())?;
        if port == 0 {
            return Err(invalid());
        }
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let ip: IpAddr = host.parse().map_err(|_| invalid())?;
        if !crate::private_network::is_tailnet_address(ip) {
            return Err(invalid());
        }
        let declared = tailnet_peers.keys().any(|peer| {
            peer.parse::<IpAddr>()
                .map(|peer| peer == ip)
                .unwrap_or(false)
        });
        if !declared {
            return Err(ConfigError::Invalid(format!(
                "brain.embedding.endpoint {ip} is a tailnet address but not a declared \
                 [tailnet_peers] peer"
            )));
        }
        Ok(())
    }
}

impl OdindBrainConfig {
    fn validate(&self, tailnet_peers: &BTreeMap<String, String>) -> Result<(), ConfigError> {
        let name = self.serving_model.name.as_bytes();
        if name.is_empty()
            || self.serving_model.name.trim() != self.serving_model.name
            || self
                .serving_model
                .name
                .chars()
                .any(|character| character.is_control())
        {
            return Err(ConfigError::Invalid(
                "brain.serving_model.name must be a non-empty, trimmed, control-free model \
                 identity"
                    .to_owned(),
            ));
        }
        for lane in self.lane_windows.keys() {
            if lane.is_empty()
                || lane.trim() != lane
                || lane.chars().any(|character| character.is_control())
            {
                return Err(ConfigError::Invalid(format!(
                    "brain.lane_windows key {lane:?} must be a non-empty, trimmed, \
                     control-free model identity"
                )));
            }
        }
        for (key, source) in &self.sources {
            source
                .validate_for(key)
                .map_err(|reason| ConfigError::Invalid(format!("brain.sources.{key}: {reason}")))?;
        }
        if let Some(embedding) = &self.embedding {
            embedding.validate(tailnet_peers)?;
        }
        Ok(())
    }
}

impl OdindBrainSourceConfig {
    fn validate_for(&self, key: &str) -> Result<(), String> {
        if AtlasId::new(key).is_err() {
            return Err(format!(
                "source key must parse as an AtlasId (e.g. atlas:odin), found {key:?}"
            ));
        }
        match self.kind.as_str() {
            "atlas" => {
                if self.archive_fields_declared() {
                    return Err(
                        "an atlas source declares no archive format, path, namespace, privacy \
                         class, dedupe key, or selection policy"
                            .to_owned(),
                    );
                }
                if self.port.is_some()
                    || self.expected_space_root.is_some()
                    || !self.general_namespaces.is_empty()
                    || self.generated_namespace.is_some()
                    || !self.excluded_namespaces.is_empty()
                    || self.max_pages.is_some()
                {
                    return Err(
                        "an atlas source declares neither port, expected_space_root, nor any \
                         vault namespace scope"
                            .to_owned(),
                    );
                }
                match &self.root {
                    Some(root) if root.is_absolute() => Ok(()),
                    Some(root) => Err(format!("root {root:?} must be absolute")),
                    None => Err("an atlas source requires an absolute root".to_owned()),
                }
            }
            "silverbullet" => {
                if self.root.is_some() || self.archive_fields_declared() {
                    return Err(
                        "a silverbullet source declares no root and no archive fields".to_owned(),
                    );
                }
                match self.port {
                    Some(0) => Err("port must be a positive loopback port".to_owned()),
                    Some(_) => {
                        if let Some(space_root) = &self.expected_space_root {
                            if !std::path::Path::new(space_root).is_absolute() {
                                return Err(format!(
                                    "expected_space_root {space_root:?} must be absolute"
                                ));
                            }
                        }
                        let generated = self.generated_namespace.as_deref().ok_or_else(|| {
                            "a silverbullet source requires a generated namespace".to_owned()
                        })?;
                        let max_pages = self.max_pages.ok_or_else(|| {
                            "a silverbullet source requires a page-count ceiling".to_owned()
                        })?;
                        if self.general_namespaces.is_empty() {
                            return Err("a silverbullet source requires at least one retrieval \
                                 namespace"
                                .to_owned());
                        }
                        if self.general_namespaces.len() > 32 {
                            return Err(
                                "a silverbullet source allows at most 32 retrieval namespaces"
                                    .to_owned(),
                            );
                        }
                        let mut allowlist = std::collections::BTreeSet::new();
                        for namespace in &self.general_namespaces {
                            confined_namespace_segment(namespace).map_err(|reason| {
                                format!("general namespace {namespace:?}: {reason}")
                            })?;
                            if !allowlist.insert(namespace.as_str()) {
                                return Err(format!(
                                    "general namespace {namespace:?} is declared twice"
                                ));
                            }
                        }
                        let segments = generated.split('/').count();
                        if segments > 8 {
                            return Err(format!(
                                "generated namespace {generated:?} must be at most 8 segments"
                            ));
                        }
                        for segment in generated.split('/') {
                            confined_namespace_segment(segment).map_err(|reason| {
                                format!("generated namespace {generated:?}: {reason}")
                            })?;
                        }
                        if self.excluded_namespaces.len() > 32 {
                            return Err(
                                "a silverbullet source allows at most 32 excluded namespaces"
                                    .to_owned(),
                            );
                        }
                        let mut exclusions = std::collections::BTreeSet::new();
                        for namespace in &self.excluded_namespaces {
                            confined_namespace_segment(namespace).map_err(|reason| {
                                format!("excluded namespace {namespace:?}: {reason}")
                            })?;
                            if allowlist.contains(namespace.as_str()) {
                                return Err(format!(
                                    "excluded namespace {namespace:?} must not intersect the \
                                     retrieval allowlist"
                                ));
                            }
                            if generated
                                .split('/')
                                .any(|segment| segment == namespace.as_str())
                            {
                                return Err(format!(
                                    "excluded namespace {namespace:?} must not name a generated \
                                     namespace segment"
                                ));
                            }
                            if !exclusions.insert(namespace.as_str()) {
                                return Err(format!(
                                    "excluded namespace {namespace:?} is declared twice"
                                ));
                            }
                        }
                        if max_pages == 0 || max_pages > 100_000 {
                            return Err(format!("max_pages {max_pages} must be within 1..=100000"));
                        }
                        Ok(())
                    }
                    None => Err("a silverbullet source requires a loopback port".to_owned()),
                }
            }
            kind @ ("state.registry" | "state.live" | "state.tasks" | "state.repos"
            | "ops.history") => {
                // A state source takes NO operator-declarable field: its
                // authority is the daemon's own control-plane singleton —
                // the published registry snapshot, the materialized read
                // model, the durable task authority — composed in Rust at
                // startup and never named by configuration. Every atlas or
                // vault field is therefore irrelevant here and rejected
                // strictly: a misplaced field would otherwise silently
                // mean nothing.
                if self.root.is_some()
                    || self.port.is_some()
                    || self.expected_space_root.is_some()
                    || !self.general_namespaces.is_empty()
                    || self.generated_namespace.is_some()
                    || !self.excluded_namespaces.is_empty()
                    || self.max_pages.is_some()
                {
                    return Err(format!(
                        "a {kind} source takes no root, port, or vault namespace fields; \
                         its authority is the daemon's own control-plane state, composed \
                         at startup"
                    ));
                }
                if matches!(kind, "state.repos" | "ops.history") && key != kind {
                    return Err(format!(
                        "source kind {kind} must use its canonical identity"
                    ));
                }
                Ok(())
            }
            "memory" => {
                // A memory source takes NO operator-declarable field: its
                // authority is the daemon's validated Hermes vault
                // singleton — the canonical id `memory.<seat>` resolves
                // the reserved per-seat namespace
                // `<generated>/memories/<seat>` at startup, through the
                // same vault the governed write path uses. Every atlas or
                // vault field is therefore irrelevant here and rejected
                // strictly: a misplaced field would otherwise silently
                // mean nothing, and a caller-declared root or port could
                // point a seat's memory anywhere.
                if self.root.is_some()
                    || self.port.is_some()
                    || self.expected_space_root.is_some()
                    || !self.general_namespaces.is_empty()
                    || self.generated_namespace.is_some()
                    || !self.excluded_namespaces.is_empty()
                    || self.max_pages.is_some()
                {
                    return Err(
                        "a memory source takes no root, port, or vault namespace fields; \
                         its scope is the reserved per-seat subtree of the configured \
                         Hermes vault, composed at startup"
                            .to_owned(),
                    );
                }
                let Some(seat) = key.strip_prefix("memory.") else {
                    return Err(format!(
                        "a memory source id is memory.<seat>, found {key:?}"
                    ));
                };
                confined_namespace_segment(seat)
                    .map_err(|reason| format!("memory source seat {seat:?}: {reason}"))
            }
            "archive" => {
                if self.root.is_some()
                    || self.port.is_some()
                    || self.expected_space_root.is_some()
                    || !self.general_namespaces.is_empty()
                    || self.generated_namespace.is_some()
                    || !self.excluded_namespaces.is_empty()
                    || self.max_pages.is_some()
                {
                    return Err(
                        "an archive source declares neither root, port, nor any vault namespace \
                         scope"
                            .to_owned(),
                    );
                }
                let declaration = odin_domain::knowledge::ArchiveSourceDeclaration {
                    format: self
                        .format
                        .ok_or_else(|| "an archive source requires a declared format".to_owned())?,
                    path: self
                        .export_path
                        .clone()
                        .ok_or_else(|| "an archive source requires an export path".to_owned())?,
                    memory_namespace: self.memory_namespace.clone().ok_or_else(|| {
                        "an archive source requires a memory namespace".to_owned()
                    })?,
                    privacy_class: self
                        .privacy_class
                        .ok_or_else(|| "an archive source requires a privacy class".to_owned())?,
                    dedupe_key: self
                        .dedupe_key
                        .ok_or_else(|| "an archive source requires a dedupe key".to_owned())?,
                    selection: self.selection.clone().ok_or_else(|| {
                        "an archive source requires a selection policy".to_owned()
                    })?,
                };
                declaration
                    .validate()
                    .map_err(|error| format!("an archive source declares invalid policy: {error}"))
            }
            other => Err(format!(
                "kind must be \"atlas\", \"silverbullet\", \"memory\", \
                 \"state.registry\", \"state.live\", \"state.tasks\", \"state.repos\", \
                 \"ops.history\", or \"archive\", found {other:?}"
            )),
        }
    }

    /// Whether any archive-only field is set; used to reject archive fields
    /// on the other source kinds.
    fn archive_fields_declared(&self) -> bool {
        self.format.is_some()
            || self.export_path.is_some()
            || self.memory_namespace.is_some()
            || self.privacy_class.is_some()
            || self.dedupe_key.is_some()
            || self.selection.is_some()
    }
}

#[test]
fn state_source_declaration_cannot_substitute_a_filesystem_authority() {
    let mut source: OdindBrainSourceConfig =
        toml::from_str("kind = \"state.registry\"").expect("minimal state source");
    source
        .validate_for("state.registry")
        .expect("daemon authority needs no paths");
    source.root = Some(std::path::PathBuf::from("/tmp/foreign-registry"));
    assert!(source.validate_for("state.registry").is_err());
}

#[test]
fn repository_source_authority_is_declared_by_projects_not_operator_paths() {
    let mut source: OdindBrainSourceConfig = toml::from_str("kind = \"state.repos\"").unwrap();
    source.validate_for("state.repos").unwrap();
    assert!(source.validate_for("state.live").is_err());
    source.root = Some("/tmp/undeclared-repository".into());
    assert!(source.validate_for("state.repos").is_err());
}

#[test]
fn operations_history_cannot_substitute_a_foreign_ledger() {
    let mut source: OdindBrainSourceConfig = toml::from_str("kind = \"ops.history\"").unwrap();
    source.validate_for("ops.history").unwrap();
    assert!(source.validate_for("state.tasks").is_err());
    source.root = Some("/tmp/foreign-ledger".into());
    assert!(source.validate_for("ops.history").is_err());
}

#[test]
fn memory_source_declaration_is_canonical_and_takes_no_operator_fields() {
    let mut source: OdindBrainSourceConfig =
        toml::from_str("kind = \"memory\"").expect("minimal memory source");
    source
        .validate_for("memory.sinmara")
        .expect("the canonical memory id composes from the vault singleton");
    source.port = Some(3000);
    assert!(source.validate_for("memory.sinmara").is_err());
    source.port = None;
    source.root = Some(std::path::PathBuf::from("/tmp/foreign-memory"));
    assert!(source.validate_for("memory.sinmara").is_err());
    source.root = None;
    assert!(source.validate_for("memory.").is_err());
    assert!(source.validate_for("sinmara").is_err());
    assert!(source.validate_for("memory.traversal/../seat").is_err());
}

/// Matches SilverBullet namespace constraints: one nonempty path segment, at most 128 bytes.
fn confined_namespace_segment(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("namespace segment must be non-empty".to_owned());
    }
    if value.len() > 128 {
        return Err("namespace segment must be at most 128 bytes".to_owned());
    }
    if value.contains('/') {
        return Err("namespace segment must be a single path segment".to_owned());
    }
    if value.contains('\0') {
        return Err("namespace segment must not contain NUL".to_owned());
    }
    if value == "." || value == ".." {
        return Err("namespace segment must not be a relative traversal".to_owned());
    }
    Ok(())
}

impl OdindKubeConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.kubeconfig.is_absolute() {
            return Err(ConfigError::Invalid(
                "kube.kubeconfig must be absolute".to_owned(),
            ));
        }
        if self.cluster.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "kube.cluster must be non-empty".to_owned(),
            ));
        }
        let namespace = self.namespace.as_bytes();
        if namespace.is_empty()
            || namespace.len() > 63
            || !namespace[0].is_ascii_lowercase() && !namespace[0].is_ascii_digit()
            || !namespace[namespace.len() - 1].is_ascii_lowercase()
                && !namespace[namespace.len() - 1].is_ascii_digit()
            || namespace
                .iter()
                .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'-')
        {
            return Err(ConfigError::Invalid(
                "kube.namespace must be a DNS label".to_owned(),
            ));
        }
        for (field, value) in [
            (
                "kube.request_timeout_seconds",
                self.request_timeout_seconds.get(),
            ),
            (
                "kube.teardown_timeout_seconds",
                self.teardown_timeout_seconds.get(),
            ),
        ] {
            if value > 3600 {
                return Err(ConfigError::Invalid(format!(
                    "{field} must not exceed 3600"
                )));
            }
        }
        if !self.image_identity.is_absolute() {
            return Err(ConfigError::Invalid(
                "kube.image_identity must be absolute".to_owned(),
            ));
        }
        if self
            .export_root
            .as_ref()
            .is_some_and(|root| !odin_registry::schema::valid_pod_path(&root.display().to_string()))
        {
            return Err(ConfigError::Invalid(
                "kube.export_root must be a normal absolute path".to_owned(),
            ));
        }
        Ok(())
    }
}

impl OdindDelegationConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        for (field, value) in [
            ("delegation.provider", self.provider.as_str()),
            ("delegation.model", self.model.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ConfigError::Invalid(format!("{field} must be non-empty")));
            }
        }
        range(
            "delegation.max_children_per_session",
            self.max_children_per_session.get() as i64,
            1,
            8,
        )?;
        range(
            "delegation.max_prompt_bytes",
            self.max_prompt_bytes.get() as i64,
            1024,
            262_144,
        )?;
        range(
            "delegation.child_timeout_seconds",
            self.child_timeout_seconds.get() as i64,
            60,
            14_400,
        )?;
        range(
            "delegation.child_token_ttl_seconds",
            self.child_token_ttl_seconds.get() as i64,
            300,
            86_400,
        )?;
        if self.child_token_ttl_seconds.get() < self.child_timeout_seconds.get() {
            return Err(ConfigError::Invalid(
                "delegation.child_token_ttl_seconds must cover child_timeout_seconds".to_owned(),
            ));
        }
        if let Some(stall) = self.child_stall_seconds {
            range(
                "delegation.child_stall_seconds",
                stall.get() as i64,
                60,
                3_600,
            )?;
            if stall.get() >= self.child_timeout_seconds.get() {
                return Err(ConfigError::Invalid(
                    "delegation.child_stall_seconds must be shorter than child_timeout_seconds"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl OdindHermesConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.state_dir.is_absolute() {
            return Err(ConfigError::Invalid(
                "hermes.state_dir must be an absolute path".to_owned(),
            ));
        }
        if let Some(discord) = &self.discord {
            discord.validate()?;
        }
        // The account selector is the explicit routing key of every
        // email/calendar operation: an ambiguous declaration would silently
        // route one account's credential to another's provider, so every
        // selector must be unique.
        let mut selectors = BTreeSet::new();
        for account in &self.accounts {
            account.validate()?;
            if !selectors.insert(account.account.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "hermes.accounts account {:?} is declared more than once: every \
                     account selector must be unique",
                    account.account
                )));
            }
        }
        if let Some(vault) = &self.vault {
            vault.validate()?;
        }
        if let Some(finance) = &self.finance {
            finance.validate()?;
        }
        let immich = self.immich.as_ref();
        for (field, url) in [
            ("hermes.review_gateway", self.review_gateway.as_ref()),
            ("hermes.immich.url", immich.map(|immich| &immich.url)),
            (
                "hermes.immich.web_url",
                immich.map(|immich| &immich.web_url),
            ),
        ] {
            let Some(url) = url else { continue };
            let rest = url
                .strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"));
            if rest
                .is_none_or(|rest| rest.is_empty() || rest.contains('@') || rest.starts_with('/'))
            {
                return Err(ConfigError::Invalid(format!(
                    "{field} must be an http(s) URL with a host and no userinfo"
                )));
            }
        }
        for (field, path) in [
            (
                "hermes.immich.api_key_path",
                immich.map(|immich| &immich.api_key_path),
            ),
            ("hermes.brain_raw_root", self.brain_raw_root.as_ref()),
        ] {
            if path.is_some_and(|path| !path.is_absolute()) {
                return Err(ConfigError::Invalid(format!(
                    "{field} must be an absolute path"
                )));
            }
        }
        Ok(())
    }
}

impl OdindHermesDiscordConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        for (field, value) in [
            ("hermes.discord.seat", self.seat.as_str()),
            ("hermes.discord.project", self.project.as_str()),
            ("hermes.discord.owner_user_id", self.owner_user_id.as_str()),
            (
                "hermes.discord.notify_channel_id",
                self.notify_channel_id.as_str(),
            ),
            ("hermes.discord.capability", self.capability.as_str()),
            (
                "hermes.discord.bot_token_handle",
                self.bot_token_handle.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(ConfigError::Invalid(format!("{field} must be non-empty")));
            }
        }
        range(
            "hermes.discord.egress_capacity",
            self.egress_capacity as i64,
            1,
            4_096,
        )?;
        range(
            "hermes.discord.ttl_seconds",
            self.ttl_seconds,
            60,
            2_592_000,
        )?;
        if self.gateway_intents == 0 {
            return Err(ConfigError::Invalid(
                "hermes.discord.gateway_intents must not be zero".to_owned(),
            ));
        }
        for token in &self.scrub_tokens {
            if token.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "hermes.discord.scrub_tokens entries must be non-empty".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl OdindHermesAccountConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.account.trim().is_empty() || self.account.len() > MAX_HERMES_ACCOUNT_CHARS {
            return Err(ConfigError::Invalid(format!(
                "hermes.accounts.account must be 1..={MAX_HERMES_ACCOUNT_CHARS} characters"
            )));
        }
        if self.secret_handle.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "hermes.accounts.secret_handle must be non-empty".to_owned(),
            ));
        }
        if !self.secret_path.is_absolute() {
            return Err(ConfigError::Invalid(
                "hermes.accounts.secret_path must be an absolute path".to_owned(),
            ));
        }
        self.provider.validate()
    }
}

impl OdindHermesProviderConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Jmap {
                session_url,
                identity_id,
                from_address,
                drafts_mailbox_id,
                archive_mailbox_id,
                trash_mailbox_id,
                calendar_id,
                request_timeout_ms,
                max_response_bytes,
            } => {
                https_field("hermes.accounts.jmap.session_url", session_url)?;
                for (field, value) in [
                    ("hermes.accounts.jmap.identity_id", identity_id.as_str()),
                    ("hermes.accounts.jmap.from_address", from_address.as_str()),
                    (
                        "hermes.accounts.jmap.drafts_mailbox_id",
                        drafts_mailbox_id.as_str(),
                    ),
                    (
                        "hermes.accounts.jmap.archive_mailbox_id",
                        archive_mailbox_id.as_str(),
                    ),
                    (
                        "hermes.accounts.jmap.trash_mailbox_id",
                        trash_mailbox_id.as_str(),
                    ),
                ] {
                    non_empty_field(field, value)?;
                }
                if let Some(calendar_id) = calendar_id {
                    non_empty_field("hermes.accounts.jmap.calendar_id", calendar_id)?;
                }
                bounded_transfer(
                    "hermes.accounts.jmap.request_timeout_ms",
                    "hermes.accounts.jmap.max_response_bytes",
                    *request_timeout_ms,
                    *max_response_bytes,
                )
            }
            Self::Google {
                token_url,
                gmail_api_url,
                calendar_api_url,
                calendar_id,
                request_timeout_ms,
                max_response_bytes,
            } => {
                https_field("hermes.accounts.google.token_url", token_url)?;
                https_field("hermes.accounts.google.gmail_api_url", gmail_api_url)?;
                https_field("hermes.accounts.google.calendar_api_url", calendar_api_url)?;
                non_empty_field("hermes.accounts.google.calendar_id", calendar_id)?;
                bounded_transfer(
                    "hermes.accounts.google.request_timeout_ms",
                    "hermes.accounts.google.max_response_bytes",
                    *request_timeout_ms,
                    *max_response_bytes,
                )
            }
            Self::Generic {
                from_address,
                imap_host,
                imap_port,
                imap_tls: _,
                smtp_host,
                smtp_port,
                smtp_tls: _,
                helo_name,
                inbox_mailbox_id,
                drafts_mailbox_id,
                archive_mailbox_id,
                trash_mailbox_id,
                caldav_base_url,
                caldav_calendar_url,
                request_timeout_ms,
                max_response_bytes,
            } => {
                address_field("hermes.accounts.generic.from_address", from_address)?;
                host_field("hermes.accounts.generic.imap_host", imap_host)?;
                host_field("hermes.accounts.generic.smtp_host", smtp_host)?;
                if *imap_port == 0 || *smtp_port == 0 {
                    return Err(ConfigError::Invalid(
                        "hermes.accounts.generic mail ports must be 1..=65535".to_owned(),
                    ));
                }
                host_field("hermes.accounts.generic.helo_name", helo_name)?;
                for (field, value) in [
                    (
                        "hermes.accounts.generic.inbox_mailbox_id",
                        inbox_mailbox_id.as_str(),
                    ),
                    (
                        "hermes.accounts.generic.drafts_mailbox_id",
                        drafts_mailbox_id.as_str(),
                    ),
                    (
                        "hermes.accounts.generic.archive_mailbox_id",
                        archive_mailbox_id.as_str(),
                    ),
                    (
                        "hermes.accounts.generic.trash_mailbox_id",
                        trash_mailbox_id.as_str(),
                    ),
                ] {
                    non_empty_field(field, value)?;
                }
                if let Some(base_url) = caldav_base_url {
                    caldav_url_field("hermes.accounts.generic.caldav_base_url", base_url)?;
                    if let Some(calendar_url) = caldav_calendar_url {
                        caldav_url_field(
                            "hermes.accounts.generic.caldav_calendar_url",
                            calendar_url,
                        )?;
                    }
                } else if caldav_calendar_url.is_some() {
                    return Err(ConfigError::Invalid(
                        "hermes.accounts.generic.caldav_calendar_url requires \
                         hermes.accounts.generic.caldav_base_url"
                            .to_owned(),
                    ));
                }
                bounded_transfer(
                    "hermes.accounts.generic.request_timeout_ms",
                    "hermes.accounts.generic.max_response_bytes",
                    *request_timeout_ms,
                    *max_response_bytes,
                )
            }
        }
    }
}

/// Non-empty wire field inside one life-account declaration.
fn non_empty_field(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::Invalid(format!("{field} must be non-empty")));
    }
    Ok(())
}

/// HTTPS endpoint wire field inside one life-account declaration.
fn https_field(field: &'static str, value: &str) -> Result<(), ConfigError> {
    non_empty_field(field, value)?;
    if !value.starts_with("https://") {
        return Err(ConfigError::Invalid(format!(
            "{field} must be an HTTPS endpoint"
        )));
    }
    Ok(())
}

/// Matches life-account provider limits for request duration and response size.
fn bounded_transfer(
    timeout_field: &'static str,
    bytes_field: &'static str,
    request_timeout_ms: u64,
    max_response_bytes: u64,
) -> Result<(), ConfigError> {
    range(timeout_field, request_timeout_ms as i64, 1_000, 300_000)?;
    range(bytes_field, max_response_bytes as i64, 1_024, 16_777_216)
}

fn address_field(field: &'static str, value: &str) -> Result<(), ConfigError> {
    non_empty_field(field, value)?;
    if value.len() > 320 || value.chars().any(char::is_control) {
        return Err(ConfigError::Invalid(format!(
            "{field} must be a bounded address without control characters"
        )));
    }
    if value.matches('@').count() != 1 {
        return Err(ConfigError::Invalid(format!(
            "{field} must contain exactly one @ separator"
        )));
    }
    Ok(())
}

fn host_field(field: &'static str, value: &str) -> Result<(), ConfigError> {
    non_empty_field(field, value)?;
    if value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return Err(ConfigError::Invalid(format!(
            "{field} must be a bounded host name of letters, digits, '-', '.', '_'"
        )));
    }
    Ok(())
}

/// Plain HTTP is allowed only for loopback CalDAV endpoints.
fn caldav_url_field(field: &'static str, value: &str) -> Result<(), ConfigError> {
    non_empty_field(field, value)?;
    if value.starts_with("https://") {
        return Ok(());
    }
    let url = url::Url::parse(value)
        .map_err(|_| ConfigError::Invalid(format!("{field} must be a valid HTTP or HTTPS URL")))?;
    let loopback = matches!(
        url.host_str(),
        Some("127.0.0.1") | Some("[::1]") | Some("localhost")
    ) || url
        .host_str()
        .and_then(|host| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::Ipv6Addr>()
                .ok()
        })
        .is_some_and(|addr| addr.is_loopback());
    if url.scheme() == "http" && loopback {
        return Ok(());
    }
    Err(ConfigError::Invalid(format!(
        "{field} must be HTTPS, or plain HTTP on the loopback interface only"
    )))
}

impl OdindHermesVaultConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.vault_root.is_absolute() {
            return Err(ConfigError::Invalid(
                "hermes.vault.vault_root must be an absolute path".to_owned(),
            ));
        }
        if self.source_id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "hermes.vault.source_id must be non-empty".to_owned(),
            ));
        }
        if self.general_namespaces.is_empty() {
            return Err(ConfigError::Invalid(
                "hermes.vault.general_namespaces must not be empty".to_owned(),
            ));
        }
        if self.generated_namespace.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "hermes.vault.generated_namespace must be non-empty".to_owned(),
            ));
        }
        for namespace in &self.excluded_namespaces {
            if self.general_namespaces.contains(namespace) {
                return Err(ConfigError::Invalid(format!(
                    "hermes.vault.excluded_namespaces entry {namespace:?} must not intersect \
                     the general allowlist"
                )));
            }
        }
        range("hermes.vault.max_pages", self.max_pages as i64, 1, 100_000)?;
        range(
            "hermes.vault.max_page_bytes",
            self.max_page_bytes as i64,
            1,
            4_194_304,
        )?;
        range(
            "hermes.vault.timeout_ms",
            self.timeout_ms as i64,
            1_000,
            60_000,
        )
    }
}

impl OdindHermesFinanceConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.budget_db.is_absolute() {
            return Err(ConfigError::Invalid(
                "hermes.finance.budget_db must be an absolute path".to_owned(),
            ));
        }
        Ok(())
    }
}

impl OdindDisplayConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match self.source {
            BrowserDisplaySource::Xvfb => {
                if self.xvfb_binary.is_some() && self.display.is_none() {
                    return Ok(());
                }
                Err(ConfigError::Invalid(
                    "browser display source `xvfb` requires exactly an absolute xvfb_binary"
                        .to_owned(),
                ))
            }
            BrowserDisplaySource::Existing => {
                if self.display.is_some() && self.xvfb_binary.is_none() {
                    return Ok(());
                }
                Err(ConfigError::Invalid(
                    "browser display source `existing` requires exactly a display name".to_owned(),
                ))
            }
        }
    }
}

/// Symlink-expansion bound for [`resolve_state_prefix`], mirroring the
/// kernel's own `ELOOP` limit: expansion past it is a cycle, not a path.
const MAX_STATE_SYMLINK_HOPS: usize = 40;

/// Composition-time refusal of `..` in a declared path: parent components
/// interact with symlinked earlier segments in ways lexical normalization
/// cannot observe, and no legitimate deployment declares one. Applies to
/// the state root itself and every covered field.
fn ban_parent_components(key: &str, path: &Path) -> Result<(), ConfigError> {
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(ConfigError::Invalid(format!(
            "{key} must not contain parent (..) path components"
        )));
    }
    Ok(())
}

/// Kernel-faithful resolution for composition-time containment: every
/// component of `path` is applied step by step and every symlink the walk
/// crosses is expanded in place — including a dangling target, which
/// resolves to where it WOULD land — so the result is the location the
/// kernel would act on, never a lexical join. Absent components keep
/// walking harmlessly, so a declared path need not exist and nothing is
/// created, written, or required to exist. Any probe error that is not
/// plain absence fails closed, as does expansion past
/// [`MAX_STATE_SYMLINK_HOPS`].
pub(super) fn resolve_state_prefix(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("must be an absolute path".to_owned());
    }
    let mut hops = 0usize;
    resolve_walk(PathBuf::from("/"), path.components().skip(1), &mut hops)
}

/// Applies `components` onto the already-resolved `resolved`, expanding a
/// symlink depth-first: the link's target resolves fully first, then the
/// remaining components continue on top of it. All recursion levels share
/// one hop counter, so [`MAX_STATE_SYMLINK_HOPS`] bounds every expansion
/// the walk performs — across nested target chains and continuations alike
/// — and recursion depth, one level per in-flight expansion, with it.
/// Components borrow from distinct sources per level (the declared path,
/// then each read target), hence the per-call lifetime.
fn resolve_walk<'c>(
    mut resolved: PathBuf,
    mut components: impl Iterator<Item = std::path::Component<'c>>,
    hops: &mut usize,
) -> Result<PathBuf, String> {
    while let Some(component) = components.next() {
        match component {
            std::path::Component::Normal(part) => resolved.push(part),
            std::path::Component::CurDir => continue,
            std::path::Component::ParentDir => {
                resolved.pop();
                continue;
            }
            _ => return Err("unexpected path component".to_owned()),
        }
        match std::fs::symlink_metadata(&resolved) {
            Ok(meta) if meta.file_type().is_symlink() => {
                *hops += 1;
                if *hops > MAX_STATE_SYMLINK_HOPS {
                    return Err(format!(
                        "symlink expansion exceeded {MAX_STATE_SYMLINK_HOPS} hops (cycle)"
                    ));
                }
                let target = std::fs::read_link(&resolved)
                    .map_err(|error| format!("symlink read failed closed: {error}"))?;
                let base = if target.is_absolute() {
                    PathBuf::from("/")
                } else {
                    let mut parent = resolved;
                    parent.pop();
                    parent
                };
                let mut target_components = target.components();
                if target.is_absolute() {
                    target_components.next();
                }
                let nested = resolve_walk(base, target_components, &mut *hops)?;
                return resolve_walk(nested, components, hops);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("path probe failed closed: {error}")),
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::knowledge::{
        ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
    };

    fn archive_source() -> OdindBrainSourceConfig {
        OdindBrainSourceConfig {
            kind: "archive".to_owned(),
            privacy: None,
            root: None,
            port: None,
            expected_space_root: None,
            general_namespaces: Vec::new(),
            generated_namespace: None,
            excluded_namespaces: Vec::new(),
            max_pages: None,
            format: Some(ArchiveFormat::Mbox),
            export_path: Some(std::path::PathBuf::from("/srv/exports/mail.mbox")),
            memory_namespace: Some("archive.gmail".to_owned()),
            privacy_class: Some(ArchivePrivacyClass::Private),
            dedupe_key: Some(ArchiveDedupeKey::ContentDigest),
            selection: Some(ArchiveSelectionPolicy {
                since: None,
                exclude_labels: vec!["Spam".to_owned()],
                exclude_if_header: Vec::new(),
                keep_if_participant: false,
                participant_emails: Vec::new(),
                suspicious_rules: Vec::new(),
                exclude_do_not_remember: None,
            }),
        }
    }

    #[test]
    fn archive_source_validates_and_rejects_cross_kind_fields() {
        archive_source()
            .validate_for("archive:gmail")
            .expect("valid archive source");
        let mut cross_kind = archive_source();
        cross_kind.kind = "atlas".to_owned();
        assert!(cross_kind.validate_for("archive:gmail").is_err());
        let mut with_root = archive_source();
        with_root.root = Some(std::path::PathBuf::from("/srv/repo"));
        assert!(with_root.validate_for("archive:gmail").is_err());
    }

    #[test]
    fn archive_source_rejects_invalid_policy_at_the_config_seam() {
        // A thread rule with no declared addresses is valid: the export's
        // own sent metadata proves participation and no identity is ever
        // inferred, so the gate can run without an operator address.
        let mut source = archive_source();
        source.selection = Some(ArchiveSelectionPolicy {
            since: None,
            exclude_labels: Vec::new(),
            exclude_if_header: Vec::new(),
            keep_if_participant: true,
            participant_emails: Vec::new(),
            suspicious_rules: Vec::new(),
            exclude_do_not_remember: None,
        });
        source
            .validate_for("archive:gmail")
            .expect("sent metadata alone proves participation");
        // A supplied address must still be one exact address: the same seam
        // refuses a malformed declaration.
        let mut malformed = archive_source();
        malformed.selection = Some(ArchiveSelectionPolicy {
            since: None,
            exclude_labels: Vec::new(),
            exclude_if_header: Vec::new(),
            keep_if_participant: true,
            participant_emails: vec!["not-an-address".to_owned()],
            suspicious_rules: Vec::new(),
            exclude_do_not_remember: None,
        });
        let error = malformed
            .validate_for("archive:gmail")
            .expect_err("a malformed participant address must fail");
        assert!(error.contains("participant"), "{error}");
    }

    #[test]
    fn archive_source_requires_every_declared_field() {
        let mut source = archive_source();
        source.format = None;
        assert!(source.validate_for("archive:gmail").is_err());
        let mut source = archive_source();
        source.selection = None;
        assert!(source.validate_for("archive:gmail").is_err());
    }

    #[test]
    fn atlas_and_silverbullet_sources_stay_valid_without_archive_fields() {
        let atlas = OdindBrainSourceConfig {
            kind: "atlas".to_owned(),
            privacy: None,
            root: Some(std::path::PathBuf::from("/srv/repo")),
            port: None,
            expected_space_root: None,
            general_namespaces: Vec::new(),
            generated_namespace: None,
            excluded_namespaces: Vec::new(),
            max_pages: None,
            format: None,
            export_path: None,
            memory_namespace: None,
            privacy_class: None,
            dedupe_key: None,
            selection: None,
        };
        atlas.validate_for("atlas:odin").expect("atlas stays valid");
    }
}
