use odin_registry::{AccountKind, EnvironmentTransport, ObjectConfig, DEFAULT_ACCOUNT};

use super::*;

pub(super) fn run_sys_01(context: &SystemContext, deadline: Instant) -> CheckResult {
    super::run_check("SYS-01", sys_01_body, context, deadline)
}

fn sys_01_body(context: &SystemContext, deadline: Instant) -> Outcome {
    let mut evidence = Vec::new();
    let scratch = command_scratch(context, "SYS-01")?;

    let executable = env::current_exe().map_err(|error| {
        CheckFailure::fail(
            "sweep-executable-unresolved",
            format!("the sweep executable could not be resolved: {error}"),
        )
    })?;
    let version = run_bounded(
        &executable,
        &[OsString::from("--version")],
        &scratch,
        &context.odin_root,
        deadline,
    )
    .map_err(|error| {
        CheckFailure::fail(
            "version-command-failed",
            format!("sweep --version could not execute: {error}"),
        )
    })?;
    if let Some(problem) = command_problem(&version) {
        return Err(CheckFailure::fail(
            problem,
            "sweep --version did not complete successfully",
        ));
    }
    if trimmed_stdout(&version).is_empty() {
        return Err(CheckFailure::fail(
            "version-output-empty",
            "sweep --version returned no version identity",
        ));
    }
    note_evidence(&mut evidence, "sweep-version=responded");

    let schemas_root = context.odin_root.join("schemas");
    let entries = walk_entries(&schemas_root, 8).map_err(|error| {
        CheckFailure::fail(
            "schema-inventory-unbounded",
            format!("schema inventory could not be bounded: {error}"),
        )
    })?;
    let mut schema_paths = entries
        .iter()
        .filter(|entry| {
            entry.file_type().is_file() && entry.path().extension() == Some(OsStr::new("json"))
        })
        .map(|entry| entry.path().to_path_buf())
        .collect::<Vec<_>>();
    schema_paths.sort();
    if schema_paths.is_empty() {
        return Err(CheckFailure::fail(
            "schema-inventory-empty",
            "no committed JSON schemas were found",
        ));
    }
    let mut schemas = Vec::with_capacity(schema_paths.len());
    let mut resources = Vec::with_capacity(schema_paths.len());
    for path in &schema_paths {
        let bytes = read_bounded(path).map_err(|error| {
            CheckFailure::fail(
                "schema-unreadable",
                format!("committed schema {} is unreadable: {error}", path.display()),
            )
        })?;
        let schema: JsonValue = serde_json::from_slice(&bytes).map_err(|_| {
            CheckFailure::fail(
                "schema-json-malformed",
                format!("committed schema {} is malformed JSON", path.display()),
            )
        })?;
        let uri = schema
            .get("$id")
            .and_then(JsonValue::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "https://odin.local/schemas/{}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                )
            });
        let resource = jsonschema::Resource::from_contents(schema.clone())
            .map_err(|error| CheckFailure::fail("schema-resource-invalid", error.to_string()))?;
        resources.push((uri.clone(), resource));
        schemas.push((path, uri, schema));
    }
    let registry = jsonschema::Registry::try_from_resources(resources)
        .map_err(|error| CheckFailure::fail("schema-reference-invalid", error.to_string()))?;
    for (path, uri, schema) in schemas {
        jsonschema::options()
            .with_registry(registry.clone())
            .with_base_uri(uri)
            .build(&schema)
            .map_err(|error| {
                CheckFailure::fail(
                    "schema-compile-failed",
                    format!("committed schema {}: {error}", path.display()),
                )
            })?;
    }
    note_evidence(
        &mut evidence,
        format!("json-schemas-compiled={}", schema_paths.len()),
    );

    if context.runtime_manifest.is_none() {
        return Ok(CheckOutcome {
            status: CheckStatus::Blocked,
            summary: format!(
                "sweep --version and {} committed schemas verified; the configured composition is absent so config integrity was not evaluated",
                schema_paths.len()
            ),
            reason: Some("runtime-manifest-unconfigured".to_owned()),
            evidence,
        });
    }
    let runtime = require_manifest(context, CheckStatus::Blocked)?;
    let config_reference = &runtime.odind_config;
    let encoded = config_reference
        .digest
        .strip_prefix("blake3:")
        .ok_or_else(|| {
            CheckFailure::fail(
                "odind-config-digest-malformed",
                "runtime manifest odind_config digest lacks the blake3: prefix",
            )
        })?;
    let bytes = read_bounded(&config_reference.path).map_err(|error| {
        CheckFailure::fail(
            "odind-config-unreadable",
            format!(
                "packaged odind config {} is unreadable: {error}",
                config_reference.path.display()
            ),
        )
    })?;
    let observed = blake3::hash(&bytes).to_hex().to_string();
    if observed != encoded {
        return Err(CheckFailure::fail(
            "odind-config-digest-mismatch",
            format!(
                "packaged odind config {} digests to blake3:{observed}, manifest declares {encoded}",
                config_reference.path.display()
            ),
        ));
    }
    let config = OdindConfig::load(&config_reference.path).map_err(|error| {
        CheckFailure::fail(
            "odind-config-invalid",
            format!(
                "packaged odind config {} rejected: {error}",
                config_reference.path.display()
            ),
        )
    })?;
    note_evidence(&mut evidence, "odind-config=digest-verified-and-validated");

    let objects = odin_registry::SnapshotStore::new(&config.paths.registry_snapshot)
        .load_verified()
        .map_err(|error| {
            CheckFailure::fail(
                "registry-snapshot-unverified",
                format!("the published registry snapshot is not verified: {error}"),
            )
        })?
        .objects;
    let home = env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let declared = declared_accounts(
        config
            .seats
            .iter()
            .flat_map(|seat| &seat.launch_options)
            .filter_map(|option| option.harness.as_ref()),
        &objects,
    );
    let signed_out: Vec<String> = declared
        .iter()
        .filter(|(kind, name)| !kind.signed_in(&home, name))
        .map(|(kind, name)| {
            format!(
                "{}:{name} (sign in: {})",
                kind.as_str(),
                kind.sign_in_hint(name)
            )
        })
        .collect();
    note_evidence(
        &mut evidence,
        format!("accounts-declared={}", handles(declared.iter().cloned())),
    );
    note_evidence(
        &mut evidence,
        format!(
            "accounts-signed-in={}",
            handles(
                [AccountKind::ClaudeCode, AccountKind::Codex]
                    .into_iter()
                    .flat_map(|kind| kind
                        .discover(&home)
                        .into_iter()
                        .map(move |name| (kind, name)))
            )
        ),
    );
    if !signed_out.is_empty() {
        return Err(CheckFailure::fail(
            "account-signed-out",
            format!("declared accounts not signed in: {}", signed_out.join("; ")),
        ));
    }

    CheckOutcome::pass(
        format!(
            "sweep --version responded, {} committed JSON schemas compile, the packaged strict config validates, and \
             its {} declared accounts are signed in",
            schema_paths.len(),
            declared.len()
        ),
        evidence,
    )
}

fn handles(accounts: impl Iterator<Item = (AccountKind, String)>) -> String {
    let joined = accounts
        .map(|(kind, name)| format!("{}:{name}", kind.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    if joined.is_empty() {
        "none".to_owned()
    } else {
        joined
    }
}

/// The accounts agents on this host may run on: a launch option's own account, the accounts projects declare for a
/// kind such a launch option signs in with, and `default` for that kind while any project leaves it undeclared.
fn declared_accounts<'a>(
    bindings: impl Iterator<Item = &'a odin_domain::huginn::HarnessBinding>,
    objects: &[odin_registry::RegistryObject],
) -> BTreeSet<(AccountKind, String)> {
    let mut harnesses = BTreeMap::new();
    let mut local_environments = BTreeSet::new();
    let mut projects = Vec::new();
    for object in objects {
        match &object.config {
            ObjectConfig::Harness(harness) if harness.enabled => {
                if let Some(kind) = harness.account {
                    harnesses.insert(object.id.as_str(), kind);
                }
            }
            ObjectConfig::Environment(environment)
                if environment.enabled
                    && matches!(
                        environment.transport,
                        EnvironmentTransport::FleetHost | EnvironmentTransport::K3sPod
                    ) =>
            {
                local_environments.insert(object.id.as_str());
            }
            ObjectConfig::Project(project) if project.enabled => projects.push(&project.accounts),
            _ => {}
        }
    }
    let mut declared = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for binding in
        bindings.filter(|binding| local_environments.contains(binding.environment.as_str()))
    {
        let Some(&kind) = harnesses.get(binding.harness.as_str()) else {
            continue;
        };
        match &binding.account {
            Some(name) => {
                declared.insert((kind, name.clone()));
            }
            None => {
                kinds.insert(kind);
            }
        }
    }
    for kind in kinds {
        for accounts in &projects {
            declared.insert((
                kind,
                accounts
                    .get(&kind)
                    .cloned()
                    .unwrap_or_else(|| DEFAULT_ACCOUNT.to_owned()),
            ));
        }
    }
    declared
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Account discovery includes local launch bindings and project defaults, excluding other hosts.
    #[test]
    fn the_declared_accounts_are_the_options_and_the_projects() {
        let registry = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry");
        let object = |kind, id: &str, path: &str| {
            odin_registry::schema::parse_object_toml(
                kind,
                id,
                path,
                &fs::read_to_string(registry.join(path)).expect("declaration"),
            )
            .expect("parses")
        };
        let mut objects = vec![
            object(
                odin_registry::RegistryKind::Harness,
                "codex",
                "harnesses/codex/harness.toml",
            ),
            object(
                odin_registry::RegistryKind::Environment,
                "sandbox-authority",
                "environments/sandbox-authority/environment.toml",
            ),
            object(
                odin_registry::RegistryKind::Environment,
                "laptop-ssh",
                "environments/laptop-ssh/environment.toml",
            ),
            object(
                odin_registry::RegistryKind::Project,
                "weno5",
                "projects/weno5/project.toml",
            ),
            object(
                odin_registry::RegistryKind::Project,
                "odin",
                "projects/odin/project.toml",
            ),
        ];
        let ObjectConfig::Project(weno5) = &mut objects[3].config else {
            panic!("project");
        };
        weno5
            .accounts
            .insert(AccountKind::Codex, "school".to_owned());
        let binding = |harness: &str, environment: &str, account: Option<&str>| {
            odin_domain::huginn::HarnessBinding {
                harness: harness.to_owned(),
                environment: environment.to_owned(),
                account: account.map(str::to_owned),
            }
        };
        let bindings = [
            binding("codex", "sandbox-authority", None),
            binding("codex", "sandbox-authority", Some("club")),
            binding("codex", "laptop-ssh", Some("remote")),
        ];
        let declared = declared_accounts(bindings.iter(), &objects);
        assert_eq!(
            handles(declared.into_iter()),
            "codex:club,codex:default,codex:school"
        );
        assert_eq!(
            handles(declared_accounts([].iter(), &objects).into_iter()),
            "none"
        );
    }

    #[test]
    fn every_committed_schema_compiles_under_its_declared_draft() {
        let schemas_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas");
        let entries =
            walk_entries(&schemas_root, 8).expect("the committed schemas tree is walkable");
        let mut schema_paths: Vec<PathBuf> = entries
            .iter()
            .filter(|entry| {
                entry.file_type().is_file() && entry.path().extension() == Some(OsStr::new("json"))
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();
        assert!(
            !schema_paths.is_empty(),
            "the committed schemas tree must be non-empty"
        );
        schema_paths.sort();
        let mut schemas = Vec::with_capacity(schema_paths.len());
        let mut resources = Vec::with_capacity(schema_paths.len());
        for path in &schema_paths {
            let bytes = read_bounded(path).expect("committed schema is readable");
            let schema: JsonValue =
                serde_json::from_slice(&bytes).expect("committed schema is valid JSON");
            let uri = schema
                .get("$id")
                .and_then(JsonValue::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    format!(
                        "https://odin.local/schemas/{}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    )
                });
            let resource =
                jsonschema::Resource::from_contents(schema.clone()).unwrap_or_else(|error| {
                    panic!(
                        "committed schema {} compiles as a resource: {error}",
                        path.display()
                    )
                });
            resources.push((uri.clone(), resource));
            schemas.push((path.clone(), uri, schema));
        }
        let registry = jsonschema::Registry::try_from_resources(resources)
            .expect("committed schema references resolve");
        for (path, uri, schema) in schemas {
            jsonschema::options()
                .with_registry(registry.clone())
                .with_base_uri(uri)
                .build(&schema)
                .unwrap_or_else(|error| panic!("committed schema {}: {error}", path.display()));
        }
    }
}
