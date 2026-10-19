//! Validate skeleton contracts before compiling declared fill variables.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::compile::{compile_patch, compile_registry, CompiledFill};
use super::values::{
    parse_filled_value, parse_variable_type, validate_stable_id, FilledValue, VariableType,
};
use crate::relational::{ignored, sorted_paths, AdmittedBinding};
use crate::schema::{RegistryKind, REGISTRY_SCHEMA};
use crate::RegistryFinding;

pub const SKELETON_VARIABLE_SCHEMA: &str = "odin.skeleton.variables.v1";
pub const SKELETON_PATCH_SCHEMA: &str = "odin.skeleton.patch.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkeletonKind {
    NewAlert,
    NewCapability,
    NewContainer,
    NewEnvironment,
    NewHarness,
    NewHost,
    NewLane,
    NewNode,
    NewProject,
    NewProvider,
    NewSeat,
    NewSlice,
    NewSurface,
    NewWorkload,
}

impl SkeletonKind {
    pub const ALL: [Self; 14] = [
        Self::NewAlert,
        Self::NewCapability,
        Self::NewContainer,
        Self::NewEnvironment,
        Self::NewHarness,
        Self::NewHost,
        Self::NewLane,
        Self::NewNode,
        Self::NewProject,
        Self::NewProvider,
        Self::NewSeat,
        Self::NewSlice,
        Self::NewSurface,
        Self::NewWorkload,
    ];

    pub const fn folder(self) -> &'static str {
        match self {
            Self::NewAlert => "new-alert",
            Self::NewCapability => "new-capability",
            Self::NewContainer => "new-container",
            Self::NewEnvironment => "new-environment",
            Self::NewHarness => "new-harness",
            Self::NewHost => "new-host",
            Self::NewLane => "new-lane",
            Self::NewNode => "new-node",
            Self::NewProject => "new-project",
            Self::NewProvider => "new-provider",
            Self::NewSeat => "new-seat",
            Self::NewSlice => "new-slice",
            Self::NewSurface => "new-surface",
            Self::NewWorkload => "new-workload",
        }
    }

    pub const fn kind_str(self) -> &'static str {
        match self {
            Self::NewAlert => "new-alert",
            Self::NewCapability => "capability",
            Self::NewContainer => "container",
            Self::NewEnvironment => "environment",
            Self::NewHarness => "harness",
            Self::NewHost => "host",
            Self::NewLane => "lane",
            Self::NewNode => "node",
            Self::NewProject => "project",
            Self::NewProvider => "provider",
            Self::NewSeat => "seat",
            Self::NewSlice => "slice",
            Self::NewSurface => "new-surface",
            Self::NewWorkload => "workload",
        }
    }

    pub const fn destination(self) -> &'static str {
        match self {
            Self::NewAlert | Self::NewSurface => "container-patch",
            Self::NewCapability => "capabilities",
            Self::NewContainer => "containers",
            Self::NewEnvironment => "environments",
            Self::NewHarness => "harnesses",
            Self::NewHost => "hosts",
            Self::NewLane => "lanes",
            Self::NewNode => "nodes",
            Self::NewProject => "projects",
            Self::NewProvider => "providers",
            Self::NewSeat => "seats",
            Self::NewSlice => "slices",
            Self::NewWorkload => "workloads",
        }
    }

    pub const fn template_schema(self) -> &'static str {
        match self {
            Self::NewAlert | Self::NewSurface => SKELETON_PATCH_SCHEMA,
            _ => REGISTRY_SCHEMA,
        }
    }

    pub const fn operation(self) -> Option<&'static str> {
        match self {
            Self::NewAlert => Some("append_watchdog"),
            Self::NewSurface => Some("append_surface"),
            _ => None,
        }
    }

    pub const fn registry_kind(self) -> Option<RegistryKind> {
        match self {
            Self::NewAlert | Self::NewSurface => None,
            Self::NewCapability => Some(RegistryKind::Capability),
            Self::NewContainer => Some(RegistryKind::Container),
            Self::NewEnvironment => Some(RegistryKind::Environment),
            Self::NewHarness => Some(RegistryKind::Harness),
            Self::NewHost => Some(RegistryKind::Host),
            Self::NewLane => Some(RegistryKind::Lane),
            Self::NewNode => Some(RegistryKind::Node),
            Self::NewProject => Some(RegistryKind::Project),
            Self::NewProvider => Some(RegistryKind::Provider),
            Self::NewSeat => Some(RegistryKind::Seat),
            Self::NewSlice => Some(RegistryKind::Slice),
            Self::NewWorkload => Some(RegistryKind::Workload),
        }
    }

    fn from_folder(folder: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.folder() == folder)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SkeletonVariable {
    pub name: String,
    pub variable_type: String,
    pub required: bool,
    pub meaning: String,
}

impl SkeletonVariable {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn variable_type(&self) -> &str {
        &self.variable_type
    }

    pub fn meaning(&self) -> &str {
        &self.meaning
    }
}

#[derive(Clone, Debug)]
pub struct SkeletonContract {
    pub(super) kind: SkeletonKind,
    variables: Vec<SkeletonVariable>,
    blank_occurrences: usize,
    pub(super) template: toml::Value,
    pub(super) template_path: PathBuf,
    pub(super) variables_path: PathBuf,
}

impl SkeletonContract {
    pub const fn kind(&self) -> SkeletonKind {
        self.kind
    }

    pub const fn folder(&self) -> &'static str {
        self.kind.folder()
    }

    pub const fn kind_str(&self) -> &'static str {
        self.kind.kind_str()
    }

    pub const fn destination(&self) -> &'static str {
        self.kind.destination()
    }

    pub const fn registry_kind(&self) -> Option<RegistryKind> {
        self.kind.registry_kind()
    }

    pub const fn operation(&self) -> Option<&'static str> {
        self.kind.operation()
    }

    pub fn variables(&self) -> impl ExactSizeIterator<Item = &SkeletonVariable> {
        self.variables.iter()
    }

    pub fn variable(&self, name: &str) -> Option<&SkeletonVariable> {
        self.variables
            .binary_search_by_key(&name, |variable| variable.name.as_str())
            .ok()
            .map(|index| &self.variables[index])
    }

    pub const fn blank_occurrences(&self) -> usize {
        self.blank_occurrences
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AuthoringIssue {
    pub code: String,
    pub path: PathBuf,
    pub variable: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AuthoringErrors {
    pub issues: Vec<AuthoringIssue>,
}

impl AuthoringErrors {
    pub fn new(mut issues: Vec<AuthoringIssue>) -> Self {
        issues.sort();
        issues.dedup();
        Self { issues }
    }

    pub fn single(issue: AuthoringIssue) -> Self {
        Self::new(vec![issue])
    }

    pub fn issues(&self) -> &[AuthoringIssue] {
        &self.issues
    }

    pub fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }
}

impl fmt::Display for AuthoringErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} authoring issue(s)", self.issues.len())?;
        for issue in &self.issues {
            write!(
                formatter,
                "; {} at {}: {}",
                issue.code,
                issue.path.display(),
                issue.message
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for AuthoringErrors {}

/// Extra filesystem entries are nonblocking issues; contract defects prevent loading.
#[derive(Clone, Debug)]
pub struct SkeletonCatalog {
    contracts: BTreeMap<SkeletonKind, SkeletonContract>,
    anomalies: Vec<AuthoringIssue>,
}

impl SkeletonCatalog {
    pub fn load(root: impl AsRef<Path>) -> Result<Self, AuthoringErrors> {
        let root = root.as_ref();
        let metadata = fs::symlink_metadata(root).map_err(|error| {
            AuthoringErrors::single(issue(
                "skeleton-root-read",
                PathBuf::from("skeletons"),
                None::<String>,
                format!("could not read skeleton root: {error}"),
            ))
        })?;
        if !metadata.file_type().is_dir() {
            return Err(AuthoringErrors::single(issue(
                "skeleton-root-type",
                PathBuf::from("skeletons"),
                None::<String>,
                "skeleton root must be a regular directory",
            )));
        }

        let mut issues = Vec::new();
        let entries = sorted_paths(root).map_err(|error| {
            AuthoringErrors::single(issue(
                "skeleton-root-read",
                PathBuf::from("skeletons"),
                None::<String>,
                format!("could not enumerate skeleton root: {error}"),
            ))
        })?;
        for entry in entries {
            let Some(name) = entry.file_name() else {
                issues.push(issue(
                    "skeleton-anomalous-entry",
                    skeleton_relative(root, &entry),
                    None::<String>,
                    "unexpected skeleton entry has no filesystem name",
                ));
                continue;
            };
            if ignored(name) {
                continue;
            }
            if name.to_str().and_then(SkeletonKind::from_folder).is_none() {
                issues.push(issue(
                    "skeleton-anomalous-entry",
                    skeleton_relative(root, &entry),
                    None::<String>,
                    "unexpected skeleton entry is not an authoring destination",
                ));
            }
        }

        let mut contracts = BTreeMap::new();
        for kind in SkeletonKind::ALL {
            if let Some(contract) = load_contract(root, kind, &mut issues) {
                contracts.insert(kind, contract);
            }
        }
        if issues
            .iter()
            .any(|value| value.code != "skeleton-anomalous-entry")
        {
            return Err(AuthoringErrors::new(issues));
        }
        issues.sort();
        Ok(Self {
            contracts,
            anomalies: issues,
        })
    }

    pub fn contracts(&self) -> impl ExactSizeIterator<Item = &SkeletonContract> {
        self.contracts.values()
    }

    pub fn contract(&self, kind: SkeletonKind) -> Option<&SkeletonContract> {
        self.contracts.get(&kind)
    }

    pub fn anomalies(&self) -> &[AuthoringIssue] {
        &self.anomalies
    }

    pub fn compile(&self, request: FillRequest) -> Result<CompiledFill, AuthoringErrors> {
        self.compile_with_bindings(request, &[])
    }

    pub fn compile_with_bindings(
        &self,
        request: FillRequest,
        admitted_bindings: &[AdmittedBinding],
    ) -> Result<CompiledFill, AuthoringErrors> {
        let Some(contract) = self.contract(request.skeleton) else {
            return Err(AuthoringErrors::single(issue(
                "authoring-skeleton-missing",
                PathBuf::from("skeletons").join(request.skeleton.folder()),
                None::<String>,
                "requested skeleton is not present in the audited catalog",
            )));
        };

        let declared: BTreeSet<String> = contract
            .variables
            .iter()
            .map(|variable| variable.name.clone())
            .collect();
        let provided: BTreeSet<String> = request.values.0.keys().cloned().collect();
        let mut issues = Vec::new();
        for variable in &contract.variables {
            if variable.required && !provided.contains(&variable.name) {
                issues.push(issue(
                    "authoring-value-missing",
                    &contract.variables_path,
                    Some(&variable.name),
                    "required fill value is missing",
                ));
            }
        }
        for unknown in provided.difference(&declared) {
            issues.push(issue(
                "authoring-value-unknown",
                &contract.variables_path,
                Some(unknown),
                "fill contains a value not declared by this skeleton",
            ));
        }
        if let Err(message) = validate_stable_id(&request.destination_id) {
            issues.push(issue(
                "authoring-destination-id",
                &contract.variables_path,
                None::<String>,
                message,
            ));
        }
        if request.skeleton.operation().is_some()
            && request
                .values
                .0
                .get("container")
                .and_then(toml::Value::as_str)
                .is_some_and(|container| container != request.destination_id)
        {
            issues.push(issue(
                "authoring-target-mismatch",
                &contract.variables_path,
                Some("container"),
                "patch target must equal destination_id",
            ));
        }
        if !issues.is_empty() {
            return Err(AuthoringErrors::new(issues));
        }

        let mut filled = BTreeMap::new();
        for variable in &contract.variables {
            let variable_type = match parse_variable_type(&variable.variable_type) {
                Ok(value) => value,
                Err(message) => {
                    issues.push(issue(
                        "authoring-value-invalid",
                        &contract.variables_path,
                        Some(&variable.name),
                        message,
                    ));
                    continue;
                }
            };
            match request.values.0.get(&variable.name) {
                Some(raw) => match parse_filled_value(&variable_type, raw) {
                    Ok(value) => {
                        filled.insert(variable.name.clone(), value);
                    }
                    Err(message) => issues.push(issue(
                        "authoring-value-invalid",
                        &contract.variables_path,
                        Some(&variable.name),
                        message,
                    )),
                },
                None if !variable.required => {
                    filled.insert(variable.name.clone(), FilledValue::Omitted);
                }
                None => {}
            }
        }
        if !issues.is_empty() {
            return Err(AuthoringErrors::new(issues));
        }

        if request.skeleton.registry_kind().is_some() {
            compile_registry(contract, request.destination_id, &filled, admitted_bindings)
        } else {
            compile_patch(contract, request.destination_id, &filled)
        }
    }
}

/// Keep TOML values typed rather than encoding arrays, scalars, or omission markers in strings.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FillValues(pub toml::Table);

impl From<toml::Table> for FillValues {
    fn from(values: toml::Table) -> Self {
        Self(values)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FillRequest {
    pub skeleton: SkeletonKind,
    pub destination_id: String,
    pub values: FillValues,
}

/// Retain the committed source path so parse errors identify the fill document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FillDocumentSource {
    pub relative_path: PathBuf,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkeletonVariablesDocument {
    schema: String,
    kind: String,
    destination: String,
    variable: Vec<SkeletonVariableDocument>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkeletonVariableDocument {
    name: String,
    #[serde(rename = "type")]
    variable_type: String,
    required: bool,
    meaning: String,
}

pub(super) fn issue(
    code: impl Into<String>,
    path: impl Into<PathBuf>,
    variable: Option<impl Into<String>>,
    message: impl Into<String>,
) -> AuthoringIssue {
    AuthoringIssue {
        code: code.into(),
        path: path.into(),
        variable: variable.map(Into::into),
        message: message.into(),
    }
}

pub(super) fn issue_from_finding(finding: RegistryFinding) -> AuthoringIssue {
    AuthoringIssue {
        code: finding.code,
        path: finding.path,
        variable: None,
        message: finding.message,
    }
}

fn load_contract(
    root: &Path,
    kind: SkeletonKind,
    issues: &mut Vec<AuthoringIssue>,
) -> Option<SkeletonContract> {
    let initial_issue_count = issues.len();
    let folder = root.join(kind.folder());
    let relative_folder = PathBuf::from("skeletons").join(kind.folder());
    match fs::symlink_metadata(&folder) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            issues.push(issue(
                "skeleton-folder-type",
                &relative_folder,
                None::<String>,
                "fixed skeleton entry must be a regular directory",
            ));
            return None;
        }
        Err(error) => {
            issues.push(issue(
                "skeleton-folder-read",
                &relative_folder,
                None::<String>,
                format!("could not inspect fixed skeleton directory: {error}"),
            ));
            return None;
        }
    }

    let absolute_template = folder.join("TEMPLATE.toml");
    let absolute_variables = folder.join("variables.toml");
    let template_path = relative_folder.join("TEMPLATE.toml");
    let variables_path = relative_folder.join("variables.toml");
    let template_source = read_regular_utf8(
        &absolute_template,
        &template_path,
        "skeleton-template-read",
        "skeleton-template-type",
        "skeleton-template-utf8",
        issues,
    );
    let variables_source = read_regular_utf8(
        &absolute_variables,
        &variables_path,
        "skeleton-variables-read",
        "skeleton-variables-type",
        "skeleton-variables-utf8",
        issues,
    );
    let (Some(template_source), Some(variables_source)) = (template_source, variables_source)
    else {
        return None;
    };

    let variables_document = match toml::from_str::<SkeletonVariablesDocument>(&variables_source) {
        Ok(document) => Some(document),
        Err(error) => {
            issues.push(issue(
                "skeleton-variables-parse",
                &variables_path,
                None::<String>,
                format!("strict variables TOML rejected: {error}"),
            ));
            None
        }
    };
    let template = match toml::from_str::<toml::Value>(&template_source) {
        Ok(value) => Some(value),
        Err(error) => {
            issues.push(issue(
                "skeleton-template-parse",
                &template_path,
                None::<String>,
                format!("strict template TOML rejected: {error}"),
            ));
            None
        }
    };
    let blank_counts = template_blank_counts(&template_source, &template_path, issues);
    let variables_document = variables_document?;

    if variables_document.schema != SKELETON_VARIABLE_SCHEMA {
        issues.push(issue(
            "skeleton-variables-schema",
            &variables_path,
            None::<String>,
            format!(
                "variables schema must be {SKELETON_VARIABLE_SCHEMA:?}, found {:?}",
                variables_document.schema
            ),
        ));
    }
    if variables_document.kind != kind.folder() {
        issues.push(issue(
            "skeleton-variables-kind",
            &variables_path,
            None::<String>,
            format!(
                "variables kind must be {:?}, found {:?}",
                kind.folder(),
                variables_document.kind
            ),
        ));
    }
    if variables_document.destination != kind.destination() {
        issues.push(issue(
            "skeleton-variables-destination",
            &variables_path,
            None::<String>,
            format!(
                "variables destination must be {:?}, found {:?}",
                kind.destination(),
                variables_document.destination
            ),
        ));
    }
    if variables_document.variable.is_empty() {
        issues.push(issue(
            "skeleton-variables-empty",
            &variables_path,
            None::<String>,
            "skeleton must declare at least one required variable",
        ));
    }

    let names: Vec<String> = variables_document
        .variable
        .iter()
        .map(|variable| variable.name.clone())
        .collect();
    let mut sorted_names = names.clone();
    sorted_names.sort();
    let mut unique_names = sorted_names.clone();
    unique_names.dedup();
    if unique_names.len() != sorted_names.len() {
        issues.push(issue(
            "skeleton-variable-duplicate",
            &variables_path,
            None::<String>,
            "variable names must be unique",
        ));
    }

    let mut parsed_types = BTreeMap::new();
    for variable in &variables_document.variable {
        if !valid_variable_name(&variable.name) {
            issues.push(issue(
                "skeleton-variable-name",
                &variables_path,
                Some(&variable.name),
                "variable name must match [a-z][a-z0-9_]*",
            ));
        }
        match parse_variable_type(&variable.variable_type) {
            Ok(variable_type) => {
                let optional = matches!(&variable_type, VariableType::Optional(_));
                if optional == variable.required {
                    issues.push(issue(
                        "skeleton-variable-required",
                        &variables_path,
                        Some(&variable.name),
                        "optional<T> variables must use required=false and all other variables must use required=true",
                    ));
                }
                parsed_types.insert(variable.name.as_str(), variable_type);
            }
            Err(message) => issues.push(issue(
                "skeleton-variable-type",
                &variables_path,
                Some(&variable.name),
                message,
            )),
        }
        if variable.meaning.trim().is_empty() {
            issues.push(issue(
                "skeleton-variable-meaning",
                &variables_path,
                Some(&variable.name),
                "variable meaning must be nonempty",
            ));
        }
    }

    let declared: BTreeSet<&str> = variables_document
        .variable
        .iter()
        .map(|variable| variable.name.as_str())
        .collect();
    let blanks: BTreeSet<&str> = blank_counts.keys().map(String::as_str).collect();
    for missing in declared.difference(&blanks) {
        issues.push(issue(
            "skeleton-template-blank-missing",
            &template_path,
            Some(*missing),
            "declared variable has no template blank",
        ));
    }
    for unknown in blanks.difference(&declared) {
        issues.push(issue(
            "skeleton-template-blank-unknown",
            &template_path,
            Some(*unknown),
            "template blank is not declared in variables.toml",
        ));
    }

    if let Some(expected) = expected_patch_variables(kind) {
        let expected: BTreeSet<&str> = expected.iter().copied().collect();
        if declared != expected {
            issues.push(issue(
                "skeleton-patch-signature",
                &variables_path,
                None::<String>,
                "structured patch variables do not match the fixed operation signature",
            ));
        }
    }

    let template = template?;
    match template.get("schema").and_then(toml::Value::as_str) {
        Some(schema) if schema == kind.template_schema() => {}
        found => issues.push(issue(
            "skeleton-template-schema",
            &template_path,
            None::<String>,
            format!(
                "template schema must be {:?}, found {found:?}",
                kind.template_schema()
            ),
        )),
    }
    match template.get("kind").and_then(toml::Value::as_str) {
        Some(template_kind) if template_kind == kind.kind_str() => {}
        found => issues.push(issue(
            "skeleton-template-kind",
            &template_path,
            None::<String>,
            format!(
                "template kind must be {:?}, found {found:?}",
                kind.kind_str()
            ),
        )),
    }
    if let Some(operation) = kind.operation() {
        if template.get("target_kind").and_then(toml::Value::as_str) != Some("container") {
            issues.push(issue(
                "skeleton-patch-target-kind",
                &template_path,
                None::<String>,
                "structured patch target_kind must be \"container\"",
            ));
        }
        if template.get("operation").and_then(toml::Value::as_str) != Some(operation) {
            issues.push(issue(
                "skeleton-patch-operation",
                &template_path,
                None::<String>,
                format!("structured patch operation must be {operation:?}"),
            ));
        }
        if template.get("target_id").and_then(toml::Value::as_str) != Some("__container__") {
            issues.push(issue(
                "skeleton-patch-target-id",
                &template_path,
                Some("container"),
                "structured patch target_id must be the container blank",
            ));
        }
    }

    let mut dynamic_keys = BTreeSet::new();
    collect_dynamic_keys(&template, &mut dynamic_keys);
    for name in dynamic_keys {
        if parsed_types
            .get(name)
            .is_none_or(|kind| kind != &VariableType::Id)
        {
            issues.push(issue(
                "skeleton-template-dynamic-key",
                &template_path,
                Some(name),
                "dynamic table keys must use an id variable",
            ));
        }
    }
    if issues.len() != initial_issue_count {
        return None;
    }

    let blank_occurrences = blank_counts.values().sum();
    let mut variables: Vec<_> = variables_document
        .variable
        .into_iter()
        .map(|variable| SkeletonVariable {
            name: variable.name,
            variable_type: variable.variable_type,
            required: variable.required,
            meaning: variable.meaning,
        })
        .collect();
    variables.sort_by(|left, right| left.name.cmp(&right.name));
    Some(SkeletonContract {
        kind,
        variables,
        blank_occurrences,
        template,
        template_path,
        variables_path,
    })
}

fn read_regular_utf8(
    absolute: &Path,
    issue_path: &Path,
    read_code: &'static str,
    type_code: &'static str,
    utf8_code: &'static str,
    issues: &mut Vec<AuthoringIssue>,
) -> Option<String> {
    match fs::symlink_metadata(absolute) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => {
            issues.push(issue(
                type_code,
                issue_path,
                None::<String>,
                "catalog document must be a regular file",
            ));
            return None;
        }
        Err(error) => {
            issues.push(issue(
                read_code,
                issue_path,
                None::<String>,
                format!("could not inspect catalog document: {error}"),
            ));
            return None;
        }
    }
    let bytes = match fs::read(absolute) {
        Ok(bytes) => bytes,
        Err(error) => {
            issues.push(issue(
                read_code,
                issue_path,
                None::<String>,
                format!("could not read catalog document: {error}"),
            ));
            return None;
        }
    };
    match String::from_utf8(bytes) {
        Ok(source) => Some(source),
        Err(_) => {
            issues.push(issue(
                utf8_code,
                issue_path,
                None::<String>,
                "catalog document is not valid UTF-8",
            ));
            None
        }
    }
}

fn skeleton_relative(root: &Path, path: &Path) -> PathBuf {
    let prefix = root
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("skeletons"));
    path.strip_prefix(root)
        .map(|relative| prefix.join(relative))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn expected_patch_variables(kind: SkeletonKind) -> Option<&'static [&'static str]> {
    match kind {
        SkeletonKind::NewAlert => Some(&[
            "alert_id",
            "condition",
            "consecutive_hits",
            "container",
            "cooldown_seconds",
            "severity",
            "slice",
        ]),
        SkeletonKind::NewSurface => Some(&[
            "container",
            "media_type",
            "refresh_seconds",
            "renderer",
            "source",
            "surface_id",
            "surface_kind",
        ]),
        _ => None,
    }
}

fn valid_variable_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn template_blank_counts(
    source: &str,
    path: &Path,
    issues: &mut Vec<AuthoringIssue>,
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    let mut cursor = 0;
    while let Some(open_relative) = source[cursor..].find("__") {
        let open = cursor + open_relative;
        let value_start = open + 2;
        let Some(close_relative) = source[value_start..].find("__") else {
            issues.push(issue(
                "skeleton-template-blank-malformed",
                path,
                None::<String>,
                "template contains an unterminated blank",
            ));
            break;
        };
        let close = value_start + close_relative;
        let name = &source[value_start..close];
        if valid_variable_name(name) {
            *counts.entry(name.to_owned()).or_default() += 1;
        } else {
            issues.push(issue(
                "skeleton-template-blank-malformed",
                path,
                Some(name),
                "template blank must match __[a-z][a-z0-9_]*__",
            ));
        }
        cursor = close + 2;
    }
    counts
}

pub(super) fn blank_name(value: &str) -> Option<&str> {
    let name = value.strip_prefix("__")?.strip_suffix("__")?;
    valid_variable_name(name).then_some(name)
}

fn collect_dynamic_keys<'a>(value: &'a toml::Value, names: &mut BTreeSet<&'a str>) {
    match value {
        toml::Value::Array(values) => {
            for value in values {
                collect_dynamic_keys(value, names);
            }
        }
        toml::Value::Table(values) => {
            for (key, value) in values {
                if let Some(name) = blank_name(key) {
                    names.insert(name);
                }
                collect_dynamic_keys(value, names);
            }
        }
        _ => {}
    }
}
