//! The model catalog commands: AVAILABLE refresh, card prefill and the live
//! gateway re-render. AVAILABLE is the one committed catalog of every model
//! the operator's sign-ins, keys and official clients expose
//! (`registry/models.available.json`), written verbatim from
//! `omp models --json` with the deployed gateway's own echo filtered out and
//! the Claude Code / agy official-client lists appended in the same shape.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::Duration;

use clap::{Args, Subcommand};
use serde_json::{json, Value};

use odin_registry::MODELS_AVAILABLE;

use crate::RunStatus;

use super::{resolve_odin_root, run_git, DEFAULT_RENDERER};

/// A model-list command must answer within this bound or the refresh refuses.
const LIST_BOUND: Duration = Duration::from_secs(120);
const LIST_OUTPUT_LIMIT: usize = 16 << 20;

/// The gateway unit a render restarts.
const GATEWAY_UNIT: &str = "litellm.service";

/// Where the committed AVAILABLE document lives in the checkout.
fn available_path(root: &Path) -> PathBuf {
    root.join("registry").join(MODELS_AVAILABLE)
}

#[derive(Debug, Args)]
pub(crate) struct ModelsArgs {
    #[command(subcommand)]
    pub(crate) command: Option<ModelsCommand>,
    /// Emit compact redacted JSON (without a subcommand).
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ModelsCommand {
    /// Refresh the committed AVAILABLE catalog from the authority's omp, agy
    /// and Claude Code lists, then commit it. Run on the authority host with
    /// the sops-rendered provider environment sourced.
    Refresh(ModelsRefreshArgs),
    /// Write a prefilled model card from AVAILABLE into registry/models/ for
    /// tuning.
    Card(ModelsCardArgs),
    /// Re-render the live gateway config from the registry and AVAILABLE,
    /// then restart the gateway unit.
    Render(ModelsRenderArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ModelsRefreshArgs {
    /// The pinned OMP executable to list models with.
    #[arg(long, value_name = "PATH", default_value = "omp")]
    omp: String,
    /// The agy CLI to list Antigravity models with; not on PATH or unsigned
    /// skips the antigravity entries with a note.
    #[arg(long, value_name = "PATH", default_value = "agy")]
    agy: String,
    /// The Odin checkout whose origin main the refresh commits to; its own
    /// HEAD and working tree are never touched.
    #[arg(long, value_name = "PATH")]
    root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct ModelsCardArgs {
    /// The AVAILABLE selector to prefill from, provider/model.
    selector: String,
    /// The Odin checkout holding the registry.
    #[arg(long, value_name = "PATH")]
    root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct ModelsRenderArgs {
    /// Nix-rendered deploy facts for the gateway renderer; defaults to
    /// ~/.config/odin/gateway-facts.json.
    #[arg(long, value_name = "FILE")]
    facts: Option<PathBuf>,
    /// The state directory the renderer writes litellm.yaml and
    /// omp-models.yml into; defaults to ~/.local/state/odin-gateway.
    #[arg(long, value_name = "DIR")]
    out: Option<PathBuf>,
    /// The registry directory to render from; defaults to the checkout's.
    #[arg(long, value_name = "DIR")]
    registry: Option<PathBuf>,
    /// The AVAILABLE document to render from; defaults to the checkout's.
    #[arg(long, value_name = "FILE")]
    available: Option<PathBuf>,
    /// The gateway renderer executable.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_RENDERER)]
    renderer: String,
    /// Render only; skip the gateway unit restart.
    #[arg(long)]
    no_restart: bool,
    /// The Odin checkout the defaults resolve against.
    #[arg(long, value_name = "PATH")]
    root: Option<PathBuf>,
}

pub(crate) fn models_command(
    command: ModelsCommand,
    output: &mut impl Write,
) -> Result<RunStatus, String> {
    match command {
        ModelsCommand::Refresh(arguments) => refresh(arguments, output),
        ModelsCommand::Card(arguments) => card(arguments, output),
        ModelsCommand::Render(arguments) => render(arguments, output),
    }
}

/// Run one model-list command under a bound, returning its stdout. `env`
/// names additional exports the child needs.
fn capture(command: &str, arguments: &[&str], env: &[(String, String)]) -> Result<String, String> {
    let output = odin_process::run_bounded(
        ProcessCommand::new(command).args(arguments).envs(
            env.iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        ),
        None,
        odin_process::ChildBounds {
            timeout: LIST_BOUND,
            max_stdout_bytes: LIST_OUTPUT_LIMIT,
            max_stderr_bytes: LIST_OUTPUT_LIMIT,
        },
    )
    .map_err(|error| format!("could not run {command}: {error}"))?;
    let status = output
        .status
        .ok_or_else(|| format!("{command} did not answer within {LIST_BOUND:?}"))?;
    if !status.success() {
        return Err(output
            .stderr_text()
            .lines()
            .find(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{command} exited {status}")));
    }
    if output.stdout.truncated() {
        return Err(format!(
            "{command} printed more than {LIST_OUTPUT_LIMIT} bytes"
        ));
    }
    Ok(output.stdout_text())
}

/// Claude Code has no models-list CLI; the servable set is declared here,
/// verified against the installed client.
fn declared_claude_code_entries() -> Vec<Value> {
    vec![json!({
        "provider": "claude-code",
        "kind": "chat",
        "id": "claude-opus-5-5",
        "selector": "claude-code/claude-opus-5-5",
        "name": "Claude Opus 5.5",
        "contextWindow": null,
        "maxTokens": null,
        "reasoning": true,
        "thinking": null,
        "input": ["text", "image"],
        "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
        "pricingStatus": "unknown",
    })]
}

/// Parse `agy models` text into AVAILABLE entries: one model id per line,
/// taking the first whitespace token of each line. Unsigned or failed runs
/// contribute nothing; the parser tightens against a captured signed-in
/// listing.
fn agy_entries(text: &str) -> Vec<Value> {
    text.lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|token| {
            token.len() >= 2
                && token.len() <= 128
                && token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
        })
        .map(|id| {
            json!({
                "provider": "agy",
                "kind": "chat",
                "id": id,
                "selector": format!("agy/{id}"),
                "name": null,
                "contextWindow": null,
                "maxTokens": null,
                "reasoning": true,
                "thinking": null,
                "input": null,
                "cost": null,
                "pricingStatus": "unknown",
            })
        })
        .collect()
}

fn refresh(arguments: ModelsRefreshArgs, output: &mut impl Write) -> Result<RunStatus, String> {
    let root = arguments.root.clone().map_or_else(resolve_odin_root, Ok)?;
    // omp's google provider reads GEMINI_API_KEY; the fleet's sops-rendered
    // key is GOOGLE_AI_STUDIO_KEY, so the missing name is re-exported.
    let mut env = Vec::new();
    if let Some(key) = std::env::var_os("GOOGLE_AI_STUDIO_KEY").filter(|key| !key.is_empty()) {
        if std::env::var_os("GEMINI_API_KEY")
            .map(|value| value.is_empty())
            .unwrap_or(true)
        {
            env.push((
                "GEMINI_API_KEY".to_owned(),
                key.to_string_lossy().into_owned(),
            ));
        }
    }
    let raw = capture(&arguments.omp, &["models", "--json"], &env)?;
    let parsed: Value =
        serde_json::from_str(&raw).map_err(|error| format!("omp models --json: {error}"))?;
    let models = parsed
        .get("models")
        .and_then(Value::as_array)
        .ok_or_else(|| "omp models --json returned no models array".to_owned())?
        .clone();
    // The deployed gateway echoes its own lanes back; keep AVAILABLE
    // non-circular by dropping them. Antigravity uses only the official agy
    // client, never OMP's banned OAuth route.
    let mut entries: Vec<Value> = models
        .into_iter()
        .filter(|entry| {
            entry.get("provider").and_then(Value::as_str) != Some("gateway")
                && entry.get("provider").and_then(Value::as_str) != Some("google-antigravity")
        })
        .collect();
    entries.extend(declared_claude_code_entries());
    let mut notes = Vec::new();
    match capture(&arguments.agy, &["models"], &[]) {
        Ok(text) => {
            let found = agy_entries(&text);
            notes.push(format!("agy models listed {}", found.len()));
            entries.extend(found);
        }
        Err(error) => notes.push(format!("agy models skipped: {error}")),
    }
    // The commit lands on origin/main through its own detached worktree,
    // never on the checkout's HEAD; cards and the previous AVAILABLE are
    // read from that same origin/main tree.
    let worktree = MainWorktree::add(&root)?;
    let path = available_path(worktree.path());
    keep_failed_providers(&previous_entries(&path)?, &mut entries, &mut notes);
    keep_carded_models(
        &worktree.path().join("registry"),
        &path,
        &mut entries,
        &mut notes,
    )?;
    entries.sort_by(|left, right| {
        let left_key = (
            left.get("provider").and_then(Value::as_str).unwrap_or(""),
            left.get("id").and_then(Value::as_str).unwrap_or(""),
        );
        let right_key = (
            right.get("provider").and_then(Value::as_str).unwrap_or(""),
            right.get("id").and_then(Value::as_str).unwrap_or(""),
        );
        left_key.cmp(&right_key)
    });
    let generated = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| format!("could not format the refresh time: {error}"))?;
    let document = json!({
        "version": 1,
        "generated": generated,
        "models": entries,
    });
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("could not encode AVAILABLE: {error}"))?;
    bytes.push(b'\n');
    std::fs::write(&path, &bytes)
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    let commit = worktree.commit_and_push(&path)?;
    for note in notes {
        writeln!(output, "{note}").map_err(|error| format!("could not write output: {error}"))?;
    }
    writeln!(output, "{MODELS_AVAILABLE} {commit}")
        .map_err(|error| format!("could not write output: {error}"))?;
    Ok(RunStatus::Success)
}

/// The previous AVAILABLE's models; none when the file does not exist yet.
fn previous_entries(previous_path: &Path) -> Result<Vec<Value>, String> {
    match std::fs::read(previous_path) {
        Ok(bytes) => Ok(serde_json::from_slice::<Value>(&bytes)
            .map_err(|error| format!("{} is invalid: {error}", previous_path.display()))?
            .get("models")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!(
            "could not read {}: {error}",
            previous_path.display()
        )),
    }
}

/// A provider with no model in the new listing failed to list (a refresh
/// that runs while the gateway restarts sees every listing fail): its previous
/// entries are kept whole, so AVAILABLE does not shrink until the next refresh.
fn keep_failed_providers(previous: &[Value], entries: &mut Vec<Value>, notes: &mut Vec<String>) {
    let provider = |entry: &Value| {
        entry
            .get("selector")
            .and_then(Value::as_str)
            .and_then(|selector| selector.split_once('/'))
            .map(|(provider, _)| provider.to_owned())
    };
    let listed: BTreeSet<String> = entries.iter().filter_map(provider).collect();
    let mut kept: BTreeMap<String, usize> = BTreeMap::new();
    for entry in previous {
        if let Some(name) = provider(entry).filter(|name| !listed.contains(name)) {
            entries.push(entry.clone());
            *kept.entry(name).or_default() += 1;
        }
    }
    for (name, count) in kept {
        notes.push(format!(
            "provider {name}'s listing failed; its {count} previous AVAILABLE entries are kept"
        ));
    }
}

/// A refresh never drops a model an enabled gateway card serves: when the
/// new listing lacks it, the previous AVAILABLE entry is kept and the note
/// names the provider whose listing failed. A card model in neither the
/// listing nor the previous AVAILABLE refuses the refresh — writing it
/// would drop a lane the registry serves and odind would refuse its config
/// (as the credential-less refresh did on 2026-10-27 22:58).
fn keep_carded_models(
    registry: &Path,
    previous_path: &Path,
    entries: &mut Vec<Value>,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    let objects = super::load_registry_objects(registry)?;
    let previous = previous_entries(previous_path)?;
    let selector = |entry: &Value| {
        entry
            .get("selector")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    for object in &objects {
        let odin_registry::ObjectConfig::Model(card) = &object.config else {
            continue;
        };
        if !card.enabled
            || card.route != odin_registry::GATEWAY_ROUTE
            || card.account.as_deref() == Some(odin_registry::LOCAL_ACCOUNT)
        {
            continue;
        }
        let Some(served) = card.served.as_deref() else {
            continue;
        };
        if entries
            .iter()
            .any(|entry| selector(entry).as_deref() == Some(served))
        {
            continue;
        }
        let provider = served
            .split_once('/')
            .map_or(served, |(provider, _)| provider);
        match previous
            .iter()
            .find(|entry| selector(entry).as_deref() == Some(served))
        {
            Some(entry) => {
                entries.push(entry.clone());
                notes.push(format!(
                    "card {} served {served} kept from the previous AVAILABLE: provider \
                     {provider}'s listing failed",
                    card.id
                ));
            }
            None => {
                return Err(format!(
                    "card {} serves {served}, which the new listing omits and the previous \
                     AVAILABLE never carried: provider {provider}'s listing failed and there is \
                     no entry to keep; refusing to write an AVAILABLE that drops it",
                    card.id
                ));
            }
        }
    }
    Ok(())
}

/// A detached worktree at a freshly fetched origin/main, removed on drop.
struct MainWorktree {
    root: PathBuf,
    directory: tempfile::TempDir,
}

impl MainWorktree {
    fn add(root: &Path) -> Result<Self, String> {
        Self::remove_stale(root);
        git(root, &["fetch", "-q", "origin", "main"])?;
        let directory = tempfile::Builder::new()
            .prefix("odin-models-refresh.")
            .tempdir()
            .map_err(|error| format!("could not create the refresh worktree: {error}"))?;
        let path = directory.path().to_string_lossy().into_owned();
        git(
            root,
            &["worktree", "add", "-q", "--detach", &path, "origin/main"],
        )?;
        Ok(Self {
            root: root.to_path_buf(),
            directory,
        })
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    /// Remove refresh worktrees an earlier run left behind. Drop never runs
    /// when the unit is stopped mid-refresh (a deploy's SIGTERM), so each one
    /// stayed registered; refreshes never overlap, so any found here is stale.
    fn remove_stale(root: &Path) {
        let Ok(list) = git(root, &["worktree", "list", "--porcelain"]) else {
            return;
        };
        let temp = std::env::temp_dir();
        for path in list
            .lines()
            .filter_map(|line| line.strip_prefix("worktree "))
        {
            let candidate = Path::new(path);
            let stale = candidate.parent() == Some(temp.as_path())
                && candidate
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("odin-models-refresh."));
            if stale {
                let _ = git(root, &["worktree", "remove", "--force", path]);
            }
        }
        let _ = git(root, &["worktree", "prune"]);
    }

    /// Commit AVAILABLE and push it to origin main, rebased onto its tip;
    /// an unchanged listing commits nothing. A push that loses the race
    /// with another writer landing on main between the rebase and the push
    /// is rebased and retried once; a second loss or any other failure
    /// names git's own error.
    fn commit_and_push(&self, path: &Path) -> Result<String, String> {
        let tree = self.path();
        let listing = std::fs::read(path)
            .map_err(|error| format!("{} is unreadable: {error}", path.display()))?;
        if !Self::commit(tree, path)? {
            return Ok("unchanged".to_owned());
        }
        if !Self::onto_main(tree, path, &listing)? {
            return Ok("unchanged".to_owned());
        }
        match git(tree, &["push", "-q", "origin", "HEAD:main"]) {
            Ok(_) => (),
            Err(error) if lost_push_race(&error) => {
                if !Self::onto_main(tree, path, &listing)? {
                    return Ok("unchanged".to_owned());
                }
                git(tree, &["push", "-q", "origin", "HEAD:main"]).map_err(|error| {
                    format!("push after rebasing the concurrent update failed: {error}")
                })?;
            }
            Err(error) => return Err(error),
        }
        Ok(format!(
            "committed and pushed {}",
            git(tree, &["rev-parse", "--short", "HEAD"])?.trim()
        ))
    }
}

impl MainWorktree {
    /// Stages AVAILABLE and commits it; false when nothing changed.
    fn commit(tree: &Path, path: &Path) -> Result<bool, String> {
        git(tree, &["add", "--", &path.to_string_lossy()])?;
        if git(tree, &["diff", "--cached", "--quiet"]).is_ok() {
            return Ok(false);
        }
        git(
            tree,
            &[
                "commit",
                "-q",
                "-m",
                "models: refresh the AVAILABLE catalog",
            ],
        )?;
        Ok(true)
    }

    /// Rebases the refresh onto origin/main. When another refresh rewrote
    /// AVAILABLE meanwhile, this capture is restated on top of it instead;
    /// false when the result equals main.
    fn onto_main(tree: &Path, path: &Path, listing: &[u8]) -> Result<bool, String> {
        if git(tree, &["pull", "-q", "--rebase", "origin", "main"]).is_ok() {
            return Ok(true);
        }
        let _ = git(tree, &["rebase", "--abort"]);
        git(tree, &["reset", "-q", "--hard", "origin/main"])?;
        std::fs::write(path, listing)
            .map_err(|error| format!("{} is unwritable: {error}", path.display()))?;
        Self::commit(tree, path)
    }
}

/// A moved remote tip is retryable, including a race after Git advertised it.
/// Authentication, hook and transport failures are returned unchanged.
fn lost_push_race(error: &str) -> bool {
    error.contains("non-fast-forward")
        || error.contains("fetch first")
        || error.contains("incorrect old value provided")
        || (error.contains("cannot lock ref 'refs/heads/main': is at ")
            && error.contains(" but expected "))
}

impl Drop for MainWorktree {
    fn drop(&mut self) {
        let path = self.path().to_string_lossy().into_owned();
        let _ = git(&self.root, &["worktree", "remove", "--force", &path]);
    }
}

/// Run git in `directory`; a failure names the command and git's stderr.
fn git(directory: &Path, arguments: &[&str]) -> Result<String, String> {
    run_git(directory, arguments).map(|stdout| String::from_utf8_lossy(&stdout).into_owned())
}

/// Escape one TOML basic-string value.
fn toml_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn card(arguments: ModelsCardArgs, output: &mut impl Write) -> Result<RunStatus, String> {
    let root = arguments.root.clone().map_or_else(resolve_odin_root, Ok)?;
    let path = available_path(&root);
    let bytes = std::fs::read(&path).map_err(|error| {
        format!(
            "could not read {}: {error}; run `odin models refresh` first",
            path.display()
        )
    })?;
    let document: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{} is invalid: {error}", path.display()))?;
    let models = document
        .get("models")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{} has no models array", path.display()))?;
    let entry = models
        .iter()
        .find(|entry| {
            entry.get("selector").and_then(Value::as_str) == Some(arguments.selector.as_str())
                || entry.get("id").and_then(Value::as_str) == Some(arguments.selector.as_str())
        })
        .ok_or_else(|| format!("{} is not in {}", arguments.selector, path.display()))?;
    let selector = entry
        .get("selector")
        .and_then(Value::as_str)
        .unwrap_or(&arguments.selector);
    let lane = entry
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{selector} carries no model id"))?;
    let provider = entry
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("an unknown provider");
    let name = entry
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(selector);
    let directory = root.join("registry").join("models").join(lane);
    if directory.exists() {
        return Err(format!("model card {} already exists", directory.display()));
    }
    let mut lines = Vec::new();
    lines.push("schema = \"odin.registry.v1\"".to_owned());
    lines.push("kind = \"model\"".to_owned());
    lines.push("enabled = true".to_owned());
    lines.push(format!(
        "description = \"{}\"",
        toml_text(&format!("{name} on {provider}."))
    ));
    lines.push("# The card id; everything else names the bare lane (this folder).".to_owned());
    lines.push(format!("id = \"gateway/{}\"", toml_text(lane)));
    lines.push("# Upstream provider/model exactly as AVAILABLE lists it.".to_owned());
    lines.push(format!("served = \"{}\"", toml_text(selector)));
    lines.push("# Tune: frontier, everyday or fast-cheap.".to_owned());
    lines.push("tier = \"everyday\"".to_owned());
    lines.push("# Tune: the account pin holding this card's credentials.".to_owned());
    lines.push("# account = \"\"".to_owned());
    lines.push("# Tune: one line naming when this card is the right pick.".to_owned());
    lines.push(format!(
        "strengths = \"{}\"",
        toml_text("Tune: name when this card is the right pick.")
    ));
    // Context window stays in AVAILABLE. A card `[window]` is an optional
    // policy override or an official-client fact, never a copied catalog value.
    let max_output = entry.get("maxTokens").and_then(Value::as_u64);
    if let Some(max_output) = max_output {
        lines.push(String::new());
        lines.push("[window]".to_owned());
        lines.push(format!("max_output_tokens = {max_output}"));
    }
    let levels = entry
        .get("thinking")
        .and_then(Value::as_array)
        .map(|levels| {
            levels
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !levels.is_empty() {
        lines.push(String::new());
        lines.push("[thinking]".to_owned());
        let quoted: Vec<String> = levels.iter().map(|level| format!("\"{level}\"")).collect();
        lines.push(format!("levels = [{}]", quoted.join(", ")));
        lines.push("# Tune: default = \"\"".to_owned());
    }
    if entry
        .get("input")
        .and_then(Value::as_array)
        .is_some_and(|inputs| inputs.iter().any(|input| input.as_str() == Some("image")))
    {
        lines.push(String::new());
        lines.push("image = true".to_owned());
    }
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("could not create {}: {error}", directory.display()))?;
    let card_path = directory.join("model.toml");
    std::fs::write(&card_path, format!("{}\n", lines.join("\n")))
        .map_err(|error| format!("could not write {}: {error}", card_path.display()))?;
    writeln!(
        output,
        "prefilled {} — tune id, tier, account, strengths and seats, then author-stage",
        card_path.display()
    )
    .map_err(|error| format!("could not write output: {error}"))?;
    Ok(RunStatus::Success)
}

fn home_path(relative: &str) -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|home| home.join(relative))
        .ok_or_else(|| "HOME is unavailable for the default gateway paths".to_owned())
}

fn render(arguments: ModelsRenderArgs, output: &mut impl Write) -> Result<RunStatus, String> {
    let root = arguments.root.clone().map_or_else(resolve_odin_root, Ok)?;
    let registry = arguments.registry.unwrap_or_else(|| root.join("registry"));
    let available = arguments.available.unwrap_or_else(|| available_path(&root));
    let facts = match arguments.facts {
        Some(facts) => facts,
        None => home_path(".config/odin/gateway-facts.json")?,
    };
    let out = match arguments.out {
        Some(out) => out,
        None => home_path(".local/state/odin-gateway")?,
    };
    render_gateway(
        &registry,
        &available,
        &facts,
        &out,
        &arguments.renderer,
        !arguments.no_restart,
        output,
    )
}

/// Re-render the live gateway config from the registry and AVAILABLE, then
/// restart the gateway unit. Called by `odin models render` and by every
/// registry publication configured with a gateway section.
pub(crate) fn render_gateway(
    registry: &Path,
    available: &Path,
    facts: &Path,
    out: &Path,
    renderer: &str,
    restart: bool,
    output: &mut impl Write,
) -> Result<RunStatus, String> {
    let config = out.join("litellm.yaml");
    let before = std::fs::read(&config).ok();
    // The renderer reads one model.toml per card directory under registry/models.
    let status = ProcessCommand::new(renderer)
        .arg("--registry")
        .arg(registry.join("models"))
        .arg("--available")
        .arg(available)
        .arg("--facts")
        .arg(facts)
        .arg("--out")
        .arg(out)
        .status()
        .map_err(|error| format!("could not run {renderer}: {error}"))?;
    if !status.success() {
        return Err(format!("{renderer} exited {status}"));
    }
    // A publish that left the gateway's config as it was (a routine, a seat edit) restarts nothing:
    // a restart would cut every in-flight model call.
    let restart = restart && std::fs::read(&config).ok() != before;
    if restart {
        let status = ProcessCommand::new("systemctl")
            .args(["--user", "restart", GATEWAY_UNIT])
            .status()
            .map_err(|error| format!("could not restart {GATEWAY_UNIT}: {error}"))?;
        if !status.success() {
            return Err(format!(
                "systemctl --user restart {GATEWAY_UNIT} exited {status}"
            ));
        }
    }
    let tail = if restart {
        format!(" and restarted {GATEWAY_UNIT}")
    } else {
        String::new()
    };
    writeln!(output, "rendered {}{}", out.display(), tail)
        .map_err(|error| format!("could not write output: {error}"))?;
    Ok(RunStatus::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::git;

    #[test]
    fn a_render_reads_the_cards_and_an_unchanged_config_restarts_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).expect("out");
        // The fake renderer records the cards directory it was given and writes the same config.
        let renderer = dir.path().join("render");
        std::fs::write(
            &renderer,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do case $1 in --registry) CARDS=$2;; --out) OUT=$2;; esac; \
             shift; done\necho \"$CARDS\" > \"$OUT/cards\"\nprintf 'model_list: []\\n' > \"$OUT/litellm.yaml\"\n",
        )
        .expect("renderer");
        std::fs::set_permissions(&renderer, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::write(out.join("litellm.yaml"), "model_list: []\n").expect("live config");
        let registry = dir.path().join("registry");
        let mut said = Vec::new();
        render_gateway(
            &registry,
            &registry.join(MODELS_AVAILABLE),
            &dir.path().join("facts.json"),
            &out,
            renderer.to_str().expect("utf-8"),
            true,
            &mut said,
        )
        .expect("render");
        let cards = std::fs::read_to_string(out.join("cards")).expect("cards argument");
        assert_eq!(cards.trim(), registry.join("models").display().to_string());
        let said = String::from_utf8(said).expect("utf-8");
        assert!(!said.contains("restarted"), "{said}");
    }

    /// A fixture registry holding one enabled, seat-serving gateway card.
    fn carded_registry(root: &Path) -> PathBuf {
        let registry = root.join("registry");
        for kind in odin_registry::RegistryKind::ALL {
            std::fs::create_dir_all(registry.join(kind.directory())).expect("registry kind");
        }
        let card = registry.join("models").join("goat-flash");
        std::fs::create_dir_all(&card).expect("create card directory");
        std::fs::write(
            card.join("model.toml"),
            "schema = \"odin.registry.v1\"\n\
             kind = \"model\"\n\
             enabled = true\n\
             description = \"Goat Flash on the Command Code account\"\n\
             id = \"gateway/goat-flash\"\n\
             served = \"commandcode/goat-flash\"\n\
             tier = \"everyday\"\n\
             order = 1\n\
             account = \"commandcode\"\n\
             strengths = \"Cheap and quick\"\n\
             seats = true\n",
        )
        .expect("write card");
        registry
    }

    fn available(root: &Path, selectors: &[&str]) -> PathBuf {
        let path = root.join(MODELS_AVAILABLE);
        let models: Vec<Value> = selectors
            .iter()
            .map(|selector| json!({"selector": selector}))
            .collect();
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({"version": 1, "generated": "t", "models": models}))
                .expect("encode fixture AVAILABLE"),
        )
        .expect("write fixture AVAILABLE");
        path
    }

    #[test]
    fn a_card_model_no_listing_carries_refuses_the_available_write() {
        let fixture = tempfile::TempDir::new().expect("temporary directory");
        let registry = carded_registry(fixture.path());
        let previous = available(fixture.path(), &["deepseek/deepseek-chat"]);
        let mut entries = vec![json!({"selector": "deepseek/deepseek-chat"})];
        let mut notes = Vec::new();
        let error = keep_carded_models(&registry, &previous, &mut entries, &mut notes)
            .expect_err("a card model in neither listing refuses the refresh");
        assert!(
            error.contains("gateway/goat-flash") && error.contains("commandcode"),
            "the refusal names the card and the provider whose listing failed: {error}"
        );
        assert!(notes.is_empty(), "a refusal is not a note: {notes:?}");
    }

    /// A bare origin seeded with one commit, a root clone whose worktrees
    /// the refresh uses, and a competitor clone holding one commit ready
    /// to push into the race.
    fn raced_origin(root: &Path) -> (PathBuf, PathBuf) {
        let origin = root.join("origin.git");
        std::fs::create_dir_all(&origin).expect("create origin directory");
        git(&origin, &["init", "-q", "--bare", "-b", "main"]);
        let repo = root.join("repo");
        git(root, &["clone", "-q", "origin.git", "repo"]);
        let identity = |repo: &Path| {
            for (key, value) in [
                ("user.name", "Odin Test"),
                ("user.email", "odin-test@example.invalid"),
                ("commit.gpgsign", "false"),
            ] {
                git(repo, &["config", key, value]);
            }
        };
        identity(&repo);
        std::fs::write(repo.join("seed"), "seed\n").expect("write seed");
        git(&repo, &["add", "seed"]);
        git(&repo, &["commit", "-q", "-m", "seed"]);
        git(&repo, &["push", "-q", "origin", "HEAD:main"]);
        let competitor = root.join("competitor");
        git(root, &["clone", "-q", "origin.git", "competitor"]);
        identity(&competitor);
        git(
            &competitor,
            &["commit", "--allow-empty", "-q", "-m", "competitor lands"],
        );
        (repo, competitor)
    }

    /// Install a pre-push hook on the root clone: every invocation is
    /// logged, and the first also pushes the competitor's waiting commit
    /// to origin before our own push is sent.
    fn racing_hook(root: &Path, repo: &Path, competitor: &Path) {
        let hooks = root.join("hooks");
        std::fs::create_dir_all(&hooks).expect("create hooks directory");
        let hook = hooks.join("pre-push");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\n\
                 # pre-push exports GIT_DIR; drop it so the competitor push\n\
                 # is a real second writer, not a push of this repo.\n\
                 unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE\n\
                 printf 'invoked\\n' >> '{log}'\n\
                 if [ ! -f '{fired}' ]; then\n\
                 \x20 : > '{fired}'\n\
                 \x20 git -C '{competitor}' push -q origin HEAD:main\n\
                 fi\n\
                 exit 0\n",
                log = root.join("hook.log").display(),
                fired = root.join("hook.fired").display(),
                competitor = competitor.display(),
            ),
        )
        .expect("write pre-push hook");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))
            .expect("make the hook executable");
        git(
            repo,
            &["config", "core.hooksPath", &hooks.to_string_lossy()],
        );
    }

    fn hook_invocations(root: &Path) -> usize {
        std::fs::read_to_string(root.join("hook.log"))
            .map(|log| log.lines().count())
            .unwrap_or(0)
    }

    fn committed_available(worktree: &MainWorktree) -> PathBuf {
        let path = available_path(worktree.path());
        std::fs::create_dir_all(path.parent().expect("registry directory"))
            .expect("create registry directory");
        std::fs::write(&path, b"{\"version\":1,\"models\":[]}\n").expect("write AVAILABLE");
        path
    }

    #[test]
    fn a_worktree_left_by_a_killed_refresh_is_removed_by_the_next() {
        let fixture = tempfile::TempDir::new().expect("temporary directory");
        let (repo, _competitor) = raced_origin(fixture.path());
        let killed = MainWorktree::add(&repo).expect("add the first refresh worktree");
        let left = killed.path().to_path_buf();
        std::mem::forget(killed);
        let next = MainWorktree::add(&repo).expect("add the next refresh worktree");
        let listed = git(&repo, &["worktree", "list", "--porcelain"]);
        assert!(!left.exists(), "the stale worktree is gone");
        assert!(
            !listed.contains(&*left.to_string_lossy()),
            "the stale worktree is unregistered: {listed}"
        );
        assert!(listed.contains(&*next.path().to_string_lossy()));
    }

    #[test]
    fn a_push_that_loses_the_race_is_rebased_and_retried_once() {
        let fixture = tempfile::TempDir::new().expect("temporary directory");
        let root = fixture.path();
        let (repo, competitor) = raced_origin(root);
        racing_hook(root, &repo, &competitor);
        let worktree = MainWorktree::add(&repo).expect("add the refresh worktree");
        let path = committed_available(&worktree);
        let pushed = worktree
            .commit_and_push(&path)
            .expect("the concurrent push is recovered from");
        assert!(
            pushed.starts_with("committed and pushed"),
            "the retry landed the refresh: {pushed}"
        );
        git(&repo, &["fetch", "-q", "origin"]);
        let log = git(&repo, &["log", "--format=%s", "origin/main"]);
        assert_eq!(
            log.lines().next(),
            Some("models: refresh the AVAILABLE catalog"),
            "the refresh is rebased on top of the competitor: {log}"
        );
        assert!(
            log.contains("competitor lands"),
            "the winning concurrent push is kept: {log}"
        );
        assert!(
            root.join("hook.fired").exists(),
            "the race actually happened before our first push"
        );
        assert_eq!(
            hook_invocations(root),
            2,
            "the first push was rejected, exactly one retry pushed"
        );
    }
}
