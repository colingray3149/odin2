//! What a workflow may touch: declared config, the process runner, HTTP,
//! Odin's own facts, and progress.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use serde_json::Value;
use url::Url;

use crate::config::{Root, ToolsConfig};
use crate::desk::Desk;
use crate::http::{HTTP_CONNECT, HTTP_TOTAL};
use crate::sandbox::{RunFault, RunOutput, RunSpec, Runner};
use crate::{Call, Failure};

/// The scratch root every call's working folder lives under.
pub const SCRATCH_ROOT: &str = "scratch";
/// The folder under the scratch root that holds staged inputs.
const INPUTS_FOLDER: &str = "in";

/// Odin's own facts, so a family reuses what Odin already computes instead of probing again.
pub trait OdinFacts: Send + Sync {
    /// Open incidents.
    fn incidents(&self) -> Value;
    /// The cluster's health, as `kube.health.read` reports it.
    fn cluster(&self) -> Value;
    /// The fleet's hosts and whether each answers.
    fn fleet(&self) -> Value;
}

/// The one context the catalog and any pump share. Cloning is cheap.
#[derive(Clone)]
pub struct Ctx {
    pub config: Arc<ToolsConfig>,
    bwrap: Option<PathBuf>,
    runner: Arc<dyn Runner>,
    http: Arc<OnceLock<Result<reqwest::blocking::Client, String>>>,
    odin: Option<Arc<dyn OdinFacts>>,
    desk: Option<Arc<dyn Desk>>,
}

/// A secret value. It prints as `<secret key>`, never its value.
pub struct Secret {
    key: String,
    value: String,
}

impl Secret {
    /// The value, for exactly one header or environment variable.
    pub fn expose(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<secret {}>", self.key)
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<secret {}>", self.key)
    }
}

impl Ctx {
    /// `bwrap` is the authority's bubblewrap (`None` where workflows run no tools).
    pub fn new(config: ToolsConfig, bwrap: Option<PathBuf>, runner: Arc<dyn Runner>) -> Self {
        Self {
            config: Arc::new(config),
            bwrap,
            runner,
            http: Arc::new(OnceLock::new()),
            odin: None,
            desk: None,
        }
    }

    pub fn with_odin(mut self, facts: Arc<dyn OdinFacts>) -> Self {
        self.odin = Some(facts);
        self
    }

    pub fn with_desk(mut self, desk: Arc<dyn Desk>) -> Self {
        self.desk = Some(desk);
        self
    }

    pub fn bwrap(&self) -> Result<&Path, Failure> {
        self.bwrap.as_deref().ok_or_else(|| {
            Failure::unavailable("bubblewrap is not composed on this host, so no tool can run")
        })
    }

    pub fn exe(&self, key: &str) -> Result<&Path, Failure> {
        self.config
            .executables
            .get(key)
            .map(PathBuf::as_path)
            .ok_or_else(|| {
                Failure::unavailable(format!(
                    "the {key} executable is not declared in services.odin.tools.executables"
                ))
            })
    }

    pub fn root(&self, key: &str) -> Result<&Root, Failure> {
        self.config.roots.get(key).ok_or_else(|| {
            Failure::unavailable(format!(
                "the {key} root is not declared in services.odin.tools.roots"
            ))
        })
    }

    pub fn endpoint(&self, key: &str) -> Result<&Url, Failure> {
        self.config.endpoints.get(key).ok_or_else(|| {
            Failure::unavailable(format!(
                "the {key} endpoint is not declared in services.odin.tools.endpoints"
            ))
        })
    }

    /// The declared secret file, checked readable without reading it.
    pub fn secret_path(&self, key: &str) -> Result<&Path, Failure> {
        let path = self.config.secrets.get(key).ok_or_else(|| {
            Failure::unavailable(format!(
                "the {key} secret is not declared in services.odin.tools.secrets"
            ))
        })?;
        if !path.is_file() {
            return Err(unreadable_secret(key));
        }
        Ok(path)
    }

    /// Reads the declared secret file. The value never enters a Failure, a log line or a result.
    pub fn secret(&self, key: &str) -> Result<Secret, Failure> {
        let value =
            std::fs::read_to_string(self.secret_path(key)?).map_err(|_| unreadable_secret(key))?;
        Ok(Secret {
            key: key.to_owned(),
            value: value.trim().to_owned(),
        })
    }

    /// This call's own working folder, `<scratch>/<key>`, created on first use.
    pub fn scratch(&self, call: &Call) -> Result<PathBuf, Failure> {
        self.call_folder(call, "")
    }

    /// Where the glue stages this call's input files, `<scratch>/in/<key>`.
    pub fn inputs(&self, call: &Call) -> Result<PathBuf, Failure> {
        self.call_folder(call, INPUTS_FOLDER)
    }

    /// Removes the call's scratch and input folders once its result is out.
    pub fn release(&self, call: &Call) -> Result<(), String> {
        let root = self.root(SCRATCH_ROOT).map_err(|failure| failure.cause)?;
        let name = call_folder_name(&call.key).map_err(|failure| failure.cause)?;
        for dir in [
            root.path.join(&name),
            root.path.join(INPUTS_FOLDER).join(&name),
        ] {
            match std::fs::remove_dir_all(&dir) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!("could not remove {}: {error}", dir.display()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn call_folder(&self, call: &Call, parent: &str) -> Result<PathBuf, Failure> {
        let root = self.root(SCRATCH_ROOT)?;
        let name = call_folder_name(&call.key)?;
        let dir = root.path.join(parent).join(name);
        std::fs::create_dir_all(&dir).map_err(|error| {
            Failure::unavailable(format!("could not create {}: {error}", dir.display()))
        })?;
        Ok(dir)
    }

    /// Runs one sandboxed process to its end. A nonzero exit is an output, not a Failure.
    pub fn run(&self, spec: &RunSpec) -> Result<RunOutput, Failure> {
        self.run_lines(spec, &mut |_| {})
    }

    /// Like `run`, handing each stdout and stderr line to `on_line` as it arrives.
    pub fn run_lines(
        &self,
        spec: &RunSpec,
        on_line: &mut dyn FnMut(&str),
    ) -> Result<RunOutput, Failure> {
        self.runner.run(spec, on_line).map_err(|fault| match fault {
            RunFault::NotStarted(cause) => {
                Failure::unavailable(format!("{} could not start: {cause}", spec.tool))
            }
            RunFault::Lost(cause) => {
                Failure::uncertain(format!("{} was lost while running: {cause}", spec.tool))
            }
        })
    }

    /// The shared HTTP client (connect `HTTP_CONNECT`, whole exchange `HTTP_TOTAL`).
    pub fn http(&self) -> Result<&reqwest::blocking::Client, Failure> {
        self.http
            .get_or_init(|| {
                reqwest::blocking::Client::builder()
                    .connect_timeout(HTTP_CONNECT)
                    .timeout(HTTP_TOTAL)
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|error| format!("the HTTP client could not be built: {error}"))
            })
            .as_ref()
            .map_err(|cause| Failure::unavailable(cause.clone()))
    }

    /// Sets the running job's progress line (shown by `status {op:"jobs"}`).
    pub fn progress(&self, line: impl Into<String>) {
        odin_domain::progress::report(line);
    }

    /// Odin's own facts: incidents, cluster health, fleet.
    pub fn odin(&self) -> Result<&dyn OdinFacts, Failure> {
        self.odin
            .as_deref()
            .ok_or_else(|| Failure::unavailable("Odin's own facts are not composed on this host"))
    }

    /// The owner's desktop: desk steps and transfers within his current ask.
    pub fn desk(&self) -> Result<&dyn Desk, Failure> {
        self.desk
            .as_deref()
            .ok_or_else(|| Failure::unavailable("the desktop is not composed on this host"))
    }
}

/// The folder name of a call key, in scratch and quarantine alike: letters, digits,
/// `-` and `.`; anything else becomes `_`. A key with nothing to name it by is refused,
/// so no call can resolve to a root's own folder or its parent.
pub(crate) fn call_folder_name(key: &str) -> Result<String, Failure> {
    let name: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.trim_matches(['.', '_']).is_empty() {
        return Err(Failure::arguments(
            "the call has no command id to name its working folder",
        ));
    }
    Ok(name)
}

fn unreadable_secret(key: &str) -> Failure {
    Failure::unavailable(format!(
        "the {key} secret file is unreadable; check the sops secret is rendered"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ctx_for;

    #[test]
    fn a_call_key_names_one_folder_and_a_key_with_nothing_to_name_it_by_is_refused() {
        assert_eq!(call_folder_name("cmd 1/x").unwrap(), "cmd_1_x");
        for bad in ["", ".", "..", "__"] {
            assert!(call_folder_name(bad).is_err(), "{bad:?}");
        }
        let dir = tempfile::tempdir().expect("dir");
        let ctx = ctx_for(dir.path(), &[], &[], &[], &[]);
        let call = Call {
            key: "..".to_owned(),
            ..Call::default()
        };
        assert!(
            ctx.release(&call).is_err(),
            "release never resolves to the scratch parent"
        );
        assert!(dir.path().is_dir());
    }
}
