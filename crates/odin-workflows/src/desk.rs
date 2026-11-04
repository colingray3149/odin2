//! The desktop a workflow may use while answering the owner: desk steps and file
//! transfer to and from a desk host. Composed by the authority; absent in tests
//! unless faked.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

/// What one transfer moved.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Transfer {
    pub files: usize,
    pub bytes: u64,
}

pub trait Desk: Send + Sync {
    /// One `odin desk serve` request on `device` (None: the conversation desktop),
    /// carrying the owner's current ask; returns the reply's `did` lines. A stop or
    /// error is Err with its text.
    fn steps(
        &self,
        device: Option<&str>,
        steps: Vec<Value>,
        bound: Duration,
    ) -> Result<Vec<String>, String>;

    /// Copies `files` (relative to `remote_dir` on the desk host) into `local_dir`
    /// on the authority.
    fn pull(
        &self,
        device: Option<&str>,
        remote_dir: &Path,
        files: &[PathBuf],
        local_dir: &Path,
        bound: Duration,
    ) -> Result<Transfer, String>;

    /// Copies `files` (relative to `local_dir`) to the same-named path on the desk host.
    fn push(
        &self,
        device: Option<&str>,
        local_dir: &Path,
        files: &[PathBuf],
        bound: Duration,
    ) -> Result<Transfer, String>;
}
