//! The in-crate test bench the document and data families share: fake executables
//! under one scratch tree, run through a runner that keeps every bwrap argv.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use crate::sandbox::{RunFault, RunOutput, RunSpec, Runner};
use crate::testing::{ctx_for, recorded_args, FakeExe, LocalRunner, TEST_BWRAP};
use crate::{Call, Ctx, SCRATCH_ROOT};

/// Runs like `LocalRunner` and keeps every bwrap argv.
#[derive(Default)]
pub struct Recorder(Mutex<Vec<Vec<String>>>);

impl Recorder {
    /// Panics unless something ran and every run was sandboxed without network.
    pub fn assert_offline(&self) {
        let runs = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(!runs.is_empty(), "nothing ran");
        for argv in runs.iter() {
            assert!(argv.contains(&"--unshare-all".to_owned()), "{argv:?}");
            assert!(!argv.contains(&"--share-net".to_owned()), "{argv:?}");
        }
    }
}

impl Runner for Recorder {
    fn run(&self, spec: &RunSpec, on_line: &mut dyn FnMut(&str)) -> Result<RunOutput, RunFault> {
        let argv = spec
            .argv
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(argv);
        LocalRunner.run(spec, on_line)
    }
}

/// One family's scratch tree: fake executables under `bin`, a `Recorder` as the runner,
/// and the call key every test uses.
pub struct Workbench {
    pub dir: tempfile::TempDir,
    pub recorder: Arc<Recorder>,
    fakes: Vec<(String, PathBuf)>,
}

impl Workbench {
    pub const KEY: &'static str = "cmd-1";

    /// A temp tree holding `bin` and each of `folders`.
    pub fn new(folders: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("dir");
        for folder in std::iter::once(&"bin").chain(folders) {
            std::fs::create_dir_all(dir.path().join(folder)).expect("folder");
        }
        Self {
            dir,
            recorder: Arc::default(),
            fakes: Vec::new(),
        }
    }

    /// The call's scratch folder.
    pub fn job(&self) -> PathBuf {
        self.dir.path().join(SCRATCH_ROOT).join(Self::KEY)
    }

    pub fn fake(&mut self, name: &str, build: impl FnOnce(FakeExe) -> FakeExe) -> PathBuf {
        let path = build(FakeExe::new(&self.dir.path().join("bin"), name)).install();
        self.fakes.push((name.to_owned(), path.clone()));
        path
    }

    /// A context declaring every fake and `roots`, run through the recorder.
    pub fn ctx(&self, roots: &[(&str, &Path, bool)]) -> Ctx {
        let exes: Vec<(&str, &Path)> = self
            .fakes
            .iter()
            .map(|(key, path)| (key.as_str(), path.as_path()))
            .collect();
        let config = ctx_for(self.dir.path(), &exes, roots, &[], &[])
            .config
            .as_ref()
            .clone();
        let runner: Arc<dyn Runner> = self.recorder.clone();
        Ctx::new(config, Some(PathBuf::from(TEST_BWRAP)), runner)
    }

    pub fn call(&self, files: Vec<PathBuf>) -> Call {
        Call {
            key: Self::KEY.to_owned(),
            files,
            ..Call::default()
        }
    }

    /// The arguments of the named fake's last run.
    pub fn args_of(&self, name: &str) -> Vec<String> {
        recorded_args(&self.dir.path().join("bin").join(name))
    }
}
