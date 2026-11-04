use std::collections::BTreeMap;

use odin_ledger::Ledger;
use odin_workflows::testing::ctx_for;

use super::*;

struct ReferenceArtifacts {
    root: PathBuf,
    scope: Scope,
}

impl super::super::coding::CodingRoute for ReferenceArtifacts {
    fn nix(
        &self,
        _: &odin_kernel::operation::PreparedEffect,
        _: &Scope,
        _: super::super::coding::NixVerb,
        _: Option<String>,
    ) -> Result<Value, String> {
        panic!("staging must not execute Nix")
    }

    fn propose(
        &self,
        _: &odin_kernel::operation::PreparedEffect,
        _: &Scope,
        _: String,
        _: Option<String>,
    ) -> Result<Value, super::super::coding::ProposalFailure> {
        panic!("staging must not publish code")
    }

    fn artifact_file(&self, scope: &Scope, id: &str) -> Result<(std::fs::File, String), String> {
        if scope != &self.scope {
            return Err("artifact is outside the caller's scope".to_owned());
        }
        let (name, media) = match id {
            "blake3:source" => ("source.md", "text/markdown"),
            "blake3:reference" => (
                "reference.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            _ => return Err("unknown artifact".to_owned()),
        };
        std::fs::File::open(self.root.join(name))
            .map(|file| (file, media.to_owned()))
            .map_err(|error| error.to_string())
    }
}

#[test]
fn workflow_reference_is_last_and_never_replaces_the_source() {
    let dir = tempfile::tempdir().expect("root");
    let runtime = HermesRuntime::open(
        crate::config::HermesSettings::new(
            dir.path().join("hermes"),
            None,
            None,
            vec![],
        )
        .expect("settings"),
        super::super::HermesLedgers {
            conversation: Ledger::open_in_memory().expect("conversation ledger"),
            adapter: Arc::new(parking_lot::Mutex::new(
                Ledger::open_in_memory().expect("adapter ledger"),
            )),
            purchase: Arc::new(std::sync::Mutex::new(
                Ledger::open_in_memory().expect("purchase ledger"),
            )),
        },
        &BTreeMap::new(),
        None,
        8192,
        BTreeMap::new(),
        None,
    )
    .expect("runtime");
    let scope = Scope {
        seat: Some(odin_domain::SeatId::new("seat:writer").expect("seat")),
        ..Scope::default()
    };
    std::fs::write(dir.path().join("source.md"), b"# Original source").expect("source");
    std::fs::write(dir.path().join("reference.docx"), b"reference style bytes").expect("reference");
    runtime.set_coding_route(Arc::new(ReferenceArtifacts {
        root: dir.path().to_path_buf(),
        scope: scope.clone(),
    }));
    let catalog = Catalog::new(&[], ctx_for(dir.path(), &[], &[], &[], &[])).expect("catalog");
    for (key, arguments, expected) in [
        (
            "inline",
            json!({"source":"# Inline source", "reference":"blake3:reference"}),
            vec![b"reference style bytes".as_slice()],
        ),
        (
            "artifact",
            json!({"artifact":"blake3:source", "reference":"blake3:reference"}),
            vec![
                b"# Original source".as_slice(),
                b"reference style bytes".as_slice(),
            ],
        ),
    ] {
        let call = Call {
            key: key.into(),
            ..Call::default()
        };
        let staged = stage_inputs(&runtime, &catalog, &scope, &call, &arguments).expect("stage");
        let bytes: Vec<Vec<u8>> = staged
            .iter()
            .map(|path| std::fs::read(path).expect("staged"))
            .collect();
        assert_eq!(bytes, expected);
        std::fs::write(staged.last().expect("reference"), b"changed working copy")
            .expect("edit copy");
        assert_eq!(
            std::fs::read(dir.path().join("reference.docx")).expect("original"),
            b"reference style bytes"
        );
        catalog.ctx().release(&call).expect("release");
    }
    let call = Call {
        key: "refused".into(),
        ..Call::default()
    };
    assert!(stage_inputs(
        &runtime,
        &catalog,
        &Scope::default(),
        &call,
        &json!({"source":"# Inline", "reference":"blake3:reference"}),
    )
    .is_err());
    catalog.ctx().release(&call).expect("release refused call");
}
