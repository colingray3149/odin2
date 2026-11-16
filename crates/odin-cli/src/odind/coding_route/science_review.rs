//! Science verdicts: a judge seat's approve or changes on one proposal
//! artifact, kept per proposal digest under `science-verdicts/`. The
//! artifact id is its content digest, so a changed proposal has no verdict.

use std::io::Write;
use std::path::{Path, PathBuf};

use odin_domain::Scope;
use serde_json::{json, Value};

use super::{verify_artifact, DaemonCodingRoute};

fn verdicts_file(state_root: &Path, proposal: &str) -> Result<PathBuf, String> {
    let digest = proposal
        .rsplit(':')
        .next()
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| format!("{proposal} is not an artifact id"))?;
    Ok(state_root
        .join("science-verdicts")
        .join(format!("{digest}.jsonl")))
}

fn append_verdict(state_root: &Path, proposal: &str, verdict: &Value) -> Result<(), String> {
    let path = verdicts_file(state_root, proposal)?;
    let parent = path.parent().ok_or("verdict path has no parent")?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    writeln!(file, "{verdict}").map_err(|error| format!("cannot write {}: {error}", path.display()))
}



impl DaemonCodingRoute {
    pub(super) fn record_science_verdict_on(
        &self,
        scope: &Scope,
        proposal: &str,
        approve: bool,
        notes: &str,
    ) -> Result<Value, String> {
        let reviewer = scope.seat.as_ref().ok_or("this verdict has no seat")?;
        let (mut file, metadata) = self.open_artifact(scope, proposal)?;
        verify_artifact(&mut file, &metadata, proposal)?;
        let at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| error.to_string())?;
        append_verdict(
            &self.state_root,
            proposal,
            &json!({
                "proposal": proposal,
                "approve": approve,
                "notes": notes,
                "reviewer": reviewer.as_str(),
                "project": scope.project.as_ref().map(|project| project.as_str()),
                "at": at,
            }),
        )?;
        Ok(json!({ "proposal": proposal, "approve": approve, "reviewer": reviewer.as_str() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verdict_binds_the_exact_proposal() {
        let root = tempfile::tempdir().expect("tempdir");
        let proposal = format!("blake3:{}", "a".repeat(64));
        let changed = format!("blake3:{}", "b".repeat(64));
        append_verdict(
            root.path(),
            &proposal,
            &json!({"proposal": proposal, "approve": false}),
        )
        .expect("first");
        append_verdict(
            root.path(),
            &proposal,
            &json!({"proposal": proposal, "approve": true}),
        )
        .expect("second");
        let latest = latest_science_verdict(root.path(), &proposal)
            .expect("read")
            .expect("verdict");
        assert_eq!(latest["approve"], true);
        assert_eq!(
            latest_science_verdict(root.path(), &changed).expect("read"),
            None
        );
        assert!(latest_science_verdict(root.path(), "not-an-artifact").is_err());
    }

}
