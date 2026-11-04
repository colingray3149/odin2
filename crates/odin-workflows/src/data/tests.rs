use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::bench::Workbench;
use crate::{Failure, FailureKind};

struct Case(Workbench);

impl Deref for Case {
    type Target = Workbench;

    fn deref(&self) -> &Workbench {
        &self.0
    }
}

impl DerefMut for Case {
    fn deref_mut(&mut self) -> &mut Workbench {
        &mut self.0
    }
}

impl Case {
    fn new() -> Self {
        let bench = Workbench::new(&["scratch/in/cmd-1"]);
        Self(bench)
    }

    fn staged(&self, name: &str, body: &[u8]) -> PathBuf {
        let path = self
            .dir
            .path()
            .join("scratch")
            .join("in")
            .join(Workbench::KEY)
            .join(name);
        std::fs::write(&path, body).expect("staged input");
        path
    }

    fn run(&self, id: &str, files: Vec<PathBuf>, args: Value) -> Result<Value, Failure> {
        let workflow = super::WORKFLOWS
            .iter()
            .find(|workflow| workflow.capability == id)
            .expect("listed workflow");
        (workflow.run)(&self.ctx(&[]), &self.call(files), &args)
    }

    fn script(&self) -> String {
        std::fs::read_to_string(self.job().join("q.sql")).expect("query script")
    }

    fn assert_offline(&self) {
        self.recorder.assert_offline();
    }
}

fn failed(result: Result<Value, Failure>) -> (FailureKind, String) {
    let failure = result.expect_err("a failure");
    (failure.kind, failure.cause)
}

#[test]
fn query_files_and_pasted_csv_become_tables() {
    let mut case = Case::new();
    case.fake("duckdb", |fake| {
        fake.stdout("[{\"month\":\"feb\",\"total\":30}]\n")
    });
    let csv = case.staged("sales.csv", b"month,total\nfeb,30\n");
    let parquet = case.staged("artifact-bb.bin", b"PAR1....");
    let out = case
        .run(
            "data.query",
            vec![csv.clone(), parquet.clone()],
            json!({
                "artifacts": ["blake3:aa", "blake3:bb"],
                "tables": {"notes": "month,total\njan,10\n"},
                "sql": "select * from sales order by total desc;"
            }),
        )
        .expect("queried");
    assert_eq!(out["columns"], json!(["month", "total"]));
    assert_eq!(out["rows"], json!([{"month": "feb", "total": 30}]));
    let script = case.script();
    let job = case.job();
    for line in [
        "SET enable_external_access = false;".to_owned(),
        "SET lock_configuration = true;".to_owned(),
        format!(
            "CREATE VIEW \"sales\" AS SELECT * FROM read_csv('{}', auto_detect = true);",
            csv.display()
        ),
        format!(
            "CREATE VIEW \"artifact_bb\" AS SELECT * FROM read_parquet('{}');",
            parquet.display()
        ),
        format!(
            "CREATE VIEW \"notes\" AS SELECT * FROM read_csv('{}', auto_detect = true);",
            job.join("notes.csv").display()
        ),
    ] {
        assert!(script.contains(&line), "{line}\n{script}");
    }
    assert!(
        script.ends_with("select * from sales order by total desc;\n"),
        "{script}"
    );
    assert_eq!(
        case.args_of("duckdb"),
        [
            "-json",
            "-no-stdin",
            "-init",
            "/dev/null",
            ":memory:",
            "-c",
            &format!(".read {}", job.join("q.sql").display())
        ]
    );
    case.assert_offline();
}

#[test]
fn query_reading_outside_the_files_is_named() {
    let mut case = Case::new();
    case.fake("duckdb", |fake| {
        fake.stderr("Permission Error: Cannot access file \"/etc/passwd\"\n")
            .exit(1)
    });
    let (kind, cause) = failed(case.run(
        "data.query",
        vec![],
        json!({"tables": {"t": "a\n1\n"}, "sql": "select * from read_csv('/etc/passwd')"}),
    ));
    assert_eq!(kind, FailureKind::Upstream);
    assert!(cause.contains("outside"), "{cause}");
}

#[test]
fn query_save_as_adds_copy_and_artifact() {
    let mut case = Case::new();
    let job = case.job();
    case.fake("duckdb", |fake| {
        fake.stdout("[{\"a\":1}]\n")
            .file(job.join("quarter.parquet"), "PAR1")
    });
    let out = case
        .run(
            "data.query",
            vec![],
            json!({
                "tables": {"t": "a\n1\n"},
                "sql": "select a from t",
                "save_as": "parquet",
                "name": "Quarter"
            }),
        )
        .expect("queried");
    assert_eq!(out["artifacts"], json!([job.join("quarter.parquet")]));
    assert!(job.join("quarter.parquet").is_file());
    assert!(!job.join("result.parquet").exists());
    assert!(case.script().contains("TO '") && case.script().contains("quarter.parquet"));
}

#[test]
fn edit_keeps_original_and_returns_diff() {
    let mut case = Case::new();
    case.fake("yq", |fake| fake);
    case.fake("diff", |fake| {
        fake.stdout(
            "--- before\n+++ after\n@@ -1 +1 @@\n-  image: nginx:1.27\n+  image: nginx:1.29\n",
        )
        .exit(1)
    });
    let staged = case.staged("compose.yaml", b"web:\n  # pinned\n  image: nginx:1.27\n");
    let expr = ".web.image = \"nginx:1.29\" | .web.note = 'a b'";
    let out = case
        .run(
            "data.edit",
            vec![staged.clone()],
            json!({"intake": "1/1", "expr": expr}),
        )
        .expect("edited");
    let job = case.job();
    assert!(out["diff"]
        .as_str()
        .unwrap()
        .contains("+  image: nginx:1.29"));
    assert_eq!(out["artifacts"], json!([job.join("compose.yaml")]));
    assert_eq!(
        std::fs::read_to_string(job.join("orig")).unwrap(),
        std::fs::read_to_string(&staged).unwrap()
    );
    let yq = case.args_of("yq");
    assert_eq!(
        yq,
        [
            "--security-disable-env-ops",
            "--security-disable-file-ops",
            "-p",
            "yaml",
            "-o",
            "yaml",
            "-i",
            expr,
            &job.join("compose.yaml").display().to_string(),
        ]
    );
    case.assert_offline();
}
