use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::bench::Workbench;
use crate::{Ctx, Failure, FailureKind};

struct Case {
    bench: Workbench,
    bib: bool,
}

impl Deref for Case {
    type Target = Workbench;

    fn deref(&self) -> &Workbench {
        &self.bench
    }
}

impl DerefMut for Case {
    fn deref_mut(&mut self) -> &mut Workbench {
        &mut self.bench
    }
}

impl Case {
    fn new() -> Self {
        let bench = Workbench::new(&["in", "theme", "scratch"]);
        std::fs::write(
            bench.dir.path().join("theme/theme.typ"),
            "#let accent = red\n",
        )
        .expect("theme");
        Self { bench, bib: false }
    }

    fn staged(&self, name: &str, body: &str) -> PathBuf {
        let path = self.dir.path().join("in").join(name);
        std::fs::write(&path, body).expect("staged input");
        path
    }

    fn with_bib(&mut self) {
        std::fs::create_dir_all(self.dir.path().join("library")).expect("library");
        std::fs::write(self.dir.path().join("library/zotero.bib"), "@book{k,}").expect("bib");
        self.bib = true;
    }

    fn ctx(&self) -> Ctx {
        let theme = self.dir.path().join("theme");
        let library = self.dir.path().join("library");
        let mut roots = vec![("docs-theme", theme.as_path(), false)];
        if self.bib {
            roots.push(("bib", library.as_path(), false));
        }
        self.bench.ctx(&roots)
    }

    fn run(&self, id: &str, files: Vec<PathBuf>, args: Value) -> Result<Value, Failure> {
        let workflow = super::WORKFLOWS
            .iter()
            .find(|workflow| workflow.capability == id)
            .expect("listed workflow");
        (workflow.run)(&self.ctx(), &self.call(files), &args)
    }

    fn assert_offline(&self) {
        self.recorder.assert_offline();
    }

    /// pdfinfo says `pages`; pdftoppm draws page 1.
    fn poppler(&mut self, pages: u32) {
        let job = self.job();
        self.fake("pdfinfo", |fake| {
            fake.stdout(format!("Title: x\nPages:          {pages}\n"))
        });
        self.fake("pdftoppm", |fake| fake.file(job.join("page-1.png"), "png"));
    }
}

fn kind(result: Result<Value, Failure>) -> (FailureKind, String) {
    let failure = result.expect_err("a failure");
    (failure.kind, failure.cause)
}

#[test]
fn render_markdown_runs_pandoc_then_typst() {
    let mut case = Case::new();
    let job = case.job();
    case.fake("pandoc", |fake| fake.file(job.join("main.typ"), "= Lab"));
    case.fake("typst", |fake| {
        fake.file(job.join("lab-3.pdf"), "%PDF")
            .stderr("main.typ:4:1: warning: unknown font family: inter\n")
    });
    case.poppler(6);
    let out = case
        .run(
            "docs.render",
            vec![],
            json!({"source": "# Lab 3\n\nText.", "title": "Lab 3"}),
        )
        .expect("rendered");
    assert_eq!(out["page_count"], 6);
    assert_eq!(out["artifacts"], json!([job.join("lab-3.pdf")]));
    assert_eq!(out["preview"], json!([job.join("page-1.png")]));
    assert_eq!(
        out["warnings"][0],
        "main.typ:4:1: warning: unknown font family: inter"
    );
    let pandoc = case.args_of("pandoc");
    for expected in [
        "--sandbox",
        "--to=typst",
        "look=report",
        "phone=false",
        "title=Lab 3",
    ] {
        assert!(pandoc.contains(&expected.to_owned()), "{pandoc:?}");
    }
    assert!(pandoc.contains(&"--from=markdown-citations+autolink_bare_uris".to_owned()));
    assert_eq!(
        std::fs::read_to_string(job.join("in.md")).unwrap(),
        "# Lab 3\n\nText."
    );
    for template in ["odin.typ", "slides.typ", "pandoc.typst", "theme.typ"] {
        assert!(job.join(template).is_file(), "{template}");
    }
    case.assert_offline();
}

#[test]
fn render_compile_error_names_the_line() {
    let mut case = Case::new();
    case.fake("typst", |fake| {
        fake.stderr("main.typ:12:5: error: unknown variable: foo\n")
            .exit(1)
    });
    let (kind, cause) = kind(case.run("docs.render", vec![], json!({"source": "#let x = foo"})));
    assert_eq!(kind, FailureKind::Arguments);
    assert!(
        cause.contains("main.typ:12:5") && cause.contains("foo"),
        "{cause}"
    );
}

#[test]
fn render_cite_reads_the_library_or_says_none_is_declared() {
    let mut case = Case::new();
    case.fake("pandoc", |fake| fake.exit(0));
    let (kind, cause) = kind(case.run(
        "docs.render",
        vec![],
        json!({"source": "# A", "cite": true}),
    ));
    assert_eq!(kind, FailureKind::Unavailable);
    assert!(
        cause.contains("reference library") && cause.contains("bib"),
        "{cause}"
    );
    case.with_bib();
    let job = case.job();
    case.fake("pandoc", |fake| fake.file(job.join("main.typ"), "="));
    case.fake("typst", |fake| fake.file(job.join("document.pdf"), "%PDF"));
    case.poppler(1);
    case.run(
        "docs.render",
        vec![],
        json!({"source": "# A [@k]", "cite": true}),
    )
    .expect("rendered");
    assert!(job.join("refs.bib").is_file());
    let pandoc = case.args_of("pandoc");
    assert!(
        pandoc.contains(&"bibliography=refs.bib".to_owned()),
        "{pandoc:?}"
    );
    assert!(pandoc.contains(&"--from=markdown+autolink_bare_uris".to_owned()));
}

#[test]
fn convert_unnamed_docx_to_pdf_uses_libreoffice_and_checks_the_output() {
    let mut case = Case::new();
    let job = case.job();
    case.fake("file", |fake| {
        fake.stdout("application/vnd.openxmlformats-officedocument.wordprocessingml.document\n")
    });
    case.fake("soffice", |fake| {
        fake.file(job.join("artifact-ab.pdf"), "%PDF").exit(1)
    });
    case.poppler(5);
    let staged = case.staged("artifact-ab.bin", "PK");
    let out = case
        .run(
            "docs.convert",
            vec![staged],
            json!({"artifact": "blake3:ab", "to": "pdf"}),
        )
        .expect("converted");
    assert_eq!(out["artifacts"], json!([job.join("artifact-ab.pdf")]));
    let soffice = case.args_of("soffice");
    assert!(soffice.contains(&"-env:UserInstallation=file:///tmp/lo-profile".to_owned()));
    assert_eq!(
        soffice.last(),
        Some(&job.join("artifact-ab.docx").display().to_string())
    );
    case.assert_offline();
}

#[test]
fn convert_md_to_docx_uses_pandoc() {
    let mut case = Case::new();
    let job = case.job();
    case.fake("pandoc", |fake| fake.file(job.join("document.docx"), "PK"));
    let out = case
        .run(
            "docs.convert",
            vec![],
            json!({"source": "# Hello", "to": "docx"}),
        )
        .expect("converted");
    assert_eq!(out["artifacts"], json!([job.join("document.docx")]));
    let pandoc = case.args_of("pandoc");
    for expected in ["--sandbox", "--from=markdown", "--to=docx"] {
        assert!(pandoc.contains(&expected.to_owned()), "{pandoc:?}");
    }
}

#[test]
fn preview_office_converts_then_draws() {
    let mut case = Case::new();
    let job = case.job();
    case.fake("soffice", |fake| fake.file(job.join("report.pdf"), "%PDF"));
    case.poppler(5);
    let staged = case.staged("report.docx", "PK");
    let out = case
        .run("docs.preview", vec![staged], json!({"intake": "1/1"}))
        .expect("previewed");
    assert_eq!(out["preview"], json!([job.join("page-1.png")]));
    assert!(out.get("artifacts").is_none());
    case.assert_offline();
}

#[test]
fn ocr_skips_text_by_default_and_truncates_the_inline_text() {
    let mut case = Case::new();
    let job = case.job();
    case.fake("pdfinfo", |fake| fake.stdout("Pages: 12\n"));
    case.fake("ocrmypdf", |fake| {
        fake.file(job.join("scan.pdf"), "%PDF")
            .file(job.join("scan.txt"), "x".repeat(10_000))
    });
    let staged = case.staged("scan.pdf", "%PDF");
    let out = case
        .run(
            "docs.ocr",
            vec![staged.clone()],
            json!({"artifact": "blake3:s"}),
        )
        .expect("ocr");
    assert_eq!(out["text"].as_str().unwrap().len(), 6000);
    assert_eq!(out["text_truncated"], true);
    assert_eq!(
        out["artifacts"],
        json!([job.join("scan.pdf"), job.join("scan.txt")])
    );
    let args = case.args_of("ocrmypdf");
    assert!(args.contains(&"--skip-text".to_owned()), "{args:?}");
    assert!(!args.contains(&"--image-dpi".to_owned()));
    assert_eq!(args[args.len() - 2], staged.display().to_string());
    case.assert_offline();
}
