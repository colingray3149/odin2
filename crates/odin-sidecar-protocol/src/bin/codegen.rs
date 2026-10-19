//! Generates the authority wire v2 schema, Rust/TypeScript codecs, and vectors.

#![forbid(unsafe_code)]

#[path = "codegen/json.rs"]
mod json;
#[path = "codegen/model.rs"]
mod model;
#[path = "codegen/render_rust.rs"]
mod render_rust;
#[path = "codegen/render_ts.rs"]
mod render_ts;
#[path = "codegen/schema.rs"]
mod schema;
#[path = "codegen/validate.rs"]
mod validate;

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use crate::json::{json, json_file, json_text, JsonMap, JsonValue, ToJson};
use crate::model::{model, Model, FIXTURE_ID, MAX_FRAME_BYTES, MAX_REQUEST_BYTES};
use crate::render_rust::render_rust;
use crate::render_ts::render_ts;
use crate::schema::render_schema;

const CONFORMANCE_PRELUDE: &str = include_str!("../../templates/conformance-prelude.mjs.tmpl");
const CONFORMANCE_EPILOGUE: &str = include_str!("../../templates/conformance-epilogue.mjs.tmpl");

fn subst(template: &str, holes: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (marker, value) in holes {
        out = out.replace(marker, value);
    }
    out
}

fn line(out: &mut String, args: std::fmt::Arguments<'_>) {
    out.write_fmt(args).expect("String write cannot fail");
    out.push('\n');
}

fn render_fixture(model: &Model) -> Result<String, String> {
    let vectors = model
        .vectors
        .iter()
        .map(|vector| {
            json!({
                "name":(vector.name),
                "direction":(vector.direction.as_str()),
                "message":(vector.message.clone()),
                "canonical":(vector.canonical.clone()),
                "frame_hex":(vector.frame_hex.clone())
            })
        })
        .collect::<Vec<_>>();
    let v1_rejections = model
        .v1_rejections
        .iter()
        .map(|case| {
            json!({
                "name":(case.name),
                "direction":(case.direction.as_str()),
                "payload":(case.payload)
            })
        })
        .collect::<Vec<_>>();
    let echo_pairs = model
        .echo_pairs
        .iter()
        .map(|pair| {
            json!({
                "request":(pair.request),
                "response":(pair.response)
            })
        })
        .collect::<Vec<_>>();
    let fixture = json!({
        "fixture":FIXTURE_ID,
        "version":2,
        "limits":{
            "max_request_bytes":MAX_REQUEST_BYTES,
            "max_frame_bytes":MAX_FRAME_BYTES
        },
        "vectors":vectors,
        "v1_rejections":v1_rejections,
        "echo_pairs":echo_pairs
    });
    json_file(&fixture)
}

fn render_conformance(model: &Model) -> Result<String, String> {
    let vectors = model
        .vectors
        .iter()
        .map(|vector| {
            json!({
                "name":(vector.name),
                "direction":(vector.direction.as_str()),
                "message":(vector.message.clone()),
                "canonical":(vector.canonical.clone()),
                "frame_hex":(vector.frame_hex.clone())
            })
        })
        .collect::<Vec<_>>();
    let v1 = model
        .v1_rejections
        .iter()
        .map(|case| {
            json!({
                "name":(case.name),
                "direction":(case.direction.as_str()),
                "payload":(case.payload)
            })
        })
        .collect::<Vec<_>>();
    let echoes = model
        .echo_pairs
        .iter()
        .map(|pair| {
            json!({
                "request":(pair.request),
                "response":(pair.response)
            })
        })
        .collect::<Vec<_>>();
    let malformed = model
        .malformed
        .iter()
        .map(|case| {
            let payload_hex = odin_types::hash::hex_encode(&case.payload);
            json!({
                "name":(case.name),
                "direction":(case.direction.as_str()),
                "payload_hex":payload_hex
            })
        })
        .collect::<Vec<_>>();
    let mut out = String::new();
    out.push_str(CONFORMANCE_PRELUDE);
    line(
        &mut out,
        format_args!(
            "const LIMITS = Object.freeze({{ maxRequestBytes: {MAX_REQUEST_BYTES}, maxFrameBytes: {MAX_FRAME_BYTES} }});"
        ),
    );
    out.push_str("const VECTORS = ");
    out.push_str(&json_text(&vectors)?);
    out.push_str(";\nconst V1_REJECTIONS = ");
    out.push_str(&json_text(&v1)?);
    out.push_str(";\nconst ECHO_PAIRS = ");
    out.push_str(&json_text(&echoes)?);
    out.push_str(";\nconst MALFORMED = [\n");
    for case in &malformed {
        out.push('\t');
        out.push_str(&json_text(case)?);
        out.push_str(",\n");
    }
    out.push_str("];\n\n");
    out.push_str(CONFORMANCE_EPILOGUE);
    Ok(out)
}

fn format_rust(source: &str) -> Result<String, String> {
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot start pinned rustfmt: {error}"))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "pinned rustfmt stdin was unavailable".to_string())?;
        std::io::Write::write_all(&mut stdin, source.as_bytes())
            .map_err(|error| format!("cannot write generated Rust to pinned rustfmt: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for pinned rustfmt: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "pinned rustfmt rejected generated Rust ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("pinned rustfmt emitted non-UTF-8 output: {error}"))
}

fn render_artifacts(model: &Model) -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| format!("cannot resolve repository root: {error}"))?;
    let src = root.join("crates/odin-sidecar-protocol/src");
    let mut artifacts = vec![(
        root.join("schemas/authority/odin-authority-wire-v2.schema.json"),
        render_schema(model)?.into_bytes(),
    )];
    for source in render_rust(model) {
        artifacts.push((
            src.join(source.path),
            format_rust(&source.source)?.into_bytes(),
        ));
    }
    artifacts.extend([
        (
            root.join("sweep/fixtures/authority-wire-v2.json"),
            render_fixture(model)?.into_bytes(),
        ),
        (
            root.join("extension/generated/odin-authority-wire-v2.ts"),
            render_ts(model).into_bytes(),
        ),
        (
            root.join("extension/generated/odin-authority-wire-v2.conformance.mjs"),
            render_conformance(model)?.into_bytes(),
        ),
    ]);
    Ok(artifacts)
}

fn write_artifacts(artifacts: &[(PathBuf, Vec<u8>)]) -> Result<(), String> {
    for (path, bytes) in artifacts {
        let parent = path
            .parent()
            .ok_or_else(|| format!("{} has no parent", path.display()))?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        fs::write(path, bytes)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        println!("generated {}", relative_display(path));
    }
    Ok(())
}

fn check_artifacts(artifacts: &[(PathBuf, Vec<u8>)]) -> Result<(), String> {
    for (path, expected) in artifacts {
        let actual = fs::read(path).map_err(|error| {
            format!(
                "generated artifact {} is missing or unreadable: {error}",
                relative_display(path)
            )
        })?;
        if actual != *expected {
            return Err(format!("generated artifact {} is stale; run `cargo run -p odin-sidecar-protocol --bin codegen`", relative_display(path)));
        }
        println!("checked {}", relative_display(path));
    }
    Ok(())
}

fn relative_display(path: &Path) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    path.strip_prefix(root.canonicalize().unwrap_or(root))
        .unwrap_or(path)
        .display()
        .to_string()
}

fn run() -> Result<(), String> {
    let check = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [flag] if flag == "--check" => true,
        _ => return Err("usage: codegen [--check]".to_string()),
    };
    let artifacts = render_artifacts(&model()?)?;
    if check {
        check_artifacts(&artifacts)
    } else {
        write_artifacts(&artifacts)
    }
}

fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .compact()
        .with_writer(std::io::stderr)
        .init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "codegen");
            ExitCode::FAILURE
        }
    }
}
