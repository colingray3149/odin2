//! Admitting a fetched file: its real type, checked by `file` in bwrap, must
//! be one of the classes the workflow expects. Anything else moves to the
//! `rejected` folder beside it (code never deletes it) and the failure says why.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::sandbox::{Net, Sandbox};
use crate::{cause, paths, Call, Ctx, Failure};

/// How long `file` may take on one file.
const FILE_WAIT: Duration = Duration::from_secs(30);
/// How far the size may stray from the expected bytes, in percent.
/// How far a download may differ from the size its source listed.
pub(crate) const SIZE_TOLERANCE_PERCENT: u64 = 10;
/// The folder rejected files move into, beside the file.
pub const REJECTED: &str = "rejected";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    Video,
    Audio,
    Image,
    /// PDF and the OOXML/ODF office containers.
    Document,
    /// EPUB.
    Ebook,
    Subtitle,
    Data,
}

impl Class {
    fn name(self) -> &'static str {
        match self {
            Self::Video => "a video",
            Self::Audio => "audio",
            Self::Image => "an image",
            Self::Document => "a document",
            Self::Ebook => "an ebook",
            Self::Subtitle => "a subtitle",
            Self::Data => "a data file",
        }
    }

    fn admits(self, mime: &str) -> bool {
        match self {
            Self::Video => mime.starts_with("video/"),
            Self::Audio => mime.starts_with("audio/"),
            Self::Image => mime.starts_with("image/"),
            Self::Document => {
                mime == "application/pdf"
                    || mime.starts_with("application/vnd.openxmlformats-officedocument.")
                    || mime.starts_with("application/vnd.oasis.opendocument.")
            }
            Self::Ebook => mime == "application/epub+zip",
            Self::Subtitle => matches!(mime, "text/plain" | "text/vtt" | "application/x-subrip"),
            Self::Data => matches!(mime, "application/json" | "text/csv" | "text/plain"),
        }
    }
}

const EXECUTABLES: &[&str] = &[
    "application/x-executable",
    "application/x-pie-executable",
    "application/x-sharedlib",
    "application/x-dosexec",
    "application/x-mach-binary",
    "application/vnd.microsoft.portable-executable",
];

const ARCHIVES: &[&str] = &[
    "application/zip",
    "application/x-tar",
    "application/gzip",
    "application/x-7z-compressed",
    "application/x-rar",
    "application/vnd.rar",
    "application/x-xz",
    "application/zstd",
    "application/x-bzip2",
];

/// Creates this call's folder inside a writable quarantine root.
pub fn call_dir(root: &crate::config::Root, call: &Call) -> Result<PathBuf, Failure> {
    if !root.writable {
        return Err(Failure::unavailable(format!(
            "the quarantine root {} is read-only",
            root.path.display()
        )));
    }
    let name = crate::ctx::call_folder_name(&call.key)?;
    let dir = paths::child(root, &name)?;
    std::fs::create_dir_all(&dir).map_err(|error| {
        Failure::unavailable(format!("could not create {}: {error}", dir.display()))
    })?;
    let canonical = dir.canonicalize().map_err(|error| {
        Failure::unavailable(format!("could not read {}: {error}", dir.display()))
    })?;
    let base = root.path.canonicalize().map_err(|error| {
        Failure::unavailable(format!("could not read {}: {error}", root.path.display()))
    })?;
    if !canonical.starts_with(base) {
        return Err(Failure::arguments(
            "the quarantine folder leads outside its root through a link",
        ));
    }
    Ok(canonical)
}

/// Returns the file's MIME type when it is one of `allow`; otherwise moves it
/// to `rejected/` beside it and fails naming what it really is. Checks the size
/// against `expected_bytes` within 10 % when given.
pub fn admit(
    ctx: &Ctx,
    path: &Path,
    allow: &[Class],
    expected_bytes: Option<u64>,
) -> Result<String, Failure> {
    let mime = sniff_mime(ctx, path)?;
    let expected = allow
        .iter()
        .map(|class| class.name())
        .collect::<Vec<_>>()
        .join(" or ");
    let refusal = if EXECUTABLES.contains(&mime.as_str()) {
        Some(format!("is an executable ({mime}), not {expected}"))
    } else if starts_with_shebang(path) {
        Some(format!("is a script ({mime}), not {expected}"))
    } else if ARCHIVES.contains(&mime.as_str()) {
        Some(format!("is an archive ({mime}), not {expected}"))
    } else if !allow.iter().any(|class| class.admits(&mime)) {
        Some(format!("is {mime}, not {expected}"))
    } else {
        size_mismatch(path, expected_bytes)
    };
    match refusal {
        None => Ok(mime),
        Some(why) => {
            let rejected = reject(path)?;
            Err(Failure::upstream(format!(
                "{} {why}; it stays in {}",
                paths::file_name(path),
                rejected.display()
            )))
        }
    }
}

/// What `file` says the file's MIME type is.
pub fn sniff_mime(ctx: &Ctx, path: &Path) -> Result<String, Failure> {
    let spec = Sandbox::new(ctx, "file")?
        .args(["--mime-type", "-b"])
        .arg(path)
        .ro(path)
        .net(Net::None)
        .timeout(FILE_WAIT)
        .build();
    let out = ctx.run(&spec)?;
    if let Some(failure) = cause::failure("file", &[], &[], &out, FILE_WAIT) {
        return Err(failure);
    }
    Ok(out.stdout_text().trim().to_owned())
}

fn starts_with_shebang(path: &Path) -> bool {
    let mut head = [0; 2];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut head))
        .is_ok_and(|()| &head == b"#!")
}

/// Whether a file's size is within `SIZE_TOLERANCE_PERCENT` of the size its source listed.
pub(crate) fn within_listed_size(actual: u64, expected: u64) -> bool {
    actual.abs_diff(expected) <= expected * SIZE_TOLERANCE_PERCENT / 100
}

fn size_mismatch(path: &Path, expected: Option<u64>) -> Option<String> {
    let expected = expected?;
    let actual = std::fs::metadata(path).map_or(0, |meta| meta.len());
    (!within_listed_size(actual, expected))
        .then(|| format!("is {actual} bytes, not the expected {expected}"))
}

fn reject(path: &Path) -> Result<PathBuf, Failure> {
    let dir = path.parent().unwrap_or(Path::new("/")).join(REJECTED);
    std::fs::create_dir_all(&dir).map_err(|error| {
        Failure::unavailable(format!("could not create {}: {error}", dir.display()))
    })?;
    let target = paths::unique(&dir, &paths::file_name(path));
    std::fs::rename(path, &target).map_err(|error| {
        Failure::unavailable(format!(
            "could not move {} into {}: {error}",
            path.display(),
            dir.display()
        ))
    })?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{ctx_for, FakeExe};

    #[test]
    fn call_folders_stay_in_the_writable_quarantine_root() {
        let dir = tempfile::tempdir().expect("dir");
        let root = dir.path().join("quarantine");
        let ctx = ctx_for(dir.path(), &[], &[("quarantine", &root, true)], &[], &[]);
        let call = Call {
            key: "../command-123".to_owned(),
            ..Call::default()
        };
        let folder = call_dir(ctx.root("quarantine").expect("root"), &call).expect("folder");
        assert_eq!(
            folder,
            root.canonicalize().expect("root").join(".._command-123")
        );
        assert!(folder.is_dir());
        assert!(call_dir(ctx.root("quarantine").expect("root"), &Call::default()).is_err());
        let ctx = ctx_for(dir.path(), &[], &[("quarantine", &root, false)], &[], &[]);
        assert!(call_dir(ctx.root("quarantine").expect("root"), &call).is_err());
    }

    fn admit_as(mime: &str, allow: &[Class]) -> (tempfile::TempDir, Result<String, Failure>) {
        admit_file(mime, b"MZ fixture", allow, None)
    }

    fn admit_file(
        mime: &str,
        content: &[u8],
        allow: &[Class],
        expected_bytes: Option<u64>,
    ) -> (tempfile::TempDir, Result<String, Failure>) {
        let dir = tempfile::tempdir().expect("dir");
        let file = FakeExe::new(dir.path(), "file")
            .stdout(format!("{mime}\n"))
            .install();
        let ctx = ctx_for(dir.path(), &[("file", file.as_path())], &[], &[], &[]);
        let quarantine = dir.path().join("quarantine");
        std::fs::create_dir_all(&quarantine).expect("quarantine");
        let fetched = quarantine.join("clip.mp4");
        std::fs::write(&fetched, content).expect("fetched");
        let admitted = admit(&ctx, &fetched, allow, expected_bytes);
        (dir, admitted)
    }

    #[test]
    fn admit_rejects_an_executable() {
        let (dir, admitted) = admit_as("application/x-executable", &[Class::Video]);
        let failure = admitted.expect_err("executable");
        let rejected = dir.path().join("quarantine").join(REJECTED);
        assert_eq!(
            failure.cause,
            format!(
                "clip.mp4 is an executable (application/x-executable), not a video; it stays in {}",
                rejected.display()
            )
        );
        assert!(rejected.join("clip.mp4").is_file());
    }

    #[test]
    fn a_script_posing_as_a_video_and_a_wrong_size_are_rejected_but_a_close_size_is_not() {
        let (dir, admitted) =
            admit_file("video/mp4", b"#!/bin/sh\nrm -rf ~\n", &[Class::Video], None);
        assert!(admitted.expect_err("script").cause.contains("is a script"));
        assert!(dir
            .path()
            .join("quarantine")
            .join(REJECTED)
            .join("clip.mp4")
            .is_file());

        let (_dir, admitted) = admit_file("video/mp4", &[0; 1000], &[Class::Video], Some(1050));
        assert_eq!(admitted.expect("within 10 percent"), "video/mp4");
        let (dir, admitted) = admit_file("video/mp4", &[0; 1000], &[Class::Video], Some(2000));
        assert!(admitted
            .expect_err("half the listed size")
            .cause
            .contains("not the expected 2000"));
        assert!(dir
            .path()
            .join("quarantine")
            .join(REJECTED)
            .join("clip.mp4")
            .is_file());
    }
}
