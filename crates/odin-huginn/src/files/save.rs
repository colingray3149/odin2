//! Saving a file into a writable declared root: confined like reads
//! (openat2 beneath the root, no symlinks, no `..`), folders created as
//! needed, and never over an existing file: a taken name gets ` (2)`, ` (3)`…

mod receipt;

use odin_domain::huginn::{media_type_for_name, FileRoot, FileRootAccess, RelativePath};

use super::roots::{create_beneath, file_limit, invalid_file, open_or_create_dir, open_root};
use odin_domain::huginn::HuginnProtocolError;

/// The most numbered names tried before a save gives up.
const MAX_SUFFIX: u32 = 99;
/// The most bytes read from the source and written at once.
const COPY_CHUNK_BYTES: usize = 64 * 1024;

/// `name` and its numbered alternatives: `Draft.pdf`, `Draft (2).pdf`, …
fn candidates(name: &str) -> impl Iterator<Item = String> + '_ {
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem, format!(".{extension}")),
        _ => (name, String::new()),
    };
    std::iter::once(name.to_owned())
        .chain((2..=MAX_SUFFIX).map(move |number| format!("{stem} ({number}){extension}")))
}

/// Writes `bytes` as a new file named `name` in `folder` (created as needed)
/// beneath a writable root, and returns the path it was saved at.
pub fn save_into_root(
    root: &FileRoot,
    folder: Option<&RelativePath>,
    name: &str,
    bytes: &[u8],
) -> Result<RelativePath, HuginnProtocolError> {
    save_stream_into_root(
        root,
        folder,
        name,
        &mut std::io::Cursor::new(bytes),
        bytes.len() as u64,
        odin_domain::Digest::hash(bytes),
    )
}

/// Validates a save before attempting transport or writing queue state.
pub fn validate_save(
    root: &FileRoot,
    name: &str,
    byte_len: u64,
) -> Result<(), HuginnProtocolError> {
    if root.access != FileRootAccess::ReadWrite {
        return Err(invalid_file(format!("{} is read-only", root.root_id)));
    }
    if name.is_empty()
        || name.len() > 200
        || name == "."
        || name == ".."
        || name.contains(['/', '\0'])
        || name.chars().any(char::is_control)
    {
        return Err(invalid_file(format!("{name:?} is not a plain file name")));
    }
    // A type no extension names is `application/octet-stream`: only a root
    // that declares it (raw data such as TDMS or HDF5) takes such a file.
    let media = media_type_for_name(name).unwrap_or("application/octet-stream");
    if !root.media_policy.allows(media) {
        return Err(invalid_file(format!(
            "{name}: its type is not one {} accepts",
            root.root_id
        )));
    }
    if byte_len > root.max_object_bytes.get() {
        return Err(file_limit("file-object-bytes"));
    }
    Ok(())
}

/// Copies and verifies a stream before publishing success; failed copies
/// remove only the new incomplete destination, never their source.
pub fn save_stream_into_root(
    root: &FileRoot,
    folder: Option<&RelativePath>,
    name: &str,
    reader: &mut dyn std::io::Read,
    byte_len: u64,
    digest: odin_domain::Digest,
) -> Result<RelativePath, HuginnProtocolError> {
    save_stream(
        root,
        folder,
        name,
        VerifiedStream {
            reader,
            byte_len,
            digest,
        },
        None,
        true,
    )
}

/// Like [`save_stream_into_root`] at the root's top, but a taken name is
/// refused instead of numbered: the file is created as `name` or not at all.
pub fn save_new_into_root(
    root: &FileRoot,
    name: &str,
    reader: &mut dyn std::io::Read,
    byte_len: u64,
    digest: odin_domain::Digest,
) -> Result<RelativePath, HuginnProtocolError> {
    save_stream(
        root,
        None,
        name,
        VerifiedStream {
            reader,
            byte_len,
            digest,
        },
        None,
        false,
    )
}

/// A durable transfer id makes a retry after lost acknowledgement reuse its
/// already verified destination rather than create a second numbered copy.
pub fn save_stream_into_root_with_id(
    root: &FileRoot,
    folder: Option<&RelativePath>,
    name: &str,
    reader: &mut dyn std::io::Read,
    byte_len: u64,
    digest: odin_domain::Digest,
    id: uuid::Uuid,
) -> Result<RelativePath, HuginnProtocolError> {
    validate_save(root, name, byte_len)?;
    let mut receipt = receipt::Receipt::open(root, folder, name, byte_len, digest, id)?;
    if let Some(saved) = receipt.verified_destination(root)? {
        copy_verified(reader, &mut std::io::sink(), byte_len, digest)
            .map_err(|error| invalid_file(format!("file stream could not be verified: {error}")))?;
        return Ok(saved);
    }
    save_stream(
        root,
        folder,
        name,
        VerifiedStream {
            reader,
            byte_len,
            digest,
        },
        Some(&mut receipt),
        true,
    )
}

fn copy_verified(
    reader: &mut dyn std::io::Read,
    writer: &mut dyn std::io::Write,
    byte_len: u64,
    digest: odin_domain::Digest,
) -> std::io::Result<()> {
    let mut remaining = byte_len;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0; COPY_CHUNK_BYTES];
    while remaining > 0 {
        let cap = remaining.min(buffer.len() as u64) as usize;
        let count = reader.read(&mut buffer[..cap])?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "file stream ended early",
            ));
        }
        writer.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if reader.read(&mut buffer[..1])? != 0 || hasher.finalize().as_bytes() != digest.as_bytes() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file stream length or digest differs",
        ));
    }
    Ok(())
}

struct VerifiedStream<'a> {
    reader: &'a mut dyn std::io::Read,
    byte_len: u64,
    digest: odin_domain::Digest,
}

fn save_stream(
    root: &FileRoot,
    folder: Option<&RelativePath>,
    name: &str,
    stream: VerifiedStream<'_>,
    mut receipt: Option<&mut receipt::Receipt>,
    numbered: bool,
) -> Result<RelativePath, HuginnProtocolError> {
    let VerifiedStream {
        reader,
        byte_len,
        digest,
    } = stream;
    validate_save(root, name, byte_len)?;
    let mut dir = open_root(root)?;
    if let Some(folder) = folder {
        for component in folder.as_str().split('/') {
            dir = open_or_create_dir(&dir, component).map_err(|error| {
                invalid_file(format!("folder {folder} cannot be opened or made: {error}"))
            })?;
        }
    }
    for candidate in candidates(name) {
        let mut file = match create_beneath(&dir, &candidate) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && !numbered => {
                return Err(invalid_file(format!(
                    "{candidate} already exists in {} and is never overwritten",
                    root.root_id
                )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(invalid_file(format!(
                    "{candidate} cannot be created: {error}"
                )))
            }
        };
        let written = (|| -> std::io::Result<()> {
            let saved = match folder {
                Some(folder) => format!("{folder}/{candidate}"),
                None => candidate.clone(),
            };
            if let Some(receipt) = receipt.as_mut() {
                receipt.reserve(&saved)?;
            }
            copy_verified(reader, &mut file, byte_len, digest)?;
            file.sync_all()?;
            // Read the destination back, not merely the incoming stream.
            let mut destination = super::roots::open_beneath(
                &dir,
                std::path::Path::new(&candidate),
                super::roots::read_flags(),
            )?;
            let mut verified = blake3::Hasher::new();
            verified.update_reader(&mut destination)?;
            if verified.finalize().as_bytes() != digest.as_bytes() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "saved file fails its digest",
                ));
            }
            dir.sync_all()
        })();
        if let Err(error) = written {
            let _ = rustix::fs::unlinkat(&dir, candidate.as_str(), rustix::fs::AtFlags::empty());
            return Err(invalid_file(format!(
                "{candidate} could not be written: {error}"
            )));
        }
        let saved = match folder {
            Some(folder) => format!("{folder}/{candidate}"),
            None => candidate,
        };
        return RelativePath::new(saved).map_err(super::roots::map_domain);
    }
    Err(invalid_file(format!(
        "{name} and its numbered alternatives up to ({MAX_SUFFIX}) all exist"
    )))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use odin_domain::huginn::{FileRoot, FileRootAccess, FileRootInit, RelativePath};

    use super::save_into_root;
    use crate::files::test_root_init;

    fn root(dir: &std::path::Path, access: FileRootAccess) -> FileRoot {
        FileRoot::new(test_root_init(
            "pc-downloads",
            dir,
            access,
            "application/pdf",
        ))
        .unwrap()
    }

    #[test]
    fn jsonl_evidence_saves_as_json() {
        let dir = tempfile::tempdir().unwrap();
        let writable = FileRoot::new(test_root_init(
            "pc-downloads",
            dir.path(),
            FileRootAccess::ReadWrite,
            "application/json",
        ))
        .unwrap();
        // The OSINT tools retain their evidence as line-delimited JSON; it
        // classifies as JSON, so a downloads folder that takes JSON takes it.
        let first = save_into_root(&writable, None, "graph.jsonl", b"{}\n").unwrap();
        assert_eq!(first.as_str(), "graph.jsonl");
        let second = save_into_root(&writable, None, "graph.jsonl", b"{}\n").unwrap();
        assert_eq!(second.as_str(), "graph (2).jsonl");
    }

    #[test]
    fn lost_save_acknowledgements_reuse_the_verified_destination() {
        let directory = tempfile::tempdir().unwrap();
        let root = root(directory.path(), FileRootAccess::ReadWrite);
        let id = uuid::Uuid::new_v4();
        let bytes = b"complete original";
        let digest = odin_domain::Digest::hash(bytes);
        for _ in 0..2 {
            let path = super::save_stream_into_root_with_id(
                &root,
                None,
                "original.pdf",
                &mut std::io::Cursor::new(bytes),
                bytes.len() as u64,
                digest,
                id,
            )
            .unwrap();
            assert_eq!(path.as_str(), "original.pdf");
        }
        assert!(!directory.path().join("original (2).pdf").exists());
        assert!(super::save_stream_into_root_with_id(
            &root,
            None,
            "different.pdf",
            &mut std::io::Cursor::new(bytes),
            bytes.len() as u64,
            digest,
            id,
        )
        .is_err());
        // A changed destination is preserved, not overwritten on recovery.
        std::fs::write(directory.path().join("original.pdf"), b"user edit").unwrap();
        let recovered = super::save_stream_into_root_with_id(
            &root,
            None,
            "original.pdf",
            &mut std::io::Cursor::new(bytes),
            bytes.len() as u64,
            digest,
            id,
        )
        .unwrap();
        assert_eq!(recovered.as_str(), "original (2).pdf");
        assert_eq!(
            std::fs::read(directory.path().join("original.pdf")).unwrap(),
            b"user edit"
        );
    }

    #[test]
    fn large_originals_stream_in_bounded_chunks_and_verify_byte_identically() {
        use std::io::Read;
        struct Source {
            remaining: u64,
            largest_read: usize,
        }
        impl Read for Source {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                self.largest_read = self.largest_read.max(output.len());
                let count = self.remaining.min(output.len() as u64) as usize;
                output[..count].fill(0xa7);
                self.remaining -= count as u64;
                Ok(count)
            }
        }
        let size = 4 * 1024 * 1024;
        let directory = tempfile::tempdir().unwrap();
        let root = FileRoot::new(FileRootInit {
            max_object_bytes: NonZeroU64::new(size).unwrap(),
            ..test_root_init(
                "pc-downloads",
                directory.path(),
                FileRootAccess::ReadWrite,
                "application/pdf",
            )
        })
        .unwrap();
        let mut expected = blake3::Hasher::new();
        expected
            .update_reader(std::io::repeat(0xa7).take(size))
            .unwrap();
        let digest = odin_domain::Digest::new(*expected.finalize().as_bytes());
        let mut source = Source {
            remaining: size,
            largest_read: 0,
        };
        let saved =
            super::save_stream_into_root(&root, None, "original.pdf", &mut source, size, digest)
                .unwrap();
        assert!(source.largest_read <= super::COPY_CHUNK_BYTES);
        let (metadata, mut destination) = crate::files::open_from_root(&root, &saved).unwrap();
        assert_eq!(metadata.byte_len, size);
        let mut actual = blake3::Hasher::new();
        actual.update_reader(&mut destination).unwrap();
        assert_eq!(actual.finalize().as_bytes(), digest.as_bytes());
    }

    #[test]
    fn failed_streams_remove_only_the_incomplete_destination_and_retain_source() {
        let directory = tempfile::tempdir().unwrap();
        let root = root(directory.path(), FileRootAccess::ReadWrite);
        let digest = odin_domain::Digest::hash(b"complete");
        for bytes in [b"short".as_slice(), b"complete-extra", b"corrupt!"] {
            assert!(super::save_stream_into_root(
                &root,
                None,
                "bad.pdf",
                &mut std::io::Cursor::new(bytes),
                8,
                digest
            )
            .is_err());
            assert!(!directory.path().join("bad.pdf").exists());
        }
        std::fs::write(directory.path().join("source.pdf"), b"complete").unwrap();
        let source = RelativePath::parse("source.pdf").unwrap();
        assert!(crate::files::browse::remove_verified_source(
            &root,
            &source,
            odin_domain::Digest::hash(b"different")
        )
        .is_err());
        assert_eq!(
            std::fs::read(directory.path().join("source.pdf")).unwrap(),
            b"complete"
        );
    }

    #[test]
    fn saves_never_overwrite_and_never_leave_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let writable = root(dir.path(), FileRootAccess::ReadWrite);
        let folder = RelativePath::parse("Sinmara/CS91").unwrap();
        let first = save_into_root(&writable, Some(&folder), "Draft.pdf", b"one").unwrap();
        let second = save_into_root(&writable, Some(&folder), "Draft.pdf", b"two").unwrap();
        assert_eq!(first.as_str(), "Sinmara/CS91/Draft.pdf");
        assert_eq!(second.as_str(), "Sinmara/CS91/Draft (2).pdf");
        assert_eq!(
            std::fs::read(dir.path().join("Sinmara/CS91/Draft.pdf")).unwrap(),
            b"one"
        );
        assert_eq!(
            std::fs::read(dir.path().join("Sinmara/CS91/Draft (2).pdf")).unwrap(),
            b"two"
        );

        // A symlinked folder or a symlink at the name is never written through.
        std::os::unix::fs::symlink(outside.path(), dir.path().join("Out")).unwrap();
        let out = RelativePath::parse("Out").unwrap();
        assert!(save_into_root(&writable, Some(&out), "x.pdf", b"x").is_err());
        std::os::unix::fs::symlink(outside.path().join("t.pdf"), dir.path().join("t.pdf")).unwrap();
        let linked = save_into_root(&writable, None, "t.pdf", b"x").unwrap();
        assert_eq!(
            linked.as_str(),
            "t (2).pdf",
            "the symlinked name counts as taken"
        );
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());

        for name in ["../x.pdf", "a/b.pdf", "notes.exe", ".", ".."] {
            assert!(
                save_into_root(&writable, None, name, b"x").is_err(),
                "{name}"
            );
        }
        // A leading dot is a naming convention, not traversal: an exported
        // evidence file like `.seeds` saves like any other name, still confined.
        let dotted = save_into_root(&writable, None, ".hidden.pdf", b"x").unwrap();
        assert_eq!(dotted.as_str(), ".hidden.pdf");
        assert!(save_into_root(&writable, None, "big.pdf", &[0; 2048]).is_err());
        let read_only = root(dir.path(), FileRootAccess::ReadOnly);
        assert!(save_into_root(&read_only, None, "r.pdf", b"x").is_err());
    }
}
