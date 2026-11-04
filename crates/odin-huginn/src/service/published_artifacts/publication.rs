use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::service::{decode_content, encode_content, invalid_protocol};
use odin_domain::huginn::HuginnProtocolError;
use odin_domain::{ArtifactId, Digest};

use super::PublishedArtifactRecord;

/// How many records name each payload. It lives inside the store's publication lock, which every record
/// write and removal holds, so retiring a record frees its payload without reading every other record
/// (that read was the whole store, once per retired browser frame).
#[derive(Default)]
pub(super) struct PayloadRefs(HashMap<String, usize>);

impl PayloadRefs {
    /// Counts the records already on disk, once, when the store opens.
    pub(super) fn scan(root: &Path) -> Result<Self, HuginnProtocolError> {
        let mut refs = Self::default();
        for entry in fs::read_dir(root.join("records")).map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactRecord",
                format!("reading {}: {error}", root.join("records").display()),
            )
        })? {
            let entry = entry.map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactRecord",
                    format!("reading {}: {error}", root.join("records").display()),
                )
            })?;
            let path = entry.path();
            if path.extension() != Some(std::ffi::OsStr::new("cbor")) {
                continue;
            }
            if !entry
                .file_type()
                .map_err(|error| {
                    HuginnProtocolError::unavailable(
                        "publishedArtifactRecord",
                        format!("reading {}: {error}", path.display()),
                    )
                })?
                .is_file()
            {
                return Err(HuginnProtocolError::unavailable(
                    "publishedArtifactRecord",
                    format!("{} is not a file", path.display()),
                ));
            }
            let record: PublishedArtifactRecord =
                decode_content(&fs::read(&path).map_err(|error| {
                    HuginnProtocolError::unavailable(
                        "publishedArtifactRecord",
                        format!("reading {}: {error}", path.display()),
                    )
                })?)?;
            if published_record_path(root, &record.artifact.artifact_id) != path
                || record.payload_name != payload_name(record.artifact.content_digest)
            {
                return Err(HuginnProtocolError::unavailable(
                    "publishedArtifactBinding",
                    format!(
                        "{} does not match its record's artifact or payload",
                        path.display()
                    ),
                ));
            }
            *refs.0.entry(record.payload_name).or_default() += 1;
        }
        Ok(refs)
    }

    fn release(&mut self, payload_name: &str) {
        if let Some(count) = self.0.get_mut(payload_name) {
            *count -= 1;
            if *count == 0 {
                self.0.remove(payload_name);
            }
        }
    }
}

pub(super) fn persist_payload(
    source: &Path,
    destination: &Path,
    expected_len: u64,
    expected_digest: Digest,
) -> Result<(), HuginnProtocolError> {
    if destination.try_exists().map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPayload",
            format!("checking {}: {error}", destination.display()),
        )
    })? {
        return validate_payload(destination, expected_len, expected_digest);
    }
    let parent = destination.parent().ok_or_else(|| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPayload",
            format!("{} has no parent", destination.display()),
        )
    })?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut input = File::open(source).map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactSource",
            format!("opening {}: {error}", source.display()),
        )
    })?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options.open(&temporary).map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPayload",
            format!("creating {}: {error}", temporary.display()),
        )
    })?;
    std::io::copy(&mut input, &mut output)
        .and_then(|_| output.sync_all())
        .map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactPayload",
                format!(
                    "copying {} to {}: {error}",
                    source.display(),
                    temporary.display()
                ),
            )
        })?;
    validate_payload(&temporary, expected_len, expected_digest)?;
    match fs::rename(&temporary, destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            validate_payload(destination, expected_len, expected_digest)?;
        }
        Err(error) => {
            return Err(HuginnProtocolError::unavailable(
                "publishedArtifactPayload",
                format!("renaming into {}: {error}", destination.display()),
            ))
        }
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactPayload",
                format!("syncing {}: {error}", parent.display()),
            )
        })
}

pub(super) fn persist_payload_bytes(
    bytes: &[u8],
    destination: &Path,
    expected_len: u64,
    expected_digest: Digest,
) -> Result<(), HuginnProtocolError> {
    if bytes.len() as u64 != expected_len || Digest::hash(bytes) != expected_digest {
        return Err(invalid_protocol(
            "publishedArtifactDigest",
            "browser payload length or digest does not match its declaration",
        ));
    }
    if destination.try_exists().map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPayload",
            format!("checking {}: {error}", destination.display()),
        )
    })? {
        return validate_payload(destination, expected_len, expected_digest);
    }
    let parent = destination.parent().ok_or_else(|| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPayload",
            format!("{} has no parent", destination.display()),
        )
    })?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| {
        let mut output = options.open(&temporary).map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactPayload",
                format!("creating {}: {error}", temporary.display()),
            )
        })?;
        output
            .write_all(bytes)
            .and_then(|()| output.sync_all())
            .map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactPayload",
                    format!("writing {}: {error}", temporary.display()),
                )
            })?;
        validate_payload(&temporary, expected_len, expected_digest)?;
        match fs::hard_link(&temporary, destination) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_payload(destination, expected_len, expected_digest)?;
            }
            Err(error) => {
                return Err(HuginnProtocolError::unavailable(
                    "publishedArtifactPayload",
                    format!("linking {}: {error}", destination.display()),
                ))
            }
        }
        fs::remove_file(&temporary).map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactPayload",
                format!("removing {}: {error}", temporary.display()),
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactPayload",
                    format!("syncing {}: {error}", parent.display()),
                )
            })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_payload(
    path: &Path,
    expected_len: u64,
    expected_digest: Digest,
) -> Result<(), HuginnProtocolError> {
    let mut file = File::open(path).map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPayload",
            format!("opening {}: {error}", path.display()),
        )
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactPayload",
                format!("reading {}: {error}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        length = length.checked_add(read as u64).ok_or_else(|| {
            HuginnProtocolError::unavailable(
                "publishedArtifactPayload",
                format!("{} overflows u64 bytes", path.display()),
            )
        })?;
        hasher.update(&buffer[..read]);
    }
    if length != expected_len
        || Digest::from_bytes(*hasher.finalize().as_bytes()) != expected_digest
    {
        return Err(HuginnProtocolError::unavailable(
            "publishedArtifactPayload",
            format!(
                "{} ({length} bytes) does not match its declaration",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub(super) fn persist_published_record(
    root: &Path,
    refs: &mut PayloadRefs,
    record: &PublishedArtifactRecord,
) -> Result<(), HuginnProtocolError> {
    let path = root
        .join("records")
        .join(format!("{}.cbor", record.artifact.artifact_id.as_str()));
    let encoded = encode_content(record)?;
    if path.try_exists().map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactRecord",
            format!("checking {}: {error}", path.display()),
        )
    })? {
        let existing: PublishedArtifactRecord =
            decode_content(&fs::read(&path).map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactRecord",
                    format!("reading {}: {error}", path.display()),
                )
            })?)?;
        return if existing == *record {
            Ok(())
        } else {
            Err(HuginnProtocolError::Conflict {
                code: "publishedArtifactReuse".to_owned(),
                message: "artifact ID is already bound to another payload".to_owned(),
            })
        };
    }
    let parent = path.parent().ok_or_else(|| {
        HuginnProtocolError::unavailable(
            "publishedArtifactRecord",
            format!("{} has no parent", path.display()),
        )
    })?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactRecord",
            format!("creating {}: {error}", temporary.display()),
        )
    })?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactRecord",
                format!("writing {}: {error}", temporary.display()),
            )
        })?;
    fs::rename(&temporary, &path).map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactRecord",
            format!("renaming into {}: {error}", path.display()),
        )
    })?;
    *refs.0.entry(record.payload_name.clone()).or_default() += 1;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactRecord",
                format!("syncing {}: {error}", parent.display()),
            )
        })
}

pub(super) fn payload_name(digest: Digest) -> String {
    format!("{}.blob", digest.hex())
}

pub(super) fn published_record_path(root: &Path, artifact_id: &ArtifactId) -> PathBuf {
    root.join("records")
        .join(format!("{}.cbor", artifact_id.as_str()))
}

pub(super) fn read_published_record(
    root: &Path,
    artifact_id: &ArtifactId,
) -> Result<Option<PublishedArtifactRecord>, HuginnProtocolError> {
    let path = published_record_path(root, artifact_id);
    if !path.try_exists().map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactRecord",
            format!("checking {}: {error}", path.display()),
        )
    })? {
        return Ok(None);
    }
    let record: PublishedArtifactRecord = decode_content(&fs::read(&path).map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactRecord",
            format!("reading {}: {error}", path.display()),
        )
    })?)?;
    if &record.artifact.artifact_id != artifact_id
        || record.payload_name != payload_name(record.artifact.content_digest)
    {
        return Err(HuginnProtocolError::unavailable(
            "publishedArtifactBinding",
            format!(
                "{} does not match artifact {artifact_id} or its payload",
                path.display()
            ),
        ));
    }
    Ok(Some(record))
}

pub(super) fn delete_payload_if_unreferenced(
    root: &Path,
    refs: &PayloadRefs,
    candidate_payload_name: &str,
) -> Result<(), HuginnProtocolError> {
    if refs.0.contains_key(candidate_payload_name) {
        return Ok(());
    }
    let payloads = root.join("payloads");
    match fs::remove_file(payloads.join(candidate_payload_name)) {
        Ok(()) => File::open(&payloads)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactPayload",
                    format!("syncing {}: {error}", payloads.display()),
                )
            }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(HuginnProtocolError::unavailable(
            "publishedArtifactPayload",
            format!("removing {candidate_payload_name}: {error}"),
        )),
    }
}

pub(super) fn retire_published_record(
    root: &Path,
    refs: &mut PayloadRefs,
    record: &PublishedArtifactRecord,
) -> Result<(), HuginnProtocolError> {
    retire_published_records(root, refs, std::slice::from_ref(record))
}

/// Removes the records, then every payload no remaining record names, with one directory sync for each
/// side: a batch from the replay store can be thousands of feed frames.
pub(super) fn retire_published_records(
    root: &Path,
    refs: &mut PayloadRefs,
    records: &[PublishedArtifactRecord],
) -> Result<(), HuginnProtocolError> {
    let mut removed = false;
    for record in records {
        let Some(existing) = read_published_record(root, &record.artifact.artifact_id)? else {
            continue;
        };
        if existing != *record {
            return Err(HuginnProtocolError::unavailable(
                "publishedArtifactBinding",
                format!(
                    "artifact {} differs from its published record",
                    record.artifact.artifact_id
                ),
            ));
        }
        fs::remove_file(published_record_path(root, &record.artifact.artifact_id)).map_err(
            |error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactRecord",
                    format!(
                        "removing the record of {}: {error}",
                        record.artifact.artifact_id
                    ),
                )
            },
        )?;
        refs.release(&record.payload_name);
        removed = true;
    }
    if removed {
        File::open(root.join("records"))
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactRecord",
                    format!("syncing {}: {error}", root.join("records").display()),
                )
            })?;
    }
    // Payloads go only once their records are durably gone, so no record ever names a missing payload.
    let payloads = root.join("payloads");
    let mut removed = false;
    for record in records {
        if refs.0.contains_key(&record.payload_name) {
            continue;
        }
        match fs::remove_file(payloads.join(&record.payload_name)) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(HuginnProtocolError::unavailable(
                    "publishedArtifactPayload",
                    format!("removing payload {}: {error}", record.payload_name),
                ))
            }
        }
    }
    if removed {
        File::open(&payloads)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactPayload",
                    format!("syncing {}: {error}", payloads.display()),
                )
            })?;
    }
    Ok(())
}

pub(super) fn remove_stale_publication_temporaries(root: &Path) -> Result<(), HuginnProtocolError> {
    for directory_name in ["records", "payloads", "browser-pointers"] {
        let directory = root.join(directory_name);
        let mut removed = false;
        for entry in fs::read_dir(&directory).map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactRecovery",
                format!("reading {}: {error}", directory.display()),
            )
        })? {
            let entry = entry.map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactRecovery",
                    format!("reading {}: {error}", directory.display()),
                )
            })?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactRecovery",
                    format!("{} holds a name that is not UTF-8", directory.display()),
                )
            })?;
            if name.starts_with('.') && name.ends_with(".tmp") {
                if !entry
                    .file_type()
                    .map_err(|error| {
                        HuginnProtocolError::unavailable(
                            "publishedArtifactRecovery",
                            format!("reading {}: {error}", directory.display()),
                        )
                    })?
                    .is_file()
                {
                    return Err(HuginnProtocolError::unavailable(
                        "publishedArtifactRecovery",
                        format!("{} is not a file", entry.path().display()),
                    ));
                }
                fs::remove_file(entry.path()).map_err(|error| {
                    HuginnProtocolError::unavailable(
                        "publishedArtifactRecovery",
                        format!("removing {}: {error}", entry.path().display()),
                    )
                })?;
                removed = true;
            }
        }
        if removed {
            File::open(&directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    HuginnProtocolError::unavailable(
                        "publishedArtifactRecovery",
                        format!("syncing {}: {error}", directory.display()),
                    )
                })?;
        }
    }
    Ok(())
}
