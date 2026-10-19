use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::service::{decode_content, encode_content, invalid_protocol, unavailable_protocol};
use odin_domain::huginn::HuginnProtocolError;
use odin_domain::{ArtifactId, Digest};

use super::PublishedArtifactRecord;

pub(super) fn persist_payload(
    source: &Path,
    destination: &Path,
    expected_len: u64,
    expected_digest: Digest,
) -> Result<(), HuginnProtocolError> {
    if destination
        .try_exists()
        .map_err(|_| unavailable_protocol("publishedArtifactPayload"))?
    {
        return validate_payload(destination, expected_len, expected_digest);
    }
    let parent = destination
        .parent()
        .ok_or_else(|| unavailable_protocol("publishedArtifactPayload"))?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut input =
        File::open(source).map_err(|_| unavailable_protocol("publishedArtifactSource"))?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options
        .open(&temporary)
        .map_err(|_| unavailable_protocol("publishedArtifactPayload"))?;
    std::io::copy(&mut input, &mut output)
        .and_then(|_| output.sync_all())
        .map_err(|_| unavailable_protocol("publishedArtifactPayload"))?;
    validate_payload(&temporary, expected_len, expected_digest)?;
    match fs::rename(&temporary, destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            validate_payload(destination, expected_len, expected_digest)?;
        }
        Err(_) => return Err(unavailable_protocol("publishedArtifactPayload")),
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| unavailable_protocol("publishedArtifactPayload"))
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
    if destination
        .try_exists()
        .map_err(|_| unavailable_protocol("publishedArtifactPayload"))?
    {
        return validate_payload(destination, expected_len, expected_digest);
    }
    let parent = destination
        .parent()
        .ok_or_else(|| unavailable_protocol("publishedArtifactPayload"))?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| {
        let mut output = options
            .open(&temporary)
            .map_err(|_| unavailable_protocol("publishedArtifactPayload"))?;
        output
            .write_all(bytes)
            .and_then(|()| output.sync_all())
            .map_err(|_| unavailable_protocol("publishedArtifactPayload"))?;
        validate_payload(&temporary, expected_len, expected_digest)?;
        match fs::hard_link(&temporary, destination) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_payload(destination, expected_len, expected_digest)?;
            }
            Err(_) => return Err(unavailable_protocol("publishedArtifactPayload")),
        }
        fs::remove_file(&temporary)
            .map_err(|_| unavailable_protocol("publishedArtifactPayload"))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| unavailable_protocol("publishedArtifactPayload"))
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
    let mut file =
        File::open(path).map_err(|_| unavailable_protocol("publishedArtifactPayload"))?;
    let mut hasher = blake3::Hasher::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| unavailable_protocol("publishedArtifactPayload"))?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(read as u64)
            .ok_or_else(|| unavailable_protocol("publishedArtifactPayload"))?;
        hasher.update(&buffer[..read]);
    }
    if length != expected_len
        || Digest::from_bytes(*hasher.finalize().as_bytes()) != expected_digest
    {
        return Err(unavailable_protocol("publishedArtifactPayload"));
    }
    Ok(())
}

pub(super) fn persist_published_record(
    root: &Path,
    record: &PublishedArtifactRecord,
) -> Result<(), HuginnProtocolError> {
    let path = root
        .join("records")
        .join(format!("{}.cbor", record.artifact.artifact_id.as_str()));
    let encoded = encode_content(record)?;
    if path
        .try_exists()
        .map_err(|_| unavailable_protocol("publishedArtifactRecord"))?
    {
        let existing: PublishedArtifactRecord = decode_content(
            &fs::read(path).map_err(|_| unavailable_protocol("publishedArtifactRecord"))?,
        )?;
        return if existing == *record {
            Ok(())
        } else {
            Err(HuginnProtocolError::Conflict {
                code: "publishedArtifactReuse".to_owned(),
                message: "artifact ID is already bound to another payload".to_owned(),
            })
        };
    }
    let parent = path
        .parent()
        .ok_or_else(|| unavailable_protocol("publishedArtifactRecord"))?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| unavailable_protocol("publishedArtifactRecord"))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| unavailable_protocol("publishedArtifactRecord"))?;
    fs::rename(&temporary, &path).map_err(|_| unavailable_protocol("publishedArtifactRecord"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| unavailable_protocol("publishedArtifactRecord"))
}

pub(super) fn payload_name(digest: Digest) -> Result<String, HuginnProtocolError> {
    let digest_text = digest.to_string();
    let digest_hex = digest_text
        .strip_prefix("blake3:")
        .ok_or_else(|| unavailable_protocol("publishedArtifactDigest"))?;
    Ok(format!("{digest_hex}.blob"))
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
    if !path
        .try_exists()
        .map_err(|_| unavailable_protocol("publishedArtifactRecord"))?
    {
        return Ok(None);
    }
    let record: PublishedArtifactRecord = decode_content(
        &fs::read(path).map_err(|_| unavailable_protocol("publishedArtifactRecord"))?,
    )?;
    if &record.artifact.artifact_id != artifact_id
        || record.payload_name != payload_name(record.artifact.content_digest)?
    {
        return Err(unavailable_protocol("publishedArtifactBinding"));
    }
    Ok(Some(record))
}

pub(super) fn delete_payload_if_unreferenced(
    root: &Path,
    candidate_payload_name: &str,
) -> Result<(), HuginnProtocolError> {
    let records = root.join("records");
    for entry in
        fs::read_dir(&records).map_err(|_| unavailable_protocol("publishedArtifactRecord"))?
    {
        let entry = entry.map_err(|_| unavailable_protocol("publishedArtifactRecord"))?;
        let path = entry.path();
        if path.extension() != Some(std::ffi::OsStr::new("cbor")) {
            continue;
        }
        if !entry
            .file_type()
            .map_err(|_| unavailable_protocol("publishedArtifactRecord"))?
            .is_file()
        {
            return Err(unavailable_protocol("publishedArtifactRecord"));
        }
        let record: PublishedArtifactRecord = decode_content(
            &fs::read(&path).map_err(|_| unavailable_protocol("publishedArtifactRecord"))?,
        )?;
        if published_record_path(root, &record.artifact.artifact_id) != path
            || record.payload_name != payload_name(record.artifact.content_digest)?
        {
            return Err(unavailable_protocol("publishedArtifactBinding"));
        }
        if record.payload_name == candidate_payload_name {
            return Ok(());
        }
    }
    let payloads = root.join("payloads");
    match fs::remove_file(payloads.join(candidate_payload_name)) {
        Ok(()) => File::open(payloads)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| unavailable_protocol("publishedArtifactPayload")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(unavailable_protocol("publishedArtifactPayload")),
    }
}

pub(super) fn retire_published_record(
    root: &Path,
    record: &PublishedArtifactRecord,
) -> Result<(), HuginnProtocolError> {
    let records = root.join("records");
    let path = published_record_path(root, &record.artifact.artifact_id);
    if let Some(existing) = read_published_record(root, &record.artifact.artifact_id)? {
        if existing != *record {
            return Err(unavailable_protocol("publishedArtifactBinding"));
        }
        fs::remove_file(path).map_err(|_| unavailable_protocol("publishedArtifactRecord"))?;
        File::open(records)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| unavailable_protocol("publishedArtifactRecord"))?;
    }
    delete_payload_if_unreferenced(root, &record.payload_name)
}

pub(super) fn remove_stale_publication_temporaries(root: &Path) -> Result<(), HuginnProtocolError> {
    for directory_name in ["records", "payloads", "browser-pointers"] {
        let directory = root.join(directory_name);
        let mut removed = false;
        for entry in fs::read_dir(&directory)
            .map_err(|_| unavailable_protocol("publishedArtifactRecovery"))?
        {
            let entry = entry.map_err(|_| unavailable_protocol("publishedArtifactRecovery"))?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| unavailable_protocol("publishedArtifactRecovery"))?;
            if name.starts_with('.') && name.ends_with(".tmp") {
                if !entry
                    .file_type()
                    .map_err(|_| unavailable_protocol("publishedArtifactRecovery"))?
                    .is_file()
                {
                    return Err(unavailable_protocol("publishedArtifactRecovery"));
                }
                fs::remove_file(entry.path())
                    .map_err(|_| unavailable_protocol("publishedArtifactRecovery"))?;
                removed = true;
            }
        }
        if removed {
            File::open(directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| unavailable_protocol("publishedArtifactRecovery"))?;
        }
    }
    Ok(())
}
