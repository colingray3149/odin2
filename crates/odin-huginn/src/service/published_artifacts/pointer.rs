use std::collections::{HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use odin_domain::huginn::{ArtifactKind, BrowserSessionId, HuginnProtocolError};
use odin_domain::{ArtifactId, Digest};
use serde::{Deserialize, Serialize};

use crate::service::{decode_content, encode_content};

use super::publication::{
    delete_payload_if_unreferenced, payload_name, persist_payload_bytes, persist_published_record,
    read_published_record, remove_stale_publication_temporaries, retire_published_record,
    PayloadRefs,
};
use super::retirement::BrowserArtifactTracker;
use super::{
    browser_retirement_resource_limit, BrowserArtifactKind, BrowserArtifactRetirement,
    PublishedArtifactRecord, BROWSER_FRAME_RETENTION_CAPACITY, BROWSER_RETIREMENT_BACKLOG_CAPACITY,
    BROWSER_TIMELINE_RETENTION_CAPACITY,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BrowserArtifactPointer {
    pub(super) browser_session: BrowserSessionId,
    pub(super) kind: BrowserArtifactKind,
    pub(super) retained: VecDeque<PublishedArtifactRecord>,
    #[serde(default)]
    pub(super) awaiting_projection: VecDeque<PublishedArtifactRecord>,
    pub(super) pending: Option<PublishedArtifactRecord>,
    pub(super) retiring: VecDeque<PublishedArtifactRecord>,
}

fn browser_pointer_path(
    root: &Path,
    browser_session: BrowserSessionId,
    kind: BrowserArtifactKind,
) -> Result<PathBuf, HuginnProtocolError> {
    let identity = serde_json::to_vec(&("browser-pointer", browser_session, kind))
        .map_err(|error| HuginnProtocolError::unavailable("publishedArtifactPointer", error))?;
    Ok(root
        .join("browser-pointers")
        .join(format!("{}.cbor", Digest::hash(&identity).hex())))
}

fn browser_retention_capacity(kind: BrowserArtifactKind) -> Result<usize, HuginnProtocolError> {
    match kind {
        BrowserArtifactKind::Frame => Ok(BROWSER_FRAME_RETENTION_CAPACITY),
        BrowserArtifactKind::Timeline => Ok(BROWSER_TIMELINE_RETENTION_CAPACITY),
        BrowserArtifactKind::Screenshot | BrowserArtifactKind::Download => {
            Err(HuginnProtocolError::unavailable(
                "publishedArtifactPointer",
                format!("{kind:?} artifacts have no browser pointer"),
            ))
        }
    }
}
fn browser_pointer_retirement_backlog_len(
    pointer: &BrowserArtifactPointer,
) -> Result<usize, HuginnProtocolError> {
    pointer
        .retiring
        .len()
        .checked_add(pointer.awaiting_projection.len())
        .ok_or_else(|| {
            HuginnProtocolError::unavailable(
                "publishedArtifactPointer",
                "the retirement backlog length overflows",
            )
        })
}

fn validate_browser_pointer(pointer: &BrowserArtifactPointer) -> Result<(), HuginnProtocolError> {
    validate_browser_pointer_records(pointer)?;
    let capacity = browser_retention_capacity(pointer.kind)?;
    if pointer.retained.len() > capacity
        || pointer.awaiting_projection.len() > capacity
        || browser_pointer_retirement_backlog_len(pointer)? > BROWSER_RETIREMENT_BACKLOG_CAPACITY
        || (pointer.pending.is_some() && !pointer.awaiting_projection.is_empty())
    {
        return Err(HuginnProtocolError::unavailable(
            "publishedArtifactPointer",
            "the pointer exceeds its capacity or holds a pending record beside unprojected ones",
        ));
    }
    Ok(())
}

fn validate_browser_pointer_records(
    pointer: &BrowserArtifactPointer,
) -> Result<(), HuginnProtocolError> {
    browser_retention_capacity(pointer.kind)?;
    if pointer.kind != BrowserArtifactKind::Timeline && !pointer.awaiting_projection.is_empty() {
        return Err(HuginnProtocolError::unavailable(
            "publishedArtifactPointer",
            format!(
                "a {:?} pointer holds records awaiting projection",
                pointer.kind
            ),
        ));
    }
    let mut durable_ids = HashSet::with_capacity(
        pointer
            .retained
            .len()
            .saturating_add(pointer.awaiting_projection.len())
            .saturating_add(pointer.retiring.len())
            .saturating_add(if pointer.pending.is_some() { 1 } else { 0 }),
    );
    for record in pointer
        .retained
        .iter()
        .chain(pointer.awaiting_projection.iter())
        .chain(pointer.retiring.iter())
    {
        validate_browser_record(pointer.browser_session, pointer.kind, record)?;
        if !durable_ids.insert(record.artifact.artifact_id.as_str()) {
            return Err(HuginnProtocolError::unavailable(
                "publishedArtifactPointer",
                format!(
                    "the pointer lists artifact {} twice",
                    record.artifact.artifact_id
                ),
            ));
        }
    }
    if let Some(pending) = pointer.pending.as_ref() {
        validate_browser_record(pointer.browser_session, pointer.kind, pending)?;
        if !durable_ids.insert(pending.artifact.artifact_id.as_str()) {
            return Err(HuginnProtocolError::unavailable(
                "publishedArtifactPointer",
                format!(
                    "pending artifact {} is already listed",
                    pending.artifact.artifact_id
                ),
            ));
        }
    }
    Ok(())
}

fn validate_browser_record(
    browser_session: BrowserSessionId,
    browser_kind: BrowserArtifactKind,
    record: &PublishedArtifactRecord,
) -> Result<(), HuginnProtocolError> {
    let expected_kind = match browser_kind {
        BrowserArtifactKind::Frame => {
            ArtifactKind::Render(odin_domain::huginn::RenderKind::RasterImage)
        }
        BrowserArtifactKind::Timeline => ArtifactKind::File,
        BrowserArtifactKind::Screenshot | BrowserArtifactKind::Download => {
            return Err(HuginnProtocolError::unavailable(
                "publishedArtifactBinding",
                format!("{browser_kind:?} artifacts have no browser pointer"),
            ));
        }
    };
    if record.artifact.kind != expected_kind {
        return Err(HuginnProtocolError::unavailable(
            "publishedArtifactBinding",
            format!(
                "artifact {} is {:?}, expected {expected_kind:?}",
                record.artifact.artifact_id, record.artifact.kind
            ),
        ));
    }
    if record.payload_name != payload_name(record.artifact.content_digest) {
        return Err(HuginnProtocolError::unavailable(
            "publishedArtifactBinding",
            format!(
                "artifact {} payload {} does not match its digest",
                record.artifact.artifact_id, record.payload_name
            ),
        ));
    }
    let identity = serde_json::to_vec(&(
        "browser",
        browser_session,
        browser_kind,
        record.artifact.kind,
        &record.artifact.display_name,
        &record.artifact.media_type,
        record.artifact.byte_len,
        record.artifact.content_digest,
    ))
    .map_err(|error| HuginnProtocolError::unavailable("publishedArtifactBinding", error))?;
    let identity_hex = Digest::hash(&identity).hex();
    let expected = ArtifactId::new(format!("artifact:huginn:{identity_hex}"))
        .map_err(|error| HuginnProtocolError::unavailable("publishedArtifactBinding", error))?;
    if record.artifact.artifact_id != expected {
        return Err(HuginnProtocolError::unavailable(
            "publishedArtifactBinding",
            format!(
                "artifact {} does not match its browser identity {expected}",
                record.artifact.artifact_id
            ),
        ));
    }
    Ok(())
}

pub(super) fn persist_browser_pointer(
    root: &Path,
    pointer: &BrowserArtifactPointer,
) -> Result<(), HuginnProtocolError> {
    validate_browser_pointer(pointer)?;
    let path = browser_pointer_path(root, pointer.browser_session, pointer.kind)?;
    let parent = path.parent().ok_or_else(|| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPointer",
            format!("{} has no parent", path.display()),
        )
    })?;
    let encoded = encode_content(pointer)?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary).map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactPointer",
                format!("creating {}: {error}", temporary.display()),
            )
        })?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactPointer",
                    format!("writing {}: {error}", temporary.display()),
                )
            })?;
        fs::rename(&temporary, &path).map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactPointer",
                format!("renaming into {}: {error}", path.display()),
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactPointer",
                    format!("syncing {}: {error}", parent.display()),
                )
            })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_browser_pointer(
    root: &Path,
    browser_session: BrowserSessionId,
    kind: BrowserArtifactKind,
) -> Result<(), HuginnProtocolError> {
    let path = browser_pointer_path(root, browser_session, kind)?;
    let parent = path.parent().ok_or_else(|| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPointer",
            format!("{} has no parent", path.display()),
        )
    })?;
    match fs::remove_file(&path) {
        Ok(()) => File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactPointer",
                    format!("syncing {}: {error}", parent.display()),
                )
            }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(HuginnProtocolError::unavailable(
            "publishedArtifactPointer",
            format!("removing {}: {error}", path.display()),
        )),
    }
}

pub(super) fn persist_or_remove_browser_pointer(
    root: &Path,
    pointer: &BrowserArtifactPointer,
) -> Result<(), HuginnProtocolError> {
    if pointer.retained.is_empty()
        && pointer.awaiting_projection.is_empty()
        && pointer.pending.is_none()
        && pointer.retiring.is_empty()
    {
        remove_browser_pointer(root, pointer.browser_session, pointer.kind)
    } else {
        persist_browser_pointer(root, pointer)
    }
}

fn enforce_browser_retention_capacity(
    pointer: &mut BrowserArtifactPointer,
) -> Result<Vec<PublishedArtifactRecord>, HuginnProtocolError> {
    let capacity = browser_retention_capacity(pointer.kind)?;
    let mut evicted = Vec::new();
    while pointer.retained.len() > capacity {
        if browser_pointer_retirement_backlog_len(pointer)? >= BROWSER_RETIREMENT_BACKLOG_CAPACITY {
            return Err(browser_retirement_resource_limit());
        }
        let record = pointer.retained.pop_front().ok_or_else(|| {
            HuginnProtocolError::unavailable(
                "publishedArtifactPointer",
                "the retained queue emptied while over capacity",
            )
        })?;
        match pointer.kind {
            BrowserArtifactKind::Frame => pointer.retiring.push_back(record.clone()),
            BrowserArtifactKind::Timeline => {
                pointer.awaiting_projection.push_back(record.clone());
            }
            BrowserArtifactKind::Screenshot | BrowserArtifactKind::Download => {
                return Err(HuginnProtocolError::unavailable(
                    "publishedArtifactPointer",
                    format!("{:?} artifacts have no browser pointer", pointer.kind),
                ));
            }
        }
        evicted.push(record);
    }
    if pointer.awaiting_projection.len() > capacity {
        return Err(HuginnProtocolError::unavailable(
            "browserTimelineAcknowledgement",
            "more timeline records await projection than the pointer retains",
        ));
    }
    Ok(evicted)
}

fn commit_pending_browser_record(
    pointer: &mut BrowserArtifactPointer,
) -> Result<Vec<PublishedArtifactRecord>, HuginnProtocolError> {
    let record = pointer.pending.take().ok_or_else(|| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPointer",
            "the pointer has no pending record to commit",
        )
    })?;
    pointer.retained.retain(|retained| retained != &record);
    pointer.retiring.retain(|retiring| retiring != &record);
    pointer
        .awaiting_projection
        .retain(|awaiting| awaiting != &record);
    pointer.retained.push_back(record);
    enforce_browser_retention_capacity(pointer)
}

fn finish_browser_retirements(
    root: &Path,
    refs: &mut PayloadRefs,
    pointer: &mut BrowserArtifactPointer,
) -> Result<(), HuginnProtocolError> {
    for retiring in &pointer.retiring {
        retire_published_record(root, refs, retiring)?;
    }
    pointer.retiring.clear();
    persist_or_remove_browser_pointer(root, pointer)
}

fn recover_browser_pointer(
    root: &Path,
    refs: &mut PayloadRefs,
    mut pointer: BrowserArtifactPointer,
) -> Result<Option<BrowserArtifactPointer>, HuginnProtocolError> {
    validate_browser_pointer_records(&pointer)?;
    if !pointer.retiring.is_empty() {
        finish_browser_retirements(root, refs, &mut pointer)?;
    }
    if let Some(pending) = pointer.pending.clone() {
        match read_published_record(root, &pending.artifact.artifact_id)? {
            Some(existing) => {
                if existing != pending {
                    return Err(HuginnProtocolError::unavailable(
                        "publishedArtifactBinding",
                        format!(
                            "pending artifact {} differs from its published record",
                            pending.artifact.artifact_id
                        ),
                    ));
                }
                commit_pending_browser_record(&mut pointer)?;
                persist_browser_pointer(root, &pointer)?;
            }
            None => {
                delete_payload_if_unreferenced(root, refs, &pending.payload_name)?;
                pointer.pending = None;
                enforce_browser_retention_capacity(&mut pointer)?;
                persist_or_remove_browser_pointer(root, &pointer)?;
            }
        }
    }
    if !enforce_browser_retention_capacity(&mut pointer)?.is_empty() {
        persist_browser_pointer(root, &pointer)?;
    }
    if pointer.kind == BrowserArtifactKind::Frame && !pointer.retained.is_empty() {
        pointer.retiring.append(&mut pointer.retained);
        persist_browser_pointer(root, &pointer)?;
    }
    if !pointer.retiring.is_empty() {
        finish_browser_retirements(root, refs, &mut pointer)?;
    }
    for retained in pointer
        .retained
        .iter()
        .chain(pointer.awaiting_projection.iter())
    {
        if read_published_record(root, &retained.artifact.artifact_id)?.as_ref() != Some(retained) {
            return Err(HuginnProtocolError::unavailable(
                "publishedArtifactBinding",
                format!(
                    "retained artifact {} differs from its published record",
                    retained.artifact.artifact_id
                ),
            ));
        }
    }
    if pointer.retained.is_empty() && pointer.awaiting_projection.is_empty() {
        persist_or_remove_browser_pointer(root, &pointer)?;
        Ok(None)
    } else {
        validate_browser_pointer(&pointer)?;
        Ok(Some(pointer))
    }
}

pub(super) fn read_browser_pointer(
    root: &Path,
    browser_session: BrowserSessionId,
    kind: BrowserArtifactKind,
) -> Result<Option<BrowserArtifactPointer>, HuginnProtocolError> {
    let path = browser_pointer_path(root, browser_session, kind)?;
    if !path.try_exists().map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPointer",
            format!("checking {}: {error}", path.display()),
        )
    })? {
        return Ok(None);
    }
    let pointer: BrowserArtifactPointer = decode_content(&fs::read(&path).map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPointer",
            format!("reading {}: {error}", path.display()),
        )
    })?)?;
    if pointer.browser_session != browser_session || pointer.kind != kind {
        return Err(HuginnProtocolError::unavailable(
            "publishedArtifactPointer",
            format!(
                "{} belongs to another browser session or kind",
                path.display()
            ),
        ));
    }
    validate_browser_pointer(&pointer)?;
    Ok(Some(pointer))
}

pub(super) fn load_browser_pointer(
    root: &Path,
    browser_session: BrowserSessionId,
    kind: BrowserArtifactKind,
) -> Result<Option<BrowserArtifactPointer>, HuginnProtocolError> {
    let Some(pointer) = read_browser_pointer(root, browser_session, kind)? else {
        return Ok(None);
    };
    if pointer.pending.is_some() {
        return Err(HuginnProtocolError::unavailable(
            "publishedArtifactPointer",
            "the pointer still holds a pending record",
        ));
    }
    for retained in pointer
        .retained
        .iter()
        .chain(pointer.awaiting_projection.iter())
    {
        if read_published_record(root, &retained.artifact.artifact_id)?.as_ref() != Some(retained) {
            return Err(HuginnProtocolError::unavailable(
                "publishedArtifactBinding",
                format!(
                    "retained artifact {} differs from its published record",
                    retained.artifact.artifact_id
                ),
            ));
        }
    }
    Ok(Some(pointer))
}

pub(super) fn replace_browser_artifact(
    root: &Path,
    refs: &mut PayloadRefs,
    browser_session: BrowserSessionId,
    kind: BrowserArtifactKind,
    record: &PublishedArtifactRecord,
    bytes: &[u8],
    tracker: &BrowserArtifactTracker,
) -> Result<Vec<PublishedArtifactRecord>, HuginnProtocolError> {
    let mut pointer =
        load_browser_pointer(root, browser_session, kind)?.unwrap_or(BrowserArtifactPointer {
            browser_session,
            kind,
            retained: VecDeque::new(),
            awaiting_projection: VecDeque::new(),
            pending: None,
            retiring: VecDeque::new(),
        });
    validate_browser_record(browser_session, kind, record)?;
    if pointer.retained.back() == Some(record) {
        persist_payload_bytes(
            bytes,
            &root.join("payloads").join(&record.payload_name),
            record.artifact.byte_len,
            record.artifact.content_digest,
        )?;
        persist_published_record(root, refs, record)?;
        return Ok(Vec::new());
    }
    if kind == BrowserArtifactKind::Timeline && !pointer.awaiting_projection.is_empty() {
        return Err(HuginnProtocolError::unavailable(
            "browserTimelineAcknowledgement",
            "timeline records still await projection",
        ));
    }

    let reservation = pointer
        .retained
        .front()
        .cloned()
        .map(|record| BrowserArtifactRetirement {
            browser_session,
            kind,
            record,
        });
    if let Some(reservation) = reservation.as_ref() {
        tracker.reserve_retirement(reservation)?;
    }
    let result = (|| {
        pointer.pending = Some(record.clone());
        persist_browser_pointer(root, &pointer)?;
        persist_payload_bytes(
            bytes,
            &root.join("payloads").join(&record.payload_name),
            record.artifact.byte_len,
            record.artifact.content_digest,
        )?;
        persist_published_record(root, refs, record)?;

        let retired = commit_pending_browser_record(&mut pointer)?;
        persist_browser_pointer(root, &pointer)?;
        Ok(retired)
    })();
    if result.is_err() {
        if let Some(reservation) = reservation.as_ref() {
            tracker.cancel_retirement_reservation(reservation)?;
        }
    }
    result
}

pub(super) fn retire_browser_pointer(
    root: &Path,
    browser_session: BrowserSessionId,
    kind: BrowserArtifactKind,
    tracker: &BrowserArtifactTracker,
) -> Result<Vec<PublishedArtifactRecord>, HuginnProtocolError> {
    let Some(mut pointer) = load_browser_pointer(root, browser_session, kind)? else {
        return Ok(Vec::new());
    };
    let retired = pointer.retained.iter().cloned().collect::<Vec<_>>();
    if browser_pointer_retirement_backlog_len(&pointer)?
        .checked_add(retired.len())
        .is_none_or(|backlog| backlog > BROWSER_RETIREMENT_BACKLOG_CAPACITY)
    {
        return Err(browser_retirement_resource_limit());
    }
    for record in &retired {
        tracker.reserve_retirement(&BrowserArtifactRetirement {
            browser_session,
            kind,
            record: record.clone(),
        })?;
    }
    pointer.retained.clear();
    pointer.retiring.extend(retired.iter().cloned());
    if let Err(error) = persist_or_remove_browser_pointer(root, &pointer) {
        for record in &retired {
            tracker.cancel_retirement_reservation(&BrowserArtifactRetirement {
                browser_session,
                kind,
                record: record.clone(),
            })?;
        }
        return Err(error);
    }
    Ok(retired)
}

pub(super) fn recover_browser_pointers(
    root: &Path,
    refs: &mut PayloadRefs,
) -> Result<Vec<BrowserArtifactRetirement>, HuginnProtocolError> {
    remove_stale_publication_temporaries(root)?;
    let pointers = root.join("browser-pointers");
    let mut retirements = Vec::with_capacity(BROWSER_RETIREMENT_BACKLOG_CAPACITY);
    for entry in fs::read_dir(&pointers).map_err(|error| {
        HuginnProtocolError::unavailable(
            "publishedArtifactPointer",
            format!("reading {}: {error}", pointers.display()),
        )
    })? {
        let entry = entry.map_err(|error| {
            HuginnProtocolError::unavailable(
                "publishedArtifactPointer",
                format!("reading {}: {error}", pointers.display()),
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
                    "publishedArtifactPointer",
                    format!("reading {}: {error}", path.display()),
                )
            })?
            .is_file()
        {
            return Err(HuginnProtocolError::unavailable(
                "publishedArtifactPointer",
                format!("{} is not a file", path.display()),
            ));
        }
        let pointer: BrowserArtifactPointer =
            decode_content(&fs::read(&path).map_err(|error| {
                HuginnProtocolError::unavailable(
                    "publishedArtifactPointer",
                    format!("reading {}: {error}", path.display()),
                )
            })?)?;
        if browser_pointer_path(root, pointer.browser_session, pointer.kind)? != path {
            return Err(HuginnProtocolError::unavailable(
                "publishedArtifactPointer",
                format!("{} does not match its pointer identity", path.display()),
            ));
        }
        if let Some(pointer) = recover_browser_pointer(root, refs, pointer)? {
            for record in pointer
                .retiring
                .iter()
                .chain(pointer.awaiting_projection.iter())
            {
                if retirements.len() >= BROWSER_RETIREMENT_BACKLOG_CAPACITY {
                    return Err(browser_retirement_resource_limit());
                }
                retirements.push(BrowserArtifactRetirement {
                    browser_session: pointer.browser_session,
                    kind: pointer.kind,
                    record: record.clone(),
                });
            }
        }
    }
    Ok(retirements)
}
