//! Framed, append-only, crash-tolerant segment journals.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, IoSlice, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

pub const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RECORD_BYTES: u32 = 4 * 1024 * 1024;
const FRAME_HEADER_BYTES: usize = 4;
const FRAME_DIGEST_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum SegmentError {
    #[error("segment path {0:?} is not a numbered segment file")]
    UnknownName(PathBuf),
    #[error("record at byte {offset} is corrupt: {reason}")]
    Corrupt { offset: u64, reason: String },
    #[error("record of {size} bytes exceeds the {limit} byte ceiling")]
    RecordTooLarge { size: u64, limit: u32 },
    #[error("single-file journals cannot rotate")]
    RotateUnsupported,
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Clone, Debug)]
pub enum SegmentLayout {
    Numbered { dir: PathBuf, prefix: &'static str },
    Single { path: PathBuf },
}

impl SegmentLayout {
    fn path(&self, index: u64) -> PathBuf {
        match self {
            Self::Numbered { dir, prefix } => dir.join(format!("{prefix}-{index:08}.seg")),
            Self::Single { path } => path.clone(),
        }
    }

    /// Crate-visible indexed lookup for direct ordinal seeks.
    pub(crate) fn nth_path(&self, index: u64) -> PathBuf {
        self.path(index)
    }

    fn dir(&self) -> Option<&Path> {
        match self {
            Self::Numbered { dir, .. } => Some(dir),
            Self::Single { path } => path.parent(),
        }
    }

    fn ensure_parent(&self) -> io::Result<()> {
        match self {
            Self::Numbered { dir, .. } => fs::create_dir_all(dir),
            Self::Single { path } => path.parent().map_or(Ok(()), fs::create_dir_all),
        }
    }
}

pub struct SegmentWriter {
    layout: SegmentLayout,
    index: u64,
    file: File,
    written: u64,
    /// The file's directory entry is not proven durable yet: the next commit
    /// fsyncs the directories before it succeeds (a failed fsync stays owed).
    entry_unsynced: bool,
}

impl SegmentWriter {
    pub fn create(layout: SegmentLayout) -> Result<Self, SegmentError> {
        layout.ensure_parent()?;
        let path = layout.path(0);
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)?;
        Ok(Self {
            layout,
            index: 0,
            file,
            written: 0,
            entry_unsynced: true,
        })
    }

    pub fn resume(layout: SegmentLayout) -> Result<Self, SegmentError> {
        layout.ensure_parent()?;
        let index = match &layout {
            SegmentLayout::Numbered { dir, prefix } => numbered_paths(dir, prefix)?
                .last()
                .map_or(0, |(index, _)| *index),
            SegmentLayout::Single { .. } => 0,
        };
        let path = layout.path(index);
        let existed = path.exists();
        let valid_bytes = if existed {
            SegmentReader::validated_len(&path)?.1
        } else {
            0
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        if file.metadata()?.len() != valid_bytes {
            file.set_len(valid_bytes)?;
            file.sync_data()?;
        }
        // An existing file's entry may be one an earlier writer created and
        // failed to fsync: every resumed writer proves it again.
        let mut writer = Self {
            layout,
            index,
            file,
            written: valid_bytes,
            entry_unsynced: true,
        };
        if writer.written >= MAX_SEGMENT_BYTES
            && matches!(&writer.layout, SegmentLayout::Numbered { .. })
        {
            writer.rotate()?;
        }
        Ok(writer)
    }

    /// Whether the open file is still the one its path names: a segment
    /// moved or replaced behind the writer is resumed from disk instead.
    pub fn is_current(&self) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        match (
            fs::metadata(self.layout.path(self.index)),
            self.file.metadata(),
        ) {
            (Ok(named), Ok(open)) => named.dev() == open.dev() && named.ino() == open.ino(),
            _ => false,
        }
    }

    pub(crate) const fn index(&self) -> u64 {
        self.index
    }

    pub(crate) const fn written(&self) -> u64 {
        self.written
    }

    pub fn append(&mut self, record: &[u8]) -> Result<(), SegmentError> {
        let size = u64::try_from(record.len()).map_err(|_| SegmentError::RecordTooLarge {
            size: u64::MAX,
            limit: MAX_RECORD_BYTES,
        })?;
        if size == 0 || size > u64::from(MAX_RECORD_BYTES) {
            return Err(SegmentError::RecordTooLarge {
                size,
                limit: MAX_RECORD_BYTES,
            });
        }
        let length = u32::try_from(record.len()).map_err(|_| SegmentError::RecordTooLarge {
            size,
            limit: MAX_RECORD_BYTES,
        })?;
        let header = length.to_le_bytes();
        let digest = blake3::hash(record);
        let mut slices = [
            IoSlice::new(&header),
            IoSlice::new(record),
            IoSlice::new(digest.as_bytes()),
        ];
        // One writev: header, payload, and digest share a syscall.
        // `write_all_vectored` is still unstable (rust#70436); the stable
        // `write_vectored` loop is what it expands to, and a short write
        // retries the tail so the frame bytes stay identical.
        let mut bufs: &mut [IoSlice<'_>] = &mut slices;
        while !bufs.is_empty() {
            match self.file.write_vectored(bufs) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    )
                    .into());
                }
                Ok(written) => IoSlice::advance_slices(&mut bufs, written),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.written = self
            .written
            .checked_add(size + (FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES) as u64)
            .ok_or(SegmentError::RecordTooLarge {
                size: u64::MAX,
                limit: MAX_RECORD_BYTES,
            })?;
        if self.written >= MAX_SEGMENT_BYTES {
            match &self.layout {
                SegmentLayout::Numbered { .. } => self.rotate()?,
                SegmentLayout::Single { .. } => self.commit()?,
            }
        }
        Ok(())
    }

    pub fn commit(&mut self) -> Result<(), SegmentError> {
        self.file.flush()?;
        self.file.sync_data()?;
        if self.entry_unsynced {
            // The file's entry, and its directory's, must outlive a power
            // loss as surely as the frames committed into it.
            if let Some(dir) = self.layout.dir() {
                sync_dir(dir)?;
                if let Some(parent) = dir.parent() {
                    sync_dir(parent)?;
                }
            }
            self.entry_unsynced = false;
        }
        Ok(())
    }

    pub fn rotate(&mut self) -> Result<(), SegmentError> {
        if matches!(&self.layout, SegmentLayout::Single { .. }) {
            return Err(SegmentError::RotateUnsupported);
        }
        self.commit()?;
        self.index = self.index.checked_add(1).ok_or(SegmentError::Corrupt {
            offset: self.written,
            reason: "segment index exhausted".to_owned(),
        })?;
        let path = self.layout.path(self.index);
        self.file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)?;
        self.entry_unsynced = true;
        self.written = 0;
        Ok(())
    }
}

pub struct SegmentReader;

impl SegmentReader {
    /// The numbered segments of a `Numbered` layout as `(index, path)`
    /// pairs in durable order; a `Single` layout has no numbering.
    pub fn numbered(layout: &SegmentLayout) -> Result<Vec<(u64, PathBuf)>, SegmentError> {
        Ok(match layout {
            SegmentLayout::Numbered { dir, prefix } => numbered_paths(dir, prefix)?,
            SegmentLayout::Single { .. } => Vec::new(),
        })
    }

    pub fn scan(layout: &SegmentLayout) -> Result<Vec<Vec<u8>>, SegmentError> {
        let paths = match layout {
            SegmentLayout::Numbered { dir, prefix } => numbered_paths(dir, prefix)?
                .into_iter()
                .map(|(_, path)| path)
                .collect::<Vec<_>>(),
            SegmentLayout::Single { path } if path.exists() => vec![path.clone()],
            SegmentLayout::Single { .. } => Vec::new(),
        };
        let mut records = Vec::new();
        for path in paths {
            records.extend(Self::scan_file(&path)?.0);
        }
        Ok(records)
    }

    /// Valid frame count and byte length. Hashes each frame into one reused
    /// buffer and drops it: resume only needs the torn-tail boundary, not
    /// the payloads `scan_file` would retain.
    pub(crate) fn validated_len(path: &Path) -> Result<(u64, u64), SegmentError> {
        let mut frames = Self::frames(path)?;
        while frames.next_frame()?.is_some() {}
        Ok((frames.count, frames.valid_bytes))
    }

    /// Opens a streaming reader. The caller decodes one frame at a time;
    /// the payload buffer is reused, so a journal load does not hold every
    /// raw frame beside the decoded value.
    pub(crate) fn frames(path: &Path) -> Result<FrameReader, SegmentError> {
        FrameReader::open(path)
    }

    pub(crate) fn frames_at(path: &Path, offset: u64) -> Result<FrameReader, SegmentError> {
        FrameReader::open_at(path, offset)
    }

    pub fn scan_file(path: &Path) -> Result<(Vec<Vec<u8>>, u64), SegmentError> {
        let mut frames = Self::frames(path)?;
        let mut records = Vec::new();
        while let Some(record) = frames.next_frame()? {
            records.push(record.to_vec());
        }
        Ok((records, frames.valid_bytes))
    }
}

/// One segment, read frame by frame. Stop rules match `scan_file`: a torn
/// or corrupt tail ends the stream and is not part of `valid_bytes`.
pub(crate) struct FrameReader {
    reader: BufReader<File>,
    buffer: Vec<u8>,
    /// Next byte to read. Not a durable boundary until the frame verifies.
    offset: u64,
    valid_bytes: u64,
    count: u64,
}

impl FrameReader {
    fn open(path: &Path) -> Result<Self, SegmentError> {
        Self::open_at(path, 0)
    }

    fn open_at(path: &Path, offset: u64) -> Result<Self, SegmentError> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        Ok(Self {
            reader: BufReader::with_capacity(64 * 1024, file),
            buffer: Vec::new(),
            offset,
            valid_bytes: offset,
            count: 0,
        })
    }

    pub(crate) const fn valid_bytes(&self) -> u64 {
        self.valid_bytes
    }

    pub(crate) const fn offset(&self) -> u64 {
        self.offset
    }

    pub(crate) fn next_frame(&mut self) -> Result<Option<&[u8]>, SegmentError> {
        let mut header = [0u8; FRAME_HEADER_BYTES];
        match read_exact_or_eof(&mut self.reader, &mut header)? {
            ReadState::Eof | ReadState::Torn => return Ok(None),
            ReadState::Complete => {}
        }
        self.bump(FRAME_HEADER_BYTES as u64)?;
        let length = u32::from_le_bytes(header);
        if length == 0 || length > MAX_RECORD_BYTES {
            return Ok(None);
        }
        let length = length as usize;
        self.buffer.resize(length, 0);
        if !matches!(
            read_exact_or_eof(&mut self.reader, &mut self.buffer)?,
            ReadState::Complete
        ) {
            return Ok(None);
        }
        self.bump(length as u64)?;
        let mut digest = [0u8; FRAME_DIGEST_BYTES];
        if !matches!(
            read_exact_or_eof(&mut self.reader, &mut digest)?,
            ReadState::Complete
        ) {
            return Ok(None);
        }
        self.bump(FRAME_DIGEST_BYTES as u64)?;
        if blake3::hash(&self.buffer).as_bytes() != &digest {
            return Ok(None);
        }
        self.valid_bytes = self.offset;
        self.count = self.count.saturating_add(1);
        Ok(Some(self.buffer.as_slice()))
    }

    fn bump(&mut self, bytes: u64) -> Result<(), SegmentError> {
        self.offset = self
            .offset
            .checked_add(bytes)
            .ok_or(SegmentError::Corrupt {
                offset: self.valid_bytes,
                reason: "journal byte offset overflow".to_owned(),
            })?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ReadState {
    Complete,
    Eof,
    Torn,
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn read_exact_or_eof(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<ReadState> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..])? {
            0 if filled == 0 => return Ok(ReadState::Eof),
            0 => return Ok(ReadState::Torn),
            read => filled += read,
        }
    }
    Ok(ReadState::Complete)
}

fn numbered_paths(dir: &Path, prefix: &str) -> Result<Vec<(u64, PathBuf)>, SegmentError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let stem_prefix = format!("{prefix}-");
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&stem_prefix) || !name.ends_with(".seg") {
            continue;
        }
        let raw = &name[stem_prefix.len()..name.len() - 4];
        let index = raw
            .parse::<u64>()
            .map_err(|_| SegmentError::UnknownName(entry.path()))?;
        paths.push((index, entry.path()));
    }
    paths.sort_by_key(|(index, _)| *index);
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "odin-segment-{label}-{}-{nanos}.seg",
            std::process::id()
        ))
    }

    #[test]
    fn append_writes_length_payload_and_digest_as_one_frame() {
        let path = temp_path("frame");
        let layout = SegmentLayout::Single { path: path.clone() };
        let mut writer = SegmentWriter::create(layout).expect("create");
        let payload = b"journal-frame";
        writer.append(payload).expect("append");
        writer.commit().expect("commit");
        drop(writer);

        let bytes = fs::read(&path).expect("read frame");
        let mut expected = Vec::new();
        expected.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        expected.extend_from_slice(payload);
        expected.extend_from_slice(blake3::hash(payload).as_bytes());
        assert_eq!(bytes, expected, "vectored write must keep the frame layout");
        let (records, valid) = SegmentReader::scan_file(&path).expect("scan");
        assert_eq!(records, vec![payload.to_vec()]);
        assert_eq!(valid, expected.len() as u64);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn validated_len_matches_scan_file_including_a_torn_tail() {
        let path = temp_path("torn");
        let layout = SegmentLayout::Single { path: path.clone() };
        let mut writer = SegmentWriter::create(layout).expect("create");
        writer.append(b"one").expect("frame");
        writer.append(b"two").expect("frame");
        writer.commit().expect("commit");
        drop(writer);
        let mut bytes = fs::read(&path).expect("read");
        let intact = bytes.len() as u64;
        bytes.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);
        fs::write(&path, &bytes).expect("tear tail");

        let (records, scanned) = SegmentReader::scan_file(&path).expect("scan");
        let (count, validated) = SegmentReader::validated_len(&path).expect("length");
        assert_eq!(records.len() as u64, count);
        assert_eq!(scanned, validated);
        assert_eq!(validated, intact, "the torn tail is not a valid prefix");
        assert_eq!(records, vec![b"one".to_vec(), b"two".to_vec()]);
        let _ = fs::remove_file(&path);
    }
}
