use super::{fixture_spec, recovery_launch_for, write_fixture};
use crate::frames::MAX_FRAME_BYTES;
use crate::process::streams::{read_physical_line, PhysicalLine, PhysicalLineState};
use crate::process::{OmpLifecycleState, OmpProcess, OmpProcessError};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::time::timeout;

#[tokio::test]
async fn bounded_line_reader_reads_exact_physical_frames() {
    // Every terminated frame retains its newline: the decoder requires it.
    let mut reader: &[u8] = b"first\n\nsecond\n";
    let mut state = PhysicalLineState::default();
    assert_eq!(
        read_physical_line(&mut reader, &mut state).await.unwrap(),
        Some(PhysicalLine::Terminated(b"first\n".to_vec()))
    );
    assert_eq!(
        read_physical_line(&mut reader, &mut state).await.unwrap(),
        Some(PhysicalLine::Terminated(b"\n".to_vec()))
    );
    assert_eq!(
        read_physical_line(&mut reader, &mut state).await.unwrap(),
        Some(PhysicalLine::Terminated(b"second\n".to_vec()))
    );
    assert_eq!(
        read_physical_line(&mut reader, &mut state).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn cancelled_line_read_preserves_the_partial_frame() {
    let (mut writer, reader) = tokio::io::duplex(64);
    let mut reader = BufReader::new(reader);
    let mut state = PhysicalLineState::default();
    writer.write_all(b"{\"partial").await.unwrap();
    // The read consumes the prefix and then pends; the timeout cancels it
    // there, and the accumulated prefix must survive in the state.
    let cancelled = timeout(
        Duration::from_millis(50),
        read_physical_line(&mut reader, &mut state),
    )
    .await;
    assert!(cancelled.is_err(), "the read pends mid-frame and times out");
    writer.write_all(b"\":1}\n").await.unwrap();
    let line = timeout(
        Duration::from_secs(5),
        read_physical_line(&mut reader, &mut state),
    )
    .await
    .expect("the resumed read completes")
    .expect("the reader is healthy");
    assert_eq!(
        line,
        Some(PhysicalLine::Terminated(b"{\"partial\":1}\n".to_vec()))
    );
}

#[tokio::test]
async fn bounded_line_reader_enforces_physical_ceiling_exactly() {
    let mut stream = vec![b'x'; MAX_FRAME_BYTES - 1];
    stream.push(b'\n');
    let mut reader: &[u8] = stream.as_slice();
    let mut state = PhysicalLineState::default();
    assert_eq!(
        read_physical_line(&mut reader, &mut state).await.unwrap(),
        Some(PhysicalLine::Terminated(stream.clone()))
    );

    let mut stream = vec![b'x'; MAX_FRAME_BYTES];
    stream.push(b'\n');
    stream.extend_from_slice(b"ok\n");
    let mut reader: &[u8] = stream.as_slice();
    let mut state = PhysicalLineState::default();
    assert_eq!(
        read_physical_line(&mut reader, &mut state).await.unwrap(),
        Some(PhysicalLine::Oversized {
            size: MAX_FRAME_BYTES + 1,
            prefix: vec![b'x'; MAX_FRAME_BYTES],
        })
    );

    // The stream position stays sane after an oversized frame, and only
    // its exact in-ceiling prefix was retained.
    assert_eq!(
        read_physical_line(&mut reader, &mut state).await.unwrap(),
        Some(PhysicalLine::Terminated(b"ok\n".to_vec()))
    );
}

#[tokio::test]
async fn a_broken_stdin_leaves_ready() {
    let scratch = tempfile::tempdir().unwrap();
    let path = write_fixture(scratch.path(), "broken-stdin");
    let mut process = OmpProcess::new(
        fixture_spec(path.clone(), std::env::temp_dir()),
        recovery_launch_for(&path),
    );
    process.state = OmpLifecycleState::Ready;
    // The write fails with no stdin pipe and the pipe is discarded: a
    // half-written JSONL stream must not stay command-capable.
    let error = process
        .send_json(&json!({"type": "prompt"}))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, OmpProcessError::StdinBroken { detail } if detail.contains("closed")),
        "{error:?}"
    );
    assert_eq!(process.state(), OmpLifecycleState::Draining);
    let error = process
        .send_json(&json!({"type": "prompt"}))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        OmpProcessError::InvalidTransition {
            operation: "send_json",
            from: OmpLifecycleState::Draining
        }
    ));
}
