use super::{fixture_spec, recovery_launch_for, write_fixture};
use crate::frames::{RpcFrameDecoder, RpcFrameErrorKind, RpcProtocolVersion, MAX_FRAME_BYTES};
use crate::process::streams::{
    join_drainer, read_physical_line, PhysicalLine, PhysicalLineState, LINE_READ_CAPACITY,
};
use crate::process::{OmpLifecycleState, OmpProcess, OmpProcessError};
use serde_json::json;
use std::fs;
use std::time::{Duration, Instant};
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
async fn exact_ceiling_unterminated_tail_is_preserved() {
    // Exactly MAX_FRAME_BYTES of non-newline input fits the ceiling: EOF
    // retains it as unterminated evidence rather than reporting oversized.
    let stream = vec![b'x'; MAX_FRAME_BYTES];
    let mut reader: &[u8] = stream.as_slice();
    let mut state = PhysicalLineState::default();
    assert_eq!(
        read_physical_line(&mut reader, &mut state).await.unwrap(),
        Some(PhysicalLine::Unterminated(stream.clone()))
    );
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V1);
    let error = decoder.push_physical_line(&stream).unwrap_err();
    assert_eq!(*error.kind(), RpcFrameErrorKind::MissingNewline);
    assert_eq!(error.evidence(), &[stream]);

    // A newline after an exact-ceiling payload is what makes the frame
    // oversized: the terminator itself crosses the ceiling.
    let mut stream = vec![b'x'; MAX_FRAME_BYTES];
    stream.push(b'\n');
    let mut reader: &[u8] = stream.as_slice();
    let mut state = PhysicalLineState::default();
    assert_eq!(
        read_physical_line(&mut reader, &mut state).await.unwrap(),
        Some(PhysicalLine::Oversized {
            size: MAX_FRAME_BYTES + 1,
            prefix: vec![b'x'; MAX_FRAME_BYTES],
        })
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

/// A line that fills the read buffer must not donate that capacity to later
/// frames. Evidence and drain budgets charge `len`; a 64 KiB spare per frame
/// is invisible to them. Measurement: the published short line's capacity and
/// the warm accumulator's pointer, not a timer.
#[tokio::test]
async fn published_lines_do_not_keep_the_warm_read_buffer() {
    let mut stream = vec![b'x'; LINE_READ_CAPACITY - 1];
    stream.push(b'\n');
    let short_bytes: &[u8] = b"{\"a\":1}\n";
    stream.extend_from_slice(short_bytes);
    let mut reader: &[u8] = stream.as_slice();
    let mut state = PhysicalLineState::default();

    let read = read_physical_line(&mut reader, &mut state)
        .await
        .unwrap()
        .expect("long line");
    let PhysicalLine::Terminated(long) = read else {
        panic!("long line terminated");
    };
    assert_eq!(long.len(), LINE_READ_CAPACITY);
    assert!(
        long.capacity() <= long.len().saturating_add(4096),
        "published line kept a grown spare: capacity {}",
        long.capacity()
    );
    let warm = state.accumulator_ptr();
    assert!(
        state.retained_capacity() >= LINE_READ_CAPACITY,
        "warm accumulator dropped its capacity: {}",
        state.retained_capacity()
    );

    let read = read_physical_line(&mut reader, &mut state)
        .await
        .unwrap()
        .expect("short line");
    let PhysicalLine::Terminated(short) = read else {
        panic!("short line terminated");
    };
    assert_eq!(short, short_bytes);
    assert!(
        short.capacity() < 1024,
        "short frame kept the warm read buffer: capacity {}",
        short.capacity()
    );
    assert_eq!(
        state.accumulator_ptr(),
        warm,
        "take_line replaced the warm accumulator"
    );
    assert!(
        state.retained_capacity() >= LINE_READ_CAPACITY,
        "warm accumulator was moved into the frame: capacity {}",
        state.retained_capacity()
    );

    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V1);
    let frame = decoder
        .push_owned_line(short)
        .expect("short json decodes")
        .expect("short json completes a frame");
    assert!(
        frame.lines()[0].capacity() < 1024,
        "evidence kept the warm read buffer: capacity {}",
        frame.lines()[0].capacity()
    );
}

#[tokio::test]
async fn bounded_line_reader_reports_unterminated_tail() {
    let mut reader: &[u8] = b"trailing";
    let mut state = PhysicalLineState::default();
    assert_eq!(
        read_physical_line(&mut reader, &mut state).await.unwrap(),
        Some(PhysicalLine::Unterminated(b"trailing".to_vec()))
    );
    let mut reader: &[u8] = b"";
    let mut state = PhysicalLineState::default();
    assert_eq!(
        read_physical_line(&mut reader, &mut state).await.unwrap(),
        None
    );

    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V1);
    let error = decoder.push_physical_line(b"trailing").unwrap_err();
    assert!(matches!(error.kind(), RpcFrameErrorKind::MissingNewline));
    assert_eq!(error.evidence(), &[b"trailing".to_vec()]);
}

#[tokio::test]
async fn a_broken_stdin_leaves_ready() {
    let path = write_fixture("broken-stdin");
    let mut process = OmpProcess::new(
        fixture_spec(path.clone(), std::env::temp_dir()),
        recovery_launch_for(&path),
    );
    process.state = OmpLifecycleState::Ready(RpcProtocolVersion::V1);
    // The write fails with no stdin pipe and the pipe is discarded: a
    // half-written JSONL stream must not stay command-capable.
    let error = process
        .send_json(&json!({"type": "prompt"}))
        .await
        .unwrap_err();
    assert!(matches!(error, OmpProcessError::StdinBroken { .. }));
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
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn drainer_join_is_bounded_and_aborts() {
    // A drainer whose writer never closes pends forever; the join must
    // abort it at the bound instead of awaiting it.
    let stuck = tokio::spawn(async {
        std::future::pending::<()>().await;
    });
    let started = Instant::now();
    join_drainer(stuck, Duration::from_millis(50)).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "a stuck drainer is aborted at the bound"
    );
}
