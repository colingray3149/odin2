use super::*;

use crate::frames::{RpcFrameDecoder, RpcProtocolVersion};

mod checkpoint;
mod classification;
#[cfg(unix)]
mod config;
#[cfg(unix)]
mod confirmation;
#[cfg(unix)]
mod context_epoch;
mod correlation;
#[cfg(unix)]
mod epoch_binding;
mod evidence;
#[cfg(unix)]
mod fixture;
#[cfg(unix)]
mod parked_resume;
#[cfg(unix)]
mod prompt_open_loop;
mod recovery;
#[cfg(unix)]
mod remote_launch;
mod resume;
#[cfg(unix)]
mod rollover_fresh;
mod side_channel;
#[cfg(unix)]
mod startup;
#[cfg(unix)]
mod stop_disposition;

/// Decodes one complete v1 frame through the real decoder boundary.
fn decode(line: &[u8]) -> DecodedRpcFrame {
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V1);
    decoder
        .push_physical_line(line)
        .expect("frame decodes")
        .expect("complete frame")
}

fn command_id(text: &str) -> CommandId {
    CommandId::new(text).expect("command id satisfies the domain grammar")
}

#[test]
fn trusted_extension_identity_is_exact_and_unambiguous() {
    assert_eq!(trusted_extension_from_args(&[]), None);
    assert_eq!(
        trusted_extension_from_args(&["--no-skills".to_owned()]),
        None
    );
    let space_form = vec![
        "--trusted-extension".to_owned(),
        "/nix/store/aaa-odin-extension/index.ts".to_owned(),
        "--no-skills".to_owned(),
    ];
    assert_eq!(
        trusted_extension_from_args(&space_form),
        Some("/nix/store/aaa-odin-extension/index.ts".to_owned())
    );
    let equals_form = vec!["--trusted-extension=/nix/store/bbb/index.ts".to_owned()];
    assert_eq!(
        trusted_extension_from_args(&equals_form),
        Some("/nix/store/bbb/index.ts".to_owned())
    );
    // A second selection is ambiguity, never a guess.
    let two = vec![
        "--trusted-extension".to_owned(),
        "/nix/store/aaa/index.ts".to_owned(),
        "--trusted-extension".to_owned(),
        "/nix/store/bbb/index.ts".to_owned(),
    ];
    assert_eq!(trusted_extension_from_args(&two), None);
    // A dangling flag names no artifact.
    let dangling = vec!["--no-skills".to_owned(), "--trusted-extension".to_owned()];
    assert_eq!(trusted_extension_from_args(&dangling), None);
}
