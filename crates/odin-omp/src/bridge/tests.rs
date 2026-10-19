use super::*;

use crate::frames::{RpcFrameDecoder, RpcFrameErrorKind, RpcProtocolVersion};
use crate::uri::{UriOperation, UriRequest, UriScheme};

mod checkpoint;
mod classification;
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

fn outcome(id: &str) -> SideChannelOutcome {
    SideChannelOutcome {
        request_id: id.to_owned(),
        kind: SideChannelKind::Tool,
        name: "tool".to_owned(),
        status: SideChannelStatus::Completed {
            result: json!({}),
            sent: true,
        },
    }
}

#[test]
fn streaming_behavior_uses_pinned_wire_literals() {
    assert_eq!(StreamingBehavior::Steer.as_str(), "steer");
    assert_eq!(StreamingBehavior::FollowUp.as_str(), "followUp");
}

#[test]
fn context_refusal_schema_is_strict_and_closed() {
    let frame = |error: &str| {
        json!({
            "type": "extension_error",
            "extensionPath": "/nix/store/trusted-odin-extension/index.ts",
            "event": "before_provider_request",
            "error": error,
        })
    };
    let valid = frame(
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":\"measured 9000 + input 2500 + reserve 500 = 12000 exceeds the declared window 10000\",\"request_bytes\":2500,\"input_tokens\":1800,\"window\":10000,\"reserve\":500}",
    );
    let refusal = parse_context_refusal(&valid).expect("the strict schema parses");
    assert_eq!(refusal.code, "window_exceeded");
    assert!(refusal.reason.contains("12000"));

    // Every one of these is data-shaped like a refusal but must fail the
    // strict schema closed: arbitrary provider/plugin error text can
    // never satisfy the contract by accident or by spoof.
    for error in [
        // no marker prefix at all
        "{\"code\":\"window_exceeded\",\"reason\":\"x\"}",
        // marker without the separator
        "odin.context_refusal.v1{\"code\":\"window_exceeded\",\"reason\":\"x\"}",
        // malformed JSON tail
        "odin.context_refusal.v1|not-json",
        // non-object tail
        "odin.context_refusal.v1|[1,2]",
        // unknown code, including a plausible future one
        "odin.context_refusal.v1|{\"code\":\"window_almost_exceeded\",\"reason\":\"x\"}",
        "odin.context_refusal.v1|{\"code\":\"\",\"reason\":\"x\"}",
        // missing or empty reason
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\"}",
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":\"\"}",
        // wrong field types
        "odin.context_refusal.v1|{\"code\":7,\"reason\":\"x\"}",
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":7}",
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":\"x\",\"request_bytes\":\"2500\"}",
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":\"x\",\"input_tokens\":\"1800\"}",
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":\"x\",\"window\":null}",
        // the final structured fit field is closed: only the exhaustion
        // value parses; any other string, number, or shape is malformed
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":\"x\",\"fit\":\"tried\"}",
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":\"x\",\"fit\":\"\"}",
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":\"x\",\"fit\":7}",
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":\"x\",\"fit\":null}",
    ] {
        assert!(
            parse_context_refusal(&frame(error)).is_none(),
            "must fail closed: {error}"
        );
    }
    let exhausted = frame(
        "odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":\"the final structured fit reduced every registered retrieval block to its mandatory floor and still could not fit\",\"input_tokens\":16000,\"fit\":\"final_fit_exhausted\"}",
    );
    let parsed = parse_context_refusal(&exhausted).expect("the exhaustion fit value parses");
    assert_eq!(parsed.code, "window_exceeded");
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
