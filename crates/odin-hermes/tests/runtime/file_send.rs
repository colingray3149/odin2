//! `discord_file_send` with a brain result id: Immich photos and brain documents.

use crate::fixtures::{discord_runtime_with, discord_settings};
use odin_hermes::config::{HermesSettings, ImmichSettings};
use odin_omp::host_tools::{HostInvocation, HostToolError};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

const PHOTO: &str = "11111111-1111-4111-8111-111111111111";
const HUGE: &str = "22222222-2222-4222-8222-222222222222";
const LOCKED: &str = "33333333-3333-4333-8333-333333333333";
/// HEIC originals: Immich has a full-size JPEG for the first; for the second
/// it redirects to the preview, as it does with full-size generation off.
const HEIC: &str = "44444444-4444-4444-8444-444444444444";
const HEIC_NO_FULLSIZE: &str = "55555555-5555-4555-8555-555555555555";

/// One loopback server standing in for both Immich and Discord's REST API;
/// it records every uploaded multipart body.
fn fake_server() -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
    use axum::extract::{Path, RawQuery};
    use axum::http::HeaderMap;
    use axum::response::{IntoResponse, Redirect};
    use axum::routing::{get, post};
    let uploads = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&uploads);
    let authorized = |headers: &HeaderMap| headers["x-api-key"] == "test-key";
    let app = axum::Router::new()
        .route(
            "/api/assets/{id}",
            get(
                move |Path(id): Path<String>, headers: HeaderMap| async move {
                    assert!(authorized(&headers));
                    let visibility = if id == LOCKED { "locked" } else { "timeline" };
                    let (name, mime) = if id == HEIC || id == HEIC_NO_FULLSIZE {
                        ("beach.heic", "image/heic")
                    } else {
                        ("beach.jpeg", "image/jpeg")
                    };
                    axum::Json(json!({
                        "id": id, "visibility": visibility, "isTrashed": false,
                        "originalFileName": name, "originalMimeType": mime,
                    }))
                },
            ),
        )
        .route(
            "/api/assets/{id}/original",
            get(move |Path(id): Path<String>| async move {
                if id == HUGE {
                    vec![0_u8; odin_hermes::discord::MAX_FILE_BYTES + 1]
                } else {
                    b"original-bytes".to_vec()
                }
            }),
        )
        .route(
            "/api/assets/{id}/thumbnail",
            get(
                |Path(id): Path<String>, RawQuery(query): RawQuery| async move {
                    match query.as_deref() {
                        Some("size=fullsize") if id == HEIC_NO_FULLSIZE => {
                            Redirect::to("?size=preview").into_response()
                        }
                        Some("size=fullsize") => b"fullsize-jpeg".to_vec().into_response(),
                        _ => b"preview-jpeg".to_vec().into_response(),
                    }
                },
            ),
        )
        .route(
            "/channels/{channel}/messages",
            post(
                move |Path(channel): Path<String>, body: axum::body::Bytes| async move {
                    seen.lock().push(body.to_vec());
                    axum::Json(json!({ "id": "1300000000000000001", "channel_id": channel }))
                },
            ),
        );
    let (ready, address) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            ready.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });
    });
    (format!("http://{}", address.recv().unwrap()), uploads)
}

struct Fixture {
    _dir: tempfile::TempDir,
    raw_root: std::path::PathBuf,
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
    uploads: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn fixture(immich: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (base, uploads) = fake_server();
    let key_path = dir.path().join("immich-key");
    std::fs::write(&key_path, "test-key\n").unwrap();
    let raw_root = dir.path().join("raw");
    std::fs::create_dir_all(raw_root.join("google-takeout/Drive")).unwrap();
    let mut settings = HermesSettings::new(
        dir.path().join("state"),
        Some(discord_settings()),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    settings.immich = immich.then(|| ImmichSettings {
        url: base.clone(),
        web_url: "https://photos.example".to_owned(),
        api_key_path: key_path,
    });
    settings.brain_raw_root = Some(raw_root.clone());
    let runtime = discord_runtime_with(
        settings,
        odin_ledger::Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );
    runtime.set_discord_catch_up_transport(Arc::new(
        odin_hermes::discord::DiscordRestTransport::with_api_base(
            odin_hermes::discord::DiscordCredential::token(
                odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
                odin_hermes::discord::SecretToken::new("test-token").unwrap(),
            ),
            reqwest::Client::new(),
            base,
        )
        .unwrap(),
    ));
    Fixture {
        _dir: dir,
        raw_root,
        runtime,
        uploads,
    }
}

fn send(fixture: &Fixture, asset: &str) -> Result<Value, HostToolError> {
    let tools = odin_hermes::runtime::hermes_host_tools(&fixture.runtime);
    let tool = tools
        .iter()
        .find(|tool| tool.definition().name == "discord_file_send")
        .unwrap();
    tool.invoke(HostInvocation {
        scope: odin_domain::Scope::default(),
        arguments: json!({ "asset": asset }),
    })
}

fn uploaded(fixture: &Fixture) -> String {
    let uploads = fixture.uploads.lock();
    assert_eq!(uploads.len(), 1, "exactly one file reaches the DM");
    String::from_utf8_lossy(&uploads[0]).into_owned()
}

fn refusal(result: Result<Value, HostToolError>) -> String {
    match result {
        Err(HostToolError::Unavailable { reason, .. }) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_immich_photo_is_sent_as_its_original() {
    let fixture = fixture(true);
    let result = send(&fixture, &format!("immich/{PHOTO}")).unwrap();
    assert_eq!(result["sent"], "beach.jpeg");
    assert!(result.get("note").is_none());
    let body = uploaded(&fixture);
    assert!(body.contains("filename=\"beach.jpeg\"") && body.contains("original-bytes"));
    assert!(!body.contains("test-key"));
}

#[test]
fn an_immich_asset_too_large_for_discord_is_sent_as_its_preview() {
    let fixture = fixture(true);
    let result = send(&fixture, &format!("immich/{HUGE}")).unwrap();
    assert_eq!(result["sent"], "beach.jpg");
    assert!(result["note"].as_str().unwrap().contains("preview"));
    assert!(uploaded(&fixture).contains("preview-jpeg"));
}

#[test]
fn a_heic_original_is_sent_as_immichs_full_size_jpeg() {
    let fixture = fixture(true);
    let result = send(&fixture, &format!("immich/{HEIC}")).unwrap();
    assert_eq!(result["sent"], "beach.jpg");
    assert!(result["note"].as_str().unwrap().contains("HEIC"));
    assert!(uploaded(&fixture).contains("fullsize-jpeg"));
}

#[test]
fn a_heic_original_without_a_full_size_jpeg_is_sent_as_its_preview() {
    let fixture = fixture(true);
    let result = send(&fixture, &format!("immich/{HEIC_NO_FULLSIZE}")).unwrap();
    assert_eq!(result["sent"], "beach.jpg");
    assert!(result["note"].as_str().unwrap().contains("a preview JPEG"));
    assert!(uploaded(&fixture).contains("preview-jpeg"));
}

#[test]
fn a_locked_immich_asset_is_refused() {
    let fixture = fixture(true);
    let reason = refusal(send(&fixture, &format!("immich/{LOCKED}")));
    assert!(reason.contains("\"locked\""), "{reason}");
    assert!(fixture.uploads.lock().is_empty());
}

#[test]
fn an_immich_asset_is_refused_when_immich_is_not_configured() {
    let fixture = fixture(false);
    let reason = refusal(send(&fixture, &format!("immich/{PHOTO}")));
    assert!(
        reason.contains("hermes.immich is not configured"),
        "{reason}"
    );
}

#[test]
fn a_brain_document_under_the_raw_root_is_sent() {
    let fixture = fixture(true);
    std::fs::write(
        fixture.raw_root.join("google-takeout/Drive/notes.pdf"),
        b"%PDF-notes",
    )
    .unwrap();
    let result = send(&fixture, "google-takeout/Drive/notes.pdf").unwrap();
    assert_eq!(result["sent"], "notes.pdf");
    assert!(uploaded(&fixture).contains("%PDF-notes"));
}

#[test]
fn a_brain_document_path_escaping_the_raw_root_is_refused() {
    let fixture = fixture(true);
    std::fs::write(fixture.raw_root.join("../secret.txt"), b"outside").unwrap();
    refusal(send(&fixture, "../secret.txt"));
    assert!(fixture.uploads.lock().is_empty());
}
