use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpListener};

use serde_json::json;
use url::Url;

use super::*;
use crate::testing::{ctx_for, FakeHttp};
use crate::FailureKind;

const READ: &[Allow] = &[Allow {
    method: Method::Get,
    prefix: "/control",
}];
const SERVICE: Service = Service {
    endpoint: "service",
    secret: None,
    auth: Auth::None,
    allow: READ,
};

#[test]
fn unreadable_body_does_not_expose_query_credentials() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("address"));
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("read");
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort")
            .expect("truncated body");
    });
    let dir = tempfile::tempdir().expect("dir");
    let key = dir.path().join("key");
    std::fs::write(&key, "private-query-token").expect("key");
    let ctx = ctx_for(
        dir.path(),
        &[],
        &[],
        &[("key", &key)],
        &[("service", &endpoint)],
    );
    let service = Service {
        auth: Auth::Query("token"),
        secret: Some("key"),
        ..SERVICE
    };
    let failure =
        call(&ctx, &service, Method::Get, "/control", None).expect_err("truncated response");
    worker.join().expect("worker");
    assert_eq!(failure.kind, FailureKind::Upstream);
    assert!(
        !failure.cause.contains("private-query-token"),
        "{}",
        failure.cause
    );
    assert!(!failure.cause.contains("?token="), "{}", failure.cause);
}

fn response(status: u16, headers: &str, body: &[u8]) -> (Url, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("address")
    ))
    .expect("url");
    let body = body.to_vec();
    let headers = headers.to_owned();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut request = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("read");
            if line == "\r\n" || line.is_empty() {
                break;
            }
            request.push_str(&line);
        }
        write!(
            stream,
            "HTTP/1.1 {status} Fixture\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("headers");
        stream.write_all(&body).expect("body");
        request
    });
    (url, worker)
}

#[test]
fn authenticated_service_redirect_never_reaches_another_endpoint() {
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    destination.set_nonblocking(true).expect("nonblocking");
    let headers = format!(
        "Location: http://{}/stolen\r\n",
        destination.local_addr().expect("address")
    );
    let (url, worker) = response(302, &headers, b"");
    let dir = tempfile::tempdir().expect("dir");
    let key = dir.path().join("key");
    std::fs::write(&key, "fixture-secret").expect("key");
    let ctx = ctx_for(
        dir.path(),
        &[],
        &[],
        &[("key", &key)],
        &[("service", url.as_str())],
    );
    let service = Service {
        auth: Auth::Query("token"),
        secret: Some("key"),
        ..SERVICE
    };
    assert_eq!(
        call(&ctx, &service, Method::Get, "/control", None)
            .expect_err("redirect")
            .kind,
        FailureKind::Upstream
    );
    assert!(worker
        .join()
        .expect("worker")
        .contains("token=fixture-secret"));
    assert_eq!(
        destination.accept().expect_err("no redirect").kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn download_streams_binary_without_overwrite_and_checks_size() {
    let dir = tempfile::tempdir().expect("dir");
    let body = b"\0\xffbook";
    std::fs::write(dir.path().join("book.epub"), b"old").expect("existing");
    let (url, worker) = response(200, "", body);
    let ctx = ctx_for(dir.path(), &[], &[], &[], &[("source", url.as_str())]);
    let path = download(
        &ctx,
        &["source"],
        &url,
        Some(body.len() as u64),
        dir.path(),
        "book.epub",
        "",
    )
    .expect("download");
    worker.join().expect("worker");
    assert_eq!(path.file_name().expect("name"), "book (2).epub");
    assert_eq!(std::fs::read(path).expect("downloaded"), body);
    assert_eq!(
        std::fs::read(dir.path().join("book.epub")).expect("old"),
        b"old"
    );
    let (url, worker) = response(200, "", b"short");
    let ctx = ctx_for(dir.path(), &[], &[], &[], &[("source", url.as_str())]);
    assert!(download(
        &ctx,
        &["source"],
        &url,
        Some(100),
        dir.path(),
        "bad.epub",
        ""
    )
    .expect_err("size")
    .cause
    .contains("size"));
    worker.join().expect("worker");
    assert!(
        !dir.path().join("bad.epub").exists(),
        "a download that fails its size check leaves no file"
    );
}

#[test]
fn a_declared_source_covers_its_own_subdomains_but_not_lookalikes_other_schemes_or_ports() {
    let sources = [
        Url::parse("https://books.example/").unwrap(),
        Url::parse("http://10.0.0.5:8080/").unwrap(),
    ];
    let refs: Vec<&Url> = sources.iter().collect();
    for allowed in [
        "https://books.example/a",
        "https://cdn.books.example/a",
        "http://10.0.0.5:8080/a",
    ] {
        assert!(
            download::declared_source(&Url::parse(allowed).unwrap(), &refs).is_ok(),
            "{allowed}"
        );
    }
    for refused in [
        "https://evilbooks.example/a",
        "http://books.example/a",
        "https://books.example:444/a",
        "https://user@books.example/a",
    ] {
        assert!(
            download::declared_source(&Url::parse(refused).unwrap(), &refs).is_err(),
            "{refused}"
        );
    }
}

const ALBUMS: &[Allow] = &[Allow {
    method: Method::Get,
    prefix: "/api/albums",
}];

const PHOTOS: Service = Service {
    endpoint: "photos",
    secret: Some("photos"),
    auth: Auth::Header("x-api-key"),
    allow: ALBUMS,
};

#[test]
fn call_sends_the_key_only_in_its_header_and_maps_statuses() {
    let (url, recorded) = FakeHttp::start(&[
        (Method::Get, "/api/albums", 200, r#"[{"id": "a1"}]"#),
        (Method::Get, "/api/albums/locked", 401, "no"),
    ]);
    let dir = tempfile::tempdir().expect("dir");
    let key = dir.path().join("photos.key");
    std::fs::write(&key, "fixture-key\n").expect("key");
    let ctx = ctx_for(
        dir.path(),
        &[],
        &[],
        &[("photos", key.as_path())],
        &[("photos", url.as_str())],
    );
    let albums = call(&ctx, &PHOTOS, Method::Get, "/api/albums", None).expect("albums");
    assert_eq!(albums, json!([{"id": "a1"}]));
    let sent = recorded.requests();
    assert_eq!(sent[0].header("x-api-key"), Some("fixture-key"));
    assert!(!sent[0].path.contains("fixture-key"));

    let refused =
        call(&ctx, &PHOTOS, Method::Get, "/api/albums/locked", None).expect_err("refused key");
    assert_eq!(
        refused.cause,
        "the photos key was refused (401); check the sops secret"
    );
    let outside =
        call(&ctx, &PHOTOS, Method::Delete, "/api/albums", None).expect_err("not allowed");
    assert_eq!(
        outside.cause,
        "DELETE /api/albums is not an allowed photos call"
    );
    assert_eq!(recorded.requests().len(), 2, "the refused call never left");
}
