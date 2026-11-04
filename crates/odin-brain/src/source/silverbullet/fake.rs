//! A synthetic SilverBullet over real loopback HTTP for the source's and the
//! service's tests: a canned `/.fs/` listing and page bodies, every requested
//! path reported over a channel. It serves a fixed number of connections and
//! then closes, so an unexpected fetch fails the client loudly.

use std::io::{BufRead, Write};
use std::sync::mpsc::{channel, Receiver};

/// One page the fake serves: name, text, and last-modified time in ms.
pub(crate) type Page = (&'static str, &'static str, u64);

/// How the fake answers beyond the plain protocol.
#[derive(Clone, Copy, Default)]
pub(crate) struct Quirks {
    /// The `X-Space-Path` header on the listing.
    pub space_path: Option<&'static str>,
    /// Page bodies go out in chunked framing, split in two.
    pub chunked: bool,
}

pub(crate) fn serve(pages: Vec<Page>, requests: usize) -> (u16, Receiver<String>) {
    serve_with(pages, Quirks::default(), requests)
}

pub(crate) fn serve_with(
    pages: Vec<Page>,
    quirks: Quirks,
    requests: usize,
) -> (u16, Receiver<String>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(requests) {
            let mut stream = stream.unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut head = Vec::new();
            loop {
                let mut line = Vec::new();
                if reader.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
                    break;
                }
                let end = line == b"\r\n" || line == b"\n";
                head.extend_from_slice(&line);
                if end {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&head);
            let path = text.split_whitespace().nth(1).unwrap_or("").to_owned();
            let mut extra = String::new();
            let (status, body): (&str, Vec<u8>) = if path == "/.fs/" {
                if let Some(space) = quirks.space_path {
                    extra = format!("X-Space-Path: {space}\r\n");
                }
                let entries: Vec<String> = pages
                    .iter()
                    .map(|(name, text, modified)| {
                        format!(
                            "{{\"name\": {name:?}, \"size\": {}, \
                             \"lastModified\": {modified}, \"perm\": \"rw\"}}",
                            text.len()
                        )
                    })
                    .collect();
                ("200 OK", format!("[{}]", entries.join(",")).into_bytes())
            } else if let Some(rest) = path.strip_prefix("/.fs/") {
                let requested = percent_decode(rest);
                match pages.iter().find(|(name, _, _)| *name == requested) {
                    Some((_, text, _)) => ("200 OK", text.as_bytes().to_vec()),
                    None => ("404 Not Found", Vec::new()),
                }
            } else {
                ("404 Not Found", Vec::new())
            };
            sender.send(path.clone()).ok();
            let response = if quirks.chunked && path != "/.fs/" {
                let (first, second) = body.split_at(body.len() / 2);
                let mut response = format!(
                    "HTTP/1.1 {status}\r\n{extra}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                )
                .into_bytes();
                for part in [first, second] {
                    response.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                    response.extend_from_slice(part);
                    response.extend_from_slice(b"\r\n");
                }
                response.extend_from_slice(b"0\r\n\r\n");
                response
            } else {
                let mut response = format!(
                    "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                response.extend_from_slice(&body);
                response
            };
            stream.write_all(&response).unwrap();
        }
    });
    (port, receiver)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let hex = bytes
            .get(index + 1..index + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (bytes[index], hex) {
            (b'%', Some(byte)) => {
                decoded.push(byte);
                index += 3;
            }
            (byte, _) => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}
