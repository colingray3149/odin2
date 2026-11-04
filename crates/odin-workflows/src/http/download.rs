//! Streaming downloads restricted to the declared source hosts, checked at every redirect.
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use url::Url;

use super::{status_failure, HTTP_CONNECT};
use crate::cause::limit_text;
use crate::quarantine::{within_listed_size, SIZE_TOLERANCE_PERCENT};
use crate::{paths, Ctx, Failure};

const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const DOWNLOAD_TOTAL: Duration = Duration::from_secs(50 * 60);
const PROGRESS_EVERY: Duration = Duration::from_secs(5);
const CHUNK: usize = 64 * 1024;
const ERROR_BYTES: u64 = 8192;

/// Streams into `dir/name` without overwriting. Source endpoint hosts and their
/// subdomains are allowed, on the declared scheme and port; no credentials travel.
/// Listed sizes must match within `SIZE_TOLERANCE_PERCENT`, including when Content-Length is absent.
/// A file that fails midway or by size is removed.
pub fn download(
    ctx: &Ctx,
    sources: &[&str],
    url: &Url,
    expected: Option<u64>,
    dir: &Path,
    name: &str,
    label: &str,
) -> Result<PathBuf, Failure> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(Failure::arguments(
            "the download name must be a plain filename",
        ));
    }
    if expected.is_some_and(|size| size > MAX_BYTES) {
        return Err(Failure::arguments(format!(
            "the listed file is larger than the {} download limit",
            limit_text(MAX_BYTES)
        )));
    }
    let sources = sources
        .iter()
        .map(|key| ctx.endpoint(key))
        .collect::<Result<Vec<_>, _>>()?;
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(HTTP_CONNECT)
        .timeout(DOWNLOAD_TOTAL)
        .build()
        .map_err(|error| {
            Failure::unavailable(format!("the download client could not be built: {error}"))
        })?;
    let started = Instant::now();
    let mut url = url.clone();
    let mut response = None;
    for hop in 0..=MAX_REDIRECTS {
        declared_source(&url, &sources)?;
        let remaining = DOWNLOAD_TOTAL
            .checked_sub(started.elapsed())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| Failure::upstream("the download exceeded its 50 minute limit"))?;
        let answer = client
            .get(url.clone())
            .timeout(remaining)
            .send()
            .map_err(|error| {
                let cause = if error.is_timeout() {
                    "timed out"
                } else if error.is_connect() {
                    "could not connect to its declared source"
                } else {
                    "failed while requesting the file"
                };
                Failure::upstream(format!("the download {cause}: {}", error.without_url()))
            })?;
        if !matches!(answer.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            response = Some(answer);
            break;
        }
        if hop == MAX_REDIRECTS {
            return Err(Failure::upstream(format!(
                "the download redirected more than {MAX_REDIRECTS} times"
            )));
        }
        let location = answer
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                Failure::upstream("the download redirected without a readable location")
            })?;
        url = url
            .join(location)
            .map_err(|_| Failure::upstream("the download redirected to an unreadable address"))?;
    }
    let mut response = response.expect("a final response or redirect error");
    let host = url.host_str().unwrap_or("the source");
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        let mut body = String::new();
        let _ = response.take(ERROR_BYTES).read_to_string(&mut body);
        return Err(status_failure(host, status, url.path(), &body));
    }
    let length = response.content_length();
    if length.is_some_and(|size| size > MAX_BYTES) {
        return Err(Failure::upstream(format!(
            "the served file is larger than the {} download limit",
            limit_text(MAX_BYTES)
        )));
    }
    if let Some(length) = length {
        check_size(length, expected)?;
    }
    let (path, mut file) = loop {
        let path = paths::unique(dir, name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => break (path, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Failure::unavailable(format!(
                    "could not create {}: {error}",
                    path.display()
                )))
            }
        }
    };
    let copied = (|| {
        let mut buffer = [0; CHUNK];
        let mut written = 0;
        let mut reported = Instant::now();
        loop {
            let read = response.read(&mut buffer).map_err(|error| {
                Failure::upstream(format!("{host} stopped sending {name}: {error}"))
            })?;
            if read == 0 {
                break;
            }
            written += read as u64;
            if written > MAX_BYTES {
                return Err(Failure::upstream(format!(
                    "{name} grew past the {} download limit",
                    limit_text(MAX_BYTES)
                )));
            }
            file.write_all(&buffer[..read]).map_err(|error| {
                Failure::unavailable(format!("could not write {}: {error}", path.display()))
            })?;
            if reported.elapsed() >= PROGRESS_EVERY {
                reported = Instant::now();
                ctx.progress(match length {
                    Some(total) => format!(
                        "{label}downloading {}% of {total} bytes",
                        written * 100 / total.max(1)
                    ),
                    None => format!("{label}downloaded {written} bytes"),
                });
            }
        }

        check_size(written, expected)
    })();
    if let Err(failure) = copied {
        let _ = std::fs::remove_file(&path);
        return Err(failure);
    }
    Ok(path)
}

fn check_size(actual: u64, expected: Option<u64>) -> Result<(), Failure> {
    if let Some(expected) = expected {
        if !within_listed_size(actual, expected) {
            return Err(Failure::upstream(format!(
                "the download size is {actual} bytes, not the listed {expected} ({SIZE_TOLERANCE_PERCENT}% tolerance)"
            )));
        }
    }
    Ok(())
}

pub(super) fn declared_source(url: &Url, sources: &[&Url]) -> Result<(), Failure> {
    let host = url.host_str().unwrap_or("");
    let allowed = matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && sources.iter().any(|source| {
            source.scheme() == url.scheme()
                && source.port_or_known_default() == url.port_or_known_default()
                && source.host_str().is_some_and(|known| {
                    host == known
                        || (host
                            .strip_suffix(known)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                            && known.parse::<std::net::IpAddr>().is_err())
                })
        });
    if allowed {
        Ok(())
    } else {
        Err(Failure::upstream(format!(
            "the download led to {host}, which is not a declared source on this scheme and port"
        )))
    }
}
