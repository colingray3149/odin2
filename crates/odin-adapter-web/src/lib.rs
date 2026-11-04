//! Configured search backends share sanitized errors so responses cannot expose upstream secrets.

pub mod credentials;

use std::borrow::Cow;
use std::future::Future;
use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use odin_adapter_core::config::{AdapterDeployment, SearchBackend};
use odin_adapter_core::transport::{AdapterErrorCode, WebSearchInput};
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use serde_json::{json, Value};
use url::Url;

use crate::credentials::{resolve, Secret};

/// The header name comes from Brave's protocol; endpoint and credentials remain configurable.
const TOKEN_HEADER: HeaderName = HeaderName::from_static("x-subscription-token");

const MAX_TITLE_CHARS: usize = 512;
const MAX_URL_BYTES: usize = 2048;
const MAX_DESCRIPTION_CHARS: usize = 1024;
const MAX_AGE_CHARS: usize = 64;

const MAX_CA_BUNDLE_BYTES: usize = 1024 * 1024;

// Static messages keep upstream text, URLs, and credentials out of errors.
const MSG_PARAMS: &str = "web.search input out of bounds";
const MSG_CREDENTIAL: &str = "the configured credential is unavailable";
const MSG_CREDENTIAL_HEADER: &str = "the configured credential is not a usable token";
const MSG_CLIENT: &str = "http client initialization failed";
const MSG_CA_BUNDLE_READ: &str = "the configured CA bundle is unavailable";
const MSG_CA_BUNDLE_INVALID: &str = "the configured CA bundle is invalid";
const MSG_CA_BUNDLE_TOO_LARGE: &str = "the configured CA bundle exceeds the byte bound";
const MSG_SEND_FAILED: &str = "upstream search request failed";
const MSG_BODY_FAILED: &str = "upstream search response failed";
const MSG_REJECTED: &str = "upstream search rejected the request";
const MSG_ACCOUNT: &str = "the external search account is unavailable";
const MSG_TIMEOUT: &str = "upstream search exceeded its configured deadline";
const MSG_TOO_LARGE: &str = "upstream search response exceeded the configured byte bound";
const MSG_PARSE: &str = "upstream search response was not the expected shape";
const MSG_ENGINES_DOWN: &str = "every upstream search engine was unresponsive";
const MSG_ALL_REJECTED: &str = "every upstream search result was outside the result schema";

#[derive(Clone, Debug)]
pub struct BackendError {
    code: AdapterErrorCode,
    message: &'static str,
    detail: Option<String>,
}

impl BackendError {
    pub const fn new(code: AdapterErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            detail: None,
        }
    }

    /// Keep secret-free diagnostics in the journal without exposing them to the seat.
    pub fn with_detail(mut self, detail: String) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    pub const fn code(&self) -> AdapterErrorCode {
        self.code
    }

    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for BackendError {}

#[derive(serde::Serialize)]
struct BraveQuery<'a> {
    q: &'a str,
    count: u32,
}

/// SearXNG has no result-count parameter, so results are limited after parsing.
#[derive(serde::Serialize)]
struct SearxngQuery<'a> {
    q: &'a str,
    format: &'static str,
}

/// Invalid caller input must not trigger a retry through the configured fallback.
pub async fn search(
    deployment: &AdapterDeployment,
    input: &WebSearchInput,
) -> Result<Value, BackendError> {
    input.validate().map_err(|error| {
        BackendError::new(AdapterErrorCode::InvalidParams, MSG_PARAMS)
            .with_detail(error.to_string())
    })?;
    match search_backend(deployment, input).await {
        Err(error) if error.code() != AdapterErrorCode::InvalidParams => {
            match deployment.fallback() {
                Some(fallback) => search_backend(fallback, input).await,
                None => Err(error),
            }
        }
        outcome => outcome,
    }
}

/// Request and body reads share a deadline so streaming cannot extend the timeout.
async fn search_backend(
    deployment: &AdapterDeployment,
    input: &WebSearchInput,
) -> Result<Value, BackendError> {
    let count = input.count().min(deployment.max_results().get());
    let client = client(deployment)?;
    let timeout = Duration::from_millis(deployment.request_timeout_ms().get());
    let deadline = tokio::time::Instant::from_std(Instant::now() + timeout);

    let request = client
        .get(deployment.endpoint().as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .timeout(timeout);
    let request = match deployment.backend() {
        SearchBackend::Brave => {
            let credential = deployment.credential().ok_or(BackendError::new(
                AdapterErrorCode::CredentialsUnavailable,
                MSG_CREDENTIAL,
            ))?;
            let secret = resolve(credential).map_err(|error| {
                BackendError::new(AdapterErrorCode::CredentialsUnavailable, MSG_CREDENTIAL)
                    .with_detail(format!("credential {}", error.cause()))
            })?;
            request
                .query(&BraveQuery {
                    q: input.query(),
                    count,
                })
                .header(TOKEN_HEADER, token_header(&secret)?)
        }
        SearchBackend::Searxng => request.query(&SearxngQuery {
            q: input.query(),
            format: "json",
        }),
    };

    let mut response = bounded(deadline, request.send(), MSG_SEND_FAILED).await?;

    let status = response.status();
    if !status.is_success() {
        return Err(match status.as_u16() {
            401 | 403 => BackendError::new(AdapterErrorCode::AccountUnavailable, MSG_ACCOUNT),
            _ => BackendError::new(AdapterErrorCode::InternalError, MSG_REJECTED),
        });
    }

    let body = bounded_body(
        &mut response,
        deadline,
        deployment.max_response_bytes().get(),
    )
    .await?;
    let mut page = match deployment.backend() {
        SearchBackend::Brave => parse_brave_bytes(&body, count)?,
        SearchBackend::Searxng => parse_searxng_bytes(&body, count)?,
    };
    page["backend"] = json!(deployment.backend().as_str());
    Ok(page)
}

/// Cache client initialization, including failures, to avoid rebuilding it on every request.
static CLIENT: LazyLock<Result<reqwest::Client, BackendError>> = LazyLock::new(|| {
    client_builder().build().map_err(|error| {
        BackendError::new(AdapterErrorCode::InternalError, MSG_CLIENT)
            .with_detail(error.to_string())
    })
});

fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
}

fn client(deployment: &AdapterDeployment) -> Result<Cow<'static, reqwest::Client>, BackendError> {
    let Some(path) = deployment.ca_bundle_path() else {
        return CLIENT
            .as_ref()
            .map(Cow::Borrowed)
            .map_err(BackendError::clone);
    };
    // Re-read private trust on each call so removed or invalid certificates cannot stay trusted.
    let bundle = read_ca_bundle(path)?;
    let builder = add_ca_bundle(client_builder(), &bundle)?;
    builder.build().map(Cow::Owned).map_err(|error| {
        BackendError::new(AdapterErrorCode::InternalError, MSG_CA_BUNDLE_INVALID)
            .with_detail(error.to_string())
    })
}

fn read_ca_bundle(path: &Path) -> Result<Vec<u8>, BackendError> {
    let unavailable = || BackendError::new(AdapterErrorCode::InternalError, MSG_CA_BUNDLE_READ);
    // Certificates are public, so store paths and symlinks are allowed unlike credential paths.
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| unavailable().with_detail(error.to_string()))?;
    let parent = canonical.parent().ok_or_else(unavailable)?;
    let leaf = canonical.file_name().ok_or_else(unavailable)?;
    let root = odin_confined_fs::Capability::seal(parent)
        .map_err(|error| unavailable().with_detail(error.to_string()))?;
    let file = root
        .open_read(Path::new(leaf))
        .map_err(|error| unavailable().with_detail(error.to_string()))?;
    let len = file
        .metadata()
        .map_err(|error| unavailable().with_detail(error.to_string()))?
        .len();
    if len > MAX_CA_BUNDLE_BYTES as u64 {
        return Err(BackendError::new(
            AdapterErrorCode::InternalError,
            MSG_CA_BUNDLE_TOO_LARGE,
        ));
    }
    let mut bytes = Vec::with_capacity(len as usize + 1);
    file.take(MAX_CA_BUNDLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| unavailable().with_detail(error.to_string()))?;
    if bytes.len() > MAX_CA_BUNDLE_BYTES {
        return Err(BackendError::new(
            AdapterErrorCode::InternalError,
            MSG_CA_BUNDLE_TOO_LARGE,
        ));
    }
    Ok(bytes)
}

fn add_ca_bundle(
    mut builder: reqwest::ClientBuilder,
    bundle: &[u8],
) -> Result<reqwest::ClientBuilder, BackendError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let invalid = || BackendError::new(AdapterErrorCode::InternalError, MSG_CA_BUNDLE_INVALID);
    let mut remaining = std::str::from_utf8(bundle)
        .map_err(|error| invalid().with_detail(error.to_string()))?
        .trim_ascii();
    if remaining.is_empty() {
        return Err(invalid());
    }
    // reqwest ignores non-certificate PEM content; reject it instead of accepting malformed bundles.
    while !remaining.is_empty() {
        if !remaining.starts_with(BEGIN) {
            return Err(invalid());
        }
        let body_end = remaining.find(END).ok_or_else(invalid)?;
        if !remaining[BEGIN.len()..body_end].bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte.is_ascii_whitespace() || b"+/=".contains(&byte)
        }) {
            return Err(invalid());
        }
        let end = body_end + END.len();
        let certificates = reqwest::Certificate::from_pem_bundle(&remaining.as_bytes()[..end])
            .map_err(|error| invalid().with_detail(error.to_string()))?;
        if certificates.len() != 1 {
            return Err(invalid());
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
        remaining = remaining[end..].trim_ascii();
    }
    Ok(builder)
}

async fn bounded<T>(
    deadline: tokio::time::Instant,
    future: impl Future<Output = Result<T, reqwest::Error>>,
    message: &'static str,
) -> Result<T, BackendError> {
    match tokio::time::timeout_at(deadline, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) if error.is_timeout() => Err(timeout_error()),
        Ok(Err(error)) => Err(BackendError::new(AdapterErrorCode::InternalError, message)
            .with_detail(error.to_string())),
        Err(_) => Err(timeout_error()),
    }
}

async fn bounded_body(
    response: &mut reqwest::Response,
    deadline: tokio::time::Instant,
    max_response_bytes: u64,
) -> Result<Vec<u8>, BackendError> {
    let mut body = Vec::new();
    if let Some(len) = response.content_length() {
        if let Ok(cap) = usize::try_from(len.min(max_response_bytes)) {
            body.reserve(cap);
        }
    }
    loop {
        let Some(chunk) = bounded(deadline, response.chunk(), MSG_BODY_FAILED).await? else {
            return Ok(body);
        };
        if body.len() as u64 + chunk.len() as u64 > max_response_bytes {
            return Err(BackendError::new(
                AdapterErrorCode::InternalError,
                MSG_TOO_LARGE,
            ));
        }
        body.extend_from_slice(&chunk);
    }
}

const fn timeout_error() -> BackendError {
    BackendError::new(AdapterErrorCode::Timeout, MSG_TIMEOUT)
}

const fn parse_error() -> BackendError {
    BackendError::new(AdapterErrorCode::ParseError, MSG_PARSE)
}

/// Mark credentials sensitive so HTTP diagnostics do not expose them.
fn token_header(secret: &Secret) -> Result<HeaderValue, BackendError> {
    let mut value = HeaderValue::from_str(secret.as_str()).map_err(|error| {
        BackendError::new(
            AdapterErrorCode::CredentialsUnavailable,
            MSG_CREDENTIAL_HEADER,
        )
        .with_detail(error.to_string())
    })?;
    value.set_sensitive(true);
    Ok(value)
}

fn required_text(value: Option<&Value>, max_chars: usize) -> Result<String, BackendError> {
    match value {
        Some(Value::String(text)) => owned_bounded(text, max_chars),
        _ => Err(parse_error()),
    }
}

fn owned_bounded(text: &str, max_chars: usize) -> Result<String, BackendError> {
    if text.chars().count() <= max_chars {
        Ok(text.to_owned())
    } else {
        Err(parse_error())
    }
}

/// Parse URLs to reject userinfo and validate the normalized link rather than an unchecked prefix.
fn required_url(value: Option<&Value>) -> Result<String, BackendError> {
    let text = match value {
        Some(Value::String(text)) => text,
        _ => return Err(parse_error()),
    };
    normalize_https_url(text)
}

fn normalize_https_url(text: &str) -> Result<String, BackendError> {
    let parsed = Url::parse(text).map_err(|error| parse_error().with_detail(error.to_string()))?;
    // HTTPS parsing requires a host but still permits userinfo, which this adapter rejects.
    let without_userinfo = parsed.username().is_empty() && parsed.password().is_none();
    if parsed.scheme() != "https"
        || parsed.host_str().is_none_or(str::is_empty)
        || !without_userinfo
    {
        return Err(parse_error());
    }
    let normalized = parsed.to_string();
    if normalized.len() > MAX_URL_BYTES {
        return Err(parse_error());
    }
    Ok(normalized)
}

/// Skip invalid entries so one malformed result does not discard the entire page.
fn result_item(entry: &Value, snippet: &str, age: &str) -> Option<Value> {
    let title = required_text(entry.get("title"), MAX_TITLE_CHARS).ok()?;
    let url = required_url(entry.get("url")).ok()?;
    let description: String = entry
        .get(snippet)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .chars()
        .take(MAX_DESCRIPTION_CHARS)
        .collect();
    let mut item = json!({ "title": title, "url": url, "description": description });
    if let Some(age) = entry
        .get(age)
        .and_then(Value::as_str)
        .filter(|age| age.chars().count() <= MAX_AGE_CHARS)
    {
        item["age"] = json!(age);
    }
    Some(item)
}

/// Reject pages with no valid entries so the configured fallback can serve results.
fn kept_results<'a>(
    entries: impl IntoIterator<Item = &'a serde_json::value::RawValue>,
    count: u32,
    snippet: &str,
    age: &str,
) -> Result<Vec<Value>, BackendError> {
    let (mut results, mut examined) = (Vec::new(), 0usize);
    for raw in entries {
        let entry = result_value(raw)?;
        if results.len() < count as usize {
            examined += 1;
            results.extend(result_item(&entry, snippet, age));
        }
    }
    if results.is_empty() && examined > 0 {
        return Err(BackendError::new(
            AdapterErrorCode::ParseError,
            MSG_ALL_REJECTED,
        ));
    }
    Ok(results)
}

/// Brave omits the web section when there are no web results.
fn parse_brave_bytes(body: &[u8], count: u32) -> Result<Value, BackendError> {
    let document: BraveDocument<'_> = serde_json::from_slice(body)
        .map_err(|error| parse_error().with_detail(error.to_string()))?;
    let entries = document
        .web
        .iter()
        .flat_map(|web| web.results.iter().copied());
    let results = kept_results(entries, count, "description", "age")?;
    Ok(json!({ "results": results, "resultCount": results.len() }))
}

/// RawValue permits recursion and numbers that Value rejects, so validate each entry.
fn result_value(raw: &serde_json::value::RawValue) -> Result<Value, BackendError> {
    serde_json::from_str(raw.get()).map_err(|error| parse_error().with_detail(error.to_string()))
}

/// An enum accepts escaped JSON strings that a borrowed discriminator would reject.
#[derive(serde::Deserialize)]
enum SearchKind {
    #[serde(rename = "search")]
    Search,
}

#[derive(serde::Deserialize)]
struct BraveDocument<'a> {
    #[serde(rename = "type")]
    _kind: SearchKind,
    #[serde(borrow, default, deserialize_with = "present_web")]
    web: Option<BraveWeb<'a>>,
}

fn present_web<'de, D>(deserializer: D) -> Result<Option<BraveWeb<'de>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

#[derive(serde::Deserialize)]
struct BraveWeb<'a> {
    #[serde(borrow)]
    results: Vec<&'a serde_json::value::RawValue>,
}

/// Empty results with unresponsive engines trigger fallback instead of reporting a successful search.
fn parse_searxng_bytes(body: &[u8], count: u32) -> Result<Value, BackendError> {
    let document: SearxDocument<'_> = serde_json::from_slice(body)
        .map_err(|error| parse_error().with_detail(error.to_string()))?;
    let results = kept_results(
        document.results.iter().copied(),
        count,
        "content",
        "publishedDate",
    )?;
    if results.is_empty() && document.unresponsive_engines {
        return Err(BackendError::new(
            AdapterErrorCode::InternalError,
            MSG_ENGINES_DOWN,
        ));
    }
    Ok(json!({ "results": results, "resultCount": results.len() }))
}

#[derive(serde::Deserialize)]
struct SearxDocument<'a> {
    #[serde(borrow)]
    results: Vec<&'a serde_json::value::RawValue>,
    #[serde(default, deserialize_with = "nonempty_array_flag")]
    unresponsive_engines: bool,
}

fn nonempty_array_flag<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value: Value = serde::Deserialize::deserialize(deserializer)?;
    Ok(value.as_array().is_some_and(|engines| !engines.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(title: &str, url: &str, description: &str) -> Value {
        json!({ "title": title, "url": url, "description": description })
    }

    #[test]
    fn url_userinfo_and_foreign_schemes_are_rejected() {
        for hostile in [
            "https://user:pass@example.com/",
            "https://user@example.com/",
            "https://:pass@example.com/",
            "http://example.com/",
            "ftp://example.com/file",
            "file:///etc/passwd",
            "https://",
            "https://exa mple.com/",
            "not a url",
        ] {
            assert!(
                required_url(Some(&json!(hostile))).is_err(),
                "accepted {hostile}"
            );
        }
    }

    fn brave(document: Value, count: u32) -> Result<Value, BackendError> {
        parse_brave_bytes(&serde_json::to_vec(&document).unwrap(), count)
    }

    #[test]
    fn a_page_that_is_not_a_result_page_is_a_parse_error() {
        for shape in [
            json!({ "type": "search", "web": {} }),
            json!({ "type": "search", "web": { "results": "none" } }),
            json!({ "type": "search", "web": { "results": null } }),
            json!(["not", "a", "page"]),
            json!({}),
            json!({ "web": { "results": [] } }),
            json!({ "type": "search", "web": null }),
            json!({ "type": "suggest", "web": { "results": [entry("t", "https://e.io/a", "d")] } }),
            json!({ "type": null }),
        ] {
            assert_eq!(
                brave(shape.clone(), 5).unwrap_err().message(),
                MSG_PARSE,
                "{shape}"
            );
        }
    }

    #[test]
    fn page_is_sanitized_to_schema_fields_and_count() {
        let page = brave(
            json!({ "type": "search", "web": { "results": [
                { "title": "t", "url": "https://e.io/a", "description": "d", "age": "2 days ago", "rank": 1 },
                entry("t2", "https://e.io/b", "d2"),
            ] } }),
            5,
        )
        .unwrap();
        assert_eq!(
            page,
            json!({
                "results": [
                    { "title": "t", "url": "https://e.io/a", "description": "d", "age": "2 days ago" },
                    { "title": "t2", "url": "https://e.io/b", "description": "d2" },
                ],
                "resultCount": 2,
            })
        );
    }

    #[test]
    fn brave_entries_outside_the_schema_are_skipped_not_fatal() {
        let long_title = "t".repeat(MAX_TITLE_CHARS + 1);
        let long_description = "d".repeat(MAX_DESCRIPTION_CHARS + 1);
        let long_age = "a".repeat(MAX_AGE_CHARS + 1);
        let page = brave(
            json!({ "type": "search", "web": { "results": [
                { "url": "https://e.io/a", "description": "d" },
                { "title": 7, "url": "https://e.io/a", "description": "d" },
                { "title": "t", "url": null, "description": "d" },
                { "title": "t", "url": "http://e.io/a", "description": "d" },
                { "title": "t", "url": "https://u:p@e.io/a", "description": "d" },
                { "title": long_title, "url": "https://e.io/a", "description": "d" },
                "not-an-object",
                { "title": "no snippet", "url": "https://e.io/b", "age": 3 },
                { "title": "cut", "url": "https://e.io/c", "description": long_description, "age": long_age },
            ] } }),
            10,
        )
        .unwrap();
        assert_eq!(page["resultCount"], json!(2));
        assert_eq!(
            page["results"][0],
            json!({ "title": "no snippet", "url": "https://e.io/b", "description": "" })
        );
        assert_eq!(
            page["results"][1]["description"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            MAX_DESCRIPTION_CHARS
        );
        assert!(page["results"][1].get("age").is_none());
    }

    /// A one-request loopback HTTP server answering `status` with `body`;
    /// the join handle yields the request line it saw.
    fn serve_once(status: &str, body: Value) -> (String, std::thread::JoinHandle<String>) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/search", listener.local_addr().unwrap());
        let status = status.to_owned();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            let body = body.to_string();
            write!(
                &stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            request_line
        });
        (endpoint, handle)
    }

    fn searxng_at(endpoint: &str) -> AdapterDeployment {
        use std::num::{NonZeroU32, NonZeroU64};
        AdapterDeployment::new(
            SearchBackend::Searxng,
            odin_adapter_core::config::AdapterEndpoint::parse(endpoint).unwrap(),
            None,
            NonZeroU64::new(5_000).unwrap(),
            NonZeroU32::new(5).unwrap(),
            NonZeroU64::new(65_536).unwrap(),
        )
        .unwrap()
    }

    fn run(deployment: &AdapterDeployment) -> Result<Value, BackendError> {
        let input = WebSearchInput::new("arxiv transformers", 3).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(search(deployment, &input))
    }

    #[test]
    fn private_trust_failures_are_bounded_typed_and_sanitized() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private-path-sentinel.pem");
        let deployment = searxng_at("https://127.0.0.1:9/search")
            .with_ca_bundle_path(path.clone())
            .unwrap();
        for (contents, message) in [
            (None, MSG_CA_BUNDLE_READ),
            (Some(Vec::new()), MSG_CA_BUNDLE_INVALID),
            (
                Some(b"private-content-sentinel".to_vec()),
                MSG_CA_BUNDLE_INVALID,
            ),
            (
                Some(b"-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n".to_vec()),
                MSG_CA_BUNDLE_INVALID,
            ),
            (
                Some(b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n".to_vec()),
                MSG_CA_BUNDLE_INVALID,
            ),
            (
                Some(b"-----BEGIN CERTIFICATE-----\nYWJj\n".to_vec()),
                MSG_CA_BUNDLE_INVALID,
            ),
            (
                Some(vec![b'x'; MAX_CA_BUNDLE_BYTES + 1]),
                MSG_CA_BUNDLE_TOO_LARGE,
            ),
        ] {
            if let Some(contents) = contents {
                std::fs::write(&path, contents).unwrap();
            }
            let error = run(&deployment).unwrap_err();
            assert_eq!(error.code(), AdapterErrorCode::InternalError);
            assert_eq!(error.message(), message);
            assert!(!format!("{error:?}").contains("sentinel"));
        }
        let directory_deployment = searxng_at("https://127.0.0.1:9/search")
            .with_ca_bundle_path(directory.path().to_path_buf())
            .unwrap();
        assert_eq!(
            run(&directory_deployment).unwrap_err().message(),
            MSG_CA_BUNDLE_READ
        );
    }

    fn searxng_page() -> Value {
        json!({ "query": "q", "results": [
            { "title": "Attention", "url": "https://arxiv.org/abs/1706.03762", "content": "Transformer", "engine": "bing" },
        ], "unresponsive_engines": [] })
    }

    #[test]
    fn searxng_serves_a_page_that_names_its_backend() {
        let (endpoint, server) = serve_once("200 OK", searxng_page());
        let page = run(&searxng_at(&endpoint)).unwrap();
        assert!(server.join().unwrap().contains("format=json"));
        assert_eq!(page["backend"], json!("searxng"));
        assert_eq!(page["resultCount"], json!(1));
        assert_eq!(
            page["results"][0]["url"],
            json!("https://arxiv.org/abs/1706.03762")
        );
    }

    #[test]
    fn a_failing_primary_is_served_by_the_declared_fallback() {
        let (down, down_server) = serve_once("503 Service Unavailable", json!({}));
        let (up, up_server) = serve_once("200 OK", searxng_page());
        let deployment = searxng_at(&down).with_fallback(searxng_at(&up)).unwrap();
        let page = run(&deployment).unwrap();
        down_server.join().unwrap();
        up_server.join().unwrap();
        assert_eq!(page["resultCount"], json!(1));
    }

    #[test]
    fn a_brave_primary_without_its_key_falls_back_to_searxng() {
        use odin_adapter_core::config::{AdapterCredential, AdapterEndpoint};
        use odin_adapter_core::OpaqueCredentialHandle;
        use std::num::{NonZeroU32, NonZeroU64};
        let brave = AdapterDeployment::new(
            SearchBackend::Brave,
            AdapterEndpoint::parse("https://127.0.0.1:9/search").unwrap(),
            Some(
                AdapterCredential::new(
                    OpaqueCredentialHandle::new("cred:brave-search").unwrap(),
                    "/nonexistent/odin-test/BRAVE_API_KEY".into(),
                )
                .unwrap(),
            ),
            NonZeroU64::new(5_000).unwrap(),
            NonZeroU32::new(5).unwrap(),
            NonZeroU64::new(65_536).unwrap(),
        )
        .unwrap();
        assert_eq!(
            run(&brave).unwrap_err().code(),
            AdapterErrorCode::CredentialsUnavailable
        );
        let (up, up_server) = serve_once("200 OK", searxng_page());
        let page = run(&brave.with_fallback(searxng_at(&up)).unwrap()).unwrap();
        up_server.join().unwrap();
        assert_eq!(page["backend"], json!("searxng"));
    }
}
