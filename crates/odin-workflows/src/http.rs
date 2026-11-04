//! Calls to a declared REST service: only the method and path prefixes the
//! family allows, the key only in the auth header or query, and every status
//! mapped to one sentence.

use std::time::Duration;

use serde_json::Value;

use crate::cause::QUOTED_CHARS;
use crate::{Ctx, Failure};

mod download;
pub use download::download;

#[cfg(test)]
#[path = "http/tests.rs"]
mod behavior_tests;

/// How long an HTTP connect may take.
pub const HTTP_CONNECT: Duration = Duration::from_secs(10);
/// How long one whole HTTP exchange may take.
pub const HTTP_TOTAL: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    fn reqwest(self) -> reqwest::Method {
        match self {
            Self::Get => reqwest::Method::GET,
            Self::Post => reqwest::Method::POST,
            Self::Put => reqwest::Method::PUT,
            Self::Patch => reqwest::Method::PATCH,
            Self::Delete => reqwest::Method::DELETE,
        }
    }
}

/// One allowed method and path prefix.
#[derive(Clone, Copy, Debug)]
pub struct Allow {
    pub method: Method,
    pub prefix: &'static str,
}

/// How the service's key travels.
#[derive(Clone, Copy, Debug)]
pub enum Auth {
    /// In the named header.
    Header(&'static str),
    /// As `Authorization: Bearer <key>`.
    Bearer,
    /// A secret containing `username:password`.
    Basic,
    /// In the named query parameter.
    Query(&'static str),
    None,
}

/// One declared service: its endpoint key (also its name in messages), its
/// secret key, how the key travels, and what may be called.
#[derive(Clone, Copy, Debug)]
pub struct Service {
    pub endpoint: &'static str,
    pub secret: Option<&'static str>,
    pub auth: Auth,
    pub allow: &'static [Allow],
}

/// Whether `method path` is inside a listed path boundary.
pub fn allowed(allow: &[Allow], method: Method, path: &str) -> bool {
    let route = path.split('?').next().unwrap_or("");
    if !route.starts_with('/')
        || route.starts_with("//")
        || path.contains('#')
        || route
            .bytes()
            .any(|byte| byte == b'\\' || byte.is_ascii_control() || byte == b' ')
    {
        return false;
    }
    let Ok(parsed) = url::Url::parse(&format!("http://allowed.invalid{route}")) else {
        return false;
    };
    let lower = route.to_ascii_lowercase();
    if parsed.path() != route
        || ["%2f", "%5c", "%25"]
            .iter()
            .any(|escape| lower.contains(escape))
    {
        return false;
    }
    allow.iter().any(|entry| {
        entry.method == method
            && route.strip_prefix(entry.prefix).is_some_and(|rest| {
                rest.is_empty() || entry.prefix.ends_with('/') || rest.starts_with('/')
            })
    })
}

/// The one mapping of a failed status: 401/403 the key, 404 the path, 5xx the service.
pub fn status_failure(service: &str, status: u16, path: &str, body: &str) -> Failure {
    let first_line: String = body
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .chars()
        .take(QUOTED_CHARS)
        .collect();
    match status {
        401 | 403 => Failure::unavailable(format!(
            "the {service} key was refused ({status}); check the sops secret"
        )),
        404 => Failure::arguments(format!("{service} has no {path}")),
        429 => Failure::upstream(format!(
            "{service} is rate-limiting requests (429); try again later"
        )),
        300..=399 => Failure::upstream(format!(
            "{service} redirected {path}; the declared service did not answer it"
        )),
        500.. => Failure::upstream(format!("{service} failed ({status}): {first_line}")),
        _ => Failure::arguments(format!(
            "{service} refused the request ({status}): {first_line}"
        )),
    }
}

/// Calls `service` and returns its JSON answer (`null` for an empty body, a
/// string for a non-JSON one).
pub fn call(
    ctx: &Ctx,
    service: &Service,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> Result<Value, Failure> {
    let response = send(ctx, service, method, path, body, HTTP_TOTAL)?;
    answer(service.endpoint, path, response)
}

/// A missing resource is `None` only for HTTP 404; every other failure stays a failure.
pub fn call_optional(
    ctx: &Ctx,
    service: &Service,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> Result<Option<Value>, Failure> {
    let response = send(ctx, service, method, path, body, HTTP_TOTAL)?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    answer(service.endpoint, path, response).map(Some)
}

/// Posts JSON and returns the response bytes unchanged (for audio and other binary replies).
pub fn post_bytes(
    ctx: &Ctx,
    service: &Service,
    path: &str,
    body: &Value,
    timeout: Duration,
) -> Result<Vec<u8>, Failure> {
    let response = send(ctx, service, Method::Post, path, Some(body), timeout)?;
    let status = response.status().as_u16();
    let bytes = response.bytes().map_err(|error| {
        Failure::upstream(format!(
            "{} answer was unreadable: {}",
            service.endpoint,
            error.without_url()
        ))
    })?;
    if !(200..300).contains(&status) {
        return Err(status_failure(
            service.endpoint,
            status,
            path,
            &String::from_utf8_lossy(&bytes),
        ));
    }
    Ok(bytes.to_vec())
}

fn send(
    ctx: &Ctx,
    service: &Service,
    method: Method,
    path: &str,
    body: Option<&Value>,
    timeout: Duration,
) -> Result<reqwest::blocking::Response, Failure> {
    let name = service.endpoint;
    if !allowed(service.allow, method, path) {
        return Err(Failure::arguments(format!(
            "{} {path} is not an allowed {name} call",
            method.as_str()
        )));
    }
    let base = ctx.endpoint(name)?;
    let url = format!("{}{path}", base.as_str().trim_end_matches('/'));
    let secret = service.secret.map(|key| ctx.secret(key)).transpose()?;
    let mut request = ctx.http()?.request(method.reqwest(), url).timeout(timeout);
    if let Some(secret) = &secret {
        request = match service.auth {
            Auth::Header(header) => request.header(header, secret.expose()),
            Auth::Bearer => request.bearer_auth(secret.expose()),
            Auth::Basic => {
                let (user, password) = secret
                    .expose()
                    .split_once(':')
                    .filter(|(user, _)| !user.is_empty())
                    .ok_or_else(|| {
                        Failure::unavailable(format!(
                            "the {name} secret must contain username:password"
                        ))
                    })?;
                request.basic_auth(user, Some(password))
            }
            Auth::Query(parameter) => request.query(&[(parameter, secret.expose())]),
            Auth::None => request,
        };
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    request.send().map_err(|error| {
        if error.is_connect() {
            Failure::unavailable(format!("{name} is not answering at its declared endpoint"))
        } else if error.is_timeout() && method != Method::Get {
            Failure::uncertain(format!(
                "{name} did not answer {} {path} within {} s; it may have applied it",
                method.as_str(),
                timeout.as_secs()
            ))
        } else {
            Failure::upstream(format!(
                "{name} did not answer {path}: {}",
                error.without_url()
            ))
        }
    })
}

fn answer(name: &str, path: &str, response: reqwest::blocking::Response) -> Result<Value, Failure> {
    let status = response.status().as_u16();
    let text = response.text().map_err(|error| {
        Failure::upstream(format!(
            "{name} answer was unreadable: {}",
            error.without_url()
        ))
    })?;
    if !(200..300).contains(&status) {
        return Err(status_failure(name, status, path, &text));
    }
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
}
