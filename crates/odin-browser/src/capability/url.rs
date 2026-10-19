//! Sanitized display URLs retain exact identity only as a BLAKE3 digest.

use std::borrow::Cow;

use serde::{Deserialize, Serialize, Serializer};

use odin_domain::Digest;

use super::error::CapabilityError;
use super::MAX_URL_BYTES;

/// Retains scheme, host, port, and path for display; userinfo, query, and fragment
/// survive only in the exact URL digest and cannot be recovered.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(try_from = "String")]
pub struct SanitizedUrl {
    display: String,
    origin: String,
    exact_url_digest: Digest,
}

impl SanitizedUrl {
    /// Parses a URL or URL reference, stripping userinfo, query, and
    /// fragment. Browser-special schemes and network-path references are
    /// parsed through their authority rather than by textual `://` splitting.
    /// The exact string is consumed and survives only as a digest.
    pub fn parse(exact: &str) -> Result<Self, CapabilityError> {
        let exact = exact.trim();
        if exact.is_empty() {
            return Err(CapabilityError::InvalidRequest {
                reason: "url is empty".to_owned(),
            });
        }
        if exact.len() > MAX_URL_BYTES {
            return Err(CapabilityError::BoundExceeded {
                limit: MAX_URL_BYTES as u64,
                requested: exact.len() as u64,
            });
        }
        if exact.chars().any(char::is_control) {
            return Err(CapabilityError::InvalidRequest {
                reason: "url contains a control character".to_owned(),
            });
        }

        let redacted = strip_url_suffix(exact);
        let (display, origin) = match split_url_scheme(redacted) {
            Some((raw_scheme, rest)) => {
                let scheme = raw_scheme.to_ascii_lowercase();
                match scheme.as_str() {
                    "http" | "https" | "ws" | "wss" | "ftp" => {
                        let normalized = normalize_browser_slashes(rest);
                        let authority_and_path = normalized.trim_start_matches('/');
                        sanitize_hierarchical_url(
                            Some(&scheme),
                            &format!("{scheme}://"),
                            authority_and_path,
                            false,
                        )?
                    }
                    "file" => {
                        let normalized = normalize_browser_slashes(rest);
                        if let Some(authority_and_path) = normalized.strip_prefix("//") {
                            sanitize_hierarchical_url(
                                Some(&scheme),
                                "file://",
                                authority_and_path,
                                true,
                            )?
                        } else {
                            (format!("file:{normalized}"), "null".to_owned())
                        }
                    }
                    "blob" | "filesystem" | "view-source" => {
                        let nested = Self::parse(rest)?;
                        let origin = if scheme == "view-source" {
                            "null".to_owned()
                        } else {
                            nested.origin().to_owned()
                        };
                        (format!("{scheme}:{}", nested.display_url()), origin)
                    }
                    _ if has_network_path_prefix(rest) => {
                        let normalized = normalize_browser_slashes(rest);
                        let authority_and_path = normalized.trim_start_matches('/');
                        sanitize_hierarchical_url(
                            Some(&scheme),
                            &format!("{scheme}://"),
                            authority_and_path,
                            false,
                        )?
                    }
                    _ => (format!("{scheme}:{rest}"), "null".to_owned()),
                }
            }
            None if has_network_path_prefix(redacted) => {
                let normalized = normalize_browser_slashes(redacted);
                let authority_and_path = normalized.trim_start_matches('/');
                sanitize_hierarchical_url(None, "//", authority_and_path, false)?
            }
            None => (redacted.to_owned(), "null".to_owned()),
        };

        if display.is_empty() {
            return Err(CapabilityError::InvalidRequest {
                reason: "url has no displayable form".to_owned(),
            });
        }
        if display.len() > MAX_URL_BYTES {
            return Err(CapabilityError::BoundExceeded {
                limit: MAX_URL_BYTES as u64,
                requested: display.len() as u64,
            });
        }
        let exact_url_digest = Digest::hash(exact.as_bytes());
        Ok(Self {
            display,
            origin,
            exact_url_digest,
        })
    }

    /// The sanitized display URL: no userinfo, no query, no fragment.
    pub fn display_url(&self) -> &str {
        &self.display
    }

    /// The standards-derived origin, or "null" for relative and opaque URLs.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The only retained trace of the unsanitized location.
    pub fn exact_url_digest(&self) -> Digest {
        self.exact_url_digest
    }
}

fn strip_url_suffix(url: &str) -> &str {
    let end = url
        .char_indices()
        .find_map(|(index, character)| matches!(character, '?' | '#').then_some(index))
        .unwrap_or(url.len());
    &url[..end]
}

fn split_url_scheme(url: &str) -> Option<(&str, &str)> {
    let colon = url.find(':')?;
    let scheme = &url[..colon];
    let mut characters = scheme.chars();
    if !characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
    {
        return None;
    }
    Some((scheme, &url[colon + 1..]))
}

fn has_network_path_prefix(url: &str) -> bool {
    let mut bytes = url.bytes();
    bytes
        .next()
        .is_some_and(|byte| matches!(byte, b'/' | b'\\'))
        && bytes
            .next()
            .is_some_and(|byte| matches!(byte, b'/' | b'\\'))
}

fn normalize_browser_slashes(url: &str) -> Cow<'_, str> {
    if url.contains('\\') {
        Cow::Owned(url.replace('\\', "/"))
    } else {
        Cow::Borrowed(url)
    }
}

fn sanitize_hierarchical_url(
    scheme: Option<&str>,
    prefix: &str,
    authority_and_path: &str,
    allow_empty_authority: bool,
) -> Result<(String, String), CapabilityError> {
    let authority_end = authority_and_path
        .find('/')
        .unwrap_or(authority_and_path.len());
    let (authority, path) = authority_and_path.split_at(authority_end);
    let authority = sanitize_authority(authority, allow_empty_authority)?;
    let display = format!("{prefix}{authority}{path}");
    let origin = match scheme {
        Some(scheme)
            if !authority.is_empty()
                && matches!(scheme, "http" | "https" | "ws" | "wss" | "ftp") =>
        {
            format!("{scheme}://{authority}")
        }
        _ => "null".to_owned(),
    };
    Ok((display, origin))
}

fn sanitize_authority(authority: &str, allow_empty: bool) -> Result<String, CapabilityError> {
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    if host_port.is_empty() {
        if allow_empty && authority.is_empty() {
            return Ok(String::new());
        }
        return Err(CapabilityError::InvalidRequest {
            reason: "url authority has no host".to_owned(),
        });
    }
    if host_port.chars().any(|character| {
        character.is_control()
            || character.is_whitespace()
            || matches!(character, '/' | '\\' | '?' | '#' | '@')
    }) {
        return Err(CapabilityError::InvalidRequest {
            reason: "url authority is malformed".to_owned(),
        });
    }

    if host_port.starts_with('[') {
        let close = host_port
            .find(']')
            .ok_or_else(|| CapabilityError::InvalidRequest {
                reason: "url IPv6 authority is missing its closing bracket".to_owned(),
            })?;
        let (host, suffix) = host_port.split_at(close + 1);
        if !suffix.is_empty()
            && suffix.strip_prefix(':').is_none_or(|port| {
                port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(CapabilityError::InvalidRequest {
                reason: "url authority has an invalid port".to_owned(),
            });
        }
        return Ok(format!("{}{suffix}", host.to_ascii_lowercase()));
    }
    if host_port.contains('[') || host_port.contains(']') {
        return Err(CapabilityError::InvalidRequest {
            reason: "url authority has malformed host brackets".to_owned(),
        });
    }

    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            if host.is_empty()
                || (!port.is_empty() && !port.bytes().all(|byte| byte.is_ascii_digit()))
            {
                return Err(CapabilityError::InvalidRequest {
                    reason: "url authority has an invalid host or port".to_owned(),
                });
            }
            (host, (!port.is_empty()).then_some(port))
        }
        Some(_) => {
            return Err(CapabilityError::InvalidRequest {
                reason: "IPv6 URL hosts must be bracketed".to_owned(),
            });
        }
        None => (host_port, None),
    };
    let host = host.to_ascii_lowercase();
    Ok(port.map_or(host.clone(), |port| format!("{host}:{port}")))
}
impl Serialize for SanitizedUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.display)
    }
}

impl TryFrom<String> for SanitizedUrl {
    type Error = CapabilityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}
pub(super) fn restore_sanitized_url(
    display: String,
    exact_url_digest: Digest,
    field: &str,
) -> Result<SanitizedUrl, CapabilityError> {
    let mut url = SanitizedUrl::parse(&display)?;
    if url.display_url() != display.as_str() {
        return Err(CapabilityError::InvalidRequest {
            reason: format!("{field} must not contain userinfo, query, or fragment"),
        });
    }
    url.exact_url_digest = exact_url_digest;
    Ok(url)
}
