//! Independent plain-HTTP reader used while the Obscura session remains open.
//! DNS answers and every redirect stay public; no challenge solving or cookies.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::Url;

use crate::read::{document_verdict, DocumentVerdict, PageRead};

const READ_BYTES: usize = 8 << 20;
const ALTERNATE_BUDGET: Duration = Duration::from_secs(5);
/// The most the article extractor may take on one page.
const ARTICLE_BUDGET: Duration = Duration::from_secs(10);

struct PublicDns;

impl Resolve for PublicDns {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses: Vec<SocketAddr> =
                tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            if addresses.is_empty() || addresses.iter().any(|address| !public_ip(address.ip())) {
                return Err(
                    std::io::Error::other("the reader requires public DNS addresses").into(),
                );
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

fn public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || address.octets() == [168, 63, 129, 16]
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || (b == 0 && c <= 2) || (b == 88 && c == 99)))
                || (a == 198 && (matches!(b, 18 | 19) || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            (segments[0] & 0xe000) == 0x2000
                && segments[0] != 0x2002
                && !(segments[0] == 0x2001
                    && (segments[1] == 0
                        || segments[1] == 2
                        || segments[1] == 0x0db8
                        || (segments[1] & 0xfff0) == 0x0010
                        || (segments[1] & 0xfff0) == 0x0020))
        }
    }
}

fn public_url(url: &Url) -> bool {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.port_or_known_default(), Some(80 | 443))
    {
        return false;
    }
    match url.host() {
        Some(url::Host::Ipv4(address)) => public_ip(address.into()),
        Some(url::Host::Ipv6(address)) => public_ip(address.into()),
        Some(url::Host::Domain(_)) => true,
        None => false,
    }
}

/// The article extractor's text when it succeeds, else the page converted whole.
pub(crate) fn html_text(body: &[u8], article: Option<&str>, deadline: Instant) -> Option<String> {
    let deadline = deadline.min(Instant::now() + ARTICLE_BUDGET);
    article
        .and_then(|converter| crate::read::article_text(converter, body, deadline))
        .or_else(|| html2text::from_read(body, 120).ok())
}

pub(crate) fn read(url: &str, deadline: Instant, article: Option<&str>) -> Option<PageRead> {
    let url = Url::parse(url).ok()?;
    if !public_url(&url) {
        return None;
    }
    // Leave time for Wayback in the same enclosing MCP session deadline.
    let remaining = deadline.saturating_duration_since(Instant::now());
    let budget = ALTERNATE_BUDGET.min(remaining / 2);
    if budget.is_zero() {
        return None;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    runtime.block_on(async {
        tokio::time::timeout(budget, async {
            let client = reqwest::Client::builder()
                .no_proxy()
                .dns_resolver(Arc::new(PublicDns))
                .redirect(reqwest::redirect::Policy::custom(|attempt| {
                    if attempt.previous().len() >= 8 || !public_url(attempt.url()) {
                        attempt.error("the reader refused a non-public redirect or redirect loop")
                    } else {
                        attempt.follow()
                    }
                }))
                .timeout(budget)
                .build()
                .ok()?;
            let mut response = client.get(url).send().await.ok()?;
            let status = response.status().as_u16();
            let url = response.url().to_string();
            let kind = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)?
                .to_str()
                .ok()?;
            let html = kind.starts_with("text/html") || kind.starts_with("application/xhtml+xml");
            if !kind.starts_with("text/") && !html {
                return None;
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.ok()? {
                if body.len().saturating_add(chunk.len()) > READ_BYTES {
                    return None;
                }
                body.extend_from_slice(&chunk);
            }
            let text = if html {
                html_text(&body, article, deadline)?
            } else {
                String::from_utf8(body).ok()?
            };
            match document_verdict(&format!("[{status}] GET {url}"), &text) {
                DocumentVerdict::Loaded(_) if !text.trim().is_empty() => {
                    Some(PageRead { url, text })
                }
                _ => None,
            }
        })
        .await
        .ok()
        .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternate_reader_rejects_private_and_transition_destinations() {
        for address in [
            "10.0.0.11",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.12",
            "::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "2002:7f00:1::1",
            "2001::1",
        ] {
            assert!(!public_ip(address.parse().unwrap()), "{address}");
        }
        assert!(public_ip("93.184.215.14".parse().unwrap()));
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
        assert!(!public_url(&Url::parse("file:///etc/passwd").unwrap()));
        assert!(!public_url(
            &Url::parse("http://example.com:8080/").unwrap()
        ));
    }
}
