//! Process-wide blocking HTTP clients. One client per redirect policy so
//! the connection pool and rustls session survive across calls. Deadlines
//! stay on the request: a shared client must not impose the shortest
//! caller's timeout on everyone else.
//!
//! `reqwest::blocking::Client` is an `Arc` around the pool. Building one
//! per call throws the pool away and repeats the TLS handshake.
//!
//! Every client still has a connect bound and a total ceiling, so a request
//! whose caller set no deadline fails by name instead of hanging.

use std::sync::LazyLock;
use std::time::Duration;

use reqwest::redirect::Policy;

static NO_REDIRECT: LazyLock<Result<reqwest::blocking::Client, reqwest::Error>> =
    LazyLock::new(|| {
        reqwest::blocking::Client::builder()
            .redirect(Policy::none())
            .connect_timeout(CONNECT_BOUND)
            .timeout(CEILING)
            .build()
    });

static DEFAULT_REDIRECT: LazyLock<Result<reqwest::blocking::Client, reqwest::Error>> =
    LazyLock::new(|| {
        reqwest::blocking::Client::builder()
            .connect_timeout(CONNECT_BOUND)
            .timeout(CEILING)
            .build()
    });

/// How long reaching a server may take.
pub(crate) const CONNECT_BOUND: Duration = Duration::from_secs(10);
/// The longest any request may take when its caller set no shorter deadline.
pub(crate) const CEILING: Duration = Duration::from_secs(300);
/// The longest per-call deadline a configured mail, calendar or vault wire may set, in milliseconds.
pub(crate) const MAX_CALL_TIMEOUT_MS: u64 = 60_000;
/// The most response bytes a configured mail or calendar wire may buffer.
pub(crate) const MAX_CALL_RESPONSE_BYTES: u64 = 8_388_608;

/// Redirects disabled. Env proxy stays on (unlike the web-search client).
pub(crate) fn no_redirect() -> Result<&'static reqwest::blocking::Client, &'static reqwest::Error> {
    NO_REDIRECT.as_ref()
}

/// Default redirect policy (`limited(10)`) and env proxy.
pub(crate) fn default_redirect(
) -> Result<&'static reqwest::blocking::Client, &'static reqwest::Error> {
    DEFAULT_REDIRECT.as_ref()
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use super::no_redirect;

    #[test]
    fn no_redirect_pool_returns_302_instead_of_following() {
        let target = TcpListener::bind("127.0.0.1:0").expect("target");
        target.set_nonblocking(true).expect("nonblocking");
        let target_addr = target.local_addr().expect("target addr");
        let redirector = TcpListener::bind("127.0.0.1:0").expect("redirector");
        let redirect_addr = redirector.local_addr().expect("redirect addr");
        let response = format!(
            "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\nLocation: http://{target_addr}/gone\r\n\r\n"
        );
        thread::spawn(move || {
            let Ok((mut stream, _)) = redirector.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(response.as_bytes());
        });

        let status = no_redirect()
            .expect("pool")
            .get(format!("http://{redirect_addr}/"))
            .timeout(Duration::from_secs(2))
            .send()
            .expect("302")
            .status();
        assert_eq!(status.as_u16(), 302);
        match target.accept() {
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            other => panic!("redirect was followed: {other:?}"),
        }
    }
}
