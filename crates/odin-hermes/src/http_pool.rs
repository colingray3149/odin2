//! Process-wide blocking HTTP clients. One client per redirect policy so
//! the connection pool and rustls session survive across calls. Deadlines
//! stay on the request: a shared client must not impose the shortest
//! caller's timeout on everyone else.
//!
//! `reqwest::blocking::Client` is an `Arc` around the pool. Building one
//! per call throws the pool away and repeats the TLS handshake.

use std::sync::LazyLock;

use reqwest::redirect::Policy;

static NO_REDIRECT: LazyLock<Result<reqwest::blocking::Client, reqwest::Error>> =
    LazyLock::new(|| {
        reqwest::blocking::Client::builder()
            .redirect(Policy::none())
            .build()
    });

static DEFAULT_REDIRECT: LazyLock<Result<reqwest::blocking::Client, reqwest::Error>> =
    LazyLock::new(|| reqwest::blocking::Client::builder().build());

/// Redirects disabled. Env proxy stays on (unlike the web-search client).
pub(crate) fn no_redirect() -> Result<&'static reqwest::blocking::Client, &'static reqwest::Error> {
    NO_REDIRECT.as_ref()
}

/// Default redirect policy (`limited(10)`) and env proxy. No client timeout.
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

    use super::{default_redirect, no_redirect};

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

    #[test]
    fn request_timeout_overrides_an_untimed_shared_client() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            thread::sleep(Duration::from_secs(2));
        });

        let error = default_redirect()
            .expect("pool")
            .get(format!("http://{address}/"))
            .timeout(Duration::from_millis(200))
            .send()
            .expect_err("deadline");
        assert!(error.is_timeout(), "{error}");
    }
}
