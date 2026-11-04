use std::fs;
use std::io::ErrorKind;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use odin_sidecar_protocol::{read_request, write_response, WireLimits};
use rustix::event::{poll, PollFd, PollFlags, Timespec};

use crate::authority::{rejection_response, Sidecar};
use crate::storage;
use crate::{PeerCredentials, SidecarError, SidecarErrorCode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    wire_limits: WireLimits,
    expected_peer: PeerCredentials,
}

impl ServerConfig {
    pub const fn new(wire_limits: WireLimits, expected_peer: PeerCredentials) -> Self {
        Self {
            wire_limits,
            expected_peer,
        }
    }

    pub const fn wire_limits(&self) -> WireLimits {
        self.wire_limits
    }

    pub const fn expected_peer(&self) -> PeerCredentials {
        self.expected_peer
    }
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
            {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

/// Peer credentials restrict socket access; the kernel still authorizes every request.
pub struct SidecarServer {
    listener: UnixListener,
    socket_path: PathBuf,
    _socket_guard: SocketGuard,
    sidecar: Sidecar,
    config: ServerConfig,
}

impl SidecarServer {
    pub fn bind(
        socket_root: &Path,
        sidecar: Sidecar,
        config: ServerConfig,
    ) -> Result<Self, SidecarError> {
        storage::create_private_directory(socket_root)?;
        let socket_path = socket_root.join("authority.sock");
        let listener = UnixListener::bind(&socket_path)
            .map_err(|error| SidecarError::filesystem(&socket_path, error))?;
        if let Err(error) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&socket_path);
            return Err(SidecarError::filesystem(&socket_path, error));
        }
        let metadata = fs::symlink_metadata(&socket_path)
            .map_err(|error| SidecarError::filesystem(&socket_path, error))?;
        if !metadata.file_type().is_socket() || metadata.permissions().mode() & 0o077 != 0 {
            let _ = fs::remove_file(&socket_path);
            return Err(SidecarError::new(
                SidecarErrorCode::Filesystem,
                "bound endpoint is not a private Unix socket",
            ));
        }
        Ok(Self {
            listener,
            socket_path: socket_path.clone(),
            _socket_guard: SocketGuard {
                path: socket_path,
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            sidecar,
            config,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Keep waiting after unrelated peers connect, but stop if the parent dies or the deadline expires.
    pub fn accept_expected_until(
        &self,
        parent: &OwnedFd,
        accept_timeout: Duration,
    ) -> Result<(), SidecarError> {
        let deadline = Instant::now() + accept_timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(SidecarError::new(
                    SidecarErrorCode::Lifecycle,
                    "accept deadline elapsed before the expected peer connected",
                ));
            }
            let remaining = Timespec::try_from(deadline - now).map_err(|error| {
                SidecarError::new(
                    SidecarErrorCode::Lifecycle,
                    format!("accept deadline is out of representable range: {error}"),
                )
            })?;
            let mut fds = [
                PollFd::new(&self.listener, PollFlags::IN),
                PollFd::new(parent, PollFlags::IN),
            ];
            let ready = poll(&mut fds, Some(&remaining)).map_err(|error| {
                SidecarError::new(SidecarErrorCode::Lifecycle, error.to_string())
            })?;
            if ready == 0 {
                continue;
            }
            if !fds[1].revents().is_empty() {
                return Err(SidecarError::new(
                    SidecarErrorCode::Lifecycle,
                    "parent process exited before the expected peer connected",
                ));
            }
            let listener_events = fds[0].revents();
            if listener_events.is_empty() {
                continue;
            }
            if listener_events.contains(PollFlags::NVAL) || listener_events.contains(PollFlags::ERR)
            {
                return Err(SidecarError::new(
                    SidecarErrorCode::Lifecycle,
                    "listener became unreadable while waiting for the expected peer",
                ));
            }
            if !listener_events.contains(PollFlags::IN) {
                continue;
            }
            let (mut stream, _) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionAborted
                            | ErrorKind::ConnectionReset
                            | ErrorKind::Interrupted
                            | ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(SidecarError::filesystem(&self.socket_path, error)),
            };
            let peer = peer_credentials(&stream)?;
            if peer != self.config.expected_peer {
                continue;
            }
            return self.serve_connection(&mut stream);
        }
    }

    fn serve_connection(&self, stream: &mut UnixStream) -> Result<(), SidecarError> {
        loop {
            let request = match read_request(stream, self.config.wire_limits) {
                Ok(Some(request)) => request,
                Ok(None) => return Ok(()),
                Err(error) => {
                    write_response(
                        stream,
                        &rejection_response(error.code(), &error.to_string()),
                        self.config.wire_limits,
                    )?;
                    return Ok(());
                }
            };
            let response = match self.sidecar.transport(request) {
                Ok(response) => response,
                Err(rejection) => rejection_response(rejection.code, &rejection.detail),
            };
            write_response(stream, &response, self.config.wire_limits)?;
        }
    }
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, SidecarError> {
    let credentials = rustix::net::sockopt::socket_peercred(stream)
        .map_err(|error| SidecarError::new(SidecarErrorCode::PeerMismatch, error.to_string()))?;
    Ok(PeerCredentials {
        pid: credentials.pid.as_raw_pid(),
        uid: credentials.uid.as_raw(),
        gid: credentials.gid.as_raw(),
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use odin_sidecar_protocol::Response;

    use super::*;
    use crate::authority::transport_only::{
        fixture_host, fixture_token, invoke_request, now_ms, tempfile_root, SIGNING_KEY,
    };
    use crate::SidecarClient;
    use odin_kernel::token::TokenIssuer;

    /// A bound server waiting for `peer` on its own thread, with the pieces a test keeps alive.
    struct Serving {
        _scratch: tempfile::TempDir,
        socket: PathBuf,
        _launcher: UnixStream,
        thread: std::thread::JoinHandle<(SidecarServer, Result<(), SidecarError>)>,
    }

    fn serve(peer: PeerCredentials, accept_timeout: Duration) -> Serving {
        let scratch = tempfile_root();
        let issuer = TokenIssuer::new(SIGNING_KEY.to_vec()).expect("issuer");
        let now = now_ms();
        let host = fixture_host(scratch.path(), fixture_token(&issuer, now, now + 60_000));
        let limits = WireLimits::new(4_096, 8_192).expect("limits");
        let server = SidecarServer::bind(
            &scratch.path().join("run"),
            host,
            ServerConfig::new(limits, peer),
        )
        .expect("bound server");
        let socket = server.socket_path().to_path_buf();
        // The launcher's end of this pair stays open for as long as the server should wait.
        let (parent, launcher) = UnixStream::pair().expect("parent pair");
        let serving = std::thread::spawn(move || {
            let accepted = server.accept_expected_until(&OwnedFd::from(parent), accept_timeout);
            (server, accepted)
        });
        Serving {
            _scratch: scratch,
            socket,
            _launcher: launcher,
            thread: serving,
        }
    }

    fn ask(socket: &Path) -> Result<Response, SidecarError> {
        let limits = WireLimits::new(4_096, 8_192).expect("limits");
        let mut client = SidecarClient::connect(socket, limits)?;
        client.request(invoke_request(
            "capsule-alpha",
            "00112233445566778899aabbccddeeff",
            0,
            r#"{"path":"notes.txt","content_hex":"6869"}"#,
        ))
    }

    #[test]
    fn the_expected_peer_gets_typed_answers_and_the_socket_goes_with_the_server() {
        let serving = serve(PeerCredentials::current(), Duration::from_secs(30));
        let socket = serving.socket.clone();
        let response = ask(&socket).expect("the expected peer is served");
        assert!(
            matches!(&response, Response::Rejected { code, .. } if code.as_str() == "authority.budget_denied"),
            "{response:?}"
        );
        let (server, finished) = serving.thread.join().expect("server thread");
        finished.expect("the connection ended cleanly");
        assert_eq!(
            fs::metadata(&socket).expect("socket").permissions().mode() & 0o777,
            0o600
        );
        drop(server);
        assert!(!socket.exists(), "the socket is removed with the server");
    }

    #[test]
    fn another_peer_is_dropped_unanswered_and_the_wait_ends_at_its_deadline() {
        let mut stranger = PeerCredentials::current();
        stranger.pid += 1;
        let serving = serve(stranger, Duration::from_millis(500));
        let error = ask(&serving.socket).expect_err("an unexpected peer gets no answer");
        assert_eq!(error.code(), SidecarErrorCode::Protocol, "{error}");
        let (_server, finished) = serving.thread.join().expect("server thread");
        let error = finished.expect_err("no expected peer connected");
        assert_eq!(error.code(), SidecarErrorCode::Lifecycle);
    }
}
