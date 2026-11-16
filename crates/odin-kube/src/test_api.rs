//! A loopback Kubernetes API that answers each request with the next scripted body, for tests of
//! the list and watch paths. A watch body is newline-delimited events; the connection then closes.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{KubeClient, KubeConfig};

pub(crate) struct ScriptedApi {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl ScriptedApi {
    /// Serves `replies` in order, one per request; a request past the script gets a 500.
    pub(crate) async fn start(replies: Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback API");
        let port = listener.local_addr().expect("API address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let mut replies = replies.into_iter();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.expect("API connection");
                let mut head = Vec::new();
                let mut chunk = [0u8; 1024];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut chunk).await.expect("request head");
                    if read == 0 {
                        break;
                    }
                    head.extend_from_slice(&chunk[..read]);
                }
                let head = String::from_utf8_lossy(&head);
                let target = head.split_whitespace().nth(1).unwrap_or_default();
                seen.lock().expect("request log").push(target.to_owned());
                let (status, body) = match replies.next() {
                    Some(body) => ("200 OK", body),
                    None => ("500 Internal Server Error", "script exhausted".to_owned()),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("response");
            }
        });
        Self { port, requests }
    }

    pub(crate) fn client(&self) -> KubeClient {
        KubeClient {
            client: kube::Client::try_from(kube::Config::new(
                format!("http://127.0.0.1:{}", self.port)
                    .parse()
                    .expect("API URI"),
            ))
            .expect("client"),
            config: KubeConfig {
                kubeconfig: "/nonexistent/kubeconfig".into(),
                cluster: "scripted".to_owned(),
                namespace: "default".to_owned(),
                allowed_nodes: Default::default(),
                node_data_roots: Default::default(),
                request_timeout: std::time::Duration::from_secs(5),
                teardown_timeout: std::time::Duration::from_secs(5),
                vpn_transport: None,
            },
        }
    }

    /// Request targets (path and query) in arrival order.
    pub(crate) fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("request log").clone()
    }
}
