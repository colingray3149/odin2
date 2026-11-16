//! The cross-encoder pass over a turn's fused candidates: the declared
//! loopback reranker (bge-reranker-v2-m3 under llama.cpp on the authority,
//! `[brain.rerank]`) reads the query beside each candidate's text and
//! reorders them. It only reorders what the turn already admitted: the
//! candidates it sees passed the serving scope, the visibility filter and
//! the record address, so it can never add a chunk a seat may not read.
//!
//! Measured on mini (2026-10-26, 195 fixed queries, top 16): over the fused
//! BM25 and vector legs the first relevant hit's reciprocal rank rose from
//! 0.41 to 0.58 for 32 candidates, at 0.43 s p50 on the iGPU.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::error::{BrainError, BrainResult};

const RERANK_PATH: &str = "/v1/rerank";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// One turn's pass reads at most this long; past it the fused order serves.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// The declared reranker: its loopback address and how many of a turn's
/// best fused candidates it reorders.
#[derive(Clone, Debug)]
pub struct Reranker {
    pub address: SocketAddr,
    pub candidates: usize,
}

impl Reranker {
    /// The order the reranker puts `documents` in for `query`: indexes into
    /// `documents`, most relevant first.
    pub fn order(&self, query: &str, documents: &[&str]) -> BrainResult<Vec<usize>> {
        let body = serde_json::to_vec(&serde_json::json!({
            "query": query,
            "documents": documents,
            "top_n": documents.len(),
        }))
        .map_err(|error| unavailable(format!("the request failed to serialize: {error}")))?;
        let mut stream = TcpStream::connect_timeout(&self.address, CONNECT_TIMEOUT)
            .map_err(|error| unavailable(format!("cannot connect to {}: {error}", self.address)))?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
            .map_err(|error| unavailable(format!("cannot bound the connection: {error}")))?;
        let head = format!(
            "POST {RERANK_PATH} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.address,
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .and_then(|()| stream.flush())
            .map_err(|error| unavailable(format!("writing the request: {error}")))?;
        // read_response's own errors name the embedding gateway; a rerank fault must not.
        let peer = format!("the reranker at {}", self.address);
        let (status, body) =
            super::embedding::read_response(&mut stream, &peer).map_err(|error| match error {
                BrainError::EmbeddingUnavailable { reason, .. } => unavailable(reason),
                other => unavailable(format!("{peer}: {other}")),
            })?;
        if status != 200 {
            return Err(unavailable(format!(
                "{} {RERANK_PATH} answered HTTP {status}: {}",
                self.address,
                String::from_utf8_lossy(&body)
                    .chars()
                    .take(200)
                    .collect::<String>()
            )));
        }
        parse_order(&body, documents.len())
    }
}

/// The indexes of `{"results": [{"index", "relevance_score"}]}`, best first;
/// every document must be scored exactly once.
fn parse_order(body: &[u8], documents: usize) -> BrainResult<Vec<usize>> {
    #[derive(serde::Deserialize)]
    struct Scored {
        index: usize,
        relevance_score: f64,
    }
    #[derive(serde::Deserialize)]
    struct Response {
        results: Vec<Scored>,
    }
    let mut response: Response = serde_json::from_slice(body)
        .map_err(|error| unavailable(format!("unreadable response: {error}")))?;
    let mut seen = vec![false; documents];
    for scored in &response.results {
        match seen.get_mut(scored.index) {
            Some(slot) if !*slot && scored.relevance_score.is_finite() => *slot = true,
            _ => {
                return Err(unavailable(format!(
                    "document {} was scored out of range, twice or as {}",
                    scored.index, scored.relevance_score
                )))
            }
        }
    }
    if seen.iter().any(|seen| !seen) {
        return Err(unavailable(format!(
            "{} of {documents} documents came back scored",
            response.results.len()
        )));
    }
    response
        .results
        .sort_by(|left, right| right.relevance_score.total_cmp(&left.relevance_score));
    Ok(response.results.iter().map(|scored| scored.index).collect())
}

fn unavailable(reason: String) -> BrainError {
    BrainError::Unavailable {
        component: "brain-rerank",
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::Reranker;
    use crate::retrieval::embedding::test_gateway::serve_n;

    fn answering(status: &str, body: &str) -> Reranker {
        let reply = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        Reranker {
            address: ([127, 0, 0, 1], serve_n(1, reply.into_bytes())).into(),
            candidates: 32,
        }
    }

    #[test]
    fn the_reranker_over_http_orders_the_documents_or_says_why_not() {
        let scored =
            r#"{"results":[{"index":0,"relevance_score":0.2},{"index":1,"relevance_score":0.9}]}"#;
        assert_eq!(
            answering("200 OK", scored).order("q", &["a", "b"]).unwrap(),
            [1, 0]
        );
        let failed = answering("500 Internal Server Error", "model not loaded")
            .order("q", &["a", "b"])
            .unwrap_err();
        assert!(
            failed.to_string().contains("500") && failed.to_string().contains("model not loaded"),
            "{failed}"
        );
        let short = answering(
            "200 OK",
            r#"{"results":[{"index":0,"relevance_score":1.0}]}"#,
        )
        .order("q", &["a", "b"])
        .unwrap_err();
        assert!(short.to_string().contains("1 of 2"), "{short}");
    }

    #[test]
    fn a_framing_fault_names_the_reranker_not_the_embedding_gateway() {
        let reply = b"garbage".to_vec();
        let broken = Reranker {
            address: ([127, 0, 0, 1], serve_n(1, reply)).into(),
            candidates: 32,
        };
        let error = broken.order("q", &["a", "b"]).unwrap_err().to_string();
        assert!(error.contains("the reranker at 127.0.0.1"), "{error}");
        assert!(!error.contains("embedding"), "{error}");
    }
}
