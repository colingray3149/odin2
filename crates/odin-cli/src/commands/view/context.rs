//! The injected-context panel's bridge side: the `context` line, a session's newest injected-context record.

use super::{emit, Bridge};
use odin_domain::huginn as live;
use odin_omp::live::context_trace;
use serde_json::json;

impl Bridge {
    /// The newest injection of a session (request records are not one), from
    /// this host's trace. Only the authority writes traces, so another host
    /// answers with a note rather than a guess.
    pub(super) fn context(&self, session: &str) {
        let read = session
            .parse::<live::LiveSessionId>()
            .map_err(|_| format!("{session:?} is not a session id"))
            .and_then(|id| context_trace::read(&context_trace::root(&self.state_root), id));
        let mut line = json!({ "t": "context", "session": session });
        match read {
            Ok(Some(records)) => match records
                .iter()
                .rev()
                .find(|record| record.kind != context_trace::Kind::Request)
            {
                Some(record) => line["record"] = json!(record),
                None => line["note"] = json!(format!("no injected context recorded for {session}")),
            },
            Ok(None) => line["note"] = json!(format!("no injected context recorded for {session}")),
            Err(error) => line["note"] = json!(error),
        }
        emit(&line);
    }
}
