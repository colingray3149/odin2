use std::{fmt, str::FromStr};

use odin_domain::{CommandId, EventId, SessionId};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

#[derive(Clone, Debug, PartialEq)]
pub struct NewLiveSession {
    pub session_id: SessionId,
    pub seat_id: String,
    pub project_id: String,
    pub slice_id: String,
    pub lane_id: String,
    pub target_node_id: String,
    pub provider: String,
    pub model: String,
    pub title: Option<String>,
    pub manifest: Value,
    pub open_tab: bool,
    pub state: String,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LiveSession {
    pub session_id: SessionId,
    pub epoch: i64,
    pub event_head: i64,
    pub terminal_head: i64,
    pub revision: i64,
    pub manifest: Value,
    pub title: Option<String>,
    pub state: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewLiveEvent {
    pub event_id: EventId,
    pub session_id: SessionId,
    pub expected_epoch: i64,
    pub occurred_at: OffsetDateTime,
    pub body: Value,
    pub blob_refs: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LiveEvent {
    pub event_id: EventId,
    pub session_id: SessionId,
    pub epoch: i64,
    pub sequence: i64,
    pub occurred_at: OffsetDateTime,
    pub body: Value,
    pub blob_refs: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewLiveCommand {
    pub command_id: CommandId,
    pub session_id: SessionId,
    pub expected_epoch: i64,
    pub expected_event_head: Option<i64>,
    pub body: Value,
    pub issued_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LiveCommand {
    pub command_id: CommandId,
    pub session_id: SessionId,
    pub expected_epoch: i64,
    pub expected_event_head: Option<i64>,
    pub body: Value,
    pub issued_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    pub outcome: Option<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AppendLiveCommand {
    Inserted(LiveCommand),
    Existing(LiveCommand),
}
#[derive(Clone, Debug, PartialEq)]
pub enum CompleteLiveCommand {
    Completed(LiveCommand),
    Existing(LiveCommand),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveMetadataKind {
    Terminal,
    File,
    Render,
}
impl LiveMetadataKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::File => "file",
            Self::Render => "render",
        }
    }
}

/// Failed means child exit outside a bridge stop; Ended means a completed bridge stop.
/// Neither state is reopened to fix expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveSessionExit {
    Failed,
    Ended,
}

impl LiveSessionExit {
    fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Ended => "ended",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LiveMetadata {
    pub session_id: SessionId,
    pub kind: LiveMetadataKind,
    pub key: String,
    pub payload: Value,
    pub revision: i64,
    pub updated_at: OffsetDateTime,
}

impl Ledger {
    pub fn create_live_session(&mut self, new: &NewLiveSession) -> LedgerResult<LiveSession> {
        self.create_live_session_at(new, 1)
    }

    /// Publish the supervisor journal's exact admission epoch rather than restarting its counter.
    pub fn create_live_session_at(
        &mut self,
        new: &NewLiveSession,
        epoch: i64,
    ) -> LedgerResult<LiveSession> {
        positive("live session epoch", epoch)?;
        let title = new.title.as_ref().map(json).transpose()?;
        let manifest = json(&new.manifest)?;
        let at = encode_utc(new.created_at)?;
        self.with_tx(|tx| {
            tx.execute("INSERT INTO live_sessions(session_id,seat_id,project_id,slice_id,lane_id,target_node_id,provider,model,title_json,manifest_json,epoch,event_head,terminal_head,open_tab,state,revision,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,0,?12,?13,0,?14,?14)", params![new.session_id.to_string(),new.seat_id,new.project_id,new.slice_id,new.lane_id,new.target_node_id,new.provider,new.model,title,manifest,epoch,new.open_tab,new.state,at])?;
            session(tx, &new.session_id)
        })
    }

    pub fn reclaim_live_session(
        &mut self,
        id: &SessionId,
        expected_epoch: i64,
        at: OffsetDateTime,
    ) -> LedgerResult<LiveSession> {
        positive("expected epoch", expected_epoch)?;
        let at = encode_utc(at)?;
        self.with_tx(|tx| {
            // Ended sessions cannot return to ready, and stale epochs cannot reclaim them.
            let (row_epoch, row_state): (i64, String) = tx
                .query_row(
                    "SELECT epoch,state FROM live_sessions WHERE session_id=?1",
                    [id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .ok_or_else(|| missing("live session", id))?;
            if row_state == "ended" {
                return Err(LedgerError::SessionEnded { id: id.to_string() });
            }
            if row_epoch != expected_epoch {
                return Err(stale_session(tx, id, expected_epoch)?);
            }
            let changed = tx.query_row("UPDATE live_sessions SET epoch=epoch+1,revision=revision+1,updated_at=?3,retired_at=NULL,state='ready' WHERE session_id=?1 AND epoch=?2 RETURNING epoch", params![id.to_string(),expected_epoch,at], |r| r.get::<_,i64>(0)).optional()?;
            if changed.is_none() { return Err(stale_session(tx,id,expected_epoch)?); }
            session(tx,id)
        })
    }

    /// Atomically reconcile to the supervisor's epoch without rewinding a newer row or reopening an ended session.
    pub fn reclaim_live_session_to(
        &mut self,
        id: &SessionId,
        epoch: i64,
        at: OffsetDateTime,
    ) -> LedgerResult<LiveSession> {
        positive("live session epoch", epoch)?;
        let at = encode_utc(at)?;
        self.with_tx(|tx| {
            let (row_epoch, row_state): (i64, String) = tx
                .query_row(
                    "SELECT epoch,state FROM live_sessions WHERE session_id=?1",
                    [id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .ok_or_else(|| missing("live session", id))?;
            if row_state == "ended" {
                return Err(LedgerError::SessionEnded { id: id.to_string() });
            }
            if row_epoch > epoch {
                return Err(stale_session(tx, id, epoch)?);
            }
            let changed = tx.query_row("UPDATE live_sessions SET epoch=?2,revision=revision+1,updated_at=?3,retired_at=NULL,state='ready' WHERE session_id=?1 AND state!='ended' RETURNING epoch", params![id.to_string(),epoch,at], |r| r.get::<_,i64>(0)).optional()?;
            if changed.is_none() {
                return Err(stale_session(tx, id, epoch)?);
            }
            session(tx, id)
        })
    }

    /// Retires the session; repeated exits are unchanged, failed may advance to ended,
    /// and ended is final.
    pub fn finish_live_session(
        &mut self,
        id: &SessionId,
        expected_epoch: i64,
        exit: LiveSessionExit,
        at: OffsetDateTime,
    ) -> LedgerResult<LiveSession> {
        let at = encode_utc(at)?;
        let state = exit.as_str();
        self.with_tx(|tx| {
            let changed = tx.execute(
                "UPDATE live_sessions SET state=?4,retired_at=?3,revision=revision+1,\
                 updated_at=?3 WHERE session_id=?1 AND epoch=?2 AND state!='ended' AND state!=?4",
                params![id.to_string(), expected_epoch, at, state],
            )?;
            if changed == 0 {
                let (row_epoch, retired): (i64, Option<String>) = tx
                    .query_row(
                        "SELECT epoch,retired_at FROM live_sessions WHERE session_id=?1",
                        [id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?
                    .ok_or_else(|| missing("live session", id))?;
                if row_epoch != expected_epoch || retired.is_none() {
                    return Err(stale_session(tx, id, expected_epoch)?);
                }
                return session(tx, id);
            }
            session(tx, id)
        })
    }

    pub fn live_session(&self, id: &SessionId) -> LedgerResult<LiveSession> {
        session(self.connection(), id)
    }

    /// Returns ready sessions oldest by update time for startup reconciliation.
    pub fn ready_live_sessions(&self) -> LedgerResult<Vec<LiveSession>> {
        let mut statement = self.connection().prepare(
            "SELECT session_id,title_json,manifest_json,epoch,event_head,terminal_head,state,\
             revision,created_at,updated_at FROM live_sessions WHERE state='ready' \
             ORDER BY updated_at",
        )?;
        let raw = statement
            .query_map([], raw_session)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raw.into_iter().map(TryInto::try_into).collect()
    }

    /// Returns ended and failed sessions for reconciling an unfinished file journal.
    pub fn terminal_live_session_states(&self) -> LedgerResult<Vec<(String, i64, String)>> {
        let mut statement = self.connection().prepare(
            "SELECT session_id, epoch, state FROM live_sessions WHERE state IN ('ended', 'failed')",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn reconnect_head(&self, id: &SessionId) -> LedgerResult<i64> {
        self.connection()
            .prepare_cached("SELECT event_head FROM live_sessions WHERE session_id=?1")?
            .query_row([id.as_str()], |row| row.get(0))
            .optional()?
            .ok_or_else(|| missing("live session", id))
    }

    /// All references in `blob_refs` must already be durable. Allocation and insert are atomic.
    pub fn append_live_event_after_blobs(&mut self, new: &NewLiveEvent) -> LedgerResult<LiveEvent> {
        positive("expected epoch", new.expected_epoch)?;
        let at = encode_utc(new.occurred_at)?;
        let body = json(&new.body)?;
        let blobs = json(&new.blob_refs)?;
        let sequence = self.with_tx(|tx| {
            let mut advance = tx.prepare_cached(
                "UPDATE live_sessions SET event_head=event_head+1,revision=revision+1,updated_at=?3 WHERE session_id=?1 AND epoch=?2 RETURNING event_head",
            )?;
            let seq = advance
                .query_row(
                    params![new.session_id.as_str(), new.expected_epoch, &at],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            let seq = match seq {
                Some(value) => value,
                None => return Err(stale_session(tx, &new.session_id, new.expected_epoch)?),
            };
            tx.prepare_cached(
                "INSERT INTO live_events(event_id,session_id,epoch,sequence,occurred_at,body_json,blob_refs_json) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            )?
            .execute(params![
                new.event_id.as_str(),
                new.session_id.as_str(),
                new.expected_epoch,
                seq,
                &at,
                &body,
                &blobs,
            ])?;
            Ok(seq)
        })?;
        // Return the written values to avoid another query and JSON decode.
        Ok(LiveEvent {
            event_id: new.event_id.clone(),
            session_id: new.session_id.clone(),
            epoch: new.expected_epoch,
            sequence,
            occurred_at: decode_utc(&at)?,
            body: new.body.clone(),
            blob_refs: new.blob_refs.clone(),
        })
    }

    /// Returns exactly `(cursor, captured_head]`, ordered by durable sequence.
    pub fn live_event_history(
        &self,
        id: &SessionId,
        cursor: i64,
        head: i64,
    ) -> LedgerResult<Vec<LiveEvent>> {
        nonnegative("cursor", cursor)?;
        nonnegative("captured head", head)?;
        if head < cursor {
            return Err(LedgerError::invalid_data(format!(
                "captured head {head} precedes cursor {cursor}"
            )));
        }
        let actual = self.reconnect_head(id)?;
        if head > actual {
            return Err(LedgerError::invalid_data(format!(
                "captured head {head} exceeds durable head {actual}"
            )));
        }
        let mut statement = self.connection().prepare_cached(
            "SELECT event_id,session_id,epoch,sequence,occurred_at,body_json,blob_refs_json FROM live_events WHERE session_id=?1 AND sequence>?2 AND sequence<=?3 ORDER BY sequence",
        )?;
        let raw = statement
            .query_map(params![id.as_str(), cursor, head], raw_event)?
            .collect::<Result<Vec<_>, _>>()?;
        raw.into_iter().map(TryInto::try_into).collect()
    }

    /// Persists before execution. Duplicate IDs return their exact original command.
    pub fn append_live_command(&mut self, new: &NewLiveCommand) -> LedgerResult<AppendLiveCommand> {
        positive("expected epoch", new.expected_epoch)?;
        if let Some(h) = new.expected_event_head {
            nonnegative("expected event head", h)?;
        }
        let at = encode_utc(new.issued_at)?;
        let body = json(&new.body)?;
        self.with_tx(|tx| {
            if let Some(old)=optional_command(tx,&new.command_id)? { return Ok(AppendLiveCommand::Existing(old)); }
            let (epoch,head)=tx.query_row("SELECT epoch,event_head FROM live_sessions WHERE session_id=?1",[new.session_id.to_string()],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?))).optional()?.ok_or_else(||missing("live session",&new.session_id))?;
            if epoch!=new.expected_epoch { return Err(stale(format!("live session {} epoch",new.session_id),new.expected_epoch,epoch)); }
            if let Some(expected)=new.expected_event_head { if expected!=head { return Err(stale(format!("live session {} event head",new.session_id),expected,head)); } }
            tx.execute("INSERT INTO live_commands(command_id,session_id,expected_epoch,expected_event_head,body_json,issued_at,completed_at,outcome_json) VALUES(?1,?2,?3,?4,?5,?6,NULL,NULL)",params![new.command_id.to_string(),new.session_id.to_string(),new.expected_epoch,new.expected_event_head,body,at])?;
            Ok(AppendLiveCommand::Inserted(command(tx,&new.command_id)?))
        })
    }

    pub fn complete_live_command_once(
        &mut self,
        id: &CommandId,
        outcome: &Value,
        at: OffsetDateTime,
    ) -> LedgerResult<CompleteLiveCommand> {
        let outcome = json(outcome)?;
        let at = encode_utc(at)?;
        self.with_tx(|tx| {
            let old=command(tx,id)?;
            if old.completed_at.is_some() { return Ok(CompleteLiveCommand::Existing(old)); }
            let changed=tx.execute("UPDATE live_commands SET completed_at=?2,outcome_json=?3 WHERE command_id=?1 AND completed_at IS NULL",params![id.to_string(),at,outcome])?;
            let stored=command(tx,id)?;
            if changed==1 { Ok(CompleteLiveCommand::Completed(stored)) } else { Ok(CompleteLiveCommand::Existing(stored)) }
        })
    }

    pub fn live_command(&self, id: &CommandId) -> LedgerResult<LiveCommand> {
        command(self.connection(), id)
    }

    pub fn put_live_metadata(
        &mut self,
        id: &SessionId,
        kind: LiveMetadataKind,
        key: &str,
        payload: &Value,
        expected: Option<i64>,
        at: OffsetDateTime,
    ) -> LedgerResult<LiveMetadata> {
        if key.is_empty() {
            return Err(LedgerError::invalid_data(
                "live metadata key must not be empty".into(),
            ));
        }
        if let Some(v) = expected {
            nonnegative("expected metadata revision", v)?;
        }
        let payload = json(payload)?;
        let at = encode_utc(at)?;
        self.with_tx(|tx| {
            match expected {
                None=>{tx.execute("INSERT INTO live_metadata(session_id,kind,metadata_key,payload_json,revision,updated_at) VALUES(?1,?2,?3,?4,0,?5)",params![id.to_string(),kind.as_str(),key,payload,at])?;}
                Some(rev)=>{let n=tx.execute("UPDATE live_metadata SET payload_json=?4,revision=revision+1,updated_at=?5 WHERE session_id=?1 AND kind=?2 AND metadata_key=?3 AND revision=?6",params![id.to_string(),kind.as_str(),key,payload,at,rev])?;if n!=1{return Err(stale_metadata(tx,id,kind,key,rev)?);}}
            }
            metadata(tx,id,kind,key)
        })
    }

    pub fn live_metadata(
        &self,
        id: &SessionId,
        kind: LiveMetadataKind,
        key: &str,
    ) -> LedgerResult<LiveMetadata> {
        metadata(self.connection(), id, kind, key)
    }
}

fn stale(actor: String, expected_revision: i64, actual_revision: i64) -> LedgerError {
    LedgerError::StaleActor {
        actor,
        expected_revision,
        actual_revision,
    }
}
fn missing(kind: &'static str, id: &impl fmt::Display) -> LedgerError {
    LedgerError::NotFound {
        kind,
        id: id.to_string(),
    }
}
fn json(v: &impl serde::Serialize) -> LedgerResult<String> {
    Ok(serde_json::to_string(v)?)
}
fn parsed<T: serde::de::DeserializeOwned>(v: &str) -> LedgerResult<T> {
    Ok(serde_json::from_str(v)?)
}
fn parse_id<T: FromStr>(kind: &str, v: &str) -> LedgerResult<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    v.parse().map_err(|error| {
        LedgerError::invalid_data_caused_by(format!("invalid stored {kind} {v:?}"), error)
    })
}
fn positive(name: &str, v: i64) -> LedgerResult<()> {
    if v > 0 {
        Ok(())
    } else {
        Err(LedgerError::invalid_data(format!(
            "{name} must be positive, got {v}"
        )))
    }
}
fn nonnegative(name: &str, v: i64) -> LedgerResult<()> {
    if v >= 0 {
        Ok(())
    } else {
        Err(LedgerError::invalid_data(format!(
            "{name} must be nonnegative, got {v}"
        )))
    }
}

struct RawSession {
    session: String,
    title: Option<String>,
    manifest: String,
    epoch: i64,
    event_head: i64,
    terminal_head: i64,
    state: String,
    revision: i64,
    created: String,
    updated: String,
}
fn raw_session(r: &Row<'_>) -> rusqlite::Result<RawSession> {
    Ok(RawSession {
        session: r.get(0)?,
        title: r.get(1)?,
        manifest: r.get(2)?,
        epoch: r.get(3)?,
        event_head: r.get(4)?,
        terminal_head: r.get(5)?,
        state: r.get(6)?,
        revision: r.get(7)?,
        created: r.get(8)?,
        updated: r.get(9)?,
    })
}
impl TryFrom<RawSession> for LiveSession {
    type Error = LedgerError;
    fn try_from(v: RawSession) -> LedgerResult<Self> {
        Ok(Self {
            session_id: parse_id("session_id", &v.session)?,
            epoch: v.epoch,
            event_head: v.event_head,
            terminal_head: v.terminal_head,
            revision: v.revision,
            manifest: parsed(&v.manifest)?,
            title: v.title.as_deref().map(parsed).transpose()?,
            state: v.state,
            created_at: decode_utc(&v.created)?,
            updated_at: decode_utc(&v.updated)?,
        })
    }
}
fn session(c: &Connection, id: &SessionId) -> LedgerResult<LiveSession> {
    let raw=c.query_row("SELECT session_id,title_json,manifest_json,epoch,event_head,terminal_head,state,revision,created_at,updated_at FROM live_sessions WHERE session_id=?1",[id.to_string()],raw_session).optional()?.ok_or_else(||missing("live session",id))?;
    raw.try_into()
}
fn stale_session(tx: &Transaction<'_>, id: &SessionId, expected: i64) -> LedgerResult<LedgerError> {
    let actual = tx
        .query_row(
            "SELECT epoch FROM live_sessions WHERE session_id=?1",
            [id.to_string()],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;
    Ok(match actual {
        Some(a) => stale(format!("live session {id} epoch"), expected, a),
        None => missing("live session", id),
    })
}

struct RawEvent {
    event: String,
    session: String,
    epoch: i64,
    sequence: i64,
    at: String,
    body: String,
    blobs: String,
}
fn raw_event(r: &Row<'_>) -> rusqlite::Result<RawEvent> {
    Ok(RawEvent {
        event: r.get(0)?,
        session: r.get(1)?,
        epoch: r.get(2)?,
        sequence: r.get(3)?,
        at: r.get(4)?,
        body: r.get(5)?,
        blobs: r.get(6)?,
    })
}
impl TryFrom<RawEvent> for LiveEvent {
    type Error = LedgerError;
    fn try_from(v: RawEvent) -> LedgerResult<Self> {
        Ok(Self {
            event_id: parse_id("event_id", &v.event)?,
            session_id: parse_id("session_id", &v.session)?,
            epoch: v.epoch,
            sequence: v.sequence,
            occurred_at: decode_utc(&v.at)?,
            body: parsed(&v.body)?,
            blob_refs: parsed(&v.blobs)?,
        })
    }
}

struct RawCommand {
    command: String,
    session: String,
    epoch: i64,
    head: Option<i64>,
    body: String,
    issued: String,
    completed: Option<String>,
    outcome: Option<String>,
}
fn raw_command(r: &Row<'_>) -> rusqlite::Result<RawCommand> {
    Ok(RawCommand {
        command: r.get(0)?,
        session: r.get(1)?,
        epoch: r.get(2)?,
        head: r.get(3)?,
        body: r.get(4)?,
        issued: r.get(5)?,
        completed: r.get(6)?,
        outcome: r.get(7)?,
    })
}
impl TryFrom<RawCommand> for LiveCommand {
    type Error = LedgerError;
    fn try_from(v: RawCommand) -> LedgerResult<Self> {
        Ok(Self {
            command_id: parse_id("command_id", &v.command)?,
            session_id: parse_id("session_id", &v.session)?,
            expected_epoch: v.epoch,
            expected_event_head: v.head,
            body: parsed(&v.body)?,
            issued_at: decode_utc(&v.issued)?,
            completed_at: v.completed.as_deref().map(decode_utc).transpose()?,
            outcome: v.outcome.as_deref().map(parsed).transpose()?,
        })
    }
}
fn optional_command(c: &Connection, id: &CommandId) -> LedgerResult<Option<LiveCommand>> {
    c.query_row("SELECT command_id,session_id,expected_epoch,expected_event_head,body_json,issued_at,completed_at,outcome_json FROM live_commands WHERE command_id=?1",[id.to_string()],raw_command).optional()?.map(TryInto::try_into).transpose()
}
fn command(c: &Connection, id: &CommandId) -> LedgerResult<LiveCommand> {
    optional_command(c, id)?.ok_or_else(|| missing("live command", id))
}

fn metadata(
    c: &Connection,
    id: &SessionId,
    kind: LiveMetadataKind,
    key: &str,
) -> LedgerResult<LiveMetadata> {
    let raw=c.query_row("SELECT payload_json,revision,updated_at FROM live_metadata WHERE session_id=?1 AND kind=?2 AND metadata_key=?3",params![id.to_string(),kind.as_str(),key],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?))).optional()?.ok_or_else(||LedgerError::NotFound{kind:"live metadata",id:format!("{}/{}/{}",id,kind.as_str(),key)})?;
    Ok(LiveMetadata {
        session_id: id.clone(),
        kind,
        key: key.into(),
        payload: parsed(&raw.0)?,
        revision: raw.1,
        updated_at: decode_utc(&raw.2)?,
    })
}
fn stale_metadata(
    tx: &Transaction<'_>,
    id: &SessionId,
    kind: LiveMetadataKind,
    key: &str,
    expected: i64,
) -> LedgerResult<LedgerError> {
    let actual=tx.query_row("SELECT revision FROM live_metadata WHERE session_id=?1 AND kind=?2 AND metadata_key=?3",params![id.to_string(),kind.as_str(),key],|r|r.get::<_,i64>(0)).optional()?;
    Ok(match actual {
        Some(a) => stale(
            format!("live metadata {}/{}/{}", id, kind.as_str(), key),
            expected,
            a,
        ),
        None => LedgerError::NotFound {
            kind: "live metadata",
            id: format!("{}/{}/{}", id, kind.as_str(), key),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn at() -> OffsetDateTime {
        decode_utc("2026-08-31T12:00:00Z").expect("timestamp")
    }

    fn path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "odin-live-{label}-{}-{nonce}.sqlite",
            std::process::id()
        ))
    }

    fn open(path: &std::path::Path) -> Ledger {
        let ledger = Ledger::open(path).expect("open");
        ledger.connection().execute(
            "INSERT OR IGNORE INTO lanes(lane_id,seat_id,template_id,backend,status,created_by,created_at,updated_at)
             VALUES('lane:test','seat:test','template:test','local_omp','ready','test',
                    '2026-08-31T12:00:00Z','2026-08-31T12:00:00Z')", [],
        ).expect("lane");
        ledger
    }

    fn spec() -> NewLiveSession {
        NewLiveSession {
            session_id: SessionId::new("session:test").unwrap(),
            seat_id: "seat:test".into(),
            project_id: "project:test".into(),
            slice_id: "slice:test".into(),
            lane_id: "lane:test".into(),
            target_node_id: "node:test".into(),
            provider: "provider".into(),
            model: "model".into(),
            title: None,
            manifest: json!({}),
            open_tab: true,
            state: "idle".into(),
            created_at: at(),
        }
    }

    /// The durable retirement stamp lives on the row, not on the domain
    /// projection; tests read it straight from the table.
    fn retired_at(ledger: &Ledger, id: &SessionId) -> Option<String> {
        ledger
            .connection()
            .query_row(
                "SELECT retired_at FROM live_sessions WHERE session_id=?1",
                [id.to_string()],
                |row| row.get::<_, Option<String>>(0),
            )
            .expect("retired_at read")
    }

    #[test]
    fn finish_live_session_retires_the_row_and_replays_idempotently() {
        let path = path("finish");
        let mut ledger = open(&path);
        let session = ledger.create_live_session(&spec()).unwrap();
        let finished = ledger
            .finish_live_session(&session.session_id, 1, LiveSessionExit::Failed, at())
            .unwrap();
        assert_eq!(finished.state, "failed");
        assert!(retired_at(&ledger, &session.session_id).is_some());
        // Idempotent: a second death record neither resurrects the row nor
        // double-advances its revision.
        let again = ledger
            .finish_live_session(&session.session_id, 1, LiveSessionExit::Failed, at())
            .unwrap();
        assert_eq!(again.revision, finished.revision);
        assert_eq!(again.state, "failed");
        // A stale epoch cannot retire the row.
        assert!(ledger
            .finish_live_session(&session.session_id, 9, LiveSessionExit::Failed, at())
            .is_err());
        // Recovery clears the retirement stamp and republishes the live
        // state: neither a dead nor a reclaimed session stays a lie.
        let reclaimed = ledger
            .reclaim_live_session(&session.session_id, 1, at())
            .unwrap();
        assert_eq!(reclaimed.epoch, 2);
        assert!(retired_at(&ledger, &session.session_id).is_none());
        assert_eq!(reclaimed.state, "ready");
        drop(ledger);
        fs::remove_file(path).ok();
    }

    #[test]
    fn reclaim_live_session_refuses_a_truthfully_ended_row() {
        let path = path("ended-refusal");
        let mut ledger = open(&path);
        let session = ledger.create_live_session(&spec()).unwrap();
        // A crashed (`failed`) session stays finalizable to `ended`: an
        // explicit operator stop after a crash must win.
        ledger
            .finish_live_session(&session.session_id, 1, LiveSessionExit::Failed, at())
            .unwrap();
        let ended = ledger
            .finish_live_session(&session.session_id, 1, LiveSessionExit::Ended, at())
            .unwrap();
        assert_eq!(ended.state, "ended");
        // A terminal session is never epoch-bumped back to `ready`, no
        // matter which caller asked.
        let error = ledger
            .reclaim_live_session(&session.session_id, 1, at())
            .unwrap_err();
        assert!(
            error.to_string().contains("truthfully ended"),
            "the refusal must name the terminal state: {error}"
        );
        assert!(retired_at(&ledger, &session.session_id).is_some());
        drop(ledger);
        fs::remove_file(path).ok();
    }

    #[test]
    fn reclaim_live_session_to_binds_the_exact_requested_epoch() {
        let path = path("reclaim-to");
        let mut ledger = open(&path);
        let session = ledger.create_live_session(&spec()).unwrap();
        // A row behind the supervisor's requested admission epoch is
        // corrected FORWARD to exactly that epoch, never bumped past it.
        let bound = ledger
            .reclaim_live_session_to(&session.session_id, 4, at())
            .unwrap();
        assert_eq!(bound.epoch, 4);
        assert_eq!(bound.state, "ready");
        assert!(retired_at(&ledger, &session.session_id).is_none());
        // A row already at the requested epoch re-asserts `ready`
        // idempotently at the same epoch.
        let reasserted = ledger
            .reclaim_live_session_to(&session.session_id, 4, at())
            .unwrap();
        assert_eq!(reasserted.epoch, 4);
        assert_eq!(reasserted.revision, bound.revision + 1);
        // A row AHEAD of the request is a stale incarnation asking to
        // rewind a published epoch: refused typed.
        let error = ledger
            .reclaim_live_session_to(&session.session_id, 2, at())
            .unwrap_err();
        assert!(
            error.to_string().contains("stale"),
            "the rewind request must be refused as stale: {error}"
        );
        assert_eq!(
            ledger.live_session(&session.session_id).unwrap().epoch,
            4,
            "the refused rewind must not move the row"
        );
        drop(ledger);
        fs::remove_file(path).ok();
    }

    #[test]
    fn reclaim_live_session_to_refuses_a_truthfully_ended_row() {
        let path = path("reclaim-to-ended");
        let mut ledger = open(&path);
        let session = ledger.create_live_session(&spec()).unwrap();
        ledger
            .finish_live_session(&session.session_id, 1, LiveSessionExit::Ended, at())
            .unwrap();
        let error = ledger
            .reclaim_live_session_to(&session.session_id, 5, at())
            .unwrap_err();
        assert!(
            error.to_string().contains("truthfully ended"),
            "the exact-epoch binding must honor terminality: {error}"
        );
        drop(ledger);
        fs::remove_file(path).ok();
    }

    #[test]
    fn create_live_session_at_publishes_the_requested_first_epoch() {
        let path = path("create-at");
        let mut ledger = open(&path);
        let created = ledger.create_live_session_at(&spec(), 7).unwrap();
        assert_eq!(created.epoch, 7);
        assert_eq!(created.event_head, 0);
        assert!(ledger.create_live_session_at(&spec(), 0).is_err());
        drop(ledger);
        fs::remove_file(path).ok();
    }

    #[test]
    fn reconnect_interval_and_epoch_sequence() {
        let path = path("replay");
        let mut ledger = open(&path);
        let session = ledger.create_live_session(&spec()).unwrap();
        for n in 1..=3 {
            ledger
                .append_live_event_after_blobs(&NewLiveEvent {
                    event_id: EventId::new(format!("event:{n}")).unwrap(),
                    session_id: session.session_id.clone(),
                    expected_epoch: 1,
                    occurred_at: at(),
                    body: json!({"n": n}),
                    blob_refs: json!([]),
                })
                .unwrap();
        }
        let head = ledger.reconnect_head(&session.session_id).unwrap();
        let sequences = ledger
            .live_event_history(&session.session_id, 1, head)
            .unwrap()
            .into_iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>();
        assert_eq!(sequences, vec![2, 3]);
        ledger
            .reclaim_live_session(&session.session_id, 1, at())
            .unwrap();
        let event = ledger
            .append_live_event_after_blobs(&NewLiveEvent {
                event_id: EventId::new("event:4").unwrap(),
                session_id: session.session_id,
                expected_epoch: 2,
                occurred_at: at(),
                body: json!({}),
                blob_refs: json!([]),
            })
            .unwrap();
        assert_eq!(event.sequence, 4);
        drop(ledger);
        fs::remove_file(path).ok();
    }

    #[test]
    fn appended_event_matches_the_row_history_reads() {
        let path = path("append-roundtrip");
        let mut ledger = open(&path);
        let session = ledger.create_live_session(&spec()).unwrap();
        let appended = ledger
            .append_live_event_after_blobs(&NewLiveEvent {
                event_id: EventId::new("event:round").unwrap(),
                session_id: session.session_id.clone(),
                expected_epoch: 1,
                occurred_at: at(),
                body: json!({"n": 1, "text": "kept"}),
                blob_refs: json!([]),
            })
            .unwrap();
        let stored = ledger
            .live_event_history(&session.session_id, 0, appended.sequence)
            .unwrap();
        assert_eq!(stored, vec![appended]);
        drop(ledger);
        fs::remove_file(path).ok();
    }

    #[test]
    fn duplicate_command_and_stale_epoch() {
        let path = path("command");
        let mut ledger = open(&path);
        let session = ledger.create_live_session(&spec()).unwrap();
        let original = NewLiveCommand {
            command_id: CommandId::new("command:one").unwrap(),
            session_id: session.session_id.clone(),
            expected_epoch: 1,
            expected_event_head: Some(0),
            body: json!({"original": true}),
            issued_at: at(),
        };
        assert!(matches!(
            ledger.append_live_command(&original).unwrap(),
            AppendLiveCommand::Inserted(_)
        ));
        let mut duplicate = original.clone();
        duplicate.body = json!({"replacement": true});
        match ledger.append_live_command(&duplicate).unwrap() {
            AppendLiveCommand::Existing(stored) => assert_eq!(stored.body, original.body),
            AppendLiveCommand::Inserted(_) => panic!("duplicate inserted"),
        }
        ledger
            .reclaim_live_session(&session.session_id, 1, at())
            .unwrap();
        let stale = NewLiveCommand {
            command_id: CommandId::new("command:stale").unwrap(),
            ..original
        };
        assert!(matches!(
            ledger.append_live_command(&stale),
            Err(LedgerError::StaleActor { .. })
        ));
        drop(ledger);
        fs::remove_file(path).ok();
    }

    #[test]
    fn terminal_file_and_render_metadata_survive_reopen() {
        let path = path("metadata");
        let session_id = {
            let mut ledger = open(&path);
            let session = ledger.create_live_session(&spec()).unwrap();
            for (kind, key) in [
                (LiveMetadataKind::Terminal, "terminal"),
                (LiveMetadataKind::File, "file"),
                (LiveMetadataKind::Render, "render"),
            ] {
                ledger
                    .put_live_metadata(
                        &session.session_id,
                        kind,
                        key,
                        &json!({"key": key}),
                        None,
                        at(),
                    )
                    .unwrap();
            }
            session.session_id
        };
        let ledger = Ledger::open(&path).unwrap();
        for (kind, key) in [
            (LiveMetadataKind::Terminal, "terminal"),
            (LiveMetadataKind::File, "file"),
            (LiveMetadataKind::Render, "render"),
        ] {
            assert_eq!(
                ledger
                    .live_metadata(&session_id, kind, key)
                    .unwrap()
                    .payload,
                json!({"key": key})
            );
        }
        drop(ledger);
        fs::remove_file(path).ok();
    }
}
