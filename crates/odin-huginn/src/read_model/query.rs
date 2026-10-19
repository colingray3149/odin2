use odin_domain::huginn::{FreshnessState, ObjectKind, ObjectRef, QueryScope, Revision};
use odin_domain::Digest;
use serde::Serialize;

pub type ProjectionScope = QueryScope;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionMetadata {
    pub title: String,
    pub summary: String,
    pub scopes: Vec<ProjectionScope>,
    pub evidence_links: Vec<ObjectRef>,
}

impl ProjectionMetadata {
    pub fn new(title: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            summary: summary.into(),
            scopes: Vec::new(),
            evidence_links: Vec::new(),
        }
    }

    pub fn in_scope(mut self, scope: ProjectionScope) -> Self {
        if !self.scopes.contains(&scope) {
            self.scopes.push(scope);
        }
        self
    }

    pub fn with_evidence(mut self, evidence: ObjectRef) -> Self {
        if !self.evidence_links.contains(&evidence) {
            self.evidence_links.push(evidence);
        }
        self
    }
}

pub(crate) fn matches_scope(metadata: &ProjectionMetadata, scope: &QueryScope) -> bool {
    matches!(scope, QueryScope::All) || metadata.scopes.iter().any(|candidate| candidate == scope)
}

pub(crate) fn matches_kinds(kind: ObjectKind, kinds: &[ObjectKind]) -> bool {
    kinds.is_empty() || kinds.contains(&kind)
}

pub(crate) fn includes_freshness(state: FreshnessState, include_stale: bool) -> bool {
    include_stale || matches!(state, FreshnessState::Fresh)
}

/// The kind set a query means: order and duplicates never change it.
pub(crate) fn canonical_kinds(kinds: &[ObjectKind]) -> Vec<ObjectKind> {
    let mut kinds = kinds.to_vec();
    kinds.sort_unstable();
    kinds.dedup();
    kinds
}

/// The tag of each opaque cursor domain: a cursor of one never parses as
/// another's.
pub(crate) const SNAPSHOT_CURSOR: &str = "huginn.snapshot";
pub(crate) const SEARCH_CURSOR: &str = "huginn.search";
pub(crate) const DELTA_CURSOR: &str = "huginn.delta";

/// The canonical identity a page cursor binds: the operation, scope, kind
/// set, stale filter and normalized search text — never the page limit, so
/// a client may vary its page size along one chain.
#[derive(Serialize)]
struct PageQueryIdentity<'a> {
    operation: &'a str,
    scope: &'a QueryScope,
    kinds: Vec<ObjectKind>,
    include_stale: bool,
    text: Option<String>,
}

pub(crate) fn page_query_digest(
    operation: &str,
    scope: &QueryScope,
    kinds: &[ObjectKind],
    include_stale: bool,
    text: Option<&str>,
) -> Result<String, serde_json::Error> {
    let identity = serde_json::to_vec(&PageQueryIdentity {
        operation,
        scope,
        kinds: canonical_kinds(kinds),
        include_stale,
        text: text.map(normalized_search_text),
    })?;
    Ok(Digest::hash(&identity)
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(crate) fn normalized_search_text(text: &str) -> String {
    text.trim().to_lowercase()
}

pub(crate) struct PageCursor<'a> {
    pub(crate) incarnation: &'a str,
    pub(crate) query: &'a str,
    pub(crate) revision: Revision,
    pub(crate) offset: usize,
}

/// A page cursor names its domain, the model incarnation that issued it,
/// the query identity, the revision and the offset: revisions restart at
/// zero with every model, so the revision alone cannot tell this model's
/// cursor from an earlier daemon's, nor one query's from another's.
pub(crate) fn encode_page_cursor(
    tag: &str,
    incarnation: &str,
    query: &str,
    revision: Revision,
    offset: usize,
) -> String {
    format!("{tag}:{incarnation}:{query}:{}:{offset}", revision.get())
}

pub(crate) fn decode_page_cursor<'a>(tag: &str, cursor: &'a str) -> Result<PageCursor<'a>, String> {
    let mut parts = cursor.split(':');
    let (Some(cursor_tag), Some(incarnation), Some(query), Some(revision), Some(offset), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err("cursor has invalid form".to_owned());
    };
    if cursor_tag != tag {
        return Err(format!("cursor is not a {tag} cursor"));
    }
    let revision =
        Revision::parse(revision).map_err(|_| "cursor revision is invalid".to_owned())?;
    let offset = offset
        .parse::<usize>()
        .map_err(|_| "cursor offset is invalid".to_owned())?;
    Ok(PageCursor {
        incarnation,
        query,
        revision,
        offset,
    })
}

/// The empty-model delta cursor: every model is empty at revision zero.
pub(crate) const DELTA_CURSOR_EMPTY: &str = "0";

pub(crate) fn encode_delta_cursor(incarnation: &str, revision: Revision) -> String {
    format!("{DELTA_CURSOR}:{incarnation}:{}", revision.get())
}

/// Returns `None` for the empty-model cursor; all other cursors include a model and revision.
pub(crate) fn decode_delta_cursor(cursor: &str) -> Result<Option<(&str, Revision)>, String> {
    if cursor == DELTA_CURSOR_EMPTY {
        return Ok(None);
    }
    let mut parts = cursor.split(':');
    let (Some(tag), Some(incarnation), Some(revision), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("delta cursor has invalid form".to_owned());
    };
    if tag != DELTA_CURSOR {
        return Err(format!("cursor is not a {DELTA_CURSOR} cursor"));
    }
    let revision =
        Revision::parse(revision).map_err(|_| "delta cursor revision is invalid".to_owned())?;
    Ok(Some((incarnation, revision)))
}
