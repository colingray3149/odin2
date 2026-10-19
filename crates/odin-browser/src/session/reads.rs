//! Bounded, always-untrusted page observation and typed read projection.

use std::collections::BTreeMap;
use std::time::Duration;

use time::OffsetDateTime;

use odin_domain::Digest;

use crate::capability::{
    AccessibilityNode, AccessibilityProjection, CapabilityError, DomNode, LinkEntry,
    LinksProjection, PageProvenance, ReadBasis, ReadFreshness, ReadKind, ReadRequest,
    SanitizedDomProjection, TableEntry, TablesProjection, TextProjection, TypedRead,
    MAX_ACCESSIBILITY_NODES, MAX_DOM_NODES, MAX_FRAGMENT_BYTES, MAX_LINK_ENTRIES, MAX_TABLES,
    MAX_TABLE_COLUMNS, MAX_TABLE_ROWS,
};
use crate::worker::{
    ObservePageParams, ObservePageResult, ReadParams, ReadResult, WorkerAccessibilityNode,
    WorkerCaller, WorkerDomNode, WorkerError, WorkerErrorCode, WorkerLink, WorkerMethod,
    WorkerPageIdentity, WorkerReadData, WorkerTable,
};

use super::SessionError;

const SHA256_TOKEN_HEX_BYTES: usize = 64;

/// Current page identity observed through the closed worker protocol.
#[derive(Clone, Debug)]
pub(super) struct PageObservation {
    pub(super) provenance: PageProvenance,
    pub(super) page_title: String,
}

#[derive(Debug, Eq, PartialEq)]
struct ValidatedIdentity {
    display_url: String,
    origin: String,
    exact_url_digest: Digest,
    document_digest: Digest,
}

/// Observes a stable location around the bounded title extraction. Only the
/// worker's sanitized display URL and origin cross stdout; exact URL and
/// document identities cross as opaque SHA-256 tokens and are immediately
/// rebound to Rust-owned BLAKE3 digests.
pub(super) async fn observe_page(
    client: &WorkerCaller,
    deadline: Duration,
) -> Result<PageObservation, SessionError> {
    let response: ObservePageResult = client
        .call(WorkerMethod::ObservePage, &ObservePageParams {}, deadline)
        .await
        .map_err(|error| worker_transport(error, "page observation"))?;
    let identity = stable_identity(
        response.before,
        response.after,
        "page changed during observation",
    )?;
    let observed_at = OffsetDateTime::now_utc();
    let provenance = identity.into_provenance(observed_at)?;
    Ok(PageObservation {
        provenance,
        page_title: truncate_utf8(response.page_title, MAX_FRAGMENT_BYTES),
    })
}

/// Executes one closed, bounded worker read and constructs the public typed
/// projection in Rust. The worker returns only the fixed read variant and
/// sanitized page identity; Rust rechecks the bracket, request/response kind,
/// token format, collection caps, projection byte bounds, freshness, and
/// always-untrusted trust classification.
pub(super) async fn execute_read(
    client: &WorkerCaller,
    request: ReadRequest,
    deadline: Duration,
) -> Result<TypedRead, SessionError> {
    // Reconstruct to validate requests received through unchecked serde fields.
    let request = ReadRequest::new(request.kind, request.max_bytes)?;
    let params = ReadParams {
        kind: request.kind,
        max_bytes: request.max_bytes,
    };
    let response: ReadResult = client
        .call(WorkerMethod::Read, &params, deadline)
        .await
        .map_err(|error| worker_transport(error, "browser read"))?;
    let identity = stable_identity(
        response.before,
        response.after,
        "page changed during read extraction",
    )?;
    let observed_at = OffsetDateTime::now_utc();
    let provenance = identity.into_provenance(observed_at)?;
    let basis = ReadBasis::new(
        provenance,
        ReadFreshness::current(observed_at),
        request.max_bytes,
    )?;

    match (request.kind, response.data) {
        (ReadKind::Text, WorkerReadData::Text { text }) => {
            Ok(TypedRead::Text(TextProjection::build(basis, text)?))
        }
        (ReadKind::Links, WorkerReadData::Links { links }) => Ok(TypedRead::Links(
            LinksProjection::build(basis, convert_links(links)?)?,
        )),
        (ReadKind::Tables, WorkerReadData::Tables { tables }) => Ok(TypedRead::Tables(
            TablesProjection::build(basis, convert_tables(tables)?)?,
        )),
        (ReadKind::Accessibility, WorkerReadData::Accessibility { root }) => {
            Ok(TypedRead::Accessibility(AccessibilityProjection::build(
                basis,
                convert_accessibility(root)?,
            )?))
        }
        (ReadKind::SanitizedDom, WorkerReadData::SanitizedDom { root }) => Ok(
            TypedRead::SanitizedDom(SanitizedDomProjection::build(basis, convert_dom(root)?)?),
        ),
        _ => Err(malformed("worker read kind did not match request")),
    }
}

impl ValidatedIdentity {
    fn from_worker(identity: WorkerPageIdentity) -> Result<Self, SessionError> {
        Ok(Self {
            display_url: identity.display_url,
            origin: identity.origin,
            exact_url_digest: worker_token_digest(
                &identity.url_token,
                "worker exact-URL token was malformed",
            )?,
            document_digest: worker_token_digest(
                &identity.document_token,
                "worker document token was malformed",
            )?,
        })
    }

    fn into_provenance(
        self,
        observed_at: OffsetDateTime,
    ) -> Result<PageProvenance, CapabilityError> {
        PageProvenance::from_sanitized_parts(
            self.display_url,
            self.origin,
            self.exact_url_digest,
            self.document_digest,
            observed_at,
        )
    }
}

fn stable_identity(
    before: WorkerPageIdentity,
    after: WorkerPageIdentity,
    reason: &'static str,
) -> Result<ValidatedIdentity, SessionError> {
    let before = ValidatedIdentity::from_worker(before)?;
    let after = ValidatedIdentity::from_worker(after)?;
    if before != after {
        return Err(CapabilityError::StaleBinding {
            reason: reason.to_owned(),
        }
        .into());
    }
    Ok(after)
}

fn convert_links(links: Vec<WorkerLink>) -> Result<Vec<LinkEntry>, SessionError> {
    if links.len() > MAX_LINK_ENTRIES {
        return Err(malformed("worker links exceeded the entry bound"));
    }
    let mut converted = Vec::with_capacity(links.len());
    for link in links {
        let url_digest =
            worker_token_digest(&link.url_token, "worker link exact-URL token was malformed")?;
        let text = truncate_utf8(link.text, MAX_FRAGMENT_BYTES);
        // Invalid or overlong sanitized hrefs have no safe typed
        // representation. Omit the individual link rather than exposing the
        // string or failing an otherwise valid bounded read.
        if let Ok(link) = LinkEntry::from_sanitized_parts(link.display_url, url_digest, text) {
            converted.push(link);
        }
    }
    Ok(converted)
}

fn convert_tables(tables: Vec<WorkerTable>) -> Result<Vec<TableEntry>, SessionError> {
    if tables.len() > MAX_TABLES {
        return Err(malformed("worker tables exceeded the table bound"));
    }
    let mut converted = Vec::with_capacity(tables.len());
    for table in tables {
        if table.rows.len() > MAX_TABLE_ROWS {
            return Err(malformed("worker table exceeded the row bound"));
        }
        let caption = table
            .caption
            .map(|caption| truncate_utf8(caption, MAX_FRAGMENT_BYTES));
        let mut rows = Vec::with_capacity(table.rows.len());
        for row in table.rows {
            if row.len() > MAX_TABLE_COLUMNS {
                return Err(malformed("worker table row exceeded the column bound"));
            }
            rows.push(
                row.into_iter()
                    .map(|cell| truncate_utf8(cell, MAX_FRAGMENT_BYTES))
                    .collect(),
            );
        }
        converted.push(TableEntry { caption, rows });
    }
    Ok(converted)
}

fn convert_accessibility(root: WorkerAccessibilityNode) -> Result<AccessibilityNode, SessionError> {
    fn convert(
        node: WorkerAccessibilityNode,
        remaining: &mut usize,
    ) -> Result<AccessibilityNode, SessionError> {
        if *remaining == 0 {
            return Err(malformed(
                "worker accessibility tree exceeded the node bound",
            ));
        }
        *remaining -= 1;
        let role = truncate_utf8(node.role, MAX_FRAGMENT_BYTES);
        let forced_leaf = matches!(
            role.to_ascii_lowercase().as_str(),
            "textbox"
                | "textfield"
                | "searchbox"
                | "searchfield"
                | "spinbutton"
                | "combobox"
                | "menulistpopup"
        );
        if forced_leaf {
            return Ok(AccessibilityNode::new(role, String::new(), Vec::new()));
        }
        let name = truncate_utf8(node.name, MAX_FRAGMENT_BYTES);
        let mut children = Vec::with_capacity(node.children.len().min(*remaining));
        for child in node.children {
            children.push(convert(child, remaining)?);
        }
        Ok(AccessibilityNode::new(role, name, children))
    }

    let mut remaining = MAX_ACCESSIBILITY_NODES;
    convert(root, &mut remaining)
}

fn convert_dom(root: WorkerDomNode) -> Result<DomNode, SessionError> {
    fn convert(node: WorkerDomNode, remaining: &mut usize) -> Result<DomNode, SessionError> {
        if *remaining == 0 {
            return Err(malformed("worker DOM exceeded the node bound"));
        }
        *remaining -= 1;
        let mut children = Vec::with_capacity(node.children.len().min(*remaining));
        for child in node.children {
            children.push(convert(child, remaining)?);
        }
        Ok(DomNode::new(
            truncate_utf8(node.tag, MAX_FRAGMENT_BYTES),
            convert_attributes(node.attributes),
            node.text
                .map(|text| truncate_utf8(text, MAX_FRAGMENT_BYTES)),
            children,
        ))
    }

    fn convert_attributes(attributes: BTreeMap<String, String>) -> BTreeMap<String, String> {
        attributes
            .into_iter()
            .map(|(key, value)| {
                (
                    truncate_utf8(key, MAX_FRAGMENT_BYTES),
                    truncate_utf8(value, MAX_FRAGMENT_BYTES),
                )
            })
            .collect()
    }

    let mut remaining = MAX_DOM_NODES;
    convert(root, &mut remaining)
}

fn worker_token_digest(token: &str, reason: &'static str) -> Result<Digest, SessionError> {
    if token.len() != SHA256_TOKEN_HEX_BYTES
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(malformed(reason));
    }
    Ok(Digest::hash(token.as_bytes()))
}

fn truncate_utf8(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn worker_transport(error: WorkerError, operation: &'static str) -> SessionError {
    match error {
        WorkerError::DeadlineExceeded
        | WorkerError::Remote {
            code: WorkerErrorCode::DeadlineExceeded,
            ..
        } => SessionError::Timeout { operation },
        WorkerError::Remote {
            code: WorkerErrorCode::BrowserClosed,
            ..
        } => SessionError::TargetClosed,
        WorkerError::Remote {
            code: WorkerErrorCode::StaleBinding | WorkerErrorCode::DocumentChanged,
            ..
        } => CapabilityError::StaleBinding {
            reason: "worker reported a changed page identity".to_owned(),
        }
        .into(),
        error => SessionError::Transport(error.to_string()),
    }
}

fn malformed(reason: &'static str) -> SessionError {
    SessionError::Transport(reason.to_owned())
}
