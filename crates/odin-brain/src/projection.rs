//! Human-sized Markdown summaries of the projected sources, never another
//! source and never one page per record: the brain serves records from its
//! own index. A source projects either its summary pages (one per project or
//! UTC day, marked on the items) or one index page of record headlines. Each
//! page's bytes depend only on its own content, so an unchanged page is never
//! rewritten and one new record rewrites one page.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use odin_domain::knowledge::AtlasId;
use odin_domain::Digest;

use crate::error::{BrainError, BrainResult};
use crate::source::SourceItem;

pub const MIN_PAGE_BOUND_BYTES: usize = 1024;
const RENDERER: &str = "odin-knowledge-v2";

#[derive(Clone, Copy)]
pub enum ProjectionKind {
    Registry,
    Tasks,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionPage {
    pub relative_page: String,
    pub content: String,
}

/// The daemon implements this over its existing VaultBridge. All writes fully
/// replace pages; retirement deletes stale pages, including after process restart.
/// Listing failure must propagate. Callbacks must not re-enter BrainService.
pub trait KnowledgeProjectionSink: Send + Sync {
    fn max_page_bytes(&self) -> usize;
    fn write_page(&self, source: &AtlasId, relative_page: &str, content: &str) -> BrainResult<()>;
    /// Writes one page shared by every seat (`<source>/<relative_page>`, no
    /// seat subtree): its bytes never depend on the emitting seat.
    fn write_shared_page(
        &self,
        source: &AtlasId,
        relative_page: &str,
        content: &str,
    ) -> BrainResult<()>;
    fn stored_pages(&self, source: &AtlasId) -> BrainResult<Vec<String>>;
    fn remove_page(
        &self,
        source: &AtlasId,
        relative_page: &str,
        superseded_by: &Digest,
    ) -> BrainResult<()>;
}

/// One `<page>.md` per summary page the items name (a project's repository
/// summary, a day of operations history), holding exactly that page's items
/// in source order; records without a summary page never render. Nothing
/// outside the page's own items (no combined source head, no seat) enters
/// its bytes.
pub fn render_summary_pages(
    source: &AtlasId,
    revision: &Digest,
    items: &[SourceItem],
    bound: usize,
) -> BrainResult<Vec<ProjectionPage>> {
    check_items(source, revision, items, bound)?;
    let mut grouped: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for item in items {
        if let Some(page) = &item.summary_page {
            grouped.entry(page).or_default().push(&item.text);
        }
    }
    grouped
        .into_iter()
        .map(|(page, texts)| {
            let body = texts.join("\n\n");
            let fence = "`".repeat(fence_length(&body));
            let prefix = format!(
                "{}# {source} {page}\n\nGenerated reference data; do not edit.\n\n{fence}\n",
                stamp(source, Some(page))
            );
            let suffix = format!("\n{fence}\n");
            let marker = "\n[truncated at the page bound]";
            let mut body = body.as_str();
            let mut truncated = "";
            if prefix.len() + body.len() + suffix.len() > bound {
                let available = bound
                    .checked_sub(prefix.len() + suffix.len() + marker.len())
                    .ok_or_else(|| invalid("page bound cannot hold a summary page"))?;
                let mut end = available.min(body.len());
                while !body.is_char_boundary(end) {
                    end -= 1;
                }
                body = &body[..end];
                truncated = marker;
            }
            Ok(ProjectionPage {
                relative_page: format!("{page}.md"),
                content: format!("{prefix}{body}{truncated}{suffix}"),
            })
        })
        .collect()
}

/// The one `index.md` of a source without summary pages: every record's
/// headline (its first line), sorted, inert in a fence, plus the declared
/// relationship graph for the registry and delegated tasks. Headlines past
/// the page bound are counted, never silently dropped.
pub fn render_source_index(
    source: &AtlasId,
    revision: &Digest,
    items: &[SourceItem],
    kind: ProjectionKind,
    bound: usize,
) -> BrainResult<ProjectionPage> {
    check_items(source, revision, items, bound)?;
    let mut headlines: Vec<&str> = items
        .iter()
        .map(|item| item.text.lines().next().unwrap_or_default())
        .collect();
    headlines.sort_unstable();
    let fence = "`".repeat(fence_length(&headlines.join("\n")));
    let prefix = format!(
        "{}# {source}\n\n{} records; the brain serves each one. Generated reference data; do not edit.\n\n{fence}\n",
        stamp(source, None),
        items.len(),
    );
    let edges = graph_edges(items, kind)?;
    let mut suffix = format!("{fence}\n");
    if !edges.is_empty() {
        suffix.push_str("\n## Declared relationships\n\nThese edges describe source declarations, not live grants.\n\n```mermaid\nflowchart TB\n");
        suffix.extend(edges);
        suffix.push_str("```\n");
    }
    let marker_room = "… 18446744073709551615 more records\n".len();
    let mut budget = bound
        .checked_sub(prefix.len() + suffix.len() + marker_room)
        .ok_or_else(|| invalid("page bound cannot hold the index metadata and relationships"))?;
    let mut content = prefix;
    let mut listed = 0;
    for headline in &headlines {
        if headline.len() + 1 > budget {
            break;
        }
        budget -= headline.len() + 1;
        content.push_str(headline);
        content.push('\n');
        listed += 1;
    }
    if listed < headlines.len() {
        writeln!(content, "… {} more records", headlines.len() - listed).expect("write to string");
    }
    content.push_str(&suffix);
    Ok(ProjectionPage {
        relative_page: "index.md".to_owned(),
        content,
    })
}

fn stamp(source: &AtlasId, page: Option<&str>) -> String {
    let page = page
        .map(|page| format!("page: {page}\n"))
        .unwrap_or_default();
    format!(
        "---\ntags: [generated, knowledge]\nsource: {source}\n{page}renderer: {RENDERER}\n---\n\n"
    )
}

fn check_items(
    source: &AtlasId,
    revision: &Digest,
    items: &[SourceItem],
    bound: usize,
) -> BrainResult<()> {
    if bound < MIN_PAGE_BOUND_BYTES {
        return Err(invalid("page bound cannot hold projection metadata"));
    }
    if items
        .iter()
        .any(|item| item.source != *source || item.source_revision != *revision)
    {
        return Err(BrainError::StaleAuthority {
            authority: "knowledge_projection",
            detail: "projection items do not share the pinned source head".into(),
        });
    }
    Ok(())
}

fn invalid(reason: impl Into<String>) -> BrainError {
    BrainError::InvalidRequest(reason.into())
}

fn fence_length(text: &str) -> usize {
    let mut longest = 0;
    let mut run = 0;
    for byte in text.bytes() {
        if byte == b'`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    (longest + 1).max(3)
}

fn graph_edges(items: &[SourceItem], kind: ProjectionKind) -> BrainResult<BTreeSet<String>> {
    let mut edges = BTreeSet::new();
    for item in items {
        let first = item.text.lines().next().unwrap_or_default();
        match kind {
            ProjectionKind::Registry => {
                let Some(seat) = first.strip_prefix("registry seat ") else {
                    continue;
                };
                let marker = "\ndeclared who-can-do-what (eligibility if bound to each slice; not a live session grant)";
                let (_, grants) = item.text.rsplit_once(marker).ok_or_else(|| {
                    invalid("registry projection has no declaration eligibility section")
                })?;
                for line in grants.lines().filter(|line| !line.is_empty()) {
                    if line == "  (no slices declared)" {
                        continue;
                    }
                    let (_, capabilities) = line
                        .strip_prefix("  slice ")
                        .and_then(|line| line.split_once(": "))
                        .ok_or_else(|| invalid("malformed registry declaration eligibility row"))?;
                    if matches!(
                        capabilities,
                        "disabled or seat disabled; grants nothing"
                            | "no declared effective capabilities"
                    ) {
                        continue;
                    }
                    for capability in capabilities.split(", ") {
                        edges.insert(edge("seat", seat, "capability", capability));
                    }
                }
            }
            ProjectionKind::Tasks => {
                let Some(child) = first.strip_prefix("delegated task ") else {
                    continue;
                };
                let parent = item
                    .text
                    .lines()
                    .find_map(|line| line.strip_prefix("lineage: "))
                    .and_then(|line| line.split_once(" (run "))
                    .map(|(parent, _)| parent)
                    .ok_or_else(|| invalid("delegated task projection has no parent lineage"))?;
                edges.insert(edge("session", parent, "session", child));
            }
            ProjectionKind::Other => {}
        }
    }
    Ok(edges)
}

fn edge(from_kind: &str, from: &str, to_kind: &str, to: &str) -> String {
    let node = |kind: &str, value: &str| {
        let digest = Digest::hash(format!("{kind}\0{value}").as_bytes()).to_string();
        format!("n{}[\"{}: {}\"]", &digest[7..], kind, graph_label(value))
    };
    format!("  {} --> {}\n", node(from_kind, from), node(to_kind, to))
}

fn graph_label(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric()
            || matches!(character, ' ' | '.' | ':' | '_' | '-' | '/')
        {
            escaped.push(character);
        } else {
            write!(escaped, "#{};", u32::from(character)).expect("write to string");
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::knowledge::{KnowledgeItemId, TrustClass};

    fn item(source: &AtlasId, revision: Digest, key: &str, text: &str) -> SourceItem {
        SourceItem {
            source: source.clone(),
            source_revision: revision,
            item_id: KnowledgeItemId::new(Digest::hash(key.as_bytes())),
            trust: TrustClass::Observed,
            provenance: None,
            project: None,
            text: text.into(),
            summary_page: None,
        }
    }

    #[test]
    fn summary_pages_hold_only_their_own_items_and_never_a_record() {
        let source = AtlasId::new("state.repos").unwrap();
        let revision = Digest::hash(b"combined-a");
        let summary = item(
            &source,
            revision,
            "repo/demo/summary",
            &format!("project demo at /r\nhead abc123\n{}", "é".repeat(2000)),
        )
        .with_summary_page("demo");
        let record = item(&source, revision, "repo/demo/ast/node", "fn record() {}");
        let pages =
            render_summary_pages(&source, &revision, &[summary.clone(), record], 1024).unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].relative_page, "demo.md");
        assert!(pages[0].content.len() <= 1024);
        assert!(pages[0].content.contains("head abc123"));
        assert!(pages[0].content.contains("[truncated at the page bound]"));
        assert!(!pages[0].content.contains("fn record"));
        // The combined source head never enters the bytes: another seat's
        // view (different combined head) renders the identical page.
        let other = Digest::hash(b"combined-b");
        let mut moved = summary;
        moved.source_revision = other;
        assert_eq!(
            render_summary_pages(&source, &other, &[moved], 1024).unwrap(),
            pages
        );
    }

    #[test]
    fn a_new_record_rewrites_only_its_days_page() {
        let source = AtlasId::new("ops.history").unwrap();
        let day = |revision: Digest, day: &str, project: &str, count: u32| {
            item(
                &source,
                revision,
                &format!("summary/{day}/project/{project}"),
                &format!("operations history {day} project {project}\naudit events: {count}"),
            )
            .with_summary_page(day)
        };
        let record =
            |revision: Digest, id: &str| item(&source, revision, id, &format!("audit event {id}"));
        let before = Digest::hash(b"before");
        let first = render_summary_pages(
            &source,
            &before,
            &[
                day(before, "2026-10-03", "odin", 1),
                day(before, "2026-10-04", "odin", 1),
                day(before, "2026-10-04", "surtr", 1),
                record(before, "a"),
                record(before, "b"),
                record(before, "c"),
            ],
            4096,
        )
        .unwrap();
        assert_eq!(
            first
                .iter()
                .map(|page| page.relative_page.as_str())
                .collect::<Vec<_>>(),
            ["2026-10-03.md", "2026-10-04.md"]
        );
        assert!(
            first[1].content.contains("project odin") && first[1].content.contains("project surtr")
        );
        let after = Digest::hash(b"after");
        let second = render_summary_pages(
            &source,
            &after,
            &[
                day(after, "2026-10-03", "odin", 1),
                day(after, "2026-10-04", "odin", 2),
                day(after, "2026-10-04", "surtr", 1),
                record(after, "a"),
                record(after, "b"),
                record(after, "c"),
                record(after, "d"),
            ],
            4096,
        )
        .unwrap();
        assert_eq!(second[0], first[0], "an earlier day's page keeps its bytes");
        assert_ne!(second[1], first[1]);
        assert_eq!(second.len(), 2);
    }

    #[test]
    fn index_lists_headlines_inertly_and_counts_what_the_bound_drops() {
        let source = AtlasId::new("state.tasks").unwrap();
        let revision = Digest::hash(b"head");
        let items: Vec<_> = (0..200)
            .map(|index| {
                item(
                    &source,
                    revision,
                    &format!("task-{index}"),
                    &format!("workload run {index:03} ```space-lua\nerror('inert')\ndetail"),
                )
            })
            .collect();
        let page =
            render_source_index(&source, &revision, &items, ProjectionKind::Other, 2048).unwrap();
        assert_eq!(page.relative_page, "index.md");
        assert!(page.content.len() <= 2048);
        assert!(page.content.contains("200 records"));
        assert!(page
            .content
            .contains("````\nworkload run 000 ```space-lua\n"));
        assert!(!page.content.contains("error('inert')"));
        let listed = page.content.matches("workload run").count();
        assert!(page
            .content
            .contains(&format!("… {} more records\n````\n", 200 - listed)));
        let mut reversed = items.clone();
        reversed.reverse();
        assert_eq!(
            render_source_index(&source, &revision, &reversed, ProjectionKind::Other, 2048)
                .unwrap(),
            page
        );
    }

    #[test]
    fn stale_items_refuse_the_entire_projection() {
        let source = AtlasId::new("state.live").unwrap();
        let revision = Digest::hash(b"head");
        let old = item(&source, Digest::hash(b"old"), "key", "old fact");
        assert!(matches!(
            render_source_index(&source, &revision, &[old], ProjectionKind::Other, 2048),
            Err(BrainError::StaleAuthority { .. })
        ));
    }

    #[test]
    fn graphs_follow_declared_eligibility_and_parent_lineage() {
        let source = AtlasId::new("custom.registry").unwrap();
        let revision = Digest::hash(b"head");
        let seat = item(&source, revision, "seat", "registry seat worker\ndeclared who-can-do-what (eligibility if bound to each slice; not a live session grant)\n  slice allowed: brain.read\n  slice disabled: disabled or seat disabled; grants nothing");
        let graph =
            render_source_index(&source, &revision, &[seat], ProjectionKind::Registry, 2048)
                .unwrap()
                .content;
        assert!(graph.contains("## Declared relationships"));
        assert!(graph.contains("seat: worker"));
        assert!(graph.contains("capability: brain.read"));
        assert!(!graph.contains("capability: disabled"));
        let task = item(&source, revision, "task", "delegated task child\nlineage: parent\"<& (run root) delegated worker child (run child-run) at depth 1");
        let graph = render_source_index(&source, &revision, &[task], ProjectionKind::Tasks, 2048)
            .unwrap()
            .content;
        assert!(graph.contains("parent#34;#60;#38;"));
        assert!(graph.contains("session: child"));
        assert!(!graph.contains("parent\"<&"));
    }
}
