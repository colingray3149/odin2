//! Renders the owner's capability sheet from the registry: toolsets, their ops, what asks first.

use crate::schema::{CapabilityApprovalToml, RegistryObject};
use crate::toolsets::{
    declared_toolsets, example_op, first_sentence, seat_grants, tool_name, undeclared_toolset,
    Grant,
};

/// How many toolsets contribute a line to "Try saying".
const TRY_SAYING_TOOLSETS: usize = 5;

/// One rendered sheet and the seat it describes.
pub struct Sheet {
    pub seat: String,
    pub markdown: String,
}

/// One sheet for the conversation seat named by `seat`: its toolsets after grants (toolset macros already
/// expanded), in the seat's grant order. Errors name the seat or the toolset.
pub fn render(objects: &[RegistryObject], seat: &str) -> Result<Sheet, String> {
    let toolsets = declared_toolsets(objects);
    let grants = seat_grants(objects, seat)?;
    let mut groups: Vec<(&str, Vec<&Grant>)> = Vec::new();
    let mut direct = Vec::new();
    for grant in &grants {
        match grant.group() {
            Some(group) => match groups.iter_mut().find(|(name, _)| *name == group) {
                Some((_, members)) => members.push(grant),
                None => groups.push((group, vec![grant])),
            },
            None => direct.push(grant),
        }
    }
    let mut title = seat.to_owned();
    if let Some(first) = title.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    let mut lines = vec![
        format!("# What {title} can do"),
        String::new(),
        "Generated from the registry; do not edit.".to_owned(),
        String::new(),
        "## Try saying".to_owned(),
    ];
    let mut tried = 0usize;
    let mut sections = Vec::new();
    for (group, members) in &groups {
        let toolset = toolsets
            .get(*group)
            .ok_or_else(|| undeclared_toolset(group))?;
        let ops: Vec<String> = members.iter().map(|grant| op_of(grant)).collect();
        if tried < TRY_SAYING_TOOLSETS {
            tried += 1;
            if let Some(example) = toolset.examples.iter().find(|example| {
                example_op(example).is_some_and(|op| ops.iter().any(|held| held == op))
            }) {
                lines.push(if example.starts_with(*group) {
                    format!("- `{example}`")
                } else {
                    format!("- `{group} {example}`")
                });
            }
        }
        sections.push(String::new());
        sections.push(format!("## {group}: {}", toolset.description));
        for (grant, op) in members.iter().zip(&ops) {
            sections.push(entry(op, grant));
        }
    }
    lines.extend(sections);
    if !direct.is_empty() {
        lines.push(String::new());
        lines.push("## Other tools".to_owned());
        for grant in direct {
            lines.push(entry(&tool_name(grant.id), grant));
        }
    }
    lines.push(String::new());
    Ok(Sheet {
        seat: seat.to_owned(),
        markdown: lines.join("\n"),
    })
}

fn op_of(grant: &Grant) -> String {
    grant
        .view
        .map(|view| view.op.clone())
        .or_else(|| grant.capability.op.clone())
        .unwrap_or_else(|| grant.id.rsplit('.').next().unwrap_or(grant.id).to_owned())
}

/// One sheet line.
fn entry(name: &str, grant: &Grant) -> String {
    let description = grant.capability.description.trim();
    let marker = match (
        grant.capability.approval_policy == CapabilityApprovalToml::Operator,
        grant.capability.approval_decider.is_owner(),
    ) {
        (true, true) => " [asks you first]",
        (true, false) => " [decided by declaration]",
        (false, _) => "",
    };
    format!("- **{name}**: {}{marker}", first_sentence(description))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RegistryFinding;

    const SEAT: &str = "sinmara";

    fn objects() -> Vec<RegistryObject> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let parsed = crate::parse_objects(&crate::walk(root.join("registry")).objects);
        assert!(
            !parsed.findings.iter().any(RegistryFinding::is_failure),
            "{:?}",
            parsed.findings
        );
        parsed.objects
    }

    fn sheet() -> String {
        render(&objects(), SEAT)
            .expect("the shipped seat renders")
            .markdown
    }

    #[test]
    fn operator_owner_ops_say_asks_you_first() {
        let rendered = sheet();
        let line = rendered
            .lines()
            .find(|line| line.starts_with("- **deploy**"))
            .expect("odin.deploy is listed")
            .to_owned();
        assert!(line.ends_with("[asks you first]"), "{line}");
        let purchase = rendered
            .lines()
            .find(|line| line.starts_with("- **purchase**"))
            .expect("purchase.submit is listed")
            .to_owned();
        assert!(
            purchase.ends_with("[asks you first]"),
            "an omitted owner decider still asks: {purchase}"
        );
    }

    #[test]
    fn internal_capabilities_are_absent() {
        let sheet = sheet();
        assert!(!sheet.contains("discord_intake") && !sheet.contains("**intake**"));
    }

    #[test]
    fn try_saying_lines_name_the_toolset() {
        let rendered = sheet();
        let section: Vec<&str> = rendered
            .lines()
            .skip_while(|line| *line != "## Try saying")
            .skip(1)
            .take_while(|line| line.starts_with("- "))
            .collect();
        assert!(!section.is_empty());
        assert!(
            section.iter().all(|line| !line.starts_with("- `{")),
            "{section:?}"
        );
    }

    #[test]
    fn desktop_lines_say_what_each_op_does() {
        let rendered = sheet();
        assert!(
            rendered.contains("- **device**: Bluetooth") && rendered.contains("- **scene**: Runs")
        );
        assert!(!rendered.contains("Used on the desktop only when"));
    }

    #[test]
    fn declaration_decided_ops_are_marked() {
        let rendered = sheet();
        let marked = rendered
            .lines()
            .filter(|line| line.ends_with("[decided by declaration]"))
            .count();
        assert!(marked > 0, "no declaration-decided op is marked");
        assert!(!rendered.contains("[asks you first] [decided"));
    }
}
