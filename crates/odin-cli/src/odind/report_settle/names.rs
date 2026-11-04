//! What a report's files are called once they leave the pod.

use super::*;

/// The name `path` carries outside the pod: the report's own PDF and
/// companion take the report's name (`stem`), every other file its own.
pub(super) fn delivered_name(path: &str, stem: &str) -> String {
    match path {
        PDF_NAME => format!("{stem}.pdf"),
        COMPANION => format!("{stem}.md"),
        _ => file_name(path).to_owned(),
    }
}

pub(super) fn copy_name(path: &str, stem: &str, used: &mut BTreeSet<String>) -> String {
    let base = delivered_name(path, stem);
    let mut name = base.clone();
    let mut n = 2;
    while !used.insert(name.clone()) {
        let stem = base.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(&base);
        let ext = base.rsplit_once('.').map(|(_, ext)| ext);
        name = match ext {
            Some(ext) => format!("{stem}-{n}.{ext}"),
            None => format!("{stem}-{n}"),
        };
        n += 1;
    }
    name
}

/// The folder the report is filed under, and why: the launch's company, else
/// the report's own title, else the run.
pub(super) fn report_subject(run: &ReportRun, body: &str) -> (String, &'static str) {
    match (run.company.as_deref(), heading_title(body)) {
        (Some(company), _) => (company.to_owned(), "the launch contract"),
        (None, Some(title)) => (
            title,
            "the report's title, because the launch named no company",
        ),
        (None, None) => (
            fallback_subject(&run.target.run),
            "the run, because the launch named no company",
        ),
    }
}

/// What the report's own files are called outside the pod: its title (the
/// companion's first heading), else the company, then the day the run was
/// measured, in the owner's time.
pub(super) fn report_stem(
    run: &ReportRun,
    body: &str,
    captured_at: &str,
) -> Result<String, String> {
    let date = run.runtime.owner_date(captured_at)?;
    let title = heading_title(body)
        .or_else(|| {
            run.company
                .as_deref()
                .map(|company| format!("{} report", company.trim()))
        })
        .unwrap_or_else(|| "Research report".to_owned());
    Ok(format!("{title} {date}"))
}

/// The report's title: its first heading, as a file name.
pub(super) fn heading_title(body: &str) -> Option<String> {
    body.lines()
        .find_map(|line| line.strip_prefix("# "))
        .map(plain_title)
        .filter(|title| !title.is_empty())
}

/// A heading as a file name: no path or reserved characters, one space
/// between words, at most 80 characters.
fn plain_title(heading: &str) -> String {
    let words: Vec<String> = heading
        .split_whitespace()
        .map(|word| {
            word.chars()
                .filter(|c| !c.is_control() && !"/\\:*?\"<>|".contains(*c))
                .collect()
        })
        .filter(|word: &String| !word.is_empty())
        .collect();
    let title: String = words.join(" ").chars().take(80).collect();
    title.trim().trim_end_matches('.').to_owned()
}
