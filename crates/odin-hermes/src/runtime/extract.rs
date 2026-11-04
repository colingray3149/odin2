//! Plain text of a file Sinmara is given, for DM intake, email attachments
//! and host files alike: PDF through `pdftotext`; DOCX, ODT, PPTX, ODP, XLSX
//! and ODS from their zipped XML; RTF by a small control-word reader; text
//! as it is; a ZIP as its entry list plus the text of the documents inside.
//! `None` when the file carries no text code can read (images, audio).

use std::io::{Read as _, Write as _};

/// The most one zip member (document XML, or a file inside a ZIP) may inflate to.
const MAX_MEMBER_BYTES: u64 = 32 * 1024 * 1024;
/// The longest text one file yields; past it the text ends with a note.
const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
/// Rows and columns kept per spreadsheet sheet.
const MAX_ROWS: usize = 500;
const MAX_COLUMNS: usize = 50;
/// ZIP entries listed, and documents inside a ZIP whose text is extracted.
const MAX_ZIP_LISTED: usize = 200;
const MAX_ZIP_EXTRACTED: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Pdf,
    Docx,
    Odt,
    Pptx,
    Odp,
    Xlsx,
    Ods,
    Rtf,
    Text,
    Zip,
}

fn kind(name: &str, media_type: Option<&str>) -> Option<Kind> {
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    const OOXML: &str = "application/vnd.openxmlformats-officedocument.";
    const ODF: &str = "application/vnd.oasis.opendocument.";
    let by_type = match media_type.unwrap_or_default() {
        "application/pdf" => Some(Kind::Pdf),
        kind if kind == format!("{OOXML}wordprocessingml.document") => Some(Kind::Docx),
        kind if kind == format!("{OOXML}presentationml.presentation") => Some(Kind::Pptx),
        kind if kind == format!("{OOXML}spreadsheetml.sheet") => Some(Kind::Xlsx),
        kind if kind == format!("{ODF}text") => Some(Kind::Odt),
        kind if kind == format!("{ODF}presentation") => Some(Kind::Odp),
        kind if kind == format!("{ODF}spreadsheet") => Some(Kind::Ods),
        "application/rtf" | "text/rtf" => Some(Kind::Rtf),
        "application/zip" | "application/x-zip-compressed" => Some(Kind::Zip),
        _ => None,
    };
    by_type.or(match extension.as_str() {
        "pdf" => Some(Kind::Pdf),
        "docx" => Some(Kind::Docx),
        "odt" => Some(Kind::Odt),
        "pptx" => Some(Kind::Pptx),
        "odp" => Some(Kind::Odp),
        "xlsx" => Some(Kind::Xlsx),
        "ods" => Some(Kind::Ods),
        "rtf" => Some(Kind::Rtf),
        "zip" => Some(Kind::Zip),
        "md" | "txt" | "csv" | "tsv" | "tex" | "json" | "toml" | "html" | "htm" => Some(Kind::Text),
        _ if media_type.is_some_and(|kind| kind.starts_with("text/")) => Some(Kind::Text),
        _ => None,
    })
}

pub(crate) fn extract_text(
    name: &str,
    media_type: Option<&str>,
    bytes: &[u8],
) -> Result<Option<String>, String> {
    extract(name, media_type, bytes, 0).map(|text| text.map(bounded))
}

/// `depth` is 1 inside a ZIP: a ZIP there is listed but not opened.
fn extract(
    name: &str,
    media_type: Option<&str>,
    bytes: &[u8],
    depth: usize,
) -> Result<Option<String>, String> {
    let Some(kind) = kind(name, media_type) else {
        return Ok(None);
    };
    let text = match kind {
        Kind::Pdf => pdf_text(bytes)?,
        Kind::Text => String::from_utf8_lossy(bytes).into_owned(),
        Kind::Rtf => rtf_text(&String::from_utf8_lossy(bytes)),
        Kind::Zip => zip_text(bytes, depth)?,
        office => {
            let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
                .map_err(|error| format!("{name} is not a readable zip: {error}"))?;
            match office {
                Kind::Docx => docx_text(&member(&mut archive, "word/document.xml")?),
                Kind::Odt => odf_text(&member(&mut archive, "content.xml")?, false),
                Kind::Odp => odf_text(&member(&mut archive, "content.xml")?, true),
                Kind::Ods => ods_text(&member(&mut archive, "content.xml")?),
                Kind::Pptx => pptx_text(&mut archive)?,
                Kind::Xlsx => xlsx_text(&mut archive)?,
                _ => unreachable!("handled above"),
            }
        }
    };
    Ok(Some(text))
}

fn bounded(mut text: String) -> String {
    if text.len() > MAX_TEXT_BYTES {
        let mut end = MAX_TEXT_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("\n[text cut at 2 MiB]");
    }
    text
}

fn pdf_text(bytes: &[u8]) -> Result<String, String> {
    let mut child = std::process::Command::new("pdftotext")
        .args(["-layout", "-enc", "UTF-8", "-", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| format!("pdftotext is unavailable: {error}"))?;
    let mut stdin = child.stdin.take().ok_or("pdftotext has no stdin")?;
    let input = bytes.to_vec();
    // Feed stdin on its own thread so a large PDF cannot deadlock on a full stdout pipe.
    let feeder = std::thread::spawn(move || stdin.write_all(&input));
    let output = child
        .wait_with_output()
        .map_err(|error| format!("pdftotext failed: {error}"))?;
    let fed = feeder.join().map_err(|panic| {
        format!(
            "pdftotext's input thread panicked: {}",
            super::panic_cause(&*panic)
        )
    })?;
    if !output.status.success() || fed.is_err() {
        return Err("the PDF could not be read".to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

type Archive<'a> = zip::ZipArchive<std::io::Cursor<&'a [u8]>>;

/// One member of a zip as text, bounded.
fn member(archive: &mut Archive<'_>, name: &str) -> Result<String, String> {
    let bytes = member_bytes(archive, name)?;
    String::from_utf8(bytes).map_err(|error| format!("{name} is not UTF-8 XML: {error}"))
}

fn member_bytes(archive: &mut Archive<'_>, name: &str) -> Result<Vec<u8>, String> {
    let file = archive
        .by_name(name)
        .map_err(|error| format!("the file has no {name}: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_MEMBER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{name} is unreadable: {error}"))?;
    if bytes.len() as u64 > MAX_MEMBER_BYTES {
        return Err(format!("{name} inflates past 32 MiB"));
    }
    Ok(bytes)
}

// -- XML --------------------------------------------------------------------

/// One step through an XML document: element starts and ends (`<a/>` is
/// both) with the raw attribute text, and unescaped text between tags.
enum Xml<'a> {
    Open(&'a str, &'a str),
    Close(&'a str),
    Text(String),
}

fn xml_events(document: &str) -> Vec<Xml<'_>> {
    let mut events = Vec::new();
    let mut rest = document;
    while let Some(open) = rest.find('<') {
        if open > 0 {
            events.push(Xml::Text(xml_unescape(&rest[..open])));
        }
        rest = &rest[open..];
        let (skip, end) = if rest.starts_with("<!--") {
            (true, "-->")
        } else if let Some(cdata) = rest.strip_prefix("<![CDATA[") {
            let close = cdata.find("]]>").unwrap_or(cdata.len());
            events.push(Xml::Text(cdata[..close].to_owned()));
            rest = cdata.get(close + 3..).unwrap_or_default();
            continue;
        } else if rest.starts_with("<?") || rest.starts_with("<!") {
            (true, ">")
        } else {
            (false, ">")
        };
        let Some(close) = rest.find(end) else {
            break;
        };
        let tag = &rest[1..close];
        rest = &rest[close + end.len()..];
        if skip {
            continue;
        }
        if let Some(name) = tag.strip_prefix('/') {
            events.push(Xml::Close(name.trim()));
            continue;
        }
        let empty = tag.ends_with('/');
        let tag = tag.trim_end_matches('/');
        let (name, attributes) = tag
            .split_once(|c: char| c.is_whitespace())
            .unwrap_or((tag, ""));
        events.push(Xml::Open(name, attributes));
        if empty {
            events.push(Xml::Close(name));
        }
    }
    events
}

/// One attribute's unescaped value from an element's raw attribute text.
fn attribute(attributes: &str, key: &str) -> Option<String> {
    let mut rest = attributes;
    while let Some(at) = rest.find(key) {
        let before = rest[..at].chars().last();
        let after = &rest[at + key.len()..];
        if before.is_none_or(char::is_whitespace) {
            if let Some(value) = after.trim_start().strip_prefix('=') {
                let value = value.trim_start();
                let quote = value
                    .chars()
                    .next()
                    .filter(|quote| matches!(quote, '"' | '\''))?;
                let value = &value[1..];
                return Some(xml_unescape(&value[..value.find(quote)?]));
            }
        }
        rest = after;
    }
    None
}

fn xml_unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let entity_end = rest[amp..].find(';').map(|end| amp + end);
        let decoded = entity_end.and_then(|end| match &rest[amp + 1..end] {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            entity => entity
                .strip_prefix("#x")
                .map(|hex| u32::from_str_radix(hex, 16))
                .or_else(|| entity.strip_prefix('#').map(str::parse::<u32>))
                .and_then(Result::ok)
                .and_then(char::from_u32),
        });
        match (decoded, entity_end) {
            (Some(ch), Some(end)) => {
                out.push(ch);
                rest = &rest[end + 1..];
            }
            _ => {
                out.push('&');
                rest = &rest[amp + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Paragraph text of an OOXML part: the text of `run` elements (`w:t`,
/// `a:t`), a line per `paragraph` (`w:p`, `a:p`), tabs and breaks kept.
fn ooxml_paragraphs(document: &str, prefix: &str) -> String {
    let (run, paragraph) = (format!("{prefix}:t"), format!("{prefix}:p"));
    let (tab, br) = (format!("{prefix}:tab"), format!("{prefix}:br"));
    let mut text = String::new();
    let mut in_run = false;
    for event in xml_events(document) {
        match event {
            Xml::Open(name, _) if name == run => in_run = true,
            Xml::Close(name) if name == run => in_run = false,
            Xml::Close(name) if name == paragraph => text.push('\n'),
            Xml::Open(name, _) if name == tab => text.push('\t'),
            Xml::Open(name, _) if name == br || name == "w:cr" => text.push('\n'),
            Xml::Text(content) if in_run => text.push_str(&content),
            _ => {}
        }
    }
    text
}

fn docx_text(document: &str) -> String {
    ooxml_paragraphs(document, "w")
}

/// Slides in order (`ppt/slides/slideN.xml` by N), each under a `Slide N` line.
fn pptx_text(archive: &mut Archive<'_>) -> Result<String, String> {
    let mut slides: Vec<(u32, String)> = archive
        .file_names()
        .filter_map(|name| {
            let name = name.ok()?;
            let number = name
                .strip_prefix("ppt/slides/slide")?
                .strip_suffix(".xml")?
                .parse()
                .ok()?;
            Some((number, name.into_owned()))
        })
        .collect();
    slides.sort();
    let mut text = String::new();
    for (index, (_, name)) in slides.iter().enumerate() {
        text.push_str(&format!("Slide {}\n", index + 1));
        text.push_str(ooxml_paragraphs(&member(archive, name)?, "a").trim_end());
        text.push_str("\n\n");
    }
    Ok(text)
}

/// OpenDocument text or slides from `content.xml`: a line per paragraph or
/// heading, `text:s` spaces, tabs and line breaks kept; slides under a
/// `Slide N` line, speaker notes left out.
fn odf_text(content: &str, slides: bool) -> String {
    let mut text = String::new();
    let (mut slide, mut notes, mut paragraph) = (0, 0usize, 0usize);
    for event in xml_events(content) {
        match event {
            Xml::Open("draw:page", _) if slides => {
                slide += 1;
                text.push_str(&format!("\nSlide {slide}\n"));
            }
            Xml::Open("presentation:notes", _) => notes += 1,
            Xml::Close("presentation:notes") => notes = notes.saturating_sub(1),
            _ if notes > 0 => {}
            Xml::Open("text:p" | "text:h", _) => paragraph += 1,
            Xml::Close("text:p" | "text:h") => {
                paragraph = paragraph.saturating_sub(1);
                text.push('\n');
            }
            Xml::Open("text:tab", _) => text.push('\t'),
            Xml::Open("text:line-break", _) => text.push('\n'),
            Xml::Open("text:s", attributes) => {
                let count = attribute(attributes, "text:c")
                    .and_then(|count| count.parse::<usize>().ok())
                    .unwrap_or(1);
                text.push_str(&" ".repeat(count.min(64)));
            }
            Xml::Text(content) if paragraph > 0 => text.push_str(&content),
            _ => {}
        }
    }
    text.trim_start().to_owned()
}

/// One sheet as tab-separated rows, trailing empty cells and rows dropped,
/// bounded at [`MAX_ROWS`] by [`MAX_COLUMNS`].
fn sheet_table(name: &str, rows: &[Vec<String>]) -> String {
    let mut rows: Vec<&Vec<String>> = rows.iter().collect();
    while rows
        .last()
        .is_some_and(|row| row.iter().all(String::is_empty))
    {
        rows.pop();
    }
    let mut text = format!("Sheet {name}\n");
    for row in rows.iter().take(MAX_ROWS) {
        let mut cells: Vec<&str> = row.iter().take(MAX_COLUMNS).map(String::as_str).collect();
        while cells.last().is_some_and(|cell| cell.is_empty()) {
            cells.pop();
        }
        text.push_str(&cells.join("\t"));
        text.push('\n');
    }
    if rows.len() > MAX_ROWS {
        let more = rows.len() - MAX_ROWS;
        let noun = if more == 1 { "row" } else { "rows" };
        text.push_str(&format!("[{more} more {noun}]\n"));
    }
    text
}

/// XLSX sheets in workbook order through the workbook relationships, cell
/// values resolved through the shared-string table.
fn xlsx_text(archive: &mut Archive<'_>) -> Result<String, String> {
    let shared: Vec<String> = match member(archive, "xl/sharedStrings.xml") {
        Ok(strings) => {
            let mut shared = Vec::new();
            let mut in_text = false;
            for event in xml_events(&strings) {
                match event {
                    Xml::Open("si", _) => shared.push(String::new()),
                    Xml::Open("t", _) => in_text = true,
                    Xml::Close("t") => in_text = false,
                    Xml::Text(content) if in_text => {
                        if let Some(last) = shared.last_mut() {
                            last.push_str(&content);
                        }
                    }
                    _ => {}
                }
            }
            shared
        }
        Err(_) => Vec::new(),
    };
    let relationships = member(archive, "xl/_rels/workbook.xml.rels")?;
    let targets: Vec<(String, String)> = xml_events(&relationships)
        .into_iter()
        .filter_map(|event| match event {
            Xml::Open("Relationship", attributes) => Some((
                attribute(attributes, "Id")?,
                attribute(attributes, "Target")?,
            )),
            _ => None,
        })
        .collect();
    let workbook = member(archive, "xl/workbook.xml")?;
    let sheets: Vec<(String, String)> = xml_events(&workbook)
        .into_iter()
        .filter_map(|event| match event {
            Xml::Open("sheet", attributes) => {
                let id = attribute(attributes, "r:id")?;
                let target = targets.iter().find(|(rid, _)| *rid == id)?.1.clone();
                let path = match target.strip_prefix('/') {
                    Some(absolute) => absolute.to_owned(),
                    None => format!("xl/{target}"),
                };
                Some((attribute(attributes, "name").unwrap_or_default(), path))
            }
            _ => None,
        })
        .collect();
    let mut text = String::new();
    for (name, path) in sheets {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let (mut column, mut cell_type, mut value, mut in_value) =
            (0usize, String::new(), String::new(), false);
        for event in xml_events(&member(archive, &path)?) {
            match event {
                Xml::Open("row", _) => rows.push(Vec::new()),
                Xml::Open("c", attributes) => {
                    column = attribute(attributes, "r")
                        .map(|reference| column_index(&reference))
                        .unwrap_or_else(|| rows.last().map_or(0, Vec::len));
                    cell_type = attribute(attributes, "t").unwrap_or_default();
                    value.clear();
                }
                Xml::Open("v" | "t", _) => in_value = true,
                Xml::Close("v" | "t") => in_value = false,
                Xml::Text(content) if in_value => value.push_str(&content),
                Xml::Close("c") => {
                    let shown = match cell_type.as_str() {
                        "s" => value
                            .trim()
                            .parse::<usize>()
                            .ok()
                            .and_then(|index| shared.get(index).cloned())
                            .unwrap_or_default(),
                        "b" => (if value.trim() == "1" { "TRUE" } else { "FALSE" }).to_owned(),
                        _ => value.clone(),
                    };
                    if let Some(row) = rows.last_mut().filter(|_| column < MAX_COLUMNS) {
                        if row.len() <= column {
                            row.resize(column + 1, String::new());
                        }
                        row[column] = shown;
                    }
                }
                _ => {}
            }
        }
        text.push_str(&sheet_table(&name, &rows));
        text.push('\n');
    }
    Ok(text)
}

/// `B12` → 1: the zero-based column of a cell reference.
fn column_index(reference: &str) -> usize {
    reference
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .fold(0, |index, letter| {
            index * 26 + (letter.to_ascii_uppercase() as usize - 'A' as usize + 1)
        })
        .saturating_sub(1)
}

/// ODS sheets from `content.xml`; repeated rows and cells expand only while
/// they hold text, so a sheet's 16,384 empty trailing columns stay unexpanded.
fn ods_text(content: &str) -> String {
    let mut text = String::new();
    let (mut name, mut rows) = (String::new(), Vec::<Vec<String>>::new());
    let (mut row_repeat, mut cell_repeat, mut cell, mut paragraph) =
        (1usize, 1usize, String::new(), false);
    let repeat = |attributes: &str, key: &str| {
        attribute(attributes, key)
            .and_then(|count| count.parse::<usize>().ok())
            .unwrap_or(1)
    };
    for event in xml_events(content) {
        match event {
            Xml::Open("table:table", attributes) => {
                name = attribute(attributes, "table:name").unwrap_or_default();
                rows.clear();
            }
            Xml::Close("table:table") => {
                text.push_str(&sheet_table(&name, &rows));
                text.push('\n');
            }
            Xml::Open("table:table-row", attributes) => {
                row_repeat = repeat(attributes, "table:number-rows-repeated");
                rows.push(Vec::new());
            }
            Xml::Close("table:table-row") => {
                if let Some(last) = rows.last().cloned() {
                    if !last.iter().all(String::is_empty) {
                        for _ in 1..row_repeat {
                            if rows.len() > MAX_ROWS {
                                break;
                            }
                            rows.push(last.clone());
                        }
                    }
                }
            }
            Xml::Open("table:table-cell" | "table:covered-table-cell", attributes) => {
                cell_repeat = repeat(attributes, "table:number-columns-repeated");
                cell.clear();
            }
            Xml::Close("table:table-cell" | "table:covered-table-cell") => {
                if let Some(row) = rows.last_mut() {
                    let count = if cell.is_empty() { 1 } else { cell_repeat };
                    for _ in 0..count.min(MAX_COLUMNS) {
                        if row.len() < MAX_COLUMNS {
                            row.push(cell.clone());
                        }
                    }
                }
            }
            Xml::Open("text:p", _) => {
                if !cell.is_empty() {
                    cell.push(' ');
                }
                paragraph = true;
            }
            Xml::Close("text:p") => paragraph = false,
            Xml::Text(content) if paragraph => cell.push_str(&content),
            _ => {}
        }
    }
    text
}

/// RTF text: control words dropped, `\par` and `\line` as line breaks,
/// `\tab`, `\'hh` (Windows-1252 as Latin-1) and `\uN` decoded; font,
/// colour, style, info and picture groups (and `{\*…}` destinations) skipped.
fn rtf_text(rtf: &str) -> String {
    const SKIPPED: &[&str] = &[
        "fonttbl",
        "colortbl",
        "stylesheet",
        "info",
        "pict",
        "header",
        "footer",
        "listtable",
        "listoverridetable",
        "listtext",
        "pntext",
        "generator",
        "xmlnstbl",
        "themedata",
        "datastore",
    ];
    let mut text = String::new();
    // Per group: whether its text is skipped.
    let mut groups = vec![false];
    let mut chars = rtf.chars().peekable();
    let mut skip_next_char = 0usize;
    while let Some(ch) = chars.next() {
        let skipping = *groups.last().unwrap_or(&false);
        match ch {
            '{' => groups.push(skipping),
            '}' => {
                groups.pop();
                if groups.is_empty() {
                    break;
                }
            }
            '\\' => {
                let Some(&next) = chars.peek() else { break };
                if next == '\'' {
                    chars.next();
                    let hex: String = chars.by_ref().take(2).collect();
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        if !skipping && skip_next_char == 0 {
                            text.push(byte as char);
                        }
                        skip_next_char = skip_next_char.saturating_sub(1);
                    }
                    continue;
                }
                if !next.is_ascii_alphabetic() {
                    chars.next();
                    match next {
                        '*' => {
                            if let Some(skip) = groups.last_mut() {
                                *skip = true;
                            }
                        }
                        '~' if !skipping => text.push(' '),
                        '\\' | '{' | '}' if !skipping => text.push(next),
                        _ => {}
                    }
                    continue;
                }
                let mut word = String::new();
                while let Some(&letter) = chars.peek().filter(|c| c.is_ascii_alphabetic()) {
                    word.push(letter);
                    chars.next();
                }
                let mut number = String::new();
                while let Some(&digit) = chars.peek().filter(|c| c.is_ascii_digit() || **c == '-') {
                    number.push(digit);
                    chars.next();
                }
                if chars.peek() == Some(&' ') {
                    chars.next();
                }
                if SKIPPED.contains(&word.as_str()) {
                    if let Some(skip) = groups.last_mut() {
                        *skip = true;
                    }
                    continue;
                }
                if skipping {
                    continue;
                }
                match word.as_str() {
                    "par" | "line" | "row" => text.push('\n'),
                    "tab" | "cell" => text.push('\t'),
                    "u" => {
                        let code = number.parse::<i32>().unwrap_or(0);
                        let code = if code < 0 { code + 65_536 } else { code };
                        text.extend(char::from_u32(code as u32));
                        // The ANSI fallback character that follows \uN.
                        skip_next_char = 1;
                    }
                    _ => {}
                }
            }
            '\r' | '\n' => {}
            _ if skipping => {}
            _ if skip_next_char > 0 => skip_next_char -= 1,
            _ => text.push(ch),
        }
    }
    text
}

/// A ZIP's entries, then the text of each supported document inside. Entry
/// names are labels only (nothing is written out); names that climb out of
/// the archive are skipped. A ZIP inside is listed, not opened.
fn zip_text(bytes: &[u8], depth: usize) -> Result<String, String> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|error| format!("the ZIP is not readable: {error}"))?;
    let mut listing = format!("ZIP with {} entries\n", archive.len());
    let mut documents = String::new();
    let (mut extracted, mut unread) = (0, 0);
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("ZIP entry {index} is unreadable: {error}"))?;
        let Some(name) = entry
            .enclosed_name()
            .map(|path| path.to_string_lossy().into_owned())
        else {
            listing.push_str(&format!(
                "- [entry {} with an unsafe name skipped]\n",
                index + 1
            ));
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        if index < MAX_ZIP_LISTED {
            listing.push_str(&format!("- {name} ({} bytes)\n", entry.size()));
        }
        let Some(kind) = kind(&name, None) else {
            continue;
        };
        if kind == Kind::Zip && depth > 0 {
            continue;
        }
        if extracted == MAX_ZIP_EXTRACTED {
            unread += 1;
            continue;
        }
        if entry.size() > MAX_MEMBER_BYTES {
            documents.push_str(&format!("\n== {name}\n[over 32 MiB, not read]\n"));
            continue;
        }
        let mut inner = Vec::new();
        entry
            .by_ref()
            .take(MAX_MEMBER_BYTES + 1)
            .read_to_end(&mut inner)
            .map_err(|error| format!("ZIP entry {name} is unreadable: {error}"))?;
        if inner.len() as u64 > MAX_MEMBER_BYTES {
            documents.push_str(&format!("\n== {name}\n[inflates past 32 MiB, not read]\n"));
            continue;
        }
        extracted += 1;
        let text = match extract(&name, None, &inner, depth + 1) {
            Ok(Some(text)) => text,
            Ok(None) => continue,
            Err(reason) => format!("[could not be read: {reason}]"),
        };
        documents.push_str(&format!("\n== {name}\n{}\n", text.trim_end()));
    }
    if archive.len() > MAX_ZIP_LISTED {
        listing.push_str(&format!(
            "[{} more entries]\n",
            archive.len() - MAX_ZIP_LISTED
        ));
    }
    if unread > 0 {
        documents.push_str(&format!("\n[{unread} more documents not read]\n"));
    }
    Ok(listing + &documents)
}

#[cfg(test)]
mod tests {
    use super::{extract_text, MAX_ZIP_EXTRACTED};
    use std::io::Write as _;

    fn zipped(members: &[(&str, &[u8])]) -> Vec<u8> {
        // Names are written verbatim, `../escape.txt` included.
        let mut bytes = Vec::new();
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
        for (name, content) in members {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(content).unwrap();
        }
        zip.finish().unwrap();
        bytes
    }

    fn text(name: &str, bytes: &[u8]) -> String {
        extract_text(name, None, bytes).unwrap().unwrap()
    }

    #[test]
    fn docx_paragraphs_runs_tabs_and_entities_become_lines() {
        let xml = r#"<?xml version="1.0"?><w:document><w:body>
            <w:p><w:r><w:t>Review of </w:t></w:r><w:r><w:t xml:space="preserve">R&amp;D draft</w:t></w:r></w:p>
            <w:p><w:r><w:t>Score:</w:t><w:tab/><w:t>4 &#x2192; 5</w:t></w:r></w:p>
            </w:body></w:document>"#;
        let docx = zipped(&[("word/document.xml", xml.as_bytes())]);
        assert_eq!(
            text("Review.docx", &docx),
            "Review of R&D draft\nScore:\t4 \u{2192} 5\n"
        );
        assert!(extract_text("photo.jpg", Some("image/jpeg"), b"x")
            .unwrap()
            .is_none());
        assert!(extract_text("broken.docx", None, b"not a zip").is_err());
    }

    #[test]
    fn xlsx_and_ods_sheets_become_tab_separated_tables() {
        let xlsx = zipped(&[
            ("xl/workbook.xml", br#"<workbook><sheets><sheet name="Budget" sheetId="1" r:id="rId1"/></sheets></workbook>"#.as_slice()),
            ("xl/_rels/workbook.xml.rels", br#"<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>"#.as_slice()),
            ("xl/sharedStrings.xml", br#"<sst><si><t>Item</t></si><si><r><t>Co</t></r><r><t>st</t></r></si></sst>"#.as_slice()),
            ("xl/worksheets/sheet1.xml", br#"<worksheet><sheetData>
                <row r="1"><c r="A1" t="s"><v>0</v></c><c r="C1" t="s"><v>1</v></c></row>
                <row r="2"><c r="A2" t="inlineStr"><is><t>Rent</t></is></c><c r="C2"><v>950</v></c></row>
                </sheetData></worksheet>"#.as_slice()),
        ]);
        assert_eq!(
            text("b.xlsx", &xlsx),
            "Sheet Budget\nItem\t\tCost\nRent\t\t950\n\n"
        );
        let ods = r#"<office:spreadsheet><table:table table:name="Grades">
            <table:table-row><table:table-cell><text:p>Name</text:p></table:table-cell>
              <table:table-cell table:number-columns-repeated="2"><text:p>x</text:p></table:table-cell>
              <table:table-cell table:number-columns-repeated="16380"/></table:table-row>
            <table:table-row table:number-rows-repeated="1048570"><table:table-cell table:number-columns-repeated="16384"/></table:table-row>
            </table:table></office:spreadsheet>"#;
        assert_eq!(
            text("g.ods", &zipped(&[("content.xml", ods.as_bytes())])),
            "Sheet Grades\nName\tx\tx\n\n"
        );
    }

    #[test]
    fn a_zip_lists_entries_reads_documents_and_opens_only_one_level() {
        let inner = zipped(&[("deep.txt", b"too deep".as_slice())]);
        let middle = zipped(&[
            ("notes.md", b"# inside".as_slice()),
            ("inner.zip", inner.as_slice()),
        ]);
        let outer = zipped(&[
            ("readme.txt", b"hello".as_slice()),
            ("photo.jpg", b"\xff\xd8".as_slice()),
            ("../escape.txt", b"climbs out".as_slice()),
            ("middle.zip", middle.as_slice()),
        ]);
        let listing = text("bundle.zip", &outer);
        assert!(
            listing
                .starts_with("ZIP with 4 entries\n- readme.txt (5 bytes)\n- photo.jpg (2 bytes)\n"),
            "{listing}"
        );
        assert!(
            listing.contains("[entry 3 with an unsafe name skipped]"),
            "{listing}"
        );
        assert!(!listing.contains("climbs out"), "{listing}");
        assert!(listing.contains("== readme.txt\nhello"), "{listing}");
        assert!(
            listing.contains("== middle.zip\nZIP with 2 entries"),
            "{listing}"
        );
        assert!(listing.contains("# inside"), "{listing}");
        assert!(listing.contains("- inner.zip"), "{listing}");
        assert!(
            !listing.contains("too deep"),
            "nested zips stop at one level: {listing}"
        );
        let names: Vec<String> = (0..MAX_ZIP_EXTRACTED + 3)
            .map(|n| format!("note{n}.txt"))
            .collect();
        let many: Vec<(&str, &[u8])> = names
            .iter()
            .map(|name| (name.as_str(), b"x".as_slice()))
            .collect();
        assert!(
            text("many.zip", &zipped(&many)).ends_with("[3 more documents not read]\n"),
            "documents past the cap are counted, not dropped silently"
        );
    }
}
