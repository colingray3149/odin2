//! `APL_RESTRICTED` and `SECRET` content is withheld from every model and replaced
//! with an explicit refusal. Effective privacy is the strictest source, project,
//! and note classification.

use serde::{Deserialize, Serialize};

/// One protocol privacy class, ordered from least to most restricted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivacyClass {
    Public,
    Personal,
    School,
    ThesisUnreleased,
    AplRestricted,
    Secret,
}

impl PrivacyClass {
    /// True for the classes whose content never reaches any model payload.
    pub const fn withheld_from_models(self) -> bool {
        matches!(self, Self::AplRestricted | Self::Secret)
    }

    /// The protocol's spelling (`APL_RESTRICTED`), used in refusals.
    pub const fn protocol_name(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Personal => "PERSONAL",
            Self::School => "SCHOOL",
            Self::ThesisUnreleased => "THESIS_UNRELEASED",
            Self::AplRestricted => "APL_RESTRICTED",
            Self::Secret => "SECRET",
        }
    }

    /// Parses a declared token: case-insensitive, `-` or `_` separated, an
    /// optional leading `#`, and either spelling (`apl-restricted`,
    /// `APL_RESTRICTED`). Unknown tokens are `None`, never guessed.
    pub fn parse_token(token: &str) -> Option<Self> {
        let normalized = token
            .trim()
            .trim_matches(['"', '\''])
            .trim_start_matches('#')
            .to_ascii_lowercase()
            .replace('-', "_");
        match normalized.as_str() {
            "public" => Some(Self::Public),
            "personal" => Some(Self::Personal),
            "school" => Some(Self::School),
            "thesis_unreleased" => Some(Self::ThesisUnreleased),
            "apl_restricted" => Some(Self::AplRestricted),
            "secret" => Some(Self::Secret),
            _ => None,
        }
    }

    /// The strictest class text touched: a refusal or a note's declaration,
    /// not prose that merely names a class.
    pub fn strictest_in(text: &str) -> Option<Self> {
        PrivacyRefusal::classes_in(text)
            .chain(note_privacy_class(text))
            .max()
    }
}

impl std::fmt::Display for PrivacyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.protocol_name())
    }
}

/// The typed refusal for one withheld item: its class and the subject a
/// person recognises it by (a page name, or the source id).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyRefusal {
    pub class: PrivacyClass,
    pub subject: String,
}

impl PrivacyRefusal {
    /// The plain sentence that stands in for the withheld content. It is
    /// what every model sees instead, so the model can say so plainly.
    pub fn sentence(&self) -> String {
        format!(
            "\"{}\"{MARKED}{}{WITHHELD}: it is never given to a model or \
             sent to an external lane. Tell the owner plainly that you cannot read it.",
            self.subject, self.class
        )
    }

    /// The classes the refusal sentences in `text` name: what a model turn
    /// was refused, so touched without reading.
    pub fn classes_in(text: &str) -> impl Iterator<Item = PrivacyClass> + '_ {
        text.split(MARKED)
            .skip(1)
            .filter_map(|rest| PrivacyClass::parse_token(rest.split_once(WITHHELD)?.0))
    }
}

const MARKED: &str = " is marked ";
const WITHHELD: &str = ", so its content is withheld";

/// The class a note declares about itself, if any: frontmatter `privacy:`
/// (or `privacy_class:`), frontmatter `tags:` entries, and the body
/// hashtags `#apl_restricted` / `#apl-restricted` / `#secret`. The
/// strictest declared class wins. A declaration that cannot be read fails
/// closed: a `privacy:` value that is no known class makes the note `SECRET`,
/// and a frontmatter fence that never closes still counts as frontmatter.
pub fn note_privacy_class(text: &str) -> Option<PrivacyClass> {
    let mut found: Option<PrivacyClass> = None;
    let mut raise = |class: PrivacyClass| {
        found = Some(found.map_or(class, |current| current.max(class)));
    };
    let body = match frontmatter(text) {
        Some((front, body)) => {
            let mut in_tags = false;
            for line in front.lines() {
                let trimmed = line.trim();
                if in_tags {
                    if let Some(item) = trimmed.strip_prefix("- ") {
                        if let Some(class) = PrivacyClass::parse_token(yaml_value(item)) {
                            raise(class);
                        }
                        continue;
                    }
                    in_tags = false;
                }
                let Some((key, value)) = trimmed.split_once(':') else {
                    continue;
                };
                let key = key.trim().to_ascii_lowercase().replace('-', "_");
                let value = yaml_value(value);
                match key.as_str() {
                    "privacy" | "privacy_class" if !value.is_empty() => {
                        raise(PrivacyClass::parse_token(value).unwrap_or(PrivacyClass::Secret));
                    }
                    "tags" => {
                        if value.is_empty() {
                            in_tags = true;
                        }
                        for tag in value.trim_matches(['[', ']']).split(',') {
                            if let Some(class) = PrivacyClass::parse_token(tag) {
                                raise(class);
                            }
                        }
                    }
                    _ => {}
                }
            }
            body
        }
        None => text,
    };
    for word in body.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let Some(tag) = word.strip_prefix('#') else {
            continue;
        };
        let tag = tag.trim_end_matches(['.', ')', ':']);
        if let Some(class) = PrivacyClass::parse_token(tag).filter(|c| c.withheld_from_models()) {
            raise(class);
        }
    }
    found
}

/// A YAML scalar without its trailing comment or sentence punctuation.
fn yaml_value(raw: &str) -> &str {
    let value = raw.trim();
    let comment = value
        .char_indices()
        .skip(1)
        .find(|(at, c)| *c == '#' && value[..*at].ends_with(char::is_whitespace))
        .map_or(value.len(), |(at, _)| at);
    value[..comment].trim().trim_end_matches(['.', ',', ';'])
}

/// Splits a leading `---` frontmatter block from the body. A fence that never
/// closes makes the rest of the note frontmatter and body at once.
fn frontmatter(text: &str) -> Option<(&str, &str)> {
    let rest = text
        .trim_start_matches('\u{feff}')
        .strip_prefix("---")?
        .strip_prefix('\n')
        .or_else(|| text.trim_start_matches('\u{feff}').strip_prefix("---\r\n"))?;
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        if line.trim_end() == "---" {
            return Some((&rest[..offset], &rest[offset + line.len()..]));
        }
        offset += line.len();
    }
    Some((rest, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_apl_restricted_and_secret_are_withheld() {
        let withheld: Vec<_> = [
            PrivacyClass::Public,
            PrivacyClass::Personal,
            PrivacyClass::School,
            PrivacyClass::ThesisUnreleased,
            PrivacyClass::AplRestricted,
            PrivacyClass::Secret,
        ]
        .into_iter()
        .filter(|class| class.withheld_from_models())
        .collect();
        assert_eq!(
            withheld,
            vec![PrivacyClass::AplRestricted, PrivacyClass::Secret]
        );
    }

    #[test]
    fn notes_declare_their_class_by_frontmatter_tags_or_hashtag() {
        assert_eq!(
            note_privacy_class("---\nprivacy: APL_RESTRICTED\n---\nbody\n"),
            Some(PrivacyClass::AplRestricted)
        );
        assert_eq!(
            note_privacy_class("---\ntags: [work, apl-restricted]\n---\nbody\n"),
            Some(PrivacyClass::AplRestricted)
        );
        assert_eq!(
            note_privacy_class("---\ntags:\n  - school\n  - secret\n---\nbody\n"),
            Some(PrivacyClass::Secret)
        );
        assert_eq!(
            note_privacy_class("meeting notes #apl_restricted\n"),
            Some(PrivacyClass::AplRestricted)
        );
        assert_eq!(
            note_privacy_class("---\nprivacy: school\n---\n"),
            Some(PrivacyClass::School)
        );
    }

    #[test]
    fn a_declaration_that_cannot_be_read_fails_closed() {
        // A trailing YAML comment or sentence punctuation does not hide the class.
        for text in [
            "---\nprivacy: APL_RESTRICTED  # reviewed monthly\n---\nbody\n",
            "---\nprivacy: \"apl-restricted\".\n---\nbody\n",
            "---\ntags: [work, apl-restricted] # note\n---\nbody\n",
            "---\ntags:\n  - apl_restricted # note\n---\nbody\n",
        ] {
            assert_eq!(
                note_privacy_class(text),
                Some(PrivacyClass::AplRestricted),
                "{text}"
            );
        }
        // A frontmatter fence that never closes still declares.
        assert_eq!(
            note_privacy_class("---\nprivacy: secret\ntitle: plans\nbody continues\n"),
            Some(PrivacyClass::Secret)
        );
        // A privacy value that is no known class withholds the note.
        assert_eq!(
            note_privacy_class("---\nprivacy: confidential\n---\nbody\n"),
            Some(PrivacyClass::Secret)
        );
        assert_eq!(note_privacy_class("---\nprivacy:\n---\nbody\n"), None);
    }
}
