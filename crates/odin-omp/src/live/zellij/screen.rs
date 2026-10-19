//! A worker's current screen for the seat that delegated it: the newest
//! lines of its tab, bounded, with credential-shaped words withheld.

use odin_domain::huginn::LiveError;

use super::ZellijLiveAdapter;

/// Prefixes of credential tokens that common tools print.
const TOKEN_PREFIXES: &[&str] = &[
    "sk-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "AIza",
];

/// Keys whose value is withheld, in `key=value` or `key: value`; a
/// `Bearer`/`Basic` scheme word is kept and its credential withheld.
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
];

const WITHHELD: &str = "[withheld]";

impl ZellijLiveAdapter {
    /// The newest lines of the tab's screen within `max_bytes`, redacted.
    /// Nothing is journaled: this is a read, not a terminal snapshot.
    pub async fn screen(&self, max_bytes: usize) -> Result<String, LiveError> {
        Ok(screen_tail(&self.pane.capture().await?.contents, max_bytes))
    }
}

/// The redacted screen, then its newest whole lines within `max_bytes`.
pub fn screen_tail(contents: &str, max_bytes: usize) -> String {
    let mut in_key = false;
    let redacted: Vec<String> = contents
        .lines()
        .filter_map(|line| redact_line(line, &mut in_key))
        .collect();
    let mut kept = Vec::new();
    let mut used = 0;
    for line in redacted
        .iter()
        .rev()
        .skip_while(|line| line.trim().is_empty())
    {
        used += line.len() + 1;
        if used > max_bytes {
            break;
        }
        kept.push(line.as_str());
    }
    kept.reverse();
    kept.join("\n")
}

/// One line with its secrets withheld; `None` drops a private key's body.
fn redact_line(line: &str, in_key: &mut bool) -> Option<String> {
    if *in_key {
        if line.contains("-----END") {
            *in_key = false;
        }
        return None;
    }
    if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
        *in_key = !line.contains("-----END");
        return Some("[private key withheld]".to_owned());
    }
    let mut withhold_next = false;
    let words: Vec<String> = line
        .split(' ')
        .map(|word| {
            if word.is_empty() {
                return String::new();
            }
            let bare = word.trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ',' | ';'));
            if scheme(bare) {
                withhold_next = true;
                return word.to_owned();
            }
            if std::mem::take(&mut withhold_next) {
                return WITHHELD.to_owned();
            }
            if TOKEN_PREFIXES
                .iter()
                .any(|prefix| bare.starts_with(prefix) && bare.len() >= prefix.len() + 16)
            {
                return WITHHELD.to_owned();
            }
            if let Some((key, value)) = bare.split_once(['=', ':']) {
                if secret_key(key) {
                    if value.is_empty() {
                        withhold_next = true;
                        return word.to_owned();
                    }
                    return format!("{key}{}{WITHHELD}", &bare[key.len()..=key.len()]);
                }
            }
            word.to_owned()
        })
        .collect();
    Some(words.join(" "))
}

fn scheme(word: &str) -> bool {
    word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic")
}

fn secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|secret| key.ends_with(secret))
}

#[cfg(test)]
mod tests {
    use super::screen_tail;

    #[test]
    fn the_screen_tail_is_bounded_whole_lines_newest_last() {
        let screen = "first\nsecond\n> what is surtr?\n● Surtr is a CFD solver.\n\n\n";
        assert_eq!(
            screen_tail(screen, 48),
            "> what is surtr?\n● Surtr is a CFD solver."
        );
        assert_eq!(screen_tail(screen, 4), "");
    }

    #[test]
    fn credential_shaped_words_are_withheld() {
        let screen = "export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuv\n\
                      token: ghp_abcdefghijklmnopqrstuvwxyz0123\n\
                      password: hunter2 is set\n\
                      curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9'\n\
                      -----BEGIN OPENSSH PRIVATE KEY-----\n\
                      b3BlbnNzaC1rZXktdjEAAAAA\n\
                      -----END OPENSSH PRIVATE KEY-----\n\
                      the task-runner risk-free desk-lamp stays";
        assert_eq!(
            screen_tail(screen, 4096),
            "export ANTHROPIC_API_KEY=[withheld]\n\
             token: [withheld]\n\
             password: [withheld] is set\n\
             curl -H 'Authorization: Bearer [withheld]\n\
             [private key withheld]\n\
             the task-runner risk-free desk-lamp stays"
        );
    }
}
