//! A worker's current screen for the seat that delegated it: the newest
//! lines of its tab, bounded, with credential-shaped words withheld.

use odin_domain::huginn::LiveError;

use super::ZellijLiveAdapter;

use crate::redact::redact_line;

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

#[cfg(test)]
mod tests {
    use super::screen_tail;

    #[test]
    fn the_screen_tail_is_bounded_whole_lines_newest_last() {
        let screen = "first\nsecond\n> what is orbit?\n● Orbit is a CFD solver.\n\n\n";
        assert_eq!(
            screen_tail(screen, 48),
            "> what is orbit?\n● Orbit is a CFD solver."
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
