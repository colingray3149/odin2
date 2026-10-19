//! Discover signed-in accounts under home; default uses the agent's own sign-in location.

use std::path::Path;

use serde::{Deserialize, Serialize};

pub const DEFAULT_ACCOUNT: &str = "default";

const ACCOUNT_NAME_MAX: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccountKind {
    ClaudeCode,
    Codex,
}

/// Keep account paths relative to HOME for confinement and pod mounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountLayout {
    /// Mount login state writable in the sandbox or pod.
    pub paths: Vec<String>,
    pub dir: String,
    /// Default accounts need no directory override variable.
    pub env: Option<&'static str>,
    /// Claude Code requires both login and account record files to open a signed-in session.
    pub sign_in: Vec<String>,
}

impl AccountKind {
    pub const ALL: [Self; 2] = [Self::ClaudeCode, Self::Codex];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
        }
    }

    const fn accounts_dir(self) -> &'static str {
        match self {
            Self::ClaudeCode => ".claude-accounts",
            Self::Codex => ".codex-accounts",
        }
    }

    const fn credential_file(self) -> &'static str {
        match self {
            Self::ClaudeCode => ".credentials.json",
            Self::Codex => "auth.json",
        }
    }

    fn record(self, dir: Option<&str>) -> Option<String> {
        match (self, dir) {
            (Self::ClaudeCode, Some(dir)) => Some(format!("{dir}/.claude.json")),
            (Self::ClaudeCode, None) => Some(".claude.json".to_owned()),
            (Self::Codex, _) => None,
        }
    }

    pub fn layout(self, name: &str) -> AccountLayout {
        if name == DEFAULT_ACCOUNT {
            let (dir, paths): (&str, &[&str]) = match self {
                Self::ClaudeCode => (".claude", &[".claude", ".claude.json"]),
                Self::Codex => (".codex", &[".codex"]),
            };
            return AccountLayout {
                paths: paths.iter().map(|path| (*path).to_owned()).collect(),
                dir: dir.to_owned(),
                env: None,
                sign_in: std::iter::once(format!("{dir}/{}", self.credential_file()))
                    .chain(self.record(None))
                    .collect(),
            };
        }
        let dir = format!("{}/{name}", self.accounts_dir());
        AccountLayout {
            paths: vec![dir.clone()],
            env: Some(match self {
                Self::ClaudeCode => "CLAUDE_CONFIG_DIR",
                Self::Codex => "CODEX_HOME",
            }),
            sign_in: std::iter::once(format!("{dir}/{}", self.credential_file()))
                .chain(self.record(Some(&dir)))
                .collect(),
            dir,
        }
    }

    fn locations(self, home: &Path) -> Vec<(String, Vec<String>)> {
        let mut locations = vec![(
            DEFAULT_ACCOUNT.to_owned(),
            self.layout(DEFAULT_ACCOUNT).paths,
        )];
        let mut named: Vec<String> = std::fs::read_dir(home.join(self.accounts_dir()))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        named.sort();
        locations.extend(named.into_iter().map(|name| {
            let path = format!("{}/{name}", self.accounts_dir());
            (name, vec![path])
        }));
        locations
    }

    pub fn sign_in_hint(self, name: &str) -> String {
        let layout = self.layout(name);
        let prefix = layout
            .env
            .map(|var| format!("{var}=~/{} ", layout.dir))
            .unwrap_or_default();
        match self {
            Self::ClaudeCode => format!("{prefix}claude, then /login"),
            Self::Codex => format!("{prefix}codex login"),
        }
    }

    pub fn signed_in(self, home: &Path, name: &str) -> bool {
        valid_account_name(name)
            && self
                .layout(name)
                .sign_in
                .iter()
                .all(|file| home.join(file).is_file())
    }

    pub fn discover(self, home: &Path) -> Vec<String> {
        let mut named: Vec<String> = std::fs::read_dir(home.join(self.accounts_dir()))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name != DEFAULT_ACCOUNT && self.signed_in(home, name))
            .collect();
        named.sort();
        let mut found = Vec::with_capacity(named.len() + 1);
        if self.signed_in(home, DEFAULT_ACCOUNT) {
            found.push(DEFAULT_ACCOUNT.to_owned());
        }
        found.extend(named);
        found
    }
}

/// Hide every other account location; sessions without an account must not see any.
pub fn foreign_account_paths(home: &Path, own: Option<(AccountKind, &str)>) -> Vec<String> {
    AccountKind::ALL
        .into_iter()
        .flat_map(|kind| {
            kind.locations(home)
                .into_iter()
                .filter(move |(name, _)| own != Some((kind, name.as_str())))
                .flat_map(|(_, paths)| paths)
        })
        .collect()
}

/// Restrict handles to lowercase letters, digits, and inner dashes so they name one directory.
pub fn valid_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= ACCOUNT_NAME_MAX
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_account_lives_in_its_own_directory_and_default_where_the_program_keeps_it() {
        let school = AccountKind::ClaudeCode.layout("school");
        assert_eq!(school.paths, [".claude-accounts/school"]);
        assert_eq!(school.dir, ".claude-accounts/school");
        assert_eq!(school.env, Some("CLAUDE_CONFIG_DIR"));
        assert_eq!(
            school.sign_in,
            [
                ".claude-accounts/school/.credentials.json",
                ".claude-accounts/school/.claude.json"
            ]
        );
        let default = AccountKind::ClaudeCode.layout(DEFAULT_ACCOUNT);
        assert_eq!(default.paths, [".claude", ".claude.json"]);
        assert_eq!(default.env, None);
        assert_eq!(
            default.sign_in,
            [".claude/.credentials.json", ".claude.json"]
        );
        assert_eq!(AccountKind::Codex.layout("astra").env, Some("CODEX_HOME"));
        assert_eq!(
            AccountKind::Codex.layout(DEFAULT_ACCOUNT).sign_in,
            [".codex/auth.json"]
        );
        assert_eq!(
            AccountKind::ClaudeCode.sign_in_hint("school"),
            "CLAUDE_CONFIG_DIR=~/.claude-accounts/school claude, then /login"
        );
        assert_eq!(
            AccountKind::Codex.sign_in_hint(DEFAULT_ACCOUNT),
            "codex login"
        );
    }

    #[test]
    fn accounts_are_discovered_by_their_sign_in() {
        let home = tempfile::tempdir().expect("home");
        let root = home.path();
        assert!(AccountKind::ClaudeCode.discover(root).is_empty());
        for (dir, signed) in [
            (".claude", true),
            (".claude-accounts/school", true),
            (".claude-accounts/club", true),
            (".claude-accounts/empty", false),
            (".claude-accounts/Bad", true),
        ] {
            std::fs::create_dir_all(root.join(dir)).expect("dir");
            if signed {
                std::fs::write(root.join(dir).join(".credentials.json"), "{}").expect("file");
                std::fs::write(root.join(dir).join(".claude.json"), "{}").expect("record");
            }
        }
        std::fs::write(root.join(".claude.json"), "{}").expect("default record");
        assert_eq!(
            AccountKind::ClaudeCode.discover(root),
            ["default", "club", "school"]
        );
        assert!(AccountKind::ClaudeCode.signed_in(root, "school"));
        assert!(!AccountKind::ClaudeCode.signed_in(root, "empty"));
        assert!(!AccountKind::ClaudeCode.signed_in(root, "../.claude"));
        assert!(AccountKind::Codex.discover(root).is_empty());
    }

    #[test]
    fn a_claude_login_without_its_account_record_is_not_signed_in() {
        let home = tempfile::tempdir().expect("home");
        let school = home.path().join(".claude-accounts/school");
        std::fs::create_dir_all(&school).expect("dir");
        std::fs::write(school.join(".credentials.json"), "{}").expect("login");
        assert!(!AccountKind::ClaudeCode.signed_in(home.path(), "school"));
        std::fs::write(school.join(".claude.json"), "{}").expect("record");
        assert!(AccountKind::ClaudeCode.signed_in(home.path(), "school"));
    }

    #[test]
    fn every_account_but_the_sessions_own_is_foreign() {
        let home = tempfile::tempdir().expect("home");
        for dir in [
            ".claude-accounts/school",
            ".claude-accounts/club",
            ".codex-accounts/astra",
        ] {
            std::fs::create_dir_all(home.path().join(dir)).expect("dir");
        }
        assert_eq!(
            foreign_account_paths(home.path(), Some((AccountKind::ClaudeCode, "school"))),
            [
                ".claude",
                ".claude.json",
                ".claude-accounts/club",
                ".codex",
                ".codex-accounts/astra"
            ]
        );
        assert_eq!(
            foreign_account_paths(
                home.path(),
                Some((AccountKind::ClaudeCode, DEFAULT_ACCOUNT))
            ),
            [
                ".claude-accounts/club",
                ".claude-accounts/school",
                ".codex",
                ".codex-accounts/astra"
            ]
        );
        assert_eq!(foreign_account_paths(home.path(), None).len(), 6);
    }

    #[test]
    fn handles_cannot_leave_the_accounts_directory() {
        for good in ["school", "class-2", "a"] {
            assert!(valid_account_name(good), "{good}");
        }
        for bad in ["", "..", "a/b", "School", "-x", "x-", &"a".repeat(33)] {
            assert!(!valid_account_name(bad), "{bad}");
        }
    }
}
