use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use odin_registry::schema::{valid_account_name, AccountKind};
use rustix::fd::OwnedFd;
use rustix::fs::{open, openat, Mode, OFlags};

const MAX_CREDENTIAL_BYTES: u64 = 256 * 1024;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Load only the selected account's two sign-in inputs, never its state tree.
/// Directory descriptors pin every traversed ancestor; NOFOLLOW also protects the
/// final open, rather than relying on a racy symlink_metadata preflight.
pub(super) fn selected_credentials(
    home: &Path,
    account: &str,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    if !valid_account_name(account) {
        return Err("invalid Claude account handle".to_owned());
    }
    let home_fd = open_home(home)?;
    let kind = AccountKind::ClaudeCode;
    if !kind.signed_in(home, account) {
        return Err(format!(
            "selected Claude account is missing or not signed in; sign in on the host with: {}",
            kind.sign_in_hint(account)
        ));
    }

    let mut credentials = BTreeMap::new();
    for input in kind.layout(account).sign_in {
        let path = Path::new(&input);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| matches!(*name, ".credentials.json" | ".claude.json"))
            .ok_or_else(|| "unsupported Claude sign-in input".to_owned())?;
        let mut directory = openat(&home_fd, ".", DIRECTORY_FLAGS, Mode::empty())
            .map_err(|_| "cannot open Claude credential directory".to_owned())?;
        if let Some(parent) = path.parent() {
            for component in parent.components() {
                let Component::Normal(segment) = component else {
                    return Err("invalid Claude sign-in path".to_owned());
                };
                directory = openat(&directory, segment, DIRECTORY_FLAGS, Mode::empty())
                    .map_err(|_| "unsafe or unavailable Claude credential ancestry".to_owned())?;
            }
        }
        // NONBLOCK prevents a substituted FIFO from blocking before its type is checked.
        let fd = openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| "unsafe or unavailable Claude credential input".to_owned())?;
        let file = File::from(fd);
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect Claude credential input".to_owned())?;
        if !metadata.is_file() {
            return Err("Claude credential input is not a regular file".to_owned());
        }
        if metadata.len() > MAX_CREDENTIAL_BYTES {
            return Err("Claude credential input exceeds size limit".to_owned());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_CREDENTIAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read Claude credential input".to_owned())?;
        if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
            return Err("Claude credential input exceeds size limit".to_owned());
        }
        credentials.insert(name.to_owned(), bytes);
    }
    Ok(credentials)
}

fn open_home(home: &Path) -> Result<OwnedFd, String> {
    let absolute = if home.is_absolute() {
        home.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| "cannot resolve Claude account home".to_owned())?
            .join(home)
    };
    let mut directory = open("/", DIRECTORY_FLAGS, Mode::empty())
        .map_err(|_| "cannot open Claude account home ancestry".to_owned())?;
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(segment) => {
                directory = openat(&directory, segment, DIRECTORY_FLAGS, Mode::empty())
                    .map_err(|_| "unsafe or unavailable Claude account home ancestry".to_owned())?;
            }
            _ => return Err("invalid Claude account home ancestry".to_owned()),
        }
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn sign_in(home: &Path, account: &str, marker: &[u8]) {
        for input in AccountKind::ClaudeCode.layout(account).sign_in {
            let path = home.join(input);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, marker).unwrap();
        }
    }

    #[test]
    fn loads_only_selected_account_sign_in_inputs() {
        let home = tempfile::tempdir().unwrap();
        sign_in(home.path(), "chosen", b"chosen-secret");
        sign_in(home.path(), "other", b"other-secret");
        sign_in(home.path(), "default", b"default-secret");
        let directory = home.path().join(".claude-accounts/chosen");
        fs::write(directory.join("settings.json"), b"settings").unwrap();
        fs::create_dir(directory.join("projects")).unwrap();
        fs::write(directory.join("projects/transcript.jsonl"), b"transcript").unwrap();

        let inputs = selected_credentials(home.path(), "chosen").unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[".credentials.json"], b"chosen-secret");
        assert_eq!(inputs[".claude.json"], b"chosen-secret");
    }

    #[test]
    fn default_uses_home_record_and_default_config_credentials() {
        let home = tempfile::tempdir().unwrap();
        sign_in(home.path(), "default", b"default-secret");
        fs::write(home.path().join(".claude.json"), b"home-record").unwrap();
        fs::write(home.path().join(".claude/.claude.json"), b"wrong-record").unwrap();
        let inputs = selected_credentials(home.path(), "default").unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[".credentials.json"], b"default-secret");
        assert_eq!(inputs[".claude.json"], b"home-record");
    }

    #[test]
    fn rejects_invalid_missing_and_partially_signed_in_accounts() {
        let home = tempfile::tempdir().unwrap();
        sign_in(home.path(), "default", b"secret");
        for account in ["", "../default", "Chosen", "missing"] {
            assert!(selected_credentials(home.path(), account).is_err());
        }
        sign_in(home.path(), "chosen", b"secret");
        fs::remove_file(home.path().join(".claude-accounts/chosen/.claude.json")).unwrap();
        assert!(selected_credentials(home.path(), "chosen").is_err());
    }

    #[test]
    fn rejects_symlinked_files_account_directories_and_home_ancestry() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        sign_in(&home, "chosen", b"secret");
        let credential = home.join(".claude-accounts/chosen/.credentials.json");
        let target = root.path().join("secret");
        fs::rename(&credential, &target).unwrap();
        symlink(&target, &credential).unwrap();
        assert!(selected_credentials(&home, "chosen").is_err());
        fs::remove_file(&credential).unwrap();
        fs::rename(&target, &credential).unwrap();

        let account = home.join(".claude-accounts/chosen");
        let external = root.path().join("external");
        fs::rename(&account, &external).unwrap();
        symlink(&external, &account).unwrap();
        assert!(selected_credentials(&home, "chosen").is_err());
        fs::remove_file(&account).unwrap();
        fs::rename(&external, &account).unwrap();

        let alias = root.path().join("alias");
        symlink(&home, &alias).unwrap();
        assert!(selected_credentials(&alias, "chosen").is_err());
        let ancestor_alias = root.path().join("ancestor-alias");
        symlink(root.path(), &ancestor_alias).unwrap();
        assert!(selected_credentials(&ancestor_alias.join("home"), "chosen").is_err());
    }

    #[test]
    fn rejects_non_regular_inputs() {
        let home = tempfile::tempdir().unwrap();
        sign_in(home.path(), "chosen", b"secret");
        let credential = home
            .path()
            .join(".claude-accounts/chosen/.credentials.json");
        fs::remove_file(&credential).unwrap();
        fs::create_dir(&credential).unwrap();
        assert!(selected_credentials(home.path(), "chosen").is_err());
    }

    #[test]
    fn bounds_each_input_and_accepts_exact_limit() {
        let home = tempfile::tempdir().unwrap();
        sign_in(home.path(), "chosen", b"secret");
        for input in AccountKind::ClaudeCode.layout("chosen").sign_in {
            let path = home.path().join(input);
            File::create(&path)
                .unwrap()
                .set_len(MAX_CREDENTIAL_BYTES + 1)
                .unwrap();
            assert_eq!(
                selected_credentials(home.path(), "chosen").unwrap_err(),
                "Claude credential input exceeds size limit"
            );
            File::create(&path)
                .unwrap()
                .set_len(MAX_CREDENTIAL_BYTES)
                .unwrap();
            assert!(selected_credentials(home.path(), "chosen").is_ok());
            fs::write(path, b"secret").unwrap();
        }
    }
}
