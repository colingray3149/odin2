//! Desktop-gated workspace commands and isolated launches.

/// Exit code of a desktop script when the device has no graphical session.
pub(super) const OPEN_NO_SESSION: i32 = 64;
/// Exit code of a desktop script when the device's screen is locked.
pub(super) const OPEN_LOCKED: i32 = 65;

/// Run only in an unlocked graphical session; otherwise exit without executing the command.
pub(super) fn desktop_script(command: &str) -> String {
    format!(
        "env=$(systemctl --user show-environment 2>/dev/null) || exit {OPEN_NO_SESSION}; \
         printf '%s\\n' \"$env\" | grep -qE '^(WAYLAND_)?DISPLAY=' || exit {OPEN_NO_SESSION}; \
         sid=$(printf '%s\\n' \"$env\" | sed -n 's/^XDG_SESSION_ID=//p'); \
         hint=$(timeout 5 loginctl show-session \"$sid\" -p LockedHint --value 2>/dev/null || true); \
         if [ -z \"$sid\" ] || [ \"$hint\" != no ]; then exit {OPEN_LOCKED}; fi; \
         {command}"
    )
}

/// The command typing its stdin into the focused window with ydotool
/// (the uinput daemon of programs.ydotool), then Enter (key 28) when asked.
pub(super) fn desktop_input_command(enter: bool) -> String {
    let enter = if enter {
        " && ydotool key 28:1 28:0"
    } else {
        ""
    };
    format!(
        "export YDOTOOL_SOCKET=\"${{YDOTOOL_SOCKET:-/run/ydotoold/socket}}\"; \
         ydotool type --file -{enter}"
    )
}

/// Single-quotes one word for the remote POSIX shell.
fn shell_word(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// Open through the user's graphical session; Zed is `zeditor` on NixOS and `zed` elsewhere.
pub(super) fn workspace_open_command(
    connection: &odin_hermes::runtime::WorkspaceConnection,
) -> Result<(String, String), String> {
    use odin_hermes::runtime::WorkspaceConnectionKind;
    let (argv, what): (Vec<String>, String) = match connection.kind {
        WorkspaceConnectionKind::Zed => {
            let url = connection
                .command
                .strip_prefix("zed ")
                .ok_or_else(|| format!("unexpected zed command {:?}", connection.command))?;
            (
                vec![
                    "sh".to_owned(),
                    "-c".to_owned(),
                    "exec \"$(command -v zeditor || command -v zed)\" \"$1\"".to_owned(),
                    "zed".to_owned(),
                    url.to_owned(),
                ],
                format!("Zed on {} ({})", connection.target, connection.host),
            )
        }
        WorkspaceConnectionKind::Zellij => {
            let words: Vec<&str> = connection.command.split_whitespace().collect();
            let ["zr", host, session] = words.as_slice() else {
                return Err(format!(
                    "unexpected zellij command {:?}",
                    connection.command
                ));
            };
            (
                vec![
                    "konsole".to_owned(),
                    "-e".to_owned(),
                    "zr".to_owned(),
                    (*host).to_owned(),
                    (*session).to_owned(),
                ],
                format!(
                    "a terminal attached to the zellij session {} on {}",
                    connection.target, connection.host
                ),
            )
        }
    };
    let command = argv
        .iter()
        .map(|word| shell_word(word))
        .collect::<Vec<_>>()
        .join(" ");
    Ok((command, what))
}

/// Isolated opt-in launch. The service publishes its own lease before execing any GUI.
/// RuntimeDirectory owns both the receipt and Zed data and removes them on service exit.
/// Shell parameter expansion belongs to sh, not systemd-run's environment substitution.
pub(super) fn workspace_owned_command(
    connection: &odin_hermes::runtime::WorkspaceConnection,
    owner: &str,
) -> Result<(String, String), String> {
    if owner.is_empty()
        || owner.len() > 64
        || !owner.as_bytes()[0].is_ascii_alphanumeric()
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("invalid workspace launch owner".to_owned());
    }
    let (shared_command, what) = workspace_open_command(connection)?;
    let name = format!("odin-workspace-{owner}");
    let unit = format!("{name}.service");
    let command = match connection.kind {
        odin_hermes::runtime::WorkspaceConnectionKind::Zed => {
            let url = connection
                .command
                .strip_prefix("zed ")
                .ok_or("invalid Zed command")?;
            format!("exec \"$(command -v zeditor || command -v zed)\" --foreground --new --user-data-dir \"$RUNTIME_DIRECTORY/data\" {}", shell_word(url))
        }
        odin_hermes::runtime::WorkspaceConnectionKind::Zellij => {
            format!(
                "exec {}",
                shared_command.replacen("'konsole'", "'konsole' '--separate'", 1)
            )
        }
    };
    let service = format!(
        r#"set -eu
group=$(sed -n 's/^0:://p' /proc/self/cgroup)
case "$group" in /user.slice/*/{unit}) ;; *) exit 1;; esac
case "$INVOCATION_ID" in ''|*[!0-9a-f]*) exit 1;; esac
[ "${{#INVOCATION_ID}}" = 32 ]
inode=$(stat -Lc %i "/sys/fs/cgroup$group")
device=$(stat -Lc %d "/sys/fs/cgroup$group")
set -C
printf '{{"unit":"{unit}","owner":{{"group":"%s","invocation":"%s","inode":%s,"device":%s}}}}\n' "$group" "$INVOCATION_ID" "$inode" "$device" > "$RUNTIME_DIRECTORY/.ownership.json"
ln "$RUNTIME_DIRECTORY/.ownership.json" "$RUNTIME_DIRECTORY/ownership.json"
{command}"#
    );
    let script = format!(
        r#"set -eu
root="${{XDG_RUNTIME_DIR:-/run/user/$(id -u)}}/{name}"
[ "$(systemctl --user show {unit} -p LoadState --value 2>/dev/null)" = not-found ]
umask 077
mkdir "$root"
reservation=''
cleanup_reservation() {{
  if [ -n "$reservation" ] && [ "$(stat -c '%d:%i' -- "$root" 2>/dev/null)" = "$reservation" ]; then
    rmdir -- "$root" 2>/dev/null || :
  fi
}}
trap cleanup_reservation EXIT
trap 'exit 1' HUP INT TERM
reservation=$(stat -c '%d:%i' -- "$root")
systemd-run --user --collect --quiet --expand-environment=no --unit={unit} --property=Type=exec --property=ExitType=cgroup --property=KillMode=control-group --property=RuntimeDirectory={name} --property=RuntimeDirectoryMode=0700 -- sh -c {service}
n=0
while [ "$n" -lt 100 ]; do
  if [ -f "$root/ownership.json" ]; then trap - EXIT HUP INT TERM; cat "$root/ownership.json"; exit 0; fi
  n=$((n + 1)); sleep 0.05
done
exit 1"#,
        service = shell_word(&service)
    );
    Ok((script, what))
}

#[cfg(test)]
mod workspace_open_tests {
    use odin_hermes::runtime::{WorkspaceConnection, WorkspaceConnectionKind};

    #[test]
    fn owned_launch_isolated_and_receipted_before_gui_exec() {
        let mut connection = WorkspaceConnection {
            command: "zed ssh://mini/home/colin/project".to_owned(),
            kind: WorkspaceConnectionKind::Zed,
            host: "mini".to_owned(),
            target: "project".to_owned(),
        };
        let (script, _) = super::workspace_owned_command(&connection, "run-123").unwrap();
        assert!(script.contains("--unit=odin-workspace-run-123.service"));
        assert!(script.contains("--property=ExitType=cgroup"));
        assert!(script.contains("--property=RuntimeDirectory=odin-workspace-run-123"));
        assert!(script.contains("mkdir \"$root\""));
        assert!(script.contains("trap cleanup_reservation EXIT"));
        assert!(script.contains("reservation=$(stat -c '%d:%i' -- \"$root\")"));
        assert!(script.contains("rmdir -- \"$root\""));
        assert!(script.contains("trap - EXIT HUP INT TERM; cat"));
        assert!(!script.contains("rm -r"));
        assert!(!script.contains("mkdir -p"));
        assert!(!script.contains("--replace"));
        assert!(script.contains("--foreground --new --user-data-dir"));
        assert!(
            script
                .find("ln \"$RUNTIME_DIRECTORY/.ownership.json\"")
                .unwrap()
                < script.find("--foreground").unwrap()
        );
        for invalid in ["", "../foreign", "with space", "UPPER", "-leading"] {
            assert!(super::workspace_owned_command(&connection, invalid).is_err());
        }
        assert!(super::workspace_owned_command(&connection, &"a".repeat(65)).is_err());
        connection.kind = WorkspaceConnectionKind::Zellij;
        connection.command = "zr mini odin".to_owned();
        let (script, _) = super::workspace_owned_command(&connection, "run-123").unwrap();
        assert!(script.contains("--separate"));
    }

    #[test]
    fn owned_launch_preserves_shell_expansion_through_systemd_arguments() {
        let connection = WorkspaceConnection {
            command: "zed ssh://mini/home/colin/project".to_owned(),
            kind: WorkspaceConnectionKind::Zed,
            host: "mini".to_owned(),
            target: "project".to_owned(),
        };
        let (script, _) = super::workspace_owned_command(&connection, "expansion-test").unwrap();
        let root = tempfile::tempdir().unwrap();
        // Parse the real outer shell quoting and intercept argv before any service
        // starts. A failed submission also exercises the reservation-only cleanup.
        let harness = format!(
            "systemctl() {{ printf 'not-found\\n'; }}\n\
             systemd-run() {{ printf '%s\\000' \"$@\"; return 42; }}\n{script}"
        );
        let output = std::process::Command::new("sh")
            .args(["-c", &harness])
            .env("XDG_RUNTIME_DIR", root.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(42));
        assert!(!root.path().join("odin-workspace-expansion-test").exists());
        let argv: Vec<&str> = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|word| !word.is_empty())
            .map(|word| std::str::from_utf8(word).unwrap())
            .collect();
        let separator = argv.iter().position(|word| *word == "--").unwrap();
        assert_eq!(&argv[separator + 1..separator + 3], &["sh", "-c"]);
        let service = argv[separator + 3];
        let guard = service
            .lines()
            .filter(|line| {
                line.starts_with("case \"$INVOCATION_ID\"")
                    || line.starts_with("[ \"${#INVOCATION_ID}\"")
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(guard.lines().count(), 2);
        // Model the relevant systemd intermediate substitution: #INVOCATION_ID
        // is not a valid environment name, so ${#INVOCATION_ID} becomes empty.
        // Execute both paths, rather than only checking a command substring.
        let run_guard = |expand: bool, invocation: &str| {
            let argument = if expand {
                guard.replace("${#INVOCATION_ID}", "")
            } else {
                guard.clone()
            };
            std::process::Command::new("sh")
                .args(["-eu", "-c", &argument])
                .env("INVOCATION_ID", invocation)
                .status()
                .unwrap()
                .success()
        };
        let invocation = "0123456789abcdef0123456789abcdef";
        assert!(!run_guard(true, invocation), "default expansion must fail");
        let expand = !argv[..separator].contains(&"--expand-environment=no");
        assert!(run_guard(expand, invocation));
        assert!(!run_guard(expand, "0123456789abcdef0123456789abcde"));
        assert!(!run_guard(expand, "g123456789abcdef0123456789abcdef"));
    }

    /// (acceptance chat.clarify: "the connection helper
    /// returned a launch command rather than opening your editor"): the
    /// open step runs the editor or terminal in the device's desktop
    /// session, quoted, and refuses without a session or with a locked
    /// screen.
    #[test]
    fn a_workspace_opens_in_the_devices_desktop_session() {
        let zed = WorkspaceConnection {
            command: "zed ssh://mini/home/colin/valhalla/surtr".to_owned(),
            kind: WorkspaceConnectionKind::Zed,
            host: "mini".to_owned(),
            target: "surtr".to_owned(),
        };
        let open = |connection: &WorkspaceConnection| {
            let (command, what) = super::workspace_open_command(connection).expect("command");
            (
                super::desktop_script(&format!(
                    "systemd-run --user --collect --quiet -- {command}"
                )),
                what,
            )
        };
        let (script, what) = open(&zed);
        assert!(
            script.contains("systemd-run --user --collect --quiet -- 'sh' '-c'"),
            "{script}"
        );
        assert!(
            script.contains("command -v zeditor || command -v zed"),
            "{script}"
        );
        assert!(
            script.contains("'ssh://mini/home/colin/valhalla/surtr'"),
            "{script}"
        );
        assert!(
            script.contains("LockedHint") && script.contains("exit 65"),
            "{script}"
        );
        assert!(script.contains("exit 64"), "{script}");
        assert_eq!(what, "Zed on surtr (mini)");
        let zellij = WorkspaceConnection {
            command: "zr mini odin".to_owned(),
            kind: WorkspaceConnectionKind::Zellij,
            host: "mini".to_owned(),
            target: "odin".to_owned(),
        };
        let (script, _) = open(&zellij);
        assert!(
            script.ends_with("-- 'konsole' '-e' 'zr' 'mini' 'odin'"),
            "{script}"
        );
        assert_eq!(super::shell_word("it's"), "'it'\\''s'");
    }

    /// Text goes to ydotool on stdin, never through shell interpolation.
    #[test]
    fn desktop_input_types_stdin_behind_the_desktop_law() {
        let script = super::desktop_script(&super::desktop_input_command(true));
        assert!(
            script.contains("exit 64") && script.contains("exit 65"),
            "{script}"
        );
        assert!(
            script.ends_with("ydotool type --file - && ydotool key 28:1 28:0"),
            "{script}"
        );
        assert!(
            script.contains("YDOTOOL_SOCKET:-/run/ydotoold/socket"),
            "{script}"
        );
        assert!(super::desktop_input_command(false).ends_with("ydotool type --file -"));
    }

    #[test]
    fn an_unknown_desktop_session_is_locked() {
        let root = tempfile::tempdir().expect("temp");
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).expect("bin");
        std::fs::write(
            bin.join("systemctl"),
            "#!/bin/sh\nprintf '%s\\n' 'WAYLAND_DISPLAY=wayland-1' 'XDG_SESSION_ID='\n",
        )
        .expect("systemctl");
        std::fs::write(bin.join("loginctl"), "#!/bin/sh\nexit 1\n").expect("loginctl");
        std::fs::write(bin.join("timeout"), "#!/bin/sh\nshift 2\nexec \"$@\"\n").expect("timeout");
        for name in ["systemctl", "loginctl", "timeout"] {
            let path = bin.join(name);
            let mut perms = std::fs::metadata(&path).expect("meta").permissions();
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("chmod");
        }
        let script = super::desktop_script("echo typed");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut path = std::env::split_paths(&path).collect::<Vec<_>>();
        path.insert(0, bin);
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .env("PATH", std::env::join_paths(path).expect("path"))
            .status()
            .expect("script");
        assert_eq!(status.code(), Some(super::OPEN_LOCKED));
    }
}
