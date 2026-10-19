use super::*;

pub(in crate::syscheck) fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(in crate::syscheck) fn is_wildcard_host(host: &str) -> bool {
    matches!(host, "*" | "0.0.0.0" | "::" | "")
}

pub(in crate::syscheck) fn is_loopback_host(host: &str) -> bool {
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Splits one `host:port` listener endpoint, normalizing brackets and zones.
pub(in crate::syscheck) fn parse_listener_endpoint(endpoint: &str) -> Option<(String, u16)> {
    let (host, port) = endpoint.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split_once('%')
        .map_or(host.trim().trim_matches(&['[', ']'][..]), |(address, _)| {
            address
        })
        .to_owned();
    Some((host, port))
}

pub(in crate::syscheck) fn endpoint_host_port(url: &str) -> Option<(String, u16)> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split('/').next()?;
    parse_listener_endpoint(authority)
}

/// The private-binding policy: exact declared address, or any loopback
/// address when the declared address itself is loopback. Wildcards never pass.
pub(in crate::syscheck) fn host_allowed(required: &str, observed: &str) -> bool {
    if is_wildcard_host(observed) {
        return false;
    }
    required == observed || (is_loopback_host(required) && is_loopback_host(observed))
}

pub(in crate::syscheck) fn listener_owner_pid(line: &str) -> Option<u32> {
    let start = line.find("pid=")? + "pid=".len();
    let bytes = line.as_bytes();
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == start {
        return None;
    }
    line.get(start..end)?.parse().ok()
}

fn listener_owner_name(line: &str) -> Option<String> {
    let start = line.find("((\"")? + 3;
    let end = start + line.get(start..)?.find('"')?;
    Some(line.get(start..end)?.to_owned())
}

const LISTENER_INVENTORY_CAP: usize = 2_048;

fn parse_listener_inventory(stdout: &[u8]) -> Result<Vec<SocketObservation>, CheckFailure> {
    let text = String::from_utf8_lossy(stdout);
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() > LISTENER_INVENTORY_CAP {
        return Err(CheckFailure::fail(
            "listener-inventory-truncated",
            format!(
                "the listener inventory has {} rows, over the {LISTENER_INVENTORY_CAP}-row cap; sockets past it would go unchecked",
                lines.len()
            ),
        ));
    }
    Ok(lines
        .into_iter()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 4 || fields[0] != "LISTEN" {
                return None;
            }
            let (address, port) = parse_listener_endpoint(fields[3])?;
            Some(SocketObservation {
                address,
                port,
                owner_pid: listener_owner_pid(line),
                owner_name: listener_owner_name(line),
            })
        })
        .collect())
}

pub(in crate::syscheck) fn listener_inventory(
    tool: &Path,
    command_scratch: &Path,
    current_dir: &Path,
    deadline: Instant,
) -> Result<Vec<SocketObservation>, CheckFailure> {
    let outcome = run_bounded(
        tool,
        &[OsString::from("-H"), OsString::from("-ltnp")],
        command_scratch,
        current_dir,
        deadline,
    )
    .map_err(|error| {
        CheckFailure::fail(
            "listener-inventory-failed",
            format!("listener inventory could not execute: {error}"),
        )
    })?;
    if let Some(problem) = command_problem(&outcome) {
        return Err(CheckFailure::fail(
            "listener-inventory-failed",
            format!("listener inventory did not complete: {problem}"),
        ));
    }
    parse_listener_inventory(&outcome.stdout)
}

pub(in crate::syscheck) fn path_has_component(path: &str, component: &str) -> bool {
    Path::new(path)
        .components()
        .any(|part| matches!(part, Component::Normal(value) if value == OsStr::new(component)))
}

pub(in crate::syscheck) fn parse_last_u64(bytes: &[u8]) -> Option<u64> {
    String::from_utf8_lossy(bytes)
        .split_whitespace()
        .filter_map(|field| field.parse::<u64>().ok())
        .next_back()
}

pub(in crate::syscheck) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(in crate::syscheck) fn walk_entries(
    root: &Path,
    max_depth: usize,
) -> io::Result<Vec<walkdir::DirEntry>> {
    let mut entries = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .max_depth(max_depth)
        .into_iter()
    {
        let entry = entry.map_err(io::Error::other)?;
        if entries.len() == WALK_ENTRY_CAP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem walk exceeded entry cap",
            ));
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Numbered `system-<n>-link` entries, counted by name alone.
pub(in crate::syscheck) fn system_generation_links(
    profiles_root: &Path,
) -> Result<Vec<String>, CheckFailure> {
    let entries = fs::read_dir(profiles_root).map_err(|error| {
        CheckFailure::fail(
            "generations-profile-unreadable",
            format!(
                "the NixOS system profile root {} could not be read: {error}",
                profiles_root.display()
            ),
        )
    })?;
    let mut generations = Vec::new();
    let mut examined = 0_usize;
    for entry in entries {
        let entry = entry.map_err(|error| {
            CheckFailure::fail(
                "generations-profile-unreadable",
                format!(
                    "the NixOS system profile root {} could not be walked: {error}",
                    profiles_root.display()
                ),
            )
        })?;
        examined += 1;
        if examined > WALK_ENTRY_CAP {
            return Err(CheckFailure::fail(
                "generations-profile-unbounded",
                "the system profile root exceeded its entry cap",
            ));
        }
        if is_system_generation_name(&entry.file_name()) {
            generations.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    generations.sort();
    Ok(generations)
}

fn is_system_generation_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name.strip_prefix("system-")
        .and_then(|rest| rest.strip_suffix("-link"))
        .is_some_and(|number| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_rows_carry_the_owner_name_and_an_overfull_inventory_fails() {
        let row = "LISTEN 0 128 0.0.0.0:9418 0.0.0.0:* users:((\"git-daemon\",pid=7,fd=3))\n";
        let parsed = parse_listener_inventory(row.as_bytes()).expect("one row");
        assert_eq!(parsed[0].owner_name.as_deref(), Some("git-daemon"));
        assert_eq!(parsed[0].owner_pid, Some(7));
        let overfull = row.repeat(LISTENER_INVENTORY_CAP + 1);
        let failure = parse_listener_inventory(overfull.as_bytes())
            .expect_err("sockets past the cap would go unchecked");
        assert_eq!(failure.reason, "listener-inventory-truncated");
    }
}
