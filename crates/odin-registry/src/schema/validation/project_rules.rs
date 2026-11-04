//! Project declarations and their exact capsule sphere.

use super::*;
pub(super) fn validate_project(
    object: &RegistryObject,
    value: &ProjectToml,
    findings: &mut Vec<RegistryFinding>,
) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    require_nonempty(
        object,
        "default_seat",
        value.default_seat.as_str(),
        findings,
    );
    require_allowed(
        object,
        "artifact_policy",
        &value.artifact_policy,
        &["standard", "private", "large-scientific"],
        findings,
    );
    for (kind, name) in &value.accounts {
        if !crate::schema::valid_account_name(name) {
            findings.push(fail(
                object,
                "project-account",
                format!(
                    "accounts.{} = {name:?} must be an account handle (lowercase letters, digits, inner dashes)",
                    kind.as_str()
                ),
            ));
        }
    }
    if let Some(deploy) = value
        .deploy
        .as_ref()
        .filter(|deploy| deploy.targets.is_empty())
    {
        findings.push(fail(
            object,
            "project-deploy",
            format!("deploy from {} names no targets to switch", deploy.host),
        ));
    }
    if let Some(deploy) = &value.deploy {
        let checkout = std::path::Path::new(&deploy.checkout);
        if deploy.checkout.is_empty()
            || checkout.is_absolute()
            || checkout
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            findings.push(fail(
                object,
                "project-deploy",
                format!(
                    "deploy.checkout = {:?} must be a plain path relative to home",
                    deploy.checkout
                ),
            ));
        }
    }
    if let Some(repo) = &value.repo {
        let valid = |part: &str| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        };
        let slug = match repo.split_once('/') {
            Some((owner, name)) => valid(owner) && valid(name) && !name.contains('/'),
            None => false,
        };
        if !slug {
            findings.push(fail(
                object,
                "project-repo",
                format!("repo = {repo:?} must be a GitHub owner/name slug"),
            ));
        }
    }
    for namespace in &value.memory_namespaces {
        if !valid_memory_namespace(namespace.as_str()) {
            findings.push(fail(
                object,
                "project-memory-namespace",
                format!(
                    "memory_namespaces entry {namespace:?} must be a nonempty atlas.<subtree> or memory.<name> \
                     namespace"
                ),
            ));
        }
    }
    if let Some(sphere) = &value.sphere {
        validate_sphere(object, sphere, findings);
    }
}

fn validate_sphere(
    object: &RegistryObject,
    sphere: &crate::schema::ProjectSphereToml,
    findings: &mut Vec<RegistryFinding>,
) {
    let mut reject = |message: String| findings.push(fail(object, "project-sphere", message));
    let plain_absolute = |value: &str| {
        let path = std::path::Path::new(value);
        path.is_absolute()
            && value != "/"
            && !value.ends_with('/')
            && !value.contains("//")
            && path
                .components()
                .skip(1)
                .all(|part| matches!(part, std::path::Component::Normal(_)))
            && !value.bytes().any(|b| b.is_ascii_control())
    };
    let mut roots: Vec<&str> = Vec::new();
    for root in sphere
        .data_roots
        .iter()
        .chain(std::iter::once(&sphere.scratch))
    {
        if !plain_absolute(root) || root == "/dev" || root.starts_with("/dev/") {
            reject(format!(
                "sphere root {root:?} must be a normalized absolute non-device path"
            ));
        }
        for previous in &roots {
            if paths_nest_or_collide(root, previous) {
                reject(format!("sphere roots {root:?} and {previous:?} overlap"));
            }
        }
        roots.push(root.as_str());
    }
    for profile in &sphere.pod_profiles {
        if !valid_id(profile) {
            reject(format!("invalid sphere pod profile {profile:?}"));
        }
    }
    let mut devices = BTreeSet::new();
    for device in &sphere.devices {
        if !valid_id(&device.name) || !devices.insert(&device.name) {
            reject(format!(
                "invalid or duplicate sphere device {:?}",
                device.name
            ));
        }
        match (&device.node, &device.api, &device.endpoint) {
            (Some(node), None, None) if plain_absolute(node)
                && node.strip_prefix("/dev/serial/by-id/").is_some_and(|name| !name.is_empty() && !name.contains('/')) => {}
            (None, Some(api), None) if http_endpoint(api) => {}
            (None, None, Some(endpoint)) if admitted_device_endpoint(endpoint) => {}
            (None, None, None) => {}
            _ => reject(format!(
                "device {:?} must declare at most one stable serial node, HTTP(S) API, or bound endpoint",
                device.name
            )),
        }
        let mut actions = BTreeSet::new();
        if device.actions.is_empty() {
            reject(format!("device {:?} has no actions", device.name));
        }
        for action in &device.actions {
            if !valid_id(&action.name) || !actions.insert(&action.name) {
                reject(format!(
                    "invalid or duplicate action {:?} on {:?}",
                    action.name, device.name
                ));
            }
            match action.argv.first() {
                Some(exe) if !exe.contains("/target/")
                    && ((exe.starts_with("/nix/store/") && plain_absolute(exe))
                    || exe.strip_prefix("{capsule}/").is_some_and(|suffix| !suffix.is_empty()
                        && std::path::Path::new(suffix).components().all(|part| matches!(part, std::path::Component::Normal(_))))
                    || exe.strip_prefix("{runtime.").and_then(|s| s.strip_suffix('}')).is_some_and(valid_id)) => {}
                _ => reject(format!(
                    "action {:?} must pin an installed executable in /nix/store, the capsule, or a runtime manifest binding, not a clone build artifact",
                    action.name
                )),
            }
            for param in action.params.keys() {
                if !valid_id(param)
                    || matches!(
                        param.as_str(),
                        "node" | "api" | "endpoint" | "capsule" | "scratch"
                    )
                {
                    reject(format!("invalid or reserved action parameter {param:?}"));
                }
            }
            let mut used = BTreeSet::new();
            for (index, arg) in action.argv.iter().enumerate() {
                if arg.is_empty() || arg.bytes().any(|b| b.is_ascii_control()) {
                    reject(format!(
                        "action {:?} contains an empty or control-character argv",
                        action.name
                    ));
                }
                let mut rest = arg.as_str();
                while let Some(open) = rest.find('{') {
                    if rest[..open].contains('}') {
                        reject(format!(
                            "action {:?} contains malformed placeholders",
                            action.name
                        ));
                    }
                    let Some(close) = rest[open + 1..].find('}') else {
                        reject(format!(
                            "action {:?} contains malformed placeholders",
                            action.name
                        ));
                        rest = "";
                        break;
                    };
                    let name = &rest[open + 1..open + 1 + close];
                    let allowed = match name {
                        "node" => device.node.is_some(),
                        "api" => device.api.is_some(),
                        "endpoint" => device.endpoint.is_some(),
                        "capsule" | "scratch" => true,
                        _ if index == 0 && arg == &format!("{{{name}}}") => {
                            name.strip_prefix("runtime.").is_some_and(valid_id)
                                || action.params.contains_key(name)
                        }
                        _ => action.params.contains_key(name),
                    };
                    if !allowed {
                        reject(format!(
                            "action {:?} has undeclared placeholder {name:?}",
                            action.name
                        ));
                    }
                    used.insert(name.to_owned());
                    rest = &rest[open + close + 2..];
                }
                if rest.contains('}') {
                    reject(format!(
                        "action {:?} contains malformed placeholders",
                        action.name
                    ));
                }
            }
            for param in action.params.keys() {
                if !used.contains(param) {
                    reject(format!(
                        "action {:?} does not use parameter {param:?}",
                        action.name
                    ));
                }
            }
        }
    }
}

fn http_endpoint(value: &str) -> bool {
    (value.starts_with("http://") || value.starts_with("https://"))
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

/// A bound device endpoint is either an absolute HTTP(S) URL or
/// `unix://<absolute-socket>`. The socket path is one normalized absolute
/// path with no query, so it can be bound into the lane bubble.
fn admitted_device_endpoint(value: &str) -> bool {
    if http_endpoint(value) {
        return true;
    }
    let Some(path) = value.strip_prefix("unix://") else {
        return false;
    };
    let socket = std::path::Path::new(path);
    socket.is_absolute()
        && path != "/"
        && !path.ends_with('/')
        && !path.contains("//")
        && !path.contains('?')
        && !path.contains('#')
        && socket
            .components()
            .skip(1)
            .all(|part| matches!(part, std::path::Component::Normal(_)))
        && !path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}
