use super::*;

/// Bounded scan window for the zellij-web unit block's `ExecStart`.
const ZELLIJ_UNIT_WINDOW_BYTES: usize = 512;

/// The declared zellij web endpoint. The declared service — the
/// `zellij-web` systemd user unit — is the source of truth, never the
/// settings block (whose `web_server = false` merely turns off the
/// built-in server the unit replaces, and whose `web_server_port =
/// webPort` names an identifier, not a port).
///
/// The declared host facts win when present; otherwise the tracked
/// dotfiles declaration is scanned: enabled exactly when the zellij-web
/// unit declares an `ExecStart`, host from `web_server_ip`, and port from
/// the `webPort = <u16>;` let-binding.
pub(in crate::syscheck) fn zellij_declared_endpoint(
    dotfiles_root: &Path,
    facts: Option<&ZellijWebFacts>,
) -> Result<ZellijWebDeclaration, CheckFailure> {
    if let Some(declared) = facts {
        return Ok(ZellijWebDeclaration {
            enabled: declared.enabled,
            endpoint: (declared.ip.clone(), declared.port),
        });
    }
    let path = dotfiles_root.join("modules/home/zellij.nix");
    let bytes = read_bounded(&path).map_err(|error| {
        CheckFailure::fail(
            "zellij-declaration-unreadable",
            format!(
                "tracked zellij declaration {} is unreadable: {error}",
                path.display()
            ),
        )
    })?;
    let source = String::from_utf8_lossy(&bytes);
    let declared = |pattern: &str| -> Option<String> {
        let start = source.find(pattern)? + pattern.len();
        let rest = &source[start..];
        let end = rest.find(';')?;
        Some(rest[..end].trim().trim_matches('"').to_owned())
    };
    let enabled = source.find("services.zellij-web").is_some_and(|start| {
        let window = &source[start..];
        let window = &window[..window.len().min(ZELLIJ_UNIT_WINDOW_BYTES)];
        window.contains("ExecStart") && window.contains("zellij web")
    });
    let host = declared("web_server_ip = ").ok_or_else(|| {
        CheckFailure::fail(
            "zellij-declaration-invalid",
            "tracked zellij declaration does not declare web_server_ip",
        )
    })?;
    let port = declared("webPort = ")
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            CheckFailure::fail(
                "zellij-declaration-invalid",
                "tracked zellij declaration does not declare a numeric webPort let-binding",
            )
        })?;
    Ok(ZellijWebDeclaration {
        enabled,
        endpoint: (host, port),
    })
}

/// The deployed gateway ownership claim: whether the packaged strict odind
/// composition — the config the live daemon consumes — declares the
/// governed `[hermes].discord` surface. Deployed metadata only: the
/// unactivated dotfiles candidate never decides a live requirement.
pub(in crate::syscheck) fn odin_discord_declared(config: &OdindConfig) -> bool {
    config
        .hermes
        .as_ref()
        .and_then(|hermes| hermes.discord.as_ref())
        .is_some()
}

/// The digest-verified gateway projection's first route endpoint.
pub(in crate::syscheck) fn model_endpoint(
    config: &OdindConfig,
) -> Result<(String, u16), CheckFailure> {
    let reference = &config.catalogs.gateway_projection;
    let bytes = read_bounded(&reference.path).map_err(|error| {
        CheckFailure::fail(
            "gateway-projection-unreadable",
            format!(
                "gateway projection {} is unreadable: {error}",
                reference.path.display()
            ),
        )
    })?;
    let digest = blake3::hash(&bytes).to_hex().to_string();
    if format!("blake3:{digest}") != reference.digest {
        return Err(CheckFailure::fail(
            "gateway-projection-digest-mismatch",
            format!(
                "gateway projection {} digests to blake3:{digest}, config declares {}",
                reference.path.display(),
                reference.digest
            ),
        ));
    }
    let projection: GatewayProjectionManifest =
        serde_json::from_slice(&bytes).map_err(|error| {
            CheckFailure::fail(
                "gateway-projection-malformed",
                format!("gateway projection is malformed: {error}"),
            )
        })?;
    projection.verify().map_err(|error| {
        CheckFailure::fail(
            "gateway-projection-unverifiable",
            format!("gateway projection failed typed verification: {error}"),
        )
    })?;
    let route = projection.routes.first().ok_or_else(|| {
        CheckFailure::fail(
            "gateway-projection-empty",
            "gateway projection declares no model route",
        )
    })?;
    endpoint_host_port(&route.endpoint).ok_or_else(|| {
        CheckFailure::fail(
            "gateway-projection-endpoint-invalid",
            format!(
                "model endpoint {} is not a host:port authority",
                route.endpoint
            ),
        )
    })
}

/// Probe LiteLLM's liveness response: another service can occupy the configured port while model requests fail.
pub(in crate::syscheck) fn gateway_answers_as_litellm(addr: SocketAddr, deadline: Instant) -> bool {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return false;
    }
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, left.min(Duration::from_secs(3))) else {
        return false;
    };
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return false;
    }
    let _ = stream.set_read_timeout(Some(left.min(Duration::from_secs(5))));
    let request = format!("GET /health/liveliness HTTP/1.0\r\nHost: {addr}\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = Vec::new();
    let _ = stream.take(4096).read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response);
    text.split_whitespace().nth(1) == Some("200") && text.contains("I'm alive")
}

/// Parses a bounded YAML file.
pub(in crate::syscheck) fn parse_yaml_file(path: &Path) -> io::Result<serde_yaml::Value> {
    let bytes = read_bounded(path)?;
    serde_yaml::from_slice(&bytes).map_err(io::Error::other)
}

/// Collects one bounded, unique, string-keyed model id set from a YAML path.
pub(in crate::syscheck) fn yaml_model_names(
    root: &serde_yaml::Value,
    path: &[&str],
    id_field: &str,
) -> Option<BTreeSet<String>> {
    let mut current = root;
    for key in path {
        current = current.get(*key)?;
    }
    let sequence = current.as_sequence()?;
    if sequence.is_empty() || sequence.len() > 512 {
        return None;
    }
    let mut names = BTreeSet::new();
    for item in sequence {
        let name = item.get(id_field)?.as_str()?;
        if !is_safe_identifier(name) || !names.insert(name.to_owned()) {
            return None;
        }
    }
    Some(names)
}

/// Strict scalar equality across the YAML and JSON projections.
pub(in crate::syscheck) fn yaml_json_scalar_equal(
    yaml: Option<&serde_yaml::Value>,
    json: Option<&JsonValue>,
) -> bool {
    match (yaml, json) {
        (Some(serde_yaml::Value::String(left)), Some(JsonValue::String(right))) => left == right,
        (Some(serde_yaml::Value::Number(left)), Some(JsonValue::Number(right))) => {
            left.to_string() == right.to_string()
        }
        (Some(serde_yaml::Value::Number(left)), Some(JsonValue::String(right))) => {
            decimal_budget_units(&left.to_string())
                .zip(decimal_budget_units(right))
                .is_some_and(|(left, right)| left == right)
        }
        (Some(serde_yaml::Value::String(left)), Some(JsonValue::Number(right))) => {
            decimal_budget_units(left)
                .zip(decimal_budget_units(&right.to_string()))
                .is_some_and(|(left, right)| left == right)
        }
        (Some(serde_yaml::Value::Bool(left)), Some(JsonValue::Bool(right))) => left == right,
        _ => false,
    }
}

pub(in crate::syscheck) fn decimal_budget_units(value: &str) -> Option<u64> {
    if !decimal_budget_ok(value) {
        return None;
    }
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let cents = match fraction.len() {
        0 => 0,
        1 => fraction.parse::<u64>().ok()?.checked_mul(10)?,
        _ => fraction.parse::<u64>().ok()?,
    };
    whole
        .parse::<u64>()
        .ok()?
        .checked_mul(100)?
        .checked_add(cents)
}

/// The frozen budget decimal shape: at most 12 characters, at most two
/// fractional digits, no leading zeros, never negative.
pub(in crate::syscheck) fn decimal_budget_ok(value: &str) -> bool {
    if value.is_empty() || value.len() > 12 {
        return false;
    }
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    if whole.is_empty()
        || (whole.len() > 1 && whole.starts_with('0'))
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    match fraction {
        Some(fraction) => {
            (1..=2).contains(&fraction.len()) && fraction.bytes().all(|byte| byte.is_ascii_digit())
        }
        None => true,
    }
}
