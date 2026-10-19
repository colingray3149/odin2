use super::*;

pub(super) fn run_sys_09(context: &SystemContext, deadline: Instant) -> CheckResult {
    super::run_check("SYS-09", sys_09_body, context, deadline)
}

/// Read ExecStart from the loaded unit rather than guessing the generated config path.
fn litellm_config_from_unit(
    units: &mut UnitStateReader,
) -> Result<(PathBuf, String), CheckFailure> {
    let properties = units.unit("litellm.service")?;
    if properties.get("LoadState").map(String::as_str) != Some("loaded") {
        return Err(CheckFailure::blocked(
            "litellm-config-unconfigured",
            "the litellm unit is not loaded; the gateway config cannot be located",
        ));
    }
    let exec_start = properties.get("ExecStart").ok_or_else(|| {
        CheckFailure::fail(
            "litellm-execstart-missing",
            "the loaded litellm unit declares no ExecStart",
        )
    })?;
    let config = config_path_from_exec_start(exec_start).ok_or_else(|| {
        CheckFailure::fail(
            "litellm-config-argument-missing",
            "the litellm unit ExecStart names no --config path",
        )
    })?;
    Ok((config, exec_start.clone()))
}

fn listen_from_exec_start(exec_start: &str) -> Option<std::net::SocketAddr> {
    let fields = exec_start.split_whitespace().collect::<Vec<_>>();
    let value = |option: &str| {
        fields.windows(2).find_map(|pair| {
            (pair[0].trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-') == option)
                .then(|| pair[1].trim_matches(&['"', '\'', ';', '}', '{'][..]))
        })
    };
    format!("{}:{}", value("--host")?, value("--port")?)
        .parse()
        .ok()
}

/// Pairwise scanning distinguishes option values from positional arguments.
fn config_path_from_exec_start(exec_start: &str) -> Option<PathBuf> {
    let fields = exec_start.split_whitespace().collect::<Vec<_>>();
    let mut found = None;
    for pair in fields.windows(2) {
        if pair[0].trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-') == "--config" {
            let value = pair[1].trim_matches(&['"', '\'', ';', '}', '{'][..]);
            if !value.is_empty() {
                found = Some(PathBuf::from(value));
                break;
            }
        }
    }
    found
}

/// Read the running service's environment to include values loaded through EnvironmentFile.
fn service_environ(units: &mut UnitStateReader, var: &str) -> Result<Vec<u8>, CheckFailure> {
    let properties = units.unit("litellm.service")?;
    properties
        .get("MainPID")
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid > 0)
        .and_then(|pid| fs::read(format!("/proc/{pid}/environ")).ok())
        .and_then(|blob| environ_value(&blob, var).map(<[u8]>::to_vec))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            unverifiable_accounting(format!(
                "{var} is not set to a nonempty value in the running litellm service environment, or that environment could not be read"
            ))
        })
}

fn unverifiable_accounting(detail: String) -> CheckFailure {
    CheckFailure::fail(
        "gateway-budget-accounting-unverifiable",
        format!("LiteLLM's spend accounting database is not proven: {detail}; without it spend is invisible and a declared cap blocks nothing"),
    )
}

fn sys_09_body(context: &SystemContext, deadline: Instant) -> Outcome {
    match load_host_facts()?.and_then(|facts| facts.gateway) {
        Some(relay) => sys_09_relay(context, deadline, &relay),
        None => sys_09_local(context, deadline),
    }
}

fn sys_09_local(context: &SystemContext, deadline: Instant) -> Outcome {
    let mut evidence = Vec::new();

    // Compare against the running unit to detect drift in the installed sweep configuration.
    let mut units = UnitStateReader::for_host(ManagerScope::UserThenSystem)?;
    let (litellm_path, exec_start) = litellm_config_from_unit(&mut units)?;
    if let Some(declared) = env::var_os("SWEEP_LITELLM_CONFIG").filter(|value| !value.is_empty()) {
        if Path::new(&declared) != litellm_path {
            return Err(CheckFailure::fail(
                "litellm-config-drift",
                format!(
                    "the running litellm unit serves {}, but the installed sweep declares {}",
                    litellm_path.display(),
                    Path::new(&declared).display()
                ),
            ));
        }
    }
    let addr = listen_from_exec_start(&exec_start).ok_or_else(|| {
        CheckFailure::fail(
            "litellm-bind-missing",
            "the litellm unit ExecStart names no --host/--port bind",
        )
    })?;
    if !gateway_answers_as_litellm(addr, deadline) {
        return Err(CheckFailure::fail(
            "gateway-not-serving",
            format!("LiteLLM does not answer its liveness route at its declared bind {addr}; the service is down or another service holds the port"),
        ));
    }
    note_evidence(&mut evidence, format!("gateway-live={addr}"));
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            CheckFailure::blocked(
                "home-unavailable",
                "HOME is not set; generated gateway metadata paths cannot be resolved",
            )
        })?;
    let lane_path = env::var_os("SWEEP_LANE_METADATA")
        .filter(|value| !value.is_empty())
        .map_or_else(|| home.join(".pi/agent/lane-meta.json"), PathBuf::from);
    let omp_path = env::var_os("SWEEP_OMP_MODELS")
        .filter(|value| !value.is_empty())
        .map_or_else(|| home.join(".omp/agent/models.yml"), PathBuf::from);

    // Restrict parsing to public configuration and scratch inputs to avoid reading credentials.
    let public_config = |path: PathBuf| -> Result<PathBuf, CheckFailure> {
        let resolved = fs::canonicalize(&path).map_err(|error| {
            CheckFailure::blocked(
                "gateway-config-unavailable",
                format!("gateway configuration {}: {error}", path.display()),
            )
        })?;
        if !resolved.starts_with("/nix/store") && !resolved.starts_with(&context.scratch_root) {
            return Err(CheckFailure::blocked("private-gateway-config-not-read",
                format!("refusing to read potentially credential-bearing configuration {}; use a public declarative projection", path.display())));
        }
        Ok(resolved)
    };
    let litellm_path = public_config(litellm_path)?;
    let lane_path = public_config(lane_path)?;
    let omp_path = public_config(omp_path)?;

    let litellm = parse_yaml_file(&litellm_path).map_err(|error| {
        CheckFailure::fail(
            "litellm-config-malformed",
            format!(
                "LiteLLM config {} is missing or malformed: {error}",
                litellm_path.display()
            ),
        )
    })?;
    let lane_bytes = read_bounded(&lane_path).map_err(|error| {
        CheckFailure::fail(
            "lane-metadata-malformed",
            format!(
                "lane metadata {} is missing or malformed: {error}",
                lane_path.display()
            ),
        )
    })?;
    let lane_metadata: JsonValue = serde_json::from_slice(&lane_bytes).map_err(|_| {
        CheckFailure::fail("lane-metadata-malformed", "lane metadata is not valid JSON")
    })?;
    let omp_models = parse_yaml_file(&omp_path).map_err(|error| {
        CheckFailure::fail(
            "omp-models-malformed",
            format!(
                "OMP models {} are missing or malformed: {error}",
                omp_path.display()
            ),
        )
    })?;
    note_evidence(
        &mut evidence,
        format!("litellm-config={}", litellm_path.display()),
    );

    let lane_ids: BTreeSet<String> = lane_metadata
        .get("gateway")
        .and_then(JsonValue::as_object)
        .map(|gateway| gateway.keys().cloned().collect())
        .ok_or_else(|| {
            CheckFailure::fail(
                "lane-metadata-gateway-invalid",
                "lane metadata has no gateway lane map",
            )
        })?;
    if lane_ids.is_empty() || lane_ids.len() > 512 {
        return Err(CheckFailure::fail(
            "lane-metadata-gateway-invalid",
            "lane metadata gateway map is empty or unbounded",
        ));
    }
    let litellm_models =
        yaml_model_names(&litellm, &["model_list"], "model_name").ok_or_else(|| {
            CheckFailure::fail(
                "litellm-model-list-invalid",
                "the LiteLLM model list is malformed",
            )
        })?;
    let omp_model_ids = yaml_model_names(&omp_models, &["providers", "gateway", "models"], "id")
        .ok_or_else(|| {
            CheckFailure::fail(
                "omp-model-list-invalid",
                "the OMP gateway model list is malformed",
            )
        })?;

    // Budget projections must agree; accounting remains required even when no cap is declared.
    let lite_budget = litellm
        .get("litellm_settings")
        .and_then(serde_yaml::Value::as_mapping)
        .ok_or_else(|| {
            CheckFailure::fail(
                "litellm-budget-missing",
                "LiteLLM budget settings are absent",
            )
        })?;
    let lane_budget = lane_metadata.get("gatewayBudget").ok_or_else(|| {
        CheckFailure::fail("lane-budget-missing", "lane metadata budget is absent")
    })?;
    let cap = budget_cap_projection(lite_budget, lane_budget)?;
    note_evidence(
        &mut evidence,
        format!("budget-cap={}", cap.as_deref().unwrap_or("none")),
    );

    // Upstream enforcement reads general_settings, so a litellm_settings copy has no effect.
    let general_settings = litellm
        .get("general_settings")
        .and_then(serde_yaml::Value::as_mapping);
    fail_closed_enforced(general_settings, lite_budget)?;

    // The proxy-wide cap requires a live database; without one, upstream never blocks spending.
    let configured_url = match general_settings
        .and_then(|map| map.get(serde_yaml::Value::String("database_url".to_owned())))
    {
        Some(value) => Some(match value.as_str() {
            Some(url) => url.trim(),
            None => {
                return Err(CheckFailure::fail(
                    "gateway-budget-accounting-malformed",
                    "general_settings.database_url is not a string; set a literal URL or os.environ/DATABASE_URL",
                ));
            }
        }),
        None => None,
    };
    let (source, url) = match configured_url {
        Some("") => {
            return Err(CheckFailure::fail(
                "gateway-budget-accounting-malformed",
                "general_settings.database_url is declared but empty; set a literal URL, os.environ/DATABASE_URL, or remove the key to use the DATABASE_URL service-environment form",
            ));
        }
        Some(url) => match url.strip_prefix("os.environ/") {
            None => ("config-literal", url.as_bytes().to_vec()),
            Some(var) if var.trim().is_empty() => {
                return Err(CheckFailure::fail(
                    "gateway-budget-accounting-malformed",
                    "general_settings.database_url uses os.environ/ with an empty variable name; set os.environ/DATABASE_URL or a literal URL",
                ));
            }
            Some(var) => ("service-environ", service_environ(&mut units, var)?),
        },
        None => (
            "service-environ",
            service_environ(&mut units, "DATABASE_URL")?,
        ),
    };
    let endpoint = database_answers(&String::from_utf8_lossy(&url), deadline)
        .map_err(unverifiable_accounting)?;
    let accounting = format!("{source} database={endpoint} answers as postgres");
    note_evidence(&mut evidence, format!("budget-accounting={accounting}"));

    let missing_litellm = lane_ids
        .difference(&litellm_models)
        .cloned()
        .collect::<Vec<_>>();
    let missing_omp = lane_ids
        .difference(&omp_model_ids)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_litellm.is_empty() || !missing_omp.is_empty() {
        return Err(CheckFailure::fail(
            "lane-model-unreachable",
            format!(
                "declared lanes missing from LiteLLM {:?} and OMP {:?}",
                missing_litellm, missing_omp
            ),
        ));
    }
    note_evidence(&mut evidence, format!("lanes-resolved={}", lane_ids.len()));

    CheckOutcome::pass(
        format!(
            "{} declared lanes resolve with consistent budget projections, a general_settings fail-closed flag, and a configured accounting prerequisite",
            lane_ids.len()
        ),
        evidence,
    )
}

fn budget_cap_projection(
    lite_budget: &serde_yaml::Mapping,
    lane_budget: &JsonValue,
) -> Result<Option<String>, CheckFailure> {
    let lite_cap = lite_budget.get(serde_yaml::Value::String("max_budget".to_owned()));
    let lite_duration = lite_budget.get(serde_yaml::Value::String("budget_duration".to_owned()));
    let declared = |key: &str| lane_budget.get(key).filter(|value| !value.is_null());
    let (lane_cap, lane_duration) = (declared("capUsd"), declared("duration"));
    if !lane_budget.is_null() && !lane_budget.is_object() {
        return Err(CheckFailure::fail(
            "lane-budget-missing",
            "lane metadata budget is not an object",
        ));
    }
    if lite_cap.is_none() && lane_cap.is_none() {
        return Ok(None);
    }
    if lite_cap.is_none()
        || lite_duration.is_none()
        || lane_cap.is_none()
        || lane_duration.is_none()
        || !yaml_json_scalar_equal(lite_cap, lane_cap)
        || !yaml_json_scalar_equal(lite_duration, lane_duration)
    {
        return Err(CheckFailure::fail(
            "gateway-budget-inconsistent",
            "LiteLLM and lane budget projections are absent or inconsistent",
        ));
    }
    match lane_cap {
        Some(cap) if declared_budget_cap_ok(cap) => Ok(Some(match cap {
            JsonValue::String(text) => text.clone(),
            other => other.to_string(),
        })),
        cap => Err(CheckFailure::fail(
            "gateway-budget-malformed",
            format!(
                "the declared budget cap {} is not a valid decimal amount",
                cap.map(JsonValue::to_string).unwrap_or_default(),
            ),
        )),
    }
}

/// Generators emit numeric caps, while explicit configuration may use decimal strings.
fn declared_budget_cap_ok(lane_cap: &JsonValue) -> bool {
    match lane_cap {
        JsonValue::String(text) => decimal_budget_units(text).is_some(),
        JsonValue::Number(number) => decimal_budget_units(&number.to_string()).is_some(),
        _ => false,
    }
}

/// LiteLLM ignores this flag under litellm_settings, so its placement matters.
fn fail_closed_enforced(
    general_settings: Option<&serde_yaml::Mapping>,
    litellm_settings: &serde_yaml::Mapping,
) -> Result<(), CheckFailure> {
    const KEY: &str = "fail_closed_budget_enforcement";
    if general_settings
        .and_then(|map| map.get(serde_yaml::Value::String(KEY.to_owned())))
        .and_then(serde_yaml::Value::as_bool)
        == Some(true)
    {
        return Ok(());
    }
    let misplaced = litellm_settings
        .get(serde_yaml::Value::String(KEY.to_owned()))
        .is_some();
    Err(CheckFailure::fail(
        if misplaced {
            "gateway-fail-closed-misplaced"
        } else {
            "gateway-fail-closed-missing"
        },
        if misplaced {
            "fail_closed_budget_enforcement under litellm_settings is inert; move it under general_settings and restart litellm"
        } else {
            "fail_closed_budget_enforcement is not true under general_settings; unverifiable spend then fails open upstream"
        },
    ))
}

fn environ_value<'a>(blob: &'a [u8], key: &str) -> Option<&'a [u8]> {
    blob.split(|byte| *byte == 0).find_map(|entry| {
        let split = entry.iter().position(|byte| *byte == b'=')?;
        (&entry[..split] == key.as_bytes()).then(|| &entry[split + 1..])
    })
}

/// SSLRequest checks PostgreSQL availability without sending credentials or validating authentication.
fn database_answers(url: &str, deadline: Instant) -> Result<String, String> {
    use std::io::{Read, Write};
    const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];
    fn speaks_postgres(stream: &mut (impl Read + Write)) -> bool {
        let mut answer = [0_u8; 1];
        stream.write_all(&SSL_REQUEST).is_ok()
            && stream.read_exact(&mut answer).is_ok()
            && matches!(answer[0], b'S' | b'N')
    }
    let rest = url
        .strip_prefix("postgresql://")
        .or_else(|| url.strip_prefix("postgres://"))
        .ok_or_else(|| "the database URL is not a postgres URL".to_owned())?;
    let (authority, query) = match rest.split_once('?') {
        Some((head, query)) => (head.split('/').next().unwrap_or_default(), query),
        None => (rest.split('/').next().unwrap_or_default(), ""),
    };
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(']') || host.starts_with('[') => (
            host,
            port.parse::<u16>()
                .map_err(|_| "the database URL port is not a number".to_owned())?,
        ),
        _ => (host_port, 5432),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let socket_dir = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("host="))
        .filter(|dir| dir.starts_with('/'));
    let left = || {
        let left = deadline.saturating_duration_since(Instant::now());
        (!left.is_zero())
            .then_some(left.min(Duration::from_secs(3)))
            .ok_or_else(|| "the check deadline passed".to_owned())
    };
    let (endpoint, answered) = match (host, socket_dir) {
        (_, Some(dir)) => {
            let budget = left()?;
            let socket = Path::new(dir).join(format!(".s.PGSQL.{port}"));
            let mut stream = std::os::unix::net::UnixStream::connect(&socket)
                .map_err(|error| format!("{} refused a connection: {error}", socket.display()))?;
            let _ = stream.set_read_timeout(Some(budget));
            let _ = stream.set_write_timeout(Some(budget));
            (socket.display().to_string(), speaks_postgres(&mut stream))
        }
        ("", None) => return Err("the database URL names no host".to_owned()),
        (host, None) => {
            let budget = left()?;
            let address = match host.parse::<IpAddr>() {
                Ok(ip) => SocketAddr::new(ip, port),
                Err(_) => {
                    use std::net::ToSocketAddrs;
                    (host, port)
                        .to_socket_addrs()
                        .ok()
                        .and_then(|mut addresses| addresses.next())
                        .ok_or_else(|| format!("{host}:{port} does not resolve"))?
                }
            };
            let mut stream = TcpStream::connect_timeout(&address, budget)
                .map_err(|error| format!("{host}:{port} refused a connection: {error}"))?;
            let budget = left()?;
            let _ = stream.set_read_timeout(Some(budget));
            let _ = stream.set_write_timeout(Some(budget));
            (format!("{host}:{port}"), speaks_postgres(&mut stream))
        }
    };
    if !answered {
        return Err(format!(
            "{endpoint} accepted a connection but does not answer as postgres"
        ));
    }
    Ok(endpoint)
}
fn sys_09_relay(context: &SystemContext, deadline: Instant, relay: &GatewayRelayFacts) -> Outcome {
    let mut units = UnitStateReader::for_host(ManagerScope::UserThenSystem)?;
    let declared_config = env::var_os("SWEEP_LITELLM_CONFIG").filter(|value| !value.is_empty());
    sys_09_relay_at(
        context,
        &mut units,
        deadline,
        relay,
        declared_config.as_deref(),
    )
}

fn sys_09_relay_at(
    context: &SystemContext,
    units: &mut UnitStateReader,
    deadline: Instant,
    relay: &GatewayRelayFacts,
    declared_config: Option<&std::ffi::OsStr>,
) -> Outcome {
    let mut evidence = Vec::new();
    let listen = validate_relay(relay)?;
    if declared_config.is_some() {
        return Err(CheckFailure::fail(
            "gateway-relay-config-claimed",
            "a relay host declares no local LiteLLM config; SWEEP_LITELLM_CONFIG must be unset",
        ));
    }
    note_evidence(&mut evidence, "gateway-posture=relay");

    let socket = units.unit(&relay.socket_unit)?;
    if !unit_active(&socket) {
        return Err(CheckFailure::fail(
            "gateway-relay-listener-missing",
            format!(
                "declared relay socket {} is not loaded and listening",
                relay.socket_unit
            ),
        ));
    }
    // Listen includes each address and socket type, allowing extra listeners to be rejected.
    let listen_value = socket.get("Listen").filter(|value| !value.is_empty());
    let listen_ok = listen_value
        .map(|value| listen_matches(value, listen))
        .unwrap_or(true);
    if listen_value.is_none() || !listen_ok {
        return Err(CheckFailure::fail(
            "gateway-relay-bind-mismatch",
            format!(
                "declared relay socket {} does not listen on {}",
                relay.socket_unit, listen
            ),
        ));
    }
    note_evidence(
        &mut evidence,
        format!("gateway-socket={} listen={listen}", relay.socket_unit),
    );

    let service = units.unit(&relay.service_unit)?;
    if service.get("LoadState").map(String::as_str) != Some("loaded") {
        return Err(CheckFailure::fail(
            "gateway-relay-unit-missing",
            format!("declared relay unit {} is not loaded", relay.service_unit),
        ));
    }
    let exec_start = service.get("ExecStart").map(String::as_str).unwrap_or("");
    let target = socket_proxyd_target(exec_start).ok_or_else(|| {
        CheckFailure::fail(
            "gateway-relay-target-mismatch",
            format!(
                "declared relay unit {} is not systemd-socket-proxyd to {}",
                relay.service_unit, relay.upstream
            ),
        )
    })?;
    if target != relay.upstream {
        return Err(CheckFailure::fail(
            "gateway-relay-target-mismatch",
            format!(
                "declared relay unit {} forwards to {target}, not {}",
                relay.service_unit, relay.upstream
            ),
        ));
    }
    note_evidence(
        &mut evidence,
        format!(
            "gateway-service={} target={}",
            relay.service_unit, relay.upstream
        ),
    );

    let authority = authority_gateway_host_port(&context.odin_root)?;
    let declared = host_port(&relay.upstream).expect("validated upstream");
    if (&authority.0[..], authority.1) != declared {
        return Err(CheckFailure::fail(
            "gateway-relay-authority-mismatch",
            format!(
                "declared relay target {} is not the authority gateway {}:{}",
                relay.upstream, authority.0, authority.1
            ),
        ));
    }
    note_evidence(
        &mut evidence,
        format!("authority-gateway={}:{}", authority.0, authority.1),
    );

    if !gateway_answers_as_litellm(listen, deadline) {
        return Err(CheckFailure::fail(
            "gateway-relay-upstream-unavailable",
            format!(
                "LiteLLM does not answer its liveness route through the declared relay at {listen}"
            ),
        ));
    }
    note_evidence(&mut evidence, format!("gateway-live={listen}"));
    note_evidence(
        &mut evidence,
        format!(
            "odind: gateway_relay_verified listen={listen} upstream={} accounting=authority",
            relay.upstream
        ),
    );
    CheckOutcome::pass(
        format!(
            "declared relay {listen} forwards to authority {}; LiteLLM answers through the relay; local accounting database is N/A (enforced on the authority, not proven here)",
            relay.upstream
        ),
        evidence,
    )
}

fn validate_relay(relay: &GatewayRelayFacts) -> Result<std::net::SocketAddr, CheckFailure> {
    let invalid = |detail: &str| {
        CheckFailure::fail(
            "gateway-relay-invalid",
            format!("gateway relay declaration is invalid: {detail}"),
        )
    };
    if relay.posture != "relay" {
        return Err(invalid("posture must be relay"));
    }
    if !unit_name_ok(&relay.socket_unit, ".socket") {
        return Err(invalid("socketUnit is not a socket unit name"));
    }
    if !unit_name_ok(&relay.service_unit, ".service") {
        return Err(invalid("serviceUnit is not a service unit name"));
    }
    let listen = relay
        .listen
        .parse::<std::net::SocketAddr>()
        .map_err(|_| invalid("listen is not a host:port"))?;
    if !listen.ip().is_loopback() || listen.port() == 0 {
        return Err(invalid("listen must be a nonzero loopback port"));
    }
    if host_port(&relay.upstream).is_none() {
        return Err(invalid("upstream is not a host:port"));
    }
    Ok(listen)
}

fn unit_name_ok(name: &str, suffix: &str) -> bool {
    !name.is_empty()
        && name.ends_with(suffix)
        && !name.contains('/')
        && !name.contains(char::is_whitespace)
        && name.bytes().all(|byte| byte.is_ascii_graphic())
}

fn host_port(value: &str) -> Option<(&str, u16)> {
    if value.contains('/') || value.contains("://") {
        return None;
    }
    let (host, port) = value.rsplit_once(':')?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    let port = port.parse().ok().filter(|port| *port != 0)?;
    Some((host, port))
}

fn exec_token(raw: &str) -> &str {
    raw.trim_matches(|c: char| matches!(c, '"' | '\'' | ';' | '{' | '}' | ','))
}

fn socket_proxyd_target(exec_start: &str) -> Option<&str> {
    let mut tokens = exec_start
        .split_whitespace()
        .map(exec_token)
        .filter(|token| !token.is_empty());
    let binary = tokens.find_map(|token| token.strip_prefix("argv[]="))?;
    if Path::new(binary).file_name().and_then(|name| name.to_str()) != Some("systemd-socket-proxyd")
    {
        return None;
    }
    let mut target = None;
    for token in tokens {
        if token == "--config" || token.starts_with("--config=") {
            return None;
        }
        if token.starts_with('-') {
            continue;
        }
        if token.contains('=') {
            break;
        }
        if host_port(token).is_none() || target.is_some() {
            return None;
        }
        target = Some(token);
    }
    target
}

fn listen_matches(value: &str, bind: std::net::SocketAddr) -> bool {
    let mut found = false;
    for token in value.split_whitespace() {
        let token = token.trim_matches(|c: char| matches!(c, '"' | '\'' | ','));
        if token.is_empty() || token.starts_with('(') {
            continue;
        }
        let Ok(addr) = token.parse::<std::net::SocketAddr>() else {
            return false;
        };
        if addr.ip().is_unspecified() || addr != bind || found {
            return false;
        }
        found = true;
    }
    found
}

fn authority_gateway_host_port(odin_root: &Path) -> Result<(String, u16), CheckFailure> {
    let unverified =
        |detail: String| CheckFailure::fail("gateway-relay-authority-unverified", detail);
    let registry = odin_root.join("registry");
    let discovery = odin_registry::walk(&registry);
    let parsed = odin_registry::parse_objects(&discovery.objects);
    if let Some(finding) = discovery
        .findings
        .iter()
        .chain(parsed.findings.iter())
        .find(|finding| {
            finding.is_failure()
                && (finding.code.starts_with("registry-")
                    || finding
                        .path
                        .components()
                        .any(|component| component.as_os_str() == "nodes"))
        })
    {
        return Err(unverified(format!("{}: {}", finding.code, finding.message)));
    }
    let mut found = None;
    for object in &parsed.objects {
        let odin_registry::ObjectConfig::Node(node) = &object.config else {
            continue;
        };
        if !node.enabled || !node.authoritative_state {
            continue;
        }
        if found.is_some() {
            return Err(unverified(
                "more than one enabled authoritative node declares a gateway".to_owned(),
            ));
        }
        let endpoint = node.gateway_endpoint.as_deref().ok_or_else(|| {
            unverified(format!(
                "authoritative node {} declares no gateway_endpoint",
                object.id
            ))
        })?;
        let parsed =
            odin_registry::schema::NodeGatewayEndpoint::parse(endpoint).map_err(|error| {
                unverified(format!("authority gateway_endpoint is not usable: {error}"))
            })?;
        found = Some((parsed.host().to_owned(), parsed.port()));
    }
    found.ok_or_else(|| {
        unverified("no enabled authoritative node declares a gateway_endpoint".to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_process::test_support::RegisteredWorkerFixture;
    use odin_process::Value as DbusValue;

    /// Separate D-Bus fixture managers count queries to check lookup order and caching.
    struct ManagerFixture {
        user: RegisteredWorkerFixture,
        system: RegisteredWorkerFixture,
    }

    impl ManagerFixture {
        fn new() -> Self {
            Self {
                user: RegisteredWorkerFixture::new().expect("user manager fixture"),
                system: RegisteredWorkerFixture::new().expect("system manager fixture"),
            }
        }

        fn reader(&self) -> UnitStateReader {
            UnitStateReader::at(
                ManagerScope::UserThenSystem,
                self.user.bus().clone(),
                self.system.bus().clone(),
            )
        }
    }

    /// One `ExecStart` property holding a single command in the real
    /// `a(sasbttttuii)` shape the manager serves: path, argv,
    /// `ignore_errors`, then the start/exit timestamps, uid, exit code,
    /// and exit status (verified against the live systemd 261 wire).
    fn exec_start_value(argv: &[&str]) -> DbusValue {
        DbusValue::Array(
            "(sasbttttuii)".to_owned(),
            vec![DbusValue::Struct(vec![
                DbusValue::String(argv[0].to_owned()),
                DbusValue::Array(
                    "s".to_owned(),
                    argv.iter()
                        .map(|word| DbusValue::String((*word).to_owned()))
                        .collect(),
                ),
                DbusValue::Bool(false),
                // A started, still-running command: both start timestamps
                // set, exit timestamps, uid, exit code, and status zero.
                DbusValue::Uint64(1_790_000_000_000_000),
                DbusValue::Uint64(946_000_000_000),
                DbusValue::Uint64(0),
                DbusValue::Uint64(0),
                DbusValue::Uint32(1000),
                DbusValue::Int32(0),
                DbusValue::Int32(0),
            ])],
        )
    }

    /// One `Listen` property in the real `a(ss)` shape the manager
    /// serves: one (type, address) entry per line, here stream TCP binds
    /// as `("Stream", host:port)`.
    fn listen_value(addresses: &[&str]) -> DbusValue {
        DbusValue::Array(
            "(ss)".to_owned(),
            addresses
                .iter()
                .map(|address| {
                    DbusValue::Struct(vec![
                        DbusValue::String("Stream".to_owned()),
                        DbusValue::String((*address).to_owned()),
                    ])
                })
                .collect(),
        )
    }

    fn litellm_exec_start() -> (&'static str, DbusValue) {
        (
            "ExecStart",
            exec_start_value(&[
                "/nix/store/abc/bin/litellm",
                "serve",
                "--config",
                "/nix/store/def/litellm.yaml",
            ]),
        )
    }

    #[test]
    fn an_active_user_unit_yields_its_config_without_consulting_the_system_manager() {
        let managers = ManagerFixture::new();
        let (property, value) = litellm_exec_start();
        managers.user.plant_unit(
            "litellm.service",
            "loaded",
            "active",
            "running",
            &[(property, value)],
        );
        managers.system.plant_unit(
            "litellm.service",
            "loaded",
            "active",
            "running",
            &[(
                "ExecStart",
                exec_start_value(&[
                    "/usr/bin/litellm",
                    "--config",
                    "/nix/store/wrong/litellm.yaml",
                ]),
            )],
        );
        let mut units = managers.reader();
        let (config, _) =
            litellm_config_from_unit(&mut units).expect("the active user unit names its config");
        assert_eq!(config, PathBuf::from("/nix/store/def/litellm.yaml"));
        assert_eq!(
            managers.system.queries(),
            0,
            "a loaded user unit resolves without any system-manager query"
        );
    }

    #[test]
    fn a_system_only_unit_is_resolved_through_the_user_then_system_lookup() {
        let managers = ManagerFixture::new();
        managers.system.plant_unit(
            "litellm.service",
            "loaded",
            "active",
            "running",
            &[(
                "ExecStart",
                exec_start_value(&[
                    "/usr/bin/litellm",
                    "--config",
                    "/nix/store/ghi/litellm.yaml",
                ]),
            )],
        );
        let mut units = managers.reader();
        let (config, _) = litellm_config_from_unit(&mut units)
            .expect("the system unit is found through the second manager");
        assert_eq!(config, PathBuf::from("/nix/store/ghi/litellm.yaml"));
        assert!(
            managers.system.queries() > 0,
            "the system manager answered the second lookup"
        );
    }

    #[test]
    fn a_unit_loaded_nowhere_blocks_as_unconfigured_after_both_managers() {
        let managers = ManagerFixture::new();
        let mut units = managers.reader();
        let failure =
            litellm_config_from_unit(&mut units).expect_err("no manager can name a config");
        assert_eq!(failure.status, CheckStatus::Blocked);
        assert_eq!(failure.reason, "litellm-config-unconfigured");
        assert!(
            managers.user.queries() > 0 && managers.system.queries() > 0,
            "both managers were consulted before the honest not-found answer won"
        );
    }

    /// The litellm unit is read once per sweep: the ExecStart (config) and
    /// MainPID (environ) lookups share one cached unit-state read.
    #[test]
    fn the_config_and_environ_lookups_share_one_unit_read() {
        let managers = ManagerFixture::new();
        let (property, value) = litellm_exec_start();
        let probe = ProbeChild::spawn("ODIN_SWEEP_UNIT_STATE_PROBE");
        managers.user.plant_unit(
            "litellm.service",
            "loaded",
            "active",
            "running",
            &[
                (property, value),
                ("MainPID", DbusValue::Uint32(probe.pid())),
            ],
        );
        let mut units = managers.reader();
        let (config, _) = litellm_config_from_unit(&mut units).expect("config resolves");
        assert_eq!(config, PathBuf::from("/nix/store/def/litellm.yaml"));
        let after_first = managers.user.queries();
        assert!(after_first > 0, "the first read goes to the bus");
        let _ = litellm_config_from_unit(&mut units).expect("the cached read resolves");
        let value = service_environ(&mut units, "ODIN_SWEEP_UNIT_STATE_PROBE")
            .expect("the live environ answers from the same cached read");
        assert_eq!(value, b"1".to_vec());
        assert_eq!(
            managers.user.queries(),
            after_first,
            "one unit-state read per sweep: config and environ share it"
        );
    }

    /// The accounting provenance is a real process: the planted MainPID
    /// points at a child the test controls, and `/proc/<pid>/environ`
    /// serves back exactly the variable exec set.
    #[test]
    fn the_running_service_environ_proves_the_accounting_variable() {
        let managers = ManagerFixture::new();
        let probe = ProbeChild::spawn("ODIN_SWEEP_UNIT_STATE_PROBE");
        managers.user.plant_unit(
            "litellm.service",
            "loaded",
            "active",
            "running",
            &[("MainPID", DbusValue::Uint32(probe.pid()))],
        );
        let mut units = managers.reader();
        let value = service_environ(&mut units, "ODIN_SWEEP_UNIT_STATE_PROBE")
            .expect("the running service carries the variable");
        assert_eq!(value, b"1".to_vec());
    }

    /// A unit that is not running has no MainPID: the accounting is
    /// unverifiable, never silently absent.
    #[test]
    fn a_unit_without_a_running_mainpid_proves_nothing() {
        let managers = ManagerFixture::new();
        managers
            .user
            .plant_unit("litellm.service", "loaded", "inactive", "dead", &[]);
        let mut units = managers.reader();
        let failure = service_environ(&mut units, "DATABASE_URL")
            .expect_err("no running process, no proven environ");
        assert_eq!(failure.reason, "gateway-budget-accounting-unverifiable");
    }

    /// The renderer accepts only the element signature real systemd
    /// serves: the invented `a(sasb)` shape (pre-2015 systemd) yields no
    /// ExecStart at all, so the config lookup fails typed instead of
    /// parsing a shape no current manager sends.
    #[test]
    fn an_execstart_in_the_stale_invented_shape_is_refused() {
        let managers = ManagerFixture::new();
        managers.user.plant_unit(
            "litellm.service",
            "loaded",
            "active",
            "running",
            &[(
                "ExecStart",
                DbusValue::Array(
                    "(sasb)".to_owned(),
                    vec![DbusValue::Struct(vec![
                        DbusValue::String("/usr/bin/litellm".to_owned()),
                        DbusValue::Array(
                            "s".to_owned(),
                            vec![
                                DbusValue::String("/usr/bin/litellm".to_owned()),
                                DbusValue::String("--config".to_owned()),
                                DbusValue::String("/nix/store/def/litellm.yaml".to_owned()),
                            ],
                        ),
                        DbusValue::Bool(false),
                    ])],
                ),
            )],
        );
        let mut units = managers.reader();
        let failure = litellm_config_from_unit(&mut units)
            .expect_err("a shape no current manager serves is not a readable ExecStart");
        assert_eq!(failure.status, CheckStatus::Fail);
        assert_eq!(failure.reason, "litellm-execstart-missing");
    }

    /// One real child carrying the probe variable in its exec environ —
    /// exactly what `/proc/<pid>/environ` serves back — killed on drop.
    struct ProbeChild(std::process::Child);

    impl ProbeChild {
        fn spawn(variable: &'static str) -> Self {
            let child = std::process::Command::new("sleep")
                .arg("30")
                .env(variable, "1")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("probe child spawns");
            Self(child)
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for ProbeChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn numeric_declared_cap_and_string_decimals_pass_the_strict_gate() {
        assert!(declared_budget_cap_ok(&JsonValue::Number(30u64.into())));
        assert!(declared_budget_cap_ok(&JsonValue::String("30".to_owned())));
        assert!(declared_budget_cap_ok(&JsonValue::String(
            "12.5".to_owned()
        )));
    }

    #[test]
    fn malformed_negative_and_nonscalar_caps_fail_the_strict_gate() {
        assert!(!declared_budget_cap_ok(&JsonValue::String(
            "030".to_owned()
        )));
        assert!(!declared_budget_cap_ok(&JsonValue::String(
            "1e10".to_owned()
        )));
        assert!(!declared_budget_cap_ok(&JsonValue::Number((-5i64).into())));
        assert!(!declared_budget_cap_ok(&JsonValue::Null));
        assert!(!declared_budget_cap_ok(&json!(["30"])));
    }

    /// Budget caps may be absent on both sides; one-sided or differing caps fail.
    #[test]
    fn no_cap_on_both_sides_is_valid_and_a_one_sided_cap_is_not() {
        let none: serde_yaml::Value = serde_yaml::from_str("drop_params: true").unwrap();
        let capped: serde_yaml::Value =
            serde_yaml::from_str("max_budget: 30\nbudget_duration: 30d").unwrap();
        let lane_none = json!({ "capUsd": null, "duration": null });
        let lane_capped = json!({ "capUsd": 30, "duration": "30d" });
        let lane_other = json!({ "capUsd": 40, "duration": "30d" });
        assert_eq!(
            budget_cap_projection(none.as_mapping().unwrap(), &lane_none).unwrap(),
            None
        );
        assert_eq!(
            budget_cap_projection(none.as_mapping().unwrap(), &JsonValue::Null).unwrap(),
            None
        );
        assert_eq!(
            budget_cap_projection(capped.as_mapping().unwrap(), &lane_capped).unwrap(),
            Some("30".to_owned())
        );
        for (lite, lane) in [
            (&none, &lane_capped),
            (&capped, &lane_none),
            (&capped, &lane_other),
        ] {
            let failure = budget_cap_projection(lite.as_mapping().unwrap(), lane)
                .expect_err("a one-sided or differing cap is inconsistent");
            assert_eq!(failure.reason, "gateway-budget-inconsistent");
        }
    }

    #[test]
    fn fail_closed_only_counts_under_general_settings() {
        let general_ok: serde_yaml::Value =
            serde_yaml::from_str("fail_closed_budget_enforcement: true").unwrap();
        let general_false: serde_yaml::Value =
            serde_yaml::from_str("fail_closed_budget_enforcement: false").unwrap();
        let general_empty: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let litellm_flag: serde_yaml::Value =
            serde_yaml::from_str("fail_closed_budget_enforcement: true").unwrap();
        let litellm_empty: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();

        assert!(
            fail_closed_enforced(general_ok.as_mapping(), litellm_empty.as_mapping().unwrap())
                .is_ok()
        );
        let misplaced = fail_closed_enforced(
            general_empty.as_mapping(),
            litellm_flag.as_mapping().unwrap(),
        )
        .expect_err("a litellm_settings-only flag is inert");
        assert_eq!(misplaced.reason, "gateway-fail-closed-misplaced");
        let missing = fail_closed_enforced(
            general_false.as_mapping(),
            litellm_empty.as_mapping().unwrap(),
        )
        .expect_err("a false or absent general_settings flag fails closed");
        assert_eq!(missing.reason, "gateway-fail-closed-missing");
    }

    #[test]
    fn environ_values_are_read_by_exact_name() {
        let blob = b"PATH=/bin\0DATABASE_URL=x\0EMPTY=\0NOEQUALS\0DATABASE_URL_OLD=y\0";
        assert_eq!(environ_value(blob, "DATABASE_URL"), Some(&b"x"[..]));
        assert_eq!(environ_value(blob, "EMPTY"), Some(&b""[..]));
        assert_eq!(environ_value(blob, "ABSENT"), None);
        assert_eq!(environ_value(blob, "NOEQUALS"), None);
        assert_eq!(environ_value(b"", "DATABASE_URL"), None);
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    #[test]
    fn a_configured_database_must_answer_as_postgres() {
        use std::io::{Read, Write};
        let serve = |answer: &'static [u8]| {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut request = [0_u8; 8];
                    let _ = stream.read_exact(&mut request);
                    let _ = stream.write_all(answer);
                }
            });
            port
        };
        let url = |port: u16| format!("postgresql://litellm:secret@127.0.0.1:{port}/litellm");
        let port = serve(b"N");
        assert_eq!(
            database_answers(&url(port), soon()),
            Ok(format!("127.0.0.1:{port}"))
        );
        let foreign = database_answers(&url(serve(b"HTTP/1.1 400\r\n")), soon())
            .expect_err("a listener that is not postgres is not accounting");
        assert!(!foreign.contains("secret"), "{foreign}");
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(database_answers(&url(closed), soon()).is_err());
        assert!(database_answers("mysql://x@127.0.0.1/db", soon()).is_err());
        assert!(
            database_answers(&url(serve(b"N")), Instant::now()).is_err(),
            "a spent deadline never connects"
        );
    }

    #[test]
    fn the_declared_bind_is_parsed_from_exec_start() {
        let exec = "{ path=/nix/store/x/bin/litellm ; argv[]=/nix/store/x/bin/litellm --config /nix/store/c.yaml --host 127.0.0.1 --port 4000 ; ignore_errors=no }";
        assert_eq!(
            listen_from_exec_start(exec),
            Some("127.0.0.1:4000".parse().unwrap())
        );
        assert_eq!(listen_from_exec_start("litellm --config c.yaml"), None);
    }

    #[test]
    fn only_litellm_liveness_counts_as_a_serving_gateway() {
        use std::io::{Read, Write};
        let serve = |response: &'static str| {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut request = [0_u8; 512];
                    let _ = stream.read(&mut request);
                    let _ = stream.write_all(response.as_bytes());
                }
            });
            addr
        };
        let litellm = serve("HTTP/1.1 200 OK\r\ncontent-length: 12\r\n\r\n\"I'm alive!\"");
        assert!(gateway_answers_as_litellm(litellm, soon()));
        let other = serve("HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n");
        assert!(!gateway_answers_as_litellm(other, soon()));
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(!gateway_answers_as_litellm(closed, soon()));
    }

    fn relay(listen: &str, upstream: &str) -> GatewayRelayFacts {
        GatewayRelayFacts {
            posture: "relay".to_owned(),
            socket_unit: "litellm-gateway.socket".to_owned(),
            service_unit: "litellm-gateway.service".to_owned(),
            listen: listen.to_owned(),
            upstream: upstream.to_owned(),
        }
    }

    fn node_toml(authoritative: bool, endpoint: &str) -> String {
        format!(
            "schema = \"odin.registry.v1\"\nkind = \"node\"\nenabled = true\ndescription = \"fixture\"\nhost = \"mini\"\nrole = \"control\"\ncapabilities = [\"control\"]\nallow_workloads = true\nauthoritative_state = {authoritative}\ngateway_endpoint = \"{endpoint}\"\n"
        )
    }

    fn authority_registry(root: &Path) {
        let registry = root.join("registry");
        for kind in odin_registry::RegistryKind::ALL {
            fs::create_dir_all(registry.join(kind.directory())).expect("registry kind dir");
        }
        let nodes = registry.join("nodes");
        fs::create_dir_all(nodes.join("mini")).expect("authority node dir");
        fs::create_dir_all(nodes.join("laptop")).expect("follower node dir");
        fs::write(
            nodes.join("mini/node.toml"),
            node_toml(true, "http://100.64.0.11:14000/v1"),
        )
        .expect("authority node");
        fs::write(
            nodes.join("laptop/node.toml"),
            node_toml(false, "http://100.64.0.12:14000/v1"),
        )
        .expect("follower node");
    }

    /// Two fixture managers plus a disposable authority registry: the relay
    /// leg resolves its units over the real D-Bus framing, so every refusal,
    /// mismatch, and pass below is behavioral.
    struct RelayManagers {
        user: RegisteredWorkerFixture,
        system: RegisteredWorkerFixture,
        odin_root: tempfile::TempDir,
    }

    impl RelayManagers {
        fn with_socket(
            socket_state: Option<&[(&str, DbusValue)]>,
            service_properties: &[(&str, DbusValue)],
        ) -> Self {
            let user = RegisteredWorkerFixture::new().expect("user manager fixture");
            let system = RegisteredWorkerFixture::new().expect("system manager fixture");
            if let Some(socket_properties) = socket_state {
                user.plant_unit(
                    "litellm-gateway.socket",
                    "loaded",
                    "active",
                    "running",
                    socket_properties,
                );
            }
            user.plant_unit(
                "litellm-gateway.service",
                "loaded",
                "active",
                "running",
                service_properties,
            );
            let odin_root = tempfile::tempdir().expect("authority registry root");
            authority_registry(odin_root.path());
            Self {
                user,
                system,
                odin_root,
            }
        }

        fn new(
            socket_properties: &[(&str, DbusValue)],
            service_properties: &[(&str, DbusValue)],
        ) -> Self {
            Self::with_socket(Some(socket_properties), service_properties)
        }

        fn context(&self) -> SystemContext {
            SystemContext {
                odin_root: self.odin_root.path().to_path_buf(),
                dotfiles_root: self.odin_root.path().to_path_buf(),
                runtime_manifest: None,
                scratch_root: self.odin_root.path().join("scratch"),
            }
        }

        fn check(&self, relay: &GatewayRelayFacts) -> Result<CheckOutcome, CheckFailure> {
            let mut units = UnitStateReader::at(
                ManagerScope::UserThenSystem,
                self.user.bus().clone(),
                self.system.bus().clone(),
            );
            sys_09_relay_at(
                &self.context(),
                &mut units,
                Instant::now() + Duration::from_secs(20),
                relay,
                None,
            )
        }
    }

    fn proxyd(target: &str) -> DbusValue {
        exec_start_value(&[
            "/nix/store/x/lib/systemd/systemd-socket-proxyd",
            "--exit-idle-time=5min",
            target,
        ])
    }

    #[test]
    fn a_relay_with_the_wrong_target_fails_closed() {
        let fake = RelayManagers::new(
            &[("Listen", listen_value(&["127.0.0.1:4000"]))],
            &[("ExecStart", proxyd("10.1.2.3:9"))],
        );
        let failure = fake
            .check(&relay("127.0.0.1:4000", "100.64.0.11:14000"))
            .expect_err("a mismatched proxyd target is not the declared relay");
        assert_eq!(failure.status, CheckStatus::Fail);
        assert_eq!(failure.reason, "gateway-relay-target-mismatch");
        assert!(!failure.summary.contains("postgres"), "{}", failure.summary);
    }

    #[test]
    fn a_relay_with_no_listener_fails_closed() {
        // The socket unit exists but is not even loaded and listening: the
        // declared relay listener is missing, however the service unit looks.
        let fake =
            RelayManagers::with_socket(None, &[("ExecStart", proxyd("100.64.0.11:14000"))]);
        let failure = fake
            .check(&relay("127.0.0.1:4000", "100.64.0.11:14000"))
            .expect_err("a missing socket is not a serving relay");
        assert_eq!(failure.status, CheckStatus::Fail);
        assert_eq!(failure.reason, "gateway-relay-listener-missing");
    }

    #[test]
    fn a_relay_bound_to_the_wrong_address_fails_closed() {
        let fake = RelayManagers::new(
            &[("Listen", listen_value(&["127.0.0.1:9"]))],
            &[("ExecStart", proxyd("100.64.0.11:14000"))],
        );
        let failure = fake
            .check(&relay("127.0.0.1:4000", "100.64.0.11:14000"))
            .expect_err("a socket on the wrong port is not the declared bind");
        assert_eq!(failure.reason, "gateway-relay-bind-mismatch");
    }

    #[test]
    fn a_relay_target_that_is_not_the_authority_fails_closed() {
        let fake = RelayManagers::new(
            &[("Listen", listen_value(&["127.0.0.1:4000"]))],
            &[("ExecStart", proxyd("10.9.8.7:14000"))],
        );
        let failure = fake
            .check(&relay("127.0.0.1:4000", "10.9.8.7:14000"))
            .expect_err("a target other than the authority gateway is not the contract");
        assert_eq!(failure.reason, "gateway-relay-authority-mismatch");
        assert!(
            failure.summary.contains("100.64.0.11:14000"),
            "{}",
            failure.summary
        );
    }

    #[test]
    fn a_valid_relay_passes_without_a_local_postgres() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0_u8; 512];
                let _ = stream.read(&mut request);
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 12\r\n\r\n\"I'm alive!\"");
            }
        });
        let listen = addr.to_string();
        let upstream = "100.64.0.11:14000";
        let fake = RelayManagers::new(
            &[("Listen", listen_value(&[listen.as_str()]))],
            &[("ExecStart", proxyd(upstream))],
        );
        let outcome = fake
            .check(&relay(&listen, upstream))
            .expect("a matching relay with live LiteLLM passes without postgres");
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(
            outcome.summary.contains("not proven here"),
            "{}",
            outcome.summary
        );
        assert!(
            !outcome.summary.contains("postgres") && !outcome.summary.contains("verified"),
            "{}",
            outcome.summary
        );
        assert!(outcome.evidence.iter().any(|note| {
            note.starts_with("odind: gateway_relay_verified ")
                && note.contains("accounting=authority")
                && note.contains("upstream=100.64.0.11:14000")
        }));
        assert!(outcome
            .evidence
            .iter()
            .any(|note| note == "authority-gateway=100.64.0.11:14000"));
        assert!(outcome
            .evidence
            .iter()
            .all(|note| !note.contains("answers as postgres")));
    }

    #[test]
    fn an_invalid_relay_declaration_does_not_fall_through_to_local_litellm() {
        let fake = RelayManagers::with_socket(None, &[]);
        let mut declared = relay("127.0.0.1:4000", "100.64.0.11:14000");
        declared.posture = "local".to_owned();
        let failure = fake
            .check(&declared)
            .expect_err("a non-relay posture is not the local unit path");
        assert_eq!(failure.reason, "gateway-relay-invalid");
        assert_eq!(
            fake.user.queries() + fake.system.queries(),
            0,
            "an invalid declaration is refused before any unit query"
        );
    }

    #[test]
    fn a_path_token_cannot_impersonate_the_proxyd_argv() {
        let impersonated =
            "{ path=/systemd-socket-proxyd ; argv[]=/bin/other 100.64.0.11:14000 ; ignore_errors=no }";
        assert_eq!(socket_proxyd_target(impersonated), None);
        let real = "{ path=/bin/other ; argv[]=/nix/store/x/lib/systemd/systemd-socket-proxyd --exit-idle-time=5min 100.64.0.11:14000 ; ignore_errors=no }";
        assert_eq!(socket_proxyd_target(real), Some("100.64.0.11:14000"));
        let fake = RelayManagers::new(
            &[("Listen", listen_value(&["127.0.0.1:4000"]))],
            &[(
                "ExecStart",
                exec_start_value(&["/bin/other", "100.64.0.11:14000"]),
            )],
        );
        let failure = fake
            .check(&relay("127.0.0.1:4000", "100.64.0.11:14000"))
            .expect_err("path= is not the argv binary");
        assert_eq!(failure.reason, "gateway-relay-target-mismatch");
    }

    #[test]
    fn an_extra_or_wildcard_listener_is_not_the_declared_bind() {
        let bind = "127.0.0.1:4000".parse().unwrap();
        assert!(listen_matches("127.0.0.1:4000 (Stream)", bind));
        assert!(!listen_matches(
            "127.0.0.1:4000 (Stream) 0.0.0.0:4000 (Stream)",
            bind
        ));
        assert!(!listen_matches(
            "127.0.0.1:4000 (Stream) 127.0.0.1:4001 (Stream)",
            bind
        ));
        assert!(!listen_matches("0.0.0.0:4000 (Stream)", bind));
        assert!(!listen_matches(
            "/run/litellm/relay.sock (FIFO) 127.0.0.1:4000 (Stream)",
            bind
        ));
        assert!(!listen_matches("[::]:4000 (Stream)", bind));
        let fake = RelayManagers::new(
            &[("Listen", listen_value(&["127.0.0.1:4000", "0.0.0.0:4000"]))],
            &[("ExecStart", proxyd("100.64.0.11:14000"))],
        );
        let failure = fake
            .check(&relay("127.0.0.1:4000", "100.64.0.11:14000"))
            .expect_err("an extra wildcard listener is not the declared bind");
        assert_eq!(failure.reason, "gateway-relay-bind-mismatch");
    }

    /// Reject malformed Listen values rather than guessing the relay address.
    #[test]
    fn a_listen_in_the_stale_invented_shape_fails_the_bind_proof() {
        let fake = RelayManagers::new(
            &[(
                "Listen",
                DbusValue::Array(
                    "(sas)".to_owned(),
                    vec![DbusValue::Struct(vec![
                        DbusValue::String("Stream".to_owned()),
                        DbusValue::Array(
                            "s".to_owned(),
                            vec![DbusValue::String("127.0.0.1:4000".to_owned())],
                        ),
                    ])],
                ),
            )],
            &[("ExecStart", proxyd("100.64.0.11:14000"))],
        );
        let failure = fake
            .check(&relay("127.0.0.1:4000", "100.64.0.11:14000"))
            .expect_err("a shape no current manager serves is not a readable Listen");
        assert_eq!(failure.reason, "gateway-relay-bind-mismatch");
    }

    #[test]
    fn a_non_loopback_relay_listen_is_invalid() {
        let fake = RelayManagers::with_socket(None, &[]);
        for listen in [
            "0.0.0.0:4000",
            "100.64.0.11:4000",
            "127.0.0.1:0",
            "[::]:4000",
        ] {
            let failure = fake
                .check(&relay(listen, "100.64.0.11:14000"))
                .expect_err("a non-loopback or zero listen is not a relay bind");
            assert_eq!(failure.reason, "gateway-relay-invalid", "{listen}");
        }
        assert_eq!(
            fake.user.queries() + fake.system.queries(),
            0,
            "an invalid bind is refused before any unit query"
        );
    }
}
