use super::*;

/// Refuses only nonsense: a negative or non-finite price, a key that is not a secret name, an
/// ssh-target account without its target, a cap order that can never hold.
pub(super) fn validate_compute_provider(
    object: &RegistryObject,
    value: &super::super::compute_provider::ComputeProviderToml,
    findings: &mut Vec<RegistryFinding>,
) {
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    let mut refuse = |code: &str, reason: &str| findings.push(fail(object, code, reason));
    let price = |usd: f64| usd.is_finite() && usd >= 0.0;
    if value.key.is_empty()
        || !value
            .key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        refuse(
            "compute-provider-key",
            "key names the secret holding the API key (letters, digits, _ and -), never its value",
        );
    }
    if let Some(ssh) = &value.runpod_ssh {
        let valid_key = |key: &str| {
            let mut parts = key.split_whitespace();
            parts
                .next()
                .is_some_and(|kind| kind.starts_with("ssh-") || kind.starts_with("ecdsa-"))
                && parts.next().is_some()
                && parts.next().is_none()
        };
        if ssh.account_id.is_empty()
            || !ssh.account_id.bytes().all(|b| b.is_ascii_alphanumeric())
            || !valid_key(&ssh.known_host)
            || !valid_key(&ssh.public_key)
        {
            refuse("compute-provider-runpod-ssh", "Runpod SSH needs an account ID and owner-verified proxy host and client public keys");
        }
    }
    if !price(value.max_hourly_usd) {
        refuse(
            "compute-provider-cost",
            "max_hourly_usd must be finite and not negative",
        );
    }
    if value.account_max_usd.is_some() != value.account_window_days.is_some()
        || value.account_max_usd.is_some_and(|usd| !price(usd))
    {
        refuse(
            "compute-provider-account-budget",
            "account_max_usd and account_window_days must be declared together, with a finite non-negative cap",
        );
    }
    if value.offers.values().any(|offer| {
        !price(offer.usd_per_hour) || offer.machine.is_empty() || offer.image.is_empty()
    }) {
        refuse(
            "compute-provider-offer",
            "every offer names its machine and image and a finite, non-negative usd_per_hour",
        );
    }
    if value.offers.is_empty() {
        refuse(
            "compute-provider-offer",
            "an account declares at least one offer",
        );
    }
    match &value.target {
        None => refuse(
            "compute-provider-target",
            "join = \"ssh-target\" needs [target]",
        ),
        Some(target) if !target.remote_root.starts_with('/') => refuse(
            "compute-provider-target",
            "target.remote_root must be absolute",
        ),
        _ => {}
    }
}

pub(super) fn validate_compute_target(
    object: &RegistryObject,
    value: &super::super::compute_target::ComputeTargetToml,
    findings: &mut Vec<RegistryFinding>,
) {
    use super::super::compute_target::{ComputeExecutor, OffloadRuntime};
    validate_common(
        object,
        &value.schema,
        value.kind,
        &value.description,
        findings,
    );
    let mut refuse = |code: &str, reason: &str| findings.push(fail(object, code, reason));
    let plain = |text: &str| {
        !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
    };
    if !plain(&value.ssh_host) {
        refuse(
            "compute-target-ssh-host",
            "ssh_host must be one host name, alias or address",
        );
    }
    let mut key = value.known_host.split_whitespace();
    if !(key
        .next()
        .is_some_and(|kind| kind.starts_with("ssh-") || kind.starts_with("ecdsa-"))
        && key.next().is_some()
        && key.next().is_none())
    {
        refuse(
            "compute-target-known-host",
            "known_host must be the target's host key as `<type> <base64>`",
        );
    }
    let absolute = |path: &str| {
        path.starts_with('/')
            && !path.split('/').any(|part| part == "..")
            && !path
                .chars()
                .any(|c| c.is_whitespace() || "'\"$`\\".contains(c))
    };
    if !absolute(&value.remote_root) {
        refuse(
            "compute-target-remote-root",
            "remote_root must be an absolute path without .., spaces or shell quoting",
        );
    }
    if value
        .identity_file
        .as_deref()
        .is_some_and(|path| !absolute(path))
    {
        refuse(
            "compute-target-identity-file",
            "identity_file must be an absolute path",
        );
    }
    if value
        .control_master
        .as_deref()
        .is_some_and(|path| !absolute(path))
    {
        refuse(
            "compute-target-control-master",
            "control_master must be an absolute socket path",
        );
    }
    if value.runtime != OffloadRuntime::Host
        && value
            .image
            .as_deref()
            .is_some_and(|image| !plain_image(image))
    {
        refuse(
            "compute-target-image",
            "image must be a SIF path or an OCI reference",
        );
    }
    if value.executor == ComputeExecutor::Ssh
        && (value.partition.is_some() || value.account.is_some())
    {
        refuse(
            "compute-target-slurm-fields",
            "partition and account belong to a slurm target",
        );
    }
    for name in value.partition.iter().chain(value.account.iter()) {
        if !plain(name) {
            refuse(
                "compute-target-slurm-fields",
                "partition and account must be plain names",
            );
        }
    }
    if value.cost.as_ref().is_some_and(|cost| {
        [cost.usd_per_core_hour, cost.usd_per_hour]
            .into_iter()
            .flatten()
            .any(|price| !price.is_finite() || price < 0.0)
    }) {
        refuse(
            "compute-target-cost",
            "cost prices must be finite and not negative",
        );
    }
}

fn plain_image(image: &str) -> bool {
    !image.is_empty()
        && image
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-:@".contains(c))
}
