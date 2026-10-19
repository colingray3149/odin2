use super::*;

pub(in crate::syscheck) const HOST_FACTS_SCHEMA: &str = "odin.sweep-host-facts.v1";

/// The declared boot layout of this host. Only the ESP layouts
/// (systemd-boot, lanzaboote) carry a /boot NixOS-generation advisory; a
/// grub-bios or other layout keeps kernels in the store and has no
/// generation files in /boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(in crate::syscheck) enum Bootloader {
    Lanzaboote,
    SystemdBoot,
    GrubBios,
    Other,
}

impl Bootloader {
    pub(in crate::syscheck) const fn as_str(self) -> &'static str {
        match self {
            Self::Lanzaboote => "lanzaboote",
            Self::SystemdBoot => "systemd-boot",
            Self::GrubBios => "grub-bios",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::syscheck) struct ZellijWebFacts {
    pub(in crate::syscheck) enabled: bool,
    pub(in crate::syscheck) ip: String,
    pub(in crate::syscheck) port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::syscheck) struct GatewayRelayFacts {
    pub(in crate::syscheck) posture: String,
    pub(in crate::syscheck) socket_unit: String,
    pub(in crate::syscheck) service_unit: String,
    pub(in crate::syscheck) listen: String,
    pub(in crate::syscheck) upstream: String,
}

/// Deny-unknown typed view of the declared host-facts file
/// (`odin.sweep-host-facts.v1`, rendered by the dotfiles home-manager
/// activation at `$XDG` `~/.config/odin/host-facts.json`). The activation
/// renders the file as a symlink into the immutable `/nix/store`; the
/// loader accepts exactly that shape.
///
/// Declared facts select WHAT each check verifies — which boot layout the
/// /boot advisory reads, which machine (`host`) the candidate toplevel
/// evaluates for and which revision it evaluates from, which
/// rendered-secrets roots are walked, which zellij endpoint the listener
/// verdict compares against, which replica holds the nightly backup, and
/// which dotfiles checkout the source checks read. They never relax a verdict.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::syscheck) struct HostFacts {
    pub(in crate::syscheck) schema: String,
    pub(in crate::syscheck) host: String,
    pub(in crate::syscheck) candidate_revision: String,
    pub(in crate::syscheck) bootloader: Bootloader,
    pub(in crate::syscheck) zellij_web: ZellijWebFacts,
    pub(in crate::syscheck) sops_rendered_dirs: Vec<PathBuf>,
    /// Dotfiles checkout declared by the deployed host generation; absent falls back to ~/dotfiles.
    pub(in crate::syscheck) dotfiles_root: Option<PathBuf>,
    /// Whether this host is the declared Odin authority (dotfiles
    /// `odin.node.isAuthority`). `false` scopes `sweep --system` to the
    /// follower subset; absent keeps every check (an authority whose facts
    /// predate the field must never silently skip its checks).
    #[serde(default)]
    pub(in crate::syscheck) odin_authority: Option<bool>,
    /// Replica that holds the nightly backup. Absent on facts that predate
    /// the field; SYS-11 then fails closed rather than passing.
    #[serde(default)]
    pub(in crate::syscheck) backup_replica_host: Option<String>,
    /// Directory on the replica whose `completed` stamp SYS-11 ages.
    #[serde(default)]
    pub(in crate::syscheck) backup_path: Option<PathBuf>,
    #[serde(
        default,
        deserialize_with = "deserialize_gateway",
        skip_serializing_if = "Option::is_none"
    )]
    pub(in crate::syscheck) gateway: Option<GatewayRelayFacts>,
}

fn deserialize_gateway<'de, D>(deserializer: D) -> Result<Option<GatewayRelayFacts>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <GatewayRelayFacts as serde::Deserialize>::deserialize(deserializer).map(Some)
}

/// The symlink acceptance policy for the facts path: exactly the
/// Home-Manager shape — a symlink whose canonicalized target is a regular
/// file under the immutable `/nix/store`. A symlink whose target is
/// mutable (the home, a tmp checkout) is refused even when it points at a
/// regular file, and so is a symlink to a store directory: only an
/// immutable regular file is the declared facts.
fn accepts_hm_symlink(canonical_target: &Path, target_is_regular_file: bool) -> bool {
    target_is_regular_file && canonical_target.starts_with("/nix/store")
}

/// Reads the facts entry at `path`. A direct entry keeps the strict
/// [`read_bounded`] policy unchanged (regular file, never a symlink). A
/// symlinked entry is read through its canonical target only when it has
/// exactly the Home-Manager shape ([`accepts_hm_symlink`]); every other
/// symlink is a typed refusal, never a silent follow.
fn read_facts_entry(path: &Path) -> io::Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.is_symlink() {
        return read_bounded(path);
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("symlink target is unresolvable: {error}"),
        )
    })?;
    let target_is_regular_file = fs::metadata(&canonical)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false);
    if !accepts_hm_symlink(&canonical, target_is_regular_file) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "symlink target {} is not an immutable /nix/store regular file",
                canonical.display()
            ),
        ));
    }
    read_bounded(&canonical)
}

/// The host-facts path policy: `SWEEP_HOST_FACTS` when set, else the XDG
/// default. `None` means no facts source is resolvable at all.
pub(in crate::syscheck) fn host_facts_path() -> Option<PathBuf> {
    if let Some(path) = env::var_os("SWEEP_HOST_FACTS").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(path));
    }
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(".config/odin/host-facts.json"))
}

/// Loads the declared host facts. Typed absence (`Ok(None)`): a missing
/// facts file leaves every check on its current default behavior — never a
/// crash, never a fabricated pass. A present file that cannot be read,
/// carries a foreign schema discriminant, or fails the strict
/// deny-unknown parse is a typed failure. The facts path may be a symlink
/// only in the Home-Manager shape ([`accepts_hm_symlink`]); any other
/// symlinked or non-regular entry is a typed refusal.
pub(in crate::syscheck) fn load_host_facts() -> Result<Option<HostFacts>, CheckFailure> {
    load_host_facts_from(host_facts_path().as_deref())
}

pub(in crate::syscheck) fn load_host_facts_from(
    path: Option<&Path>,
) -> Result<Option<HostFacts>, CheckFailure> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = match read_facts_entry(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CheckFailure::fail(
                "host-facts-unreadable",
                format!("host facts {} are unreadable: {error}", path.display()),
            ));
        }
    };
    let facts: HostFacts = serde_json::from_slice(&bytes).map_err(|error| {
        CheckFailure::fail(
            "host-facts-malformed",
            format!("host facts {} rejected: {error}", path.display()),
        )
    })?;
    if facts.schema != HOST_FACTS_SCHEMA {
        return Err(CheckFailure::fail(
            "host-facts-schema-unknown",
            format!(
                "host facts {} declare schema {:?}; expected {HOST_FACTS_SCHEMA:?}",
                path.display(),
                facts.schema
            ),
        ));
    }
    Ok(Some(facts))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_facts(name: &str, body: &str) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().expect("facts fixture root is creatable");
        let path = root.path().join(name);
        fs::write(&path, body).expect("facts fixture is writable");
        let path = path.to_path_buf();
        (root, path)
    }

    #[test]
    fn an_absent_facts_file_is_typed_absence_never_an_error() {
        let root = tempfile::tempdir().expect("absent facts root is creatable");
        assert_eq!(
            load_host_facts_from(Some(&root.path().join("host-facts.json"))).expect("absent"),
            None
        );
        assert_eq!(load_host_facts_from(None).expect("no source"), None);
    }

    #[test]
    fn a_declared_facts_file_parses_strictly_against_the_contract_shape() {
        let body = r#"{"schema":"odin.sweep-host-facts.v1","host":"pc","candidateRevision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bootloader":"grub-bios","zellijWeb":{"enabled":true,"ip":"127.0.0.1","port":8093},"sopsRenderedDirs":["/run/secrets"]}"#;
        let (_root, path) = write_facts("host-facts.json", body);
        let facts = load_host_facts_from(Some(&path))
            .expect("the declared facts parse")
            .expect("present");
        assert_eq!(facts.host, "pc");
        assert_eq!(facts.bootloader, Bootloader::GrubBios);
        assert_eq!(
            facts.zellij_web,
            ZellijWebFacts {
                enabled: true,
                ip: "127.0.0.1".to_owned(),
                port: 8093,
            }
        );
        assert_eq!(
            facts.sops_rendered_dirs,
            vec![PathBuf::from("/run/secrets")]
        );
        assert_eq!(facts.dotfiles_root, None);
    }

    #[test]
    fn a_present_facts_file_with_an_unknown_field_is_a_typed_failure() {
        let body = r#"{"schema":"odin.sweep-host-facts.v1","host":"pc","candidateRevision":"unknown","bootloader":"other","zellijWeb":{"enabled":false,"ip":"127.0.0.1","port":1},"sopsRenderedDirs":[],"extra":true}"#;
        let (_root, path) = write_facts("host-facts.json", body);
        let failure = load_host_facts_from(Some(&path))
            .expect_err("unknown fields must fail the strict parse");
        assert_eq!(failure.status, CheckStatus::Fail);
        assert_eq!(failure.reason, "host-facts-malformed");
    }

    #[test]
    fn a_foreign_schema_discriminant_is_a_typed_failure() {
        let body = r#"{"schema":"something.else.v9","host":"pc","candidateRevision":"unknown","bootloader":"other","zellijWeb":{"enabled":false,"ip":"127.0.0.1","port":1},"sopsRenderedDirs":[]}"#;
        let (_root, path) = write_facts("host-facts.json", body);
        let failure =
            load_host_facts_from(Some(&path)).expect_err("a foreign schema must fail the load");
        assert_eq!(failure.reason, "host-facts-schema-unknown");
    }

    #[test]
    fn an_unknown_bootloader_value_is_a_typed_failure() {
        let body = r#"{"schema":"odin.sweep-host-facts.v1","host":"pc","candidateRevision":"unknown","bootloader":"lilo","zellijWeb":{"enabled":false,"ip":"127.0.0.1","port":1},"sopsRenderedDirs":[]}"#;
        let (_root, path) = write_facts("host-facts.json", body);
        let failure =
            load_host_facts_from(Some(&path)).expect_err("an unknown bootloader must fail");
        assert_eq!(failure.reason, "host-facts-malformed");
    }

    #[test]
    fn the_accepted_symlink_shape_is_exactly_a_store_regular_file() {
        assert!(accepts_hm_symlink(
            Path::new("/nix/store/3x9k2mq7-host-facts.json"),
            true
        ));
        // A mutable target is refused even when it is a regular file, a
        // store directory is refused, and a store-prefix lookalike
        // (/nix/store-evil) is refused: starts_with is component-wise.
        assert!(!accepts_hm_symlink(
            Path::new("/home/colin/.config/odin/host-facts.json"),
            true
        ));
        assert!(!accepts_hm_symlink(
            Path::new("/nix/store/3x9k2mq7-some-directory"),
            false
        ));
        assert!(!accepts_hm_symlink(
            Path::new("/nix/store-evil/host-facts.json"),
            true
        ));
    }

    #[test]
    fn a_symlink_to_a_mutable_target_is_a_typed_refusal() {
        let body = r#"{"schema":"odin.sweep-host-facts.v1","host":"pc","candidateRevision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bootloader":"grub-bios","zellijWeb":{"enabled":false,"ip":"127.0.0.1","port":1},"sopsRenderedDirs":[]}"#;
        let root = tempfile::tempdir().expect("mutable symlink root is creatable");
        let target = root.path().join("real-facts.json");
        fs::write(&target, body).expect("facts fixture is writable");
        let link = root.path().join("host-facts.json");
        std::os::unix::fs::symlink(&target, &link).expect("symlink is creatable");
        let failure = load_host_facts_from(Some(&link))
            .expect_err("a symlink into the mutable home must stay a refusal");
        assert_eq!(failure.status, CheckStatus::Fail);
        assert_eq!(failure.reason, "host-facts-unreadable");
    }

    #[test]
    fn a_dangling_symlink_at_the_facts_path_is_a_typed_refusal() {
        let root = tempfile::tempdir().expect("dangling symlink root is creatable");
        let link = root.path().join("host-facts.json");
        std::os::unix::fs::symlink(root.path().join("missing.json"), &link)
            .expect("symlink is creatable");
        let failure = load_host_facts_from(Some(&link))
            .expect_err("a dangling symlink must refuse, never read as absent");
        assert_eq!(failure.reason, "host-facts-unreadable");
    }

    #[test]
    fn a_directory_at_the_facts_path_is_a_typed_failure() {
        let root = tempfile::tempdir().expect("directory fixture root is creatable");
        let path = root.path().join("host-facts.json");
        fs::create_dir(&path).expect("facts fixture directory is creatable");
        let failure =
            load_host_facts_from(Some(&path)).expect_err("a directory must stay a failure");
        assert_eq!(failure.reason, "host-facts-unreadable");
    }

    /// One readable small regular file under `/nix/store`, so the loader
    /// test exercises a real immutable target. `None` off-Nix (no store,
    /// e.g. CI without Nix).
    fn a_store_regular_file() -> Option<PathBuf> {
        for package in fs::read_dir("/nix/store").ok()?.flatten() {
            let package = package.path();
            if !package.is_dir() {
                continue;
            }
            for entry in fs::read_dir(&package).ok()?.flatten() {
                let path = entry.path();
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                if metadata.is_file() && metadata.len() < 1024 * 1024 {
                    return Some(path);
                }
            }
        }
        None
    }

    #[test]
    fn a_real_store_symlink_loads_through_the_full_loader_path() {
        let Some(target) = a_store_regular_file() else {
            eprintln!("skipping: no /nix/store regular file on this host (non-nix CI)");
            return;
        };
        let root = tempfile::tempdir().expect("store symlink root is creatable");
        let link = root.path().join("host-facts.json");
        std::os::unix::fs::symlink(&target, &link).expect("store symlink is creatable");
        // A parse/schema failure confirms the symlink was read rather than rejected as unreadable.
        match load_host_facts_from(Some(&link)) {
            Ok(_) => {} // the store file happened to carry valid facts
            Err(failure) => assert_ne!(
                failure.reason,
                "host-facts-unreadable",
                "an HM-shaped /nix/store symlink must be accepted, not refused \
                 (target {})",
                target.display()
            ),
        }
    }

    #[test]
    fn the_declared_dotfiles_root_parses_when_present() {
        let body = r#"{"schema":"odin.sweep-host-facts.v1","host":"pc","candidateRevision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bootloader":"systemd-boot","zellijWeb":{"enabled":false,"ip":"127.0.0.1","port":1},"sopsRenderedDirs":[],"dotfilesRoot":"/home/colin/dotfiles"}"#;
        let (_root, path) = write_facts("host-facts.json", body);
        let facts = load_host_facts_from(Some(&path))
            .expect("the declared facts parse")
            .expect("present");
        assert_eq!(
            facts.dotfiles_root,
            Some(PathBuf::from("/home/colin/dotfiles"))
        );
    }

    #[test]
    fn an_absent_gateway_keeps_the_local_contract() {
        let body = r#"{"schema":"odin.sweep-host-facts.v1","host":"pc","candidateRevision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bootloader":"systemd-boot","zellijWeb":{"enabled":false,"ip":"127.0.0.1","port":1},"sopsRenderedDirs":[]}"#;
        let (_root, path) = write_facts("host-facts.json", body);
        let facts = load_host_facts_from(Some(&path))
            .expect("facts without gateway parse")
            .expect("present");
        assert_eq!(facts.gateway, None);
    }

    #[test]
    fn a_declared_gateway_relay_parses_and_a_null_or_foreign_key_fails() {
        let relay = r#"{"schema":"odin.sweep-host-facts.v1","host":"laptop","candidateRevision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bootloader":"systemd-boot","zellijWeb":{"enabled":false,"ip":"127.0.0.1","port":1},"sopsRenderedDirs":[],"gateway":{"posture":"relay","socketUnit":"litellm-gateway.socket","serviceUnit":"litellm-gateway.service","listen":"127.0.0.1:4000","upstream":"100.64.0.11:14000"}}"#;
        let (_root, path) = write_facts("host-facts.json", relay);
        let facts = load_host_facts_from(Some(&path))
            .expect("the declared relay parses")
            .expect("present");
        assert_eq!(
            facts.gateway,
            Some(GatewayRelayFacts {
                posture: "relay".to_owned(),
                socket_unit: "litellm-gateway.socket".to_owned(),
                service_unit: "litellm-gateway.service".to_owned(),
                listen: "127.0.0.1:4000".to_owned(),
                upstream: "100.64.0.11:14000".to_owned(),
            })
        );
        let null = r#"{"schema":"odin.sweep-host-facts.v1","host":"laptop","candidateRevision":"unknown","bootloader":"other","zellijWeb":{"enabled":false,"ip":"127.0.0.1","port":1},"sopsRenderedDirs":[],"gateway":null}"#;
        let (_root, path) = write_facts("null.json", null);
        let failure = load_host_facts_from(Some(&path)).expect_err("null gateway is not absence");
        assert_eq!(failure.reason, "host-facts-malformed");
        let foreign = r#"{"schema":"odin.sweep-host-facts.v1","host":"laptop","candidateRevision":"unknown","bootloader":"other","zellijWeb":{"enabled":false,"ip":"127.0.0.1","port":1},"sopsRenderedDirs":[],"gatewayRelay":{"unit":"litellm-relay.service"}}"#;
        let (_root, path) = write_facts("foreign.json", foreign);
        let failure =
            load_host_facts_from(Some(&path)).expect_err("gatewayRelay is not the contract");
        assert_eq!(failure.reason, "host-facts-malformed");
    }
}
