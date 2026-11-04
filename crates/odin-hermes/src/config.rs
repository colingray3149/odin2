//! Runtime settings validated from the daemon's `[hermes]` configuration.
//!
//! Endpoints, paths, lanes, and credential handles have no compiled defaults.
//! Absent optional sections disable adapters but retain handlers that report typed unavailability.

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

use odin_domain::{CapabilityId, DomainError, ProjectId, SeatId};

use crate::account::MAX_ACCOUNT_CHARS;
use crate::discord::GATEWAY_INTENT_DIRECT_MESSAGES;
use crate::vault::VaultConfig;

/// Bounds mirrored from the daemon wire validation; enforced again at the
/// composition boundary so a programmatically built settings value can never
/// bypass the daemon schema.
mod bounds {
    pub const EGRESS_CAPACITY_MIN: usize = 1;
    pub const EGRESS_CAPACITY_MAX: usize = 4_096;
    pub const TTL_SECONDS_MIN: i64 = 60;
    pub const TTL_SECONDS_MAX: i64 = 2_592_000;
}

/// The TLS discipline of one generic-provider mail endpoint, rendered
/// by the daemon from the operator declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailTls {
    /// TLS from the first octet (IMAP 993 style).
    ImplicitTls,
    /// Plaintext greeting, then a mandatory STARTTLS upgrade (SMTP 587
    /// style).
    StartTls,
}

/// Provider configuration contains secret references, never credential values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifeProviderSettings {
    /// JMAP (RFC 8620) mail and calendar.
    Jmap {
        session_url: String,
        identity_id: String,
        from_address: String,
        drafts_mailbox_id: String,
        archive_mailbox_id: String,
        trash_mailbox_id: String,
        /// The JMAP calendar id; `None` serves no calendar for this
        /// account.
        calendar_id: Option<String>,
        request_timeout_ms: u64,
        max_response_bytes: u64,
    },
    /// Google Gmail API v1 + Calendar API v3, and Drive API v3 when
    /// `drive` is given. Only public endpoints and the calendar id are
    /// configuration; the token value lives behind the account's secret
    /// handle/path (GoogleTokenFile schema).
    Google {
        token_url: String,
        gmail_api_url: String,
        calendar_api_url: String,
        calendar_id: String,
        request_timeout_ms: u64,
        max_response_bytes: u64,
    },
    Generic {
        from_address: String,
        imap_host: String,
        imap_port: u16,
        imap_tls: MailTls,
        smtp_host: String,
        smtp_port: u16,
        smtp_tls: MailTls,
        helo_name: String,
        inbox_mailbox_id: String,
        drafts_mailbox_id: String,
        archive_mailbox_id: String,
        trash_mailbox_id: String,
        caldav_base_url: Option<String>,
        caldav_calendar_url: Option<String>,
        request_timeout_ms: u64,
        max_response_bytes: u64,
    },
}

impl LifeProviderSettings {
    pub fn serves_calendar(&self) -> bool {
        match self {
            Self::Jmap { calendar_id, .. } => calendar_id.is_some(),
            Self::Google { .. } => true,
            Self::Generic {
                caldav_base_url, ..
            } => caldav_base_url.is_some(),
        }
    }

    fn validate(&self) -> Result<(), HermesConfigError> {
        match self {
            Self::Jmap {
                session_url,
                identity_id,
                from_address,
                drafts_mailbox_id,
                archive_mailbox_id,
                trash_mailbox_id,
                calendar_id,
                request_timeout_ms,
                max_response_bytes,
            } => {
                https_field("jmap.session_url", session_url)?;
                for (field, value) in [
                    ("jmap.identity_id", identity_id.as_str()),
                    ("jmap.from_address", from_address.as_str()),
                    ("jmap.drafts_mailbox_id", drafts_mailbox_id.as_str()),
                    ("jmap.archive_mailbox_id", archive_mailbox_id.as_str()),
                    ("jmap.trash_mailbox_id", trash_mailbox_id.as_str()),
                ] {
                    non_empty(field, value)?;
                }
                if let Some(calendar_id) = calendar_id {
                    non_empty("jmap.calendar_id", calendar_id)?;
                }
                positive_pair(*request_timeout_ms, *max_response_bytes)
            }
            Self::Google {
                token_url,
                gmail_api_url,
                calendar_api_url,
                calendar_id,
                request_timeout_ms,
                max_response_bytes,
            } => {
                https_field("google.token_url", token_url)?;
                https_field("google.gmail_api_url", gmail_api_url)?;
                https_field("google.calendar_api_url", calendar_api_url)?;
                non_empty("google.calendar_id", calendar_id)?;
                positive_pair(*request_timeout_ms, *max_response_bytes)
            }
            Self::Generic {
                from_address,
                imap_host,
                imap_port,
                imap_tls: _,
                smtp_host,
                smtp_port,
                smtp_tls: _,
                helo_name,
                inbox_mailbox_id,
                drafts_mailbox_id,
                archive_mailbox_id,
                trash_mailbox_id,
                caldav_base_url,
                caldav_calendar_url,
                request_timeout_ms,
                max_response_bytes,
            } => {
                address_field("generic.from_address", from_address)?;
                host_field("generic.imap_host", imap_host)?;
                host_field("generic.smtp_host", smtp_host)?;
                if *imap_port == 0 || *smtp_port == 0 {
                    return Err(HermesConfigError::field(
                        "generic.mail_port",
                        "must be 1..=65535",
                    ));
                }
                host_field("generic.helo_name", helo_name)?;
                for (field, value) in [
                    ("generic.inbox_mailbox_id", inbox_mailbox_id.as_str()),
                    ("generic.drafts_mailbox_id", drafts_mailbox_id.as_str()),
                    ("generic.archive_mailbox_id", archive_mailbox_id.as_str()),
                    ("generic.trash_mailbox_id", trash_mailbox_id.as_str()),
                ] {
                    non_empty(field, value)?;
                }
                if let Some(base_url) = caldav_base_url {
                    caldav_url_field("generic.caldav_base_url", base_url)?;
                    if let Some(calendar_url) = caldav_calendar_url {
                        caldav_url_field("generic.caldav_calendar_url", calendar_url)?;
                    }
                } else if caldav_calendar_url.is_some() {
                    return Err(HermesConfigError::field(
                        "generic.caldav_calendar_url",
                        "requires generic.caldav_base_url",
                    ));
                }
                positive_pair(*request_timeout_ms, *max_response_bytes)
            }
        }
    }
}

/// One declared life account: the stable selector every email/calendar
/// operation names explicitly, the opaque credential handle and the
/// absolute sops-rendered secret file it resolves, and the tagged
/// provider facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifeAccountSettings {
    pub account: String,
    pub secret_handle: String,
    pub secret_path: PathBuf,
    pub provider: LifeProviderSettings,
}

impl LifeAccountSettings {
    /// Validates the account's bounded identity fields and provider
    /// facts. The credential value is never representable here.
    pub fn validate(&self) -> Result<(), HermesConfigError> {
        if self.account.trim().is_empty() || self.account.len() > MAX_ACCOUNT_CHARS {
            return Err(HermesConfigError::field(
                "account",
                format!("must be 1..={MAX_ACCOUNT_CHARS} characters"),
            ));
        }
        non_empty("secret_handle", &self.secret_handle)?;
        if !self.secret_path.is_absolute() {
            return Err(HermesConfigError::field(
                "secret_path",
                "must be an absolute path",
            ));
        }
        self.provider.validate()?;
        Ok(())
    }
}

fn non_empty(field: &str, value: &str) -> Result<(), HermesConfigError> {
    if value.trim().is_empty() {
        return Err(HermesConfigError::field(field, "must be non-empty"));
    }
    Ok(())
}

fn https_field(field: &str, value: &str) -> Result<(), HermesConfigError> {
    non_empty(field, value)?;
    if !value.starts_with("https://") {
        return Err(HermesConfigError::field(field, "must be an HTTPS endpoint"));
    }
    Ok(())
}
fn positive_pair(
    request_timeout_ms: u64,
    max_response_bytes: u64,
) -> Result<(), HermesConfigError> {
    if request_timeout_ms == 0 {
        return Err(HermesConfigError::field(
            "request_timeout_ms",
            "must be at least 1",
        ));
    }
    if max_response_bytes == 0 {
        return Err(HermesConfigError::field(
            "max_response_bytes",
            "must be at least 1",
        ));
    }
    Ok(())
}

fn address_field(field: &str, value: &str) -> Result<(), HermesConfigError> {
    non_empty(field, value)?;
    if value.len() > 320 || value.chars().any(char::is_control) {
        return Err(HermesConfigError::field(
            field,
            "must be a bounded address without control characters",
        ));
    }
    if value.matches('@').count() != 1 {
        return Err(HermesConfigError::field(
            field,
            "must contain exactly one @ separator",
        ));
    }
    Ok(())
}

fn host_field(field: &str, value: &str) -> Result<(), HermesConfigError> {
    non_empty(field, value)?;
    if value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return Err(HermesConfigError::field(
            field,
            "must be a bounded host name of letters, digits, '-', '.', '_'",
        ));
    }
    Ok(())
}

/// Remote CalDAV requires HTTPS; plain HTTP is allowed only for loopback bridges.
fn caldav_url_field(field: &str, value: &str) -> Result<(), HermesConfigError> {
    non_empty(field, value)?;
    if value.starts_with("https://") {
        return Ok(());
    }
    let url = url::Url::parse(value).map_err(|error| {
        HermesConfigError::field(field, format!("must be a valid HTTP or HTTPS URL: {error}"))
    })?;
    let loopback = matches!(
        url.host_str(),
        Some("127.0.0.1") | Some("[::1]") | Some("localhost")
    ) || url
        .host_str()
        .and_then(|host| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::Ipv6Addr>()
                .ok()
        })
        .is_some_and(|addr| addr.is_loopback());
    if url.scheme() == "http" && loopback {
        return Ok(());
    }
    Err(HermesConfigError::field(
        field,
        "must be HTTPS, or plain HTTP on the loopback interface only",
    ))
}

/// One composition failure of the Hermes settings. The detail names the
/// offending field and never carries credential material.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("hermes settings rejected: {detail}")]
pub struct HermesConfigError {
    detail: String,
}

impl HermesConfigError {
    fn field(field: &str, reason: impl AsRef<str>) -> Self {
        Self {
            detail: format!("{field}: {}", reason.as_ref()),
        }
    }

    fn domain(field: &str, error: DomainError) -> Self {
        Self {
            detail: format!("{field}: {error}"),
        }
    }
}

/// Discord uses one configured seat and project, never a transport-selected default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordSettings {
    pub seat: SeatId,
    pub project: ProjectId,
    pub owner_user_id: String,
    pub owner_name: String,
    pub notify_channel_id: String,
    pub capability: CapabilityId,
    pub egress_capacity: usize,
    pub gateway_intents: u64,
    pub bot_token_handle: String,
    pub scrub_tokens: BTreeSet<String>,
    pub ttl_seconds: i64,
}

/// The raw Discord surface values, before seat, project, and capability validation.
pub struct DiscordSettingsInput<'a> {
    pub seat: &'a str,
    pub project: &'a str,
    pub owner_user_id: String,
    pub owner_name: String,
    pub notify_channel_id: String,
    pub capability: &'a str,
    pub egress_capacity: usize,
    pub gateway_intents: u64,
    pub bot_token_handle: String,
    pub scrub_tokens: BTreeSet<String>,
    pub ttl_seconds: i64,
}

impl DiscordSettings {
    /// Validates and binds one Discord surface configuration. The bot token
    /// value never appears here — only its handle name; the secret itself is
    /// resolved from the sops-rendered unit environment at composition.
    pub fn new(input: DiscordSettingsInput<'_>) -> Result<Self, HermesConfigError> {
        let DiscordSettingsInput {
            seat,
            project,
            owner_user_id,
            owner_name,
            notify_channel_id,
            capability,
            egress_capacity,
            gateway_intents,
            bot_token_handle,
            scrub_tokens,
            ttl_seconds,
        } = input;
        let seat =
            SeatId::new(seat).map_err(|error| HermesConfigError::domain("discord.seat", error))?;
        let project = ProjectId::new(project)
            .map_err(|error| HermesConfigError::domain("discord.project", error))?;
        let capability = CapabilityId::new(capability)
            .map_err(|error| HermesConfigError::domain("discord.capability", error))?;
        if owner_user_id.trim().is_empty() {
            return Err(HermesConfigError::field(
                "discord.owner_user_id",
                "must be non-empty",
            ));
        }
        if owner_name.trim().is_empty() {
            return Err(HermesConfigError::field(
                "discord.owner_name",
                "must be non-empty",
            ));
        }
        if notify_channel_id.trim().is_empty() {
            return Err(HermesConfigError::field(
                "discord.notify_channel_id",
                "must be non-empty",
            ));
        }
        if bot_token_handle.trim().is_empty() {
            return Err(HermesConfigError::field(
                "discord.bot_token_handle",
                "must be non-empty",
            ));
        }
        if !(bounds::EGRESS_CAPACITY_MIN..=bounds::EGRESS_CAPACITY_MAX).contains(&egress_capacity) {
            return Err(HermesConfigError::field(
                "discord.egress_capacity",
                format!(
                    "must be within {}..={}",
                    bounds::EGRESS_CAPACITY_MIN,
                    bounds::EGRESS_CAPACITY_MAX
                ),
            ));
        }
        // The owner-paired surface serves DMs only: the gateway must
        // request DIRECT_MESSAGES (4096); a portal-enabled deployment may
        // render MESSAGE_CONTENT on top, never a guild or group intent.
        if gateway_intents & GATEWAY_INTENT_DIRECT_MESSAGES == 0 {
            return Err(HermesConfigError::field(
                "discord.gateway_intents",
                "must request the direct-messages intent bit (4096): the owner-paired \
                 surface serves direct messages only",
            ));
        }
        if !(bounds::TTL_SECONDS_MIN..=bounds::TTL_SECONDS_MAX).contains(&ttl_seconds) {
            return Err(HermesConfigError::field(
                "discord.ttl_seconds",
                format!(
                    "must be within {}..={}",
                    bounds::TTL_SECONDS_MIN,
                    bounds::TTL_SECONDS_MAX
                ),
            ));
        }
        if scrub_tokens.iter().any(|token| token.trim().is_empty()) {
            return Err(HermesConfigError::field(
                "discord.scrub_tokens",
                "entries must be non-empty",
            ));
        }
        Ok(Self {
            seat,
            project,
            owner_user_id,
            owner_name,
            notify_channel_id,
            capability,
            egress_capacity,
            gateway_intents,
            bot_token_handle,
            scrub_tokens,
            ttl_seconds,
        })
    }
}

/// The full Hermes/Sinmara runtime settings. Built by the daemon from
/// its strict `[hermes]` section; every field is required exactly as
/// rendered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HermesSettings {
    /// Absolute private state directory for the Hermes surface's durable
    /// event cursor. Created mode `0700` only when absent.
    pub state_dir: PathBuf,
    /// Owner-paired Discord surface. `None` disables the Discord surface.
    pub discord: Option<DiscordSettings>,
    /// SilverBullet vault adapter. `None` disables vault operations — they
    /// report typed unavailable instead of degrading.
    pub vault: Option<VaultConfig>,
    /// One declaration per served life account. An empty list is the
    /// typed disabled state: the email and calendar adapters compose
    /// nothing and their operations report typed unavailable instead of
    /// degrading.
    pub accounts: Vec<LifeAccountSettings>,
    /// Root brain `doc` result paths are relative to (`~/brain`: `raw/...`,
    /// `archive/...`; `private/` is refused).
    pub brain_raw_root: Option<PathBuf>,
    /// Minutes between the wakes of an open ask: a request whose delegated
    /// jobs all ended without a delivered result.
    pub open_ask_minutes: u32,
    /// Minutes the same cause about the same job wakes the seat once, however
    /// often the harness observes it again.
    pub quiet_wake_minutes: u32,
}

/// The one declaration of [`HermesSettings::open_ask_minutes`] until a host overrides it.
pub const DEFAULT_OPEN_ASK_MINUTES: u32 = 15;

/// The one declaration of [`HermesSettings::quiet_wake_minutes`] until a host overrides it.
pub const DEFAULT_QUIET_WAKE_MINUTES: u32 = 30;


impl HermesSettings {
    /// The declared account names (only calendar-serving ones when
    /// `calendar`): the exact `account` choices the email and calendar
    /// tools offer, so a seat picks a real account instead of guessing.
    pub fn account_names(&self, calendar: bool) -> Vec<String> {
        self.accounts
            .iter()
            .filter(|account| !calendar || account.provider.serves_calendar())
            .map(|account| account.account.clone())
            .collect()
    }

    /// Validates the state directory, every present sub-setting, and
    /// every declared life account. Account selectors must be unique:
    /// the selector is the explicit routing key of every email/calendar
    /// operation, and an ambiguous declaration would silently route one
    /// account's credential to another's provider.
    pub fn new(
        state_dir: PathBuf,
        discord: Option<DiscordSettings>,
        vault: Option<VaultConfig>,
        accounts: Vec<LifeAccountSettings>,
    ) -> Result<Self, HermesConfigError> {
        if !state_dir.is_absolute() {
            return Err(HermesConfigError::field(
                "state_dir",
                "must be an absolute path",
            ));
        }
        if let Some(vault) = &vault {
            vault
                .validate()
                .map_err(|error| HermesConfigError::field("vault", error.to_string()))?;
        }
        let mut selectors: HashSet<String> = HashSet::with_capacity(accounts.len());
        for account in &accounts {
            account.validate()?;
            if !selectors.insert(account.account.clone()) {
                return Err(HermesConfigError::field(
                    "account",
                    format!(
                        "duplicate account selector {:?}: every selector must be unique",
                        account.account
                    ),
                ));
            }
        }
        Ok(Self {
            state_dir,
            discord,
            vault,
            accounts,
            brain_raw_root: None,
            open_ask_minutes: DEFAULT_OPEN_ASK_MINUTES,
            quiet_wake_minutes: DEFAULT_QUIET_WAKE_MINUTES,
        })
    }
}

#[cfg(test)]
mod account_name_tests {}

#[cfg(test)]
mod discord_settings_tests {
    use super::*;

    fn input() -> DiscordSettingsInput<'static> {
        DiscordSettingsInput {
            seat: "sinmara",
            project: "garden",
            owner_user_id: "1".to_owned(),
            owner_name: "the owner".to_owned(),
            notify_channel_id: "2".to_owned(),
            capability: "discord.intake",
            egress_capacity: bounds::EGRESS_CAPACITY_MIN,
            gateway_intents: GATEWAY_INTENT_DIRECT_MESSAGES,
            bot_token_handle: "cred:discord-bot".to_owned(),
            scrub_tokens: BTreeSet::new(),
            ttl_seconds: bounds::TTL_SECONDS_MIN,
        }
    }

    /// Each refusal names the field to fix.
    #[test]
    fn a_refused_discord_setting_names_its_field() {
        assert!(DiscordSettings::new(input()).is_ok());
        type Spoil = fn(&mut DiscordSettingsInput<'static>);
        let cases: [(&str, Spoil); 6] = [
            ("discord.owner_name", |i| i.owner_name = " ".to_owned()),
            ("discord.egress_capacity", |i| i.egress_capacity = 0),
            ("discord.gateway_intents", |i| i.gateway_intents = 1 << 9),
            ("discord.ttl_seconds", |i| i.ttl_seconds = 0),
            ("discord.scrub_tokens", |i| {
                i.scrub_tokens.insert(" ".to_owned());
            }),
            ("discord.bot_token_handle", |i| i.bot_token_handle.clear()),
        ];
        for (field, spoil) in cases {
            let mut spoiled = input();
            spoil(&mut spoiled);
            let error = DiscordSettings::new(spoiled).expect_err(field);
            assert!(error.to_string().contains(field), "{field}: {error}");
        }
    }
}
