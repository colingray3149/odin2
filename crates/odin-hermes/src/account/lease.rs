//! Opaque credential leases with account, capability, and expiry checks.

use odin_domain::huginn::OpaqueCredentialHandle;
use odin_domain::CapabilityId;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use time::OffsetDateTime;

use super::errors::LeaseRejection;

/// Lifetime of one scoped credential lease. A life operation resolves
/// its lease at execution time only; a stale lease is re-issued, never
/// renewed in place.
pub const LEASE_TTL_SECONDS: i64 = 300;

/// Grants one account and capability until expiry without exposing or serializing the secret.
#[derive(Clone)]
pub struct ScopedCredentialLease {
    account: String,
    capability: CapabilityId,
    handle: OpaqueCredentialHandle,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl ScopedCredentialLease {
    pub(crate) fn new(
        account: impl Into<String>,
        capability: CapabilityId,
        handle: OpaqueCredentialHandle,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            account: account.into(),
            capability,
            handle,
            issued_at,
            expires_at,
        }
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Compares the configured credential handle without resolving its secret value.
    pub fn binds_handle(&self, handle: &OpaqueCredentialHandle) -> bool {
        let lease: String = self.handle.clone().into();
        let other: String = handle.clone().into();
        lease == other
    }

    /// Rechecks account, capability, and expiry at use time rather than trusting issuance alone.
    pub fn admits(
        &self,
        capability: &CapabilityId,
        account: &str,
        now: OffsetDateTime,
    ) -> Result<(), LeaseRejection> {
        if self.account != account || self.capability != *capability {
            return Err(LeaseRejection::ScopeMismatch);
        }
        if now >= self.expires_at {
            return Err(LeaseRejection::Expired);
        }
        Ok(())
    }
}

impl fmt::Debug for ScopedCredentialLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedCredentialLease")
            .field("account", &self.account)
            .field("capability", &self.capability.as_str())
            .field("handle", &"[REDACTED]")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Implementations check configured accounts and credential availability before issuing leases.
pub trait CredentialLeases: Send + Sync {
    fn issue(
        &self,
        capability: &CapabilityId,
        account: &str,
        now: OffsetDateTime,
    ) -> Result<ScopedCredentialLease, LeaseRejection>;

    /// Checks credential prerequisites without issuing a lease or contacting the provider.
    /// Issuance repeats the check; readiness alone does not authorize an operation.
    fn availability(&self, account: &str) -> Result<(), LeaseRejection>;
}

/// One account's credential reference: the opaque handle plus the
/// absolute sops-rendered secret file the trusted backend resolves.
/// The value behind the path never enters configuration, leases,
/// envelopes, or receipts.
#[derive(Clone, Debug)]
pub struct AccountSecretRef {
    handle: OpaqueCredentialHandle,
    secret_path: PathBuf,
}

impl AccountSecretRef {
    /// Builds a reference. `secret_path` must be absolute: relative
    /// paths would silently depend on process working directory.
    pub fn new(
        handle: OpaqueCredentialHandle,
        secret_path: PathBuf,
    ) -> Result<Self, LeaseRejection> {
        if !secret_path.is_absolute() {
            return Err(LeaseRejection::CredentialsUnavailable);
        }
        Ok(Self {
            handle,
            secret_path,
        })
    }

    pub fn handle(&self) -> &OpaqueCredentialHandle {
        &self.handle
    }

    /// The sops-rendered secret path. Exposed only to the trusted
    /// backend that reads the value; never serialized into any
    /// envelope (this type implements no `Serialize`).
    pub fn secret_path(&self) -> &std::path::Path {
        &self.secret_path
    }
}

/// Checks explicitly configured accounts against the filesystem at issuance time.
pub struct FileCredentialLeases {
    accounts: BTreeMap<String, AccountSecretRef>,
}

impl FileCredentialLeases {
    pub fn new(accounts: BTreeMap<String, AccountSecretRef>) -> Self {
        Self { accounts }
    }

    /// Checks that the account is configured and its secret path is a regular file,
    /// without reading the secret or contacting the provider.
    pub fn resolve_availability(&self, account: &str) -> Result<(), LeaseRejection> {
        let reference = self
            .accounts
            .get(account)
            .ok_or(LeaseRejection::UnknownAccount)?;
        let metadata = std::fs::metadata(reference.secret_path())
            .map_err(|_| LeaseRejection::CredentialsUnavailable)?;
        if !metadata.is_file() {
            return Err(LeaseRejection::CredentialsUnavailable);
        }
        Ok(())
    }
}

impl CredentialLeases for FileCredentialLeases {
    fn availability(&self, account: &str) -> Result<(), LeaseRejection> {
        self.resolve_availability(account)
    }

    fn issue(
        &self,
        capability: &CapabilityId,
        account: &str,
        now: OffsetDateTime,
    ) -> Result<ScopedCredentialLease, LeaseRejection> {
        self.resolve_availability(account)?;
        let reference = self
            .accounts
            .get(account)
            .expect("availability resolution proved the account is configured");
        let expires_at = now + time::Duration::seconds(LEASE_TTL_SECONDS);
        Ok(ScopedCredentialLease::new(
            account.to_owned(),
            capability.clone(),
            reference.handle().clone(),
            now,
            expires_at,
        ))
    }
}
