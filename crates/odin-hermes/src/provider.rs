//! Route email and calendar requests by account without selecting a default provider.
//!
//! The router rejects leases for another account; providers validate capabilities,
//! expiry, and credential handles before each exchange.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::account::{AccountUnavailable, BatchFault, ScopedCredentialLease, TransportFault};
use crate::calendar::{
    CalendarEventSummary, CalendarMutationReceipt, CalendarProposal, CalendarTransport,
    CalendarWindow,
};
use crate::email::{
    EmailDraft, EmailManagement, EmailManagementReceipt, EmailMessage, EmailSearchQuery,
    EmailSummary, EmailTransport,
};

const MSG_ROUTER_REFUSED: &str = "the credential lease does not bind this account";

/// Declares which accounts a provider serves, independently of its wire protocol.
pub trait LifeProvider: Send + Sync {
    /// The email transport serving `account`, or `None` when this
    /// provider does not serve it.
    fn email_transport(&self, account: &str) -> Option<Arc<dyn EmailTransport>>;

    /// The calendar transport serving `account`, or `None` when this
    /// provider does not serve it.
    fn calendar_transport(&self, account: &str) -> Option<Arc<dyn CalendarTransport>>;
}

/// Routes both transports through the provider configured for the request's account.
pub struct ProviderRouter {
    bindings: BTreeMap<String, Arc<dyn LifeProvider>>,
}

impl ProviderRouter {
    /// Starts without a default provider; bindings come from deployment configuration.
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }

    /// Replaces any existing provider for the account.
    pub fn bind(&mut self, account: impl Into<String>, provider: Arc<dyn LifeProvider>) {
        self.bindings.insert(account.into(), provider);
    }

    fn email_for(&self, account: &str) -> Result<Arc<dyn EmailTransport>, TransportFault> {
        self.bindings
            .get(account)
            .and_then(|provider| provider.email_transport(account))
            .ok_or(TransportFault::Unavailable(AccountUnavailable::Account))
    }

    fn calendar_for(&self, account: &str) -> Result<Arc<dyn CalendarTransport>, TransportFault> {
        self.bindings
            .get(account)
            .and_then(|provider| provider.calendar_transport(account))
            .ok_or(TransportFault::Unavailable(AccountUnavailable::Account))
    }

    /// Rejects a lease for another account before delegating to its transport.
    fn check_binding(
        &self,
        lease: &ScopedCredentialLease,
        account: &str,
    ) -> Result<(), TransportFault> {
        if lease.account() != account {
            return Err(TransportFault::Refused(MSG_ROUTER_REFUSED));
        }
        Ok(())
    }
}

impl Default for ProviderRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailTransport for ProviderRouter {
    fn readiness(&self, account: &str) -> Result<(), TransportFault> {
        self.email_for(account)?.readiness(account)
    }

    fn search(
        &self,
        lease: &ScopedCredentialLease,
        query: &EmailSearchQuery,
        now: time::OffsetDateTime,
    ) -> Result<Vec<EmailSummary>, TransportFault> {
        let transport = self.email_for(&query.account)?;
        self.check_binding(lease, &query.account)?;
        transport.search(lease, query, now)
    }

    fn read(
        &self,
        lease: &ScopedCredentialLease,
        email_id: &str,
        now: time::OffsetDateTime,
    ) -> Result<Option<EmailMessage>, TransportFault> {
        self.check_binding(lease, lease.account())?;
        self.email_for(lease.account())?.read(lease, email_id, now)
    }

    fn save_draft(
        &self,
        lease: &ScopedCredentialLease,
        draft: &EmailDraft,
        now: time::OffsetDateTime,
    ) -> Result<crate::email::EmailDraftReceipt, TransportFault> {
        self.check_binding(lease, lease.account())?;
        self.email_for(lease.account())?
            .save_draft(lease, draft, now)
    }

    fn send_draft(
        &self,
        lease: &ScopedCredentialLease,
        receipt: &crate::email::EmailDraftReceipt,
        now: time::OffsetDateTime,
    ) -> Result<String, TransportFault> {
        self.check_binding(lease, lease.account())?;
        self.email_for(lease.account())?
            .send_draft(lease, receipt, now)
    }

    fn manage(
        &self,
        lease: &ScopedCredentialLease,
        management: &EmailManagement,
        now: time::OffsetDateTime,
    ) -> Result<EmailManagementReceipt, BatchFault> {
        let transport = self.email_for(&management.account)?;
        self.check_binding(lease, &management.account)?;
        transport.manage(lease, management, now)
    }
}

impl CalendarTransport for ProviderRouter {
    fn readiness(&self, account: &str) -> Result<(), TransportFault> {
        self.calendar_for(account)?.readiness(account)
    }

    fn read_window(
        &self,
        lease: &ScopedCredentialLease,
        window: &CalendarWindow,
        now: time::OffsetDateTime,
    ) -> Result<Vec<CalendarEventSummary>, TransportFault> {
        let transport = self.calendar_for(&window.account)?;
        self.check_binding(lease, &window.account)?;
        transport.read_window(lease, window, now)
    }

    fn apply(
        &self,
        lease: &ScopedCredentialLease,
        proposal: &CalendarProposal,
        now: time::OffsetDateTime,
    ) -> Result<CalendarMutationReceipt, BatchFault> {
        let transport = self.calendar_for(&proposal.account)?;
        self.check_binding(lease, &proposal.account)?;
        transport.apply(lease, proposal, now)
    }
}
