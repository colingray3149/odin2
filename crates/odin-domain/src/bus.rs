//! Synchronous, transport-neutral event bus contracts and stable subjects.

use std::num::NonZeroUsize;

use crate::{DomainError, EventEnvelope};

pub const SUBJECT_REGISTRY_CHANGED: &str = "odin.registry.changed";
pub const SUBJECT_LANE_CHANGED: &str = "odin.lane.changed";
pub const SUBJECT_RUN_CHANGED: &str = "odin.run.changed";
pub const SUBJECT_ATTEMPT_CHANGED: &str = "odin.attempt.changed";
pub const SUBJECT_COMMAND_CHANGED: &str = "odin.command.changed";
pub const SUBJECT_APPROVAL_CHANGED: &str = "odin.approval.changed";
pub const SUBJECT_INCIDENT_CHANGED: &str = "odin.incident.changed";
pub const SUBJECT_ARTIFACT_PUBLISHED: &str = "odin.artifact.published";
pub const SUBJECT_PROVIDER_LEASE_CHANGED: &str = "odin.provider_lease.changed";
pub const SUBJECT_LIVE_EVENT: &str = "odin.live.event";
pub const SUBJECT_KNOWLEDGE_CHANGED: &str = "odin.knowledge.changed";
pub const SUBJECT_SWEEP_COMPLETED: &str = "odin.sweep.completed";

/// All stable event subjects in deterministic taxonomy order.
pub const SUBJECTS: &[&str] = &[
    SUBJECT_REGISTRY_CHANGED,
    SUBJECT_LANE_CHANGED,
    SUBJECT_RUN_CHANGED,
    SUBJECT_ATTEMPT_CHANGED,
    SUBJECT_COMMAND_CHANGED,
    SUBJECT_APPROVAL_CHANGED,
    SUBJECT_INCIDENT_CHANGED,
    SUBJECT_ARTIFACT_PUBLISHED,
    SUBJECT_PROVIDER_LEASE_CHANGED,
    SUBJECT_LIVE_EVENT,
    SUBJECT_KNOWLEDGE_CHANGED,
    SUBJECT_SWEEP_COMPLETED,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionRequest {
    kinds: Vec<String>,
    capacity: NonZeroUsize,
}

impl SubscriptionRequest {
    pub fn new<I, S>(kinds: I, capacity: usize) -> Result<Self, DomainError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let capacity =
            NonZeroUsize::new(capacity).ok_or(DomainError::InvalidCapacity { capacity })?;
        let mut kinds: Vec<String> = kinds.into_iter().map(Into::into).collect();
        kinds.sort_unstable();
        kinds.dedup();

        if kinds.is_empty() {
            return Err(DomainError::InvalidSubscription(
                "subscription must contain at least one event kind".to_owned(),
            ));
        }
        if kinds.iter().any(String::is_empty) {
            return Err(DomainError::InvalidSubscription(
                "subscription event kinds must not be empty".to_owned(),
            ));
        }

        Ok(Self { kinds, capacity })
    }

    pub fn kinds(&self) -> &[String] {
        &self.kinds
    }

    pub const fn capacity(&self) -> usize {
        self.capacity.get()
    }
}

pub trait EventBus {
    type Subscription;
    type Error;

    fn publish(&self, event: &EventEnvelope) -> Result<(), Self::Error>;

    fn subscribe(&self, request: SubscriptionRequest) -> Result<Self::Subscription, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_capacity_must_be_nonzero() {
        assert_eq!(
            SubscriptionRequest::new([SUBJECT_RUN_CHANGED], 0),
            Err(DomainError::InvalidCapacity { capacity: 0 })
        );
    }

    #[test]
    fn subscription_kinds_are_sorted_and_deduplicated() {
        let request = SubscriptionRequest::new(
            [
                SUBJECT_RUN_CHANGED,
                SUBJECT_LANE_CHANGED,
                SUBJECT_RUN_CHANGED,
            ],
            8,
        )
        .expect("valid subscription");

        assert_eq!(
            request.kinds(),
            &[
                SUBJECT_LANE_CHANGED.to_owned(),
                SUBJECT_RUN_CHANGED.to_owned()
            ]
        );
        assert_eq!(request.capacity(), 8);
    }

    #[test]
    fn subscription_kinds_must_be_nonempty() {
        assert!(matches!(
            SubscriptionRequest::new(Vec::<String>::new(), 1),
            Err(DomainError::InvalidSubscription(_))
        ));
        assert!(matches!(
            SubscriptionRequest::new([""], 1),
            Err(DomainError::InvalidSubscription(_))
        ));
    }
}
