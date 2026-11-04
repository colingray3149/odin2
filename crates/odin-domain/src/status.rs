use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LaneStatus {
    Desired,
    Provisioning,
    Ready,
    Running,
    WaitingApproval,
    Paused,
    Recovering,
    Succeeded,
    Failed,
    Blocked,
    Cancelled,
    Retired,
}

impl LaneStatus {
    pub const fn legal_transitions(self) -> &'static [Self] {
        match self {
            Self::Desired => &[Self::Provisioning, Self::Cancelled, Self::Retired],
            Self::Provisioning => &[Self::Ready, Self::Failed, Self::Blocked, Self::Cancelled],
            Self::Ready => &[Self::Running, Self::Cancelled, Self::Retired],
            Self::Running => &[
                Self::WaitingApproval,
                Self::Paused,
                Self::Recovering,
                Self::Succeeded,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::WaitingApproval => &[
                Self::Running,
                Self::Paused,
                Self::Recovering,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::Paused => &[
                Self::Running,
                Self::Recovering,
                Self::Blocked,
                Self::Cancelled,
                Self::Retired,
            ],
            Self::Recovering => &[
                Self::Running,
                Self::WaitingApproval,
                Self::Paused,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::Succeeded | Self::Failed | Self::Blocked | Self::Cancelled | Self::Retired => &[],
        }
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        self.legal_transitions().contains(&next)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Blocked | Self::Cancelled | Self::Retired
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RunStatus {
    Pending,
    Planning,
    Running,
    WaitingApproval,
    Paused,
    Recovering,
    Succeeded,
    Failed,
    Blocked,
    Cancelled,
}

impl RunStatus {
    pub const fn legal_transitions(self) -> &'static [Self] {
        match self {
            Self::Pending => &[Self::Planning, Self::Cancelled],
            Self::Planning => &[
                Self::Running,
                Self::WaitingApproval,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::Running => &[
                Self::WaitingApproval,
                Self::Paused,
                Self::Recovering,
                Self::Succeeded,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::WaitingApproval => &[
                Self::Running,
                Self::Paused,
                Self::Recovering,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::Paused => &[
                Self::Running,
                Self::Recovering,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::Recovering => &[
                Self::Running,
                Self::WaitingApproval,
                Self::Paused,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::Succeeded | Self::Failed | Self::Blocked | Self::Cancelled => &[],
        }
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        self.legal_transitions().contains(&next)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Blocked | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AttemptStatus {
    Pending,
    Starting,
    Running,
    WaitingApproval,
    Paused,
    Orphaned,
    Recovering,
    Succeeded,
    Failed,
    Blocked,
    Cancelled,
}

impl AttemptStatus {
    pub const fn legal_transitions(self) -> &'static [Self] {
        match self {
            Self::Pending => &[Self::Starting, Self::Cancelled],
            Self::Starting => &[
                Self::Running,
                Self::Orphaned,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::Running => &[
                Self::WaitingApproval,
                Self::Paused,
                Self::Orphaned,
                Self::Recovering,
                Self::Succeeded,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::WaitingApproval => &[
                Self::Running,
                Self::Paused,
                Self::Orphaned,
                Self::Recovering,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::Paused => &[
                Self::Running,
                Self::Orphaned,
                Self::Recovering,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::Orphaned => &[
                Self::Recovering,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::Recovering => &[
                Self::Running,
                Self::WaitingApproval,
                Self::Paused,
                Self::Orphaned,
                Self::Failed,
                Self::Blocked,
                Self::Cancelled,
            ],
            Self::Succeeded | Self::Failed | Self::Blocked | Self::Cancelled => &[],
        }
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        self.legal_transitions().contains(&next)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Blocked | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ApprovalStatus {
    Requested,
    Approved,
    Denied,
    Expired,
    Consumed,
    Cancelled,
}

impl ApprovalStatus {
    pub const fn legal_transitions(self) -> &'static [Self] {
        match self {
            Self::Requested => &[Self::Approved, Self::Denied, Self::Expired, Self::Cancelled],
            Self::Approved => &[Self::Consumed, Self::Expired, Self::Cancelled],
            Self::Denied | Self::Expired | Self::Consumed | Self::Cancelled => &[],
        }
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        self.legal_transitions().contains(&next)
    }

    pub const fn is_terminal(self) -> bool {
        match self {
            Self::Denied | Self::Expired | Self::Consumed | Self::Cancelled => true,
            Self::Requested | Self::Approved => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EffectClass {
    #[serde(rename = "R0")]
    R0,
    #[serde(rename = "R1")]
    R1,
    #[serde(rename = "R2")]
    R2,
    #[serde(rename = "R3")]
    R3,
}

#[cfg(test)]
mod tests {
    use super::{ApprovalStatus, LaneStatus, RunStatus};

    #[test]
    fn lane_and_run_transitions_are_directional() {
        assert!(LaneStatus::Desired.can_transition_to(LaneStatus::Provisioning));
        assert!(LaneStatus::Running.can_transition_to(LaneStatus::WaitingApproval));
        assert!(LaneStatus::WaitingApproval.can_transition_to(LaneStatus::Running));
        assert!(!LaneStatus::Desired.can_transition_to(LaneStatus::Running));
        assert!(!LaneStatus::Paused.can_transition_to(LaneStatus::Succeeded));

        assert!(RunStatus::Pending.can_transition_to(RunStatus::Planning));
        assert!(RunStatus::Running.can_transition_to(RunStatus::Succeeded));
        assert!(!RunStatus::Pending.can_transition_to(RunStatus::Running));
        assert!(!RunStatus::Paused.can_transition_to(RunStatus::Succeeded));
    }

    #[test]
    fn approval_decisions_and_expiry_are_one_way() {
        assert!(ApprovalStatus::Requested.can_transition_to(ApprovalStatus::Approved));
        assert!(ApprovalStatus::Requested.can_transition_to(ApprovalStatus::Expired));
        assert!(ApprovalStatus::Approved.can_transition_to(ApprovalStatus::Consumed));
        assert!(ApprovalStatus::Approved.can_transition_to(ApprovalStatus::Expired));
        assert!(!ApprovalStatus::Approved.can_transition_to(ApprovalStatus::Denied));
        assert!(!ApprovalStatus::Consumed.can_transition_to(ApprovalStatus::Approved));
    }
}
