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

    pub const fn terminal_kind(self) -> Option<TerminalKind> {
        match self {
            Self::Succeeded => Some(TerminalKind::Succeeded),
            Self::Failed => Some(TerminalKind::Failed),
            Self::Blocked => Some(TerminalKind::Blocked),
            Self::Cancelled => Some(TerminalKind::Cancelled),
            Self::Retired => Some(TerminalKind::Retired),
            Self::Desired
            | Self::Provisioning
            | Self::Ready
            | Self::Running
            | Self::WaitingApproval
            | Self::Paused
            | Self::Recovering => None,
        }
    }

    pub const fn is_terminal(self) -> bool {
        self.terminal_kind().is_some()
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

    pub const fn terminal_kind(self) -> Option<TerminalKind> {
        match self {
            Self::Succeeded => Some(TerminalKind::Succeeded),
            Self::Failed => Some(TerminalKind::Failed),
            Self::Blocked => Some(TerminalKind::Blocked),
            Self::Cancelled => Some(TerminalKind::Cancelled),
            Self::Pending
            | Self::Planning
            | Self::Running
            | Self::WaitingApproval
            | Self::Paused
            | Self::Recovering => None,
        }
    }

    pub const fn is_terminal(self) -> bool {
        self.terminal_kind().is_some()
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

    pub const fn terminal_kind(self) -> Option<TerminalKind> {
        match self {
            Self::Succeeded => Some(TerminalKind::Succeeded),
            Self::Failed => Some(TerminalKind::Failed),
            Self::Blocked => Some(TerminalKind::Blocked),
            Self::Cancelled => Some(TerminalKind::Cancelled),
            Self::Pending
            | Self::Starting
            | Self::Running
            | Self::WaitingApproval
            | Self::Paused
            | Self::Orphaned
            | Self::Recovering => None,
        }
    }

    pub const fn is_terminal(self) -> bool {
        self.terminal_kind().is_some()
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
#[serde(rename_all = "camelCase")]
pub enum SweepStatus {
    Pass,
    Fail,
    Blocked,
    Unimplemented,
    Flag,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TerminalKind {
    Succeeded,
    Failed,
    Blocked,
    Cancelled,
    Retired,
}

#[cfg(test)]
mod tests {
    use super::{ApprovalStatus, AttemptStatus, LaneStatus, RunStatus, TerminalKind};

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
    fn attempt_recovery_requires_a_legal_rung() {
        assert!(AttemptStatus::Orphaned.can_transition_to(AttemptStatus::Recovering));
        assert!(AttemptStatus::Recovering.can_transition_to(AttemptStatus::Running));
        assert!(!AttemptStatus::Orphaned.can_transition_to(AttemptStatus::Running));
        assert!(!AttemptStatus::Pending.can_transition_to(AttemptStatus::Recovering));
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

    #[test]
    fn terminal_states_have_no_successors() {
        for status in [
            LaneStatus::Succeeded,
            LaneStatus::Failed,
            LaneStatus::Blocked,
            LaneStatus::Cancelled,
            LaneStatus::Retired,
        ] {
            assert!(status.is_terminal());
            assert!(status.legal_transitions().is_empty());
        }
        assert_eq!(
            LaneStatus::Succeeded.terminal_kind(),
            Some(TerminalKind::Succeeded)
        );

        for status in [
            RunStatus::Succeeded,
            RunStatus::Failed,
            RunStatus::Blocked,
            RunStatus::Cancelled,
        ] {
            assert!(status.is_terminal());
            assert!(status.legal_transitions().is_empty());
        }

        for status in [
            AttemptStatus::Succeeded,
            AttemptStatus::Failed,
            AttemptStatus::Blocked,
            AttemptStatus::Cancelled,
        ] {
            assert!(status.is_terminal());
            assert!(status.legal_transitions().is_empty());
        }

        for status in [
            ApprovalStatus::Denied,
            ApprovalStatus::Expired,
            ApprovalStatus::Consumed,
            ApprovalStatus::Cancelled,
        ] {
            assert!(status.is_terminal());
            assert!(status.legal_transitions().is_empty());
        }
    }
}
