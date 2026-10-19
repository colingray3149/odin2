use crate::ids::{AttemptId, LaneId, NodeId, ProjectId, RunId, SeatId, SessionId};
use serde::{Deserialize, Serialize};

/// A parent scope contains a child only when every bound parent dimension is present and equal.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Scope {
    pub seat: Option<SeatId>,
    pub project: Option<ProjectId>,
    pub lane: Option<LaneId>,
    pub run: Option<RunId>,
    pub attempt: Option<AttemptId>,
    pub session: Option<SessionId>,
    pub node: Option<NodeId>,
}

impl Scope {
    pub fn contains(&self, child: &Self) -> bool {
        (self.seat.is_none() || self.seat == child.seat)
            && (self.project.is_none() || self.project == child.project)
            && (self.lane.is_none() || self.lane == child.lane)
            && (self.run.is_none() || self.run == child.run)
            && (self.attempt.is_none() || self.attempt == child.attempt)
            && (self.session.is_none() || self.session == child.session)
            && (self.node.is_none() || self.node == child.node)
    }
}

#[cfg(test)]
mod tests {
    use super::Scope;

    #[test]
    fn unbound_parent_dimensions_are_wildcards() {
        let parent = Scope {
            seat: Some("seat-a".parse().unwrap()),
            project: Some("project-a".parse().unwrap()),
            ..Scope::default()
        };
        let child = Scope {
            seat: Some("seat-a".parse().unwrap()),
            project: Some("project-a".parse().unwrap()),
            lane: Some("lane-a".parse().unwrap()),
            run: Some("run-a".parse().unwrap()),
            attempt: Some("attempt-a".parse().unwrap()),
            session: Some("session-a".parse().unwrap()),
            node: Some("node-a".parse().unwrap()),
        };

        assert!(parent.contains(&child));
        assert!(Scope::default().contains(&child));
    }

    #[test]
    fn bound_parent_dimensions_require_exact_child_values() {
        let parent = Scope {
            seat: Some("seat-a".parse().unwrap()),
            project: Some("project-a".parse().unwrap()),
            lane: Some("lane-a".parse().unwrap()),
            run: Some("run-new".parse().unwrap()),
            ..Scope::default()
        };
        let exact = parent.clone();
        let stale_run = Scope {
            run: Some("run-old".parse().unwrap()),
            ..parent.clone()
        };
        let different_lane = Scope {
            lane: Some("lane-b".parse().unwrap()),
            ..parent.clone()
        };

        assert!(parent.contains(&exact));
        assert!(!parent.contains(&stale_run));
        assert!(!parent.contains(&different_lane));
    }

    #[test]
    fn wider_child_cannot_satisfy_a_bound_parent() {
        let parent = Scope {
            seat: Some("seat-a".parse().unwrap()),
            project: Some("project-a".parse().unwrap()),
            lane: Some("lane-a".parse().unwrap()),
            ..Scope::default()
        };
        let child = Scope {
            seat: Some("seat-a".parse().unwrap()),
            project: None,
            lane: Some("lane-a".parse().unwrap()),
            ..Scope::default()
        };

        assert!(!parent.contains(&child));
    }
}
