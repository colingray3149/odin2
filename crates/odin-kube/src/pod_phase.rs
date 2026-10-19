//! A pod's lifecycle as the cluster recorded it: when it was created,
//! scheduled onto a node, its container started, it turned Ready and its
//! container finished. Read from the pod object the caller already holds;
//! never a separate poll.

use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::jiff::Timestamp;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PodTimeline {
    pub created: Option<Timestamp>,
    pub scheduled: Option<Timestamp>,
    pub started: Option<Timestamp>,
    pub ready: Option<Timestamp>,
    pub finished: Option<Timestamp>,
}

impl PodTimeline {
    pub fn of(pod: &Pod) -> Self {
        let status = pod.status.as_ref();
        let condition = |kind: &str| {
            status
                .and_then(|status| status.conditions.as_ref())
                .and_then(|conditions| {
                    conditions
                        .iter()
                        .find(|condition| condition.type_ == kind && condition.status == "True")
                })
                .and_then(|condition| condition.last_transition_time.as_ref())
                .map(|time| time.0)
        };
        let container = status
            .and_then(|status| status.container_statuses.as_ref())
            .and_then(|statuses| statuses.first())
            .and_then(|status| status.state.as_ref());
        Self {
            created: pod.metadata.creation_timestamp.as_ref().map(|time| time.0),
            scheduled: condition("PodScheduled"),
            started: container
                .and_then(|state| {
                    state
                        .running
                        .as_ref()
                        .and_then(|running| running.started_at.as_ref())
                        .or_else(|| {
                            state
                                .terminated
                                .as_ref()
                                .and_then(|terminated| terminated.started_at.as_ref())
                        })
                })
                .map(|time| time.0),
            ready: condition("Ready"),
            finished: container
                .and_then(|state| state.terminated.as_ref())
                .and_then(|terminated| terminated.finished_at.as_ref())
                .map(|time| time.0),
        }
    }

    /// `scheduled_ms= started_ms= ready_ms= finished_ms=`: each phase's
    /// offset from the pod's creation (`-` when the cluster has not
    /// recorded it), then `extra` (`connected_ms=` for an agent carrier) at
    /// the given Unix millisecond.
    pub fn fields(&self, extra: Option<(&str, i64)>) -> String {
        let offset = |at: Option<i64>| match (self.created, at) {
            (Some(created), Some(at)) => (at - created.as_millisecond()).to_string(),
            _ => "-".to_owned(),
        };
        let offset_of = |at: Option<Timestamp>| offset(at.map(|at| at.as_millisecond()));
        let mut fields = format!(
            "scheduled_ms={} started_ms={} ready_ms={} finished_ms={}",
            offset_of(self.scheduled),
            offset_of(self.started),
            offset_of(self.ready),
            offset_of(self.finished)
        );
        if let Some((name, at)) = extra {
            fields.push_str(&format!(" {name}={}", offset(Some(at))));
        }
        fields
    }
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateRunning, ContainerStatus, PodCondition, PodStatus,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    use super::*;

    fn at(ms: i64) -> Time {
        Time(Timestamp::from_millisecond(1_790_000_000_000 + ms).expect("time"))
    }

    #[test]
    fn phases_are_offsets_from_creation_and_unrecorded_ones_say_so() {
        let condition = |kind: &str, ms: i64| PodCondition {
            type_: kind.to_owned(),
            status: "True".to_owned(),
            last_transition_time: Some(at(ms)),
            ..PodCondition::default()
        };
        let pod = Pod {
            metadata: kube::api::ObjectMeta {
                creation_timestamp: Some(at(0)),
                ..Default::default()
            },
            status: Some(PodStatus {
                conditions: Some(vec![
                    condition("PodScheduled", 40),
                    condition("Ready", 2_300),
                ]),
                container_statuses: Some(vec![ContainerStatus {
                    state: Some(ContainerState {
                        running: Some(ContainerStateRunning {
                            started_at: Some(at(2_100)),
                        }),
                        ..ContainerState::default()
                    }),
                    ..ContainerStatus::default()
                }]),
                ..PodStatus::default()
            }),
            ..Pod::default()
        };
        let timeline = PodTimeline::of(&pod);
        assert_eq!(
            timeline.fields(Some(("connected_ms", at(2_900).0.as_millisecond()))),
            "scheduled_ms=40 started_ms=2100 ready_ms=2300 finished_ms=- connected_ms=2900"
        );
        assert_eq!(
            PodTimeline::of(&Pod::default()).fields(None),
            "scheduled_ms=- started_ms=- ready_ms=- finished_ms=-"
        );
    }
}
