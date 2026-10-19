//! Smart-ring gestures as routine triggers.
//!
//! ringd, on the device the ring is bonded to, reports each recognized
//! gesture over Huginn with that device's paired credential. The report
//! reaches here only on the authenticated port; the device must still be
//! paired (a revoked one is refused like an unknown one). The gesture then
//! fires the conversation seat's `ring_gesture` routines through the same
//! routine path as files and pushes, keyed by device and gesture id, so a
//! retried report fires nothing new.

use std::sync::Arc;

use odin_domain::huginn as live;
use odin_huginn::devices::DeviceTrustStore;
use odin_registry::schema::RoutineEvent;

pub(crate) trait GestureRoutines: Send + Sync + 'static {
    /// Queues every matching routine once per `key`; returns how many fired.
    fn ring_gesture(
        &self,
        gesture: &str,
        key: &str,
        detail: &str,
        at_ms: i64,
    ) -> Result<usize, String>;
}

impl GestureRoutines for odin_hermes::runtime::HermesRuntime {
    fn ring_gesture(
        &self,
        gesture: &str,
        key: &str,
        detail: &str,
        at_ms: i64,
    ) -> Result<usize, String> {
        self.routine_event(RoutineEvent::RingGesture, Some(gesture), key, detail, at_ms)
    }
}

pub(crate) struct RingGestureIntake<D, R> {
    devices: Arc<D>,
    routines: Arc<R>,
}

fn occurrence_key(device: live::DeviceId, gesture_id: &str) -> String {
    format!("ring:{device}:{gesture_id}")
}

impl<D: DeviceTrustStore + 'static, R: GestureRoutines> RingGestureIntake<D, R> {
    pub(crate) fn new(devices: Arc<D>, routines: Arc<R>) -> Self {
        Self { devices, routines }
    }

    pub(crate) async fn report(
        &self,
        device: live::DeviceId,
        report: live::RingGestureReport,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        report
            .check()
            .map_err(|message| live::HuginnProtocolError::InvalidRequest {
                code: "ringGesture".to_owned(),
                message,
            })?;
        let label = match self.devices.get(device).await {
            Ok(Some(record)) if record.revoked_at.is_none() => record.label,
            Ok(_) => {
                tracing::error!("ring gesture refused device={device} reason=not paired");
                return Err(live::HuginnProtocolError::Unauthenticated);
            }
            Err(error) => {
                tracing::error!("ring gesture device_lookup_failed device={device} error={error}");
                return Err(live::HuginnProtocolError::Unavailable {
                    code: "ringGestureDevice".to_owned(),
                });
            }
        };
        let key = occurrence_key(device, &report.gesture_id);
        let detail = format!(
            "Colin made the ring gesture '{}' (reported by {label})",
            report.gesture
        );
        let at_ms =
            i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                .unwrap_or(i64::MAX);
        let routines = Arc::clone(&self.routines);
        let gesture = report.gesture.clone();
        // Queuing writes the schedule store: off the async workers.
        let fired = tokio::task::spawn_blocking(move || {
            routines.ring_gesture(&gesture, &key, &detail, at_ms)
        })
        .await
        .map_err(|error| {
            tracing::error!("ring gesture join_failed error={error}");
            unavailable_routines()
        })?
        .map_err(|error| {
            tracing::error!(
                "ring gesture not queued device={device} gesture={} id={} error={error}",
                report.gesture,
                report.gesture_id
            );
            unavailable_routines()
        })?;
        tracing::info!(
            "ring gesture device={device} surface={label} gesture={} id={} routines_fired={fired}",
            report.gesture,
            report.gesture_id
        );
        Ok(live::HuginnResponse::Ack)
    }
}

fn unavailable_routines() -> live::HuginnProtocolError {
    live::HuginnProtocolError::Unavailable {
        code: "ringGestureRoutines".to_owned(),
    }
}

#[cfg(test)]
#[path = "tests/ring_gesture.rs"]
mod tests;
