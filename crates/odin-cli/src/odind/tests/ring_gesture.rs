//! a ring gesture from the paired device fires the routines that
//! follow it once per gesture id; an unpaired or revoked device fires
//! nothing.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use odin_domain::huginn as live;
use odin_huginn::devices::{DeviceTrustStore, NewDeviceRecord, SqliteDeviceTrustStore};
use odin_registry::schema::RoutineTriggerToml;

use super::{GestureRoutines, RingGestureIntake};

/// Match Hermes deduplication by routine and occurrence key.
struct Routines {
    declared: Vec<(&'static str, RoutineTriggerToml)>,
    rows: Mutex<BTreeSet<String>>,
}

impl GestureRoutines for Routines {
    fn ring_gesture(&self, gesture: &str, key: &str, _: &str, _: i64) -> Result<usize, String> {
        let mut rows = self.rows.lock().map_err(|error| error.to_string())?;
        Ok(self
            .declared
            .iter()
            .filter(|(_, trigger)| trigger.follows_gesture(gesture))
            .filter(|(id, _)| rows.insert(format!("routine:{id}:{key}")))
            .count())
    }
}

fn trigger(gesture: &str) -> RoutineTriggerToml {
    RoutineTriggerToml {
        schedule: None,
        event: Some(odin_registry::schema::RoutineEvent::RingGesture),
        profile: None,
        matches: Some(gesture.to_owned()),
        lead_minutes: None,
        account: None,
    }
}

fn report(id: &str, gesture: &str) -> live::RingGestureReport {
    live::RingGestureReport {
        gesture_id: id.to_owned(),
        gesture: gesture.to_owned(),
    }
}

async fn paired(store: &SqliteDeviceTrustStore, label: &str) -> live::DeviceId {
    let device_id = live::DeviceId::new(uuid::Uuid::new_v4()).unwrap();
    store
        .insert(NewDeviceRecord {
            device_id,
            tailnet_node_id: live::TailnetNodeId::new(format!("node.{label}")).unwrap(),
            label: label.to_owned(),
            credential_digest: odin_domain::Digest::hash(label.as_bytes()),
            created_at: time::OffsetDateTime::now_utc(),
        })
        .await
        .unwrap();
    device_id
}

fn fixture() -> (
    Arc<SqliteDeviceTrustStore>,
    Arc<Routines>,
    RingGestureIntake<SqliteDeviceTrustStore, Routines>,
) {
    let devices = Arc::new(SqliteDeviceTrustStore::open_in_memory().unwrap());
    let routines = Arc::new(Routines {
        declared: vec![("ring-lights", trigger("double-tap"))],
        rows: Mutex::new(BTreeSet::new()),
    });
    let intake = RingGestureIntake::new(Arc::clone(&devices), Arc::clone(&routines));
    (devices, routines, intake)
}

fn fired(routines: &Routines) -> usize {
    routines.rows.lock().unwrap().len()
}

#[tokio::test]
async fn a_gesture_fires_its_routine_once_per_gesture_id() {
    let (devices, routines, intake) = fixture();
    let laptop = paired(&devices, "laptop").await;

    let first = intake.report(laptop, report("g-1", "double-tap")).await;
    assert_eq!(first, Ok(live::HuginnResponse::Ack));
    assert_eq!(fired(&routines), 1);

    // ringd retried the same report: acknowledged, nothing new fires.
    let retry = intake.report(laptop, report("g-1", "double-tap")).await;
    assert_eq!(retry, Ok(live::HuginnResponse::Ack));
    assert_eq!(fired(&routines), 1);

    // The next double tap is a new occurrence; another gesture follows nothing.
    intake
        .report(laptop, report("g-2", "double-tap"))
        .await
        .unwrap();
    intake.report(laptop, report("g-3", "shake")).await.unwrap();
    assert_eq!(fired(&routines), 2);
}

#[tokio::test]
async fn an_unpaired_or_revoked_device_is_refused() {
    let (devices, routines, intake) = fixture();
    let stranger = live::DeviceId::new(uuid::Uuid::new_v4()).unwrap();
    assert_eq!(
        intake.report(stranger, report("g-1", "double-tap")).await,
        Err(live::HuginnProtocolError::Unauthenticated)
    );
    let old_phone = paired(&devices, "old-phone").await;
    assert!(devices
        .revoke(old_phone, time::OffsetDateTime::now_utc())
        .await
        .unwrap());
    assert_eq!(
        intake.report(old_phone, report("g-1", "double-tap")).await,
        Err(live::HuginnProtocolError::Unauthenticated)
    );
    assert_eq!(fired(&routines), 0);
}

#[tokio::test]
async fn a_malformed_report_is_refused_before_anything_fires() {
    let (devices, routines, intake) = fixture();
    let laptop = paired(&devices, "laptop").await;
    let refused = intake.report(laptop, report("g 1", "double-tap")).await;
    assert!(
        matches!(refused, Err(live::HuginnProtocolError::InvalidRequest { ref code, .. }) if code == "ringGesture"),
        "{refused:?}"
    );
    assert_eq!(fired(&routines), 0);
}
