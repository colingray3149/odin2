//! Only paired, unrevoked devices can report a project event; a retried key wakes no watcher again.

use std::sync::{Arc, Mutex};

use odin_domain::huginn as live;
use odin_huginn::devices::{DeviceTrustStore, NewDeviceRecord, SqliteDeviceTrustStore};

use super::{ProjectEventIntake, ProjectRoutines};

/// Records accepted reports and watcher wakes.
#[derive(Default)]
struct Routines {
    fired: Mutex<Vec<(String, String, String, String)>>,
    woken: Mutex<Vec<(String, String, String)>>,
}

impl ProjectRoutines for Routines {
    fn project_event(
        &self,
        project: &str,
        kind: &str,
        key: &str,
        detail: &str,
        _: i64,
    ) -> Result<usize, String> {
        let mut fired = self.fired.lock().map_err(|error| error.to_string())?;
        fired.push((
            project.to_owned(),
            kind.to_owned(),
            key.to_owned(),
            detail.to_owned(),
        ));
        Ok(1)
    }

    async fn wake_watchers(&self, watch: &str, project: &str, id: &str, _: &str) -> bool {
        self.woken
            .lock()
            .unwrap()
            .push((watch.to_owned(), project.to_owned(), id.to_owned()));
        true
    }
}

fn report(key: &str) -> live::ProjectEventReport {
    live::ProjectEventReport {
        project: odin_domain::ProjectId::new("project-alpha").unwrap(),
        kind: "job_done".to_owned(),
        key: key.to_owned(),
        detail: r#"{"job":"j1","state":"COMMITTED"}"#.to_owned(),
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

#[tokio::test]
async fn a_paired_report_fires_routines_and_wakes_its_project_watchers_once() {
    let devices = Arc::new(SqliteDeviceTrustStore::open_in_memory().unwrap());
    let routines = Arc::new(Routines::default());
    let intake = ProjectEventIntake::new(Arc::clone(&devices), Arc::clone(&routines));
    let unknown = live::DeviceId::new(uuid::Uuid::new_v4()).unwrap();
    assert_eq!(
        intake.report(unknown, report("j1")).await,
        Err(live::HuginnProtocolError::Unauthenticated)
    );
    assert!(routines.fired.lock().unwrap().is_empty());
    let mini = paired(&devices, "mini").await;
    let bad = live::ProjectEventReport {
        detail: "not json".to_owned(),
        ..report("j1")
    };
    assert!(matches!(
        intake.report(mini, bad).await,
        Err(live::HuginnProtocolError::InvalidRequest { .. })
    ));
    for _ in 0..2 {
        assert_eq!(
            intake.report(mini, report("j1")).await,
            Ok(live::HuginnResponse::Ack)
        );
    }
    let fired = routines.fired.lock().unwrap().clone();
    assert_eq!(fired.len(), 2, "the schedule store dedupes routine keys");
    assert_eq!(
        (
            fired[0].0.as_str(),
            fired[0].1.as_str(),
            fired[0].2.as_str()
        ),
        (
            "project-alpha",
            "job_done",
            "project_event:project-alpha:j1"
        )
    );
    assert!(fired[0].3.ends_with("(reported by mini)"), "{}", fired[0].3);
    assert_eq!(
        routines.woken.lock().unwrap().clone(),
        vec![(
            "project_event".to_owned(),
            "project-alpha".to_owned(),
            "project_event:project-alpha:j1".to_owned()
        )]
    );
    let old = paired(&devices, "old-laptop").await;
    assert!(devices
        .revoke(old, time::OffsetDateTime::now_utc())
        .await
        .unwrap());
    assert_eq!(
        intake.report(old, report("j2")).await,
        Err(live::HuginnProtocolError::Unauthenticated)
    );
}
