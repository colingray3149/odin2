//! Publication tasks; readers only consume the durable event journal.
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use odin_kernel::operation::ChildEffectGrant;
use odin_kube::claude_pod::ClaudePodReceipt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::{
    runtime::Handle,
    sync::{watch, Mutex},
    task::JoinHandle,
};

use super::{publication, publication_authority};

#[derive(Clone)]
pub(super) struct Context {
    pub cell: Arc<crate::kube::KubeRuntimeCell>,
    pub grant: ChildEffectGrant,
    pub receipt: ClaudePodReceipt,
    pub project_root: PathBuf,
    pub project_id: String,
    pub session: String,
    pub state_root: PathBuf,
}

pub(super) struct WorkerCustody {
    context: Context,
    gate: Arc<Mutex<()>>,
    cancel: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), String>>>,
}

pub(super) fn start(runtime: &Handle, context: Context) -> WorkerCustody {
    let gate = Arc::new(Mutex::new(()));
    let (cancel, receiver) = watch::channel(false);
    let task = runtime.spawn(run(context.clone(), gate.clone(), receiver));
    WorkerCustody {
        context,
        gate,
        cancel,
        task: Some(task),
    }
}
impl WorkerCustody {
    /// Do not abort an in-flight governed effect: finish it before freezing.
    pub(super) async fn quiesce(&mut self) -> Result<(), String> {
        let _ = self.cancel.send(true);
        if let Some(task) = self.task.as_mut() {
            let result = task
                .await
                .map_err(|error| format!("join publication worker failed: {error}"));
            self.task = None;
            result??;
        }
        Ok(())
    }

    /// Retain the original grant. Its ledger lease is checked by every run.
    pub(super) fn restart(&mut self, runtime: &Handle) -> Result<(), String> {
        if self.task.is_some() {
            return Err("publication worker has not been quiesced".into());
        }
        let (cancel, receiver) = watch::channel(false);
        self.cancel = cancel;
        self.task = Some(runtime.spawn(run(self.context.clone(), self.gate.clone(), receiver)));
        Ok(())
    }
}

impl Drop for WorkerCustody {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Journal {
    results: BTreeMap<String, Value>,
    failures: BTreeMap<String, String>,
    events: Vec<Value>,
}

fn path(root: &Path, session: &str) -> Result<PathBuf, String> {
    let id = uuid::Uuid::parse_str(session).map_err(|_| "invalid publication session")?;
    if id.is_nil() || id.to_string() != session {
        return Err("invalid publication session".into());
    }
    Ok(root
        .join("publication-events")
        .join(format!("{session}.json")))
}

fn load(root: &Path, session: &str) -> Result<Journal, String> {
    match fs::read(path(root, session)?) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|_| "invalid publication event journal".into())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Journal::default()),
        Err(_) => Err("cannot read publication event journal".into()),
    }
}

fn save(root: &Path, session: &str, journal: &Journal) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = path(root, session)?;
    let directory = path.parent().ok_or("missing publication directory")?;
    fs::create_dir_all(directory).map_err(|_| "cannot create publication event directory")?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| "cannot secure publication event directory")?;
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec(journal).map_err(|_| "cannot serialize publication events")?;
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        fs::File::open(directory)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_: std::io::Error| "cannot persist publication events".into())
}

fn append(journal: &mut Journal, mut event: Value) -> Result<(), String> {
    let cursor = u64::try_from(journal.events.len())
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or("publication cursor exhausted")?;
    let object = event.as_object_mut().ok_or("invalid publication event")?;
    object.remove("driver_cursor");
    object.insert("publication_cursor".into(), json!(cursor));
    journal.events.push(event);
    Ok(())
}

pub(super) fn events(state_root: &Path, session: &str) -> Result<Vec<Value>, String> {
    Ok(load(state_root, session)?.events)
}

pub(super) fn recovery_refused(state_root: &Path, session: &str) -> Result<(), String> {
    let mut journal = load(state_root, session)?;
    if journal.failures.contains_key("recovery") {
        return Ok(());
    }
    let reason = "publication authority recovery refused";
    journal.failures.insert("recovery".into(), reason.into());
    append(
        &mut journal,
        json!({"type":"publication_refused","reason":reason}),
    )?;
    save(state_root, session, &journal)
}

fn failure(
    context: &Context,
    journal: &mut Journal,
    key: &str,
    category: &str,
) -> Result<(), String> {
    if journal
        .failures
        .get(key)
        .is_some_and(|previous| previous == category)
    {
        return Ok(());
    }
    journal.failures.insert(key.to_owned(), category.to_owned());
    // Never expose pod payloads, Git diagnostics, credentials, or ledger errors.
    append(
        journal,
        json!({"type":"publication_failed","reason":category}),
    )?;
    save(&context.state_root, &context.session, journal)
}

async fn run(
    context: Context,
    gate: Arc<Mutex<()>>,
    mut cancel: watch::Receiver<bool>,
) -> Result<(), String> {
    let mut journal = load(&context.state_root, &context.session)?;
    if Handle::current().runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        failure(
            &context,
            &mut journal,
            "runtime",
            "publication requires a multithread runtime",
        )?;
        return Err("publication requires a multithread runtime".into());
    }
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = cancel.changed() => return Ok(()),
            _ = interval.tick() => {}
        }
        if *cancel.borrow() {
            return Ok(());
        }
        let _guard = tokio::select! {
            biased;
            _ = cancel.changed() => return Ok(()),
            guard = gate.lock() => guard,
        };
        let client = match context.cell.client().await {
            Ok(client) => client,
            Err(_) => {
                failure(
                    &context,
                    &mut journal,
                    "transport",
                    "publication transport unavailable",
                )?;
                continue;
            }
        };
        let requests = match publication::discover(&client, &context.receipt).await {
            Ok(requests) => requests,
            Err(_) => {
                failure(
                    &context,
                    &mut journal,
                    "discovery",
                    "publication discovery failed",
                )?;
                continue;
            }
        };
        for request in requests {
            if *cancel.borrow() {
                return Ok(());
            }
            let key = blake3::hash(
                &serde_json::to_vec(&request).map_err(|_| "invalid publication request")?,
            )
            .to_hex()
            .to_string();
            let refusal_key = format!("refused:{key}");
            if journal.failures.contains_key(&refusal_key) {
                if publication::reject(&client, &context.receipt, &request)
                    .await
                    .is_err()
                {
                    failure(
                        &context,
                        &mut journal,
                        &key,
                        "publication refusal acknowledgement pending",
                    )?;
                }
                continue;
            }
            // Lend the executor thread back without detaching a blocking task:
            // quiescence still joins this task before freezing the pod.
            let result = tokio::task::block_in_place(|| {
                let candidate = publication::validate_candidate(
                    &context.receipt,
                    &context.project_root,
                    &context.project_id,
                    &context.session,
                    &context.state_root,
                    &request,
                )
                .map_err(|_| "publication candidate rejected")?;
                let admitted = publication_authority::request(&context.grant, &candidate)
                    .map_err(|_| "publication target rejected")?;
                // Every replay checks the current lease; committed replay
                // returns kernel evidence rather than invoking Git again.
                context
                    .grant
                    .run(admitted, || {
                        publication::perform(
                            &context.receipt,
                            &context.project_root,
                            &context.project_id,
                            &context.session,
                            &context.state_root,
                            &request,
                            &candidate,
                        )
                    })
                    .map_err(|_| "publication authority refused or effect uncertain")
            });
            let result = match result {
                Ok(result) => result,
                Err(category) => {
                    failure(&context, &mut journal, &refusal_key, category)?;
                    if publication::reject(&client, &context.receipt, &request)
                        .await
                        .is_err()
                    {
                        failure(
                            &context,
                            &mut journal,
                            &key,
                            "publication refusal acknowledgement pending",
                        )?;
                    }
                    continue;
                }
            };
            if !journal.results.contains_key(&key) {
                if let Some(events) = result["events"].as_array() {
                    for event in events {
                        append(&mut journal, event.clone())?;
                    }
                }
                journal.results.insert(key.clone(), result.clone());
                save(&context.state_root, &context.session, &journal)?;
            }
            if publication::acknowledge(&client, &context.receipt, &result)
                .await
                .is_err()
            {
                failure(
                    &context,
                    &mut journal,
                    &key,
                    "publication acknowledgement pending",
                )?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_cursor_is_independent_of_driver_cursor() {
        let mut journal = Journal::default();
        append(
            &mut journal,
            json!({"type":"branch_published","driver_cursor":77}),
        )
        .unwrap();
        append(&mut journal, json!({"type":"publication_failed"})).unwrap();
        assert_eq!(journal.events[0]["publication_cursor"], 1);
        assert_eq!(journal.events[1]["publication_cursor"], 2);
        assert!(journal.events[0].get("driver_cursor").is_none());
    }

    #[test]
    fn event_path_cannot_escape_session_directory() {
        assert!(path(Path::new("state"), "../escape").is_err());
        assert!(path(Path::new("state"), &uuid::Uuid::nil().to_string()).is_err());
    }

    #[test]
    fn durable_events_replay_without_new_cursor_or_side_effect() {
        let root = tempfile::tempdir().unwrap();
        let session = uuid::Uuid::new_v4().to_string();
        let mut journal = Journal::default();
        append(
            &mut journal,
            json!({"type":"branch_published","commit":"abc"}),
        )
        .unwrap();
        save(root.path(), &session, &journal).unwrap();
        let first = events(root.path(), &session).unwrap();
        assert_eq!(events(root.path(), &session).unwrap(), first);
        assert_eq!(first[0]["publication_cursor"], 1);
    }
}
