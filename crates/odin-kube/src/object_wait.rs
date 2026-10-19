//! Waits on one named object through a field-selected watch instead of a
//! GET every second: a list gives the current state and the resume point,
//! the watch delivers each change, a `410 Gone` or a closed session lists
//! again. The caller's bound covers the whole wait.

use std::fmt::Debug;
use std::time::Duration;

use futures_util::StreamExt;
use kube::api::{ListParams, WatchEvent, WatchParams};
use kube::{Api, Resource};
use serde::de::DeserializeOwned;

use crate::client::KubeError;

/// One decision over the object's observed state (`None`: absent).
pub(crate) enum Settle<T> {
    Wait,
    Done(T),
    Fail(KubeError),
}

/// Watches `name` until `decide` settles, or fails `Unavailable` with
/// `timeout_reason` once `bound` passes.
pub(crate) async fn wait_for<K, T>(
    api: &Api<K>,
    name: &str,
    bound: Duration,
    timeout_reason: impl FnOnce() -> String,
    mut decide: impl FnMut(Option<&K>) -> Settle<T>,
) -> Result<T, KubeError>
where
    K: Resource + Clone + DeserializeOwned + Debug + Send + 'static,
{
    let field = format!("metadata.name={name}");
    let wait = async {
        loop {
            let listing = api.list(&ListParams::default().fields(&field)).await?;
            match decide(listing.items.first()) {
                Settle::Wait => {}
                Settle::Done(value) => return Ok(value),
                Settle::Fail(error) => return Err(error),
            }
            let from = listing.metadata.resource_version.unwrap_or_default();
            let mut session = api
                .watch(&WatchParams::default().fields(&field), &from)
                .await?
                .boxed();
            while let Some(event) = session.next().await {
                let observed = match event? {
                    WatchEvent::Added(object) | WatchEvent::Modified(object) => {
                        decide(Some(&object))
                    }
                    WatchEvent::Deleted(_) => decide(None),
                    WatchEvent::Bookmark(_) => Settle::Wait,
                    WatchEvent::Error(_) => break,
                };
                match observed {
                    Settle::Wait => {}
                    Settle::Done(value) => return Ok(value),
                    Settle::Fail(error) => return Err(error),
                }
            }
        }
    };
    tokio::time::timeout(bound, wait)
        .await
        .map_err(|_| KubeError::unavailable(timeout_reason()))?
}
