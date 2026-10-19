//! `Spend` over Huginn: `odin huginn spend` on any paired
//! host shows what the authority's model gateway spent per day, lane,
//! seat and pod workload — the same reading Sinmara's `spend.read` answers "what did this
//! week cost?" from.

use std::sync::Arc;

use odin_domain::huginn as live;
use serde_json::Value;

fn cents(value: &Value) -> u64 {
    let usd = value.get("usd").and_then(Value::as_f64).unwrap_or(0.0);
    (usd * 100.0).round().max(0.0) as u64
}

fn line(row: &Value, label_key: &str) -> live::SpendLine {
    live::SpendLine {
        label: row
            .get(label_key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        usd_cents: cents(row),
        tokens: row.get("tokens").and_then(Value::as_u64).unwrap_or(0),
        requests: row.get("requests").and_then(Value::as_u64).unwrap_or(0),
    }
}

fn lines(summary: &Value, key: &str, label_key: &str) -> Vec<live::SpendLine> {
    summary
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|row| line(row, label_key))
        .collect()
}

pub(super) fn view(summary: &Value) -> live::SpendView {
    let text = |key: &str| {
        summary
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let mut total = line(summary.get("total").unwrap_or(&Value::Null), "label");
    total.label = "total".to_owned();
    live::SpendView {
        from: text("from"),
        to: text("to"),
        total,
        days: lines(summary, "days", "date"),
        lanes: lines(summary, "lanes", "lane"),
        seats: lines(summary, "seats", "seat"),
        workloads: lines(summary, "workloads", "workload"),
        untagged_usd_cents: summary
            .get("untagged_usd")
            .map(|usd| cents(&serde_json::json!({ "usd": usd })))
            .unwrap_or(0),
        note: text("note"),
    }
}

pub(super) async fn read(
    request: live::SpendRequest,
) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
    if request.days == 0 || request.days > live::SPEND_MAX_DAYS {
        return Err(live::HuginnProtocolError::Unavailable {
            code: "spendDaysOutOfRange".to_owned(),
        });
    }
    let days = i64::from(request.days);
    let summary =
        tokio::task::spawn_blocking(move || odin_hermes::runtime::read_gateway_spend(days))
            .await
            .map_err(|_| live::HuginnProtocolError::Unavailable {
                code: "spendUnavailable".to_owned(),
            })?
            .map_err(|error| {
                tracing::error!("huginn spend read failed days={days}: {error}");
                live::HuginnProtocolError::Unavailable {
                    code: "spendUnavailable".to_owned(),
                }
            })?;
    Ok(live::HuginnResponse::Spend(view(&summary)))
}

/// Match the gateway spend tool's default weekly window.
pub(super) const SPEND_PUBLISH_DAYS: u8 = 7;

/// Encode spend as a Status object understood by Snapshot decoders.
fn spend_object() -> live::ObjectRef {
    live::ObjectRef {
        kind: live::ObjectKind::Status,
        id: "spend".to_owned(),
    }
}

/// Publishes the authority's gateway spend into the read model: the
/// existing [`read`] over the canonical window and the existing [`view`]
/// body, re-published only when the encoded digest changes. An unchanged
/// read is a no-op that never moves `subscribe_head`; the per-read
/// freshness timestamp lives on the snapshot metadata and never enters
/// the compared body. Returns whether the object changed.
pub(super) async fn publish(
    read_model: &odin_huginn::read_model::MaterializedReadModel,
    observed_at: time::OffsetDateTime,
) -> Result<bool, String> {
    let response = read(live::SpendRequest {
        days: SPEND_PUBLISH_DAYS,
    })
    .await
    .map_err(|error| format!("spend read: {error}"))?;
    let body = match response {
        live::HuginnResponse::Spend(body) => body,
        other => return Err(format!("spend read: unexpected response {other:?}")),
    };
    publish_body(read_model, &body, observed_at)
}

/// The digest-gated upsert behind [`publish`]: a body identical to the
/// current `spend` object is skipped; anything else — a cent, a token,
/// a row, the note — lands as the object's next revision.
fn publish_body(
    read_model: &odin_huginn::read_model::MaterializedReadModel,
    body: &live::SpendView,
    observed_at: time::OffsetDateTime,
) -> Result<bool, String> {
    let value = serde_json::to_value(body).map_err(|error| error.to_string())?;
    let object = spend_object();
    let current = read_model.get(&object).map_err(|error| error.to_string())?;
    if current
        .as_ref()
        .is_some_and(|current| current.value == value)
    {
        return Ok(false);
    }
    let revision = current.map_or(1, |current| current.revision.get().saturating_add(1));
    let encoded = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    read_model
        .upsert(live::ObjectSnapshot {
            object,
            revision: live::Revision::new(revision),
            revision_source: live::RevisionSource::Ledger,
            freshness: live::Freshness {
                state: live::FreshnessState::Fresh,
                observed_at,
                source_updated_at: Some(observed_at),
                stale_after_seconds: None,
            },
            content_digest: odin_domain::Digest::hash(&encoded),
            value,
        })
        .map_err(|error| error.to_string())?;
    Ok(true)
}

/// Arms the spend pump: every 60 s the authority's `spend.read` summary is
/// re-read and republished into the read model as the `Status` object
/// id `spend` when its encoded digest changed (`odin huginn spend`); an
/// unchanged read is a no-op that never moves `subscribe_head`.
/// Only the authority has gateway spend; keep this slow read off the kube tick.
pub(super) fn arm_spend_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    posture: odin_huginn::NodePosture,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
) {
    if posture == odin_huginn::NodePosture::Follower {
        tracing::warn!("follower posture: spend pump stays disarmed; no gateway spend of its own");
        return;
    }
    pumps.spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) = publish(&read_model, time::OffsetDateTime::now_utc()).await {
                tracing::error!("spend publication failed: {error}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn a_spend_summary_reads_as_whole_cents_per_day_lane_seat_and_workload() {
        let summary = json!({
            "from": "2026-09-27", "to": "2026-10-03",
            "total": {"usd": 44.08, "tokens": 900u64, "requests": 617u64},
            "days": [{"date": "2026-10-03", "usd": 44.08, "tokens": 900u64, "requests": 617u64}],
            "lanes": [{"lane": "astra", "usd": 40.53, "tokens": 800u64, "requests": 300u64}],
            "seats": [{"seat": "sinmara", "usd": 20.5, "tokens": 500u64, "requests": 40u64}],
            "workloads": [{"workload": "surtr-readme-heading", "usd": 0.0, "tokens": 90u64, "requests": 3u64}],
            "untagged_usd": 23.58,
            "note": "subscription lanes cost no extra money",
        });
        let view = super::view(&summary);
        assert_eq!(view.total.usd_cents, 4408);
        assert_eq!(view.total.label, "total");
        assert_eq!(view.days[0].label, "2026-10-03");
        assert_eq!(view.lanes[0].label, "astra");
        assert_eq!(view.lanes[0].usd_cents, 4053);
        assert_eq!(view.seats[0].label, "sinmara");
        assert_eq!(view.workloads[0].label, "surtr-readme-heading");
        assert_eq!(view.workloads[0].requests, 3);
        assert_eq!(view.untagged_usd_cents, 2358);
        let unavailable = super::view(&json!({"seats": "per-seat view unavailable: x"}));
        assert!(
            unavailable.seats.is_empty(),
            "an unreadable seat view is no rows"
        );
    }
    use super::{publish_body, spend_object, view};
    use odin_domain::huginn::{ObjectDeltaBody, Revision, RevisionSource};
    use odin_huginn::read_model::MaterializedReadModel;

    /// Whole cents, busiest lanes first, with seat and workload attribution.
    fn summary() -> serde_json::Value {
        json!({
            "from": "2026-09-27", "to": "2026-10-03",
            "total": {"usd": 29.7, "tokens": 21598438u64, "requests": 109526u64},
            "days": [
                {"date": "2026-10-02", "usd": 0.01, "tokens": 100u64, "requests": 1u64},
                {"date": "2026-10-03", "usd": 29.69, "tokens": 21598338u64, "requests": 109525u64},
            ],
            "lanes": [
                {"lane": "astra", "usd": 26.96, "tokens": 9000000u64, "requests": 300u64},
                {"lane": "openai/WeMM-Embedding-2B", "usd": 0.05, "tokens": 9057271u64, "requests": 109000u64},
            ],
            "seats": [{"seat": "seat:kubert", "usd": 2.5, "tokens": 10u64, "requests": 2u64}],
            "workloads": [{"workload": "workload:surtr", "usd": 1.25, "tokens": 5u64, "requests": 1u64}],
            "untagged_usd": 0.19,
            "note": "USD is each lane's declared API list price applied to its tokens",
        })
    }

    #[test]
    fn first_publish_mints_the_spend_object_at_revision_one_and_notifies_the_head() {
        let model = MaterializedReadModel::new(64, time::OffsetDateTime::now_utc());
        let mut head = model.subscribe_head().unwrap();
        let changed =
            publish_body(&model, &view(&summary()), time::OffsetDateTime::now_utc()).unwrap();
        assert!(changed);
        let snapshot = model
            .get(&spend_object())
            .unwrap()
            .expect("the spend object exists");
        assert_eq!(snapshot.revision.get(), 1);
        assert!(matches!(snapshot.revision_source, RevisionSource::Ledger));
        assert_eq!(
            snapshot.value,
            serde_json::to_value(view(&summary())).unwrap()
        );
        assert!(
            head.has_changed().unwrap(),
            "the first publish notifies subscribe_head"
        );
        assert_eq!(*head.borrow_and_update(), 1);
    }

    /// Freshness belongs to snapshot metadata, not the content digest.
    #[test]
    fn unchanged_spend_does_not_move_the_head() {
        let model = MaterializedReadModel::new(64, time::OffsetDateTime::now_utc());
        let mut head = model.subscribe_head().unwrap();
        let observed = time::OffsetDateTime::now_utc();
        assert!(publish_body(&model, &view(&summary()), observed).unwrap());
        head.borrow_and_update();

        let mut reread = summary();
        reread["generated"] = json!("2026-10-06T12:00:00Z");
        let later = observed + time::Duration::minutes(1);
        assert!(!publish_body(&model, &view(&reread), later).unwrap());
        assert!(
            !head.has_changed().unwrap(),
            "an unchanged read never notifies subscribe_head"
        );
        assert_eq!(
            model
                .get(&spend_object())
                .unwrap()
                .expect("exists")
                .revision
                .get(),
            1
        );
    }

    /// A real content change — one cent — lands as the object's next
    /// revision, the whole view as a Replace delta: the digest skip never
    /// loses a change.
    #[test]
    fn a_changed_summary_lands_the_next_revision_as_a_replace_of_the_whole_view() {
        let model = MaterializedReadModel::new(64, time::OffsetDateTime::now_utc());
        let mut head = model.subscribe_head().unwrap();
        assert!(publish_body(&model, &view(&summary()), time::OffsetDateTime::now_utc()).unwrap());
        head.borrow_and_update();

        let mut pricier = summary();
        pricier["total"]["usd"] = json!(29.71);
        let expected = serde_json::to_value(view(&pricier)).unwrap();
        assert!(publish_body(&model, &view(&pricier), time::OffsetDateTime::now_utc()).unwrap());
        assert!(
            head.has_changed().unwrap(),
            "a real change notifies subscribe_head"
        );
        assert_eq!(*head.borrow_and_update(), 2);

        let snapshot = model.get(&spend_object()).unwrap().expect("exists");
        assert_eq!(snapshot.revision.get(), 2);
        assert_eq!(snapshot.value, expected);
        let batch = model.deltas_after(Revision::new(1)).unwrap();
        assert_eq!(batch.deltas.len(), 1);
        assert_eq!(batch.deltas[0].object, spend_object());
        assert_eq!(batch.deltas[0].to_revision.get(), 2);
        assert!(matches!(
            &batch.deltas[0].body,
            ObjectDeltaBody::Replace(body) if *body == expected
        ));
    }
}
