//! `Spend` over Huginn: `odin huginn spend` on any paired
//! host shows what the authority's model gateway spent per day, lane,
//! seat and pod workload — the same reading Sinmara's `spend.read` answers "what did this
//! week cost?" from. The authority also publishes today's reading as `Status/spend`, which
//! `odin view` shows instead of asking the gateway itself.

use std::sync::Arc;

use odin_domain::huginn as live;
use serde_json::Value;

fn cents(value: &Value, key: &str) -> u64 {
    let usd = value.get(key).and_then(Value::as_f64).unwrap_or(0.0);
    (usd * 100.0).round().max(0.0) as u64
}

fn line(row: &Value, label_key: &str) -> live::SpendLine {
    live::SpendLine {
        label: row
            .get(label_key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        usd_cents: cents(row, "usd"),
        included_cents: cents(row, "included_usd"),
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
        compute: summary
            .get("compute")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|row| {
                let mut line = line(row, "label");
                if let Some(source) = row.get("source").and_then(Value::as_str) {
                    line.label = format!("{} ({source})", line.label);
                }
                line
            })
            .collect(),
        untagged_usd_cents: summary
            .get("untagged_usd")
            .map(|usd| cents(&serde_json::json!({ "usd": usd }), "usd"))
            .unwrap_or(0),
        note: text("note"),
    }
}

pub(super) async fn read(
    gateway: Option<String>,
    request: live::SpendRequest,
    huginn_root: Option<&std::path::Path>,
) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
    let Some(gateway) = gateway else {
        tracing::error!("huginn spend read refused: hermes.model_gateway is not configured");
        return Err(live::HuginnProtocolError::unavailable(
            "spendUnavailable",
            "hermes.model_gateway is not configured",
        ));
    };
    if request.days == 0 || request.days > live::SPEND_MAX_DAYS {
        return Err(live::HuginnProtocolError::unavailable(
            "spendDaysOutOfRange",
            format!(
                "{} days is outside 1..={}",
                request.days,
                live::SPEND_MAX_DAYS
            ),
        ));
    }
    let days = i64::from(request.days);
    let mut summary = tokio::task::spawn_blocking(move || {
        odin_hermes::runtime::read_gateway_spend(&gateway, days)
    })
    .await
    .map_err(|error| live::HuginnProtocolError::unavailable("spendUnavailable", error))?
    .map_err(|error| {
        tracing::error!("huginn spend read failed days={days}: {error}");
        live::HuginnProtocolError::unavailable("spendUnavailable", error)
    })?;
    if let Some(root) = huginn_root {
        let usage = odin_registry::ComputeUsage::load(root)
            .map_err(|error| live::HuginnProtocolError::unavailable("spendUnavailable", error))?;
        let now_ms =
            u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                .unwrap_or(0);
        odin_hermes::runtime::append_compute(&mut summary, &usage, request.days.into(), now_ms);
    }
    Ok(live::HuginnResponse::Spend(view(&summary)))
}

/// The model board (`odin models`): the same reading `models.read` answers from.
pub(super) async fn models(
    gateway: Option<String>,
) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
    let gateway = gateway.ok_or_else(|| {
        live::HuginnProtocolError::unavailable(
            "modelsUnavailable",
            "hermes.model_gateway is not configured",
        )
    })?;
    tokio::task::spawn_blocking(move || odin_hermes::runtime::read_model_board(&gateway))
        .await
        .map_err(|error| live::HuginnProtocolError::unavailable("modelsUnavailable", error))?
        .map(live::HuginnResponse::Models)
        .map_err(|error| {
            tracing::error!("huginn models read failed: {error}");
            live::HuginnProtocolError::unavailable("modelsUnavailable", error)
        })
}

/// Today only: `odin view` reads the published object and shows today's seats, and a one-day pass
/// reads just the tags that spent today. Longer windows are read on request (`odin huginn spend`).
pub(super) const SPEND_PUBLISH_DAYS: u8 = 1;

/// A `Status` object of the read model.
pub(super) fn status_object(id: &str) -> live::ObjectRef {
    live::ObjectRef {
        kind: live::ObjectKind::Status,
        id: id.to_owned(),
    }
}

/// Encode spend as a Status object understood by Snapshot decoders.
fn spend_object() -> live::ObjectRef {
    status_object("spend")
}

/// Publishes the authority's gateway spend into the read model: the
/// existing [`read`] over the canonical window and the existing [`view`]
/// body, re-published only when the encoded digest changes. An unchanged
/// read is a no-op that never moves `subscribe_head`; the per-read
/// freshness timestamp lives on the snapshot metadata and never enters
/// the compared body. Returns whether the object changed.
pub(super) async fn publish(
    gateway: &str,
    read_model: &odin_huginn::read_model::MaterializedReadModel,
    observed_at: time::OffsetDateTime,
) -> Result<bool, String> {
    let response = read(
        Some(gateway.to_owned()),
        live::SpendRequest {
            days: SPEND_PUBLISH_DAYS,
        },
        None,
    )
    .await
    .map_err(|error| format!("spend read: {error}"))?;
    let body = match response {
        live::HuginnResponse::Spend(body) => body,
        other => return Err(format!("spend read: unexpected response {other:?}")),
    };
    publish_body(read_model, &body, observed_at)
}

fn publish_body(
    read_model: &odin_huginn::read_model::MaterializedReadModel,
    body: &live::SpendView,
    observed_at: time::OffsetDateTime,
) -> Result<bool, String> {
    let value = serde_json::to_value(body).map_err(|error| error.to_string())?;
    publish_status(read_model, spend_object(), value, observed_at)
}

/// The digest-gated upsert behind the spend and CI objects: a value identical to the current fresh
/// object is skipped; anything else — a cent, a token, a row, the note, a return from stale —
/// lands as the object's next revision.
pub(super) fn publish_status(
    read_model: &odin_huginn::read_model::MaterializedReadModel,
    object: live::ObjectRef,
    value: Value,
    observed_at: time::OffsetDateTime,
) -> Result<bool, String> {
    let current = read_model.get(&object).map_err(|error| error.to_string())?;
    if current.as_ref().is_some_and(|current| {
        current.value == value && current.freshness.state == live::FreshnessState::Fresh
    }) {
        return Ok(false);
    }
    upsert_status(
        read_model,
        object,
        current,
        value,
        live::FreshnessState::Fresh,
        observed_at,
    )?;
    Ok(true)
}

fn upsert_status(
    read_model: &odin_huginn::read_model::MaterializedReadModel,
    object: live::ObjectRef,
    current: Option<live::ObjectSnapshot>,
    value: Value,
    state: live::FreshnessState,
    observed_at: time::OffsetDateTime,
) -> Result<(), String> {
    let revision = current.map_or(1, |current| current.revision.get().saturating_add(1));
    let encoded = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    read_model
        .upsert(live::ObjectSnapshot {
            object,
            revision: live::Revision::new(revision),
            revision_source: live::RevisionSource::Kernel,
            freshness: live::Freshness {
                state,
                observed_at,
                source_updated_at: Some(observed_at),
                stale_after_seconds: None,
            },
            content_digest: odin_domain::Digest::hash(&encoded),
            value,
        })
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// A failed read keeps the last spend but no longer calls it fresh, so the view (which skips stale
/// objects) stops showing a figure the gateway has not confirmed.
fn mark_stale(read_model: &odin_huginn::read_model::MaterializedReadModel) -> Result<(), String> {
    let object = spend_object();
    let Some(current) = read_model.get(&object).map_err(|error| error.to_string())? else {
        return Ok(());
    };
    if current.freshness.state != live::FreshnessState::Fresh {
        return Ok(());
    }
    let (value, observed_at) = (current.value.clone(), current.freshness.observed_at);
    upsert_status(
        read_model,
        object,
        Some(current),
        value,
        live::FreshnessState::Stale,
        observed_at,
    )
}

/// Arms the spend pump: every 60 s the authority's `spend.read` summary for today is
/// re-read and republished into the read model as the `Status` object
/// id `spend` when its encoded digest changed (`odin view` reads it); an
/// unchanged read is a no-op that never moves `subscribe_head`, and a failed
/// read marks the object stale.
/// Only the authority has gateway spend; keep this slow read off the kube tick.
pub(super) fn arm_spend_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    posture: odin_huginn::NodePosture,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    gateway: Option<String>,
) {
    if posture == odin_huginn::NodePosture::Follower {
        tracing::warn!("follower posture: spend pump stays disarmed; no gateway spend of its own");
        return;
    }
    let Some(gateway) = gateway else {
        tracing::warn!("spend pump stays disarmed: hermes.model_gateway is not configured");
        return;
    };
    pumps.spawn(async move {
        /// How often today's gateway spend is read again.
        const SPEND_TICK: std::time::Duration = std::time::Duration::from_secs(60);
        let mut ticker = tokio::time::interval(SPEND_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) =
                publish(&gateway, &read_model, time::OffsetDateTime::now_utc()).await
            {
                tracing::error!("spend publication failed: {error}");
                if let Err(error) = mark_stale(&read_model) {
                    tracing::error!("spend object could not be marked stale: {error}");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn spend_view_shows_compute_rows_apart_from_models() {
        let view = super::view(&json!({"total": {"usd": 1.0},
            "compute": [{"label": "lease:box", "usd": 2.5, "source": "declared price"}]}));
        assert_eq!(view.total.usd_cents, 100);
        assert_eq!(view.compute[0].usd_cents, 250);
        assert_eq!(view.compute[0].label, "lease:box (declared price)");
    }

    #[test]
    fn a_spend_summary_reads_as_whole_cents_per_day_lane_seat_and_workload() {
        let summary = json!({
            "from": "2026-09-27", "to": "2026-10-03",
            "total": {"usd": 44.08, "tokens": 900u64, "requests": 617u64},
            "days": [{"date": "2026-10-03", "usd": 44.08, "tokens": 900u64, "requests": 617u64}],
            "lanes": [{"lane": "astra", "usd": 0.0, "included_usd": 40.53, "tokens": 800u64, "requests": 300u64}],
            "seats": [{"seat": "sinmara", "usd": 20.5, "tokens": 500u64, "requests": 40u64}],
            "workloads": [{"workload": "rig-readme-heading", "usd": 0.0, "tokens": 90u64, "requests": 3u64}],
            "untagged_usd": 23.58,
            "note": "subscription lanes cost no extra money",
        });
        let view = super::view(&summary);
        assert_eq!(view.total.usd_cents, 4408);
        assert_eq!(view.total.label, "total");
        assert_eq!(view.days[0].label, "2026-10-03");
        assert_eq!(view.lanes[0].label, "astra");
        assert_eq!(view.lanes[0].usd_cents, 0);
        assert_eq!(view.lanes[0].included_cents, 4053);
        assert_eq!(view.seats[0].label, "sinmara");
        assert_eq!(view.workloads[0].label, "rig-readme-heading");
        assert_eq!(view.workloads[0].requests, 3);
        assert_eq!(view.untagged_usd_cents, 2358);
        let unavailable = super::view(&json!({
            "note": "USD is the gateway's configured per-token price. Per-seat view unavailable: x."
        }));
        assert!(
            unavailable.seats.is_empty(),
            "an unreadable seat view is no rows"
        );
        assert!(unavailable.note.contains("Per-seat view unavailable: x"));
    }
    use super::{publish_body, spend_object, view};
    use odin_domain::huginn::RevisionSource;
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
            "workloads": [{"workload": "workload:rig", "usd": 1.25, "tokens": 5u64, "requests": 1u64}],
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
        assert!(matches!(snapshot.revision_source, RevisionSource::Kernel));
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

    /// A read that failed leaves the last spend in place as stale, once; the next good read — even an
    /// identical one — makes it fresh again.
    #[test]
    fn a_failed_read_marks_the_spend_stale_until_the_next_good_one() {
        use odin_domain::huginn::FreshnessState;
        let model = MaterializedReadModel::new(64, time::OffsetDateTime::now_utc());
        let now = time::OffsetDateTime::now_utc();
        super::mark_stale(&model).unwrap();
        assert!(
            model.get(&spend_object()).unwrap().is_none(),
            "nothing to mark yet"
        );
        assert!(publish_body(&model, &view(&summary()), now).unwrap());

        super::mark_stale(&model).unwrap();
        super::mark_stale(&model).unwrap();
        let stale = model.get(&spend_object()).unwrap().expect("exists");
        assert_eq!(stale.freshness.state, FreshnessState::Stale);
        assert_eq!(stale.revision.get(), 2, "marked once");
        assert_eq!(stale.value, serde_json::to_value(view(&summary())).unwrap());
        assert_eq!(
            stale.freshness.observed_at, now,
            "the last good read's time"
        );

        assert!(publish_body(&model, &view(&summary()), now).unwrap());
        let fresh = model.get(&spend_object()).unwrap().expect("exists");
        assert_eq!(fresh.freshness.state, FreshnessState::Fresh);
        assert_eq!(fresh.revision.get(), 3);
        assert!(!publish_body(&model, &view(&summary()), now).unwrap());
    }
}
