//! `odind archive backfill`: embeds a published archive generation in place
//! through the declared gateway lane.

use super::*;

pub(crate) fn run_backfill(
    args: ArchiveBackfillArgs,
    output: &mut dyn Write,
) -> Result<(), String> {
    // Backfill moves the persisted publication to model-bound vectors: no
    // prepare stream, no demand disposition.
    let state = setup(&args.config_args.config, &args.source)?;
    let mut seats = Vec::new();
    for (seat, policy) in state.composition.authorized_seats(&state.source) {
        // The lane owns the raw parts of this declared route: the lease
        // coordinator, its ledger, and its transport are single-owner by
        // construction (the daemon's executor binds its own composition),
        // so every seat's lane composes its own and its request ids are
        // its own.
        let lease_lane = state
            .composition
            .config
            .lane_bindings
            .iter()
            .filter(|binding| binding.seat == seat)
            .map(|binding| binding.lane.clone())
            .min()
            .ok_or_else(|| {
                format!("seat {seat} declares no session lane to lease the backfill under")
            })?;
        let parts = served_embedding_parts(
            &state.composition.config,
            &state.composition.snapshot,
            &lease_lane,
            &mut |name| std::env::var(name).ok(),
        )?
        .ok_or_else(|| {
            "no embedding route is declared for this controller, so the archive keeps \
             serving keyword-only"
                .to_owned()
        })?;
        let embedding_model = parts.model.clone();
        let brain = state.composition.open_brain(
            &seat,
            &policy,
            &state.ledger,
            Some(embedding_model.clone()),
        )?;
        let mut lane = GatewayBatchLane {
            provider: parts.provider,
            coordinator: parts.coordinator,
            ledger: parts.ledger,
            transport: parts.transport,
            protocol: parts.protocol,
            request_counter: 0,
        };
        let report = brain
            .backfill_archive_embeddings(
                &ArchiveEmbeddingBackfillRequest {
                    source: state.source.clone(),
                    embedding_model,
                    batch_size: args.batch_size,
                    max_batches: args.max_batches,
                    until: args.until,
                },
                &mut lane,
            )
            .map_err(|error| format!("embedding backfill failed: {error}"))?;
        seats.push(seat_backfill_report(&seat, &report));
    }
    let mut report = setup_report(&state, "backfilled");
    report.seats = Some(seats);
    write_report(output, &report)
}

fn seat_backfill_report(seat: &SeatId, report: &ArchiveEmbeddingBackfillReport) -> SeatReport {
    let outcome = match &report.outcome {
        ArchiveBackfillOutcome::Embedded => serde_json::json!({ "kind": "embedded" }),
        ArchiveBackfillOutcome::Pending { reason, pending } => serde_json::json!({
            "kind": "pending",
            "reason": reason,
            "pending": pending,
        }),
    };
    SeatReport {
        seat: seat.as_str().to_owned(),
        material: serde_json::json!({
            "vectorsEmbedded": report.vectors_embedded,
            "generation": report.generation.generation_id.to_string(),
            "embeddingModel": report.embedding_model.as_str(),
            "outcome": outcome,
        }),
    }
}

/// The declared gateway lane the archive backfill embeds through: one
/// kernel-lease-governed batch per call over the composed provider
/// identity. The brain names the lane contract; this wiring supplies the
/// existing executor port — the brain never contacts a provider directly.
struct GatewayBatchLane {
    provider: ProviderId,
    coordinator: ProviderLeaseCoordinator,
    ledger: Ledger,
    transport: PrivateGatewayTransport,
    /// The resolved route's declared embedding protocol; the brain's
    /// `embed` seam applies it once for every backfill batch, exactly as it
    /// does for serving queries.
    protocol: Option<EmbeddingProtocolToml>,
    request_counter: u64,
}

impl EmbeddingBatchLane for GatewayBatchLane {
    fn embed_batch(
        &mut self,
        texts: &[String],
    ) -> odin_brain::error::BrainResult<Vec<EmbeddingVector>> {
        self.request_counter += 1;
        let request_id = format!(
            "archive-backfill-{}-{}",
            self.provider.as_str(),
            self.request_counter
        );
        let output = embed(
            &self.provider,
            &mut self.coordinator,
            &mut self.ledger,
            EmbedBatch {
                request_id: &request_id,
                inputs: texts,
                protocol: self.protocol.as_ref(),
                now: OffsetDateTime::now_utc(),
            },
            &mut self.transport,
        )?;
        Ok(output.vectors)
    }
}
