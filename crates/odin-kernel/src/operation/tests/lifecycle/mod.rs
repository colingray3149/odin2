//! Independent lifecycle model checked against the authorization pipeline and ledger.

use super::*;

/// Inside every fixture token's lifetime (`expires_at_ms` is 1_000).
const LC_VERIFY_NOW: u64 = 500;

const LC_SESSION_ONE: &str = "00000000-0000-4000-8000-000000000001";
const LC_SESSION_TWO: &str = "00000000-0000-4000-8000-000000000002";

mod authority;
mod closure;
mod fate;

/// One authority presentation: the owning identity at a token generation,
/// or a foreign seat / foreign session presenting strictly newer issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Presenter {
    Owner(u64),
    ForeignSeat,
    ForeignSession,
}

impl Presenter {
    fn seat(self) -> &'static str {
        match self {
            Presenter::Owner(_) | Presenter::ForeignSession => "seat.one",
            Presenter::ForeignSeat => "seat.two",
        }
    }

    fn session(self) -> &'static str {
        match self {
            Presenter::Owner(_) | Presenter::ForeignSeat => LC_SESSION_ONE,
            Presenter::ForeignSession => LC_SESSION_TWO,
        }
    }

    fn generation(self) -> u64 {
        match self {
            Presenter::Owner(generation) => generation,
            Presenter::ForeignSeat | Presenter::ForeignSession => 300,
        }
    }

    fn tag(self) -> String {
        match self {
            Presenter::Owner(generation) => format!("owner@{generation}"),
            Presenter::ForeignSeat => "foreign-seat".to_owned(),
            Presenter::ForeignSession => "foreign-session".to_owned(),
        }
    }
}

/// An open presenter's generation is the lease's recorded issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseModel {
    Absent,
    Open { bound: Presenter },
    Closed { close_mode: &'static str },
}

struct ModelRow {
    creator: Presenter,
    state: EffectState,
    evidence: Option<String>,
    landed: bool,
}

struct Model {
    lease: LeaseModel,
    rows: BTreeMap<String, ModelRow>,
    usage: BTreeMap<&'static str, (u64, u64, u64)>,
    rebind_events: usize,
    stops: BTreeMap<String, &'static str>,
    files: BTreeMap<String, String>,
    executions: u64,
}

impl Default for Model {
    fn default() -> Self {
        Self {
            lease: LeaseModel::Absent,
            rows: BTreeMap::new(),
            usage: BTreeMap::new(),
            rebind_events: 0,
            stops: BTreeMap::new(),
            files: BTreeMap::new(),
            executions: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvokeModel {
    Decided {
        state: EffectState,
        replay: bool,
    },
    CapsuleAuthorityMismatch,
    CapsuleClosed,
    /// The rotation was blocked by unresolved rows in the capsule.
    CapsuleBlocked {
        pending: u64,
    },
}

impl Model {
    /// Fresh correlations use lease admission; replays use the existing operation row.
    fn apply_invoke(
        &mut self,
        presenter: Presenter,
        correlation_id: &str,
        path: &str,
        content: &str,
    ) -> InvokeModel {
        match self.lease {
            // Closed is terminal: the lease gate refuses every presenter
            // before any authority comparison.
            LeaseModel::Closed { .. } => InvokeModel::CapsuleClosed,
            LeaseModel::Absent => {
                // Any verified authority may open a fresh capsule: first
                // presenter wins, and its generation is the recorded
                // issuance.
                self.lease = LeaseModel::Open { bound: presenter };
                self.dispatch_new(presenter, correlation_id, path, content)
            }
            LeaseModel::Open { bound }
                if bound.seat() == presenter.seat() && bound.session() == presenter.session() =>
            {
                if bound.generation() < presenter.generation() {
                    // A strictly newer same-identity generation rotates the
                    // lease — unless unresolved rows block it, in which case
                    // nothing moves and nothing is charged.
                    let pending = self.pending_count();
                    if pending > 0 {
                        return InvokeModel::CapsuleBlocked { pending };
                    }
                    self.lease = LeaseModel::Open { bound: presenter };
                    self.rebind_events += 1;
                    self.dispatch_new(presenter, correlation_id, path, content)
                } else if bound.generation() == presenter.generation() {
                    // An identical token reuses the lease without another event.
                    match self.rows.get_mut(correlation_id) {
                        Some(row) => {
                            // Exact replay drives the durable row: terminal
                            // rows replay their state, nonterminal rows
                            // settle from evidence, without re-execution.
                            let settled = lc_settle_law(row.state, row.landed);
                            row.state = settled;
                            InvokeModel::Decided {
                                state: settled,
                                replay: true,
                            }
                        }
                        None => self.dispatch_new(presenter, correlation_id, path, content),
                    }
                } else {
                    // Older generations cannot replace the lease.
                    InvokeModel::CapsuleAuthorityMismatch
                }
            }
            // Foreign seat or session, whatever its recency.
            LeaseModel::Open { .. } => InvokeModel::CapsuleAuthorityMismatch,
        }
    }

    /// Model one charge, one execution, and committed output for a fresh invocation.
    fn dispatch_new(
        &mut self,
        presenter: Presenter,
        correlation_id: &str,
        path: &str,
        content: &str,
    ) -> InvokeModel {
        self.files.insert(path.to_owned(), content.to_owned());
        self.record_row(
            correlation_id,
            ModelRow {
                creator: presenter,
                state: EffectState::Committed,
                evidence: Some(receipt_digest(content).to_string()),
                landed: true,
            },
        );
        InvokeModel::Decided {
            state: EffectState::Committed,
            replay: false,
        }
    }

    /// Prepared rows incur a request charge but no execution.
    fn record_row(&mut self, correlation_id: &str, row: ModelRow) {
        if !matches!(row.state, EffectState::Prepared) {
            self.executions += 1;
        }
        let entry = self.usage.entry(row.creator.session()).or_insert((0, 0, 0));
        entry.0 += 1;
        self.rows.insert(correlation_id.to_owned(), row);
    }

    /// Unresolved rows in the capsule: they block every rotation.
    fn pending_count(&self) -> u64 {
        self.rows
            .values()
            .filter(|row| row.state.is_nonterminal())
            .count() as u64
    }
}

/// Predicts settlement from durable state and whether the effect reached the world.
fn lc_settle_law(state: EffectState, landed: bool) -> EffectState {
    match state {
        EffectState::Committed | EffectState::Aborted => state,
        // A prepared row never dispatched: it aborts without any effect.
        EffectState::Prepared => EffectState::Aborted,
        // Observed output commits; absence aborts without creating output evidence.
        EffectState::InDoubt if landed => EffectState::Committed,
        EffectState::InDoubt => EffectState::Aborted,
        // No row stays effect_started outside a live dispatch here: every
        // scenario's dispatch settles synchronously.
        EffectState::EffectStarted => {
            unreachable!("effect_started rows cannot be produced by these scenarios")
        }
    }
}

/// Opaque production identities pinned at first observation: the lease
/// token may move only with a modeled generation change, the close record
/// never moves at all, and an operation's identity fields never move.
#[derive(Default)]
struct Shadow {
    lease_token: Option<String>,
    lease_generation: Option<u64>,
    close_record: Option<(Option<String>, i64)>,
    rows: BTreeMap<String, RowIdentity>,
}

#[derive(Clone)]
struct RowIdentity {
    operation_id: String,
    token_id: String,
    request_digest: String,
    binding_digest: String,
    prepared_binding: String,
}

/// Uses the presenter's seat for both token verification and policy authorization.
fn lc_invoke(
    fixture: &Fixture,
    presenter: Presenter,
    correlation_id: &CorrelationId,
    path: &str,
    content: &str,
) -> Result<OperationDecision, OperationRejection> {
    let mut context = fixture.context.clone();
    context.seat_id = SeatId::new(presenter.seat()).expect("fixture seat id");
    let authorized = authorize_invocation(
        proof_with(
            presenter.seat(),
            presenter.session(),
            b"policy",
            presenter.generation(),
            LC_VERIFY_NOW,
        ),
        &arguments_at(path, content),
        LC_VERIFY_NOW,
        "command.one",
        &fixture.contracts,
        &context,
        fixture.schemas.as_ref(),
    );
    fixture
        .authority
        .invoke_authorized(authorized, &invoke_request(correlation_id, 1))
}

/// Identical arguments mint the same token so each generation can replay.
fn lc_owner_proof(generation: u64) -> FreshAuthority {
    proof_with(
        "seat.one",
        LC_SESSION_ONE,
        b"policy",
        generation,
        LC_VERIFY_NOW,
    )
}

fn lc_expect_decided(
    expected: InvokeModel,
    outcome: &Result<OperationDecision, OperationRejection>,
    label: &str,
) {
    let decision = outcome
        .as_ref()
        .unwrap_or_else(|error| panic!("{label}: expected {expected:?}, got {error:?}"));
    match expected {
        InvokeModel::Decided { state, replay } => {
            assert_eq!(decision.state, state, "{label}: decision state");
            assert_eq!(decision.replay, replay, "{label}: decision replay flag");
        }
        other => panic!("{label}: expected {other:?}, got {decision:?}"),
    }
}

fn lc_expect_err(
    expected: InvokeModel,
    outcome: &Result<OperationDecision, OperationRejection>,
    label: &str,
) {
    let error = outcome
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("{label}: expected {expected:?}, got a decision"));
    match (expected, error) {
        (
            InvokeModel::CapsuleAuthorityMismatch,
            OperationRejection::CapsuleAuthorityMismatch { .. },
        )
        | (InvokeModel::CapsuleClosed, OperationRejection::CapsuleClosed { .. }) => {}
        (
            InvokeModel::CapsuleBlocked { pending },
            OperationRejection::CapsuleBlocked { blocked, .. },
        ) if *blocked == pending => {}
        (expected, error) => panic!("{label}: expected {expected:?}, got {error:?}"),
    }
}

/// Checks lease identity, operation rows, usage, stop intents, rebind events, and world state.
fn lc_verify(fixture: &Fixture, model: &Model, shadow: &mut Shadow, label: &str) {
    let ledger = fixture.authority.lock_store().expect("ledger lock");
    let connection = ledger.connection();

    let lease = store::lease_row(connection, CAPSULE).expect("lease read");
    match model.lease {
        LeaseModel::Absent => {
            assert!(
                lease.is_none(),
                "{label}: no lease may exist, got {lease:?}"
            );
        }
        LeaseModel::Open { bound } => {
            let lease = lease.unwrap_or_else(|| panic!("{label}: open lease must exist"));
            assert_eq!(lease.state, "open", "{label}: lease state");
            assert_eq!(lease.seat_id, bound.seat(), "{label}: lease seat");
            assert_eq!(lease.session_id, bound.session(), "{label}: lease session");
            assert_eq!(
                lease.token_issued_at_ms,
                Some(bound.generation()),
                "{label}: lease recorded issuance"
            );
            match shadow.lease_generation {
                Some(pinned) if pinned == bound.generation() => assert_eq!(
                    shadow.lease_token.as_deref(),
                    Some(lease.token_id.as_str()),
                    "{label}: lease token moved without a modeled rotation"
                ),
                // Only rotation to a newer generation may change the lease token.
                _ => shadow.lease_token = Some(lease.token_id.clone()),
            }
            shadow.lease_generation = Some(bound.generation());
        }
        LeaseModel::Closed { close_mode } => {
            let lease = lease.unwrap_or_else(|| panic!("{label}: closed lease must exist"));
            assert_eq!(lease.state, "closed", "{label}: lease state");
            assert_eq!(
                lease.close_mode.as_deref(),
                Some(close_mode),
                "{label}: close mode"
            );
            let record = (lease.close_mode.clone(), lease.drained);
            match &shadow.close_record {
                None => shadow.close_record = Some(record),
                Some(pinned) => assert_eq!(
                    pinned, &record,
                    "{label}: the close record is immutable under later closes"
                ),
            }
        }
    }

    // Both fixture sessions are exact: an unmodeled charge on the other
    // session fails even though no modeled row names it.
    for session in [LC_SESSION_ONE, LC_SESSION_TWO] {
        let usage = store::usage(connection, session).expect("usage read");
        let modeled = model.usage.get(session).copied().unwrap_or_default();
        assert_eq!(
            (usage.requests, usage.stops, usage.spend),
            modeled,
            "{label}: usage for {session}"
        );
    }

    // The durable operation set is EXACTLY the modeled set: an extra row a
    // refusal committed, and a committed row that vanished, both fail.
    for (correlation_id, row) in &model.rows {
        let durable = store::operation_row(connection, correlation_id)
            .expect("operation row read")
            .unwrap_or_else(|| panic!("{label}: operation {correlation_id} must exist"));
        assert_eq!(
            durable.effect_state, row.state,
            "{label}: {correlation_id} state"
        );
        assert_eq!(
            durable.evidence_digest, row.evidence,
            "{label}: {correlation_id} evidence"
        );
        assert_eq!(
            durable.capsule_id, CAPSULE,
            "{label}: {correlation_id} capsule"
        );
        assert_eq!(
            durable.seat_id,
            row.creator.seat(),
            "{label}: {correlation_id} seat"
        );
        assert_eq!(
            durable.session_id,
            row.creator.session(),
            "{label}: {correlation_id} session"
        );
        let identity = shadow
            .rows
            .entry(correlation_id.clone())
            .or_insert_with(|| RowIdentity {
                operation_id: durable.operation_id.clone(),
                token_id: durable.token_id.clone(),
                request_digest: durable.request_digest.clone(),
                binding_digest: durable.binding_digest.clone(),
                prepared_binding: durable.prepared_binding.clone(),
            });
        assert_eq!(
            identity.operation_id, durable.operation_id,
            "{label}: {correlation_id} operation identity is immutable"
        );
        assert_eq!(
            identity.token_id, durable.token_id,
            "{label}: {correlation_id} token binding is immutable"
        );
        assert_eq!(
            identity.request_digest, durable.request_digest,
            "{label}: {correlation_id} request identity is immutable"
        );
        assert_eq!(
            identity.binding_digest, durable.binding_digest,
            "{label}: {correlation_id} binding identity is immutable"
        );
        assert_eq!(
            identity.prepared_binding, durable.prepared_binding,
            "{label}: {correlation_id} prepared binding is immutable"
        );
    }
    let total_operations: i64 = connection
        .query_row("SELECT COUNT(*) FROM operation_journal", [], |row| {
            row.get(0)
        })
        .expect("operation count");
    assert_eq!(
        total_operations,
        model.rows.len() as i64,
        "{label}: the durable operation set is exactly the modeled set"
    );

    let nonterminal = store::nonterminal_rows(connection, None).expect("nonterminal read");
    let mut modeled_nonterminal: Vec<&String> = model
        .rows
        .iter()
        .filter(|(_, row)| row.state.is_nonterminal())
        .map(|(correlation_id, _)| correlation_id)
        .collect();
    let mut durable_nonterminal: Vec<&String> =
        nonterminal.iter().map(|row| &row.correlation_id).collect();
    modeled_nonterminal.sort_unstable();
    durable_nonterminal.sort_unstable();
    assert_eq!(
        modeled_nonterminal, durable_nonterminal,
        "{label}: nonterminal set"
    );

    // The durable stop set is EXACTLY the modeled set.
    for (correlation_id, state) in &model.stops {
        let stop = store::stop_row(connection, correlation_id)
            .expect("stop row read")
            .unwrap_or_else(|| panic!("{label}: stop intent {correlation_id} must exist"));
        assert_eq!(stop.state, *state, "{label}: stop intent {correlation_id}");
    }
    let total_stops: i64 = connection
        .query_row("SELECT COUNT(*) FROM stop_intent", [], |row| row.get(0))
        .expect("stop count");
    assert_eq!(
        total_stops,
        model.stops.len() as i64,
        "{label}: the durable stop set is exactly the modeled set"
    );

    assert_eq!(
        rebind_events(&ledger),
        model.rebind_events,
        "{label}: durable rebind events"
    );

    let files = fixture
        .world
        .files
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(*files, model.files, "{label}: world files");
    drop(files);
    assert_eq!(
        fixture.world.executions.load(Ordering::SeqCst),
        model.executions,
        "{label}: world executions"
    );
}
