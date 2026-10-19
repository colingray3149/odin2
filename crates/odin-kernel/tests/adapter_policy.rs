//! Unhealthy or unknown adapters must be hidden from listings and rejected during
//! authorization, including with stale listings. Adapter-less capabilities are unaffected.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use odin_domain::knowledge::{ToolName, ToolSchema};
use odin_domain::{
    CapabilityId, CommandId, Digest, EffectClass, LaneId, PlanId, SeatId, SessionId, SliceId,
};
use odin_kernel::approval::ApprovalGate;
use odin_kernel::capability::{
    list_capabilities, AdapterHealth, ApprovalRequirement, AuthorizationRejection,
    CapabilityContract, HandlerBinding, IdempotencyPolicy, InvocationTarget, RetryPolicy,
    SchemaCatalog, ToolInvocation,
};
use odin_kernel::error::KernelResult;
use odin_kernel::policy::{
    arguments_digest, authorize, effective, AuthorizationOutcome, PlanGate, PolicyContext,
};
use odin_kernel::token::{
    ExpectedBindings, FreshAuthority, MemoryRevocations, MintRequest, TokenIssuer,
};
use odin_ledger::Ledger;
use serde_json::json;

const SEARCH: &str = "tool.search";
const LOCAL: &str = "tool.local";
const ADAPTER: &str = "web-search";
const KEY: &[u8] = b"adapter policy fixture signing key";
const NOW_MS: u64 = 20;

struct Schemas(ToolSchema);

impl SchemaCatalog for Schemas {
    fn schema(&self, _reference: &str) -> KernelResult<ToolSchema> {
        Ok(self.0.clone())
    }
}

fn contract(id: &str, tool: &str, adapter: Option<&str>) -> CapabilityContract {
    CapabilityContract {
        id: CapabilityId::new(id).unwrap(),
        delegate_to: None,
        version: 3,
        tool_name: ToolName::new(tool).unwrap(),
        description: format!("{id} fixture"),
        handler: HandlerBinding::Builtin {
            name: "write".to_owned(),
        },
        input_schema_ref: format!("schemas/capability/{tool}.input.json"),
        output_schema_ref: format!("schemas/capability/{tool}.output.json"),
        effect_class: EffectClass::R0,
        seat_tags: BTreeSet::from(["builder".to_owned()]),
        timeout_seconds: NonZeroU32::new(5).unwrap(),
        idempotency: IdempotencyPolicy::Pure,
        retry: RetryPolicy { max_attempts: 1 },
        approval: ApprovalRequirement::None,
        evidence_extractor: HandlerBinding::Builtin {
            name: "write_evidence".to_owned(),
        },
        adapter: adapter.map(str::to_owned),
        preview: None,
        batchable: false,
        batch: None,
    }
}

fn seat_authority() -> odin_kernel::token::SeatAuthority {
    let seat = SeatId::new("seat.one").unwrap();
    let slice = SliceId::new("slice.one").unwrap();
    let lane = LaneId::new("lane.one").unwrap();
    let session = SessionId::new("00000000-0000-4000-8000-000000000001").unwrap();
    let expected = ExpectedBindings {
        seat: &seat,
        slice: &slice,
        lane: &lane,
        session: &session,
        seat_revision: Digest::hash(b"seat"),
        slice_revision: Digest::hash(b"slice"),
        capability_policy_digest: Digest::hash(b"policy"),
        context_policy_digest: Digest::hash(b"context"),
    };
    let issuer = TokenIssuer::new(KEY.to_vec()).unwrap();
    let token = issuer
        .mint(MintRequest {
            seat: seat.clone(),
            slice: slice.clone(),
            lane: lane.clone(),
            session: session.clone(),
            seat_revision: expected.seat_revision,
            slice_revision: expected.slice_revision,
            capability_policy_digest: expected.capability_policy_digest,
            context_policy_digest: expected.context_policy_digest,
            issued_at_ms: 0,
            expires_at_ms: 1_000,
            entropy: b"entropy",
        })
        .unwrap();
    FreshAuthority::verify(
        &token,
        expected,
        KEY.to_vec(),
        MemoryRevocations::new(),
        NOW_MS,
    )
    .unwrap()
    .get()
    .clone()
}

struct Fixture {
    authority: odin_kernel::token::SeatAuthority,
    contracts: BTreeMap<CapabilityId, CapabilityContract>,
    schemas: Schemas,
}

impl Fixture {
    /// The adapter-backed `web.search` capability and one adapter-less
    /// builtin, both otherwise admissible for this seat.
    fn new() -> Self {
        let contracts = BTreeMap::from([
            (
                CapabilityId::new(SEARCH).unwrap(),
                contract(SEARCH, "tool_search", Some(ADAPTER)),
            ),
            (
                CapabilityId::new(LOCAL).unwrap(),
                contract(LOCAL, "tool_local", None),
            ),
        ]);
        Self {
            authority: seat_authority(),
            contracts,
            schemas: Schemas(ToolSchema::from_value(json!({"type": "object"})).unwrap()),
        }
    }

    fn context(&self, health: BTreeMap<String, bool>) -> PolicyContext {
        let allowed: BTreeSet<CapabilityId> = self.contracts.keys().cloned().collect();
        PolicyContext {
            seat_id: self.authority.seat().clone(),
            slice_id: self.authority.slice().clone(),
            lane_id: self.authority.lane().clone(),
            seat_revision: self.authority.seat_revision(),
            slice_revision: self.authority.slice_revision(),
            capability_policy_digest: self.authority.capability_policy_digest(),
            seat_tool_refs: allowed.clone(),
            slice_capabilities: allowed.clone(),
            project_capabilities: allowed.clone(),
            lane_capabilities: allowed,
            denied_capabilities: BTreeSet::new(),
            denied_tools: BTreeSet::new(),
            seat_categories: BTreeSet::from(["builder".to_owned()]),
            adapter_health: AdapterHealth::new(health),
            resource_constraints: BTreeMap::new(),
            seat_hints: BTreeMap::new(),
        }
    }

    fn listing(&self, context: &PolicyContext) -> odin_domain::knowledge::CapabilityListing {
        list_capabilities(
            &self.authority,
            context,
            &self.contracts,
            &self.schemas,
            NOW_MS,
        )
        .unwrap()
    }

    fn invocation(
        &self,
        capability: &str,
        listing_digest: odin_domain::knowledge::CapabilityListingDigest,
    ) -> ToolInvocation {
        let arguments = json!({"query": "odin kernel", "count": 3});
        ToolInvocation {
            command_id: CommandId::new("command.one").unwrap(),
            capability_id: CapabilityId::new(capability).unwrap(),
            capability_version: 3,
            listing_digest,
            arguments_digest: arguments_digest(&arguments),
            arguments,
            target: InvocationTarget {
                kind: "lane".to_owned(),
                id: "lane.one".to_owned(),
            },
            executor_binding: None,
            expected_revision: None,
            plan_id: Some(PlanId::new("plan.one").unwrap()),
            approval_id: None,
            resource: None,
        }
    }

    fn authorize(
        &self,
        context: &PolicyContext,
        listing: &odin_domain::knowledge::CapabilityListing,
        invocation: &ToolInvocation,
    ) -> AuthorizationOutcome {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let mut approvals = ApprovalGate::new(&mut ledger);
        authorize(
            odin_kernel::policy::AuthorizationEnvironment {
                authority: &self.authority,
                policy: context,
                contracts: &self.contracts,
                schemas: &self.schemas,
                listing,
            },
            invocation,
            PlanGate::Accepted,
            &mut approvals,
            NOW_MS,
        )
        .unwrap()
    }

    fn listed_ids(listing: &odin_domain::knowledge::CapabilityListing) -> Vec<String> {
        listing
            .tools
            .iter()
            .map(|tool| tool.capability_id.as_str().to_owned())
            .collect()
    }
}

#[test]
fn healthy_adapter_is_listed_and_authorizable() {
    let fixture = Fixture::new();
    let context = fixture.context(BTreeMap::from([(ADAPTER.to_owned(), true)]));
    let listing = fixture.listing(&context);
    assert_eq!(
        Fixture::listed_ids(&listing),
        vec![LOCAL.to_owned(), SEARCH.to_owned()]
    );
    let outcome = fixture.authorize(
        &context,
        &listing,
        &fixture.invocation(SEARCH, listing.digest),
    );
    assert!(
        matches!(outcome, AuthorizationOutcome::Authorized(_)),
        "a healthy adapter capability authorizes: {outcome:?}"
    );
}

#[test]
fn unknown_adapter_fails_closed_and_stale_listing_cannot_authorize() {
    let fixture = Fixture::new();
    let healthy = fixture.context(BTreeMap::from([(ADAPTER.to_owned(), true)]));
    let stale = fixture.listing(&healthy);

    // The health refresh comes back without any verdict for web-search:
    // unknown must close the capability exactly like unhealthy.
    let unknown = fixture.context(BTreeMap::from([("other-adapter".to_owned(), true)]));
    assert!(!effective(&unknown, &fixture.contracts).contains(&CapabilityId::new(SEARCH).unwrap()));
    assert!(
        !unknown.is_capability_effective(&CapabilityId::new(SEARCH).unwrap(), &fixture.contracts)
    );
    let refreshed = fixture.listing(&unknown);
    assert_eq!(Fixture::listed_ids(&refreshed), vec![LOCAL.to_owned()]);

    // A listing issued while healthy cannot bypass the refreshed adapter policy.
    let outcome = fixture.authorize(&unknown, &stale, &fixture.invocation(SEARCH, stale.digest));
    assert_eq!(
        outcome,
        AuthorizationOutcome::Rejected(AuthorizationRejection::Unavailable {
            capability_id: CapabilityId::new(SEARCH).unwrap(),
            reason: "capability is outside the current effective policy".to_owned(),
        })
    );
}

#[test]
fn explicitly_unhealthy_adapter_is_omitted() {
    let fixture = Fixture::new();
    let context = fixture.context(BTreeMap::from([(ADAPTER.to_owned(), false)]));
    assert!(effective(&context, &fixture.contracts).contains(&CapabilityId::new(LOCAL).unwrap()));
    assert!(!effective(&context, &fixture.contracts).contains(&CapabilityId::new(SEARCH).unwrap()));
    let listing = fixture.listing(&context);
    assert_eq!(Fixture::listed_ids(&listing), vec![LOCAL.to_owned()]);
}

#[test]
fn adapter_less_capability_is_unaffected_by_adapter_health() {
    let fixture = Fixture::new();
    // Empty health snapshot: every adapter is unknown, yet the builtin
    // capability must remain fully available.
    let context = fixture.context(BTreeMap::new());
    let listing = fixture.listing(&context);
    assert_eq!(Fixture::listed_ids(&listing), vec![LOCAL.to_owned()]);
    let outcome = fixture.authorize(
        &context,
        &listing,
        &fixture.invocation(LOCAL, listing.digest),
    );
    assert!(
        matches!(outcome, AuthorizationOutcome::Authorized(_)),
        "an adapter-less capability authorizes regardless of adapter health: {outcome:?}"
    );
}

#[test]
fn recovery_requires_a_fresh_listing_and_restores_availability() {
    let fixture = Fixture::new();
    let unknown = fixture.context(BTreeMap::new());
    let unavailable = fixture.listing(&unknown);

    // The actual health refresh flips web-search back to healthy.
    let recovered = fixture.context(BTreeMap::from([(ADAPTER.to_owned(), true)]));
    let fresh = fixture.listing(&recovered);
    assert_eq!(
        Fixture::listed_ids(&fresh),
        vec![LOCAL.to_owned(), SEARCH.to_owned()]
    );
    // Availability changes the listing digest.
    assert_ne!(fresh.digest, unavailable.digest);

    let outcome = fixture.authorize(
        &recovered,
        &fresh,
        &fixture.invocation(SEARCH, fresh.digest),
    );
    assert!(
        matches!(outcome, AuthorizationOutcome::Authorized(_)),
        "recovery authorizes through a fresh listing: {outcome:?}"
    );
    // The stale unavailable-era digest must NEVER authorize. Both
    // rejections are the contract — the kernel may name it stale (the
    // listing no longer matches the recomputed effective set) or
    // unavailable (the capability left the effective set) — so no
    // precedence between them is pinned here.
    let stale = fixture.authorize(
        &recovered,
        &unavailable,
        &fixture.invocation(SEARCH, unavailable.digest),
    );
    assert!(
        matches!(stale, AuthorizationOutcome::Rejected(_)),
        "the stale unavailable-era listing must never authorize: {stale:?}"
    );
    // The fresh recomputed digest is the ONLY thing that authorizes
    // after the real health recovery.
    let recovered_outcome = fixture.authorize(
        &recovered,
        &fresh,
        &fixture.invocation(SEARCH, fresh.digest),
    );
    assert!(
        matches!(recovered_outcome, AuthorizationOutcome::Authorized(_)),
        "the fresh recomputed digest authorizes after recovery: {recovered_outcome:?}"
    );
    // The old digest keeps failing on repeat attempts.
    let stale_again = fixture.authorize(
        &recovered,
        &unavailable,
        &fixture.invocation(SEARCH, unavailable.digest),
    );
    assert!(
        matches!(stale_again, AuthorizationOutcome::Rejected(_)),
        "the stale digest keeps rejecting after recovery: {stale_again:?}"
    );
}
