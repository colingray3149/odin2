//! Lane wall budget decision for a new delegated child.

use odin_domain::LaneId;

use super::{DelegationLink, GovernedTaskOwner, TaskToolFailure};

impl GovernedTaskOwner {
    /// The lane's declared `[limits]`, or empty when this owner has no registry pin. A missing pin does not invent a budget.
    pub(in crate::host_tools::delegation) fn declared_lane_limits(
        &self,
        lane: &LaneId,
    ) -> Result<odin_registry::LaneLimitsToml, TaskToolFailure> {
        let Some(pin) = &self.governance.registry else {
            return Ok(odin_registry::LaneLimitsToml::default());
        };
        let snapshot = pin.current();
        let Some(odin_registry::ObjectConfig::Lane(declared)) = snapshot
            .object(odin_registry::RegistryKind::Lane, lane.as_str())
            .map(|object| &object.config)
        else {
            return Err(TaskToolFailure::new(
                "lane_undeclared",
                format!("lane {lane} has no lane declaration; its budget cannot be read"),
            ));
        };
        Ok(declared.limits.clone())
    }

    /// Refuses a new child once a live worker of this lane has already
    /// filled the effective wall cap (the declaration, or a typed raise
    /// above it). A lane that declares no wall admits.
    pub(in crate::host_tools::delegation) fn admit_lane_wall(
        &self,
        lane: &LaneId,
    ) -> Result<(), TaskToolFailure> {
        let declared = self.declared_lane_limits(lane)?;
        let rows = self
            .links
            .all_rows()
            .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?;
        let raised = odin_registry::RaisedLaneBudgets::load(self.links.huginn_root())
            .map_err(|error| TaskToolFailure::new("lane_budget_unreadable", error))?;
        let stored = raised.as_ref().and_then(|raised| {
            raised.effective(
                lane.as_str(),
                odin_registry::LaneBudgetKind::WallSeconds.declared(&declared),
                odin_registry::LaneBudgetKind::WallSeconds,
            )
        });
        lane_wall_refusal(
            lane,
            &declared,
            rows.iter().map(|row| &row.link),
            stored,
            Self::clock_ms(),
        )
    }
}

pub(super) fn lane_wall_refusal<'a>(
    lane: &LaneId,
    declared: &odin_registry::LaneLimitsToml,
    links: impl Iterator<Item = &'a DelegationLink>,
    stored_cap: Option<u32>,
    now_ms: u64,
) -> Result<(), TaskToolFailure> {
    let mut budget = odin_registry::LaneBudget::declared(declared);
    let mut oldest = None;
    for link in links {
        if link.lane.as_ref() != Some(lane) {
            continue;
        }
        if !link.phase.is_live() {
            continue;
        }
        for raise in &link.budget_raises {
            if raise.kind == odin_registry::LaneBudgetKind::WallSeconds {
                let _ = budget.raise(declared, *raise);
            }
        }
        oldest = Some(oldest.unwrap_or(u64::MAX).min(link.created_at_ms));
    }
    let Some(started) = oldest else {
        return Ok(());
    };
    // The recorded raises and the store can each only lift; the effective
    // cap is the highest of declaration, row history and store.
    let cap = stored_cap
        .map(|stored| stored.max(budget.wall_seconds.unwrap_or(0)))
        .or(budget.wall_seconds);
    let Some(cap) = cap else {
        return Ok(());
    };
    let elapsed = now_ms.saturating_sub(started) / 1_000;
    let used = u32::try_from(elapsed).unwrap_or(u32::MAX);
    odin_registry::at_cap(odin_registry::LaneBudgetKind::WallSeconds, Some(cap), used).map_err(
        |detail| {
            TaskToolFailure::new(
                "exact_limit",
                format!("lane {lane} wall budget refused: {detail}"),
            )
        },
    )
}

#[cfg(test)]
mod lane_wall_tests {
    use odin_domain::huginn::LiveSessionId;
    use odin_domain::{CommandId, Digest, LaneId, ProjectId, RunId, SessionId};

    use super::lane_wall_refusal;
    use crate::host_tools::delegation::links::{
        DelegationLink, DelegationPhase, DELEGATION_LINK_SCHEMA,
    };
    fn limits(wall_seconds: u32) -> odin_registry::LaneLimitsToml {
        odin_registry::LaneLimitsToml {
            wall_seconds: std::num::NonZeroU32::new(wall_seconds),
            ..odin_registry::LaneLimitsToml::default()
        }
    }

    fn link(
        lane: Option<&str>,
        phase: DelegationPhase,
        created_at_ms: u64,
        raises: Vec<odin_registry::LaneBudgetRaise>,
    ) -> DelegationLink {
        DelegationLink {
            schema: DELEGATION_LINK_SCHEMA.to_owned(),
            child: LiveSessionId::new(
                uuid::Uuid::parse_str("00000000-0000-4000-8000-0000000000b1").expect("child UUID"),
            )
            .expect("child session"),
            parent: SessionId::new("00000000-0000-4000-8000-0000000000a1").expect("parent session"),
            parent_seat: None,
            parent_run: RunId::new("run:parent").expect("parent run"),
            child_run: RunId::new("run:live:child").expect("child run"),
            command: CommandId::new("odin.task.create:test").expect("command"),
            project: ProjectId::new("project.odin").expect("project"),
            lane: lane.map(|lane| LaneId::new(lane).expect("lane id")),
            provider: "gateway".to_owned(),
            model: "glm-flash".to_owned(),
            prompt_digest: Digest::hash(b"prompt"),
            assignment: String::new(),
            rollover_admissions: 0,
            depth: 1,
            phase,
            created_at_ms,
            learning_capture_sequence: None,
            escalated_to: None,
            escalation_open: false,
            learning_result_sequence: None,
            learning_proposal_id: None,
            stall_retries: 0,
            stalls: Vec::new(),
            switched_to: None,
            handled_stall_event: None,
            refusals: Vec::new(),
            gateway_fallbacks: Vec::new(),
            reported_answer: None,
            pending_report: None,
            budget_raises: raises,
        }
    }

    fn wall_raise(seconds: u32) -> odin_registry::LaneBudgetRaise {
        odin_registry::LaneBudgetRaise {
            kind: odin_registry::LaneBudgetKind::WallSeconds,
            value: seconds,
        }
    }

    #[test]
    fn a_spent_window_refuses_the_next_child_and_names_the_limit() {
        let lane = LaneId::new("gungnir-odin").expect("lane");
        let now = 10_000_000;
        let rows = [
            link(
                Some("gungnir-odin"),
                DelegationPhase::Running,
                now - 700_000,
                Vec::new(),
            ),
            // A younger sibling does not close the window the oldest opened.
            link(
                Some("gungnir-odin"),
                DelegationPhase::Running,
                now - 60_000,
                Vec::new(),
            ),
        ];
        let refused = lane_wall_refusal(&lane, &limits(600), rows.iter(), None, now)
            .expect_err("window spent");
        assert_eq!(refused.kind, "exact_limit");
        assert!(
            refused.detail.contains(odin_registry::WALL_LIMIT_KEY),
            "{refused:?}"
        );
        assert!(refused.detail.contains("600"), "{refused:?}");
    }

    #[test]
    fn a_typed_raise_lifts_the_refusal_whether_recorded_or_stored() {
        let lane = LaneId::new("gungnir-odin").expect("lane");
        let now = 10_000_000;
        let old = now - 700_000;
        let spent = [link(
            Some("gungnir-odin"),
            DelegationPhase::Running,
            old,
            Vec::new(),
        )];
        assert!(lane_wall_refusal(&lane, &limits(600), spent.iter(), Some(3_600), now).is_ok());
        let recorded = [link(
            Some("gungnir-odin"),
            DelegationPhase::Running,
            old,
            vec![wall_raise(3_600)],
        )];
        assert!(lane_wall_refusal(&lane, &limits(600), recorded.iter(), None, now).is_ok());
        // The store never lowers a recorded raise.
        let both = [link(
            Some("gungnir-odin"),
            DelegationPhase::Running,
            old,
            vec![wall_raise(3_600)],
        )];
        assert!(lane_wall_refusal(&lane, &limits(600), both.iter(), Some(700), now).is_ok());
    }
}
