use std::collections::{BTreeMap, BTreeSet};

use crate::schema::{
    CapabilityToml, LaneDirection, LaneToml, PayloadKind, RegistryObject, SeatConversationToml,
    SeatToml, SliceToml,
};
use crate::RegistryFinding;

use super::paths::relation_failure;

/// Restrict declaration-changing capabilities to owner-facing conversation seats.
pub(super) fn validate_creation_holder(
    object: &RegistryObject,
    seat: &SeatToml,
    findings: &mut Vec<RegistryFinding>,
) {
    if seat.conversation.is_some() {
        return;
    }
    for capability in &seat.tool_refs {
        if crate::CREATION_CAPABILITIES.contains(&capability.as_str()) {
            findings.push(relation_failure(
                object,
                format!(
                    "tool_refs entry {:?} creates kernel declarations; only the owner-facing \
                     conversation seat may hold it",
                    capability.as_str()
                ),
            ));
        }
    }
}

/// Reject unavailable seat tools at publication; composition also checks the actual seat-to-slice mapping.
pub(super) fn validate_seat_tools(
    object: &RegistryObject,
    seat: &SeatToml,
    capabilities: &BTreeMap<&str, &CapabilityToml>,
    slices: &[&SliceToml],
    findings: &mut Vec<RegistryFinding>,
) {
    if !seat.enabled {
        return;
    }
    for entry in seat.tools.iter().flat_map(|tools| &tools.always) {
        if !seat
            .tool_refs
            .iter()
            .any(|capability| crate::schema::always_covers(entry, capability.as_str()))
        {
            findings.push(relation_failure(
                object,
                format!("[tools] always entry {entry:?} covers none of the seat's tool_refs"),
            ));
        }
    }
    for capability_id in &seat.tool_refs {
        let id = capability_id.as_str();
        // A missing capability is already a reference failure.
        let Some(capability) = capabilities.get(id) else {
            continue;
        };
        let problem = if !capability.enabled {
            Some("names a disabled capability".to_owned())
        } else if !capability.seat_tags.contains("*")
            && seat
                .categories
                .iter()
                .all(|category| !capability.seat_tags.contains(category.as_str()))
        {
            Some(format!(
                "is not admitted for this seat's categories {:?} (capability seat_tags {:?})",
                seat.categories, capability.seat_tags
            ))
        } else if !slices
            .iter()
            .any(|slice| slice.enabled && slice.capabilities.contains(capability_id))
        {
            Some("is granted by no enabled slice".to_owned())
        } else {
            None
        };
        if let Some(problem) = problem {
            findings.push(relation_failure(
                object,
                format!("tool_refs entry {id:?} {problem}"),
            ));
        }
    }
}

pub(super) fn validate_brain_scope(
    object: &RegistryObject,
    seat: &SeatToml,
    findings: &mut Vec<RegistryFinding>,
) {
    let scopes: BTreeSet<&str> = seat
        .brain_scope
        .iter()
        .map(|scope| scope.as_str())
        .collect();
    for scope in &scopes {
        if !crate::schema::valid_brain_scope(scope) {
            findings.push(relation_failure(
                object,
                format!(
                    "brain_scope entry {scope:?} must name an atlas.* subtree, an archive \
                     export, memory.<seat>, or a supported state source"
                ),
            ));
        }
    }
    let Some(knowledge) = &seat.knowledge else {
        return;
    };
    let sources: BTreeSet<&str> = knowledge
        .atlas_sources
        .iter()
        .map(|source| source.as_str())
        .collect();
    for scope in scopes.difference(&sources) {
        findings.push(relation_failure(
            object,
            format!(
                "brain_scope subtree {scope:?} has no matching knowledge.atlas_sources reference"
            ),
        ));
    }
    for source in sources.difference(&scopes) {
        findings.push(relation_failure(
            object,
            format!("knowledge.atlas_sources entry {source:?} is outside brain_scope"),
        ));
    }
}

pub(super) fn validate_seat_lane(
    object: &RegistryObject,
    field: &str,
    lane_id: &str,
    direction: LaneDirection,
    payload: PayloadKind,
    lanes: &BTreeMap<&str, &LaneToml>,
    findings: &mut Vec<RegistryFinding>,
) {
    let Some(lane) = lanes.get(lane_id) else {
        let message = format!("{field} references missing lane {lane_id:?}");
        if !object.enabled() && lanes.is_empty() {
            findings.push(RegistryFinding::flag(
                "registry-forward-reference",
                &object.relative_config,
                message,
            ));
        } else {
            findings.push(relation_failure(object, message));
        }
        return;
    };
    if lane.direction != Some(direction) || lane.payload_kind != Some(payload) {
        findings.push(relation_failure(
            object,
            format!(
                "{field} requires direction={direction:?} payload={payload:?}, but {lane_id:?} declares direction={:?} payload_kind={:?}",
                lane.direction, lane.payload_kind
            ),
        ));
    }
}

/// Resolve delegation to an enabled live seat without hardcoding seat or capability names.
pub(super) fn validate_delegation_target(
    object: &RegistryObject,
    capability: &CapabilityToml,
    seats: &BTreeMap<&str, &SeatToml>,
    findings: &mut Vec<RegistryFinding>,
) {
    let Some(target) = &capability.delegate_to else {
        return;
    };
    let Some(seat) = seats.get(target.as_str()) else {
        findings.push(relation_failure(
            object,
            format!("delegate_to references missing seat {:?}", target.as_str()),
        ));
        return;
    };
    if !seat.enabled {
        findings.push(relation_failure(
            object,
            format!(
                "delegate_to {:?} references a disabled seat",
                target.as_str()
            ),
        ));
    }
    if seat.live.is_none() {
        findings.push(relation_failure(
            object,
            format!(
                "delegate_to {:?} requires a target seat with a declared live plane",
                target.as_str()
            ),
        ));
    }
}

/// Resolve conversation delegation through the index so declaration order cannot change the target.
pub(super) fn validate_conversation_ask_capability(
    object: &RegistryObject,
    conversation: &SeatConversationToml,
    capabilities: &BTreeMap<&str, &CapabilityToml>,
    findings: &mut Vec<RegistryFinding>,
) {
    let ask = conversation.ask_capability.as_str();
    let Some(capability) = capabilities.get(ask) else {
        findings.push(relation_failure(
            object,
            format!("conversation.ask_capability {ask:?} references missing capability"),
        ));
        return;
    };
    if !capability.enabled {
        findings.push(relation_failure(
            object,
            format!("conversation.ask_capability {ask:?} references a disabled capability"),
        ));
    }
    if !capability.is_implemented() {
        findings.push(relation_failure(
            object,
            format!("conversation.ask_capability {ask:?} references an unimplemented capability"),
        ));
    }
    if capability
        .delegate_to
        .as_ref()
        .is_none_or(|seat| seat.as_str() != object.id)
    {
        findings.push(relation_failure(
            object,
            format!(
                "conversation.ask_capability {ask:?} must delegate to the declaring seat {:?}, found {:?}",
                object.id,
                capability.delegate_to.as_ref().map(|seat| seat.as_str()),
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use crate::relational::fixtures::{
        ask_capability_object, ask_schema_root, capability_mut, conversation_findings, fixture_set,
        lane_fixtures, project_object, seat_mut, seat_object, seat_object_named, with_delegate_to,
    };
    use crate::relational::validate;
    use crate::relational::RelationContext;
    use crate::schema::{BuiltinHandlerToml, HandlerBindingToml, RegistryObject};

    use super::*;

    #[test]
    fn declaration_permutations_preserve_exact_conversation_authority() {
        fn permutations(
            objects: &mut [RegistryObject],
            index: usize,
            check: &mut impl FnMut(&[RegistryObject]),
        ) {
            if index == objects.len() {
                check(objects);
                return;
            }
            for next in index..objects.len() {
                objects.swap(index, next);
                permutations(objects, index + 1, check);
                objects.swap(index, next);
            }
        }

        let root = ask_schema_root();
        let context = RelationContext::new(&root);
        let mut infrastructure = lane_fixtures();
        for (id, path, config) in [
            (
                "control",
                "registry/hosts/control/host.toml",
                crate::schema::ObjectConfig::Host(Box::new(
                    toml::from_str(
                        r#"schema = "odin.registry.v1"
kind = "host"
enabled = true
description = "permutation fixture"
hardware = "fixture"
role = "control"
tailscale = "fixture-control"
enrolled = true
"#,
                    )
                    .unwrap(),
                )),
            ),
            (
                "control",
                "registry/nodes/control/node.toml",
                crate::schema::ObjectConfig::Node(Box::new(
                    toml::from_str(
                        r#"schema = "odin.registry.v1"
kind = "node"
enabled = true
description = "permutation fixture"
host = "control"
role = "control"
capabilities = []
allow_workloads = false
authoritative_state = true
"#,
                    )
                    .unwrap(),
                )),
            ),
            (
                "model",
                "registry/providers/model/provider.toml",
                crate::schema::ObjectConfig::Provider(Box::new(
                    toml::from_str(
                        r#"schema = "odin.registry.v1"
kind = "provider"
enabled = true
description = "permutation fixture"
adapter = "fixture"
policy = { routes = [] }
recovery = { allowed_rungs = ["escalate"], blocked_missing_decision = "operator decision required", max_attempts = { retry = 1, restart_worker = 1, checkpoint = 1, rehome = 1, escalate = 1 }, cooldown_seconds = { retry = 0, restart_worker = 0, checkpoint = 0, rehome = 0, escalate = 0 } }
"#,
                    )
                    .unwrap(),
                )),
            ),
        ] {
            infrastructure.push(RegistryObject {
                id: id.to_owned(),
                relative_config: path.into(),
                config,
            });
        }
        let conversation = |capability: &str| {
            format!(
                "conversation = {{ project = \"fixture\", ask_capability = \"{capability}\", guidance = \"Speak plainly.\", answer_timeout_seconds = 240 }}"
            )
        };
        let baseline = vec![
            project_object(true),
            seat_object(&conversation("ask.owner"), true),
            seat_object_named("second", &conversation("ask.second"), true),
            ask_capability_object("ask.owner", "fixture"),
            ask_capability_object("ask.second", "second"),
        ];
        for fault in 0..4 {
            let mut declarations = baseline.clone();
            match fault {
                0 => {}
                // A different enabled seat exists; it must not silently
                // substitute for the exact owner declared by conversation.
                1 => with_delegate_to(&mut declarations[3], "second"),
                2 => seat_mut(&mut declarations[2]).enabled = false,
                3 => declarations[0] = project_object(false),
                _ => unreachable!(),
            }
            permutations(&mut declarations, 0, &mut |ordered| {
                let mut objects = infrastructure.clone();
                objects.extend_from_slice(ordered);
                let failures: Vec<_> = validate(&objects, &context)
                    .into_iter()
                    .filter(|finding| finding.is_failure())
                    .collect();
                assert_eq!(
                    failures.is_empty(),
                    fault == 0,
                    "declaration order changed exact admission for fault {fault}: {failures:?}"
                );
            });
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A declared conversation binds exactly one enabled in-scope project;
    /// missing or disabled references fail closed relationally. No
    /// identity is involved: this seat is a generic fixture seat.
    #[test]
    fn conversation_binds_one_enabled_in_scope_project() {
        let conversation =
            "conversation = { project = \"fixture\", ask_capability = \"seat.ask.fixture\", guidance = \"Speak plainly.\", answer_timeout_seconds = 240 }";
        let in_scope = fixture_set(project_object(true), seat_object(conversation, true));
        let findings = conversation_findings(&in_scope);
        assert!(
            findings.is_empty(),
            "a valid conversation must validate cleanly: {findings:?}"
        );

        let mut missing = lane_fixtures();
        missing.push(ask_capability_object("seat.ask.fixture", "fixture"));
        missing.push(seat_object(conversation, true));
        let findings = conversation_findings(&missing);
        assert!(findings.iter().any(|finding| finding.is_failure()
            && finding
                .message
                .contains("conversation.project references missing project")));

        let disabled = fixture_set(project_object(false), seat_object(conversation, true));
        let findings = conversation_findings(&disabled);
        assert!(findings.iter().any(|finding| finding.is_failure()
            && finding.message
                == "conversation.project \"fixture\" references a disabled project"));

        let elsewhere =
            "conversation = { project = \"elsewhere\", ask_capability = \"seat.ask.fixture\", guidance = \"Speak plainly.\", answer_timeout_seconds = 240 }";
        let unregistered = fixture_set(project_object(true), seat_object(elsewhere, true));
        let findings = conversation_findings(&unregistered);
        assert!(findings.iter().any(|finding| finding.is_failure()
            && finding
                .message
                .contains("conversation.project references missing project \"elsewhere\"")));
        assert!(findings.iter().any(|finding| finding.is_failure()
            && finding.message == "conversation.project \"elsewhere\" must be listed in the seat's project_scope"));

        // Resolving a project reference does not grant access outside the seat scope.
        let outsider: RegistryObject = {
            let mut object = project_object(true);
            object.id = "elsewhere".to_owned();
            object.relative_config = PathBuf::from("registry/projects/elsewhere/project.toml");
            object
        };
        let out_of_scope = fixture_set(outsider, seat_object(elsewhere, true));
        let findings = conversation_findings(&out_of_scope);
        assert!(findings.iter().any(|finding| finding.is_failure()
            && finding.message == "conversation.project \"elsewhere\" must be listed in the seat's project_scope"));
        assert!(!findings.iter().any(|finding| finding
            .message
            .contains("references missing project \"elsewhere\"")));
    }

    /// A conversation vehicle rides the live plane; a seat without one
    /// cannot own a standing conversation.
    #[test]
    fn conversation_requires_the_live_plane() {
        let conversation =
            "conversation = { project = \"fixture\", ask_capability = \"seat.ask.fixture\", guidance = \"Speak plainly.\", answer_timeout_seconds = 240 }";
        let findings = conversation_findings(&fixture_set(
            project_object(true),
            seat_object(conversation, false),
        ));
        assert!(findings.iter().any(|finding| finding.is_failure()
            && finding.message == "conversation requires the seat to declare its live plane"));
    }

    /// Absence means not conversation-owned: no conversation findings, and
    /// reference checks must hold regardless of declaration order because
    /// every index is built before any relation runs.
    #[test]
    fn conversation_references_are_declaration_order_independent() {
        let conversation =
            "conversation = { project = \"fixture\", ask_capability = \"seat.ask.fixture\", guidance = \"Speak plainly.\", answer_timeout_seconds = 240 }";
        let mut seat_first = lane_fixtures();
        seat_first.push(seat_object(conversation, true));
        seat_first.push(ask_capability_object("seat.ask.fixture", "fixture"));
        seat_first.push(project_object(true));
        let mut project_first = lane_fixtures();
        project_first.push(project_object(true));
        project_first.push(ask_capability_object("seat.ask.fixture", "fixture"));
        project_first.push(seat_object(conversation, true));
        let seat_first_findings = conversation_findings(&seat_first);
        let project_first_findings = conversation_findings(&project_first);
        assert_eq!(seat_first_findings, project_first_findings);
        assert!(seat_first_findings.is_empty(), "{seat_first_findings:?}");

        let plain = fixture_set(project_object(true), seat_object("", true));
        let findings = conversation_findings(&plain);
        assert!(
            findings.is_empty(),
            "a seat without conversation is not conversation-owned: {findings:?}"
        );

        // The same broken declaration must fail identically whichever way
        // the declarations are ordered.
        let mut seat_first = lane_fixtures();
        seat_first.push(seat_object(conversation, true));
        seat_first.push(ask_capability_object("seat.ask.fixture", "fixture"));
        seat_first.push(project_object(false));
        let mut project_first = lane_fixtures();
        project_first.push(project_object(false));
        project_first.push(ask_capability_object("seat.ask.fixture", "fixture"));
        project_first.push(seat_object(conversation, true));
        let seat_first_findings = conversation_findings(&seat_first);
        let project_first_findings = conversation_findings(&project_first);
        assert_eq!(seat_first_findings, project_first_findings);
        assert!(
            seat_first_findings
                .iter()
                .any(|finding| finding.message.contains("references a disabled project")),
            "the failing order check must carry the disabled-project failure"
        );
    }

    /// A conversation's ask capability is one exact published delegation
    /// edge: the reference must resolve to an enabled implemented capability
    /// whose `delegate_to` is exactly the declaring seat, whatever the
    /// capability and seat are named.
    #[test]
    fn conversation_ask_capability_binds_exactly_one_delegation_edge() {
        let conversation =
            "conversation = { project = \"fixture\", ask_capability = \"seat.ask.fixture\", guidance = \"Speak plainly.\", answer_timeout_seconds = 240 }";

        // The exact edge validates cleanly.
        let findings = conversation_findings(&fixture_set(
            project_object(true),
            seat_object(conversation, true),
        ));
        assert!(
            findings.is_empty(),
            "the exact ask edge must validate: {findings:?}"
        );

        // Unknown reference fails closed.
        let missing = conversation.replace("seat.ask.fixture", "seat.ask.absent");
        let findings = conversation_findings(&fixture_set(
            project_object(true),
            seat_object(&missing, true),
        ));
        assert!(findings.iter().any(|finding| finding.is_failure()
            && finding.message.contains(
                "conversation.ask_capability \"seat.ask.absent\" references missing capability"
            )));

        // Mismatched ownership: the referenced capability delegates elsewhere.
        let mut mismatched = fixture_set(project_object(true), seat_object(conversation, true));
        with_delegate_to(
            mismatched
                .iter_mut()
                .find(|object| object.id == "seat.ask.fixture")
                .expect("ask capability fixture"),
            "elsewhere",
        );
        let findings = conversation_findings(&mismatched);
        assert!(findings.iter().any(|finding| finding.is_failure()
            && finding
                .message
                .contains("must delegate to the declaring seat \"fixture\"")));

        // Disabled and unimplemented targets fail closed.
        let mut disabled = fixture_set(project_object(true), seat_object(conversation, true));
        capability_mut(
            disabled
                .iter_mut()
                .find(|object| object.id == "seat.ask.fixture")
                .expect("ask capability fixture"),
        )
        .enabled = false;
        let findings = conversation_findings(&disabled);
        assert!(findings.iter().any(|finding| finding.is_failure()
            && finding.message.contains("references a disabled capability")));

        let mut unimplemented = fixture_set(project_object(true), seat_object(conversation, true));
        capability_mut(
            unimplemented
                .iter_mut()
                .find(|object| object.id == "seat.ask.fixture")
                .expect("ask capability fixture"),
        )
        .implementation = Some("unimplemented".to_owned());
        let findings = conversation_findings(&unimplemented);
        assert!(findings.iter().any(|finding| finding.is_failure()
            && finding
                .message
                .contains("references an unimplemented capability")));
    }

    /// The published delegation target is judged relationally — it must
    /// exist, be enabled, and declare the live plane — under arbitrary
    /// names, and resolution must not depend on declaration order.
    #[test]
    fn delegation_target_must_be_an_enabled_live_seat() {
        let root = ask_schema_root();
        let context = RelationContext::new(&root);
        // The full registry-wide invariants (node authority, provider
        // availability) are other layers' contracts; this test judges only
        // findings located at the delegation's own declarations.
        let relevant = |findings: Vec<RegistryFinding>| -> Vec<String> {
            findings
                .into_iter()
                .filter(|finding| {
                    let path = finding.path.to_string_lossy();
                    path.contains("seat.toml") || path.contains("capability.toml")
                })
                .map(|finding| finding.message)
                .collect()
        };
        let conversation =
            "conversation = { project = \"fixture\", ask_capability = \"seat.ask.fixture\", guidance = \"Speak plainly.\", answer_timeout_seconds = 240 }";
        let mut valid = lane_fixtures();
        valid.push(project_object(true));
        valid.push(ask_capability_object("seat.ask.fixture", "fixture"));
        valid.push(seat_object(conversation, true));
        let happy = relevant(validate(&valid, &context));
        assert!(
            happy.is_empty(),
            "a published delegation onto an enabled live seat must validate cleanly: {happy:?}"
        );

        // Unknown target.
        let mut unknown = valid.clone();
        with_delegate_to(
            unknown
                .iter_mut()
                .find(|object| object.id == "seat.ask.fixture")
                .expect("ask capability fixture"),
            "nowhere",
        );
        let findings = relevant(validate(&unknown, &context));
        assert!(findings
            .iter()
            .any(|message| message.contains("delegate_to references missing seat \"nowhere\"")));

        // Disabled target seat.
        let mut disabled = valid.clone();
        seat_mut(
            disabled
                .iter_mut()
                .find(|object| object.relative_config.ends_with("seat.toml"))
                .expect("fixture seat"),
        )
        .enabled = false;
        let findings = relevant(validate(&disabled, &context));
        assert!(findings
            .iter()
            .any(|message| message == "delegate_to \"fixture\" references a disabled seat"));

        // Target seat without a live plane.
        let mut unlive = lane_fixtures();
        unlive.push(project_object(true));
        unlive.push(ask_capability_object("seat.ask.fixture", "fixture"));
        unlive.push(seat_object("", false));
        let findings = relevant(validate(&unlive, &context));
        assert!(findings.iter().any(|message| {
            message == "delegate_to \"fixture\" requires a target seat with a declared live plane"
        }));

        // The same declarations in the opposite order resolve identically.
        let mut reversed = valid.clone();
        reversed.reverse();
        let valid_relevant: std::collections::BTreeSet<_> =
            relevant(validate(&valid, &context)).into_iter().collect();
        let reversed_relevant: std::collections::BTreeSet<_> =
            relevant(validate(&reversed, &context))
                .into_iter()
                .collect();
        assert_eq!(valid_relevant, reversed_relevant);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Every seat_ask primitive requires delegate_to and the generic schema/evidence
    /// tuple, even when disabled; other handlers cannot delegate.
    #[test]
    fn delegation_declaration_law_is_per_object() {
        let base = ask_capability_object("custom.assistance", "someseat");
        let codes = |object: &RegistryObject| {
            crate::schema::validate_object(object)
                .into_iter()
                .filter(RegistryFinding::is_failure)
                .map(|finding| finding.code)
                .collect::<BTreeSet<_>>()
        };
        assert!(codes(&base).is_empty());

        let mut missing = base.clone();
        capability_mut(&mut missing).delegate_to = None;
        assert!(codes(&missing).contains("capability-delegation-target"));

        let mut other = base.clone();
        capability_mut(&mut other).handler =
            Some(HandlerBindingToml::Builtin(BuiltinHandlerToml {
                id: "fixture.handle".to_owned(),
            }));
        assert!(codes(&other).contains("capability-delegation-reserved"));

        let mut weaker = base.clone();
        capability_mut(&mut weaker).effect_class = odin_domain::EffectClass::R1;
        capability_mut(&mut weaker).approval_policy = crate::schema::CapabilityApprovalToml::None;
        assert!(codes(&weaker).contains("capability-delegation-approval"));

        let mut extractor = base.clone();
        capability_mut(&mut extractor).evidence_extractor =
            Some(HandlerBindingToml::Builtin(BuiltinHandlerToml {
                id: "other_evidence".to_owned(),
            }));
        assert!(codes(&extractor).contains("capability-delegation-tuple"));

        let mut schema = base;
        capability_mut(&mut schema).input_schema =
            Some("schemas/capability/seat.ask.legacy.input.json".to_owned());
        assert!(codes(&schema).contains("capability-delegation-tuple"));
    }
}

#[cfg(test)]
mod creation_tests {
    use super::super::fixtures::{seat_mut, seat_object_named};
    use super::validate_creation_holder;

    #[test]
    fn only_a_conversation_seat_may_hold_creation_capabilities() {
        let mut worker = seat_object_named("worker", "", false);
        seat_mut(&mut worker).tool_refs =
            std::collections::BTreeSet::from(["project.create".parse().expect("capability id")]);
        let mut findings = Vec::new();
        validate_creation_holder(
            &worker,
            super::super::fixtures::seat_mut(&mut worker.clone()),
            &mut findings,
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0]
            .message
            .contains("only the owner-facing conversation seat"));

        let mut coordinator = seat_object_named(
            "coordinator",
            "[conversation]\nproject = \"fixture\"\nask_capability = \"seat.ask.coordinator\"\nguidance = \"g\"\nanswer_timeout_seconds = 60\n",
            false,
        );
        seat_mut(&mut coordinator).tool_refs =
            std::collections::BTreeSet::from(["project.create".parse().expect("capability id")]);
        let mut findings = Vec::new();
        validate_creation_holder(
            &coordinator,
            super::super::fixtures::seat_mut(&mut coordinator.clone()),
            &mut findings,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }
}

#[cfg(test)]
mod tool_law_tests {
    use super::super::fixtures::{
        bound_capability, capability_mut, seat_mut, seat_object_named, slice_object,
    };
    use crate::relational::{validate, RelationContext};
    use crate::schema::{ObjectConfig, RegistryObject};

    fn failures(objects: &[RegistryObject]) -> Vec<String> {
        validate(objects, &RelationContext::new("/nonexistent/odin-tool-law"))
            .into_iter()
            .filter(|finding| finding.is_failure())
            .map(|finding| finding.message)
            .filter(|message| {
                message.starts_with("tool_refs") || message.contains("root-equivalent")
            })
            .collect()
    }

    /// Published seat tools must be enabled capabilities admitted by its categories and an enabled slice.
    #[test]
    fn a_seat_may_declare_only_tools_it_can_hold() {
        let (capability, _) = bound_capability();
        let mut seat = seat_object_named("worker", "", false);
        seat_mut(&mut seat).tool_refs = ["fixture.tool".parse().unwrap()].into();
        seat_mut(&mut seat).categories = ["builder".to_owned()].into();
        let mut slice = slice_object(true);
        let granting = |slice: &mut RegistryObject| {
            if let ObjectConfig::Slice(value) = &mut slice.config {
                value.capabilities = ["fixture.tool".parse().unwrap()].into();
            }
        };

        let held = {
            let mut slice = slice.clone();
            granting(&mut slice);
            vec![capability.clone(), seat.clone(), slice]
        };
        assert!(failures(&held).is_empty(), "{:?}", failures(&held));

        // Granted by no slice.
        let ungranted = vec![capability.clone(), seat.clone(), slice.clone()];
        assert_eq!(
            failures(&ungranted),
            ["tool_refs entry \"fixture.tool\" is granted by no enabled slice"]
        );

        // A disabled reservation.
        granting(&mut slice);
        let mut disabled = capability.clone();
        capability_mut(&mut disabled).enabled = false;
        assert_eq!(
            failures(&[disabled, seat.clone(), slice.clone()]),
            ["tool_refs entry \"fixture.tool\" names a disabled capability"]
        );

        // Categories the capability does not admit.
        let mut operator = seat.clone();
        seat_mut(&mut operator).categories = ["operator".to_owned()].into();
        let refused = failures(&[capability.clone(), operator, slice]);
        assert_eq!(refused.len(), 1);
        assert!(refused[0].contains("is not admitted for this seat's categories"));
    }

    #[test]
    fn root_equivalent_capabilities_cannot_be_declared() {
        for id in crate::ROOT_EQUIVALENT_CAPABILITIES {
            let (mut capability, _) = bound_capability();
            capability.id = (*id).to_owned();
            capability_mut(&mut capability).enabled = false;
            assert_eq!(
                failures(&[capability]),
                ["declares root-equivalent power, which no governed seat or pod may hold"],
                "{id}"
            );
        }
    }
}

#[cfg(test)]
mod always_tests {
    use super::super::fixtures::{seat_mut, seat_object};
    use super::*;

    #[test]
    fn an_always_entry_must_cover_one_of_the_seats_tool_refs() {
        let mut object = seat_object("", false);
        let seat = seat_mut(&mut object);
        seat.tool_refs = [odin_domain::CapabilityId::new("email.search").expect("id")].into();
        seat.tools.as_mut().expect("tools").always = [
            "email".to_owned(),
            "email.search".to_owned(),
            "fleet".to_owned(),
            "emai".to_owned(),
        ]
        .into();
        let seat = seat.clone();
        let mut findings = Vec::new();
        validate_seat_tools(&object, &seat, &BTreeMap::new(), &[], &mut findings);
        let messages: Vec<_> = findings
            .iter()
            .map(|finding| finding.message.as_str())
            .collect();
        assert_eq!(messages.len(), 2, "{messages:?}");
        assert!(messages[0].contains("\"emai\""), "{messages:?}");
        assert!(messages[1].contains("\"fleet\""), "{messages:?}");
    }
}
