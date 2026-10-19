use std::fs;
use std::path::PathBuf;

use super::{commit_all, git, write_fixture_registry, TestDirectory};
use crate::relational::AdmittedBinding;
use crate::schema::{BuiltinHandlerToml, HandlerBindingToml, RegistryKind};
use crate::snapshot::store::versioned_snapshot_path;
use crate::snapshot::{PublicationOutcome, Snapshot, SnapshotStore, ValidatedSnapshotCandidate};

fn conversation_fixture_worktree() -> (TestDirectory, PathBuf) {
    let directory = TestDirectory::new();
    let worktree = directory.0.join("worktree");
    fs::create_dir_all(&worktree).unwrap();
    git(&worktree, &["-c", "init.defaultBranch=main", "init"]);
    write_fixture_registry(&worktree, &[("alpha", true)]);
    fs::create_dir_all(worktree.join("registry/providers/gateway")).unwrap();
    fs::write(
        worktree.join("registry/providers/gateway/provider.toml"),
        include_str!("../../../../../registry/providers/gateway/provider.toml"),
    )
    .unwrap();

    let project = "schema = \"odin.registry.v1\"\n\
         kind = \"project\"\n\
         enabled = true\n\
         description = \"conversation fixture project\"\n\
         source_root = \"\"\n\
         default_seat = \"herald\"\n\
         memory_namespaces = []\n\
         artifact_policy = \"standard\"\n";
    fs::create_dir_all(worktree.join("registry/projects/letter")).unwrap();
    fs::write(
        worktree.join("registry/projects/letter/project.toml"),
        project,
    )
    .unwrap();

    let lane = |direction: &str, payload: &str| {
        format!(
            "schema = \"odin.registry.v1\"\n\
             kind = \"lane\"\n\
             enabled = true\n\
             description = \"conversation fixture lane\"\n\
             project = \"letter\"\n\
             family = \"transfer\"\n\
             default_seat = \"herald\"\n\
             queue = \"interactive\"\n\
             requires_independent_review = false\n\
             direction = \"{direction}\"\n\
             payload_kind = \"{payload}\"\n"
        )
    };
    for (name, direction, payload) in [
        ("file.in", "ingress", "file"),
        ("file.out", "egress", "file"),
        ("render.in", "ingress", "render"),
        ("render.out", "egress", "render"),
    ] {
        fs::create_dir_all(worktree.join("registry/lanes").join(name)).unwrap();
        fs::write(
            worktree.join("registry/lanes").join(name).join("lane.toml"),
            lane(direction, payload),
        )
        .unwrap();
    }

    let seat = |conversation: &str| {
        format!(
            "schema = \"odin.registry.v1\"\n\
             kind = \"seat\"\n\
             enabled = true\n\
             description = \"conversation fixture seat\"\n\
             categories = []\n\
             tool_refs = []\n\
             project_scope = [\"letter\"]\n\
             approval_defaults = {{ r0 = \"auto\", r1 = \"auto\", r2 = \"auto\", r3 = \"approval\" }}\n\
             brain_scope = []\n\
             limits = {{ max_parallel_runs = 4, max_sessions = 4, budget = {{ usd_micros = 1000000, window = {{ duration_seconds = 2592000 }} }} }}\n\
             knowledge = {{ atlas_sources = [], required_tags = [], denied_tags = [], top_k = 16 }}\n\
             context = {{ max_bundle_tokens = 24576, profile = \"fixture\" }}\n\
             tools = {{ deny = [], redirects = {{ max_http_hops = 0, allow_cross_origin = false, disabled_aliases = [] }} }}\n\
             \n\
             [live]\n\
             max_sessions = 4\n\
             file_ingress_lane = \"file.in\"\n\
             file_egress_lane = \"file.out\"\n\
             render_ingress_lane = \"render.in\"\n\
             render_egress_lane = \"render.out\"\n\
             {conversation}"
        )
    };
    fs::create_dir_all(worktree.join("registry/seats/herald")).unwrap();
    fs::write(worktree.join("registry/seats/herald/seat.toml"), seat("")).unwrap();
    fs::create_dir_all(worktree.join("registry/context-profiles/fixture")).unwrap();
    fs::write(
        worktree.join("registry/context-profiles/fixture/context-profile.toml"),
        "schema = \"odin.registry.v1\"\nkind = \"context-profile\"\nenabled = true\ndescription = \"Fixture context profile.\"\ncore_tokens = 2048\ninject_tokens = 6144\ninject_k = 8\n",
    )
    .unwrap();

    // The fixture's ask capability binds the one generic primitive tuple and
    // names its target explicitly: arbitrary names, one shared surface.
    let ask_capability = "schema = \"odin.registry.v1\"\n\
         kind = \"capability\"\n\
         enabled = true\n\
         implementation = \"builtin\"\n\
         version = 1\n\
         description = \"conversation fixture ask capability\"\n\
         handler = { id = \"seat_ask\" }\n\
         delegate_to = \"herald\"\n\
         input_schema = \"schemas/capability/seat.ask.input.json\"\n\
         output_schema = \"schemas/capability/seat.ask.output.json\"\n\
         effect_class = \"R3\"\n\
         seat_tags = [\"*\"]\n\
         timeout_seconds = 30\n\
         idempotency = \"required\"\n\
         retry = { max_attempts = 0 }\n\
         approval_policy = \"operator\"\n\
         evidence_extractor = { id = \"odin_hermes_seat_ask_evidence\" }\n";
    fs::create_dir_all(worktree.join("registry/capabilities/seat.ask.herald")).unwrap();
    fs::write(
        worktree.join("registry/capabilities/seat.ask.herald/capability.toml"),
        ask_capability,
    )
    .unwrap();
    fs::create_dir_all(worktree.join("schemas/capability")).unwrap();
    for name in ["seat.ask.input.json", "seat.ask.output.json"] {
        fs::write(
            worktree.join("schemas/capability").join(name),
            r#"{"$schema": "https://json-schema.org/draft/2020-12/schema"}"#,
        )
        .unwrap();
    }
    (directory, worktree)
}

/// The single compiled primitive tuple the fixture capability declares; the
/// production composition admits it once and every logical ask capability
/// matches it.
fn herald_ask_admitted_binding() -> AdmittedBinding {
    AdmittedBinding {
        version: 1,
        input_schema: "schemas/capability/seat.ask.input.json".to_owned(),
        output_schema: "schemas/capability/seat.ask.output.json".to_owned(),
        handler: HandlerBindingToml::Builtin(BuiltinHandlerToml {
            id: "seat_ask".to_owned(),
        }),
        evidence_extractor: HandlerBindingToml::Builtin(BuiltinHandlerToml {
            id: "odin_hermes_seat_ask_evidence".to_owned(),
        }),
    }
}

/// The full publication chain carries the declared conversation vehicle:
/// a pre-conversation seat publishes without the field, a child commit may
/// add it, the active snapshot retains the metadata, and the previous
/// revision stays loadable byte-for-byte.
#[test]
fn published_snapshot_migrates_and_retains_conversation_metadata() {
    let (directory, worktree) = conversation_fixture_worktree();
    let store = SnapshotStore::new(directory.0.join("state/registry/snapshot.json"));

    let admitted = [herald_ask_admitted_binding()];
    let first_commit = commit_all(&worktree, "conversation-less seat");
    let first = ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &first_commit,
        admitted.iter().cloned(),
    )
    .expect("conversation-less candidate");
    store
        .publish_committed(&first, 1)
        .expect("publish revision 1");
    let plain = store
        .load_verified()
        .expect("verified legacy-shaped snapshot");
    assert!(plain
        .objects
        .iter()
        .filter_map(|object| match &object.config {
            crate::schema::ObjectConfig::Seat(value) => Some(value),
            _ => None,
        })
        .all(|seat| seat.conversation.is_none()));

    let seat_path = worktree.join("registry/seats/herald/seat.toml");
    let source = fs::read_to_string(&seat_path).unwrap();
    fs::write(
        &seat_path,
        source.replace(
            "render_egress_lane = \"render.out\"\n",
            "render_egress_lane = \"render.out\"\n\n[conversation]\nproject = \"letter\"\nask_capability = \"seat.ask.herald\"\nguidance = \"Speak plainly, and ask one short clarifying question when a request is open-ended.\"\nanswer_timeout_seconds = 240\n",
        ),
    )
    .unwrap();
    let second_commit = commit_all(&worktree, "declare the conversation vehicle");
    let second = ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &second_commit,
        admitted.iter().cloned(),
    )
    .expect("conversation candidate");
    let result = store
        .publish_committed(&second, 2)
        .expect("publish revision 2");
    assert_eq!(result.outcome, PublicationOutcome::Published);

    let active = store.load_verified().expect("verified active snapshot");
    assert_eq!(active.revision, 2);
    let seat = active
        .listed_objects(RegistryKind::Seat)
        .find(|object| object.id == "herald")
        .expect("herald seat in snapshot");
    let crate::schema::ObjectConfig::Seat(value) = &seat.config else {
        panic!("herald must parse as a seat");
    };
    let conversation = value.conversation.as_ref().expect("conversation retained");
    assert_eq!(conversation.project.as_str(), "letter");
    assert_eq!(conversation.ask_capability.as_str(), "seat.ask.herald");
    assert_eq!(
        conversation.guidance,
        "Speak plainly, and ask one short clarifying question when a request is open-ended."
    );
    assert_eq!(conversation.answer_timeout_seconds.get(), 240);

    // The published delegation edge survives reopen intact: the capability's
    // target seat and the conversation's ask capability stay bound to each
    // other through the published snapshot, never through caller literals.
    let ask = active
        .listed_objects(RegistryKind::Capability)
        .find(|object| object.id == "seat.ask.herald")
        .expect("ask capability in snapshot");
    let crate::schema::ObjectConfig::Capability(capability) = &ask.config else {
        panic!("seat.ask.herald must parse as a capability");
    };
    assert_eq!(
        capability
            .delegate_to
            .as_ref()
            .expect("delegation target retained")
            .as_str(),
        "herald"
    );

    // Republishing the identical declarations finds the same publication:
    // reopen-serialize is a canonical fixed point, so adding or keeping
    // delegation metadata never churns the snapshot hash.
    let again =
        ValidatedSnapshotCandidate::from_committed_worktree(&worktree, &second_commit, admitted)
            .expect("identical candidate");
    let result = store
        .publish_committed(&again, 2)
        .expect("republish identical content");
    assert_eq!(result.outcome, PublicationOutcome::Unchanged);

    let plain_snapshot: Snapshot = serde_json::from_slice(
        &fs::read(versioned_snapshot_path(store.path(), 1)).expect("read revision 1"),
    )
    .expect("parse revision 1");
    assert_eq!(plain_snapshot.revision, 1);
    assert!(plain_snapshot
        .objects
        .iter()
        .filter_map(|object| match &object.config {
            crate::schema::ObjectConfig::Seat(value) => Some(value),
            _ => None,
        })
        .all(|value| value.conversation.is_none()));
}
