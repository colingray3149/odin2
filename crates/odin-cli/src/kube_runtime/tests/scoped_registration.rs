//! Generated admission artifacts must be readable only by their declared run.

use std::sync::{Arc, Mutex};

use odin_domain::huginn::KubeJobLabels;
use odin_domain::{AttemptId, Digest, LaneId, ProjectId, RunId, SeatId, TaskId};
use odin_kube::artifacts::ArtifactStore;
use odin_kube::KubeError;
use odin_ledger::Ledger;

use odin_omp::host_tools::HostToolError;

use super::super::extension::{compose_extension_launch, ProfileBinding};
use super::compose_models_config_launch;

const TOOL: &str = "odin_kube.workload.create";

fn identity_bytes() -> Vec<u8> {
    serde_json::json!({
        "schema": "odin.workload-image-identity.v1",
        "reference":
            "localhost/odin-workload@sha256:03b10056bbcf49d56fa61ba9050b674b66dc878752c021bd334dc0cc4e513428",
        "image_name": "localhost/odin-workload",
        "tag": "18.1.18-c3k9b4ljsj9h",
        "manifest_digest":
            "sha256:03b10056bbcf49d56fa61ba9050b674b66dc878752c021bd334dc0cc4e513428",
        "config_digest":
            "sha256:b8a188f01192d0a857dd4fe1e469cc3217ef4757acbfc4abfc7db804aa46112e",
        "import_archive": "odin-workload-image-oci.tar",
        "omp_source_revision": "00085d4e7dfdcfbf302c122fa2682b410a0f43d1",
        "archive_sha256":
            "63045bbd2d848ff1702b2366f359a69b06ed485451f8ea1411fc963b0af04326",
        "source_revision": "c3k9b4ljsj9hdwbna37r644b8l471cyj",
        "tools": {
            "omp": {
                "in_image": "/odin/bin/omp",
                "store": "/nix/store/q9d42swrbrrzfjr7ahmgrs2r1cwag940-omp-18.1.18/bin/omp",
                "blake3": "blake3:f85cc84dd70a78c09b4d99dccaadca7b0935e35a30b568bb6038c2714cf37cda"
            },
            "odin": {
                "in_image": "/odin/bin/odin",
                "store": "/nix/store/c3k9b4ljsj9hdwbna37r644b8l471cyj-odin-0.0.0/bin/odin",
                "blake3": "blake3:7494a9efea0995fe1ad2c8dacdb1d9afc0c856def5785b3dc9ade9de9593f1c5"
            },
            "odind": {
                "in_image": "/odin/bin/odind",
                "store": "/nix/store/c3k9b4ljsj9hdwbna37r644b8l471cyj-odin-0.0.0/bin/odind",
                "blake3": "blake3:e5defddcdbc6ecfa8c3a53252404e9fcdbb7f716eb6be4e6e6e5a8ece06e4551"
            },
            "node": {
                "in_image": "/odin/bin/node",
                "store": "/nix/store/2gd4h12irmnanhg33md2rpjygrsj5ypb-nodejs-slim-22.23.2/bin/node",
                "blake3": "blake3:f5c4477e866cddea8e44623400f2c28cf0773398f38de4cde9cf390448e7b74c"
            },
            "chromium": {
                "in_image": "/odin/bin/chromium",
                "store": "/nix/store/3qgx41z8882ff85y9prdc5zgbb2id6y8-chromium-152.0.7977.64/bin/chromium",
                "blake3": "blake3:b82d1bafb8339c402fdba594fb639849c93c4e3ee1671a9b5741c48a385235b5"
            },
            "xvfb": {
                "in_image": "/odin/bin/Xvfb",
                "store": "/nix/store/2ngsl5s8gmkbvav54pg2khb5ykxc4d10-xvfb-21.1.24/bin/Xvfb",
                "blake3": "blake3:bf39900803fa36f3ab95e89d7b5bb04648982b0dbb1b44c881f6b0431140d2ed"
            },
            "extension": {
                "in_image": "/odin/lib/odin-extension/index.ts",
                "store": "/nix/store/00000000000000000000000000000000-odin-extension/index.ts",
                "blake3": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        },
        "module_roots": {
            "playwright": {
                "in_image": "/odin/lib/playwright-core",
                "store": "/odin/lib/playwright-core"
            }
        },
        "mount_points": ["/state", "/export"],
        "config": {
            "user": "65534:65534",
            "working_dir": "/state",
            "entrypoint": serde_json::Value::Null,
            "command": serde_json::Value::Null,
            "env": ["PATH=/odin/bin:/bin", "HOME=/state"]
        }
    })
    .to_string()
    .into_bytes()
}

struct Suite {
    _root: tempfile::TempDir,
    store: ArtifactStore,
    ledger: Arc<Mutex<Ledger>>,
    run: RunId,
    attempt: AttemptId,
    seat: SeatId,
    project: ProjectId,
    lane: LaneId,
}

impl Suite {
    /// The declaring Job's labels: exactly the scope the producers bind
    /// the generated material to.
    fn declared_labels(&self) -> KubeJobLabels {
        KubeJobLabels {
            task_id: TaskId::new("workload-task-scope-regression").expect("task id"),
            run_id: self.run.clone(),
            attempt_id: self.attempt.clone(),
            seat_id: self.seat.clone(),
            project_id: self.project.clone(),
            lane_id: self.lane.clone(),
            model: "glm-flash".to_owned(),
            budget_policy_digest: Digest::hash(b"scope-regression-budget"),
            container_identity: Digest::hash(b"scope-regression-image"),
        }
    }

    /// A different run on the SAME seat, project, and lane: the narrow
    /// run grant is exactly what must not leak across it.
    fn foreign_run_labels(&self) -> KubeJobLabels {
        KubeJobLabels {
            run_id: RunId::new("run-scope-regression-foreign").expect("run id"),
            ..self.declared_labels()
        }
    }
}

/// The declared node gateway endpoint the composed workload documents and
/// the egress pin both derive from: one parse, reused by every case here.
fn declared_gateway() -> odin_registry::schema::NodeGatewayEndpoint {
    odin_registry::schema::NodeGatewayEndpoint::parse("http://100.64.0.12:14000/v1")
        .expect("the fixture endpoint is a declared node gateway")
}

fn suite() -> Suite {
    let root = tempfile::tempdir().expect("confined artifact root");
    let ledger = Arc::new(Mutex::new(
        Ledger::open_in_memory().expect("in-memory ledger with the odin schema"),
    ));
    Suite {
        store: ArtifactStore::new(Arc::clone(&ledger), root.path().to_path_buf()),
        ledger,
        run: RunId::new("run-scope-regression").expect("run id"),
        attempt: AttemptId::new("workload-attempt-scope-regression").expect("attempt id"),
        seat: SeatId::new("colin").expect("seat id"),
        project: ProjectId::new("odin").expect("project id"),
        lane: LaneId::new("scope-regression").expect("lane id"),
        _root: root,
    }
}

#[test]
fn generated_material_reads_only_for_its_declared_run() {
    let suite = suite();
    let identity = suite
        .store
        .register_bytes(&identity_bytes(), "objects/scope-regression/identity.json")
        .expect("pinned image identity registers");
    let models = compose_models_config_launch(
        TOOL,
        &suite.store,
        &suite.ledger,
        "gateway",
        "glm-flash",
        &declared_gateway(),
        &suite.run,
    )
    .expect("models document composes and binds");
    let extension = compose_extension_launch(
        TOOL,
        &suite.store,
        &suite.ledger,
        &identity.artifact_id,
        7,
        &ProfileBinding {
            image_reference:
                "localhost/odin-workload:18.1.18@sha256:03b10056bbcf49d56fa61ba9050b674b66dc878752c021bd334dc0cc4e513428",
            launcher: "/odin/bin/omp",
            supervisor: "/odin/bin/odind",
            browser: "/odin/bin/chromium",
            playwright: "/odin/lib/playwright-core",
            xvfb: "/odin/bin/Xvfb",
        },
        3,
        &suite.run,
    )
    .expect("extension policy composes and binds");

    for material in [&models.staging_input, &extension.staging_input] {
        let metadata = suite
            .store
            .prepare_content(&suite.declared_labels(), material)
            .expect("the declared run's Job reads its own generated material");
        assert_eq!(
            metadata.artifact_id, material.artifact_id,
            "the reader resolved exactly the registered artifact"
        );

        let error = suite
            .store
            .prepare_content(&suite.foreign_run_labels(), material)
            .expect_err("a different run on the same seat/project/lane must not read");
        assert!(
            matches!(error, KubeError::Rejected { .. }),
            "the leak attempt is a typed rejection: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("no ledger reference binds the artifact to the Job scope"),
            "the typed reader law refused: {error}"
        );
    }
}

/// A retried admission of identical content keeps the consumer behavior
/// stable: the declared run still reads, a foreign run on the same
/// seat/project/lane still does not.
#[test]
fn readmission_keeps_the_same_run_reading_and_foreign_runs_refused() {
    let suite = suite();
    let first = compose_models_config_launch(
        TOOL,
        &suite.store,
        &suite.ledger,
        "gateway",
        "glm-flash",
        &declared_gateway(),
        &suite.run,
    )
    .expect("first admission composes and binds");
    let second = compose_models_config_launch(
        TOOL,
        &suite.store,
        &suite.ledger,
        "gateway",
        "glm-flash",
        &declared_gateway(),
        &suite.run,
    )
    .expect("re-admission composes and binds");
    assert_eq!(first, second, "re-admission replays the identical binding");

    suite
        .store
        .prepare_content(&suite.declared_labels(), &second.staging_input)
        .expect("the declared run still reads after re-admission");
    let error = suite
        .store
        .prepare_content(&suite.foreign_run_labels(), &second.staging_input)
        .expect_err("a foreign run on the same seat/project/lane still must not read");
    assert!(
        matches!(error, KubeError::Rejected { .. }),
        "the leak attempt is a typed rejection: {error:?}"
    );
}

/// A declared browser surface the pinned image identity does not carry is a
/// typed composition refusal, before any policy composes or any bytes
/// register: the identity's exact tool and module-root bindings are the
/// only ones a launch may name.
#[test]
fn browser_surface_off_the_pinned_identity_refuses_before_composition() {
    let suite = suite();
    let identity = suite
        .store
        .register_bytes(&identity_bytes(), "objects/scope-regression/identity.json")
        .expect("pinned image identity registers");
    let reference =
        "localhost/odin-workload:18.1.18@sha256:03b10056bbcf49d56fa61ba9050b674b66dc878752c021bd334dc0cc4e513428";
    for (what, binding) in [
        (
            "browser",
            ProfileBinding {
                image_reference: reference,
                launcher: "/odin/bin/omp",
                supervisor: "/odin/bin/odind",
                browser: "/usr/bin/chromium",
                playwright: "/odin/lib/playwright-core",
                xvfb: "/odin/bin/Xvfb",
            },
        ),
        (
            "playwright",
            ProfileBinding {
                image_reference: reference,
                launcher: "/odin/bin/omp",
                supervisor: "/odin/bin/odind",
                browser: "/odin/bin/chromium",
                playwright: "/usr/lib/node_modules/playwright-core",
                xvfb: "/odin/bin/Xvfb",
            },
        ),
        (
            "xvfb",
            ProfileBinding {
                image_reference: reference,
                launcher: "/odin/bin/omp",
                supervisor: "/odin/bin/odind",
                browser: "/odin/bin/chromium",
                playwright: "/odin/lib/playwright-core",
                xvfb: "/usr/bin/Xvfb",
            },
        ),
    ] {
        let error = compose_extension_launch(
            TOOL,
            &suite.store,
            &suite.ledger,
            &identity.artifact_id,
            7,
            &binding,
            3,
            &suite.run,
        )
        .expect_err("a browser surface off the pinned identity is refused");
        assert!(
            matches!(error, HostToolError::Arguments { .. }),
            "{what} mismatch is a typed arguments refusal: {error:?}"
        );
    }
}
