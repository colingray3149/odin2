//! Bindings of the deploy capabilities: one merged commit to the fleet, and its progress.

use super::{CompiledCapabilityBinding, CompiledHandlerBinding};

pub(super) static ODIN_DEPLOY_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/odin.deploy.input.json",
    output_schema: "schemas/capability/odin.deploy.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "odin_deploy" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_odin_deploy_evidence",
    },
};

pub(super) static ODIN_DEPLOY_STATUS_BINDING: CompiledCapabilityBinding =
    CompiledCapabilityBinding {
        version: 1,
        input_schema: "schemas/capability/odin.deploy.status.input.json",
        output_schema: "schemas/capability/odin.deploy.status.output.json",
        handler: CompiledHandlerBinding::Builtin {
            id: "odin_deploy_status",
        },
        evidence_extractor: CompiledHandlerBinding::Builtin {
            id: "odin_hermes_odin_deploy_status_evidence",
        },
    };
