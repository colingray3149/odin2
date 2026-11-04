//! Explicit bindings for the capsule's eval, file edit, structural rewrite and browser capture.

use super::{CompiledCapabilityBinding, CompiledHandlerBinding};

pub(super) static CAPSULE_EVAL_RUN_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/capsule.eval.run.input.json",
    output_schema: "schemas/capability/capsule.eval.run.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_eval.run",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_eval.run_evidence",
    },
};

pub(super) static CAPSULE_FILE_EDIT_BINDING: CompiledCapabilityBinding =
    CompiledCapabilityBinding {
        version: 1,
        input_schema: "schemas/capability/capsule.file.edit.input.json",
        output_schema: "schemas/capability/capsule.file.edit.output.json",
        handler: CompiledHandlerBinding::Builtin {
            id: "odin_file.edit",
        },
        evidence_extractor: CompiledHandlerBinding::Builtin {
            id: "odin_file.edit_evidence",
        },
    };

pub(super) static CODE_REWRITE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/code.rewrite.input.json",
    output_schema: "schemas/capability/code.rewrite.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_code.rewrite",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_code.rewrite_evidence",
    },
};

pub(super) static CODE_LOOK_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/code.look.input.json",
    output_schema: "schemas/capability/code.look.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "odin_code.look",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_code.look_evidence",
    },
};
