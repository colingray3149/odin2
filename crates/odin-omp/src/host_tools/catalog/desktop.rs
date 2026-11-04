//! Sinmara's hands on the owner's desktop: one look and one act.

use super::{CompiledCapabilityBinding, CompiledHandlerBinding};

pub(super) static DESKTOP_LOOK_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/desktop.look.input.json",
    output_schema: "schemas/capability/desktop.look.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "desktop_look" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_desktop_look_evidence",
    },
};

pub(super) static DESKTOP_ACT_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/desktop.act.input.json",
    output_schema: "schemas/capability/desktop.act.output.json",
    handler: CompiledHandlerBinding::Builtin { id: "desktop_act" },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_desktop_act_evidence",
    },
};

pub(super) static DESKTOP_DEVICE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/desktop.device.input.json",
    output_schema: "schemas/capability/desktop.act.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "desktop_device",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_desktop_act_evidence",
    },
};

pub(super) static DESKTOP_SCENE_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/desktop.scene.input.json",
    output_schema: "schemas/capability/desktop.act.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "desktop_scene",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_desktop_act_evidence",
    },
};

pub(super) static DESKTOP_HEADLESS_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/desktop.headless.input.json",
    output_schema: "schemas/capability/desktop.act.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "desktop_headless",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_desktop_act_evidence",
    },
};

pub(super) static DESKTOP_DISPLAY_BINDING: CompiledCapabilityBinding = CompiledCapabilityBinding {
    version: 1,
    input_schema: "schemas/capability/desktop.display.input.json",
    output_schema: "schemas/capability/desktop.act.output.json",
    handler: CompiledHandlerBinding::Builtin {
        id: "desktop_display",
    },
    evidence_extractor: CompiledHandlerBinding::Builtin {
        id: "odin_hermes_desktop_display_evidence",
    },
};
