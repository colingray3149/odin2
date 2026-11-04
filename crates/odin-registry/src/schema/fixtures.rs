//! Shared declaration fixtures for the schema test modules.

pub(crate) const COMPLETE_SEAT: &str = r#"
schema = "odin.registry.v1"
kind = "seat"
enabled = true
description = "Strict seat shape."
categories = ["builder", "operator"]
tool_refs = ["artifact.read", "registry.read"]
project_scope = ["odin"]
brain_scope = ["atlas.code", "atlas.registry"]
limits = { max_parallel_runs = 8, max_sessions = 16, budget = { usd_micros = 1000000, window = { duration_seconds = 2592000 } } }
live = { max_sessions = 4, file_ingress_lane = "file.in", file_egress_lane = "file.out", render_ingress_lane = "render.in", render_egress_lane = "render.out" }
knowledge = { atlas_sources = ["atlas.core"], required_tags = ["rust"], denied_tags = [], top_k = 16 }
context = { max_bundle_tokens = 24576, profile = "fixture" }
tools = { deny = ["Bash"], redirects = { max_http_hops = 0, allow_cross_origin = false, disabled_aliases = ["FileReadTool"] } }
"#;
