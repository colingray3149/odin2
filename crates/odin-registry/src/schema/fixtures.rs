//! Shared declaration fixtures for the schema test modules.

pub(crate) const COMPLETE_SEAT: &str = r#"
schema = "odin.registry.v1"
kind = "seat"
enabled = true
description = "Strict seat shape."
categories = ["builder", "operator"]
tool_refs = ["artifact.read", "registry.read"]
project_scope = ["odin"]
approval_defaults = { r0 = "auto", r1 = "plan", r2 = "approval", r3 = "deny" }
brain_scope = ["atlas.code", "atlas.registry"]
limits = { max_parallel_runs = 8, max_sessions = 16, budget = { usd_micros = 1000000, window = { duration_seconds = 2592000 } } }
live = { max_sessions = 4, file_ingress_lane = "file.in", file_egress_lane = "file.out", render_ingress_lane = "render.in", render_egress_lane = "render.out" }
knowledge = { atlas_sources = ["atlas.core"], required_tags = ["rust"], denied_tags = [], top_k = 16 }
context = { max_bundle_tokens = 24576, profile = "fixture" }
tools = { deny = ["Bash"], redirects = { max_http_hops = 0, allow_cross_origin = false, disabled_aliases = ["FileReadTool"] } }
"#;

pub(crate) const COMPLETE_SLICE: &str = r#"
schema = "odin.registry.v1"
kind = "slice"
enabled = true
description = "Strict slice shape."
capabilities = ["artifact.read", "registry.read"]
variables = { cycles = { type = "integer", min = 1, max = 100, meaning = "Bounded cycles." } }
redirects = { out_of_scope = "NeedsPlan" }
budget = { usd_micros = 500000, window = { duration_seconds = 86400 } }
live = { max_sessions_per_seat = 8, max_prompt_bytes = 262144, transfer_chunk_bytes = 1048576, max_file_bytes = 268435456, max_render_bytes = 67108864, allowed_file_media_types = ["application/json", "text/plain"], allowed_render_media_types = ["image/png"] }
knowledge = { required = false, atlas_sources = ["atlas.core"], retrieval_mode = "hybrid", candidate_limit = 128, top_k = 24, min_score_micros = 100000, chunk_tokens = 512, chunk_overlap_tokens = 64, embedding_backend = "local" }
context = { max_bundle_tokens = 32768, reserve_output_tokens = 4096, control_tokens = 4096, history_tokens = 12288, core_tokens = 2048, prefetch_tokens = 512, tool_result_tokens = 4096, tool_schema_tokens = 4096, max_item_tokens = 2048 }
tools = { allow = ["Read", "Edit"], deny = ["Bash"], redirects = { max_http_hops = 2, allow_cross_origin = false, allow_https_downgrade = false }, alias_redirect = [{ from = "FileReadTool", to = "Read", schema_digest = "blake3:0000000000000000000000000000000000000000000000000000000000000000" }] }
"#;
