# Odin

Odin is a harness for coding and research agents. One authority daemon, `odind`, reconciles a declarative
registry into running seats, pods and routines; every model call and tool call goes through one kernel that
authorizes it against the calling seat's grants and journals what happened.

## The pieces

- **Kernel** (`crates/odin-kernel`): capability contracts, authorization and approvals, seat tokens, the
  operation journal, provider leases and the recovery ladder. A call runs only if the seat's declaration grants
  it, inside that seat's sandbox; an action that needs the owner's yes is held for an approval.
- **Seats** (`registry/seats`): long-lived agents with a persona, a model class, tool grants and project scope.
  A coordinator seat delegates to builder, reviewer, operator and architect seats; each delegated job runs in
  its own clone and lane.
- **Toolsets**: model-visible tools are projections of capability declarations (`registry/capabilities`), grouped
  into fixed toolsets called as `toolset({op, ...fields})`. `op: "help"` returns a member's exact schema, so the
  listing stays small and fixed across turns.
- **Workflows**: routines (`registry/routines`) start turns on a schedule or an event, and seats chain pods and
  delegated tasks; every result comes back to the conversation that asked as a job report.
- **Pods** (`registry/workloads`, `crates/odin-kube`): declared workload profiles run on k3s with a narrowed tool
  set, such as the `research` and `research-deep` profiles with web reading, a headless browser and domain and
  scholarly research tools (`nix/pod-tools.nix`).
- **Brain** (`crates/odin-brain`): seat memory and knowledge search over PostgreSQL: BM25 keyword legs and vector
  legs fused by reciprocal rank and reordered by a reranker, with citations a seat can open in full.
- **Huginn** (`crates/odin-huginn`): the operator's interface: an authenticated transport with a read model,
  durable feeds, file and render transfer, and device trust.

Models are reached through one gateway whose lanes and classes are rendered from model cards in
`registry/models`; seats name a class or a specific model.

## Layout

- `crates/`: Rust services, shared types, adapters and the `odin`/`odind` binaries.
- `registry/`: seats, capabilities, projects, lanes, slices, workloads, routines and context profiles.
- `schemas/`: JSON Schemas for every capability's input and output.
- `skeletons/`: fill-only templates for registry authoring.
- `view/`: `odin view`, the terminal view of every seat; `extension/`: the Odin extension the OMP agent runtime loads.
- `docs/SCENARIOS.md`: the scenario inventory and the runner's live checks.

## Code and web tools

`code.rewrite` previews structural matches or applies an ast-grep replacement in a
builder's capsule. `code.look` starts an offline dev command or serves built files,
captures phone/desktop screenshots with the shipped Playwright/Chromium package,
and returns console errors and failed requests. Both are journaled Execute effects
inside the capsule's network-isolated bubble. Research pod images also include
`uv`, with interpreter downloads disabled and a persistent `/state/uv-cache`.
The manifest-selected ast-grep wrapper includes a pinned TOML parser and an
immutable authority-owned configuration; project configuration cannot select
native parsers, and no parser is downloaded at runtime.

MCP bridges require `--surface <64 lowercase hex>`, a BLAKE3 pin over canonical JSON
for served names, descriptions and input schemas, including sequence/load-check
dependencies. `surface_digest` returns a `Result`; describe and operation calls
refuse drift before invoking a tool. Print a reviewed pin with the built
`odin-adapter-mcp --print-surface <same flags> -- <server argv>`. Ship pins and the
bridge binary together.

An optional `--article-text` converter improves plain-HTTP article extraction;
converter failure retains html2text and the document verdict still applies.
`odin registry cheatsheet --registry <root> --seat <seat> [--out <file>]` generates
the granted toolset sheet and marks operations that ask the owner first.

## Checks

`tools/gate.sh` runs formatting, lint, design rules, typos, secrets, clippy, the test suites, dependency policy and
the package build, and stops on the first failure.
