# odin2

Odin is a declarative, self-hosted AI agent harness for one person: seats, model lanes, projects, workloads, routines and permissions are TOML files in `registry/`, and one Rust daemon (`odind`) reconciles a small NixOS fleet to match them.
The owner talks to a coordinator seat, Sinmara, over Discord DMs or the `odin huginn` CLI; she handles mail, calendar, reminders, web and browser tasks, and delegates code work to helper seats that branch, build, test, get an independent review and merge across eleven projects.
Every tool call passes a kernel that checks seat, slice, project and lane permissions, journals the effect before it runs, and holds risky actions (sending mail, purchases, consequential browser steps) for explicit approval.
Seat sessions run in bubblewrap with no capabilities, their own throwaway copy of the repo and no network for the shell; k3s pods run unprivileged under per-run CPU, memory, time and egress-host limits.
A brain gives every seat hybrid Postgres search over notes, code, mail, chats and AI history plus memory learned after each turn, and models route through one gateway (Grok, GPT, Kimi, GLM and a local Qwen at ~50 tok/s).
State is backed up nightly with encrypted restic snapshots to a second machine, Backblaze B2 and an external SSD, and NixOS keeps five generations to roll back to.

## Size

| | Files | Lines | Code | Comments | Blank |
|---|---:|---:|---:|---:|---:|
| Rust | 1,145 | 555,911 | 514,968 | 10,617 | 30,326 |
| TypeScript / JS | 12 | 6,157 | 5,346 | 494 | 317 |
| TOML (registry, config) | 296 | 8,733 | 6,826 | 1,173 | 734 |
| JSON (capability schemas) | 201 | 12,422 | 12,422 | 0 | 0 |
| SQL, Python, Nix, shell, templates | 76 | 7,621 | 5,701 | 1,517 | 403 |

Counted with `tokei`, which treats `///` doc comments as code.

## Architecture map

This map is module-level: Rust crates live in `crates/odin-*`, desired state in `registry/`, and build and deploy tooling at the repo root.

### Layout

- `crates/` — Cargo workspace members, all prefixed `odin-`; the daemon, CLI, and every authority library.
- `registry/` — declarative TOML desired state, one folder per object under a kind folder.
- `schemas/` — SQLite/Postgres migrations, plus JSON Schemas for capabilities, adapters, wire and odind config.
- `skeletons/` — fill-only templates (`TEMPLATE.toml`, `variables.toml`) for authoring new registry objects.
- `extension/` — trusted TypeScript extension loaded by stock OMP; gates tools through the kernel.
- `tools/` — `gate.sh` (fmt, clippy, cargo deny) and `deploy.sh`.
- `sweep/` — fixtures for the `odin-sweep` checks.
- `nix/` — composition, workload image, Obscura browser build, and the Home Manager `services.odin` module.

### crates/odin-kernel

Capability authorization, approvals, seat tokens, operation journaling, provider leases, recovery ladder, and worker launch/stop authority.

- `src/capability/` — capability contracts, unchecked versus authorized invocations, seat-token-bound listings.
- `src/operation/` — `OperationAuthority`: admits, journals before dispatch, settles and reconciles effects without replay.
- `src/approval.rs` — durable exact-scope approvals: request, decide, deny, expire.
- `src/policy.rs` — effective capability policy and pre-handler authorization.
- `src/token.rs` — seat-token minting, validation, revocation.
- `src/authority_transition.rs` — sole controller of seat authority transitions and dispatch.
- `src/recovery.rs` — pure recovery-ladder state machine: rungs, limits, cooldowns.
- `src/stop/` — `StopAuthority`: journals launch and stop intent; local, job and pod worker backends, stop evidence.
- `src/worker_broker/` — parent broker for workers on hosts without bus access: wire protocol, client, server, scopes.

### crates/odin-domain

Transport-neutral vocabulary: IDs, envelopes, operations, stop and worker states, Huginn contracts, knowledge policy types.

- `src/ids.rs` — validated string ID newtypes and 32-byte `Digest`.
- `src/envelope.rs` — event and command envelopes with correlation, actor, redaction, capability.
- `src/operation.rs`, `scope.rs`, `status.rs` — capability classes, cost and limits, scope narrowing, status enums.
- `src/stop.rs`, `worker.rs`, `token.rs` — stop states, worker phases and records, `SeatToken` claims.
- `src/bus.rs` — synchronous `EventBus` trait and stable subjects.
- `src/extension_policy.rs`, `image_identity.rs` — extension-policy and workload-image identity types with BLAKE3 digests.
- `src/huginn/` — phone/owner surface contracts: protocol, live streams, sessions, files, terminals, browser, kube, simulation.
- `src/knowledge/` — privacy classes, archive declarations, context policy, tool vocabulary, facts and retrieval types.

### crates/odin-registry

Discovery, parsing, validation, authoring and snapshot publication of the TOML registry.

- `src/discover.rs` — walks the registry root and collects raw TOML objects.
- `src/schema/` — typed per-kind declarations (seat, capability, container, workload, provider, harness, node) and field validation.
- `src/relational/` — cross-declaration reference checks: capabilities, seats, containers, workloads, graph.
- `src/authoring/` — compiles and validates skeleton fills in private staging, then installs them.
- `src/snapshot/` — immutable published snapshots: atomic store, pinned handle, composition digest, committed provenance.
- `src/container_identity.rs` — hashes container fields into a stable `ContainerIdentity`.

### crates/odin-ledger

Durable SQLite/WAL authority for control-plane state, with migrations and typed stores.

- `src/lib.rs`, `migration.rs` — `Ledger` handle, transactions, canonical and extension migrations.
- `src/operation/` — operation journal with compare-and-set effect states, capsule leases, stop intents, usage.
- `src/approval.rs`, `approval_feed.rs`, `command.rs`, `idempotency.rs`, `inbox.rs` — approvals, commands, idempotency, inbox dedup.
- `src/worker.rs`, `stop.rs`, `pod.rs`, `kube.rs` — worker rows, stop evidence, pod and Kubernetes operation persistence.
- `src/lease.rs`, `provider_lease.rs`, `materialized.rs`, `snapshot.rs` — leases, projection rebuilds, backup and restore.

### crates/odin-cli

Operator CLI (`odin`) and the `odind` daemon: command surface, authority provisioning, serving loop, routes, pumps and runtimes.

- `src/main.rs`, `src/commands/` — `odin` subcommands: account, approve, authority, registry, author, session, plan, huginn.
- `src/session/` — `odin session` open/attach client with plan gate and interactive terminal surface.
- `src/authority_provision/` — private authority keys, seat tokens, device pairing, session composition outside git.
- `src/eval_daemon/`, `src/live_authority/` — per-live-session sidecar authority pool, child provisioning, worker supervision.
- `src/browser_runtime/` — browser runtime composition: dispatch, launch, pod routes, approved-action coordinator.
- `src/kube_runtime/` — owner of `kube.workload.*` capabilities against k3s Jobs: admission, execution, evidence.
- `src/odind.rs`, `src/odind/entry.rs` — daemon entry, clap surface and subcommands.
- `src/odind/live.rs`, `live/` — daemon serving composition: assembly, shutdown, settlement, session discovery, harness launch.
- `src/odind/coding_route/` — coding tools over session capsules: navigation, Git/Nix execution, review, reviewed publication.
- `src/odind/claude_*`, `claude_pod_backend/` — Claude Code driver: sessions store, protocol, host tabs, pod supervisor, publication.
- `src/odind/*_authoring.rs` — runtime authoring of registry, projects, seats, routines, workloads through governed transactions.
- `src/odind/workload_*.rs` — workload pods: exec, park, monitor watchdogs, anti-stuck recovery, watch findings.

### crates/odin-omp

Journaled RPC bridge over the pinned OMP harness, host tools, scoped URI reads, live-session runtime and conformance probe.

- `src/bridge/` — `OmpBridge`: journaled command surface over one child, correlation, checkpoints, rollover, side channel.
- `src/process/` — supervises one `omp --mode rpc` child: launch, bwrap sandbox, startup handshake, bounded streams.
- `src/frames.rs` — decodes protocol v1/v2 JSONL frames with bounds and chunk reassembly.
- `src/host_tools/` — model-visible tools, capability bindings, adapters, kube and brain tool traits.
- `src/host_tools/delegation/` — governed `task.*` delegation: parent links, lifecycle, reports.
- `src/host_tools/operations/` — kernel-governed authorization and dispatch of host tool calls.
- `src/live/` — live sessions behind Huginn: supervisor, session actors, normalizer, rollover, kernel MCP server.
- `src/live/harness/` — non-OMP harnesses: ACP, terminal, process turns, observe-only remote followers.
- `src/live/ledger/` — durable filesystem live-session journal with segments and replay.
- `src/live/zellij/` — Zellij terminal adapter: panes, control leases, screen capture.
- `src/uri/` — read-only scoped URI router: `atlas://`, `brain://`, `odin-artifact://`, run, lane, incident.
- `src/probe/` — 21-case conformance suite against the pinned OMP; `fixtures/` holds Bun peers.

### crates/odin-hermes

Life-workflow and conversation runtime: email, calendar, finance, vault, purchase, Discord, durable per-seat conversations.

- `src/conversation/` — one durable conversation per (seat, project): prompts, queue, delivery, rollover, vehicle.
- `src/runtime/` — `HermesRuntime` composing tools, ledgers, approval delivery, routes, schedule, coding and registry tools.
- `src/runtime/files.rs` — sends the owner real Discord attachments: intake files, shared artifacts, Immich photos and videos (converted to JPEG when Discord can't show the original) and brain documents.
- `src/email.rs`, `calendar.rs`, `provider.rs` — mail and calendar tools, approval-gated send and propose, account router.
- `src/account/` — scoped credential leases, account errors, durable external-effect settlement.
- `src/schedule.rs`, `natural.rs`, `delegation.rs`, `correlation.rs` — reminders and wakes, owner decision parsing, seat delegation, message-to-key mapping.

### crates/odin-huginn

ColinRemote backend and client library: tailnet-authenticated CBOR transport, read model, feeds, files, renders, k3s and simulation controls, device trust.

- `src/service.rs`, `state.rs`, `router.rs` — service composition, ports, HTTP/WebSocket router, content tickets.
- `src/auth.rs`, `devices.rs`, `private_network.rs` — tailnet device authentication, trusted-device SQLite store, peer verification.
- `src/protocol/` — versioned canonical CBOR frames, request and response codecs.
- `src/dispatch/` — authenticated serve loop: admission, routing, bounded outbox, connection registry.
- `src/streams/` — bounded multiplexer, credit backpressure, durable replay store.
- `src/read_model/` — materialized object snapshots, deltas, queries, search.
- `src/sessions/` — live-session adapters and seat roster projection.
- `src/files/`, `renders/` — confined file gateway with watches; render jobs with sanitized SVG.
- `src/kube/`, `browser/`, `simulation/` — k3s projection and workload controls, headed browser projection, simulation board.
- `src/client/` — shared client: transport trait, credentials, streams, chunked transfers, CLI path mapping.

### crates/odin-brain

Knowledge indexing, retrieval, archive ingest, seat memory and learned entries, over SQLite and PostgreSQL with pgvector.

- `src/service/` — `BrainService`: serving generations, scoped retrieval, core memory, prefetch, archive ingest, projection.
- `src/index/` — generation chunking, BM25 lexical indexes, SQLite store, PostgreSQL storage and sealing.
- `src/retrieval/` — retrieval plans, lexical and vector ranking, fusion, embedding through the gateway.
- `src/source/` — knowledge sources: Atlas, ops history, SilverBullet vault, registry, repos, tasks, live state.
- `src/source/archive/` — streaming parsers for ChatGPT, Claude, Gemini, Grok, NotebookLM and mbox exports.
- `src/archive/` — normalized archive record store with revisions and publications.
- `src/context/` — declared context budgets and exact token counting with a pinned Qwen tokenizer.
- `src/learn.rs`, `config.rs`, `projection.rs` — learned-entry store in git, policy from registry, Markdown projection.
- `migrations/`, `.sqlx/`, `assets/` — Postgres migrations, offline query metadata, tokenizer files.

### crates/odin-kube

Kubernetes execution: Job and pod creation, reconciliation, watches, placement, state carry, exec, ledger-journaled operations.

- `src/client.rs`, `config.rs` — `KubeClient` from an explicit kubeconfig.
- `src/job.rs`, `workload.rs`, `workload/` — Job builder and workload pod plans: state, egress NetworkPolicy, volume placement.
- `src/reconciler/` — run-addressed Job create, cancel, suspend, resume, restart, rehome, orphan collection.
- `src/backend.rs` — UID-guarded Job stop backend for the stop authority.
- `src/claude_pod.rs`, `terminal_pod.rs` — Claude and terminal pod plans, plus the terminal pod stop backend.
- `src/journal.rs` — ledger-backed operation journal for Kubernetes launches.

### crates/odin-process

Shell-free Linux process isolation: bounded runner, systemd D-Bus scopes, registered workers stopped by cgroup.

- `src/runner.rs`, `argv.rs`, `environment.rs`, `output.rs` — shell-free bounded runner with frozen argv and allowlisted environment.
- `src/systemd/` — minimal D-Bus client for transient scopes and unit properties.
- `src/worker/` — `WorkerAuthority`: owned launch, bootstrap, identity proof, cgroup stop, residue scan.
- `src/bin/odin-worker-bootstrap.rs` — strips bus authority, then execs the payload.

### crates/odin-browser

Headed Chromium BrowserArm in an isolated profile via a Playwright worker, with bounded untrusted reads and gated actions.

- `worker/worker.cjs` — sole Playwright adapter speaking bounded JSONL.
- `src/session.rs`, `session/` — session lifecycle, durable control state, authorization-bound handle, actions, reads, teardown.
- `src/policy.rs`, `safety.rs`, `scanner.rs`, `download.rs` — per-session rules, protected-value gate, malware scan, download quarantine.

### crates/odin-sweep

Production check runner: code-quality gates, SYS-nn system checks against live state, INT-* integration probes, graded report.

- `src/main.rs`, `runner.rs`, `report.rs` — CLI modes, tool command construction, result grading and exit code.
- `src/syscheck/` — SYS checks: pins, listeners, secrets, disk, activation drift, services, ledger, gateway, backup, hygiene.
- `src/probe_registry/` — INT probes: browser, k3s, kube, ledger, life, OMP, vault, via exact cargo test selection.

### crates/odin-sidecar, odin-sidecar-protocol, odin-effector, odin-confined-fs

Sidecar hosts the sole kernel operation authority over a Unix socket; the other three supply its wire, effector worker and confined filesystem.

- `odin-sidecar/src/{server,client,main}.rs` — Unix-socket server, client, and binary reading launch credentials on stdin.
- `odin-sidecar/src/authority/` — assembles kernel and ledger; admission, dispatch, provisioning, receipt store.
- `odin-sidecar-protocol/src/generated/` — authority wire v2 Rust codec, generated; do not hand-edit.
- `odin-sidecar-protocol/src/bin/codegen/` — generator from a frozen model to schema, Rust and TypeScript codecs, vectors.
- `odin-effector/src/main.rs`, `capsule.rs` — one-request worker: declare, observe, execute file, process and Git effects in a capsule.
- `odin-confined-fs/src/` — openat2-style confined, descriptor-relative reads, private atomic writes, relative-path validation.

### crates/odin-launch

Builds `odin-acp`: an ACP agent over stdio fronting the governed controller through Huginn, so editors attach to seat sessions.

- `src/main.rs` — explicit args (manifest, seat, project, provider); wires Huginn client and ACP streams.
- `src/acp.rs` — ACP JSON-RPC types, newline framing, frame limit, capabilities.
- `src/backend.rs` — plane actor over Huginn: session list and subscribe, reconnect, cursor tracking.
- `src/frontend.rs` — ACP state machine: events, permission replies bound to exact outstanding requests, setup checks.

### crates/odin-adapter-core, odin-adapter-mcp, odin-adapter-web

External adapter contract and its two shipped adapters.

- `odin-adapter-core/src/` — wire models validated against JSON Schemas, JSON-RPC transport, config, health status.
- `odin-adapter-core/src/dispatch.rs`, `evidence.rs` — `AdapterExecutor` under kernel authorization; receipt persisted before success.
- `odin-adapter-mcp/src/` — binary bridging one framed call to an MCP stdio server; read-only tools as R0, PDF windowing.
- `odin-adapter-web/src/` — `web.search` binary: SearXNG with Brave fallback, credentials from pinned files.

### crates/odin-atlas

Deterministic source-derived index (`odin.atlas.v1`) of Rust and TypeScript symbols, registry objects and skeletons, with scoped queries.

- `src/lib.rs` — `Atlas`, scoped queries, build and byte serialization.
- `src/code/` — Rust symbol discovery via syn (reachable public items) and TypeScript via tree-sitter.

### crates/odin-strict-json

Strict JSON decoding (duplicate-key rejection, byte ceilings) and canonical sorted compact ASCII encoding.

- `src/parse.rs`, `value.rs` — hand-written validating parser, then serde typed decode.
- `src/canonical.rs` — canonical serializer: sorted keys, compact, ASCII escapes.

### crates/odin-types

Shared validated identifiers, hashes and protocol reason codes.

- `src/ids.rs`, `hash.rs`, `gate.rs` — ID newtypes, hash helpers, gate reason codes.

### crates/odin-node

Validates registry node and host identity at startup; worker lifecycle stays in the kernel.

- `src/config.rs` — `NodeIdentity`: node and host present, enabled, enrolled, role match, gateway endpoint valid.

### registry/

Desired state in TOML (`schema = "odin.registry.v1"`, `kind`, `enabled`, `description`); `odin registry publish` commits and publishes a snapshot, `odind` reconciles it.

- `hosts/` — machines: laptop (paired client), mini (always-on control), pc (GPU worker).
- `nodes/` — the Odin runtime on a host (role, capabilities, gateway endpoint); mini is authoritative, laptop and pc are workers.
- `providers/` — model or service sources with budgets and recovery rungs: gateway, brain-embedding, codex-cli, openai-codex, observed, web-search.
- `harnesses/` — how an agent process runs: omp (governed through the kernel), codex (observed per prompt), observe (passive transcript).
- `capabilities/` — 91 governed tools with effect class R0 to R3, approval policy and schemas under `schemas/capability/`.
- `slices/` — named capability bundles admitted to sessions: architect-engine, colinremote-engine, gungnir-build, kubert-ops, sinmara-life, skuld-build, skuld-judge-review.
- `seats/` — agent roles with tools, allowed models and context profile: sinmara (coordinator), gungnir (coder), forseti (reviewer), kubert (ops), architect, reginn, scribe, skuld-builder, skuld-judge.
- `projects/` — repo or source roots with default seat and memory namespaces (odin, dotfiles, colinremote, skuld, surtr, life and others).
- `lanes/` — seat-on-project work lanes with family, queue and review rules, plus file and render exchange lanes.
- `containers/` — runnable profiles offered to seats: native OMP process or finite Kubernetes Job, optionally tied to a slice.
- `environments/` — where a harness runs: host, transport, sandbox, which seats (local sandbox, ssh, pod, Claude host tabs).
- `workloads/` — pod or script profiles (image, harness, network, state, lifetime); acceptance fixtures and probes.
- `routines/` — seat actions on schedule or event trigger; grant no extra permission.
- `context-profiles/` — core and injected memory budgets: lean, medium, high, codebase.
- Relations: lane binds seat to project; seat lists slices, capabilities and context profile; container, environment, harness and provider serve seats.

### schemas/

- `0001`–`0021_*.sql` — canonical ledger migrations: control plane, authority, workers, policy, kube operations, pods, approvals, trace.
- `authority/` — JSON Schema of authority wire v2.
- `control/` — JSON Schemas for adapter descriptor, operation, receipt and status, and `odind` config.
- `capability/` — `<capability>.input.json` and `.output.json` for each registry capability.
- `hermes/`, `huginn/` — SQLite migrations for the scheduler and for trusted devices and session grants.

### tooling

- `tools/deploy.sh` — pc-only: pins an origin/main commit in dotfiles, builds, switches hosts, publishes the registry.
- `skeletons/new-*/` — templates for alert, capability, container, environment, harness, host, lane, node, project, provider, seat, slice, surface, workload.
- `extension/` — `odin.ts` gates OMP tools by kernel listings and bridges host tools; `generated/` is the TS wire codec.
- `sweep/fixtures/` — wire vectors, home-module expected composition, authoring fills, browser handoff fixtures.
- `nix/`, `flake.nix` — crane builds, composition output, workload image, Home Manager module.
