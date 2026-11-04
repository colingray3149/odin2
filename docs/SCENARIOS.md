# Scenarios

What the owner can ask, what he should see, and the one backend check. Inventory for `tools/scenarios/run.py`.

```bash
python3 tools/scenarios/run.py --list
python3 tools/scenarios/run.py --dry-run fleet.host-devices
python3 tools/scenarios/run.py --area life
python3 tools/scenarios/run.py chat.casual seat.ask-kubert
```

`--list` prints tab-separated id, area, and status columns. A live row has a runner recipe. A manual row has no checker and needs a person to verify it; Needs records any additional prerequisite. The runner talks to live Huginn and the authority. Do not start a row against a host you do not intend to change.

`--dry-run` prints the selected recipes with sample tags and makes no live calls.

Run coding rows on the host that holds their declared checkouts; the runner never creates replacement repositories. Cleanup discovers only repositories used by the row, and deletes row-tagged workload jobs with their captured UID as an API precondition. Job checks wait for observable creation and phase, not the first delegation acknowledgement. Conversation checks use Huginn's owner thread; real Discord intake and attachment delivery remain separate prerequisites.

The gate runs fmt, clippy, tests, tsc/Bun, and deny; it does not run these scenarios or contract scans. A manual row is not a gate pass.

Columns: what the owner says, what he should see, one backend check, what the row needs. `—` means the runner sends no line, or the row has no extra need. `{tag}` and `{rid}` are the runner's nonce. Live checks are the recipe token.

`sessionseat:<seat>` requires a non-ended session started after the row began and a new `seat.ask.<seat>` journal entry. An older session does not pass.

Workload reclaim uses the pod's per-run `PI_CODING_AGENT_DIR` and stable working directory:
assembly reclaim and normal bridge recovery pass `--continue` through `workload-exec` to OMP.
They never resolve pod transcripts through host `HOME`. Fresh launches omit the selector;
fresh-context rollover strips it so the new conversation remains independently persisted.

Terra research/PDF review requires the daemon's explicit `ODIN_OMP_MODELS` declaration
to contain the selected provider/model. Pod admission preserves its image input,
context/output limits, reasoning/thinking and strict-mode compatibility metadata,
plus provider API/compatibility; only pod routing, credentials and spend tags are injected.
After deployment, manually exercise a sparse web-tool call and an image/PDF-page review
in an actual research pod. Check that strict schemas accept omitted optional fields and
that the model identifies page content rather than receiving image placeholders.
Generated-config contract tests alone do not prove this live OMP behavior.


### 5.1 Conversation

| ID | Says | Sees | Check | Needs |
|---|---|---|---|---|
| chat.casual | Say hello in one sentence. | A one-sentence greeting. | expectre: whole-word hello, hi, or hey | — |
| chat.facts | What is 17 times 42? | 714. | expect:714 | — |
| chat.lane | What is 17 times 23? | 391 on the declared lane. | expect:391 | — |
| chat.clarify | Book it sometime. | One clarification, no mutating action. | clarification reply; no new mutating journal entry | — |
| chat.refusal | Run a raw kubectl command for me. | A plain refusal. | expectre: cannot, can't, won't, refuse, or will not | — |
| chat.correction | Quote the first line of the odin README. | That line, from a fresh read. | readme: bounded wait for the README's first line in the reply | — |
| chat.model-switch | Switch to the other declared model and compute 6 times 7. | 42 on the target pair. | expect:42 | — |
| chat.astra-lane | Use the alternative lane and compute 9 times 9. | 81 on the alternative pair. | expect:81 | — |
| chat.restart-memory | Remember a fact, restart odind, ask again. | The fact is still there. A DM sent while down is answered after the daemon is back. | no checker | restarts odind; owner maintenance window |
| chat.whats-running | What is running? | Status that matches live workloads. | workloads | — |
| chat.web-search | Search the web for the current NixOS version and name the source. | A sourced answer. | journal-new:web.search | — |
| chat.web-failed-load | Read https://invalid.invalid/ and report the failure. | The page did not load. | journal-new:web.read; reply says did not load or could not load | — |
| chat.web-fallback | Search when searx misses. | A settled brave backend. | no checker | organic; searx is not stopped |
| adapter.web-fallback-controlled | — | The compiled adapter harness falls back from searxng to brave. | no checker | contract harness, not a conversation |
| time.convert | What is 15:30 UTC in Tokyo? | 00:30. | journal-new:time.convert_time | — |

### 5.2 Surfaces

| ID | Says | Sees | Check | Needs |
|---|---|---|---|---|
| chat.laptop-discord | Say a word on Discord, then on the laptop, then back. | Each surface recalls the other surface's word. | no checker | owner present, laptop unlocked |
| chat.surface-roam | Continue the same conversation across Discord, the laptop, and the installed Sessions UI. | The same thread, with a visible reply on each surface. | no checker | owner present, installed Sessions UI |
| chat.workspace-open | Open the workspace on the laptop. | Zed opens on the laptop under an owned unit. | no checker | owner present, laptop Zed |
| chat.workspace-project | Open the workspace for a project. | Zed opens on that project. | no checker | owner present, laptop Zed |
| workspace.zed-edit | Type a governed edit on the reserved desktop. | Those bytes land in the remote file. | no checker | owner present, reserved desktop |
| terminal.desktop-input | Send one desktop input into an owned empty terminal. | That one marker arrives, and focus returns. | no checker | owner present, reserved desktop |
| harness.zed-acp | Drive a Zed ACP session. | The visible Zed surface shows the session. | no checker | visible Zed surface; listed for the owner |
| huginn.terminal-control | Open a tabbed session, write a line into its terminal, then release it. | The write advances the terminal head, then the lease is released. A headless session refuses control. | sessionseat:sinmara | — |
| fleet.host-devices | — | Each of pc, mini, laptop, and enrolled hosts authenticates, and lastSeenAt advances. | devices | — |
| fleet.device-matrix | Send from a real phone. | The phone send lands, and the phone's lastSeenAt advances. | no checker | needs a real phone |

### 5.3 Life

| ID | Says | Sees | Check | Needs |
|---|---|---|---|---|
| life.csv-routine | Create a file_received routine named {rid} for CSV files. It must mention {tag} and state the data-row count. | The DM states that row count. | no checker | owner attaches the CSV in the Discord DM; huginn upload is not FileReceived |
| routine.repo-push | Create a temporary repo-push routine named {rid}, then push a scratch branch containing {tag} so it notifies. Leave main unchanged. | The DM names the branch. Cleanup removes the temporary routine. | push-fired:odin | — |
| life.history-research | Read one page about liquid rocket injectors and cite it. | A cited page, written under the research target. | journal-new:web.read | — |

### 5.4 Permissions

| ID | Says | Sees | Check | Needs |
|---|---|---|---|---|
| perm.task-grant | Ask for one grant covering two sends, then answer yes. | Both sends complete under that grant. No other question. | no checker | needs the owner to answer an approval |
| perm.no-worries | Answer "no worries", then a real no. | "no worries" leaves the question open. The real no denies it. Nothing is sent. | no checker | needs the owner to answer an approval |
| perm.paired-decision | Approve the pending question from the paired device. | One send, decided by that device. | no checker | needs the owner's paired approval |
| privacy.apl | Write a privacy note tagged {tag} whose secret line is SECRET-{tag} and whose class is APL_RESTRICTED. | The reply names APL_RESTRICTED and does not contain the secret line. | absent:SECRET-{tag} | — |

### 5.5 Memory

| ID | Says | Sees | Check | Needs |
|---|---|---|---|---|
| memory.forget | Remember secret {tag}. Then: Forget {tag}. | It is stored, then it is not recalled. | memgone:colin:{tag} | — |
| brain.correct | Remember {tag} means seven. Then: That's wrong: {tag} means nine. | The learned value is nine, and seven is gone. | memfile:colin:{tag}:nine:seven | — |
| brain.learn | Teach a fact, restart odind, ask in a fresh turn. | The fact is recalled without a search. | no checker | restarts odind; owner maintenance window |
| brain.repo | Run the rig test command you already learned. | That command runs. No rediscovery. | sessionseat:gungnir | — |
| brain.budget | Answer in one sentence: what is 2 plus 2? Then the same for 3 plus 3 and 4 plus 4. | Three short answers inside the core and prefetch budgets. | budget | — |
| brain.retirement | — | No retired identifiers in the production tree. | no checker | no checker |
| memory.knowledge-fabric | — | Knowledge pages are fresh, atlas sources are real, and no seat holds root-level tools. | no checker | no checker |
| memory.seat-task-lesson | Have gungnir record lesson {tag} from a report-only task. | The lesson is in gungnir's memory. | mempage:gungnir:{tag} | — |
| memory.project-isolation | Learn {tag} into the dotfiles project only. | dotfiles can read it. odin cannot. | memabsent:project.odin:{tag} | — |
| memory.seat-recall | Learn {tag} into the worker namespace, then have a fresh child of that seat read it back. | The child recalls it. The later question does not carry the value. | mempage:gungnir:{tag} | — |
| memory.personal-recall | Cite one item already in my personal notes and its source. Do not invent a token. | That item and its source. | vaultnote | — |
| memory.yesterday | What did I do yesterday? Cite the record, do not invent a token. | A record from the previous local day. | yesterday's local date: YYYY-MM-DD or month and day | — |

### 5.6 Seats

| ID | Says | Sees | Check | Needs |
|---|---|---|---|---|
| seat.ask-kubert | Ask Kubert whether the cluster is healthy. | Kubert answers from a cluster read. | sessionseat:kubert | — |
| seat.registry-read | Ask Kubert to name one workload profile. | A real profile name. | sessionseat:kubert | — |
| seat.parallel | Ask Kubert for the Ready node count and the architect for the flake input names. | Each seat answers its own ask. | sessionseat:architect | — |
| seat.publication-during-delegation | Publish routine {rid} that fires every five minutes and mentions {tag}, and ask Kubert to read cluster health without dropping this conversation. | The routine exists and a fresh Kubert session starts. | routine:{rid}; sessionseat:kubert | — |
| seat.escalation | Ask whether half-to-even or truncation is right, and put the answer on branch seat/acceptance/{rid} in rig. Do not delete the repository. Then: half-to-even. | The branch contains half-to-even. | gitfile:rig:{rid}:half-to-even | — |
| seat.pause-steer | Start a task on branch seat/acceptance/{rid} in rig and pause it. Do not delete the repository. Then: Steer that task to a single-return (a + b) / 2. | The branch contains that function. | gitfile:rig:{rid}:(a + b) / 2 | — |
| seat.temp-helper | Propose a temporary helper whose branch contains {rid}. Do not delete rig. | The helper exists for the task, then leaves the registry. | git:rig:{rid} | — |
| seat.two-tasks-one-repo | In rig, at the same time, have one child write def add on branch seat/acceptance/{rid}-a and another write def mul on branch seat/acceptance/{rid}-b. Leave main unchanged. Do not delete the repository. | Two branches, main unchanged. | children:2 | — |
| seat.seat-create | Make a helper called acceptance-scribe to write concise summaries of my Odin work. | That seat is declared, and a fresh child can see its checkout. | seatfile:acceptance-scribe | — |
| seat.gungnir-branch-merge | On the rig fixture, land a reviewed merge of two branches whose names contain {rid}-a and {rid}-b. Do not delete the fixture. | The merge lands. Both branches are reviewed. | merge:rig:{rid} | — |
| seat.rust-merge | On the rig fixture, merge two functions under the shared anchor on branches {rid}-a and {rid}-b. Do not delete the fixture. | mergiraf resolves them, and the fixture tests run. | merge:rig:{rid} | — |
| seat.gungnir-refactor | On rig, push branch seat/gungnir/refactor-{rid} with a narrowed change. Do not delete the repository. | That branch exists with the narrowed change. | gitfile:rig:{rid}:fn | — |
| seat.stall-resume | — | An organic stall resumes on its own child. | no checker | organic; not induced |
| seat.quota-rotation | — | An organic rotation reaches a resumed request on the selected lane. | no checker | organic; not induced |
| seat.fallback-lineage | — | A gateway-fallback line matches that child's fallback record. | no checker | organic; not induced |
| seat.observe-foreign | — | An already-open observer fires on the needle and stays quiet on the benign backlog. | no checker | needs an already-open observer; odind must not be restarted for it |
| registry.environment-kind | — | The required environment declaration is published and valid. | no checker | no checker |

### 5.7 Claude

Claude is a workload driver, not a seat. These rows wait on the owner's account.

| ID | Says | Sees | Check | Needs |
|---|---|---|---|---|
| seat.claude-driver | Open Claude, prompt it once, read the result, stop. | One prompt, a branch tip, a stop that does not discard the work. | no checker | owner account hold |
| seat.claude-driver-host-tab | Open the host-tab preset, select its transcript in odin view and page beyond one bounded page. | A bwrapped owner-driven hub PTY, Remote Control enabled, verified transcript cursors with no duplicate frames. It is not prompted by Odin. | no checker | owner account hold |
| seat.claude-driver-normal | Open the normal-cwd preset. | Bubblewrap remains active; dirty files in the cwd are preserved. No worktree is created. | no checker | owner account hold |
| seat.claude-review | Run claude_review on a small non-sensitive brain-relative bundle, then three self-invoked reviews in one UTC day. | Review returns text and an artifact; self reviews stay silent unless material. Fourth self call names self_per_day; eleventh total names max_per_day. Archive/private/records/media components and opaque artifacts are refused. | no checker | owner account hold |

### 5.8 Pods

| ID | Says | Sees | Check | Needs |
|---|---|---|---|---|
| pod.lifecycle | Start a restart-on-failure service job. Then suspend, resume, and stop it. | Suspend, a fresh pod on resume, then absence. | kube:absent | — |
| pod.exports | Run an export job and report the captured files. | The captured files are named. | artifact | — |
| pod.watchdog-telemetry | Start a job so its watchdog publishes a warning and does not page the phone. | One warning, phone=false. | incident:phone=false | — |
| pod.anti-stuck | Start a counter job that stays stuck so the watchdog pages the phone. | One stuck incident, phone=true. | incident:phone=true | — |
| pod.emergency-stop | Emergency-stop, then resume. | Jobs and odind stop. After resume, Sinmara answers. | no checker | global kill; owner window |
| lifecycle.browser-containment | Open a browser in a pod and report the frame. | A frame artifact. Off-host navigation is refused. | frame | — |
| board.simulation | Register a simulation mission whose run contains {tag}. | The mission is visible, with its checkpoint and renderers. | tagged run's mission has a checkpoint and renderers | — |

### 5.9 Fleet

| ID | Says | Sees | Check | Needs |
|---|---|---|---|---|
| fleet.one-commit | — | mini and pc report the same configuration revision and no failed units. Laptop may be away. arm is not rolled. | fleet | — |
| fleet.sweep | — | `sweep --system` on mini passes its authority checks. | sweep | — |
| fleet.follower-sweep | — | pc and laptop report the follower subset. Authority-only checks are N/A. | sweep:followers | — |
| fleet.reach | — | LAN, Huginn, and Ready nodes answer. | nodes | — |
| fleet.vault-sync | — | A scratch note appears on mini, then disappears after local retirement. | vault:{tag} | — |
| fleet.embeddings | — | An authority-local embedding request returns a numeric 256-d vector. | embed | — |
| fleet.drain-restore | Say mini is going down, then that it is back. | Work pauses and rehomes. Mini is cordoned, then uncordoned. Authority does not move. | no checker | cordons the authority host |

### 5.10 Manual checks

These have no runner checker.

| ID | Says | Sees | Check | Needs |
|---|---|---|---|---|
| §3 Declared project roots may advance | — | Declared roots still resolve. | no checker | no checker |
| §3 Brain cost while idle and per turn | — | Per-turn budget holds. Idle cost is not measured here. | no checker | needs idle-cost measurement |
| §3 A re-embedded pool is the same pool | — | An exact re-embed scores as the same pool. | no checker | no checker |
| §4 Creation law in code | — | A widening fill is rejected and does not publish. | no checker | no checker |
| §6 One pinned workload image per odin pin | — | Published workload image references match the deployed pin. | no checker | needs deployed image comparison |
| §6 Cross-node pod network (854 Mbit/s) | — | Cross-node pod behavior holds. | no checker | needs throughput measurement |
| §7 Authority move pc → mini | — | Mini is the authority. The move is not repeated. | no checker | historical, not repeatable |
| §7 Cross-device pick-up | — | The laptop picks up the same conversation. | no checker | owner present |
| §7 Phone alerts via ntfy | — | A warning has no ntfy post. A page does. | no checker | owner window |
| pod.independent-review | Launch research and research-deep pods with distinct questions. | Each Job has its own independent Kubert `gateway/glm-flash` session. Every declared 180s cycle receives the profile brief, verified staged question/inputs, recent events/tool errors, progress, idle age and settlement state. Structured decisions steer, restart, cancel, or wake Sinmara through daemon authority bound to that Job only. | After integration: exercise two pods, restart the daemon between dispatch and response, verify no cross-pod control or duplicate action, then finish/cancel both and observe reviewer termination. | Authoritative daemon, reachable cluster/gateway; durable `workload-review.json`. No live check performed during implementation. |

Names that are not rows: harness.acp, pod.agent-non-omp, seat.non-omp-ask, seat.non-omp-laptop-stop, perm.approval-law-registry. Claude is a driver (5.7). Do not put those names back in a table.
