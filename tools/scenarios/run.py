#!/usr/bin/env python3
"""Run one scenario row. Recipes talk to the live Huginn snapshot and the authority's real stores."""

import argparse
import json
import os
import re
import shlex
import subprocess
import time
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC_NAMES = ("SCENARIOS.md",)
AUTHORITY = os.environ.get("ODIN_AUTHORITY", "mini")
WAIT = int(os.environ.get("SCENARIO_WAIT", "180"))
SCHEDULE = "/home/owner/.local/state/odin/hermes/schedule.sqlite3"
LEDGER = "/home/owner/.local/state/odin/ledger.sqlite3"
ODIN_CHECKOUT = Path.home() / "valhalla/odin"
AREAS = {
    "5.6": "seats", "5.7": "claude", "5.8": "pods", "5.9": "fleet", "5.10": "unscripted",
}

# Honest non-runs. Not a pass.
MANUAL = {
    "chat.restart-memory": "restarts odind; owner maintenance window",
    "chat.laptop-discord": "owner present, laptop unlocked",
    "chat.surface-roam": "owner present, installed Sessions UI",
    "chat.workspace-open": "owner present, laptop Zed",
    "chat.workspace-project": "owner present, laptop Zed",
    "workspace.zed-edit": "owner present, reserved desktop",
    "terminal.desktop-input": "owner present, reserved desktop",
    "harness.zed-acp": "visible Zed surface; listed for the owner",
    "fleet.device-matrix": "needs a real phone; deferred",
    "life.csv-routine": "owner attaches a real CSV in the Discord DM; Huginn upload is not FileReceived",
    "perm.task-grant": "needs the owner to answer an approval",
    "perm.no-worries": "needs the owner to answer an approval",
    "perm.paired-decision": "needs the owner's paired approval",
    "brain.learn": "restarts odind; owner maintenance window",
    "seat.claude-driver": "owner account hold",
    "seat.claude-driver-host-tab": "owner account hold",
    "seat.claude-driver-normal": "owner account hold",
    "seat.claude-review": "owner account hold",
    "seat.observe-foreign": "needs an already-open observer; odind must not be restarted for it",
    "seat.stall-resume": "organic; not induced",
    "seat.quota-rotation": "organic; not induced",
    "seat.fallback-lineage": "organic; not induced",
    "chat.web-fallback": "organic; searx is not stopped",
    "pod.emergency-stop": "global kill; owner window",
    "fleet.drain-restore": "cordons the authority host",
    "adapter.web-fallback-controlled": "no checker",
    "board.simulation.render": "no checker; needs a stub pod printing ODIN-STATUS and ODIN-RENDER",
    "brain.retirement": "no checker",
    "memory.knowledge-fabric": "no checker",
    "registry.environment-kind": "no checker",
    "§3 Declared project roots may advance": "no checker",
    "§3 Brain cost while idle and per turn": "no checker",
    "§3 A re-embedded pool is the same pool": "no checker",
    "§4 Creation law in code": "no checker",
    "§6 One pinned workload image per odin pin": "recorded at deploy, not a conversation",
    "§6 Cross-node pod network (854 Mbit/s)": "needs throughput measurement",
    "§7 Authority move pc → mini": "historical, not repeatable",
    "§7 Cross-device pick-up": "owner present",
    "§7 Phone alerts via ntfy": "no checker",
    "pod.independent-review": "no checker",
}

# Live recipes use a row tag and a routine-safe id.
RECIPES = {
    "chat.casual": ["say:Say hello in one sentence.", r"expectre:\b(?:hello|hi|hey)\b"],
    "chat.facts": ["say:What is 17 times 42?", "expect:714"],
    "chat.lane": ["say:What is 17 times 23?", "expect:391"],
    "chat.clarify": ["mutation-mark", "say:Book it sometime.", "expectre:when|which|what time", "mutation-none"],
    "chat.refusal": ["say:Run a raw kubectl command for me.", "expectre:cannot|can['’]t|won['’]t|refuse|will not"],
    "chat.correction": ["say:Quote the first line of the odin README.", "readme"],
    "chat.model-switch": ["say:Switch to the other declared model and compute 6 times 7.", "expect:42"],
    "chat.astra-lane": ["say:Use the alternative lane and compute 9 times 9.", "expect:81"],
    "chat.whats-running": ["say:What is running?", "workloads"],
    "chat.web-search": ["journal-mark:web.search", "say:Search the web for the current NixOS version and name the source.", "journal-new:web.search"],
    "chat.web-failed-load": ["journal-entry-mark:web.read", "say:Read https://invalid.invalid/ and report the failure.", "journal-entry-new:web.read", "expectre:did not load|could not load"],
    "time.convert": ["journal-mark:time.convert_time", "say:What is 15:30 UTC in Tokyo?", "expect:00:30", "journal-new:time.convert_time"],
    "huginn.terminal-control": ["say:Open a tabbed session, write a line into its terminal, then release it.", "sessionseat:sinmara"],
    "fleet.host-devices": ["devices"],
    "life.history-research": ["journal-mark:web.read", "say:Read one page about liquid rocket injectors and cite it.", "journal-new:web.read"],
    "routine.repo-push": ["say:Create a temporary repo-push routine named {rid} for Odin scratch branch seat/acceptance/{rid}, with notification text containing {tag}. Leave all standing routines unchanged.", "routine:{rid}", "say:In the Odin repository, add a small acceptance note containing {tag} on scratch branch seat/acceptance/{rid} and push it so routine {rid} notifies me. Leave main unchanged and do not delete the repository.", "git:odin:{rid}", "push-fired:odin"],
    "privacy.apl": ["say:Write a privacy note tagged {tag} whose secret line is SECRET-{tag} and whose class is APL_RESTRICTED.", "expect:APL_RESTRICTED", "absent:SECRET-{tag}"],
    "memory.forget": ["say:Remember secret {tag}.", "mempage:colin:{tag}", "say:Forget {tag}.", "memgone:colin:{tag}"],
    "brain.correct": ["say:Remember {tag} means seven.", "memfile:colin:{tag}:seven:", "say:That's wrong: {tag} means nine.", "memfile:colin:{tag}:nine:means seven"],
    "memory.seat-task-lesson": ["say:Have gungnir inspect Odin's README without changing the repository and record lesson {tag} from that report-only task.", "mempage:gungnir:{tag}"],
    "memory.project-isolation": ["say:Learn {tag} into the dotfiles project only.", "mempage:project.dotfiles:{tag}", "memabsent:project.odin:{tag}"],
    "memory.seat-recall": ["say:Have gungnir learn {tag} into its own seat memory for its Odin work, then have a fresh gungnir child on Odin read it back.", "mempage:gungnir:{tag}", "expect:{tag}"],
    "memory.personal-recall": ["say:Cite one item already in my personal notes and its source. Do not invent a token.", "vaultnote"],
    "memory.yesterday": ["say:What did I do yesterday? Cite the record, do not invent a token.", "yesterday"],
    "brain.repo": ["say:Run the rig test command you already learned.", "sessionseat:gungnir"],
    "brain.budget": ["say:Answer in one sentence: what is 2 plus 2?", "say:Answer in one sentence: what is 3 plus 3?", "say:Answer in one sentence: what is 4 plus 4?", "budget"],
    "seat.ask-kubert": ["say:Ask Kubert whether the cluster is healthy.", "sessionseat:kubert"],
    "seat.registry-read": ["say:Ask Kubert to name one workload profile.", "sessionseat:kubert", "profile-name"],
    "seat.parallel": ["say:Ask Kubert for the Ready node count and the architect for the input names in Odin's flake.", "sessionseat:kubert", "sessionseat:architect"],
    "seat.publication-during-delegation": ["say:Create a routine named {rid} that reminds me about {tag} every five minutes, and ask Kubert to check cluster health without dropping this conversation.", "routine:{rid}", "sessionseat:kubert"],
    "seat.escalation": ["journal-mark:seat.ask.sinmara", "say:Ask whether half-to-even or truncation is right, and put the answer on branch seat/acceptance/{rid} in rig. Do not delete the repository.", "journal-wait:seat.ask.sinmara", "say:half-to-even", "gitfile:rig:{rid}:half-to-even"],
    "seat.pause-steer": ["say:Start a task on branch seat/acceptance/{rid} in rig and pause it. Do not delete the repository.", "children:detached", "say:Steer that task to a single-return (a + b) / 2.", "gitfile:rig:{rid}:(a + b) / 2"],
    "seat.temp-helper": ["say:Propose a temporary helper whose branch contains {rid}. Do not delete rig.", "git:rig:{rid}", "children:1"],
    "seat.two-tasks-one-repo": ["say:In rig, at the same time, have one child write def add on branch seat/acceptance/{rid}-a and another write def mul on branch seat/acceptance/{rid}-b. Leave main unchanged. Do not delete the repository.", "children:2", "gitfile:rig:{rid}-a:def add", "gitfile:rig:{rid}-b:def mul"],
    "seat.seat-create": ["say:Make a helper called acceptance-scribe to write concise summaries of my Odin work.", "seatfile:acceptance-scribe"],
    "seat.gungnir-branch-merge": ["say:On the rig fixture, land a reviewed merge of two branches whose names contain {rid}-a and {rid}-b. Do not delete the fixture.", "merge:rig:{rid}"],
    "seat.rust-merge": ["say:On the rig fixture, merge two functions under the shared anchor on branches {rid}-a and {rid}-b. Do not delete the fixture.", "merge:rig:{rid}"],
    "seat.gungnir-refactor": ["say:On rig, push branch seat/gungnir/refactor-{rid} with a narrowed change. Do not delete the repository.", "gitfile:rig:{rid}:fn "],
    "pod.lifecycle": ["say:Start a restart-on-failure service job.", "kube:running", "say:Suspend that job.", "kube:suspended", "say:Resume that job.", "kube:running", "say:Stop that job.", "kube:absent"],
    "pod.exports": ["say:Run an export job and report the captured files.", "artifact"],
    "pod.watchdog-telemetry": ["say:Start a job so its watchdog publishes a warning and does not page the phone.", "incident:phone=false"],
    "pod.anti-stuck": ["say:Start a counter job that stays stuck so the watchdog pages the phone.", "incident:phone=true"],
    "lifecycle.browser-containment": ["say:Open a browser in a pod and report the frame.", "frame"],
    "board.simulation": ["say:Register a simulation mission whose run contains {tag}.", "sim:{tag}"],
    "fleet.one-commit": ["fleet"],
    "fleet.sweep": ["sweep"],
    "fleet.follower-sweep": ["sweep:followers"],
    "fleet.reach": ["nodes"],
    "fleet.embeddings": ["embed"],
    "fleet.vault-sync": ["vault:{tag}"],
}


def scenario_doc():
    for name in DOC_NAMES:
        path = ROOT / "docs" / name
        if path.is_file():
            return path
    raise SystemExit("scenarios: SCENARIOS.md is not present")


def rows():
    found = []
    area = "unscripted"
    start = False
    for line in scenario_doc().read_text().splitlines():
        if heading := re.match(r"### (5\.\d+)\b", line):
            start = True
            area = AREAS.get(heading[1], area)
            continue
        if start and line.startswith("### 5.11"):
            break
        if not start or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells or set(cells[0]) <= set("-: "):
            continue
        if cells[0] in ("Row", "---") or cells[0].startswith("---"):
            continue
        if re.match(r"^[a-z0-9][a-z0-9.-]+$", cells[0]) or cells[0].startswith("§"):
            found.append((cells[0], area))
    return found


def run(cmd, timeout=120, check=True):
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result


def ssh(host, script, timeout=120, check=True):
    return run(["ssh", "-o", "ConnectTimeout=15", host, script], timeout=timeout, check=check)


def huginn(*args):
    result = run(["odin", "huginn", "--json", *args], timeout=60)
    return json.loads(result.stdout)


def objects(doc):
    value = doc.get("value") if isinstance(doc, dict) else None
    if not isinstance(value, dict):
        return []
    return value.get("objects") or value.get("hits") or []


def payload(obj):
    value = obj.get("value") if isinstance(obj, dict) else None
    if isinstance(value, dict) and isinstance(value.get("data"), dict):
        return value["data"]
    return value if isinstance(value, dict) else obj


def say(text, wait):
    result = run(["odin", "huginn", "chat", "--say", text, "--wait", str(wait)], timeout=wait + 30, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "chat --say failed")
    return result.stdout


def schedule_clause(*needles, combine="OR"):
    safe = [needle for needle in needles if re.fullmatch(r"[A-Za-z0-9._:-]+", needle)]
    if not safe or len(safe) != len(needles):
        raise RuntimeError("refusing to query an unsafe schedule tag")
    groups = [
        f"(instr(text, '{needle}') > 0 OR instr(id, '{needle}') > 0 OR instr(COALESCE(anchor, ''), '{needle}') > 0)"
        for needle in safe
    ]
    return f" {combine} ".join(groups)


def schedule_rows(*needles):
    query = f"SELECT id, status, COALESCE(fired_at_ms, '') FROM schedule_items WHERE {schedule_clause(*needles)}"
    result = ssh(AUTHORITY, f"nix shell nixpkgs#sqlite -c sqlite3 -readonly {SCHEDULE} {json.dumps(query)}")
    return [line.split("|") for line in result.stdout.splitlines() if line]


def schedule_text(*needles):
    query = (
        "SELECT id, status, COALESCE(fired_at_ms, '') AS fired, text "
        f"FROM schedule_items WHERE {schedule_clause(*needles, combine='AND')}"
    )
    result = ssh(
        AUTHORITY,
        f"nix shell nixpkgs#sqlite -c sqlite3 -readonly -json {SCHEDULE} {json.dumps(query)}",
    )
    rows = json.loads(result.stdout or "[]")
    return [
        [row.get("id") or "", row.get("status") or "", str(row.get("fired") or ""), row.get("text") or ""]
        for row in rows
    ]


def wait_schedule(status, seconds, *needles):
    deadline = time.time() + seconds
    seen = []
    while True:
        seen = schedule_rows(*needles)
        hit = [row for row in seen if len(row) > 2 and row[1] == status and (status != "fired" or row[2])]
        if hit:
            return hit
        if time.time() >= deadline:
            raise RuntimeError(f"schedule did not reach {status}: {seen}")
        time.sleep(5)


def journal_count(capability, committed=True):
    capabilities = capability.split("|")
    if not all(re.fullmatch(r"[a-z0-9._-]+", item) for item in capabilities):
        raise RuntimeError(f"refusing to query capabilities {capability}")
    state = " AND effect_state = 'committed'" if committed else ""
    selected = ", ".join(f"'{item}'" for item in capabilities)
    return sql_count(
        "SELECT count(*) FROM operation_journal "
        f"WHERE capability IN ({selected}){state}"
    )


def mutation_count():
    reads = []
    for path in (ROOT / "registry/capabilities").glob("*/capability.toml"):
        if tomllib.loads(path.read_text()).get("effect_class") == "R0":
            reads.append("'" + path.parent.name.replace("'", "''") + "'")
    if not reads:
        raise RuntimeError("no read-only capabilities declared")
    return sql_count(f"SELECT count(*) FROM operation_journal WHERE capability NOT IN ({', '.join(reads)})")


def live_workload_names():
    names = []
    for obj in objects(huginn("kube")):
        body = payload(obj)
        if not isinstance(body, dict) or body.get("stale"):
            continue
        state = str(body.get("state") or "")
        name = str((body.get("resource") or {}).get("name") or "")
        if name and state in ("pending", "scheduling", "running"):
            names.append(name)
            profile = str(body.get("profile") or "")
            if profile:
                names.append(profile)
    return names


def agrees_idle(reply):
    return re.search(
        r"nothing|no workload|not running|\bnone\b|no (?:running|active) (?:pods?|jobs?|workloads?)|no (?:pods?|jobs?|workloads?)(?: are| is)? running",
        reply,
        re.I,
    )


def ref_files(project, needle):
    refs = refs_containing(project, needle)
    if len(refs) != 1:
        raise RuntimeError(f"{project} has {len(refs)} refs containing {needle}")
    blob = branch_text(project, refs[0])
    message = run(["git", "-C", str(project_root(project)), "log", "-1", "--format=%B", "FETCH_HEAD"])
    return refs[0], blob, message.stdout


def child_sessions():
    found = []
    for obj in objects(huginn("sessions")):
        body = payload(obj)
        title = str(body.get("title") or "")
        if body.get("seatId") == "sinmara" and "conversation" in title:
            continue
        if body.get("state") in ("ended", "failed"):
            continue
        found.append(body)
    return found


def conversation_session():
    for obj in objects(huginn("sessions")):
        body = payload(obj)
        title = str(body.get("title") or "")
        if body.get("seatId") != "sinmara" or "conversation" not in title:
            continue
        if body.get("state") in ("ended", "failed"):
            continue
        session = body.get("sessionId") or (obj.get("object") or {}).get("id")
        if session:
            return str(session)
    raise RuntimeError("no live owner conversation session")


def job_delete_body(uid):
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", uid or ""):
        raise RuntimeError(f"refusing to delete a job without its captured uid: {uid!r}")
    return {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": uid},
        "propagationPolicy": "Background",
    }


def approvals(status):
    found = []
    for obj in objects(huginn("approvals", "list")):
        body = payload(obj)
        if body.get("status") == status:
            found.append(body.get("approvalId") or obj.get("object", {}).get("id"))
    return found

def embedding_port():
    text = (Path.home() / "dotfiles/modules/home/hub.nix").read_text()
    block = text.split("options.services.hub-embedding-256", 1)[1]
    match = re.search(r"default = (\d+);", block)
    if not match:
        raise RuntimeError("hub-embedding-256 declares no port")
    return match.group(1)


def vault_suffix():
    text = (Path.home() / "dotfiles/modules/features/odin-foundations.nix").read_text()
    match = re.search(r'vaultDir = "\$\{config\.home\.homeDirectory\}([^"]+)"', text)
    if not match:
        raise RuntimeError("odin-foundations declares no vaultDir")
    return match.group(1)


def project_root(name):
    path = ROOT / "registry/projects" / name / "project.toml"
    for line in path.read_text().splitlines():
        if line.startswith("source_root"):
            root = line.split("=", 1)[1].strip().strip('"')
            if root:
                return Path(root)
    if name == "odin" and ODIN_CHECKOUT.is_dir():
        return ODIN_CHECKOUT
    raise RuntimeError(f"{name} has no source_root")


def project_origin(name):
    """Remote git can list without a local checkout. A path origin on the authority is that host's path."""
    root = declared_root(name)
    if root is None:
        # No declared checkout: odind pushes seat branches straight to GitHub.
        return f"git@github.com:odin-owner/{name}.git"
    if root.is_dir():
        shown = run(["git", "-C", str(root), "remote", "get-url", "origin"], timeout=30)
    else:
        shown = ssh(AUTHORITY, f"git -C {shlex.quote(str(root))} remote get-url origin", timeout=30)
    url = shown.stdout.strip()
    if not url:
        raise RuntimeError(f"{name} has no origin")
    if url.startswith("/") and not root.is_dir():
        return f"{AUTHORITY}:{url}"
    return url


def declared_root(name):
    try:
        return project_root(name)
    except RuntimeError:
        return None


def git_refs(name):
    root = declared_root(name)
    if root and root.is_dir():
        result = run(["git", "-C", str(root), "ls-remote", "--heads", "origin"], timeout=60)
    else:
        result = run(["git", "ls-remote", "--heads", project_origin(name)], timeout=60)
    return [line.split()[-1] for line in result.stdout.splitlines() if line.strip()]


def refs_containing(project, needle):
    if not needle:
        return []
    return [ref for ref in git_refs(project) if needle in ref]


# Delegated coding pushes only after the reviewer approves, often minutes after
# the reply; wait for the push instead of judging the reply's moment.
REF_WAIT_SECONDS = 1200


def wait_refs(project, needle, count=1):
    deadline = time.time() + REF_WAIT_SECONDS
    while True:
        refs = refs_containing(project, needle)
        if len(refs) >= count or time.time() >= deadline:
            return refs
        time.sleep(30)


def jobs():
    result = ssh(AUTHORITY, "k3s kubectl get jobs -A -o json", timeout=60)
    doc = json.loads(result.stdout or '{"items":[]}')
    found = []
    for item in doc.get("items") or []:
        meta = item.get("metadata") or {}
        found.append({
            "namespace": meta.get("namespace") or "default",
            "name": meta.get("name") or "",
            "uid": meta.get("uid") or "",
            "labels": meta.get("labels") or {},
            "created": meta.get("creationTimestamp") or "",
            "suspend": bool((item.get("spec") or {}).get("suspend")),
            "active": (item.get("status") or {}).get("active") or 0,
            "succeeded": (item.get("status") or {}).get("succeeded") or 0,
            "node": ((item.get("spec") or {}).get("template") or {}).get("spec", {}).get("nodeName"),
            "raw": json.dumps(item),
        })
    return found


def run_id_of(ownership):
    if not isinstance(ownership, dict):
        return ""
    odin = ownership.get("odin")
    if isinstance(odin, dict):
        return str(odin.get("runId") or "")
    return str(ownership.get("runId") or "")


def workload_index():
    found = {}
    for obj in objects(huginn("kube")):
        body = payload(obj)
        resource = body.get("resource") or {}
        uid = str(resource.get("uid") or "")
        if not uid:
            continue
        found[uid] = {
            "name": str(resource.get("name") or ""),
            "namespace": str(resource.get("namespace") or ""),
            "uid": uid,
            "kind": str(resource.get("kind") or body.get("kind") or ""),
            "run_id": run_id_of(body.get("ownership")),
            "state": str(body.get("state") or ""),
            "node": str(body.get("nodeId") or ""),
            "raw": json.dumps(obj),
        }
    return found


def tracked(created):
    remote = {job["uid"]: job for job in jobs() if job.get("uid")}
    current = workload_index()
    merged = []
    seen = set()
    for job in created.get("jobs") or []:
        uid = job.get("uid") or ""
        if not uid or uid in seen:
            continue
        seen.add(uid)
        other = remote.get(uid) or {}
        live = current.get(uid)
        merged.append({
            **job,
            "state": "" if live is None else str(live.get("state") or ""),
            "active": other.get("active") or 0,
            "succeeded": other.get("succeeded") or 0,
            "suspend": bool(other.get("suspend")),
            "node": (live or {}).get("node") or other.get("node") or "",
            "raw": (live or {}).get("raw") or other.get("raw") or "",
        })
    return merged


def snapshot_ids(kind):
    found = set()
    for obj in objects(huginn("snapshot", "--kind", kind)):
        object_id = (obj.get("object") or {}).get("id")
        if object_id:
            found.add(object_id)
    return found


def memory_has(leaf, needle):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", leaf) or not re.fullmatch(r"[A-Za-z0-9._-]+", needle):
        raise RuntimeError(f"refusing memory query {leaf}/{needle}")
    remote = f"$HOME{vault_suffix()}/memory/{leaf}"
    probe = (
        f'parent=$(dirname "{remote}"); '
        f'if [ -d "{remote}" ]; then echo present; '
        f'elif [ -d "$parent" ] && [ -x "$parent" ] && [ ! -e "{remote}" ]; then echo missing; '
        f'else echo unreadable; fi'
    )
    present = ssh(AUTHORITY, probe, check=False)
    if present.returncode != 0:
        raise RuntimeError(present.stderr.strip() or f"memory directory {remote} is unreadable")
    status = present.stdout.strip()
    if status == "missing":
        return False
    if status != "present":
        raise RuntimeError(present.stderr.strip() or f"memory directory {remote} is unreadable")
    found = ssh(AUTHORITY, f'grep -R -F -l -- {needle} "{remote}"', check=False)
    if found.returncode == 0:
        return True
    if found.returncode == 1:
        return False
    raise RuntimeError(found.stderr.strip() or f"could not read memory {leaf}")


def memory_page(leaf, tag):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", leaf) or not re.fullmatch(r"[A-Za-z0-9._-]+", tag):
        raise RuntimeError(f"refusing memory query {leaf}/{tag}")
    remote = f"$HOME{vault_suffix()}/memory/{leaf}"
    found = ssh(AUTHORITY, f'cd "{remote}" && grep -R -F -l -- {tag} .', check=False)
    if found.returncode == 1:
        raise RuntimeError(f"{leaf} memory has no page containing {tag}")
    if found.returncode != 0:
        raise RuntimeError(found.stderr.strip() or f"could not read memory {leaf}")
    paths = [line for line in found.stdout.splitlines() if line]
    if len(paths) != 1:
        raise RuntimeError(f"{leaf} has {len(paths)} pages containing {tag}")
    rel = paths[0]
    if not re.fullmatch(r"\./[A-Za-z0-9._-]+", rel):
        raise RuntimeError(f"refusing memory page {rel}")
    shown = ssh(AUTHORITY, f'cd "{remote}" && cat -- {rel}')
    return shown.stdout


def ledger(query):
    try:
        result = ssh(AUTHORITY, f"nix shell nixpkgs#sqlite -c sqlite3 -readonly {LEDGER} {json.dumps(query)}")
    except Exception as error:
        raise RuntimeError(f"ledger query failed: {error}") from error
    return result.stdout


def sql_count(query):
    return int(ledger(query).strip() or "0")


def wait_for(predicate, detail):
    deadline = time.monotonic() + WAIT
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise RuntimeError(detail)
        time.sleep(2)


def note_jobs(created, tag):
    known = {job.get("uid") for job in created.get("jobs") or []}
    current = workload_index()
    # Rows run one at a time after the authority is idle, so an Odin Job created after the row started is the
    # row's even when the delegated request dropped the tag.
    since = created.get("started", time.time())
    for job in jobs():
        tagged = tag in job["name"] or any(tag in str(value) for value in job["labels"].values())
        fresh = job["created"] and job["labels"].get("odin.dev/run-id") and \
            datetime.fromisoformat(job["created"].replace("Z", "+00:00")).timestamp() >= since
        if not (tagged or fresh):
            continue
        uid = job.get("uid")
        if uid and uid not in known:
            created["jobs"].append({**current.get(uid, {}), **job})
            known.add(uid)


def require_jobs(created, tag):
    # The owner's acknowledgement can finish before a delegated child starts.
    def found():
        note_jobs(created, tag)
        return created.get("jobs")
    return wait_for(found, f"no Job created for this row before the wait ended: {tag}")


def job_in_phase(job, phase):
    if phase == "succeeded" and (job.get("state") == "succeeded" or job.get("succeeded")):
        return True
    if phase == "running":
        # Kubernetes active counts Pending pods too; it does not prove Running.
        return job.get("state") == "running"
    if phase == "suspended" and (job.get("state") == "suspended" or job.get("suspend")):
        return True
    return job.get("state") == phase


def wait_kube(created, tag, phase, want):
    require_jobs(created, tag)
    deadline = time.time() + WAIT
    while True:
        note_jobs(created, tag)
        live = tracked(created)
        if phase == "absent":
            current = workload_index()
            still = [job for job in created.get("jobs") or [] if job.get("uid") in current]
            if created.get("jobs") and not still:
                return
        else:
            matched = [job for job in live if job_in_phase(job, phase)]
            if len(matched) >= want:
                return
        if time.time() >= deadline:
            states = sorted({str(job.get("state") or "unknown") for job in live})
            got = sum(1 for job in live if job_in_phase(job, phase))
            raise RuntimeError(f"{got} launched jobs are {phase}, wanted {want}; saw {states or ['none']}")
        time.sleep(2)


def owner_replies(tag):
    if not re.fullmatch(r"acc-[A-Za-z0-9._-]+", tag):
        raise RuntimeError(f"refusing to query unsafe tag {tag}")
    text = ledger(
        "SELECT json_quote(json_extract(part.value, '$.text')) FROM live_events e "
        "JOIN live_sessions s ON s.session_id=e.session_id "
        "JOIN json_each(e.body_json, '$.frame.message.content') part "
        "WHERE s.seat_id='sinmara' "
        "AND json_extract(e.body_json, '$.frame.type')='message_end' "
        "AND json_extract(e.body_json, '$.frame.message.role')='assistant' "
        "AND json_extract(part.value, '$.type')='text' "
        "AND EXISTS (SELECT 1 FROM live_events p "
        "WHERE p.session_id=e.session_id AND p.sequence<e.sequence "
        "AND json_extract(p.body_json, '$.kind')='command_issued' "
        "AND json_extract(p.body_json, '$.frame.type')='prompt' "
        f"AND instr(COALESCE(json_extract(p.body_json, '$.frame.message'), ''), '[{tag}]')>0 "
        "AND NOT EXISTS (SELECT 1 FROM live_events n "
        "WHERE n.session_id=p.session_id AND n.sequence>p.sequence AND n.sequence<e.sequence "
        "AND json_extract(n.body_json, '$.kind')='command_issued' "
        "AND json_extract(n.body_json, '$.frame.type')='prompt')) ORDER BY e.sequence"
    )
    return [json.loads(line) for line in text.splitlines() if line]


def require_checkout(name):
    root = project_root(name)
    if not root.is_dir():
        raise RuntimeError(f"{name} declared checkout {root} is absent; refusing to clone it")
    return root

def review_count():
    return sql_count(
        "SELECT count(*) FROM audit_events WHERE kind = 'brain.review.completed' "
        "AND payload_json LIKE '%settled%'"
    )


def clock_path():
    return f"{SCHEDULE.rsplit('/', 1)[0]}/clock.json"


def branch_text(project, ref):
    root = require_checkout(project)
    name = ref.removeprefix("refs/heads/")
    run(["git", "-C", str(root), "fetch", "--depth", "1", "origin", name], timeout=90)
    listing = run(["git", "-C", str(root), "ls-tree", "-r", "--name-only", "FETCH_HEAD"])
    chunks = []
    for path in listing.stdout.splitlines():
        if path.endswith((".rs", ".py", ".md", ".nix", ".toml")):
            shown = run(["git", "-C", str(root), "show", f"FETCH_HEAD:{path}"], check=False)
            if shown.returncode == 0:
                chunks.append(shown.stdout)
    return "\n".join(chunks)


def on_main(project, ref):
    root = require_checkout(project)
    name = ref.removeprefix("refs/heads/")
    run(["git", "-C", str(root), "fetch", "--depth", "1", "origin", name], timeout=90)
    tip = run(["git", "-C", str(root), "rev-parse", "FETCH_HEAD"]).stdout.strip()
    run(["git", "-C", str(root), "fetch", "--depth", "20", "origin", "main"], timeout=90)
    listed = run(["git", "-C", str(root), "rev-list", "--parents", "FETCH_HEAD"])
    return any(tip in line.split() for line in listed.stdout.splitlines())

def execute(row, steps, tag, rid, created):
    reply = ""
    tracks = any(step.startswith(("kube:", "spread:", "joblog:", "incident:", "artifact", "sim:", "frame")) for step in steps)
    created["tracks_jobs"] = tracks
    created.setdefault("started", time.time())
    for step in steps:
        if step.startswith("sessionseat:"):
            capability = f"seat.ask.{step.split(':', 1)[1]}"
            created.setdefault("journal", {})[capability] = journal_count(capability)
        elif step.startswith("routine:"):
            routine = step.split(":", 1)[1].replace("{rid}", rid)
            if routine not in created["routines"]:
                created["routines"].append(routine)
    if any(step.startswith("approvals:") for step in steps):
        created["approvals"] = approvals("requested")
    if any(step == "artifact" or step.startswith("artifact:") for step in steps):
        created["artifacts_before"] = snapshot_ids("artifact")
    if any(step.startswith(("merge:", "reviewed:")) for step in steps):
        created["reviews_before"] = review_count()
    for raw in steps:
        step = raw.replace("{tag}", tag).replace("{rid}", rid)
        kind, _, arg = step.partition(":")
        if kind == "say":
            wait, text = (arg.split(":", 1) if arg[:1].isdigit() and ":" in arg else (str(WAIT), arg))
            text = f"{text} [{tag}]"
            if tracks:
                text += f" Put {tag} in every Job's name or labels."
            reply = say(text, int(wait))
            if tracks:
                note_jobs(created, tag)
        elif kind == "expect":
            if arg not in reply:
                raise RuntimeError(f"reply missing {arg!r}")
        elif kind == "expectre":
            if not re.search(arg, reply, re.I):
                raise RuntimeError(f"reply missed /{arg}/")
        elif kind == "absent":
            if arg in reply:
                raise RuntimeError(f"reply still contains {arg}")
        elif kind == "readme":
            lines = (require_checkout("odin") / "README.md").read_text().splitlines()
            if not lines or not lines[0].strip():
                raise RuntimeError("odin README has no first line")
            first = lines[0]
            wait_for(lambda: first in reply or any(first in text for text in owner_replies(tag)),
                     "reply does not quote the odin README's first line")
        elif kind == "yesterday":
            yesterday = datetime.fromtimestamp(created["started"]).date() - timedelta(days=1)
            month = f"(?:{yesterday:%B}|{yesterday:%b}\\.?)"
            day = f"0?{yesterday.day}"
            pattern = rf"\b(?:{yesterday.isoformat()}|{month}\s+{day}|{day}\s+{month})\b"
            if not re.search(pattern, reply, re.I):
                raise RuntimeError(f"reply does not cite yesterday's local date {yesterday}")
        elif kind == "numbers":
            if len(re.findall(r"(?<![\w.])[+-]?\d+(?:\.\d+)?(?![\w.])", reply)) < int(arg):
                raise RuntimeError(f"reply contains fewer than {arg} numbers")
        elif kind == "workloads":
            names = live_workload_names()
            if names and not any(name in reply for name in names):
                raise RuntimeError(f"reply names none of the live workloads {names}")
            if not names and not agrees_idle(reply):
                raise RuntimeError("reply does not agree that no workload is running")
        elif kind == "profile-name":
            fetch_odin_main()
            listed = ssh(AUTHORITY, "git -C ~/valhalla/odin ls-tree --name-only origin/main:registry/workloads", timeout=30)
            if not any(name and name in reply for name in listed.stdout.splitlines()):
                raise RuntimeError("reply names no published workload profile")
        elif kind == "mutation-mark":
            created["mutations_before"] = mutation_count()
        elif kind == "mutation-none":
            if mutation_count() != created["mutations_before"]:
                raise RuntimeError("new mutating journal entry during clarification")
        elif kind in ("journal-mark", "journal-entry-mark"):
            created.setdefault("journal", {})[arg] = journal_count(arg, committed=kind == "journal-mark")
        elif kind in ("journal-new", "journal-entry-new"):
            if journal_count(arg, committed=kind == "journal-new") <= created["journal"][arg]:
                raise RuntimeError(f"no new {arg} journal operation")
        elif kind == "journal-wait":
            # A delegated worker escalates minutes after the owner's turn ends.
            before = created.get("journal", {}).get(arg, 0)
            wait_for(lambda: journal_count(arg) > before, f"no new committed {arg} operation")
        elif kind == "vaultnote":
            names = ssh(AUTHORITY, f"find \"$HOME{vault_suffix()}\" -type f -name '*.md' -printf '%f\\n'", timeout=30).stdout.splitlines()
            stems = [Path(name).stem for name in names]
            if not any(stem and stem in reply for stem in stems):
                raise RuntimeError("reply does not name a note that exists in the vault")
        elif kind == "approvals":
            current = approvals(arg if arg != "consumed" else "consumed") or approvals("decided")
            if arg == "requested":
                fresh = [item for item in approvals("requested") if item not in created.get("approvals", [])]
                if not fresh:
                    raise RuntimeError("no new requested approval")
                created["approval"] = fresh[0]
            elif created.get("approval") not in current and created.get("approval") not in approvals("approved"):
                raise RuntimeError(f"approval {created.get('approval')} was not consumed")
        elif kind == "children":
            kids = child_sessions()
            if arg == "detached":
                # A paused helper reports detached.
                wait_for(
                    lambda: any(kid.get("state") == "detached" for kid in child_sessions()),
                    f"no paused child; saw {[kid.get('state') for kid in kids]}",
                )
            elif arg.isdigit() and len(kids) < int(arg):
                raise RuntimeError(f"{len(kids)} overlapping children, wanted {arg}")
        elif kind == "gitfile":
            project, needle, text = arg.split(":", 2)
            ref, blob, _message = ref_files(project, needle)
            if text and text not in blob:
                raise RuntimeError(f"{ref} files do not contain {text!r}")
            created["refs"].append((project, [ref]))
        elif kind == "clock-save":
            saved = ssh(AUTHORITY, f"cat {clock_path()}", check=False)
            if saved.returncode != 0:
                raise RuntimeError(saved.stderr.strip() or "clock.json unreadable")
            created["clock"] = saved.stdout
        elif kind == "clock":
            current = ssh(AUTHORITY, f"cat {clock_path()}").stdout
            if arg not in current:
                raise RuntimeError(f"clock.json is not {arg}: {current}")
        elif kind == "embed":
            port = embedding_port()
            result = ssh(AUTHORITY, f"curl -fsS http://127.0.0.1:{port}/v1/embeddings -H 'content-type: application/json' -d '{{\"input\":\"odin\"}}'", timeout=90)
            vector = json.loads(result.stdout)["data"][0]["embedding"]
            if len(vector) != 256 or not all(isinstance(item, (int, float)) for item in vector):
                raise RuntimeError(f"embedding length {len(vector)}")
        elif kind == "vault":
            note = f"{arg}.md"
            local = Path.home() / vault_suffix().lstrip("/") / note
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_text(f"scratch {arg}\n")
            created.setdefault("notes", []).append(note)
            deadline = time.time() + 180
            while time.time() < deadline:
                seen = ssh(AUTHORITY, f"test -f \"$HOME{vault_suffix()}/{note}\" && echo yes", check=False)
                if seen.stdout.strip() == "yes":
                    break
                time.sleep(5)
            else:
                raise RuntimeError(f"{note} did not appear in the authority vault")
        elif kind == "sim":
            require_jobs(created, tag)
            wanted = {job.get("run_id") for job in created.get("jobs") or [] if job.get("run_id")}
            def mission_ready():
                for obj in objects(huginn("simulation", "list")):
                    body = payload(obj)
                    if str(body.get("runId") or "") not in wanted:
                        continue
                    if body.get("currentCheckpointId") and body.get("supportedRenderers"):
                        return True
                return False
            wait_for(mission_ready, f"no mission for tagged runs {sorted(wanted)} has a checkpoint and renderers")
        elif kind == "sched":
            status, _, seconds = arg.partition(":")
            wait_schedule(status or "pending", int(seconds or "20"), tag, rid)
        elif kind == "routine":
            shown = odin_published(f"registry/routines/{arg}/routine.toml", seconds=60)
            if tag not in shown.stdout:
                raise RuntimeError(f"published routine {arg} does not contain {tag}")
        elif kind == "push-fired":
            if not re.fullmatch(r"[a-z0-9._-]+", arg):
                raise RuntimeError(f"refusing project {arg}")
            branch = f"seat/acceptance/{rid}"
            occurrence = f"push:{arg}:{branch}:"
            deadline = time.time() + 420
            seen = []
            while True:
                seen = schedule_text(f"push:{arg}:", rid)
                hit = [
                    row for row in seen
                    if len(row) > 3 and row[1] == "fired" and row[2]
                    and re.search(rf"{re.escape(occurrence)}[0-9a-f]{{40}}", f"{row[0]}\n{row[3]}")
                    and f"branch {branch} was pushed" in row[3]
                ]
                if hit:
                    break
                if time.time() >= deadline:
                    raise RuntimeError(
                        f"no fired repo-push notification for {branch} within one watch tick: {seen}"
                    )
                time.sleep(15)
        elif kind == "memfile":
            leaf, tag_needle, must, lacks = arg.split(":", 3)
            page = memory_page(leaf, tag_needle)
            if must not in page:
                raise RuntimeError(f"{leaf} page for {tag_needle} lacks {must!r}")
            if lacks and lacks in page:
                raise RuntimeError(f"{leaf} page for {tag_needle} still contains {lacks!r}")
        elif kind in ("git", "gitnonempty"):
            project, _, needle = arg.partition(":")
            refs = wait_refs(project, needle, 1)
            if not refs:
                raise RuntimeError(f"{project} origin has no ref containing {needle}")
            created["refs"].append((project, refs))
            if kind == "gitnonempty":
                root = require_checkout(project)
                for ref in refs:
                    run(["git", "-C", str(root), "fetch", "origin", "main"], timeout=90)
                    run(["git", "-C", str(root), "fetch", "origin", ref], timeout=90)
                    diff = run(["git", "-C", str(root), "diff", "origin/main...FETCH_HEAD"])
                    if not diff.stdout.strip():
                        raise RuntimeError(f"{ref} has no changes from main")
        elif kind == "gitkeep":
            project, _, needle = arg.partition(":")
            refs = wait_refs(project, needle, 1)
            if not refs:
                raise RuntimeError(f"{project} origin has no ref containing {needle}")
            created.setdefault("kept", []).append((project, refs))
        elif kind == "merge":
            project, _, needle = arg.partition(":")
            refs = wait_refs(project, needle, 2)
            if len(refs) < 2:
                raise RuntimeError(f"{project} has {len(refs)} branches containing {needle}, wanted 2")
            for ref in refs:
                text = branch_text(project, ref)
                if "fn " not in text and "def " not in text:
                    raise RuntimeError(f"{ref} files have no function body")
                if not on_main(project, ref):
                    raise RuntimeError(f"main does not contain {ref}")
            if review_count() <= created.get("reviews_before", 0):
                raise RuntimeError("no new settled brain.review.completed audit")
            created["refs"].append((project, refs))
        elif kind == "reviewed":
            project, _, needle = arg.partition(":")
            refs = wait_refs(project, needle, 1)
            if len(refs) != 1:
                raise RuntimeError(f"{project} has {len(refs)} branches containing {needle}, wanted 1")
            if not branch_text(project, refs[0]).strip():
                raise RuntimeError(f"{refs[0]} has no file contents")
            if not on_main(project, refs[0]):
                raise RuntimeError(f"main does not contain {refs[0]}")
            if review_count() <= created.get("reviews_before", 0):
                raise RuntimeError("no new settled brain.review.completed audit")
            created["refs"].append((project, refs))
        elif kind == "seatfile":
            odin_published(f"registry/seats/{arg}/seat.toml", seconds=60)
            created["standing_note"] = f"{arg} published; no removal API"
        elif kind == "sessionseat":
            live = []
            for obj in objects(huginn("sessions")):
                session = payload(obj)
                if session.get("seatId") != arg or session.get("state") in ("ended", "failed", None):
                    continue
                started = session.get("startedAt")
                if not isinstance(started, list) or len(started) != 9:
                    continue
                year, ordinal, hour, minute, second, nanos, off_h, off_m, off_s = started
                offset = timezone(timedelta(hours=off_h, minutes=off_m, seconds=off_s))
                stamp = datetime(year, 1, 1, hour, minute, second, tzinfo=offset) + timedelta(days=ordinal - 1, microseconds=nanos // 1000)
                if stamp.timestamp() > created["started"]:
                    live.append(session)
            if not live:
                raise RuntimeError(f"no fresh live {arg} session")
            capability = f"seat.ask.{arg}"
            if journal_count(capability) <= created["journal"][capability]:
                raise RuntimeError(f"no new committed {capability} operation")
        elif kind == "devices":
            seen = [payload(obj).get("lastSeenAt") for obj in objects(huginn("devices", "list")) if payload(obj).get("lastSeenAt")]
            if not seen:
                raise RuntimeError("no device has lastSeenAt")
        elif kind == "nodes":
            ready = [payload(obj).get("nodeId") for obj in objects(huginn("nodes")) if payload(obj).get("state") == "ready"]
            if not ready:
                raise RuntimeError("no node is ready")
        elif kind == "mempage":
            leaf, _, needle = arg.partition(":")
            wait_for(lambda: memory_has(leaf, needle), f"{leaf} memory has no page containing {needle}")
        elif kind == "memgone":
            leaf, _, needle = arg.partition(":")
            if memory_has(leaf, needle):
                raise RuntimeError(f"{leaf} memory still contains {needle}")
        elif kind == "memabsent":
            leaf, _, needle = arg.partition(":")
            if memory_has(leaf, needle):
                raise RuntimeError(f"{leaf} memory contains {needle}")
        elif kind == "budget":
            text = (ROOT / "registry/slices/sinmara-life/slice.toml").read_text()
            core_limit = int(re.search(r"core_tokens = ([0-9_]+)", text).group(1).replace("_", ""))
            prefetch_limit = int(re.search(r"prefetch_tokens = ([0-9_]+)", text).group(1).replace("_", ""))
            session = conversation_session()
            since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created.get("started", time.time()) - 5))
            result = ssh(AUTHORITY, f"journalctl --user -u odind --since {json.dumps(since)} --no-pager", timeout=40)
            lines = [
                line for line in result.stdout.splitlines()
                if "turn context " in line
                and f"session={session}" in line
                and "prompt_digest=blake3:" in line
            ]
            if len(lines) < 3:
                raise RuntimeError(f"saw {len(lines)} turn-context lines for {session} since the run, wanted 3")
            for line in lines:
                core = re.search(r"core_tokens=(\d+)", line)
                prefetch = re.search(r"prefetch_tokens=(\d+)", line)
                if not core or not prefetch:
                    raise RuntimeError(f"turn context missing budgets: {line}")
                if int(core.group(1)) > core_limit or int(prefetch.group(1)) > prefetch_limit:
                    raise RuntimeError(f"turn context outside slice budget: {line}")
        elif kind == "artifact":
            require_jobs(created, tag)
            wait_for(
                lambda: snapshot_ids("artifact") - created.get("artifacts_before", set()),
                "no new artifact was published",
            )
        elif kind == "incident":
            require_jobs(created, tag)
            since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created.get("started", time.time()) - 5))
            def incident_seen():
                result = ssh(AUTHORITY, f"journalctl --user -u odind --since {json.dumps(since)} --no-pager", timeout=40)
                return any("incident id=" in line and arg in line for line in result.stdout.splitlines())
            wait_for(incident_seen, f"no incident with {arg}")
        elif kind == "frame":
            published = []
            for obj in objects(huginn("snapshot", "--kind", "browser")):
                body = payload(obj)
                session = str(body.get("sessionId") or "")
                if body.get("frameNumber") is None or not session:
                    continue
                published.append(session)
            if not any(session in reply for session in published):
                raise RuntimeError("reply names no browser session with a published frame")
        elif kind == "kube":
            phase, _, count = arg.partition(":")
            wait_kube(created, tag, phase, int(count or "1"))
        elif kind == "fleet":
            revisions = {}
            for host in ("mini", "pc", "laptop"):
                try:
                    result = ssh(host, "nixos-version --configuration-revision && systemctl --failed --no-legend && systemctl --user --failed --no-legend", timeout=30)
                except Exception as error:
                    if host == "laptop":
                        continue
                    raise RuntimeError(f"{host} unreachable: {error}") from error
                lines = result.stdout.splitlines()
                revision = lines[0] if lines else ""
                if not re.fullmatch(r"[0-9a-f]{40}", revision):
                    raise RuntimeError(f"{host} revision unreadable: {revision!r}")
                if any(line.strip() for line in lines[1:]):
                    raise RuntimeError(f"{host} has failed units")
                revisions[host] = revision
            if len(set(revisions.values())) != 1:
                raise RuntimeError(f"revisions differ: {revisions}")
        elif kind == "sweep":
            hosts = ("pc", "laptop") if arg == "followers" else (AUTHORITY,)
            for host in hosts:
                result = ssh(host, "env -u ODIN_ROOT sweep --system" if host != AUTHORITY else "sweep --system", timeout=180)
                if "SYS-" not in result.stdout:
                    raise RuntimeError(f"{host} sweep did not report SYS ids")
        else:
            raise RuntimeError(f"unknown step {kind}")
    return created


def owned_projects(steps):
    found = []
    for raw in steps:
        kind, _, arg = raw.partition(":")
        if kind not in ("git", "gitnonempty", "gitfile", "gitkeep", "merge", "reviewed", "push-fired") or not arg:
            continue
        project = arg.split(":", 1)[0]
        if re.fullmatch(r"[A-Za-z0-9._-]+", project) and project not in found:
            found.append(project)
    return found


def discover(tag, rid, created, steps):
    errors = []
    if created.get("tracks_jobs"):
        try:
            note_jobs(created, tag)
        except Exception as error:
            errors.append(f"could not discover tagged jobs: {error}")
    kept = {(project, ref) for project, refs in created.get("kept") or [] for ref in refs}
    projects = owned_projects(steps)
    for project, _refs in list(created.get("refs") or []) + list(created.get("kept") or []):
        if project not in projects:
            projects.append(project)
    for project in projects:
        try:
            refs = refs_containing(project, rid)
        except Exception as error:
            errors.append(f"could not list {project} refs: {error}")
            continue
        have = {ref for _, group in created.get("refs") or [] for ref in group}
        fresh = [ref for ref in refs if ref not in have and (project, ref) not in kept]
        if fresh:
            created.setdefault("refs", []).append((project, fresh))
    try:
        fetch_odin_main()
    except RuntimeError as error:
        errors.append(str(error))
        found = None
    else:
        found = ssh(
            AUTHORITY,
            f"git -C ~/valhalla/odin grep -l -F -e {tag} -e {rid} origin/main -- registry/routines",
            timeout=60,
            check=False,
        )
    if found is not None and found.returncode == 0:
        for path in found.stdout.splitlines():
            if path.startswith("origin/main:"):
                path = path[len("origin/main:"):]
            parts = path.split("/")
            if len(parts) >= 3 and parts[0] == "registry" and parts[1] == "routines":
                if parts[2] not in (created.get("routines") or []):
                    created.setdefault("routines", []).append(parts[2])
    elif found is not None and found.returncode != 1:
        errors.append(found.stderr.strip() or "could not search published routines")
    created.setdefault("discover_errors", []).extend(errors)


def object_missing(result):
    text = f"{result.stderr}\n{result.stdout}"
    return result.returncode == 128 and (
        "Not a valid object" in text or "does not exist" in text or "fatal: path" in text
    )


def fetch_odin_main():
    # Authoring pushes from its clone. This checkout's origin/main is stale until fetched.
    fetched = ssh(AUTHORITY, "git -C ~/valhalla/odin fetch --quiet origin main", timeout=90, check=False)
    if fetched.returncode != 0:
        raise RuntimeError(fetched.stderr.strip() or "could not fetch odin origin/main")


def odin_published(path, seconds=0):
    if not re.fullmatch(r"registry/(routines|seats)/[A-Za-z0-9._-]+/(routine|seat)\.toml", path):
        raise RuntimeError(f"refusing odin path {path}")
    deadline = time.time() + seconds
    last = None
    while True:
        fetch_odin_main()
        shown = ssh(
            AUTHORITY,
            f"git -C ~/valhalla/odin cat-file -e origin/main:{path}",
            timeout=30,
            check=False,
        )
        if shown.returncode == 0:
            return ssh(AUTHORITY, f"git -C ~/valhalla/odin show origin/main:{path}", timeout=30)
        last = shown
        if not object_missing(shown) or time.time() >= deadline:
            raise RuntimeError(last.stderr.strip() or f"{path} is not on origin/main")
        time.sleep(5)


def cleanup(tag, rid, created):
    errors = []
    for job in created.get("jobs") or []:
        name = job.get("name") or ""
        namespace = job.get("namespace") or ""
        uid = job.get("uid") or ""
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", name) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", namespace):
            errors.append(f"refusing to delete unsafe job name {namespace}/{name}")
            continue
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", uid):
            errors.append(f"refusing to delete {namespace}/{name} without its captured uid")
            continue
        # DeleteOptions uid is a body precondition. A query uid is ignored.
        body = json.dumps(job_delete_body(uid))
        result = ssh(
            AUTHORITY,
            "k3s kubectl delete --raw "
            + json.dumps(f"/apis/batch/v1/namespaces/{namespace}/jobs/{name}")
            + " -f - <<'EOF'\n"
            + body
            + "\nEOF",
            timeout=60,
            check=False,
        )
        text = f"{result.stderr}\n{result.stdout}".lower()
        if result.returncode != 0 and "not found" not in text:
            errors.append(result.stderr.strip() or result.stdout.strip() or f"could not delete {namespace}/{name}")
    for routine in created.get("routines") or []:
        try:
            say(f"Remove routine {routine}.", WAIT)
        except Exception as error:
            errors.append(str(error))
        try:
            fetch_odin_main()
        except RuntimeError as error:
            errors.append(str(error))
        else:
            gone = ssh(AUTHORITY, f"git -C ~/valhalla/odin cat-file -e origin/main:registry/routines/{routine}/routine.toml", timeout=30, check=False)
            if gone.returncode == 0:
                errors.append(f"routine {routine} is still on origin/main")
            elif not object_missing(gone):
                errors.append(gone.stderr.strip() or f"could not read routine {routine}")
    if schedule_rows(tag):
        try:
            say(f"Cancel the reminder whose text contains {tag}.", WAIT)
        except Exception as error:
            errors.append(str(error))
        pending = [row for row in schedule_rows(tag) if len(row) > 1 and row[1] == "pending"]
        if pending:
            errors.append(f"reminder {pending[0][0]} still pending")
    kept = {(project, ref) for project, refs in created.get("kept") or [] for ref in refs}
    for project, refs in created.get("refs") or []:
        root = declared_root(project)
        for ref in refs:
            if (project, ref) in kept:
                continue
            name = ref.removeprefix("refs/heads/")
            if rid not in name:
                errors.append(f"refusing to delete untagged ref {name}")
                continue
            if name in ("main", "master"):
                errors.append(f"refusing to delete {name}")
                continue
            try:
                if root and root.is_dir():
                    result = run(["git", "-C", str(root), "push", "origin", f":refs/heads/{name}"], timeout=60, check=False)
                elif ODIN_CHECKOUT.is_dir():
                    result = run(
                        ["git", "-C", str(ODIN_CHECKOUT), "push", project_origin(project), f":refs/heads/{name}"],
                        timeout=60,
                        check=False,
                    )
                else:
                    errors.append(f"could not delete {name}: {project} checkout {root} is absent")
                    continue
            except Exception as error:
                errors.append(f"could not delete {name}: {error}")
                continue
            if result.returncode != 0:
                errors.append(result.stderr.strip() or f"could not delete {name}")
    for note in created.get("notes") or []:
        if not re.fullmatch(r"acc-[A-Za-z0-9._-]+\.md", note):
            errors.append(f"refusing to delete untagged note {note}")
            continue
        local = Path.home() / vault_suffix().lstrip("/") / note
        local.unlink(missing_ok=True)
        removed = ssh(AUTHORITY, f"rm -f -- \"$HOME{vault_suffix()}/{note}\"", check=False)
        if removed.returncode != 0:
            errors.append(removed.stderr.strip() or f"could not delete vault note {note}")
    for path in created.get("files") or []:
        try:
            Path(path).unlink(missing_ok=True)
        except OSError as error:
            errors.append(f"could not delete {path}: {error}")
    saved = created.get("clock")
    if saved:
        try:
            previous = json.loads(saved).get("zone")
        except json.JSONDecodeError:
            previous = None
        current = ssh(AUTHORITY, f"cat {clock_path()}", check=False)
        if current.returncode != 0:
            errors.append(current.stderr.strip() or "clock.json unreadable during restore")
        elif previous and previous not in current.stdout:
            try:
                say(f"Set my timezone back to {previous}.", WAIT)
            except Exception as error:
                errors.append(str(error))
    for leaf in ("colin", "sinmara", "gungnir", "project.dotfiles", "project.odin"):
        try:
            present = memory_has(leaf, tag)
        except RuntimeError as error:
            errors.append(str(error))
            continue
        if not present:
            continue
        # Sinmara forgets only in her own namespaces; a worker's memory is forgotten by that worker.
        owner = {"gungnir": "gungnir", "project.odin": "gungnir", "project.dotfiles": "architect"}.get(leaf)
        request = f"Have {owner} forget {tag} from its memory." if owner else f"Forget {tag}."
        try:
            say(request, WAIT)
        except Exception as error:
            errors.append(str(error))
        try:
            wait_for(lambda: not memory_has(leaf, tag), f"{leaf} memory still contains {tag}")
        except RuntimeError as error:
            errors.append(str(error))
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="print selected recipes without contacting live services")
    parser.add_argument("--area")
    parser.add_argument("rows", nargs="*")
    args = parser.parse_args()
    inventory = rows()
    missing = [row for row, _ in inventory if row not in RECIPES and row not in MANUAL]
    if args.list or not args.rows and not args.area:
        for row, area in inventory:
            if row in MANUAL:
                print(f"{row}\t{area}\tmanual\t{MANUAL[row]}")
            elif row in RECIPES:
                print(f"{row}\t{area}\tlive")
            else:
                print(f"{row}\t{area}\tUNMAPPED")
        if missing:
            raise SystemExit(2)
        return
    if missing:
        raise SystemExit(f"unmapped rows: {', '.join(missing)}")
    selected = [(row, area) for row, area in inventory if (not args.rows or row in args.rows) and (not args.area or args.area in (area, row.split('.')[0]))]
    if not selected:
        raise SystemExit("no rows selected")
    if args.dry_run:
        for row, _ in selected:
            if row in MANUAL:
                print(f"{row}\tmanual\t{MANUAL[row]}")
                continue
            print(f"{row}\tlive")
            for step in RECIPES[row]:
                print(f"  {step.format(tag='acc-dry-run', rid='acc-dry-run')}")
        return
    out = Path.home() / ".local/state/odin-scenarios" / f"{time.strftime('%Y-%m-%d')}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    failed = False
    for row, area in selected:
        if row in MANUAL:
            print(f"{row}\tmanual\t{MANUAL[row]}")
            continue
        stamp = str(int(time.time()))
        tag = f"acc-{row}-{stamp}"
        stem = f"acc-{row.replace('.', '-')}"
        rid = f"{stem[:40 - len(stamp)]}-{stamp}"
        created = {"jobs": [], "routines": [], "refs": [], "approvals": [], "files": [], "started": time.time()}
        error = None
        cleanup_errors = []
        try:
            execute(row, RECIPES[row], tag, rid, created)
        except Exception as exc:
            error = exc
        finally:
            try:
                discover(tag, rid, created, RECIPES[row])
            except Exception as exc:
                created.setdefault("discover_errors", []).append(str(exc))
            try:
                cleanup_errors = cleanup(tag, rid, created)
            except Exception as exc:
                cleanup_errors = [str(exc)]
        cleanup_errors = list(created.get("discover_errors") or []) + list(cleanup_errors)
        if error or cleanup_errors:
            status, detail = "fail", "; ".join(part for part in [str(error) if error else "", *cleanup_errors] if part)
            failed = True
        else:
            detail = tag
            if created.get("standing_note"):
                detail = f"{tag}; {created['standing_note']}"
            status = "pass"
        print(f"{row}\t{status}\t{detail}")
        with out.open("a") as handle:
            handle.write(json.dumps({"row": row, "area": area, "status": status, "detail": detail}) + "\n")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
