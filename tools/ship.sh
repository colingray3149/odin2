#!/usr/bin/env bash
# ship.sh <commit> <progress.json> — the deploy behind the capability odin.deploy, run from a worktree
# checked out at <commit> on the project's deploy host, holding the deploy lock as fd 9 (odind's start script
# took it). It gates the commit (writing its gate record) unless a passing record already exists, then runs
# tools/deploy.sh, which waits for all agent work before restarting odind. Each stage replaces one line in
# <progress.json> (with this process's pid, so a reader can tell a dead ship); output goes to the .log beside it.
set -euo pipefail
T=${1:?usage: ship.sh <commit> <progress.json>}
progress=${2:?usage: ship.sh <commit> <progress.json>}
[ "$#" -eq 2 ] || { echo "usage: ship.sh <commit> <progress.json>" >&2; exit 2; }
cd "$(dirname "$(readlink -f "$0")")/.."
log=${progress%.json}.log
: >"$log"
stage() { # stage, line
  jq -cn --arg commit "$T" --arg stage "$1" --arg line "$2" --arg at "$(date -Is)" --argjson pid $$ \
    '{commit: $commit, stage: $stage, line: $line, at: $at, pid: $pid}' >"$progress.tmp"
  mv "$progress.tmp" "$progress"
}
run() { # what, command...: a failure ends the ship with the log's last lines as its cause
  local what=$1
  shift
  if ! "$@" >>"$log" 2>&1; then
    stage failed "$what failed: $(grep -v '^\s*$' "$log" | tail -n 3 | tr '\n' ' ' | cut -c1-600)"
    exit 1
  fi
}
[ "$(git rev-parse HEAD)" = "$T" ] && [ -z "$(git status --porcelain)" ] ||
  { stage failed "the ship worktree is not a clean checkout of $T"; exit 1; }
started=$SECONDS
if python3 tools/gate-results.py passed "$T" 2>/dev/null; then
  stage deploying "the gate already passed on $T; deploying"
else
  stage gate "gating $T"
  run gate nix develop -c env TMPDIR=/tmp tools/gate.sh
  python3 tools/gate-results.py passed "$T" 2>>"$log" || { stage failed "the gate passed but left no passing record for $T"; exit 1; }
  stage deploying "gate passed in $(((SECONDS - started) / 60)) min; deploying"
fi
run deploy tools/deploy.sh "$T"
stage "done" "$(tail -n 1 "$log") ($(((SECONDS - started) / 60)) min)"
