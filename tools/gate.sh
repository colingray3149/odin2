#!/usr/bin/env bash
# Every check runs; the first failure stops the gate. CARGO overrides the cargo binary; the default
# is the slot wrapper, so the gate shares the build slots every builder uses.
# The cheap checks run beside clippy and are joined before the test run, so a lint or format failure stops the
# gate before its longest step; the Nix package builds beside the tests.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
CARGO=${CARGO:-$PWD/tools/cargo-slot}
start=$(git rev-parse HEAD)
# The slot memory cap and test threads every gate run uses; the caller may override them. The whole workspace
# compiles in one slot here, which takes more than the 9G cap of an agent's focused build.
export SLOT_MEM=${SLOT_MEM:-20G} NEXTEST_TEST_THREADS=${NEXTEST_TEST_THREADS:-8}
# The cores the Nix package build may use while the tests run.
PACKAGE_CORES=4
# Each section names itself with step. A finished step appends "<step> <pass|fail> <milliseconds>" to $outcomes;
# gate-results.py records those lines, and a step with no line did not run.
STEPS=(install fmt slop design typos ruff shellcheck biome secrets personal machete knip view extension python deny clippy test capabilities package)
outcomes=$(mktemp)
current=""
began=0
now_ms() { echo $(($(date +%s%N) / 1000000)); }
finish() {
  [ -n "$current" ] && echo "$current $1 $(($(now_ms) - began))" >>"$outcomes"
  current=""
}
step() { finish pass; current=$1; began=$(now_ms); echo "gate: $1"; }
# background <step> <command...> runs the command in a subshell beside the foreground steps. Its output goes to a
# log that join prints on failure; its outcome line comes from the subshell's own EXIT trap.
bg_pids=()
bg_names=()
bg_logs=()
bg_finish() { # bg_finish <step> <started ms> <exit code>; a step the gate stopped is not recorded
  local outcome=fail
  [ -e "$outcomes.stopped" ] && return
  [ "$3" = 0 ] && outcome=pass
  echo "$1 $outcome $(($(now_ms) - $2))" >>"$outcomes"
}
background() {
  local log name=$1
  log=$(mktemp)
  bg_names+=("$name")
  bg_logs+=("$log")
  (
    began=$(now_ms)
    trap 'bg_finish "$name" "$began" $?' EXIT
    set -e
    "${@:2}" >"$log" 2>&1
  ) &
  bg_pids+=("$!")
}
# join [step...] waits for the named background steps (all of them without names). Each failure prints its log and
# is named; the gate then fails.
join() {
  local i failed=0
  finish pass
  for i in "${!bg_pids[@]}"; do
    [ -n "${bg_pids[$i]}" ] || continue
    if [ "$#" -gt 0 ] && [[ " $* " != *" ${bg_names[$i]} "* ]]; then continue; fi
    if ! wait "${bg_pids[$i]}"; then
      cat "${bg_logs[$i]}"
      echo "gate: ${bg_names[$i]} failed" >&2
      failed=1
    fi
    rm -f "${bg_logs[$i]}"
    bg_pids[i]=""
  done
  if [ "$failed" = 1 ]; then exit 1; fi
}
# nextest keeps its store under the workspace target/ (its [store] dir default), not CARGO_TARGET_DIR.
junit=$PWD/target/nextest/gate/junit.xml
# A report left by an earlier run must never stand in for this one.
rm -f "$junit"
on_exit() {
  if [ "$1" = 0 ]; then finish pass; else finish fail; fi
  # A background step still running when the gate stops is killed with its command and not recorded.
  touch "$outcomes.stopped"
  for pid in "${bg_pids[@]}"; do
    [ -z "$pid" ] || { pkill -TERM -P "$pid" 2>/dev/null; kill "$pid" 2>/dev/null; } || true
  done
  wait 2>/dev/null || true
  python3 tools/gate-results.py "$start" "$1" "$outcomes" "${STEPS[*]}" "$junit"
  rm -f "$outcomes" "$outcomes.stopped"
}
trap 'on_exit $?' EXIT

step install
# The type checks read each package's installed dependencies.
(cd view && bun install --frozen-lockfile --silent)
(cd extension && bun install --frozen-lockfile --silent)

# fmt, machete and deny compile nothing, so they skip the build slots and never queue clippy.
check_fmt() { cargo fmt --all --check; }
check_secrets() { tools/secrets.sh; }
check_personal() { python3 tools/public/export.py --check; }
check_machete() { cargo machete; }
check_deny() { cargo deny check; }
check_shellcheck() { shellcheck -f gcc tools/*.sh tools/cargo-slot view/dev/drive.sh; }
check_biome() { biome lint --diagnostic-level=error .; }
check_knip() { (cd view && ./node_modules/.bin/knip --no-progress); }
check_view() {
  local build
  build=$(mktemp -d)
  (cd view && bun test && bun build main.ts --target=bun --outdir "$build" >/dev/null)
  rm -rf "$build"
}
check_extension() {
  tsc --noEmit -p extension/tsconfig.json
  (cd extension && bun test odin.test.ts && bun generated/odin-authority-wire-v2.conformance.mjs)
  "$CARGO" run -q -p odin-sidecar-protocol --bin codegen -- --check
}
# Every Python suite in the tree; a new *_test.py or test_*.py is picked up without editing this list.
check_python() {
  local suites
  mapfile -t suites < <(git ls-files '*_test.py' '*/test_*.py')
  python3 -m unittest "${suites[@]}"
}
# The Nix package deploy ships has its own source filter (it excludes registry/); the cargo steps never build it.
# Pin nixpkgs and omp to the revisions dotfiles' flake.lock gives them, as deploy does, so the derivation is deploy's.
locked_ref() { # locked_ref <odin flake input>: the github: reference dotfiles pins for that input
  local lock=${ODIN_DEPLOY_DOTFILES:-$HOME/dotfiles}/flake.lock node ref
  [ -f "$lock" ] || { echo "gate: cannot read $lock for the package step" >&2; exit 1; }
  node=$(jq -r --arg input "$1" '.nodes.root.inputs[$input] // empty' "$lock")
  ref=$(jq -r --arg node "$node" '.nodes[$node].locked | select(.type == "github") | "github:\(.owner)/\(.repo)/\(.rev)"' "$lock")
  [ -n "$ref" ] || { echo "gate: $lock has no github lock node for input $1 (node: ${node:-none})" >&2; exit 1; }
  echo "$ref"
}
check_package() {
  nix build --no-link --cores "$PACKAGE_CORES" .#odin \
    --override-input nixpkgs "$(locked_ref nixpkgs)" --override-input omp "$(locked_ref omp)"
}

background fmt check_fmt
background slop python3 tools/slop.py
background design python3 tools/design-check.py
background typos typos --format brief
background ruff ruff check --quiet
background shellcheck check_shellcheck
background biome check_biome
background secrets check_secrets
background personal check_personal
background machete check_machete
background knip check_knip
background view check_view
background extension check_extension
background python check_python
background deny check_deny
step clippy
"$CARGO" clippy --workspace --all-targets -- -D warnings
join fmt slop design typos ruff shellcheck biome secrets personal machete knip view extension python deny
background package check_package
step test
"$CARGO" nextest --version >/dev/null 2>&1 || { echo "gate: nextest missing (cargo nextest is not installed)" >&2; exit 1; }
"$CARGO" nextest run --workspace --profile gate
# A capability's `tests` name nextest tests; each must have run and passed, so a deployed capability's tests passed.
step capabilities
python3 tools/gate-results.py capabilities "$junit"
join package
echo "gate: pass"
