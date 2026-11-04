#!/usr/bin/env bash
# deploy.sh <odin-commit-on-origin-main> — pin that commit and switch the hosts the odin
# project declares (registry/projects/odin: deploy.host runs this, deploy.targets are switched; the target whose
# registry role is control runs odind and gets the registry). It waits for all agent work, checks the candidate on the
# control host, publishes the registry, then switches the control host before the others.
set -euo pipefail
{ set +x; } 2>/dev/null
[[ ${1:-} =~ ^[0-9a-f]{40}$ ]] || { echo "usage: deploy.sh <odin-commit-on-origin-main>" >&2; exit 2; }
[ "$#" -eq 1 ] || { echo "usage: deploy.sh <odin-commit-on-origin-main>" >&2; exit 2; }
T=$1
# ssh waits and poll budgets, in seconds.
CONNECT=15 PROBE_CONNECT=8 SWITCH_CONNECT=20 KEEPALIVE=30 KEEPALIVE_MISSES=20
BUSY_POLL=10 BUSY_POLLS=90 WRITER_POLL=5 WRITER_POLLS=60 HUGINN_POLL=2 HUGINN_POLLS=15
# One owner line says hello to Sinmara after the switch and waits this long for her committed reply.
CONVERSATION_SAY="Deploy check: reply with the single word ready."
CONVERSATION_WAIT=180
die() { echo "deploy: $*" >&2; exit 1; }
cd "$(dirname "$(readlink -f "$0")")/.."
# shellcheck disable=SC2016 # ${...} in the single-quoted expression is Nix interpolation, not the shell's
declared() { # the odin project's deploy declaration, one value per line: host, checkout, targets, control target
  nix eval --raw --impure --expr '
    let p = (builtins.fromTOML (builtins.readFile ./registry/projects/odin/project.toml)).deploy;
        role = h: (builtins.fromTOML (builtins.readFile (./registry/hosts + "/${h}/host.toml"))).role;
    in "${p.host}\n${p.checkout}\n${toString p.targets}\n${toString (builtins.filter (h: role h == "control") p.targets)}\n"'
}
{ read -r HOST; read -r CHECKOUT; read -r TARGETS; read -r AUTH; } < <(declared) || die "the odin project's deploy declaration is unreadable"
SELF=$(hostname)
[ "$SELF" = "$HOST" ] || die "run this on $HOST (registry/projects/odin deploy.host), not $SELF"
[ -n "$AUTH" ] && [ "${AUTH#* }" = "$AUTH" ] || die "deploy.targets must hold exactly one control host, not '${AUTH}'"
# One deploy at a time. tools/ship.sh hands down the lock it took as fd 9; locking it again is a no-op.
{ true >&9; } 2>/dev/null || exec 9>"$HOME/.local/state/odin/deploy.lock"
flock -n 9 || die "another deploy is running (it holds ~/.local/state/odin/deploy.lock)"
# The dotfiles checkout this deploy pins and builds; another clean clone of main serves while ~/dotfiles holds work in progress.
DOT=${ODIN_DEPLOY_DOTFILES:-$HOME/dotfiles}
PWFILE=$HOME/.config/odin-coord/sudo-password
[ -f "$PWFILE" ] && [ ! -L "$PWFILE" ] || { echo "deploy: sudo credential missing" >&2; exit 1; }
IFS= read -r PW <"$PWFILE" || [ -n "${PW:-}" ] || { echo "deploy: sudo credential unreadable" >&2; exit 1; }
[ -n "$PW" ] || { echo "deploy: sudo credential empty" >&2; exit 1; }
REPO=$PWD
cd "$DOT"
[ -z "$(git status --porcelain)" ] || { echo "deploy: $DOT is dirty" >&2; exit 1; }
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || { echo "deploy: $DOT is not on main" >&2; exit 1; }
git pull --rebase
url=$(jq -r .nodes.odin.locked.url flake.lock)
tip=$(git ls-remote "${url#git+}" refs/heads/main | awk 'NR==1 {print $1}')
# Registry declarations and this orchestration script may follow T without changing the gated closure; the
# authority applies the same rule when it picks the commit to publish.
DECLARATIONS=(. ':!registry' ':!tools/deploy.sh')
[ "$tip" = "$T" ] || {
  git -C "$REPO" fetch -q origin main
  if ! { git -C "$REPO" merge-base --is-ancestor "$T" "$tip" && git -C "$REPO" diff --quiet "$T" "$tip" -- "${DECLARATIONS[@]}"; }; then
    echo "deploy: origin/main is ${tip:-missing}, not $T (and not only registry/deploy-script commits on top of it)" >&2
    exit 1
  fi
}
python3 "$REPO/tools/gate-results.py" passed "$T" || die "$T has no passing gate record"
pinned=$(jq -r .nodes.odin.locked.rev flake.lock)
if [ "$pinned" != "$T" ]; then
  # Pin and commit before building, so the built closure's dotfiles revision includes the pin commit
  # (`77451fb-dirty` labels); the pin is pushed only after the build and checks pass.
  nix flake lock --override-input odin "git+ssh://git@github.com/odin-owner/odin?ref=main&rev=$T"
  [ "$(jq -r .nodes.odin.locked.rev flake.lock)" = "$T" ] || { echo "deploy: lock did not pin $T" >&2; exit 1; }
  git add flake.lock
  git commit -S -m "odin: pin $T [skip-guide]"
fi
nix flake update yt-dlp
if ! git diff --quiet -- flake.lock; then
  git add flake.lock
  git commit -S -m "tools: refresh yt-dlp [skip-guide]"
fi

# Each build is a GC root until the next deploy: nix's own min-free collection
# runs mid-deploy on a full disk and would delete an unrooted toplevel.
roots=$HOME/.local/state/odin/deploy-roots
new=$roots.new
rm -rf "$new"
mkdir -p "$new"
# One build of every target (one evaluation, one schedule under the host's nix caps) while the flake's checks run
# beside it, instead of the check and each host one after another.
nix flake check --no-update-lock-file &
check=$!
read -ra targets <<<"$TARGETS"
toplevels=()
for h in "${targets[@]}"; do toplevels+=(".#nixosConfigurations.$h.config.system.build.toplevel"); done
nix build --out-link "$new/system" "${toplevels[@]}" ||
  { kill "$check" 2>/dev/null; die "building ${targets[*]} failed"; }
wait "$check" || die "nix flake check failed"
# The gate's results for this commit, recorded on the authority as tested.json: the gate record for $T plus the
# flake revision and its check names.
gate_json=$HOME/.local/state/odin/gate-pass/$T.json
base=$(cat "$gate_json") || die "cannot read $gate_json"
work_results=$(mktemp) || die "cannot create the results file"
checks=$(nix eval --json .#checks.x86_64-linux --apply builtins.attrNames) || die "cannot evaluate the flake checks"
printf '%s' "$base" | jq --arg rev "$(git rev-parse HEAD)" --argjson checks "$checks" \
  '. + {flake:{rev:$rev, checks:$checks}}' >"$work_results" || die "cannot write the results file"
# The build succeeded: swap in the new roots, keeping the old ones until the swap so a failed build leaves the
# previous deploy's GC roots in place.
rm -rf "$roots"
mv "$new" "$roots"
declare -A OUT
# nix names the links system, system-1, system-2, … in the order the targets were given.
for i in "${!targets[@]}"; do
  link=$roots/system
  [ "$i" = 0 ] || link=$roots/system-$i
  OUT[${targets[$i]}]=$(readlink -f "$link")
done
git push
DOT_REV=$(git rev-parse HEAD)
# ssh-ng is the copy transport the fleet actually switches from; a plain ssh:// store does not.
# The control host must take the deploy; any other remote target is skipped while unreachable.
REMOTE=() SKIPPED=() COPY_PIDS=() COPY_HOSTS=()
for h in $TARGETS; do
  [ "$h" = "$SELF" ] && continue
  if [ "$h" != "$AUTH" ] && ! ssh -o BatchMode=yes -o ConnectTimeout="$PROBE_CONNECT" -- "$h" true; then
    echo "deploy: $h unreachable, skipping" >&2
    SKIPPED+=("$h")
    continue
  fi
  nix copy --no-check-sigs --to "ssh-ng://$h" "${OUT[$h]}" &
  COPY_PIDS+=("$!") COPY_HOSTS+=("$h")
  REMOTE+=("$h")
done
# The copies run concurrently; every one must finish before any host switches.
for i in "${!COPY_PIDS[@]}"; do
  wait "${COPY_PIDS[$i]}" || die "${COPY_HOSTS[$i]} copy failed"
done

switch_remote() { # host path
  local host=$1 path=$2
  builtin printf '%s\n' "$PW" | ssh -o ConnectTimeout="$SWITCH_CONNECT" -o ServerAliveInterval="$KEEPALIVE" -o ServerAliveCountMax="$KEEPALIVE_MISSES" "$host" "
    { set +x; } 2>/dev/null
    IFS= read -r PW || exit 1
    [ \"\$(readlink -f /run/current-system)\" = '$path' ] && { echo '$host: unchanged'; exit 0; }
    su() { builtin printf '%s\n' \"\$PW\" | sudo -S -p '' \"\$@\"; }
    su nix-env -p /nix/var/nix/profiles/system --set '$path' &&
      su systemd-run --unit=switch-\$(date +%s) --service-type=exec --wait '$path/bin/switch-to-configuration' switch
  "
}
switch_local() {
  [ "$(readlink -f /run/current-system)" = "$1" ] && { echo "$SELF: unchanged"; return 0; }
  { set +x; } 2>/dev/null
  su() { builtin printf '%s\n' "$PW" | sudo -S -p '' "$@"; }
  su nix-env -p /nix/var/nix/profiles/system --set "$1" &&
    unit=switch-$(date +%s) &&
    su systemd-run --unit="$unit" --service-type=exec --wait "$1/bin/switch-to-configuration" switch
}
# A follower whose ~/dotfiles cannot fast-forward keeps its old sources; the switched system does not depend on them.
sync_remote_sources() {
  local host=$1
  ssh -o BatchMode=yes -o ConnectTimeout="$CONNECT" "$host" "
    set -eu
    cd ~/dotfiles
    if [ -n \"\$(git status --porcelain)\" ] || [ \"\$(git branch --show-current)\" != main ]; then
      printf '%s ~/dotfiles is dirty or not on main, left at %s\n' '$host' \"\$(git rev-parse HEAD)\"
      exit 1
    fi
    git fetch -q origin main
    git merge --ff-only -q '$DOT_REV'
  " || echo "deploy: warning: $host ~/dotfiles was not synced to $DOT_REV" >&2
}
failed_units() {
  set -o pipefail
  systemctl --failed --no-legend --plain | sed 's/^/system /'
  systemctl --user --failed --no-legend --plain | sed 's/^/user /'
}
failed() { # host, or empty for this machine: the failed units of both managers, one per line; nonzero if unreadable
  if [ -n "${1:-}" ]; then
    ssh -o ConnectTimeout="$CONNECT" "$1" bash -s <<<"$(declare -f failed_units); failed_units"
  else
    failed_units
  fi
}
declare -A UNITS_BEFORE
remember_failed() { UNITS_BEFORE[${1:-.}]=$(failed "${1:-}") || UNITS_BEFORE[${1:-.}]=; }
clear() { # host label: a unit that failed since this deploy began fails it; units that were already failed stay theirs
  local now fresh
  now=$(failed "$1") || { echo "deploy: $2 health unreadable" >&2; exit 1; }
  fresh=$(comm -13 <(printf '%s\n' "${UNITS_BEFORE[${1:-.}]}" | cut -d' ' -f1-2 | sort) <(printf '%s\n' "$now" | cut -d' ' -f1-2 | sort))
  [ -z "$fresh" ] || { echo "deploy: $2 has units that failed after the switch" >&2; printf '%s\n' "$fresh" >&2; exit 1; }
}

# Switching the control host restarts odind: preserve every seat's running turns,
# background jobs and delegated children. Conversation seats come from the registry.
conversation_seats=$(python3 - "$REPO" <<'PY'
import json, pathlib, sys, tomllib
seats = pathlib.Path(sys.argv[1], "registry/seats").glob("*/seat.toml")
print(json.dumps([path.parent.name for path in seats if "conversation" in tomllib.loads(path.read_text())]))
PY
) || die "cannot read conversation seats"
on_auth() { ssh -o ConnectTimeout="$SWITCH_CONNECT" -- "$AUTH" "$@"; }
quiet=0
for _ in $(seq "$BUSY_POLLS"); do
  sessions=$(odin huginn --json sessions 2>&1) || {
    # A stopped odind has no work to wait for; any other failure to read the sessions is a failure to deploy.
    [ "$(on_auth 'systemctl --user is-active odind' || true)" != active ] || die "cannot read live sessions from Huginn: $sessions"
    echo "deploy: odind is not running on $AUTH; no live work to wait for"
    quiet=2
    break
  }
  busy=$(printf '%s\n' "$sessions" | jq -er --argjson seats "$conversation_seats" '
    [.value.objects[].value.data
      | select(.state == "running" or .state == "starting" or .state == "requiresAction" or .state == "aborting"
        or (.state == "idle" and (.seatId as $seat | ($seats | index($seat)) == null)))]
    | length') || die "cannot read live sessions from Huginn"
  running=$(odin huginn --json jobs | jq -er '.value.running') || die "cannot read background jobs from Huginn"
  if [ "$busy" -eq 0 ] && [ "$running" -eq 0 ]; then quiet=$((quiet + 1)); else quiet=0; fi
  [ "$quiet" -ge 2 ] && break
  sleep "$BUSY_POLL"
done
[ "$quiet" -ge 2 ] || die "agent work stayed busy for $((BUSY_POLL * BUSY_POLLS / 60)) min; odind was not restarted"
# Candidate check on the control host with the NEW binaries and odind.toml from its built closure, by store path:
# the gateway config rendered by the same renderer and facts the closure carries against the candidate registry,
# a dry-run publish, then a publish into a staged copy of the live store, then `odind check --snapshot` on that
# copy with scratch state, parsing the rendered config through the production model book (FP27: a lane that lost
# its account windows is refused here, before anything publishes). Nothing live changes here. Odin commits its
# own runtime declarations to main: when everything on main after T touches only registry/, the tip is published
# instead, so a declaration that landed mid-deploy is neither lost nor refused as newer than T.
hm=".#nixosConfigurations.$AUTH.config.home-manager.users.$USER.services.odin"
gw=".#nixosConfigurations.$AUTH.config.home-manager.users.$USER.gateway"
publisher=".#nixosConfigurations.$AUTH.config.home-manager.users.$USER.odin.architect.registryPublishConfig"
# Preflight-only inputs need their own roots: the switched system closure
# does not necessarily retain the renderer or its facts.
nix build --out-link "$roots/gateway-preflight" "$gw.modelsRenderer" "$gw.factsFile" "$publisher" ||
  die "building the candidate gateway and registry publication inputs failed"
BIN=$(nix eval --raw "$hm.package")/bin || die "cannot evaluate the candidate odin package"
CONFIG=$(nix eval --raw "$hm.configFile") || die "cannot evaluate the candidate odind.toml"
RENDERER=$(nix eval --raw "$gw.modelsRenderer")/bin/odin-gateway-render || die "cannot evaluate the candidate gateway renderer"
FACTS=$(nix eval --raw "$gw.factsFile") || die "cannot evaluate the candidate gateway facts"
PUBLISH_CONFIG=$(nix eval --raw "$publisher") || die "cannot evaluate the candidate registry publisher config"
nix copy --no-check-sigs --to "ssh-ng://$AUTH" \
  "${RENDERER%/bin/odin-gateway-render}" "$FACTS" "$PUBLISH_CONFIG" ||
  die "copying the candidate gateway and registry publication inputs to $AUTH failed"
plan=$(on_auth bash -s -- "$CHECKOUT" "$T" "$BIN" "$CONFIG" "$RENDERER" "$FACTS" "${DECLARATIONS[@]}" <<'SH'
set -euo pipefail
checkout=$HOME/$1 T=$2 bin=$3 config=$4 renderer=$5 facts=$6
shift 6
cd "$checkout"
git fetch -q origin
ahead=$(git log --format='  %h %s' origin/main..HEAD)
[ -z "$ahead" ] || { printf 'deploy: %s has commits not on origin/main; push or drop them first:\n%s\n' "$checkout" "$ahead" >&2; exit 1; }
pub=$T tip=$(git rev-parse origin/main)
if git merge-base --is-ancestor "$T" "$tip" && git diff --quiet "$T" "$tip" -- "$@"; then pub=$tip; fi
work=$(mktemp -d)
trap 'git -C "$checkout" worktree remove --force "$work/src" 2>/dev/null; rm -rf "$work"' EXIT
git worktree add -q --detach "$work/src" "$pub"
# The rendered gateway config this deploy will serve: the closure's own
# renderer and facts against the candidate registry at $pub — exactly what
# odind re-renders after the publish. Checked before any publish runs.
render=$work/gateway
"$renderer" --registry "$work/src/registry/models" --available "$work/src/registry/models.available.json" \
  --facts "$facts" --out "$render" ||
  { echo "deploy: candidate gateway render failed for $pub" >&2; exit 1; }
live=$HOME/.local/state/odin/registry
mkdir "$work/store"
flock "$live/.snapshot.json.publish.lock" cp -a "$live/snapshot.json" "$live/revisions" "$work/store/"
printf '{"schema":"odin.registry-publish-config.v1","snapshot_store":"%s"}' "$work/store/snapshot.json" >"$work/config.json"
publish() {
  "$bin/odin" registry publish --config "$work/config.json" --worktree "$work/src" --commit "$pub" \
    --output "$work/out.json" "$@" >/dev/null 2>>"$work/err"
}
# A changed registry publishes at the next revision, an unchanged one at the active.
active=$(jq -er .revision "$work/store/snapshot.json")
rev=$((active + 1))
publish --dry-run --expected-revision "$rev" || { rev=$active; publish --dry-run --expected-revision "$rev"; } ||
  { printf 'deploy: candidate publish of %s refused:\n' "$pub" >&2; cat "$work/err" >&2; exit 1; }
: >"$work/err"
publish --expected-revision "$rev" || { cat "$work/err" >&2; exit 1; }
# The check never contacts the gateway; its declared credential only has to
# be present. The rendered config is parsed by the production model book:
# a lane without account windows is refused here, not by odind after the
# switch (the 03:46 deploy).
LITELLM_MASTER_KEY=candidate-check "$bin/odind" check --config "$config" --snapshot "$work/store/snapshot.json" \
  --rendered-gateway "$render/litellm.yaml" >/dev/null ||
  { echo "deploy: candidate odind check failed against $pub at revision $rev (rendered gateway $render/litellm.yaml)" >&2; exit 1; }
echo "$pub $rev"
SH
) || die "candidate check failed on $AUTH; every host is on its old generation"
read -r PUB REV <<<"$plan"
echo "deploy: candidate checked: $PUB publishes at revision $REV"
# A registry-only commit on top of $T may name tests the gate run of $T never saw: every test a published capability
# names must have passed in that run.
caps=$(mktemp -d) || die "cannot create a scratch directory"
git -C "$REPO" fetch -q origin main
{ git -C "$REPO" archive "$PUB" registry | tar -x -C "$caps"; } || { rm -rf "$caps"; die "cannot read the registry at $PUB"; }
python3 "$REPO/tools/gate-results.py" capabilities "$gate_json" "$caps/registry" ||
  { rm -rf "$caps"; die "a capability names a test the gate run of $T did not pass; every host is on its old generation"; }
rm -rf "$caps"
# Keep writers running through builds and candidate checks. Pause only for
# the publication/control-host switch, and restore timers on every exit.
backup=$(on_auth 'systemctl is-active odin-backup.service' || true)
[ "$backup" = inactive ] || die "odin-backup.service on $AUTH is ${backup:-unreachable}"
writer_timers=(
  brain-archive-refresh.timer brain-commit.timer brain-google-pull.timer brain-grow.timer
  brain-inventory.timer brain-load.timer brain-reduce.timer media-mirror.timer
)
writer_state=$(on_auth bash -s -- "${writer_timers[@]}" <<'SH'
set -euo pipefail
for timer in "$@"; do
  state=$(systemctl --user show --property=ActiveState --value "$timer") ||
    { echo "deploy: cannot read $timer" >&2; exit 1; }
  case "$state" in
    active) action=start ;;
    inactive|failed) action=stop ;;
    *) echo "deploy: $timer is ${state:-unreadable}; wait for a stable timer state" >&2; exit 1 ;;
  esac
  printf '%s %s ' "$action" "$timer"
done
SH
) || die "cannot snapshot brain timers on $AUTH"
read -ra writer_restore <<<"$writer_state"
restore_brain_writers() {
  on_auth bash -s -- "${writer_restore[@]}" <<'SH'
set -uo pipefail
result=0
while [ "$#" -gt 0 ]; do
  action=$1 timer=$2
  shift 2
  systemctl --user "$action" "$timer" || {
    echo "deploy: cannot restore $timer ($action)" >&2
    result=1
  }
done
exit "$result"
SH
}
restore_writers_on_exit() {
  local result=$?
  if ! restore_brain_writers; then
    echo "deploy: failed to restore brain timers on $AUTH" >&2
    [ "$result" -ne 0 ] || result=1
  fi
  exit "$result"
}
trap restore_writers_on_exit EXIT
# A writer left failed is as stopped as an inactive one; the snapshot above treats both alike.
on_auth bash -s -- "$WRITER_POLL" "$WRITER_POLLS" "${writer_timers[@]}" <<'SH' || die "cannot pause brain writers on $AUTH"
set -euo pipefail
poll=$1 polls=$2
shift 2
for timer in "$@"; do
  systemctl --user stop "$timer" ||
    { echo "deploy: cannot stop $timer" >&2; exit 1; }
done
for timer in "$@"; do
  service=${timer%.timer}.service
  for ((attempt = 0; attempt < polls; attempt++)); do
    state=$(systemctl --user show --property=ActiveState --value "$service") ||
      { echo "deploy: cannot read $service" >&2; exit 1; }
    case "$state" in inactive|failed) break ;; esac
    sleep "$poll"
  done
  case "$state" in
    inactive|failed) ;;
    *) echo "deploy: $service did not stop within $((poll * polls))s (${state:-unreadable})" >&2; exit 1 ;;
  esac
done
SH
# Publish before the switch, from a detached worktree at PUB, with odind stopped, so odind starts once, on the new
# binary over the matching snapshot. The revision comes from the publish's own output, taken under the store lock.
on_auth 'cat > ~/.local/state/odin/tested.json.tmp && mv ~/.local/state/odin/tested.json.tmp ~/.local/state/odin/tested.json' <"$work_results" ||
  die "cannot record the gate results on $AUTH; every host is on its old generation"
rm -f "$work_results"
published=$(on_auth bash -s -- "$CHECKOUT" "$PUB" "$REV" "$BIN" "$PUBLISH_CONFIG" <<'SH'
set -euo pipefail
checkout=$HOME/$1 pub=$2 rev=$3 bin=$4 publish_config=$5
git -C "$checkout" merge --ff-only -q "$pub"
work=$(mktemp -d)
trap 'git -C "$checkout" worktree remove --force "$work/src" 2>/dev/null; rm -rf "$work"' EXIT
git -C "$checkout" worktree add -q --detach "$work/src" "$pub"
systemctl --user stop odind
"$bin/odin" registry publish --config "$publish_config" --worktree "$work/src" --commit "$pub" \
  --expected-revision "$rev" --output "$work/out.json" >/dev/null ||
  { systemctl --user start odind; echo "deploy: publish failed; odind restarted on the old system" >&2; exit 1; }
jq -er '"\(.outcome) \(.receipt.revision)"' "$work/out.json"
SH
) || die "registry publish failed on $AUTH; every host is on its old generation"
echo "deploy: registry $published"
# From here on, roll forward only.
start_odind() { on_auth 'systemctl --user reset-failed odind; systemctl --user start odind'; }
for h in "${REMOTE[@]}"; do remember_failed "$h"; done
[ -z "${OUT[$SELF]:-}" ] || remember_failed ""
switch_remote "$AUTH" "${OUT[$AUTH]}" || { start_odind; die "switching $AUTH failed after the publish; roll forward"; }
start_odind || die "cannot start odind on $AUTH"
restore_brain_writers || die "cannot restore brain timers on $AUTH"
trap - EXIT
for h in "${REMOTE[@]}"; do [ "$h" = "$AUTH" ] || switch_remote "$h" "${OUT[$h]}"; done
[ -z "${OUT[$SELF]:-}" ] || switch_local "${OUT[$SELF]}"
# odind restarts with the switch; Huginn answers 502 until it is back.
odind=$(on_auth 'systemctl --user is-active odind') || die "cannot read odind on $AUTH"
[ "$odind" = active ] || die "odind is $odind on $AUTH"
for _ in $(seq "$HUGINN_POLLS"); do odin huginn status >/dev/null 2>&1 && break; sleep "$HUGINN_POLL"; done
odin huginn status >/dev/null || die "huginn status failed $((HUGINN_POLL * HUGINN_POLLS)) s after the switch"
# Her conversation opens on the candidate: the open reads the live tool listing, memory and device credential
# that no check before the switch can reach. A cause here is already live; fix it and deploy again.
reply=$(odin huginn chat --say "$CONVERSATION_SAY" --wait "$CONVERSATION_WAIT" 2>&1) ||
  die "Sinmara's conversation did not open on $T after the switch (odind is running it): $reply"
for h in "${REMOTE[@]}"; do sync_remote_sources "$h"; done
for h in "${REMOTE[@]}"; do clear "$h" "$h"; done
[ -z "${OUT[$SELF]:-}" ] || clear "" "$SELF"
echo "deploy: pin=$T switched=${REMOTE[*]}${OUT[$SELF]:+ $SELF} skipped=${SKIPPED[*]:-none} odind=active huginn=ok conversation=open"
