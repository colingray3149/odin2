#!/usr/bin/env bash
# deploy.sh <odin-commit-on-origin-main> — pin that commit and switch the fleet. pc only.
set -euo pipefail
{ set +x; } 2>/dev/null
[ "$(hostname)" = pc ] || { echo "deploy: run this on pc" >&2; exit 1; }
[[ ${1:-} =~ ^[0-9a-f]{40}$ ]] || { echo "usage: deploy.sh <odin-commit-on-origin-main>" >&2; exit 2; }
T=$1
DOT=$HOME/dotfiles
PWFILE=$HOME/.config/odin-coord/sudo-password
[ -f "$PWFILE" ] && [ ! -L "$PWFILE" ] || { echo "deploy: sudo credential missing" >&2; exit 1; }
IFS= read -r PW <"$PWFILE" || [ -n "${PW:-}" ] || { echo "deploy: sudo credential unreadable" >&2; exit 1; }
[ -n "$PW" ] || { echo "deploy: sudo credential empty" >&2; exit 1; }

cd "$DOT"
[ -z "$(git status --porcelain)" ] || { echo "deploy: ~/dotfiles is dirty" >&2; exit 1; }
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || { echo "deploy: ~/dotfiles is not on main" >&2; exit 1; }
git pull --rebase
url=$(jq -r .nodes.odin.locked.url flake.lock)
tip=$(git ls-remote "$url" refs/heads/main | awk 'NR==1 {print $1}')
[ "$tip" = "$T" ] || { echo "deploy: origin/main is ${tip:-missing}, not $T" >&2; exit 1; }
if [ "$(jq -r .nodes.odin.locked.rev flake.lock)" != "$T" ]; then
  nix flake update odin
  [ "$(jq -r .nodes.odin.locked.rev flake.lock)" = "$T" ] || { echo "deploy: lock did not pin $T" >&2; exit 1; }
  nix flake check --no-update-lock-file
  git add flake.lock
  git commit -S -m "odin: pin $T [skip-guide]"
  git push
else
  nix flake check --no-update-lock-file
fi
DOT_REV=$(git rev-parse HEAD)

build() { nix build --no-link --print-out-paths ".#nixosConfigurations.$1.config.system.build.toplevel"; }
MINI=$(build mini)
PC=$(build pc)
LAPTOP=$(build laptop)
# ssh-ng is the copy transport the fleet actually switches from; a plain ssh:// store does not.
nix copy --no-check-sigs --to ssh-ng://mini "$MINI"
if ssh -o BatchMode=yes -o ConnectTimeout=8 laptop true; then
  nix copy --no-check-sigs --to ssh-ng://laptop "$LAPTOP" || { echo "deploy: laptop copy failed" >&2; exit 1; }
  LAPTOP_OK=1
else
  echo "deploy: laptop unreachable, skipping" >&2
  LAPTOP_OK=0
fi

switch_remote() { # host path
  local host=$1 path=$2
  builtin printf '%s\n' "$PW" | ssh -o ConnectTimeout=20 -o ServerAliveInterval=30 -o ServerAliveCountMax=20 "$host" "
    { set +x; } 2>/dev/null
    IFS= read -r PW || exit 1
    su() { builtin printf '%s\n' \"\$PW\" | sudo -S -p '' \"\$@\"; }
    su nix-env -p /nix/var/nix/profiles/system --set '$path' &&
      su systemd-run --unit=switch-\$(date +%s) --collect --service-type=exec --wait '$path/bin/switch-to-configuration' switch
  "
}
switch_local() {
  { set +x; } 2>/dev/null
  su() { builtin printf '%s\n' "$PW" | sudo -S -p '' "$@"; }
  su nix-env -p /nix/var/nix/profiles/system --set "$1" &&
    unit=switch-$(date +%s) &&
    su systemd-run --unit="$unit" --collect --service-type=exec --wait "$1/bin/switch-to-configuration" switch
}
sync_remote_sources() {
  local host=$1
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$host" "
    set -eu
    cd ~/dotfiles
    if [ -n \"\$(git status --porcelain)\" ] || [ \"\$(git branch --show-current)\" != main ]; then
      printf 'deploy: %s ~/dotfiles left at %s (dirty or not on main)\n' '$host' \"\$(git rev-parse HEAD)\"
      exit 0
    fi
    git fetch -q origin main
    git merge --ff-only -q '$DOT_REV'
  " || echo "deploy: $host ~/dotfiles sync failed; system switch unaffected" >&2
}
failed() { # host, or empty for this machine. Both managers. Nonzero if either is unreadable.
  local host=${1:-} out
  if [ -n "$host" ]; then
    out=$(ssh -o ConnectTimeout=15 "$host" 'systemctl --failed --no-legend && systemctl --user --failed --no-legend') || return 1
  else
    out=$(systemctl --failed --no-legend && systemctl --user --failed --no-legend) || return 1
  fi
  printf '%s\n' "$out"
}
clear() { # host label
  local units
  units=$(failed "$1") || { echo "deploy: $2 health unreadable" >&2; exit 1; }
  [ -z "$units" ] || { echo "deploy: $2 has failed units" >&2; printf '%s\n' "$units" >&2; exit 1; }
}

switch_remote mini "$MINI"
# odind serves the published registry snapshot, so publish T's registry with the new binary and restart odind on it.
ssh -o ConnectTimeout=20 mini "
  set -eu
  cd ~/valhalla/odin && git fetch -q origin && git merge --ff-only -q '$T'
  store=\$HOME/.local/state/odin/registry/snapshot.json
  next=\$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[\"revision\"] + 1)' \"\$store\")
  config=\$(mktemp); printf '{\"schema\":\"odin.registry-publish-config.v1\",\"snapshot_store\":\"%s\"}' \"\$store\" >\"\$config\"
  # An unchanged registry republishes at the active revision; a changed one at the next.
  odin registry publish --config \"\$config\" --worktree ~/valhalla/odin --commit '$T' --expected-revision \"\$next\" --output \"\$config.out\" >/dev/null 2>&1 ||
    odin registry publish --config \"\$config\" --worktree ~/valhalla/odin --commit '$T' --expected-revision \"\$((next - 1))\" --output \"\$config.out\" >/dev/null
  rm -f \"\$config\" \"\$config.out\"
  systemctl --user reset-failed odind; systemctl --user restart odind
" || { echo "deploy: registry publish or odind restart failed on mini" >&2; exit 1; }
if [ "$LAPTOP_OK" = 1 ]; then switch_remote laptop "$LAPTOP"; fi
switch_local "$PC"
sync_remote_sources mini
if [ "$LAPTOP_OK" = 1 ]; then sync_remote_sources laptop; fi
clear mini mini
if [ "$LAPTOP_OK" = 1 ]; then clear laptop laptop; fi
clear "" pc
odind=$(ssh -o ConnectTimeout=15 mini 'systemctl --user is-active odind') || { echo "deploy: cannot read odind on mini" >&2; exit 1; }
[ "$odind" = active ] || { echo "deploy: odind is $odind on mini" >&2; exit 1; }
odin huginn status >/dev/null || { echo "deploy: huginn status failed" >&2; exit 1; }
echo "deploy: pin=$T mini=switched laptop=$([ "$LAPTOP_OK" = 1 ] && echo switched || echo skipped) pc=switched failed=0 odind=active huginn=ok"
