#!/usr/bin/env bash
# Working tree (tracked and untracked source) and commits since merge-base origin/main.
# gitleaks dir does not honor .gitignore, so the tree scan is the git file set's
# top-level dirs and root files — target/, result, and .direnv are not walked.
# Names are NUL records: quoting would skip a unicode, tab, or newline path.
# The report template has no secret field; --redact is the backstop.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
root=$(pwd)
tpl=$root/tools/gitleaks.tmpl
scan() {
  gitleaks dir --redact --no-banner --log-level error \
    --config "$root/.gitleaks.toml" \
    --report-format template --report-template "$tpl" --report-path - \
    "$@"
}
fail=0
out=$(mktemp)
list=$(mktemp)
trap 'rm -f "$out" "$list"' EXIT
if ! git ls-files -z --cached --others --exclude-standard >"$list"; then
  echo "secrets: could not list source files" >&2
  exit 1
fi
declare -A seen=()
while IFS= read -r -d '' path; do
  top=${path%%/*}
  [ -n "$top" ] || continue
  seen["$top"]=1
done <"$list"
scan_one() {
  if ! scan "$1" >>"$out"; then
    fail=1
  fi
}
for top in "${!seen[@]}"; do
  if [ -d "$top/node_modules" ] || [ -d "$top/target" ] || [ -d "$top/dist" ]; then
    children=$(mktemp)
    if ! find "$top" -mindepth 1 -maxdepth 1 \
      ! -name node_modules ! -name target ! -name dist ! -name .direnv -print0 >"$children"; then
      echo "secrets: could not list $top" >&2
      rm -f "$children"
      exit 1
    fi
    while IFS= read -r -d '' child; do
      [ -n "$child" ] || continue
      scan_one "$child"
    done <"$children"
    rm -f "$children"
  elif [ -d "$top" ] || [ -f "$top" ]; then
    scan_one "$top"
  fi
done
base=$(git merge-base origin/main HEAD)
if [ "$base" != "$(git rev-parse HEAD)" ]; then
  if ! gitleaks git --redact --no-banner --log-level error \
    --config "$root/.gitleaks.toml" \
    --report-format template --report-template "$tpl" --report-path - \
    --log-opts="${base}..HEAD" >>"$out"; then
    fail=1
  fi
fi
if grep -q '[^[:space:]]' "$out"; then
  grep '[^[:space:]]' "$out"
  fail=1
fi
[ "$fail" -eq 0 ]
