#!/usr/bin/env bash
# Five stages, stop on the first failure. CARGO overrides the cargo binary;
# on this pc the default is the slot wrapper so a raw cargo cannot start.
set -euo pipefail
if [ -z "${CARGO:-}" ]; then
  if [ -x "$HOME/wt/final/bin/cargo-slot" ]; then
    CARGO=$HOME/wt/final/bin/cargo-slot
  else
    CARGO=cargo
  fi
fi
cd "$(dirname "$(readlink -f "$0")")/.."
echo "gate: fmt ($CARGO)"
"$CARGO" fmt --all --check
echo "gate: clippy"
"$CARGO" clippy --workspace --all-targets -- -D warnings
echo "gate: test"
if "$CARGO" nextest --version >/dev/null 2>&1; then
  "$CARGO" nextest run --workspace
else
  "$CARGO" test --workspace
fi
echo "gate: extension"
tsc --noEmit -p extension/tsconfig.json
(cd extension && bun install --frozen-lockfile && bun test odin.test.ts)
echo "gate: deny"
"$CARGO" deny check
echo "gate: pass"
