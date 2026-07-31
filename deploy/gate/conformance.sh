#!/usr/bin/env bash
# A real conformance run: the Rust harness certifying the Python component, cross-language.
#
# `spec/08 §3.3` is "no green conformance run, no registration", and `spec/08 §4` says what a run
# must have checked. This script performs one against the gateway's own self-test — the same path a
# third party's component takes, with nothing shortened for the fact that we wrote both halves.
#
# It is deliberately NOT part of clean-install.sh. That gate lives entirely in Docker and the harness
# spawns its component as a local subprocess; wiring the two together would mean a step whose
# failures are about container plumbing rather than about conformance. This runs against build
# outputs an operator already has, and it is listed in deploy/README §5 as part of the release
# checklist.
#
# The run builds and discards its own kernel. It reads no configuration, touches no deployment, and
# leaves nothing behind but the result document.
#
#   usage: deploy/gate/conformance.sh [--python <interpreter>]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${REPO}/gateway/.venv/bin/python"
while [ $# -gt 0 ]; do
  case "$1" in
    --python) PYTHON="$2"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

fail() { printf '\n\033[1;31mCONFORMANCE FAILED:\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

command -v cargo >/dev/null || fail "cargo is required to build the harness"
[ -x "$PYTHON" ] || fail "no interpreter at $PYTHON — pass --python <path> or create gateway/.venv"
"$PYTHON" -c 'import stozher_gateway' 2>/dev/null ||
  fail "$PYTHON cannot import stozher_gateway; install the gateway into it first"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

step "1  building the harness"
cargo build --manifest-path "${REPO}/kernel/Cargo.toml" -p stozher-kernel --quiet
HARNESS="${REPO}/kernel/target/debug/stozher-kernel"
[ -x "$HARNESS" ] || fail "the harness binary was not produced at $HARNESS"

step "2  the component's identity and the manifest it is signed under"
# One key, two artefacts. The harness refuses a run where the key saying hello is not the key the
# manifest was signed with, so they have to be produced together.
python3 -c "print('11' * 32)" > "${WORK}/seed.hex"
chmod 600 "${WORK}/seed.hex"
"$PYTHON" -m stozher_gateway.conformance \
  --seed "${WORK}/seed.hex" --emit-manifest --name github > "${WORK}/manifest.json" ||
  fail "the component could not produce a signed manifest"

step "3  spec/08 section 4, all seven groups"
# A fixed instant: §08 §4 requires a run to be deterministic, and two runs that produced different
# bytes could not be compared by the operator who has to trust one of them.
"$HARNESS" conformance \
  --manifest "${WORK}/manifest.json" \
  --vectors "${REPO}/spec/vectors" \
  --at "2026-07-26T09:00:00.000Z" \
  --component "$PYTHON -m stozher_gateway.conformance --seed ${WORK}/seed.hex --manifest ${WORK}/manifest.json" \
  > "${WORK}/run.json" || fail "the run is red — see the result above"

python3 - "${WORK}/run.json" <<'PY' || exit 1
import json, sys
run = json.load(open(sys.argv[1]))
if not run.get("green"):
    print(f"the run reported itself red: {run.get('outstanding')}", file=sys.stderr)
    raise SystemExit(1)
for group, result in sorted(run["groups"].items()):
    print(f"  {result['result']:<15} {group:<22} {result.get('checks', '')}")
print(f"\n  manifest-hash: {run['manifest-hash']}")
PY

printf '\n\033[1mCONFORMANCE PASSED\033[0m — a green run, which is evidence and not a registration.\n'
echo "spec/08 §3.1 still wants a human signature over the manifest hash above." >&2
