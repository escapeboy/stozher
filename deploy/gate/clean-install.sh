#!/usr/bin/env bash
# THE S5 GATE — clean machine to first audited envelope, under thirty minutes, measured.
#
# `docs/build-plan.md` states S5's gate as: *"clean-machine install to first audited envelope in
# under 30 minutes"*. This script is that sentence made executable. It starts from nothing, runs the
# path `deploy/README.md` documents — no shortcut, no pre-warmed state, no private helper the
# documentation does not mention — and fails if the wall clock says otherwise.
#
# What "clean" means here, precisely
# ----------------------------------
#   * No store. `var/` is removed, so there is no reused SQLite file and no chain to inherit.
#   * No keys. `secrets/` is removed, so every seed is generated during the run.
#   * No configuration. `config/` and `.env` are removed, so the ceremony writes them.
#   * No images. Both are deleted and rebuilt with `--no-cache`, so the Rust compile and the Python
#     install are inside the measured window. A machine that has never seen this project has no
#     layer cache, and a number that assumed one would be a number about *this* machine.
#
# The clock is wall-clock, taken from the shell before the first command and after the last
# assertion. Nothing is excluded from it and nothing is done before it starts.
#
# What it proves at the end
# -------------------------
# A **real audited envelope**: an effect the kernel accepted, on a real chain, produced by a real
# foreign MCP client calling a real downstream server through the gateway — where the call was
# gated, parked, signed for by a named human, and only then applied. The chain is then verified.
# "The install finished" is not the assertion; "the audit trail exists and verifies" is.
#
# Usage: gate/clean-install.sh [--dirty] [--keep-images] [--budget 1800]
#   --dirty        skip the wipe (for iterating; the measured number then means nothing)
#   --keep-images  skip the image rebuild (same caveat)

set -euo pipefail

DEPLOY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DEPLOY"

BUDGET=1800
CLEAN="yes"
REBUILD="yes"
ROOT_SUBJECT="human:gate-operator"
while [ $# -gt 0 ]; do
  case "$1" in
    --dirty) CLEAN="no"; shift ;;
    --keep-images) REBUILD="no"; shift ;;
    --budget) BUDGET="$2"; shift 2 ;;
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

START=$(date +%s)
step() { printf '\n\033[1m[%4ds] %s\033[0m\n' "$(( $(date +%s) - START ))" "$*"; }
fail() { printf '\n\033[1;31mGATE FAILED: %s\033[0m\n' "$*" >&2; exit 1; }
elapsed() { echo $(( $(date +%s) - START )); }

command -v docker >/dev/null || fail "docker is required"
command -v python3 >/dev/null || fail "python3 is required to drive an MCP client"

# ---------------------------------------------------------------------------------------------
step "0  wiping every trace of a previous install"
if [ "$CLEAN" = "yes" ]; then
  docker compose down --remove-orphans --volumes >/dev/null 2>&1 || true
  rm -rf var secrets genesis backups config/kernel-config.json config/stozher-gateway.toml .env
  if [ "$REBUILD" = "yes" ]; then
    docker image rm -f stozher-kernel:0.1.0 stozher-gateway:0.1.0 >/dev/null 2>&1 || true
  fi
  echo "  removed: var/ secrets/ genesis/ config/*.json config/*.toml .env"
  # Asserted, not assumed. A gate that quietly reused a store or a seed would measure the time to
  # restart something that was already installed, and would report it as a clean install.
  if [ -e var ]; then fail "var/ survived the wipe"; fi
  if [ -e secrets ]; then fail "secrets/ survived the wipe — a gate that reuses keys measures nothing"; fi
  if [ -e config/kernel-config.json ]; then fail "the previous configuration survived the wipe"; fi
  echo "  confirmed: no store, no keys, no config"
else
  echo "  SKIPPED (--dirty): the measured duration below is not a clean-install number"
fi

# ---------------------------------------------------------------------------------------------
step "1  building both images from source"
if [ "$REBUILD" = "yes" ] && [ "$CLEAN" = "yes" ]; then
  printf 'STOZHER_UID=%s\nSTOZHER_GID=%s\n' "$(id -u)" "$(id -g)" > .env
  docker compose build --no-cache kernel gateway
else
  printf 'STOZHER_UID=%s\nSTOZHER_GID=%s\n' "$(id -u)" "$(id -g)" > .env
  docker compose build kernel gateway
fi

# ---------------------------------------------------------------------------------------------
step "2  the ceremony (bin/stozher-bootstrap, exactly as documented)"
rm -f .env
./bin/stozher-bootstrap --root "$ROOT_SUBJECT" --port 8787

set -a; . ./.env; set +a
GATEWAY=(docker compose -f "$DEPLOY/docker-compose.yml" run --rm -T gateway)

# ---------------------------------------------------------------------------------------------
step "3  a foreign MCP client calls a tool the policy has never heard of"
PROBE=$(python3 gate/mcp_probe.py \
  --call notes__write_note --args '{"name":"gate","body":"the first audited write"}' \
  -- "${GATEWAY[@]}")
printf '%s\n' "$PROBE" | python3 -c 'import sys;[print("  "+l[:220]) for l in sys.stdin]'

REQUEST=$(printf '%s\n' "$PROBE" | python3 -c '
import json, sys
for line in sys.stdin:
    row = json.loads(line)
    if row.get("event") == "call" and (row.get("refusal") or {}).get("result") == "parked":
        print(row["refusal"]["request-hash"]); break
')
[ -n "$REQUEST" ] || fail "the unknown tool did not park at the first-call gate"
echo "  parked: $REQUEST"

# ---------------------------------------------------------------------------------------------
step "4  a named human approves it, signing with a key the kernel has never held"
./bin/stozher-approve "$REQUEST" --root "$ROOT_SUBJECT" >/dev/null

# ---------------------------------------------------------------------------------------------
step "5  the same call again — now it applies, and the downstream is actually invoked"
AGAIN=$(python3 gate/mcp_probe.py \
  --call notes__write_note --args '{"name":"gate","body":"the first audited write"}' \
  --call notes__list_notes --args '{}' \
  -- "${GATEWAY[@]}")
printf '%s\n' "$AGAIN" | python3 -c 'import sys;[print("  "+l[:220]) for l in sys.stdin]'
printf '%s\n' "$AGAIN" | python3 -c '
import json, sys
applied = False
for line in sys.stdin:
    row = json.loads(line)
    if row.get("event") == "call" and row.get("tool") == "notes__write_note":
        applied = not row["is_error"] and "wrote gate.txt" in row["text"]
sys.exit(0 if applied else 1)
' || fail "the approved call did not reach the downstream server — the approval bought nothing"

# ---------------------------------------------------------------------------------------------
step "6  the audit trail holds the envelope, and the chain verifies"
python3 - "$STOZHER_KERNEL_PORT" "$STOZHER_KERNEL_TOKEN" <<'PY' || exit 1
import json, sys, urllib.request

port, token = sys.argv[1], sys.argv[2]

def get(path):
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode())

records = get("/v1/envelopes?limit=200")["records"]
audited = [
    r for r in records
    if (r.get("envelope", r).get("execution") or {}).get("action") == "notes.write_note"
    and (r.get("envelope", r).get("execution") or {}).get("outcome") == "applied"
]
if not audited:
    print("no applied notes.write_note envelope in the audit trail", file=sys.stderr)
    raise SystemExit(1)
envelope = audited[0].get("envelope", audited[0])
print(f"  audited envelope: {envelope['stream']} seq={envelope['seq']} "
      f"{envelope['kind']} {envelope['classification']}")
if "authorization" not in envelope:
    print("the applied envelope carries no authorization — it was not gated", file=sys.stderr)
    raise SystemExit(1)
print(f"  approved by: {envelope['authorization']['decision']['sig']['key']}")

failures = []
for stream in {r.get("envelope", r)["stream"] for r in records}:
    report = get(f"/v1/streams/{stream}/verify")
    ok = report.get("valid") is not False and "head-hash" in report
    print(f"  {'VALID  ' if ok else 'INVALID'} {stream}  ({report.get('count')} envelopes, "
          f"anchored={report.get('anchored')})")
    if not ok:
        failures.append(stream)
if failures:
    print(f"chain verification failed for {failures}", file=sys.stderr)
    raise SystemExit(1)
PY

# ---------------------------------------------------------------------------------------------
TOTAL=$(elapsed)
printf '\n\033[1m================================================================\033[0m\n'
printf '\033[1m  clean install to first audited envelope: %d s (%d min %02d s)\033[0m\n' \
  "$TOTAL" "$((TOTAL / 60))" "$((TOTAL % 60))"
printf '\033[1m  budget: %d s\033[0m\n' "$BUDGET"
printf '\033[1m================================================================\033[0m\n'
if [ "$TOTAL" -ge "$BUDGET" ]; then
  fail "took ${TOTAL}s, over the ${BUDGET}s budget"
fi
if [ "$CLEAN" != "yes" ] || [ "$REBUILD" != "yes" ]; then
  echo
  echo "NOTE: run without --dirty/--keep-images for a number that means 'clean machine'." >&2
fi
echo "GATE PASSED"
