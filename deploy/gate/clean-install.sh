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
#   * No configuration. `config/*` and `.env` are removed, so the ceremony writes them.
#   * No ceremony output. `genesis/` is removed, so the envelopes are signed during the run.
#   * No images. Both are deleted and rebuilt with `--no-cache`, so the Rust compile and the Python
#     install are inside the measured window. A machine that has never seen this project has no
#     layer cache, and a number that assumed one would be a number about *this* machine.
#
# That list is exhaustive, and `backups/` is deliberately not on it. This script used to remove it
# too — silently, with the confirmation line below not mentioning it — so anyone who ran the gate in
# a directory that was also a real deployment lost their archives without being told. Nothing in
# `backups/` can affect the measured install: `bin/stozher-bootstrap` never reads it. A wipe that
# reaches further than the thing it is trying to measure is not a cleaner wipe, it is a destructive
# one.
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
# Usage: gate/clean-install.sh [--dirty] [--keep-images] [--budget 1800] [--port 8787]
#   --dirty        skip the wipe (for iterating; the measured number then means nothing)
#   --keep-images  skip the image rebuild (same caveat)
#   --port         publish the kernel here instead of 8787, for a host that already has an install
#
# STOZHER_KERNEL_IMAGE / STOZHER_GATEWAY_IMAGE override the image tags this deletes and rebuilds.
# The tags are the docker daemon's, not the compose project's, so on a host with a second install
# the default ones are that install's too.

set -euo pipefail

DEPLOY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DEPLOY"

BUDGET=1800
CLEAN="yes"
REBUILD="yes"
ROOT_SUBJECT="human:gate-operator"
# The port the ceremony publishes on. A host that already runs an install holds 8787, and a gate
# that can only ever be run on a machine with no deployment on it cannot be run on the machine the
# deployment is on. Defaults to the documented 8787; `--port` is what makes a second one possible.
PORT="${STOZHER_KERNEL_PORT:-8787}"
# The image tags are global to the docker daemon, not to the compose project, so a gate that deletes
# and rebuilds `stozher-kernel:0.1.0` deletes and rebuilds the *host's* one — the tag another
# install's next `up` would resolve. Overridable for the same reason `COMPOSE_PROJECT_NAME` is.
# Read from the existing `.env` *before* falling back to the default, because the line below
# `export`s whichever value wins — and an exported variable beats `.env` in compose interpolation.
# Until 2026-08-04 the default was exported unconditionally, so an operator who set these in `.env`
# exactly as `deploy/README.md` §1 instructs was overridden by this script and the gate rebuilt the
# *host's* `stozher-kernel:0.1.0` anyway. It happened: a design-partner evaluation clobbered a
# running production deployment's tags, leaving its container on an untagged image id. The block at
# `GATE_CARRIED` below was written to prevent exactly this and could not, because it runs after the
# export it needed to precede. Precedence is the ordinary one — a real environment variable still
# wins over `.env`.
from_env_file() {
  [ -f .env ] || return 0
  grep -E "^[[:space:]]*$1=" .env | tail -n 1 | cut -d= -f2- || true
}
KERNEL_IMAGE="${STOZHER_KERNEL_IMAGE:-$(from_env_file STOZHER_KERNEL_IMAGE)}"
GATEWAY_IMAGE="${STOZHER_GATEWAY_IMAGE:-$(from_env_file STOZHER_GATEWAY_IMAGE)}"
KERNEL_IMAGE="${KERNEL_IMAGE:-stozher-kernel:0.1.0}"
GATEWAY_IMAGE="${GATEWAY_IMAGE:-stozher-gateway:0.1.0}"
export STOZHER_KERNEL_IMAGE="$KERNEL_IMAGE" STOZHER_GATEWAY_IMAGE="$GATEWAY_IMAGE"
while [ $# -gt 0 ]; do
  case "$1" in
    --dirty) CLEAN="no"; shift ;;
    --keep-images) REBUILD="no"; shift ;;
    --budget) BUDGET="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    -h|--help) sed -n '2,43p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

START=$(date +%s)
step() { printf '\n\033[1m[%4ds] %s\033[0m\n' "$(( $(date +%s) - START ))" "$*"; }
SAID_WHY="no"
fail() { SAID_WHY="yes"; printf '\n\033[1;31mGATE FAILED: %s\033[0m\n' "$*" >&2; exit 1; }
elapsed() { echo $(( $(date +%s) - START )); }

# A gate that dies on an unanticipated command — a `set -e` trip, a python traceback, a Ctrl-C —
# used to end in a raw stack trace with no verdict line. Whether the gate passed is the entire
# output of this script, so it says so on every exit path, not only the ones it predicted.
FAILED_AT=""
on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$SAID_WHY" = "no" ]; then
    printf '\n\033[1;31mGATE FAILED: exited %d at %s:%s — see the output above\033[0m\n' \
      "$rc" "$(basename "$0")" "${FAILED_AT:-?}" >&2
  fi
  exit "$rc"
}
trap 'FAILED_AT="$LINENO"' ERR
trap on_exit EXIT

# Preconditions, checked before the clock has anything to measure. Each of these fails the run
# several minutes in — after a Rust compile, typically — and each is a one-line question here.
command -v docker >/dev/null || fail "docker is required"
command -v python3 >/dev/null || fail "python3 is required to drive an MCP client"
docker info >/dev/null 2>&1 || fail "the docker daemon is not reachable — 'docker info' failed. Start it and re-run."

# The ceremony below publishes on 127.0.0.1:8787 and nothing tells it to pick another port. A port
# already in use fails at step 2, after the images have been built.
python3 - "$PORT" <<'PY' || fail "127.0.0.1:$PORT is already in use — free it, or stop the other install, or pass --port, and re-run"
import socket, sys
probe = socket.socket()
probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    probe.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    probe.close()
PY

# The Rust compile, the Python install and both images need room. This asks about the filesystem
# holding this checkout; on a machine where the docker daemon keeps its images on a different one
# (a Linux VM under Docker Desktop or OrbStack) that daemon's own disk is not covered here, and a
# build that runs out of space there will say so itself.
HEADROOM_KB=$(df -Pk . 2>/dev/null | awk 'NR==2 {print $4}')
case "$HEADROOM_KB" in
  # "could not measure" and "measured, and it is low" are different answers, and a check that
  # reported the first as the second would be this script telling the same kind of confident wrong
  # story the install used to. Say which one it is.
  ''|*[!0-9]*) echo "  note: could not read free space from df — skipping the headroom check" >&2 ;;
  *) [ "$HEADROOM_KB" -ge 5242880 ] || fail "under 5 GB free on the filesystem holding this checkout ($(( HEADROOM_KB / 1024 )) MB) — a --no-cache build of both images needs more" ;;
esac

# `COMPOSE_PROJECT_NAME` is the operator's, and it is the only thing standing between this gate and
# the *other* install on this host: every `docker compose` call below — the wiping `down --volumes`
# first among them — addresses whatever project the environment resolves to. This script used to
# truncate it out of `.env` on the line before that `down`, so a host set up the way README.md §1
# "Two installs on one host" documents had its other deployment torn down by a gate that had been
# told, in that same file, which project it was for. Read it once, before anything writes, and
# re-emit it into every `.env` this script produces — the ceremony already does exactly this.
# The operator's own keys, read once before anything writes and re-emitted into every `.env` this
# script produces. `.env.example` tells an operator to put all three here and `bin/stozher-bootstrap`
# preserves all three; a gate that kept only the project name left the other two to fall back to
# defaults that belong to the *other* install on the host. The port one fails safe — the preflight
# below catches the collision and says to pass `--port` — but two files disagreeing about where a
# setting lives is how an operator ends up not trusting either.
GATE_CARRIED=""
if [ -f .env ]; then
  for key in COMPOSE_PROJECT_NAME STOZHER_KERNEL_IMAGE STOZHER_GATEWAY_IMAGE; do
    line="$(grep -E "^[[:space:]]*${key}=" .env | tail -n 1 || true)"
    if [ -n "$line" ]; then GATE_CARRIED="${GATE_CARRIED}${line}
"; fi
  done
fi
write_env() {
  printf 'STOZHER_UID=%s\nSTOZHER_GID=%s\n' "$(id -u)" "$(id -g)" > .env
  if [ -n "$GATE_CARRIED" ]; then printf '%s' "$GATE_CARRIED" >> .env; fi
  # The port this run was told to use, not the one the previous install left behind: `--port` is how
  # a second install is possible at all, and it must win over anything carried over.
  printf 'STOZHER_KERNEL_PORT=%s\n' "$PORT" >> .env
}

# ---------------------------------------------------------------------------------------------
step "0  wiping every trace of a previous install"
if [ "$CLEAN" = "yes" ]; then
  # `.env` first and only then `down`: compose interpolates the whole file on every invocation, and
  # `user:` has no default (SEC-7), so a `down` run without STOZHER_UID errors out — and this one is
  # `|| true`, which would leave the previous install's containers standing while claiming a wipe.
  write_env
  docker compose down --remove-orphans --volumes >/dev/null 2>&1 || true
  rm -rf var secrets genesis config/kernel-config.json config/stozher-gateway.toml .env
  if [ "$REBUILD" = "yes" ]; then
    docker image rm -f "$KERNEL_IMAGE" "$GATEWAY_IMAGE" >/dev/null 2>&1 || true
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
  write_env
  docker compose build --no-cache kernel gateway
else
  write_env
  docker compose build kernel gateway
fi

# ---------------------------------------------------------------------------------------------
step "2  the ceremony (bin/stozher-bootstrap, exactly as documented)"
# Not `rm -f .env`: the ceremony reads this file for the operator's own keys before it rewrites it,
# and removing it here is how the project name got lost on the way into the install that needed it.
write_env
# `--accept-unrecoverable` because this gate is *measuring an install*, not producing a
# deployment anyone keeps: it wipes the directory it runs in, and its own README says so twice.
# The flag is passed explicitly rather than the refusal being weakened, so the one path that
# legitimately wants a disposable single-root install says so out loud and every other caller
# still gets stopped (DEF-19).
./bin/stozher-bootstrap --root "$ROOT_SUBJECT" --port "$PORT" --accept-unrecoverable

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
