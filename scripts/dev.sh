#!/usr/bin/env bash
set -euo pipefail

# Sondera dev wiring (DEMO-01, D-85)
#
# Builds and runs the full local demo stack together:
#   harness server (Unix-socket adjudicator)
#   dashboard API  (read-only, 127.0.0.1:${SONDERA_DASHBOARD_PORT:-8787})
#   web frontend   (Vite dev server on :5173, or dashboard-served in --built mode)
#
# Flags:
#   --seed     bulk-seed the demo trajectories BEFORE the frontend starts
#              (Pitfall 7: the bulk flurry must never hit an open UI)
#   --replay   after startup, run the seeder in paced replay mode in the
#              foreground so the live feed demo is watchable
#   --built    build web/ and serve it from the dashboard via --ui-dir
#              (D-75 one-port mode on :8787) instead of starting Vite
#   -h, --help show usage
#
# Prerequisites:
#   - SONDERA_DASHBOARD_TOKEN set in the environment or in ~/.sondera/env
#     (the dashboard loads the env file itself per D-39; this script never
#     prints the token value)
#   - Ollama is OPTIONAL: it powers live-agent guardrails only. The seeded
#     demo (D-83) never calls Ollama, so a missing Ollama is a warning,
#     not an error (D-85).
#
# IMPORTANT — Turso write-lock constraint:
#   The trajectory store (~/.sondera/trajectories.db) is an embedded Turso
#   database that allows ONE writer process at a time. The harness server
#   holds that write lock for its whole lifetime, so the seeder can never
#   run while the harness is up ("File is locked by another process").
#   This script therefore orders processes around the lock:
#     --seed    runs the bulk seed BEFORE the harness server starts
#     --replay  defers the harness start until the foreground replay
#               completes (the dashboard is unaffected — it reads from a
#               point-in-time copy and only stats the live DB)
#   Do NOT run `sondera-seed` manually in another terminal while the stack
#   is up — use `./scripts/dev.sh --seed --replay` to demo the live feed.
#
# Ctrl-C tears down every child process via the PID-array trap.

cd "$(dirname "$0")/.."

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SEED=false
REPLAY=false
BUILT=false

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --seed       Bulk-seed demo trajectories before the harness/frontend start"
    echo "  --replay     Run the seeder in paced replay mode after startup (foreground)."
    echo "               The harness server starts AFTER the replay completes: the"
    echo "               seeder and the harness cannot share the embedded Turso"
    echo "               write lock (single-writer database)."
    echo "  --built      Build web/ and serve it from the dashboard (--ui-dir, one port)"
    echo "  -h, --help   Show this help message"
    echo ""
    echo "Requires SONDERA_DASHBOARD_TOKEN in the environment or ~/.sondera/env."
    echo "Ollama is optional (live-agent guardrails only; the seeded demo never needs it)."
    echo "Never run sondera-seed manually while the harness server is up — the demo"
    echo "live feed is driven via './scripts/dev.sh --seed --replay'."
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --seed)
            SEED=true
            shift
            ;;
        --replay)
            REPLAY=true
            shift
            ;;
        --built)
            BUILT=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

PIDS=()

# Kill a process and its whole descendant tree, deepest-first. A plain
# kill on the PID array misses grandchildren: `npm run dev` spawns the
# actual vite node process as a child, which would survive as an orphan
# (T-07-24).
kill_tree() {
    local pid=$1
    local child
    for child in $(pgrep -P "$pid" 2>/dev/null || true); do
        kill_tree "$child"
    done
    kill "$pid" 2>/dev/null || true
}

cleanup() {
    trap - INT TERM EXIT
    if [[ ${#PIDS[@]} -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}Shutting down...${NC}"
        local pid
        for pid in "${PIDS[@]}"; do
            kill_tree "$pid"
        done
        wait 2>/dev/null || true
        echo -e "${GREEN}All processes stopped.${NC}"
    fi
}
trap cleanup INT TERM EXIT

# (1) Ollama reachability — warning only, never fatal (D-85): the seeded
# demo does not call Ollama; only live-agent guardrails need it.
echo "Checking Ollama (optional)..."
if curl -fsS http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo -e "${GREEN}Ollama reachable — live-agent guardrails available.${NC}"
else
    echo -e "${YELLOW}WARN: Ollama not reachable on :11434 — live agent guardrails unavailable; seeded demo unaffected.${NC}"
fi

# (2) Token presence check — the dashboard itself loads ~/.sondera/env
# (D-39); the script only verifies a token is configured SOMEWHERE.
# T-07-23: never echo the token's value.
SONDERA_ENV_FILE="${HOME}/.sondera/env"
if [[ -z "${SONDERA_DASHBOARD_TOKEN:-}" ]] && \
   ! { [[ -f "${SONDERA_ENV_FILE}" ]] && grep -q '^SONDERA_DASHBOARD_TOKEN=' "${SONDERA_ENV_FILE}"; }; then
    echo -e "${RED}Error: no dashboard token configured.${NC}"
    echo "Set SONDERA_DASHBOARD_TOKEN in your environment, e.g.:"
    echo "  export SONDERA_DASHBOARD_TOKEN=<your-secret>"
    echo "or add a SONDERA_DASHBOARD_TOKEN=... line to ${SONDERA_ENV_FILE}."
    echo "The dashboard refuses to start without one."
    exit 1
fi
echo -e "${GREEN}Dashboard token configured.${NC}"

# (3) Build everything first so startup failures are build errors, not
# half-started stacks. +stable is mandatory: the default local toolchain
# (1.89) is too old for the pinned cranelift (standing Phase 2 decision).
echo "Building harness, dashboard, and seeder..."
cargo +stable build -p sondera-harness -p sondera-dashboard -p sondera-seed

# (4) Bulk seed FIRST — before the harness server starts AND before the
# frontend opens. Two reasons:
#   - Turso write lock: the harness server opens ~/.sondera/trajectories.db
#     at startup and holds the single-writer lock for its lifetime; a seeder
#     started afterwards always fails with "File is locked by another
#     process". The seeder must finish before the harness opens the DB.
#   - Pitfall 7: an open UI must not watch the bulk flurry arrive through
#     /stream, so the seed also precedes the frontend.
if [[ "${SEED}" == "true" ]]; then
    echo "Seeding demo trajectories (bulk, before the harness opens the DB)..."
    target/debug/sondera-seed
    echo -e "${GREEN}Seed complete.${NC}"
fi

# (5) Harness server — unless --replay: the paced replay seeder needs the
# same exclusive Turso write lock the harness would hold, so in replay mode
# the harness start is DEFERRED until the replay completes (step 8). The
# dashboard never needs the lock (it reads a point-in-time copy and only
# stats the live DB), and the seeded demo never adjudicates live-agent
# events, so nothing in the demo misses the harness during the replay.
if [[ "${REPLAY}" == "true" ]]; then
    echo -e "${YELLOW}Replay mode: harness server start deferred until the replay completes (Turso single-writer lock).${NC}"
else
    echo "Starting sondera-harness-server..."
    target/debug/sondera-harness-server &
    PIDS+=($!)
fi

# (6) Dashboard API (one-port static serving in --built mode, D-75)
if [[ "${BUILT}" == "true" ]]; then
    echo "Building web/ for one-port mode..."
    (cd web && npm run build)
    echo "Starting sondera-dashboard with --ui-dir web/build..."
    target/debug/sondera-dashboard --ui-dir web/build &
    PIDS+=($!)
else
    echo "Starting sondera-dashboard..."
    target/debug/sondera-dashboard &
    PIDS+=($!)
fi

# (7) Frontend — Vite dev server (skipped in --built mode: the dashboard
# serves the built SPA on its own port).
if [[ "${BUILT}" != "true" ]]; then
    echo "Starting Vite dev server..."
    (cd web && npm run dev) &
    PIDS+=($!)
fi

DASHBOARD_PORT="${SONDERA_DASHBOARD_PORT:-8787}"
echo ""
echo -e "${GREEN}Sondera demo stack is up.${NC}"
if [[ "${BUILT}" == "true" ]]; then
    echo -e "  UI + API (one port): ${GREEN}http://127.0.0.1:${DASHBOARD_PORT}${NC}"
else
    echo -e "  Frontend (Vite):  ${GREEN}http://localhost:5173${NC}"
    echo -e "  Dashboard API:    ${GREEN}http://127.0.0.1:${DASHBOARD_PORT}${NC}"
fi
echo "  The token gate expects your SONDERA_DASHBOARD_TOKEN value."
echo "  Press Ctrl-C to stop all processes."

# (8) Paced replay in the foreground so the operator watches the live demo.
# The harness server is NOT running yet (step 5 deferred it), so the seeder
# can take the exclusive Turso write lock. Once the replay finishes and the
# lock is released, the harness starts (step 9) and the full stack is up.
if [[ "${REPLAY}" == "true" ]]; then
    echo ""
    echo -e "${YELLOW}Replay starts in 5s — open the dashboard now to watch it live.${NC}"
    sleep 5
    target/debug/sondera-seed --replay
    echo -e "${GREEN}Replay complete.${NC}"

    # (9) Deferred harness start — the seeder has released the write lock.
    echo "Starting sondera-harness-server (deferred until after replay)..."
    target/debug/sondera-harness-server &
    PIDS+=($!)
    echo -e "${GREEN}Stack fully up — keeps serving until Ctrl-C.${NC}"
fi

# (10) Keep serving until Ctrl-C; cleanup() reaps every child.
wait
