#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Common test helpers for tpm2-cli integration tests.
# Source this file from individual test scripts.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export TPM2_BIN="${REPO_ROOT}/target/release/tpm2"
SWTPM_PID=""
SWTPM_PORT=""
SWTPM_CTRL_PORT=""
export TEST_TMPDIR=""

# Colours for output (disabled if not a terminal and not in CI).
if [ -t 1 ] || [ "${CI:-}" = "true" ]; then
    GREEN=$'\033[32m'
    RED=$'\033[31m'
    YELLOW=$'\033[33m'
    RESET=$'\033[0m'
else
    GREEN="" RED="" YELLOW="" RESET=""
fi

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "${GREEN}  PASS${RESET}: $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "${RED}  FAIL${RESET}: $1"
    if [ -n "${2:-}" ]; then
        echo "        $2"
    fi
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::error::FAIL: $1"
    fi
}

skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    echo "${YELLOW}  SKIP${RESET}: $1"
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::warning::SKIP: $1"
    fi
}

summary() {
    echo ""
    echo "Results: ${GREEN}${PASS_COUNT} passed${RESET}, ${RED}${FAIL_COUNT} failed${RESET}, ${YELLOW}${SKIP_COUNT} skipped${RESET}"
    if [ "$FAIL_COUNT" -gt 0 ]; then
        return 1
    fi
    return 0
}

# Start an swtpm simulator and set TPM2TOOLS_TCTI.
start_swtpm() {
    TEST_TMPDIR="$(mktemp -d)"
    export TEST_TMPDIR

    # Pick a random port range to avoid collisions.
    SWTPM_PORT=$((20000 + RANDOM % 10000))
    SWTPM_CTRL_PORT=$((SWTPM_PORT + 1))

    swtpm socket \
        --tpmstate dir="$TEST_TMPDIR" \
        --tpm2 \
        --server type=tcp,port="$SWTPM_PORT" \
        --ctrl type=tcp,port="$SWTPM_CTRL_PORT" \
        --flags startup-clear &
    SWTPM_PID=$!

    # Wait for swtpm to be ready.
    for _ in $(seq 1 20); do
        if bash -c "echo >/dev/tcp/localhost/$SWTPM_PORT" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done

    export TPM2TOOLS_TCTI="swtpm:host=localhost,port=${SWTPM_PORT}"
}

# Stop swtpm and clean up.
stop_swtpm() {
    if [ -n "$SWTPM_PID" ]; then
        kill "$SWTPM_PID" 2>/dev/null || true
        wait "$SWTPM_PID" 2>/dev/null || true
        SWTPM_PID=""
    fi
    if [ -n "$TEST_TMPDIR" ]; then
        rm -rf "$TEST_TMPDIR"
        TEST_TMPDIR=""
    fi
}

trap stop_swtpm EXIT

# Run the tpm2 binary. Suppress INFO log output.
tpm2() {
    "$TPM2_BIN" -v Off "$@"
}
export -f tpm2

# Run a test case. Usage: run_test "description" command [args...]
# Captures stdout+stderr; on failure prints them.
run_test() {
    local desc="$1"
    shift
    local output
    if output=$("$@" 2>&1); then
        pass "$desc"
    else
        fail "$desc" "$(echo "$output" | head -5)"
    fi
}

# Build the binary if needed.
ensure_built() {
    if [ ! -x "$TPM2_BIN" ]; then
        echo "Building tpm2 binary..."
        (cd "$REPO_ROOT" && cargo build --release --quiet)
    fi
}
