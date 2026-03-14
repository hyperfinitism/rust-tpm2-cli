#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run all tpm2-cli integration tests.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Helper: extract a number preceding a keyword from output (e.g. "3 passed" → 3).
extract_count() {
    local keyword="$1"
    local text="$2"
    echo "$text" | grep -oE "[0-9]+ ${keyword}" | grep -oE '[0-9]+' || echo "0"
}

# Build first.
echo "Building tpm2 binary..."
(cd "$REPO_ROOT" && cargo build --release --quiet 2>&1)
echo ""

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
FAILED_SUITES=()

for test_script in "$SCRIPT_DIR"/test_*.sh; do
    suite_name="$(basename "$test_script" .sh)"

    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::group::${suite_name}"
    else
        echo "========================================"
        echo "Running: $suite_name"
        echo "========================================"
    fi

    if output=$(bash "$test_script" 2>&1); then
        echo "$output"
    else
        echo "$output"
        FAILED_SUITES+=("$suite_name")
    fi

    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::endgroup::"
    fi

    # Extract counts from output.
    pass=$(extract_count "passed" "$output")
    fail=$(extract_count "failed" "$output")
    skip=$(extract_count "skipped" "$output")
    TOTAL_PASS=$((TOTAL_PASS + pass))
    TOTAL_FAIL=$((TOTAL_FAIL + fail))
    TOTAL_SKIP=$((TOTAL_SKIP + skip))
    echo ""
done

echo "========================================"
echo "OVERALL: ${TOTAL_PASS} passed, ${TOTAL_FAIL} failed, ${TOTAL_SKIP} skipped"
if [ ${#FAILED_SUITES[@]} -gt 0 ]; then
    echo "Failed suites: ${FAILED_SUITES[*]}"
fi
echo "========================================"

# Write GitHub Actions job summary if available.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "## Integration Test Results"
        echo ""
        echo "| Result | Count |"
        echo "|--------|-------|"
        echo "| Passed | ${TOTAL_PASS} |"
        echo "| Failed | ${TOTAL_FAIL} |"
        echo "| Skipped | ${TOTAL_SKIP} |"
        if [ ${#FAILED_SUITES[@]} -gt 0 ]; then
            echo ""
            echo "**Failed suites:** ${FAILED_SUITES[*]}"
        fi
    } >> "$GITHUB_STEP_SUMMARY"
fi

[ "$TOTAL_FAIL" -eq 0 ] && [ ${#FAILED_SUITES[@]} -eq 0 ]
