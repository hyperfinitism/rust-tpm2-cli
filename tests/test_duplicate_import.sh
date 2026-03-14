#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: duplicate, import, unseal, hmac
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== Duplicate, Import, Unseal, HMAC ==="

tpm2 startup --clear >/dev/null 2>&1

# These commands require specific key types (fixedTPM=false, sealed data, keyedHash)
# that our create commands don't produce. Test that they parse correctly.
run_test "duplicate --help" tpm2 duplicate --help
run_test "import --help" tpm2 import --help
run_test "unseal --help" tpm2 unseal --help
run_test "hmac --help" tpm2 hmac --help

summary
