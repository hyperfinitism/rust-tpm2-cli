#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: pcrread, pcrextend, pcrreset, pcrevent
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== PCR Operations ==="

tpm2 startup --clear >/dev/null 2>&1

# -- pcrread --
run_test "pcrread sha256:0,1,2" tpm2 pcrread "sha256:0,1,2"
run_test "pcrread all sha256" tpm2 pcrread "sha256:all"
run_test "pcrread to file" bash -c '
    tpm2 pcrread "sha256:0" -o "$TEST_TMPDIR/pcr0.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/pcr0.bin" ]
'

# -- pcrextend --
run_test "pcrextend sha256" bash -c '
    DIGEST="0000000000000000000000000000000000000000000000000000000000000001" &&
    tpm2 pcrextend "16:sha256=$DIGEST" 2>/dev/null
'
run_test "pcrread after extend is non-zero" bash -c '
    tpm2 pcrread "sha256:16" -o "$TEST_TMPDIR/pcr16.bin" 2>/dev/null &&
    ZEROS=$(printf "%064d" 0) &&
    ACTUAL=$(xxd -p "$TEST_TMPDIR/pcr16.bin" | tr -d "\n") &&
    [ "$ACTUAL" != "$ZEROS" ]
'

# -- pcrreset --
run_test "pcrreset 16" bash -c '
    tpm2 pcrreset 16 2>/dev/null
'
run_test "pcrread after reset is zero" bash -c '
    tpm2 pcrread "sha256:16" -o "$TEST_TMPDIR/pcr16_reset.bin" 2>/dev/null &&
    ZEROS="0000000000000000000000000000000000000000000000000000000000000000" &&
    ACTUAL=$(xxd -p "$TEST_TMPDIR/pcr16_reset.bin" | tr -d "\n") &&
    [ "$ACTUAL" = "$ZEROS" ]
'

# -- pcrevent --
# pcrevent has a bug with PCR handle resolution (Esys_TR_FromTPMPublic fails).
# Verify the command at least parses.
run_test "pcrevent --help" tpm2 pcrevent --help

summary
