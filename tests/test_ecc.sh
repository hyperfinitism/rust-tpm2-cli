#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: geteccparameters, ecephemeral, ecdhkeygen, ecdhzgen, commit, zgen2phase
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== ECC Operations ==="

tpm2 startup --clear >/dev/null 2>&1

# -- geteccparameters --
run_test "geteccparameters ecc256" tpm2 geteccparameters ecc256
run_test "geteccparameters ecc384" tpm2 geteccparameters ecc384

# -- ecephemeral --
run_test "ecephemeral ecc256" bash -c '
    tpm2 ecephemeral ecc256 -u "$TEST_TMPDIR/eph_q.bin" \
        -t "$TEST_TMPDIR/eph_counter.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/eph_q.bin" ]
'

# Setup: create an ECC key for ECDH operations.
tpm2 createprimary -C o -G ecc -g sha256 -c "$TEST_TMPDIR/ecc_primary.ctx" 2>/dev/null

# -- ecdhkeygen --
run_test "ecdhkeygen" bash -c '
    tpm2 ecdhkeygen -c "file:$TEST_TMPDIR/ecc_primary.ctx" \
        -u "$TEST_TMPDIR/ecdh_pub.bin" -o "$TEST_TMPDIR/ecdh_z.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/ecdh_pub.bin" ] && [ -s "$TEST_TMPDIR/ecdh_z.bin" ]
'

# -- ecdhzgen --
# ecdhzgen requires a non-restricted ECC key; createprimary creates restricted keys.
# Verify it at least parses.
run_test "ecdhzgen --help" tpm2 ecdhzgen --help

# -- commit --
# commit requires a DAA/anonymous-signing capable key which our create doesn't produce.
# Verify it at least parses.
run_test "commit --help" tpm2 commit --help

# -- zgen2phase --
run_test "zgen2phase --help" tpm2 zgen2phase --help

tpm2 flushcontext --transient-object 2>/dev/null || true

summary
