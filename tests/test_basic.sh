#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: startup, shutdown, getrandom, selftest, gettestresult, incrementalselftest,
#        testparms, stirrandom, readclock, getcap, hash, rcdecode, print
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== Basic TPM Operations ==="

# -- startup / shutdown --
run_test "startup --clear" tpm2 startup --clear
run_test "shutdown --clear" tpm2 shutdown --clear
run_test "startup (state)" tpm2 startup
run_test "shutdown (state)" tpm2 shutdown

# Restart for remaining tests.
tpm2 startup --clear >/dev/null 2>&1

# -- getrandom --
run_test "getrandom 16 --hex" bash -c 'out=$(tpm2 getrandom 16 --hex 2>/dev/null) && [ ${#out} -eq 32 ]'
run_test "getrandom to file" bash -c '
    tpm2 getrandom 32 -o "$TEST_TMPDIR/rand.bin" 2>/dev/null &&
    [ "$(wc -c < "$TEST_TMPDIR/rand.bin")" -eq 32 ]
'

# -- selftest --
run_test "selftest --full-test" tpm2 selftest --full-test

# -- gettestresult --
run_test "gettestresult" tpm2 gettestresult

# -- incrementalselftest --
run_test "incrementalselftest sha256" tpm2 incrementalselftest sha256

# -- testparms --
run_test "testparms rsa2048" tpm2 testparms rsa2048
run_test "testparms aes128" tpm2 testparms aes128
run_test "testparms keyedhash" tpm2 testparms keyedhash

# -- stirrandom --
run_test "stirrandom" bash -c '
    dd if=/dev/urandom of="$TEST_TMPDIR/entropy.bin" bs=32 count=1 2>/dev/null &&
    tpm2 stirrandom -i "$TEST_TMPDIR/entropy.bin" 2>/dev/null
'

# -- readclock --
run_test "readclock" tpm2 readclock

# -- getcap --
run_test "getcap --list" tpm2 getcap --list
run_test "getcap algorithms" tpm2 getcap algorithms
run_test "getcap pcrs" tpm2 getcap pcrs
run_test "getcap properties-fixed" tpm2 getcap properties-fixed
run_test "getcap properties-variable" tpm2 getcap properties-variable
run_test "getcap ecc-curves" tpm2 getcap ecc-curves
run_test "getcap handles-persistent" tpm2 getcap handles-persistent

# -- hash --
run_test "hash sha256" bash -c '
    echo -n "hello" > "$TEST_TMPDIR/msg.bin" &&
    tpm2 hash -g sha256 -o "$TEST_TMPDIR/digest.bin" "$TEST_TMPDIR/msg.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/digest.bin" ]
'
run_test "hash sha256 with ticket" bash -c '
    echo -n "hello" > "$TEST_TMPDIR/msg2.bin" &&
    tpm2 hash -g sha256 -o "$TEST_TMPDIR/digest2.bin" -t "$TEST_TMPDIR/ticket.bin" "$TEST_TMPDIR/msg2.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/ticket.bin" ]
'

# -- rcdecode --
run_test "rcdecode 0x000" tpm2 rcdecode 0x000
run_test "rcdecode 0x100" tpm2 rcdecode 0x100

# -- print --
# readpublic writes TPMT_PUBLIC (no size prefix), so use that type.
run_test "print TPMT_PUBLIC" bash -c '
    tpm2 createprimary -c "$TEST_TMPDIR/primary.ctx" 2>/dev/null &&
    tpm2 readpublic -c "file:$TEST_TMPDIR/primary.ctx" -o "$TEST_TMPDIR/pub.bin" 2>/dev/null &&
    tpm2 print -t TPMT_PUBLIC "$TEST_TMPDIR/pub.bin" 2>/dev/null
'
run_test "print TPMS_CONTEXT" bash -c '
    tpm2 print -t TPMS_CONTEXT "$TEST_TMPDIR/primary.ctx" 2>/dev/null
'

summary
