#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: sign, verifysignature (RSA + ECC), hash with ticket for signing
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== Sign & Verify ==="

tpm2 startup --clear >/dev/null 2>&1

# Setup: create a signing key (RSA).
tpm2 createprimary -C o -c "$TEST_TMPDIR/primary.ctx" 2>/dev/null
tpm2 create -C "$TEST_TMPDIR/primary.ctx" -G rsa -g sha256 \
    -r "$TEST_TMPDIR/sign_rsa.priv" -u "$TEST_TMPDIR/sign_rsa.pub" 2>/dev/null
tpm2 load -C "$TEST_TMPDIR/primary.ctx" \
    -r "$TEST_TMPDIR/sign_rsa.priv" -u "$TEST_TMPDIR/sign_rsa.pub" \
    -c "$TEST_TMPDIR/sign_rsa.ctx" 2>/dev/null

# Setup: create a signing key (ECC).
tpm2 create -C "$TEST_TMPDIR/primary.ctx" -G ecc -g sha256 \
    -r "$TEST_TMPDIR/sign_ecc.priv" -u "$TEST_TMPDIR/sign_ecc.pub" 2>/dev/null
tpm2 load -C "$TEST_TMPDIR/primary.ctx" \
    -r "$TEST_TMPDIR/sign_ecc.priv" -u "$TEST_TMPDIR/sign_ecc.pub" \
    -c "$TEST_TMPDIR/sign_ecc.ctx" 2>/dev/null

# Prepare a digest.
echo -n "test message for signing" > "$TEST_TMPDIR/msg.bin"
tpm2 hash -g sha256 -C o \
    -o "$TEST_TMPDIR/digest.bin" -t "$TEST_TMPDIR/hash_ticket.bin" \
    "$TEST_TMPDIR/msg.bin" 2>/dev/null

# -- RSA sign & verify --
run_test "sign RSA (rsassa)" bash -c '
    tpm2 sign -c "$TEST_TMPDIR/sign_rsa.ctx" -g sha256 -s rsassa \
        -d "$TEST_TMPDIR/digest.bin" -t "$TEST_TMPDIR/hash_ticket.bin" \
        -o "$TEST_TMPDIR/sig_rsa.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/sig_rsa.bin" ]
'
run_test "verifysignature RSA" bash -c '
    tpm2 verifysignature -c "$TEST_TMPDIR/sign_rsa.ctx" \
        -d "$TEST_TMPDIR/digest.bin" -s "$TEST_TMPDIR/sig_rsa.bin" \
        -t "$TEST_TMPDIR/verify_ticket.bin" 2>/dev/null
'

# -- ECC sign & verify --
run_test "sign ECC (ecdsa)" bash -c '
    tpm2 sign -c "$TEST_TMPDIR/sign_ecc.ctx" -g sha256 -s ecdsa \
        -d "$TEST_TMPDIR/digest.bin" -t "$TEST_TMPDIR/hash_ticket.bin" \
        -o "$TEST_TMPDIR/sig_ecc.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/sig_ecc.bin" ]
'
run_test "verifysignature ECC" bash -c '
    tpm2 verifysignature -c "$TEST_TMPDIR/sign_ecc.ctx" \
        -d "$TEST_TMPDIR/digest.bin" -s "$TEST_TMPDIR/sig_ecc.bin" 2>/dev/null
'

# -- verifysignature with external key file --
run_test "verifysignature with external key file" bash -c '
    tpm2 readpublic -c "$TEST_TMPDIR/sign_rsa.ctx" -o "$TEST_TMPDIR/sign_rsa_pub.bin" 2>/dev/null &&
    tpm2 flushcontext --transient-object 2>/dev/null &&
    tpm2 verifysignature -k "$TEST_TMPDIR/sign_rsa_pub.bin" \
        -d "$TEST_TMPDIR/digest.bin" -s "$TEST_TMPDIR/sig_rsa.bin" 2>/dev/null
'

# -- verifysignature with message (hash internally) --
run_test "verifysignature with -m message" bash -c '
    tpm2 load -C "$TEST_TMPDIR/primary.ctx" \
        -r "$TEST_TMPDIR/sign_rsa.priv" -u "$TEST_TMPDIR/sign_rsa.pub" \
        -c "$TEST_TMPDIR/sign_rsa2.ctx" 2>/dev/null &&
    tpm2 verifysignature -c "$TEST_TMPDIR/sign_rsa2.ctx" -g sha256 \
        -m "$TEST_TMPDIR/msg.bin" -s "$TEST_TMPDIR/sig_rsa.bin" 2>/dev/null
'

tpm2 flushcontext --transient-object 2>/dev/null || true

summary
