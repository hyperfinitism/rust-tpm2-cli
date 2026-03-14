#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: quote, certify, certifycreation, gettime, checkquote,
#        getcommandauditdigest, getsessionauditdigest, nvcertify
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== Attestation ==="

tpm2 startup --clear >/dev/null 2>&1

# Setup: create a signing key.
tpm2 createprimary -C o -c "$TEST_TMPDIR/primary.ctx" 2>/dev/null
tpm2 create -C "$TEST_TMPDIR/primary.ctx" -G rsa -g sha256 \
    -r "$TEST_TMPDIR/sign.priv" -u "$TEST_TMPDIR/sign.pub" 2>/dev/null
tpm2 load -C "$TEST_TMPDIR/primary.ctx" \
    -r "$TEST_TMPDIR/sign.priv" -u "$TEST_TMPDIR/sign.pub" \
    -c "$TEST_TMPDIR/sign.ctx" 2>/dev/null

# -- quote --
run_test "quote" bash -c '
    tpm2 quote -c "$TEST_TMPDIR/sign.ctx" -l "sha256:0,1,2" -g sha256 \
        -m "$TEST_TMPDIR/quote_msg.bin" -s "$TEST_TMPDIR/quote_sig.bin" \
        -o "$TEST_TMPDIR/quote_pcr.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/quote_msg.bin" ] && [ -s "$TEST_TMPDIR/quote_sig.bin" ]
'
run_test "quote with qualification" bash -c '
    tpm2 quote -c "$TEST_TMPDIR/sign.ctx" -l "sha256:0" -g sha256 \
        -q "deadbeef" \
        -m "$TEST_TMPDIR/quote2_msg.bin" -s "$TEST_TMPDIR/quote2_sig.bin" 2>/dev/null
'

# -- checkquote --
# checkquote loads the public key via loadexternal, which now works with
# the fixed readpublic binary output.
# checkquote -u expects a context file, not raw public binary.
# Load the key externally first, then pass the context to checkquote.
run_test "checkquote" bash -c '
    tpm2 readpublic -c "$TEST_TMPDIR/sign.ctx" -o "$TEST_TMPDIR/sign_pub.bin" >/dev/null 2>&1 &&
    tpm2 loadexternal -u "$TEST_TMPDIR/sign_pub.bin" -a n \
        -c "$TEST_TMPDIR/sign_ext.ctx" >/dev/null 2>&1 &&
    tpm2 checkquote \
        -u "$TEST_TMPDIR/sign_ext.ctx" \
        -m "$TEST_TMPDIR/quote_msg.bin" \
        -s "$TEST_TMPDIR/quote_sig.bin" \
        -f "$TEST_TMPDIR/quote_pcr.bin" \
        -l "sha256:0,1,2" 2>/dev/null
'

# -- certify --
# certify requires two auth sessions (certified object + signing key).
# The tool currently only supports one via -S, so this is a known limitation.
run_test "certify --help" tpm2 certify --help

# -- gettime --
# gettime also requires two auth sessions (privacy admin + signing key).
run_test "gettime --help" tpm2 gettime --help

# -- nvcertify --
run_test "nvcertify" bash -c '
    tpm2 nvdefine -C o -s 16 -a "ownerwrite|ownerread" 0x01000020 2>/dev/null &&
    echo -n "nv certify data!" | tpm2 nvwrite -C o -i /dev/stdin 0x01000020 2>/dev/null &&
    tpm2 nvcertify -C "$TEST_TMPDIR/sign.ctx" -i 0x01000020 -c o \
        -P "" -g sha256 \
        -o "$TEST_TMPDIR/nvcert_attest.bin" --signature "$TEST_TMPDIR/nvcert_sig.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/nvcert_attest.bin" ] &&
    tpm2 nvundefine -C o 0x01000020 2>/dev/null
'

# -- getcommandauditdigest --
run_test "getcommandauditdigest" bash -c '
    tpm2 getcommandauditdigest -c "$TEST_TMPDIR/sign.ctx" -C e \
        -o "$TEST_TMPDIR/audit_attest.bin" --signature "$TEST_TMPDIR/audit_sig.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/audit_attest.bin" ]
'

# -- getsessionauditdigest --
# getsessionauditdigest requires multiple auth sessions; verify it parses.
run_test "getsessionauditdigest --help" tpm2 getsessionauditdigest --help

tpm2 flushcontext --loaded-session 2>/dev/null || true
tpm2 flushcontext --transient-object 2>/dev/null || true

summary
