#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: createek, createak, makecredential, activatecredential
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== EK/AK & Credential ==="

tpm2 startup --clear >/dev/null 2>&1

# -- createek RSA --
run_test "createek RSA" bash -c '
    tpm2 createek -G rsa -c "$TEST_TMPDIR/ek.ctx" \
        -u "$TEST_TMPDIR/ek_pub.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/ek_pub.bin" ]
'

# -- createek ECC --
run_test "createek ECC" bash -c '
    tpm2 createek -G ecc -c "$TEST_TMPDIR/ek_ecc.ctx" 2>/dev/null
'

# Setup for credential activation: create EK and AK outside of run_test
# so subsequent tests can depend on the files.
tpm2 createek -G rsa -c "$TEST_TMPDIR/ek.ctx" -u "$TEST_TMPDIR/ek_pub.bin" 2>/dev/null || true
tpm2 flushcontext --transient-object 2>/dev/null || true

# -- createak --
run_test "createak RSA" bash -c '
    tpm2 createak -C "$TEST_TMPDIR/ek.ctx" -c "$TEST_TMPDIR/ak.ctx" \
        -G rsa -g sha256 \
        -u "$TEST_TMPDIR/ak_pub.bin" -r "$TEST_TMPDIR/ak_priv.bin" \
        -n "$TEST_TMPDIR/ak_name.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/ak_pub.bin" ] && [ -s "$TEST_TMPDIR/ak_name.bin" ]
'

# -- makecredential --
run_test "makecredential" bash -c '
    echo -n "secret credential!" > "$TEST_TMPDIR/secret.bin" &&
    tpm2 makecredential \
        -u "$TEST_TMPDIR/ek_pub.bin" \
        -s "$TEST_TMPDIR/secret.bin" \
        -n "$TEST_TMPDIR/ak_name.bin" \
        -o "$TEST_TMPDIR/cred_blob.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/cred_blob.bin" ]
'

# -- activatecredential --
run_test "activatecredential" bash -c '
    tpm2 activatecredential \
        -c "$TEST_TMPDIR/ak.ctx" \
        -C "$TEST_TMPDIR/ek.ctx" \
        -i "$TEST_TMPDIR/cred_blob.bin" \
        -o "$TEST_TMPDIR/certinfo.bin" 2>/dev/null &&
    diff "$TEST_TMPDIR/secret.bin" "$TEST_TMPDIR/certinfo.bin"
'

tpm2 flushcontext --transient-object 2>/dev/null || true

summary
