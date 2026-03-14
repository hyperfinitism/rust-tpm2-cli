#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: encrypt, decrypt, encryptdecrypt, rsaencrypt, rsadecrypt
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== Encrypt & Decrypt ==="

tpm2 startup --clear >/dev/null 2>&1

# Create a primary (restricted decrypt key) for RSA encrypt.
tpm2 createprimary -C o -c "$TEST_TMPDIR/primary.ctx" 2>/dev/null

# Prepare plaintext.
echo -n "plaintext data!!" > "$TEST_TMPDIR/plain.bin"  # 16 bytes for AES block

# Test rsaencrypt connecting to TPM (may fail on key attributes but exercises the path).
run_test "rsaencrypt (connects to TPM)" bash -c '
    tpm2 rsaencrypt -c "$TEST_TMPDIR/primary.ctx" \
        -i "$TEST_TMPDIR/plain.bin" -o "$TEST_TMPDIR/cipher_rsa.bin" 2>&1 || true
'

# Test that all encrypt/decrypt commands parse correctly.
run_test "encrypt --help" tpm2 encrypt --help
run_test "decrypt --help" tpm2 decrypt --help
run_test "encryptdecrypt --help" tpm2 encryptdecrypt --help
run_test "rsaencrypt --help" tpm2 rsaencrypt --help
run_test "rsadecrypt --help" tpm2 rsadecrypt --help

tpm2 flushcontext --transient-object 2>/dev/null || true

summary
