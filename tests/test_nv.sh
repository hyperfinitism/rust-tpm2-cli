#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: nvdefine, nvwrite, nvread, nvreadpublic, nvreadlock, nvwritelock,
#        nvundefine, nvincrement, nvextend, nvsetbits
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== NV Storage ==="

tpm2 startup --clear >/dev/null 2>&1

NV_IDX="0x01000001"
NV_IDX2="0x01000002"

# -- nvdefine & nvwrite & nvread --
run_test "nvdefine ordinary" tpm2 nvdefine -C o -s 32 -a "ownerwrite|ownerread" "$NV_IDX"

run_test "nvreadpublic" tpm2 nvreadpublic "$NV_IDX"

run_test "nvwrite" bash -c '
    echo -n "hello world, nv storage!12345678" > "$TEST_TMPDIR/nv_data.bin" &&
    tpm2 nvwrite -C o -i "$TEST_TMPDIR/nv_data.bin" '"$NV_IDX"' 2>/dev/null
'
run_test "nvread" bash -c '
    tpm2 nvread -C o -s 32 -o "$TEST_TMPDIR/nv_read.bin" '"$NV_IDX"' 2>/dev/null &&
    diff "$TEST_TMPDIR/nv_data.bin" "$TEST_TMPDIR/nv_read.bin"
'
run_test "nvread auto-size" bash -c '
    tpm2 nvread -C o -o "$TEST_TMPDIR/nv_read2.bin" '"$NV_IDX"' 2>/dev/null &&
    [ "$(wc -c < "$TEST_TMPDIR/nv_read2.bin")" -eq 32 ]
'

# -- nvundefine --
run_test "nvundefine" tpm2 nvundefine -C o "$NV_IDX"

# -- nvdefine with auth --
run_test "nvdefine with auth" tpm2 nvdefine -C o -s 16 -a "ownerwrite|ownerread" -p "nvpass" "$NV_IDX2"
run_test "nvundefine (auth index)" tpm2 nvundefine -C o "$NV_IDX2"

# -- nvreadlock / nvwritelock --
# These require read_stclear / write_stclear NV attributes which the tool's
# attribute parser doesn't currently support (no nt= or stclear flags).
# Verify the commands at least parse.
run_test "nvreadlock --help" tpm2 nvreadlock --help
run_test "nvwritelock --help" tpm2 nvwritelock --help

# -- nvincrement / nvextend / nvsetbits --
# These require special NV types (counter, extend, bits) which require the
# nt= attribute flag not yet supported by the NV attribute parser.
# Verify the commands at least parse.
run_test "nvincrement --help" tpm2 nvincrement --help
run_test "nvextend --help" tpm2 nvextend --help
run_test "nvsetbits --help" tpm2 nvsetbits --help

summary
