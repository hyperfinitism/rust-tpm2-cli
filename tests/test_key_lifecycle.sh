#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: createprimary, create, load, readpublic, flushcontext, evictcontrol,
#        changeauth, loadexternal
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== Key Lifecycle ==="

tpm2 startup --clear >/dev/null 2>&1

# -- createprimary --
run_test "createprimary RSA (owner)" bash -c '
    tpm2 createprimary -C o -G rsa -g sha256 -c "$TEST_TMPDIR/primary.ctx" 2>/dev/null
'
run_test "createprimary ECC (owner)" bash -c '
    tpm2 createprimary -C o -G ecc -g sha256 -c "$TEST_TMPDIR/primary_ecc.ctx" 2>/dev/null
'
run_test "createprimary with auth" bash -c '
    tpm2 createprimary -C o -G rsa -p "parentpass" -c "$TEST_TMPDIR/primary_auth.ctx" 2>/dev/null
'

# -- readpublic --
run_test "readpublic" bash -c '
    tpm2 readpublic -c "file:$TEST_TMPDIR/primary.ctx" -o "$TEST_TMPDIR/primary_pub.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/primary_pub.bin" ]
'

# -- create (child key) --
run_test "create RSA child key" bash -c '
    tpm2 create -C "file:$TEST_TMPDIR/primary.ctx" -G rsa -g sha256 \
        -r "$TEST_TMPDIR/child.priv" -u "$TEST_TMPDIR/child.pub" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/child.priv" ] && [ -s "$TEST_TMPDIR/child.pub" ]
'
run_test "create ECC child key" bash -c '
    tpm2 create -C "file:$TEST_TMPDIR/primary.ctx" -G ecc -g sha256 \
        -r "$TEST_TMPDIR/child_ecc.priv" -u "$TEST_TMPDIR/child_ecc.pub" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/child_ecc.priv" ] && [ -s "$TEST_TMPDIR/child_ecc.pub" ]
'
run_test "create child key with auth" bash -c '
    tpm2 create -C "file:$TEST_TMPDIR/primary.ctx" -G rsa -g sha256 -p "childpass" \
        -r "$TEST_TMPDIR/child_auth.priv" -u "$TEST_TMPDIR/child_auth.pub" 2>/dev/null
'

# -- load --
run_test "load RSA child key" bash -c '
    tpm2 load -C "file:$TEST_TMPDIR/primary.ctx" \
        -r "$TEST_TMPDIR/child.priv" -u "$TEST_TMPDIR/child.pub" \
        -c "$TEST_TMPDIR/child.ctx" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/child.ctx" ]
'
run_test "load ECC child key" bash -c '
    tpm2 load -C "file:$TEST_TMPDIR/primary.ctx" \
        -r "$TEST_TMPDIR/child_ecc.priv" -u "$TEST_TMPDIR/child_ecc.pub" \
        -c "$TEST_TMPDIR/child_ecc.ctx" 2>/dev/null
'

# -- readpublic on loaded child --
run_test "readpublic loaded child" bash -c '
    tpm2 readpublic -c "file:$TEST_TMPDIR/child.ctx" 2>/dev/null
'

# -- flushcontext --
run_test "flushcontext" bash -c '
    tpm2 flushcontext --transient-object 2>/dev/null
'

# -- evictcontrol (persist and evict) --
run_test "evictcontrol persist" bash -c '
    tpm2 createprimary -C o -c "$TEST_TMPDIR/evict_primary.ctx" 2>/dev/null &&
    tpm2 evictcontrol -C o -c "file:$TEST_TMPDIR/evict_primary.ctx" 0x81000010 2>/dev/null
'
run_test "readpublic persistent handle" bash -c '
    tpm2 readpublic -c hex:0x81000010 2>/dev/null
'
run_test "evictcontrol evict" bash -c '
    tpm2 evictcontrol -C o -c hex:0x81000010 0x81000010 2>/dev/null
'

# -- changeauth (hierarchy) --
run_test "changeauth owner hierarchy" bash -c '
    tpm2 changeauth --object-hierarchy o -r "newpass" 2>/dev/null &&
    tpm2 changeauth --object-hierarchy o -p "newpass" -r "" 2>/dev/null
'

# -- changeauth (object) --
run_test "changeauth object" bash -c '
    tpm2 createprimary -C o -c "$TEST_TMPDIR/ca_parent.ctx" 2>/dev/null &&
    tpm2 create -C "file:$TEST_TMPDIR/ca_parent.ctx" -G rsa -p "old" \
        -r "$TEST_TMPDIR/ca.priv" -u "$TEST_TMPDIR/ca.pub" 2>/dev/null &&
    tpm2 load -C "file:$TEST_TMPDIR/ca_parent.ctx" \
        -r "$TEST_TMPDIR/ca.priv" -u "$TEST_TMPDIR/ca.pub" \
        -c "$TEST_TMPDIR/ca.ctx" 2>/dev/null &&
    tpm2 changeauth -c "file:$TEST_TMPDIR/ca.ctx" \
        -C "file:$TEST_TMPDIR/ca_parent.ctx" \
        -p "old" -r "new" -o "$TEST_TMPDIR/ca_new.priv" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/ca_new.priv" ]
'

# -- loadexternal --
run_test "loadexternal public key" bash -c '
    tpm2 createprimary -C o -c "$TEST_TMPDIR/le_primary.ctx" 2>/dev/null &&
    tpm2 readpublic -c "file:$TEST_TMPDIR/le_primary.ctx" -o "$TEST_TMPDIR/le_pub.bin" 2>/dev/null &&
    tpm2 loadexternal -u "$TEST_TMPDIR/le_pub.bin" -a n \
        -c "$TEST_TMPDIR/le_ext.ctx" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/le_ext.ctx" ]
'

# Cleanup transients before next test file.
tpm2 flushcontext --transient-object 2>/dev/null || true

summary
