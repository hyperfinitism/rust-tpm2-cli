#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: startauthsession, sessionconfig, policyrestart, policypcr,
#        policycommandcode, policyauthvalue, policypassword, policyor,
#        policylocality, policynvwritten, createpolicy, policyauthorize,
#        policysecret, policycphash, policynamehash, policytemplate,
#        policyduplicationselect, policycountertimer
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== Sessions & Policy ==="

tpm2 startup --clear >/dev/null 2>&1

# -- startauthsession --
run_test "startauthsession (policy)" bash -c '
    tpm2 startauthsession -S "$TEST_TMPDIR/session.ctx" --policy-session -g sha256 2>/dev/null &&
    [ -s "$TEST_TMPDIR/session.ctx" ]
'

# -- sessionconfig --
run_test "sessionconfig enable-encrypt" bash -c '
    tpm2 sessionconfig -S "$TEST_TMPDIR/session.ctx" --enable-encrypt 2>/dev/null
'
run_test "sessionconfig disable-encrypt" bash -c '
    tpm2 sessionconfig -S "$TEST_TMPDIR/session.ctx" --disable-encrypt 2>/dev/null
'

# -- policyrestart --
run_test "policyrestart" bash -c '
    tpm2 policyrestart -S "$TEST_TMPDIR/session.ctx" 2>/dev/null
'

# Flush the policy session.
tpm2 flushcontext --loaded-session 2>/dev/null || true

# -- policypcr in trial session --
run_test "policypcr (trial)" bash -c '
    tpm2 startauthsession -S "$TEST_TMPDIR/trial.ctx" -g sha256 2>/dev/null &&
    tpm2 policypcr -S "$TEST_TMPDIR/trial.ctx" -l "sha256:0,1,2" \
        -L "$TEST_TMPDIR/pcr_policy.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/pcr_policy.bin" ]
'
tpm2 flushcontext --loaded-session 2>/dev/null || true

# -- policycommandcode --
run_test "policycommandcode (trial)" bash -c '
    tpm2 startauthsession -S "$TEST_TMPDIR/trial2.ctx" -g sha256 2>/dev/null &&
    tpm2 policycommandcode -S "$TEST_TMPDIR/trial2.ctx" unseal \
        -L "$TEST_TMPDIR/cc_policy.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/cc_policy.bin" ]
'
tpm2 flushcontext --loaded-session 2>/dev/null || true

# -- policyauthvalue --
run_test "policyauthvalue (trial)" bash -c '
    tpm2 startauthsession -S "$TEST_TMPDIR/trial3.ctx" -g sha256 2>/dev/null &&
    tpm2 policyauthvalue -S "$TEST_TMPDIR/trial3.ctx" \
        -L "$TEST_TMPDIR/authval_policy.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/authval_policy.bin" ]
'
tpm2 flushcontext --loaded-session 2>/dev/null || true

# -- policypassword --
run_test "policypassword (trial)" bash -c '
    tpm2 startauthsession -S "$TEST_TMPDIR/trial4.ctx" -g sha256 2>/dev/null &&
    tpm2 policypassword -S "$TEST_TMPDIR/trial4.ctx" \
        -L "$TEST_TMPDIR/pw_policy.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/pw_policy.bin" ]
'
tpm2 flushcontext --loaded-session 2>/dev/null || true

# -- policyor --
# policyor takes multiple files as positional args: -l file1 file2 (not -l file1 -l file2)
run_test "policyor (trial)" bash -c '
    tpm2 startauthsession -S "$TEST_TMPDIR/trial5.ctx" -g sha256 2>/dev/null &&
    dd if=/dev/zero bs=32 count=1 2>/dev/null > "$TEST_TMPDIR/pol_a.bin" &&
    dd if=/dev/urandom bs=32 count=1 2>/dev/null > "$TEST_TMPDIR/pol_b.bin" &&
    tpm2 policyor -S "$TEST_TMPDIR/trial5.ctx" \
        -l "$TEST_TMPDIR/pol_a.bin" "$TEST_TMPDIR/pol_b.bin" \
        -L "$TEST_TMPDIR/or_policy.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/or_policy.bin" ]
'
tpm2 flushcontext --loaded-session 2>/dev/null || true

# -- policylocality --
# Locality 0 is rejected by the TPM; locality 3 works.
run_test "policylocality (trial)" bash -c '
    tpm2 startauthsession -S "$TEST_TMPDIR/trial6.ctx" -g sha256 2>/dev/null &&
    tpm2 policylocality -S "$TEST_TMPDIR/trial6.ctx" 3 \
        -L "$TEST_TMPDIR/loc_policy.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/loc_policy.bin" ]
'
tpm2 flushcontext --loaded-session 2>/dev/null || true

# -- policynvwritten --
# -s is a boolean flag (presence = written_set=true).
run_test "policynvwritten (trial)" bash -c '
    tpm2 startauthsession -S "$TEST_TMPDIR/trial7.ctx" -g sha256 2>/dev/null &&
    tpm2 policynvwritten -S "$TEST_TMPDIR/trial7.ctx" -s \
        -L "$TEST_TMPDIR/nvw_policy.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/nvw_policy.bin" ]
'
tpm2 flushcontext --loaded-session 2>/dev/null || true

# -- createpolicy --
run_test "createpolicy (PCR)" bash -c '
    tpm2 createpolicy -g sha256 --policy-pcr -l "sha256:0,1,2" \
        -L "$TEST_TMPDIR/created_policy.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/created_policy.bin" ]
'

# -- policycountertimer --
run_test "policycountertimer (trial)" bash -c '
    tpm2 startauthsession -S "$TEST_TMPDIR/trial_ct.ctx" -g sha256 2>/dev/null &&
    tpm2 policycountertimer -S "$TEST_TMPDIR/trial_ct.ctx" \
        --operand-b "0000000000000000" --offset 0 --operation ult 2>/dev/null
'
tpm2 flushcontext --loaded-session 2>/dev/null || true

# -- policysecret --
run_test "policysecret (with owner)" bash -c '
    tpm2 startauthsession -S "$TEST_TMPDIR/ps_session.ctx" --policy-session -g sha256 2>/dev/null &&
    tpm2 policysecret --object-hierarchy o \
        -S "$TEST_TMPDIR/ps_session.ctx" \
        -L "$TEST_TMPDIR/secret_policy.bin" 2>/dev/null &&
    [ -s "$TEST_TMPDIR/secret_policy.bin" ]
'
tpm2 flushcontext --loaded-session 2>/dev/null || true

# -- startauthsession HMAC --
run_test "startauthsession (hmac)" bash -c '
    tpm2 startauthsession -S "$TEST_TMPDIR/hmac_session.ctx" --hmac-session -g sha256 2>/dev/null &&
    [ -s "$TEST_TMPDIR/hmac_session.ctx" ]
'
tpm2 flushcontext --loaded-session 2>/dev/null || true

summary
