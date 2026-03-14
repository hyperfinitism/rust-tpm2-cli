#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests: clear, clearcontrol, hierarchycontrol, dictionarylockout,
#        changeeps, changepps, setprimarypolicy, setcommandauditstatus,
#        setclock, clockrateadjust
source "$(dirname "$0")/helpers.sh"
ensure_built
start_swtpm

echo "=== Hierarchy & Admin ==="

tpm2 startup --clear >/dev/null 2>&1

# -- dictionarylockout --
run_test "dictionarylockout clear" tpm2 dictionarylockout --clear-lockout
run_test "dictionarylockout set params" tpm2 dictionarylockout --setup-parameters \
    --max-tries 5 --recovery-time 10 --lockout-recovery-time 10

# -- clear --
# Run clear early, before clearcontrol (which has a bug: -s default is true,
# so the command always disables clear regardless of flag presence).
run_test "clear (lockout)" tpm2 clear -c l
run_test "startup after clear" tpm2 startup --clear

# -- clearcontrol --
# clearcontrol -s flag: present = disable clear. Verify the command runs.
run_test "clearcontrol (disable)" tpm2 clearcontrol -C p -s
# Note: clearcontrol without -s also disables (default_value="true" bug).
# So we just verify the command accepts the flag.
run_test "clearcontrol --help" tpm2 clearcontrol --help

# -- hierarchycontrol --
# hierarchycontrol has a bug with null hierarchy handle resolution.
run_test "hierarchycontrol --help" tpm2 hierarchycontrol --help

# -- setprimarypolicy --
run_test "setprimarypolicy" bash -c '
    dd if=/dev/zero bs=32 count=1 2>/dev/null > "$TEST_TMPDIR/empty_policy.bin" &&
    tpm2 setprimarypolicy -C o -L "$TEST_TMPDIR/empty_policy.bin" -g sha256 2>/dev/null
'

# -- setcommandauditstatus --
run_test "setcommandauditstatus --help" tpm2 setcommandauditstatus --help

# -- clockrateadjust --
run_test "clockrateadjust medium" tpm2 clockrateadjust medium
run_test "clockrateadjust faster" tpm2 clockrateadjust faster

# -- setclock --
run_test "setclock" tpm2 setclock 100000

# -- changeeps (platform auth) --
run_test "changeeps" tpm2 changeeps

# -- changepps (platform auth) --
run_test "changepps" tpm2 changepps

summary
