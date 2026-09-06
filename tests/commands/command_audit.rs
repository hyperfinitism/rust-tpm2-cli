// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 21 — Command Audit.

mod setcommandauditstatus {
    use crate::common::SwtpmSession;

    #[test]
    fn setcommandauditstatus_set_and_clear() {
        let s = SwtpmSession::new();
        // TCG TPM 2.0 Spec requires the audit hash algorithm to be configured before
        // commands can be added to the audit list. Initialize it first.
        s.cmd("setcommandauditstatus")
            .args(["-C", "o", "-g", "sha256"])
            .assert()
            .success();

        // Set getrandom (0x0000017B) for audit.
        s.cmd("setcommandauditstatus")
            .args(["-C", "o", "-g", "sha256", "--set-list", "0x17B"])
            .assert()
            .success();

        // Clear it.
        s.cmd("setcommandauditstatus")
            .args(["-C", "o", "-g", "sha256", "--clear-list", "0x17B"])
            .assert()
            .success();
    }
}
