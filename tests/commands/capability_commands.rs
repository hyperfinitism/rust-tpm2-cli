// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 30 — Capability Commands.

mod getcap {
    use crate::common::SwtpmSession;

    #[test]
    fn getcap_algorithms() {
        let s = SwtpmSession::new();
        s.cmd("getcap").arg("algorithms").assert().success();
    }

    #[test]
    fn getcap_ecc_curves() {
        let s = SwtpmSession::new();
        s.cmd("getcap").arg("ecc-curves").assert().success();
    }

    #[test]
    fn getcap_handles_persistent() {
        let s = SwtpmSession::new();
        s.cmd("getcap").arg("handles-persistent").assert().success();
    }

    #[test]
    fn getcap_handles_transient() {
        let s = SwtpmSession::new();
        s.cmd("getcap").arg("handles-transient").assert().success();
    }

    #[test]
    fn getcap_list() {
        let s = SwtpmSession::new();
        s.cmd("getcap").arg("--list").assert().success();
    }

    #[test]
    fn getcap_pcrs() {
        let s = SwtpmSession::new();
        s.cmd("getcap").arg("pcrs").assert().success();
    }

    #[test]
    fn getcap_properties_fixed() {
        let s = SwtpmSession::new();
        s.cmd("getcap").arg("properties-fixed").assert().success();
    }

    #[test]
    fn getcap_properties_variable() {
        let s = SwtpmSession::new();
        s.cmd("getcap")
            .arg("properties-variable")
            .assert()
            .success();
    }
}

mod testparms {
    use crate::common::SwtpmSession;

    #[test]
    fn testparms_aes128() {
        let s = SwtpmSession::new();
        s.cmd("testparms").arg("aes128").assert().success();
    }

    #[test]
    fn testparms_keyedhash() {
        let s = SwtpmSession::new();
        s.cmd("testparms").arg("keyedhash").assert().success();
    }

    #[test]
    fn testparms_rsa2048() {
        let s = SwtpmSession::new();
        s.cmd("testparms").arg("rsa2048").assert().success();
    }
}
