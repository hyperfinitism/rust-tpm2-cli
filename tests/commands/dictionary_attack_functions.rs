// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 25 — Dictionary Attack Functions.

mod dictionarylockout {
    use crate::common::SwtpmSession;

    #[test]
    fn dictionarylockout_clear() {
        let s = SwtpmSession::new();
        s.cmd("dictionarylockout")
            .arg("--clear-lockout")
            .assert()
            .success();
    }

    #[test]
    fn dictionarylockout_set_params() {
        let s = SwtpmSession::new();
        s.cmd("dictionarylockout")
            .args([
                "--setup-parameters",
                "--max-tries",
                "5",
                "--recovery-time",
                "10",
                "--lockout-recovery-time",
                "10",
            ])
            .assert()
            .success();
    }
}
