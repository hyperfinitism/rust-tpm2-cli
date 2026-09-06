// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 9 — Start-up.

mod startup {
    use crate::common::SwtpmSession;

    #[test]
    fn startup_clear() {
        let s = SwtpmSession::new(); // already does startup --clear
        s.cmd("shutdown").arg("--clear").assert().success();
        s.cmd("startup").arg("--clear").assert().success();
    }

    #[test]
    fn startup_state() {
        let s = SwtpmSession::new();
        s.cmd("shutdown").assert().success();
        s.cmd("startup").assert().success();
    }
}

mod shutdown {
    use crate::common::SwtpmSession;

    #[test]
    fn shutdown_clear() {
        let s = SwtpmSession::new();
        s.cmd("shutdown").arg("--clear").assert().success();
    }

    #[test]
    fn shutdown_state() {
        let s = SwtpmSession::new();
        s.cmd("shutdown").assert().success();
    }
}
