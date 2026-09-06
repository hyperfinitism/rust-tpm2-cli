// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 10 — Testing.

mod gettestresult {
    use crate::common::SwtpmSession;

    #[test]
    fn gettestresult() {
        let s = SwtpmSession::new();
        s.cmd("gettestresult").assert().success();
    }
}

mod incrementalselftest {
    use crate::common::SwtpmSession;

    #[test]
    fn incrementalselftest_sha256() {
        let s = SwtpmSession::new();
        s.cmd("incrementalselftest")
            .arg("sha256")
            .assert()
            .success();
    }
}

mod selftest {
    use crate::common::SwtpmSession;

    #[test]
    fn selftest_full() {
        let s = SwtpmSession::new();
        s.cmd("selftest").arg("--full-test").assert().success();
    }
}
