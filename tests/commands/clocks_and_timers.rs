// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 29 — Clocks and Timers.

mod readclock {
    use crate::common::SwtpmSession;

    #[test]
    fn readclock() {
        let s = SwtpmSession::new();
        s.cmd("readclock").assert().success();
    }
}

mod clockrateadjust {
    use crate::common::SwtpmSession;

    #[test]
    fn clockrateadjust_medium() {
        let s = SwtpmSession::new();
        s.cmd("clockrateadjust").arg("medium").assert().success();
    }

    #[test]
    fn clockrateadjust_fast() {
        let s = SwtpmSession::new();
        s.cmd("clockrateadjust").arg("fast").assert().success();
    }
}

mod clockset {
    use crate::common::SwtpmSession;

    #[test]
    fn clockset() {
        let s = SwtpmSession::new();
        s.cmd("clockset").arg("100000").assert().success();
    }
}
