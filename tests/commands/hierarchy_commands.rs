// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 24 — Hierarchy Commands.

mod changeeps {
    use crate::common::SwtpmSession;

    #[test]
    fn changeeps() {
        let s = SwtpmSession::new();
        s.cmd("changeeps").assert().success();
    }
}

mod changepps {
    use crate::common::SwtpmSession;

    #[test]
    fn changepps() {
        let s = SwtpmSession::new();
        s.cmd("changepps").assert().success();
    }
}

mod clear {
    use crate::common::SwtpmSession;

    #[test]
    fn clear_after_clearcontrol_disable_fails() {
        let s = SwtpmSession::new();
        s.cmd("clearcontrol")
            .args(["-C", "p", "-s"])
            .assert()
            .success();
        s.cmd("clear").args(["-c", "l"]).assert().failure();
    }

    #[test]
    fn clear_lockout() {
        let s = SwtpmSession::new();
        s.cmd("clear").args(["-c", "l"]).assert().success();
        // Need startup after clear.
        s.cmd("startup").arg("--clear").assert().success();
    }
}

mod clearcontrol {
    use crate::common::SwtpmSession;

    #[test]
    fn clearcontrol_disable() {
        let s = SwtpmSession::new();
        s.cmd("clearcontrol")
            .args(["-C", "p", "-s"])
            .assert()
            .success();
        s.cmd("clearcontrol")
            .args(["-C", "p", "--disable-clear=false"])
            .assert()
            .success();
        s.cmd("clear").args(["-c", "l"]).assert().success();
    }
}

mod hierarchycontrol {
    use crate::common::SwtpmSession;

    #[test]
    fn hierarchycontrol_disable_and_enable() {
        let s = SwtpmSession::new();
        s.cmd("hierarchycontrol")
            .arg("e")
            .arg("--state=false")
            .assert()
            .success();
        let ek_ctx = s.tmp().path().join("ek.ctx");
        s.cmd("createek")
            .args(["-G", "rsa", "-c"])
            .arg(&ek_ctx)
            .assert()
            .failure();

        s.cmd("hierarchycontrol").arg("e").assert().success();
        s.cmd("createek")
            .args(["-G", "rsa", "-c"])
            .arg(&ek_ctx)
            .assert()
            .success();
        assert!(ek_ctx.exists());
    }
}

mod setprimarypolicy {
    use crate::common::SwtpmSession;

    #[test]
    fn setprimarypolicy() {
        let s = SwtpmSession::new();
        let policy = s.write_tmp_file("empty_policy.bin", &[0u8; 32]);
        s.cmd("setprimarypolicy")
            .args(["-C", "o", "-L"])
            .arg(&policy)
            .args(["-g", "sha256"])
            .assert()
            .success();
    }
}

mod changeauth {
    use crate::common::SwtpmSession;

    #[test]
    fn changeauth_owner_hierarchy() {
        let s = SwtpmSession::new();
        s.cmd("changeauth")
            .args(["--object-hierarchy", "o", "-r", "newpass"])
            .assert()
            .success();
        s.cmd("changeauth")
            .args(["--object-hierarchy", "o", "-p", "newpass", "-r", ""])
            .assert()
            .success();
    }
}

mod createprimary {
    use crate::common::SwtpmSession;

    #[test]
    fn createprimary_ecc_owner() {
        let s = SwtpmSession::new();
        let ctx = s.create_primary_ecc("primary_ecc");
        assert!(ctx.exists());
    }

    #[test]
    fn createprimary_endorsement_hierarchy() {
        let s = SwtpmSession::new();
        let ctx = s.tmp().path().join("primary_e.ctx");
        s.cmd("createprimary")
            .args(["-C", "e", "-G", "rsa", "-c"])
            .arg(&ctx)
            .assert()
            .success();
        assert!(ctx.exists());
    }

    #[test]
    fn createprimary_invalid_algorithm_fails() {
        let s = SwtpmSession::new();
        let ctx = s.tmp().path().join("fail.ctx");
        s.cmd("createprimary")
            .args(["-C", "o", "-G", "invalidalg", "-c"])
            .arg(&ctx)
            .assert()
            .failure();
    }

    #[test]
    fn createprimary_rsa_owner() {
        let s = SwtpmSession::new();
        let ctx = s.create_primary_rsa("primary");
        assert!(ctx.exists());
    }

    #[test]
    fn createprimary_with_auth() {
        let s = SwtpmSession::new();
        let ctx = s.tmp().path().join("primary_auth.ctx");
        s.cmd("createprimary")
            .args(["-C", "o", "-G", "rsa", "-p", "parentpass", "-c"])
            .arg(&ctx)
            .assert()
            .success();
        assert!(ctx.exists());
    }
}
