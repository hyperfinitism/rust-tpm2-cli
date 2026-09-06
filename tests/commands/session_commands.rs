// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 11 — Session Commands.

mod policyrestart {
    use crate::common::SwtpmSession;

    #[test]
    fn policyrestart() {
        let s = SwtpmSession::new();
        let session_ctx = s.tmp().path().join("session.ctx");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&session_ctx)
            .args(["--policy-session", "-g", "sha256"])
            .assert()
            .success();
        s.cmd("policyrestart")
            .arg("-S")
            .arg(&session_ctx)
            .assert()
            .success();
    }
}

mod startauthsession {
    use crate::common::SwtpmSession;

    #[test]
    fn startauthsession_hmac() {
        let s = SwtpmSession::new();
        let session_ctx = s.tmp().path().join("hmac_session.ctx");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&session_ctx)
            .args(["--hmac-session", "-g", "sha256"])
            .assert()
            .success();
        assert!(session_ctx.exists());
    }

    #[test]
    fn startauthsession_policy() {
        let s = SwtpmSession::new();
        let session_ctx = s.tmp().path().join("session.ctx");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&session_ctx)
            .args(["--policy-session", "-g", "sha256"])
            .assert()
            .success();
        assert!(session_ctx.exists());
    }

    #[test]
    fn startauthsession_audit() {
        let s = SwtpmSession::new();
        let session = s.tmp().path().join("audit-session.ctx");
        s.cmd("startauthsession")
            .args(["--audit-session", "-S"])
            .arg(&session)
            .assert()
            .success();
        assert!(session.exists());
    }

    #[test]
    fn startauthsession_salted_and_bound() {
        let s = SwtpmSession::new();
        let salt_key = s.create_primary_rsa("salt-key");
        let bind_key = s.create_primary_rsa("bind-key");
        let session = s.tmp().path().join("salted-bound-session.ctx");
        s.cmd("startauthsession")
            .args(["--hmac-session", "--tpm-key"])
            .arg(SwtpmSession::file_ref(&salt_key))
            .arg("--bind")
            .arg(SwtpmSession::file_ref(&bind_key))
            .arg("-S")
            .arg(&session)
            .assert()
            .success();
        assert!(session.exists());
    }
}
