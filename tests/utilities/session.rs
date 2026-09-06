// SPDX-License-Identifier: Apache-2.0

//! Integration tests for configuring attributes on saved authorization sessions.

mod sessionconfig {
    use crate::common::SwtpmSession;

    #[test]
    fn sessionconfig_enable_disable_encrypt() {
        let s = SwtpmSession::new();
        let session_ctx = s.tmp().path().join("session.ctx");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&session_ctx)
            .args(["--policy-session", "-g", "sha256"])
            .assert()
            .success();

        s.cmd("sessionconfig")
            .arg("-S")
            .arg(&session_ctx)
            .arg("--enable-encrypt")
            .assert()
            .success();

        s.cmd("sessionconfig")
            .arg("-S")
            .arg(&session_ctx)
            .arg("--disable-encrypt")
            .assert()
            .success();
    }
}
