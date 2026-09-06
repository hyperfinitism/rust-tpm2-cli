// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for sealing and unsealing.

mod sealed_object_roundtrip {
    use crate::common::SwtpmSession;

    #[test]
    fn e2e_seal_and_unseal_roundtrip() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");

        let input = s.write_tmp_file("seal_input.bin", b"top secret sealed payload");
        let priv_f = s.tmp().path().join("sealed.priv");
        let pub_f = s.tmp().path().join("sealed.pub");
        s.cmd("create")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary))
            .args(["-G", "keyedhash", "-g", "sha256", "-i"])
            .arg(&input)
            .arg("-r")
            .arg(&priv_f)
            .arg("-u")
            .arg(&pub_f)
            .assert()
            .success();

        let ctx = s.tmp().path().join("sealed.ctx");
        s.cmd("load")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-r")
            .arg(&priv_f)
            .arg("-u")
            .arg(&pub_f)
            .arg("-c")
            .arg(&ctx)
            .assert()
            .success();

        let output = s.tmp().path().join("unseal_output.bin");
        s.cmd("unseal")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&ctx))
            .arg("-o")
            .arg(&output)
            .assert()
            .success();

        assert_eq!(
            std::fs::read(&output).unwrap(),
            b"top secret sealed payload"
        );
    }

    #[test]
    fn e2e_seal_with_auth_unseal_with_correct_auth() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");

        let input = s.write_tmp_file("seal_auth_input.bin", b"auth-protected secret data");
        let priv_f = s.tmp().path().join("sealed_auth.priv");
        let pub_f = s.tmp().path().join("sealed_auth.pub");
        s.cmd("create")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary))
            .args(["-G", "keyedhash", "-g", "sha256", "-i"])
            .arg(&input)
            .args(["-p", "sealpass", "-r"])
            .arg(&priv_f)
            .arg("-u")
            .arg(&pub_f)
            .assert()
            .success();

        let ctx = s.tmp().path().join("sealed_auth.ctx");
        s.cmd("load")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-r")
            .arg(&priv_f)
            .arg("-u")
            .arg(&pub_f)
            .arg("-c")
            .arg(&ctx)
            .assert()
            .success();

        let output = s.tmp().path().join("unseal_auth_output.bin");
        s.cmd("unseal")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&ctx))
            .args(["-p", "sealpass", "-o"])
            .arg(&output)
            .assert()
            .success();

        assert_eq!(
            std::fs::read(&output).unwrap(),
            b"auth-protected secret data"
        );
    }
}
