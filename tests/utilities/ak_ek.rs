// SPDX-License-Identifier: Apache-2.0

//! Integration tests for profile-oriented EK/AK creation and EK certificate
//! retrieval utilities.

mod createak {
    use crate::common::SwtpmSession;

    #[test]
    fn createak_rsa() {
        let s = SwtpmSession::new();
        let ek_ctx = s.tmp().path().join("ek.ctx");
        let ek_pub = s.tmp().path().join("ek_pub.bin");
        s.cmd("createek")
            .args(["-G", "rsa", "-c"])
            .arg(&ek_ctx)
            .arg("-u")
            .arg(&ek_pub)
            .assert()
            .success();

        s.flush_transient();

        let ak_ctx = s.tmp().path().join("ak.ctx");
        let ak_pub = s.tmp().path().join("ak_pub.bin");
        let ak_priv = s.tmp().path().join("ak_priv.bin");
        let ak_name = s.tmp().path().join("ak_name.bin");
        s.cmd("createak")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&ek_ctx))
            .arg("-c")
            .arg(&ak_ctx)
            .args(["-G", "rsa", "-g", "sha256", "-u"])
            .arg(&ak_pub)
            .arg("-r")
            .arg(&ak_priv)
            .arg("-n")
            .arg(&ak_name)
            .assert()
            .success();
        assert!(ak_pub.exists());
        assert!(ak_name.exists());
    }
}

mod createek {
    use crate::common::SwtpmSession;

    #[test]
    fn createek_ecc() {
        let s = SwtpmSession::new();
        let ek_ctx = s.tmp().path().join("ek_ecc.ctx");
        s.cmd("createek")
            .args(["-G", "ecc", "-c"])
            .arg(&ek_ctx)
            .assert()
            .success();
        assert!(ek_ctx.exists());
    }

    #[test]
    fn createek_persistent_reuses_supplied_session() {
        let s = SwtpmSession::new();
        let session = s.tmp().path().join("createek-session.ctx");
        s.cmd("startauthsession")
            .args(["--hmac-session", "-S"])
            .arg(&session)
            .assert()
            .success();

        let ek_ctx = s.tmp().path().join("persistent-ek.ctx");
        s.cmd("createek")
            .args(["-G", "rsa", "-c"])
            .arg(&ek_ctx)
            .args(["--persistent", "0x81000020", "-S"])
            .arg(&session)
            .assert()
            .success();

        s.cmd("readpublic")
            .arg("-c")
            .arg("hex:0x81000020")
            .assert()
            .success();
    }

    #[test]
    fn createek_rsa() {
        let s = SwtpmSession::new();
        let ek_ctx = s.tmp().path().join("ek.ctx");
        let ek_pub = s.tmp().path().join("ek_pub.bin");
        s.cmd("createek")
            .args(["-G", "rsa", "-c"])
            .arg(&ek_ctx)
            .arg("-u")
            .arg(&ek_pub)
            .assert()
            .success();
        assert!(ek_pub.exists());
    }
}

mod getekcertificate {
    use crate::common::SwtpmSession;

    #[test]
    fn getekcertificate_reuses_session_across_chunks() {
        let s = SwtpmSession::new();
        let nv_index = "0x01000070";
        let certificate: Vec<u8> = (0..600).map(|value| (value % 251) as u8).collect();
        let input = s.write_tmp_file("ek-cert.bin", &certificate);

        s.cmd("nvdefine")
            .args([
                "-C",
                "o",
                "-s",
                "600",
                "-a",
                "ownerwrite|ownerread",
                nv_index,
            ])
            .assert()
            .success();
        s.cmd("nvwrite")
            .args(["-C", "o", "-i"])
            .arg(&input)
            .arg(nv_index)
            .assert()
            .success();

        let session = s.tmp().path().join("getekcertificate-session.ctx");
        s.cmd("startauthsession")
            .args(["--hmac-session", "-S"])
            .arg(&session)
            .assert()
            .success();

        let output = s.tmp().path().join("ek-cert-read.bin");
        s.cmd("getekcertificate")
            .args(["--nv-index", nv_index, "-C", "o", "--chunk-size", "128"])
            .arg("-S")
            .arg(&session)
            .arg("-o")
            .arg(&output)
            .assert()
            .success();

        assert_eq!(std::fs::read(output).unwrap(), certificate);
    }
}
