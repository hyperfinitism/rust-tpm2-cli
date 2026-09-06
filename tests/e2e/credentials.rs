// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for credential activation protocol.

mod credential_activation {
    use crate::common::SwtpmSession;

    #[test]
    fn e2e_makecredential_and_activatecredential_roundtrip() {
        let s = SwtpmSession::new();
        let (ek_ctx, ek_pub, ak_ctx, ak_name) = s.create_credential_keys();

        let secret = s.write_tmp_file("secret.bin", b"secret credential!");
        let cred_blob = s.tmp().path().join("cred_blob.bin");
        s.cmd("makecredential")
            .arg("-u")
            .arg(&ek_pub)
            .arg("-s")
            .arg(&secret)
            .arg("-n")
            .arg(&ak_name)
            .arg("-o")
            .arg(&cred_blob)
            .assert()
            .success();
        assert!(cred_blob.exists());

        let certinfo = s.tmp().path().join("certinfo.bin");
        s.cmd("activatecredential")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&ak_ctx))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&ek_ctx))
            .arg("-i")
            .arg(&cred_blob)
            .arg("-o")
            .arg(&certinfo)
            .assert()
            .success();

        assert_eq!(std::fs::read(&certinfo).unwrap(), b"secret credential!");
    }
}
