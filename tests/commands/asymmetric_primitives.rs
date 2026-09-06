// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 14 — Asymmetric Primitives.

mod ecdhkeygen {
    use crate::common::SwtpmSession;

    #[test]
    fn ecdhkeygen() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_ecc("ecc_primary");
        let pub_file = s.tmp().path().join("ecdh_pub.bin");
        let z_file = s.tmp().path().join("ecdh_z.bin");
        s.cmd("ecdhkeygen")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-u")
            .arg(&pub_file)
            .arg("-o")
            .arg(&z_file)
            .assert()
            .success();
        assert!(std::fs::metadata(&pub_file).unwrap().len() > 0);
        assert!(std::fs::metadata(&z_file).unwrap().len() > 0);
    }
}

mod ecdhzgen {
    use crate::common::{SwtpmSession, ecdh_public};

    #[test]
    fn ecdhzgen_reproduces_the_generated_shared_point() {
        let s = SwtpmSession::new();
        let key = s.create_primary_from_public("ecdh-key", &ecdh_public());
        let peer_public = s.tmp().path().join("peer-public.bin");
        let generated_z = s.tmp().path().join("generated-z.bin");
        s.cmd("ecdhkeygen")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .arg("-u")
            .arg(&peer_public)
            .arg("-o")
            .arg(&generated_z)
            .assert()
            .success();

        let reproduced_z = s.tmp().path().join("reproduced-z.bin");
        s.cmd("ecdhzgen")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .arg("-u")
            .arg(&peer_public)
            .arg("-o")
            .arg(&reproduced_z)
            .assert()
            .success();

        assert_eq!(s.read_file(&reproduced_z), s.read_file(&generated_z));
    }

    #[test]
    fn ecdhzgen_rejects_a_restricted_parent_key() {
        let s = SwtpmSession::new();
        let key = s.create_primary_ecc("ecc-key");
        let public = s.tmp().path().join("peer-public.bin");
        s.cmd("ecdhkeygen")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .arg("-u")
            .arg(&public)
            .arg("-o")
            .arg(s.tmp().path().join("ephemeral-z.bin"))
            .assert()
            .success();

        let output = s.tmp().path().join("z.bin");
        s.cmd("ecdhzgen")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .arg("-u")
            .arg(&public)
            .arg("-o")
            .arg(&output)
            .assert()
            .failure();
    }
}

mod geteccparameters {
    use crate::common::SwtpmSession;

    #[test]
    fn geteccparameters_ecc256() {
        let s = SwtpmSession::new();
        s.cmd("geteccparameters").arg("ecc256").assert().success();
    }

    #[test]
    fn geteccparameters_ecc384() {
        let s = SwtpmSession::new();
        s.cmd("geteccparameters").arg("ecc384").assert().success();
    }
}

mod rsadecrypt {
    use crate::common::{SwtpmSession, unrestricted_rsa_decryption_public};

    #[test]
    fn rsadecrypt_recovers_rsaencrypt_plaintext() {
        let s = SwtpmSession::new();
        let key = s.create_primary_from_public(
            "rsa-decryption-key",
            &unrestricted_rsa_decryption_public(),
        );
        let plaintext = s.write_tmp_file("plaintext.bin", b"plaintext data");
        let ciphertext = s.tmp().path().join("ciphertext.bin");
        s.cmd("rsaencrypt")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .arg("-i")
            .arg(&plaintext)
            .arg("-o")
            .arg(&ciphertext)
            .assert()
            .success();

        let decrypted = s.tmp().path().join("decrypted.bin");
        s.cmd("rsadecrypt")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .arg("-i")
            .arg(&ciphertext)
            .arg("-o")
            .arg(&decrypted)
            .assert()
            .success();

        assert_eq!(s.read_file(&decrypted), b"plaintext data");
    }

    #[test]
    fn rsadecrypt_on_restricted_key_fails() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let plain = s.write_tmp_file("plain.bin", b"plaintext data!!");
        let cipher = s.tmp().path().join("cipher.bin");
        s.cmd("rsaencrypt")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-i")
            .arg(&plain)
            .arg("-o")
            .arg(&cipher)
            .assert()
            .success();

        s.cmd("rsadecrypt")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-i")
            .arg(&cipher)
            .arg("-o")
            .arg(s.tmp().path().join("dec.bin"))
            .assert()
            .failure();
    }
}

mod rsaencrypt {
    use crate::common::SwtpmSession;

    #[test]
    fn rsaencrypt_on_primary_key() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let plain = s.write_tmp_file("plain.bin", b"plaintext data!!");
        let cipher = s.tmp().path().join("cipher.bin");
        s.cmd("rsaencrypt")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-i")
            .arg(&plain)
            .arg("-o")
            .arg(&cipher)
            .assert()
            .success();
        assert!(std::fs::metadata(&cipher).unwrap().len() > 0);
    }
}
