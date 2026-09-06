// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 15 — Symmetric Primitives.

mod encryptdecrypt2 {
    use crate::common::{SwtpmSession, symmetric_cipher_public};

    #[test]
    fn encryptdecrypt2_round_trips_aes_cfb_data() {
        let s = SwtpmSession::new();
        let parent = s.create_primary_rsa("parent");
        let (key, _, _) = s.create_and_load_from_public(
            &parent,
            "symmetric-key",
            &symmetric_cipher_public(),
            Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        );
        let plaintext = s.write_tmp_file("plaintext.bin", b"symmetric plaintext");
        let iv = s.write_tmp_file("iv.bin", &[0x5a; 16]);
        let ciphertext = s.tmp().path().join("ciphertext.bin");
        s.cmd("encryptdecrypt2")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .args(["-G", "cfb", "-i"])
            .arg(&iv)
            .arg("-o")
            .arg(&ciphertext)
            .arg(&plaintext)
            .assert()
            .success();
        assert_ne!(s.read_file(&ciphertext), b"symmetric plaintext");

        let decrypted = s.tmp().path().join("decrypted.bin");
        s.cmd("encryptdecrypt2")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .args(["--decrypt", "-G", "cfb", "-i"])
            .arg(&iv)
            .arg("-o")
            .arg(&decrypted)
            .arg(&ciphertext)
            .assert()
            .success();
        assert_eq!(s.read_file(&decrypted), b"symmetric plaintext");
    }

    #[test]
    fn encryptdecrypt2_rejects_a_non_symmetric_key() {
        let s = SwtpmSession::new();
        let key = s.create_primary_rsa("primary");
        let input = s.write_tmp_file("input.bin", b"plaintext");
        s.cmd("encryptdecrypt2")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .args(["-G", "cfb"])
            .arg("-o")
            .arg(s.tmp().path().join("output.bin"))
            .arg(&input)
            .assert()
            .failure();
    }
}

mod hash {
    use crate::common::SwtpmSession;
    use sha2::{Digest, Sha256};

    #[test]
    fn hash_supported_algorithms_produce_expected_lengths() {
        let s = SwtpmSession::new();
        let input = s.write_tmp_file("input.bin", b"hello");
        for (algorithm, expected_len) in
            [("sha1", 20), ("sha256", 32), ("sha384", 48), ("sha512", 64)]
        {
            let output = s.tmp().path().join(format!("{algorithm}.bin"));
            s.cmd("hash")
                .args(["-g", algorithm, "-o"])
                .arg(&output)
                .arg(&input)
                .assert()
                .success();
            assert_eq!(std::fs::metadata(output).unwrap().len(), expected_len);
        }
    }

    #[test]
    fn hash_sha256_matches_expected_digest() {
        let s = SwtpmSession::new();
        let input = s.write_tmp_file("input.bin", b"hello");
        let output = s.tmp().path().join("digest.bin");
        s.cmd("hash")
            .args(["-g", "sha256", "-o"])
            .arg(&output)
            .arg(input)
            .assert()
            .success();
        assert_eq!(
            std::fs::read(output).unwrap(),
            Sha256::digest(b"hello").as_slice()
        );
    }

    #[test]
    fn hash_nonexistent_input_fails() {
        let s = SwtpmSession::new();
        s.cmd("hash")
            .arg("-o")
            .arg(s.tmp().path().join("digest.bin"))
            .arg(s.tmp().path().join("missing.bin"))
            .assert()
            .failure();
    }

    #[test]
    fn hash_outputs_a_validation_ticket() {
        let s = SwtpmSession::new();
        let input = s.write_tmp_file("input.bin", b"hello");
        let digest = s.tmp().path().join("digest.bin");
        let ticket = s.tmp().path().join("ticket.bin");
        s.cmd("hash")
            .args(["-g", "sha256", "-C", "o", "-o"])
            .arg(&digest)
            .arg("-t")
            .arg(&ticket)
            .arg(input)
            .assert()
            .success();
        assert!(std::fs::metadata(ticket).unwrap().len() > 0);
    }
}

mod hmac {
    use crate::common::SwtpmSession;

    #[test]
    fn hmac_outputs_a_sha256_digest() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let private = s.tmp().path().join("hmac.priv");
        let public = s.tmp().path().join("hmac.pub");
        let key = s.tmp().path().join("hmac.ctx");
        s.cmd("create")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary))
            .args(["-G", "hmac", "-g", "sha256", "-r"])
            .arg(&private)
            .arg("-u")
            .arg(&public)
            .assert()
            .success();
        s.cmd("load")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-r")
            .arg(&private)
            .arg("-u")
            .arg(&public)
            .arg("-c")
            .arg(&key)
            .assert()
            .success();

        let input = s.write_tmp_file("input.bin", b"hello world");
        let output = s.tmp().path().join("hmac.bin");
        s.cmd("hmac")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .args(["-g", "sha256", "-i"])
            .arg(input)
            .arg("-o")
            .arg(&output)
            .assert()
            .success();
        assert_eq!(std::fs::metadata(output).unwrap().len(), 32);
    }
}
