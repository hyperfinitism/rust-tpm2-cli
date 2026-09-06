// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 22 — Integrity Collection (PCR).

mod pcrallocate {
    use crate::common::SwtpmSession;

    #[test]
    fn pcrallocate_sha256() {
        let s = SwtpmSession::new();
        // Allocate SHA-256 for PCRs 0-7 (platform auth).
        s.cmd("pcrallocate")
            .arg("sha256:0,1,2,3,4,5,6,7")
            .assert()
            .success();
    }
}

mod pcrevent {
    use crate::common::SwtpmSession;
    use sha2::{Digest, Sha256};

    #[test]
    fn pcrevent_computed_value_matches() {
        // pcrevent hashes the data first, then extends: PCR = H(old || H(data))
        let s = SwtpmSession::new();
        s.cmd("pcrreset").arg("16").assert().success();

        let event_data = b"compute me";
        let data_file = s.write_tmp_file("event.bin", event_data);
        s.cmd("pcrevent")
            .arg("16")
            .arg("-i")
            .arg(&data_file)
            .assert()
            .success();

        let out = s.tmp().path().join("pcr16.bin");
        s.cmd("pcrread")
            .arg("sha256:16")
            .arg("-o")
            .arg(&out)
            .assert()
            .success();

        // Expected: SHA-256(zeros_32 || SHA-256(event_data))
        let data_hash = Sha256::digest(event_data);
        let mut hasher = Sha256::new();
        hasher.update([0u8; 32]);
        hasher.update(data_hash);
        let expected = hasher.finalize();

        assert_eq!(std::fs::read(&out).unwrap(), expected.as_slice());
    }
}

mod pcrextend {
    use crate::common::SwtpmSession;
    use sha2::{Digest, Sha256};

    #[test]
    fn pcrextend_computed_value_matches() {
        let s = SwtpmSession::new();
        // Reset PCR 16 to zeros.
        s.cmd("pcrreset").arg("16").assert().success();

        let extend_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        s.cmd("pcrextend")
            .arg(format!("16:sha256={extend_hex}"))
            .assert()
            .success();

        let out = s.tmp().path().join("pcr16.bin");
        s.cmd("pcrread")
            .arg("sha256:16")
            .arg("-o")
            .arg(&out)
            .assert()
            .success();

        // Compute expected: SHA-256(32_zero_bytes || extend_digest_bytes)
        let old_pcr = [0u8; 32];
        let extend_bytes = hex::decode(extend_hex).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(old_pcr);
        hasher.update(&extend_bytes);
        let expected = hasher.finalize();

        assert_eq!(std::fs::read(&out).unwrap(), expected.as_slice());
    }
}

mod pcrread {
    use crate::common::SwtpmSession;

    #[test]
    fn pcrread_all_sha256() {
        let s = SwtpmSession::new();
        s.cmd("pcrread").arg("sha256:all").assert().success();
    }

    #[test]
    fn pcrread_sha256_selected() {
        let s = SwtpmSession::new();
        s.cmd("pcrread").arg("sha256:0,1,2").assert().success();
    }

    #[test]
    fn pcrread_to_file() {
        let s = SwtpmSession::new();
        let out = s.tmp().path().join("pcr0.bin");
        s.cmd("pcrread")
            .arg("sha256:0")
            .arg("-o")
            .arg(&out)
            .assert()
            .success();
        assert!(out.exists());
        assert!(std::fs::metadata(&out).unwrap().len() > 0);
    }
}

mod pcrreset {
    use crate::common::SwtpmSession;

    #[test]
    fn pcrreset_zeros_pcr() {
        let s = SwtpmSession::new();
        // Extend first to make it non-zero.
        let digest = "0000000000000000000000000000000000000000000000000000000000000001";
        s.cmd("pcrextend")
            .arg(format!("16:sha256={digest}"))
            .assert()
            .success();

        s.cmd("pcrreset").arg("16").assert().success();

        let out = s.tmp().path().join("pcr16_reset.bin");
        s.cmd("pcrread")
            .arg("sha256:16")
            .arg("-o")
            .arg(&out)
            .assert()
            .success();
        assert_eq!(std::fs::read(&out).unwrap(), vec![0u8; 32]);
    }
}

mod pcrsetauthpolicy {
    use crate::common::SwtpmSession;

    #[test]
    fn pcrsetauthpolicy_rejects_a_non_policy_configurable_pcr() {
        let s = SwtpmSession::new();
        let policy = s.write_tmp_file("policy.bin", &[0u8; 32]);
        s.cmd("pcrsetauthpolicy")
            .arg("16")
            .arg("-L")
            .arg(policy)
            .args(["-g", "sha256"])
            .assert()
            .failure();
    }
}

mod pcrsetauthvalue {
    use crate::common::SwtpmSession;

    #[test]
    fn pcrsetauthvalue_rejects_a_non_auth_configurable_pcr() {
        let s = SwtpmSession::new();
        s.cmd("pcrsetauthvalue")
            .args(["16", "-r", "new-auth"])
            .assert()
            .failure();
    }
}
