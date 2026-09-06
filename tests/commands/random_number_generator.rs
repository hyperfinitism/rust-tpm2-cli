// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 16 — Random Number Generator.

mod getrandom {
    use crate::common::SwtpmSession;

    #[test]
    fn getrandom_1_byte() {
        let s = SwtpmSession::new();
        let output = s.cmd("getrandom").args(["1", "--hex"]).output().unwrap();
        assert!(output.status.success());
        let hex = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(hex.len(), 2);
    }

    #[test]
    fn getrandom_hex_16_bytes() {
        let s = SwtpmSession::new();
        let output = s.cmd("getrandom").args(["16", "--hex"]).output().unwrap();
        assert!(output.status.success());
        let hex = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(hex.len(), 32, "16 bytes should produce 32 hex chars");
    }

    #[test]
    fn getrandom_to_file() {
        let s = SwtpmSession::new();
        let out_file = s.tmp().path().join("rand.bin");
        s.cmd("getrandom")
            .args(["32", "-o"])
            .arg(&out_file)
            .assert()
            .success();
        let data = std::fs::read(&out_file).unwrap();
        assert_eq!(data.len(), 32);
    }
}

mod stirrandom {
    use crate::common::SwtpmSession;

    #[test]
    fn stirrandom() {
        let s = SwtpmSession::new();
        let entropy_file = s.write_tmp_file("entropy.bin", &[0xAB; 32]);
        s.cmd("stirrandom")
            .arg("-i")
            .arg(&entropy_file)
            .assert()
            .success();
    }
}
