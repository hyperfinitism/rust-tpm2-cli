// SPDX-License-Identifier: Apache-2.0

//! Integration tests for utilities that compose TPM commands to create
//! authorization policies.

mod createpolicy {
    use crate::common::SwtpmSession;

    #[test]
    fn createpolicy_pcr() {
        let s = SwtpmSession::new();
        let policy_file = s.tmp().path().join("created_policy.bin");
        s.cmd("createpolicy")
            .args(["-g", "sha256", "--policy-pcr", "-l", "sha256:0,1,2", "-L"])
            .arg(&policy_file)
            .assert()
            .success();
        assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
    }
}
