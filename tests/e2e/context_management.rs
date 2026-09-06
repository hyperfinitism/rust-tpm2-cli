// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for context management.

mod context_roundtrip {
    use crate::common::SwtpmSession;

    #[test]
    fn e2e_contextsave_and_contextload_roundtrip() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");

        // Save the context to a file.
        let saved = s.tmp().path().join("saved.json");
        s.cmd("contextsave")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-o")
            .arg(&saved)
            .assert()
            .success();
        assert!(std::fs::metadata(&saved).unwrap().len() > 0);

        // Flush the object so the handle is freed.
        s.flush_transient();

        // Reload the context from the saved file.
        let restored = s.tmp().path().join("restored.json");
        s.cmd("contextload")
            .arg("-c")
            .arg(&saved)
            .arg("-o")
            .arg(&restored)
            .assert()
            .success();
        assert!(std::fs::metadata(&restored).unwrap().len() > 0);
    }
}
