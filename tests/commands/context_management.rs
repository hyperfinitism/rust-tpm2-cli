// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 28 — Context Management.

mod contextload {
    use crate::common::SwtpmSession;

    #[test]
    fn contextload_then_readpublic() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");

        // Read public from original handle.
        let pub_orig = s.tmp().path().join("pub_orig.bin");
        s.cmd("readpublic")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-o")
            .arg(&pub_orig)
            .assert()
            .success();

        // Save and reload.
        let saved = s.tmp().path().join("saved.json");
        s.cmd("contextsave")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-o")
            .arg(&saved)
            .assert()
            .success();

        s.flush_transient();

        let restored = s.tmp().path().join("restored.json");
        s.cmd("contextload")
            .arg("-c")
            .arg(&saved)
            .arg("-o")
            .arg(&restored)
            .assert()
            .success();

        // Read public from restored context — should match.
        let pub_restored = s.tmp().path().join("pub_restored.bin");
        s.cmd("readpublic")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&restored))
            .arg("-o")
            .arg(&pub_restored)
            .assert()
            .success();

        assert_eq!(
            std::fs::read(&pub_orig).unwrap(),
            std::fs::read(&pub_restored).unwrap()
        );
    }
}

mod contextsave {
    use crate::common::SwtpmSession;

    #[test]
    fn contextsave_ecc_key() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_ecc("ecc_primary");

        let saved = s.tmp().path().join("ecc_saved.json");
        s.cmd("contextsave")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-o")
            .arg(&saved)
            .assert()
            .success();
        assert!(std::fs::metadata(&saved).unwrap().len() > 0);
    }
}

mod evictcontrol {
    use crate::common::SwtpmSession;

    #[test]
    fn evictcontrol_persist_and_evict() {
        let s = SwtpmSession::new();
        let primary_ctx = s.create_primary_rsa("evict_primary");

        // Persist.
        s.cmd("evictcontrol")
            .args(["-C", "o", "-c"])
            .arg(SwtpmSession::file_ref(&primary_ctx))
            .arg("0x81000010")
            .assert()
            .success();

        // Read persistent handle.
        s.cmd("readpublic")
            .args(["-c", "hex:0x81000010"])
            .assert()
            .success();

        // Evict.
        s.cmd("evictcontrol")
            .args(["-C", "o", "-c", "hex:0x81000010", "0x81000010"])
            .assert()
            .success();
    }
}

mod flushcontext {
    use crate::common::SwtpmSession;

    #[test]
    fn flushcontext_transient() {
        let s = SwtpmSession::new();
        let _primary = s.create_primary_rsa("primary");
        s.cmd("flushcontext")
            .arg("--transient-object")
            .assert()
            .success();
    }

    #[test]
    fn flushcontext_resolves_saved_session_handle() {
        let s = SwtpmSession::new();
        let session_ctx = s.tmp().path().join("flush_session.ctx");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&session_ctx)
            .args(["--hmac-session", "-g", "sha256"])
            .assert()
            .success();

        let output = s
            .cmd("getcap")
            .arg("handles-saved-session")
            .output()
            .unwrap();
        assert!(output.status.success());
        let handles: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        let handle = handles.first().expect("saved session handle");

        s.cmd("flushcontext")
            .arg("--handle")
            .arg(handle)
            .assert()
            .success();

        s.cmd("sessionconfig")
            .arg("-S")
            .arg(&session_ctx)
            .arg("--enable-audit")
            .assert()
            .failure();
    }
}
