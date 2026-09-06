// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 17 — Hash/HMAC/Event/Signature Sequences.

mod hashsequencestart {
    use crate::common::SwtpmSession;

    #[test]
    fn hashsequencestart_saves_a_sequence_context() {
        let s = SwtpmSession::new();
        let context = s.tmp().path().join("hash-sequence.ctx");
        s.cmd("hashsequencestart")
            .args(["-g", "sha256", "-o"])
            .arg(&context)
            .assert()
            .success();
        assert!(std::fs::metadata(context).unwrap().len() > 0);
    }
}

mod hmacsequencestart {
    use crate::common::SwtpmSession;

    #[test]
    fn hmacsequencestart_saves_a_sequence_context() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let private = s.tmp().path().join("hmac.priv");
        let public = s.tmp().path().join("hmac.pub");
        let key = s.tmp().path().join("hmac.ctx");
        s.cmd("create")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary))
            .args(["-G", "hmac", "-r"])
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

        let context = s.tmp().path().join("hmac-sequence.ctx");
        s.cmd("hmacsequencestart")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .arg("-o")
            .arg(&context)
            .assert()
            .success();
        assert!(std::fs::metadata(context).unwrap().len() > 0);
    }
}

mod sequencecomplete {
    use crate::common::SwtpmSession;

    #[test]
    fn sequencecomplete_finishes_a_hash_sequence() {
        let s = SwtpmSession::new();
        let context = s.tmp().path().join("sequence.ctx");
        let output = s.tmp().path().join("digest.bin");
        s.cmd("hashsequencestart")
            .args(["-g", "sha256", "-o"])
            .arg(&context)
            .assert()
            .success();
        s.cmd("sequencecomplete")
            .arg("-c")
            .arg(&context)
            .arg("-o")
            .arg(&output)
            .assert()
            .success();
        assert_eq!(std::fs::metadata(output).unwrap().len(), 32);
    }
}

mod sequenceupdate {
    use crate::common::SwtpmSession;

    #[test]
    fn sequenceupdate_updates_and_resaves_the_context() {
        let s = SwtpmSession::new();
        let context = s.tmp().path().join("sequence.ctx");
        let input = s.write_tmp_file("input.bin", b"sequence data");
        s.cmd("hashsequencestart")
            .args(["-g", "sha256", "-o"])
            .arg(&context)
            .assert()
            .success();
        s.cmd("sequenceupdate")
            .arg("-c")
            .arg(&context)
            .arg("-i")
            .arg(input)
            .assert()
            .success();
        assert!(std::fs::metadata(context).unwrap().len() > 0);
    }
}
