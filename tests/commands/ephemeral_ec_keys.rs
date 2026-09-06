// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 19 — Ephemeral EC Keys.

mod ecephemeral {
    use crate::common::SwtpmSession;

    #[test]
    fn ecephemeral_ecc256() {
        let s = SwtpmSession::new();
        let q = s.tmp().path().join("eph_q.bin");
        let counter = s.tmp().path().join("eph_counter.bin");
        s.cmd("ecephemeral")
            .arg("ecc256")
            .arg("-u")
            .arg(&q)
            .arg("-t")
            .arg(&counter)
            .assert()
            .success();
        assert!(std::fs::metadata(&q).unwrap().len() > 0);
        assert!(std::fs::metadata(&counter).unwrap().len() > 0);
    }

    #[test]
    fn ecephemeral_ecc384() {
        let s = SwtpmSession::new();
        let q = s.tmp().path().join("eph384_q.bin");
        let counter = s.tmp().path().join("eph384_counter.bin");
        s.cmd("ecephemeral")
            .arg("ecc384")
            .arg("-u")
            .arg(&q)
            .arg("-t")
            .arg(&counter)
            .assert()
            .success();
        assert!(std::fs::metadata(&q).unwrap().len() > 0);
    }
}

mod commit {
    use crate::common::{SwtpmSession, ecdaa_public};

    #[test]
    fn commit_outputs_an_ephemeral_point_and_counter() {
        let s = SwtpmSession::new();
        let key = s.create_primary_from_public("ecdaa-key", &ecdaa_public());
        let e = s.tmp().path().join("e.bin");
        let counter = s.tmp().path().join("counter.bin");
        s.cmd("commit")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .arg("--public")
            .arg(&e)
            .arg("--counter")
            .arg(&counter)
            .assert()
            .success();

        assert_eq!(std::fs::metadata(e).unwrap().len(), 64);
        assert_eq!(std::fs::metadata(counter).unwrap().len(), 2);
    }
}

mod zgen2phase {
    use crate::common::{SwtpmSession, ecdh_public};

    #[test]
    fn zgen2phase_outputs_two_shared_points() {
        let s = SwtpmSession::new();
        let key = s.create_primary_from_public("two-phase-key", &ecdh_public());
        let static_public = s.tmp().path().join("static.bin");
        s.cmd("ecdhkeygen")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .arg("-u")
            .arg(&static_public)
            .arg("-o")
            .arg(s.tmp().path().join("unused-z.bin"))
            .assert()
            .success();

        let ephemeral_public = s.tmp().path().join("ephemeral.bin");
        let counter_file = s.tmp().path().join("ephemeral-counter.bin");
        s.cmd("ecephemeral")
            .arg("ecc256")
            .arg("-u")
            .arg(&ephemeral_public)
            .arg("-t")
            .arg(&counter_file)
            .assert()
            .success();
        let bytes: [u8; 2] = s.read_file(&counter_file).try_into().unwrap();
        let counter = u16::from_be_bytes(bytes).to_string();

        let z1 = s.tmp().path().join("z1.bin");
        let z2 = s.tmp().path().join("z2.bin");
        s.cmd("zgen2phase")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .arg("--static-public")
            .arg(&static_public)
            .arg("--ephemeral-public")
            .arg(&ephemeral_public)
            .arg("--counter")
            .arg(counter)
            .arg("--output-Z1")
            .arg(&z1)
            .arg("--output-Z2")
            .arg(&z2)
            .assert()
            .success();

        assert_eq!(std::fs::metadata(z1).unwrap().len(), 64);
        assert_eq!(std::fs::metadata(z2).unwrap().len(), 64);
    }
}
