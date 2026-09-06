// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 13 — Duplication Commands.

mod duplicate {
    use crate::common::SwtpmSession;

    #[test]
    fn duplicate_outputs_a_private_area_and_seed() {
        let s = SwtpmSession::new();
        let original_parent = s.create_primary_rsa("original-parent");
        let new_parent = s.create_primary_rsa("new-parent");
        let (object, _, _, policy) =
            s.create_object_for_duplication(&original_parent, &new_parent, "duplicable-object");
        let duplicate = s.tmp().path().join("duplicate.priv");
        let seed = s.tmp().path().join("duplicate.seed");
        s.cmd("duplicate")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&object))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&new_parent))
            .arg("-r")
            .arg(&duplicate)
            .arg("-s")
            .arg(&seed)
            .arg("--policy-session")
            .arg(&policy)
            .assert()
            .success();
        assert!(std::fs::metadata(duplicate).unwrap().len() > 0);
        assert!(std::fs::metadata(seed).unwrap().len() > 0);
    }

    #[test]
    fn duplicate_requires_a_policy_session() {
        let s = SwtpmSession::new();
        s.cmd("duplicate")
            .args([
                "-c",
                "file:object.ctx",
                "--parent-context-null",
                "-r",
                "duplicate.priv",
                "-s",
                "duplicate.seed",
            ])
            .assert()
            .failure();
    }
}

mod import {
    use crate::common::SwtpmSession;

    #[test]
    fn import_converts_a_duplicate_for_the_new_parent() {
        let s = SwtpmSession::new();
        let original_parent = s.create_primary_rsa("original-parent");
        let new_parent = s.create_primary_rsa("new-parent");
        let (object, public, _, policy) =
            s.create_object_for_duplication(&original_parent, &new_parent, "duplicable-object");
        let duplicate = s.tmp().path().join("duplicate.priv");
        let seed = s.tmp().path().join("duplicate.seed");
        let encryption_key = s.tmp().path().join("encryption-key.bin");
        s.cmd("duplicate")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&object))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&new_parent))
            .arg("-r")
            .arg(&duplicate)
            .arg("-s")
            .arg(&seed)
            .arg("-k")
            .arg(&encryption_key)
            .arg("--policy-session")
            .arg(&policy)
            .assert()
            .success();

        let imported = s.tmp().path().join("imported.priv");
        s.cmd("import")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&new_parent))
            .arg("-u")
            .arg(&public)
            .arg("-r")
            .arg(&duplicate)
            .arg("-s")
            .arg(&seed)
            .arg("-k")
            .arg(&encryption_key)
            .arg("-o")
            .arg(&imported)
            .assert()
            .success();
        assert!(std::fs::metadata(imported).unwrap().len() > 0);
    }
}

mod rewrap {
    use crate::common::SwtpmSession;

    #[test]
    fn rewrap_moves_a_duplicate_to_another_parent() {
        let s = SwtpmSession::new();
        let original_parent = s.create_primary_rsa("original-parent");
        let old_parent = s.create_primary_rsa("old-parent");
        let new_parent = s.create_primary_rsa("new-parent");
        let (object, _, name, policy) =
            s.create_object_for_duplication(&original_parent, &old_parent, "duplicable-object");
        let duplicate = s.tmp().path().join("duplicate.priv");
        let seed = s.tmp().path().join("duplicate.seed");
        s.cmd("duplicate")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&object))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&old_parent))
            .arg("-r")
            .arg(&duplicate)
            .arg("-s")
            .arg(&seed)
            .arg("--policy-session")
            .arg(&policy)
            .assert()
            .success();

        let rewrapped = s.tmp().path().join("rewrapped.priv");
        let rewrapped_seed = s.tmp().path().join("rewrapped.seed");
        s.cmd("rewrap")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&old_parent))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&new_parent))
            .arg("-i")
            .arg(&duplicate)
            .arg("-n")
            .arg(&name)
            .arg("-s")
            .arg(&seed)
            .arg("-o")
            .arg(&rewrapped)
            .arg("--out-encrypted-seed")
            .arg(&rewrapped_seed)
            .assert()
            .success();
        assert!(std::fs::metadata(rewrapped).unwrap().len() > 0);
        assert!(std::fs::metadata(rewrapped_seed).unwrap().len() > 0);
    }
}
