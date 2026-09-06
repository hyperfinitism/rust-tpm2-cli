// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 31 — Non-Volatile Storage.

use crate::common::SwtpmSession;
use std::path::Path;

fn define(s: &SwtpmSession, handle: &str, size: &str, attributes: &str) {
    s.cmd("nvdefine")
        .arg(handle)
        .args(["-s", size, "-a", attributes])
        .assert()
        .success();
}

fn read(s: &SwtpmSession, handle: &str, output: &Path) -> Vec<u8> {
    s.cmd("nvread")
        .arg(handle)
        .arg("-o")
        .arg(output)
        .assert()
        .success();
    std::fs::read(output).unwrap()
}

mod nvcertify {
    use super::*;

    #[test]
    fn nvcertify_caps_implicit_size_to_the_tpm_limit() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let (ak_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "ak");
        define(&s, "0x01000001", "2048", "ownerwrite|ownerread");
        let input = s.write_tmp_file("nv-data.bin", b"initialized");
        s.cmd("nvwrite")
            .arg("0x01000001")
            .arg("-i")
            .arg(input)
            .assert()
            .success();

        let attest = s.tmp().path().join("nv-attest.bin");
        let signature = s.tmp().path().join("nv-signature.bin");
        s.cmd("nvcertify")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&ak_ctx))
            .args(["-i", "0x01000001", "-o"])
            .arg(&attest)
            .arg("--signature")
            .arg(&signature)
            .assert()
            .success();
        assert!(std::fs::metadata(attest).unwrap().len() > 0);
        assert!(std::fs::metadata(signature).unwrap().len() > 0);
    }
}

mod nvchangeauth {
    use super::*;

    #[test]
    fn nvchangeauth_changes_authorization_with_an_admin_policy() {
        let s = SwtpmSession::new();
        let trial = s.tmp().path().join("nv-change-auth-trial.ctx");
        let policy = s.tmp().path().join("nv-change-auth.policy");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&trial)
            .assert()
            .success();
        s.cmd("policycommandcode")
            .arg("-S")
            .arg(&trial)
            .arg("0x13b")
            .arg("-L")
            .arg(&policy)
            .assert()
            .success();
        s.cmd("nvdefine")
            .args(["0x01000002", "-s", "8", "-a", "authread|ownerwrite"])
            .arg("-L")
            .arg(&policy)
            .assert()
            .success();

        let session = s.tmp().path().join("nv-change-auth.ctx");
        s.cmd("startauthsession")
            .args(["--policy-session", "-S"])
            .arg(&session)
            .assert()
            .success();
        s.cmd("policycommandcode")
            .arg("-S")
            .arg(&session)
            .arg("0x13b")
            .assert()
            .success();
        s.cmd("nvchangeauth")
            .args(["0x01000002", "-r", "new-auth", "--policy-session"])
            .arg(&session)
            .assert()
            .success();
    }

    #[test]
    fn nvchangeauth_requires_a_policy_session() {
        let s = SwtpmSession::new();
        s.cmd("nvchangeauth")
            .args(["0x01000002", "-r", "new-auth"])
            .assert()
            .failure();
    }
}

mod nvdefine {
    use super::*;

    #[test]
    fn nvdefine_creates_an_index_and_rejects_a_duplicate() {
        let s = SwtpmSession::new();
        define(&s, "0x01000003", "32", "ownerwrite|ownerread");
        s.cmd("nvdefine")
            .args(["0x01000003", "-s", "32", "-a", "ownerwrite|ownerread"])
            .assert()
            .failure();
    }
}

mod nvextend {
    use super::*;

    #[test]
    fn nvextend_accumulates_data() {
        let s = SwtpmSession::new();
        define(&s, "0x01000004", "32", "nt=extend|ownerwrite|ownerread");
        let first = s.write_tmp_file("first.bin", b"first event");
        let second = s.write_tmp_file("second.bin", b"second event");
        s.cmd("nvextend")
            .args(["0x01000004", "-i"])
            .arg(&first)
            .assert()
            .success();
        let after_first = read(&s, "0x01000004", &s.tmp().path().join("first-value.bin"));
        s.cmd("nvextend")
            .args(["0x01000004", "-i"])
            .arg(&second)
            .assert()
            .success();
        let after_second = read(&s, "0x01000004", &s.tmp().path().join("second-value.bin"));
        assert_ne!(after_first, after_second);
    }
}

mod nvglobalwritelock {
    use super::*;

    #[test]
    fn nvglobalwritelock_prevents_writes_to_global_lock_indices() {
        let s = SwtpmSession::new();
        define(&s, "0x01000005", "8", "ownerwrite|ownerread|globallock");
        s.cmd("nvglobalwritelock").assert().success();
        let input = s.write_tmp_file("locked.bin", b"locked");
        s.cmd("nvwrite")
            .arg("0x01000005")
            .arg("-i")
            .arg(input)
            .assert()
            .failure();
    }
}

mod nvincrement {
    use super::*;

    #[test]
    fn nvincrement_is_monotonic() {
        let s = SwtpmSession::new();
        define(&s, "0x01000006", "8", "nt=counter|ownerwrite|ownerread");
        s.cmd("nvincrement").arg("0x01000006").assert().success();
        let first = read(&s, "0x01000006", &s.tmp().path().join("counter-1.bin"));
        s.cmd("nvincrement").arg("0x01000006").assert().success();
        let second = read(&s, "0x01000006", &s.tmp().path().join("counter-2.bin"));
        let first = u64::from_be_bytes(first.try_into().unwrap());
        let second = u64::from_be_bytes(second.try_into().unwrap());
        assert_eq!(second, first + 1);
    }
}

mod nvread {
    use super::*;

    #[test]
    fn nvread_reads_the_full_index_when_size_is_omitted() {
        let s = SwtpmSession::new();
        define(&s, "0x01000007", "8", "ownerwrite|ownerread");
        let input = s.write_tmp_file("input.bin", b"12345678");
        s.cmd("nvwrite")
            .arg("0x01000007")
            .arg("-i")
            .arg(input)
            .assert()
            .success();
        let output = read(&s, "0x01000007", &s.tmp().path().join("output.bin"));
        assert_eq!(output, b"12345678");
    }
}

mod nvreadlock {
    use super::*;

    #[test]
    fn nvreadlock_prevents_subsequent_reads() {
        let s = SwtpmSession::new();
        define(&s, "0x01000008", "8", "ownerwrite|ownerread|read_stclear");
        s.cmd("nvreadlock").arg("0x01000008").assert().success();
        s.cmd("nvread").arg("0x01000008").assert().failure();
    }
}

mod nvreadpublic {
    use super::*;

    #[test]
    fn nvreadpublic_reads_defined_index_metadata() {
        let s = SwtpmSession::new();
        define(&s, "0x01000009", "8", "ownerwrite|ownerread");
        s.cmd("nvreadpublic").arg("0x01000009").assert().success();
    }
}

mod nvsetbits {
    use super::*;

    #[test]
    fn nvsetbits_accumulates_bits() {
        let s = SwtpmSession::new();
        define(&s, "0x0100000a", "8", "nt=bits|ownerwrite|ownerread");
        s.cmd("nvsetbits")
            .args(["0x0100000a", "-i", "0x1"])
            .assert()
            .success();
        s.cmd("nvsetbits")
            .args(["0x0100000a", "-i", "0x10"])
            .assert()
            .success();
        let value = read(&s, "0x0100000a", &s.tmp().path().join("bits.bin"));
        assert_eq!(u64::from_be_bytes(value.try_into().unwrap()), 0x11);
    }
}

mod nvundefine {
    use super::*;

    #[test]
    fn nvundefine_removes_an_index() {
        let s = SwtpmSession::new();
        define(&s, "0x0100000b", "8", "ownerwrite|ownerread");
        s.cmd("nvundefine").arg("0x0100000b").assert().success();
        s.cmd("nvreadpublic").arg("0x0100000b").assert().failure();
    }
}

mod nvundefinespacespecial {
    use super::*;

    #[test]
    fn nvundefinespacespecial_removes_a_policydelete_index() {
        let s = SwtpmSession::new();
        let trial = s.tmp().path().join("nv-undefine-trial.ctx");
        let policy = s.tmp().path().join("nv-undefine.policy");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&trial)
            .assert()
            .success();
        s.cmd("policycommandcode")
            .arg("-S")
            .arg(&trial)
            .arg("0x11f")
            .arg("-L")
            .arg(&policy)
            .assert()
            .success();
        s.cmd("nvdefine")
            .args([
                "0x0100000f",
                "-C",
                "p",
                "-s",
                "8",
                "-a",
                "ppread|policywrite|policydelete|platformcreate",
            ])
            .arg("-L")
            .arg(&policy)
            .assert()
            .success();

        let session = s.tmp().path().join("nv-undefine.ctx");
        s.cmd("startauthsession")
            .args(["--policy-session", "-S"])
            .arg(&session)
            .assert()
            .success();
        s.cmd("policycommandcode")
            .arg("-S")
            .arg(&session)
            .arg("0x11f")
            .assert()
            .success();
        s.cmd("nvundefinespacespecial")
            .arg("0x0100000f")
            .arg("--policy-session")
            .arg(&session)
            .assert()
            .success();
        s.cmd("nvreadpublic").arg("0x0100000f").assert().failure();
    }
}

mod nvwrite {
    use super::*;

    #[test]
    fn nvwrite_overwrites_index_data() {
        let s = SwtpmSession::new();
        define(&s, "0x0100000c", "8", "ownerwrite|ownerread");
        let first = s.write_tmp_file("first.bin", b"12345678");
        let second = s.write_tmp_file("second.bin", b"abcdefgh");
        for input in [&first, &second] {
            s.cmd("nvwrite")
                .arg("0x0100000c")
                .arg("-i")
                .arg(input)
                .assert()
                .success();
        }
        let output = read(&s, "0x0100000c", &s.tmp().path().join("output.bin"));
        assert_eq!(output, b"abcdefgh");
    }
}

mod nvwritelock {
    use super::*;

    #[test]
    fn nvwritelock_prevents_subsequent_writes() {
        let s = SwtpmSession::new();
        define(&s, "0x0100000d", "8", "ownerwrite|ownerread|writedefine");
        s.cmd("nvwritelock").arg("0x0100000d").assert().success();
        let input = s.write_tmp_file("locked.bin", b"locked");
        s.cmd("nvwrite")
            .arg("0x0100000d")
            .arg("-i")
            .arg(input)
            .assert()
            .failure();
    }
}
