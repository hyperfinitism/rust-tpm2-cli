// SPDX-License-Identifier: Apache-2.0

//! Integration tests for client-side TPM structure and response-code output utilities.

mod print {
    use crate::common::SwtpmSession;

    #[test]
    fn print_tpms_context() {
        let s = SwtpmSession::new();
        let primary_ctx = s.create_primary_rsa("primary");
        s.cmd("print")
            .args(["-t", "TPMS_CONTEXT"])
            .arg(&primary_ctx)
            .assert()
            .success();
    }

    #[test]
    fn print_tpmt_public() {
        let s = SwtpmSession::new();
        let primary_ctx = s.create_primary_rsa("primary");
        let pub_file = s.tmp().path().join("pub.bin");
        s.cmd("readpublic")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&primary_ctx))
            .arg("-o")
            .arg(&pub_file)
            .assert()
            .success();
        s.cmd("print")
            .args(["-t", "TPMT_PUBLIC"])
            .arg(&pub_file)
            .assert()
            .success();
    }
}

mod rcdecode {
    use crate::common::SwtpmSession;

    #[test]
    fn rcdecode_initialize() {
        let s = SwtpmSession::new();
        s.cmd("rcdecode").arg("0x100").assert().success();
    }

    #[test]
    fn rcdecode_success() {
        let s = SwtpmSession::new();
        s.cmd("rcdecode").arg("0x000").assert().success();
    }
}
