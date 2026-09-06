// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for non-volatile storage.

mod nv_roundtrip {
    use crate::common::SwtpmSession;

    const NV_IDX: &str = "0x01000001";

    #[test]
    fn e2e_nvwrite_and_read_roundtrip() {
        let s = SwtpmSession::new();
        s.cmd("nvdefine")
            .args(["-C", "o", "-s", "32", "-a", "ownerwrite|ownerread", NV_IDX])
            .assert()
            .success();

        let data = b"hello world, nv storage!12345678";
        let data_file = s.write_tmp_file("nv_data.bin", data);
        s.cmd("nvwrite")
            .args(["-C", "o", "-i"])
            .arg(&data_file)
            .arg(NV_IDX)
            .assert()
            .success();

        let read_file = s.tmp().path().join("nv_read.bin");
        s.cmd("nvread")
            .args(["-C", "o", "-s", "32", "-o"])
            .arg(&read_file)
            .arg(NV_IDX)
            .assert()
            .success();

        assert_eq!(std::fs::read(&read_file).unwrap(), data);
    }
}
