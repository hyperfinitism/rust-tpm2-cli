// SPDX-License-Identifier: Apache-2.0
//! ECC operation tests: geteccparameters, ecephemeral, ecdhkeygen.

mod common;

use common::SwtpmSession;

#[test]
fn geteccparameters_ecc256() {
    let s = SwtpmSession::new();
    s.cmd("geteccparameters").arg("ecc256").assert().success();
}

#[test]
fn geteccparameters_ecc384() {
    let s = SwtpmSession::new();
    s.cmd("geteccparameters").arg("ecc384").assert().success();
}

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

#[test]
fn ecdhkeygen() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_ecc("ecc_primary");
    let pub_file = s.tmp().path().join("ecdh_pub.bin");
    let z_file = s.tmp().path().join("ecdh_z.bin");
    s.cmd("ecdhkeygen")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-u")
        .arg(&pub_file)
        .arg("-o")
        .arg(&z_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&pub_file).unwrap().len() > 0);
    assert!(std::fs::metadata(&z_file).unwrap().len() > 0);
}

#[test]
fn ecdhkeygen_produces_different_keys() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_ecc("ecc_primary");

    let pub1 = s.tmp().path().join("ecdh_pub1.bin");
    let z1 = s.tmp().path().join("ecdh_z1.bin");
    s.cmd("ecdhkeygen")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-u")
        .arg(&pub1)
        .arg("-o")
        .arg(&z1)
        .assert()
        .success();

    let pub2 = s.tmp().path().join("ecdh_pub2.bin");
    let z2 = s.tmp().path().join("ecdh_z2.bin");
    s.cmd("ecdhkeygen")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-u")
        .arg(&pub2)
        .arg("-o")
        .arg(&z2)
        .assert()
        .success();

    assert_ne!(std::fs::read(&pub1).unwrap(), std::fs::read(&pub2).unwrap());
}
