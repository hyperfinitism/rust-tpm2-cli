// SPDX-License-Identifier: Apache-2.0
//! Session & policy tests: startauthsession, sessionconfig, policyrestart,
//! policypcr, policycommandcode, policyauthvalue, policypassword, policyor,
//! policylocality, policynvwritten, createpolicy, policycountertimer, policysecret.

mod common;

use common::SwtpmSession;

#[test]
fn startauthsession_policy() {
    let s = SwtpmSession::new();
    let session_ctx = s.tmp().path().join("session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&session_ctx)
        .args(["--policy-session", "-g", "sha256"])
        .assert()
        .success();
    assert!(session_ctx.exists());
}

#[test]
fn sessionconfig_enable_disable_encrypt() {
    let s = SwtpmSession::new();
    let session_ctx = s.tmp().path().join("session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&session_ctx)
        .args(["--policy-session", "-g", "sha256"])
        .assert()
        .success();

    s.cmd("sessionconfig")
        .arg("-S")
        .arg(&session_ctx)
        .arg("--enable-encrypt")
        .assert()
        .success();

    s.cmd("sessionconfig")
        .arg("-S")
        .arg(&session_ctx)
        .arg("--disable-encrypt")
        .assert()
        .success();
}

#[test]
fn policyrestart() {
    let s = SwtpmSession::new();
    let session_ctx = s.tmp().path().join("session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&session_ctx)
        .args(["--policy-session", "-g", "sha256"])
        .assert()
        .success();
    s.cmd("policyrestart")
        .arg("-S")
        .arg(&session_ctx)
        .assert()
        .success();
}

#[test]
fn policypcr_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    let policy_file = s.tmp().path().join("pcr_policy.bin");
    s.cmd("policypcr")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-l", "sha256:0,1,2", "-L"])
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

#[test]
fn policycommandcode_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    let policy_file = s.tmp().path().join("cc_policy.bin");
    s.cmd("policycommandcode")
        .arg("-S")
        .arg(&trial_ctx)
        .arg("unseal")
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

#[test]
fn policyauthvalue_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    let policy_file = s.tmp().path().join("authval_policy.bin");
    s.cmd("policyauthvalue")
        .arg("-S")
        .arg(&trial_ctx)
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

#[test]
fn policypassword_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    let policy_file = s.tmp().path().join("pw_policy.bin");
    s.cmd("policypassword")
        .arg("-S")
        .arg(&trial_ctx)
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

#[test]
fn policyor_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    let pol_a = s.write_tmp_file("pol_a.bin", &[0u8; 32]);
    let pol_b = s.write_tmp_file("pol_b.bin", &[0xABu8; 32]);
    let policy_file = s.tmp().path().join("or_policy.bin");
    s.cmd("policyor")
        .arg("-S")
        .arg(&trial_ctx)
        .arg("-l")
        .arg(&pol_a)
        .arg(&pol_b)
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

#[test]
fn policylocality_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    let policy_file = s.tmp().path().join("loc_policy.bin");
    s.cmd("policylocality")
        .arg("-S")
        .arg(&trial_ctx)
        .arg("3")
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

#[test]
fn policynvwritten_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    let policy_file = s.tmp().path().join("nvw_policy.bin");
    s.cmd("policynvwritten")
        .arg("-S")
        .arg(&trial_ctx)
        .arg("-s")
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

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

#[test]
fn policycountertimer_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    s.cmd("policycountertimer")
        .arg("-S")
        .arg(&trial_ctx)
        .args([
            "--operand-b",
            "0000000000000000",
            "--offset",
            "0",
            "--operation",
            "ult",
        ])
        .assert()
        .success();
}

#[test]
fn policysecret_with_owner() {
    let s = SwtpmSession::new();
    let session_ctx = s.tmp().path().join("ps_session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&session_ctx)
        .args(["--policy-session", "-g", "sha256"])
        .assert()
        .success();

    let policy_file = s.tmp().path().join("secret_policy.bin");
    s.cmd("policysecret")
        .args(["--object-hierarchy", "o"])
        .arg("-S")
        .arg(&session_ctx)
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

#[test]
fn startauthsession_hmac() {
    let s = SwtpmSession::new();
    let session_ctx = s.tmp().path().join("hmac_session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&session_ctx)
        .args(["--hmac-session", "-g", "sha256"])
        .assert()
        .success();
    assert!(session_ctx.exists());
}

#[test]
fn policypcr_is_deterministic() {
    let s = SwtpmSession::new();

    let trial1 = s.tmp().path().join("det1.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial1)
        .args(["-g", "sha256"])
        .assert()
        .success();
    let pol1 = s.tmp().path().join("pcr_pol1.bin");
    s.cmd("policypcr")
        .arg("-S")
        .arg(&trial1)
        .args(["-l", "sha256:0,1,2", "-L"])
        .arg(&pol1)
        .assert()
        .success();
    s.flush_sessions();

    let trial2 = s.tmp().path().join("det2.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial2)
        .args(["-g", "sha256"])
        .assert()
        .success();
    let pol2 = s.tmp().path().join("pcr_pol2.bin");
    s.cmd("policypcr")
        .arg("-S")
        .arg(&trial2)
        .args(["-l", "sha256:0,1,2", "-L"])
        .arg(&pol2)
        .assert()
        .success();

    assert_eq!(std::fs::read(&pol1).unwrap(), std::fs::read(&pol2).unwrap());
}

#[test]
fn different_pcr_selection_different_policy() {
    let s = SwtpmSession::new();

    let trial1 = s.tmp().path().join("diff1.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial1)
        .args(["-g", "sha256"])
        .assert()
        .success();
    let pol_a = s.tmp().path().join("pcr_polA.bin");
    s.cmd("policypcr")
        .arg("-S")
        .arg(&trial1)
        .args(["-l", "sha256:0", "-L"])
        .arg(&pol_a)
        .assert()
        .success();
    s.flush_sessions();

    let trial2 = s.tmp().path().join("diff2.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial2)
        .args(["-g", "sha256"])
        .assert()
        .success();
    let pol_b = s.tmp().path().join("pcr_polB.bin");
    s.cmd("policypcr")
        .arg("-S")
        .arg(&trial2)
        .args(["-l", "sha256:1", "-L"])
        .arg(&pol_b)
        .assert()
        .success();

    assert_ne!(
        std::fs::read(&pol_a).unwrap(),
        std::fs::read(&pol_b).unwrap()
    );
}
