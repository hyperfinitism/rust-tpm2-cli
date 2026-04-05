// SPDX-License-Identifier: Apache-2.0
//! Session & policy tests covering all policy subcommands:
//! startauthsession, sessionconfig, createpolicy, policyrestart,
//! policyauthvalue, policyauthorize, policyauthorizenv, policycommandcode,
//! policycountertimer, policycphash, policyduplicationselect, policylocality,
//! policynamehash, policynv, policynvwritten, policyor, policypassword,
//! policypcr, policysecret, policysigned, policytemplate.

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

// ════════════════════════════════════════════════════════════════════
// policycphash
// ════════════════════════════════════════════════════════════════════

#[test]
fn policycphash_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    // Use a 32-byte digest as cpHash.
    let cphash = s.write_tmp_file("cphash.bin", &[0xAAu8; 32]);
    let policy_file = s.tmp().path().join("cphash_policy.bin");
    s.cmd("policycphash")
        .arg("-S")
        .arg(&trial_ctx)
        .arg("--cphash")
        .arg(&cphash)
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

// ════════════════════════════════════════════════════════════════════
// policynamehash
// ════════════════════════════════════════════════════════════════════

#[test]
fn policynamehash_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    // Use a 32-byte digest as nameHash.
    let namehash = s.write_tmp_file("namehash.bin", &[0xBBu8; 32]);
    let policy_file = s.tmp().path().join("namehash_policy.bin");
    s.cmd("policynamehash")
        .arg("-S")
        .arg(&trial_ctx)
        .arg("--namehash")
        .arg(&namehash)
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

// ════════════════════════════════════════════════════════════════════
// policytemplate
// ════════════════════════════════════════════════════════════════════

#[test]
fn policytemplate_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    // Use a 32-byte digest as templateHash.
    let template_hash = s.write_tmp_file("template_hash.bin", &[0xCCu8; 32]);
    let policy_file = s.tmp().path().join("template_policy.bin");
    s.cmd("policytemplate")
        .arg("-S")
        .arg(&trial_ctx)
        .arg("--template-hash")
        .arg(&template_hash)
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

// ════════════════════════════════════════════════════════════════════
// policyduplicationselect
// ════════════════════════════════════════════════════════════════════

#[test]
fn policyduplicationselect_trial() {
    let s = SwtpmSession::new();
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    // In trial mode the TPM computes the policy hash from the names
    // without verifying they refer to real objects.
    // TPM name format: 2-byte algorithm ID (00 0B = SHA-256) + 32-byte hash.
    let mut obj_name = vec![0x00, 0x0B];
    obj_name.extend_from_slice(&[0x11u8; 32]);
    let obj_name_file = s.write_tmp_file("obj_name.bin", &obj_name);

    let mut parent_name = vec![0x00, 0x0B];
    parent_name.extend_from_slice(&[0x22u8; 32]);
    let parent_name_file = s.write_tmp_file("parent_name.bin", &parent_name);

    let policy_file = s.tmp().path().join("dupsel_policy.bin");
    s.cmd("policyduplicationselect")
        .arg("-S")
        .arg(&trial_ctx)
        .arg("-n")
        .arg(&obj_name_file)
        .arg("-N")
        .arg(&parent_name_file)
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}

// ════════════════════════════════════════════════════════════════════
// policynv
// ════════════════════════════════════════════════════════════════════

#[test]
fn policynv_eq_trial() {
    let s = SwtpmSession::new();

    // Define NV index with known value.
    let nv_idx = "0x01000050";
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "8", "-a", "ownerwrite|ownerread", nv_idx])
        .assert()
        .success();

    let data = s.write_tmp_file("nv_data.bin", &[0x42u8; 8]);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(nv_idx)
        .assert()
        .success();

    // Trial session: policynv with eq succeeds when values match.
    let trial = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial)
        .args(["-g", "sha256"])
        .assert()
        .success();

    s.cmd("policynv")
        .arg("-S")
        .arg(&trial)
        .args(["-i", nv_idx, "-C", "o"])
        .args([
            "--operand-b",
            "4242424242424242",
            "--offset",
            "0",
            "--operation",
            "eq",
        ])
        .assert()
        .success();

    let _ = s.cmd("nvundefine").args(["-C", "o", nv_idx]).ok();
}

#[test]
fn policynv_neq_fails_when_equal() {
    let s = SwtpmSession::new();

    let nv_idx = "0x01000051";
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "8", "-a", "ownerwrite|ownerread", nv_idx])
        .assert()
        .success();

    let data = s.write_tmp_file("nv_data.bin", &[0x42u8; 8]);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(nv_idx)
        .assert()
        .success();

    // Policy session: policynv with "neq" should fail
    // because the NV contents are equal to operand-b.
    let policy_session = s.tmp().path().join("policy_session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&policy_session)
        .args(["--policy-session", "-g", "sha256"])
        .assert()
        .success();

    s.cmd("policynv")
        .arg("-S")
        .arg(&policy_session)
        .args(["-i", nv_idx, "-C", "o"])
        .args([
            "--operand-b",
            "4242424242424242",
            "--offset",
            "0",
            "--operation",
            "neq",
        ])
        .assert()
        .failure();

    let _ = s.cmd("nvundefine").args(["-C", "o", nv_idx]).ok();
}

#[test]
fn policynv_ult_unsigned_less_than() {
    let s = SwtpmSession::new();

    let nv_idx = "0x01000052";
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "8", "-a", "ownerwrite|ownerread", nv_idx])
        .assert()
        .success();

    // Write value 0x0000000000000005.
    let data = s.write_tmp_file("nv_data.bin", &[0, 0, 0, 0, 0, 0, 0, 5]);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(nv_idx)
        .assert()
        .success();

    // Trial: policynv with "ult" — NV(5) < operand(10) → should succeed.
    let trial = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial)
        .args(["-g", "sha256"])
        .assert()
        .success();

    s.cmd("policynv")
        .arg("-S")
        .arg(&trial)
        .args(["-i", nv_idx, "-C", "o"])
        .args([
            "--operand-b",
            "000000000000000A",
            "--offset",
            "0",
            "--operation",
            "ult",
        ])
        .assert()
        .success();

    let _ = s.cmd("nvundefine").args(["-C", "o", nv_idx]).ok();
}

#[test]
fn policynv_ult_fails_when_greater() {
    let s = SwtpmSession::new();

    let nv_idx = "0x01000053";
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "8", "-a", "ownerwrite|ownerread", nv_idx])
        .assert()
        .success();

    // Write value 0x0000000000000010 (16).
    let data = s.write_tmp_file("nv_data.bin", &[0, 0, 0, 0, 0, 0, 0, 0x10]);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(nv_idx)
        .assert()
        .success();

    // Policy session: policynv with "ult" — NV(16) < operand(5) → should fail.
    let session = s.tmp().path().join("session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&session)
        .args(["--policy-session", "-g", "sha256"])
        .assert()
        .success();

    s.cmd("policynv")
        .arg("-S")
        .arg(&session)
        .args(["-i", nv_idx, "-C", "o"])
        .args([
            "--operand-b",
            "0000000000000005",
            "--offset",
            "0",
            "--operation",
            "ult",
        ])
        .assert()
        .failure();

    let _ = s.cmd("nvundefine").args(["-C", "o", nv_idx]).ok();
}

// ════════════════════════════════════════════════════════════════════
// policyauthorizenv
// ════════════════════════════════════════════════════════════════════

#[test]
fn policyauthorizenv_trial() {
    let s = SwtpmSession::new();

    // Step 1: compute a trial policy (policyauthvalue) to store in NV.
    let trial1 = s.tmp().path().join("trial1.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial1)
        .args(["-g", "sha256"])
        .assert()
        .success();

    let stored_policy = s.tmp().path().join("stored_policy.bin");
    s.cmd("policyauthvalue")
        .arg("-S")
        .arg(&trial1)
        .arg("-L")
        .arg(&stored_policy)
        .assert()
        .success();

    let policy_bytes = std::fs::read(&stored_policy).unwrap();
    s.flush_sessions();

    // Step 2: define NV index and write the policy digest as a marshaled
    // TPMT_HA (2-byte big-endian hashAlg + digest). PolicyAuthorizeNV
    // reads the NV data as TPMT_HA and checks that its hashAlg matches
    // the policy session's hash algorithm.
    let nv_idx = "0x01000070";
    let mut tpmt_ha = Vec::with_capacity(2 + policy_bytes.len());
    tpmt_ha.extend_from_slice(&0x000Bu16.to_be_bytes()); // TPM2_ALG_SHA256
    tpmt_ha.extend_from_slice(&policy_bytes);
    let nv_data = s.write_tmp_file("nv_policy.bin", &tpmt_ha);

    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            &tpmt_ha.len().to_string(),
            "-a",
            "ownerwrite|ownerread",
            nv_idx,
        ])
        .assert()
        .success();

    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&nv_data)
        .arg(nv_idx)
        .assert()
        .success();

    // Step 3: start a policy session, replay the approved policy so that
    // policyDigest matches the NV data, then call policyauthorizenv.
    let policy_session = s.tmp().path().join("policy_session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&policy_session)
        .args(["--policy-session", "-g", "sha256"])
        .assert()
        .success();

    s.cmd("policyauthvalue")
        .arg("-S")
        .arg(&policy_session)
        .assert()
        .success();

    s.cmd("policyauthorizenv")
        .arg("-S")
        .arg(&policy_session)
        .args(["-i", nv_idx, "-C", "o"])
        .assert()
        .success();

    let _ = s.cmd("nvundefine").args(["-C", "o", nv_idx]).ok();
}

// ════════════════════════════════════════════════════════════════════
// policyauthorize
// ════════════════════════════════════════════════════════════════════

#[test]
fn policyauthorize_with_signed_policy() {
    let s = SwtpmSession::new();

    // Step 1: create a signing key for policy authorization.
    let primary = s.create_primary_rsa("primary");
    let (signing_key, signing_pub, _) =
        s.create_and_load_signing_key(&primary, "rsa", "auth_signer");

    // Step 2: compute a trial policy to be authorized.
    let trial1 = s.tmp().path().join("trial1.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial1)
        .args(["-g", "sha256"])
        .assert()
        .success();

    let approved_policy = s.tmp().path().join("approved_policy.bin");
    s.cmd("policypassword")
        .arg("-S")
        .arg(&trial1)
        .arg("-L")
        .arg(&approved_policy)
        .assert()
        .success();
    s.flush_sessions();

    // Step 3: hash the approved policy digest for signing.
    let policy_hash = s.tmp().path().join("policy_hash.bin");
    let hash_ticket = s.tmp().path().join("hash_ticket.bin");
    s.cmd("hash")
        .arg("-g")
        .arg("sha256")
        .arg("-C")
        .arg("o")
        .arg("-o")
        .arg(&policy_hash)
        .arg("-t")
        .arg(&hash_ticket)
        .arg(&approved_policy)
        .assert()
        .success();

    // Step 4: sign the policy hash.
    let signature = s.tmp().path().join("policy_sig.bin");
    s.cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&signing_key))
        .arg("-g")
        .arg("sha256")
        .arg("-s")
        .arg("rsassa")
        .arg("-o")
        .arg(&signature)
        .arg("-d")
        .arg(&policy_hash)
        .assert()
        .success();

    // Step 5: verify the signature to get a verification ticket.
    let verify_ticket = s.tmp().path().join("verify_ticket.bin");
    s.cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&signing_key))
        .arg("-s")
        .arg(&signature)
        .arg("-t")
        .arg(&verify_ticket)
        .arg("-d")
        .arg(&policy_hash)
        .assert()
        .success();

    // Step 6: get the signing key name via loadexternal.
    let key_name = s.tmp().path().join("signer_name.bin");
    let ext_ctx = s.tmp().path().join("ext_signer.ctx");
    s.cmd("loadexternal")
        .arg("-u")
        .arg(&signing_pub)
        .arg("-c")
        .arg(&ext_ctx)
        .arg("-n")
        .arg(&key_name)
        .assert()
        .success();

    // Step 7: start a policy session and call policyauthorize.
    // PolicyAuthorize requires that policyDigest == approvedPolicy,
    // so we must replay the approved policy (policypassword) on the
    // policy session before calling policyauthorize.
    let policy_session = s.tmp().path().join("pa_session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&policy_session)
        .args(["--policy-session", "-g", "sha256"])
        .assert()
        .success();

    s.cmd("policypassword")
        .arg("-S")
        .arg(&policy_session)
        .assert()
        .success();

    s.cmd("policyauthorize")
        .arg("-S")
        .arg(&policy_session)
        .arg("-i")
        .arg(&approved_policy)
        .arg("-n")
        .arg(&key_name)
        .arg("-t")
        .arg(&verify_ticket)
        .assert()
        .success();
}

// ════════════════════════════════════════════════════════════════════
// policysigned
// ════════════════════════════════════════════════════════════════════

#[test]
fn policysigned_trial() {
    let s = SwtpmSession::new();

    // Create a signing key.
    let primary = s.create_primary_rsa("primary");
    let (signing_key, _, _) = s.create_and_load_signing_key(&primary, "rsa", "signer");

    // In trial mode, the TPM does not verify the signature — it only
    // updates the policy digest. We still need a structurally valid
    // TPMT_SIGNATURE. Sign some dummy data to obtain one.
    let dummy_data = s.write_tmp_file("dummy.bin", &[0u8; 32]);
    let signature = s.tmp().path().join("sig.bin");
    s.cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&signing_key))
        .arg("-g")
        .arg("sha256")
        .arg("-s")
        .arg("rsassa")
        .arg("-o")
        .arg(&signature)
        .arg("-d")
        .arg(&dummy_data)
        .assert()
        .success();

    // Start trial session and call policysigned.
    let trial_ctx = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial_ctx)
        .args(["-g", "sha256"])
        .assert()
        .success();

    let policy_file = s.tmp().path().join("signed_policy.bin");
    s.cmd("policysigned")
        .arg("-S")
        .arg(&trial_ctx)
        .arg("-c")
        .arg(SwtpmSession::file_ref(&signing_key))
        .arg("-s")
        .arg(&signature)
        .arg("-L")
        .arg(&policy_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&policy_file).unwrap().len() > 0);
}
