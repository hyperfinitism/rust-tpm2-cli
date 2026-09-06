// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 23 — Enhanced Authorization (EA) Commands.

use crate::common::SwtpmSession;

mod policyauthorizenv {
    use super::*;

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
}

mod policyauthvalue {
    use super::*;

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
}

mod policycommandcode {
    use super::*;

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
}

mod policycountertimer {
    use super::*;

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
}

mod policycphash {
    use super::*;

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
}

mod policyduplicationselect {
    use super::*;

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
}

mod policylocality {
    use super::*;

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
}

mod policynamehash {
    use super::*;

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
}

mod policynv {
    use super::*;

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
}

mod policynvwritten {
    use super::*;

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
}

mod policyor {
    use super::*;

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
}

mod policypassword {
    use super::*;

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
}

mod policypcr {
    use super::*;

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
}

mod policysecret {
    use super::*;

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
}

mod policysigned {
    use super::*;

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
}

mod policytemplate {
    use super::*;

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
}

mod policygetdigest {
    use super::*;

    #[test]
    fn policygetdigest_outputs_the_current_policy_digest() {
        let s = SwtpmSession::new();
        let session = s.tmp().path().join("policy.ctx");
        let digest = s.tmp().path().join("policy.bin");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&session)
            .args(["-g", "sha256"])
            .assert()
            .success();
        s.cmd("policygetdigest")
            .arg("-S")
            .arg(&session)
            .arg("-o")
            .arg(&digest)
            .assert()
            .success();
        assert_eq!(std::fs::metadata(digest).unwrap().len(), 32);
    }
}

mod policyphysicalpresence {
    use super::*;

    #[test]
    fn policyphysicalpresence_extends_a_trial_policy() {
        let s = SwtpmSession::new();
        let session = s.tmp().path().join("policy.ctx");
        let digest = s.tmp().path().join("policy.bin");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&session)
            .args(["-g", "sha256"])
            .assert()
            .success();
        s.cmd("policyphysicalpresence")
            .arg("-S")
            .arg(&session)
            .arg("-L")
            .arg(&digest)
            .assert()
            .success();
        assert_eq!(std::fs::metadata(digest).unwrap().len(), 32);
    }
}

mod policyauthorize {
    use crate::common::SwtpmSession;

    #[test]
    fn policyauthorize_accepts_a_verified_policy() {
        let s = SwtpmSession::new();
        let parent = s.create_primary_rsa("primary");
        let (signing_key, _, _) = s.create_and_load_signing_key(&parent, "rsa", "authorizer");
        let key_name = s.read_object_name(&signing_key, "authorizer.name");

        let trial = s.tmp().path().join("trial.ctx");
        let approved_policy = s.tmp().path().join("approved-policy.bin");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&trial)
            .assert()
            .success();
        s.cmd("policypassword")
            .arg("-S")
            .arg(&trial)
            .arg("-L")
            .arg(&approved_policy)
            .assert()
            .success();

        let policy_hash = s.tmp().path().join("policy-hash.bin");
        s.cmd("hash")
            .args(["-g", "sha256", "-o"])
            .arg(&policy_hash)
            .arg(&approved_policy)
            .assert()
            .success();
        let signature = s.tmp().path().join("policy-signature.bin");
        s.cmd("sign")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&signing_key))
            .args(["-g", "sha256", "-s", "rsassa", "-d"])
            .arg(&policy_hash)
            .arg("-o")
            .arg(&signature)
            .assert()
            .success();
        let ticket = s.tmp().path().join("verification-ticket.bin");
        s.cmd("verifysignature")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&signing_key))
            .arg("-d")
            .arg(&policy_hash)
            .arg("-s")
            .arg(&signature)
            .arg("-t")
            .arg(&ticket)
            .assert()
            .success();

        let policy_session = s.tmp().path().join("policy.ctx");
        s.cmd("startauthsession")
            .args(["--policy-session", "-S"])
            .arg(&policy_session)
            .assert()
            .success();
        s.cmd("policypassword")
            .arg("-S")
            .arg(&policy_session)
            .assert()
            .success();
        let authorized_policy = s.tmp().path().join("authorized-policy.bin");
        s.cmd("policyauthorize")
            .arg("-S")
            .arg(&policy_session)
            .arg("-i")
            .arg(&approved_policy)
            .arg("-n")
            .arg(&key_name)
            .arg("-t")
            .arg(&ticket)
            .arg("-L")
            .arg(&authorized_policy)
            .assert()
            .success();
        assert_eq!(std::fs::metadata(authorized_policy).unwrap().len(), 32);
    }
}

mod policyticket {
    use crate::common::SwtpmSession;

    #[test]
    fn policyticket_rejects_a_null_policysecret_ticket() {
        let s = SwtpmSession::new();
        let first_session = s.tmp().path().join("first-policy.ctx");
        let ticket = s.tmp().path().join("null-ticket.bin");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&first_session)
            .assert()
            .success();
        s.cmd("policysecret")
            .args(["--object-hierarchy", "e", "-S"])
            .arg(&first_session)
            .arg("--ticket")
            .arg(&ticket)
            .assert()
            .success();

        let second_session = s.tmp().path().join("second-policy.ctx");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&second_session)
            .assert()
            .success();
        s.cmd("policyticket")
            .arg("-S")
            .arg(&second_session)
            .args(["-n", "4000000b", "-t"])
            .arg(&ticket)
            .assert()
            .failure();
    }
}
