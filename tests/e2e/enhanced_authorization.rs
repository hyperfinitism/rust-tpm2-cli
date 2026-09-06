// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for enhanced authorization.

mod signed_policy_authorization {
    use crate::common::SwtpmSession;

    #[test]
    fn e2e_policyauthorize_with_signed_policy() {
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
}
