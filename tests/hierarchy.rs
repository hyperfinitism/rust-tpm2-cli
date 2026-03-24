// SPDX-License-Identifier: Apache-2.0
//! Hierarchy & admin tests: clear, clearcontrol, dictionarylockout,
//! setprimarypolicy, clockrateadjust, setclock, changeeps, changepps.

mod common;

use common::SwtpmSession;

#[test]
fn dictionarylockout_clear() {
    let s = SwtpmSession::new();
    s.cmd("dictionarylockout")
        .arg("--clear-lockout")
        .assert()
        .success();
}

#[test]
fn dictionarylockout_set_params() {
    let s = SwtpmSession::new();
    s.cmd("dictionarylockout")
        .args([
            "--setup-parameters",
            "--max-tries",
            "5",
            "--recovery-time",
            "10",
            "--lockout-recovery-time",
            "10",
        ])
        .assert()
        .success();
}

#[test]
fn clear_lockout() {
    let s = SwtpmSession::new();
    s.cmd("clear").args(["-c", "l"]).assert().success();
    // Need startup after clear.
    s.cmd("startup").arg("--clear").assert().success();
}

#[test]
fn clearcontrol_disable() {
    let s = SwtpmSession::new();
    s.cmd("clearcontrol")
        .args(["-C", "p", "-s"])
        .assert()
        .success();
}

#[test]
fn setprimarypolicy() {
    let s = SwtpmSession::new();
    let policy = s.write_tmp_file("empty_policy.bin", &[0u8; 32]);
    s.cmd("setprimarypolicy")
        .args(["-C", "o", "-L"])
        .arg(&policy)
        .args(["-g", "sha256"])
        .assert()
        .success();
}

#[test]
fn clockrateadjust_medium() {
    let s = SwtpmSession::new();
    s.cmd("clockrateadjust").arg("medium").assert().success();
}

#[test]
fn clockrateadjust_faster() {
    let s = SwtpmSession::new();
    s.cmd("clockrateadjust").arg("faster").assert().success();
}

#[test]
fn setclock() {
    let s = SwtpmSession::new();
    s.cmd("setclock").arg("100000").assert().success();
}

#[test]
fn changeeps() {
    let s = SwtpmSession::new();
    s.cmd("changeeps").assert().success();
}

#[test]
fn changepps() {
    let s = SwtpmSession::new();
    s.cmd("changepps").assert().success();
}

#[test]
fn clear_after_clearcontrol_disable_fails() {
    let s = SwtpmSession::new();
    s.cmd("clearcontrol")
        .args(["-C", "p", "-s"])
        .assert()
        .success();
    s.cmd("clear").args(["-c", "l"]).assert().failure();
}

// ── hierarchycontrol ────────────────────────────────────────────────

#[test]
fn hierarchycontrol_enable() {
    let s = SwtpmSession::new();
    // Enable endorsement hierarchy (already enabled, but validates command works).
    s.cmd("hierarchycontrol")
        .args(["-C", "p", "e"])
        .assert()
        .success();

    // Verify endorsement hierarchy is usable.
    let ek_ctx = s.tmp().path().join("ek.ctx");
    s.cmd("createek")
        .args(["-G", "rsa", "-c"])
        .arg(&ek_ctx)
        .assert()
        .success();
    assert!(ek_ctx.exists());
}
