//! Process-boundary tests for the standalone ZEC collector authority command.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used)]

use std::process::Command;

#[test]
fn command_is_explicit_and_missing_policy_fails_without_echoing_its_path() {
    let unavailable = "/definitely-unavailable/private-wallet-identity.toml";
    let output = Command::new(env!("CARGO_BIN_EXE_wcash-poold"))
        .args(["zec-authority-check", "--config", unavailable])
        .output()
        .expect("pool daemon command runs");

    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 diagnostic");
    assert!(stderr.len() <= 256);
    assert!(!stderr.contains(unavailable));
    assert!(!stderr.contains("wallet-identity"));
    assert!(stderr.contains("configuration is unsafe"));
}

#[test]
fn help_describes_the_one_time_authority_gate() {
    let output = Command::new(env!("CARGO_BIN_EXE_wcash-poold"))
        .args(["zec-authority-check", "--help"])
        .output()
        .expect("pool daemon help runs");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 help");
    assert!(stdout.contains("finalized, empty Zcash Testnet collector"));
    assert!(stdout.contains("--config"));
}
