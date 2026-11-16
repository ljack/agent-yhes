//! Command-line surface: usage, input sources and the absence of bypasses.
mod support;
use serde_json::json;
use support::Machine;

#[test]
fn starting_signer_for_diagnostics_requests_no_key_or_approval() {
    let mac = Machine::new();
    let result = mac.run(&["doctor", "--start-signer"]);
    let value: serde_json::Value = serde_json::from_str(&result.stdout).unwrap();
    assert_eq!(value["command"], "doctor");
    assert_eq!(mac.signer.enrollments.get(), 0);
    assert_eq!(mac.signer.reviews.get(), 0);
    assert_eq!(mac.run(&["send", "--start-signer"]).exit, 2);
}

#[test]
fn commands_before_setup_and_bad_usage_are_actionable() {
    let mac = Machine::new();
    assert_eq!(mac.run(&["status"]).ok()["set_up"], json!(false));
    assert_eq!(
        mac.run(&["send", "--as", "codex", "--text", "x"]).error(),
        "not_set_up"
    );
    assert_eq!(mac.run(&["inbox", "--as", "codex"]).error(), "not_set_up");

    let out = mac.run(&["send", "--as", "codex", "PRIVATE_POSITIONAL_TEXT"]);
    assert_eq!(out.exit, 2);
    assert!(!out.stdout.contains("PRIVATE_POSITIONAL_TEXT"));
    assert_eq!(mac.run(&["pilot"]).exit, 2);
    assert_eq!(mac.run(&["frobnicate"]).exit, 2);
    let help = mac.run(&["help"]);
    assert_eq!(help.exit, 0);
    assert!(help.stdout.contains("yhes pilot"));
}

#[test]
fn there_is_no_signing_export_receipt_or_test_key_command() {
    let mac = Machine::new();
    mac.pilot();
    for argv in [
        vec!["sign", "--as", "codex"],
        vec!["export", "--as", "codex"],
        vec!["confirm", "--as", "codex"],
        vec!["receipt", "--as", "codex"],
        vec!["send", "--as", "codex", "--text", "x", "--test-key", "1"],
        vec!["send", "--as", "codex", "--text", "x", "--insecure"],
        vec!["pilot", "--human", "alice", "--software-signer"],
        vec!["pilot", "--human", "alice", "--ghes-user-id", "7"],
    ] {
        assert_eq!(mac.run(&argv).exit, 2, "{argv:?}");
    }
    let help = mac.run(&["help"]).stdout.to_lowercase();
    for word in [
        "sign-bytes",
        "export",
        "receipt",
        "fixture",
        "test-key",
        "insecure",
    ] {
        assert!(!help.contains(word), "{word}");
    }
}

#[test]
fn text_sources_and_profiles_are_checked() {
    let mac = Machine::new();
    mac.pilot();
    assert_eq!(
        mac.run(&["send", "--as", "grok", "--text", "x"]).error(),
        "unknown_profile"
    );
    assert_eq!(
        mac.run(&["send", "--as", "codex", "--text", "   "]).error(),
        "input"
    );
    // The harness reports a terminal on stdin, so no text source is a usage error.
    assert_eq!(mac.run(&["send", "--as", "codex"]).exit, 2);
    assert_eq!(
        mac.run_with_stdin(&["send", "--as", "codex", "--text", "a", "--stdin"], "b")
            .exit,
        2
    );
    let big = "x".repeat(70_000);
    assert_eq!(
        mac.run_with_stdin(&["send", "--as", "codex", "--body-file", "-"], &big)
            .error(),
        "too_large"
    );
    assert_eq!(
        mac.run(&["say", "--as", "codex", "--text", "bell\u{7}"])
            .error(),
        "input"
    );
    assert_eq!(
        mac.run(&[
            "send",
            "--as",
            "codex",
            "--operation",
            "../x",
            "--text",
            "x"
        ])
        .exit,
        2
    );

    mac.run_with_stdin(
        &["send", "--as", "codex", "--body-file", "-"],
        "from a pipe\n",
    )
    .ok();
    let inbox = mac.run(&["inbox", "--as", "claude"]).ok();
    assert_eq!(inbox["messages"][0]["text"], json!("from a pipe"));
}
