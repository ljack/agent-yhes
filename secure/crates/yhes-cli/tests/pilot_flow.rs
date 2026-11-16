//! End-to-end pilot under injected test identities: real core, real vault
//! files, real local log. The human key and key custody are test stand-ins.
mod support;
use serde_json::{json, Value};
use support::{Behavior, FakeSigner, Machine};

const AGENT_TEXT: &str = "AGENT_PRIVATE_73114: build is green";
const HUMAN_TEXT: &str = "HUMAN_PRIVATE_90216: ship the reviewed design";

fn texts(messages: &Value) -> Vec<(String, String, bool)> {
    messages
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["author"].as_str().unwrap().to_owned(),
                m["text"]
                    .as_str()
                    .or(m["human_text"].as_str())
                    .unwrap()
                    .to_owned(),
                m["replayed"].as_bool().unwrap(),
            )
        })
        .collect()
}

#[test]
fn setup_send_say_inbox_and_restart() {
    let mac = Machine::new();
    let pilot = mac.pilot();
    assert_eq!(pilot["ready"], json!(true));
    for stage in [
        "identity",
        "vaults",
        "registry",
        "delegations",
        "group_create",
        "group_add",
        "join",
    ] {
        assert_eq!(pilot["stages"][stage], json!("completed"), "{stage}");
    }
    assert_eq!(pilot["group"]["audience"], json!(["claude", "codex"]));
    assert_eq!(pilot["group"]["owner"], json!("codex"));
    // One enrollment; one registry, two delegations, two membership approvals.
    assert_eq!(mac.signer.enrollments.get(), 1);
    assert_eq!(
        *mac.signer.reviewed.borrow(),
        [
            "registry",
            "agent.delegation",
            "agent.delegation",
            "action.authorization",
            "action.authorization"
        ]
    );

    // A second run finds every stage done and asks the human nothing.
    let again = mac.pilot();
    assert_eq!(again["ready"], json!(true));
    for (stage, state) in again["stages"].as_object().unwrap() {
        assert_eq!(state, &json!("already-done"), "{stage}");
    }
    assert_eq!(mac.signer.reviews.get(), 5);

    // Agent-authored text from standard input: no human approval.
    let sent = mac
        .run_with_stdin(
            &["send", "--as", "codex", "--stdin"],
            &format!("{AGENT_TEXT}\n"),
        )
        .ok();
    assert_eq!(sent["author"], json!("codex"));
    assert_eq!(sent["kind"], json!("agent.message"));
    assert!(sent["human_original_author"].is_null());
    assert_eq!(mac.signer.reviews.get(), 5);

    let inbox = mac.run(&["inbox", "--as", "claude"]).ok();
    assert_eq!(
        texts(&inbox["messages"]),
        [("codex".to_owned(), AGENT_TEXT.to_owned(), false)]
    );
    assert_eq!(inbox["messages"][0]["origin"], json!("agent"));
    assert_eq!(inbox["messages"][0]["human_authored"], json!(false));

    // The human's exact words: one native review, relayed by the agent.
    let body = mac.project.parent().unwrap().join("statement.txt");
    std::fs::write(&body, HUMAN_TEXT).unwrap();
    let said = mac.run(&[
        "say",
        "--as",
        "codex",
        "--body-file",
        body.to_str().unwrap(),
    ]);
    assert!(
        !said.stderr.contains("HUMAN_PRIVATE"),
        "progress must not carry text"
    );
    let said = said.ok();
    assert_eq!(said["author"], json!("codex"));
    assert_eq!(said["kind"], json!("agent.relay"));
    assert_eq!(said["human_original_author"], json!("alice"));
    assert_eq!(
        mac.signer.reviewed.borrow().last().unwrap(),
        "human.statement"
    );
    assert_eq!(said["receive_before"], json!(support::NOW + 1800));

    let synced = mac.run(&["sync", "--as", "claude"]).ok();
    let relay = &synced["messages"][0];
    assert_eq!(relay["author"], json!("codex"));
    assert_eq!(relay["human_original_author"], json!("alice"));
    assert_eq!(relay["human_authored"], json!(false));
    assert_eq!(relay["origin"], json!("human-statement-relayed-by-agent"));
    assert_eq!(relay["human_text"], json!(HUMAN_TEXT));
    assert_eq!(relay["replayed"], json!(false));

    // The other direction, then a later look at the durable inbox.
    mac.run(&["send", "--as", "claude", "--text", "ack"]).ok();
    let codex = mac.run(&["inbox", "--as", "codex"]).ok();
    assert_eq!(
        texts(&codex["messages"]),
        [("claude".to_owned(), "ack".to_owned(), false)]
    );
    let later = mac.run(&["inbox", "--as", "claude", "--no-sync"]).ok();
    assert_eq!(
        texts(&later["messages"]),
        [
            ("codex".to_owned(), AGENT_TEXT.to_owned(), true),
            ("codex".to_owned(), HUMAN_TEXT.to_owned(), true)
        ]
    );

    // Neither the shared log nor the private folder holds readable text.
    for marker in ["AGENT_PRIVATE_73114", "HUMAN_PRIVATE_90216"] {
        assert!(!Machine::leaks(&mac.project, marker));
        assert!(!Machine::leaks(&mac.private, marker));
    }
    assert!(mac.project.join(".agents/messages/secure").is_dir());

    let status = mac.run(&["status"]).ok();
    assert_eq!(status["profiles"][0]["key_custody"], json!("injected-test"));
    assert!(status["ghes"].is_null());
    for profile in status["profiles"].as_array().unwrap() {
        assert_eq!(profile["group"]["active"], json!(true), "{profile}");
        assert_eq!(profile["outbox"]["unpublished"], json!([]));
    }
    let doctor = mac.run(&["doctor"]);
    let failing: Vec<&Value> = doctor.json["checks"]
        .as_array()
        .unwrap()
        .iter()
        // The test binary is not a signed build, so it has no pinned team.
        .filter(|c| c["ok"] != json!(true) && c["check"] != json!("signer-pin"))
        .collect();
    assert!(failing.is_empty(), "{failing:?}");
}

#[test]
fn interrupted_setup_resumes_without_repeating_approved_stages() {
    let mac = Machine::new();
    // The human cancels the fifth review: adding `claude` to the group.
    mac.signer.behavior.set(Behavior::Cancel);
    mac.signer.misbehave_from.set(5);
    assert_eq!(mac.run(&["pilot", "--human", "alice"]).error(), "cancelled");
    let status = mac.run(&["status"]).ok();
    let codex = status["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["agent"] == "codex")
        .unwrap();
    assert_eq!(codex["group"]["audience"], json!(["codex"]));

    mac.signer.behavior.set(Behavior::Honest);
    let resumed = mac.pilot();
    for stage in [
        "identity",
        "vaults",
        "registry",
        "delegations",
        "group_create",
    ] {
        assert_eq!(resumed["stages"][stage], json!("already-done"), "{stage}");
    }
    assert_eq!(resumed["stages"]["group_add"], json!("completed"));
    assert_eq!(resumed["stages"]["join"], json!("completed"));
    // Five reviews in the first run (the last one cancelled) plus one new approval.
    assert_eq!(mac.signer.reviews.get(), 6);
    assert_eq!(mac.signer.enrollments.get(), 1);

    mac.run(&["send", "--as", "claude", "--text", "joined"])
        .ok();
    let inbox = mac.run(&["inbox", "--as", "codex"]).ok();
    assert_eq!(inbox["messages"][0]["text"], json!("joined"));

    // A different human or project ID cannot take over the existing setup.
    assert_eq!(
        mac.run(&["pilot", "--human", "mallory"]).error(),
        "pin_mismatch"
    );
}

#[test]
fn named_operation_is_sent_once_and_cannot_change_its_text() {
    let mac = Machine::new();
    mac.pilot();
    let first = mac
        .run(&[
            "send",
            "--as",
            "codex",
            "--operation",
            "report-1",
            "--text",
            "one",
        ])
        .ok();
    assert_eq!(first["replayed"], json!(false));
    let retry = mac
        .run(&[
            "send",
            "--as",
            "codex",
            "--operation",
            "report-1",
            "--text",
            "one",
        ])
        .ok();
    assert_eq!(retry["replayed"], json!(true));
    assert_eq!(retry["event_id"], first["event_id"]);
    assert_eq!(
        mac.run(&[
            "send",
            "--as",
            "codex",
            "--operation",
            "report-1",
            "--text",
            "two"
        ])
        .error(),
        "operation_conflict"
    );
    // The same name cannot turn an agent message into a human statement either.
    assert_eq!(
        mac.run(&[
            "say",
            "--as",
            "codex",
            "--operation",
            "report-1",
            "--text",
            "one"
        ])
        .error(),
        "operation_conflict"
    );
    let inbox = mac.run(&["inbox", "--as", "claude"]).ok();
    assert_eq!(inbox["messages"].as_array().unwrap().len(), 1);

    // A retried `say` reuses the stored signed statement: one review in total.
    let before = mac.signer.reviews.get();
    mac.run(&[
        "say",
        "--as",
        "codex",
        "--operation",
        "decision-1",
        "--text",
        "go",
    ])
    .ok();
    let retry = mac
        .run(&[
            "say",
            "--as",
            "codex",
            "--operation",
            "decision-1",
            "--text",
            "go",
        ])
        .ok();
    assert_eq!(retry["replayed"], json!(true));
    assert_eq!(mac.signer.reviews.get(), before + 1);
    let inbox = mac.run(&["inbox", "--as", "claude"]).ok();
    assert_eq!(inbox["messages"].as_array().unwrap().len(), 2);
    assert_eq!(inbox["new_messages"], json!(1));
    assert_eq!(inbox["messages"][0]["new"], json!(false));
    assert_eq!(inbox["messages"][1]["new"], json!(true));
}

#[test]
fn expired_trust_stops_sending_until_the_human_renews_it() {
    let mac = Machine::new();
    mac.pilot();
    mac.run(&["send", "--as", "codex", "--text", "before"]).ok();
    mac.run(&["sync", "--as", "claude"]).ok();
    // Registry and delegations last seven days. Nothing extends them silently.
    mac.advance(8 * 86_400);
    assert_ne!(
        mac.run(&["send", "--as", "codex", "--text", "late"]).exit,
        0
    );
    let status = mac.run(&["status"]).ok();
    assert_eq!(status["profiles"][0]["registry_current"], json!(false));
    assert_eq!(status["profiles"][0]["delegation_current"], json!(false));

    let reviews = mac.signer.reviews.get();
    let renewed = mac.pilot();
    assert_eq!(renewed["stages"]["registry"], json!("completed"));
    assert_eq!(renewed["stages"]["delegations"], json!("completed"));
    assert_eq!(renewed["stages"]["group_create"], json!("already-done"));
    assert_eq!(renewed["registry"]["generation"], json!(2));
    // One registry and two delegations; the group itself is untouched.
    assert_eq!(mac.signer.reviews.get(), reviews + 3);
    mac.run(&["send", "--as", "codex", "--text", "after"]).ok();
    let inbox = mac.run(&["inbox", "--as", "claude"]).ok();
    let all = texts(&inbox["messages"]);
    assert_eq!(
        all.last().unwrap(),
        &("codex".to_owned(), "after".to_owned(), false)
    );
    // The message accepted before expiry is still there as history.
    assert_eq!(all[0], ("codex".to_owned(), "before".to_owned(), true));
}

#[test]
fn p256_human_key_like_the_native_signer_completes_setup_send_and_say() {
    // Raw 65-byte SEC1 public key and raw 64-byte signatures, as the Secure
    // Enclave signer produces; the transport accepts no other algorithm.
    let mac = Machine::with(FakeSigner::p256());
    let pilot = mac.pilot();
    for (stage, state) in pilot["stages"].as_object().unwrap() {
        assert_eq!(state, &json!("completed"), "{stage}");
    }
    let status = mac.run(&["status"]).ok();
    assert!(status["authority_key_id"]
        .as_str()
        .unwrap()
        .starts_with("k_"));
    let registry = std::fs::read_to_string(
        mac.project
            .join(".agents/messages/secure/identities/registry-1.json"),
    )
    .unwrap();
    assert!(registry.contains("\"algorithm\":\"p256-sha256\""));

    mac.run(&["send", "--as", "codex", "--text", "agent text"])
        .ok();
    mac.run(&["say", "--as", "claude", "--text", "human words"])
        .ok();
    // `claude` admitted this message while syncing for its own `say`, so the
    // inbox reports a stored result that has not been listed before.
    let claude = mac.run(&["inbox", "--as", "claude"]).ok();
    assert_eq!(
        texts(&claude["messages"]),
        [("codex".to_owned(), "agent text".to_owned(), true)]
    );
    assert_eq!(claude["messages"][0]["new"], json!(true));
    let codex = mac.run(&["inbox", "--as", "codex"]).ok();
    assert_eq!(
        texts(&codex["messages"]),
        [("claude".to_owned(), "human words".to_owned(), false)]
    );
    assert_eq!(
        codex["messages"][0]["human_original_author"],
        json!("alice")
    );
    assert_eq!(codex["messages"][0]["author"], json!("claude"));

    // A P-256 signature by a different key is still refused.
    mac.signer.behavior.set(Behavior::SignsWithOtherKey);
    mac.signer.misbehave_from.set(mac.signer.reviews.get() + 1);
    assert_eq!(
        mac.run(&["say", "--as", "codex", "--text", "x"]).error(),
        "signer_result_rejected"
    );
}

#[test]
fn a_failure_at_any_review_is_reported_and_the_next_run_continues_from_there() {
    // Reviews in order: registry, two delegations, group creation, member add.
    for failing in 1..=5 {
        for behavior in [Behavior::Cancel, Behavior::Busy, Behavior::Garbage] {
            let mac = Machine::new();
            mac.signer.behavior.set(behavior);
            mac.signer.misbehave_from.set(failing);
            let first = mac.run(&["pilot", "--human", "alice"]);
            assert_ne!(first.exit, 0, "review {failing} {behavior:?}");
            // `claude` is not a group member until the last approval succeeds.
            assert_ne!(mac.run(&["send", "--as", "claude", "--text", "x"]).exit, 0);

            mac.signer.behavior.set(Behavior::Honest);
            let resumed = mac.pilot();
            // Exactly the approvals that had not succeeded are asked again.
            assert_eq!(
                mac.signer.reviews.get(),
                failing + (6 - failing),
                "review {failing}"
            );
            assert_eq!(mac.signer.enrollments.get(), 1);
            assert_eq!(resumed["group"]["audience"], json!(["claude", "codex"]));
            mac.run(&["send", "--as", "claude", "--text", "ready"]).ok();
            let inbox = mac.run(&["inbox", "--as", "codex"]).ok();
            assert_eq!(
                inbox["messages"][0]["text"],
                json!("ready"),
                "review {failing}"
            );
        }
    }
}

fn pin_file(mac: &Machine) -> std::path::PathBuf {
    std::fs::read_dir(&mac.private)
        .unwrap()
        .map(|entry| entry.unwrap().path().join("pin.json"))
        .find(|path| path.is_file())
        .unwrap()
}

#[test]
fn an_edited_pin_cannot_relabel_the_human_or_be_adopted_by_the_vault() {
    let mac = Machine::new();
    mac.pilot();
    mac.run(&[
        "say",
        "--as",
        "codex",
        "--operation",
        "decision",
        "--text",
        "approved",
    ])
    .ok();
    mac.run(&["sync", "--as", "claude"]).ok();

    // Same key, different name: the vault's trust fingerprint alone would not notice.
    let path = pin_file(&mac);
    let original = std::fs::read(&path).unwrap();
    let mut pin: Value = serde_json::from_slice(&original).unwrap();
    pin["human"] = json!("mallory");
    pin["authority"]["author"] = json!("mallory");
    std::fs::write(&path, serde_json::to_vec(&pin).unwrap()).unwrap();

    let commands: [&[&str]; 8] = [
        &["status"],
        &[
            "say",
            "--as",
            "codex",
            "--operation",
            "decision",
            "--text",
            "approved",
        ],
        &["send", "--as", "codex", "--text", "x"],
        &["inbox", "--as", "claude", "--no-sync"],
        &["sync", "--as", "claude"],
        // Setup under the new name must not rebind the vault either.
        &["pilot", "--human", "mallory"],
        &["pilot", "--human", "alice"],
        &["doctor"],
    ];
    let reviews = mac.signer.reviews.get();
    for argv in commands {
        let out = mac.run(argv);
        assert_ne!(out.exit, 0, "{argv:?}");
        assert!(!out.stdout.contains("mallory"), "{argv:?}: {}", out.stdout);
        if argv[0] == "pilot" && argv[2] == "alice" {
            assert_eq!(out.error(), "pin_mismatch");
        } else if argv[0] != "doctor" {
            assert_eq!(out.error(), "pin_changed", "{argv:?}");
        }
    }
    assert_eq!(mac.signer.reviews.get(), reviews, "no review was requested");

    // The binding was not overwritten: the original file works again, and the
    // stored relay is still attributed to the human who signed it.
    std::fs::write(&path, &original).unwrap();
    let replay = mac
        .run(&[
            "say",
            "--as",
            "codex",
            "--operation",
            "decision",
            "--text",
            "approved",
        ])
        .ok();
    assert_eq!(replay["replayed"], json!(true));
    assert_eq!(replay["human_original_author"], json!("alice"));
    let inbox = mac.run(&["inbox", "--as", "claude"]).ok();
    assert_eq!(
        inbox["messages"][0]["human_original_author"],
        json!("alice")
    );
    assert_eq!(mac.run(&["status"]).ok()["human"], json!("alice"));
}
