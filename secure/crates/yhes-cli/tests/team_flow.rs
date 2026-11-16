mod team_support;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use team_support::*;

#[test]
fn explicit_git_settings_are_pinned_and_incomplete_signing_options_fail_before_identity() {
    let team = Team::new();
    let base = [
        "team-init",
        "--project-id",
        "demo",
        "--human",
        "alice",
        "--as",
        "alice-agent",
        "--remote",
        &team.remote,
    ];
    let mut invalid = base.to_vec();
    invalid.extend(["--git-signing-format", "ssh"]);
    assert_eq!(team.founder.run(&invalid).error(), "usage");
    assert!(team.founder.signer.reviews.borrow().is_empty());
    assert!(!team.founder.network().join("team.json").exists());
    let mut configured = base.to_vec();
    configured.extend([
        "--git-author-name",
        "Alice Test",
        "--git-author-email",
        "alice@tests.invalid",
    ]);
    let first = team.founder.run(&configured).ok();
    let reviews = team.founder.signer.reviews.borrow().len();
    assert_eq!(
        first["bootstrap_head"],
        team.founder.run(&configured).ok()["bootstrap_head"]
    );
    assert_eq!(reviews, team.founder.signer.reviews.borrow().len());
    assert_eq!(team.founder.run(&base).error(), "team_pin_mismatch");
    let path = team.founder.network().join("team.json");
    let mut pin: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    pin["git_options"]["author_name"] = json!("Changed author");
    std::fs::write(path, serde_json::to_vec(&pin).unwrap()).unwrap();
    assert_eq!(
        team.founder.run(&["team-status"]).error(),
        "team_pin_changed"
    );
}

#[test]
fn public_artifact_rollback_with_the_same_registry_is_refused() {
    let team = Team::new();
    team.init();
    team.request();
    team.admit();
    let before = String::from_utf8(git(
        &team.remote,
        &["rev-parse", "refs/heads/agent-yhes/secure-team"],
    ))
    .unwrap();
    team.peer.run(&["team-connect"]).ok();
    let reviews = team.peer.signer.reviews.borrow().len();
    git(
        &team.remote,
        &[
            "update-ref",
            "refs/heads/agent-yhes/secure-team",
            before.trim(),
        ],
    );
    assert!(team.peer.run(&["team-connect"]).exit != 0);
    assert_eq!(reviews, team.peer.signer.reviews.borrow().len());
}

#[test]
fn substituted_request_name_or_controller_cannot_be_admitted() {
    let team = Team::new();
    team.init();
    team.request();
    let channel = team.channel(&team.founder);
    let bytes = channel
        .read_public("request-bob-agent.json")
        .unwrap()
        .unwrap();
    let mut request: Value = serde_json::from_slice(&bytes).unwrap();
    // Same valid peer signature relabelled as another agent cannot select it.
    channel
        .publish_public("request-pretender.json", &bytes)
        .unwrap();
    let before = team.founder.signer.reviews.borrow().len();
    assert_eq!(
        team.founder
            .run(&[
                "team-admit",
                "--peer",
                "pretender",
                "--peer-key",
                &team.peer.signer.fingerprint()
            ])
            .error(),
        "team_evidence_rejected"
    );
    // A fully self-signed but malformed binding cannot override project roles.
    let envelope = yhes_wire::Envelope::parse(
        request["registry"].as_str().unwrap().as_bytes(),
        yhes_wire::REGISTRY_PAYLOAD_TYPE,
    )
    .unwrap();
    let mut document: Value = serde_json::from_slice(envelope.payload()).unwrap();
    for participant in document["participants"].as_array_mut().unwrap() {
        if participant["kind"] == "agent" {
            participant["id"] = json!("wrong-controller");
            participant["controller"] = json!("alice");
        }
    }
    for key in document["keys"].as_array_mut().unwrap() {
        if key["participant"] == "bob-agent" {
            key["participant"] = json!("wrong-controller");
        }
    }
    request["agent"]["principal"] = json!("wrong-controller");
    request["registry"] = json!(team.peer.signer.seal(
        yhes_wire::REGISTRY_PAYLOAD_TYPE,
        &serde_json::to_vec(&document).unwrap()
    ));
    channel
        .publish_public(
            "request-wrong-controller.json",
            &serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
    assert_eq!(
        team.founder
            .run(&[
                "team-admit",
                "--peer",
                "wrong-controller",
                "--peer-key",
                &team.peer.signer.fingerprint()
            ])
            .error(),
        "team_evidence_rejected"
    );
    assert_eq!(before, team.founder.signer.reviews.borrow().len());
}

#[test]
fn substituted_valid_key_package_is_refused_before_any_membership_review() {
    let team = Team::new();
    team.init();
    team.request();
    team.admit();
    let (kp, key_id) = {
        let mut engine = team.founder.engine();
        (
            engine.key_package("attack-package", NOW).unwrap(),
            engine.identity().unwrap().key_id,
        )
    };
    let package = json!({"version":1,"project":"demo","group":"team","principal":"bob-agent","key_id":key_id,"key_package":STANDARD.encode(kp)});
    team.channel(&team.founder)
        .publish_public(
            "key-package-bob-agent.json",
            &serde_json::to_vec(&package).unwrap(),
        )
        .unwrap();
    let before = team.founder.signer.reviews.borrow().len();
    assert_eq!(
        team.founder.run(&["team-connect"]).error(),
        "team_evidence_rejected"
    );
    assert_eq!(before, team.founder.signer.reviews.borrow().len());
    assert!(team.founder.run(&["team-status"]).ok()["group"].is_null());
}

#[test]
fn exact_public_artifacts_and_key_packages_survive_restarts() {
    let team = Team::new();
    team.init();
    let first = team
        .channel(&team.founder)
        .fetch_public()
        .unwrap()
        .artifacts;
    team.init();
    assert_eq!(
        first,
        team.channel(&team.founder)
            .fetch_public()
            .unwrap()
            .artifacts
    );
    team.request();
    let request = team
        .channel(&team.peer)
        .read_public("request-bob-agent.json")
        .unwrap()
        .unwrap();
    let before = team.peer.signer.reviews.borrow().len();
    team.request();
    assert_eq!(before, team.peer.signer.reviews.borrow().len());
    assert_eq!(
        request,
        team.channel(&team.peer)
            .read_public("request-bob-agent.json")
            .unwrap()
            .unwrap()
    );
    team.admit();
    team.peer.run(&["team-connect"]).ok();
    let package = team
        .channel(&team.peer)
        .read_public("key-package-bob-agent.json")
        .unwrap()
        .unwrap();
    let before = team.peer.signer.reviews.borrow().len();
    team.peer.run(&["team-connect"]).ok();
    assert_eq!(before, team.peer.signer.reviews.borrow().len());
    assert_eq!(
        package,
        team.channel(&team.peer)
            .read_public("key-package-bob-agent.json")
            .unwrap()
            .unwrap()
    );
}

#[test]
fn independent_people_join_restart_and_exchange_exactly_once() {
    let team = Team::new();
    assert_ne!(
        team.founder.signer.fingerprint(),
        team.peer.signer.fingerprint()
    );
    team.setup();
    let first = team
        .founder
        .run(&[
            "team-send",
            "--text",
            "agent-only confidential text",
            "--operation",
            "message-one",
        ])
        .ok();
    assert_eq!(first["replayed"], false);
    let retry = team
        .founder
        .run(&[
            "team-send",
            "--text",
            "agent-only confidential text",
            "--operation",
            "message-one",
        ])
        .ok();
    assert_eq!(retry["replayed"], true);
    assert_eq!(retry["event_id"], first["event_id"]);
    assert_eq!(
        team.founder
            .run(&[
                "team-send",
                "--text",
                "changed",
                "--operation",
                "message-one"
            ])
            .error(),
        "operation_conflict"
    );
    let inbox = team.peer.run(&["team-inbox"]).ok();
    assert_eq!(inbox["messages"][0]["text"], "agent-only confidential text");
    assert_eq!(inbox["messages"][0]["author"], "alice-agent");
    assert_eq!(inbox["messages"][0]["human_authored"], false);
    let approvals = team.peer.signer.reviews.borrow().len();
    team.peer
        .run(&[
            "team-say",
            "--text",
            "my human original exact words",
            "--operation",
            "human-one",
        ])
        .ok();
    team.peer
        .run(&[
            "team-say",
            "--text",
            "my human original exact words",
            "--operation",
            "human-one",
        ])
        .ok();
    assert_eq!(team.peer.signer.reviews.borrow().len(), approvals + 1);
    let inbox = team.founder.run(&["team-inbox"]).ok();
    let relay = inbox["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["kind"] == "agent.relay")
        .unwrap();
    assert_eq!(relay["human_original_author"], "bob");
    assert_eq!(relay["author"], "bob-agent");
    assert_eq!(relay["human_text"], "my human original exact words");
    assert_eq!(relay["human_authored"], false);
    let old = team.founder.run(&["team-inbox", "--no-sync"]).ok();
    assert_eq!(old["new_messages"], 0);
    assert!(old["messages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["replayed"] == true));
    // Inspect decompressed Git blobs, not only compressed object bytes.
    let objects = git(&team.remote, &["rev-list", "--objects", "--all"]);
    for line in String::from_utf8(objects).unwrap().lines() {
        let oid = line.split_whitespace().next().unwrap();
        let content = git(&team.remote, &["cat-file", "-p", oid]);
        for secret in [
            "agent-only confidential text",
            "my human original exact words",
            "vault.db",
            "pin-binding",
        ] {
            assert!(
                !content
                    .windows(secret.len())
                    .any(|b| b == secret.as_bytes()),
                "Git leaked {secret}"
            );
        }
        for private_scalar in [[0x31u8; 32], [0x32u8; 32]] {
            assert!(!content.windows(32).any(|bytes| bytes == private_scalar));
            let encoded = STANDARD.encode(private_scalar);
            assert!(!content
                .windows(encoded.len())
                .any(|bytes| bytes == encoded.as_bytes()));
        }
    }
    assert!(!team.founder.project.join(".agents").exists());
    assert!(!team.peer.project.join(".agents").exists());
}

#[test]
fn prepared_human_message_reuses_exact_packet_after_restart_before_publication() {
    let team = Team::new();
    team.setup();
    let before = git(
        &team.remote,
        &["rev-parse", "refs/heads/agent-yhes/secure-team"],
    );
    let packet = {
        let ws =
            yhes_cli::profile::Workspace::locate(&team.peer.private, &team.peer.project, false)
                .unwrap();
        let pin: yhes_cli::team::TeamPin =
            serde_json::from_slice(&std::fs::read(team.peer.network().join("team.json")).unwrap())
                .unwrap();
        let engine = team.peer.engine();
        let channel = team.channel(&team.peer);
        let mut session = yhes_cli::team::TeamSession {
            ws,
            pin,
            engine,
            channel,
        };
        let mut progress = Vec::new();
        let mut deps = yhes_cli::Deps {
            signer: &team.peer.signer,
            custody: &team.peer.custody,
            clock: &team.peer.clock,
            private_root: team.peer.private.clone(),
            progress: &mut progress,
        };
        let prepared = yhes_cli::team::prepare_message(
            &mut session,
            &mut deps,
            true,
            "reviewed before transport".into(),
            "prepared-human",
        )
        .unwrap();
        assert_eq!(prepared.result["replayed"], false);
        prepared.packet
    };
    assert_eq!(
        before,
        git(
            &team.remote,
            &["rev-parse", "refs/heads/agent-yhes/secure-team"]
        )
    );
    let reviews = team.peer.signer.reviews.borrow().len();
    let sent = team
        .peer
        .run(&[
            "team-say",
            "--text",
            "reviewed before transport",
            "--operation",
            "prepared-human",
        ])
        .ok();
    assert_eq!(sent["replayed"], true);
    assert_eq!(reviews, team.peer.signer.reviews.borrow().len());
    let stored = {
        let mut engine = team.peer.engine();
        engine.stored_packet("prepared-human").unwrap()
    };
    assert_eq!(packet, stored);
    let inbox = team.founder.run(&["team-inbox"]).ok();
    assert_eq!(
        inbox["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["human_text"] == "reviewed before transport")
            .count(),
        1
    );
}

#[test]
fn explicit_fingerprints_are_required_before_enrollment_or_admission() {
    let team = Team::new();
    team.init();
    let stranger = Human::new(0x33);
    assert_eq!(
        team.peer
            .run(&[
                "team-request",
                "--project-id",
                "demo",
                "--human",
                "bob",
                "--as",
                "bob-agent",
                "--remote",
                &team.remote,
                "--authority",
                &stranger.fingerprint(),
                "--bootstrap",
                &team.bootstrap()
            ])
            .error(),
        "team_evidence_rejected"
    );
    assert!(team.peer.signer.reviews.borrow().is_empty());
    assert!(!team.peer.network().join("team.json").exists());
    assert_eq!(
        team.peer
            .run(&[
                "team-request",
                "--project-id",
                "demo",
                "--human",
                "bob",
                "--as",
                "bob-agent",
                "--remote",
                &team.remote,
                "--authority",
                &team.founder.signer.fingerprint(),
                "--bootstrap",
                &"00".repeat(32)
            ])
            .error(),
        "team_evidence_rejected"
    );
    assert!(team.peer.signer.reviews.borrow().is_empty());
    assert!(!team.peer.network().join("team.json").exists());
    team.request();
    let reviews = team.founder.signer.reviews.borrow().len();
    assert_eq!(
        team.founder
            .run(&[
                "team-admit",
                "--peer",
                "bob-agent",
                "--peer-key",
                &stranger.fingerprint()
            ])
            .error(),
        "team_evidence_rejected"
    );
    assert_eq!(reviews, team.founder.signer.reviews.borrow().len());
    assert_eq!(
        team.peer.run(&["team-connect"]).ok()["state"],
        "waiting-for-admission"
    );
    team.admit();
}

#[test]
fn delayed_first_join_fails_closed_and_does_not_backdate() {
    let team = Team::new();
    team.init();
    team.request();
    team.admit();
    // Days may pass before connect: genesis has deliberately not been created.
    team.founder.advance(86400);
    team.peer.advance(86400);
    team.peer.run(&["team-connect"]).ok();
    team.founder.run(&["team-connect"]).ok();
    team.peer.advance(601);
    assert!(team.peer.run(&["team-connect"]).exit != 0);
    assert!(
        team.peer
            .run(&["team-send", "--text", "cannot join late"])
            .exit
            != 0
    );
    assert!(team.peer.run(&["team-status"]).ok()["group"].is_null());
}

#[test]
fn interrupted_reviews_resume_without_resigning_committed_stages() {
    let team = Team::new();
    team.init();
    team.request();
    team.admit();
    team.peer.run(&["team-connect"]).ok();
    // Founder has registry1 + registry2; delegation is review 3, create 4, add 5.
    team.founder.signer.cancel_at.set(Some(5));
    assert_eq!(team.founder.run(&["team-connect"]).error(), "cancelled");
    let status = team.founder.run(&["team-status"]).ok();
    assert_eq!(status["group"]["audience"], json!(["alice-agent"]));
    team.founder.signer.cancel_at.set(None);
    team.founder.run(&["team-connect"]).ok();
    team.peer.run(&["team-connect"]).ok();
    let reviewed = team.founder.signer.reviews.borrow();
    assert_eq!(reviewed.iter().filter(|v|v["kind"]=="action.authorization" && v["body"]["action"]=="group.create").count(),1);
    drop(reviewed);
    let before = team.founder.signer.reviews.borrow().len();
    team.init();
    team.admit();
    team.founder.run(&["team-connect"]).ok();
    assert_eq!(team.founder.signer.reviews.borrow().len(), before);
}

#[test]
fn changed_team_configuration_is_rejected_before_output_or_network() {
    let team = Team::new();
    team.setup();
    let path = team.peer.network().join("team.json");
    let mut pin: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    pin["remote"] = json!("/tmp/other-untrusted-team.git");
    std::fs::write(&path, serde_json::to_vec(&pin).unwrap()).unwrap();
    assert_eq!(team.peer.run(&["team-status"]).error(), "team_pin_changed");
    assert_eq!(team.peer.run(&["team-connect"]).error(), "team_pin_changed");
}
