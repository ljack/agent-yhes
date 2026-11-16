//! Fresh disposable fixtures only. No user's projects, origin, native key or
//! live broker are accessed by these example tests.
use super::*;
use std::{
    fs as stdfs,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
    process::Command,
};
use yhes_cli::{
    signer::{self, Mode, SignerClient},
    Custody,
};
use yhes_core::keys::Anchor;

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    lab: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        stdfs::set_permissions(&root, stdfs::Permissions::from_mode(0o700)).unwrap();
        let lab = root.join("lab");
        for dir in [&lab, &root.join("alice"), &root.join("bob")] {
            fs::directory(dir).unwrap();
        }
        fs::directory(&lab.join("nodes")).unwrap();
        let marker = json!({"version":1,"simulation":true,"project_id":"sim-0123456789abcdef",
            "alice":root.join("alice"),"bob":root.join("bob"),"broker_url":"nats://127.0.0.1:4222"});
        fs::add(&lab.join("lab.json"), &serde_json::to_vec(&marker).unwrap()).unwrap();
        for role in ["alice", "bob"] {
            let node = json!({"version":1,"simulation":true,"project_id":"sim-0123456789abcdef",
                "lab_root":lab,"project":root.join(role),"role":role});
            fs::add(
                &lab.join("nodes").join(format!("{role}.json")),
                &serde_json::to_vec(&node).unwrap(),
            )
            .unwrap();
        }
        let status = Command::new("/usr/bin/git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(["init", "--bare", "--quiet", "--template="])
            .arg(lab.join("shared.git"))
            .status()
            .unwrap();
        assert!(status.success());
        Self {
            _temp: temp,
            root,
            lab,
        }
    }
    fn node(&self, role: &str) -> PathBuf {
        self.lab.join("nodes").join(format!("{role}.json"))
    }
    fn load(&self, role: &str) -> config::Lab {
        config::Lab::load(&self.node(role)).unwrap()
    }
    fn invoke(&self, role: &str, command: &[&str]) -> (i32, Value) {
        let mut args = vec![
            if command.is_empty() {
                "identity".into()
            } else {
                "run".into()
            },
            "--node".into(),
            self.node(role).to_str().unwrap().into(),
        ];
        if !command.is_empty() {
            args.push("--".into());
            args.extend(command.iter().map(|s| s.to_string()));
        }
        let outcome = execute(&args, &mut &b""[..], false);
        let value: Value = serde_json::from_str(&outcome.stdout).unwrap();
        assert_eq!(value["simulation"], true);
        assert_eq!(value["human_authentication"], "simulated-no-touch-id");
        assert_eq!(value["key_custody"], "simulation-files");
        (outcome.exit, value)
    }
    fn ok(&self, role: &str, command: &[&str]) -> Value {
        let (exit, value) = self.invoke(role, command);
        assert_eq!(exit, 0, "{command:?}: {value}");
        assert_eq!(value["ok"], true);
        value
    }
    fn reject(&self, role: &str, command: &[&str]) {
        let (exit, value) = self.invoke(role, command);
        assert_ne!(exit, 0, "unexpected acceptance: {command:?}: {value}");
        assert_eq!(value["error"]["code"], "simulation_boundary");
    }
    fn setup(&self) {
        let alice = self.ok("alice", &[]);
        let bob = self.ok("bob", &[]);
        let init = self.ok("alice", &["team-init"]);
        self.ok(
            "bob",
            &[
                "team-request",
                "--authority",
                alice["key_id"].as_str().unwrap(),
                "--bootstrap",
                init["bootstrap_head"].as_str().unwrap(),
            ],
        );
        self.ok(
            "alice",
            &[
                "team-admit",
                "--peer",
                "sim-bob-agent",
                "--peer-key",
                bob["key_id"].as_str().unwrap(),
            ],
        );
        assert_eq!(
            self.ok("bob", &["team-connect"])["state"],
            "waiting-for-invitation"
        );
        assert_eq!(self.ok("alice", &["team-connect"])["state"], "ready");
        assert_eq!(self.ok("bob", &["team-connect"])["state"], "ready");
    }
}

#[test]
fn persistent_distinct_identities_are_private_and_scope_bound() {
    let f = Fixture::new();
    let alice = f.ok("alice", &[]);
    let bob = f.ok("bob", &[]);
    assert_ne!(alice["key_id"], bob["key_id"]);
    assert_eq!(alice, f.ok("alice", &[]));
    assert_eq!(bob, f.ok("bob", &[]));
    assert_eq!(
        stdfs::metadata(f.lab.join("private/alice/human.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let saved = stdfs::read(f.lab.join("private/alice/human.key")).unwrap();
    let key: Value = serde_json::from_slice(&saved).unwrap();
    assert!(!alice.to_string().contains(key["secret"].as_str().unwrap()));
    stdfs::write(f.lab.join("private/bob/human.key"), saved).unwrap();
    f.reject("bob", &[]);
}

#[test]
fn real_git_mls_flow_reopens_on_every_command_and_retries_once() {
    let f = Fixture::new();
    f.setup();
    let sent = f.ok(
        "alice",
        &[
            "team-send",
            "--text",
            "disposable agent text",
            "--operation",
            "one",
        ],
    );
    assert_eq!(sent["replayed"], false);
    let replay = f.ok(
        "alice",
        &[
            "team-send",
            "--text",
            "disposable agent text",
            "--operation",
            "one",
        ],
    );
    assert_eq!(replay["replayed"], true);
    f.ok("bob", &["team-inbox"]);
    f.ok(
        "bob",
        &[
            "team-say",
            "--text",
            "disposable simulated human text",
            "--operation",
            "two",
        ],
    );
    let inbox = f.ok("alice", &["team-inbox"]);
    assert!(inbox
        .to_string()
        .contains("disposable simulated human text"));
    f.ok("alice", &["team-status"]);
    f.ok("bob", &["team-status"]);
}

#[test]
fn rejects_production_commands_overrides_and_external_paths() {
    let f = Fixture::new();
    for command in [
        "pilot", "send", "say", "sync", "doctor", "help", "status", "sign", "recover",
    ] {
        f.reject("alice", &[command]);
    }
    for (flag, value) in [
        ("--project", "/"),
        ("--project-id", "production"),
        ("--human", "real-human"),
        ("--as", "sim-bob-agent"),
        ("--remote", "https://example.invalid/team.git"),
        ("--branch", "main"),
        ("--git-signing-format", "ssh"),
        ("--git-signing-key", "/keys"),
        ("--git-author-name", "test"),
        ("--git-author-email", "test@invalid"),
        ("--git-credentials", "osxkeychain"),
        ("--private-root", "/private"),
    ] {
        f.reject("alice", &["team-init", flag, value]);
    }
    f.reject("alice", &["team-init", "--git-ssh-agent"]);
    f.reject(
        "alice",
        &[
            "team-send",
            "--broker",
            "nats://localhost:4222",
            "--text",
            "test",
        ],
    );
    f.reject("alice", &["team-send", "--body-file", "/etc/passwd"]);
    f.reject("bob", &["team-init"]);
    f.reject("alice", &["team-request"]);
    assert!(!f.lab.join("private").exists());
}

#[test]
fn rejects_unknown_fields_symlinks_permissions_and_cross_role_mapping() {
    let f = Fixture::new();
    let node = f.node("alice");
    let original = stdfs::read(&node).unwrap();
    let mut value: Value = serde_json::from_slice(&original).unwrap();
    value["unexpected"] = json!(true);
    stdfs::write(&node, serde_json::to_vec(&value).unwrap()).unwrap();
    f.reject("alice", &[]);
    stdfs::write(&node, &original).unwrap();
    let mut value: Value = serde_json::from_slice(&original).unwrap();
    value["project"] = json!(f.root.join("bob"));
    stdfs::write(&node, serde_json::to_vec(&value).unwrap()).unwrap();
    f.reject("alice", &[]);
    stdfs::write(&node, &original).unwrap();
    stdfs::set_permissions(&node, stdfs::Permissions::from_mode(0o644)).unwrap();
    f.reject("alice", &[]);
    stdfs::set_permissions(&node, stdfs::Permissions::from_mode(0o600)).unwrap();
    f.ok("alice", &[]);
    let key = f.lab.join("private/alice/human.key");
    let moved = f.lab.join("private/alice/moved.key");
    stdfs::rename(&key, &moved).unwrap();
    symlink(&moved, &key).unwrap();
    f.reject("alice", &[]);
}

#[test]
fn stored_pin_cannot_enable_network_git_or_real_credentials() {
    let f = Fixture::new();
    f.ok("alice", &["team-init"]);
    let lab = f.load("alice");
    let ws = yhes_cli::profile::Workspace::locate(&lab.engine, &lab.node.project, false).unwrap();
    let path = ws.private.join("network/team.json");
    let original = stdfs::read(&path).unwrap();
    for change in ["remote", "credential", "as", "branch"] {
        let mut pin: Value = serde_json::from_slice(&original).unwrap();
        match change {
            "remote" => pin["remote"] = json!("https://example.invalid/prod.git"),
            "credential" => pin["git_options"]["credentials"] = json!("osxkeychain"),
            "as" => pin["principal"] = json!("sim-bob-agent"),
            _ => pin["branch"] = json!("main"),
        }
        stdfs::write(&path, serde_json::to_vec(&pin).unwrap()).unwrap();
        f.reject("alice", &["team-status"]);
    }
}

#[test]
fn file_custody_add_only_cas_reopens_rejects_forks_and_gaps() {
    let f = Fixture::new();
    let lab = f.load("alice");
    lab.prepare().unwrap();
    let c = custody::Files::new(&lab.role_root, "fixture-account".into()).unwrap();
    c.create_key("fixture-account").unwrap();
    assert!(c.create_key("fixture-account").is_err());
    assert!(c.load_key("other").is_err());
    let a = Anchor {
        revision: 0,
        digest: "a".repeat(64),
    };
    let b = Anchor {
        revision: 1,
        digest: "b".repeat(64),
    };
    let fork = Anchor {
        revision: 1,
        digest: "c".repeat(64),
    };
    c.anchors().advance("fixture-account", None, &a).unwrap();
    c.anchors().advance("fixture-account", None, &a).unwrap();
    let reopened = custody::Files::new(&lab.role_root, "fixture-account".into()).unwrap();
    reopened.load_key("fixture-account").unwrap();
    reopened
        .anchors()
        .advance("fixture-account", Some(&a), &b)
        .unwrap();
    reopened
        .anchors()
        .advance("fixture-account", Some(&a), &b)
        .unwrap();
    assert!(reopened
        .anchors()
        .advance("fixture-account", Some(&a), &fork)
        .is_err());
    assert!(reopened
        .anchors()
        .advance("fixture-account", None, &a)
        .is_err());
    let wrong = Anchor {
        revision: 0,
        digest: "d".repeat(64),
    };
    assert!(reopened
        .anchors()
        .advance("fixture-account", Some(&wrong), &b)
        .is_err());
    stdfs::remove_file(
        lab.role_root
            .join("custody/anchors/00000000000000000000.json"),
    )
    .unwrap();
    assert!(reopened.anchors().load("fixture-account").is_err());
}

#[test]
fn signer_rejects_wrong_scope_unknown_registry_and_generic_event() {
    let f = Fixture::new();
    let lab = f.load("alice");
    lab.prepare().unwrap();
    let human = human::Human::open(&lab).unwrap();
    assert!(signer::identity(&human, "sim-bob", &lab.node.project_id).is_err());
    let descriptor = human.descriptor().unwrap();
    for payload in [
        b"{}".as_slice(),
        br#"{"version":1,"project":"production","kind":"human.statement"}"#,
    ] {
        assert!(signer::review(&human, &descriptor, Mode::Event, payload, None).is_err());
        assert!(signer::review(&human, &descriptor, Mode::Registry, payload, None).is_err());
    }
    assert!(human.accepts(yhes_wire::Algorithm::P256Sha256));
    assert!(!human.accepts(yhes_wire::Algorithm::Ed25519));
}

#[test]
fn identity_cannot_be_rebound_by_editing_both_node_and_marker() {
    let f = Fixture::new();
    f.ok("alice", &[]);
    let other = f.root.join("other-project");
    fs::directory(&other).unwrap();
    for (path, field) in [
        (f.node("alice"), "project"),
        (f.lab.join("lab.json"), "alice"),
    ] {
        let mut value: Value = serde_json::from_slice(&stdfs::read(&path).unwrap()).unwrap();
        value[field] = json!(other);
        stdfs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }
    f.reject("alice", &[]);
}

#[test]
fn racing_checkpoint_writers_publish_only_one_revision() {
    let f = Fixture::new();
    let lab = f.load("alice");
    lab.prepare().unwrap();
    let c = custody::Files::new(&lab.role_root, "race-account".into()).unwrap();
    let genesis = Anchor {
        revision: 0,
        digest: "a".repeat(64),
    };
    c.anchors().advance("race-account", None, &genesis).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = ['b', 'c']
        .into_iter()
        .map(|letter| {
            let root = lab.role_root.clone();
            let barrier = barrier.clone();
            let genesis = genesis.clone();
            std::thread::spawn(move || {
                let c = custody::Files::new(&root, "race-account".into()).unwrap();
                let next = Anchor {
                    revision: 1,
                    digest: letter.to_string().repeat(64),
                };
                barrier.wait();
                c.anchors()
                    .advance("race-account", Some(&genesis), &next)
                    .is_ok()
            })
        })
        .collect();
    let winners = workers
        .into_iter()
        .map(|w| w.join().unwrap())
        .filter(|won| *won)
        .count();
    assert_eq!(winners, 1);
    assert_eq!(
        c.anchors().load("race-account").unwrap().unwrap().revision,
        1
    );
}

#[test]
fn broker_token_and_url_are_only_the_lab_fixture() {
    let f = Fixture::new();
    let lab = f.load("alice");
    assert!(lab.token().is_err());
    let token = "disposable-simulation-token-0123456789abcdef";
    fs::add(&f.lab.join("broker.token"), token.as_bytes()).unwrap();
    assert_eq!(lab.token().unwrap(), token);
    stdfs::set_permissions(
        f.lab.join("broker.token"),
        stdfs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(lab.token().is_err());
    let marker_path = f.lab.join("lab.json");
    let original = stdfs::read(&marker_path).unwrap();
    for url in [
        "nats://localhost:4222",
        "nats://127.0.0.1:4222/",
        "nats://user:secret@127.0.0.1:4222",
        "tls://example.invalid:4222",
        "nats://127.0.0.1:0",
    ] {
        let mut marker: Value = serde_json::from_slice(&original).unwrap();
        marker["broker_url"] = json!(url);
        stdfs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();
        f.reject("alice", &[]);
    }
}

#[test]
fn progress_forwards_readiness_but_suppresses_typed_native_approval() {
    let f = Fixture::new();
    let lab = f.load("alice");
    lab.prepare().unwrap();
    let human = human::Human::open(&lab).unwrap();
    let custody = custody::Files::new(&lab.role_root, "progress-fixture".into()).unwrap();
    let mut output = Vec::new();
    {
        let mut progress = progress::ReadyProgress::new(&mut output);
        let mut deps = Deps {
            signer: &human,
            custody: &custody,
            clock: &SystemClock,
            private_root: lab.engine,
            progress: &mut progress,
        };
        deps.say("review the complete registry and keys in YhesSigner; approve with Touch ID");
        deps.say("review the exact event and audience in YhesSigner; approve with Touch ID");
        deps.say("team identity: checking this person's native signing key");
        deps.say("realtime: waiting for ciphertext notifications; Git remains authoritative");
        deps.say("arbitrary progress must remain hidden");
    }
    assert_eq!(
        output,
        b"SIMULATION realtime: waiting for ciphertext notifications\n"
    );
}

#[test]
fn progress_requires_complete_exact_line_across_write_boundaries() {
    use std::io::Write;
    let exact =
        b"yhes: realtime: waiting for ciphertext notifications; Git remains authoritative\n";
    let mut output = Vec::new();
    {
        let mut progress = progress::ReadyProgress::new(&mut output);
        progress.write_all(b"prefix ").unwrap();
        progress.write_all(exact).unwrap();
        progress.write_all(&exact[..exact.len() - 1]).unwrap();
        progress.write_all(b" suffix\n").unwrap();
        for byte in exact {
            progress.write_all(&[*byte]).unwrap();
        }
        progress.write_all(&exact[..exact.len() - 1]).unwrap();
        progress.flush().unwrap();
    }
    assert_eq!(
        output,
        b"SIMULATION realtime: waiting for ciphertext notifications\n"
    );
}
