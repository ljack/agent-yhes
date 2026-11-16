//! Real local bare-Git integration. All identities, anchors, stores and remotes
//! are disposable fixtures; no user's repositories or platform custody are used.
include!("git_support/fixture.rs");
use std::{path::Path, process::Command};
use yhes_core::git::{GitChannel, GitCredentials, GitOptions, GitSigning};

struct Transport {
    directory: tempfile::TempDir,
    remote: PathBuf,
    a: GitChannel,
    b: GitChannel,
}
fn git_at(path: &Path, args: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .current_dir(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@invalid")
        .env("GIT_COMMITTER_NAME", "fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@invalid")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
impl Transport {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        git_at(&root, &["init", "--bare", "--template=", "remote.git"]);
        let remote = root.join("remote.git");
        let a = GitChannel::open(
            &root.join("a"),
            remote.to_str().unwrap(),
            "secure/team",
            "fixture",
        )
        .unwrap();
        let b = GitChannel::open(
            &root.join("b"),
            remote.to_str().unwrap(),
            "secure/team",
            "fixture",
        )
        .unwrap();
        Self {
            directory,
            remote,
            a,
            b,
        }
    }
    fn head(&self) -> String {
        git_at(&self.remote, &["rev-parse", "refs/heads/secure/team"])
    }
    fn pair(&self, w: &mut World) {
        let control = w.control(
            "create",
            "group.create",
            0,
            vec!["builder".into()],
            json!({}),
            None,
        );
        w.alice.e().create_group("create", control, NOW).unwrap();
        self.a.publish(w.alice.e(), "create", NOW).unwrap();
        let kp = w.bob.e().key_package("kp-reviewer", NOW).unwrap();
        let control = w.control("add-reviewer", "group.add", 0,
            vec!["builder".into(), "reviewer".into()],
            json!({"member":"reviewer","key_id":w.bob.identity.key_id,"key_package_digest":Digest::of(&kp).to_hex()}), Some(kp));
        w.alice
            .e()
            .change_membership("add-reviewer", control, NOW)
            .unwrap();
        self.a.publish(w.alice.e(), "add-reviewer", NOW).unwrap();
        let result = self.b.sync(w.bob.e(), GROUP, "builder", NOW).unwrap();
        assert_eq!(result.deliveries[0].disposition, "joined");
    }
    fn stage_message(&self, w: &mut World, operation: &str) -> Vec<u8> {
        let message = w.message(
            operation,
            "PRIVATE_GIT_FIXTURE_PLAINTEXT_78411",
            1,
            vec!["builder".into(), "reviewer".into()],
        );
        w.alice
            .e()
            .prepare_message(operation, GROUP, message, NOW)
            .unwrap()
    }
    fn hook(&self, name: &str, content: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.remote.join("hooks").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn editor(&self) -> PathBuf {
        let path = self.directory.path().join("editor");
        git_at(
            self.directory.path(),
            &[
                "clone",
                "--template=",
                "-b",
                "secure/team",
                self.remote.to_str().unwrap(),
                path.to_str().unwrap(),
            ],
        );
        path
    }
    fn commit_editor(&self, path: &Path) {
        git_at(path, &["add", "--all"]);
        git_at(path, &["commit", "-m", "untrusted remote fixture"]);
        git_at(path, &["push", "origin", "HEAD:refs/heads/secure/team"]);
    }
    fn append_packet_without_local_ack(&self, packet: &[u8]) {
        let editor = self.editor();
        let mut names = fs::read_dir(editor.join("records"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        names.sort();
        let previous = names.last().map(|name| name[21..85].to_owned());
        let sequence = names.len() as u64 + 1;
        let record = serde_json::to_vec(&json!({"version":1,"project":"fixture","sequence":sequence,"previous":previous,"packet":STANDARD.encode(packet)})).unwrap();
        fs::write(
            editor.join(format!(
                "records/{sequence:020}_{}.json",
                Digest::of(&record).to_hex()
            )),
            record,
        )
        .unwrap();
        self.commit_editor(&editor);
    }
}

#[test]
fn public_artifacts_are_immutable_and_cache_binding_is_explicit() {
    let t = Transport::new();
    assert!(t.a.fetch_public().unwrap().artifacts.is_empty());
    let p =
        t.a.publish_public("registry-1.json", b"public signed registry fixture")
            .unwrap();
    assert!(!p.replayed);
    assert_eq!(
        t.b.read_public("registry-1.json").unwrap().unwrap(),
        b"public signed registry fixture"
    );
    assert!(
        t.b.publish_public("registry-1.json", b"public signed registry fixture")
            .unwrap()
            .replayed
    );
    assert!(t
        .b
        .publish_public("registry-1.json", b"replacement")
        .is_err());
    assert_eq!(t.head(), p.commit);
    assert!(GitChannel::open(
        &t.directory.path().join("a"),
        t.remote.to_str().unwrap(),
        "another",
        "fixture"
    )
    .is_err());
    assert!(t.b.publish_public("../vault.db", b"secret").is_err());
}

#[test]
fn real_git_handshake_message_retry_restart_and_no_plaintext_objects() {
    let t = Transport::new();
    let mut w = World::new();
    t.pair(&mut w);
    let ciphertext = t.stage_message(&mut w, "message-1");
    let publication = t.a.publish(w.alice.e(), "message-1", NOW).unwrap();
    assert_eq!(publication.sequence, 3);
    assert!(!publication.replayed);
    let head = t.head();
    assert!(t.a.publish(w.alice.e(), "message-1", NOW).unwrap().replayed);
    assert_eq!(t.head(), head);
    let result = t.b.sync(w.bob.e(), GROUP, "builder", NOW).unwrap();
    assert_eq!(result.deliveries.len(), 1);
    assert_eq!(result.deliveries[0].disposition, "verified");
    w.bob.restart(&w.root);
    assert!(t
        .b
        .sync(w.bob.e(), GROUP, "builder", NOW)
        .unwrap()
        .deliveries
        .is_empty());
    assert_eq!(w.alice.e().stored_packet("message-1").unwrap(), ciphertext);
    let object_ids = git_at(
        &t.remote,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ],
    );
    for object in object_ids.lines() {
        let output = Command::new("/usr/bin/git")
            .current_dir(&t.remote)
            .args(["cat-file", "-p", object])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        for forbidden in [
            "PRIVATE_GIT_FIXTURE_PLAINTEXT_78411",
            "vault.db",
            "storage_key",
            "private_key",
        ] {
            assert!(!text.contains(forbidden), "private data in Git object");
        }
    }
}

#[test]
fn current_clock_prevents_unseen_expired_join() {
    let t = Transport::new();
    let mut w = World::new();
    let control = w.control(
        "create",
        "group.create",
        0,
        vec!["builder".into()],
        json!({}),
        None,
    );
    w.alice.e().create_group("create", control, NOW).unwrap();
    t.a.publish(w.alice.e(), "create", NOW).unwrap();
    assert!(t.b.sync(w.bob.e(), GROUP, "builder", NOW + 301).is_err());
    assert!(w.bob.e().group_status(GROUP).unwrap().is_none());
}

#[test]
fn lost_push_ack_reconciles_exact_packet_without_second_commit() {
    let t = Transport::new();
    let mut w = World::new();
    t.pair(&mut w);
    let original = t.stage_message(&mut w, "uncertain");
    // Simulate the durable remote side of a lost acknowledgment, without using
    // executable local-remote hooks (which the production adapter forbids).
    t.append_packet_without_local_ack(&original);
    assert_eq!(
        w.alice.e().outbox().unwrap().last().unwrap().status,
        "prepared"
    );
    let head = t.head();
    assert!(t.a.publish(w.alice.e(), "uncertain", NOW).unwrap().replayed);
    assert_eq!(t.head(), head);
    assert_eq!(w.alice.e().stored_packet("uncertain").unwrap(), original);
}

#[test]
fn rejected_push_keeps_pending_membership_and_approval_consumed() {
    let t = Transport::new();
    let mut w = World::new();
    t.pair(&mut w);
    let kp = w.carol.e().key_package("kp-third", NOW).unwrap();
    let control = w.control("add-third", "group.add", 1,
        vec!["builder".into(), "reviewer".into(), "third".into()],
        json!({"member":"third","key_id":w.carol.identity.key_id,"key_package_digest":Digest::of(&kp).to_hex()}), Some(kp));
    let original = w
        .alice
        .e()
        .change_membership("add-third", control, NOW)
        .unwrap();
    let head = t.head();
    let blocked_ref = t.remote.join("refs/heads/secure/team.lock");
    fs::write(&blocked_ref, b"fixture transaction holds remote ref").unwrap();
    assert!(t.a.publish(w.alice.e(), "add-third", NOW).is_err());
    assert_eq!(t.head(), head);
    let state = w.alice.e().group_status(GROUP).unwrap().unwrap();
    assert_eq!(state.epoch, 1);
    assert_eq!(state.pending_operation.as_deref(), Some("add-third"));
    assert_eq!(w.alice.e().stored_packet("add-third").unwrap(), original);
    fs::remove_file(blocked_ref).unwrap();
    t.a.publish(w.alice.e(), "add-third", NOW).unwrap();
    assert_eq!(w.alice.e().group_status(GROUP).unwrap().unwrap().epoch, 2);
}

#[test]
fn protected_cursor_rejects_remote_rollback_and_deleted_branch() {
    let t = Transport::new();
    let mut w = World::new();
    t.pair(&mut w);
    let head = t.head();
    let previous = git_at(&t.remote, &["rev-parse", &format!("{head}^")]);
    git_at(
        &t.remote,
        &["update-ref", "refs/heads/secure/team", &previous],
    );
    assert!(t.b.sync(w.bob.e(), GROUP, "builder", NOW).is_err());
    git_at(&t.remote, &["update-ref", "-d", "refs/heads/secure/team"]);
    assert!(t.b.sync(w.bob.e(), GROUP, "builder", NOW).is_err());
}

#[test]
fn same_records_on_rewritten_git_ancestry_do_not_bypass_protected_cursor() {
    let t = Transport::new();
    let mut w = World::new();
    t.pair(&mut w);
    let editor = t.editor();
    let original = t.head();
    git_at(
        &editor,
        &["commit", "--amend", "-m", "rewritten ordering evidence"],
    );
    let rewritten = git_at(&editor, &["rev-parse", "HEAD"]);
    assert_ne!(rewritten, original);
    assert_eq!(
        git_at(&editor, &["rev-parse", "HEAD^{tree}"]),
        git_at(&t.remote, &["rev-parse", &format!("{original}^{{tree}}")])
    );
    git_at(
        &editor,
        &["push", "origin", "HEAD:refs/heads/hostile-fixture"],
    );
    git_at(
        &t.remote,
        &["update-ref", "refs/heads/secure/team", &rewritten],
    );
    let relocated = GitChannel::open(
        &t.directory.path().join("relocated-cache"),
        t.remote.to_str().unwrap(),
        "secure/team",
        "fixture",
    )
    .unwrap();
    assert!(relocated.sync(w.bob.e(), GROUP, "builder", NOW).is_err());
}

#[test]
fn oversize_remote_blob_is_refused_before_blob_read_or_delivery() {
    let t = Transport::new();
    t.a.publish_public("registry-1.json", b"public registry")
        .unwrap();
    let editor = t.editor();
    fs::write(
        editor.join("public/oversize.json"),
        vec![b'x'; 2 * 1024 * 1024 + 1],
    )
    .unwrap();
    t.commit_editor(&editor);
    assert!(t.b.fetch_public().is_err());
}

#[test]
fn source_worktree_index_and_refs_are_untouched() {
    if std::env::var_os("YHES_GIT_ISOLATION_CHILD").is_some() {
        let t = Transport::new();
        t.a.publish_public("bootstrap.json", b"public bootstrap")
            .unwrap();
        assert!(!t.directory.path().join("a/repository.git/index").exists());
        return;
    }
    let t = Transport::new();
    let source = t.directory.path().join("source");
    fs::create_dir(&source).unwrap();
    git_at(&source, &["init", "--template="]);
    fs::write(source.join("tracked"), "original").unwrap();
    git_at(&source, &["add", "tracked"]);
    git_at(&source, &["commit", "-m", "fixture"]);
    fs::write(source.join("tracked"), "staged").unwrap();
    git_at(&source, &["add", "tracked"]);
    fs::write(source.join("tracked"), "unstaged").unwrap();
    let index = fs::read(source.join(".git/index")).unwrap();
    let refs = git_at(&source, &["show-ref"]);
    // Inject all common source-repository environment overrides into a separate
    // test process, avoiding process-global environment races in this suite.
    let output = Command::new(std::env::current_exe().unwrap())
        .current_dir(&source)
        .args([
            "--exact",
            "source_worktree_index_and_refs_are_untouched",
            "--nocapture",
        ])
        .env("YHES_GIT_ISOLATION_CHILD", "1")
        .env("GIT_DIR", source.join(".git"))
        .env("GIT_WORK_TREE", &source)
        .env("GIT_INDEX_FILE", source.join(".git/index"))
        .env("GIT_OBJECT_DIRECTORY", source.join(".git/objects"))
        .env(
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            source.join(".git/objects"),
        )
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", source.join(".git/hooks"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(source.join(".git/index")).unwrap(), index);
    assert_eq!(
        fs::read_to_string(source.join("tracked")).unwrap(),
        "unstaged"
    );
    assert_eq!(git_at(&source, &["show-ref"]), refs);
    assert!(!t.directory.path().join("a/repository.git/index").exists());
}

#[test]
fn edited_or_deleted_remote_artifacts_fail_full_history_validation() {
    for delete in [false, true] {
        let t = Transport::new();
        t.a.publish_public("registry-1.json", b"original public data")
            .unwrap();
        let editor = t.editor();
        let file = editor.join("public/registry-1.json");
        if delete {
            fs::remove_file(file).unwrap();
        } else {
            fs::write(file, "replacement public data").unwrap();
        }
        t.commit_editor(&editor);
        assert!(t.b.fetch_public().is_err());
    }
}

#[test]
fn unexpected_files_executables_and_symlinks_fail_before_delivery() {
    use std::os::unix::fs::PermissionsExt;
    for kind in ["unexpected", "executable", "symlink"] {
        let t = Transport::new();
        t.a.publish_public("registry-1.json", b"public").unwrap();
        let editor = t.editor();
        let path = editor.join(if kind == "unexpected" {
            "vault.db"
        } else {
            "public/evil.json"
        });
        if kind == "symlink" {
            std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
        } else {
            fs::write(&path, "untrusted data").unwrap();
        }
        if kind == "executable" {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        t.commit_editor(&editor);
        assert!(t.b.fetch_public().is_err());
    }
}

#[test]
fn invalid_ciphertext_signature_never_creates_trusted_inbox_record() {
    let t = Transport::new();
    let mut w = World::new();
    t.pair(&mut w);
    let original = t.stage_message(&mut w, "forged");
    let mut packet: Value = serde_json::from_slice(&original).unwrap();
    packet["ciphertext"] = json!(STANDARD.encode(b"forged ciphertext"));
    let forged = serde_json::to_vec(&packet).unwrap();
    let editor = t.editor();
    let mut names = fs::read_dir(editor.join("records"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    names.sort();
    let previous = names.last().unwrap()[21..85].to_owned();
    let record = serde_json::to_vec(&json!({"version":1,"project":"fixture","sequence":3,"previous":previous,"packet":STANDARD.encode(forged)})).unwrap();
    fs::write(
        editor.join(format!(
            "records/{:020}_{}.json",
            3,
            Digest::of(&record).to_hex()
        )),
        record,
    )
    .unwrap();
    t.commit_editor(&editor);
    let before = w.bob.e().inbox().unwrap().len();
    assert!(t.b.sync(w.bob.e(), GROUP, "builder", NOW).is_err());
    assert_eq!(w.bob.e().inbox().unwrap().len(), before);
    assert_eq!(
        w.alice.e().outbox().unwrap().last().unwrap().status,
        "prepared"
    );
}

#[test]
fn concurrent_publications_never_force_push_or_lose_an_existing_artifact() {
    let t = Transport::new();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            t.a.publish_public("alice.json", b"alice public")
        });
        let b = scope.spawn(|| {
            barrier.wait();
            t.b.publish_public("bob.json", b"bob public")
        });
        let a = a.join().unwrap();
        let b = b.join().unwrap();
        assert!(a.is_ok() || b.is_ok());
    });
    t.a.publish_public("alice.json", b"alice public").unwrap();
    t.b.publish_public("bob.json", b"bob public").unwrap();
    let artifacts = t.a.fetch_public().unwrap().artifacts;
    assert_eq!(artifacts.len(), 2);
    assert_eq!(artifacts["alice.json"], b"alice public");
    assert_eq!(artifacts["bob.json"], b"bob public");
    assert_eq!(
        git_at(
            &t.remote,
            &["rev-list", "--count", "refs/heads/secure/team"]
        ),
        "2"
    );
}

#[test]
fn reverse_direction_message_preserves_second_person_identity() {
    let t = Transport::new();
    let mut w = World::new();
    t.pair(&mut w);
    let grant = w.grant(&w.bob.identity);
    let event = World::event(
        &w.bob.identity,
        "reply",
        Body::AgentMessage {
            text: "reviewer reply".into(),
        },
        vec!["builder".into(), "reviewer".into()],
        1,
        &grant,
    );
    let content = w
        .bob
        .e()
        .sign_event(event, Some(grant), None, None, NOW)
        .unwrap();
    w.bob
        .e()
        .prepare_message("reply", GROUP, content, NOW)
        .unwrap();
    t.b.publish(w.bob.e(), "reply", NOW).unwrap();
    let result = t.a.sync(w.alice.e(), GROUP, "builder", NOW).unwrap();
    let message = result.deliveries.last().unwrap().message.as_ref().unwrap();
    assert_eq!(message.author, "reviewer");
    assert_eq!(message.event_id, "reply");
    assert!(!message.human_authored);
}

#[test]
fn checked_public_apis_reject_rollback_and_do_not_advance_ahead_of_sync() {
    let t = Transport::new();
    let mut w = World::new();
    t.pair(&mut w);
    let original = t.head();
    let binding = serde_json::to_vec(&(
        "yhes-git-v1",
        t.remote.to_str().unwrap(),
        "secure/team",
        "fixture",
    ))
    .unwrap();
    let key = format!("git-{}", Digest::of(&binding).to_hex());
    let checkpoint = w.alice.e().client_get(&key).unwrap();
    t.a.publish_public_checked(w.alice.e(), "registry-2.json", b"signed registry fixture")
        .unwrap();
    t.a.fetch_public_checked(w.alice.e()).unwrap();
    t.a.read_public_checked(w.alice.e(), "registry-2.json")
        .unwrap();
    assert_eq!(
        w.alice.e().client_get(&key).unwrap(),
        checkpoint,
        "public APIs must not checkpoint ahead of application sync"
    );
    t.a.sync(w.alice.e(), GROUP, "builder", NOW).unwrap();
    assert_ne!(w.alice.e().client_get(&key).unwrap(), checkpoint);
    git_at(
        &t.remote,
        &["update-ref", "refs/heads/secure/team", &original],
    );
    assert!(t.a.fetch_public_checked(w.alice.e()).is_err());
    assert!(t
        .a
        .read_public_checked(w.alice.e(), "registry-2.json")
        .is_err());
    assert!(t
        .a
        .publish_public_checked(w.alice.e(), "registry-3.json", b"next registry")
        .is_err());
    assert_eq!(t.head(), original);
    assert!(
        t.a.fetch_public().is_ok(),
        "pretrust API supplies only untrusted structural data"
    );
}

#[test]
fn own_prepared_membership_found_after_expiry_stays_pending_without_timing_proof() {
    let t = Transport::new();
    let mut w = World::new();
    t.pair(&mut w);
    let kp = w.carol.e().key_package("kp-third", NOW).unwrap();
    let control = w.control("uncertain-add", "group.add", 1, vec!["builder".into(), "reviewer".into(), "third".into()],
        json!({"member":"third","key_id":w.carol.identity.key_id,"key_package_digest":Digest::of(&kp).to_hex()}), Some(kp));
    let packet = w
        .alice
        .e()
        .change_membership("uncertain-add", control, NOW)
        .unwrap();
    t.append_packet_without_local_ack(&packet);
    let head = t.head();
    assert!(t
        .a
        .publish(w.alice.e(), "uncertain-add", NOW + 301)
        .is_err());
    let state = w.alice.e().group_status(GROUP).unwrap().unwrap();
    assert_eq!(state.epoch, 1);
    assert_eq!(state.pending_operation.as_deref(), Some("uncertain-add"));
    assert_eq!(w.alice.e().stored_packet("uncertain-add").unwrap(), packet);
    assert_eq!(t.head(), head);
}

#[test]
fn local_remote_executable_hooks_and_custom_hook_configuration_are_refused() {
    let t = Transport::new();
    let marker = t.directory.path().join("hook-ran");
    t.hook(
        "pre-receive.sample",
        &format!("#!/bin/sh\nprintf no > '{}'\n", marker.display()),
    );
    assert!(t.a.fetch_public().is_ok());
    assert!(!marker.exists());
    t.hook(
        "pre-receive",
        &format!("#!/bin/sh\nprintf no > '{}'\n", marker.display()),
    );
    assert!(t.a.publish_public("public.json", b"public data").is_err());
    assert!(!marker.exists());
    fs::remove_file(t.remote.join("hooks/pre-receive")).unwrap();
    git_at(
        &t.remote,
        &["config", "core.hooksPath", "/untrusted/custom/hooks"],
    );
    assert!(t.a.fetch_public().is_err());
    git_at(&t.remote, &["config", "--unset", "core.hooksPath"]);
    git_at(
        &t.remote,
        &["config", "include.path", "/untrusted/custom/config"],
    );
    assert!(t.a.fetch_public().is_err());
    assert!(!marker.exists());
}

#[test]
fn url_credentials_queries_and_fragments_are_never_stored() {
    let directory = tempfile::tempdir().unwrap();
    for remote in [
        "https://user:fixture-password@host.invalid/repo",
        "https://user@host.invalid/repo",
        "https://user%40host.invalid/repo",
        "https://host.invalid/repo?token=fixture",
        "https://host.invalid/repo#fixture",
        "ssh://git:fixture-password@host.invalid/repo",
        "ssh://git@host.invalid/repo?fixture",
        "ssh://git@host.invalid/repo#fixture",
    ] {
        let cache = directory.path().join("must-not-exist");
        assert!(GitChannel::open(&cache, remote, "secure/team", "fixture").is_err());
        assert!(!cache.exists());
    }
}

#[test]
fn typed_git_options_bind_cache_and_reject_arbitrary_signer_or_helper_inputs() {
    let t = Transport::new();
    let options = GitOptions {
        author_name: "Fixture author".into(),
        author_email: "fixture@example.invalid".into(),
        ..GitOptions::default()
    };
    assert!(GitChannel::open_with_options(
        &t.directory.path().join("a"),
        t.remote.to_str().unwrap(),
        "secure/team",
        "fixture",
        options.clone()
    )
    .is_err());
    assert_eq!(
        serde_json::from_slice::<GitOptions>(&serde_json::to_vec(&options).unwrap()).unwrap(),
        options
    );
    assert!(serde_json::from_str::<GitCredentials>("\"!arbitrary-command\"").is_err());
    let bad = GitOptions {
        signing: Some(GitSigning::OpenPgp {
            fingerprint: "--homedir=/untrusted".into(),
        }),
        ..options
    };
    assert!(GitChannel::open_with_options(
        &t.directory.path().join("other"),
        t.remote.to_str().unwrap(),
        "secure/team",
        "fixture",
        bad
    )
    .is_err());
}

#[test]
fn disposable_ssh_agent_signs_commit_with_explicit_options() {
    if let Some(public_key) = std::env::var_os("YHES_FIXTURE_SIGN_PUBLIC") {
        let t = Transport::new();
        let options = GitOptions {
            author_name: "Fixture signer".into(),
            author_email: "signer@example.invalid".into(),
            signing: Some(GitSigning::Ssh {
                public_key: PathBuf::from(&public_key),
            }),
            ssh_agent: true,
            ..GitOptions::default()
        };
        let signed = GitChannel::open_with_options(
            &t.directory.path().join("signed"),
            t.remote.to_str().unwrap(),
            "secure/team",
            "fixture",
            options.clone(),
        )
        .unwrap();
        let publication = signed
            .publish_public("signed.json", b"public signed artifact")
            .unwrap();
        let commit = git_at(&t.remote, &["cat-file", "commit", &publication.commit]);
        assert!(commit.contains("gpgsig -----BEGIN SSH SIGNATURE-----"));
        assert!(commit.contains("author Fixture signer <signer@example.invalid>"));
        let allowed = t.directory.path().join("allowed-signers");
        fs::write(
            &allowed,
            format!(
                "signer@example.invalid {}",
                fs::read_to_string(&public_key).unwrap()
            ),
        )
        .unwrap();
        git_at(
            &t.remote,
            &[
                "-c",
                "gpg.format=ssh",
                "-c",
                &format!("gpg.ssh.allowedSignersFile={}", allowed.display()),
                "verify-commit",
                &publication.commit,
            ],
        );
        assert!(!t
            .directory
            .path()
            .join("signed/repository.git/index")
            .exists());
        // Without opt-in, a public-key-only path cannot use the otherwise
        // available fixture agent. The temporary private key was deleted.
        let denied_options = GitOptions {
            ssh_agent: false,
            ..options
        };
        let denied = GitChannel::open_with_options(
            &t.directory.path().join("denied"),
            t.remote.to_str().unwrap(),
            "secure/team",
            "fixture",
            denied_options,
        )
        .unwrap();
        assert!(denied.publish_public("denied.json", b"public").is_err());
        assert_eq!(t.head(), publication.commit);
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("fixture-key");
    let output = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f", key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let socket = directory.path().join("agent.sock");
    let mut agent = Command::new("/usr/bin/ssh-agent")
        .env_clear()
        .args(["-D", "-a", socket.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let added = Command::new("/usr/bin/ssh-add")
        .env_clear()
        .env("SSH_AUTH_SOCK", &socket)
        .env("APPLE_SSH_ADD_BEHAVIOR", "openssh")
        .arg(&key)
        .output()
        .unwrap();
    if !added.status.success() {
        let _ = agent.kill();
        let _ = agent.wait();
        panic!("fixture-only ssh-add failed");
    }
    fs::remove_file(&key).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "disposable_ssh_agent_signs_commit_with_explicit_options",
            "--nocapture",
        ])
        .env("SSH_AUTH_SOCK", &socket)
        .env("YHES_FIXTURE_SIGN_PUBLIC", key.with_extension("pub"))
        .output()
        .unwrap();
    let _ = agent.kill();
    let _ = agent.wait();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn untrusted_remote_configuration_and_cache_symlinks_are_refused() {
    let root = tempfile::tempdir().unwrap();
    for remote in [
        "origin",
        "-x",
        "ext::sh -c echo",
        "file://remote",
        "https://host/\ncommand",
    ] {
        assert!(
            GitChannel::open(&root.path().join("cache"), remote, "secure/team", "fixture").is_err()
        );
    }
    for branch in ["--help", "../main", "a.lock", "a//b", ".hidden", "a@{1}"] {
        assert!(GitChannel::open(
            &root.path().join("cache"),
            "/tmp/fixture",
            branch,
            "fixture"
        )
        .is_err());
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.path(), root.path().join("symlink")).unwrap();
        assert!(GitChannel::open(
            &root.path().join("symlink"),
            "/tmp/fixture",
            "secure/team",
            "fixture"
        )
        .is_err());
    }
}
