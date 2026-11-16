use super::*;

fn channel(remote: &str, ssh_agent: bool, signing: bool) -> GitChannel {
    GitChannel {
        root: PathBuf::from("/unused-private-cache"),
        remote: remote.into(),
        branch: "secure/team".into(),
        project: "fixture".into(),
        binding: vec![],
        signing_key_digest: None,
        options: GitOptions {
            ssh_agent,
            signing: signing.then(|| GitSigning::Ssh {
                public_key: PathBuf::from("/fixture-public-key.pub"),
            }),
            ..GitOptions::default()
        },
    }
}
fn has_agent(channel: &GitChannel, command: &str) -> bool {
    channel
        .command(&[command], Some("/fixture-agent.sock".into()))
        .get_envs()
        .any(|(key, value)| key == "SSH_AUTH_SOCK" && value.is_some())
}

#[test]
fn local_and_https_transport_never_inherit_agent_even_when_signing_opts_in() {
    for remote in ["/fixture/remote.git", "https://host.invalid/repo.git"] {
        let channel = channel(remote, true, true);
        for command in [
            "ls-remote",
            "fetch",
            "push",
            "config",
            "hash-object",
            "cat-file",
        ] {
            assert!(!has_agent(&channel, command));
        }
        assert!(has_agent(&channel, "commit-tree"));
    }
}
#[test]
fn ssh_agent_is_explicit_and_command_scoped() {
    assert!(!has_agent(
        &channel("ssh://git@host.invalid/repo", false, true),
        "fetch"
    ));
    assert!(!has_agent(
        &channel("ssh://git@host.invalid/repo", false, true),
        "commit-tree"
    ));
    assert!(has_agent(
        &channel("ssh://git@host.invalid/repo", true, false),
        "push"
    ));
    assert!(!has_agent(
        &channel("ssh://git@host.invalid/repo", true, false),
        "commit-tree"
    ));
}

#[test]
#[cfg(unix)]
fn a_transient_fork_cannot_keep_the_channel_locked_after_guard_release() {
    // Isolate the deliberate pre-exec delay so this regression cannot inherit
    // other concurrently running tests' unrelated vault/local-channel locks.
    if std::env::var_os("YHES_GIT_FORK_CHILD").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "git::options_tests::a_transient_fork_cannot_keep_the_channel_locked_after_guard_release", "--test-threads=1"])
            .env("YHES_GIT_FORK_CHILD", "1").output().unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let channel = GitChannel::open(
        &directory.path().join("cache"),
        "/fixture/unused-remote",
        "secure/team",
        "fixture",
    )
    .unwrap();
    let guard = channel.lock().unwrap();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // Async-signal-safe child body, no allocator or Rust runtime after fork.
        unsafe {
            libc::usleep(200_000);
            libc::_exit(0);
        }
    }
    drop(guard);
    let reacquired = channel.lock();
    unsafe {
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    assert!(reacquired.is_ok());
}
