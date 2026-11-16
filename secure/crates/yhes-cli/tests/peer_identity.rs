//! The real macOS peer check: kernel audit token of a connected socket, then
//! Apple's code-signing validation of that process. No signer app, key or
//! enrollment is involved; the peers are this test and `/usr/bin/nc`.
#![cfg(target_os = "macos")]
use std::{
    os::unix::net::{UnixListener, UnixStream},
    process::{Command, Stdio},
};
use yhes_cli::native::{check_peer_requirement, signer_requirement, verify_peer};

fn socket() -> (tempfile::TempDir, std::path::PathBuf) {
    // Unix socket paths are short; the default temp folder can be too deep.
    let directory = tempfile::Builder::new()
        .prefix("yh")
        .tempdir_in("/tmp")
        .unwrap();
    let path = directory.path().join("s");
    (directory, path)
}

const TEAM: &str = "25C9H9N953";

#[test]
fn identity_without_hardened_runtime_is_not_enough() {
    // `/usr/bin/nc` is validly Apple-signed but has no hardened runtime.
    let (_directory, path) = socket();
    let listener = UnixListener::bind(&path).unwrap();
    let mut child = Command::new("/usr/bin/nc")
        .arg("-U")
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let (peer, _) = listener.accept().unwrap();
    let own = "anchor apple and identifier \"com.apple.nc\"";
    // The audit token resolves to the real process and its requirement holds...
    let requirement_only = check_peer_requirement(&peer, own);
    // ...but the full check refuses it for lacking the hardened runtime.
    let full = verify_peer(&peer, own);
    let as_signer = verify_peer(&peer, &signer_requirement(TEAM));
    let other = check_peer_requirement(&peer, "anchor apple and identifier \"com.apple.cat\"");
    drop(peer);
    let _ = child.kill();
    let _ = child.wait();
    requirement_only.expect("nc is an Apple-signed platform binary");
    assert_eq!(full.unwrap_err().code, "signer_untrusted");
    assert_eq!(as_signer.unwrap_err().code, "signer_untrusted");
    assert_eq!(other.unwrap_err().code, "signer_untrusted");
}

#[test]
fn a_hardened_apple_process_passes_the_full_check_for_its_own_identity_only() {
    // `/usr/bin/ssh-agent` is Apple-signed with the hardened runtime and none
    // of the forbidden entitlements. It serves a Unix socket in the foreground.
    let (_directory, path) = socket();
    let mut child = Command::new("/usr/bin/ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut client = None;
    for _ in 0..100 {
        if let Ok(stream) = UnixStream::connect(&path) {
            client = Some(stream);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let client = client.expect("ssh-agent socket");
    let own = verify_peer(
        &client,
        "anchor apple and identifier \"com.apple.ssh-agent\"",
    );
    let as_signer = verify_peer(&client, &signer_requirement(TEAM));
    drop(client);
    let _ = child.kill();
    let _ = child.wait();
    own.expect("hardened Apple-signed peer passes requirement and hardening");
    // Hardened and Apple-signed, but not the pinned signer identity and team.
    assert_eq!(as_signer.unwrap_err().code, "signer_untrusted");
}

#[test]
fn an_unsigned_same_user_process_is_not_the_signer() {
    // This test binary listens on the socket itself: same user, private
    // folder, correct socket type. None of that is identity.
    let (_directory, path) = socket();
    let listener = UnixListener::bind(&path).unwrap();
    let client = UnixStream::connect(&path).unwrap();
    let _server = listener.accept().unwrap();
    let failure = verify_peer(&client, &signer_requirement(TEAM)).unwrap_err();
    assert_eq!(failure.code, "signer_untrusted");
}
