//! Production signer transport: the YhesSigner app's local socket.
//!
//! The peer is identified by the kernel audit token of the connected socket
//! and Apple's code-signing validation of that exact process. A PID, a path,
//! the socket's file mode and the peer UID are not identity proof; the last
//! two are checked only as additional conditions.
use crate::{signer::Request, signer::SignerClient, signer::MAX_LINE, Failure};
use std::path::PathBuf;

pub const SIGNER_IDENTIFIER: &str = "com.agent-yhes.YhesSigner";
/// Compiled in by build.rs from `YHES_SIGNING_TEAM`. Never read at run time.
const PINNED_TEAM: Option<&str> = option_env!("YHES_PINNED_SIGNER_TEAM");

pub struct NativeSigner {
    team: Option<&'static str>,
}

fn unconfigured() -> Failure {
    Failure::new(
        "signer_unconfigured",
        "this build of yhes has no pinned signer team, so it cannot request human approval",
    )
    .hint("Use the signed helper inside YhesSigner.app, or rebuild with YHES_SIGNING_TEAM set.")
}

pub fn pinned_team() -> Option<&'static str> {
    PINNED_TEAM.filter(|team| {
        team.len() == 10
            && team
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    })
}

/// The requirement the connected signer process must satisfy.
pub fn signer_requirement(team: &str) -> String {
    format!(
        "anchor apple generic and identifier \"{SIGNER_IDENTIFIER}\" and certificate leaf[subject.OU] = \"{team}\""
    )
}

const CS_VALID: u32 = 0x0000_0001;
const CS_ADHOC: u32 = 0x0000_0002;
const CS_GET_TASK_ALLOW: u32 = 0x0000_0004;
const CS_RUNTIME: u32 = 0x0001_0000;
const CS_LINKER_SIGNED: u32 = 0x0002_0000;
const CS_DEBUGGED: u32 = 0x1000_0000;

/// Entitlements that let foreign or unsigned code run inside a process, or
/// let another process attach to it. A signer holding any of them is refused.
pub const FORBIDDEN_ENTITLEMENTS: [&str; 6] = [
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.disable-executable-page-protection",
];

/// Whether a peer with this signature (`signature_flags`), this live kernel
/// code-signing status and these entitlements may be treated as the signer,
/// once its code requirement has passed. `entitlement` returns `None` when
/// the entitlement is absent and `Some(false)` when it is explicitly denied.
pub fn hardened(
    signature_flags: u32,
    live_status: u32,
    entitlement: impl Fn(&str) -> Option<bool>,
) -> bool {
    hardened_signature(signature_flags, entitlement)
        && live_status & CS_VALID != 0
        && live_status & CS_RUNTIME != 0
        && live_status & (CS_ADHOC | CS_LINKER_SIGNED | CS_GET_TASK_ALLOW | CS_DEBUGGED) == 0
}

fn hardened_signature(flags: u32, entitlement: impl Fn(&str) -> Option<bool>) -> bool {
    flags & CS_RUNTIME != 0
        && flags & (CS_ADHOC | CS_LINKER_SIGNED) == 0
        && FORBIDDEN_ENTITLEMENTS
            .iter()
            .all(|name| entitlement(name) != Some(true))
}

/// Only temporary absence may trigger a launch or readiness retry. Identity or
/// permission failures never turn into a fallback to another process.
fn connect_or_start<T, G>(
    mut connect: impl FnMut() -> Result<T, Failure>,
    start: impl FnOnce() -> Result<G, Failure>,
    mut pause: impl FnMut(),
) -> Result<T, Failure> {
    match connect() {
        Ok(stream) => return Ok(stream),
        Err(e) if e.code == "signer_unavailable" => {}
        Err(e) => return Err(e),
    }
    let _launch_guard = start()?;
    for _ in 0..200 {
        match connect() {
            Ok(stream) => return Ok(stream),
            Err(e) if e.code == "signer_unavailable" => pause(),
            Err(e) => return Err(e),
        }
    }
    Err(Failure::new("signer_start_timeout","the signed signer app did not become reachable in time")
        .hint("Check the Yhes Signer window for a startup error, then retry. No signing request was sent."))
}

fn companion_app(executable: &std::path::Path) -> Result<PathBuf, Failure> {
    executable
        .ancestors()
        .find(|p| {
            p.extension().is_some_and(|x| x == "app")
                && p.join("Contents/MacOS/YhesSigner").is_file()
        })
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| {
            Failure::new(
                "signer_bundle_missing",
                "the engine helper has no enclosing signer app",
            )
            .hint("Use bin/yhes from the signed build; do not run a copied or unsigned helper.")
        })
}

impl NativeSigner {
    /// Commands that need no human approval still work in an unpinned build.
    pub fn production() -> Self {
        Self {
            team: pinned_team(),
        }
    }
    fn target(&self) -> Result<(PathBuf, &'static str), Failure> {
        let team = self.team.ok_or_else(unconfigured)?;
        Ok((
            crate::profile::application_support()?.join("signer.sock"),
            team,
        ))
    }
}

#[cfg(target_os = "macos")]
pub use imp::{check_peer_requirement, verify_peer};

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use crate::signer::Operation;
    use core_foundation::{
        base::{CFType, TCFType},
        boolean::CFBoolean,
        data::CFData,
        dictionary::{CFDictionary, CFDictionaryRef},
        number::CFNumber,
        string::{CFString, CFStringRef},
        url::CFURL,
    };
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
    };
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        os::{
            fd::AsRawFd,
            unix::{
                fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
                net::UnixStream,
            },
        },
        process::Command,
        time::{Duration, Instant},
    };

    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;

    fn unavailable() -> Failure {
        Failure::new(
            "signer_unavailable",
            "YhesSigner is not running or not reachable",
        )
        .hint("Run yhes doctor --start-signer to open and check the signed app. Pilot and say start it automatically.")
    }
    fn untrusted() -> Failure {
        Failure::new(
            "signer_untrusted",
            "the process listening on the signer socket is not the pinned YhesSigner app",
        )
        .hint(
            "Quit other programs using the agent-yhes folder and start the signed YhesSigner.app.",
        )
    }

    /// Additional conditions only. Identity comes from `verify_peer`.
    fn check_location(socket: &std::path::Path) -> Result<(), Failure> {
        let uid = unsafe { libc::getuid() };
        let directory = socket.parent().ok_or_else(unavailable)?;
        let d = std::fs::symlink_metadata(directory).map_err(|_| unavailable())?;
        if !d.is_dir() || d.uid() != uid || d.mode() & 0o077 != 0 {
            return Err(untrusted());
        }
        let s = std::fs::symlink_metadata(socket).map_err(|_| unavailable())?;
        if !s.file_type().is_socket() || s.uid() != uid {
            return Err(untrusted());
        }
        Ok(())
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecCodeCopySigningInformation(
            code: *const std::ffi::c_void,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> i32;
        static kSecCodeInfoFlags: CFStringRef;
        static kSecCodeInfoStatus: CFStringRef;
        static kSecCodeInfoEntitlementsDict: CFStringRef;
    }
    /// kSecCSSigningInformation | kSecCSDynamicInformation.
    const SIGNING_AND_DYNAMIC: u32 = (1 << 1) | (1 << 3);

    /// The code object of the process at the other end of a connected Unix
    /// socket. It is named by the kernel's audit token for this socket, so a
    /// recycled PID or a caller-supplied value cannot stand in.
    fn peer_code(stream: &UnixStream) -> Result<SecCode, Failure> {
        let fd = stream.as_raw_fd();
        let (mut uid, mut gid) = (0, 0);
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0
            || uid != unsafe { libc::getuid() }
        {
            return Err(untrusted());
        }
        // audit_token_t is eight 32-bit words, filled in by the kernel.
        let mut token = [0u32; 8];
        let mut length = std::mem::size_of_val(&token) as libc::socklen_t;
        let status = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if status != 0 || length as usize != std::mem::size_of_val(&token) {
            return Err(untrusted());
        }
        let bytes: Vec<u8> = token.iter().flat_map(|word| word.to_ne_bytes()).collect();
        let data = CFData::from_buffer(&bytes);
        let mut attributes = GuestAttributes::new();
        attributes.set_audit_token(data.as_concrete_TypeRef());
        SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE).map_err(|_| untrusted())
    }

    fn meets(code: &SecCode, requirement: &str) -> Result<(), Failure> {
        let requirement: SecRequirement = requirement
            .parse()
            .map_err(|_| Failure::new("internal", "cannot build the signer requirement"))?;
        code.check_validity(Flags::STRICT_VALIDATE, &requirement)
            .map_err(|_| untrusted())
    }

    /// Read real signature metadata. Dynamic status is required only for a live
    /// peer; a disk check never pretends to establish the identity of a process.
    fn hardening_of(code: *const std::ffi::c_void, live: bool) -> Result<(), Failure> {
        let mut raw: CFDictionaryRef = std::ptr::null();
        let status = unsafe {
            SecCodeCopySigningInformation(
                code,
                if live { SIGNING_AND_DYNAMIC } else { 1 << 1 },
                &mut raw,
            )
        };
        if status != 0 || raw.is_null() {
            return Err(untrusted());
        }
        let info: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_create_rule(raw) };
        let number = |key: CFStringRef| -> Option<u32> {
            let key = unsafe { CFString::wrap_under_get_rule(key) };
            let value = info.find(&key)?.downcast::<CFNumber>()?.to_i64()?;
            u32::try_from(value).ok()
        };
        let flags = number(unsafe { kSecCodeInfoFlags }).ok_or_else(untrusted)?;
        let entitlements = info
            .find(unsafe { CFString::wrap_under_get_rule(kSecCodeInfoEntitlementsDict) })
            .and_then(|value| value.downcast::<CFDictionary>());
        let entitlement = |name: &str| -> Option<bool> {
            let key = CFString::new(name);
            let value = entitlements.as_ref()?.find(key.as_CFTypeRef().cast())?;
            let value = unsafe { CFType::wrap_under_get_rule(*value) };
            // Anything that is not a plain `false` counts as granted.
            Some(value.downcast::<CFBoolean>().is_none_or(bool::from))
        };
        let valid = if live {
            hardened(
                flags,
                number(unsafe { kSecCodeInfoStatus }).ok_or_else(untrusted)?,
                entitlement,
            )
        } else {
            hardened_signature(flags, entitlement)
        };
        if valid {
            Ok(())
        } else {
            Err(untrusted())
        }
    }

    /// Only the code requirement. On its own this is NOT enough to trust a
    /// signer; it exists so tests can show which check refused a peer.
    pub fn check_peer_requirement(stream: &UnixStream, requirement: &str) -> Result<(), Failure> {
        meets(&peer_code(stream)?, requirement)
    }

    /// Full peer check: the code requirement, then hardened runtime and the
    /// absence of entitlements that let other code run inside the process.
    pub fn verify_peer(stream: &UnixStream, requirement: &str) -> Result<(), Failure> {
        let code = peer_code(stream)?;
        meets(&code, requirement)?;
        hardening_of(code.as_concrete_TypeRef().cast(), true)
    }

    fn connect(signer: &NativeSigner) -> Result<UnixStream, Failure> {
        let (socket, team) = signer.target()?;
        check_location(&socket)?;
        let stream = UnixStream::connect(&socket).map_err(|_| unavailable())?;
        // Nothing is written before the peer process is proven to be the signer.
        verify_peer(&stream, &signer_requirement(team))?;
        Ok(stream)
    }

    fn verified_companion(executable: &std::path::Path, team: &str) -> Result<PathBuf, Failure> {
        let app = companion_app(executable)?;
        let url = CFURL::from_path(&app, true).ok_or_else(untrusted)?;
        let code = SecStaticCode::from_path(&url, Flags::NONE).map_err(|_| untrusted())?;
        let requirement: SecRequirement =
            signer_requirement(team).parse().map_err(|_| untrusted())?;
        code.check_validity(Flags::STRICT_VALIDATE, &requirement)
            .map_err(|_| untrusted())?;
        hardening_of(code.as_concrete_TypeRef().cast(), false)?;
        Ok(app)
    }

    fn launch(signer: &NativeSigner) -> Result<File, Failure> {
        let (socket, team) = signer.target()?;
        let executable = std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .map_err(|_| unavailable())?;
        let app = verified_companion(&executable, team)?;

        let directory = socket.parent().ok_or_else(unavailable)?;
        crate::profile::private_dir(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("signer-launch.lock"))
            .map_err(|_| unavailable())?;
        let metadata = lock.metadata().map_err(|_| unavailable())?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::getuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(untrusted());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(unavailable());
            }
            if Instant::now() >= deadline {
                return Err(Failure::new(
                    "signer_start_busy",
                    "another client is starting the signer; retry shortly",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Another client may have finished startup while this caller waited.
        match connect(signer) {
            Ok(_) => return Ok(lock),
            Err(e) if e.code == "signer_unavailable" => {}
            Err(e) => return Err(e),
        }
        eprintln!("yhes: opening the signed YhesSigner app and waiting for its local connection");
        let status = Command::new("/usr/bin/open")
            .arg("-n")
            .arg(&app)
            .status()
            .map_err(|_| unavailable())?;
        if !status.success() {
            return Err(Failure::new(
                "signer_launch_failed",
                "macOS could not open the signed signer app",
            ));
        }
        Ok(lock)
    }

    fn ready(signer: &NativeSigner) -> Result<UnixStream, Failure> {
        connect_or_start(
            || connect(signer),
            || launch(signer),
            || std::thread::sleep(Duration::from_millis(50)),
        )
    }

    impl SignerClient for NativeSigner {
        fn probe(&self) -> Result<(), Failure> {
            connect(self).map(|_| ())
        }
        fn prepare(&self) -> Result<(), Failure> {
            ready(self).map(|_| ())
        }
        fn accepts(&self, algorithm: yhes_wire::Algorithm) -> bool {
            algorithm == yhes_wire::Algorithm::P256Sha256
        }
        fn exchange(&self, request: &Request) -> Result<Vec<u8>, Failure> {
            let line = request.encode()?;
            let mut stream = ready(self)?;
            let wait = match request.operation {
                Operation::Identity => 15,
                // The signer voids a review after 300 seconds.
                Operation::Enroll | Operation::Review => 330,
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(wait)))
                .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(15))))
                .map_err(|_| unavailable())?;
            stream.write_all(&line).map_err(|_| unavailable())?;
            let mut reply = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let n = stream.read(&mut chunk).map_err(|e| {
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) {
                        Failure::new("signer_timeout", "no answer from YhesSigner in time")
                            .hint("The pending review is void. Run the command again.")
                    } else {
                        unavailable()
                    }
                })?;
                if n == 0 {
                    break;
                }
                reply.extend_from_slice(&chunk[..n]);
                if reply.len() > MAX_LINE {
                    return Err(Failure::new(
                        "signer_reply_invalid",
                        "the signer sent an oversized reply",
                    ));
                }
                if reply.contains(&b'\n') {
                    break;
                }
            }
            if reply.is_empty() {
                return Err(Failure::new(
                    "signer_closed",
                    "YhesSigner closed the request without an answer",
                )
                .hint("The review was dropped. Run the command again."));
            }
            Ok(reply)
        }
    }
    #[cfg(test)]
    mod launch_tests {
        use super::*;
        #[test]
        fn an_unsigned_companion_is_refused_before_launch() {
            let temp = tempfile::tempdir().unwrap();
            let app = temp.path().join("YhesSigner.app");
            let executable = app.join("Contents/Helpers/Engine.app/Contents/MacOS/yhes");
            std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
            std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
            std::fs::write(app.join("Contents/MacOS/YhesSigner"), "not signed code").unwrap();
            assert_eq!(companion_app(&executable).unwrap(), app);
            assert_eq!(
                verified_companion(&executable, "25C9H9N953")
                    .unwrap_err()
                    .code,
                "signer_untrusted"
            );
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl SignerClient for NativeSigner {
    fn probe(&self) -> Result<(), Failure> {
        self.target().and(Err(Failure::new(
            "unsupported_platform",
            "the native signer exists only on macOS",
        )))
    }
    fn exchange(&self, _: &Request) -> Result<Vec<u8>, Failure> {
        self.probe().map(|_| Vec::new())
    }
    fn accepts(&self, algorithm: yhes_wire::Algorithm) -> bool {
        algorithm == yhes_wire::Algorithm::P256Sha256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED_RUNTIME: u32 = CS_RUNTIME;
    const LIVE: u32 = CS_VALID | CS_RUNTIME | 0x2000_0000;

    fn absent() -> Failure {
        Failure::new("signer_unavailable", "missing")
    }
    #[test]
    fn an_existing_verified_connection_needs_no_launch() {
        assert_eq!(
            connect_or_start(
                || Ok(17),
                || -> Result<(), Failure> { panic!("must not launch") },
                || panic!("must not wait")
            )
            .unwrap(),
            17
        );
    }
    #[test]
    fn missing_signer_launches_once_and_waits_for_readiness() {
        let mut calls = 0;
        let launches = std::cell::Cell::new(0);
        let waits = std::cell::Cell::new(0);
        let result = connect_or_start(
            || {
                calls += 1;
                if calls < 4 {
                    Err(absent())
                } else {
                    Ok(23)
                }
            },
            || {
                launches.set(launches.get() + 1);
                Ok(())
            },
            || waits.set(waits.get() + 1),
        );
        assert_eq!(result.unwrap(), 23);
        assert_eq!(launches.get(), 1);
        assert_eq!(waits.get(), 2);
    }
    #[test]
    fn untrusted_peer_never_triggers_launch_or_security_retry() {
        let bad = || Failure::new("signer_untrusted", "wrong identity");
        let result: Result<(), Failure> = connect_or_start(
            || Err(bad()),
            || -> Result<(), Failure> { panic!("must not launch") },
            || panic!("must not wait"),
        );
        assert_eq!(result.unwrap_err().code, "signer_untrusted");
        let mut calls = 0;
        let result: Result<(), Failure> = connect_or_start(
            || {
                calls += 1;
                Err(if calls == 1 { absent() } else { bad() })
            },
            || Ok(()),
            || panic!("must not retry identity failure"),
        );
        assert_eq!(result.unwrap_err().code, "signer_untrusted");
        assert_eq!(calls, 2);
    }
    #[test]
    fn failed_launch_and_readiness_timeout_return_without_a_request() {
        let result: Result<(), Failure> = connect_or_start(
            || Err(absent()),
            || Err::<(), _>(Failure::new("signer_launch_failed", "cannot launch")),
            || panic!("must not wait"),
        );
        assert_eq!(result.unwrap_err().code, "signer_launch_failed");
        let mut calls = 0;
        let waits = std::cell::Cell::new(0);
        let result: Result<(), Failure> = connect_or_start(
            || {
                calls += 1;
                Err(absent())
            },
            || Ok(()),
            || waits.set(waits.get() + 1),
        );
        assert_eq!(result.unwrap_err().code, "signer_start_timeout");
        assert_eq!(calls, 201);
        assert_eq!(waits.get(), 200);
    }
    #[test]
    fn a_detached_helper_does_not_search_for_an_app_on_path() {
        assert_eq!(
            companion_app(std::path::Path::new("/tmp/yhes"))
                .unwrap_err()
                .code,
            "signer_bundle_missing"
        );
    }

    #[test]
    fn a_hardened_release_passes() {
        assert!(hardened(SIGNED_RUNTIME, LIVE, |_| None));
        // An entitlement that is present and false grants nothing.
        assert!(hardened(SIGNED_RUNTIME, LIVE, |_| Some(false)));
    }

    #[test]
    fn missing_runtime_adhoc_debugging_and_task_access_are_refused() {
        assert!(!hardened(0, LIVE, |_| None));
        assert!(!hardened(SIGNED_RUNTIME, CS_VALID, |_| None));
        assert!(!hardened(SIGNED_RUNTIME, CS_RUNTIME, |_| None));
        assert!(!hardened(SIGNED_RUNTIME | CS_ADHOC, LIVE, |_| None));
        assert!(!hardened(SIGNED_RUNTIME | CS_LINKER_SIGNED, LIVE, |_| None));
        assert!(!hardened(SIGNED_RUNTIME, LIVE | CS_ADHOC, |_| None));
        assert!(!hardened(SIGNED_RUNTIME, LIVE | CS_GET_TASK_ALLOW, |_| {
            None
        }));
        assert!(!hardened(SIGNED_RUNTIME, LIVE | CS_DEBUGGED, |_| None));
    }

    #[test]
    fn each_forbidden_entitlement_is_refused_on_its_own() {
        assert_eq!(FORBIDDEN_ENTITLEMENTS.len(), 6);
        for forbidden in FORBIDDEN_ENTITLEMENTS {
            assert!(
                !hardened(SIGNED_RUNTIME, LIVE, |name| (name == forbidden)
                    .then_some(true)),
                "{forbidden}"
            );
        }
        assert!(hardened(SIGNED_RUNTIME, LIVE, |name| {
            (name == "com.apple.security.app-sandbox").then_some(true)
        }));
    }
}
