//! Private profile state. It lives outside the shared project, in the user's
//! application-support directory. Shared project files never select trust.
use crate::{signer::Descriptor, Custody, Failure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use yhes_core::{engine::Engine, store::Vault, trust::ProjectTrust};

pub const GROUP: &str = "team";
pub const OWNER: &str = "codex";
pub const AGENTS: [&str; 2] = ["claude", "codex"];

/// `~/Library/Application Support/agent-yhes`, from the password database
/// rather than `$HOME`.
pub fn application_support() -> Result<PathBuf, Failure> {
    let mut buffer = vec![0u8; 16384];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() || entry.pw_dir.is_null() {
        return Err(Failure::new(
            "internal",
            "cannot find the user's home directory",
        ));
    }
    let home = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }
        .to_str()
        .map_err(|_| Failure::new("internal", "home directory is not UTF-8"))?
        .to_owned();
    Ok(PathBuf::from(home).join("Library/Application Support/agent-yhes"))
}

pub fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && !s.contains("..")
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

/// How the CLI finds its pinned trust again. The vault's own trust fingerprint
/// is the enforced pin; a modified copy of this file makes the vault refuse.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub version: u8,
    pub project_id: String,
    pub project_path: String,
    pub human: String,
    pub group: String,
    pub owner: String,
    pub agents: Vec<String>,
    pub authority: Descriptor,
}

pub struct Workspace {
    pub project_root: PathBuf,
    pub private: PathBuf,
    hash: String,
}

pub(crate) fn private_dir(path: &Path) -> Result<(), Failure> {
    let bad = || {
        Failure::new(
            "private_state",
            "the private agent-yhes folder is not a private directory owned by this user",
        )
        .hint("Check ~/Library/Application Support/agent-yhes: it must be a real directory with mode 0700.")
    };
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_dir()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o077 != 0
            {
                return Err(bad());
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| bad()),
        Err(_) => Err(bad()),
    }
}

impl Workspace {
    /// `private_root` is the engine's private directory. Its parent must exist
    /// or be creatable; every level this code creates is mode 0700.
    /// Only `create` (setup) makes directories; other commands change nothing.
    pub fn locate(private_root: &Path, project: &Path, create: bool) -> Result<Self, Failure> {
        let project_root = project.canonicalize().map_err(|_| {
            Failure::new(
                "project_not_found",
                "the --project directory does not exist",
            )
        })?;
        if !project_root.is_dir() {
            return Err(Failure::new(
                "project_not_found",
                "--project must be a directory",
            ));
        }
        let text = project_root.to_str().ok_or_else(|| {
            Failure::new("project_not_found", "the project path must be valid UTF-8")
        })?;
        let hash: String = Sha256::digest(text.as_bytes())
            .iter()
            .take(16)
            .map(|b| format!("{b:02x}"))
            .collect();
        if create {
            if let Some(parent) = private_root.parent() {
                if fs::symlink_metadata(parent).is_err() {
                    private_dir(parent)?;
                }
            }
            private_dir(private_root)?;
        }
        // Before setup the folder may not exist; then there is simply no pin.
        let root = private_root
            .canonicalize()
            .unwrap_or_else(|_| private_root.to_path_buf());
        let private = root.join(&hash);
        Ok(Self {
            project_root,
            private,
            hash,
        })
    }
    fn pin_path(&self) -> PathBuf {
        self.private.join("pin.json")
    }
    pub fn pin(&self) -> Result<Option<Pin>, Failure> {
        let path = self.pin_path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Failure::new("private_state", "cannot read the local pin")),
        };
        let invalid = || {
            Failure::new(
                "pin_invalid",
                "the local trust pin for this project is damaged",
            )
            .hint("Do not edit it. The vaults still hold the real pin; ask for recovery.")
        };
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(invalid());
        }
        let pin: Pin = serde_json::from_slice(&fs::read(&path).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        if pin.version != 1
            || !valid_id(&pin.project_id)
            || !valid_id(&pin.human)
            || pin.agents.iter().any(|a| !agent_name(a))
            || pin.authority.project != pin.project_id
            || pin.authority.author != pin.human
            || pin.authority.key().is_err()
        {
            return Err(invalid());
        }
        Ok(Some(pin))
    }
    /// Written once. An existing pin is never replaced.
    pub fn write_pin(&self, pin: &Pin) -> Result<(), Failure> {
        private_dir(&self.private)?;
        let failed = || Failure::new("private_state", "cannot store the local pin");
        let bytes = serde_json::to_vec_pretty(pin).map_err(|_| failed())?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.pin_path())
            .map_err(|_| failed())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| failed())
    }
    /// One Keychain reference per project path and agent, shared by the vault
    /// key and its checkpoint.
    pub fn account(&self, agent: &str) -> String {
        format!("p{}-{agent}", self.hash)
    }
    pub fn vault_path(&self, agent: &str) -> PathBuf {
        self.private.join(agent).join("vault.db")
    }
    pub fn vault_exists(&self, agent: &str) -> bool {
        fs::symlink_metadata(self.vault_path(agent)).is_ok()
    }
}

/// Agent names double as Keychain account and directory components.
pub fn agent_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}

pub fn trust(pin: &Pin) -> Result<ProjectTrust, Failure> {
    ProjectTrust::new(&pin.project_id, vec![pin.authority.key()?], 1).map_err(Failure::from)
}

/// Open an agent profile. With `create`, a missing vault and key are made;
/// an existing key or vault is never replaced.
pub fn open_profile(
    ws: &Workspace,
    pin: &Pin,
    agent: &str,
    custody: &dyn Custody,
    create: bool,
) -> Result<Engine, Failure> {
    if !pin.agents.iter().any(|a| a == agent) {
        return Err(Failure::new(
            "unknown_profile",
            "that agent profile is not part of this project's pilot",
        )
        .hint(format!("Profiles here: {}.", pin.agents.join(", "))));
    }
    let account = ws.account(agent);
    let path = ws.vault_path(agent);
    let vault = if ws.vault_exists(agent) {
        let key = custody.load_key(&account)?;
        Vault::open(&path, &key, &pin.project_id, &account, custody.anchors()).map_err(|e| {
            Failure::from(e).hint(
                "The vault could not be opened with its checkpoint. If setup was interrupted or the \
                 folder was restored from a copy, it needs recovery; it is not reset automatically.",
            )
        })?
    } else if create {
        private_dir(&ws.private)?;
        private_dir(&ws.private.join(agent))?;
        // An interrupted earlier run may have stored the key already.
        let key = match custody.create_key(&account) {
            Ok(key) => key,
            Err(yhes_core::Error::Conflict(_)) => custody.load_key(&account)?,
            Err(e) => return Err(e.into()),
        };
        Vault::create(&path, &key, &pin.project_id, &account, custody.anchors())?
    } else {
        return Err(not_set_up());
    };
    let mut engine = Engine::open(vault, trust(pin)?, agent)?;
    bind_pin(&mut engine, pin, create)?;
    Ok(engine)
}

/// The pin file is outside the encrypted vault, and the vault's trust
/// fingerprint covers only the project and authority key. Everything else in
/// the pin (the human's name above all) is bound here: its digest is stored in
/// the vault once and must match on every later open. It is never rewritten.
fn bind_pin(engine: &mut Engine, pin: &Pin, setup: bool) -> Result<(), Failure> {
    const NAME: &str = "pin-binding";
    let canonical = serde_json::to_vec(pin)
        .map_err(|_| Failure::new("internal", "cannot encode the local pin"))?;
    let digest = yhes_wire::Digest::of(&canonical).to_hex();
    match engine.client_get(NAME)? {
        Some(stored) if stored == digest.as_bytes() => Ok(()),
        Some(_) => Err(Failure::new(
            "pin_changed",
            "the local pin file no longer matches what this vault was set up with",
        )
        .hint(
            "Names and keys in pin.json were changed after setup. Nothing was shown or sent. \
             Restore the original file; the vault keeps its own record and is not updated.",
        )),
        None if setup => engine
            .client_put(NAME, digest.as_bytes())
            .map_err(Failure::from),
        None => Err(Failure::new(
            "pin_unbound",
            "this profile's setup was interrupted before its pin was recorded in the vault",
        )
        .hint("Run `yhes pilot` with the original --human to finish setup.")),
    }
}

pub fn not_set_up() -> Failure {
    Failure::new(
        "not_set_up",
        "this project has no agent-yhes pilot on this Mac yet",
    )
    .hint("Run `yhes pilot --project PATH --human ID` first.")
}

/// Public metadata beside the sealed log. Descriptive only; never read back
/// to decide trust.
pub fn publish_public(ws: &Workspace, name: &str, bytes: &[u8]) -> Result<(), Failure> {
    let failed = || {
        Failure::new(
            "shared_log",
            "cannot write public metadata into the project",
        )
    };
    let directory = ws.project_root.join(".agents/messages/secure/identities");
    fs::create_dir_all(&directory).map_err(|_| failed())?;
    let target = directory.join(name);
    if let Ok(existing) = fs::read(&target) {
        if existing == bytes {
            return Ok(());
        }
    }
    let temporary = directory.join(format!(".{name}.{}.tmp", std::process::id()));
    fs::write(&temporary, bytes)
        .and_then(|_| fs::rename(&temporary, &target))
        .map_err(|_| {
            let _ = fs::remove_file(&temporary);
            failed()
        })
}
