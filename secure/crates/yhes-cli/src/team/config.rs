use super::rejected;
use crate::{
    profile::{self, Workspace},
    signer::Descriptor,
    Args, Custody, Deps, Failure,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use yhes_core::{
    engine::Engine,
    git::{GitChannel, GitCredentials, GitOptions, GitSigning},
    store::Vault,
    trust::ProjectTrust,
};
use yhes_wire::Digest;

pub const GROUP: &str = "team";
pub const DEFAULT_BRANCH: &str = "agent-yhes/secure-team";

/// Immutable local configuration; its complete encoding is bound inside the vault.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TeamPin {
    pub version: u8,
    pub project_id: String,
    pub project_path: String,
    pub remote: String,
    pub branch: String,
    pub git_options: GitOptions,
    pub group: String,
    pub owner: String,
    pub principal: String,
    pub human: Descriptor,
    pub authority: Descriptor,
    pub bootstrap_head: Option<String>,
}
pub struct TeamSession {
    pub ws: Workspace,
    pub pin: TeamPin,
    pub engine: Engine,
    pub channel: GitChannel,
}
pub fn directory(ws: &Workspace) -> PathBuf {
    ws.private.join("network")
}
/// Only explicit, typed settings are passed to the Git adapter. Ambient Git
/// configuration cannot select a credential helper or a signing program.
pub fn options(args: &Args) -> Result<GitOptions, Failure> {
    let mut options = GitOptions::default();
    if let Some(value) = args.get("--git-author-name") {
        options.author_name = value.into();
    }
    if let Some(value) = args.get("--git-author-email") {
        options.author_email = value.into();
    }
    options.signing = match (
        args.get("--git-signing-format"),
        args.get("--git-signing-key"),
    ) {
        (None, None) => None,
        (Some("ssh"), Some(key)) => Some(GitSigning::Ssh {
            public_key: PathBuf::from(key),
        }),
        (Some("openpgp"), Some(key)) => Some(GitSigning::OpenPgp {
            fingerprint: key.into(),
        }),
        _ => {
            return Err(Failure::new(
                "usage",
                "provide both --git-signing-format ssh|openpgp and --git-signing-key",
            ))
        }
    };
    options.credentials = match args.get("--git-credentials") {
        None => GitCredentials::None,
        Some("osxkeychain") => GitCredentials::OsxKeychain,
        Some(_) => {
            return Err(Failure::new(
                "usage",
                "--git-credentials supports only osxkeychain",
            ))
        }
    };
    options.ssh_agent = args.flag("--git-ssh-agent");
    Ok(options)
}
fn path(ws: &Workspace) -> PathBuf {
    directory(ws).join("team.json")
}
pub fn locate(args: &Args, deps: &Deps<'_>, create: bool) -> Result<Workspace, Failure> {
    let ws = Workspace::locate(
        &deps.private_root,
        Path::new(args.need("--project")?),
        create,
    )?;
    if create {
        profile::private_dir(&ws.private)?;
        profile::private_dir(&directory(&ws))?;
    }
    Ok(ws)
}
pub fn read(ws: &Workspace) -> Result<Option<TeamPin>, Failure> {
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path(ws))
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(rejected()),
    };
    let meta = file.metadata().map_err(|_| rejected())?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.len() > 32_768
    {
        return Err(rejected());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| rejected())?;
    let pin: TeamPin = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
    validate(ws, &pin)?;
    Ok(Some(pin))
}
pub fn validate(ws: &Workspace, pin: &TeamPin) -> Result<(), Failure> {
    if pin.version != 1
        || !profile::valid_id(&pin.project_id)
        || !profile::valid_id(&pin.human.author)
        || !profile::valid_id(&pin.authority.author)
        || !profile::agent_name(&pin.principal)
        || !profile::agent_name(&pin.owner)
        || pin.human.author == pin.principal
        || pin.group != GROUP
        || pin.project_path != ws.project_root.to_string_lossy()
        || pin.human.project != pin.project_id
        || pin.authority.project != pin.project_id
        || pin
            .bootstrap_head
            .as_deref()
            .is_some_and(|d| Digest::from_hex(d).is_err())
        || (pin.bootstrap_head.is_none()
            && (pin.human != pin.authority || pin.principal != pin.owner))
        || pin.human.key().is_err()
        || pin.authority.key().is_err()
    {
        return Err(rejected());
    }
    Ok(())
}
pub fn write(ws: &Workspace, pin: &TeamPin) -> Result<(), Failure> {
    validate(ws, pin)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path(ws))
        .map_err(|_| rejected())?;
    file.write_all(&serde_json::to_vec(pin).map_err(|_| rejected())?)
        .and_then(|_| file.sync_all())
        .map_err(|_| rejected())
}
pub fn engine(
    ws: &Workspace,
    pin: &TeamPin,
    custody: &dyn Custody,
    create: bool,
) -> Result<Engine, Failure> {
    validate(ws, pin)?;
    let dir = directory(ws).join(&pin.principal);
    let path = dir.join("vault.db");
    let account = ws.account(&format!("network-{}", pin.principal));
    let vault = if fs::symlink_metadata(&path).is_ok() {
        Vault::open(
            &path,
            &custody.load_key(&account)?,
            &pin.project_id,
            &account,
            custody.anchors(),
        )?
    } else if create {
        profile::private_dir(&dir)?;
        let key = match custody.create_key(&account) {
            Ok(key) => key,
            Err(yhes_core::Error::Conflict(_)) => custody.load_key(&account)?,
            Err(e) => return Err(e.into()),
        };
        Vault::create(&path, &key, &pin.project_id, &account, custody.anchors())?
    } else {
        return Err(not_set_up());
    };
    let mut engine = Engine::open(
        vault,
        ProjectTrust::new(&pin.project_id, vec![pin.authority.key()?], 1)?,
        &pin.principal,
    )?;
    let binding = Digest::of(&serde_json::to_vec(pin).map_err(|_| rejected())?).to_hex();
    match engine.client_get("team-pin-binding")? {
        Some(bytes) if bytes == binding.as_bytes() => {}
        Some(_) => {
            return Err(Failure::new(
                "team_pin_changed",
                "the team configuration no longer matches the protected vault",
            ))
        }
        None if create => engine.client_put("team-pin-binding", binding.as_bytes())?,
        None => return Err(not_set_up()),
    }
    Ok(engine)
}
pub fn channel(ws: &Workspace, pin: &TeamPin) -> Result<GitChannel, Failure> {
    GitChannel::open_with_options(
        &directory(ws).join("git"),
        &pin.remote,
        &pin.branch,
        &pin.project_id,
        pin.git_options.clone(),
    )
    .map_err(Failure::from)
}
pub fn open(args: &Args, deps: &Deps<'_>) -> Result<TeamSession, Failure> {
    let ws = locate(args, deps, false)?;
    let pin = read(&ws)?.ok_or_else(not_set_up)?;
    let engine = engine(&ws, &pin, deps.custody, false)?;
    if args.get("--as").is_some_and(|a| a != pin.principal) {
        return Err(rejected());
    }
    let channel = channel(&ws, &pin)?;
    Ok(TeamSession {
        ws,
        pin,
        engine,
        channel,
    })
}
pub fn not_set_up() -> Failure {
    Failure::new("team_not_set_up", "this project has no team profile on this Mac")
        .hint("Run team-init as founder, or team-request with the independently checked authority fingerprint and bootstrap digest.")
}
