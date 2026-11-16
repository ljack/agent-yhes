//! Opaque packet transport over a dedicated, append-only Git branch.
//! Remote content is data. See GIT-API.md for the trusted caller boundary.
use crate::{
    engine::Engine,
    local::{Entry, LocalChannel, Publication, Stored, SyncResult},
    packet, Error, Result,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use yhes_wire::Digest;

const MAX_ENTRY: usize = 2 * 1024 * 1024;
const MAX_LOG: usize = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 4096;
const MAX_PUBLIC: usize = 1024;
const MAX_COMMITS: usize = MAX_RECORDS + MAX_PUBLIC;
const COMMAND_LIMIT: Duration = Duration::from_secs(30);
const MAX_CACHE: u64 = 256 * 1024 * 1024;
const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";
#[cfg(target_os = "macos")]
const GPG: &str = "/opt/homebrew/bin/gpg";
#[cfg(not(target_os = "macos"))]
const GPG: &str = "/usr/bin/gpg";
const OSX_KEYCHAIN_HELPER: &str =
    "/Library/Developer/CommandLineTools/usr/libexec/git-core/git-credential-osxkeychain";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitOptions {
    pub author_name: String,
    pub author_email: String,
    pub signing: Option<GitSigning>,
    pub credentials: GitCredentials,
    /// Explicit permission to use the inherited agent socket for SSH transport
    /// or SSH commit signing. Local/HTTPS transports never receive that socket.
    pub ssh_agent: bool,
}
impl Default for GitOptions {
    fn default() -> Self {
        Self {
            author_name: "agent-yhes transport".into(),
            author_email: "transport@invalid".into(),
            signing: None,
            credentials: GitCredentials::None,
            ssh_agent: false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "format", rename_all = "snake_case", deny_unknown_fields)]
pub enum GitSigning {
    Ssh { public_key: PathBuf },
    OpenPgp { fingerprint: String },
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GitCredentials {
    #[default]
    None,
    OsxKeychain,
}

pub struct GitChannel {
    root: PathBuf,
    remote: String,
    branch: String,
    project: String,
    binding: Vec<u8>,
    options: GitOptions,
    signing_key_digest: Option<String>,
}

struct ChannelLock(File);
impl Drop for ChannelLock {
    fn drop(&mut self) {
        // Explicit unlock matters in a multithreaded process: another thread's
        // fork can briefly inherit this descriptor before CLOEXEC closes it.
        // Closing only our copy can otherwise leave a stale inherited flock.
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

/// Untrusted public artifacts. The caller verifies their signed schemas.
#[derive(Debug, Serialize)]
pub struct PublicSnapshot {
    pub head: Option<String>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Serialize)]
pub struct PublicPublication {
    pub name: String,
    pub digest: String,
    pub commit: String,
    pub replayed: bool,
}

struct Snapshot {
    head: Option<String>,
    commits: BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
    records: Vec<Stored>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadCheckpoint {
    version: u8,
    head: String,
}

fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|_| Error::Storage)
}
fn invalid(message: &str) -> Error {
    Error::Verification(message.into())
}
fn oid(value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(invalid("unsupported or malformed Git object ID"));
    }
    Ok(())
}
fn text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| invalid("invalid Git metadata encoding"))
}
fn private_file(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = io(options.open(path))?;
    let metadata = io(file.metadata())?;
    if !metadata.is_file() {
        return Err(invalid("Git cache file is not regular"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(invalid("Git cache file must be private and locally owned"));
        }
    }
    Ok(file)
}
fn check_cache(path: &Path, total: &mut u64, count: &mut usize) -> Result<()> {
    *count += 1;
    if *count > 100_000 {
        return Err(invalid("Git cache exceeds file count bound"));
    }
    let metadata = io(fs::symlink_metadata(path))?;
    if metadata.file_type().is_symlink() || !(metadata.is_dir() || metadata.is_file()) {
        return Err(invalid("Git cache contains a symlink or special file"));
    }
    if metadata.is_dir() {
        for entry in io(fs::read_dir(path))? {
            check_cache(&io(entry)?.path(), total, count)?;
        }
    } else {
        *total = total.checked_add(metadata.len()).ok_or(Error::Storage)?;
        if *total > MAX_CACHE {
            return Err(invalid("Git cache exceeds storage bound"));
        }
    }
    Ok(())
}

impl GitChannel {
    pub fn open(private_cache: &Path, remote: &str, branch: &str, project: &str) -> Result<Self> {
        Self::open_with_options(
            private_cache,
            remote,
            branch,
            project,
            GitOptions::default(),
        )
    }

    pub fn open_with_options(
        private_cache: &Path,
        remote: &str,
        branch: &str,
        project: &str,
        options: GitOptions,
    ) -> Result<Self> {
        packet::id(project)?;
        if !private_cache.is_absolute()
            || private_cache
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(Error::Invalid(
                "Git cache needs an absolute private path".into(),
            ));
        }
        validate_remote(remote)?;
        validate_branch(branch)?;
        let signing_key_digest = validate_options(&options, remote)?;
        if !private_cache.exists() {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            io(builder.create(private_cache))?;
        }
        let metadata = io(fs::symlink_metadata(private_cache))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("Git cache must be a real private directory"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
                return Err(invalid("Git cache must be private and locally owned"));
            }
        }
        let root = io(private_cache.canonicalize())?;
        let binding = serde_json::to_vec(&("yhes-git-v1", remote, branch, project))
            .map_err(|_| Error::Storage)?;
        // Signing/auth preferences bind the cache, but never change the protected
        // channel identity: switching options must not reset rollback detection.
        let cache_binding = serde_json::to_vec(&(
            "yhes-git-cache-v2",
            remote,
            branch,
            project,
            &options,
            &signing_key_digest,
        ))
        .map_err(|_| Error::Storage)?;
        if cache_binding.len() > 16384 {
            return Err(Error::Invalid("Git configuration exceeds bound".into()));
        }
        let channel = Self {
            root,
            remote: remote.into(),
            branch: branch.into(),
            project: project.into(),
            binding,
            options,
            signing_key_digest,
        };
        let binding_path = channel.root.join("binding.json");
        if binding_path.exists() {
            let mut bytes = Vec::new();
            io(private_file(&binding_path, false)?
                .take(16385)
                .read_to_end(&mut bytes))?;
            if bytes != cache_binding {
                return Err(invalid(
                    "Git cache is bound to different local configuration",
                ));
            }
        } else {
            if io(fs::read_dir(&channel.root))?.next().is_some() {
                return Err(invalid("refusing to adopt a nonempty Git cache directory"));
            }
            let mut file = private_file(&binding_path, true)?;
            io(file.write_all(&cache_binding))?;
            io(file.sync_all())?;
        }
        let _lock = channel.lock()?;
        if !channel.root.join("repository.git").exists() {
            channel.git(
                &[
                    "init",
                    "--bare",
                    "--object-format=sha1",
                    "--template=",
                    "repository.git",
                ],
                None,
                8192,
            )?;
        }
        Ok(channel)
    }

    fn lock(&self) -> Result<ChannelLock> {
        check_cache(&self.root, &mut 0, &mut 0)?;
        let path = self.root.join(".lock");
        let file = match private_file(&path, true) {
            Ok(file) => file,
            Err(_) => private_file(&path, false)?,
        };
        fs2::FileExt::try_lock_exclusive(&file)
            .map_err(|_| Error::Conflict("Git channel is busy; retry the same operation".into()))?;
        Ok(ChannelLock(file))
    }

    fn command(&self, args: &[&str], agent_socket: Option<std::ffi::OsString>) -> Command {
        let mut command = Command::new("/usr/bin/git");
        command.current_dir(&self.root).env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_AUTHOR_NAME", &self.options.author_name)
            .env("GIT_AUTHOR_EMAIL", &self.options.author_email)
            .env("GIT_COMMITTER_NAME", &self.options.author_name)
            .env("GIT_COMMITTER_EMAIL", &self.options.author_email)
            .env("GIT_SSH_COMMAND", "/usr/bin/ssh -F /dev/null -oBatchMode=yes -oStrictHostKeyChecking=yes -oConnectTimeout=10")
            .arg(format!("--git-dir={}", self.root.join("repository.git").display()))
            .args(["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                "-c", "credential.helper=", "-c", "protocol.allow=never",
                "-c", "protocol.file.allow=always", "-c", "protocol.https.allow=always",
                "-c", "protocol.ssh.allow=always", "-c", "fetch.fsckObjects=true",
                "-c", "http.followRedirects=false",
                "-c", "transfer.fsckObjects=true", "-c", "fetch.writeCommitGraph=false",
                "-c", "gc.auto=0", "-c", "maintenance.auto=false",
                "-c", "commit.gpgSign=false", "-c", "core.logAllRefUpdates=false"]);
        let signing = args.first() == Some(&"commit-tree");
        let transport = matches!(args.first(), Some(&"ls-remote" | &"fetch" | &"push"));
        let ssh_transport = transport
            && !Path::new(&self.remote).is_absolute()
            && !self.remote.starts_with("https://");
        let ssh_signing = signing && matches!(self.options.signing, Some(GitSigning::Ssh { .. }));
        if self.options.ssh_agent && (ssh_transport || ssh_signing) {
            if let Some(socket) = agent_socket {
                command.env("SSH_AUTH_SOCK", socket);
            }
        }
        if transport
            && self.remote.starts_with("https://")
            && self.options.credentials == GitCredentials::OsxKeychain
        {
            command.args([
                "-c",
                &format!("credential.helper={OSX_KEYCHAIN_HELPER}"),
                "-c",
                "credential.useHttpPath=true",
            ]);
        }
        if signing {
            match &self.options.signing {
                Some(GitSigning::Ssh { public_key }) => {
                    command.args([
                        "-c",
                        "gpg.format=ssh",
                        "-c",
                        &format!("gpg.ssh.program={SSH_KEYGEN}"),
                        "-c",
                        &format!("user.signingKey={}", public_key.display()),
                    ]);
                }
                Some(GitSigning::OpenPgp { fingerprint }) => {
                    command.args([
                        "-c",
                        "gpg.format=openpgp",
                        "-c",
                        &format!("gpg.program={GPG}"),
                        "-c",
                        &format!("user.signingKey={fingerprint}!"),
                    ]);
                    // Explicit OpenPGP signing uses the user's installed keyring,
                    // solely in this signing command, never ambient helper code.
                    if let Some(home) = std::env::var_os("HOME") {
                        command.env("GNUPGHOME", PathBuf::from(home).join(".gnupg"));
                    }
                }
                None => {}
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command
    }

    fn check_local_remote(&self) -> Result<()> {
        let remote = Path::new(&self.remote);
        let metadata = io(fs::symlink_metadata(remote))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("local Git remote must be a real bare directory"));
        }
        let config = remote.join("config");
        let metadata = io(fs::symlink_metadata(&config))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 65536 {
            return Err(invalid(
                "local remote configuration is not a bounded regular file",
            ));
        }
        let data = self.git(
            &[
                "config",
                "--no-includes",
                "--file",
                config.to_str().ok_or(Error::Storage)?,
                "--list",
                "--null",
            ],
            None,
            65536,
        )?;
        let mut bare = false;
        for entry in data.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            let entry = text(entry)?;
            let (key, value) = entry.split_once('\n').unwrap_or((entry, ""));
            let key = key.to_ascii_lowercase();
            if key == "core.bare" {
                bare = value == "true";
            }
            if key == "core.hookspath"
                || key == "include.path"
                || key.starts_with("includeif.")
                || key == "uploadpack.packobjectshook"
                || key == "core.alternaterefscommand"
                || key == "extensions.worktreeconfig"
            {
                return Err(invalid(
                    "local remote has forbidden executable configuration",
                ));
            }
        }
        if !bare {
            return Err(invalid("local Git remote must be bare"));
        }
        let hooks = remote.join("hooks");
        match fs::symlink_metadata(&hooks) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Error::Storage),
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                return Err(invalid("local remote hooks must not be linked"));
            }
            Ok(_) => {}
        }
        for (index, entry) in io(fs::read_dir(hooks))?.enumerate() {
            if index > 128 {
                return Err(invalid("too many local remote hook entries"));
            }
            let entry = io(entry)?;
            let metadata = io(entry.path().symlink_metadata())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(invalid("local remote hook is not a regular inert file"));
            }
            // Git's template samples are executable files but are never hook
            // names. Permit only regular samples; linked samples remain refused.
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".sample"))
            {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o111 != 0 {
                    return Err(invalid("executable local remote hooks are refused"));
                }
            }
        }
        Ok(())
    }

    // File-backed stdio avoids unbounded allocations and pipe deadlocks. Never
    // surface stderr (which may contain arbitrary remote text or credentials).
    fn run(&self, args: &[&str], input: Option<&[u8]>, limit: usize) -> Result<(bool, Vec<u8>)> {
        if matches!(args.first(), Some(&"ls-remote" | &"fetch" | &"push"))
            && Path::new(&self.remote).is_absolute()
        {
            self.check_local_remote()?;
        }
        if args.first() == Some(&"commit-tree")
            && validate_options(&self.options, &self.remote)? != self.signing_key_digest
        {
            return Err(invalid("configured signing public key changed"));
        }
        let nonce = uuid::Uuid::new_v4();
        let paths =
            ["in", "out", "err"].map(|kind| self.root.join(format!(".command-{nonce}-{kind}")));
        let result = (|| {
            let mut stdin = private_file(&paths[0], true)?;
            io(stdin.write_all(input.unwrap_or_default()))?;
            io(stdin.seek(SeekFrom::Start(0)))?;
            let mut stdout = private_file(&paths[1], true)?;
            let stderr = private_file(&paths[2], true)?;
            let mut child = io(self
                .command(args, std::env::var_os("SSH_AUTH_SOCK"))
                .args(args)
                .stdin(Stdio::from(stdin))
                .stdout(Stdio::from(io(stdout.try_clone())?))
                .stderr(Stdio::from(io(stderr.try_clone())?))
                .spawn())?;
            let start = Instant::now();
            let mut cache_check = Instant::now();
            let status = loop {
                let cache_exceeded = args.first() == Some(&"fetch")
                    && cache_check.elapsed() >= Duration::from_millis(100)
                    && {
                        cache_check = Instant::now();
                        check_cache(&self.root, &mut 0, &mut 0).is_err()
                    };
                if start.elapsed() > COMMAND_LIMIT
                    || io(stdout.metadata())?.len() > limit as u64
                    || io(stderr.metadata())?.len() > 65536
                    || cache_exceeded
                {
                    #[cfg(unix)]
                    unsafe {
                        // Include SSH/HTTPS children so a timed-out subprocess
                        // cannot keep holding its output files or socket open.
                        libc::kill(-(child.id() as i32), libc::SIGKILL);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::Conflict(
                        "Git command exceeded its bound; outcome may be uncertain".into(),
                    ));
                }
                if let Some(status) = io(child.try_wait())? {
                    break status;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            io(stdout.seek(SeekFrom::Start(0)))?;
            let mut bytes = Vec::new();
            io(stdout.take(limit as u64 + 1).read_to_end(&mut bytes))?;
            if bytes.len() > limit {
                return Err(invalid("Git output exceeds bound"));
            }
            Ok((status.success(), bytes))
        })();
        for path in paths {
            let _ = fs::remove_file(path);
        }
        result
    }

    fn git(&self, args: &[&str], input: Option<&[u8]>, limit: usize) -> Result<Vec<u8>> {
        let (success, bytes) = self.run(args, input, limit)?;
        if !success {
            return Err(Error::Conflict(
                "Git operation failed; no publication acknowledged".into(),
            ));
        }
        Ok(bytes)
    }

    fn fetch(&self) -> Result<Snapshot> {
        let reference = format!("refs/heads/{}", self.branch);
        let refs = self.git(
            &["ls-remote", "--heads", "--", &self.remote, &reference],
            None,
            4096,
        )?;
        if refs.is_empty() {
            return Ok(Snapshot {
                head: None,
                commits: BTreeSet::new(),
                files: BTreeMap::new(),
                records: Vec::new(),
            });
        }
        let lines = text(&refs)?.trim_end().split('\n').collect::<Vec<_>>();
        if lines.len() != 1 {
            return Err(invalid("remote returned ambiguous branch"));
        }
        let (advertised, name) = lines[0]
            .split_once('\t')
            .ok_or_else(|| invalid("invalid remote ref"))?;
        oid(advertised)?;
        if name != reference {
            return Err(invalid("remote returned another branch"));
        }
        let refspec = format!("+{reference}:refs/yhes/fetched");
        self.git(
            &[
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "--no-recurse-submodules",
                &format!("--depth={}", MAX_COMMITS + 1),
                "--",
                &self.remote,
                &refspec,
            ],
            None,
            8192,
        )?;
        check_cache(&self.root, &mut 0, &mut 0)?;
        let head = self.git(
            &["rev-parse", "--verify", "refs/yhes/fetched^{commit}"],
            None,
            128,
        )?;
        let head = text(&head)?.trim().to_owned();
        oid(&head)?;
        self.read_snapshot(head)
    }

    fn read_snapshot(&self, head: String) -> Result<Snapshot> {
        let raw = self.git(
            &[
                "rev-list",
                "--reverse",
                "--topo-order",
                "--parents",
                &format!("--max-count={}", MAX_COMMITS + 1),
                &head,
                "--",
            ],
            None,
            (MAX_COMMITS + 1) * 128,
        )?;
        let mut commits = BTreeSet::new();
        let mut previous: Option<String> = None;
        let mut paths = BTreeSet::new();
        let mut record_sequence = 0u64;
        for line in text(&raw)?.lines() {
            if commits.len() >= MAX_COMMITS {
                return Err(invalid("Git history exceeds commit bound"));
            }
            let parts = line.split(' ').collect::<Vec<_>>();
            let expected = if previous.is_some() { 2 } else { 1 };
            if parts.len() != expected
                || (parts.len() == 2 && Some(parts[1]) != previous.as_deref())
            {
                return Err(invalid("Git history is not a complete linear append chain"));
            }
            oid(parts[0])?;
            // A shallow boundary is never a legitimate genesis. Inspect actual
            // commit headers because rev-list hides parents at shallow roots.
            let commit = self.git(&["cat-file", "commit", parts[0]], None, 65536)?;
            let header = text(&commit)?.split("\n\n").next().unwrap_or_default();
            let parents = header
                .lines()
                .filter_map(|s| s.strip_prefix("parent "))
                .collect::<Vec<_>>();
            if parents != previous.iter().map(String::as_str).collect::<Vec<_>>() {
                return Err(invalid("Git history is shallow, merged or truncated"));
            }
            let diff = self.git(
                &[
                    "diff-tree",
                    "--root",
                    "--no-commit-id",
                    "--no-renames",
                    "--name-status",
                    "-r",
                    "-z",
                    parts[0],
                    "--",
                ],
                None,
                4096,
            )?;
            let fields = diff.split(|b| *b == 0).collect::<Vec<_>>();
            if fields.len() != 3 || fields[0] != b"A" || !fields[2].is_empty() {
                return Err(invalid(
                    "each Git commit must add exactly one immutable artifact",
                ));
            }
            let path = text(fields[1])?;
            validate_path(path)?;
            if let Some(name) = path.strip_prefix("records/") {
                record_sequence += 1;
                if name[..20] != format!("{record_sequence:020}") {
                    return Err(invalid("Git commits append records out of sequence"));
                }
            }
            if !paths.insert(path.to_owned()) {
                return Err(invalid("Git artifact path was reused"));
            }
            commits.insert(parts[0].to_owned());
            previous = Some(parts[0].into());
        }
        if previous.as_deref() != Some(&head) {
            return Err(invalid("Git head missing from complete history"));
        }
        let tree = self.git(
            &["ls-tree", "-r", "-l", "-z", &head, "--"],
            None,
            MAX_COMMITS * 384,
        )?;
        let mut files = BTreeMap::new();
        let mut total = 0usize;
        for item in tree.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            let (meta, path) = text(item)?
                .split_once('\t')
                .ok_or_else(|| invalid("invalid Git tree"))?;
            let fields = meta.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 4 || fields[0] != "100644" || fields[1] != "blob" {
                return Err(invalid(
                    "Git artifacts must be regular non-executable blobs",
                ));
            }
            validate_path(path)?;
            oid(fields[2])?;
            let size = fields[3]
                .parse::<usize>()
                .map_err(|_| invalid("invalid Git blob size"))?;
            total = total.checked_add(size).ok_or(Error::Storage)?;
            if size > MAX_ENTRY || total > MAX_LOG {
                return Err(invalid("Git artifacts exceed size bound"));
            }
            let bytes = self.git(&["cat-file", "blob", fields[2]], None, MAX_ENTRY)?;
            if bytes.len() != size {
                return Err(invalid("Git blob size changed"));
            }
            files.insert(path.to_owned(), bytes);
        }
        if files.keys().cloned().collect::<BTreeSet<_>>() != paths {
            return Err(invalid("Git tree differs from append history"));
        }
        let mut records = Vec::new();
        let mut operation_ids = BTreeSet::new();
        let mut previous = None;
        let mut public_count = 0;
        for (name, bytes) in &files {
            if name.starts_with("public/") {
                public_count += 1;
                if public_count > MAX_PUBLIC {
                    return Err(invalid("too many public artifacts"));
                }
                continue;
            }
            if records.len() >= MAX_RECORDS {
                return Err(invalid("too many Git records"));
            }
            let digest = Digest::of(bytes).to_hex();
            let sequence = records.len() as u64 + 1;
            if name != &format!("records/{sequence:020}_{digest}.json") {
                return Err(invalid("Git record has a gap, fork or changed digest"));
            }
            let entry: Entry =
                serde_json::from_slice(bytes).map_err(|_| invalid("malformed Git record"))?;
            if entry.version != 1
                || entry.project != self.project
                || entry.sequence != sequence
                || entry.previous != previous
            {
                return Err(invalid("Git record hash chain does not link"));
            }
            let packet = STANDARD
                .decode(&entry.packet)
                .map_err(|_| invalid("invalid sealed record encoding"))?;
            let header = packet::unverified_header(&packet)?;
            if header.project != self.project
                || !operation_ids.insert((header.sender, header.operation))
            {
                return Err(invalid("Git record scope or operation collision"));
            }
            previous = Some(digest.clone());
            records.push(Stored {
                entry,
                digest,
                packet,
                encoded_size: bytes.len() as u64,
            });
        }
        Ok(Snapshot {
            head: Some(head),
            commits,
            files,
            records,
        })
    }

    fn protected_head(&self, engine: &mut Engine, snapshot: &Snapshot) -> Result<()> {
        if engine.project_id() != self.project {
            return Err(invalid("Git channel project differs"));
        }
        if let Some(bytes) = engine.client_get(&self.head_key())? {
            let checkpoint: HeadCheckpoint =
                serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
            if checkpoint.version != 1 || !snapshot.commits.contains(&checkpoint.head) {
                return Err(invalid(
                    "Git branch changed behind protected history checkpoint",
                ));
            }
        }
        Ok(())
    }
    fn head_key(&self) -> String {
        format!("git-{}", Digest::of(&self.binding).to_hex())
    }
    fn save_head(&self, engine: &mut Engine, snapshot: &Snapshot) -> Result<()> {
        if let Some(head) = &snapshot.head {
            engine.client_put(
                &self.head_key(),
                &serde_json::to_vec(&HeadCheckpoint {
                    version: 1,
                    head: head.clone(),
                })
                .map_err(|_| Error::Storage)?,
            )?;
        }
        Ok(())
    }
    fn process(
        &self,
        engine: &mut Engine,
        group: &str,
        owner: &str,
        now: u64,
        snapshot: &Snapshot,
    ) -> Result<SyncResult> {
        self.protected_head(engine, snapshot)?;
        // Persist ancestry before processing: partial processing failures must not
        // let a later branch rewrite erase already-observed ordering evidence.
        self.save_head(engine, snapshot)?;
        LocalChannel::sync_transport(
            engine,
            &self.project,
            &self.binding,
            group,
            owner,
            now,
            &snapshot.records,
        )
    }

    pub fn sync(
        &self,
        engine: &mut Engine,
        group: &str,
        owner: &str,
        now: u64,
    ) -> Result<SyncResult> {
        packet::id(group)?;
        packet::id(owner)?;
        let _lock = self.lock()?;
        self.process(engine, group, owner, now, &self.fetch()?)
    }

    pub fn publish(&self, engine: &mut Engine, operation: &str, now: u64) -> Result<Publication> {
        packet::id(operation)?;
        let _lock = self.lock()?;
        let snapshot = self.fetch()?;
        self.protected_head(engine, &snapshot)?;
        let bytes = engine.stored_packet(operation)?;
        let header = packet::unverified_header(&bytes)?;
        if header.operation != operation
            || header.sender != engine.principal()
            || header.project != self.project
        {
            return Err(invalid("stored operation scope differs"));
        }
        let state = engine
            .group_status(&header.group)?
            .ok_or_else(|| invalid("outgoing group is absent"))?;
        LocalChannel::check_transport_cursor(
            engine,
            &self.project,
            &self.binding,
            &header.group,
            &state.owner,
            &snapshot.records,
        )?;
        let existing = find_operation(&snapshot, engine.principal(), operation, &bytes)?;
        let status = engine
            .outbox()?
            .into_iter()
            .find(|item| item.operation == operation)
            .ok_or_else(|| invalid("outgoing operation is absent"))?;
        if status.status == "rejected" {
            return Err(invalid("outgoing operation was rejected"));
        }
        if status.status == "accepted" && existing.is_none() {
            return Err(invalid(
                "accepted outgoing packet disappeared from Git history",
            ));
        }
        if let Some(sequence) = existing {
            self.process(engine, &header.group, &state.owner, now, &snapshot)?;
            // The cursor may already include this record after a previous return;
            // exact protected outbox acceptance is still required.
            require_accepted(engine, operation)?;
            return Ok(Publication {
                operation: operation.into(),
                packet_digest: Digest::of(&bytes).to_hex(),
                sequence,
                replayed: true,
            });
        }
        self.process(engine, &header.group, &state.owner, now, &snapshot)?;
        let ready = engine.ready(operation, now)?;
        if ready != bytes {
            return Err(invalid("ready packet differs from immutable outbox"));
        }
        let info = engine.inspect_record(&ready, now)?;
        let state = engine.group_status(&info.group)?.ok_or(Error::Storage)?;
        let last = snapshot
            .records
            .iter()
            .rev()
            .filter_map(|record| {
                packet::unverified_header(&record.packet)
                    .ok()
                    .filter(|h| {
                        h.group == info.group && matches!(h.kind.as_str(), "genesis" | "commit")
                    })
                    .map(|_| Digest::of(&record.packet).to_hex())
            })
            .next();
        if info.previous != last
            || state.last_commit != last
            || (info.kind == "genesis" && last.is_some())
        {
            return Err(Error::Conflict(
                "Git membership changed; pending attempt needs reconciliation".into(),
            ));
        }
        if snapshot.records.len() >= MAX_RECORDS {
            return Err(invalid("Git record limit reached"));
        }
        let sequence = snapshot.records.len() as u64 + 1;
        let entry = Entry {
            version: 1,
            project: self.project.clone(),
            sequence,
            previous: snapshot.records.last().map(|r| r.digest.clone()),
            packet: STANDARD.encode(&ready),
        };
        let encoded = serde_json::to_vec(&entry).map_err(|_| Error::Storage)?;
        let path = format!(
            "records/{sequence:020}_{}.json",
            Digest::of(&encoded).to_hex()
        );
        let commit = self.append(&snapshot, &path, &encoded)?;
        // Ignore all push output as an acceptance signal, including failure and
        // timeout. Authoritative fetch and exact readback settle the operation.
        let push = self.push(&commit);
        let readback = self.fetch()?;
        self.protected_head(engine, &readback)?;
        if let Some(sequence) = find_operation(&readback, engine.principal(), operation, &ready)? {
            self.process(engine, &info.group, &state.owner, now, &readback)?;
            require_accepted(engine, operation)?;
            return Ok(Publication {
                operation: operation.into(),
                packet_digest: info.digest,
                sequence,
                replayed: false,
            });
        }
        let _ = push;
        Err(Error::Conflict("Git did not confirm the exact packet; retry the same operation with pending state intact".into()))
    }

    fn append(&self, snapshot: &Snapshot, path: &str, bytes: &[u8]) -> Result<String> {
        validate_path(path)?;
        if bytes.len() > MAX_ENTRY
            || snapshot.files.len() >= MAX_COMMITS
            || snapshot
                .files
                .values()
                .map(Vec::len)
                .sum::<usize>()
                .checked_add(bytes.len())
                .is_none_or(|n| n > MAX_LOG)
            || snapshot.files.contains_key(path)
        {
            return Err(invalid("append violates artifact bounds or immutability"));
        }
        let blob = self.git(&["hash-object", "-w", "--stdin"], Some(bytes), 128)?;
        let blob = text(&blob)?.trim();
        oid(blob)?;
        // Build trees directly: no worktree or index exists or is consulted.
        let mut trees: BTreeMap<&str, BTreeMap<String, String>> = BTreeMap::new();
        if let Some(head) = &snapshot.head {
            let listing = self.git(
                &["ls-tree", "-r", "-z", head, "--"],
                None,
                MAX_COMMITS * 384,
            )?;
            for entry in listing.split(|b| *b == 0).filter(|s| !s.is_empty()) {
                let (meta, existing) = text(entry)?.split_once('\t').ok_or(Error::Storage)?;
                let (directory, name) = existing.split_once('/').ok_or(Error::Storage)?;
                let directory = if directory == "records" {
                    "records"
                } else {
                    "public"
                };
                trees
                    .entry(directory)
                    .or_default()
                    .insert(name.into(), meta.into());
            }
        }
        let (directory, name) = path.split_once('/').ok_or(Error::Storage)?;
        trees
            .entry(directory)
            .or_default()
            .insert(name.into(), format!("100644 blob {blob}"));
        let mut root = Vec::new();
        for (directory, entries) in trees {
            let mut input = Vec::new();
            for (name, meta) in entries {
                input.extend_from_slice(format!("{meta}\t{name}\0").as_bytes());
            }
            let tree = self.git(&["mktree", "-z"], Some(&input), 128)?;
            let tree = text(&tree)?.trim();
            oid(tree)?;
            root.extend_from_slice(format!("040000 tree {tree}\t{directory}\0").as_bytes());
        }
        let tree = self.git(&["mktree", "-z"], Some(&root), 128)?;
        let tree = text(&tree)?.trim();
        oid(tree)?;
        let mut args = vec!["commit-tree", tree];
        if self.options.signing.is_some() {
            args.push("-S");
        }
        if let Some(head) = &snapshot.head {
            args.extend(["-p", head]);
        }
        let commit = self.git(&args, Some(b"agent-yhes opaque artifact\n"), 128)?;
        let commit = text(&commit)?.trim().to_owned();
        oid(&commit)?;
        Ok(commit)
    }
    fn push(&self, commit: &str) -> Result<()> {
        let reference = format!("{commit}:refs/heads/{}", self.branch);
        self.git(
            &[
                "push",
                "--porcelain",
                "--no-verify",
                "--",
                &self.remote,
                &reference,
            ],
            None,
            8192,
        )?;
        Ok(())
    }

    pub fn fetch_public(&self) -> Result<PublicSnapshot> {
        let _lock = self.lock()?;
        let snapshot = self.fetch()?;
        Ok(public_snapshot(snapshot))
    }
    /// Use after an engine/vault exists. Checks the protected Git ancestry but
    /// deliberately does not advance it ahead of application synchronization.
    pub fn fetch_public_checked(&self, engine: &mut Engine) -> Result<PublicSnapshot> {
        let _lock = self.lock()?;
        let snapshot = self.fetch()?;
        self.protected_head(engine, &snapshot)?;
        Ok(public_snapshot(snapshot))
    }
    pub fn read_public_checked(&self, engine: &mut Engine, name: &str) -> Result<Option<Vec<u8>>> {
        packet::id(name)?;
        Ok(self.fetch_public_checked(engine)?.artifacts.remove(name))
    }
    pub fn read_public(&self, name: &str) -> Result<Option<Vec<u8>>> {
        packet::id(name)?;
        Ok(self.fetch_public()?.artifacts.remove(name))
    }
    pub fn publish_public_checked(
        &self,
        engine: &mut Engine,
        name: &str,
        bytes: &[u8],
    ) -> Result<PublicPublication> {
        self.publish_public_inner(Some(engine), name, bytes)
    }
    pub fn publish_public(&self, name: &str, bytes: &[u8]) -> Result<PublicPublication> {
        self.publish_public_inner(None, name, bytes)
    }
    fn publish_public_inner(
        &self,
        mut engine: Option<&mut Engine>,
        name: &str,
        bytes: &[u8],
    ) -> Result<PublicPublication> {
        packet::id(name)?;
        if bytes.is_empty() || bytes.len() > MAX_ENTRY {
            return Err(invalid("public artifact size is invalid"));
        }
        let _lock = self.lock()?;
        let snapshot = self.fetch()?;
        if let Some(engine) = engine.as_deref_mut() {
            self.protected_head(engine, &snapshot)?;
        }
        let path = format!("public/{name}");
        if let Some(existing) = snapshot.files.get(&path) {
            if existing != bytes {
                return Err(invalid("immutable public artifact name collision"));
            }
            return Ok(PublicPublication {
                name: name.into(),
                digest: Digest::of(bytes).to_hex(),
                commit: snapshot.head.ok_or(Error::Storage)?,
                replayed: true,
            });
        }
        if snapshot
            .files
            .keys()
            .filter(|name| name.starts_with("public/"))
            .count()
            >= MAX_PUBLIC
        {
            return Err(invalid("public artifact limit reached"));
        }
        let commit = self.append(&snapshot, &path, bytes)?;
        let _push = self.push(&commit);
        let readback = self.fetch()?;
        if let Some(engine) = engine {
            self.protected_head(engine, &readback)?;
        }
        if snapshot
            .head
            .as_ref()
            .is_some_and(|head| !readback.commits.contains(head))
        {
            return Err(invalid("Git branch changed during public publication"));
        }
        if readback.files.get(&path).map(Vec::as_slice) != Some(bytes) {
            return Err(Error::Conflict(
                "Git did not confirm the exact public artifact; retry unchanged".into(),
            ));
        }
        Ok(PublicPublication {
            name: name.into(),
            digest: Digest::of(bytes).to_hex(),
            commit: readback.head.ok_or(Error::Storage)?,
            replayed: false,
        })
    }
}

fn public_snapshot(snapshot: Snapshot) -> PublicSnapshot {
    PublicSnapshot {
        head: snapshot.head,
        artifacts: snapshot
            .files
            .into_iter()
            .filter_map(|(name, bytes)| name.strip_prefix("public/").map(|n| (n.to_owned(), bytes)))
            .collect(),
    }
}

fn validate_options(options: &GitOptions, remote: &str) -> Result<Option<String>> {
    for value in [&options.author_name, &options.author_email] {
        if value.is_empty()
            || value.len() > 200
            || value
                .chars()
                .any(|c| c.is_control() || matches!(c, '<' | '>'))
        {
            return Err(Error::Invalid(
                "invalid locally configured Git author identity".into(),
            ));
        }
    }
    if !options.author_email.contains('@') || options.author_email.chars().any(char::is_whitespace)
    {
        return Err(Error::Invalid(
            "invalid locally configured Git author email".into(),
        ));
    }
    if options.credentials == GitCredentials::OsxKeychain
        && (!cfg!(target_os = "macos")
            || !remote.starts_with("https://")
            || !Path::new(OSX_KEYCHAIN_HELPER).is_file())
    {
        return Err(Error::Invalid(
            "osxkeychain requires HTTPS and the installed fixed system helper".into(),
        ));
    }
    match &options.signing {
        Some(GitSigning::Ssh { public_key }) => {
            if !public_key.is_absolute()
                || public_key
                    .components()
                    .any(|c| matches!(c, Component::ParentDir))
                || public_key
                    .to_str()
                    .is_none_or(|s| s.chars().any(char::is_control))
                || !Path::new(SSH_KEYGEN).is_file()
            {
                return Err(Error::Invalid(
                    "SSH signing requires an absolute public key path and system ssh-keygen".into(),
                ));
            }
            let metadata = io(fs::symlink_metadata(public_key))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16384 {
                return Err(Error::Invalid(
                    "SSH signing public key must be a bounded regular file".into(),
                ));
            }
            let mut open = OpenOptions::new();
            open.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                open.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            let mut bytes = Vec::new();
            io(io(open.open(public_key))?
                .take(16385)
                .read_to_end(&mut bytes))?;
            if bytes.len() > 16384 {
                return Err(invalid("SSH signing public key exceeds size bound"));
            }
            let value = text(&bytes)?.trim();
            if value.contains(['\n', '\r']) {
                return Err(invalid("SSH signing needs one public key"));
            }
            let fields = value.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 2
                || !matches!(
                    fields[0],
                    "ssh-ed25519"
                        | "ssh-rsa"
                        | "ecdsa-sha2-nistp256"
                        | "ecdsa-sha2-nistp384"
                        | "ecdsa-sha2-nistp521"
                        | "sk-ssh-ed25519@openssh.com"
                        | "sk-ecdsa-sha2-nistp256@openssh.com"
                )
            {
                return Err(invalid(
                    "SSH signing path must contain an OpenSSH public key",
                ));
            }
            let decoded = STANDARD
                .decode(fields[1])
                .map_err(|_| invalid("invalid SSH signing public key"))?;
            let kind = fields[0].as_bytes();
            if decoded.len() <= kind.len() + 4
                || decoded[..4] != (kind.len() as u32).to_be_bytes()
                || &decoded[4..4 + kind.len()] != kind
            {
                return Err(invalid("invalid SSH signing public key type"));
            }
            Ok(Some(Digest::of(&bytes).to_hex()))
        }
        Some(GitSigning::OpenPgp { fingerprint }) => {
            if !matches!(fingerprint.len(), 40 | 64)
                || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
                || !Path::new(GPG).is_file()
            {
                return Err(Error::Invalid(
                    "OpenPGP signing needs a full fingerprint and installed fixed gpg executable"
                        .into(),
                ));
            }
            Ok(None)
        }
        None => Ok(None),
    }
}

fn require_accepted(engine: &mut Engine, operation: &str) -> Result<()> {
    if engine
        .outbox()?
        .iter()
        .any(|item| item.operation == operation && item.status == "accepted")
    {
        Ok(())
    } else {
        Err(invalid(
            "verified history did not accept the exact outgoing operation",
        ))
    }
}
fn find_operation(
    snapshot: &Snapshot,
    sender: &str,
    operation: &str,
    expected: &[u8],
) -> Result<Option<u64>> {
    for record in &snapshot.records {
        let header = packet::unverified_header(&record.packet)?;
        if header.sender == sender && header.operation == operation {
            if record.packet != expected {
                return Err(invalid("Git operation collides with protected packet"));
            }
            return Ok(Some(record.entry.sequence));
        }
    }
    Ok(None)
}
fn validate_path(path: &str) -> Result<()> {
    if let Some(name) = path.strip_prefix("public/") {
        return packet::id(name);
    }
    if let Some(name) = path.strip_prefix("records/") {
        let bytes = name.as_bytes();
        if bytes.len() == 90
            && bytes[..20].iter().all(u8::is_ascii_digit)
            && bytes[20] == b'_'
            && bytes[21..85]
                .iter()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && &bytes[85..] == b".json"
        {
            return Ok(());
        }
    }
    Err(invalid("unexpected path in Git transport history"))
}
fn validate_branch(branch: &str) -> Result<()> {
    if branch.is_empty()
        || branch.len() > 200
        || branch.starts_with('-')
        || branch.ends_with('.')
        || branch.contains("..")
        || branch
            .split('/')
            .any(|s| s.is_empty() || s.starts_with('.') || s.ends_with(".lock"))
        || !branch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.'))
    {
        return Err(Error::Invalid(
            "invalid explicitly configured Git branch".into(),
        ));
    }
    Ok(())
}
fn validate_remote(remote: &str) -> Result<()> {
    if remote.is_empty()
        || remote.len() > 4096
        || remote.starts_with('-')
        || remote
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(Error::Invalid(
            "invalid explicitly configured Git remote".into(),
        ));
    }
    if Path::new(remote).is_absolute() {
        return Ok(());
    }
    if remote.contains(['?', '#', '\\']) {
        return Err(Error::Invalid(
            "Git remote URLs cannot contain query strings or fragments".into(),
        ));
    }
    let allowed = if let Some(tail) = remote.strip_prefix("https://") {
        let authority = tail.split('/').next().unwrap_or_default();
        !authority.contains('@') && valid_host(authority)
    } else if let Some(tail) = remote.strip_prefix("ssh://") {
        valid_ssh_authority(tail.split('/').next().unwrap_or_default())
    } else {
        !remote.contains("://")
            && remote.split_once(':').is_some_and(|(authority, path)| {
                valid_ssh_authority(authority) && !path.is_empty() && !path.starts_with(':')
            })
    };
    if !allowed {
        return Err(Error::Invalid(
            "Git remote must be an absolute path, HTTPS or SSH URL".into(),
        ));
    }
    Ok(())
}
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        })
}
fn valid_ssh_authority(authority: &str) -> bool {
    if let Some((user, host)) = authority.split_once('@') {
        !user.is_empty()
            && user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            && valid_host(host)
    } else {
        valid_host(authority)
    }
}

#[cfg(test)]
#[path = "../tests/git_support/options_unit.rs"]
mod options_tests;
