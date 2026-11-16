//! Small private-file primitives for this example, not a production key store.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
};
use yhes_cli::Failure;

pub fn rejected() -> Failure {
    Failure::new(
        "simulation_boundary",
        "simulation configuration or private state is outside the disposable lab contract",
    )
}

/// No symlink in any component, no relative/dot spelling, canonical paths only.
/// Ancestors may be root-owned (including a sticky system temp directory).
pub fn path(path: &Path, directory: bool, private: bool) -> Result<(), Failure> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || path.canonicalize().map_err(|_| rejected())? != path
    {
        return Err(rejected());
    }
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| rejected())?;
        if meta.file_type().is_symlink()
            || (ancestor != path && !meta.is_dir())
            || (meta.uid() != unsafe { libc::geteuid() } && meta.uid() != 0)
            || (meta.mode() & 0o022 != 0 && !(meta.uid() == 0 && meta.mode() & 0o1000 != 0))
        {
            return Err(rejected());
        }
    }
    let meta = fs::symlink_metadata(path).map_err(|_| rejected())?;
    if meta.uid() != unsafe { libc::geteuid() }
        || if directory {
            !meta.is_dir()
        } else {
            !meta.is_file()
        }
        || (private && meta.mode() & 0o077 != 0)
    {
        return Err(rejected());
    }
    Ok(())
}

pub fn directory(dir: &Path) -> Result<(), Failure> {
    path(dir.parent().ok_or_else(rejected)?, true, true)?;
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => File::open(dir.parent().ok_or_else(rejected)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| rejected())?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(rejected()),
    }
    path(dir, true, true)
}

pub fn read(file: &Path, limit: u64, private: bool) -> Result<Vec<u8>, Failure> {
    path(file, false, private)?;
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(file)
        .map_err(|_| rejected())?;
    let meta = opened.metadata().map_err(|_| rejected())?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.len() > limit
        || (private && meta.mode() & 0o077 != 0)
    {
        return Err(rejected());
    }
    let mut bytes = Vec::new();
    opened
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| rejected())?;
    if bytes.len() as u64 > limit {
        return Err(rejected());
    }
    Ok(bytes)
}

/// Write and fsync the whole file before a hard-link publishes it atomically.
/// An existing name is never replaced, including by a concurrent invocation.
pub fn add(file: &Path, bytes: &[u8]) -> Result<bool, Failure> {
    let parent = file.parent().ok_or_else(rejected)?;
    path(parent, true, true)?;
    let mut temp = tempfile::Builder::new()
        .prefix(".sim-write-")
        .tempfile_in(parent)
        .map_err(|_| rejected())?;
    temp.write_all(bytes)
        .and_then(|_| temp.as_file().sync_all())
        .map_err(|_| rejected())?;
    let result = match fs::hard_link(temp.path(), file) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => return Err(rejected()),
    };
    drop(temp);
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| rejected())?;
    path(file, false, true)?;
    Ok(result)
}

pub fn exists(path: &Path) -> Result<bool, Failure> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(rejected()),
    }
}

/// Shared production adapters open descendants by name. Reject links/special
/// files before calling them. This is a disposable same-account simulation,
/// not protection against a hostile process that can mutate files concurrently.
pub fn tree(root: &Path, private: bool) -> Result<(), Failure> {
    if !exists(root)? {
        return Ok(());
    }
    let mut todo = vec![root.to_path_buf()];
    let mut count = 0;
    while let Some(item) = todo.pop() {
        count += 1;
        if count > 100_000 {
            return Err(rejected());
        }
        let meta = fs::symlink_metadata(&item).map_err(|_| rejected())?;
        path(&item, meta.is_dir(), private)?;
        if meta.is_dir() {
            for entry in fs::read_dir(&item).map_err(|_| rejected())? {
                todo.push(entry.map_err(|_| rejected())?.path());
            }
        }
    }
    Ok(())
}

pub struct Lock(File);
impl Lock {
    pub fn acquire(file: &Path) -> Result<Self, Failure> {
        if !exists(file)? {
            add(file, b"")?;
        }
        path(file, false, true)?;
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(file)
            .map_err(|_| rejected())?;
        if unsafe { libc::flock(opened.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Failure::new(
                "simulation_busy",
                "this simulated user is busy; retry the same command",
            ));
        }
        Ok(Self(opened))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
