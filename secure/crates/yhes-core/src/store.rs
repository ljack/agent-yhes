use crate::{
    keys::{Anchor, AnchorStore, StorageKey},
    Error, Result,
};
use hmac::{Hmac, Mac};
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest as _, Sha256};
use std::{fs, fs::File, path::Path, time::Duration};
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct JsonCodec;
impl Codec for JsonCodec {
    type Error = serde_json::Error;
    fn to_vec<T: Serialize>(value: &T) -> std::result::Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }
    fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> std::result::Result<T, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

pub(crate) struct Provider<'a> {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, &'a Connection>,
}
impl<'a> Provider<'a> {
    pub fn new(connection: &'a Connection) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: SqliteStorageProvider::new(connection),
        }
    }
}
impl<'a> OpenMlsProvider for Provider<'a> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, &'a Connection>;
    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}

/// An exclusively opened encrypted vault with a separately stored checkpoint.
/// The anchor provider must be protected independently of the database. Production
/// callers use PlatformKeychain; in-memory providers belong in test programs only.
pub struct Vault {
    pub(crate) connection: Connection,
    _lock: File,
    account: String,
    anchors: Box<dyn AnchorStore>,
    mac_key: Zeroizing<[u8; 32]>,
    poisoned: bool,
}

fn private_file(path: &Path, may_be_absent: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err(Error::Invalid("vault files must be regular files".into()));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.mode() & 0o077 != 0
                    || meta.nlink() != 1
                    || meta.uid() != unsafe { libc::geteuid() }
                {
                    return Err(Error::Invalid(
                        "vault file must be private and owned by this user".into(),
                    ));
                }
            }
            Ok(())
        }
        Err(e) if may_be_absent && e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Storage),
    }
}

fn lock_path(path: &Path) -> Result<File> {
    if path.to_str().is_none()
        || !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::Invalid(
            "vault needs an absolute path without parent components".into(),
        ));
    }
    let parent = path.parent().ok_or(Error::Storage)?;
    // Refuse symlink directory components, including the final directory. The
    // canonical path may be computed by the caller before choosing a new vault.
    for ancestor in parent.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| Error::Storage)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(Error::Storage);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(parent).map_err(|_| Error::Storage)?;
        if meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
            return Err(Error::Invalid(
                "vault directory must be mode 0700 and owned by this user".into(),
            ));
        }
    }
    for suffix in ["", "-wal", "-shm", "-journal", ".lock"] {
        private_file(
            &std::path::PathBuf::from(format!("{}{suffix}", path.display())),
            true,
        )?;
    }
    let lock_path = std::path::PathBuf::from(format!("{}.lock", path.display()));
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let lock = options.open(lock_path).map_err(|_| Error::Storage)?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| Error::Conflict("vault already open".into()))?;
    Ok(lock)
}

fn protected_connection(path: &Path, key: &StorageKey) -> Result<Connection> {
    private_file(path, false)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| Error::Storage)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| Error::Storage)?;
    let version: String = connection
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .map_err(|_| Error::Storage)?;
    if !version.starts_with("4.") {
        return Err(Error::Storage);
    }
    let hex = Zeroizing::new(
        key.bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    let pragma = Zeroizing::new(format!("x'{}'", hex.as_str()));
    connection
        .pragma_update(None, "key", pragma.as_str())
        .map_err(|_| Error::Storage)?;
    connection.execute_batch("PRAGMA cipher_memory_security=ON; PRAGMA cipher_plaintext_header_size=0; PRAGMA temp_store=MEMORY;")
        .map_err(|_| Error::Storage)?;
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|_| Error::Storage)?;
    connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON; PRAGMA foreign_keys=ON;")
        .map_err(|_| Error::Storage)?;
    Ok(connection)
}

fn frame(digest: &mut impl sha2::digest::Update, bytes: &[u8]) {
    digest.update(&(bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

/// Hash logical contents, not SQLite page layout. No row content is exposed or
/// formatted in error messages. Full scans deliberately trade scale for a small
/// auditable initial implementation. Bridge metadata is outside its own MAC.
fn checkpoint(db: &Connection, key: &[u8; 32], account: &str, revision: u64) -> Result<Anchor> {
    let mut hash = Sha256::new();
    frame(&mut hash, b"agent-yhes/vault-state/v1");
    frame(&mut hash, account.as_bytes());
    frame(&mut hash, &revision.to_be_bytes());
    let mut q = db
        .prepare("SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_master ORDER BY type,name")
        .map_err(|_| Error::Storage)?;
    let schema: Vec<(String, String, String, String)> = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(|_| Error::Storage)?
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Error::Storage)?;
    for (kind, name, table, sql) in schema {
        for s in [&kind, &name, &table, &sql] {
            frame(&mut hash, s.as_bytes());
        }
        if kind != "table" || name == "yhes_anchor_bridge" {
            continue;
        }
        let mut rows = db
            .prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))
            .map_err(|_| Error::Storage)?;
        let columns = rows.column_count();
        let mut hashes = Vec::new();
        let mut cursor = rows.query([]).map_err(|_| Error::Storage)?;
        while let Some(row) = cursor.next().map_err(|_| Error::Storage)? {
            let mut row_hash = Sha256::new();
            for i in 0..columns {
                match row.get_ref(i).map_err(|_| Error::Storage)? {
                    ValueRef::Null => frame(&mut row_hash, b"n"),
                    ValueRef::Integer(n) => {
                        frame(&mut row_hash, b"i");
                        frame(&mut row_hash, &n.to_be_bytes());
                    }
                    ValueRef::Real(n) => {
                        frame(&mut row_hash, b"r");
                        frame(&mut row_hash, &n.to_bits().to_be_bytes());
                    }
                    ValueRef::Text(s) => {
                        frame(&mut row_hash, b"t");
                        frame(&mut row_hash, s);
                    }
                    ValueRef::Blob(s) => {
                        frame(&mut row_hash, b"b");
                        frame(&mut row_hash, s);
                    }
                }
            }
            hashes.push(row_hash.finalize().to_vec());
        }
        hashes.sort_unstable();
        frame(&mut hash, &(hashes.len() as u64).to_be_bytes());
        for row in hashes {
            frame(&mut hash, &row);
        }
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| Error::Storage)?;
    Mac::update(&mut mac, &hash.finalize());
    let digest = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(Anchor { revision, digest })
}

fn bridge(db: &Connection) -> Result<(Option<Anchor>, Anchor)> {
    db.query_row("SELECT previous_revision,previous_digest,revision,digest FROM yhes_anchor_bridge WHERE id=1", [], |r| {
        let prev: Option<u64> = r.get(0)?;
        let previous=if let Some(revision)=prev {Some(Anchor{revision,digest:r.get(1)?})}else{None};
        Ok((previous,
            Anchor { revision: r.get(2)?, digest: r.get(3)? }))
    }).map_err(|_| Error::Storage)
}
fn write_bridge(db: &Connection, previous: Option<&Anchor>, next: &Anchor) -> Result<()> {
    db.execute(
        "INSERT OR REPLACE INTO yhes_anchor_bridge VALUES (1,?,?,?,?)",
        rusqlite::params![
            previous.map(|a| a.revision),
            previous.map(|a| a.digest.as_str()),
            next.revision,
            next.digest
        ],
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}

impl Vault {
    pub fn create(
        path: &Path,
        key: &StorageKey,
        project: &str,
        account: &str,
        anchors: Box<dyn AnchorStore>,
    ) -> Result<Self> {
        if project.is_empty() || project.len() > 128 || account.is_empty() || account.len() > 128 {
            return Err(Error::Invalid("invalid project or vault reference".into()));
        }
        let lock = lock_path(path)?;
        if anchors.load(account)?.is_some() {
            return Err(Error::Conflict("vault checkpoint already exists".into()));
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options
            .open(path)
            .map_err(|_| Error::Conflict("vault path already exists or is unavailable".into()))?;
        file.sync_all().map_err(|_| Error::Storage)?;
        // Interrupted initialization leaves an unusable file, never a fresh usable
        // ratchet. Do not remove it automatically or reinterpret it as a new vault.
        let mut connection = protected_connection(path, key)?;
        SqliteStorageProvider::<JsonCodec, _>::new(&mut connection)
            .run_migrations()
            .map_err(|_| Error::Storage)?;
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        tx.execute_batch("CREATE TABLE yhes_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
            CREATE TABLE yhes_registry (generation INTEGER PRIMARY KEY, digest TEXT UNIQUE NOT NULL, envelope BLOB NOT NULL);
            CREATE TABLE yhes_identity (id INTEGER PRIMARY KEY CHECK(id=1), principal TEXT NOT NULL, key_id TEXT NOT NULL, secret BLOB NOT NULL, public BLOB NOT NULL);
            CREATE TABLE yhes_groups (id TEXT PRIMARY KEY, mls_id BLOB NOT NULL, audience BLOB NOT NULL, last_commit TEXT, pending_operation TEXT, owner TEXT NOT NULL);
            CREATE TABLE yhes_outbox (id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, group_id TEXT NOT NULL, epoch INTEGER NOT NULL, kind TEXT NOT NULL, event_id TEXT NOT NULL, wire BLOB NOT NULL, status TEXT NOT NULL, receipt TEXT);
            CREATE TABLE yhes_inbox (digest TEXT PRIMARY KEY, event_id TEXT, sender TEXT, disposition TEXT NOT NULL, record BLOB NOT NULL);
            CREATE TABLE yhes_replay (principal TEXT NOT NULL, event_id TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(principal,event_id));
            CREATE TABLE yhes_authorizations (event_id TEXT PRIMARY KEY, operation TEXT NOT NULL, digest TEXT NOT NULL);
            CREATE TABLE yhes_anchor_bridge (id INTEGER PRIMARY KEY CHECK(id=1),previous_revision INTEGER,previous_digest TEXT,revision INTEGER NOT NULL,digest TEXT NOT NULL);
            INSERT INTO yhes_meta VALUES ('schema','1');").map_err(|_| Error::Storage)?;
        tx.execute(
            "INSERT INTO yhes_meta VALUES ('project',?)",
            [project.as_bytes()],
        )
        .map_err(|_| Error::Storage)?;
        tx.execute(
            "INSERT INTO yhes_meta VALUES ('vault_path',?)",
            [path.to_str().ok_or(Error::Storage)?.as_bytes()],
        )
        .map_err(|_| Error::Storage)?;
        let next = checkpoint(&tx, key.bytes(), account, 0)?;
        write_bridge(&tx, None, &next)?;
        if checkpoint(&tx, key.bytes(), account, 0)? != next {
            return Err(Error::Verification(
                "checkpoint changed during commit".into(),
            ));
        }
        tx.commit().map_err(|_| Error::Storage)?;
        File::open(path.parent().ok_or(Error::Storage)?)
            .and_then(|d| d.sync_all())
            .map_err(|_| Error::Storage)?;
        anchors.advance(account, None, &next)?;
        Ok(Self {
            connection,
            _lock: lock,
            account: account.to_owned(),
            anchors,
            mac_key: Zeroizing::new(*key.bytes()),
            poisoned: false,
        })
    }

    pub fn open(
        path: &Path,
        key: &StorageKey,
        expected_project: &str,
        account: &str,
        anchors: Box<dyn AnchorStore>,
    ) -> Result<Self> {
        let lock = lock_path(path)?;
        if fs::metadata(path).map_err(|_| Error::Storage)?.len() == 0 {
            return Err(Error::Storage);
        }
        let connection = protected_connection(path, key)?;
        let stored_path: Vec<u8> = connection
            .query_row(
                "SELECT value FROM yhes_meta WHERE key='vault_path'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| Error::Storage)?;
        if stored_path != path.to_str().ok_or(Error::Storage)?.as_bytes() {
            return Err(Error::Verification(
                "vault moved or cloned; recovery required".into(),
            ));
        }
        let project: Vec<u8> = connection
            .query_row("SELECT value FROM yhes_meta WHERE key='project'", [], |r| {
                r.get(0)
            })
            .map_err(|_| Error::Storage)?;
        if project != expected_project.as_bytes() {
            return Err(Error::Verification("vault project mismatch".into()));
        }
        let schema: String = connection
            .query_row("SELECT value FROM yhes_meta WHERE key='schema'", [], |r| {
                r.get(0)
            })
            .map_err(|_| Error::Storage)?;
        if schema != "1" {
            return Err(Error::Invalid("unsupported vault schema".into()));
        }
        let vault = Self {
            connection,
            _lock: lock,
            account: account.to_owned(),
            anchors,
            mac_key: Zeroizing::new(*key.bytes()),
            poisoned: false,
        };
        vault.check_anchor()?;
        Ok(vault)
    }

    fn check_anchor(&self) -> Result<Anchor> {
        if self.poisoned {
            return Err(Error::Conflict(
                "vault needs reopen after checkpoint failure".into(),
            ));
        }
        let (previous, next) = bridge(&self.connection)?;
        let calculated = checkpoint(
            &self.connection,
            &self.mac_key,
            &self.account,
            next.revision,
        )?;
        if next != calculated {
            return Err(Error::Verification(
                "vault checkpoint mismatch; quarantine required".into(),
            ));
        }
        let trusted = self.anchors.load(&self.account)?.ok_or_else(|| {
            Error::Verification("external checkpoint missing; quarantine required".into())
        })?;
        if trusted == next {
            return Ok(next);
        }
        if previous.as_ref() == Some(&trusted)
            && trusted.revision.checked_add(1) == Some(next.revision)
        {
            // One authenticated crash bridge: DB committed, external anchor did not.
            self.anchors.advance(&self.account, Some(&trusted), &next)?;
            return Ok(next);
        }
        Err(Error::Verification(
            "vault was restored or forked; quarantine required".into(),
        ))
    }

    pub(crate) fn transaction<T>(
        &mut self,
        action: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<T> {
        let previous = self.check_anchor()?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        let result = action(&tx)?;
        // Read-only/idempotent operations do not consume protected revisions.
        if checkpoint(&tx, &self.mac_key, &self.account, previous.revision)? == previous {
            tx.commit().map_err(|_| Error::Storage)?;
            return Ok(result);
        }
        let revision = previous.revision.checked_add(1).ok_or(Error::Storage)?;
        let next = checkpoint(&tx, &self.mac_key, &self.account, revision)?;
        write_bridge(&tx, Some(&previous), &next)?;
        if checkpoint(&tx, &self.mac_key, &self.account, revision)? != next {
            return Err(Error::Verification(
                "checkpoint changed during commit".into(),
            ));
        }
        tx.commit().map_err(|_| Error::Storage)?;
        if self
            .anchors
            .advance(&self.account, Some(&previous), &next)
            .is_err()
        {
            self.poisoned = true;
            return Err(Error::CheckpointPending); // Never release prepared ciphertext/result before anchor commit.
        }
        Ok(result)
    }

    pub fn cipher_version(&self) -> Result<String> {
        self.connection
            .query_row("PRAGMA cipher_version", [], |r| r.get(0))
            .map_err(|_| Error::Storage)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    #[derive(Clone, Default)]
    pub(crate) struct MemoryAnchors(pub Rc<RefCell<Option<Anchor>>>, pub Rc<RefCell<bool>>);
    impl AnchorStore for MemoryAnchors {
        fn load(&self, _: &str) -> Result<Option<Anchor>> {
            Ok(self.0.borrow().clone())
        }
        fn advance(&self, _: &str, expected: Option<&Anchor>, next: &Anchor) -> Result<()> {
            if *self.1.borrow() {
                return Err(Error::KeyProvider("injected failure".into()));
            }
            if self.0.borrow().as_ref() != expected {
                return Err(Error::Conflict("anchor mismatch".into()));
            }
            *self.0.borrow_mut() = Some(next.clone());
            Ok(())
        }
    }
    pub(crate) fn fixture() -> (tempfile::TempDir, StorageKey, MemoryAnchors, Vault) {
        let directory = tempfile::tempdir().unwrap();
        let dir = directory.path().canonicalize().unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let key = StorageKey::from_bytes([37; 32]);
        let anchors = MemoryAnchors::default();
        let vault = Vault::create(
            &dir.join("vault.db"),
            &key,
            "fixture",
            "test",
            Box::new(anchors.clone()),
        )
        .unwrap();
        (directory, key, anchors, vault)
    }
    #[test]
    fn encrypted_database_and_wal_do_not_expose_private_payload() {
        let (directory, key, anchors, mut vault) = fixture();
        let path = directory.path().canonicalize().unwrap().join("vault.db");
        let marker = b"CONFIDENTIAL_YHES_PRIVATE_STATE_47103";
        vault
            .transaction(|db| {
                db.execute(
                    "INSERT INTO yhes_meta VALUES ('secret',?)",
                    [marker.as_slice()],
                )
                .map_err(|_| Error::Storage)?;
                Ok(())
            })
            .unwrap();
        for f in fs::read_dir(directory.path()).unwrap() {
            let bytes = fs::read(f.unwrap().path()).unwrap();
            assert!(!bytes.windows(marker.len()).any(|w| w == marker));
            assert!(!bytes.starts_with(b"SQLite format 3"));
        }
        drop(vault);
        assert!(Vault::open(
            &path,
            &StorageKey::from_bytes([38; 32]),
            "fixture",
            "test",
            Box::new(anchors.clone())
        )
        .is_err());
        assert!(Vault::open(
            &path,
            &key,
            "wrong-project",
            "test",
            Box::new(anchors.clone())
        )
        .is_err());
        Vault::open(&path, &key, "fixture", "test", Box::new(anchors)).unwrap();
    }
    #[test]
    fn rollback_and_exclusive_lock() {
        let (directory, key, anchors, mut vault) = fixture();
        let path = directory.path().canonicalize().unwrap().join("vault.db");
        assert!(Vault::open(&path, &key, "fixture", "test", Box::new(anchors)).is_err());
        let before = vault.check_anchor().unwrap();
        let result: Result<()> = vault.transaction(|db| {
            db.execute("INSERT INTO yhes_meta VALUES ('uncommitted','value')", [])
                .map_err(|_| Error::Storage)?;
            Err(Error::Mls)
        });
        assert!(result.is_err());
        assert_eq!(vault.check_anchor().unwrap().digest, before.digest);
    }
    #[test]
    fn crash_bridge_recovers_but_restored_database_is_quarantined() {
        let (directory, key, anchors, mut vault) = fixture();
        let path = directory.path().canonicalize().unwrap().join("vault.db");
        vault
            .connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let old = fs::read(&path).unwrap();
        *anchors.1.borrow_mut() = true;
        assert!(vault
            .transaction(|db| {
                db.execute("INSERT INTO yhes_meta VALUES ('durable','value')", [])
                    .map_err(|_| Error::Storage)?;
                Ok(())
            })
            .is_err());
        assert!(vault.transaction(|_| Ok(())).is_err());
        drop(vault);
        *anchors.1.borrow_mut() = false;
        let vault = Vault::open(&path, &key, "fixture", "test", Box::new(anchors.clone())).unwrap();
        assert_eq!(vault.check_anchor().unwrap().revision, 1);
        drop(vault);
        fs::write(&path, old).unwrap();
        assert!(Vault::open(&path, &key, "fixture", "test", Box::new(anchors)).is_err());
    }
    #[test]
    fn incomplete_initialization_and_symlinks_are_refused() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        let p = d.path().canonicalize().unwrap().join("vault.db");
        fs::write(&p, b"").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Vault::open(
            &p,
            &StorageKey::generate(),
            "fixture",
            "test",
            Box::new(MemoryAnchors::default())
        )
        .is_err());
        fs::remove_file(&p).unwrap();
        symlink("missing", &p).unwrap();
        assert!(Vault::create(
            &p,
            &StorageKey::generate(),
            "fixture",
            "test",
            Box::new(MemoryAnchors::default())
        )
        .is_err());
    }
}

#[cfg(test)]
mod process_tests {
    use super::*;
    use std::path::PathBuf;
    // Test-only public checkpoint fixture. This is deliberately not an installed
    // AnchorStore implementation and is never selected by a production flag.
    struct FixtureAnchor {
        path: PathBuf,
        kill_on_advance: bool,
    }
    impl AnchorStore for FixtureAnchor {
        fn load(&self, _: &str) -> Result<Option<Anchor>> {
            if !self.path.exists() {
                return Ok(None);
            }
            let bytes = fs::read(&self.path).map_err(|_| Error::Storage)?;
            let (revision, digest): (u64, String) =
                serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
            Ok(Some(Anchor { revision, digest }))
        }
        fn advance(&self, account: &str, expected: Option<&Anchor>, next: &Anchor) -> Result<()> {
            if self.load(account)?.as_ref() != expected {
                return Err(Error::Conflict("fixture anchor mismatch".into()));
            }
            if self.kill_on_advance {
                unsafe {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                }
                unreachable!();
            }
            fs::write(
                &self.path,
                serde_json::to_vec(&(next.revision, &next.digest)).unwrap(),
            )
            .map_err(|_| Error::Storage)
        }
    }
    #[test]
    fn crash_worker() {
        let Some(dir) = std::env::var_os("YHES_TEST_CRASH_DIR") else {
            return;
        };
        let d = PathBuf::from(dir);
        let after = std::env::var("YHES_TEST_CRASH_STAGE").unwrap() == "after";
        let key = StorageKey::from_bytes([82; 32]);
        let mut vault = Vault::open(
            &d.join("vault.db"),
            &key,
            "crash-test",
            "crash",
            Box::new(FixtureAnchor {
                path: d.join("checkpoint"),
                kill_on_advance: after,
            }),
        )
        .unwrap();
        let _ = vault.transaction(|db| {
            let signer=crate::mls::AgentSigner::load(db)?;
            let sealed=crate::mls::send(db,&signer,b"crash-fixture",b"PRIVATE_CRASH_ATOMICITY_49510")?;
            db.execute("INSERT INTO yhes_outbox VALUES ('crash-send','fixture','crash-group',0,'application','crash-event',?,'prepared',NULL)",[sealed.ciphertext]).map_err(|_|Error::Storage)?;
            db.execute(
                "INSERT INTO yhes_meta VALUES ('crash-marker',?)",
                [b"PRIVATE_CRASH_ATOMICITY_49510".as_slice()],
            )
            .map_err(|_| Error::Storage)?;
            if !after {
                unsafe {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                }
                unreachable!();
            }
            Ok(())
        });
        panic!("worker was not killed");
    }
    #[test]
    fn real_process_kill_before_and_after_commit() {
        use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
        for stage in ["before", "after"] {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().canonicalize().unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            let key = StorageKey::from_bytes([82; 32]);
            let anchor = || {
                Box::new(FixtureAnchor {
                    path: p.join("checkpoint"),
                    kill_on_advance: false,
                }) as Box<dyn AnchorStore>
            };
            let mut initial =
                Vault::create(&p.join("vault.db"), &key, "crash-test", "crash", anchor()).unwrap();
            initial
                .transaction(|db| {
                    let signer = crate::mls::AgentSigner::init(db, "crash-agent")?;
                    crate::mls::create(db, &signer, b"crash-fixture")?;
                    Ok(())
                })
                .unwrap();
            drop(initial);
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::process_tests::crash_worker",
                    "--nocapture",
                ])
                .env("YHES_TEST_CRASH_DIR", &p)
                .env("YHES_TEST_CRASH_STAGE", stage)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            let vault =
                Vault::open(&p.join("vault.db"), &key, "crash-test", "crash", anchor()).unwrap();
            let found: i64 = vault
                .connection
                .query_row(
                    "SELECT count(*) FROM yhes_meta WHERE key='crash-marker'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(found, if stage == "after" { 1 } else { 0 });
            let outbox: i64 = vault
                .connection
                .query_row(
                    "SELECT count(*) FROM yhes_outbox WHERE id='crash-send'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(outbox, found);
            assert_eq!(
                vault.check_anchor().unwrap().revision,
                if stage == "after" { 2 } else { 1 }
            );
        }
    }
}

#[cfg(test)]
mod integrity_tests {
    use super::*;
    #[test]
    fn a_bridge_trigger_cannot_change_rows_after_their_checkpoint_is_computed() {
        let (_directory, _key, _anchors, mut vault) = super::tests::fixture();
        let before = vault.check_anchor().unwrap().digest;
        let result=vault.transaction(|db|{
            db.execute_batch("CREATE TRIGGER change_after_mac AFTER INSERT ON yhes_anchor_bridge BEGIN INSERT OR REPLACE INTO yhes_meta VALUES ('injected','value'); END;").map_err(|_|Error::Storage)?;
            Ok(())
        });
        assert!(matches!(result, Err(Error::Verification(_))));
        assert_eq!(vault.check_anchor().unwrap().digest, before);
        let triggers: i64 = vault
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='trigger'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(triggers, 0);
    }
    #[test]
    fn cloned_path_and_missing_initial_anchor_are_never_auto_trusted() {
        use std::os::unix::fs::PermissionsExt;
        let (directory, key, anchors, vault) = super::tests::fixture();
        drop(vault);
        let original = directory.path().canonicalize().unwrap().join("vault.db");
        let clone = tempfile::tempdir().unwrap();
        let dir = clone.path().canonicalize().unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("vault.db");
        fs::copy(&original, &path).unwrap();
        assert!(Vault::open(&path, &key, "fixture", "test", Box::new(anchors.clone())).is_err());
        *anchors.0.borrow_mut() = None;
        assert!(Vault::open(&original, &key, "fixture", "test", Box::new(anchors)).is_err());
    }
}
