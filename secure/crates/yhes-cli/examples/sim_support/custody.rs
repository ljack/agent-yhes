//! SIMULATION ONLY: plaintext random storage keys and an add-only file chain.
//! Unlike Keychain, this is deliberately erasable by the same OS user.
use super::fs;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use yhes_cli::{Custody, Failure};
use yhes_core::{
    keys::{Anchor, AnchorStore, StorageKey},
    Error, Result,
};

fn storage(_: Failure) -> Error {
    Error::KeyProvider("simulation file custody is unavailable".into())
}
fn conflict() -> Error {
    Error::Conflict("simulation checkpoint mismatch".into())
}

pub struct Files {
    root: PathBuf,
    account: String,
}

impl Files {
    pub fn new(role_root: &Path, account: String) -> std::result::Result<Self, Failure> {
        let root = role_root.join("custody");
        fs::directory(&root)?;
        fs::directory(&root.join("anchors"))?;
        fs::tree(&root, true)?;
        Ok(Self { root, account })
    }
    fn key_path(&self, account: &str) -> Result<PathBuf> {
        if account != self.account {
            return Err(conflict());
        }
        Ok(self.root.join("vault.key"))
    }
}

impl Custody for Files {
    fn label(&self) -> &'static str {
        "simulation-files"
    }
    fn create_key(&self, account: &str) -> Result<StorageKey> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let added = fs::add(&self.key_path(account)?, &bytes).map_err(storage)?;
        let key = StorageKey::from_bytes(bytes);
        bytes.fill(0);
        if !added {
            return Err(Error::Conflict(
                "simulation vault key already exists".into(),
            ));
        }
        Ok(key)
    }
    fn load_key(&self, account: &str) -> Result<StorageKey> {
        let mut bytes = fs::read(&self.key_path(account)?, 32, true).map_err(storage)?;
        let raw: [u8; 32] = bytes.as_slice().try_into().map_err(|_| Error::Storage)?;
        bytes.fill(0);
        Ok(StorageKey::from_bytes(raw))
    }
    fn anchors(&self) -> Box<dyn AnchorStore> {
        Box::new(Anchors {
            root: self.root.join("anchors"),
            account: self.account.clone(),
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Point {
    revision: u64,
    digest: String,
}
impl From<&Anchor> for Point {
    fn from(a: &Anchor) -> Self {
        Self {
            revision: a.revision,
            digest: a.digest.clone(),
        }
    }
}
impl From<Point> for Anchor {
    fn from(a: Point) -> Self {
        Self {
            revision: a.revision,
            digest: a.digest,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    account: String,
    previous: Option<Point>,
    next: Point,
}

pub struct Anchors {
    root: PathBuf,
    account: String,
}
impl Anchors {
    fn account(&self, account: &str) -> Result<()> {
        if account != self.account {
            return Err(conflict());
        }
        Ok(())
    }
    fn valid(anchor: &Anchor) -> Result<()> {
        if anchor.digest.len() != 64
            || !anchor
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn head(&self) -> Result<Option<Anchor>> {
        fs::path(&self.root, true, true).map_err(storage)?;
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&self.root).map_err(|_| Error::Storage)? {
            let entry = entry.map_err(|_| Error::Storage)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Storage)?;
            // A crash may leave an unlinked publication scratch file. It is
            // never authoritative. Validate even ignored files, then leave it.
            if name.starts_with(".sim-write-") {
                fs::path(&entry.path(), false, true).map_err(storage)?;
                continue;
            }
            files.push((name, entry.path()));
            if files.len() > 100_000 {
                return Err(Error::Storage);
            }
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut head: Option<Anchor> = None;
        for (name, path) in files {
            let bytes = fs::read(&path, 4096, true).map_err(storage)?;
            let record: Record = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
            let next: Anchor = record.next.clone().into();
            Self::valid(&next)?;
            if record.version != 1
                || record.account != self.account
                || record.previous != head.as_ref().map(Point::from)
                || name != format!("{:020}.json", next.revision)
                || head.as_ref().map_or(next.revision != 0, |p| {
                    p.revision.checked_add(1) != Some(next.revision)
                })
            {
                return Err(conflict());
            }
            head = Some(next);
        }
        Ok(head)
    }
}

impl AnchorStore for Anchors {
    fn load(&self, account: &str) -> Result<Option<Anchor>> {
        self.account(account)?;
        self.head()
    }
    fn advance(&self, account: &str, expected: Option<&Anchor>, next: &Anchor) -> Result<()> {
        self.account(account)?;
        Self::valid(next)?;
        if let Some(prior) = expected {
            Self::valid(prior)?;
        }
        if expected.map_or(next.revision != 0, |p| {
            p.revision.checked_add(1) != Some(next.revision)
        }) {
            return Err(conflict());
        }
        // The outer per-role command lock also serializes the engine. Atomic
        // add-only revision slots remain the CAS authority across providers.
        let head = self.head()?;
        if head.as_ref() == Some(next) {
            let bytes = fs::read(
                &self.root.join(format!("{:020}.json", next.revision)),
                4096,
                true,
            )
            .map_err(storage)?;
            let record: Record = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
            return if record.previous == expected.map(Point::from) {
                Ok(())
            } else {
                Err(conflict())
            };
        }
        if head.as_ref() != expected {
            return Err(conflict());
        }
        let record = Record {
            version: 1,
            account: account.into(),
            previous: expected.map(Point::from),
            next: Point::from(next),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| Error::Storage)?;
        let file = self.root.join(format!("{:020}.json", next.revision));
        fs::add(&file, &bytes).map_err(storage)?;
        if fs::read(&file, 4096, true).map_err(storage)? != bytes
            || self.head()?.as_ref() != Some(next)
        {
            return Err(conflict());
        }
        Ok(())
    }
}
