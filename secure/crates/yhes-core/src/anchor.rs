//! External checkpoint stored beside the encrypted vault.
//!
//! Root computes the HMAC digest and decides the next revision. This module
//! publishes that checkpoint as an add-only Data Protection record. A copied
//! or swapped database path can bypass the caller's filesystem lock, so the
//! lock is not the publication authority. The Keychain account is one slot
//! per logical account and revision; `SecItemAdd` decides the winner.
//!
//! A mutable head hint may be written afterward to speed up a later lookup.
//! Load rebuilds the head from the add-only chain and never trusts the hint.
//! History is not deleted or rewritten here.

use std::collections::BTreeMap;

use crate::{Error, Result};

use super::{account_valid, ProtectionScope, ANCHOR_SERVICE, VAULT_SERVICE};

pub const ANCHOR_DIGEST_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub revision: u64,
    pub digest: String,
}

pub trait AnchorStore {
    /// Read the authoritative checkpoint.
    ///
    /// `Ok(None)` means the account has no add-only history. A head hint is
    /// not a checkpoint. Unreadable bytes, a legacy single-item record, a gap,
    /// or two digests for one revision are errors and are left in place.
    fn load(&self, account: &str) -> Result<Option<Anchor>>;

    /// Publish `next` when `expected` is the authoritative predecessor.
    ///
    /// `expected == None` inserts the first record, or succeeds again when
    /// that exact record is still the head. `expected == Some` inserts the
    /// following revision only when the stored head equals `expected` and
    /// `next.revision` is `expected.revision + 1`. An exact retry of the
    /// published head does not insert another record. A different digest for
    /// an occupied revision is a conflict. This never writes vault key material
    /// and never deletes older checkpoints.
    fn advance(&self, account: &str, expected: Option<&Anchor>, next: &Anchor) -> Result<()>;
}

pub(super) enum Advance {
    Insert(Vec<u8>),
    Hint(Vec<u8>),
}

#[derive(Clone, Debug)]
struct StoredRecord {
    raw: Vec<u8>,
    predecessor: Option<Anchor>,
    anchor: Anchor,
}

#[derive(Clone, Debug)]
pub(super) struct History {
    logical: String,
    legacy_present: bool,
    malformed: bool,
    raw: BTreeMap<String, Vec<Vec<u8>>>,
    genesis: Vec<StoredRecord>,
    successors: BTreeMap<u64, Vec<StoredRecord>>,
}

enum Class {
    Genesis,
    Revision(u64),
    Hint,
    Legacy,
    Malformed,
    Unrelated,
}

enum Decision {
    Already,
    Add { account: String, bytes: Vec<u8> },
}

pub(super) fn genesis_account(logical: &str) -> String {
    format!("g1:{logical}")
}

pub(super) fn revision_account(logical: &str, revision: u64) -> String {
    format!("a1:{logical}:{revision}")
}

pub(super) fn hint_account(logical: &str) -> String {
    format!("h1:{logical}")
}

pub(super) fn is_duplicate(error: &Error) -> bool {
    matches!(error, Error::Conflict(message) if message == "checkpoint already exists")
}

fn unreadable() -> Error {
    Error::KeyProvider("checkpoint record is unreadable".into())
}

fn mismatch() -> Error {
    Error::Conflict("checkpoint mismatch".into())
}

fn canonical_revision(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value = text.parse::<u64>().ok()?;
    if value.to_string() == text {
        Some(value)
    } else {
        None
    }
}

fn classify(logical: &str, account: &str) -> Class {
    if account_valid(logical).is_err() {
        return Class::Malformed;
    }
    if account == logical {
        return Class::Legacy;
    }
    if let Some(name) = account.strip_prefix("g1:") {
        return if name == logical {
            Class::Genesis
        } else {
            Class::Unrelated
        };
    }
    if let Some(name) = account.strip_prefix("h1:") {
        return if name == logical {
            Class::Hint
        } else {
            Class::Unrelated
        };
    }
    if let Some(rest) = account.strip_prefix("a1:") {
        if let Some((name, revision)) = rest.rsplit_once(':') {
            if name != logical {
                return Class::Unrelated;
            }
            return match canonical_revision(revision) {
                Some(revision) => Class::Revision(revision),
                None => Class::Malformed,
            };
        }
        if rest == logical {
            return Class::Malformed;
        }
        return Class::Unrelated;
    }
    Class::Unrelated
}

fn is_genesis_account(account: &str) -> bool {
    account
        .strip_prefix("g1:")
        .is_some_and(|name| account_valid(name).is_ok())
}

fn is_hint_account(account: &str) -> bool {
    account
        .strip_prefix("h1:")
        .is_some_and(|name| account_valid(name).is_ok())
}

fn is_revision_account(account: &str) -> bool {
    let Some(rest) = account.strip_prefix("a1:") else {
        return false;
    };
    let Some((name, revision)) = rest.rsplit_once(':') else {
        return false;
    };
    account_valid(name).is_ok() && canonical_revision(revision).is_some()
}

pub(super) fn validate_anchor(anchor: &Anchor) -> Result<()> {
    if anchor.digest.len() != ANCHOR_DIGEST_LEN
        || !anchor
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::Invalid(
            "checkpoint digest must be 64 lowercase hex characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn encode_anchor(anchor: &Anchor) -> Result<Vec<u8>> {
    validate_anchor(anchor)?;
    let mut bytes = Vec::with_capacity(16 + 20 + ANCHOR_DIGEST_LEN);
    bytes.extend_from_slice(b"yhes-anchor-v1\n");
    bytes.extend_from_slice(anchor.revision.to_string().as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(anchor.digest.as_bytes());
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
pub(super) fn decode_anchor(bytes: &[u8]) -> Result<Anchor> {
    let text = std::str::from_utf8(bytes).map_err(|_| unreadable())?;
    let mut lines = text.split('\n');
    let magic = lines.next();
    let revision = lines.next();
    let digest = lines.next();
    let trailer = lines.next();
    if magic != Some("yhes-anchor-v1") || trailer != Some("") || lines.next().is_some() {
        return Err(unreadable());
    }
    let revision = revision.unwrap_or("");
    if canonical_revision(revision).is_none() {
        return Err(unreadable());
    }
    let revision = revision.parse().map_err(|_| unreadable())?;
    let anchor = Anchor {
        revision,
        digest: digest.unwrap_or("").to_string(),
    };
    validate_anchor(&anchor)?;
    if encode_anchor(&anchor)? != bytes {
        return Err(unreadable());
    }
    Ok(anchor)
}

pub(super) fn encode_record(predecessor: Option<&Anchor>, anchor: &Anchor) -> Result<Vec<u8>> {
    validate_anchor(anchor)?;
    if let Some(predecessor) = predecessor {
        validate_anchor(predecessor)?;
        if predecessor.revision.checked_add(1) != Some(anchor.revision) {
            return Err(mismatch());
        }
    }
    let mut bytes = Vec::with_capacity(64 + ANCHOR_DIGEST_LEN * 2);
    bytes.extend_from_slice(b"yhes-anchor-v2\n");
    bytes.extend_from_slice(anchor.revision.to_string().as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(anchor.digest.as_bytes());
    bytes.push(b'\n');
    match predecessor {
        None => bytes.extend_from_slice(b"-\n-\n"),
        Some(predecessor) => {
            bytes.extend_from_slice(predecessor.revision.to_string().as_bytes());
            bytes.push(b'\n');
            bytes.extend_from_slice(predecessor.digest.as_bytes());
            bytes.push(b'\n');
        }
    }
    Ok(bytes)
}

pub(super) fn decode_record(bytes: &[u8]) -> Result<(Option<Anchor>, Anchor)> {
    let text = std::str::from_utf8(bytes).map_err(|_| unreadable())?;
    let mut lines = text.split('\n');
    let magic = lines.next();
    let revision = lines.next();
    let digest = lines.next();
    let predecessor_revision = lines.next();
    let predecessor_digest = lines.next();
    let trailer = lines.next();
    if magic != Some("yhes-anchor-v2") || trailer != Some("") || lines.next().is_some() {
        return Err(unreadable());
    }
    let revision = canonical_revision(revision.unwrap_or("")).ok_or_else(unreadable)?;
    let anchor = Anchor {
        revision,
        digest: digest.unwrap_or("").to_string(),
    };
    validate_anchor(&anchor)?;
    let predecessor = match (
        predecessor_revision.unwrap_or(""),
        predecessor_digest.unwrap_or(""),
    ) {
        ("-", "-") => None,
        (revision, digest) => {
            let revision = canonical_revision(revision).ok_or_else(unreadable)?;
            let predecessor = Anchor {
                revision,
                digest: digest.to_string(),
            };
            validate_anchor(&predecessor)?;
            if predecessor.revision.checked_add(1) != Some(anchor.revision) {
                return Err(unreadable());
            }
            Some(predecessor)
        }
    };
    if encode_record(predecessor.as_ref(), &anchor)? != bytes {
        return Err(unreadable());
    }
    Ok((predecessor, anchor))
}

pub(super) fn history_from_pairs(logical: &str, pairs: &[(String, Vec<u8>)]) -> History {
    let mut history = History {
        logical: logical.to_string(),
        legacy_present: false,
        malformed: false,
        raw: BTreeMap::new(),
        genesis: Vec::new(),
        successors: BTreeMap::new(),
    };
    for (account, bytes) in pairs {
        match classify(logical, account) {
            Class::Unrelated | Class::Hint => {}
            Class::Legacy => history.legacy_present = true,
            Class::Malformed => history.malformed = true,
            Class::Genesis => {
                history
                    .raw
                    .entry(account.clone())
                    .or_default()
                    .push(bytes.clone());
                match decode_record(bytes) {
                    Ok((None, anchor)) => history.genesis.push(StoredRecord {
                        raw: bytes.clone(),
                        predecessor: None,
                        anchor,
                    }),
                    _ => history.malformed = true,
                }
            }
            Class::Revision(revision) => {
                history
                    .raw
                    .entry(account.clone())
                    .or_default()
                    .push(bytes.clone());
                match decode_record(bytes) {
                    Ok((Some(predecessor), anchor)) if anchor.revision == revision => {
                        history
                            .successors
                            .entry(revision)
                            .or_default()
                            .push(StoredRecord {
                                raw: bytes.clone(),
                                predecessor: Some(predecessor),
                                anchor,
                            });
                    }
                    _ => history.malformed = true,
                }
            }
        }
    }
    history
}

fn resolve_record(history: &History) -> Result<Option<StoredRecord>> {
    if history.malformed || history.legacy_present {
        return Err(unreadable());
    }
    if history.genesis.len() > 1
        || history
            .successors
            .values()
            .any(|versions| versions.len() != 1)
    {
        return Err(mismatch());
    }
    if history.genesis.is_empty() {
        if history.successors.is_empty() && history.raw.is_empty() {
            return Ok(None);
        }
        return Err(mismatch());
    }
    let origin = history.genesis[0].anchor.revision;
    let mut current = history.genesis[0].clone();
    while let Some(next_rev) = current.anchor.revision.checked_add(1) {
        let Some(versions) = history.successors.get(&next_rev) else {
            break;
        };
        let next = &versions[0];
        if next.anchor.revision != next_rev || next.predecessor.as_ref() != Some(&current.anchor) {
            return Err(mismatch());
        }
        current = next.clone();
    }
    let spanned =
        usize::try_from(current.anchor.revision.saturating_sub(origin)).unwrap_or(usize::MAX);
    if history.successors.len() != spanned {
        return Err(mismatch());
    }
    for revision in history.successors.keys() {
        if *revision <= origin || *revision > current.anchor.revision {
            return Err(mismatch());
        }
    }
    Ok(Some(current))
}

pub(super) fn resolve_head(history: &History) -> Result<Option<Anchor>> {
    Ok(resolve_record(history)?.map(|record| record.anchor))
}

fn decide(history: &History, expected: Option<&Anchor>, next: &Anchor) -> Result<Decision> {
    validate_anchor(next)?;
    if let Some(expected) = expected {
        validate_anchor(expected)?;
    }
    let current = resolve_record(history)?;
    match (current, expected) {
        (None, None) => Ok(Decision::Add {
            account: genesis_account(&history.logical),
            bytes: encode_record(None, next)?,
        }),
        (None, Some(_)) => Err(Error::Conflict("checkpoint is missing".into())),
        (Some(current), None) => {
            if history.successors.is_empty()
                && current.predecessor.is_none()
                && current.anchor == *next
            {
                Ok(Decision::Already)
            } else {
                Err(Error::Conflict("checkpoint already exists".into()))
            }
        }
        (Some(current), Some(expected)) => {
            let retry = current.anchor == *next
                && (current.predecessor.as_ref() == Some(expected) || current.anchor == *expected);
            if retry {
                return Ok(Decision::Already);
            }
            let Some(successor) = expected.revision.checked_add(1) else {
                return Err(mismatch());
            };
            if current.anchor == *expected && next.revision == successor {
                Ok(Decision::Add {
                    account: revision_account(&history.logical, next.revision),
                    bytes: encode_record(Some(expected), next)?,
                })
            } else {
                Err(mismatch())
            }
        }
    }
}

fn stored_bytes_match(history: &History, account: &str, bytes: &[u8]) -> Result<()> {
    match history.raw.get(account).map(Vec::as_slice) {
        Some([only]) if only.as_slice() == bytes => Ok(()),
        Some(_) => Err(mismatch()),
        None => Err(Error::Conflict("checkpoint is missing".into())),
    }
}

/// Publish one add-only record, then confirm the chain head is `next`.
///
/// `add_only` returns the duplicate-item conflict when the slot is taken.
/// The winner's bytes stay. A later hint write is best-effort.
pub(super) fn publish<L, A, H>(
    mut load_history: L,
    mut add_only: A,
    mut write_hint: H,
    expected: Option<&Anchor>,
    next: &Anchor,
) -> Result<()>
where
    L: FnMut() -> Result<History>,
    A: FnMut(&str, &[u8]) -> Result<()>,
    H: FnMut(&[u8]) -> Result<()>,
{
    let history = load_history()?;
    match decide(&history, expected, next)? {
        Decision::Already => {
            let confirmed = load_history()?;
            let record = resolve_record(&confirmed)?
                .ok_or_else(|| Error::Conflict("checkpoint is missing".into()))?;
            if record.anchor != *next {
                return Err(mismatch());
            }
            // The hint is not the checkpoint. The add-only chain already holds it.
            let _ = write_hint(&record.raw);
            Ok(())
        }
        Decision::Add { account, bytes } => {
            match add_only(&account, &bytes) {
                Ok(()) => {}
                Err(error) if is_duplicate(&error) => {}
                Err(error) => return Err(error),
            }
            let confirmed = load_history()?;
            stored_bytes_match(&confirmed, &account, &bytes)?;
            let head = resolve_head(&confirmed)?;
            if head.as_ref() != Some(next) {
                return Err(mismatch());
            }
            let _ = write_hint(&bytes);
            Ok(())
        }
    }
}

impl AnchorStore for super::PlatformKeychain {
    fn load(&self, account: &str) -> Result<Option<Anchor>> {
        account_valid(account)?;
        super::platform::load_anchor(account)
    }

    fn advance(&self, account: &str, expected: Option<&Anchor>, next: &Anchor) -> Result<()> {
        account_valid(account)?;
        validate_anchor(next)?;
        if let Some(expected) = expected {
            validate_anchor(expected)?;
        }
        super::platform::advance_anchor(account, expected, next)
    }
}

pub(super) fn apply_planned(
    scope: &ProtectionScope<'_>,
    planned: Advance,
    insert: impl FnOnce(&[u8]) -> Result<()>,
    hint: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<()> {
    if scope.service == VAULT_SERVICE {
        return Err(Error::Invalid(
            "refusing to update vault key material".into(),
        ));
    }
    if scope.service != ANCHOR_SERVICE {
        return Err(Error::Invalid("unknown keychain service".into()));
    }
    match planned {
        Advance::Insert(bytes)
            if is_genesis_account(scope.account) || is_revision_account(scope.account) =>
        {
            insert(&bytes)
        }
        Advance::Hint(bytes) if is_hint_account(scope.account) => hint(&bytes),
        Advance::Insert(_) | Advance::Hint(_) => Err(Error::Invalid(
            "refusing to rewrite a protected checkpoint".into(),
        )),
    }
}
