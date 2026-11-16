//! Same-machine append-only transport. Public files are evidence to verify, not
//! authority over keys or actions. Native approval and all private state stay out.
use crate::{
    engine::{Delivery, Engine},
    packet,
    pilot::RecordInfo,
    Error, Result,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use yhes_wire::Digest;

const MAX_ENTRY: u64 = 2 * 1024 * 1024;
const MAX_LOG: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 4096;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entry {
    pub(crate) version: u8,
    pub(crate) project: String,
    pub(crate) sequence: u64,
    pub(crate) previous: Option<String>,
    pub(crate) packet: String,
}
pub(crate) struct Stored {
    pub(crate) entry: Entry,
    pub(crate) digest: String,
    pub(crate) packet: Vec<u8>,
    pub(crate) encoded_size: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Membership {
    packet_digest: String,
    epoch: u64,
    audience: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    sequence: u64,
    head: Option<String>,
    group: String,
    owner: String,
    membership: Option<Membership>,
}

pub struct LocalChannel {
    root: PathBuf,
    project: String,
    channel_id: String,
    max_records: usize,
    max_log: u64,
}
#[derive(Serialize, Debug)]
pub struct Publication {
    pub operation: String,
    pub packet_digest: String,
    pub sequence: u64,
    pub replayed: bool,
}
#[derive(Serialize)]
pub struct SyncResult {
    pub processed: usize,
    pub deliveries: Vec<Delivery>,
}
fn io<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|_| Error::Storage)
}
fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut options = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            options.mode(0o700);
        }
        match options.create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Error::Storage),
        }
    }
    let meta = io(fs::symlink_metadata(path))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(Error::Invalid(
            "channel directory must not be a symlink".into(),
        ));
    }
    Ok(())
}
fn regular(path: &Path) -> Result<File> {
    let metadata = io(fs::symlink_metadata(path))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::Invalid(
            "channel record must be a regular file".into(),
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    io(options.open(path))
}
impl LocalChannel {
    // Remote adapters share the same protected cursor and membership admission
    // rules. They must validate the entire bounded record chain before calling
    // these helpers; this view performs no filesystem reads or publications.
    fn transport_view(project: &str, binding: &[u8]) -> Result<Self> {
        packet::id(project)?;
        if binding.is_empty() {
            return Err(Error::Invalid("missing transport binding".into()));
        }
        Ok(Self {
            root: PathBuf::new(),
            project: project.into(),
            channel_id: Digest::of(binding).to_hex(),
            max_records: MAX_RECORDS,
            max_log: MAX_LOG,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sync_transport(
        engine: &mut Engine,
        project: &str,
        binding: &[u8],
        group: &str,
        owner: &str,
        now: u64,
        records: &[Stored],
    ) -> Result<SyncResult> {
        packet::id(group)?;
        packet::id(owner)?;
        if engine.project_id() != project {
            return Err(Error::Verification("channel project mismatch".into()));
        }
        Self::transport_view(project, binding)?.sync_records(engine, group, owner, now, records)
    }
    pub(crate) fn check_transport_cursor(
        engine: &mut Engine,
        project: &str,
        binding: &[u8],
        group: &str,
        owner: &str,
        records: &[Stored],
    ) -> Result<()> {
        packet::id(group)?;
        packet::id(owner)?;
        if engine.project_id() != project {
            return Err(Error::Verification("channel project mismatch".into()));
        }
        Self::transport_view(project, binding)?
            .cursor(engine, group, owner, records)
            .map(|_| ())
    }
    pub fn open(project_root: &Path, project_id: &str) -> Result<Self> {
        packet::id(project_id)?;
        let project_root = io(project_root.canonicalize())?;
        if !project_root.is_dir() {
            return Err(Error::Invalid(
                "project path must be an existing directory".into(),
            ));
        }
        let mut root = project_root;
        for part in [".agents", "messages", "secure"] {
            root.push(part);
            private_dir(&root)?;
        }
        private_dir(&root.join("records"))?;
        let binding = serde_json::to_vec(&(root.to_str().ok_or(Error::Storage)?, project_id))
            .map_err(|_| Error::Storage)?;
        Ok(Self {
            root,
            project: project_id.to_owned(),
            channel_id: Digest::of(&binding).to_hex(),
            max_records: MAX_RECORDS,
            max_log: MAX_LOG,
        })
    }
    #[cfg(test)]
    pub(crate) fn tighten_test_limits(&mut self, records: usize, bytes: u64) {
        assert!(records <= MAX_RECORDS && bytes <= MAX_LOG);
        self.max_records = records;
        self.max_log = bytes;
    }
    fn lock(&self) -> Result<File> {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = io(options.open(self.root.join(".lock")))?;
        if !io(file.metadata())?.is_file() {
            return Err(Error::Invalid("channel lock is not a regular file".into()));
        }
        fs2::FileExt::try_lock_exclusive(&file)
            .map_err(|_| Error::Conflict("channel is busy; retry the same operation".into()))?;
        Ok(file)
    }
    fn read(&self) -> Result<Vec<Stored>> {
        let mut files = Vec::new();
        for item in io(fs::read_dir(self.root.join("records")))? {
            let item = io(item)?;
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| Error::Invalid("invalid record name".into()))?;
            if name.starts_with(".tmp-") {
                continue;
            }
            if files.len() >= self.max_records {
                return Err(Error::Conflict(
                    "local pilot log reached its record limit".into(),
                ));
            }
            files.push((name, item.path()));
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut records = Vec::new();
        let mut total = 0u64;
        let mut previous = None;
        for (index, (name, path)) in files.into_iter().enumerate() {
            let file = regular(&path)?;
            let size = io(file.metadata())?.len();
            if size > MAX_ENTRY {
                return Err(Error::Invalid("local log exceeds pilot size bounds".into()));
            }
            let mut bytes = Vec::new();
            io(file.take(MAX_ENTRY + 1).read_to_end(&mut bytes))?;
            if bytes.len() as u64 > MAX_ENTRY {
                return Err(Error::Invalid("record too large".into()));
            }
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or(Error::Storage)?;
            if total > self.max_log {
                return Err(Error::Invalid("local log exceeds pilot size bounds".into()));
            }
            let digest = Digest::of(&bytes).to_hex();
            let expected_name = format!("{:020}_{digest}.json", index + 1);
            if name != expected_name {
                return Err(Error::Verification(
                    "channel has a gap, fork or changed record".into(),
                ));
            }
            let entry: Entry = serde_json::from_slice(&bytes)
                .map_err(|_| Error::Invalid("malformed channel record".into()))?;
            if entry.version != 1
                || entry.project != self.project
                || entry.sequence != index as u64 + 1
                || entry.previous != previous
            {
                return Err(Error::Verification("channel history does not link".into()));
            }
            let packet = STANDARD
                .decode(&entry.packet)
                .map_err(|_| Error::Invalid("invalid sealed record encoding".into()))?;
            if packet.len() > packet::MAX_PACKET {
                return Err(Error::Invalid("sealed record too large".into()));
            }
            previous = Some(digest.clone());
            records.push(Stored {
                entry,
                digest,
                packet,
                encoded_size: bytes.len() as u64,
            });
        }
        Ok(records)
    }
    fn cursor_key(&self, group: &str) -> String {
        format!(
            "local-{}",
            Digest::of(format!("{}:{group}", self.channel_id).as_bytes()).to_hex()
        )
    }
    fn cursor(
        &self,
        engine: &mut Engine,
        group: &str,
        owner: &str,
        records: &[Stored],
    ) -> Result<Cursor> {
        let cursor = if let Some(bytes) = engine.client_get(&self.cursor_key(group))? {
            serde_json::from_slice::<Cursor>(&bytes).map_err(|_| Error::Storage)?
        } else {
            Cursor {
                version: 1,
                sequence: 0,
                head: None,
                group: group.to_owned(),
                owner: owner.to_owned(),
                membership: None,
            }
        };
        if cursor.version != 1 || cursor.group != group || cursor.owner != owner {
            return Err(Error::Verification("local cursor scope differs".into()));
        }
        if cursor.sequence == 0 {
            if cursor.head.is_some() {
                return Err(Error::Storage);
            }
        } else {
            let item = records
                .get((cursor.sequence - 1) as usize)
                .ok_or_else(|| Error::Verification("local log was truncated".into()))?;
            if cursor.head.as_ref() != Some(&item.digest) {
                return Err(Error::Verification(
                    "local log changed behind protected cursor".into(),
                ));
            }
        }
        Ok(cursor)
    }
    fn save_cursor(&self, engine: &mut Engine, cursor: &Cursor) -> Result<()> {
        engine.client_put(
            &self.cursor_key(&cursor.group),
            &serde_json::to_vec(cursor).map_err(|_| Error::Storage)?,
        )
    }
    pub fn publish(&self, engine: &mut Engine, operation: &str, now: u64) -> Result<Publication> {
        if engine.project_id() != self.project {
            return Err(Error::Verification("channel project mismatch".into()));
        }
        packet::id(operation)?;
        let _lock = self.lock()?;
        let records = self.read()?;
        let packet = engine.stored_packet(operation)?;
        let outbox = engine
            .outbox()?
            .into_iter()
            .find(|r| r.operation == operation)
            .ok_or_else(|| Error::Invalid("unknown outgoing operation".into()))?;
        if !matches!(outbox.kind.as_str(), "application" | "genesis" | "commit")
            || outbox.status == "rejected"
        {
            return Err(Error::Invalid("operation is not publishable".into()));
        }
        let state = engine
            .group_status(&outbox.group)?
            .ok_or_else(|| Error::Conflict("group not initialized".into()))?;
        self.cursor(engine, &outbox.group, &state.owner, &records)?;
        // Reconciliation precedes fresh admission. Only the exact immutable packet
        // already present in the authoritative log can acknowledge an uncertain send.
        for (index, record) in records.iter().enumerate() {
            let h = packet::unverified_header(&record.packet)?;
            if h.operation == operation && h.sender == engine.principal() {
                if record.packet != packet {
                    return Err(Error::Verification("operation collision in channel".into()));
                }
                let info = engine.inspect_record(&record.packet, now)?;
                position(&records[..index], &info)?;
                if outbox.status != "accepted" {
                    self.sync_records(engine, &outbox.group, &state.owner, now, &records[..index])?;
                }
                engine.confirm_publication(operation, &record.packet, &record.digest, now)?;
                return Ok(Publication {
                    operation: operation.into(),
                    packet_digest: Digest::of(&packet).to_hex(),
                    sequence: record.entry.sequence,
                    replayed: true,
                });
            }
        }
        if outbox.status == "accepted" {
            return Err(Error::Verification(
                "accepted outgoing record is missing from channel".into(),
            ));
        }
        // Drain earlier peer applications before merging a pending membership
        // change. Otherwise advancing the epoch strands valid old-epoch traffic.
        self.sync_records(engine, &outbox.group, &state.owner, now, &records)?;
        let packet = engine.ready(operation, now)?;
        let info = engine.inspect_record(&packet, now)?;
        let state = engine
            .group_status(&info.group)?
            .ok_or_else(|| Error::Conflict("group not initialized".into()))?;
        self.cursor(engine, &info.group, &state.owner, &records)?;
        let mut last_membership = None;
        for record in &records {
            let h = packet::unverified_header(&record.packet)?;
            if h.group == info.group && matches!(h.kind.as_str(), "genesis" | "commit") {
                last_membership = Some(Digest::of(&record.packet).to_hex());
            }
        }
        if last_membership != state.last_commit || info.previous != state.last_commit {
            return Err(Error::Conflict(
                "channel membership changed; sync before a new attempt".into(),
            ));
        }
        if info.kind == "genesis" && last_membership.is_some() {
            return Err(Error::Conflict("group already exists in channel".into()));
        }
        let sequence = records.len() as u64 + 1;
        let entry = Entry {
            version: 1,
            project: self.project.clone(),
            sequence,
            previous: records.last().map(|r| r.digest.clone()),
            packet: STANDARD.encode(&packet),
        };
        let bytes = serde_json::to_vec(&entry).map_err(|_| Error::Storage)?;
        if bytes.len() as u64 > MAX_ENTRY {
            return Err(Error::Invalid("record too large".into()));
        }
        let projected = records
            .iter()
            .map(|r| r.encoded_size)
            .sum::<u64>()
            .checked_add(bytes.len() as u64)
            .ok_or(Error::Storage)?;
        if records.len() >= self.max_records || projected > self.max_log {
            return Err(Error::Conflict(
                "local pilot log is full; publication was not acknowledged".into(),
            ));
        }
        let digest = Digest::of(&bytes).to_hex();
        let path = self
            .root
            .join("records")
            .join(format!("{sequence:020}_{digest}.json"));
        let temporary = self
            .root
            .join("records")
            .join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = io(options.open(&temporary))?;
        let published = (|| -> Result<()> {
            io(file.write_all(&bytes))?;
            io(file.sync_all())?;
            io(fs::hard_link(&temporary, &path))?;
            io(io(File::open(self.root.join("records")))?.sync_all())?;
            Ok(())
        })();
        let _ = fs::remove_file(&temporary);
        published?;
        let mut readback = Vec::new();
        io(regular(&path)?.read_to_end(&mut readback))?;
        if readback != bytes {
            return Err(Error::Verification("publication read-back differs".into()));
        }
        engine.confirm_publication(operation, &packet, &digest, now)?;
        Ok(Publication {
            operation: operation.into(),
            packet_digest: info.digest,
            sequence,
            replayed: false,
        })
    }
    pub fn sync(
        &self,
        engine: &mut Engine,
        group: &str,
        expected_owner: &str,
        now: u64,
    ) -> Result<SyncResult> {
        packet::id(group)?;
        packet::id(expected_owner)?;
        if engine.project_id() != self.project {
            return Err(Error::Verification("channel project mismatch".into()));
        }
        let _lock = self.lock()?;
        let records = self.read()?;
        self.sync_records(engine, group, expected_owner, now, &records)
    }
    fn sync_records(
        &self,
        engine: &mut Engine,
        group: &str,
        expected_owner: &str,
        now: u64,
        records: &[Stored],
    ) -> Result<SyncResult> {
        let mut cursor = self.cursor(engine, group, expected_owner, records)?;
        let mut result = SyncResult {
            processed: 0,
            deliveries: Vec::new(),
        };
        for record in records.iter().skip(cursor.sequence as usize) {
            let raw = packet::unverified_header(&record.packet)?;
            if raw.group != group {
                cursor.sequence = record.entry.sequence;
                cursor.head = Some(record.digest.clone());
                self.save_cursor(engine, &cursor)?;
                continue;
            }
            let own = raw.sender == engine.principal();
            if own {
                let status = engine
                    .outbox()?
                    .into_iter()
                    .find(|r| r.operation == raw.operation)
                    .ok_or_else(|| {
                        Error::Verification(
                            "own identity has unrecognized operation; reconcile device state"
                                .into(),
                        )
                    })?;
                if engine.stored_packet(&raw.operation)? != record.packet
                    || status.status == "rejected"
                {
                    return Err(Error::Verification(
                        "own publication differs from protected outbox".into(),
                    ));
                }
            }
            let info = engine.inspect_record(&record.packet, now)?;
            match info.kind.as_str() {
                "genesis" => {
                    if cursor.membership.is_some()
                        || info.sender != expected_owner
                        || info.previous.is_some()
                        || info.epoch != 0
                    {
                        return Err(Error::Verification("unexpected group genesis".into()));
                    }
                    if own {
                        engine.confirm_publication(
                            &info.operation,
                            &record.packet,
                            &record.digest,
                            now,
                        )?;
                    }
                    cursor.membership = Some(Membership {
                        packet_digest: info.digest.clone(),
                        epoch: 0,
                        audience: info.audience.clone(),
                    });
                }
                "commit" => {
                    let prior = cursor.membership.as_ref().ok_or_else(|| {
                        Error::Verification("membership change has no accepted genesis".into())
                    })?;
                    lineage(&info, prior)?;
                    if info.sender != expected_owner {
                        return Err(Error::Verification(
                            "membership change is not from expected owner".into(),
                        ));
                    }
                    if own {
                        engine.confirm_publication(
                            &info.operation,
                            &record.packet,
                            &record.digest,
                            now,
                        )?;
                    } else {
                        match engine.group_status(group)? {
                            Some(state)
                                if !state.active
                                    && info.added_member.as_deref() == Some(engine.principal()) =>
                            {
                                return Err(Error::Conflict("removed profile needs explicit fresh enrollment before rejoining".into()));
                            }
                            None if info.added_member.as_deref() == Some(engine.principal()) => {
                                engine.join(group, expected_owner, &record.packet, now)?;
                                result.deliveries.push(Delivery {
                                    disposition: "joined".into(),
                                    message: None,
                                    replayed: info.historical,
                                });
                            }
                            Some(state) if state.active => {
                                result.deliveries.push(engine.receive(&record.packet, now)?)
                            }
                            _ => {}
                        }
                    }
                    cursor.membership = Some(Membership {
                        packet_digest: info.digest.clone(),
                        epoch: info.epoch.checked_add(1).ok_or(Error::Storage)?,
                        audience: info
                            .next_audience
                            .clone()
                            .ok_or_else(|| Error::Verification("missing new audience".into()))?,
                    });
                }
                "application" => {
                    let prior = cursor.membership.as_ref().ok_or_else(|| {
                        Error::Verification("message has no accepted group history".into())
                    })?;
                    lineage(&info, prior)?;
                    if own {
                        engine.confirm_publication(
                            &info.operation,
                            &record.packet,
                            &record.digest,
                            now,
                        )?;
                    }
                    if !own && info.audience.iter().any(|m| m == engine.principal()) {
                        result.deliveries.push(engine.receive(&record.packet, now)?);
                    }
                }
                _ => return Err(Error::Verification("unsupported channel record".into())),
            }
            cursor.sequence = record.entry.sequence;
            cursor.head = Some(record.digest.clone());
            self.save_cursor(engine, &cursor)?;
            result.processed += 1;
        }
        Ok(result)
    }
}
pub(crate) fn position(prior_records: &[Stored], info: &RecordInfo) -> Result<()> {
    let mut previous = None;
    for record in prior_records {
        let h = packet::unverified_header(&record.packet)?;
        if h.group == info.group && matches!(h.kind.as_str(), "genesis" | "commit") {
            previous = Some(Membership {
                packet_digest: Digest::of(&record.packet).to_hex(),
                epoch: if h.kind == "genesis" {
                    0
                } else {
                    h.epoch.checked_add(1).ok_or(Error::Storage)?
                },
                audience: h.next_audience.unwrap_or(h.audience),
            });
        }
    }
    match previous {
        None if info.kind == "genesis" && info.previous.is_none() => Ok(()),
        Some(previous) if info.kind != "genesis" => lineage(info, &previous),
        _ => Err(Error::Verification(
            "record occupies an invalid membership position".into(),
        )),
    }
}
fn lineage(info: &RecordInfo, prior: &Membership) -> Result<()> {
    if info.previous.as_deref() != Some(prior.packet_digest.as_str())
        || info.epoch != prior.epoch
        || info.audience != prior.audience
    {
        return Err(Error::Verification(
            "record does not match accepted membership history".into(),
        ));
    }
    Ok(())
}
