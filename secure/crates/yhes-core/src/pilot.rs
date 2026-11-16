//! Public views and encrypted client checkpoints for the first usable client.
use crate::{
    engine::{self, Delivery, Engine},
    mls, packet, Error, Result,
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use yhes_actions::Parameters;
use yhes_wire::Digest;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GroupStatus {
    pub id: String,
    pub owner: String,
    pub epoch: u64,
    pub audience: Vec<String>,
    pub pending_operation: Option<String>,
    pub active: bool,
    pub last_commit: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct OutboxStatus {
    pub operation: String,
    pub group: String,
    pub epoch: u64,
    pub kind: String,
    pub event_id: String,
    pub status: String,
    pub receipt: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboxEntry {
    pub packet_digest: String,
    pub delivery: Delivery,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RecordInfo {
    pub digest: String,
    pub operation: String,
    pub project: String,
    pub sender: String,
    pub group: String,
    pub epoch: u64,
    pub kind: String,
    pub audience: Vec<String>,
    pub next_audience: Option<Vec<String>>,
    pub previous: Option<String>,
    pub added_member: Option<String>,
    pub historical: bool,
}
fn sql<T>(result: std::result::Result<T, rusqlite::Error>) -> Result<T> {
    result.map_err(|_| Error::Storage)
}
fn named(name: &str) -> Result<String> {
    if name.is_empty()
        || name.len() > 100
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(Error::Invalid("invalid client checkpoint name".into()));
    }
    Ok(format!("client/{name}"))
}
fn group_view(db: &Connection, id: &str) -> Result<Option<GroupStatus>> {
    struct Row {
        gid: Vec<u8>,
        owner: String,
        pending: Option<String>,
        last: Option<String>,
        audience: Vec<u8>,
    }
    let row:Option<Row>=sql(db.query_row(
        "SELECT mls_id,owner,pending_operation,last_commit,audience FROM yhes_groups WHERE id=?",[id],|r|Ok(Row{gid:r.get(0)?,owner:r.get(1)?,pending:r.get(2)?,last:r.get(3)?,audience:r.get(4)?})).optional())?;
    let Some(Row {
        gid,
        owner,
        pending: pending_operation,
        last: last_commit,
        audience,
    }) = row
    else {
        return Ok(None);
    };
    let state = mls::group_info(db, &gid)?;
    let audience: Vec<String> = serde_json::from_slice(&audience).map_err(|_| Error::Storage)?;
    Ok(Some(GroupStatus {
        id: id.to_owned(),
        owner,
        epoch: state.epoch,
        audience,
        pending_operation,
        active: state.active,
        last_commit,
    }))
}
impl Engine {
    pub fn project_id(&self) -> &str {
        &self.trust.project
    }
    pub fn principal(&self) -> &str {
        &self.principal
    }
    pub fn group_status(&mut self, id: &str) -> Result<Option<GroupStatus>> {
        packet::id(id)?;
        self.vault.transaction(|db| group_view(db, id))
    }
    pub fn groups(&mut self) -> Result<Vec<GroupStatus>> {
        self.vault.transaction(|db| {
            let mut q = sql(db.prepare("SELECT id FROM yhes_groups ORDER BY id"))?;
            let ids = sql(q.query_map([], |r| r.get::<_, String>(0)))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::Storage)?;
            ids.iter()
                .map(|id| group_view(db, id)?.ok_or(Error::Storage))
                .collect()
        })
    }
    pub fn outbox(&mut self) -> Result<Vec<OutboxStatus>> {
        self.vault.transaction(|db|{
            let mut q=sql(db.prepare("SELECT id,group_id,epoch,kind,event_id,status,receipt FROM yhes_outbox ORDER BY rowid"))?;
            let rows=sql(q.query_map([],|r|Ok(OutboxStatus{operation:r.get(0)?,group:r.get(1)?,epoch:r.get(2)?,kind:r.get(3)?,event_id:r.get(4)?,status:r.get(5)?,receipt:r.get(6)?})))?;
            rows.collect::<std::result::Result<Vec<_>,_>>().map_err(|_|Error::Storage)
        })
    }
    pub fn inbox(&mut self) -> Result<Vec<InboxEntry>> {
        self.vault.transaction(|db| {
            let mut q = sql(db.prepare("SELECT digest,record FROM yhes_inbox ORDER BY rowid"))?;
            let rows = sql(q.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            }))?;
            let mut results = Vec::new();
            for row in rows {
                let (digest, bytes) = sql(row)?;
                let mut delivery: Delivery =
                    serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
                delivery.replayed = true;
                results.push(InboxEntry {
                    packet_digest: digest,
                    delivery,
                });
            }
            Ok(results)
        })
    }
    pub fn stored_packet(&mut self, operation: &str) -> Result<Vec<u8>> {
        packet::id(operation)?;
        self.vault.transaction(|db| {
            sql(db.query_row(
                "SELECT wire FROM yhes_outbox WHERE id=?",
                [operation],
                |r| r.get(0),
            ))
        })
    }
    pub fn client_get(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        let key = named(name)?;
        self.vault.transaction(|db| {
            sql(db
                .query_row("SELECT value FROM yhes_meta WHERE key=?", [key], |r| {
                    r.get(0)
                })
                .optional())
        })
    }
    pub fn client_put(&mut self, name: &str, value: &[u8]) -> Result<()> {
        let key = named(name)?;
        if value.len() > 1 << 20 {
            return Err(Error::Invalid("client checkpoint too large".into()));
        }
        self.vault.transaction(|db|{sql(db.execute("INSERT INTO yhes_meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![key,value]))?;Ok(())})
    }
    /// Previously authenticated public registry data; not a fresh policy decision.
    pub fn registry_chain(&mut self) -> Result<Vec<Vec<u8>>> {
        self.vault.transaction(|db| {
            let mut q = sql(db.prepare("SELECT envelope FROM yhes_registry ORDER BY generation"))?;
            let rows = sql(q.query_map([], |r| r.get(0)))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::Storage)
        })
    }
    pub fn registry_head(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.registry_chain()?.pop())
    }
    /// Inspect a currently admissible transport record, or an exact protected
    /// historical acceptance. This does not establish inner message provenance.
    pub fn inspect_record(&mut self, bytes: &[u8], now: u64) -> Result<RecordInfo> {
        let trust = &self.trust;
        self.vault.transaction(|db| {
            let digest = Digest::of(bytes).to_hex();
            let incoming: i64 = sql(db.query_row(
                "SELECT count(*) FROM yhes_inbox WHERE digest=?",
                [&digest],
                |r| r.get(0),
            ))?;
            let outgoing: i64 = sql(db.query_row(
                "SELECT count(*) FROM yhes_outbox WHERE wire=? AND status='accepted'",
                [bytes],
                |r| r.get(0),
            ))?;
            let historical = incoming > 0 || outgoing > 0;
            let h = if historical {
                packet::unverified_header(bytes)?
            } else {
                let registry = trust.current(db, now)?;
                let p = packet::decode(bytes, &registry, now)?;
                let known: i64 = sql(db.query_row(
                    "SELECT count(*) FROM yhes_registry WHERE digest=?",
                    [&p.header.registry],
                    |r| r.get(0),
                ))?;
                if known != 1 {
                    return Err(Error::Verification("unseen registry checkpoint".into()));
                }
                if let Some(control) = &p.header.control {
                    let (r, v) = engine::action(control, &registry, now)?;
                    if r.group() != p.header.group
                        || r.epoch() != p.header.epoch
                        || r.performer() != p.header.sender
                        || v.event().author != p.header.sender
                    {
                        return Err(Error::Verification(
                            "control scope does not match transport".into(),
                        ));
                    }
                    match r.parameters() {
                        Parameters::GroupCreate {} => {
                            if p.header.kind != "genesis"
                                || p.header.previous.is_some()
                                || r.audience() != p.header.audience
                                || !p.ciphertext.is_empty()
                                || p.welcome.is_some()
                                || control.key_package.is_some()
                            {
                                return Err(Error::Verification("invalid genesis".into()));
                            }
                        }
                        Parameters::GroupAdd {
                            member,
                            key_package_digest,
                            ..
                        } => {
                            let mut next = p.header.audience.clone();
                            if next.contains(member) {
                                return Err(Error::Verification(
                                    "member already in audience".into(),
                                ));
                            }
                            next.push(member.clone());
                            next.sort();
                            if p.header.kind != "commit"
                                || p.header.previous.is_none()
                                || p.welcome.is_none()
                                || p.header.next_audience.as_deref() != Some(next.as_slice())
                                || r.audience() != next
                            {
                                return Err(Error::Verification("invalid add audience".into()));
                            }
                            use base64::Engine as _;
                            let kp = base64::engine::general_purpose::STANDARD
                                .decode(control.key_package.as_deref().ok_or_else(|| {
                                    Error::Verification("missing KeyPackage".into())
                                })?)
                                .map_err(|_| {
                                    Error::Verification("bad KeyPackage encoding".into())
                                })?;
                            if Digest::of(&kp) != *key_package_digest {
                                return Err(Error::Verification(
                                    "approved KeyPackage differs".into(),
                                ));
                            }
                        }
                        Parameters::GroupRemove { member } => {
                            let mut next = p.header.audience.clone();
                            if !next.contains(member) || member == &p.header.sender {
                                return Err(Error::Verification("invalid removed member".into()));
                            }
                            next.retain(|m| m != member);
                            if p.header.kind != "commit"
                                || p.header.previous.is_none()
                                || p.welcome.is_some()
                                || control.key_package.is_some()
                                || p.header.next_audience.as_deref() != Some(next.as_slice())
                                || r.audience() != next
                            {
                                return Err(Error::Verification("invalid remove audience".into()));
                            }
                        }
                        _ => {
                            return Err(Error::Verification("unsupported control operation".into()))
                        }
                    }
                }
                p.header
            };
            if h.project != trust.project {
                return Err(Error::Verification("record project differs".into()));
            }
            let added_member = if let Some(control) = &h.control {
                let request = yhes_actions::Request::parse(control.request.as_bytes())
                    .map_err(|_| Error::Verification("invalid action request".into()))?;
                match request.parameters() {
                    Parameters::GroupAdd { member, .. } => Some(member.clone()),
                    _ => None,
                }
            } else {
                None
            };
            Ok(RecordInfo {
                digest,
                operation: h.operation,
                project: h.project,
                sender: h.sender,
                group: h.group,
                epoch: h.epoch,
                kind: h.kind,
                audience: h.audience,
                next_audience: h.next_audience,
                previous: h.previous,
                added_member,
                historical,
            })
        })
    }
}
