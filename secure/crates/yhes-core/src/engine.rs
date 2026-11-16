//! Transactional secure-channel core. Its transport acknowledgments are an
//! internal adapter boundary, not an RPC accepting claims from an agent.
use crate::{
    mls::{self, AgentSigner, Member},
    packet::{self, Header},
    store::Vault,
    trust::{wire, ProjectTrust},
    Control, Error, Result, SignedContent,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use yhes_actions::{Parameters, Request};
use yhes_wire::{
    Algorithm, AudienceCheck, Digest, Envelope, Event, Expectation, Kind, ParticipantKind, Policy,
    Registry, VerifiedEvent, Verifier, EVENT_PAYLOAD_TYPE,
};

pub struct Engine {
    pub(crate) vault: Vault,
    pub(crate) trust: ProjectTrust,
    pub(crate) principal: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdentity {
    pub principal: String,
    pub key_id: String,
    pub public_key: String,
    pub algorithm: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedMessage {
    pub author: String,
    pub kind: String,
    pub human_authored: bool,
    pub human_original_author: Option<String>,
    pub event_id: String,
    pub payload_digest: String,
    pub accepted_at: u64,
    pub content: SignedContent,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub disposition: String,
    pub message: Option<AcceptedMessage>,
    pub replayed: bool,
}
struct Group {
    mls_id: Vec<u8>,
    audience: Vec<String>,
    previous: Option<String>,
    pending: Option<String>,
    owner: String,
}
fn storage<T>(r: std::result::Result<T, rusqlite::Error>) -> Result<T> {
    r.map_err(|_| Error::Storage)
}
fn group(db: &Connection, id: &str) -> Result<Group> {
    let (mls_id, aud, previous, pending, owner): (
        Vec<u8>,
        Vec<u8>,
        Option<String>,
        Option<String>,
        String,
    ) = storage(db.query_row(
        "SELECT mls_id,audience,last_commit,pending_operation,owner FROM yhes_groups WHERE id=?",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    ))?;
    Ok(Group {
        mls_id,
        audience: serde_json::from_slice(&aud).map_err(|_| Error::Storage)?,
        previous,
        pending,
        owner,
    })
}
fn mls_id(project: &str, group: &str) -> Vec<u8> {
    format!("agent-yhes/group/v1\0{project}\0{group}").into_bytes()
}
fn known_registry(db: &Connection, digest: &str) -> Result<()> {
    let count: i64 = storage(db.query_row(
        "SELECT count(*) FROM yhes_registry WHERE digest=?",
        [digest],
        |r| r.get(0),
    ))?;
    if count != 1 {
        return Err(Error::Verification("unseen registry checkpoint".into()));
    }
    Ok(())
}
fn member_names(members: &[Member]) -> Vec<String> {
    let mut names = members
        .iter()
        .map(|m| m.principal.clone())
        .collect::<Vec<_>>();
    names.sort();
    names
}
fn admission_deadline(event: &VerifiedEvent) -> u64 {
    let mut until = event.event().expires_at;
    for evidence in [event.grant(), event.authorization(), event.original()]
        .into_iter()
        .flatten()
    {
        until = until.min(admission_deadline(evidence));
    }
    until
}
fn roster(registry: &Registry, members: &[Member], now: u64) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for m in members {
        let key = registry
            .active_key(&m.principal, &m.key_id, now)
            .map_err(wire)?;
        if key.algorithm() != Algorithm::Ed25519
            || key.as_bytes() != m.signature_key
            || registry
                .participant(&m.principal)
                .is_none_or(|p| p.kind != ParticipantKind::Agent)
        {
            return Err(Error::Verification(
                "MLS identity is not an enrolled agent".into(),
            ));
        }
        names.push(m.principal.clone());
    }
    names.sort();
    if names.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::Verification("duplicate MLS principal".into()));
    }
    Ok(names)
}
fn verify(
    content: &SignedContent,
    registry: &Registry,
    audience: &[String],
    group: &str,
    epoch: u64,
    now: u64,
) -> Result<VerifiedEvent> {
    let v = Verifier::new(registry, Policy::default())
        .verify_event(
            content.event.as_bytes(),
            &content.evidence(),
            &Expectation {
                project: registry.project(),
                audience: AudienceCheck::Exact(audience),
                group: Some(group),
            },
            now,
        )
        .map_err(wire)?;
    if v.event().epoch != Some(epoch) {
        return Err(Error::Verification("signed event epoch mismatch".into()));
    }
    Ok(v)
}
pub(crate) fn action(
    control: &Control,
    registry: &Registry,
    now: u64,
) -> Result<(Request, VerifiedEvent)> {
    let request = Request::parse(control.request.as_bytes())
        .map_err(|_| Error::Verification("invalid action request".into()))?;
    let event = verify(
        &control.content,
        registry,
        request.audience(),
        request.group(),
        request.epoch(),
        now,
    )?;
    request
        .verify_binding(&event, now)
        .map_err(|_| Error::Verification("action request is not freshly authorized".into()))?;
    Ok((request, event))
}
fn consume_authorization(db: &Connection, event: &VerifiedEvent, operation: &str) -> Result<()> {
    let a = event
        .authorization()
        .ok_or_else(|| Error::Verification("human authorization required".into()))?;
    let identity = format!("{}/{}", a.event().author, a.event().id);
    storage(db.execute(
        "INSERT INTO yhes_authorizations VALUES (?,?,?)",
        rusqlite::params![identity, operation, a.digest().to_hex()],
    ))?;
    Ok(())
}
fn seen(db: &Connection, event: &VerifiedEvent) -> Result<bool> {
    let digest: Option<String> = storage(
        db.query_row(
            "SELECT digest FROM yhes_replay WHERE principal=? AND event_id=?",
            rusqlite::params![event.event().author, event.event().id],
            |r| r.get(0),
        )
        .optional(),
    )?;
    if let Some(digest) = digest {
        if digest != event.digest().to_hex() {
            return Err(Error::Verification(
                "event ID was reused with different content".into(),
            ));
        }
        return Ok(true);
    }
    storage(db.execute(
        "INSERT INTO yhes_replay VALUES (?,?,?)",
        rusqlite::params![
            event.event().author,
            event.event().id,
            event.digest().to_hex()
        ],
    ))?;
    Ok(false)
}
fn cached(db: &Connection, operation: &str, request_hash: &str) -> Result<Option<Vec<u8>>> {
    packet::id(operation)?;
    let row: Option<(String, Vec<u8>, String)> = storage(
        db.query_row(
            "SELECT request_hash,wire,status FROM yhes_outbox WHERE id=?",
            [operation],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional(),
    )?;
    if let Some((hash, bytes, status)) = row {
        if hash != request_hash || status == "rejected" {
            return Err(Error::Conflict("operation ID cannot be reused".into()));
        }
        return Ok(Some(bytes));
    }
    Ok(None)
}
fn outbox(
    db: &Connection,
    header: &Header,
    request_hash: &str,
    bytes: &[u8],
    event: &str,
) -> Result<()> {
    storage(db.execute(
        "INSERT INTO yhes_outbox VALUES (?,?,?,?,?,?,?,'prepared',NULL)",
        rusqlite::params![
            header.operation,
            request_hash,
            header.group,
            header.epoch,
            header.kind,
            event,
            bytes
        ],
    ))?;
    Ok(())
}
fn packet_for(
    signer: &AgentSigner,
    header: Header,
    ciphertext: Vec<u8>,
    welcome: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    packet::encode(header, ciphertext, welcome, signer.public(), |p| {
        Ok(signer.sign(packet::TRANSPORT_TYPE, p)?.signature)
    })
}
// Keep the independent signed scope bindings explicit at each call site.
#[allow(clippy::too_many_arguments)]
fn header(
    signer: &AgentSigner,
    registry: &Registry,
    operation: &str,
    group: &str,
    epoch: u64,
    audience: Vec<String>,
    previous: Option<String>,
    kind: &str,
    now: u64,
) -> Header {
    Header {
        version: 1,
        project: registry.project().to_owned(),
        operation: operation.to_owned(),
        sender: signer.principal().to_owned(),
        key_id: signer.key_id().to_string(),
        group: group.to_owned(),
        epoch,
        previous,
        kind: kind.to_owned(),
        audience,
        next_audience: None,
        registry: registry.digest().to_hex(),
        issued_at: now,
        expires_at: now + 86400,
        ciphertext_digest: Digest::of(&[]).to_hex(),
        welcome_digest: None,
        control: None,
    }
}

impl Engine {
    /// A new vault creates an agent key. An existing vault must contain the same
    /// principal and pinned trust configuration. No human key enters this engine.
    pub fn open(mut vault: Vault, trust: ProjectTrust, principal: &str) -> Result<Self> {
        packet::id(principal)?;
        vault.transaction(|db| {
            trust.bind(db)?;
            let count: i64 =
                storage(db.query_row("SELECT count(*) FROM yhes_identity", [], |r| r.get(0)))?;
            let signer = if count == 0 {
                AgentSigner::init(db, principal)?
            } else {
                AgentSigner::load(db)?
            };
            if signer.project() != trust.project || signer.principal() != principal {
                return Err(Error::Verification("vault principal mismatch".into()));
            }
            Ok(())
        })?;
        Ok(Self {
            vault,
            trust,
            principal: principal.to_owned(),
        })
    }
    pub fn identity(&mut self) -> Result<PublicIdentity> {
        self.vault.transaction(|db| {
            let s = AgentSigner::load(db)?;
            Ok(PublicIdentity {
                principal: s.principal().to_owned(),
                key_id: s.key_id().to_string(),
                public_key: STANDARD.encode(s.public().as_bytes()),
                algorithm: "ed25519".into(),
            })
        })
    }
    pub fn install_registry(&mut self, bytes: &[u8], now: u64) -> Result<String> {
        let trust = &self.trust;
        self.vault
            .transaction(|db| Ok(trust.install(db, bytes, now)?.digest().to_hex()))
    }
    /// Both authority keys and this expected current head must be approved out
    /// of band. A repository cannot choose its own bootstrap trust checkpoint.
    pub fn bootstrap_registry(
        &mut self,
        chain: &[&[u8]],
        expected_head: Digest,
        now: u64,
    ) -> Result<String> {
        let trust = &self.trust;
        self.vault.transaction(|db| {
            Ok(trust
                .bootstrap(db, chain, expected_head, now)?
                .digest()
                .to_hex())
        })
    }
    /// Only an authorized agent event can be signed. This is not a generic
    /// sign-bytes operation and cannot issue human statements or authorizations.
    pub fn sign_event(
        &mut self,
        event: Event,
        grant: Option<String>,
        authorization: Option<String>,
        original_grant: Option<String>,
        now: u64,
    ) -> Result<SignedContent> {
        let trust = &self.trust;
        let principal = &self.principal;
        self.vault.transaction(|db| {
            let registry = trust.current(db, now)?;
            let signer = AgentSigner::load(db)?;
            if event.author != *principal || event.key_id != *signer.key_id() {
                return Err(Error::Verification(
                    "agent signing identity mismatch".into(),
                ));
            }
            let payload = event.to_payload().map_err(wire)?;
            let signature = signer.sign(EVENT_PAYLOAD_TYPE, &payload)?;
            let envelope =
                Envelope::new(EVENT_PAYLOAD_TYPE, payload, vec![signature]).map_err(wire)?;
            let content = SignedContent {
                event: String::from_utf8(envelope.to_json()).map_err(|_| Error::Storage)?,
                grant,
                authorization,
                original_grant,
            };
            Verifier::new(&registry, Policy::default())
                .verify_event(
                    content.event.as_bytes(),
                    &content.evidence(),
                    &Expectation {
                        project: registry.project(),
                        audience: AudienceCheck::Exact(&event.audience),
                        group: event.group.as_deref(),
                    },
                    now,
                )
                .map_err(wire)?;
            Ok(content)
        })
    }
    /// Verify a proposed member's public package before requesting human review.
    /// This grants no membership and does not consume the package. The same
    /// checks run again when the exact reviewed change is staged and joined.
    pub fn inspect_key_package(&mut self, bytes: &[u8], now: u64) -> Result<PublicIdentity> {
        let trust = &self.trust;
        self.vault.transaction(|db| {
            let registry = trust.current(db, now)?;
            let member = mls::inspect_key_package(registry.project(), bytes)?;
            roster(&registry, std::slice::from_ref(&member), now)?;
            Ok(PublicIdentity {
                principal: member.principal,
                key_id: member.key_id.as_str().to_owned(),
                public_key: STANDARD.encode(&member.signature_key),
                algorithm: "ed25519".into(),
            })
        })
    }
    pub fn key_package(&mut self, operation: &str, now: u64) -> Result<Vec<u8>> {
        let trust = &self.trust;
        self.vault.transaction(|db|{
            let signer=AgentSigner::load(db)?;let registry=trust.current(db,now)?;
            registry.active_key(signer.principal(),signer.key_id(),now).map_err(wire)?;
            let hash=Digest::of(format!("key-package:{}",signer.key_id()).as_bytes()).to_hex();
            if let Some(bytes)=cached(db,operation,&hash)?{return Ok(bytes);}
            let bytes=mls::key_package(db,&signer)?;
            storage(db.execute("INSERT INTO yhes_outbox VALUES (?,?,'key-package',0,'key-package','',?,'prepared',NULL)",rusqlite::params![operation,hash,bytes]))?;
            Ok(bytes)
        })
    }
    pub fn create_group(&mut self, operation: &str, control: Control, now: u64) -> Result<Vec<u8>> {
        let trust = &self.trust;
        let principal = &self.principal;
        self.vault.transaction(|db| {
            let request_hash =
                Digest::of(&serde_json::to_vec(&control).map_err(|_| Error::Storage)?).to_hex();
            if let Some(bytes) = cached(db, operation, &request_hash)? {
                return Ok(bytes);
            }
            let registry = trust.current(db, now)?;
            let (request, event) = action(&control, &registry, now)?;
            if request.action().as_str() != "group.create"
                || request.performer() != principal
                || control.key_package.is_some()
            {
                return Err(Error::Verification("invalid group creation".into()));
            }
            consume_authorization(db, &event, operation)?;
            let signer = AgentSigner::load(db)?;
            let gid = mls_id(registry.project(), request.group());
            let state = mls::create(db, &signer, &gid)?;
            if roster(&registry, &state.roster, now)? != request.audience() {
                return Err(Error::Verification(
                    "created audience differs from approval".into(),
                ));
            }
            let mut h = header(
                &signer,
                &registry,
                operation,
                request.group(),
                0,
                request.audience().to_vec(),
                None,
                "genesis",
                now,
            );
            h.expires_at = admission_deadline(&event);
            h.control = Some(control.clone());
            let bytes = packet_for(&signer, h.clone(), vec![], None)?;
            storage(db.execute(
                "INSERT INTO yhes_groups VALUES (?,?,?,NULL,?,?)",
                rusqlite::params![
                    request.group(),
                    gid,
                    serde_json::to_vec(request.audience()).map_err(|_| Error::Storage)?,
                    operation,
                    principal
                ],
            ))?;
            outbox(db, &h, &request_hash, &bytes, &event.event().id)?;
            Ok(bytes)
        })
    }
    pub fn change_membership(
        &mut self,
        operation: &str,
        control: Control,
        now: u64,
    ) -> Result<Vec<u8>> {
        let trust = &self.trust;
        let principal = &self.principal;
        self.vault.transaction(|db| {
            let request_hash =
                Digest::of(&serde_json::to_vec(&control).map_err(|_| Error::Storage)?).to_hex();
            if let Some(bytes) = cached(db, operation, &request_hash)? {
                return Ok(bytes);
            }
            let registry = trust.current(db, now)?;
            let (request, event) = action(&control, &registry, now)?;
            let g = group(db, request.group())?;
            if g.pending.is_some() || g.owner != *principal || request.performer() != principal {
                return Err(Error::Conflict(
                    "membership change requires idle group owner".into(),
                ));
            }
            let state = mls::group_info(db, &g.mls_id)?;
            if state.epoch != request.epoch() || member_names(&state.roster) != g.audience {
                return Err(Error::Verification("group state mismatch".into()));
            }
            let signer = AgentSigner::load(db)?;
            let staged = match request.parameters() {
                Parameters::GroupAdd {
                    member,
                    key_id,
                    key_package_digest,
                } => {
                    let bytes = STANDARD
                        .decode(
                            control
                                .key_package
                                .as_deref()
                                .ok_or_else(|| Error::Invalid("missing KeyPackage".into()))?,
                        )
                        .map_err(|_| Error::Invalid("bad KeyPackage encoding".into()))?;
                    if Digest::of(&bytes) != *key_package_digest {
                        return Err(Error::Verification(
                            "KeyPackage differs from approval".into(),
                        ));
                    }
                    let candidate = mls::inspect_key_package(registry.project(), &bytes)?;
                    if candidate.principal != *member
                        || candidate.key_id != *key_id
                        || g.audience.contains(member)
                    {
                        return Err(Error::Verification("KeyPackage identity mismatch".into()));
                    }
                    roster(&registry, &[candidate], now)?;
                    mls::stage_add(db, &signer, &g.mls_id, &bytes)?
                }
                Parameters::GroupRemove { member } => {
                    if control.key_package.is_some() {
                        return Err(Error::Invalid("unexpected KeyPackage".into()));
                    }
                    let target = state
                        .roster
                        .iter()
                        .find(|m| m.principal == *member)
                        .ok_or_else(|| Error::Invalid("member absent".into()))?;
                    mls::stage_remove(db, &signer, &g.mls_id, member, &target.key_id)?
                }
                _ => return Err(Error::Invalid("unsupported membership action".into())),
            };
            if staged.base_epoch != state.epoch
                || staged.added.len() + staged.removed.len() != 1
                || roster(&registry, &staged.next_roster, now)? != request.audience()
            {
                return Err(Error::Verification(
                    "next roster differs from approval".into(),
                ));
            }
            consume_authorization(db, &event, operation)?;
            let mut h = header(
                &signer,
                &registry,
                operation,
                request.group(),
                state.epoch,
                g.audience,
                g.previous,
                "commit",
                now,
            );
            h.next_audience = Some(request.audience().to_vec());
            h.ciphertext_digest = Digest::of(&staged.commit).to_hex();
            h.welcome_digest = staged.welcome.as_ref().map(|w| Digest::of(w).to_hex());
            h.expires_at = admission_deadline(&event);
            h.control = Some(control.clone());
            let bytes = packet_for(&signer, h.clone(), staged.commit, staged.welcome)?;
            storage(db.execute(
                "UPDATE yhes_groups SET pending_operation=? WHERE id=?",
                rusqlite::params![operation, request.group()],
            ))?;
            outbox(db, &h, &request_hash, &bytes, &event.event().id)?;
            Ok(bytes)
        })
    }
    /// Retrieve the exact stored packet after checking current identity/epoch.
    /// Call this immediately before transport; never regenerate an uncertain send.
    pub fn ready(&mut self, operation: &str, now: u64) -> Result<Vec<u8>> {
        let trust = &self.trust;
        self.vault.transaction(|db| {
            let (bytes, status): (Vec<u8>, String) = storage(db.query_row(
                "SELECT wire,status FROM yhes_outbox WHERE id=?",
                [operation],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ))?;
            if status == "rejected" {
                return Err(Error::Conflict("operation rejected".into()));
            }
            let registry = trust.current(db, now)?;
            let packet = packet::decode(&bytes, &registry, now)?;
            known_registry(db, &packet.header.registry)?;
            let g = group(db, &packet.header.group)?;
            let state = mls::group_info(db, &g.mls_id)?;
            if status != "accepted"
                && (state.epoch != packet.header.epoch || g.audience != packet.header.audience)
            {
                return Err(Error::Conflict(
                    "unsent packet belongs to an old audience or epoch".into(),
                ));
            }
            Ok(bytes)
        })
    }
    /// Adapter callback after reading the exact accepted record back from the
    /// authoritative Git history. A broker PUBACK alone must never call this.
    pub fn confirm_publication(
        &mut self,
        operation: &str,
        accepted_record: &[u8],
        receipt: &str,
        now: u64,
    ) -> Result<()> {
        let trust = &self.trust;
        self.vault.transaction(|db|{
            let (bytes,status):(Vec<u8>,String)=storage(db.query_row("SELECT wire,status FROM yhes_outbox WHERE id=?",[operation],|r|Ok((r.get(0)?,r.get(1)?))))?;
            if bytes!=accepted_record || receipt.is_empty() || receipt.len()>256 || status=="rejected"{return Err(Error::Verification("publication receipt mismatch".into()));}
            if status=="accepted"{return Ok(());}
            let registry=trust.current(db,now)?;let p=packet::decode(&bytes,&registry,now)?;known_registry(db,&p.header.registry)?;let g=group(db,&p.header.group)?;
            if p.header.kind=="commit" || p.header.kind=="genesis" {
                if g.pending.as_deref()!=Some(operation){return Err(Error::Conflict("different membership attempt is pending".into()));}
                let audience=if p.header.kind=="commit"{roster(&registry,&mls::merge_pending(db,&g.mls_id)?.roster,now)?}else{g.audience};
                storage(db.execute("UPDATE yhes_groups SET audience=?,last_commit=?,pending_operation=NULL WHERE id=?",
                    rusqlite::params![serde_json::to_vec(&audience).map_err(|_|Error::Storage)?,Digest::of(&bytes).to_hex(),p.header.group]))?;
            }
            storage(db.execute("UPDATE yhes_outbox SET status='accepted',receipt=? WHERE id=?",rusqlite::params![receipt,operation]))?;Ok(())
        })
    }
    /// Trusted adapter callback only after definitive rejection and a fresh
    /// authoritative history check. A timeout or broker failure is not rejection.
    /// The consumed human approval stays consumed; a rebuilt attempt needs a new one.
    pub fn reject_membership(
        &mut self,
        operation: &str,
        rejected_digest: Digest,
        authoritative_head: &str,
    ) -> Result<()> {
        self.vault.transaction(|db| {
            let (bytes, status, kind, group_id): (Vec<u8>, String, String, String) =
                storage(db.query_row(
                    "SELECT wire,status,kind,group_id FROM yhes_outbox WHERE id=?",
                    [operation],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                ))?;
            if Digest::of(&bytes) != rejected_digest
                || authoritative_head.is_empty()
                || authoritative_head.len() > 256
                || kind != "commit"
                || status == "accepted"
            {
                return Err(Error::Verification(
                    "membership rejection evidence mismatch".into(),
                ));
            }
            if status == "rejected" {
                return Ok(());
            }
            let g = group(db, &group_id)?;
            if g.pending.as_deref() != Some(operation) {
                return Err(Error::Conflict(
                    "another membership attempt is pending".into(),
                ));
            }
            mls::clear_pending(db, &g.mls_id)?;
            storage(db.execute(
                "UPDATE yhes_groups SET pending_operation=NULL WHERE id=?",
                [group_id],
            ))?;
            storage(db.execute(
                "UPDATE yhes_outbox SET status='rejected',receipt=? WHERE id=?",
                rusqlite::params![authoritative_head, operation],
            ))?;
            Ok(())
        })
    }
    pub fn join(
        &mut self,
        expected_group: &str,
        expected_owner: &str,
        record: &[u8],
        now: u64,
    ) -> Result<()> {
        let trust = &self.trust;
        let principal = &self.principal;
        self.vault.transaction(|db| {
            let digest = Digest::of(record).to_hex();
            let prior: Option<(String, String, String)> = storage(
                db.query_row(
                    "SELECT disposition,event_id,sender FROM yhes_inbox WHERE digest=?",
                    [&digest],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional(),
            )?;
            if let Some((disposition, group, owner)) = prior {
                if disposition == "joined" && group == expected_group && owner == expected_owner {
                    return Ok(());
                }
                return Err(Error::Conflict(
                    "invitation already processed with a different scope".into(),
                ));
            }
            let registry = trust.current(db, now)?;
            let packet = packet::decode(record, &registry, now)?;
            let h = &packet.header;
            known_registry(db, &h.registry)?;
            if h.group != expected_group || h.sender != expected_owner || h.kind != "commit" {
                return Err(Error::Verification(
                    "invitation differs from expected group owner".into(),
                ));
            }
            let control = h
                .control
                .as_ref()
                .ok_or_else(|| Error::Verification("missing control".into()))?;
            let (request, event) = action(control, &registry, now)?;
            let Parameters::GroupAdd {
                member,
                key_id,
                key_package_digest,
            } = request.parameters()
            else {
                return Err(Error::Verification(
                    "join requires an add authorization".into(),
                ));
            };
            let signer = AgentSigner::load(db)?;
            if member != principal
                || key_id != signer.key_id()
                || event.event().author != h.sender
                || request.group() != h.group
                || request.epoch() != h.epoch
                || h.next_audience.as_deref() != Some(request.audience())
            {
                return Err(Error::Verification("invitation scope mismatch".into()));
            }
            let kp = STANDARD
                .decode(
                    control
                        .key_package
                        .as_deref()
                        .ok_or_else(|| Error::Invalid("missing KeyPackage".into()))?,
                )
                .map_err(|_| Error::Invalid("bad encoding".into()))?;
            if Digest::of(&kp) != *key_package_digest {
                return Err(Error::Verification("invitation KeyPackage mismatch".into()));
            }
            let candidate = mls::inspect_key_package(registry.project(), &kp)?;
            if candidate.principal != *principal || candidate.key_id != *signer.key_id() {
                return Err(Error::Verification("invitation key mismatch".into()));
            }
            let gid = mls_id(registry.project(), expected_group);
            let policy = |invite: &mls::Invitation| -> Result<()> {
                if invite.own_key_package_digest != *key_package_digest
                    || invite.group_id != gid
                    || invite.epoch != h.epoch + 1
                    || invite.inviter.principal != h.sender
                    || invite.inviter.key_id.as_str() != h.key_id
                    || roster(&registry, &invite.roster, now)? != request.audience()
                {
                    return Err(Error::Verification(
                        "Welcome differs from authorization".into(),
                    ));
                }
                Ok(())
            };
            mls::join(
                db,
                &signer,
                packet
                    .welcome
                    .as_deref()
                    .ok_or_else(|| Error::Invalid("missing Welcome".into()))?,
                &policy,
            )?;
            consume_authorization(db, &event, &h.operation)?;
            storage(db.execute(
                "INSERT INTO yhes_groups VALUES (?,?,?,?,NULL,?)",
                rusqlite::params![
                    expected_group,
                    gid,
                    serde_json::to_vec(request.audience()).map_err(|_| Error::Storage)?,
                    digest,
                    expected_owner
                ],
            ))?;
            let delivery = Delivery {
                disposition: "joined".into(),
                message: None,
                replayed: false,
            };
            storage(db.execute(
                "INSERT INTO yhes_inbox VALUES (?,?,?,'joined',?)",
                rusqlite::params![
                    digest,
                    expected_group,
                    expected_owner,
                    serde_json::to_vec(&delivery).map_err(|_| Error::Storage)?
                ],
            ))?;
            Ok(())
        })
    }
    pub fn prepare_message(
        &mut self,
        operation: &str,
        group_id: &str,
        content: SignedContent,
        now: u64,
    ) -> Result<Vec<u8>> {
        let trust = &self.trust;
        let principal = &self.principal;
        self.vault.transaction(|db| {
            let plaintext = content.bytes()?;
            let request_hash = Digest::of(&plaintext).to_hex();
            if let Some(bytes) = cached(db, operation, &request_hash)? {
                return Ok(bytes);
            }
            let registry = trust.current(db, now)?;
            let g = group(db, group_id)?;
            if g.pending.is_some() {
                return Err(Error::Conflict("membership confirmation is pending".into()));
            }
            let state = mls::group_info(db, &g.mls_id)?;
            if roster(&registry, &state.roster, now)? != g.audience {
                return Err(Error::Verification("current MLS roster mismatch".into()));
            }
            let v = verify(&content, &registry, &g.audience, group_id, state.epoch, now)?;
            if v.event().author != *principal
                || !matches!(v.event().kind(), Kind::AgentMessage | Kind::AgentRelay)
            {
                return Err(Error::Verification(
                    "only agent messages and human relays use this channel".into(),
                ));
            }
            if seen(db, &v)? {
                return Err(Error::Conflict(
                    "event already prepared under another operation".into(),
                ));
            }
            let signer = AgentSigner::load(db)?;
            let sealed = mls::send(db, &signer, &g.mls_id, &plaintext)?;
            let mut h = header(
                &signer,
                &registry,
                operation,
                group_id,
                sealed.epoch,
                g.audience,
                g.previous,
                "application",
                now,
            );
            h.ciphertext_digest = Digest::of(&sealed.ciphertext).to_hex();
            h.expires_at = admission_deadline(&v);
            let bytes = packet_for(&signer, h.clone(), sealed.ciphertext, None)?;
            outbox(db, &h, &request_hash, &bytes, &v.event().id)?;
            Ok(bytes)
        })
    }
    pub fn receive(&mut self, record: &[u8], now: u64) -> Result<Delivery> {
        let trust = &self.trust;
        self.vault.transaction(|db| {
            let digest = Digest::of(record).to_hex();
            let old: Option<Vec<u8>> = storage(
                db.query_row(
                    "SELECT record FROM yhes_inbox WHERE digest=?",
                    [&digest],
                    |r| r.get(0),
                )
                .optional(),
            )?;
            if let Some(old) = old {
                let mut delivery: Delivery =
                    serde_json::from_slice(&old).map_err(|_| Error::Storage)?;
                delivery.replayed = true;
                return Ok(delivery);
            }
            let registry = trust.current(db, now)?;
            let p = packet::decode(record, &registry, now)?;
            let h = &p.header;
            let known: i64 = storage(db.query_row(
                "SELECT count(*) FROM yhes_registry WHERE digest=?",
                [&h.registry],
                |r| r.get(0),
            ))?;
            if known != 1 {
                return Err(Error::Verification("unseen registry checkpoint".into()));
            }
            let g = group(db, &h.group)?;
            if (g.pending.is_some() && h.kind != "application")
                || g.audience != h.audience
                || g.previous != h.previous
            {
                return Err(Error::Conflict(
                    "membership history is not synchronized".into(),
                ));
            }
            let state = mls::group_info(db, &g.mls_id)?;
            if state.epoch != h.epoch {
                return Err(Error::Conflict("message epoch is not current".into()));
            }
            let prepared = if h.kind == "commit" {
                let c = h
                    .control
                    .as_ref()
                    .ok_or_else(|| Error::Verification("missing control".into()))?;
                let (r, v) = action(c, &registry, now)?;
                if h.sender != g.owner
                    || v.event().author != g.owner
                    || r.group() != h.group
                    || r.epoch() != h.epoch
                    || h.next_audience.as_deref() != Some(r.audience())
                {
                    return Err(Error::Verification(
                        "membership control scope mismatch".into(),
                    ));
                }
                Some((r, v))
            } else if h.kind == "application" {
                None
            } else {
                return Err(Error::Invalid("unexpected genesis".into()));
            };
            let policy = |change: &mls::Change| -> Result<()> {
                let (r, _) = prepared
                    .as_ref()
                    .ok_or_else(|| Error::Verification("unapproved MLS commit".into()))?;
                if change.committer.principal != g.owner
                    || change.committer.key_id.as_str() != h.key_id
                    || change.base_epoch != h.epoch
                    || roster(&registry, &change.next_roster, now)? != r.audience()
                {
                    return Err(Error::Verification(
                        "MLS commit differs from reviewed roster".into(),
                    ));
                }
                match r.parameters() {
                    Parameters::GroupAdd {
                        member,
                        key_id,
                        key_package_digest,
                    } => {
                        if change.added_key_package_digests.as_slice() != [*key_package_digest]
                            || change.added.len() != 1
                            || !change.removed.is_empty()
                            || change.added[0].principal != *member
                            || change.added[0].key_id != *key_id
                        {
                            return Err(Error::Verification(
                                "MLS add differs from approval".into(),
                            ));
                        }
                        let c = h.control.as_ref().unwrap();
                        let kp = STANDARD
                            .decode(
                                c.key_package
                                    .as_deref()
                                    .ok_or_else(|| Error::Verification("missing package".into()))?,
                            )
                            .map_err(|_| Error::Verification("invalid package".into()))?;
                        if Digest::of(&kp) != *key_package_digest {
                            return Err(Error::Verification(
                                "MLS package differs from approval".into(),
                            ));
                        }
                    }
                    Parameters::GroupRemove { member } => {
                        if change.removed.len() != 1
                            || !change.added.is_empty()
                            || change.removed[0].principal != *member
                        {
                            return Err(Error::Verification(
                                "MLS remove differs from approval".into(),
                            ));
                        }
                    }
                    _ => return Err(Error::Verification("unsupported MLS control".into())),
                }
                Ok(())
            };
            let delivery = match mls::receive(db, &g.mls_id, &p.ciphertext, &policy)? {
                mls::Received::Commit { change, state } => {
                    let (request, event) = prepared
                        .as_ref()
                        .ok_or_else(|| Error::Verification("unexpected commit".into()))?;
                    if state.epoch != h.epoch + 1 || state.active == change.removes_self {
                        return Err(Error::Verification("MLS epoch did not advance once".into()));
                    }
                    consume_authorization(db, event, &h.operation)?;
                    storage(db.execute(
                        "UPDATE yhes_groups SET audience=?,last_commit=? WHERE id=?",
                        rusqlite::params![
                            serde_json::to_vec(request.audience()).map_err(|_| Error::Storage)?,
                            digest,
                            h.group
                        ],
                    ))?;
                    Delivery {
                        disposition: "membership".into(),
                        message: None,
                        replayed: false,
                    }
                }
                mls::Received::Application {
                    sender,
                    epoch,
                    plaintext,
                } => {
                    if h.kind != "application"
                        || sender.principal != h.sender
                        || sender.key_id.as_str() != h.key_id
                        || epoch != h.epoch
                    {
                        return Err(Error::Verification("MLS transport sender mismatch".into()));
                    }
                    // Authenticated ciphertext with invalid application policy is
                    // consumed once and quarantined in this same transaction.
                    let checked = (|| -> Result<(SignedContent, VerifiedEvent)> {
                        let c: SignedContent = serde_json::from_slice(&plaintext)
                            .map_err(|_| Error::Verification("malformed inner content".into()))?;
                        let v = verify(&c, &registry, &g.audience, &h.group, epoch, now)?;
                        if v.event().author != h.sender
                            || v.event().key_id.as_str() != h.key_id
                            || !matches!(v.event().kind(), Kind::AgentMessage | Kind::AgentRelay)
                        {
                            return Err(Error::Verification(
                                "inner event does not match MLS sender".into(),
                            ));
                        }
                        Ok((c, v))
                    })();
                    match checked {
                        Ok((content, v)) => match seen(db, &v) {
                            Ok(true) => Delivery {
                                disposition: "duplicate".into(),
                                message: None,
                                replayed: false,
                            },
                            Err(Error::Verification(_)) => Delivery {
                                disposition: "quarantined".into(),
                                message: None,
                                replayed: false,
                            },
                            Err(e) => return Err(e),
                            Ok(false) => Delivery {
                                disposition: "verified".into(),
                                message: Some(AcceptedMessage {
                                    author: v.event().author.clone(),
                                    kind: v.event().kind().as_str().into(),
                                    human_authored: v.is_human_authored(),
                                    human_original_author: v
                                        .original()
                                        .map(|o| o.event().author.clone()),
                                    event_id: v.event().id.clone(),
                                    payload_digest: v.digest().to_hex(),
                                    accepted_at: now,
                                    content,
                                }),
                                replayed: false,
                            },
                        },
                        Err(_) => Delivery {
                            disposition: "quarantined".into(),
                            message: None,
                            replayed: false,
                        },
                    }
                }
            };
            let record = serde_json::to_vec(&delivery).map_err(|_| Error::Storage)?;
            storage(db.execute(
                "INSERT INTO yhes_inbox VALUES (?,?,?,?,?)",
                rusqlite::params![
                    digest,
                    delivery.message.as_ref().map(|m| &m.event_id),
                    h.sender,
                    delivery.disposition,
                    record
                ],
            ))?;
            Ok(delivery)
        })
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
