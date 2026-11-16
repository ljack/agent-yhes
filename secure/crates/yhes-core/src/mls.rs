//! Low-level MLS operations on the vault connection. See `MLS-API.md`.
//!
//! Every function runs inside the caller's transaction and loads the group
//! fresh. Any error means the caller must abort that transaction. Registry,
//! authority, action and audience checks, and the outbox, inbox and
//! checkpoints, belong to the caller.

use crate::{store::Provider, Error, Result};
use ed25519_dalek::{Signer as _, SigningKey};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;
use rusqlite::{Connection, OptionalExtension};
use yhes_wire::{
    pae, Algorithm, Digest, KeyId, PublicKey, SignatureEntry, EVENT_PAYLOAD_TYPE,
    TRANSPORT_PAYLOAD_TYPE,
};
use zeroize::Zeroizing;

/// The only supported ciphersuite (MLS suite 1). There is no fallback.
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// Largest accepted input of any kind.
const MAX_INPUT: usize = 1 << 20;
const CREDENTIAL_PREFIX: &[u8] = b"agent-yhes/mls/v1";

fn invalid(message: &'static str) -> Error {
    Error::Invalid(message.into())
}
fn conflict(message: &'static str) -> Error {
    Error::Conflict(message.into())
}
fn unverified(message: &'static str) -> Error {
    Error::Verification(message.into())
}

// ---------------------------------------------------------------- identity

/// The agent's Ed25519 identity. One key signs MLS content and DSSE
/// envelopes; the inputs are domain-separated by their encodings.
pub(crate) struct AgentSigner {
    project: String,
    principal: String,
    key_id: KeyId,
    public: PublicKey,
    key: SigningKey,
}

impl AgentSigner {
    /// Generates the key and stores it. Fails if an identity exists.
    pub(crate) fn init(db: &Connection, principal: &str) -> Result<AgentSigner> {
        crate::packet::id(principal)?;
        let project = project(db)?;
        let exists: Option<i64> = db
            .query_row("SELECT id FROM yhes_identity WHERE id=1", [], |r| r.get(0))
            .optional()
            .map_err(|_| Error::Storage)?;
        if exists.is_some() {
            return Err(conflict("identity already exists"));
        }
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let public = wire_key(key.verifying_key().as_bytes())?;
        let key_id = public.key_id();
        let secret = Zeroizing::new(key.to_bytes());
        db.execute(
            "INSERT INTO yhes_identity (id,principal,key_id,secret,public) VALUES (1,?,?,?,?)",
            rusqlite::params![
                principal,
                key_id.as_str(),
                secret.as_slice(),
                public.as_bytes()
            ],
        )
        .map_err(|_| Error::Storage)?;
        Ok(AgentSigner {
            project,
            principal: principal.to_owned(),
            key_id,
            public,
            key,
        })
    }

    /// Loads the stored identity and checks that the row is self-consistent.
    pub(crate) fn load(db: &Connection) -> Result<AgentSigner> {
        let project = project(db)?;
        type Row = (String, String, Zeroizing<Vec<u8>>, Vec<u8>);
        let row: Option<Row> = db
            .query_row(
                "SELECT principal,key_id,secret,public FROM yhes_identity WHERE id=1",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        Zeroizing::new(r.get::<_, Vec<u8>>(2)?),
                        r.get(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        let (principal, stored_id, secret, stored_public) =
            row.ok_or(invalid("no agent identity"))?;
        let mismatch = || unverified("stored identity is inconsistent");
        crate::packet::id(&principal).map_err(|_| mismatch())?;
        let seed: Zeroizing<[u8; 32]> =
            Zeroizing::new(secret.as_slice().try_into().map_err(|_| mismatch())?);
        let key = SigningKey::from_bytes(&seed);
        let public = wire_key(key.verifying_key().as_bytes())?;
        let key_id = public.key_id();
        if public.as_bytes() != stored_public.as_slice() || key_id.as_str() != stored_id {
            return Err(mismatch());
        }
        Ok(AgentSigner {
            project,
            principal,
            key_id,
            public,
            key,
        })
    }

    pub(crate) fn project(&self) -> &str {
        &self.project
    }
    pub(crate) fn principal(&self) -> &str {
        &self.principal
    }
    pub(crate) fn key_id(&self) -> &KeyId {
        &self.key_id
    }
    pub(crate) fn public(&self) -> &PublicKey {
        &self.public
    }

    /// DSSE signature over `pae(payload_type, payload)` for an event or a
    /// transport record. It never signs caller-chosen raw bytes.
    pub(crate) fn sign(&self, payload_type: &str, payload: &[u8]) -> Result<SignatureEntry> {
        if payload_type != EVENT_PAYLOAD_TYPE && payload_type != TRANSPORT_PAYLOAD_TYPE {
            return Err(invalid("payload type cannot be signed by an agent"));
        }
        if payload.len() > MAX_INPUT {
            return Err(invalid("payload too large"));
        }
        Ok(SignatureEntry {
            key_id: self.key_id.clone(),
            algorithm: Algorithm::Ed25519,
            signature: self.key.sign(&pae(payload_type, payload)).to_bytes(),
        })
    }

    fn credential(&self) -> CredentialWithKey {
        let mut identity = CREDENTIAL_PREFIX.to_vec();
        for part in [
            self.project.as_str(),
            self.principal.as_str(),
            self.key_id.as_str(),
        ] {
            identity.push(0);
            identity.extend_from_slice(part.as_bytes());
        }
        CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: self.public.as_bytes().to_vec().into(),
        }
    }
}

/// The MLS view of the signer. Private so that raw signing is not reachable
/// from the rest of the crate.
struct MlsSigner<'a>(&'a AgentSigner);

impl Signer for MlsSigner<'_> {
    fn sign(&self, payload: &[u8]) -> std::result::Result<Vec<u8>, SignerError> {
        Ok(self.0.key.sign(payload).to_bytes().to_vec())
    }
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

fn wire_key(raw: &[u8]) -> Result<PublicKey> {
    PublicKey::new(Algorithm::Ed25519, raw).map_err(|_| unverified("invalid signature key"))
}

fn project(db: &Connection) -> Result<String> {
    let bytes: Vec<u8> = db
        .query_row("SELECT value FROM yhes_meta WHERE key='project'", [], |r| {
            r.get(0)
        })
        .map_err(|_| Error::Storage)?;
    let project = String::from_utf8(bytes).map_err(|_| Error::Storage)?;
    crate::packet::id(&project)?;
    Ok(project)
}

// ------------------------------------------------------------------- types

/// A group member whose credential is bound to its signature key and to this
/// project. Binding is not authorization: the caller checks the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    pub principal: String,
    pub key_id: KeyId,
    /// 32 raw Ed25519 bytes.
    pub signature_key: Vec<u8>,
    /// `None` for a member that is not yet in the tree.
    pub leaf: Option<u32>,
}

impl Member {
    fn same_identity(&self, other: &Member) -> bool {
        self.principal == other.principal
            && self.key_id == other.key_id
            && self.signature_key == other.signature_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupState {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub roster: Vec<Member>,
    /// An own staged commit awaits `merge_pending` or `clear_pending`.
    pub pending: bool,
    /// False once this client has been removed.
    pub active: bool,
}

/// An own membership change that is staged but not merged.
#[derive(Debug, Clone)]
pub(crate) struct Staged {
    pub base_epoch: u64,
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub added: Vec<Member>,
    pub removed: Vec<Member>,
    pub next_roster: Vec<Member>,
}

#[derive(Debug, Clone)]
pub(crate) struct Sealed {
    pub epoch: u64,
    pub ciphertext: Vec<u8>,
}

/// An incoming commit, shown to the policy before it is merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Change {
    pub committer: Member,
    pub base_epoch: u64,
    pub added: Vec<Member>,
    /// SHA-256 of each added KeyPackage's exact TLS bytes, in the order of
    /// `added`: the same bytes `inspect_key_package` and `stage_add` take.
    pub added_key_package_digests: Vec<Digest>,
    pub removed: Vec<Member>,
    pub next_roster: Vec<Member>,
    pub removes_self: bool,
}

/// A Welcome, shown to the policy before the group is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invitation {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub inviter: Member,
    /// Includes this client.
    pub roster: Vec<Member>,
    /// SHA-256 of the exact TLS bytes of the own KeyPackage this Welcome was
    /// addressed to, as `key_package` returned them.
    pub own_key_package_digest: Digest,
}

pub(crate) enum Received {
    Application {
        sender: Member,
        epoch: u64,
        plaintext: Zeroizing<Vec<u8>>,
    },
    Commit {
        change: Change,
        state: GroupState,
    },
}

// ----------------------------------------------------------------- helpers

fn config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build()
}

fn check_input(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_INPUT {
        return Err(invalid("input is empty or too large"));
    }
    Ok(())
}

fn check_group_id(group_id: &[u8]) -> Result<()> {
    if group_id.is_empty() || group_id.len() > 128 {
        return Err(invalid("invalid group id"));
    }
    Ok(())
}

/// Parses a credential and binds it to the signature key and the project.
fn member(
    project: &str,
    credential: &Credential,
    signature_key: &[u8],
    leaf: Option<u32>,
) -> Result<Member> {
    let bad = || unverified("credential is not bound to its key and project");
    let basic = BasicCredential::try_from(credential.clone()).map_err(|_| bad())?;
    let mut parts = basic.identity().split(|b| *b == 0);
    let (Some(prefix), Some(p), Some(principal), Some(key_id), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(bad());
    };
    if prefix != CREDENTIAL_PREFIX || p != project.as_bytes() {
        return Err(bad());
    }
    let principal = std::str::from_utf8(principal).map_err(|_| bad())?;
    crate::packet::id(principal).map_err(|_| bad())?;
    let key_id = std::str::from_utf8(key_id).map_err(|_| bad())?;
    let key_id = KeyId::parse(key_id).map_err(|_| bad())?;
    let key = wire_key(signature_key).map_err(|_| bad())?;
    if key.key_id() != key_id {
        return Err(bad());
    }
    Ok(Member {
        principal: principal.to_owned(),
        key_id,
        signature_key: signature_key.to_vec(),
        leaf,
    })
}

fn member_of_leaf(project: &str, leaf: &LeafNode, index: Option<u32>) -> Result<Member> {
    member(
        project,
        leaf.credential(),
        leaf.signature_key().as_slice(),
        index,
    )
}

fn roster(
    project: &str,
    members: impl Iterator<Item = openmls::group::Member>,
) -> Result<Vec<Member>> {
    let mut out = members
        .map(|m| {
            member(
                project,
                &m.credential,
                &m.signature_key,
                Some(m.index.u32()),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(|m| m.leaf);
    Ok(out)
}

fn load(provider: &Provider<'_>, group_id: &[u8]) -> Result<MlsGroup> {
    check_group_id(group_id)?;
    MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id))
        .map_err(|_| Error::Storage)?
        .ok_or(invalid("unknown group"))
}

fn state(project: &str, group: &MlsGroup) -> Result<GroupState> {
    Ok(GroupState {
        group_id: group.group_id().as_slice().to_vec(),
        epoch: group.epoch().as_u64(),
        roster: roster(project, group.members())?,
        pending: group.pending_commit().is_some(),
        active: group.is_active(),
    })
}

/// The group must be usable for an own operation with this signer.
fn check_own(group: &MlsGroup, signer: &AgentSigner, current: &[Member]) -> Result<()> {
    if !group.is_active() {
        return Err(conflict("no longer a member of this group"));
    }
    if group.ciphersuite() != SUITE {
        return Err(unverified("unsupported ciphersuite"));
    }
    let own = group.own_leaf_index().u32();
    let bound = current.iter().any(|m| {
        m.leaf == Some(own)
            && m.principal == signer.principal
            && m.key_id == signer.key_id
            && m.signature_key == signer.public.as_bytes()
    });
    if !bound {
        return Err(unverified("group leaf does not belong to this identity"));
    }
    Ok(())
}

fn check_not_pending(group: &MlsGroup) -> Result<()> {
    if group.pending_commit().is_some() {
        return Err(conflict("a membership change is pending"));
    }
    Ok(())
}

fn validated_key_package(provider: &Provider<'_>, bytes: &[u8]) -> Result<KeyPackage> {
    check_input(bytes)?;
    let package = KeyPackageIn::tls_deserialize_exact(bytes)
        .map_err(|_| invalid("malformed key package"))?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| unverified("key package does not verify"))?;
    if package.ciphersuite() != SUITE {
        return Err(unverified("unsupported ciphersuite"));
    }
    Ok(package)
}

/// Digest of a KeyPackage's exact TLS encoding.
fn key_package_digest(package: &KeyPackage) -> Result<Digest> {
    Ok(Digest::of(
        &package.tls_serialize_detached().map_err(|_| Error::Mls)?,
    ))
}

fn serialize(message: &MlsMessageOut) -> Result<Vec<u8>> {
    message.tls_serialize_detached().map_err(|_| Error::Mls)
}

fn next_roster(current: &[Member], added: &[Member], removed: &[Member]) -> Vec<Member> {
    let mut next: Vec<Member> = current
        .iter()
        .filter(|m| !removed.iter().any(|r| r.leaf == m.leaf))
        .cloned()
        .collect();
    next.extend(added.iter().cloned());
    next
}

// -------------------------------------------------------------- operations

/// New group with this agent as the only member.
pub(crate) fn create(db: &Connection, signer: &AgentSigner, group_id: &[u8]) -> Result<GroupState> {
    check_group_id(group_id)?;
    let provider = Provider::new(db);
    let id = GroupId::from_slice(group_id);
    if MlsGroup::load(provider.storage(), &id)
        .map_err(|_| Error::Storage)?
        .is_some()
    {
        return Err(conflict("group already exists"));
    }
    let group = MlsGroup::new_with_group_id(
        &provider,
        &MlsSigner(signer),
        &config(),
        id,
        signer.credential(),
    )
    .map_err(|_| Error::Mls)?;
    state(&signer.project, &group)
}

/// Fresh KeyPackage. Private parts stay in provider storage.
pub(crate) fn key_package(db: &Connection, signer: &AgentSigner) -> Result<Vec<u8>> {
    let provider = Provider::new(db);
    let bundle = KeyPackage::builder()
        .build(SUITE, &provider, &MlsSigner(signer), signer.credential())
        .map_err(|_| Error::Mls)?;
    bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|_| Error::Mls)
}

/// Validates a KeyPackage without touching state.
pub(crate) fn inspect_key_package(project: &str, key_package: &[u8]) -> Result<Member> {
    check_input(key_package)?;
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let package = KeyPackageIn::tls_deserialize_exact(key_package)
        .map_err(|_| invalid("malformed key package"))?
        .validate(&crypto, ProtocolVersion::Mls10)
        .map_err(|_| unverified("key package does not verify"))?;
    if package.ciphersuite() != SUITE {
        return Err(unverified("unsupported ciphersuite"));
    }
    member_of_leaf(project, package.leaf_node(), None)
}

/// Stages an Add commit for one validated KeyPackage.
pub(crate) fn stage_add(
    db: &Connection,
    signer: &AgentSigner,
    group_id: &[u8],
    key_package: &[u8],
) -> Result<Staged> {
    let provider = Provider::new(db);
    let mut group = load(&provider, group_id)?;
    let current = roster(&signer.project, group.members())?;
    check_own(&group, signer, &current)?;
    check_not_pending(&group)?;
    let package = validated_key_package(&provider, key_package)?;
    let added = member_of_leaf(&signer.project, package.leaf_node(), None)?;
    if current.iter().any(|m| m.same_identity(&added)) {
        return Err(conflict("already a member"));
    }
    let base_epoch = group.epoch().as_u64();
    let (commit, welcome, _) = group
        .add_members(&provider, &MlsSigner(signer), &[package])
        .map_err(|_| Error::Mls)?;
    let added = vec![added];
    Ok(Staged {
        base_epoch,
        commit: serialize(&commit)?,
        welcome: Some(serialize(&welcome)?),
        next_roster: next_roster(&current, &added, &[]),
        added,
        removed: Vec::new(),
    })
}

/// Stages a Remove commit for the member with this principal and key.
pub(crate) fn stage_remove(
    db: &Connection,
    signer: &AgentSigner,
    group_id: &[u8],
    principal: &str,
    key_id: &KeyId,
) -> Result<Staged> {
    let provider = Provider::new(db);
    let mut group = load(&provider, group_id)?;
    let current = roster(&signer.project, group.members())?;
    check_own(&group, signer, &current)?;
    check_not_pending(&group)?;
    let target = current
        .iter()
        .find(|m| m.principal == principal && m.key_id == *key_id)
        .cloned()
        .ok_or(invalid("not a member"))?;
    let leaf = target.leaf.ok_or(invalid("not a member"))?;
    if leaf == group.own_leaf_index().u32() {
        return Err(invalid("cannot remove oneself"));
    }
    let base_epoch = group.epoch().as_u64();
    let (commit, welcome, _) = group
        .remove_members(&provider, &MlsSigner(signer), &[LeafNodeIndex::new(leaf)])
        .map_err(|_| Error::Mls)?;
    let removed = vec![target];
    Ok(Staged {
        base_epoch,
        commit: serialize(&commit)?,
        welcome: welcome.as_ref().map(serialize).transpose()?,
        next_roster: next_roster(&current, &[], &removed),
        added: Vec::new(),
        removed,
    })
}

/// Applies the own staged commit after transport accepted it.
pub(crate) fn merge_pending(db: &Connection, group_id: &[u8]) -> Result<GroupState> {
    let provider = Provider::new(db);
    let mut group = load(&provider, group_id)?;
    if group.pending_commit().is_none() {
        return Err(conflict("no membership change is pending"));
    }
    group
        .merge_pending_commit(&provider)
        .map_err(|_| Error::Mls)?;
    state(&project(db)?, &group)
}

/// Discards the own staged commit after its rejection is established.
pub(crate) fn clear_pending(db: &Connection, group_id: &[u8]) -> Result<GroupState> {
    let provider = Provider::new(db);
    let mut group = load(&provider, group_id)?;
    if group.pending_commit().is_none() {
        return Err(conflict("no membership change is pending"));
    }
    group
        .clear_pending_commit(provider.storage())
        .map_err(|_| Error::Storage)?;
    state(&project(db)?, &group)
}

/// Processes a Welcome. The group is stored only if `policy` accepts it.
pub(crate) fn join(
    db: &Connection,
    signer: &AgentSigner,
    welcome: &[u8],
    policy: &dyn Fn(&Invitation) -> Result<()>,
) -> Result<GroupState> {
    check_input(welcome)?;
    let provider = Provider::new(db);
    let message =
        MlsMessageIn::tls_deserialize_exact(welcome).map_err(|_| invalid("malformed welcome"))?;
    let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        return Err(invalid("not a welcome"));
    };
    let create_config = config();
    let processed =
        ProcessedWelcome::new_from_welcome(&provider, create_config.join_config(), welcome)
            .map_err(|_| Error::Mls)?;
    let own_key_package_digest = key_package_digest(
        processed
            .own_key_package()
            .ok_or(unverified("welcome names no own key package"))?,
    )?;
    let staged = processed
        .into_staged_welcome(&provider, None)
        .map_err(|_| Error::Mls)?;
    let context = staged.group_context();
    if context.ciphersuite() != SUITE {
        return Err(unverified("unsupported ciphersuite"));
    }
    let group_id = context.group_id().clone();
    check_group_id(group_id.as_slice())?;
    if MlsGroup::load(provider.storage(), &group_id)
        .map_err(|_| Error::Storage)?
        .is_some()
    {
        return Err(conflict("group already exists"));
    }
    let members = roster(&signer.project, staged.members())?;
    let own = staged.own_leaf_index().u32();
    let own_bound = members.iter().any(|m| {
        m.leaf == Some(own)
            && m.principal == signer.principal
            && m.key_id == signer.key_id
            && m.signature_key == signer.public.as_bytes()
    });
    if !own_bound {
        return Err(unverified("welcome is not for this identity"));
    }
    let inviter_leaf = staged.welcome_sender_index().u32();
    let inviter = members
        .iter()
        .find(|m| m.leaf == Some(inviter_leaf))
        .cloned()
        .ok_or(unverified("welcome sender is not a member"))?;
    let invitation = Invitation {
        group_id: group_id.as_slice().to_vec(),
        epoch: context.epoch().as_u64(),
        inviter,
        roster: members,
        own_key_package_digest,
    };
    policy(&invitation)?;
    let group = staged.into_group(&provider).map_err(|_| Error::Mls)?;
    state(&signer.project, &group)
}

/// Encrypts one application message.
pub(crate) fn send(
    db: &Connection,
    signer: &AgentSigner,
    group_id: &[u8],
    plaintext: &[u8],
) -> Result<Sealed> {
    if plaintext.len() > MAX_INPUT {
        return Err(invalid("input is empty or too large"));
    }
    let provider = Provider::new(db);
    let mut group = load(&provider, group_id)?;
    let current = roster(&signer.project, group.members())?;
    check_own(&group, signer, &current)?;
    check_not_pending(&group)?;
    let epoch = group.epoch().as_u64();
    let message = group
        .create_message(&provider, &MlsSigner(signer), plaintext)
        .map_err(|_| Error::Mls)?;
    Ok(Sealed {
        epoch,
        ciphertext: serialize(&message)?,
    })
}

/// Processes one incoming MLS message. A commit is merged only if `policy`
/// accepts the staged change.
pub(crate) fn receive(
    db: &Connection,
    group_id: &[u8],
    message: &[u8],
    policy: &dyn Fn(&Change) -> Result<()>,
) -> Result<Received> {
    check_input(message)?;
    let project = project(db)?;
    let provider = Provider::new(db);
    let mut group = load(&provider, group_id)?;
    if !group.is_active() {
        return Err(conflict("no longer a member of this group"));
    }
    let protocol = MlsMessageIn::tls_deserialize_exact(message)
        .map_err(|_| invalid("malformed message"))?
        .try_into_protocol_message()
        .map_err(|_| invalid("not a group message"))?;
    if protocol.group_id().as_slice() != group_id {
        return Err(invalid("message is for another group"));
    }
    let current = roster(&project, group.members())?;
    let base_epoch = group.epoch().as_u64();
    let processed = group
        .process_message(&provider, protocol)
        .map_err(|_| Error::Mls)?;
    let Sender::Member(index) = processed.sender() else {
        return Err(unverified("sender is not a member"));
    };
    let sender = current
        .iter()
        .find(|m| m.leaf == Some(index.u32()))
        .cloned()
        .ok_or(unverified("sender is not a member"))?;
    let epoch = processed.epoch().as_u64();

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => Ok(Received::Application {
            sender,
            epoch,
            plaintext: Zeroizing::new(application.into_bytes()),
        }),
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            // Incoming old-epoch applications may drain while our own Commit
            // awaits publication. Another Commit must wait for resolution.
            check_not_pending(&group)?;
            let mut added = Vec::new();
            let mut removed = Vec::new();
            let mut added_key_package_digests = Vec::new();
            for queued in staged.queued_proposals() {
                match queued.proposal() {
                    Proposal::Add(add) => {
                        let package = add.key_package();
                        if package.ciphersuite() != SUITE {
                            return Err(unverified("unsupported ciphersuite"));
                        }
                        added.push(member_of_leaf(&project, package.leaf_node(), None)?);
                        added_key_package_digests.push(key_package_digest(package)?);
                    }
                    Proposal::Remove(remove) => {
                        let leaf = remove.removed().u32();
                        let target = current
                            .iter()
                            .find(|m| m.leaf == Some(leaf))
                            .cloned()
                            .ok_or(unverified("removed leaf is not a member"))?;
                        removed.push(target);
                    }
                    _ => return Err(unverified("unsupported proposal")),
                }
            }
            // The update path may refresh the committer's keys but not its identity.
            if let Some(leaf) = staged.update_path_leaf_node() {
                if !member_of_leaf(&project, leaf, sender.leaf)?.same_identity(&sender) {
                    return Err(unverified("commit changes the committer's identity"));
                }
            }
            let change = Change {
                committer: sender,
                base_epoch,
                next_roster: next_roster(&current, &added, &removed),
                added,
                added_key_package_digests,
                removed,
                removes_self: staged.self_removed(),
            };
            policy(&change)?;
            group
                .merge_staged_commit(&provider, *staged)
                .map_err(|_| Error::Mls)?;
            let state = state(&project, &group)?;
            Ok(Received::Commit { change, state })
        }
        _ => Err(unverified("unsupported message")),
    }
}

/// Current public state of a stored group.
pub(crate) fn group_info(db: &Connection, group_id: &[u8]) -> Result<GroupState> {
    let provider = Provider::new(db);
    let group = load(&provider, group_id)?;
    state(&project(db)?, &group)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{tests::fixture, Vault};

    const GROUP: &[u8] = b"group-1";

    /// One agent with its own disposable encrypted vault.
    struct Peer {
        _directory: tempfile::TempDir,
        vault: Vault,
        signer: AgentSigner,
    }

    impl Peer {
        fn new(principal: &str) -> Peer {
            let (directory, _key, _anchors, mut vault) = fixture();
            let signer = vault
                .transaction(|db| AgentSigner::init(db, principal))
                .unwrap();
            Peer {
                _directory: directory,
                vault,
                signer,
            }
        }

        /// Runs `action` in one vault transaction; an error rolls it back.
        fn tx<T>(
            &mut self,
            action: impl FnOnce(&Connection, &AgentSigner) -> Result<T>,
        ) -> Result<T> {
            let signer = &self.signer;
            self.vault.transaction(|db| action(db, signer))
        }

        fn info(&mut self) -> GroupState {
            self.tx(|db, _| group_info(db, GROUP)).unwrap()
        }

        fn as_member(&self) -> Member {
            Member {
                principal: self.signer.principal().to_owned(),
                key_id: self.signer.key_id().clone(),
                signature_key: self.signer.public().as_bytes().to_vec(),
                leaf: None,
            }
        }
    }

    fn accept_change(_: &Change) -> Result<()> {
        Ok(())
    }
    fn accept_invitation(_: &Invitation) -> Result<()> {
        Ok(())
    }

    /// alice creates the group and adds bob; both end at epoch 1.
    fn pair() -> (Peer, Peer) {
        let mut alice = Peer::new("alice-agent");
        let mut bob = Peer::new("bob-agent");
        alice.tx(|db, s| create(db, s, GROUP)).unwrap();
        let package = bob.tx(key_package).unwrap();
        let staged = alice.tx(|db, s| stage_add(db, s, GROUP, &package)).unwrap();
        alice.tx(|db, _| merge_pending(db, GROUP)).unwrap();
        let welcome = staged.welcome.unwrap();
        bob.tx(|db, s| join(db, s, &welcome, &accept_invitation))
            .unwrap();
        (alice, bob)
    }

    /// Adds `new` through `adder`; every peer in `others` consumes the commit.
    fn add(adder: &mut Peer, others: &mut [&mut Peer], new: &mut Peer) {
        let package = new.tx(key_package).unwrap();
        let staged = adder.tx(|db, s| stage_add(db, s, GROUP, &package)).unwrap();
        adder.tx(|db, _| merge_pending(db, GROUP)).unwrap();
        for peer in others.iter_mut() {
            peer.tx(|db, _| receive(db, GROUP, &staged.commit, &accept_change))
                .unwrap();
        }
        let welcome = staged.welcome.unwrap();
        new.tx(|db, s| join(db, s, &welcome, &accept_invitation))
            .unwrap();
    }

    fn names(roster: &[Member]) -> Vec<&str> {
        roster.iter().map(|m| m.principal.as_str()).collect()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn identity_is_created_once_and_reloads_consistently() {
        let (_directory, _key, _anchors, mut vault) = fixture();
        assert!(matches!(
            vault.transaction(AgentSigner::load),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            vault.transaction(|db| AgentSigner::init(db, "../agent")),
            Err(Error::Invalid(_))
        ));
        let created = vault
            .transaction(|db| AgentSigner::init(db, "alice-agent"))
            .unwrap();
        assert_eq!(created.project(), "fixture");
        assert_eq!(created.principal(), "alice-agent");
        assert_eq!(created.public().key_id(), *created.key_id());
        assert!(matches!(
            vault.transaction(|db| AgentSigner::init(db, "alice-agent")),
            Err(Error::Conflict(_))
        ));
        let loaded = vault.transaction(AgentSigner::load).unwrap();
        assert_eq!(loaded.key_id(), created.key_id());
        assert_eq!(loaded.public(), created.public());

        // A row whose parts disagree is refused, whichever part was changed.
        for statement in [
            "UPDATE yhes_identity SET public=x'0000000000000000000000000000000000000000000000000000000000000001'",
            "UPDATE yhes_identity SET key_id='k_0000000000000000000000000000000000000000000000000000000000000000'",
            "UPDATE yhes_identity SET secret=x'0101010101010101010101010101010101010101010101010101010101010101'",
            "UPDATE yhes_identity SET secret=x'01'",
            "UPDATE yhes_identity SET principal='../x'",
        ] {
            let result: Result<()> = vault.transaction(|db| {
                db.execute(statement, []).map_err(|_| Error::Storage)?;
                AgentSigner::load(db).map(|_| ())
            });
            assert!(matches!(result, Err(Error::Verification(_))), "{statement}");
        }
        // Those attempts rolled back.
        assert_eq!(
            vault.transaction(AgentSigner::load).unwrap().key_id(),
            created.key_id()
        );
    }

    #[test]
    fn dsse_signing_is_domain_separated_and_limited_to_agent_types() {
        let alice = Peer::new("alice-agent");
        let payload = br#"{"example":true}"#;
        for payload_type in [EVENT_PAYLOAD_TYPE, TRANSPORT_PAYLOAD_TYPE] {
            let entry = alice.signer.sign(payload_type, payload).unwrap();
            assert_eq!(entry.key_id, *alice.signer.key_id());
            assert_eq!(entry.algorithm, Algorithm::Ed25519);
            let public = alice.signer.public();
            assert!(public
                .verify(&pae(payload_type, payload), &entry.signature)
                .is_ok());
            // Not a signature over the bare payload or the other type.
            assert!(public.verify(payload, &entry.signature).is_err());
            let other = if payload_type == EVENT_PAYLOAD_TYPE {
                TRANSPORT_PAYLOAD_TYPE
            } else {
                EVENT_PAYLOAD_TYPE
            };
            assert!(public
                .verify(&pae(other, payload), &entry.signature)
                .is_err());
            // The envelope layer accepts it.
            assert!(yhes_wire::Envelope::new(payload_type, payload.to_vec(), vec![entry]).is_ok());
        }
        // An agent never signs a registry, or an unknown type.
        assert!(matches!(
            alice.signer.sign(yhes_wire::REGISTRY_PAYLOAD_TYPE, payload),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            alice.signer.sign("text/plain", payload),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn create_add_join_and_exchange_messages() {
        let mut alice = Peer::new("alice-agent");
        let mut bob = Peer::new("bob-agent");

        let created = alice.tx(|db, s| create(db, s, GROUP)).unwrap();
        assert_eq!(created.group_id, GROUP);
        assert_eq!(created.epoch, 0);
        assert!(created.active && !created.pending);
        assert_eq!(created.roster.len(), 1);
        assert!(created.roster[0].same_identity(&alice.as_member()));
        assert!(matches!(
            alice.tx(|db, s| create(db, s, GROUP)),
            Err(Error::Conflict(_))
        ));

        // The candidate can be inspected before anything is staged.
        let package = bob.tx(key_package).unwrap();
        let candidate = inspect_key_package("fixture", &package).unwrap();
        assert!(candidate.same_identity(&bob.as_member()));
        assert_eq!(candidate.leaf, None);

        let staged = alice.tx(|db, s| stage_add(db, s, GROUP, &package)).unwrap();
        assert_eq!(staged.base_epoch, 0);
        assert_eq!(names(&staged.next_roster), ["alice-agent", "bob-agent"]);
        assert!(staged.added[0].same_identity(&bob.as_member()));
        assert!(staged.removed.is_empty());
        // Staging does not advance the epoch.
        let pending = alice.info();
        assert!(pending.pending);
        assert_eq!(pending.epoch, 0);
        assert_eq!(pending.roster.len(), 1);

        let merged = alice.tx(|db, _| merge_pending(db, GROUP)).unwrap();
        assert_eq!(merged.epoch, 1);
        assert!(!merged.pending);
        assert_eq!(names(&merged.roster), ["alice-agent", "bob-agent"]);

        // bob sees the invitation, with both bound identities, before joining.
        let welcome = staged.welcome.clone().unwrap();
        let seen = std::cell::RefCell::new(None);
        let joined = bob
            .tx(|db, s| {
                join(db, s, &welcome, &|invitation| {
                    *seen.borrow_mut() = Some(invitation.clone());
                    Ok(())
                })
            })
            .unwrap();
        let invitation = seen.into_inner().unwrap();
        assert_eq!(invitation.group_id, GROUP);
        assert_eq!(invitation.epoch, 1);
        assert!(invitation.inviter.same_identity(&alice.as_member()));
        assert_eq!(names(&invitation.roster), ["alice-agent", "bob-agent"]);
        assert_eq!(joined, bob.info());
        assert_eq!(joined.roster, merged.roster);
        assert_eq!(joined.epoch, 1);

        // Application messages in both directions.
        let secret = b"PLAINTEXT-MARKER-91277 from alice";
        let sealed = alice.tx(|db, s| send(db, s, GROUP, secret)).unwrap();
        assert_eq!(sealed.epoch, 1);
        assert!(!contains(&sealed.ciphertext, b"PLAINTEXT-MARKER-91277"));
        assert!(
            !contains(&staged.commit, b"bob-agent"),
            "commit must be encrypted"
        );
        match bob
            .tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change))
            .unwrap()
        {
            Received::Application {
                sender,
                epoch,
                plaintext,
            } => {
                assert!(sender.same_identity(&alice.as_member()));
                assert_eq!(epoch, 1);
                assert_eq!(plaintext.as_slice(), secret);
            }
            Received::Commit { .. } => panic!("application message expected"),
        }
        let reply = bob.tx(|db, s| send(db, s, GROUP, b"reply")).unwrap();
        match alice
            .tx(|db, _| receive(db, GROUP, &reply.ciphertext, &accept_change))
            .unwrap()
        {
            Received::Application {
                sender, plaintext, ..
            } => {
                assert!(sender.same_identity(&bob.as_member()));
                assert_eq!(plaintext.as_slice(), b"reply");
            }
            Received::Commit { .. } => panic!("application message expected"),
        }
    }

    #[test]
    fn state_survives_reload_and_private_material_is_not_in_public_bytes() {
        let (mut alice, mut bob) = pair();
        // Each call loads the group from the encrypted vault again.
        for i in 0..3u8 {
            let sealed = alice.tx(|db, s| send(db, s, GROUP, &[i; 8])).unwrap();
            let received = bob.tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change));
            assert!(matches!(received, Ok(Received::Application { .. })));
        }
        let reloaded = alice.tx(|db, _| AgentSigner::load(db)).unwrap();
        assert_eq!(reloaded.key_id(), alice.signer.key_id());
        let sealed = alice
            .tx(|db, _| send(db, &reloaded, GROUP, b"after reload"))
            .unwrap();
        assert!(bob
            .tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change))
            .is_ok());

        // The signing seed never appears in anything handed to transport.
        let seed = alice.signer.key.to_bytes();
        let package = alice.tx(key_package).unwrap();
        for public in [&sealed.ciphertext, &package] {
            assert!(!contains(public, &seed));
        }
    }

    #[test]
    fn a_rejected_join_stores_nothing_and_can_be_retried() {
        let mut alice = Peer::new("alice-agent");
        let mut bob = Peer::new("bob-agent");
        alice.tx(|db, s| create(db, s, GROUP)).unwrap();
        let package = bob.tx(key_package).unwrap();
        let staged = alice.tx(|db, s| stage_add(db, s, GROUP, &package)).unwrap();
        alice.tx(|db, _| merge_pending(db, GROUP)).unwrap();
        let welcome = staged.welcome.unwrap();

        // Policy refusal: the error comes back unchanged and nothing is stored.
        let refused = bob.tx(|db, s| {
            join(db, s, &welcome, &|_| {
                Err(Error::Verification("inviter not authorized".into()))
            })
        });
        assert!(matches!(refused, Err(Error::Verification(m)) if m == "inviter not authorized"));
        assert!(matches!(
            bob.tx(|db, _| group_info(db, GROUP)),
            Err(Error::Invalid(_))
        ));

        // A corrupted Welcome fails without consuming the KeyPackage.
        let mut corrupted = welcome.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert!(bob
            .tx(|db, s| join(db, s, &corrupted, &accept_invitation))
            .is_err());
        assert!(bob
            .tx(|db, s| join(db, s, b"junk", &accept_invitation))
            .is_err());
        // A commit is not a Welcome.
        assert!(matches!(
            bob.tx(|db, s| join(db, s, &staged.commit, &accept_invitation)),
            Err(Error::Invalid(_))
        ));

        // The valid join still works afterwards, exactly once.
        let joined = bob
            .tx(|db, s| join(db, s, &welcome, &accept_invitation))
            .unwrap();
        assert_eq!(joined.epoch, 1);
        assert!(bob
            .tx(|db, s| join(db, s, &welcome, &accept_invitation))
            .is_err());

        // A Welcome addressed to bob is useless to someone else.
        let mut carol = Peer::new("carol-agent");
        carol.tx(key_package).unwrap();
        assert!(carol
            .tx(|db, s| join(db, s, &welcome, &accept_invitation))
            .is_err());
    }

    #[test]
    fn an_incoming_commit_is_merged_only_after_the_policy_accepts_it() {
        let (mut alice, mut bob) = pair();
        let mut carol = Peer::new("carol-agent");
        let package = carol.tx(key_package).unwrap();
        let staged = alice.tx(|db, s| stage_add(db, s, GROUP, &package)).unwrap();
        alice.tx(|db, _| merge_pending(db, GROUP)).unwrap();

        // The policy sees the exact change while the group is still at epoch 1.
        let seen = std::cell::RefCell::new(None);
        let refused = bob.tx(|db, _| {
            receive(db, GROUP, &staged.commit, &|change| {
                *seen.borrow_mut() = Some((change.clone(), group_info(db, GROUP)?.epoch));
                Err(Error::Verification(
                    "recipient expansion not authorized".into(),
                ))
            })
        });
        assert!(matches!(refused, Err(Error::Verification(m)) if m.contains("not authorized")));
        let (change, epoch_during_policy) = seen.into_inner().unwrap();
        assert_eq!(epoch_during_policy, 1);
        assert_eq!(change.base_epoch, 1);
        assert!(change.committer.same_identity(&alice.as_member()));
        assert_eq!(change.added.len(), 1);
        assert!(change.added[0].same_identity(&carol.as_member()));
        assert!(change.removed.is_empty());
        assert!(!change.removes_self);
        assert_eq!(
            names(&change.next_roster),
            ["alice-agent", "bob-agent", "carol-agent"]
        );

        // Nothing moved: bob is still at epoch 1 with two members.
        let unchanged = bob.info();
        assert_eq!(unchanged.epoch, 1);
        assert_eq!(names(&unchanged.roster), ["alice-agent", "bob-agent"]);

        // Accepting the same bytes later merges them.
        match bob
            .tx(|db, _| receive(db, GROUP, &staged.commit, &accept_change))
            .unwrap()
        {
            Received::Commit {
                change: merged,
                state,
            } => {
                assert_eq!(merged, change);
                assert_eq!(state.epoch, 2);
                assert_eq!(
                    names(&state.roster),
                    ["alice-agent", "bob-agent", "carol-agent"]
                );
                assert_eq!(state.roster, alice.info().roster);
            }
            Received::Application { .. } => panic!("commit expected"),
        }
        // The same commit cannot be applied twice.
        assert!(bob
            .tx(|db, _| receive(db, GROUP, &staged.commit, &accept_change))
            .is_err());

        let welcome = staged.welcome.unwrap();
        carol
            .tx(|db, s| join(db, s, &welcome, &accept_invitation))
            .unwrap();
        let sealed = carol
            .tx(|db, s| send(db, s, GROUP, b"hello from carol"))
            .unwrap();
        for peer in [&mut alice, &mut bob] {
            match peer
                .tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change))
                .unwrap()
            {
                Received::Application {
                    sender,
                    epoch,
                    plaintext,
                } => {
                    assert_eq!(sender.principal, "carol-agent");
                    assert_eq!(epoch, 2);
                    assert_eq!(plaintext.as_slice(), b"hello from carol");
                }
                Received::Commit { .. } => panic!("application message expected"),
            }
        }
    }

    #[test]
    fn a_pending_change_blocks_sends_and_other_commits_but_accepts_applications() {
        let (mut alice, mut bob) = pair();
        let mut carol = Peer::new("carol-agent");
        let mut dave = Peer::new("dave-agent");
        let carol_package = carol.tx(key_package).unwrap();
        let dave_package = dave.tx(key_package).unwrap();

        assert!(matches!(
            alice.tx(|db, _| merge_pending(db, GROUP)),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            alice.tx(|db, _| clear_pending(db, GROUP)),
            Err(Error::Conflict(_))
        ));

        let incoming = bob
            .tx(|db, s| send(db, s, GROUP, b"while pending"))
            .unwrap();
        alice
            .tx(|db, s| stage_add(db, s, GROUP, &carol_package))
            .unwrap();
        assert!(matches!(
            alice.tx(|db, s| send(db, s, GROUP, b"x")),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            alice.tx(|db, s| stage_add(db, s, GROUP, &dave_package)),
            Err(Error::Conflict(_))
        ));
        let bob_id = bob.signer.key_id().clone();
        assert!(matches!(
            alice.tx(|db, s| stage_remove(db, s, GROUP, "bob-agent", &bob_id)),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            alice.tx(|db, _| receive(db, GROUP, &incoming.ciphertext, &accept_change)),
            Ok(Received::Application { .. })
        ));
        assert!(alice.info().pending);
        let foreign = bob
            .tx(|db, s| stage_add(db, s, GROUP, &dave_package))
            .unwrap();
        assert!(matches!(
            alice.tx(|db, _| receive(db, GROUP, &foreign.commit, &accept_change)),
            Err(Error::Conflict(_))
        ));
        bob.tx(|db, _| clear_pending(db, GROUP)).unwrap();

        // Clearing returns to the base epoch; the group is usable again.
        let cleared = alice.tx(|db, _| clear_pending(db, GROUP)).unwrap();
        assert!(!cleared.pending);
        assert_eq!(cleared.epoch, 1);
        assert_eq!(names(&cleared.roster), ["alice-agent", "bob-agent"]);
        assert!(alice
            .tx(|db, _| receive(db, GROUP, &incoming.ciphertext, &accept_change))
            .is_err());
        let next = bob
            .tx(|db, s| send(db, s, GROUP, b"after pending"))
            .unwrap();
        assert!(alice
            .tx(|db, _| receive(db, GROUP, &next.ciphertext, &accept_change))
            .is_ok());
        assert!(alice.tx(|db, s| send(db, s, GROUP, b"x")).is_ok());
    }

    #[test]
    fn racing_membership_changes_converge_on_the_winner() {
        let (mut alice, mut bob) = pair();
        let mut carol = Peer::new("carol-agent");
        let mut dave = Peer::new("dave-agent");
        let carol_package = carol.tx(key_package).unwrap();
        let dave_package = dave.tx(key_package).unwrap();

        // Both stage a change on epoch 1. Transport orders alice first.
        let winner = alice
            .tx(|db, s| stage_add(db, s, GROUP, &carol_package))
            .unwrap();
        let loser = bob
            .tx(|db, s| stage_add(db, s, GROUP, &dave_package))
            .unwrap();
        assert_eq!(winner.base_epoch, loser.base_epoch);
        alice.tx(|db, _| merge_pending(db, GROUP)).unwrap();

        // bob establishes his rejection, clears, consumes the winner, rebuilds.
        bob.tx(|db, _| clear_pending(db, GROUP)).unwrap();
        bob.tx(|db, _| receive(db, GROUP, &winner.commit, &accept_change))
            .unwrap();
        // alice refuses the stale loser.
        assert!(alice
            .tx(|db, _| receive(db, GROUP, &loser.commit, &accept_change))
            .is_err());
        assert_eq!(alice.info().epoch, 2);

        let welcome = winner.welcome.unwrap();
        carol
            .tx(|db, s| join(db, s, &welcome, &accept_invitation))
            .unwrap();
        let retry = bob
            .tx(|db, s| stage_add(db, s, GROUP, &dave_package))
            .unwrap();
        assert_eq!(retry.base_epoch, 2);
        bob.tx(|db, _| merge_pending(db, GROUP)).unwrap();
        for peer in [&mut alice, &mut carol] {
            peer.tx(|db, _| receive(db, GROUP, &retry.commit, &accept_change))
                .unwrap();
        }
        let welcome = retry.welcome.unwrap();
        dave.tx(|db, s| join(db, s, &welcome, &accept_invitation))
            .unwrap();
        // The loser's first Welcome is useless.
        let stale = loser.welcome.unwrap();
        assert!(dave
            .tx(|db, s| join(db, s, &stale, &accept_invitation))
            .is_err());

        let expected = alice.info();
        assert_eq!(expected.epoch, 3);
        assert_eq!(
            names(&expected.roster),
            ["alice-agent", "bob-agent", "carol-agent", "dave-agent"]
        );
        for peer in [&mut bob, &mut carol, &mut dave] {
            let info = peer.info();
            assert_eq!((info.epoch, &info.roster), (3, &expected.roster));
        }
        // All four can read a message sent in the converged epoch.
        let sealed = dave.tx(|db, s| send(db, s, GROUP, b"converged")).unwrap();
        for peer in [&mut alice, &mut bob, &mut carol] {
            assert!(matches!(
                peer.tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change)),
                Ok(Received::Application { .. })
            ));
        }
    }

    #[test]
    fn a_removed_member_is_cut_off_from_the_new_epoch() {
        let (mut alice, mut bob) = pair();
        let mut carol = Peer::new("carol-agent");
        add(&mut alice, &mut [&mut bob], &mut carol);

        let alice_id = alice.signer.key_id().clone();
        let carol_id = carol.signer.key_id().clone();
        assert!(matches!(
            alice.tx(|db, s| stage_remove(db, s, GROUP, "alice-agent", &alice_id)),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            alice.tx(|db, s| stage_remove(db, s, GROUP, "nobody", &carol_id)),
            Err(Error::Invalid(_))
        ));
        // The principal and the key must both match.
        assert!(matches!(
            alice.tx(|db, s| stage_remove(db, s, GROUP, "bob-agent", &carol_id)),
            Err(Error::Invalid(_))
        ));

        let old = bob
            .tx(|db, s| send(db, s, GROUP, b"before removal"))
            .unwrap();
        let staged = alice
            .tx(|db, s| stage_remove(db, s, GROUP, "carol-agent", &carol_id))
            .unwrap();
        assert!(staged.welcome.is_none());
        assert_eq!(staged.removed[0].principal, "carol-agent");
        assert_eq!(names(&staged.next_roster), ["alice-agent", "bob-agent"]);
        alice.tx(|db, _| clear_pending(db, GROUP)).unwrap();
        alice
            .tx(|db, _| receive(db, GROUP, &old.ciphertext, &accept_change))
            .unwrap();
        let staged = alice
            .tx(|db, s| stage_remove(db, s, GROUP, "carol-agent", &carol_id))
            .unwrap();
        alice.tx(|db, _| merge_pending(db, GROUP)).unwrap();

        match bob
            .tx(|db, _| receive(db, GROUP, &staged.commit, &accept_change))
            .unwrap()
        {
            Received::Commit { change, state } => {
                assert!(!change.removes_self);
                assert_eq!(change.removed[0].principal, "carol-agent");
                assert_eq!(names(&state.roster), ["alice-agent", "bob-agent"]);
                assert!(state.active);
            }
            Received::Application { .. } => panic!("commit expected"),
        }
        // carol learns of her removal and becomes inactive.
        match carol
            .tx(|db, _| receive(db, GROUP, &staged.commit, &accept_change))
            .unwrap()
        {
            Received::Commit { change, state } => {
                assert!(change.removes_self);
                assert!(!state.active);
            }
            Received::Application { .. } => panic!("commit expected"),
        }
        assert!(matches!(
            carol.tx(|db, s| send(db, s, GROUP, b"x")),
            Err(Error::Conflict(_))
        ));

        // New-epoch traffic is unreadable to carol, readable to bob.
        let sealed = alice
            .tx(|db, s| send(db, s, GROUP, b"after removal"))
            .unwrap();
        assert!(carol
            .tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change))
            .is_err());
        assert!(matches!(
            bob.tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change)),
            Ok(Received::Application { .. })
        ));
    }

    #[test]
    fn tampered_replayed_and_misdirected_messages_are_refused() {
        let (mut alice, mut bob) = pair();
        let sealed = alice.tx(|db, s| send(db, s, GROUP, b"once")).unwrap();

        for position in [sealed.ciphertext.len() - 1, sealed.ciphertext.len() / 2] {
            let mut tampered = sealed.ciphertext.clone();
            tampered[position] ^= 0x01;
            assert!(bob
                .tx(|db, _| receive(db, GROUP, &tampered, &accept_change))
                .is_err());
        }
        // The failed attempts rolled back, so the genuine message still decrypts.
        assert!(bob
            .tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change))
            .is_ok());
        // Replay.
        assert!(matches!(
            bob.tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change)),
            Err(Error::Mls)
        ));
        // The sender cannot process its own message.
        assert!(alice
            .tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change))
            .is_err());

        // Malformed and oversized input, wrong kinds of message.
        let package = bob.tx(key_package).unwrap();
        for junk in [
            &b""[..],
            &b"junk"[..],
            &package[..],
            &vec![0u8; MAX_INPUT + 1][..],
        ] {
            assert!(matches!(
                bob.tx(|db, _| receive(db, GROUP, junk, &accept_change)),
                Err(Error::Invalid(_))
            ));
        }
        assert!(matches!(
            alice.tx(|db, s| send(db, s, GROUP, &vec![0u8; MAX_INPUT + 1])),
            Err(Error::Invalid(_))
        ));

        // Unknown group, and a message that belongs to another group.
        assert!(matches!(
            bob.tx(|db, _| receive(db, b"group-2", &sealed.ciphertext, &accept_change)),
            Err(Error::Invalid(_))
        ));
        alice.tx(|db, s| create(db, s, b"group-2")).unwrap();
        let other = alice
            .tx(|db, s| send(db, s, b"group-2", b"elsewhere"))
            .unwrap();
        assert!(matches!(
            bob.tx(|db, _| receive(db, GROUP, &other.ciphertext, &accept_change)),
            Err(Error::Invalid(_))
        ));
        for id in [&b""[..], &[7u8; 129][..]] {
            assert!(matches!(
                alice.tx(|db, s| create(db, s, id)),
                Err(Error::Invalid(_))
            ));
        }
    }

    /// A KeyPackage built directly with OpenMLS, outside this module's rules.
    fn foreign_key_package(suite: Ciphersuite, identity: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
        use openmls_basic_credential::SignatureKeyPair;
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        let keys = SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity(&keys.to_public_vec())).into(),
            signature_key: keys.to_public_vec().into(),
        };
        KeyPackage::builder()
            .build(suite, &provider, &keys, credential)
            .unwrap()
            .key_package()
            .tls_serialize_detached()
            .unwrap()
    }

    fn identity(project: &str, principal: &str, key_id: &str) -> Vec<u8> {
        let mut out = CREDENTIAL_PREFIX.to_vec();
        for part in [project, principal, key_id] {
            out.push(0);
            out.extend_from_slice(part.as_bytes());
        }
        out
    }

    fn id_of(public: &[u8]) -> String {
        wire_key(public).unwrap().key_id().as_str().to_owned()
    }

    #[test]
    fn key_packages_must_bind_project_principal_and_key() {
        let mut alice = Peer::new("alice-agent");
        alice.tx(|db, s| create(db, s, GROUP)).unwrap();
        let alice_id = alice.signer.key_id().as_str().to_owned();
        let mut refuse = |package: Vec<u8>| {
            let inspected = inspect_key_package("fixture", &package);
            let staged = alice.tx(|db, s| stage_add(db, s, GROUP, &package));
            assert!(
                matches!(inspected, Err(Error::Verification(_))),
                "inspect: {inspected:?}"
            );
            assert!(matches!(staged, Err(Error::Verification(_))));
        };

        // A well-formed foreign package is accepted (control).
        let good = foreign_key_package(SUITE, |k| identity("fixture", "mallory", &id_of(k)));
        assert_eq!(
            inspect_key_package("fixture", &good).unwrap().principal,
            "mallory"
        );

        // Plain label, as in the evaluation fixtures.
        refuse(foreign_key_package(SUITE, |_| b"bob-agent".to_vec()));
        // Another project.
        refuse(foreign_key_package(SUITE, |k| {
            identity("other", "mallory", &id_of(k))
        }));
        // Key id of someone else's key: claims alice's enrolled key.
        refuse(foreign_key_package(SUITE, |_| {
            identity("fixture", "alice-agent", &alice_id)
        }));
        // Bad principal, extra and missing fields, wrong prefix.
        refuse(foreign_key_package(SUITE, |k| {
            identity("fixture", "../mallory", &id_of(k))
        }));
        refuse(foreign_key_package(SUITE, |k| {
            let mut v = identity("fixture", "mallory", &id_of(k));
            v.extend_from_slice(b"\0admin");
            v
        }));
        refuse(foreign_key_package(SUITE, |_| {
            let mut v = CREDENTIAL_PREFIX.to_vec();
            v.extend_from_slice(b"\0fixture\0mallory");
            v
        }));
        refuse(foreign_key_package(SUITE, |k| {
            let mut v = b"agent-yhes/mls/v2".to_vec();
            v.extend_from_slice(
                &identity("fixture", "mallory", &id_of(k))[CREDENTIAL_PREFIX.len()..],
            );
            v
        }));
        // Another ciphersuite, even with a plausible credential.
        refuse(foreign_key_package(
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            |_| identity("fixture", "mallory", &alice_id),
        ));

        // A tampered package fails signature validation; junk is malformed.
        let mut tampered = good.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(inspect_key_package("fixture", &tampered).is_err());
        assert!(matches!(
            inspect_key_package("fixture", b"junk"),
            Err(Error::Invalid(_))
        ));
        // The verifier's project is part of the binding.
        assert!(matches!(
            inspect_key_package("other", &good),
            Err(Error::Verification(_))
        ));

        // Nothing was staged by any refusal; the same identity cannot be added twice.
        assert!(!alice.info().pending);
        let own = alice.tx(key_package).unwrap();
        assert!(matches!(
            alice.tx(|db, s| stage_add(db, s, GROUP, &own)),
            Err(Error::Conflict(_))
        ));
    }

    #[test]
    fn a_group_cannot_be_driven_with_another_identity() {
        let (mut alice, mut bob) = pair();
        // bob's signer against alice's stored group state.
        let package = bob.tx(key_package).unwrap();
        let foreign = &bob.signer;
        let result = alice.vault.transaction(|db| send(db, foreign, GROUP, b"x"));
        assert!(matches!(result, Err(Error::Verification(_))));
        let result = alice
            .vault
            .transaction(|db| stage_add(db, foreign, GROUP, &package));
        assert!(matches!(result, Err(Error::Verification(_))));
    }

    #[test]
    fn the_exact_key_package_is_exposed_so_a_swap_is_detectable() {
        let (mut alice, mut bob) = pair();
        let mut carol = Peer::new("carol-agent");
        // Two valid KeyPackages under the same agent signing key.
        let approved = carol.tx(key_package).unwrap();
        let swapped = carol.tx(key_package).unwrap();
        assert_ne!(approved, swapped);
        let first = inspect_key_package("fixture", &approved).unwrap();
        let second = inspect_key_package("fixture", &swapped).unwrap();
        // Identity alone cannot tell them apart.
        assert_eq!(first, second);
        let approved_digest = Digest::of(&approved);
        let swapped_digest = Digest::of(&swapped);
        assert_ne!(approved_digest, swapped_digest);

        // The committer stages the package that was not approved.
        let staged = alice.tx(|db, s| stage_add(db, s, GROUP, &swapped)).unwrap();
        alice.tx(|db, _| merge_pending(db, GROUP)).unwrap();

        // A policy that compares the digest with the approved one refuses it.
        let bind = |expected: Digest| {
            move |change: &Change| -> Result<()> {
                if change.added_key_package_digests != [expected] {
                    return Err(Error::Verification(
                        "KeyPackage differs from approval".into(),
                    ));
                }
                Ok(())
            }
        };
        let seen = std::cell::RefCell::new(None);
        let refused = bob.tx(|db, _| {
            receive(db, GROUP, &staged.commit, &|change| {
                *seen.borrow_mut() = Some(change.clone());
                bind(approved_digest)(change)
            })
        });
        assert!(matches!(refused, Err(Error::Verification(m)) if m.contains("differs")));
        let change = seen.into_inner().unwrap();
        assert_eq!(change.added.len(), 1);
        assert!(change.added[0].same_identity(&first));
        // The digest is over the exact bytes that were actually committed.
        assert_eq!(change.added_key_package_digests, [swapped_digest]);
        assert_eq!(bob.info().epoch, 1);
        // The same commit passes only against the digest of what it carries.
        assert!(bob
            .tx(|db, _| receive(db, GROUP, &staged.commit, &bind(swapped_digest)))
            .is_ok());

        // The joiner sees which of its own packages the Welcome consumed.
        let welcome = staged.welcome.unwrap();
        let join_bound = |expected: Digest| {
            move |invitation: &Invitation| -> Result<()> {
                if invitation.own_key_package_digest != expected {
                    return Err(Error::Verification(
                        "KeyPackage differs from approval".into(),
                    ));
                }
                Ok(())
            }
        };
        let refused = carol.tx(|db, s| join(db, s, &welcome, &join_bound(approved_digest)));
        assert!(matches!(refused, Err(Error::Verification(m)) if m.contains("differs")));
        assert!(matches!(
            carol.tx(|db, _| group_info(db, GROUP)),
            Err(Error::Invalid(_))
        ));
        let joined = carol
            .tx(|db, s| join(db, s, &welcome, &join_bound(swapped_digest)))
            .unwrap();
        assert_eq!(joined.epoch, 2);

        // Commits without adds expose no digests.
        let carol_id = carol.signer.key_id().clone();
        let removal = alice
            .tx(|db, s| stage_remove(db, s, GROUP, "carol-agent", &carol_id))
            .unwrap();
        alice.tx(|db, _| merge_pending(db, GROUP)).unwrap();
        match bob
            .tx(|db, _| receive(db, GROUP, &removal.commit, &accept_change))
            .unwrap()
        {
            Received::Commit { change, .. } => assert!(change.added_key_package_digests.is_empty()),
            Received::Application { .. } => panic!("commit expected"),
        }
    }

    // ---- messages this module never produces, made with OpenMLS directly ----

    /// Runs `action` on the peer's stored group with direct OpenMLS access,
    /// standing in for a non-conforming client. Commits the transaction.
    fn raw<T>(
        peer: &mut Peer,
        action: impl FnOnce(&Provider<'_>, &mut MlsGroup, &MlsSigner<'_>) -> T,
    ) -> T {
        let signer = &peer.signer;
        peer.vault
            .transaction(|db| {
                let provider = Provider::new(db);
                let mut group = load(&provider, GROUP)?;
                Ok(action(&provider, &mut group, &MlsSigner(signer)))
            })
            .unwrap()
    }

    fn bytes(message: &MlsMessageOut) -> Vec<u8> {
        message.tls_serialize_detached().unwrap()
    }

    /// The receiver must refuse `message` with a verification error and stay
    /// exactly where it was.
    fn assert_refused(receiver: &mut Peer, message: &[u8], reason: &str) {
        let before = receiver.info();
        let called = std::cell::Cell::new(false);
        let result = receiver.tx(|db, _| {
            receive(db, GROUP, message, &|_| {
                called.set(true);
                Ok(())
            })
        });
        match result {
            Err(Error::Verification(m)) => assert_eq!(m, reason),
            Err(other) => panic!("expected verification error {reason:?}, got {other:?}"),
            Ok(_) => panic!("expected refusal {reason:?}"),
        }
        assert!(
            !called.get(),
            "policy must not be consulted for an unsupported message"
        );
        assert_eq!(receiver.info(), before);
    }

    /// After a refusal the group still works once the sender drops its change.
    fn assert_still_usable(sender: &mut Peer, receiver: &mut Peer) {
        sender.tx(|db, _| clear_pending(db, GROUP)).unwrap();
        // The stand-in client may also have queued proposals of its own.
        raw(sender, |provider, group, _| {
            group.clear_pending_proposals(provider.storage()).unwrap()
        });
        let sealed = sender
            .tx(|db, s| send(db, s, GROUP, b"still works"))
            .unwrap();
        assert!(matches!(
            receiver.tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change)),
            Ok(Received::Application { .. })
        ));
    }

    #[test]
    fn a_commit_with_a_group_context_extensions_proposal_is_refused() {
        let (mut alice, mut bob) = pair();
        let commit = raw(&mut bob, |provider, group, signer| {
            let (commit, _, _) = group
                .update_group_context_extensions(provider, Extensions::empty(), signer)
                .unwrap();
            bytes(&commit)
        });
        assert_refused(&mut alice, &commit, "unsupported proposal");
        assert_still_usable(&mut bob, &mut alice);
    }

    #[test]
    fn a_commit_with_a_pre_shared_key_proposal_is_refused() {
        use openmls::schedule::{ExternalPsk, PreSharedKeyId, Psk};
        let (mut alice, mut bob) = pair();
        // Both sides hold the PSK, so only this module's rule stands in the way.
        let psk_id = raw(&mut bob, |provider, _, _| {
            let id = PreSharedKeyId::new(
                SUITE,
                provider.rand(),
                Psk::External(ExternalPsk::new(b"shared-out-of-band".to_vec())),
            )
            .unwrap();
            id.store(provider, &[9u8; 32]).unwrap();
            id
        });
        raw(&mut alice, |provider, _, _| {
            psk_id.store(provider, &[9u8; 32]).unwrap()
        });

        let commit = raw(&mut bob, |provider, group, signer| {
            group
                .propose_pre_shared_key_by_value(provider, signer, psk_id.clone())
                .unwrap();
            let (commit, _, _) = group.commit_to_pending_proposals(provider, signer).unwrap();
            bytes(&commit)
        });
        assert_refused(&mut alice, &commit, "unsupported proposal");
        assert_still_usable(&mut bob, &mut alice);
    }

    #[test]
    fn standalone_proposals_and_commits_that_reference_them_are_refused() {
        let (mut alice, mut bob) = pair();
        let mut carol = Peer::new("carol-agent");
        add(&mut alice, &mut [&mut bob], &mut carol);
        let mut dave = Peer::new("dave-agent");
        let dave_package = dave.tx(key_package).unwrap();

        // carol sends an Update proposal on its own. bob, standing in for a
        // client without this module's rules, stores it and commits it by
        // reference, so the commit really carries an Update proposal.
        let proposal = raw(&mut carol, |provider, group, signer| {
            let (proposal, _) = group
                .propose_self_update(provider, signer, LeafNodeParameters::default())
                .unwrap();
            bytes(&proposal)
        });
        let commit = raw(&mut bob, |provider, group, signer| {
            let message = MlsMessageIn::tls_deserialize_exact(proposal.as_slice())
                .unwrap()
                .try_into_protocol_message()
                .unwrap();
            let ProcessedMessageContent::ProposalMessage(queued) = group
                .process_message(provider, message)
                .unwrap()
                .into_content()
            else {
                panic!("proposal expected");
            };
            group
                .store_pending_proposal(provider.storage(), *queued)
                .unwrap();
            let (commit, _, _) = group.commit_to_pending_proposals(provider, signer).unwrap();
            bytes(&commit)
        });

        // alice refuses the proposal, so she never stores it...
        assert_refused(&mut alice, &proposal, "unsupported message");
        // ...and the commit that depends on it cannot be applied either.
        let before = alice.info();
        let called = std::cell::Cell::new(false);
        let result = alice.tx(|db, _| {
            receive(db, GROUP, &commit, &|_| {
                called.set(true);
                Ok(())
            })
        });
        assert!(
            matches!(result, Err(Error::Mls)),
            "commit by reference must fail"
        );
        assert!(!called.get());
        assert_eq!(alice.info(), before);

        // Even an Add, the supported change, is refused as a standalone proposal.
        bob.tx(|db, _| clear_pending(db, GROUP)).unwrap();
        raw(&mut bob, |provider, group, _| {
            group.clear_pending_proposals(provider.storage()).unwrap()
        });
        let proposal = raw(&mut bob, |provider, group, signer| {
            let package = validated_key_package(provider, &dave_package).unwrap();
            let (proposal, _) = group
                .propose_add_member(provider, signer, &package)
                .unwrap();
            bytes(&proposal)
        });
        assert_refused(&mut alice, &proposal, "unsupported message");

        // alice was never moved and still talks to the others.
        raw(&mut bob, |provider, group, _| {
            group.clear_pending_proposals(provider.storage()).unwrap()
        });
        let sealed = bob.tx(|db, s| send(db, s, GROUP, b"still works")).unwrap();
        assert!(matches!(
            alice.tx(|db, _| receive(db, GROUP, &sealed.ciphertext, &accept_change)),
            Ok(Received::Application { .. })
        ));
    }

    #[test]
    fn a_commit_may_refresh_the_committers_keys_but_not_its_identity() {
        use openmls_basic_credential::SignatureKeyPair;
        let (mut alice, mut bob) = pair();

        // Path-only self update with the same identity: an empty change.
        let commit = raw(&mut bob, |provider, group, signer| {
            let bundle = group
                .self_update(provider, signer, LeafNodeParameters::default())
                .unwrap();
            bytes(bundle.commit())
        });
        bob.tx(|db, _| merge_pending(db, GROUP)).unwrap();
        match alice
            .tx(|db, _| receive(db, GROUP, &commit, &accept_change))
            .unwrap()
        {
            Received::Commit { change, state } => {
                assert!(change.committer.same_identity(&bob.as_member()));
                assert!(change.added.is_empty() && change.removed.is_empty());
                assert_eq!(names(&change.next_roster), ["alice-agent", "bob-agent"]);
                assert_eq!(state.epoch, 2);
                assert_eq!(state.roster, bob.info().roster);
            }
            Received::Application { .. } => panic!("commit expected"),
        }

        // The committer swaps in a new signature key, with a credential that is
        // correctly bound to that new key: under its own name, and under alice's.
        for principal in ["bob-agent", "alice-agent"] {
            let commit = raw(&mut bob, |provider, group, signer| {
                let keys = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
                let credential_with_key = CredentialWithKey {
                    credential: BasicCredential::new(identity(
                        "fixture",
                        principal,
                        &id_of(&keys.to_public_vec()),
                    ))
                    .into(),
                    signature_key: keys.to_public_vec().into(),
                };
                let bundle = group
                    .self_update_with_new_signer(
                        provider,
                        signer,
                        NewSignerBundle {
                            signer: &keys,
                            credential_with_key,
                        },
                        LeafNodeParameters::default(),
                    )
                    .unwrap();
                bytes(bundle.commit())
            });
            assert_refused(
                &mut alice,
                &commit,
                "commit changes the committer's identity",
            );
            assert_still_usable(&mut bob, &mut alice);
        }

        // A new key with a credential that is not bound at all.
        let commit = raw(&mut bob, |provider, group, signer| {
            let keys = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
            let credential_with_key = CredentialWithKey {
                credential: BasicCredential::new(b"bob-agent".to_vec()).into(),
                signature_key: keys.to_public_vec().into(),
            };
            let bundle = group
                .self_update_with_new_signer(
                    provider,
                    signer,
                    NewSignerBundle {
                        signer: &keys,
                        credential_with_key,
                    },
                    LeafNodeParameters::default(),
                )
                .unwrap();
            bytes(bundle.commit())
        });
        assert_refused(
            &mut alice,
            &commit,
            "credential is not bound to its key and project",
        );
        assert_still_usable(&mut bob, &mut alice);
    }
}
