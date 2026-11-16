//! The authority-signed registry: participants, their keys, controllers and
//! revocations. It is the only source of human/agent/service classification.

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::envelope::Envelope;
use crate::error::Error;
use crate::json::{self, check_id, Fields};
use crate::keys::{Algorithm, Digest, KeyId, PublicKey};
use crate::verify::Policy;
use crate::{MAX_ENVELOPE_BYTES, MAX_SIGNATURES, REGISTRY_PAYLOAD_TYPE};

/// Explicitly pinned authority keys for one project.
#[derive(Debug, Clone)]
pub struct TrustAnchors {
    project: String,
    authorities: BTreeMap<KeyId, PublicKey>,
    threshold: usize,
}

impl TrustAnchors {
    /// `threshold` distinct authorities must sign every registry.
    pub fn new(
        project: &str,
        authorities: Vec<PublicKey>,
        threshold: usize,
    ) -> Result<TrustAnchors, Error> {
        check_id(project, "project")?;
        if authorities.is_empty() || authorities.len() > MAX_SIGNATURES {
            return Err(Error::InvalidAnchors("authority count"));
        }
        if threshold == 0 || threshold > authorities.len() {
            return Err(Error::InvalidAnchors("threshold"));
        }
        let mut map = BTreeMap::new();
        for key in authorities {
            if map.insert(key.key_id(), key).is_some() {
                return Err(Error::InvalidAnchors("duplicate authority"));
            }
        }
        Ok(TrustAnchors {
            project: project.to_owned(),
            authorities: map,
            threshold,
        })
    }
}

/// What a participant is. Derived from the registry, never from an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParticipantKind {
    Human,
    Agent,
    Service,
}

/// A GHES account: enterprise instance host and immutable user id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GhesIdentity {
    pub instance: String,
    pub user_id: u64,
}

/// A registry participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    pub id: String,
    pub kind: ParticipantKind,
    /// The human who controls an agent (required) or a service (optional).
    pub controller: Option<String>,
    /// Required for humans, optional for services, absent for agents.
    pub ghes: Option<GhesIdentity>,
}

#[derive(Debug, Clone)]
pub(crate) struct RegistryKey {
    pub(crate) key: PublicKey,
    pub(crate) participant: String,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
}

/// A verified registry generation.
#[derive(Debug, Clone)]
pub struct Registry {
    project: String,
    generation: u64,
    digest: Digest,
    issued_at: u64,
    expires_at: u64,
    participants: BTreeMap<String, Participant>,
    keys: BTreeMap<KeyId, RegistryKey>,
    revoked: BTreeSet<KeyId>,
}

/// The last accepted registry generation, kept to refuse rollback and forks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryCheckpoint {
    project: String,
    generation: u64,
    digest: Digest,
    revoked: BTreeSet<KeyId>,
}

impl RegistryCheckpoint {
    /// Checks authority signatures, schema and the generation chain, but not
    /// the clock. Use it to replay older generations in order, or to rebuild
    /// the checkpoint from stored envelope bytes.
    pub fn advance(
        envelope: &[u8],
        anchors: &TrustAnchors,
        prior: Option<&RegistryCheckpoint>,
    ) -> Result<RegistryCheckpoint, Error> {
        Ok(authenticate(envelope, anchors, prior)?.checkpoint())
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }
}

impl Registry {
    /// Verifies a registry envelope against pinned authorities, the prior
    /// checkpoint and the clock.
    pub fn verify(
        envelope: &[u8],
        anchors: &TrustAnchors,
        prior: Option<&RegistryCheckpoint>,
        policy: &Policy,
        now: u64,
    ) -> Result<Registry, Error> {
        let registry = authenticate(envelope, anchors, prior)?;
        if registry.issued_at > now.saturating_add(policy.max_clock_skew) {
            return Err(Error::RegistryNotYetValid);
        }
        registry.check_current(now)?;
        Ok(registry)
    }

    pub(crate) fn check_current(&self, now: u64) -> Result<(), Error> {
        if now > self.expires_at {
            return Err(Error::RegistryExpired);
        }
        Ok(())
    }

    pub fn project(&self) -> &str {
        &self.project
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// SHA-256 of the exact registry payload bytes.
    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn participant(&self, id: &str) -> Option<&Participant> {
        self.participants.get(id)
    }

    pub fn participants(&self) -> impl Iterator<Item = &Participant> {
        self.participants.values()
    }

    pub fn is_revoked(&self, key_id: &KeyId) -> bool {
        self.revoked.contains(key_id)
    }

    /// The enrolled public key `key_id` of `participant`, if it is usable at
    /// `now`: the registry is unexpired, the key is not revoked, it belongs
    /// to that participant, and `now` lies in its validity period.
    pub fn active_key(
        &self,
        participant: &str,
        key_id: &KeyId,
        now: u64,
    ) -> Result<PublicKey, Error> {
        self.check_current(now)?;
        if !self.participants.contains_key(participant) {
            return Err(Error::UnknownParticipant);
        }
        if self.revoked.contains(key_id) {
            return Err(Error::KeyRevoked);
        }
        let entry = self.keys.get(key_id).ok_or(Error::UnknownKey)?;
        if entry.participant != participant {
            return Err(Error::AuthorMismatch);
        }
        if now < entry.not_before {
            return Err(Error::KeyNotYetValid);
        }
        if now > entry.not_after {
            return Err(Error::KeyExpired);
        }
        Ok(entry.key.clone())
    }

    pub fn checkpoint(&self) -> RegistryCheckpoint {
        RegistryCheckpoint {
            project: self.project.clone(),
            generation: self.generation,
            digest: self.digest,
            revoked: self.revoked.clone(),
        }
    }

    pub(crate) fn key(&self, key_id: &KeyId) -> Option<&RegistryKey> {
        self.keys.get(key_id)
    }
}

fn authenticate(
    bytes: &[u8],
    anchors: &TrustAnchors,
    prior: Option<&RegistryCheckpoint>,
) -> Result<Registry, Error> {
    let envelope = Envelope::parse(bytes, REGISTRY_PAYLOAD_TYPE)?;

    // Every signature must come from a distinct pinned authority and verify.
    let input = envelope.signing_input();
    for sig in envelope.signatures() {
        let key = anchors
            .authorities
            .get(&sig.key_id)
            .ok_or(Error::UntrustedAuthority)?;
        if key.algorithm() != sig.algorithm {
            return Err(Error::AlgorithmMismatch);
        }
        key.verify(&input, &sig.signature)?;
    }
    if envelope.signatures().len() < anchors.threshold {
        return Err(Error::ThresholdNotMet);
    }

    let (registry, previous) = parse(envelope.payload())?;
    if registry.project != anchors.project {
        return Err(Error::WrongProject);
    }

    if let Some(prior) = prior {
        if prior.project != registry.project {
            return Err(Error::WrongProject);
        }
        if registry.generation < prior.generation {
            return Err(Error::RegistryRollback);
        }
        if registry.generation == prior.generation {
            if registry.digest != prior.digest {
                return Err(Error::RegistryFork);
            }
        } else {
            if registry.generation != prior.generation + 1 {
                return Err(Error::RegistryGap);
            }
            if previous != Some(prior.digest) {
                return Err(Error::RegistryChain);
            }
        }
        if !prior.revoked.is_subset(&registry.revoked) {
            return Err(Error::RevocationDropped);
        }
    }
    Ok(registry)
}

fn parse(payload: &[u8]) -> Result<(Registry, Option<Digest>), Error> {
    let mut f = Fields::new(json::parse(payload, MAX_ENVELOPE_BYTES)?)?;
    if f.int("version")? != 1 {
        return Err(Error::UnsupportedVersion);
    }
    let project = f.id("project")?;
    let generation = f.int("generation")?;
    let previous = f
        .opt_string("previous")?
        .map(|s| Digest::from_hex(&s))
        .transpose()?;
    let issued_at = f.timestamp("issued_at")?;
    let expires_at = f.timestamp("expires_at")?;
    let participant_values = f.array("participants")?;
    let key_values = f.array("keys")?;
    let revocation_values = f.array("revocations")?;
    f.finish()?;

    if generation == 0 || generation == u64::MAX {
        return Err(Error::Schema("generation out of range"));
    }
    if (generation == 1) != previous.is_none() {
        return Err(Error::Schema("previous digest does not fit the generation"));
    }
    if expires_at < issued_at {
        return Err(Error::InvalidTimeRange);
    }

    let mut participants: BTreeMap<String, Participant> = BTreeMap::new();
    let mut last_id: Option<String> = None;
    for value in participant_values {
        let mut p = Fields::new(value)?;
        let id = p.id("id")?;
        let kind = match p.string("kind")?.as_str() {
            "human" => ParticipantKind::Human,
            "agent" => ParticipantKind::Agent,
            "service" => ParticipantKind::Service,
            _ => return Err(Error::Schema("unknown participant kind")),
        };
        let controller = p.opt_id("controller")?;
        let ghes = match p.take("ghes")? {
            json::Value::Null => None,
            value => {
                let mut g = Fields::new(value)?;
                let instance = g.string("instance")?;
                let user_id = g.int("user_id")?;
                g.finish()?;
                check_host(&instance)?;
                if user_id == 0 {
                    return Err(Error::Schema("GHES user id is zero"));
                }
                Some(GhesIdentity { instance, user_id })
            }
        };
        p.finish()?;
        if last_id.as_ref().is_some_and(|prev| *prev >= id) {
            return Err(Error::Schema("list is not sorted and unique"));
        }
        last_id = Some(id.clone());
        participants.insert(
            id.clone(),
            Participant {
                id,
                kind,
                controller,
                ghes,
            },
        );
    }

    // Controller and identity rules.
    let mut accounts = BTreeSet::new();
    for p in participants.values() {
        let controller_is_human = |c: &String| {
            participants
                .get(c)
                .is_some_and(|other| other.kind == ParticipantKind::Human)
        };
        match p.kind {
            ParticipantKind::Human => {
                if p.controller.is_some() {
                    return Err(Error::Schema("a human has a controller"));
                }
                if let Some(ghes) = &p.ghes {
                    if !accounts.insert(ghes.clone()) {
                        return Err(Error::Schema("GHES identity is bound twice"));
                    }
                }
            }
            ParticipantKind::Agent => {
                if !p.controller.as_ref().is_some_and(controller_is_human) {
                    return Err(Error::Schema("an agent lacks a human controller"));
                }
                if p.ghes.is_some() {
                    return Err(Error::Schema("an agent has a GHES identity"));
                }
            }
            ParticipantKind::Service => {
                if !p.controller.as_ref().is_none_or(controller_is_human) {
                    return Err(Error::Schema("a service controller is not a human"));
                }
                if let Some(ghes) = &p.ghes {
                    if !accounts.insert(ghes.clone()) {
                        return Err(Error::Schema("GHES identity is bound twice"));
                    }
                }
            }
        }
    }

    let mut keys: BTreeMap<KeyId, RegistryKey> = BTreeMap::new();
    let mut last_key: Option<KeyId> = None;
    for value in key_values {
        let mut k = Fields::new(value)?;
        let key_id = KeyId::parse(&k.string("key_id")?)?;
        let participant = k.id("participant")?;
        let algorithm = Algorithm::parse(&k.string("algorithm")?)?;
        let raw = STANDARD
            .decode(k.string("public_key")?.as_bytes())
            .map_err(|_| Error::Malformed("public key is not canonical base64"))?;
        let not_before = k.timestamp("not_before")?;
        let not_after = k.timestamp("not_after")?;
        k.finish()?;

        let key = PublicKey::new(algorithm, &raw)?;
        if key.key_id() != key_id {
            return Err(Error::KeyIdMismatch);
        }
        if !participants.contains_key(&participant) {
            return Err(Error::UnknownParticipant);
        }
        if not_after < not_before {
            return Err(Error::InvalidTimeRange);
        }
        if last_key.as_ref().is_some_and(|prev| *prev >= key_id) {
            return Err(Error::Schema("list is not sorted and unique"));
        }
        last_key = Some(key_id.clone());
        keys.insert(
            key_id,
            RegistryKey {
                key,
                participant,
                not_before,
                not_after,
            },
        );
    }

    let mut revoked = BTreeSet::new();
    let mut last_revoked: Option<KeyId> = None;
    for value in revocation_values {
        let mut r = Fields::new(value)?;
        let key_id = KeyId::parse(&r.string("key_id")?)?;
        r.timestamp("revoked_at")?;
        r.finish()?;
        if last_revoked.as_ref().is_some_and(|prev| *prev >= key_id) {
            return Err(Error::Schema("list is not sorted and unique"));
        }
        last_revoked = Some(key_id.clone());
        revoked.insert(key_id);
    }

    let registry = Registry {
        project,
        generation,
        digest: Digest::of(payload),
        issued_at,
        expires_at,
        participants,
        keys,
        revoked,
    };
    Ok((registry, previous))
}

/// Lowercase DNS host name; never dereferenced.
fn check_host(s: &str) -> Result<(), Error> {
    let ok = !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        });
    if ok {
        Ok(())
    } else {
        Err(Error::Schema("GHES instance is not a lowercase host name"))
    }
}
