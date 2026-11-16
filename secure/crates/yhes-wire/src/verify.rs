//! Event verification: signature, identity derivation, grants, delegations,
//! relays and action authorizations.

use crate::envelope::Envelope;
use crate::error::Error;
use crate::event::{Body, Event, Kind};
use crate::keys::Digest;
use crate::registry::{GhesIdentity, ParticipantKind, Registry};
use crate::EVENT_PAYLOAD_TYPE;

/// Time limits, in seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// How far in the future `issued_at` may lie.
    pub max_clock_skew: u64,
    /// Longest validity of an ordinary event.
    pub max_event_lifetime: u64,
    /// Longest validity of a human session grant.
    pub max_session_lifetime: u64,
    /// Longest validity of an agent delegation.
    pub max_delegation_lifetime: u64,
    /// Longest validity of an action authorization.
    pub max_authorization_lifetime: u64,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            max_clock_skew: 120,
            max_event_lifetime: 7 * 24 * 3600,
            max_session_lifetime: 30 * 60,
            max_delegation_lifetime: 7 * 24 * 3600,
            max_authorization_lifetime: 5 * 60,
        }
    }
}

/// Envelopes of the events that the verified event refers to by digest.
#[derive(Debug, Clone, Copy, Default)]
pub struct Evidence<'a> {
    /// The session grant or delegation named by the event's `session`.
    pub grant: Option<&'a [u8]>,
    /// The action authorization named by an `action.execute` body.
    pub authorization: Option<&'a [u8]>,
    /// The session grant of a session-signed original inside a relay.
    pub original_grant: Option<&'a [u8]>,
}

/// How the event's audience must relate to the verifying party.
#[derive(Debug, Clone, Copy)]
pub enum AudienceCheck<'a> {
    /// The audience must contain this participant (normally the local one).
    Includes(&'a str),
    /// The audience must be exactly this set (for example the group roster).
    Exact(&'a [String]),
    /// No recipient check: for auditing records addressed to others.
    AuditOnly,
}

/// What the caller requires of the top-level event.
#[derive(Debug, Clone, Copy)]
pub struct Expectation<'a> {
    pub project: &'a str,
    pub audience: AudienceCheck<'a>,
    /// Must equal the event's `group`, including `None` for no group.
    pub group: Option<&'a str>,
}

/// Which kind of key signed an event. Derived by the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignerRole {
    /// A registry-enrolled human device key.
    HumanDevice,
    /// A session key admitted by a human device key's session grant.
    HumanSession,
    /// A registry-enrolled agent key acting under a delegation.
    Agent,
    /// A registry-enrolled service key.
    Service,
}

/// An event that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvent {
    event: Event,
    digest: Digest,
    payload: Vec<u8>,
    signer: SignerRole,
    author_kind: ParticipantKind,
    controller: Option<String>,
    ghes: Option<GhesIdentity>,
    grant: Option<Box<VerifiedEvent>>,
    authorization: Option<Box<VerifiedEvent>>,
    original: Option<Box<VerifiedEvent>>,
}

impl VerifiedEvent {
    pub fn event(&self) -> &Event {
        &self.event
    }

    /// SHA-256 of the exact payload bytes.
    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// The exact signed payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn signer(&self) -> SignerRole {
        self.signer
    }

    pub fn author_kind(&self) -> ParticipantKind {
        self.author_kind
    }

    /// The human controlling the authoring agent or service.
    pub fn controller(&self) -> Option<&str> {
        self.controller.as_deref()
    }

    /// The author's GHES identity, when the registry binds one.
    pub fn ghes(&self) -> Option<&GhesIdentity> {
        self.ghes.as_ref()
    }

    /// The verified session grant or delegation this event was signed under.
    pub fn grant(&self) -> Option<&VerifiedEvent> {
        self.grant.as_deref()
    }

    /// The verified human authorization of an `action.execute`.
    pub fn authorization(&self) -> Option<&VerifiedEvent> {
        self.authorization.as_deref()
    }

    /// The verified human original carried by an `agent.relay`.
    pub fn original(&self) -> Option<&VerifiedEvent> {
        self.original.as_deref()
    }

    /// True only for events signed by a human device or human session key.
    /// A relay is agent-authored; its `original()` is the human-authored part.
    pub fn is_human_authored(&self) -> bool {
        matches!(
            self.signer,
            SignerRole::HumanDevice | SignerRole::HumanSession
        )
    }
}

#[derive(Clone, Copy)]
enum Mode {
    /// The event being accepted now.
    Top,
    /// Evidence must cover the dependent's claimed issue time and remain current.
    Evidence { used_at: u64 },
    /// The human original inside a relay.
    Original,
}

/// Verifies events against one verified registry.
#[derive(Debug, Clone)]
pub struct Verifier<'a> {
    registry: &'a Registry,
    policy: Policy,
}

impl<'a> Verifier<'a> {
    pub fn new(registry: &'a Registry, policy: Policy) -> Verifier<'a> {
        Verifier { registry, policy }
    }

    /// Verifies one event envelope at time `now` (Unix seconds).
    pub fn verify_event(
        &self,
        envelope: &[u8],
        evidence: &Evidence<'_>,
        expect: &Expectation<'_>,
        now: u64,
    ) -> Result<VerifiedEvent, Error> {
        self.registry.check_current(now)?;
        if expect.project != self.registry.project() {
            return Err(Error::WrongProject);
        }
        let envelope = Envelope::parse(envelope, EVENT_PAYLOAD_TYPE)?;
        let verified = self.verify_envelope(&envelope, evidence, Mode::Top, now)?;

        let audience = &verified.event.audience;
        let audience_ok = match expect.audience {
            AudienceCheck::Includes(id) => audience.iter().any(|a| a == id),
            AudienceCheck::Exact(ids) => {
                let mut wanted: Vec<&str> = ids.iter().map(String::as_str).collect();
                wanted.sort_unstable();
                wanted.dedup();
                wanted.len() == ids.len()
                    && wanted
                        .iter()
                        .copied()
                        .eq(audience.iter().map(String::as_str))
            }
            AudienceCheck::AuditOnly => true,
        };
        if !audience_ok {
            return Err(Error::WrongAudience);
        }
        if verified.event.group.as_deref() != expect.group {
            return Err(Error::WrongGroup);
        }
        Ok(verified)
    }

    fn verify_envelope(
        &self,
        envelope: &Envelope,
        evidence: &Evidence<'_>,
        mode: Mode,
        now: u64,
    ) -> Result<VerifiedEvent, Error> {
        let registry = self.registry;
        let [sig] = envelope.signatures() else {
            return Err(Error::SignatureCount);
        };
        let event = Event::parse(envelope.payload())?;
        let kind = event.kind();

        if matches!(mode, Mode::Original) && kind != Kind::HumanStatement {
            return Err(Error::RelayInvalid("original is not a human statement"));
        }
        if event.project != registry.project() {
            return Err(Error::WrongProject);
        }
        if sig.key_id != event.key_id {
            return Err(Error::KeyIdMismatch);
        }

        // Evidence must be present exactly when the event refers to it.
        match (event.session.is_some(), evidence.grant.is_some()) {
            (true, false) => return Err(Error::EvidenceRequired("grant")),
            (false, true) => return Err(Error::UnexpectedEvidence("grant")),
            _ => {}
        }
        match (
            kind == Kind::ActionExecute,
            evidence.authorization.is_some(),
        ) {
            (true, false) => return Err(Error::EvidenceRequired("authorization")),
            (false, true) => return Err(Error::UnexpectedEvidence("authorization")),
            _ => {}
        }
        if kind != Kind::AgentRelay && evidence.original_grant.is_some() {
            return Err(Error::UnexpectedEvidence("original_grant"));
        }

        // Time bounds.
        if event.expires_at < event.issued_at {
            return Err(Error::InvalidTimeRange);
        }
        if event.issued_at > now.saturating_add(self.policy.max_clock_skew) {
            return Err(Error::NotYetValid);
        }
        match mode {
            Mode::Top | Mode::Original => {
                if now > event.expires_at {
                    return Err(Error::Expired);
                }
            }
            Mode::Evidence { used_at } => {
                if used_at < event.issued_at || used_at > event.expires_at {
                    return Err(Error::OutsideGrantWindow);
                }
                // A sender controls its issued_at. It cannot establish that a
                // delegated signature was made before the grant expired.
                // Historical acceptance must come from the durable core, not
                // a backdated fresh submission to this stateless verifier.
                if now > event.expires_at {
                    return Err(Error::Expired);
                }
            }
        }
        let max_lifetime = match kind {
            Kind::SessionGrant => self.policy.max_session_lifetime,
            Kind::AgentDelegation => self.policy.max_delegation_lifetime,
            Kind::ActionAuthorization => self.policy.max_authorization_lifetime,
            _ => self.policy.max_event_lifetime,
        };
        if event.expires_at - event.issued_at > max_lifetime {
            return Err(Error::LifetimeTooLong);
        }

        // Resolve the signing key and derive the signer's role.
        if registry.is_revoked(&event.key_id) {
            return Err(Error::KeyRevoked);
        }
        let mut grant: Option<VerifiedEvent> = None;
        let (key, role) = if let Some(entry) = registry.key(&event.key_id) {
            if entry.participant != event.author {
                return Err(Error::AuthorMismatch);
            }
            if event.issued_at < entry.not_before {
                return Err(Error::KeyNotYetValid);
            }
            if event.issued_at > entry.not_after || now > entry.not_after {
                return Err(Error::KeyExpired);
            }
            let role = match self.participant_kind(&event.author)? {
                ParticipantKind::Human => SignerRole::HumanDevice,
                ParticipantKind::Agent => SignerRole::Agent,
                ParticipantKind::Service => SignerRole::Service,
            };
            (entry.key.clone(), role)
        } else if let Some(session) = event.session {
            // Not enrolled: only a session key admitted by a human grant qualifies.
            let g =
                self.verify_reference(evidence.grant, session, "grant", event.issued_at, now)?;
            let Body::SessionGrant { session_key, .. } = &g.event.body else {
                return Err(Error::UnknownKey);
            };
            if session_key.key_id() != event.key_id {
                return Err(Error::EvidenceMismatch("session key"));
            }
            if g.event.author != event.author {
                return Err(Error::AuthorMismatch);
            }
            let key = session_key.clone();
            grant = Some(g);
            (key, SignerRole::HumanSession)
        } else {
            return Err(Error::UnknownKey);
        };

        if sig.algorithm != key.algorithm() {
            return Err(Error::AlgorithmMismatch);
        }
        key.verify(&envelope.signing_input(), &sig.signature)?;

        // Which signer may issue which kind.
        let permitted = match kind {
            Kind::HumanStatement => {
                matches!(role, SignerRole::HumanDevice | SignerRole::HumanSession)
            }
            Kind::SessionGrant | Kind::AgentDelegation | Kind::ActionAuthorization => {
                role == SignerRole::HumanDevice
            }
            Kind::AgentMessage | Kind::AgentRelay => role == SignerRole::Agent,
            Kind::ActionExecute => matches!(role, SignerRole::Agent | SignerRole::HumanDevice),
            Kind::ServiceNotice => role == SignerRole::Service,
            Kind::TicketAction => role == SignerRole::Agent,
        };
        if !permitted {
            return Err(Error::KindNotPermitted(kind.as_str()));
        }

        for member in &event.audience {
            if registry.participant(member).is_none() {
                return Err(Error::UnknownParticipant);
            }
        }

        // Scope of the grant the key signs under.
        match role {
            SignerRole::HumanDevice | SignerRole::Service => {
                if event.session.is_some() {
                    return Err(Error::SessionNotAllowed);
                }
            }
            SignerRole::HumanSession => {
                let g = grant.as_ref().ok_or(Error::EvidenceRequired("grant"))?;
                let Body::SessionGrant { purposes, .. } = &g.event.body else {
                    return Err(Error::EvidenceMismatch("grant is not a session grant"));
                };
                check_scope(&event, &g.event, purposes)?;
            }
            SignerRole::Agent => {
                let session = event.session.ok_or(Error::EvidenceRequired("delegation"))?;
                let g =
                    self.verify_reference(evidence.grant, session, "grant", event.issued_at, now)?;
                let Body::AgentDelegation {
                    agent,
                    agent_key_id,
                    purposes,
                } = &g.event.body
                else {
                    return Err(Error::EvidenceMismatch("grant is not a delegation"));
                };
                if *agent != event.author || *agent_key_id != event.key_id {
                    return Err(Error::EvidenceMismatch(
                        "delegation names another agent key",
                    ));
                }
                check_scope(&event, &g.event, purposes)?;
                grant = Some(g);
            }
        }

        // Kind-specific rules.
        let mut authorization: Option<VerifiedEvent> = None;
        let mut original: Option<VerifiedEvent> = None;
        match &event.body {
            Body::HumanStatement { .. }
            | Body::AgentMessage { .. }
            | Body::ServiceNotice { .. }
            | Body::TicketAction { .. } => {}
            Body::SessionGrant {
                session_key,
                purposes,
            } => {
                if purposes.as_slice() != [Kind::HumanStatement] {
                    return Err(Error::InvalidGrant(
                        "a session may only issue human.statement",
                    ));
                }
                let id = session_key.key_id();
                if registry.key(&id).is_some() || registry.is_revoked(&id) {
                    return Err(Error::InvalidGrant(
                        "session key is an enrolled or revoked key",
                    ));
                }
            }
            Body::AgentDelegation {
                agent,
                agent_key_id,
                purposes,
            } => {
                let p = registry
                    .participant(agent)
                    .ok_or(Error::UnknownParticipant)?;
                if p.kind != ParticipantKind::Agent
                    || p.controller.as_deref() != Some(event.author.as_str())
                {
                    return Err(Error::InvalidGrant("agent is not controlled by the issuer"));
                }
                if registry.is_revoked(agent_key_id) {
                    return Err(Error::KeyRevoked);
                }
                if registry
                    .key(agent_key_id)
                    .is_none_or(|k| k.participant != *agent)
                {
                    return Err(Error::InvalidGrant("key is not enrolled for the agent"));
                }
                let allowed = [
                    Kind::AgentMessage,
                    Kind::AgentRelay,
                    Kind::ActionExecute,
                    Kind::TicketAction,
                ];
                if !purposes.iter().all(|k| allowed.contains(k)) {
                    return Err(Error::InvalidGrant("purpose cannot be delegated"));
                }
            }
            Body::ActionAuthorization { performer, .. } => {
                let p = registry
                    .participant(performer)
                    .ok_or(Error::UnknownParticipant)?;
                let own_agent = p.kind == ParticipantKind::Agent
                    && p.controller.as_deref() == Some(event.author.as_str());
                if *performer != event.author && !own_agent {
                    return Err(Error::InvalidGrant(
                        "performer is not the issuer or their agent",
                    ));
                }
            }
            Body::AgentRelay {
                original: inner, ..
            } => {
                let inner_evidence = Evidence {
                    grant: evidence.original_grant,
                    ..Evidence::default()
                };
                let o = self.verify_envelope(inner, &inner_evidence, Mode::Original, now)?;
                if !is_subset(&event.audience, &o.event.audience) {
                    return Err(Error::RelayInvalid("audience is wider than the original's"));
                }
                let relayer = registry
                    .participant(&event.author)
                    .ok_or(Error::UnknownParticipant)?;
                let was_recipient = o.event.audience.contains(&event.author)
                    || relayer.controller.as_deref() == Some(o.event.author.as_str());
                if !was_recipient {
                    return Err(Error::RelayInvalid(
                        "relayer was not a recipient of the original",
                    ));
                }
                original = Some(o);
            }
            Body::ActionExecute {
                action,
                request_digest,
                authorization: reference,
            } => {
                let a = self.verify_reference(
                    evidence.authorization,
                    *reference,
                    "authorization",
                    event.issued_at,
                    now,
                )?;
                let Body::ActionAuthorization {
                    action: approved_action,
                    request_digest: approved_digest,
                    performer,
                } = &a.event.body
                else {
                    return Err(Error::EvidenceMismatch("not an action authorization"));
                };
                if approved_action != action {
                    return Err(Error::AuthorizationMismatch("action"));
                }
                if approved_digest != request_digest {
                    return Err(Error::AuthorizationMismatch("request digest"));
                }
                if *performer != event.author {
                    return Err(Error::AuthorizationMismatch("performer"));
                }
                if a.event.audience != event.audience {
                    return Err(Error::AuthorizationMismatch("audience"));
                }
                if a.event.group != event.group || a.event.epoch != event.epoch {
                    return Err(Error::AuthorizationMismatch("group or epoch"));
                }
                authorization = Some(a);
            }
        }

        let participant = registry
            .participant(&event.author)
            .ok_or(Error::UnknownParticipant)?;
        Ok(VerifiedEvent {
            digest: envelope.digest(),
            payload: envelope.payload().to_vec(),
            signer: role,
            author_kind: participant.kind,
            controller: participant.controller.clone(),
            ghes: participant.ghes.clone(),
            grant: grant.map(Box::new),
            authorization: authorization.map(Box::new),
            original: original.map(Box::new),
            event,
        })
    }

    /// Verifies evidence covering `used_at` and still current at `now`.
    fn verify_reference(
        &self,
        bytes: Option<&[u8]>,
        expected: Digest,
        what: &'static str,
        used_at: u64,
        now: u64,
    ) -> Result<VerifiedEvent, Error> {
        let bytes = bytes.ok_or(Error::EvidenceRequired(what))?;
        let envelope = Envelope::parse(bytes, EVENT_PAYLOAD_TYPE)?;
        if envelope.digest() != expected {
            return Err(Error::EvidenceMismatch(what));
        }
        let verified = self.verify_envelope(
            &envelope,
            &Evidence::default(),
            Mode::Evidence { used_at },
            now,
        )?;
        // Only device-signed grant kinds may serve as evidence.
        match verified.event.kind() {
            Kind::SessionGrant | Kind::AgentDelegation | Kind::ActionAuthorization => Ok(verified),
            _ => Err(Error::EvidenceMismatch(what)),
        }
    }

    fn participant_kind(&self, id: &str) -> Result<ParticipantKind, Error> {
        self.registry
            .participant(id)
            .map(|p| p.kind)
            .ok_or(Error::UnknownParticipant)
    }
}

/// An event may not leave the purpose, audience or group of its grant.
fn check_scope(event: &Event, grant: &Event, purposes: &[Kind]) -> Result<(), Error> {
    if !purposes.contains(&event.kind()) {
        return Err(Error::ScopeEscalation("purpose"));
    }
    if !is_subset(&event.audience, &grant.audience) {
        return Err(Error::ScopeEscalation("audience"));
    }
    if event.group != grant.group {
        return Err(Error::ScopeEscalation("group"));
    }
    Ok(())
}

fn is_subset(inner: &[String], outer: &[String]) -> bool {
    inner.iter().all(|x| outer.binary_search(x).is_ok())
}
