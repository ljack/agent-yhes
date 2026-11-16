//! Event payload schema. Parsing checks shape only; it establishes no trust.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::json;

use crate::envelope::Envelope;
use crate::error::Error;
use crate::json::{self, sorted_ids, Fields, Value};
use crate::keys::{Algorithm, Digest, KeyId, PublicKey};
use crate::{EVENT_PAYLOAD_TYPE, MAX_AUDIENCE, MAX_ENVELOPE_BYTES, MAX_TEXT_BYTES};

/// Event kinds of version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    HumanStatement,
    SessionGrant,
    AgentDelegation,
    AgentMessage,
    AgentRelay,
    ActionAuthorization,
    ActionExecute,
    ServiceNotice,
    TicketAction,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::HumanStatement => "human.statement",
            Kind::SessionGrant => "session.grant",
            Kind::AgentDelegation => "agent.delegation",
            Kind::AgentMessage => "agent.message",
            Kind::AgentRelay => "agent.relay",
            Kind::ActionAuthorization => "action.authorization",
            Kind::ActionExecute => "action.execute",
            Kind::ServiceNotice => "service.notice",
            Kind::TicketAction => "ticket.action",
        }
    }

    pub fn parse(s: &str) -> Result<Kind, Error> {
        Ok(match s {
            "human.statement" => Kind::HumanStatement,
            "session.grant" => Kind::SessionGrant,
            "agent.delegation" => Kind::AgentDelegation,
            "agent.message" => Kind::AgentMessage,
            "agent.relay" => Kind::AgentRelay,
            "action.authorization" => Kind::ActionAuthorization,
            "action.execute" => Kind::ActionExecute,
            "service.notice" => Kind::ServiceNotice,
            "ticket.action" => Kind::TicketAction,
            _ => return Err(Error::Schema("unknown event kind")),
        })
    }
}

/// The routine ticket actions a `ticket.action` event may name. Anything
/// else, including `ticket.recover`, needs `action.execute` with a fresh
/// human authorization.
pub const TICKET_ACTIONS: [&str; 6] = [
    "ticket.create",
    "ticket.claim",
    "ticket.release",
    "ticket.update",
    "ticket.complete",
    "ticket.cancel",
];

/// Kind-specific content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    HumanStatement {
        text: String,
    },
    /// A human device key admits a short-lived session key.
    SessionGrant {
        session_key: PublicKey,
        purposes: Vec<Kind>,
    },
    /// A human device key scopes what one enrolled agent key may issue.
    AgentDelegation {
        agent: String,
        agent_key_id: KeyId,
        purposes: Vec<Kind>,
    },
    AgentMessage {
        text: String,
    },
    /// The original human envelope, unchanged, plus an agent-authored note.
    AgentRelay {
        original: Envelope,
        note: Option<String>,
    },
    /// A fresh human approval of one exact action by one performer.
    ActionAuthorization {
        action: String,
        request_digest: Digest,
        performer: String,
    },
    ActionExecute {
        action: String,
        request_digest: Digest,
        authorization: Digest,
    },
    /// A routine ticket action by a delegated agent. `action` is one of
    /// [`TICKET_ACTIONS`]; `request_digest` is the SHA-256 of the exact
    /// reviewed request sidecar.
    TicketAction {
        action: String,
        request_digest: Digest,
    },
    ServiceNotice {
        text: String,
    },
}

impl Body {
    pub fn kind(&self) -> Kind {
        match self {
            Body::HumanStatement { .. } => Kind::HumanStatement,
            Body::SessionGrant { .. } => Kind::SessionGrant,
            Body::AgentDelegation { .. } => Kind::AgentDelegation,
            Body::AgentMessage { .. } => Kind::AgentMessage,
            Body::AgentRelay { .. } => Kind::AgentRelay,
            Body::ActionAuthorization { .. } => Kind::ActionAuthorization,
            Body::ActionExecute { .. } => Kind::ActionExecute,
            Body::ServiceNotice { .. } => Kind::ServiceNotice,
            Body::TicketAction { .. } => Kind::TicketAction,
        }
    }
}

/// The fields of an event payload. Unverified: use [`crate::Verifier`] before
/// trusting any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub project: String,
    pub author: String,
    pub key_id: KeyId,
    /// Digest of the session grant or delegation event this key signs under.
    pub session: Option<Digest>,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Sorted, unique, non-empty.
    pub audience: Vec<String>,
    pub group: Option<String>,
    pub epoch: Option<u64>,
    pub previous: Option<Digest>,
    pub body: Body,
}

impl Event {
    pub fn kind(&self) -> Kind {
        self.body.kind()
    }

    /// Strictly parses payload bytes.
    pub fn parse(payload: &[u8]) -> Result<Event, Error> {
        let mut f = Fields::new(json::parse(payload, MAX_ENVELOPE_BYTES)?)?;
        if f.int("version")? != 1 {
            return Err(Error::UnsupportedVersion);
        }
        let id = f.id("id")?;
        let project = f.id("project")?;
        let kind = Kind::parse(&f.string("kind")?)?;
        let author = f.id("author")?;
        let key_id = KeyId::parse(&f.string("key_id")?)?;
        let session = opt_digest(f.opt_string("session")?)?;
        let issued_at = f.timestamp("issued_at")?;
        let expires_at = f.timestamp("expires_at")?;
        let audience = sorted_ids(f.array("audience")?, "audience")?;
        let group = f.opt_id("group")?;
        let epoch = f.opt_int("epoch")?;
        let previous = opt_digest(f.opt_string("previous")?)?;
        let body = parse_body(kind, f.take("body")?)?;
        f.finish()?;

        if audience.is_empty() || audience.len() > MAX_AUDIENCE {
            return Err(Error::Schema("audience size"));
        }
        if group.is_none() && epoch.is_some() {
            return Err(Error::Schema("epoch without group"));
        }
        Ok(Event {
            id,
            project,
            author,
            key_id,
            session,
            issued_at,
            expires_at,
            audience,
            group,
            epoch,
            previous,
            body,
        })
    }

    /// Serializes the payload bytes to sign. The result is re-parsed with the
    /// strict parser and must describe the same event.
    pub fn to_payload(&self) -> Result<Vec<u8>, Error> {
        let body = match &self.body {
            Body::HumanStatement { text }
            | Body::AgentMessage { text }
            | Body::ServiceNotice { text } => json!({ "text": text }),
            Body::SessionGrant {
                session_key,
                purposes,
            } => json!({
                "session_key": {
                    "algorithm": session_key.algorithm().as_str(),
                    "public_key": STANDARD.encode(session_key.as_bytes()),
                },
                "purposes": purposes.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
            }),
            Body::AgentDelegation {
                agent,
                agent_key_id,
                purposes,
            } => json!({
                "agent": agent,
                "agent_key_id": agent_key_id.as_str(),
                "purposes": purposes.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
            }),
            Body::AgentRelay { original, note } => json!({
                "original": original.to_json_value(),
                "note": note,
            }),
            Body::ActionAuthorization {
                action,
                request_digest,
                performer,
            } => json!({
                "action": action,
                "request_digest": request_digest.to_hex(),
                "performer": performer,
            }),
            Body::TicketAction {
                action,
                request_digest,
            } => json!({
                "action": action,
                "request_digest": request_digest.to_hex(),
            }),
            Body::ActionExecute {
                action,
                request_digest,
                authorization,
            } => json!({
                "action": action,
                "request_digest": request_digest.to_hex(),
                "authorization": authorization.to_hex(),
            }),
        };
        let value = json!({
            "version": 1,
            "id": self.id,
            "project": self.project,
            "kind": self.kind().as_str(),
            "author": self.author,
            "key_id": self.key_id.as_str(),
            "session": self.session.map(|d| d.to_hex()),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "audience": self.audience,
            "group": self.group,
            "epoch": self.epoch,
            "previous": self.previous.map(|d| d.to_hex()),
            "body": body,
        });
        let bytes = serde_json::to_vec(&value).expect("serializing JSON values cannot fail");
        if Event::parse(&bytes)? != *self {
            return Err(Error::Schema("event does not survive strict parsing"));
        }
        Ok(bytes)
    }
}

fn opt_digest(s: Option<String>) -> Result<Option<Digest>, Error> {
    s.map(|s| Digest::from_hex(&s)).transpose()
}

fn text(f: &mut Fields, name: &'static str) -> Result<String, Error> {
    let s = f.string(name)?;
    if s.len() > MAX_TEXT_BYTES {
        return Err(Error::Schema("text too long"));
    }
    Ok(s)
}

fn purposes(values: Vec<Value>) -> Result<Vec<Kind>, Error> {
    let mut out: Vec<Kind> = Vec::new();
    for v in values {
        let Value::Str(s) = v else {
            return Err(Error::Schema("expected a string"));
        };
        let kind = Kind::parse(&s)?;
        if out
            .last()
            .is_some_and(|prev| prev.as_str() >= kind.as_str())
        {
            return Err(Error::Schema("list is not sorted and unique"));
        }
        out.push(kind);
    }
    if out.is_empty() {
        return Err(Error::Schema("purposes is empty"));
    }
    Ok(out)
}

fn parse_body(kind: Kind, value: Value) -> Result<Body, Error> {
    let mut f = Fields::new(value)?;
    let body = match kind {
        Kind::HumanStatement => Body::HumanStatement {
            text: text(&mut f, "text")?,
        },
        Kind::AgentMessage => Body::AgentMessage {
            text: text(&mut f, "text")?,
        },
        Kind::ServiceNotice => Body::ServiceNotice {
            text: text(&mut f, "text")?,
        },
        Kind::SessionGrant => {
            let mut k = Fields::new(f.take("session_key")?)?;
            let algorithm = Algorithm::parse(&k.string("algorithm")?)?;
            let raw = STANDARD
                .decode(k.string("public_key")?.as_bytes())
                .map_err(|_| Error::Malformed("public key is not canonical base64"))?;
            k.finish()?;
            Body::SessionGrant {
                session_key: PublicKey::new(algorithm, &raw)?,
                purposes: purposes(f.array("purposes")?)?,
            }
        }
        Kind::AgentDelegation => Body::AgentDelegation {
            agent: f.id("agent")?,
            agent_key_id: KeyId::parse(&f.string("agent_key_id")?)?,
            purposes: purposes(f.array("purposes")?)?,
        },
        Kind::AgentRelay => {
            let original = Envelope::from_value(f.take("original")?, EVENT_PAYLOAD_TYPE)?;
            let note = f.opt_string("note")?;
            if note.as_ref().is_some_and(|n| n.len() > MAX_TEXT_BYTES) {
                return Err(Error::Schema("text too long"));
            }
            Body::AgentRelay { original, note }
        }
        Kind::ActionAuthorization => Body::ActionAuthorization {
            action: f.id("action")?,
            request_digest: Digest::from_hex(&f.string("request_digest")?)?,
            performer: f.id("performer")?,
        },
        Kind::TicketAction => {
            let action = f.string("action")?;
            if !TICKET_ACTIONS.contains(&action.as_str()) {
                return Err(Error::Schema("not a routine ticket action"));
            }
            Body::TicketAction {
                action,
                request_digest: Digest::from_hex(&f.string("request_digest")?)?,
            }
        }
        Kind::ActionExecute => Body::ActionExecute {
            action: f.id("action")?,
            request_digest: Digest::from_hex(&f.string("request_digest")?)?,
            authorization: Digest::from_hex(&f.string("authorization")?)?,
        },
    };
    f.finish()?;
    Ok(body)
}
