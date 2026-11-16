use serde::de::Deserializer;
use serde::Deserialize;
use serde_json::value::RawValue;
use yhes_wire::{Body, Digest, KeyId, Kind, SignerRole, VerifiedEvent, MAX_AUDIENCE, MAX_ID_BYTES};

/// Largest exact request sidecar accepted by this crate.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_JSON_DEPTH: usize = 8;
const MAX_TITLE_BYTES: usize = 256;
const MAX_DESCRIPTION_BYTES: usize = 16 * 1024;
const MAX_STOP_EVIDENCE_BYTES: usize = 4096;

/// Why an action request was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("request exceeds a size or nesting limit")]
    TooLarge,
    #[error("malformed request JSON")]
    Malformed,
    #[error("request schema is invalid: {0}")]
    Schema(&'static str),
    #[error("invalid request identifier: {0}")]
    InvalidId(&'static str),
    #[error("unsupported action")]
    UnsupportedAction,
    #[error("request does not match the verified action event: {0}")]
    BindingMismatch(&'static str),
    #[error("privileged action is missing a current verified human authorization")]
    AuthorizationRequired,
    #[error("authorization is not current")]
    AuthorizationExpired,
}

/// Supported secure action names. There is intentionally no generic command action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    GroupCreate,
    GroupAdd,
    GroupRemove,
    TicketRecover,
    TicketCreate,
    TicketClaim,
    TicketRelease,
    TicketUpdate,
    TicketComplete,
    TicketCancel,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GroupCreate => "group.create",
            Self::GroupAdd => "group.add",
            Self::GroupRemove => "group.remove",
            Self::TicketRecover => "ticket.recover",
            Self::TicketCreate => "ticket.create",
            Self::TicketClaim => "ticket.claim",
            Self::TicketRelease => "ticket.release",
            Self::TicketUpdate => "ticket.update",
            Self::TicketComplete => "ticket.complete",
            Self::TicketCancel => "ticket.cancel",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "group.create" => Ok(Self::GroupCreate),
            "group.add" => Ok(Self::GroupAdd),
            "group.remove" => Ok(Self::GroupRemove),
            "ticket.recover" => Ok(Self::TicketRecover),
            "ticket.create" => Ok(Self::TicketCreate),
            "ticket.claim" => Ok(Self::TicketClaim),
            "ticket.release" => Ok(Self::TicketRelease),
            "ticket.update" => Ok(Self::TicketUpdate),
            "ticket.complete" => Ok(Self::TicketComplete),
            "ticket.cancel" => Ok(Self::TicketCancel),
            _ => Err(Error::UnsupportedAction),
        }
    }

    fn privileged(self) -> bool {
        matches!(
            self,
            Self::GroupCreate | Self::GroupAdd | Self::GroupRemove | Self::TicketRecover
        )
    }
}

/// Validated, action-specific parameter shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parameters {
    GroupCreate {},
    GroupAdd {
        member: String,
        key_id: KeyId,
        key_package_digest: Digest,
    },
    GroupRemove {
        member: String,
    },
    TicketRecover {
        ticket: String,
        expected_revision: u64,
        stop_evidence: String,
    },
    TicketCreate {
        title: String,
        description: String,
    },
    TicketClaim {
        ticket: String,
        expected_revision: u64,
    },
    TicketRelease {
        ticket: String,
        expected_revision: u64,
    },
    TicketUpdate {
        ticket: String,
        expected_revision: u64,
        title: Option<String>,
        description: Option<String>,
    },
    TicketComplete {
        ticket: String,
        expected_revision: u64,
    },
    TicketCancel {
        ticket: String,
        expected_revision: u64,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire<'a> {
    version: u64,
    project: String,
    action: String,
    performer: String,
    group: String,
    epoch: u64,
    audience: Vec<String>,
    #[serde(borrow)]
    parameters: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyParameters {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupAddParameters {
    member: String,
    key_id: String,
    key_package_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupRemoveParameters {
    member: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketRevisionParameters {
    ticket: String,
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketUpdateParameters {
    ticket: String,
    expected_revision: u64,
    #[serde(default)]
    title: Patch<String>,
    #[serde(default)]
    description: Patch<String>,
}

#[derive(Debug, Default)]
struct Patch<T>(Option<T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Patch<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(|value| Patch(Some(value)))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketRecoverParameters {
    ticket: String,
    expected_revision: u64,
    stop_evidence: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketCreateParameters {
    title: String,
    description: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketActionBody {
    action: String,
    request_digest: String,
}

#[derive(Deserialize)]
struct TicketActionPayload {
    body: TicketActionBody,
}

/// A parsed request retaining the digest of the exact caller-provided bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    digest: Digest,
    project: String,
    action: Action,
    performer: String,
    group: String,
    epoch: u64,
    audience: Vec<String>,
    parameters: Parameters,
}

impl Request {
    /// Strictly parses the exact sidecar bytes without normalizing or reserializing them.
    pub fn parse(exact_bytes: &[u8]) -> Result<Request, Error> {
        if exact_bytes.is_empty() || exact_bytes.len() > MAX_REQUEST_BYTES {
            return Err(Error::TooLarge);
        }
        check_depth(exact_bytes)?;
        let wire: RequestWire<'_> =
            serde_json::from_slice(exact_bytes).map_err(|_| Error::Malformed)?;
        if wire.version != 1 {
            return Err(Error::Schema("unsupported request version"));
        }
        let action = Action::parse(&wire.action)?;
        check_id(&wire.project, "project")?;
        check_id(&wire.performer, "performer")?;
        check_id(&wire.group, "group")?;
        if wire.audience.is_empty() || wire.audience.len() > MAX_AUDIENCE {
            return Err(Error::Schema("audience size"));
        }
        let mut previous: Option<&str> = None;
        for member in &wire.audience {
            check_id(member, "audience member")?;
            if previous.is_some_and(|last| last >= member.as_str()) {
                return Err(Error::Schema("audience must be sorted and unique"));
            }
            previous = Some(member);
        }
        if action == Action::GroupCreate
            && (wire.epoch != 0 || wire.audience.as_slice() != [wire.performer.as_str()])
        {
            return Err(Error::Schema(
                "group.create must start at epoch zero with performer-only audience",
            ));
        }
        let parameters = parse_parameters(action, wire.parameters.get())?;
        Ok(Request {
            digest: Digest::of(exact_bytes),
            project: wire.project,
            action,
            performer: wire.performer,
            group: wire.group,
            epoch: wire.epoch,
            audience: wire.audience,
            parameters,
        })
    }

    /// SHA-256 of the exact request bytes supplied to `parse`.
    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn project(&self) -> &str {
        &self.project
    }

    pub fn action(&self) -> Action {
        self.action
    }

    pub fn performer(&self) -> &str {
        &self.performer
    }

    pub fn group(&self) -> &str {
        &self.group
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn audience(&self) -> &[String] {
        &self.audience
    }

    pub fn parameters(&self) -> &Parameters {
        &self.parameters
    }

    /// Checks that a verified wire event binds this exact request.
    pub fn verify_binding(&self, verified: &VerifiedEvent, now: u64) -> Result<(), Error> {
        let event = verified.event();
        if event.expires_at < now {
            return Err(Error::BindingMismatch("event is not current"));
        }
        if event.project != self.project {
            return Err(Error::BindingMismatch("project"));
        }
        if event.author != self.performer {
            return Err(Error::BindingMismatch("performer"));
        }
        if event.group.as_deref() != Some(self.group.as_str()) {
            return Err(Error::BindingMismatch("group"));
        }
        if event.epoch != Some(self.epoch) {
            return Err(Error::BindingMismatch("epoch"));
        }
        if event.audience != self.audience {
            return Err(Error::BindingMismatch("audience"));
        }

        match (&event.body, event.kind()) {
            (
                Body::ActionExecute {
                    action,
                    request_digest,
                    ..
                },
                Kind::ActionExecute,
            ) => {
                if !self.action.privileged() {
                    return Err(Error::BindingMismatch("event kind"));
                }
                if action != self.action.as_str() {
                    return Err(Error::BindingMismatch("action"));
                }
                if request_digest != &self.digest {
                    return Err(Error::BindingMismatch("request digest"));
                }
                if self.action.privileged() {
                    let authorization = verified
                        .authorization()
                        .ok_or(Error::AuthorizationRequired)?;
                    if authorization.event().expires_at < now {
                        return Err(Error::AuthorizationExpired);
                    }
                    if authorization.event().project != self.project
                        || authorization.event().audience != self.audience
                        || authorization.event().group.as_deref() != Some(self.group.as_str())
                        || authorization.event().epoch != Some(self.epoch)
                    {
                        return Err(Error::BindingMismatch("authorization scope"));
                    }
                    match &authorization.event().body {
                        Body::ActionAuthorization {
                            action,
                            request_digest,
                            performer,
                        } if action == self.action.as_str()
                            && request_digest == &self.digest
                            && performer == &self.performer => {}
                        _ => return Err(Error::BindingMismatch("authorization")),
                    }
                }
                Ok(())
            }
            (Body::TicketAction { .. }, Kind::TicketAction) => {
                if self.action.privileged() {
                    return Err(Error::AuthorizationRequired);
                }
                let ticket_event: TicketActionPayload =
                    serde_json::from_slice(verified.payload()).map_err(|_| Error::Malformed)?;
                if ticket_event.body.action != self.action.as_str() {
                    return Err(Error::BindingMismatch("action"));
                }
                let request_digest = Digest::from_hex(&ticket_event.body.request_digest)
                    .map_err(|_| Error::Malformed)?;
                if request_digest != self.digest {
                    return Err(Error::BindingMismatch("request digest"));
                }
                if verified.signer() != SignerRole::Agent {
                    return Err(Error::BindingMismatch("ticket signer role"));
                }
                Ok(())
            }
            _ => Err(Error::BindingMismatch("event kind")),
        }
    }
}

fn parse_parameters(action: Action, json: &str) -> Result<Parameters, Error> {
    match action {
        Action::GroupCreate => {
            let _: EmptyParameters = deserialize(json)?;
            Ok(Parameters::GroupCreate {})
        }
        Action::GroupAdd => {
            let value: GroupAddParameters = deserialize(json)?;
            check_id(&value.member, "member")?;
            let key_id =
                KeyId::parse(&value.key_id).map_err(|_| Error::Schema("invalid key id"))?;
            let key_package_digest = Digest::from_hex(&value.key_package_digest)
                .map_err(|_| Error::Schema("invalid key package digest"))?;
            Ok(Parameters::GroupAdd {
                member: value.member,
                key_id,
                key_package_digest,
            })
        }
        Action::GroupRemove => {
            let value: GroupRemoveParameters = deserialize(json)?;
            check_id(&value.member, "member")?;
            Ok(Parameters::GroupRemove {
                member: value.member,
            })
        }
        Action::TicketRecover => {
            let value: TicketRecoverParameters = deserialize(json)?;
            check_id(&value.ticket, "ticket")?;
            check_text(
                &value.stop_evidence,
                MAX_STOP_EVIDENCE_BYTES,
                "stop evidence",
            )?;
            if value.stop_evidence.trim().is_empty() {
                return Err(Error::Schema("stop evidence is empty"));
            }
            Ok(Parameters::TicketRecover {
                ticket: value.ticket,
                expected_revision: value.expected_revision,
                stop_evidence: value.stop_evidence,
            })
        }
        Action::TicketCreate => {
            let value: TicketCreateParameters = deserialize(json)?;
            check_text(&value.title, MAX_TITLE_BYTES, "ticket title")?;
            check_text(
                &value.description,
                MAX_DESCRIPTION_BYTES,
                "ticket description",
            )?;
            if value.title.trim().is_empty() {
                return Err(Error::Schema("ticket title is empty"));
            }
            Ok(Parameters::TicketCreate {
                title: value.title,
                description: value.description,
            })
        }
        Action::TicketClaim
        | Action::TicketRelease
        | Action::TicketComplete
        | Action::TicketCancel => {
            let value: TicketRevisionParameters = deserialize(json)?;
            check_id(&value.ticket, "ticket")?;
            Ok(match action {
                Action::TicketClaim => Parameters::TicketClaim {
                    ticket: value.ticket,
                    expected_revision: value.expected_revision,
                },
                Action::TicketRelease => Parameters::TicketRelease {
                    ticket: value.ticket,
                    expected_revision: value.expected_revision,
                },
                Action::TicketComplete => Parameters::TicketComplete {
                    ticket: value.ticket,
                    expected_revision: value.expected_revision,
                },
                Action::TicketCancel => Parameters::TicketCancel {
                    ticket: value.ticket,
                    expected_revision: value.expected_revision,
                },
                _ => unreachable!(),
            })
        }
        Action::TicketUpdate => {
            let value: TicketUpdateParameters = deserialize(json)?;
            check_id(&value.ticket, "ticket")?;
            if value.title.0.is_none() && value.description.0.is_none() {
                return Err(Error::Schema("ticket.update has no changes"));
            }
            if let Some(title) = &value.title.0 {
                check_text(title, MAX_TITLE_BYTES, "ticket title")?;
                if title.trim().is_empty() {
                    return Err(Error::Schema("ticket title is empty"));
                }
            }
            if let Some(description) = &value.description.0 {
                check_text(description, MAX_DESCRIPTION_BYTES, "ticket description")?;
            }
            Ok(Parameters::TicketUpdate {
                ticket: value.ticket,
                expected_revision: value.expected_revision,
                title: value.title.0,
                description: value.description.0,
            })
        }
    }
}

fn deserialize<'a, T: Deserialize<'a>>(json: &'a str) -> Result<T, Error> {
    serde_json::from_str(json).map_err(|_| Error::Malformed)
}

fn check_id(value: &str, name: &'static str) -> Result<(), Error> {
    let bytes = value.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= MAX_ID_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !value.contains("..");
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidId(name))
    }
}

fn check_text(value: &str, max_bytes: usize, name: &'static str) -> Result<(), Error> {
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        Err(Error::Schema(name))
    } else {
        Ok(())
    }
}

fn check_depth(bytes: &[u8]) -> Result<(), Error> {
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(Error::TooLarge);
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    Ok(())
}
