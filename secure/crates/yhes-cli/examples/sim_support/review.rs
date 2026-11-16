//! A deliberately narrow fixture approval policy. It never authorizes generic
//! signing, force/recovery, arbitrary participants, or production projects.
use super::{fs::rejected, human::Human};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use serde_json::Value;
use yhes_cli::{signer::Request, Clock, Failure, SystemClock};
use yhes_wire::{Algorithm, Body, Digest, Event, Kind, PublicKey};

pub fn event(human: &Human, request: &Request, payload: &[u8]) -> Result<(), Failure> {
    let event = Event::parse(payload).map_err(|_| rejected())?;
    let now = SystemClock.now();
    if event.project != human.project
        || event.author != human.author
        || event.key_id.as_str() != human.descriptor()?.key_id
        || event.session.is_some()
        || event.previous.is_some()
        || event.group.as_deref() != Some("team")
        || event
            .audience
            .iter()
            .any(|id| !matches!(id.as_str(), "sim-alice-agent" | "sim-bob-agent"))
        || event.issued_at > now.saturating_add(60)
        || event.expires_at < now
        || event.expires_at < event.issued_at
    {
        return Err(rejected());
    }
    let lifetime = event.expires_at - event.issued_at;
    match &event.body {
        Body::HumanStatement { text }
            if request.request.is_none()
                && lifetime <= 1800
                && event.epoch.is_some()
                && text.len() <= 32_768
                && !text.trim().is_empty()
                && !text
                    .chars()
                    .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')) =>
        {
            Ok(())
        }
        Body::AgentDelegation {
            agent, purposes, ..
        } if request.request.is_none()
            && agent == &human.agent
            && lifetime <= 7 * 86400
            && event.epoch.is_none()
            && purposes == &[Kind::ActionExecute, Kind::AgentMessage, Kind::AgentRelay] =>
        {
            Ok(())
        }
        Body::ActionAuthorization {
            action,
            request_digest,
            performer,
        } => {
            let sidecar = request.request.as_deref().ok_or_else(rejected)?;
            let parsed = yhes_actions::Request::parse(sidecar).map_err(|_| rejected())?;
            if human.author != "sim-alice"
                || lifetime > 300
                || !matches!(action.as_str(), "group.create" | "group.add")
                || performer != &human.agent
                || parsed.performer() != performer
                || parsed.action().as_str() != action
                || parsed.project() != event.project
                || parsed.group() != "team"
                || Some(parsed.epoch()) != event.epoch
                || parsed.audience() != event.audience
                || parsed.digest() != *request_digest
            {
                return Err(rejected());
            }
            match parsed.parameters() {
                yhes_actions::Parameters::GroupCreate {} => Ok(()),
                yhes_actions::Parameters::GroupAdd { member, .. } if member == "sim-bob-agent" => {
                    Ok(())
                }
                _ => Err(rejected()),
            }
        }
        _ => Err(rejected()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u8,
    project: String,
    generation: u64,
    previous: Value,
    issued_at: u64,
    expires_at: u64,
    participants: Vec<Participant>,
    keys: Vec<Key>,
    revocations: Vec<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Participant {
    id: String,
    kind: String,
    controller: Value,
    ghes: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    key_id: String,
    participant: String,
    algorithm: String,
    public_key: String,
    not_before: u64,
    not_after: u64,
}

pub fn registry(human: &Human, payload: &[u8]) -> Result<(), Failure> {
    let document: Registry = serde_json::from_slice(payload).map_err(|_| rejected())?;
    let now = SystemClock.now();
    let own = human.descriptor()?;
    let expected: Vec<&str> = match document.generation {
        1 if document.previous.is_null() => vec![&human.author, &human.agent],
        2 if human.author == "sim-alice"
            && document
                .previous
                .as_str()
                .is_some_and(|s| Digest::from_hex(s).is_ok()) =>
        {
            vec!["sim-alice", "sim-alice-agent", "sim-bob", "sim-bob-agent"]
        }
        _ => return Err(rejected()),
    };
    if document.version != 1
        || document.project != human.project
        || document.issued_at > now.saturating_add(60)
        || document.expires_at < now
        || document.expires_at < document.issued_at
        || document.expires_at - document.issued_at > 7 * 86400
        || !document.revocations.is_empty()
        || document
            .participants
            .iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>()
            != expected
        || document.keys.len() != expected.len()
        || document.keys.windows(2).any(|p| p[0].key_id >= p[1].key_id)
    {
        return Err(rejected());
    }
    for participant in &document.participants {
        let controller = participant.id.strip_suffix("-agent");
        if !participant.ghes.is_null()
            || match controller {
                Some(controller) => {
                    participant.kind != "agent"
                        || participant.controller.as_str() != Some(controller)
                }
                None => participant.kind != "human" || !participant.controller.is_null(),
            }
        {
            return Err(rejected());
        }
        let keys: Vec<&Key> = document
            .keys
            .iter()
            .filter(|k| k.participant == participant.id)
            .collect();
        let [key] = keys.as_slice() else {
            return Err(rejected());
        };
        let algorithm = if controller.is_some() {
            Algorithm::Ed25519
        } else {
            Algorithm::P256Sha256
        };
        let raw = STANDARD.decode(&key.public_key).map_err(|_| rejected())?;
        let parsed = PublicKey::new(algorithm, &raw).map_err(|_| rejected())?;
        if key.algorithm != algorithm.as_str()
            || parsed.key_id().as_str() != key.key_id
            || STANDARD.encode(&raw) != key.public_key
            || key.not_before > now.saturating_add(60)
            || key.not_after < now
            || key.not_after < key.not_before
            || key.not_after - key.not_before > 30 * 86400
            || (key.participant == human.author
                && (key.key_id != own.key_id || key.public_key != own.public_key))
        {
            return Err(rejected());
        }
    }
    Ok(())
}
