//! Shared pieces of the setup and message workflows.
use crate::{
    profile::{self, Pin, Workspace, GROUP},
    signer::{self, Mode},
    Args, Deps, Failure,
};
use serde::{de::DeserializeOwned, Serialize};
use std::path::PathBuf;
use yhes_core::{engine::Engine, local::LocalChannel, pilot::GroupStatus};
use yhes_wire::{Body, Digest, Envelope, Event, KeyId, EVENT_PAYLOAD_TYPE};

/// Renew a registry or delegation this long before it expires.
pub const RENEW_MARGIN: u64 = 86_400;
pub const WEEK: u64 = 7 * 86_400;
/// Native limits for human-signed documents.
pub const STATEMENT_LIFETIME: u64 = 1_800;
pub const AUTHORIZATION_LIFETIME: u64 = 300;

pub struct Project {
    pub ws: Workspace,
    pub pin: Pin,
}

pub fn project(args: &Args, deps: &Deps<'_>) -> Result<Project, Failure> {
    let ws = Workspace::locate(
        &deps.private_root,
        &PathBuf::from(args.need("--project")?),
        false,
    )?;
    let pin = ws.pin()?.ok_or_else(profile::not_set_up)?;
    Ok(Project { ws, pin })
}

pub fn channel(project: &Project) -> Result<LocalChannel, Failure> {
    LocalChannel::open(&project.ws.project_root, &project.pin.project_id).map_err(Failure::from)
}

/// Encrypted CLI checkpoints in the agent's own vault.
pub fn get_json<T: DeserializeOwned>(
    engine: &mut Engine,
    name: &str,
) -> Result<Option<T>, Failure> {
    match engine.client_get(name)? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            Failure::new(
                "private_state",
                "a stored workflow checkpoint is unreadable",
            )
        }),
    }
}
pub fn put_json<T: Serialize>(engine: &mut Engine, name: &str, value: &T) -> Result<(), Failure> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| Failure::new("internal", "cannot encode a workflow checkpoint"))?;
    engine.client_put(name, &bytes).map_err(Failure::from)
}

pub fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
}

pub fn parse_event(envelope: &str) -> Option<Event> {
    let envelope = Envelope::parse(envelope.as_bytes(), EVENT_PAYLOAD_TYPE).ok()?;
    Event::parse(envelope.payload()).ok()
}
pub fn event_digest(envelope: &str) -> Result<Digest, Failure> {
    Envelope::parse(envelope.as_bytes(), EVENT_PAYLOAD_TYPE)
        .map(|e| e.digest())
        .map_err(|_| Failure::new("private_state", "a stored signed event is unreadable"))
}

/// The agent's current delegation, or a failure that says how to renew it.
pub fn grant(engine: &mut Engine, now: u64) -> Result<(String, Event), Failure> {
    let missing = || {
        Failure::new(
            "delegation_expired",
            "this agent has no current delegation from its human controller",
        )
        .hint("Run `yhes pilot` again; it asks for a new delegation in YhesSigner.")
    };
    let envelope: String = get_json(engine, "grant")?.ok_or_else(missing)?;
    let event = parse_event(&envelope).ok_or_else(missing)?;
    if event.expires_at <= now {
        return Err(missing());
    }
    Ok((envelope, event))
}

/// An active group without a pending membership change.
pub fn ready_group(engine: &mut Engine) -> Result<GroupStatus, Failure> {
    let status = engine
        .group_status(GROUP)?
        .filter(|s| s.active)
        .ok_or_else(|| {
            Failure::new(
                "not_in_group",
                "this profile is not a member of the pilot group",
            )
            .hint("Run `yhes pilot` to finish setup, then `yhes sync`.")
        })?;
    if status.pending_operation.is_some() {
        return Err(Failure::new(
            "membership_pending",
            "a membership change is waiting for publication",
        )
        .hint("Run `yhes pilot` to finish it."));
    }
    Ok(status)
}

/// A draft event the human will sign on their device key.
pub fn human_event(
    pin: &Pin,
    id: String,
    now: u64,
    lifetime: u64,
    audience: Vec<String>,
    epoch: Option<u64>,
    body: Body,
) -> Result<Event, Failure> {
    Ok(Event {
        id,
        project: pin.project_id.clone(),
        author: pin.human.clone(),
        key_id: pin.authority.key_id()?,
        session: None,
        issued_at: now,
        expires_at: now + lifetime,
        audience,
        // Statements and authorizations name an exact epoch. A delegation is
        // group-wide and carries none.
        group: Some(GROUP.into()),
        epoch,
        previous: None,
        body,
    })
}

/// Native review of one exact event. Progress text names the kind only.
pub fn approve(
    deps: &mut Deps<'_>,
    pin: &Pin,
    what: &str,
    event: &Event,
    sidecar: Option<&[u8]>,
) -> Result<String, Failure> {
    let payload = event.to_payload().map_err(|_| {
        Failure::new(
            "invalid",
            "the text or identifiers do not fit a signed event",
        )
    })?;
    if payload.len() > 65_536 {
        return Err(Failure::new(
            "too_large",
            "the document exceeds the signer's 64 KiB review limit",
        ));
    }
    deps.say(&format!(
        "{what}: review it in YhesSigner and approve with Touch ID (waiting up to 5 minutes)"
    ));
    let envelope = signer::review(deps.signer, &pin.authority, Mode::Event, &payload, sidecar)?;
    deps.say(&format!("{what}: approved"));
    Ok(envelope)
}

/// An agent event issued under the agent's delegation.
#[allow(clippy::too_many_arguments)]
pub fn agent_event(
    engine: &mut Engine,
    pin: &Pin,
    id: String,
    grant: &str,
    now: u64,
    expires_at: u64,
    audience: Vec<String>,
    epoch: u64,
    body: Body,
) -> Result<Event, Failure> {
    let identity = engine.identity()?;
    Ok(Event {
        id,
        project: pin.project_id.clone(),
        author: identity.principal,
        key_id: KeyId::parse(&identity.key_id)
            .map_err(|_| Failure::new("internal", "agent key identifier is invalid"))?,
        session: Some(event_digest(grant)?),
        issued_at: now,
        expires_at,
        audience,
        group: Some(GROUP.into()),
        epoch: Some(epoch),
        previous: None,
        body,
    })
}
