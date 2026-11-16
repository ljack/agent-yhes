use super::{config::TeamSession, rejected};
use crate::{signer::Descriptor, Failure};
use serde_json::{json, Value};
use yhes_core::{engine::PublicIdentity, git::PublicSnapshot, local::SyncResult};
use yhes_wire::{
    Envelope, ParticipantKind, Policy, Registry, RegistryCheckpoint, TrustAnchors,
    REGISTRY_PAYLOAD_TYPE,
};

pub fn anchors(project: &str, authority: &Descriptor) -> Result<TrustAnchors, Failure> {
    TrustAnchors::new(project, vec![authority.key()?], 1).map_err(|_| rejected())
}
pub fn document(envelope: &[u8]) -> Result<Value, Failure> {
    let envelope = Envelope::parse(envelope, REGISTRY_PAYLOAD_TYPE).map_err(|_| rejected())?;
    serde_json::from_slice(envelope.payload()).map_err(|_| rejected())
}
pub fn single(project: &str, human: &Descriptor, agent: &PublicIdentity, now: u64) -> Value {
    let mut participants = vec![
        json!({"id": human.author, "kind": "human", "controller": null, "ghes": null}),
        json!({"id": agent.principal, "kind": "agent", "controller": human.author, "ghes": null}),
    ];
    participants.sort_by_key(|p| p["id"].as_str().unwrap_or_default().to_owned());
    let mut keys = vec![
        json!({"key_id": human.key_id, "participant": human.author, "algorithm": human.algorithm,
            "public_key": human.public_key, "not_before": now, "not_after": now + 30*86400}),
        json!({"key_id": agent.key_id, "participant": agent.principal, "algorithm": agent.algorithm,
            "public_key": agent.public_key, "not_before": now, "not_after": now + 30*86400}),
    ];
    keys.sort_by_key(|k| k["key_id"].as_str().unwrap_or_default().to_owned());
    json!({"version":1,"project":project,"generation":1,"previous":null,
        "issued_at":now,"expires_at":now+7*86400,"participants":participants,"keys":keys,"revocations":[]})
}
/// Authenticate an enrollment proposal under its explicitly expected human
/// key. This never installs the proposal as project membership.
pub fn proposal(
    bytes: &[u8],
    human: &Descriptor,
    agent: &PublicIdentity,
    now: u64,
) -> Result<Value, Failure> {
    let registry = Registry::verify(
        bytes,
        &anchors(&human.project, human)?,
        None,
        &Policy::default(),
        now,
    )
    .map_err(|_| rejected())?;
    let doc = document(bytes)?;
    if registry.generation() != 1
        || registry.participants().count() != 2
        || human.key()?.algorithm() != yhes_wire::Algorithm::P256Sha256
        || doc["keys"].as_array().is_none_or(|keys| keys.len() != 2)
        || doc["revocations"] != json!([])
        || !crate::profile::agent_name(&agent.principal)
        || agent.algorithm != "ed25519"
        || !crate::profile::valid_id(&human.author)
    {
        return Err(rejected());
    }
    let h = registry.participant(&human.author).ok_or_else(rejected)?;
    let a = registry
        .participant(&agent.principal)
        .ok_or_else(rejected)?;
    if h.kind != ParticipantKind::Human
        || h.ghes.is_some()
        || a.kind != ParticipantKind::Agent
        || a.controller.as_deref() != Some(&human.author)
        || a.ghes.is_some()
    {
        return Err(rejected());
    }
    let human_key = registry
        .active_key(&human.author, &human.key_id()?, now)
        .map_err(|_| rejected())?;
    let agent_id = yhes_wire::KeyId::parse(&agent.key_id).map_err(|_| rejected())?;
    let agent_key = registry
        .active_key(&agent.principal, &agent_id, now)
        .map_err(|_| rejected())?;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    if human_key != human.key()? || STANDARD.encode(agent_key.as_bytes()) != agent.public_key {
        return Err(rejected());
    }
    Ok(doc)
}

pub fn install(
    session: &mut TeamSession,
    snapshot: &PublicSnapshot,
    now: u64,
) -> Result<Registry, Failure> {
    let anchors = anchors(&session.pin.project_id, &session.pin.authority)?;
    let mut chain: Vec<Vec<u8>> = Vec::new();
    let mut checkpoint = None;
    for generation in 1..=4096 {
        let Some(bytes) = snapshot
            .artifacts
            .get(&format!("registry-{generation}.json"))
        else {
            break;
        };
        let next = RegistryCheckpoint::advance(bytes, &anchors, checkpoint.as_ref())
            .map_err(|_| rejected())?;
        if next.generation() != generation {
            return Err(rejected());
        }
        if generation == 1
            && session
                .pin
                .bootstrap_head
                .as_ref()
                .is_some_and(|d| *d != next.digest().to_hex())
        {
            return Err(rejected());
        }
        checkpoint = Some(next);
        chain.push(bytes.clone());
    }
    let last = chain.last().ok_or_else(rejected)?;
    // Extra registry files after a gap cannot be silently ignored.
    for name in snapshot
        .artifacts
        .keys()
        .filter(|n| n.starts_with("registry-"))
    {
        let generation = name
            .strip_prefix("registry-")
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(rejected)?;
        if generation == 0
            || generation > chain.len()
            || *name != format!("registry-{generation}.json")
        {
            return Err(rejected());
        }
    }
    let registry = Registry::verify(last, &anchors, checkpoint.as_ref(), &Policy::default(), now)
        .map_err(|_| rejected())?;
    let stored = session.engine.registry_chain()?;
    if stored.len() > chain.len() || stored.iter().zip(&chain).any(|(a, b)| a != b) {
        return Err(rejected());
    }
    if stored.is_empty() {
        let refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
        session
            .engine
            .bootstrap_registry(&refs, registry.digest(), now)?;
    } else {
        for bytes in chain.iter().skip(stored.len()) {
            session.engine.install_registry(bytes, now)?;
        }
    }
    Ok(registry)
}
/// Install the monotonic pinned registry chain before draining Git packets.
pub fn sync(session: &mut TeamSession, now: u64) -> Result<SyncResult, Failure> {
    let snapshot = session.channel.fetch_public_checked(&mut session.engine)?;
    install(session, &snapshot, now)?;
    session
        .channel
        .sync(
            &mut session.engine,
            &session.pin.group,
            &session.pin.owner,
            now,
        )
        .map_err(Failure::from)
}
