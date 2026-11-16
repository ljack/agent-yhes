//! `yhes pilot`: staged, resumable setup of two local agent profiles.
//!
//! Each stage is decided from durable state: the pin file, the vaults, the
//! encrypted client checkpoints and the group status. A rerun continues where
//! the last one stopped. Human approval happens only in the native signer.
use crate::{
    flow::{self, get_json, put_json, short_id, AUTHORIZATION_LIFETIME, RENEW_MARGIN, WEEK},
    profile::{self, open_profile, Pin, Workspace, AGENTS, GROUP, OWNER},
    signer::{self, Mode},
    Args, Deps, Failure,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use yhes_core::{
    engine::{Engine, PublicIdentity},
    local::LocalChannel,
    Control,
};
use yhes_wire::{Body, Digest, Envelope, Kind, REGISTRY_PAYLOAD_TYPE};

const KEY_VALIDITY: u64 = 30 * 86_400;
const MEMBER: &str = "claude";

/// A reviewed membership control, kept encrypted until it is published.
#[derive(Serialize, Deserialize)]
struct Staged {
    operation: String,
    control: Control,
}

fn default_project_id(ws: &Workspace) -> Option<String> {
    let name = ws.project_root.file_name()?.to_str()?;
    let id: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let id = id
        .trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_owned();
    profile::valid_id(&id).then_some(id)
}

fn identity_stage(
    args: &Args,
    deps: &mut Deps<'_>,
    ws: &Workspace,
) -> Result<(Pin, &'static str), Failure> {
    let human = args.need("--human")?;
    if let Some(pin) = ws.pin()? {
        if pin.human != human
            || args
                .get("--project-id")
                .is_some_and(|p| p != pin.project_id)
        {
            return Err(Failure::new(
                "pin_mismatch",
                "this project is already set up here for a different human or project ID",
            )
            // The pin has not been checked against a vault yet, so its names
            // are not repeated here.
            .hint("Use the --human and --project-id this project was first set up with."));
        }
        return Ok((pin, "already-done"));
    }
    let project_id = match args.get("--project-id") {
        Some(id) => id.to_owned(),
        None => default_project_id(ws).ok_or_else(|| {
            Failure::new("usage", "cannot derive a project ID from the folder name")
                .hint("Pass --project-id with letters, digits, '.', '_' or '-'.")
        })?,
    };
    if !profile::valid_id(human) || !profile::valid_id(&project_id) || AGENTS.contains(&human) {
        return Err(Failure::new(
            "usage",
            "--human and --project-id must be identifiers, and the human cannot be named like an agent",
        ));
    }
    deps.say("step 1/7 identity: asking YhesSigner for this Mac's human signing key");
    let authority = match signer::identity(deps.signer, human, &project_id)? {
        Some(descriptor) => descriptor,
        None => {
            deps.say(
                "step 1/7 identity: no key yet. Approve key setup in YhesSigner with Touch ID \
                 (waiting up to 5 minutes)",
            );
            signer::enroll(deps.signer, human, &project_id)?
        }
    };
    let pin = Pin {
        version: 1,
        project_id,
        project_path: ws.project_root.to_string_lossy().into_owned(),
        human: human.to_owned(),
        group: GROUP.into(),
        owner: OWNER.into(),
        agents: AGENTS.iter().map(|a| (*a).to_owned()).collect(),
        authority,
    };
    ws.write_pin(&pin)?;
    Ok((pin, "completed"))
}

fn registry_field(envelope: &str, field: &str) -> Option<u64> {
    let envelope = Envelope::parse(envelope.as_bytes(), REGISTRY_PAYLOAD_TYPE).ok()?;
    serde_json::from_slice::<Value>(envelope.payload()).ok()?[field].as_u64()
}

fn first_registry(pin: &Pin, agents: &[PublicIdentity], now: u64) -> Result<Vec<u8>, Failure> {
    let mut participants = vec![json!({
        // No GHES account is claimed: this pilot has no verified enrollment evidence.
        "id": pin.human, "kind": "human", "controller": null, "ghes": null,
    })];
    let mut keys = vec![json!({
        "key_id": pin.authority.key_id, "participant": pin.human,
        "algorithm": pin.authority.algorithm, "public_key": pin.authority.public_key,
        "not_before": now, "not_after": now + KEY_VALIDITY,
    })];
    for agent in agents {
        participants.push(json!({
            "id": agent.principal, "kind": "agent", "controller": pin.human, "ghes": null,
        }));
        keys.push(json!({
            "key_id": agent.key_id, "participant": agent.principal,
            "algorithm": agent.algorithm, "public_key": agent.public_key,
            "not_before": now, "not_after": now + KEY_VALIDITY,
        }));
    }
    participants.sort_by_key(|p| p["id"].as_str().unwrap_or_default().to_owned());
    keys.sort_by_key(|k| k["key_id"].as_str().unwrap_or_default().to_owned());
    serde_json::to_vec(&json!({
        "version": 1, "project": pin.project_id, "generation": 1, "previous": null,
        "issued_at": now, "expires_at": now + WEEK,
        "participants": participants, "keys": keys, "revocations": [],
    }))
    .map_err(|_| Failure::new("internal", "cannot encode the registry"))
}

/// The same participants and keys with a new validity period.
fn next_registry(head: &str, now: u64) -> Result<Vec<u8>, Failure> {
    let unreadable = || Failure::new("private_state", "the stored registry is unreadable");
    let envelope =
        Envelope::parse(head.as_bytes(), REGISTRY_PAYLOAD_TYPE).map_err(|_| unreadable())?;
    let mut registry: Value =
        serde_json::from_slice(envelope.payload()).map_err(|_| unreadable())?;
    let generation = registry["generation"].as_u64().ok_or_else(unreadable)?;
    registry["generation"] = json!(generation + 1);
    registry["previous"] = json!(envelope.digest().to_hex());
    registry["issued_at"] = json!(now);
    registry["expires_at"] = json!(now + WEEK);
    for key in registry["keys"].as_array_mut().ok_or_else(unreadable)? {
        key["not_after"] = json!(now + KEY_VALIDITY);
    }
    serde_json::to_vec(&registry).map_err(|_| unreadable())
}

/// Bring one vault to the head of an approved chain. The head digest comes
/// from the envelope the pinned human key signed, never from the project folder.
fn ensure_registry(engine: &mut Engine, chain: &[String], now: u64) -> Result<(), Failure> {
    let head = chain.last().expect("chain is never empty here");
    let have = engine.registry_chain()?.len();
    if have == 0 {
        let digest = Envelope::parse(head.as_bytes(), REGISTRY_PAYLOAD_TYPE)
            .map_err(|_| Failure::new("private_state", "the stored registry is unreadable"))?
            .digest();
        let refs: Vec<&[u8]> = chain.iter().map(|e| e.as_bytes()).collect();
        engine.bootstrap_registry(&refs, digest, now)?;
        return Ok(());
    }
    // Generations the vault already holds are history; only later ones are new.
    for envelope in chain.iter().skip(have) {
        engine.install_registry(envelope.as_bytes(), now)?;
    }
    Ok(())
}

fn registry_stage(
    deps: &mut Deps<'_>,
    ws: &Workspace,
    pin: &Pin,
    engines: &mut [Engine; 2],
) -> Result<(&'static str, Vec<String>), Failure> {
    let now = deps.clock.now();
    let unreadable = || Failure::new("private_state", "the stored registry is unreadable");
    let mut chain: Vec<String> = Vec::new();
    for engine in engines.iter_mut() {
        let stored = engine.registry_chain()?;
        if stored.len() > chain.len() {
            chain = stored
                .into_iter()
                .map(|bytes| String::from_utf8(bytes).map_err(|_| unreadable()))
                .collect::<Result<_, _>>()?;
        }
    }
    // An envelope approved in an earlier run that was not installed everywhere.
    for engine in engines.iter_mut() {
        if let Some(next) = get_json::<String>(engine, "registry-next")? {
            if registry_field(&next, "generation") == Some(chain.len() as u64 + 1) {
                chain.push(next);
            }
        }
    }
    let current = chain
        .last()
        .and_then(|head| registry_field(head, "expires_at"))
        .is_some_and(|expires| expires > now + RENEW_MARGIN);
    let mut state = "already-done";
    if !current {
        let payload = match chain.last() {
            None => {
                let mut identities = Vec::new();
                for engine in engines.iter_mut() {
                    identities.push(engine.identity()?);
                }
                first_registry(pin, &identities, now)?
            }
            Some(head) => next_registry(head, now)?,
        };
        deps.say(
            "step 3/7 registry: review the full trust registry (you and both agent keys) in \
             YhesSigner and approve with Touch ID (waiting up to 5 minutes)",
        );
        // Accepted only if it is the pinned key's signature over these exact bytes.
        let signed = signer::review(deps.signer, &pin.authority, Mode::Registry, &payload, None)?;
        deps.say("step 3/7 registry: approved");
        for engine in engines.iter_mut() {
            put_json(engine, "registry-next", &signed)?;
        }
        chain.push(signed);
        state = "completed";
    }
    for engine in engines.iter_mut() {
        ensure_registry(engine, &chain, now)?;
    }
    let head = chain.last().expect("chain has a head");
    let generation = registry_field(head, "generation").unwrap_or(0);
    profile::publish_public(ws, &format!("registry-{generation}.json"), head.as_bytes())?;
    Ok((state, chain))
}

fn delegation_stage(
    deps: &mut Deps<'_>,
    pin: &Pin,
    engines: &mut [Engine; 2],
) -> Result<&'static str, Failure> {
    let mut state = "already-done";
    let audience: Vec<String> = AGENTS.iter().map(|a| (*a).to_owned()).collect();
    for engine in engines.iter_mut() {
        let now = deps.clock.now();
        let identity = engine.identity()?;
        let key_id = yhes_wire::KeyId::parse(&identity.key_id)
            .map_err(|_| Failure::new("internal", "agent key identifier is invalid"))?;
        let stored: Option<String> = get_json(engine, "grant")?;
        let current = stored
            .as_deref()
            .and_then(flow::parse_event)
            .is_some_and(|event| {
                event.expires_at > now + RENEW_MARGIN
                    && matches!(&event.body, Body::AgentDelegation { agent, agent_key_id, .. }
                        if *agent == identity.principal && *agent_key_id == key_id)
            });
        if current {
            continue;
        }
        let event = flow::human_event(
            pin,
            format!("delegation-{}-{}", identity.principal, short_id()),
            now,
            WEEK,
            audience.clone(),
            None,
            Body::AgentDelegation {
                agent: identity.principal.clone(),
                agent_key_id: key_id,
                purposes: vec![Kind::ActionExecute, Kind::AgentMessage, Kind::AgentRelay],
            },
        )?;
        let what = format!(
            "step 4/7 delegation: let agent `{}` send messages for 7 days",
            identity.principal
        );
        let envelope = flow::approve(deps, pin, &what, &event, None)?;
        put_json(engine, "grant", &envelope)?;
        state = "completed";
    }
    Ok(state)
}

/// Human approval of one exact membership request, then the owner's
/// `action.execute` bound to it.
#[allow(clippy::too_many_arguments)]
fn authorize(
    deps: &mut Deps<'_>,
    pin: &Pin,
    owner: &mut Engine,
    what: &str,
    action: &str,
    epoch: u64,
    audience: Vec<String>,
    parameters: Value,
    key_package: Option<&[u8]>,
) -> Result<Control, Failure> {
    let now = deps.clock.now();
    let (grant, _) = flow::grant(owner, now)?;
    let request = serde_json::to_string(&json!({
        "version": 1, "project": pin.project_id, "action": action, "performer": OWNER,
        "group": GROUP, "epoch": epoch, "audience": audience, "parameters": parameters,
    }))
    .map_err(|_| Failure::new("internal", "cannot encode the action request"))?;
    yhes_actions::Request::parse(request.as_bytes())
        .map_err(|_| Failure::new("internal", "the drafted action request is invalid"))?;
    let request_digest = Digest::of(request.as_bytes());
    let authorization = flow::human_event(
        pin,
        format!("approve-{action}-{}", short_id()),
        now,
        AUTHORIZATION_LIFETIME,
        audience.clone(),
        Some(epoch),
        Body::ActionAuthorization {
            action: action.into(),
            request_digest,
            performer: OWNER.into(),
        },
    )?;
    let signed = flow::approve(deps, pin, what, &authorization, Some(request.as_bytes()))?;
    let now = deps.clock.now();
    let execute = flow::agent_event(
        owner,
        pin,
        format!("execute-{action}-{}", short_id()),
        &grant,
        now,
        authorization.expires_at.max(now),
        audience,
        epoch,
        Body::ActionExecute {
            action: action.into(),
            request_digest,
            authorization: flow::event_digest(&signed)?,
        },
    )?;
    let content = owner
        .sign_event(execute, Some(grant), Some(signed), None, now)
        .map_err(|e| {
            Failure::from(e).hint(
                "The approval may have expired (5 minutes). Run `yhes pilot` again for a new one.",
            )
        })?;
    Ok(Control {
        content,
        request,
        key_package: key_package.map(|bytes| STANDARD.encode(bytes)),
    })
}

fn publish(
    channel: &LocalChannel,
    owner: &mut Engine,
    operation: &str,
    now: u64,
) -> Result<(), Failure> {
    channel
        .publish(owner, operation, now)
        .map(|_| ())
        .map_err(|e| {
            Failure::from(e).hint(
                "A membership change is prepared but not published. If its 5-minute approval has \
             expired it needs an explicit recovery decision; it is not retried with a new time.",
            )
        })
}

/// Both profiles read a membership record as soon as it is published, while
/// its five-minute approval is current. The next human review can then take
/// its time without stranding either vault behind an expired record.
fn settle(
    deps: &Deps<'_>,
    channel: &LocalChannel,
    owner: &mut Engine,
    member: &mut Engine,
) -> Result<(), Failure> {
    for engine in [owner, member] {
        channel.sync(engine, GROUP, OWNER, deps.clock.now())?;
    }
    Ok(())
}

/// `create_group` or `change_membership`.
type Apply = dyn Fn(&mut Engine, &str, Control, u64) -> yhes_core::Result<Vec<u8>>;

/// Stage a membership control, reusing a stored approved one after a restart.
fn stage(
    owner: &mut Engine,
    name: &str,
    now: u64,
    apply: &Apply,
    fresh: &mut dyn FnMut(&mut Engine) -> Result<Control, Failure>,
) -> Result<String, Failure> {
    if let Some(stored) = get_json::<Staged>(owner, name)? {
        if apply(owner, &stored.operation, stored.control, now).is_ok() {
            return Ok(stored.operation);
        }
    }
    let staged = Staged {
        operation: format!("pilot-{name}-{}", short_id()),
        control: fresh(owner)?,
    };
    // Stored before use: a crash after this point needs no second approval.
    put_json(owner, name, &staged)?;
    apply(owner, &staged.operation, staged.control, now)?;
    Ok(staged.operation)
}

fn group_stages(
    deps: &mut Deps<'_>,
    pin: &Pin,
    channel: &LocalChannel,
    owner: &mut Engine,
    member: &mut Engine,
) -> Result<[&'static str; 3], Failure> {
    let mut states = ["already-done"; 3];
    let joined_before = member.group_status(GROUP)?.is_some_and(|s| s.active);
    let pending = |owner: &mut Engine| -> Result<Option<String>, Failure> {
        Ok(owner.group_status(GROUP)?.and_then(|s| s.pending_operation))
    };
    if let Some(operation) = pending(owner)? {
        deps.say("publishing a membership change left over from an earlier run");
        publish(channel, owner, &operation, deps.clock.now())?;
        settle(deps, channel, owner, member)?;
    }
    if owner.group_status(GROUP)?.is_none() {
        let now = deps.clock.now();
        let operation = stage(
            owner,
            "create",
            now,
            &|e, op, control, now| e.create_group(op, control, now),
            &mut |owner| {
                authorize(
                    deps,
                    pin,
                    owner,
                    "step 5/7 group: create group `team` owned by agent `codex`",
                    "group.create",
                    0,
                    vec![OWNER.into()],
                    json!({}),
                    None,
                )
            },
        )?;
        publish(channel, owner, &operation, deps.clock.now())?;
        settle(deps, channel, owner, member)?;
        states[0] = "completed";
    }
    let status = owner
        .group_status(GROUP)?
        .ok_or_else(|| Failure::new("internal", "group missing after creation"))?;
    if !status.audience.iter().any(|a| a == MEMBER) {
        let now = deps.clock.now();
        let package = member.key_package("pilot-kp-claude", now)?;
        let identity = member.identity()?;
        let mut audience = status.audience.clone();
        audience.push(MEMBER.into());
        audience.sort();
        let parameters = json!({
            "member": MEMBER, "key_id": identity.key_id,
            "key_package_digest": Digest::of(&package).to_hex(),
        });
        let operation = stage(
            owner,
            "add",
            now,
            &|e, op, control, now| e.change_membership(op, control, now),
            &mut |owner| {
                authorize(
                    deps,
                    pin,
                    owner,
                    "step 6/7 group: add agent `claude` to group `team`",
                    "group.add",
                    status.epoch,
                    audience.clone(),
                    parameters.clone(),
                    Some(&package),
                )
            },
        )?;
        publish(channel, owner, &operation, deps.clock.now())?;
        settle(deps, channel, owner, member)?;
        states[1] = "completed";
    }
    // Normally the member joined while settling the add; this covers a rerun
    // that was interrupted between publication and that read.
    if !member.group_status(GROUP)?.is_some_and(|s| s.active) {
        deps.say("step 7/7 join: agent `claude` reads the log and joins the group");
        channel.sync(member, GROUP, OWNER, deps.clock.now())?;
        if !member.group_status(GROUP)?.is_some_and(|s| s.active) {
            return Err(Failure::new(
                "join_incomplete",
                "agent `claude` could not join from the published invitation",
            )
            .hint("Run `yhes doctor --project PATH` for the failing check."));
        }
    }
    if !joined_before {
        states[2] = "completed";
    }
    Ok(states)
}

pub fn run(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let ws = Workspace::locate(
        &deps.private_root,
        &PathBuf::from(args.need("--project")?),
        true,
    )?;
    let (pin, identity) = identity_stage(args, deps, &ws)?;

    let fresh = AGENTS.iter().any(|agent| !ws.vault_exists(agent));
    if fresh {
        deps.say("step 2/7 vaults: creating protected vaults for agents `codex` and `claude`");
    }
    // Index 0 is the owner (`codex`), index 1 the invited member (`claude`).
    let mut engines = [
        open_profile(&ws, &pin, OWNER, deps.custody, true)?,
        open_profile(&ws, &pin, MEMBER, deps.custody, true)?,
    ];
    let vaults = if fresh { "completed" } else { "already-done" };

    let (registry, chain) = registry_stage(deps, &ws, &pin, &mut engines)?;
    let delegations = delegation_stage(deps, &pin, &mut engines)?;

    let channel = LocalChannel::open(&ws.project_root, &pin.project_id)?;
    let [owner, member] = &mut engines;
    let [create, add, join] = group_stages(deps, &pin, &channel, owner, member)?;

    let status = owner.group_status(GROUP)?;
    let member_status = member.group_status(GROUP)?;
    let ready = status
        .as_ref()
        .zip(member_status.as_ref())
        .is_some_and(|(a, b)| {
            a.active
                && b.active
                && a.pending_operation.is_none()
                && b.pending_operation.is_none()
                && a.id == GROUP
                && b.id == GROUP
                && a.owner == OWNER
                && b.owner == OWNER
                && a.epoch == b.epoch
                && a.last_commit == b.last_commit
                && a.audience == AGENTS.map(str::to_owned)
                && b.audience == a.audience
        });
    if !ready {
        return Err(Failure::new(
            "setup_incomplete",
            "both profiles have not reached the same ready channel",
        )
        .hint("Resume setup to synchronize the saved state. No keys will be replaced."));
    }
    let now = deps.clock.now();
    let head = chain.last().map(String::as_str).unwrap_or_default();
    let mut profiles = Vec::new();
    let mut delegations_expire = None::<u64>;
    for engine in engines.iter_mut() {
        let id = engine.identity()?;
        let (_, grant) = flow::grant(engine, now)?;
        delegations_expire =
            Some(delegations_expire.map_or(grant.expires_at, |e| e.min(grant.expires_at)));
        profiles.push(json!({"agent": id.principal, "key_id": id.key_id,
            "key_custody": deps.custody.label(), "delegation_expires_at": grant.expires_at}));
    }
    deps.say("pilot is ready: `yhes send --project PATH --as codex --text ...`");
    Ok(json!({
        "command": "pilot",
        "ready": true,
        "project_id": pin.project_id,
        "human": pin.human,
        "authority_key_id": pin.authority.key_id,
        "ghes": null,
        "stages": {"identity": identity, "vaults": vaults, "registry": registry,
            "delegations": delegations, "group_create": create, "group_add": add, "join": join},
        "group": status,
        "profiles": profiles,
        "registry": {"generation": registry_field(head, "generation"),
            "expires_at": registry_field(head, "expires_at")},
        "renew_before": delegations_expire
            .into_iter()
            .chain(registry_field(head, "expires_at"))
            .min(),
    }))
}
