use super::{
    config::{self, TeamPin, TeamSession, DEFAULT_BRANCH, GROUP},
    registry, rejected,
};
use crate::{
    flow::{self, get_json, put_json, short_id, RENEW_MARGIN, WEEK},
    profile,
    signer::{self, Descriptor, Mode},
    Args, Deps, Failure,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use yhes_core::{
    engine::{Engine, PublicIdentity},
    Control,
};
use yhes_wire::{
    Body, Digest, Envelope, Event, KeyId, Kind, ParticipantKind, Registry, REGISTRY_PAYLOAD_TYPE,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    version: u8,
    project: String,
    authority: Descriptor,
    agent: PublicIdentity,
    registry: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    version: u8,
    project: String,
    human: Descriptor,
    agent: PublicIdentity,
    registry: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    version: u8,
    project: String,
    group: String,
    principal: String,
    key_id: String,
    key_package: String,
}
#[derive(Serialize, Deserialize)]
struct Staged {
    operation: String,
    control: Control,
}

fn identity(args: &Args, deps: &mut Deps<'_>) -> Result<Descriptor, Failure> {
    let human = args.need("--human")?;
    let project = args.need("--project-id")?;
    let agent = args.need("--as")?;
    if !profile::valid_id(human)
        || !profile::valid_id(project)
        || !profile::agent_name(agent)
        || human == agent
    {
        return Err(Failure::new(
            "usage",
            "use distinct human and agent identifiers; agents are at most 32 safe characters",
        ));
    }
    deps.say("team identity: checking this person's native signing key");
    match signer::identity(deps.signer, human, project)? {
        Some(d) => Ok(d),
        None => {
            deps.say("approve this person's key setup in YhesSigner");
            signer::enroll(deps.signer, human, project)
        }
    }
}
fn check_args(args: &Args, pin: &TeamPin, founder: bool) -> Result<(), Failure> {
    if args.need("--human")? != pin.human.author
        || args.need("--as")? != pin.principal
        || args.need("--project-id")? != pin.project_id
        || args.need("--remote")? != pin.remote
        || args.get("--branch").unwrap_or(DEFAULT_BRANCH) != pin.branch
        || config::options(args)? != pin.git_options
        || (founder && (pin.human != pin.authority || pin.owner != pin.principal))
        || (!founder && args.need("--authority")? != pin.authority.key_id)
        || (!founder && Some(args.need("--bootstrap")?) != pin.bootstrap_head.as_deref())
    {
        return Err(Failure::new(
            "team_pin_mismatch",
            "these setup arguments differ from the existing team configuration",
        ));
    }
    Ok(())
}
fn result(session: &TeamSession, command: &str, state: &str, next: &str) -> Value {
    json!({"command":command,"state":state,"next":next,"project":session.pin.project_id,
        "as":session.pin.principal,"human":session.pin.human.author,"human_key":session.pin.human.key_id,
        "authority":session.pin.authority.key_id,"bootstrap_head":session.pin.bootstrap_head,
        "group":session.pin.group,"owner":session.pin.owner,"ghes":null})
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Failure> {
    serde_json::to_vec(value).map_err(|_| rejected())
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Failure> {
    serde_json::from_slice(bytes).map_err(|_| rejected())
}
fn review_registry(
    deps: &mut Deps<'_>,
    signer: &Descriptor,
    payload: &Value,
) -> Result<String, Failure> {
    deps.say("review the complete registry and keys in YhesSigner; approve with Touch ID");
    signer::review(deps.signer, signer, Mode::Registry, &encode(payload)?, None)
}
pub fn init(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let ws = config::locate(args, deps, true)?;
    let pin = if let Some(pin) = config::read(&ws)? {
        check_args(args, &pin, true)?;
        pin
    } else {
        // Refuse to initialize over an existing team before asking for keys.
        let remote = args.need("--remote")?;
        let project = args.need("--project-id")?;
        let channel = yhes_core::git::GitChannel::open_with_options(
            &config::directory(&ws).join("git"),
            remote,
            args.get("--branch").unwrap_or(DEFAULT_BRANCH),
            project,
            config::options(args)?,
        )?;
        let snapshot = channel.fetch_public()?;
        if snapshot.head.is_some() {
            return Err(Failure::new(
                "team_exists",
                "this team branch already exists; request enrollment instead",
            ));
        }
        let human = identity(args, deps)?;
        let pin = TeamPin {
            version: 1,
            project_id: project.into(),
            project_path: ws.project_root.to_string_lossy().into_owned(),
            remote: remote.into(),
            branch: args.get("--branch").unwrap_or(DEFAULT_BRANCH).into(),
            git_options: config::options(args)?,
            group: GROUP.into(),
            owner: args.need("--as")?.into(),
            principal: args.need("--as")?.into(),
            authority: human.clone(),
            human,
            bootstrap_head: None,
        };
        config::write(&ws, &pin)?;
        pin
    };
    let engine = config::engine(&ws, &pin, deps.custody, true)?;
    let channel = config::channel(&ws, &pin)?;
    let mut session = TeamSession {
        ws,
        pin,
        engine,
        channel,
    };
    let agent = session.engine.identity()?;
    let signed: String = match get_json(&mut session.engine, "team-registry-first")? {
        Some(signed) => signed,
        None => {
            let payload = registry::single(
                &session.pin.project_id,
                &session.pin.human,
                &agent,
                deps.clock.now(),
            );
            let signed = review_registry(deps, &session.pin.authority, &payload)?;
            put_json(&mut session.engine, "team-registry-first", &signed)?;
            signed
        }
    };
    registry::proposal(
        signed.as_bytes(),
        &session.pin.human,
        &agent,
        deps.clock.now(),
    )?;
    if session.engine.registry_chain()?.is_empty() {
        let digest = Envelope::parse(signed.as_bytes(), REGISTRY_PAYLOAD_TYPE)
            .map_err(|_| rejected())?
            .digest();
        session
            .engine
            .bootstrap_registry(&[signed.as_bytes()], digest, deps.clock.now())?;
    }
    session.channel.publish_public_checked(
        &mut session.engine,
        "registry-1.json",
        signed.as_bytes(),
    )?;
    let head = Envelope::parse(signed.as_bytes(), REGISTRY_PAYLOAD_TYPE)
        .map_err(|_| rejected())?
        .digest()
        .to_hex();
    let bootstrap = Bootstrap {
        version: 1,
        project: session.pin.project_id.clone(),
        authority: session.pin.authority.clone(),
        agent,
        registry: signed,
    };
    session.channel.publish_public_checked(
        &mut session.engine,
        "bootstrap.json",
        &encode(&bootstrap)?,
    )?;
    let mut output=result(&session,"team-init","waiting-for-request","Share the project ID, authority fingerprint and bootstrap_head digest out of band. The peer supplies all three to team-request; then run team-admit with their checked human fingerprint.");
    output["bootstrap_head"] = json!(head);
    Ok(output)
}

pub fn request(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let ws = config::locate(args, deps, true)?;
    let pin = if let Some(pin) = config::read(&ws)? {
        check_args(args, &pin, false)?;
        pin
    } else {
        let project = args.need("--project-id")?;
        let expected = args.need("--authority")?;
        let expected_head = Digest::from_hex(args.need("--bootstrap")?).map_err(|_| {
            Failure::new(
                "usage",
                "--bootstrap must be the full independently checked registry digest",
            )
        })?;
        KeyId::parse(expected).map_err(|_| {
            Failure::new(
                "usage",
                "--authority must be the full independently checked key fingerprint",
            )
        })?;
        let channel = yhes_core::git::GitChannel::open_with_options(
            &config::directory(&ws).join("git"),
            args.need("--remote")?,
            args.get("--branch").unwrap_or(DEFAULT_BRANCH),
            project,
            config::options(args)?,
        )?;
        let snapshot = channel.fetch_public()?;
        let bootstrap: Bootstrap = decode(
            snapshot
                .artifacts
                .get("bootstrap.json")
                .ok_or_else(rejected)?,
        )?;
        if bootstrap.version != 1
            || bootstrap.project != project
            || bootstrap.authority.project != project
            || bootstrap.authority.key_id != expected
            || snapshot.artifacts.get("registry-1.json").map(Vec::as_slice)
                != Some(bootstrap.registry.as_bytes())
        {
            return Err(rejected());
        }
        registry::proposal(
            bootstrap.registry.as_bytes(),
            &bootstrap.authority,
            &bootstrap.agent,
            deps.clock.now(),
        )?;
        let head = Envelope::parse(bootstrap.registry.as_bytes(), REGISTRY_PAYLOAD_TYPE)
            .map_err(|_| rejected())?
            .digest();
        if head != expected_head {
            return Err(rejected());
        }
        let doc = registry::document(bootstrap.registry.as_bytes())?;
        if doc["participants"].as_array().unwrap().iter().any(|p| {
            p["id"] == args.need("--as").unwrap_or_default()
                || p["id"] == args.need("--human").unwrap_or_default()
        }) {
            return Err(rejected());
        }
        let human = identity(args, deps)?;
        if human.key_id == bootstrap.authority.key_id {
            return Err(rejected());
        }
        let pin = TeamPin {
            version: 1,
            project_id: project.into(),
            project_path: ws.project_root.to_string_lossy().into_owned(),
            remote: args.need("--remote")?.into(),
            branch: args.get("--branch").unwrap_or(DEFAULT_BRANCH).into(),
            git_options: config::options(args)?,
            group: GROUP.into(),
            owner: bootstrap.agent.principal,
            principal: args.need("--as")?.into(),
            human,
            authority: bootstrap.authority,
            bootstrap_head: Some(expected_head.to_hex()),
        };
        config::write(&ws, &pin)?;
        pin
    };
    let engine = config::engine(&ws, &pin, deps.custody, true)?;
    let channel = config::channel(&ws, &pin)?;
    let mut session = TeamSession {
        ws,
        pin,
        engine,
        channel,
    };
    let snapshot = session.channel.fetch_public_checked(&mut session.engine)?;
    registry::install(&mut session, &snapshot, deps.clock.now())?;
    let agent = session.engine.identity()?;
    let signed = match get_json::<String>(&mut session.engine, "team-request")? {
        Some(signed) => signed,
        None => {
            let payload = registry::single(
                &session.pin.project_id,
                &session.pin.human,
                &agent,
                deps.clock.now(),
            );
            let signed = review_registry(deps, &session.pin.human, &payload)?;
            put_json(&mut session.engine, "team-request", &signed)?;
            signed
        }
    };
    registry::proposal(
        signed.as_bytes(),
        &session.pin.human,
        &agent,
        deps.clock.now(),
    )?;
    let proposal = Enrollment {
        version: 1,
        project: session.pin.project_id.clone(),
        human: session.pin.human.clone(),
        agent,
        registry: signed,
    };
    session.channel.publish_public_checked(
        &mut session.engine,
        &format!("request-{}.json", session.pin.principal),
        &encode(&proposal)?,
    )?;
    Ok(result(&session,"team-request","waiting-for-admission","Send your human fingerprint to the founder out of band. After admission, run team-connect while both people are online."))
}

pub fn admit(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let mut session = config::open(args, deps)?;
    if session.pin.human != session.pin.authority || session.pin.principal != session.pin.owner {
        return Err(rejected());
    }
    let peer = args.need("--peer")?;
    if !profile::agent_name(peer) {
        return Err(rejected());
    }
    let expected = args.need("--peer-key")?;
    KeyId::parse(expected).map_err(|_| rejected())?;
    let snapshot = session.channel.fetch_public_checked(&mut session.engine)?;
    let current = registry::install(&mut session, &snapshot, deps.clock.now())?;
    let proposal: Enrollment = decode(
        snapshot
            .artifacts
            .get(&format!("request-{peer}.json"))
            .ok_or_else(rejected)?,
    )?;
    if proposal.version != 1
        || proposal.project != session.pin.project_id
        || proposal.human.project != session.pin.project_id
        || proposal.agent.principal != peer
        || proposal.human.key_id != expected
        || proposal.human.key_id == session.pin.authority.key_id
    {
        return Err(rejected());
    }
    let proposed = registry::proposal(
        proposal.registry.as_bytes(),
        &proposal.human,
        &proposal.agent,
        deps.clock.now(),
    )?;
    if let Some(existing) = current.participant(peer) {
        let id = KeyId::parse(&proposal.agent.key_id).map_err(|_| rejected())?;
        if existing.kind != ParticipantKind::Agent
            || existing.controller.as_deref() != Some(&proposal.human.author)
            || current.active_key(peer, &id, deps.clock.now()).is_err()
            || current
                .active_key(
                    &proposal.human.author,
                    &proposal.human.key_id()?,
                    deps.clock.now(),
                )
                .is_err()
        {
            return Err(rejected());
        }
        return Ok(result(
            &session,
            "team-admit",
            "admitted",
            "Both people now run team-connect.",
        ));
    }
    if current.participants().count() != 2 || current.participant(&proposal.human.author).is_some()
    {
        return Err(rejected());
    }
    let head = session.engine.registry_head()?.ok_or_else(rejected)?;
    let mut merged = registry::document(&head)?;
    for name in ["participants", "keys"] {
        let list = merged[name].as_array_mut().ok_or_else(rejected)?;
        let key = if name == "keys" { "key_id" } else { "id" };
        for item in proposed[name].as_array().ok_or_else(rejected)? {
            if list.iter().any(|old| old[key] == item[key]) {
                return Err(rejected());
            }
            list.push(item.clone());
        }
        list.sort_by_key(|v| v[key].as_str().unwrap_or_default().to_owned());
    }
    merged["generation"] = json!(current.generation() + 1);
    merged["previous"] = json!(current.digest().to_hex());
    merged["issued_at"] = json!(deps.clock.now());
    merged["expires_at"] = json!(deps.clock.now() + WEEK);
    // Exact approved output survives interrupted publication; never silently
    // replace a stored approval with a newly signed proposal.
    let staged: Option<String> = get_json(&mut session.engine, "team-registry-admit")?;
    let signed = if let Some(signed) = staged {
        let doc = registry::document(signed.as_bytes())?;
        if doc["participants"] != merged["participants"]
            || doc["keys"] != merged["keys"]
            || doc["generation"] != merged["generation"]
            || doc["previous"] != merged["previous"]
        {
            return Err(rejected());
        }
        signed
    } else {
        let signed = review_registry(deps, &session.pin.authority, &merged)?;
        put_json(&mut session.engine, "team-registry-admit", &signed)?;
        signed
    };
    // Verify freshness before publication as well as installation.
    Registry::verify(
        signed.as_bytes(),
        &registry::anchors(&session.pin.project_id, &session.pin.authority)?,
        Some(&current.checkpoint()),
        &yhes_wire::Policy::default(),
        deps.clock.now(),
    )
    .map_err(|_| rejected())?;
    session.channel.publish_public_checked(
        &mut session.engine,
        &format!("registry-{}.json", current.generation() + 1),
        signed.as_bytes(),
    )?;
    session
        .engine
        .install_registry(signed.as_bytes(), deps.clock.now())?;
    Ok(result(
        &session,
        "team-admit",
        "admitted",
        "Both people now run team-connect. The peer publishes their stable KeyPackage first.",
    ))
}

pub(super) fn human_event(
    pin: &TeamPin,
    now: u64,
    lifetime: u64,
    audience: Vec<String>,
    epoch: Option<u64>,
    body: Body,
) -> Result<Event, Failure> {
    Ok(Event {
        id: format!("team-human-{}", short_id()),
        project: pin.project_id.clone(),
        author: pin.human.author.clone(),
        key_id: pin.human.key_id()?,
        session: None,
        issued_at: now,
        expires_at: now + lifetime,
        audience,
        group: Some(pin.group.clone()),
        epoch,
        previous: None,
        body,
    })
}
pub(super) fn approve(
    deps: &mut Deps<'_>,
    pin: &TeamPin,
    event: &Event,
    sidecar: Option<&[u8]>,
) -> Result<String, Failure> {
    deps.say("review the exact event and audience in YhesSigner; approve with Touch ID");
    signer::review(
        deps.signer,
        &pin.human,
        Mode::Event,
        &event.to_payload().map_err(|_| rejected())?,
        sidecar,
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn agent_event(
    engine: &mut Engine,
    pin: &TeamPin,
    grant: &str,
    now: u64,
    expires: u64,
    audience: Vec<String>,
    epoch: u64,
    body: Body,
) -> Result<Event, Failure> {
    let identity = engine.identity()?;
    Ok(Event {
        id: format!("team-agent-{}", short_id()),
        project: pin.project_id.clone(),
        author: pin.principal.clone(),
        key_id: KeyId::parse(&identity.key_id).map_err(|_| rejected())?,
        session: Some(flow::event_digest(grant)?),
        issued_at: now,
        expires_at: expires,
        audience,
        group: Some(pin.group.clone()),
        epoch: Some(epoch),
        previous: None,
        body,
    })
}
fn delegate(
    session: &mut TeamSession,
    deps: &mut Deps<'_>,
    audience: &[String],
) -> Result<(), Failure> {
    let now = deps.clock.now();
    let identity = session.engine.identity()?;
    if get_json::<String>(&mut session.engine, "grant")?
        .as_deref()
        .and_then(flow::parse_event)
        .is_some_and(|e| {
            e.expires_at > now + RENEW_MARGIN
                && e.audience == audience
                && matches!(e.body,Body::AgentDelegation{agent,agent_key_id,..}
        if agent == identity.principal && agent_key_id.as_str() == identity.key_id)
        })
    {
        return Ok(());
    }
    let event = human_event(
        &session.pin,
        now,
        WEEK,
        audience.to_vec(),
        None,
        Body::AgentDelegation {
            agent: identity.principal,
            agent_key_id: KeyId::parse(&identity.key_id).map_err(|_| rejected())?,
            purposes: vec![Kind::ActionExecute, Kind::AgentMessage, Kind::AgentRelay],
        },
    )?;
    let signed = approve(deps, &session.pin, &event, None)?;
    put_json(&mut session.engine, "grant", &signed)
}
/// Native approval and the immutable agent execution draft are checkpointed
/// before signing/staging changes MLS state.
#[derive(Serialize, Deserialize)]
struct ApprovedControl {
    operation: String,
    request: String,
    authorization: String,
    grant: String,
    execute: String,
    key_package: Option<String>,
}
#[allow(clippy::too_many_arguments)]
fn control(
    session: &mut TeamSession,
    deps: &mut Deps<'_>,
    name: &str,
    epoch: u64,
    audience: Vec<String>,
    parameters: Value,
    kp: Option<&[u8]>,
) -> Result<Staged, Failure> {
    let action = format!("group.{name}");
    let request=serde_json::to_string(&json!({"version":1,"project":session.pin.project_id,"action":action,"performer":session.pin.owner,
        "group":session.pin.group,"epoch":epoch,"audience":audience,"parameters":parameters})).map_err(|_|rejected())?;
    yhes_actions::Request::parse(request.as_bytes()).map_err(|_| rejected())?;
    let checkpoint = format!("team-approved-{name}");
    let approved = match get_json::<ApprovedControl>(&mut session.engine, &checkpoint)? {
        Some(approved) => {
            if approved.request != request || approved.key_package != kp.map(|b| STANDARD.encode(b))
            {
                return Err(rejected());
            }
            approved
        }
        None => {
            let now = deps.clock.now();
            let (grant, _) = flow::grant(&mut session.engine, now)?;
            let digest = Digest::of(request.as_bytes());
            let authorization = human_event(
                &session.pin,
                now,
                300,
                audience.clone(),
                Some(epoch),
                Body::ActionAuthorization {
                    action: action.clone(),
                    request_digest: digest,
                    performer: session.pin.owner.clone(),
                },
            )?;
            let signed = approve(deps, &session.pin, &authorization, Some(request.as_bytes()))?;
            let execute = agent_event(
                &mut session.engine,
                &session.pin,
                &grant,
                deps.clock.now(),
                authorization.expires_at,
                audience,
                epoch,
                Body::ActionExecute {
                    action,
                    request_digest: digest,
                    authorization: flow::event_digest(&signed)?,
                },
            )?;
            let approved = ApprovedControl {
                operation: format!("team-{name}-{}", short_id()),
                request,
                authorization: signed,
                grant,
                execute: String::from_utf8(execute.to_payload().map_err(|_| rejected())?)
                    .map_err(|_| rejected())?,
                key_package: kp.map(|b| STANDARD.encode(b)),
            };
            put_json(&mut session.engine, &checkpoint, &approved)?;
            approved
        }
    };
    let execute = Event::parse(approved.execute.as_bytes()).map_err(|_| rejected())?;
    Ok(Staged {
        operation: approved.operation,
        control: Control {
            content: session.engine.sign_event(
                execute,
                Some(approved.grant),
                Some(approved.authorization),
                None,
                deps.clock.now(),
            )?,
            request: approved.request,
            key_package: approved.key_package,
        },
    })
}

fn membership(
    session: &mut TeamSession,
    deps: &mut Deps<'_>,
    name: &str,
    epoch: u64,
    audience: Vec<String>,
    parameters: Value,
    kp: Option<&[u8]>,
) -> Result<(), Failure> {
    let checkpoint = format!("team-control-{name}");
    let staged = match get_json::<Staged>(&mut session.engine, &checkpoint)? {
        Some(staged) => staged,
        None => {
            let staged = control(session, deps, name, epoch, audience, parameters, kp)?;
            put_json(&mut session.engine, &checkpoint, &staged)?;
            staged
        }
    };
    let now = deps.clock.now();
    if name == "create" {
        session
            .engine
            .create_group(&staged.operation, staged.control, now)?;
    } else {
        session
            .engine
            .change_membership(&staged.operation, staged.control, now)?;
    }
    session.channel.publish(&mut session.engine,&staged.operation,deps.clock.now()).map_err(|e|Failure::from(e).hint(
        "Membership is checkpointed. Retry team-connect. Expired unseen membership requires explicit recovery; timestamps and approvals are never renewed silently."))?;
    Ok(())
}

pub fn connect(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let mut session = config::open(args, deps)?;
    let snapshot = session.channel.fetch_public_checked(&mut session.engine)?;
    let registry = registry::install(&mut session, &snapshot, deps.clock.now())?;
    let identity = session.engine.identity()?;
    let own = registry.participant(&session.pin.principal);
    if own.is_none() {
        return Ok(result(
            &session,
            "team-connect",
            "waiting-for-admission",
            "The founder must run team-admit with your independently checked human fingerprint.",
        ));
    }
    let own = own.unwrap();
    if own.kind != ParticipantKind::Agent
        || own.controller.as_deref() != Some(&session.pin.human.author)
        || registry
            .active_key(
                &session.pin.principal,
                &KeyId::parse(&identity.key_id).map_err(|_| rejected())?,
                deps.clock.now(),
            )
            .is_err()
        || registry
            .active_key(
                &session.pin.human.author,
                &session.pin.human.key_id()?,
                deps.clock.now(),
            )
            .is_err()
    {
        return Err(rejected());
    }
    let audience: Vec<String> = registry
        .participants()
        .filter(|p| p.kind == ParticipantKind::Agent)
        .map(|p| p.id.clone())
        .collect();
    if audience.len() != 2 {
        return Ok(result(
            &session,
            "team-connect",
            "waiting-for-admission",
            "Admit one other person's agent before creating the group.",
        ));
    }
    if session.pin.principal != session.pin.owner {
        delegate(&mut session, deps, &audience)?;
        let kp = session
            .engine
            .key_package("team-key-package", deps.clock.now())?;
        let descriptor = Package {
            version: 1,
            project: session.pin.project_id.clone(),
            group: session.pin.group.clone(),
            principal: identity.principal,
            key_id: identity.key_id,
            key_package: STANDARD.encode(kp),
        };
        session.channel.publish_public_checked(
            &mut session.engine,
            &format!("key-package-{}.json", session.pin.principal),
            &encode(&descriptor)?,
        )?;
        session.channel.sync(
            &mut session.engine,
            &session.pin.group,
            &session.pin.owner,
            deps.clock.now(),
        ).map_err(|error| Failure::from(error).hint(
            "First join requires both people online within five minutes of group creation. If unseen membership expired, preserve this state for explicit recovery; do not change timestamps or delete the vault."))?;
    } else {
        let peer = audience
            .iter()
            .find(|p| **p != session.pin.owner)
            .ok_or_else(rejected)?
            .clone();
        let Some(bytes) = snapshot.artifacts.get(&format!("key-package-{peer}.json")) else {
            return Ok(result(
                &session,
                "team-connect",
                "waiting-for-key-package",
                "The peer runs team-connect first. Then run this command with both people online.",
            ));
        };
        let package: Package = decode(bytes)?;
        if package.version != 1
            || package.project != session.pin.project_id
            || package.group != session.pin.group
            || package.principal != peer
        {
            return Err(rejected());
        }
        let kp = STANDARD
            .decode(&package.key_package)
            .map_err(|_| rejected())?;
        if STANDARD.encode(&kp) != package.key_package {
            return Err(rejected());
        }
        let candidate = session.engine.inspect_key_package(&kp, deps.clock.now())?;
        if candidate.principal != peer || candidate.key_id != package.key_id {
            return Err(rejected());
        }
        delegate(&mut session, deps, &audience)?;
        session.channel.sync(
            &mut session.engine,
            &session.pin.group,
            &session.pin.owner,
            deps.clock.now(),
        ).map_err(|error| Failure::from(error).hint(
            "First join requires both people online within five minutes of group creation. If unseen membership expired, preserve this state for explicit recovery; do not change timestamps or delete the vault."))?;
        if let Some(pending) = session
            .engine
            .group_status(&session.pin.group)?
            .and_then(|s| s.pending_operation)
        {
            session
                .channel
                .publish(&mut session.engine, &pending, deps.clock.now())?;
        }
        if session.engine.group_status(&session.pin.group)?.is_none() {
            let owner = session.pin.owner.clone();
            membership(
                &mut session,
                deps,
                "create",
                0,
                vec![owner],
                json!({}),
                None,
            )?;
        }
        let status = session
            .engine
            .group_status(&session.pin.group)?
            .ok_or_else(rejected)?;
        if !status.audience.contains(&peer) {
            membership(
                &mut session,
                deps,
                "add",
                status.epoch,
                audience.clone(),
                json!({"member":peer,"key_id":package.key_id,
                "key_package_digest":Digest::of(&kp).to_hex()}),
                Some(&kp),
            )?;
        }
        session.channel.sync(
            &mut session.engine,
            &session.pin.group,
            &session.pin.owner,
            deps.clock.now(),
        ).map_err(|error| Failure::from(error).hint(
            "First join requires both people online within five minutes of group creation. If unseen membership expired, preserve this state for explicit recovery; do not change timestamps or delete the vault."))?;
    }
    let status = session.engine.group_status(&session.pin.group)?;
    if status
        .as_ref()
        .is_some_and(|s| s.active && s.pending_operation.is_none() && s.audience == audience)
    {
        let mut value = result(
            &session,
            "team-connect",
            "ready",
            if session.pin.principal == session.pin.owner {
                "Your profile is ready. The peer must run team-connect within five minutes of group creation; their readiness is not yet confirmed here."
            } else {
                "The group is ready for team-send and team-say."
            },
        );
        value["group_status"] = json!(status);
        return Ok(value);
    }
    Ok(result(&session,"team-connect","waiting-for-invitation","Keep both people online. The founder runs team-connect, then immediately run this command again within five minutes."))
}
