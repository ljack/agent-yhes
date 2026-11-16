use super::{
    config::{self, TeamSession},
    handshake::{agent_event, approve, human_event},
    registry, rejected,
};
use crate::{
    flow::{self, get_json, put_json, short_id, STATEMENT_LIFETIME, WEEK},
    Args, Deps, Failure,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Read;
use yhes_core::engine::Delivery;
use yhes_wire::{Body, Digest, Envelope, Event, EVENT_PAYLOAD_TYPE};
const AGENT_TEXT_BYTES: usize = 65_536;
const HUMAN_TEXT_BYTES: usize = 32_768;
#[derive(Serialize, Deserialize)]
struct OperationRecord {
    kind: String,
    input: String,
    original: Option<String>,
}
/// Exact ciphertext already persisted in the protected outbox. Publication
/// remains a Git adapter responsibility; a broker cannot acknowledge it.
pub struct PreparedMessage {
    pub result: Value,
    pub packet: Vec<u8>,
}
pub fn prepare_message(
    session: &mut TeamSession,
    deps: &mut Deps<'_>,
    human: bool,
    text: String,
    operation: &str,
) -> Result<PreparedMessage, Failure> {
    if text.trim().is_empty()
        || text.len()
            > if human {
                HUMAN_TEXT_BYTES
            } else {
                AGENT_TEXT_BYTES
            }
        || (human
            && text
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')))
    {
        return Err(Failure::new(
            "input",
            "the message text is empty, too large or contains forbidden controls",
        ));
    }
    let command = if human { "team-say" } else { "team-send" };
    let name = format!("op-{operation}");
    let input = Digest::of(format!("{command}\0{text}").as_bytes()).to_hex();
    let mut record = match get_json::<OperationRecord>(&mut session.engine, &name)? {
        Some(record) => {
            if record.kind != command || record.input != input {
                return Err(Failure::new(
                    "operation_conflict",
                    "this operation already names a different message",
                ));
            }
            record
        }
        None => {
            let record = OperationRecord {
                kind: command.into(),
                input,
                original: None,
            };
            put_json(&mut session.engine, &name, &record)?;
            record
        }
    };
    let human_author = human.then(|| session.pin.human.author.clone());
    let kind = if human {
        "agent.relay"
    } else {
        "agent.message"
    };
    if let Some(entry) = session
        .engine
        .outbox()?
        .into_iter()
        .find(|entry| entry.operation == operation)
    {
        return Ok(PreparedMessage {
            packet: session.engine.stored_packet(operation)?,
            result: json!({
            "command":command,"as":session.pin.principal,"operation":operation,"event_id":entry.event_id,
            "author":session.pin.principal,"kind":kind,"human_original_author":human_author,
            "human_authored":false,"group":entry.group,"epoch":entry.epoch,"replayed":true}),
        });
    }
    let group = session
        .engine
        .group_status(&session.pin.group)?
        .filter(|s| s.active && s.pending_operation.is_none() && s.audience.len() == 2)
        .ok_or_else(|| {
            Failure::new("team_not_ready", "run team-connect before sending messages")
        })?;
    let now = deps.clock.now();
    let (grant, grant_event) = flow::grant(&mut session.engine, now)?;
    let (body, expires) = if human {
        let original = if let Some(original) = record.original.take() {
            if !flow::parse_event(&original).is_some_and(|e| {
                e.expires_at > now && e.epoch == Some(group.epoch) && e.audience == group.audience
            }) {
                return Err(Failure::new(
                    "statement_expired",
                    "the approved statement expired or belongs to another epoch",
                )
                .hint("Use a new --operation and approve a new statement."));
            }
            original
        } else {
            let event = human_event(
                &session.pin,
                now,
                STATEMENT_LIFETIME,
                group.audience.clone(),
                Some(group.epoch),
                Body::HumanStatement { text },
            )?;
            let original = approve(deps, &session.pin, &event, None)?;
            record.original = Some(original.clone());
            put_json(&mut session.engine, &name, &record)?;
            original
        };
        let expires = flow::parse_event(&original)
            .ok_or_else(rejected)?
            .expires_at;
        let original =
            Envelope::parse(original.as_bytes(), EVENT_PAYLOAD_TYPE).map_err(|_| rejected())?;
        (
            Body::AgentRelay {
                original,
                note: None,
            },
            expires,
        )
    } else {
        (
            Body::AgentMessage { text },
            (now + WEEK).min(grant_event.expires_at),
        )
    };
    let now = deps.clock.now();
    let event = agent_event(
        &mut session.engine,
        &session.pin,
        &grant,
        now,
        expires,
        group.audience.clone(),
        group.epoch,
        body,
    )?;
    let id = event.id.clone();
    let content = session
        .engine
        .sign_event(event, Some(grant), None, None, now)?;
    let packet = session
        .engine
        .prepare_message(operation, &session.pin.group, content, now)?;
    Ok(PreparedMessage {
        packet,
        result: json!({"command":command,"as":session.pin.principal,"operation":operation,
        "event_id":id,"author":session.pin.principal,"kind":kind,"human_original_author":human_author,"human_authored":false,
        "group":session.pin.group,"epoch":group.epoch,"audience":group.audience,"receive_before":expires,"replayed":false}),
    })
}

pub fn send(
    args: &Args,
    stdin: &mut dyn Read,
    stdin_is_terminal: bool,
    deps: &mut Deps<'_>,
    human: bool,
) -> Result<Value, Failure> {
    let operation = operation_name(args, if human { "team-say" } else { "team-send" })?;
    let text = read_text(
        args,
        stdin,
        stdin_is_terminal,
        if human {
            HUMAN_TEXT_BYTES
        } else {
            AGENT_TEXT_BYTES
        },
    )?;
    let mut session = config::open(args, deps)?;
    registry::sync(&mut session, deps.clock.now())?;
    let prepared = prepare_message(&mut session, deps, human, text, &operation)?;
    let publication = session
        .channel
        .publish(&mut session.engine, &operation, deps.clock.now())?;
    let mut result = prepared.result;
    result["published"] = json!(publication);
    Ok(result)
}

pub fn inbox(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let mut session = config::open(args, deps)?;
    let mut fresh = Vec::new();
    if !args.flag("--no-sync") {
        for delivery in registry::sync(&mut session, deps.clock.now())?.deliveries {
            if let (false, Some(message)) = (delivery.replayed, delivery.message) {
                fresh.push((message.author, message.event_id));
            }
        }
        for entry in session.engine.outbox()? {
            if entry.kind == "application" && entry.status == "prepared" {
                session
                    .channel
                    .publish(&mut session.engine, &entry.operation, deps.clock.now())?;
            }
        }
    }
    let entries = session.engine.inbox()?;
    let shown: usize = get_json(&mut session.engine, "inbox-shown")?.unwrap_or(0);
    let mut messages = Vec::new();
    let mut quarantined = 0;
    for (index, entry) in entries.iter().enumerate() {
        if entry.delivery.disposition == "quarantined" {
            quarantined += 1;
        }
        if let Some(message) = &entry.delivery.message {
            let mut item = present(
                &entry.delivery,
                !fresh
                    .iter()
                    .any(|(a, id)| *a == message.author && *id == message.event_id),
            );
            item["new"] = json!(index >= shown);
            messages.push(item);
        }
    }
    if entries.len() != shown {
        put_json(&mut session.engine, "inbox-shown", &entries.len())?;
    }
    Ok(
        json!({"command":"team-inbox","as":session.pin.principal,"synced":!args.flag("--no-sync"),
        "new_messages":messages.iter().filter(|m|m["new"]==true).count(),"messages":messages,"quarantined":quarantined}),
    )
}

pub fn status(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let mut session = config::open(args, deps)?;
    let group = session.engine.group_status(&session.pin.group)?;
    Ok(
        json!({"command":"team-status","project":session.pin.project_id,"as":session.pin.principal,
        "human":session.pin.human.author,"human_key":session.pin.human.key_id,"authority":session.pin.authority.key_id,
        "remote":session.pin.remote,"branch":session.pin.branch,"group":group,"outbox":session.engine.outbox()?,
        "registry_generations":session.engine.registry_chain()?.len(),"key_custody":deps.custody.label(),"ghes":null}),
    )
}
fn read_text(
    args: &Args,
    stdin: &mut dyn Read,
    stdin_is_terminal: bool,
    limit: usize,
) -> Result<String, Failure> {
    let usage = |m: &str| {
        Failure::new("usage", m).hint("Give the text with --text, --body-file FILE or --stdin.")
    };
    let sources = usize::from(args.get("--text").is_some())
        + usize::from(args.get("--body-file").is_some())
        + usize::from(args.flag("--stdin"));
    if sources > 1 {
        return Err(usage("give the text in exactly one way"));
    }
    let too_large = || {
        Failure::new(
            "too_large",
            "the text is larger than this message kind allows",
        )
    };
    let read_all = |source: &mut dyn Read| -> Result<String, Failure> {
        let mut bytes = Vec::new();
        source
            .take(limit as u64 + 3)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::new("input", "cannot read the message text"))?;
        let mut text = String::from_utf8(bytes)
            .map_err(|_| Failure::new("input", "the message text must be UTF-8"))?;
        // A file or pipe usually ends with one newline that is not part of the text.
        if text.ends_with('\n') {
            text.pop();
            if text.ends_with('\r') {
                text.pop();
            }
        }
        Ok(text)
    };
    let text = if let Some(text) = args.get("--text") {
        text.to_owned()
    } else if let Some(path) = args.get("--body-file").filter(|p| *p != "-") {
        let mut file = std::fs::File::open(path)
            .map_err(|_| Failure::new("input", "cannot open the --body-file"))?;
        read_all(&mut file)?
    } else if sources == 1 || !stdin_is_terminal {
        read_all(stdin)?
    } else {
        return Err(usage("no message text given"));
    };
    if text.len() > limit {
        return Err(too_large());
    }
    if text.trim().is_empty() {
        return Err(Failure::new("input", "the message text is empty"));
    }
    Ok(text)
}

fn operation_name(args: &Args, prefix: &str) -> Result<String, Failure> {
    match args.get("--operation") {
        None => Ok(format!("{prefix}-{}", short_id())),
        Some(name)
            if !name.is_empty()
                && name.len() <= 64
                && name.as_bytes()[0].is_ascii_alphanumeric()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')) =>
        {
            Ok(name.to_owned())
        }
        Some(_) => Err(Failure::new(
            "usage",
            "--operation takes up to 64 letters, digits, '_' or '-'",
        )),
    }
}

pub fn present(delivery: &Delivery, replayed: bool) -> Value {
    let mut out = json!({"disposition": delivery.disposition, "replayed": replayed});
    let Some(message) = &delivery.message else {
        return out;
    };
    out["author"] = json!(message.author);
    out["kind"] = json!(message.kind);
    out["event_id"] = json!(message.event_id);
    out["accepted_at"] = json!(message.accepted_at);
    out["human_authored"] = json!(message.human_authored);
    out["human_original_author"] = json!(message.human_original_author);
    out["origin"] = json!(if message.human_original_author.is_some() {
        "human-statement-relayed-by-agent"
    } else {
        "agent"
    });
    // The core verified this content when it accepted it; this only decodes it.
    let body = Envelope::parse(message.content.event.as_bytes(), EVENT_PAYLOAD_TYPE)
        .ok()
        .and_then(|envelope| Event::parse(envelope.payload()).ok())
        .map(|event| event.body);
    match body {
        Some(Body::AgentMessage { text }) => out["text"] = json!(text),
        Some(Body::AgentRelay { original, note }) => {
            out["note"] = json!(note);
            if let Ok(Event {
                body: Body::HumanStatement { text },
                id,
                ..
            }) = Event::parse(original.payload())
            {
                out["human_text"] = json!(text);
                out["human_event_id"] = json!(id);
            }
        }
        _ => {}
    }
    out
}
