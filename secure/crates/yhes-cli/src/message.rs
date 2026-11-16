//! `send`, `say`, `sync` and `inbox`. Message text is data: it is never
//! logged, never echoed in errors and never interpreted as a command.
use crate::{
    flow::{self, get_json, put_json, short_id, STATEMENT_LIFETIME, WEEK},
    profile::{open_profile, GROUP},
    Args, Deps, Failure,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Read;
use yhes_core::{
    engine::{Delivery, Engine},
    local::LocalChannel,
};
use yhes_wire::{Body, Digest, Envelope, Event, EVENT_PAYLOAD_TYPE};

/// Limits of the wire profile and of the native review screen.
const AGENT_TEXT_BYTES: usize = 65_536;
const HUMAN_TEXT_BYTES: usize = 32_768;

/// What a named operation was first asked to do. A retry must match it.
#[derive(Serialize, Deserialize)]
struct OperationRecord {
    kind: String,
    input: String,
    /// The human-signed statement, kept so a retry needs no second approval.
    original: Option<String>,
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

/// `send` (agent-authored) and `say` (human-signed statement relayed by the agent).
pub fn send(
    args: &Args,
    stdin: &mut dyn Read,
    stdin_is_terminal: bool,
    deps: &mut Deps<'_>,
    human: bool,
) -> Result<Value, Failure> {
    let command = if human { "say" } else { "send" };
    let agent = args.need("--as")?.to_owned();
    let operation = operation_name(args, command)?;
    let limit = if human {
        HUMAN_TEXT_BYTES
    } else {
        AGENT_TEXT_BYTES
    };
    let text = read_text(args, stdin, stdin_is_terminal, limit)?;
    if human
        && text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return Err(Failure::new(
            "input",
            "a human statement cannot contain invisible control characters",
        ));
    }
    let project = flow::project(args, deps)?;
    let pin = &project.pin;
    let mut engine = open_profile(&project.ws, pin, &agent, deps.custody, false)?;
    let channel = flow::channel(&project)?;
    // Membership and earlier records first, so the event names the current epoch.
    channel.sync(&mut engine, GROUP, &pin.owner, deps.clock.now())?;

    let record_name = format!("op-{operation}");
    let input = Digest::of(format!("{command}\0{text}").as_bytes()).to_hex();
    let mut record = match get_json::<OperationRecord>(&mut engine, &record_name)? {
        Some(record) => {
            if record.kind != command || record.input != input {
                return Err(Failure::new(
                    "operation_conflict",
                    "this --operation was already used for a different message",
                )
                .hint("Use a new --operation for new text."));
            }
            record
        }
        None => {
            let record = OperationRecord {
                kind: command.into(),
                input,
                original: None,
            };
            put_json(&mut engine, &record_name, &record)?;
            record
        }
    };
    let human_author = human.then(|| pin.human.clone());
    let kind = if human {
        "agent.relay"
    } else {
        "agent.message"
    };

    // A retry of an operation that already has its exact packet stored.
    if let Some(entry) = engine
        .outbox()?
        .into_iter()
        .find(|entry| entry.operation == operation)
    {
        let publication = if entry.status == "accepted" {
            None
        } else {
            Some(channel.publish(&mut engine, &operation, deps.clock.now())?)
        };
        return Ok(json!({
            "command": command, "as": agent, "operation": operation,
            "event_id": entry.event_id, "author": agent, "kind": kind,
            "human_original_author": human_author, "group": entry.group, "epoch": entry.epoch,
            "replayed": true, "published": publication,
        }));
    }

    let group = flow::ready_group(&mut engine)?;
    let now = deps.clock.now();
    let (grant, grant_event) = flow::grant(&mut engine, now)?;
    let (body, expires_at) = if human {
        let original = match record.original.take() {
            Some(original) => {
                let usable = flow::parse_event(&original).is_some_and(|e| {
                    e.expires_at > now
                        && e.epoch == Some(group.epoch)
                        && e.audience == group.audience
                });
                if !usable {
                    return Err(Failure::new(
                        "statement_expired",
                        "the statement approved for this operation can no longer be sent",
                    )
                    .hint(
                        "Run `yhes say` again with a new --operation; it needs a new approval.",
                    ));
                }
                original
            }
            None => {
                let statement = flow::human_event(
                    pin,
                    format!("statement-{}", short_id()),
                    now,
                    STATEMENT_LIFETIME,
                    group.audience.clone(),
                    Some(group.epoch),
                    Body::HumanStatement { text },
                )?;
                let original = flow::approve(
                    deps,
                    pin,
                    "your statement, exactly as typed",
                    &statement,
                    None,
                )?;
                record.original = Some(original.clone());
                put_json(&mut engine, &record_name, &record)?;
                original
            }
        };
        let expires_at = flow::parse_event(&original).map_or(now, |e| e.expires_at);
        let original = Envelope::parse(original.as_bytes(), EVENT_PAYLOAD_TYPE)
            .map_err(|_| Failure::new("private_state", "the stored statement is unreadable"))?;
        (
            Body::AgentRelay {
                original,
                note: None,
            },
            expires_at,
        )
    } else {
        (
            Body::AgentMessage { text },
            (now + WEEK).min(grant_event.expires_at),
        )
    };
    let now = deps.clock.now();
    let event = flow::agent_event(
        &mut engine,
        pin,
        format!("{}-{}", if human { "relay" } else { "message" }, short_id()),
        &grant,
        now,
        expires_at,
        group.audience.clone(),
        group.epoch,
        body,
    )?;
    let event_id = event.id.clone();
    let content = engine.sign_event(event, Some(grant), None, None, now)?;
    // The exact ciphertext is stored under the operation before any transport.
    engine.prepare_message(&operation, GROUP, content, now)?;
    let publication = channel.publish(&mut engine, &operation, now).map_err(|e| {
        Failure::from(e).hint(format!(
            "The message is stored. `yhes sync --project PATH --as {agent}` publishes it."
        ))
    })?;
    if human {
        deps.say("sent. Recipients must run `yhes sync` or `yhes inbox` within 30 minutes");
    }
    Ok(json!({
        "command": command, "as": agent, "operation": operation, "event_id": event_id,
        "author": agent, "kind": kind, "human_original_author": human_author,
        "group": GROUP, "epoch": group.epoch, "audience": group.audience,
        "receive_before": expires_at, "replayed": false, "published": publication,
    }))
}

/// One delivery for output. `replayed` is true when this is the stored result
/// of an earlier acceptance, not a verification made now.
fn present(delivery: &Delivery, replayed: bool) -> Value {
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

/// Publish prepared messages whose first publication did not complete.
fn flush(
    engine: &mut Engine,
    channel: &LocalChannel,
    now: u64,
) -> Result<(Vec<Value>, Vec<Value>), Failure> {
    let (mut published, mut waiting) = (Vec::new(), Vec::new());
    for entry in engine.outbox()? {
        if entry.status != "prepared" || entry.kind == "key-package" {
            continue;
        }
        if entry.kind != "application" {
            waiting.push(json!({"operation": entry.operation, "kind": entry.kind,
                "reason": "membership change; run `yhes pilot`"}));
            continue;
        }
        match channel.publish(engine, &entry.operation, now) {
            Ok(publication) => published.push(json!(publication)),
            Err(e) => waiting.push(json!({"operation": entry.operation, "kind": entry.kind,
                "reason": Failure::from(e).code})),
        }
    }
    Ok((published, waiting))
}

pub fn sync(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let agent = args.need("--as")?;
    let project = flow::project(args, deps)?;
    let mut engine = open_profile(&project.ws, &project.pin, agent, deps.custody, false)?;
    let channel = flow::channel(&project)?;
    let now = deps.clock.now();
    let result = channel.sync(&mut engine, GROUP, &project.pin.owner, now)?;
    let (published, unpublished) = flush(&mut engine, &channel, now)?;
    Ok(json!({
        "command": "sync", "as": agent, "processed": result.processed,
        "messages": result.deliveries.iter().filter(|d| d.message.is_some())
            .map(|d| present(d, d.replayed)).collect::<Vec<_>>(),
        "quarantined": result.deliveries.iter().filter(|d| d.disposition == "quarantined").count(),
        "published": published, "unpublished": unpublished,
    }))
}

pub fn inbox(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let agent = args.need("--as")?;
    let project = flow::project(args, deps)?;
    let mut engine = open_profile(&project.ws, &project.pin, agent, deps.custody, false)?;
    let mut fresh = Vec::new();
    if !args.flag("--no-sync") {
        let channel = flow::channel(&project)?;
        let result = channel.sync(&mut engine, GROUP, &project.pin.owner, deps.clock.now())?;
        for delivery in result.deliveries {
            if let (false, Some(message)) = (delivery.replayed, delivery.message) {
                fresh.push((message.author, message.event_id));
            }
        }
    }
    let entries = engine.inbox()?;
    // Entries this command has listed before, by position in the durable inbox.
    let shown: usize = get_json(&mut engine, "inbox-shown")?.unwrap_or(0);
    let mut messages = Vec::new();
    let (mut quarantined, mut new_messages) = (0, 0);
    for (index, entry) in entries.iter().enumerate() {
        if entry.delivery.disposition == "quarantined" {
            quarantined += 1;
        }
        let Some(message) = &entry.delivery.message else {
            continue;
        };
        let verified_now = fresh
            .iter()
            .any(|(author, id)| *author == message.author && *id == message.event_id);
        let mut item = present(&entry.delivery, !verified_now);
        item["new"] = json!(index >= shown);
        new_messages += usize::from(index >= shown);
        messages.push(item);
    }
    if entries.len() != shown {
        put_json(&mut engine, "inbox-shown", &entries.len())?;
    }
    Ok(json!({
        "command": "inbox", "as": agent, "synced": !args.flag("--no-sync"),
        "new_messages": new_messages, "messages": messages, "quarantined": quarantined,
    }))
}
