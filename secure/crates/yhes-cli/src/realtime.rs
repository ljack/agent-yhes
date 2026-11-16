//! Server-triggered Git reconciliation. Ciphertext on the broker is a delivery
//! hint/cache; only the Git adapter can admit records or confirm publication.
use crate::{
    broker::{self, Broker, Config},
    flow, team, Args, Deps, Failure,
};
use serde_json::{json, Value};
use std::{
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};
use yhes_wire::Digest;

fn config(args: &Args) -> Result<Config, Failure> {
    let token = std::env::var("YHES_BROKER_TOKEN").map_err(|_| {
        Failure::new(
            "broker_configuration",
            "set YHES_BROKER_TOKEN privately before using the broker",
        )
    })?;
    Config::new(
        args.need("--broker")?,
        &token,
        args.get("--ca-file").map(PathBuf::from),
    )
}
fn connect(config: Config, pin: &team::TeamPin) -> Result<Broker, Failure> {
    Broker::connect(config, &pin.project_id, &pin.group, &pin.authority.key_id)
}
fn published_key(args: &Args, digest: &str) -> Result<String, Failure> {
    let scope = serde_json::to_vec(&(args.need("--broker")?, args.get("--ca-file"), digest))
        .map_err(|_| Failure::new("internal", "cannot encode broker delivery scope"))?;
    Ok(format!("broker-{}", Digest::of(&scope).to_hex()))
}
fn notification_failure(error: Failure) -> Value {
    let broker_only = error.code.starts_with("broker_");
    json!({"state":if broker_only { "pending" } else { "failed" },
        "git_confirmed":broker_only,"error":error.to_json(),
        "hint":if broker_only { "The encrypted message is saved in Git. Retry its notification with team-flush." }
            else { "The earlier send was confirmed, but a later state check failed. Preserve the operation ID and diagnose the reported error before retrying." }})
}
#[derive(Default)]
struct HintBatch {
    attempted: usize,
    already_sent: usize,
    remaining: usize,
}
impl HintBatch {
    fn select(&mut self, already_sent: bool) -> bool {
        if already_sent {
            self.already_sent += 1;
            return false;
        }
        if self.attempted == 64 {
            self.remaining += 1;
            return false;
        }
        self.attempted += 1;
        true
    }
}
pub fn initialize(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let configuration = config(args)?;
    let mut session = team::open(args, deps)?;
    team::sync(&mut session, deps.clock.now())?;
    let broker = connect(configuration, &session.pin)?;
    let mut value = broker.initialize()?;
    value["command"] = json!("team-broker-init");
    Ok(value)
}

pub fn send(
    args: &Args,
    stdin: &mut dyn Read,
    terminal: bool,
    deps: &mut Deps<'_>,
    human: bool,
) -> Result<Value, Failure> {
    // Reject malformed local configuration before creating a logical message.
    if args.get("--ca-file").is_some() && args.get("--broker").is_none() {
        return Err(Failure::new(
            "usage",
            "--ca-file requires an explicit --broker",
        ));
    }
    if args.get("--broker").is_some() {
        config(args)?;
    }
    let mut result = team::send(args, stdin, terminal, deps, human)?;
    if args.get("--broker").is_some() {
        let operation = result["operation"]
            .as_str()
            .ok_or_else(|| Failure::new("internal", "send result has no operation"))?
            .to_owned();
        result["realtime"] = match notify(args, deps, Some(&operation)) {
            Ok(value) => value,
            Err(error) => notification_failure(error),
        };
        if result["realtime"]["git_confirmed"] == false {
            result["ok"] = json!(false);
        }
    }
    Ok(result)
}

fn notify(args: &Args, deps: &mut Deps<'_>, only: Option<&str>) -> Result<Value, Failure> {
    let configuration = config(args)?;
    let mut session = team::open(args, deps)?;
    team::sync(&mut session, deps.clock.now())?;
    let broker = connect(configuration, &session.pin)?;
    let mut publications = Vec::new();
    let mut batch = HintBatch::default();
    let mut errors = Vec::new();
    let mut unarchived = Vec::new();
    for entry in session
        .engine
        .outbox()?
        .into_iter()
        .filter(|e| e.kind == "application" && only.is_none_or(|op| e.operation == op))
    {
        if entry.status != "accepted" {
            unarchived.push(entry.operation);
            continue;
        }
        let packet = session.engine.stored_packet(&entry.operation)?;
        let digest = Digest::of(&packet).to_hex();
        let key = published_key(args, &digest)?;
        // The cap applies to work still needing notification, not the first
        // rows in a long outbox. A rejected/expired prepared send cannot starve
        // later records whose publication Git has already confirmed.
        if !batch.select(session.engine.client_get(&key)?.is_some()) {
            continue;
        }
        if let Err(error) =
            session
                .channel
                .publish(&mut session.engine, &entry.operation, deps.clock.now())
        {
            errors.push(json!({"operation":entry.operation,"git_confirmed":false,"error":Failure::from(error).to_json()}));
            continue;
        }
        let receipt = match broker.publish(&packet) {
            Ok(receipt) => receipt,
            Err(error) => {
                errors.push(json!({"operation":entry.operation,"git_confirmed":true,"error":error.to_json()}));
                continue;
            }
        };
        session.engine.client_put(&key, digest.as_bytes())?;
        publications.push(receipt);
    }
    let git_confirmed = unarchived.is_empty() && errors.iter().all(|e| e["git_confirmed"] == true);
    let pending = !errors.is_empty() || batch.remaining > 0 || !unarchived.is_empty();
    Ok(
        json!({"state":if pending { "pending" } else { "published" },"git_confirmed":git_confirmed,
        "notifications":publications,"already_sent":batch.already_sent,"remaining":batch.remaining,
        "unarchived_operations":unarchived,"errors":errors}),
    )
}
pub fn flush(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let mut value = notify(args, deps, args.get("--operation"))?;
    value["command"] = json!("team-flush");
    if value["git_confirmed"] == false {
        value["ok"] = json!(false);
    }
    Ok(value)
}

/// Returns only newly shown durable inbox entries. No broker bytes are passed
/// to Engine::receive; membership ordering is entirely the Git adapter's job.
fn reconcile(args: &Args, deps: &mut Deps<'_>) -> Result<(Value, Vec<String>), Failure> {
    let mut session = team::open(args, deps)?;
    let sync = team::sync(&mut session, deps.clock.now())?;
    let fresh: Vec<_> = sync
        .deliveries
        .iter()
        .filter(|d| !d.replayed)
        .filter_map(|d| {
            d.message
                .as_ref()
                .map(|m| (m.author.clone(), m.event_id.clone()))
        })
        .collect();
    let entries = session.engine.inbox()?;
    let shown: usize = flow::get_json(&mut session.engine, "inbox-shown")?.unwrap_or(0);
    let mut messages = Vec::new();
    let mut digests = Vec::new();
    let mut quarantined = 0;
    for (index, entry) in entries.iter().enumerate() {
        digests.push(entry.packet_digest.clone());
        if entry.delivery.disposition == "quarantined" {
            quarantined += 1;
        }
        if index >= shown {
            if let Some(m) = &entry.delivery.message {
                let replayed = !fresh
                    .iter()
                    .any(|(a, id)| a == &m.author && id == &m.event_id);
                let mut value = team::present(&entry.delivery, replayed);
                value["new"] = json!(true);
                messages.push(value);
            }
        }
    }
    // Outgoing echoes can be acknowledged as notifications after Git confirms
    // them, without trying to decrypt our own MLS application message.
    for entry in session
        .engine
        .outbox()?
        .into_iter()
        .filter(|e| e.kind == "application" && e.status == "accepted")
    {
        digests.push(Digest::of(&session.engine.stored_packet(&entry.operation)?).to_hex());
    }
    if entries.len() != shown {
        flow::put_json(&mut session.engine, "inbox-shown", &entries.len())?;
    }
    Ok((
        json!({"command":"team-listen","as":session.pin.principal,"messages":messages,
        "new_messages":messages.len(),"quarantined":quarantined,"synced":true}),
        digests,
    ))
}
pub fn listen(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let seconds: u64 = args
        .get("--seconds")
        .unwrap_or("30")
        .parse()
        .map_err(|_| Failure::new("usage", "--seconds must be between 1 and 300"))?;
    if !(1..=300).contains(&seconds) {
        return Err(Failure::new("usage", "--seconds must be between 1 and 300"));
    }
    let configuration = config(args)?;
    let pin = team::open(args, deps)?.pin;
    // No vault remains locked while waiting on the network.
    let broker = connect(configuration, &pin)?;
    let consumer = broker.consumer(&pin.principal)?;
    let (mut result, _) = reconcile(args, deps)?;
    result["wake"] = json!("startup");
    if result["new_messages"].as_u64().unwrap_or(0) > 0 {
        return Ok(result);
    }
    deps.say("realtime: waiting for ciphertext notifications; Git remains authoritative");
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut last_sync = Instant::now();
    let mut notifications = 0usize;
    let mut unmatched = 0usize;
    while Instant::now() < deadline {
        let batch = broker.fetch(
            &consumer,
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(2)),
        )?;
        let wake = !batch.is_empty();
        if wake || last_sync.elapsed() >= Duration::from_secs(30) || Instant::now() >= deadline {
            let (value, accepted) = reconcile(args, deps)?;
            result = value;
            result["wake"] = json!(if wake { "broker" } else { "reconciliation" });
            last_sync = Instant::now();
            for message in batch {
                notifications += 1;
                if message.bytes().len() > broker::MAX_PACKET
                    || !accepted.contains(&Digest::of(message.bytes()).to_hex())
                {
                    unmatched += 1;
                }
                // Unknown/early ciphertext is discarded as an untrusted hint.
                // Later Git reconciliation still finds a subsequently accepted
                // record even if this notification has been acknowledged.
                broker.acknowledge(message)?;
            }
            if result["new_messages"].as_u64().unwrap_or(0) > 0 {
                break;
            }
        }
    }
    result["notifications"] = json!(notifications);
    result["unmatched_notifications"] = json!(unmatched);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_later_git_failure_does_not_claim_current_publication_confirmation() {
        let rollback = notification_failure(Failure::new(
            "verification_failed",
            "Git history rolled back",
        ));
        assert_eq!(rollback["git_confirmed"], false);
        assert_eq!(rollback["state"], "failed");
        let unavailable =
            notification_failure(Failure::new("broker_unavailable", "broker is offline"));
        assert_eq!(unavailable["git_confirmed"], true);
        assert_eq!(unavailable["state"], "pending");
    }
    #[test]
    fn a_long_notified_prefix_does_not_starve_the_next_hint() {
        let mut batch = HintBatch::default();
        for _ in 0..80 {
            assert!(!batch.select(true));
        }
        // The 81st operation must still get the first slot in this flush.
        assert!(batch.select(false));
        for _ in 1..64 {
            assert!(batch.select(false));
        }
        assert!(!batch.select(false));
        assert_eq!(batch.already_sent, 80);
        assert_eq!(batch.attempted, 64);
        assert_eq!(batch.remaining, 1);
    }
}
