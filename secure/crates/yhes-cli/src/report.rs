//! `status` and `doctor`: read-only views with actionable errors.
use crate::{
    flow::{self, get_json},
    native,
    profile::{open_profile, Workspace, GROUP},
    Args, Deps, Failure,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use yhes_wire::{Envelope, REGISTRY_PAYLOAD_TYPE};

fn registry_summary(chain: &[String]) -> Value {
    let field = |name: &str| {
        let head = chain.last()?;
        let envelope = Envelope::parse(head.as_bytes(), REGISTRY_PAYLOAD_TYPE).ok()?;
        serde_json::from_slice::<Value>(envelope.payload()).ok()?[name].as_u64()
    };
    json!({"generation": field("generation"), "expires_at": field("expires_at")})
}

fn profile_report(
    ws: &Workspace,
    pin: &crate::profile::Pin,
    agent: &str,
    deps: &Deps<'_>,
    now: u64,
) -> Result<Value, Failure> {
    let mut engine = open_profile(ws, pin, agent, deps.custody, false)?;
    let identity = engine.identity()?;
    let chain: Vec<String> = engine
        .registry_head()?
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .into_iter()
        .collect();
    let grant: Option<String> = get_json(&mut engine, "grant")?;
    let grant_expires = grant
        .as_deref()
        .and_then(flow::parse_event)
        .map(|e| e.expires_at);
    let outbox = engine.outbox()?;
    let unpublished: Vec<Value> = outbox
        .iter()
        .filter(|o| o.status == "prepared" && o.kind != "key-package")
        .map(|o| json!({"operation": o.operation, "kind": o.kind}))
        .collect();
    let inbox = engine.inbox()?;
    let count = |d: &str| inbox.iter().filter(|e| e.delivery.disposition == d).count();
    let registry = registry_summary(&chain);
    Ok(json!({
        "agent": agent,
        "key_id": identity.key_id,
        "key_custody": deps.custody.label(),
        "group": engine.group_status(GROUP)?,
        "registry": registry,
        "registry_current": registry["expires_at"].as_u64().is_some_and(|e| e > now),
        "delegation_expires_at": grant_expires,
        "delegation_current": grant_expires.is_some_and(|e| e > now),
        "outbox": {"total": outbox.len(), "unpublished": unpublished},
        "inbox": {"messages": count("verified"), "quarantined": count("quarantined")},
    }))
}

pub fn status(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let ws = Workspace::locate(
        &deps.private_root,
        &PathBuf::from(args.need("--project")?),
        false,
    )?;
    let Some(pin) = ws.pin()? else {
        return Ok(json!({"command": "status", "set_up": false,
            "hint": "Run `yhes pilot --project PATH --human ID`."}));
    };
    let now = deps.clock.now();
    let mut profiles = Vec::new();
    for agent in &pin.agents {
        match profile_report(&ws, &pin, agent, deps, now) {
            Ok(report) => profiles.push(report),
            // Names from an altered pin must not be printed as if they were vouched for.
            Err(f) if f.code == "pin_changed" => return Err(f),
            Err(f) => profiles.push(json!({"agent": agent, "error": f.to_json()})),
        }
    }
    Ok(json!({
        "command": "status", "set_up": true,
        "project_id": pin.project_id, "group": pin.group, "owner": pin.owner,
        "human": pin.human, "authority_key_id": pin.authority.key_id,
        "ghes": null,
        "now": now, "profiles": profiles,
    }))
}

pub fn doctor(args: &Args, deps: &mut Deps<'_>) -> Result<Value, Failure> {
    let mut checks: Vec<Value> = Vec::new();
    let mut add = |name: &str, result: Result<String, Failure>| {
        checks.push(match result {
            Ok(detail) => json!({"check": name, "ok": true, "detail": detail}),
            Err(f) => json!({"check": name, "ok": false, "detail": f.message,
                "code": f.code, "hint": f.hint}),
        });
    };
    add(
        "signer-pin",
        native::pinned_team()
            .map(|team| format!("this build accepts YhesSigner from team {team} only"))
            .ok_or_else(|| {
                Failure::new("signer_unconfigured", "this build has no pinned signer team")
                    .hint("Use the signed helper inside YhesSigner.app; `send`, `sync` and `inbox` still work without it only if the vault key is readable.")
            }),
    );
    add(
        "signer-app",
        (if args.flag("--start-signer") {
            deps.signer.prepare()
        } else {
            deps.signer.probe()
        })
        .map(|_| "the signer socket is served by the pinned, validly signed app".to_owned()),
    );
    if let Some(project) = args.get("--project") {
        match Workspace::locate(&deps.private_root, &PathBuf::from(project), false) {
            Err(f) => add("project", Err(f)),
            Ok(ws) => match ws.pin() {
                Err(f) => add("setup", Err(f)),
                Ok(None) => add("setup", Err(crate::profile::not_set_up())),
                Ok(Some(pin)) => {
                    add(
                        "setup",
                        Ok("a local pin exists for this project".to_owned()),
                    );
                    let now = deps.clock.now();
                    for agent in &pin.agents {
                        let report = match profile_report(&ws, &pin, agent, deps, now) {
                            Ok(report) => report,
                            Err(f) => {
                                add(&format!("profile-{agent}"), Err(f));
                                continue;
                            }
                        };
                        add(
                            &format!("profile-{agent}"),
                            Ok(format!(
                                "vault opens; key custody: {}",
                                deps.custody.label()
                            )),
                        );
                        let renew = || {
                            Failure::new("expired", "expired or missing")
                                .hint("Run `yhes pilot` again to renew it in YhesSigner.")
                        };
                        add(
                            &format!("registry-{agent}"),
                            report["registry_current"]
                                .as_bool()
                                .filter(|b| *b)
                                .map(|_| "current".to_owned())
                                .ok_or_else(renew),
                        );
                        add(
                            &format!("delegation-{agent}"),
                            report["delegation_current"]
                                .as_bool()
                                .filter(|b| *b)
                                .map(|_| "current".to_owned())
                                .ok_or_else(renew),
                        );
                        let group = &report["group"];
                        add(
                            &format!("group-{agent}"),
                            if group["active"].as_bool() == Some(true)
                                && group["pending_operation"].is_null()
                            {
                                Ok(format!("member of `{GROUP}` at epoch {}", group["epoch"]))
                            } else {
                                Err(Failure::new(
                                    "not_in_group",
                                    "not an active member, or a change is pending",
                                )
                                .hint("Run `yhes pilot` to finish setup."))
                            },
                        );
                        let waiting = report["outbox"]["unpublished"]
                            .as_array()
                            .map_or(0, Vec::len);
                        add(
                            &format!("outbox-{agent}"),
                            if waiting == 0 {
                                Ok("nothing waiting".to_owned())
                            } else {
                                Err(Failure::new(
                                    "unpublished",
                                    "prepared records are not published yet",
                                )
                                .hint(format!("Run `yhes sync --project PATH --as {agent}`.")))
                            },
                        );
                    }
                }
            },
        }
    }
    let healthy = checks.iter().all(|c| c["ok"] == json!(true));
    Ok(json!({"command": "doctor", "ok": healthy, "checks": checks}))
}
