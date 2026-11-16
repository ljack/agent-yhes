mod config;
mod custody;
mod fs;
mod human;
mod progress;
mod review;

#[cfg(test)]
mod tests;

use serde_json::{json, Value};
use std::{io::Read, path::Path};
use yhes_cli::{Deps, Failure, Outcome, SystemClock};

/// Call only at single-threaded process entry, before creating a NATS runtime.
pub fn clear_environment() {
    for (name, _) in std::env::vars_os() {
        std::env::remove_var(name);
    }
    std::env::set_var("PATH", "/usr/bin:/bin");
    std::env::set_var("LC_ALL", "C");
}

fn annotate(mut value: Value, role: Option<&str>) -> Value {
    value["simulation"] = json!(true);
    value["human_authentication"] = json!("simulated-no-touch-id");
    value["key_custody"] = json!("simulation-files");
    value["role"] = json!(role);
    value
}

pub fn execute(args: &[String], input: &mut dyn Read, terminal: bool) -> Outcome {
    let mut role = None;
    let result = (|| -> Result<(i32, Value), Failure> {
        if args.len() < 3
            || args[1] != "--node"
            || !matches!(args[0].as_str(), "identity" | "run")
            || (args[0] == "identity" && args.len() != 3)
            || (args[0] == "run" && (args.len() < 5 || args[3] != "--"))
        {
            return Err(Failure::new("simulation_usage", "use yhes_sim identity --node ABS_NODE_JSON or yhes_sim run --node ABS_NODE_JSON -- TEAM_COMMAND ARGS"));
        }
        let lab = config::Lab::load(Path::new(&args[2]))?;
        role = Some(lab.node.role.clone());
        let command = if args[0] == "run" {
            Some(lab.command(&args[4..])?)
        } else {
            None
        };
        lab.prepare()?;
        let _lock = fs::Lock::acquire(&lab.role_root.join("command.lock"))?;
        let signer = human::Human::open(&lab)?;
        let descriptor = signer.descriptor()?;
        lab.check_pin(&descriptor)?;
        let Some(command) = command else {
            let mut value = serde_json::to_value(descriptor).map_err(|_| fs::rejected())?;
            value["ok"] = json!(true);
            value["command"] = json!("identity");
            return Ok((0, value));
        };
        let parsed = yhes_cli::Args::parse(&command)?;
        if parsed.get("--broker").is_some() {
            // The production CLI reads this single variable. It receives only
            // the disposable lab token, after all scopes/paths were checked.
            std::env::set_var("YHES_BROKER_TOKEN", lab.token()?);
        }
        let ws = yhes_cli::profile::Workspace::locate(&lab.engine, &lab.node.project, false)?;
        let custody = custody::Files::new(
            &lab.role_root,
            ws.account(&format!("network-{}", lab.agent)),
        )?;
        // Forward only the fixed realtime readiness signal. Production native
        // review/Touch ID progress must never appear as simulated authentication.
        let stderr = std::io::stderr();
        let mut progress = progress::ReadyProgress::new(stderr.lock());
        let outcome = yhes_cli::run(
            &command,
            input,
            terminal,
            &mut Deps {
                signer: &signer,
                custody: &custody,
                clock: &SystemClock,
                private_root: lab.engine,
                progress: &mut progress,
            },
        );
        let mut value: Value = serde_json::from_str(&outcome.stdout).map_err(|_| fs::rejected())?;
        if !value.is_object() {
            return Err(fs::rejected());
        }
        // Native app remediation is not applicable to the injected fixture.
        if let Some(error) = value.get_mut("error").and_then(Value::as_object_mut) {
            error.insert("hint".into(), Value::Null);
        }
        Ok((outcome.exit, value))
    })();
    let (exit, value) = match result {
        Ok(result) => result,
        Err(error) => (1, json!({"ok":false,"error":error.to_json()})),
    };
    Outcome {
        exit,
        stdout: format!("{}\n", annotate(value, role.as_deref())),
    }
}
