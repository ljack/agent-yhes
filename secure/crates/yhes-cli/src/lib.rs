//! The `yhes` command line. `run` is the whole program; `main.rs` supplies the
//! production signer, key custody and clock. Tests supply their own through
//! the same Rust interface. No argument, environment variable or file can
//! select a different signer or key provider at run time.
pub mod broker;
pub mod flow;
pub mod message;
pub mod native;
pub mod pilot;
pub mod profile;
pub mod realtime;
pub mod report;
pub mod signer;
pub mod team;

use serde_json::{json, Value};
use std::{collections::BTreeMap, io::Read, path::PathBuf};
use yhes_core::keys::{AnchorStore, KeyProvider, PlatformKeychain, StorageKey};

/// A failed command. `message` and `hint` never contain message text or keys.
#[derive(Debug, Clone)]
pub struct Failure {
    pub code: String,
    pub message: String,
    pub hint: Option<String>,
    /// A fixed code from another component, such as the signer's error code.
    pub detail: Option<String>,
}
impl Failure {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
            hint: None,
            detail: None,
        }
    }
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
    pub fn to_json(&self) -> Value {
        json!({"code": self.code, "message": self.message, "hint": self.hint, "detail": self.detail})
    }
}
impl From<yhes_core::Error> for Failure {
    fn from(e: yhes_core::Error) -> Self {
        use yhes_core::Error::*;
        // Core messages are fixed strings without payload content.
        match e {
            Invalid(m) => Failure::new("invalid", &m),
            Conflict(m) => Failure::new("conflict", &m),
            Verification(m) => Failure::new("verification_failed", &m),
            Storage => Failure::new("storage", "protected store operation failed"),
            CheckpointPending => Failure::new(
                "checkpoint_pending",
                "the change was committed locally but its checkpoint was not published",
            )
            .hint("Run the same command again with the same --operation; do not assume it failed."),
            KeyProvider(m) => Failure::new("key_custody", &m).hint(
                "Vault keys are readable only by the signed engine helper (com.agent-yhes.engine) \
                 inside YhesSigner.app. An unsigned or ad-hoc build cannot open a profile.",
            ),
            Mls => Failure::new("mls_rejected", "MLS operation rejected"),
        }
    }
}

/// Where vault keys and checkpoints come from.
pub trait Custody {
    /// Reported by `status` as `key_custody`.
    fn label(&self) -> &'static str;
    fn create_key(&self, account: &str) -> yhes_core::Result<StorageKey>;
    fn load_key(&self, account: &str) -> yhes_core::Result<StorageKey>;
    fn anchors(&self) -> Box<dyn AnchorStore>;
}

/// The macOS Data Protection keychain, scoped to the signed engine identity.
pub struct PlatformCustody;
impl Custody for PlatformCustody {
    fn label(&self) -> &'static str {
        "platform-keychain"
    }
    fn create_key(&self, account: &str) -> yhes_core::Result<StorageKey> {
        PlatformKeychain.create(account)
    }
    fn load_key(&self, account: &str) -> yhes_core::Result<StorageKey> {
        KeyProvider::load(&PlatformKeychain, account)
    }
    fn anchors(&self) -> Box<dyn AnchorStore> {
        Box::new(PlatformKeychain)
    }
}

pub trait Clock {
    fn now(&self) -> u64;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

pub struct Deps<'a> {
    pub signer: &'a dyn signer::SignerClient,
    pub custody: &'a dyn Custody,
    pub clock: &'a dyn Clock,
    /// Private engine directory, outside any shared project.
    pub private_root: PathBuf,
    /// Human-readable progress. Never receives message text.
    pub progress: &'a mut dyn std::io::Write,
}
impl Deps<'_> {
    pub fn say(&mut self, line: &str) {
        let _ = writeln!(self.progress, "yhes: {line}");
    }
}

pub struct Outcome {
    pub exit: i32,
    /// Plain text for `help`; otherwise one JSON object.
    pub stdout: String,
}

pub const HELP: &str = "\
yhes — signed, encrypted messages between local agent profiles

Setup (asks for approval in the YhesSigner app):
  yhes pilot  --project PATH --human ID [--project-id ID]

Messages:
  yhes send   --project PATH --as AGENT (--text TEXT | --body-file FILE | --stdin)
              An agent-authored message. No human approval.
  yhes say    --project PATH --as AGENT (--text TEXT | --body-file FILE | --stdin)
              Your exact words: approve them in YhesSigner, then AGENT relays
              the signed original. Recipients must sync within 30 minutes.
  yhes sync   --project PATH --as AGENT     Publish pending sends, fetch new records.
  yhes inbox  --project PATH --as AGENT [--no-sync]

Checks:
  yhes status --project PATH
  yhes doctor [--project PATH] [--start-signer]

Two-person Git team (separate from local pilot):
  yhes team-init --project PATH --project-id ID --human ID --as AGENT --remote URL [--branch REF]
  yhes team-request --project PATH --project-id ID --human ID --as AGENT --remote URL
              --authority KEY_ID --bootstrap REGISTRY1_DIGEST [--branch REF]
  yhes team-admit --project PATH --peer AGENT --peer-key HUMAN_KEY_ID
  yhes team-connect --project PATH [--as AGENT]
  yhes team-send --project PATH (--text T | --body-file F | --stdin) [--operation ID]
  yhes team-say  --project PATH (--text T | --body-file F | --stdin) [--operation ID]
  yhes team-inbox --project PATH [--no-sync]
  yhes team-status --project PATH
  team-init/team-request setup options:
    --git-author-name NAME --git-author-email EMAIL
    --git-signing-format ssh|openpgp --git-signing-key PUBLIC_KEY_PATH|FULL_FINGERPRINT
    --git-ssh-agent                 Explicitly allow the existing SSH agent.
    --git-credentials osxkeychain  Explicitly use the fixed HTTPS credential helper.

Realtime server (Git-confirmed ciphertext only):
  yhes team-broker-init --project PATH --broker URL [--ca-file FILE]
  yhes team-listen --project PATH --broker URL [--seconds 30] [--ca-file FILE]
  yhes team-flush --project PATH --broker URL [--operation ID] [--ca-file FILE]
  Add --broker URL [--ca-file FILE] to team-send/team-say for immediate notification.
  Supply YHES_BROKER_TOKEN privately. Remote brokers require tls://.
  team-listen returns on a new verified message or after its bounded wait.

Options:
  --operation ID   Name a send/say so that a retry cannot send it twice.
  --body-file -    Read the text from standard input.

Results are one JSON object on standard output; progress is on standard error.
Pilot profiles are `codex` and `claude` in group `team`.
";

pub struct Args {
    pub command: String,
    values: BTreeMap<String, String>,
    flags: Vec<String>,
}
impl Args {
    pub fn parse(argv: &[String]) -> Result<Self, Failure> {
        let usage = |m: &str| Failure::new("usage", m).hint("Run `yhes help`.");
        let mut it = argv.iter();
        let command = it.next().ok_or_else(|| usage("no command given"))?.clone();
        let (valued, switches): (&[&str], &[&str]) = match command.as_str() {
            "team-init" => (
                &[
                    "--project",
                    "--project-id",
                    "--human",
                    "--as",
                    "--remote",
                    "--branch",
                    "--git-author-name",
                    "--git-author-email",
                    "--git-signing-format",
                    "--git-signing-key",
                    "--git-credentials",
                ],
                &["--git-ssh-agent"],
            ),
            "team-request" => (
                &[
                    "--project",
                    "--project-id",
                    "--human",
                    "--as",
                    "--remote",
                    "--branch",
                    "--authority",
                    "--bootstrap",
                    "--git-author-name",
                    "--git-author-email",
                    "--git-signing-format",
                    "--git-signing-key",
                    "--git-credentials",
                ],
                &["--git-ssh-agent"],
            ),
            "team-admit" => (&["--project", "--peer", "--peer-key"], &[]),
            "team-connect" | "team-status" => (&["--project", "--as"], &[]),
            "team-inbox" => (&["--project", "--as"], &["--no-sync"]),
            "team-send" | "team-say" => (
                &[
                    "--project",
                    "--as",
                    "--text",
                    "--body-file",
                    "--operation",
                    "--broker",
                    "--ca-file",
                ],
                &["--stdin"],
            ),
            "team-broker-init" => (&["--project", "--broker", "--ca-file"], &[]),
            "team-listen" => (&["--project", "--broker", "--ca-file", "--seconds"], &[]),
            "team-flush" => (&["--project", "--broker", "--ca-file", "--operation"], &[]),
            "pilot" => (&["--project", "--human", "--project-id"], &[]),
            "send" | "say" => (
                &["--project", "--as", "--text", "--body-file", "--operation"],
                &["--stdin"],
            ),
            "sync" => (&["--project", "--as"], &[]),
            "inbox" => (&["--project", "--as"], &["--no-sync"]),
            "status" => (&["--project"], &[]),
            "doctor" => (&["--project"], &["--start-signer"]),
            "help" | "--help" | "-h" => (&[], &[]),
            _ => return Err(usage("unknown command")),
        };
        let mut values = BTreeMap::new();
        let mut flags = Vec::new();
        while let Some(arg) = it.next() {
            if valued.contains(&arg.as_str()) {
                let value = it
                    .next()
                    .ok_or_else(|| usage("an option is missing its value"))?;
                if values.insert(arg.clone(), value.clone()).is_some() {
                    return Err(usage("an option was given twice"));
                }
            } else if switches.contains(&arg.as_str()) {
                flags.push(arg.clone());
            } else {
                // The argument itself may be private text given by mistake.
                return Err(usage("unexpected argument for this command"));
            }
        }
        Ok(Self {
            command,
            values,
            flags,
        })
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
    pub fn need(&self, name: &str) -> Result<&str, Failure> {
        self.get(name).ok_or_else(|| {
            Failure::new("usage", &format!("{name} is required")).hint("Run `yhes help`.")
        })
    }
    pub fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }
}

/// Run one command. `stdin` is read only when the command takes its text
/// from standard input.
pub fn run(
    argv: &[String],
    stdin: &mut dyn Read,
    stdin_is_terminal: bool,
    deps: &mut Deps<'_>,
) -> Outcome {
    let result = Args::parse(argv).and_then(|args| match args.command.as_str() {
        "help" | "--help" | "-h" => Ok(None),
        "pilot" => pilot::run(&args, deps).map(Some),
        "send" => message::send(&args, stdin, stdin_is_terminal, deps, false).map(Some),
        "say" => message::send(&args, stdin, stdin_is_terminal, deps, true).map(Some),
        "sync" => message::sync(&args, deps).map(Some),
        "inbox" => message::inbox(&args, deps).map(Some),
        "status" => report::status(&args, deps).map(Some),
        "doctor" => report::doctor(&args, deps).map(Some),
        "team-init" => team::init(&args, deps).map(Some),
        "team-request" => team::request(&args, deps).map(Some),
        "team-admit" => team::admit(&args, deps).map(Some),
        "team-connect" => team::connect(&args, deps).map(Some),
        "team-status" => team::status(&args, deps).map(Some),
        "team-inbox" => team::inbox(&args, deps).map(Some),
        "team-send" => realtime::send(&args, stdin, stdin_is_terminal, deps, false).map(Some),
        "team-say" => realtime::send(&args, stdin, stdin_is_terminal, deps, true).map(Some),
        "team-broker-init" => realtime::initialize(&args, deps).map(Some),
        "team-listen" => realtime::listen(&args, deps).map(Some),
        "team-flush" => realtime::flush(&args, deps).map(Some),
        _ => unreachable!("Args::parse accepts only known commands"),
    });
    match result {
        Ok(None) => Outcome {
            exit: 0,
            stdout: HELP.to_owned(),
        },
        Ok(Some(mut value)) => {
            let ok = value.get("ok").and_then(Value::as_bool).unwrap_or(true);
            value["ok"] = json!(ok);
            Outcome {
                exit: if ok { 0 } else { 1 },
                stdout: format!("{value}\n"),
            }
        }
        Err(failure) => Outcome {
            exit: if failure.code == "usage" { 2 } else { 1 },
            stdout: format!("{}\n", json!({"ok": false, "error": failure.to_json()})),
        },
    }
}
