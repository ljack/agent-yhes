use super::fs::{self, rejected};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use yhes_cli::{Args, Failure};

pub const BRANCH: &str = "agent-yhes/secure-simulation";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub version: u8,
    pub simulation: bool,
    pub lab_root: PathBuf,
    pub project: PathBuf,
    pub project_id: String,
    pub role: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u8,
    simulation: bool,
    project_id: String,
    alice: PathBuf,
    bob: PathBuf,
    broker_url: String,
    #[serde(default)]
    toolkit: Option<PathBuf>,
}

pub struct Lab {
    pub node: Node,
    pub broker_url: String,
    pub human: String,
    pub agent: String,
    pub role_root: PathBuf,
    pub engine: PathBuf,
    pub remote: PathBuf,
}

impl Lab {
    pub fn load(node_path: &Path) -> Result<Self, Failure> {
        let node: Node =
            serde_json::from_slice(&fs::read(node_path, 16_384, true)?).map_err(|_| rejected())?;
        if node.version != 1
            || !node.simulation
            || !matches!(node.role.as_str(), "alice" | "bob")
            || !node.project_id.strip_prefix("sim-").is_some_and(|s| {
                (16..=64).contains(&s.len())
                    && s.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
            || node_path
                != node
                    .lab_root
                    .join("nodes")
                    .join(format!("{}.json", node.role))
        {
            return Err(rejected());
        }
        fs::path(&node.lab_root, true, true)?;
        fs::path(&node.lab_root.join("nodes"), true, true)?;
        let marker: Marker =
            serde_json::from_slice(&fs::read(&node.lab_root.join("lab.json"), 16_384, true)?)
                .map_err(|_| rejected())?;
        if marker.version != 1
            || !marker.simulation
            || marker.project_id != node.project_id
            || marker.alice.starts_with(&marker.bob)
            || marker.bob.starts_with(&marker.alice)
            || [&marker.alice, &marker.bob]
                .iter()
                .any(|p| p.starts_with(&node.lab_root) || node.lab_root.starts_with(p))
            || node.project
                != if node.role == "alice" {
                    marker.alice.clone()
                } else {
                    marker.bob.clone()
                }
        {
            return Err(rejected());
        }
        fs::path(&marker.alice, true, false)?;
        fs::path(&marker.bob, true, false)?;
        if let Some(toolkit) = marker.toolkit {
            fs::path(&toolkit, true, false)?;
        }
        // Literal IPv4 loopback only: no DNS, credentials, query, alternate URL
        // spelling, redirect, CA file, or inherited broker configuration.
        let port = marker
            .broker_url
            .strip_prefix("nats://127.0.0.1:")
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|port| *port > 0)
            .ok_or_else(rejected)?;
        if marker.broker_url != format!("nats://127.0.0.1:{port}") {
            return Err(rejected());
        }
        let role_root = node.lab_root.join("private").join(&node.role);
        Ok(Self {
            broker_url: marker.broker_url,
            human: format!("sim-{}", node.role),
            agent: format!("sim-{}-agent", node.role),
            engine: role_root.join("engine"),
            remote: node.lab_root.join("shared.git"),
            role_root,
            node,
        })
    }

    pub fn prepare(&self) -> Result<(), Failure> {
        fs::directory(&self.node.lab_root.join("private"))?;
        fs::directory(&self.role_root)?;
        fs::directory(&self.engine)?;
        fs::tree(&self.role_root, false)
    }

    pub fn command(&self, input: &[String]) -> Result<Vec<String>, Failure> {
        let args = Args::parse(input).map_err(|_| rejected())?;
        let setup = matches!(args.command.as_str(), "team-init" | "team-request");
        if !matches!(
            args.command.as_str(),
            "team-init"
                | "team-request"
                | "team-admit"
                | "team-connect"
                | "team-send"
                | "team-say"
                | "team-inbox"
                | "team-status"
                | "team-broker-init"
                | "team-listen"
                | "team-flush"
        ) || (args.command == "team-init" && self.node.role != "alice")
            || (args.command == "team-request" && self.node.role != "bob")
            || (args.command == "team-admit" && self.node.role != "alice")
            || args.flag("--git-ssh-agent")
            || [
                "--git-author-name",
                "--git-author-email",
                "--git-signing-format",
                "--git-signing-key",
                "--git-credentials",
                "--ca-file",
            ]
            .iter()
            .any(|flag| args.get(flag).is_some())
            || args.get("--broker").is_some_and(|v| v != self.broker_url)
            || args.get("--peer").is_some_and(|v| v != "sim-bob-agent")
        {
            return Err(rejected());
        }
        let mut output = input.to_vec();
        let project = self.node.project.to_str().ok_or_else(rejected)?;
        let remote = self.remote.to_str().ok_or_else(rejected)?;
        for (flag, expected) in [
            ("--project", project),
            ("--project-id", &self.node.project_id),
            ("--human", &self.human),
            ("--as", &self.agent),
            ("--remote", remote),
            ("--branch", BRANCH),
        ] {
            if args.get(flag).is_some_and(|actual| actual != expected) {
                return Err(rejected());
            }
            if args.get(flag).is_none() && (flag == "--project" || setup) {
                output.extend([flag.to_owned(), expected.to_owned()]);
            }
        }
        if let Some(body) = args.get("--body-file").filter(|p| *p != "-") {
            let body = Path::new(body);
            if !body.starts_with(&self.node.project) {
                return Err(rejected());
            }
            fs::path(body, false, false)?;
        }
        fs::path(&self.remote, true, false)?;
        fs::tree(&self.remote, false)?;
        Ok(output)
    }

    pub fn token(&self) -> Result<String, Failure> {
        let bytes = fs::read(&self.node.lab_root.join("broker.token"), 4096, true)?;
        let token = String::from_utf8(bytes).map_err(|_| rejected())?;
        // Manager writes a single token, with an optional final newline.
        let token = token.strip_suffix('\n').unwrap_or(&token);
        if token.len() < 32
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(rejected());
        }
        Ok(token.to_owned())
    }

    pub fn check_pin(&self, own: &yhes_cli::signer::Descriptor) -> Result<(), Failure> {
        let ws = yhes_cli::profile::Workspace::locate(&self.engine, &self.node.project, false)?;
        let file = ws.private.join("network/team.json");
        if !fs::exists(&file)? {
            return Ok(());
        }
        let pin: yhes_cli::team::TeamPin =
            serde_json::from_slice(&fs::read(&file, 32_768, true)?).map_err(|_| rejected())?;
        if pin.version != 1
            || pin.project_id != self.node.project_id
            || Path::new(&pin.project_path) != self.node.project
            || Path::new(&pin.remote) != self.remote
            || pin.branch != BRANCH
            || pin.principal != self.agent
            || pin.human != *own
            || pin.owner != "sim-alice-agent"
            || pin.group != "team"
            || pin.git_options != yhes_core::git::GitOptions::default()
            || pin.authority.author != "sim-alice"
            || pin.authority.project != self.node.project_id
            || pin.authority.algorithm != "p256-sha256"
            || pin.authority.key().is_err()
            || (self.node.role == "alice" && pin.authority != *own)
        {
            return Err(rejected());
        }
        Ok(())
    }
}
