//! Real loopback NATS + bare Git, separate private stores and P-256 fixture
//! humans. No production Keychain, real credentials or native approvals.
mod team_support;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};
use team_support::Person;
use yhes_cli::{
    broker::{Broker, Config},
    Args, Deps,
};

const TOKEN: &str = "disposable-yhes-realtime-test-token";
struct Server {
    child: Option<Child>,
    dir: tempfile::TempDir,
    config: PathBuf,
    port: u16,
    binary: String,
}
impl Server {
    fn new() -> Self {
        let binary = std::env::var("YHES_NATS_SERVER")
            .expect("set YHES_NATS_SERVER to the official nats-server binary");
        let dir = tempfile::tempdir().unwrap();
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let config = dir.path().join("server.conf");
        fs::write(&config,format!("host: 127.0.0.1\nport: {port}\nauthorization {{ token: {TOKEN} }}\njetstream {{ store_dir: {} }}\n",serde_json::to_string(&dir.path().join("data")).unwrap())).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let mut s = Self {
            child: None,
            dir,
            config,
            port,
            binary,
        };
        s.start();
        s
    }
    fn url(&self) -> String {
        format!("nats://127.0.0.1:{}", self.port)
    }
    fn start(&mut self) {
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.path().join("server.log"))
            .unwrap();
        self.child = Some(
            Command::new(&self.binary)
                .arg("-c")
                .arg(&self.config)
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "NATS exited before readiness"
            );
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "NATS readiness timeout");
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

#[test]
#[ignore = "requires official nats-server via YHES_NATS_SERVER and openssl"]
fn tls_requires_trusted_ca_and_matching_hostname() {
    let mut server = Server::new();
    server.stop();
    let cert = server.dir.path().join("server.pem");
    let key = server.dir.path().join("server.key");
    let ca = server.dir.path().join("ca.pem");
    let ca_key = server.dir.path().join("ca.key");
    let csr = server.dir.path().join("server.csr");
    let ext = server.dir.path().join("server.ext");
    fs::write(&ext,"subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n").unwrap();
    assert!(Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=Disposable Yhes Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout"
        ])
        .arg(&ca_key)
        .arg("-out")
        .arg(&ca)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
    assert!(Command::new("openssl")
        .args([
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout"
        ])
        .arg(&key)
        .arg("-out")
        .arg(&csr)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
    assert!(Command::new("openssl")
        .args(["x509", "-req", "-sha256", "-days", "1", "-in"])
        .arg(&csr)
        .arg("-CA")
        .arg(&ca)
        .arg("-CAkey")
        .arg(&ca_key)
        .arg("-CAcreateserial")
        .arg("-extfile")
        .arg(&ext)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let mut config = fs::OpenOptions::new()
        .append(true)
        .open(&server.config)
        .unwrap();
    writeln!(
        config,
        "tls {{ cert_file: {}\n key_file: {}\n timeout: 2\n}}",
        serde_json::to_string(&cert).unwrap(),
        serde_json::to_string(&key).unwrap()
    )
    .unwrap();
    drop(config);
    server.start();
    let url = format!("tls://localhost:{}", server.port);
    assert!(Broker::connect(
        Config::new(&url, TOKEN, None).unwrap(),
        "demo",
        "team",
        "authority"
    )
    .is_err());
    let broker = Broker::connect(
        Config::new(&url, TOKEN, Some(ca.clone())).unwrap(),
        "demo",
        "team",
        "authority",
    )
    .unwrap();
    let initialized = broker.initialize().unwrap();
    // An existing stream with a widened operator configuration is not silently
    // adopted, even when its name, subjects and storage bounds still match.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let client = async_nats::ConnectOptions::new()
            .token(TOKEN.into())
            .require_tls(true)
            .add_root_certificates(ca.clone())
            .connect(&url)
            .await
            .unwrap();
        let context = async_nats::jetstream::new(client);
        let stream = context
            .get_stream(initialized["stream"].as_str().unwrap())
            .await
            .unwrap();
        let mut cfg = stream.cached_info().config.clone();
        cfg.allow_rollup = true;
        context.update_stream(cfg).await.unwrap();
    });
    assert_eq!(
        broker.initialize().unwrap_err().code,
        "broker_configuration"
    );
    let wrong_host = format!("tls://127.0.0.1:{}", server.port);
    assert!(Broker::connect(
        Config::new(&wrong_host, TOKEN, Some(ca)).unwrap(),
        "demo",
        "team",
        "authority"
    )
    .is_err());
}
enum Work {
    Run(Vec<String>),
    Prepare(String, String),
    Stop,
}
struct Progress(Sender<()>);
impl Write for Progress {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if String::from_utf8_lossy(buf).contains("realtime: waiting") {
            let _ = self.0.send(());
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Worker {
    tx: Sender<Work>,
    rx: Receiver<Value>,
    ready: Receiver<()>,
    handle: Option<thread::JoinHandle<()>>,
}
impl Worker {
    fn new(seed: u8) -> Self {
        let (tx, work) = mpsc::channel();
        let (results, rx) = mpsc::channel();
        let (ready_tx, ready) = mpsc::channel();
        let handle = thread::spawn(move || {
            let person = Person::new(seed);
            while let Ok(work) = work.recv() {
                let mut progress = Progress(ready_tx.clone());
                let mut deps = Deps {
                    signer: &person.signer,
                    custody: &person.custody,
                    clock: &person.clock,
                    private_root: person.private.clone(),
                    progress: &mut progress,
                };
                let value = match work {
                    Work::Stop => break,
                    Work::Run(mut args) => {
                        args.extend([
                            "--project".into(),
                            person.project.to_string_lossy().into_owned(),
                        ]);
                        let outcome = yhes_cli::run(&args, &mut &b""[..], true, &mut deps);
                        serde_json::from_str(&outcome.stdout).unwrap()
                    }
                    Work::Prepare(operation, text) => {
                        let args = Args::parse(&[
                            "team-status".into(),
                            "--project".into(),
                            person.project.to_string_lossy().into_owned(),
                        ])
                        .unwrap();
                        let mut session = yhes_cli::team::open(&args, &deps).unwrap();
                        yhes_cli::team::sync(&mut session, deps.clock.now()).unwrap();
                        let prepared = yhes_cli::team::prepare_message(
                            &mut session,
                            &mut deps,
                            false,
                            text,
                            &operation,
                        )
                        .unwrap();
                        json!({"ok":true,"packet":STANDARD.encode(prepared.packet),"result":prepared.result})
                    }
                };
                results.send(value).unwrap();
            }
        });
        Self {
            tx,
            rx,
            ready,
            handle: Some(handle),
        }
    }
    fn begin(&self, args: &[&str]) {
        self.tx
            .send(Work::Run(args.iter().map(|s| s.to_string()).collect()))
            .unwrap();
    }
    fn result(&self) -> Value {
        let v = self.rx.recv_timeout(Duration::from_secs(45)).unwrap();
        assert_eq!(v["ok"], true, "{v}");
        v
    }
    fn run(&self, args: &[&str]) -> Value {
        self.begin(args);
        self.result()
    }
    fn waiting(&self) {
        self.ready
            .recv_timeout(Duration::from_secs(20))
            .expect("listener did not reach its wait state");
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.tx.send(Work::Stop);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
#[ignore = "requires official nats-server via YHES_NATS_SERVER; runs real loopback networking"]
fn two_people_git_handshake_server_wakeup_human_relay_and_recovery() {
    let mut server = Server::new();
    let url = server.url();
    std::env::set_var("YHES_BROKER_TOKEN", TOKEN);
    let git = tempfile::tempdir().unwrap();
    let remote = git.path().join("team.git");
    assert!(Command::new("git")
        .args(["init", "--bare", "--quiet"])
        .arg(&remote)
        .status()
        .unwrap()
        .success());
    let remote = remote.to_str().unwrap();
    let alice = Worker::new(0x41);
    let bob = Worker::new(0x42);
    let a = alice.run(&[
        "team-init",
        "--human",
        "alice",
        "--as",
        "alice-agent",
        "--project-id",
        "demo",
        "--remote",
        remote,
    ]);
    let authority = a["authority"].as_str().unwrap();
    let bootstrap = a["bootstrap_head"]
        .as_str()
        .expect("team-init must return approved bootstrap head");
    let b = bob.run(&[
        "team-request",
        "--human",
        "bob",
        "--as",
        "bob-agent",
        "--project-id",
        "demo",
        "--remote",
        remote,
        "--authority",
        authority,
        "--bootstrap",
        bootstrap,
    ]);
    alice.run(&[
        "team-admit",
        "--peer",
        "bob-agent",
        "--peer-key",
        b["human_key"].as_str().unwrap(),
    ]);
    bob.run(&["team-connect"]);
    alice.run(&["team-connect"]);
    bob.run(&["team-connect"]);
    alice.run(&["team-broker-init", "--broker", &url]);
    let broker = Broker::connect(
        Config::new(&url, TOKEN, None).unwrap(),
        "demo",
        "team",
        authority,
    )
    .unwrap();

    bob.begin(&["team-listen", "--broker", &url, "--seconds", "10"]);
    bob.waiting();
    let sent = alice.run(&[
        "team-send",
        "--text",
        "live encrypted question",
        "--operation",
        "live-one",
        "--broker",
        &url,
    ]);
    assert_eq!(sent["realtime"]["state"], "published");
    let received = bob.result();
    assert_eq!(received["wake"], "broker");
    assert_eq!(received["messages"][0]["text"], "live encrypted question");
    assert_eq!(received["messages"][0]["disposition"], "verified");
    assert_eq!(
        received["messages"][0]["human_original_author"],
        Value::Null
    );
    let retry = alice.run(&[
        "team-send",
        "--text",
        "live encrypted question",
        "--operation",
        "live-one",
        "--broker",
        &url,
    ]);
    assert_eq!(retry["event_id"], sent["event_id"]);
    assert_eq!(retry["replayed"], true);
    assert_eq!(retry["realtime"]["already_sent"], 1);

    // A valid encrypted packet on NATS alone cannot consume a receive key.
    alice
        .tx
        .send(Work::Prepare("early-one".into(), "not in Git yet".into()))
        .unwrap();
    let prepared = alice.result();
    let packet = STANDARD
        .decode(prepared["packet"].as_str().unwrap())
        .unwrap();
    broker.publish(&packet).unwrap();
    let early = bob.run(&["team-listen", "--broker", &url, "--seconds", "1"]);
    assert_eq!(early["new_messages"], 0);
    assert!(early["unmatched_notifications"].as_u64().unwrap() > 0);
    assert_eq!(
        bob.run(&["team-inbox", "--no-sync"])["messages"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let archived = alice.run(&[
        "team-send",
        "--text",
        "not in Git yet",
        "--operation",
        "early-one",
        "--broker",
        &url,
    ]);
    assert_eq!(archived["event_id"], prepared["result"]["event_id"]);
    let after = bob.run(&["team-inbox"]);
    assert_eq!(after["new_messages"], 1);
    assert!(after["messages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["text"] == "not in Git yet"));

    bob.run(&[
        "team-say",
        "--text",
        "human original over the remote channel",
        "--operation",
        "human-one",
        "--broker",
        &url,
    ]);
    let relay = alice.run(&["team-inbox"]);
    let relay = &relay["messages"][0];
    assert_eq!(relay["origin"], "human-statement-relayed-by-agent");
    assert_eq!(relay["author"], "bob-agent");
    assert_eq!(relay["human_original_author"], "bob");
    assert_eq!(
        relay["human_text"],
        "human original over the remote channel"
    );

    // Garbage never becomes plaintext or membership; known Git history wins.
    broker.publish(b"untrusted broker data").unwrap();
    let poison = bob.run(&["team-listen", "--broker", &url, "--seconds", "1"]);
    assert_eq!(poison["new_messages"], 0);
    assert!(poison["unmatched_notifications"].as_u64().unwrap() > 0);
    assert!(Broker::connect(
        Config::new(&url, "wrong", None).unwrap(),
        "demo",
        "team",
        authority
    )
    .is_err());

    // Git publication survives a broker outage and exact notification retry.
    server.stop();
    let pending = alice.run(&[
        "team-send",
        "--text",
        "Git survives server outage",
        "--operation",
        "outage-one",
        "--broker",
        &url,
    ]);
    assert_eq!(pending["realtime"]["state"], "pending");
    assert_eq!(pending["realtime"]["git_confirmed"], true);
    let recovered = bob.run(&["team-inbox"]);
    assert_eq!(recovered["new_messages"], 1);
    server.start();
    alice.run(&["team-flush", "--broker", &url, "--operation", "outage-one"]);
    let history = bob.run(&["team-inbox", "--no-sync"]);
    assert_eq!(history["new_messages"], 0);
    assert_eq!(history["messages"].as_array().unwrap().len(), 3);
    assert_eq!(history["quarantined"], 0);
    std::env::remove_var("YHES_BROKER_TOKEN");
}
