#![allow(dead_code)]
#[path = "../support/mod.rs"]
mod shared;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde_json::{json, Value};
pub use shared::{MemoryCustody, Output, TestClock, NOW};
use std::{
    cell::{Cell, RefCell},
    path::{Path, PathBuf},
    process::Command,
};
use yhes_cli::{
    signer::{Descriptor, Request, SignerClient},
    Deps, Failure,
};
use yhes_wire::{
    Algorithm, Envelope, PublicKey, SignatureEntry, EVENT_PAYLOAD_TYPE, REGISTRY_PAYLOAD_TYPE,
};

/// A distinct software identity per simulated person. Test binary only.
pub struct Human {
    key: SigningKey,
    enrolled: RefCell<Option<(String, String)>>,
    pub reviews: RefCell<Vec<Value>>,
    pub cancel_at: Cell<Option<usize>>,
}
impl Human {
    pub fn new(byte: u8) -> Self {
        Self {
            key: SigningKey::from_slice(&[byte; 32]).unwrap(),
            enrolled: RefCell::new(None),
            reviews: RefCell::new(Vec::new()),
            cancel_at: Cell::new(None),
        }
    }
    pub fn public(&self) -> PublicKey {
        PublicKey::new(
            Algorithm::P256Sha256,
            self.key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap()
    }
    pub fn fingerprint(&self) -> String {
        self.public().key_id().to_string()
    }
    pub fn descriptor(&self, author: &str, project: &str) -> Descriptor {
        let key = self.public();
        Descriptor {
            algorithm: key.algorithm().as_str().into(),
            key_id: key.key_id().to_string(),
            public_key: STANDARD.encode(key.as_bytes()),
            author: author.into(),
            project: project.into(),
        }
    }
    pub fn seal(&self, ty: &str, payload: &[u8]) -> String {
        let signature: Signature = self.key.sign(&yhes_wire::pae(ty, payload));
        String::from_utf8(
            Envelope::new(
                ty,
                payload.to_vec(),
                vec![SignatureEntry {
                    key_id: self.public().key_id(),
                    algorithm: Algorithm::P256Sha256,
                    signature: signature.to_bytes().into(),
                }],
            )
            .unwrap()
            .to_json(),
        )
        .unwrap()
    }
}
impl SignerClient for Human {
    fn probe(&self) -> Result<(), Failure> {
        Ok(())
    }
    fn accepts(&self, algorithm: Algorithm) -> bool {
        algorithm == Algorithm::P256Sha256
    }
    fn exchange(&self, request: &Request) -> Result<Vec<u8>, Failure> {
        let frame: Value = serde_json::from_slice(&request.encode()?).unwrap();
        let author = frame["author"].as_str().unwrap();
        let project = frame["project"].as_str().unwrap();
        let mut error = None;
        let mut status = "ok";
        let data = match frame["operation"].as_str().unwrap() {
            "identity" => match self.enrolled.borrow().as_ref() {
                Some((a, p)) if a == author && p == project => {
                    Some(serde_json::to_vec(&self.descriptor(author, project)).unwrap())
                }
                Some(_) => {
                    error = Some("identity_mismatch");
                    None
                }
                None => {
                    error = Some("identity_missing");
                    None
                }
            },
            "enroll" => {
                assert!(self.enrolled.borrow().is_none());
                *self.enrolled.borrow_mut() = Some((author.into(), project.into()));
                Some(serde_json::to_vec(&self.descriptor(author, project)).unwrap())
            }
            "review" => {
                assert_eq!(
                    self.enrolled.borrow().as_ref(),
                    Some(&(author.to_owned(), project.to_owned()))
                );
                let payload = STANDARD
                    .decode(frame["payloads"][0].as_str().unwrap())
                    .unwrap();
                let document: Value = serde_json::from_slice(&payload).unwrap();
                assert_eq!(document["project"], project);
                let ty = if frame["mode"] == "registry" {
                    REGISTRY_PAYLOAD_TYPE
                } else {
                    assert_eq!(document["author"], author);
                    assert_eq!(
                        frame["request"].is_null(),
                        document["kind"] != "action.authorization"
                    );
                    EVENT_PAYLOAD_TYPE
                };
                self.reviews.borrow_mut().push(document);
                if self.cancel_at.get() == Some(self.reviews.borrow().len()) {
                    status = "cancelled";
                    error = Some("cancelled");
                    None
                } else {
                    Some(self.seal(ty, &payload).into_bytes())
                }
            }
            _ => panic!("unexpected signer endpoint"),
        };
        if error.is_some() && status != "cancelled" {
            status = "error";
        }
        Ok(format!("{}\n",json!({"version":1,"id":frame["id"],"status":status,"error":error,"result":data.map(|d|STANDARD.encode(d))})).into_bytes())
    }
}
pub struct Person {
    root: tempfile::TempDir,
    pub project: PathBuf,
    pub private: PathBuf,
    pub signer: Human,
    pub custody: MemoryCustody,
    pub clock: TestClock,
}
impl Person {
    pub fn engine(&self) -> yhes_core::engine::Engine {
        use yhes_cli::Custody;
        let ws = yhes_cli::profile::Workspace::locate(&self.private, &self.project, false).unwrap();
        let pin: yhes_cli::team::TeamPin =
            serde_json::from_slice(&std::fs::read(self.network().join("team.json")).unwrap())
                .unwrap();
        let account = ws.account(&format!("network-{}", pin.principal));
        let vault = yhes_core::store::Vault::open(
            &self.network().join(&pin.principal).join("vault.db"),
            &self.custody.load_key(&account).unwrap(),
            &pin.project_id,
            &account,
            self.custody.anchors(),
        )
        .unwrap();
        yhes_core::engine::Engine::open(
            vault,
            yhes_core::trust::ProjectTrust::new(
                &pin.project_id,
                vec![pin.authority.key().unwrap()],
                1,
            )
            .unwrap(),
            &pin.principal,
        )
        .unwrap()
    }
    pub fn new(byte: u8) -> Self {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let project = base.join("source");
        std::fs::create_dir(&project).unwrap();
        Self {
            root,
            project,
            private: base.join("private"),
            signer: Human::new(byte),
            custody: MemoryCustody::default(),
            clock: TestClock(Cell::new(NOW)),
        }
    }
    pub fn run(&self, argv: &[&str]) -> Output {
        let mut args: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        args.extend([
            "--project".into(),
            self.project.to_string_lossy().into_owned(),
        ]);
        let mut input = &b""[..];
        let mut progress = Vec::new();
        let outcome = yhes_cli::run(
            &args,
            &mut input,
            true,
            &mut Deps {
                signer: &self.signer,
                custody: &self.custody,
                clock: &self.clock,
                private_root: self.private.clone(),
                progress: &mut progress,
            },
        );
        Output {
            exit: outcome.exit,
            json: serde_json::from_str(&outcome.stdout).unwrap(),
            stderr: String::from_utf8(progress).unwrap(),
            stdout: outcome.stdout,
        }
    }
    pub fn advance(&self, seconds: u64) {
        self.clock.0.set(self.clock.0.get() + seconds);
    }
    pub fn network(&self) -> PathBuf {
        yhes_cli::profile::Workspace::locate(&self.private, &self.project, false)
            .unwrap()
            .private
            .join("network")
    }
}
pub struct Team {
    pub root: tempfile::TempDir,
    pub remote: String,
    pub founder: Person,
    pub peer: Person,
}
impl Team {
    pub fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap().join("team.git");
        assert!(Command::new("git")
            .args(["init", "--bare", "--quiet", "--template="])
            .arg(&path)
            .status()
            .unwrap()
            .success());
        Self {
            root,
            remote: path.to_string_lossy().into_owned(),
            founder: Person::new(0x31),
            peer: Person::new(0x32),
        }
    }
    pub fn init(&self) -> Value {
        self.founder
            .run(&[
                "team-init",
                "--project-id",
                "demo",
                "--human",
                "alice",
                "--as",
                "alice-agent",
                "--remote",
                &self.remote,
            ])
            .ok()
    }
    pub fn request(&self) -> Value {
        self.peer
            .run(&[
                "team-request",
                "--project-id",
                "demo",
                "--human",
                "bob",
                "--as",
                "bob-agent",
                "--remote",
                &self.remote,
                "--authority",
                &self.founder.signer.fingerprint(),
                "--bootstrap",
                &self.bootstrap(),
            ])
            .ok()
    }
    pub fn bootstrap(&self) -> String {
        let bytes = self
            .channel(&self.founder)
            .read_public("registry-1.json")
            .unwrap()
            .unwrap();
        Envelope::parse(&bytes, REGISTRY_PAYLOAD_TYPE)
            .unwrap()
            .digest()
            .to_hex()
    }
    pub fn admit(&self) -> Value {
        self.founder
            .run(&[
                "team-admit",
                "--peer",
                "bob-agent",
                "--peer-key",
                &self.peer.signer.fingerprint(),
            ])
            .ok()
    }
    pub fn setup(&self) {
        self.init();
        self.request();
        self.admit();
        assert_eq!(
            self.peer.run(&["team-connect"]).ok()["state"],
            "waiting-for-invitation"
        );
        assert_eq!(self.founder.run(&["team-connect"]).ok()["state"], "ready");
        assert_eq!(self.peer.run(&["team-connect"]).ok()["state"], "ready");
    }
    pub fn channel(&self, person: &Person) -> yhes_core::git::GitChannel {
        let pin: yhes_cli::team::TeamPin =
            serde_json::from_slice(&std::fs::read(person.network().join("team.json")).unwrap())
                .unwrap();
        yhes_core::git::GitChannel::open_with_options(
            &person.network().join("git"),
            &self.remote,
            "agent-yhes/secure-team",
            "demo",
            pin.git_options,
        )
        .unwrap()
    }
}
pub fn git(remote: &str, args: &[&str]) -> Vec<u8> {
    let result = Command::new("git")
        .arg("--git-dir")
        .arg(remote)
        .args(args)
        .output()
        .unwrap();
    assert!(result.status.success(), "git failed");
    result.stdout
}
pub fn files(path: &Path) -> Vec<PathBuf> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            all.extend(files(&path));
        } else {
            all.push(path);
        }
    }
    all
}
