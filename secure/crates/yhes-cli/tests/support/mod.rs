//! Test-only dependencies. Nothing here is linked into the `yhes` binary:
//! a software human key behind the signer protocol, and in-memory key custody.
#![allow(dead_code)]
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    path::PathBuf,
    rc::Rc,
};
use yhes_cli::{
    signer::{Request, SignerClient},
    Clock, Custody, Deps, Failure,
};
use yhes_core::keys::{Anchor, AnchorStore, StorageKey};
use yhes_wire::{
    pae, Algorithm, Envelope, PublicKey, SignatureEntry, EVENT_PAYLOAD_TYPE, REGISTRY_PAYLOAD_TYPE,
};

pub const NOW: u64 = 2_000_000_000;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Behavior {
    Honest,
    Cancel,
    Busy,
    /// Not JSON.
    Garbage,
    /// Valid shape plus an extra field.
    UnknownField,
    /// The `error` field is absent.
    MissingField,
    /// A well-formed success for some other request ID.
    OtherId,
    /// Signs a document that differs from the one submitted.
    SignsOtherDocument,
    /// Signs the right document with a key that is not the enrolled one.
    SignsWithOtherKey,
    /// Returns the previous successful reply line again.
    ReplaysPrevious,
}

/// A software human key. `P256` matches the native profile: a 65-byte
/// uncompressed SEC1 public key and raw 64-byte `r||s` signatures over
/// SHA-256 of the PAE. `Ed25519` is the wire profile's other algorithm.
pub enum HumanKey {
    Ed25519(SigningKey),
    P256(p256::ecdsa::SigningKey),
}
impl HumanKey {
    fn public(&self) -> PublicKey {
        match self {
            HumanKey::Ed25519(key) => {
                PublicKey::new(Algorithm::Ed25519, &key.verifying_key().to_bytes()).unwrap()
            }
            HumanKey::P256(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                assert_eq!(point.as_bytes().len(), 65);
                PublicKey::new(Algorithm::P256Sha256, point.as_bytes()).unwrap()
            }
        }
    }
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        match self {
            HumanKey::Ed25519(key) => key.sign(message).to_bytes(),
            HumanKey::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.to_bytes().into()
            }
        }
    }
}

/// A software stand-in for the native app's side of protocol v1.
pub struct FakeSigner {
    human: HumanKey,
    stranger: HumanKey,
    /// When set, the transport accepts only this algorithm, as the native one does.
    pub only: Cell<Option<Algorithm>>,
    enrolled: RefCell<Option<(String, String)>>,
    pub behavior: Cell<Behavior>,
    /// Applies `behavior` only from this review number on (1-based).
    pub misbehave_from: Cell<usize>,
    pub reviews: Cell<usize>,
    pub enrollments: Cell<usize>,
    /// Kinds reviewed, in order: `registry` or the event kind.
    pub reviewed: RefCell<Vec<String>>,
    last_ok: RefCell<Option<Vec<u8>>>,
}

fn seal(key: &HumanKey, payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let public = key.public();
    Envelope::new(
        payload_type,
        payload.to_vec(),
        vec![SignatureEntry {
            key_id: public.key_id(),
            algorithm: public.algorithm(),
            signature: key.sign(&pae(payload_type, payload)),
        }],
    )
    .unwrap()
    .to_json()
}

impl FakeSigner {
    pub fn new() -> Self {
        Self::with(
            HumanKey::Ed25519(SigningKey::from_bytes(&[71; 32])),
            HumanKey::Ed25519(SigningKey::from_bytes(&[72; 32])),
        )
    }
    /// The native profile's key type, from fixed test scalars.
    pub fn p256() -> Self {
        let key =
            |byte: u8| HumanKey::P256(p256::ecdsa::SigningKey::from_slice(&[byte; 32]).unwrap());
        let signer = Self::with(key(0x51), key(0x52));
        signer.only.set(Some(Algorithm::P256Sha256));
        signer
    }
    fn with(human: HumanKey, stranger: HumanKey) -> Self {
        Self {
            human,
            stranger,
            only: Cell::new(None),
            enrolled: RefCell::new(None),
            behavior: Cell::new(Behavior::Honest),
            misbehave_from: Cell::new(1),
            reviews: Cell::new(0),
            enrollments: Cell::new(0),
            reviewed: RefCell::new(vec![]),
            last_ok: RefCell::new(None),
        }
    }
    fn descriptor(&self, author: &str, project: &str) -> Vec<u8> {
        let public = self.human.public();
        serde_json::to_vec(&json!({
            "algorithm": public.algorithm().as_str(), "key_id": public.key_id().as_str(),
            "public_key": STANDARD.encode(public.as_bytes()),
            "author": author, "project": project,
        }))
        .unwrap()
    }
    fn reply(id: &str, status: &str, result: Option<&[u8]>, error: Option<&str>) -> Vec<u8> {
        let mut line = serde_json::to_vec(&json!({
            "version": 1, "id": id, "status": status,
            "result": result.map(|r| STANDARD.encode(r)), "error": error,
        }))
        .unwrap();
        line.push(b'\n');
        line
    }
}

impl SignerClient for FakeSigner {
    fn probe(&self) -> Result<(), Failure> {
        Ok(())
    }
    fn accepts(&self, algorithm: Algorithm) -> bool {
        self.only.get().is_none_or(|only| only == algorithm)
    }
    fn exchange(&self, request: &Request) -> Result<Vec<u8>, Failure> {
        // Parse the exact line the production transport would send.
        let line = request.encode()?;
        assert!(line.ends_with(b"\n") && !line[..line.len() - 1].contains(&b'\n'));
        let frame: Value = serde_json::from_slice(&line).unwrap();
        let object = frame.as_object().unwrap();
        let mut fields: Vec<&str> = object.keys().map(String::as_str).collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "author",
                "id",
                "mode",
                "operation",
                "payloads",
                "project",
                "request",
                "version"
            ]
        );
        let id = frame["id"].as_str().unwrap();
        let (author, project) = (
            frame["author"].as_str().unwrap(),
            frame["project"].as_str().unwrap(),
        );
        let operation = frame["operation"].as_str().unwrap();
        if operation != "review" {
            assert!(frame["mode"].is_null() && frame["request"].is_null());
            assert_eq!(frame["payloads"], json!([]));
            let enrolled = self.enrolled.borrow().clone();
            return Ok(match (operation, enrolled) {
                ("identity", None) => Self::reply(id, "error", None, Some("identity_missing")),
                ("enroll", None) => {
                    self.enrollments.set(self.enrollments.get() + 1);
                    *self.enrolled.borrow_mut() = Some((author.into(), project.into()));
                    Self::reply(id, "ok", Some(&self.descriptor(author, project)), None)
                }
                ("identity", Some((a, p))) if a == author && p == project => {
                    Self::reply(id, "ok", Some(&self.descriptor(author, project)), None)
                }
                ("enroll", Some(_)) => Self::reply(id, "error", None, Some("identity_exists")),
                _ => Self::reply(id, "error", None, Some("identity_mismatch")),
            });
        }
        let number = self.reviews.get() + 1;
        self.reviews.set(number);
        let payloads = frame["payloads"].as_array().unwrap();
        assert_eq!(payloads.len(), 1, "this CLI reviews one document at a time");
        let payload = STANDARD.decode(payloads[0].as_str().unwrap()).unwrap();
        let document: Value = serde_json::from_slice(&payload).unwrap();
        let mode = frame["mode"].as_str().unwrap();
        let (payload_type, kind) = match mode {
            "registry" => (REGISTRY_PAYLOAD_TYPE, "registry".to_owned()),
            "event" => (
                EVENT_PAYLOAD_TYPE,
                document["kind"].as_str().unwrap().to_owned(),
            ),
            other => panic!("unexpected review mode {other}"),
        };
        // The sidecar accompanies exactly the action authorization.
        assert_eq!(frame["request"].is_null(), kind != "action.authorization");
        assert_eq!(document["project"], json!(project));
        if mode == "event" {
            assert_eq!(document["author"], json!(author));
            assert!(document["session"].is_null());
        }
        self.reviewed.borrow_mut().push(kind);
        let behavior = if number >= self.misbehave_from.get() {
            self.behavior.get()
        } else {
            Behavior::Honest
        };
        let honest = || {
            Self::reply(
                id,
                "ok",
                Some(&seal(&self.human, payload_type, &payload)),
                None,
            )
        };
        Ok(match behavior {
            Behavior::Honest => {
                let line = honest();
                *self.last_ok.borrow_mut() = Some(line.clone());
                line
            }
            Behavior::Cancel => Self::reply(id, "cancelled", None, Some("cancelled")),
            Behavior::Busy => Self::reply(id, "error", None, Some("busy")),
            Behavior::Garbage => b"approved\n".to_vec(),
            Behavior::UnknownField => {
                let mut value: Value = serde_json::from_slice(&honest()).unwrap();
                value["approved_by"] = json!("touch-id");
                format!("{value}\n").into_bytes()
            }
            Behavior::MissingField => {
                let mut value: Value = serde_json::from_slice(&honest()).unwrap();
                value.as_object_mut().unwrap().remove("error");
                format!("{value}\n").into_bytes()
            }
            Behavior::OtherId => Self::reply(
                &uuid::Uuid::new_v4().to_string(),
                "ok",
                Some(&seal(&self.human, payload_type, &payload)),
                None,
            ),
            Behavior::SignsOtherDocument => {
                let mut other = document.clone();
                other["id"] = json!("substituted");
                let bytes = serde_json::to_vec(&other).unwrap();
                Self::reply(
                    id,
                    "ok",
                    Some(&seal(&self.human, payload_type, &bytes)),
                    None,
                )
            }
            Behavior::SignsWithOtherKey => Self::reply(
                id,
                "ok",
                Some(&seal(&self.stranger, payload_type, &payload)),
                None,
            ),
            Behavior::ReplaysPrevious => self.last_ok.borrow().clone().expect("a previous reply"),
        })
    }
}

type Keys = Rc<RefCell<HashMap<String, [u8; 32]>>>;
type Anchors = Rc<RefCell<HashMap<String, Anchor>>>;

/// In-memory stand-in for the platform keychain.
#[derive(Default)]
pub struct MemoryCustody {
    keys: Keys,
    anchors: Anchors,
}
struct MemoryAnchors(Anchors);
impl AnchorStore for MemoryAnchors {
    fn load(&self, account: &str) -> yhes_core::Result<Option<Anchor>> {
        Ok(self.0.borrow().get(account).cloned())
    }
    fn advance(
        &self,
        account: &str,
        expected: Option<&Anchor>,
        next: &Anchor,
    ) -> yhes_core::Result<()> {
        let mut anchors = self.0.borrow_mut();
        if anchors.get(account) != expected {
            return Err(yhes_core::Error::Conflict("checkpoint mismatch".into()));
        }
        anchors.insert(account.to_owned(), next.clone());
        Ok(())
    }
}
impl Custody for MemoryCustody {
    fn label(&self) -> &'static str {
        "injected-test"
    }
    fn create_key(&self, account: &str) -> yhes_core::Result<StorageKey> {
        let mut keys = self.keys.borrow_mut();
        if keys.contains_key(account) {
            return Err(yhes_core::Error::Conflict(
                "vault key reference already exists".into(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        keys.insert(account.to_owned(), bytes);
        Ok(StorageKey::from_bytes(bytes))
    }
    fn load_key(&self, account: &str) -> yhes_core::Result<StorageKey> {
        self.keys
            .borrow()
            .get(account)
            .map(|bytes| StorageKey::from_bytes(*bytes))
            .ok_or_else(|| yhes_core::Error::KeyProvider("vault key is not enrolled".into()))
    }
    fn anchors(&self) -> Box<dyn AnchorStore> {
        Box::new(MemoryAnchors(self.anchors.clone()))
    }
}

pub struct TestClock(pub Cell<u64>);
impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.get()
    }
}

pub struct Output {
    pub exit: i32,
    pub json: Value,
    pub stderr: String,
    pub stdout: String,
}
impl Output {
    pub fn ok(self) -> Value {
        assert_eq!(
            self.exit, 0,
            "command failed: {}\n{}",
            self.stdout, self.stderr
        );
        assert_eq!(self.json["ok"], json!(true));
        self.json
    }
    pub fn error(self) -> String {
        assert_ne!(
            self.exit, 0,
            "command unexpectedly succeeded: {}",
            self.stdout
        );
        assert_eq!(self.json["ok"], json!(false));
        self.json["error"]["code"].as_str().unwrap().to_owned()
    }
}

/// One Mac: a shared project folder, a private engine folder, a signer and custody.
pub struct Machine {
    _root: tempfile::TempDir,
    pub project: PathBuf,
    pub private: PathBuf,
    pub signer: FakeSigner,
    pub custody: MemoryCustody,
    pub clock: TestClock,
}

impl Machine {
    pub fn new() -> Self {
        Self::with(FakeSigner::new())
    }
    pub fn with(signer: FakeSigner) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let project = base.join("demo-project");
        std::fs::create_dir(&project).unwrap();
        Self {
            private: base.join("engine"),
            project,
            _root: root,
            signer,
            custody: MemoryCustody::default(),
            clock: TestClock(Cell::new(NOW)),
        }
    }
    /// Every call is a new process as far as the CLI is concerned: nothing but
    /// the folders, the custody and the signer survives between calls.
    pub fn run_with_stdin(&self, argv: &[&str], stdin: &str) -> Output {
        let mut argv: Vec<String> = argv.iter().map(|a| (*a).to_owned()).collect();
        if argv.first().is_some_and(|c| c != "help") && !argv.iter().any(|a| a == "--project") {
            argv.push("--project".into());
            argv.push(self.project.to_str().unwrap().into());
        }
        let mut progress = Vec::new();
        let mut input = stdin.as_bytes();
        let outcome = {
            let mut deps = Deps {
                signer: &self.signer,
                custody: &self.custody,
                clock: &self.clock,
                private_root: self.private.clone(),
                progress: &mut progress,
            };
            yhes_cli::run(&argv, &mut input, true, &mut deps)
        };
        Output {
            exit: outcome.exit,
            json: serde_json::from_str(&outcome.stdout).unwrap_or(Value::Null),
            stderr: String::from_utf8(progress).unwrap(),
            stdout: outcome.stdout,
        }
    }
    pub fn run(&self, argv: &[&str]) -> Output {
        self.run_with_stdin(argv, "")
    }
    pub fn pilot(&self) -> Value {
        self.run(&["pilot", "--human", "alice"]).ok()
    }
    pub fn advance(&self, seconds: u64) {
        self.clock.0.set(self.clock.0.get() + seconds);
    }
    /// True if `needle` occurs in any file under `directory`.
    pub fn leaks(directory: &std::path::Path, needle: &str) -> bool {
        let mut stack = vec![directory.to_path_buf()];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if std::fs::read(&path)
                    .unwrap()
                    .windows(needle.len())
                    .any(|w| w == needle.as_bytes())
                {
                    return true;
                }
            }
        }
        false
    }
}
