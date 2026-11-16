// Disposable test identities and in-memory custody only. No platform keychain.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{cell::RefCell, rc::Rc};
use yhes_core::{
    engine::{Engine, PublicIdentity},
    keys::{Anchor, AnchorStore, StorageKey},
    store::Vault,
    trust::ProjectTrust,
    Control, SignedContent,
};
use yhes_wire::{Algorithm, Digest, Envelope, Event, Kind, EVENT_PAYLOAD_TYPE};
#[derive(Clone, Default)]
struct MemoryAnchors(Rc<RefCell<Option<Anchor>>>);
impl AnchorStore for MemoryAnchors {
    fn load(&self, _: &str) -> yhes_core::Result<Option<Anchor>> {
        Ok(self.0.borrow().clone())
    }
    fn advance(&self, _: &str, expected: Option<&Anchor>, next: &Anchor) -> yhes_core::Result<()> {
        if self.0.borrow().as_ref() != expected {
            return Err(yhes_core::Error::Storage);
        }
        *self.0.borrow_mut() = Some(next.clone());
        Ok(())
    }
}
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
use yhes_wire::{Body, KeyId, PublicKey, SignatureEntry, REGISTRY_PAYLOAD_TYPE};
const NOW: u64 = 2_000_000_000;
const GROUP: &str = "engineering";
fn pubkey(k: &SigningKey) -> PublicKey {
    PublicKey::new(Algorithm::Ed25519, &k.verifying_key().to_bytes()).unwrap()
}
fn seal(k: &SigningKey, payload_type: &str, payload: &[u8]) -> String {
    let p = pubkey(k);
    let signature = k.sign(&yhes_wire::pae(payload_type, payload)).to_bytes();
    String::from_utf8(
        Envelope::new(
            payload_type,
            payload.to_vec(),
            vec![SignatureEntry {
                key_id: p.key_id(),
                algorithm: p.algorithm(),
                signature,
            }],
        )
        .unwrap()
        .to_json(),
    )
    .unwrap()
}
fn signed_json(k: &SigningKey, ty: &str, value: &Value) -> String {
    seal(k, ty, &serde_json::to_vec(value).unwrap())
}
struct Node {
    engine: Option<Engine>,
    directory: tempfile::TempDir,
    key: StorageKey,
    anchors: MemoryAnchors,
    identity: PublicIdentity,
}
impl Node {
    fn new(name: &str, root: &SigningKey) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().canonicalize().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let key = StorageKey::generate();
        let anchors = MemoryAnchors::default();
        let vault = Vault::create(
            &path.join("vault.db"),
            &key,
            "fixture",
            name,
            Box::new(anchors.clone()),
        )
        .unwrap();
        let mut engine = Engine::open(
            vault,
            ProjectTrust::new("fixture", vec![pubkey(root)], 1).unwrap(),
            name,
        )
        .unwrap();
        let identity = engine.identity().unwrap();
        Self {
            engine: Some(engine),
            directory,
            key,
            anchors,
            identity,
        }
    }
    fn e(&mut self) -> &mut Engine {
        self.engine.as_mut().unwrap()
    }
    fn path(&self) -> PathBuf {
        self.directory
            .path()
            .canonicalize()
            .unwrap()
            .join("vault.db")
    }
    fn restart(&mut self, root: &SigningKey) {
        drop(self.engine.take());
        let vault = Vault::open(
            &self.path(),
            &self.key,
            "fixture",
            &self.identity.principal,
            Box::new(self.anchors.clone()),
        )
        .unwrap();
        self.engine = Some(
            Engine::open(
                vault,
                ProjectTrust::new("fixture", vec![pubkey(root)], 1).unwrap(),
                &self.identity.principal,
            )
            .unwrap(),
        );
    }
}
struct World {
    root: SigningKey,
    human: SigningKey,
    other: SigningKey,
    alice: Node,
    bob: Node,
    carol: Node,
}
impl World {
    fn new() -> Self {
        let root = SigningKey::from_bytes(&[31; 32]);
        let human = SigningKey::from_bytes(&[32; 32]);
        let other = SigningKey::from_bytes(&[33; 32]);
        let mut alice = Node::new("builder", &root);
        let mut bob = Node::new("reviewer", &root);
        let mut carol = Node::new("third", &root);
        let mut keys = vec![];
        for (id, k) in [("alice", &human), ("bob", &other)] {
            let p = pubkey(k);
            keys.push(json!({"key_id":p.key_id().as_str(),"participant":id,"algorithm":"ed25519","public_key":STANDARD.encode(p.as_bytes()),"not_before":NOW-86400,"not_after":NOW+86400}));
        }
        for n in [&alice, &bob, &carol] {
            keys.push(json!({"key_id":n.identity.key_id,"participant":n.identity.principal,"algorithm":"ed25519","public_key":n.identity.public_key,"not_before":NOW-86400,"not_after":NOW+86400}));
        }
        keys.sort_by_key(|k| k["key_id"].as_str().unwrap().to_owned());
        let registry = json!({"version":1,"project":"fixture","generation":1,"previous":null,"issued_at":NOW-100,"expires_at":NOW+86400,
            "participants":[{"id":"alice","kind":"human","controller":null,"ghes":{"instance":"ghe.example","user_id":1001}},
                {"id":"bob","kind":"human","controller":null,"ghes":{"instance":"ghe.example","user_id":1002}},
                {"id":"builder","kind":"agent","controller":"alice","ghes":null},
                {"id":"reviewer","kind":"agent","controller":"bob","ghes":null},
                {"id":"third","kind":"agent","controller":"alice","ghes":null}],"keys":keys,"revocations":[]});
        let bytes = signed_json(&root, REGISTRY_PAYLOAD_TYPE, &registry);
        for node in [&mut alice, &mut bob, &mut carol] {
            node.e()
                .bootstrap_registry(
                    &[bytes.as_bytes()],
                    Envelope::parse(bytes.as_bytes(), REGISTRY_PAYLOAD_TYPE)
                        .unwrap()
                        .digest(),
                    NOW,
                )
                .unwrap();
        }
        Self {
            root,
            human,
            other,
            alice,
            bob,
            carol,
        }
    }
    fn grant(&self, node: &PublicIdentity) -> String {
        let (author, key) = if node.principal == "reviewer" {
            ("bob", &self.other)
        } else {
            ("alice", &self.human)
        };
        let p = pubkey(key);
        let e = Event {
            id: format!("delegation-{}", node.principal),
            project: "fixture".into(),
            author: author.into(),
            key_id: p.key_id(),
            session: None,
            issued_at: NOW,
            expires_at: NOW + 3000,
            audience: vec!["builder".into(), "reviewer".into(), "third".into()],
            group: Some(GROUP.into()),
            epoch: None,
            previous: None,
            body: Body::AgentDelegation {
                agent: node.principal.clone(),
                agent_key_id: KeyId::parse(&node.key_id).unwrap(),
                purposes: vec![Kind::ActionExecute, Kind::AgentMessage, Kind::AgentRelay],
            },
        };
        seal(key, EVENT_PAYLOAD_TYPE, &e.to_payload().unwrap())
    }
    fn event(
        node: &PublicIdentity,
        id: &str,
        body: Body,
        audience: Vec<String>,
        epoch: u64,
        grant: &str,
    ) -> Event {
        Event {
            id: id.into(),
            project: "fixture".into(),
            author: node.principal.clone(),
            key_id: KeyId::parse(&node.key_id).unwrap(),
            session: Some(
                Envelope::parse(grant.as_bytes(), EVENT_PAYLOAD_TYPE)
                    .unwrap()
                    .digest(),
            ),
            issued_at: NOW,
            expires_at: NOW + 2000,
            audience,
            group: Some(GROUP.into()),
            epoch: Some(epoch),
            previous: None,
            body,
        }
    }
    fn control(
        &mut self,
        id: &str,
        action: &str,
        epoch: u64,
        audience: Vec<String>,
        parameters: Value,
        kp: Option<Vec<u8>>,
    ) -> Control {
        let request=serde_json::to_string(&json!({"version":1,"project":"fixture","action":action,"performer":"builder","group":GROUP,"epoch":epoch,"audience":audience,"parameters":parameters})).unwrap();
        let digest = Digest::of(request.as_bytes());
        let human = pubkey(&self.human);
        let authorization = Event {
            id: format!("approve-{id}"),
            project: "fixture".into(),
            author: "alice".into(),
            key_id: human.key_id(),
            session: None,
            issued_at: NOW,
            expires_at: NOW + 300,
            audience: audience.clone(),
            group: Some(GROUP.into()),
            epoch: Some(epoch),
            previous: None,
            body: Body::ActionAuthorization {
                action: action.into(),
                request_digest: digest,
                performer: "builder".into(),
            },
        };
        let auth = seal(
            &self.human,
            EVENT_PAYLOAD_TYPE,
            &authorization.to_payload().unwrap(),
        );
        let grant = self.grant(&self.alice.identity);
        let event = Self::event(
            &self.alice.identity,
            id,
            Body::ActionExecute {
                action: action.into(),
                request_digest: digest,
                authorization: Envelope::parse(auth.as_bytes(), EVENT_PAYLOAD_TYPE)
                    .unwrap()
                    .digest(),
            },
            audience,
            epoch,
            &grant,
        );
        let content = self
            .alice
            .e()
            .sign_event(event, Some(grant), Some(auth), None, NOW)
            .unwrap();
        Control {
            content,
            request,
            key_package: kp.map(|b| STANDARD.encode(b)),
        }
    }
    fn message(
        &mut self,
        id: &str,
        text: &str,
        epoch: u64,
        audience: Vec<String>,
    ) -> SignedContent {
        let grant = self.grant(&self.alice.identity);
        let event = Self::event(
            &self.alice.identity,
            id,
            Body::AgentMessage { text: text.into() },
            audience,
            epoch,
            &grant,
        );
        self.alice
            .e()
            .sign_event(event, Some(grant), None, None, NOW)
            .unwrap()
    }
}
