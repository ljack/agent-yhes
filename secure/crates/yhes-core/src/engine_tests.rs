use super::*;
use crate::{keys::StorageKey, store::tests::MemoryAnchors};
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
    registry: Value,
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
            registry,
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
    fn pair(&mut self) {
        let control = self.control(
            "create",
            "group.create",
            0,
            vec!["builder".into()],
            json!({}),
            None,
        );
        let genesis = self.alice.e().create_group("create", control, NOW).unwrap();
        self.alice
            .e()
            .confirm_publication("create", &genesis, "git-fixture-genesis", NOW)
            .unwrap();
        let kp = self.bob.e().key_package("kp-reviewer", NOW).unwrap();
        let control=self.control("add-reviewer","group.add",0,vec!["builder".into(),"reviewer".into()],json!({"member":"reviewer","key_id":self.bob.identity.key_id,"key_package_digest":Digest::of(&kp).to_hex()}),Some(kp));
        let add = self
            .alice
            .e()
            .change_membership("add-reviewer", control, NOW)
            .unwrap();
        self.alice
            .e()
            .confirm_publication("add-reviewer", &add, "git-fixture-add", NOW)
            .unwrap();
        self.bob.e().join(GROUP, "builder", &add, NOW).unwrap();
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
#[test]
fn signed_human_relay_survives_encryption_retry_and_restart() {
    let mut w = World::new();
    w.pair();
    let audience = vec!["builder".into(), "reviewer".into()];
    let human = Event {
        id: "human-decision".into(),
        project: "fixture".into(),
        author: "alice".into(),
        key_id: pubkey(&w.human).key_id(),
        session: None,
        issued_at: NOW,
        expires_at: NOW + 2000,
        audience: audience.clone(),
        group: Some(GROUP.into()),
        epoch: Some(1),
        previous: None,
        body: Body::HumanStatement {
            text: "PRIVATE_HUMAN_DECISION_41817: use the reviewed design.".into(),
        },
    };
    let original = seal(&w.human, EVENT_PAYLOAD_TYPE, &human.to_payload().unwrap());
    let grant = w.grant(&w.alice.identity);
    let event = World::event(
        &w.alice.identity,
        "relay",
        Body::AgentRelay {
            original: Envelope::parse(original.as_bytes(), EVENT_PAYLOAD_TYPE).unwrap(),
            note: Some("Agent handoff; original retained.".into()),
        },
        audience,
        1,
        &grant,
    );
    let content = w
        .alice
        .e()
        .sign_event(event, Some(grant), None, None, NOW)
        .unwrap();
    let packet = w
        .alice
        .e()
        .prepare_message("send-relay", GROUP, content.clone(), NOW)
        .unwrap();
    assert!(!String::from_utf8_lossy(&packet).contains("PRIVATE_HUMAN"));
    w.alice.restart(&w.root);
    assert_eq!(
        packet,
        w.alice
            .e()
            .prepare_message("send-relay", GROUP, content, NOW)
            .unwrap()
    );
    let delivery = w.bob.e().receive(&packet, NOW).unwrap();
    assert_eq!(delivery.disposition, "verified");
    assert!(!delivery.replayed);
    let message = delivery.message.unwrap();
    assert_eq!(message.author, "builder");
    assert!(!message.human_authored);
    assert_eq!(message.human_original_author.as_deref(), Some("alice"));
    w.bob.restart(&w.root);
    let retried = w.bob.e().receive(&packet, NOW).unwrap();
    assert!(retried.replayed);
    assert_eq!(retried.message.unwrap().event_id, "relay");
    for n in [&w.alice, &w.bob] {
        for f in fs::read_dir(n.directory.path()).unwrap() {
            let bytes = fs::read(f.unwrap().path()).unwrap();
            let marker = b"PRIVATE_HUMAN_DECISION_41817: ";
            assert!(!bytes.windows(marker.len()).any(|v| v == marker));
        }
    }
}
#[test]
fn tampering_unauthorized_join_scope_and_revocation_are_rejected() {
    let mut w = World::new();
    w.pair();
    let content = w.message(
        "message",
        "confidential",
        1,
        vec!["builder".into(), "reviewer".into()],
    );
    let bytes = w
        .alice
        .e()
        .prepare_message("send", GROUP, content, NOW)
        .unwrap();
    let mut altered: Value = serde_json::from_slice(&bytes).unwrap();
    let mut ciphertext = STANDARD
        .decode(altered["ciphertext"].as_str().unwrap())
        .unwrap();
    ciphertext[20] ^= 1;
    altered["ciphertext"] = json!(STANDARD.encode(ciphertext));
    assert!(w
        .bob
        .e()
        .receive(&serde_json::to_vec(&altered).unwrap(), NOW)
        .is_err());
    assert_eq!(
        w.bob.e().receive(&bytes, NOW).unwrap().disposition,
        "verified"
    );
    assert!(w.carol.e().receive(&bytes, NOW).is_err());
    let mut bad_event = World::event(
        &w.alice.identity,
        "forged",
        Body::HumanStatement {
            text: "pretend human".into(),
        },
        vec!["builder".into()],
        1,
        &w.grant(&w.alice.identity),
    );
    bad_event.session = None;
    assert!(w
        .alice
        .e()
        .sign_event(bad_event, None, None, None, NOW)
        .is_err());
    let previous = Envelope::parse(
        signed_json(&w.root, REGISTRY_PAYLOAD_TYPE, &w.registry).as_bytes(),
        REGISTRY_PAYLOAD_TYPE,
    )
    .unwrap()
    .digest();
    let old = w.registry.clone();
    w.registry["generation"] = json!(2);
    w.registry["previous"] = json!(previous.to_hex());
    w.registry["revocations"] = json!([{"key_id":w.alice.identity.key_id,"revoked_at":NOW}]);
    let update = signed_json(&w.root, REGISTRY_PAYLOAD_TYPE, &w.registry);
    w.alice
        .e()
        .install_registry(update.as_bytes(), NOW)
        .unwrap();
    assert!(w.alice.e().ready("send", NOW).is_err());
    assert!(w
        .alice
        .e()
        .install_registry(
            signed_json(&w.root, REGISTRY_PAYLOAD_TYPE, &old).as_bytes(),
            NOW
        )
        .is_err());
}
#[test]
fn membership_add_remove_fences_old_packets_and_removed_member() {
    let mut w = World::new();
    w.pair();
    let content = w.message(
        "unsent",
        "old audience",
        1,
        vec!["builder".into(), "reviewer".into()],
    );
    w.alice
        .e()
        .prepare_message("unsent", GROUP, content, NOW)
        .unwrap();
    let kp = w.carol.e().key_package("kp-third", NOW).unwrap();
    let control=w.control("add-third","group.add",1,vec!["builder".into(),"reviewer".into(),"third".into()],json!({"member":"third","key_id":w.carol.identity.key_id,"key_package_digest":Digest::of(&kp).to_hex()}),Some(kp));
    let changed = control.clone();
    let add = w
        .alice
        .e()
        .change_membership("add-third", control, NOW)
        .unwrap();
    assert_eq!(
        add,
        w.alice
            .e()
            .change_membership("add-third", changed, NOW)
            .unwrap()
    );
    let content = w.message(
        "while-pending",
        "wait",
        1,
        vec!["builder".into(), "reviewer".into()],
    );
    assert!(w
        .alice
        .e()
        .prepare_message("while-pending", GROUP, content, NOW)
        .is_err());
    w.alice
        .e()
        .confirm_publication("add-third", &add, "git-fixture-third", NOW)
        .unwrap();
    assert_eq!(
        w.bob.e().receive(&add, NOW).unwrap().disposition,
        "membership"
    );
    w.carol.e().join(GROUP, "builder", &add, NOW).unwrap();
    assert!(w.alice.e().ready("unsent", NOW).is_err());
    let content = w.message(
        "all-three",
        "three-way encrypted",
        2,
        vec!["builder".into(), "reviewer".into(), "third".into()],
    );
    let packet = w
        .alice
        .e()
        .prepare_message("all-three", GROUP, content, NOW)
        .unwrap();
    assert_eq!(
        w.bob.e().receive(&packet, NOW).unwrap().disposition,
        "verified"
    );
    assert_eq!(
        w.carol.e().receive(&packet, NOW).unwrap().disposition,
        "verified"
    );
    let control = w.control(
        "remove-reviewer",
        "group.remove",
        2,
        vec!["builder".into(), "third".into()],
        json!({"member":"reviewer"}),
        None,
    );
    let remove = w
        .alice
        .e()
        .change_membership("remove-reviewer", control, NOW)
        .unwrap();
    w.alice
        .e()
        .confirm_publication("remove-reviewer", &remove, "git-fixture-remove", NOW)
        .unwrap();
    w.bob.e().receive(&remove, NOW).unwrap();
    w.carol.e().receive(&remove, NOW).unwrap();
    let content = w.message(
        "after-remove",
        "new epoch",
        3,
        vec!["builder".into(), "third".into()],
    );
    let packet = w
        .alice
        .e()
        .prepare_message("after-remove", GROUP, content, NOW)
        .unwrap();
    assert!(w.bob.e().receive(&packet, NOW).is_err());
    assert_eq!(
        w.carol.e().receive(&packet, NOW).unwrap().disposition,
        "verified"
    );
}

// Deliberately bypass the outgoing policy in this test module to model an
// enrolled, malicious MLS member. No such endpoint is compiled into the engine.
fn malicious_packet(node: &mut Node, id: &str, content: &SignedContent) -> Vec<u8> {
    node.e()
        .vault
        .transaction(|db| {
            let signer = AgentSigner::load(db)?;
            let g = group(db, GROUP)?;
            let sealed = mls::send(db, &signer, &g.mls_id, &content.bytes()?)?;
            let digest: String = storage(db.query_row(
                "SELECT digest FROM yhes_registry ORDER BY generation DESC LIMIT 1",
                [],
                |r| r.get(0),
            ))?;
            let h = Header {
                version: 1,
                project: "fixture".into(),
                operation: id.into(),
                sender: signer.principal().into(),
                key_id: signer.key_id().to_string(),
                group: GROUP.into(),
                epoch: sealed.epoch,
                previous: g.previous,
                kind: "application".into(),
                audience: g.audience,
                next_audience: None,
                registry: digest,
                issued_at: NOW,
                expires_at: NOW + 2000,
                ciphertext_digest: Digest::of(&sealed.ciphertext).to_hex(),
                welcome_digest: None,
                control: None,
            };
            packet_for(&signer, h, sealed.ciphertext, None)
        })
        .unwrap()
}
#[test]
fn authenticated_forged_inner_content_is_quarantined_and_ratchet_progress_survives() {
    let mut w = World::new();
    w.pair();
    let audience = vec!["builder".into(), "reviewer".into()];
    let good = w.message("first", "original", 1, audience.clone());
    let bytes = w
        .alice
        .e()
        .prepare_message("first", GROUP, good.clone(), NOW)
        .unwrap();
    w.bob.e().receive(&bytes, NOW).unwrap();
    // Same valid author/id, different signed payload: consume but quarantine.
    let conflicting = w.message("first", "changed", 1, audience.clone());
    let bytes = malicious_packet(&mut w.alice, "conflict", &conflicting);
    assert_eq!(
        w.bob.e().receive(&bytes, NOW).unwrap().disposition,
        "quarantined"
    );
    assert!(w.bob.e().receive(&bytes, NOW).unwrap().replayed);
    // A cryptographically valid MLS message carrying a tampered DSSE signature.
    let mut tampered = good;
    let mut envelope: Value = serde_json::from_str(&tampered.event).unwrap();
    envelope["signatures"][0]["signature"] = json!(STANDARD.encode([0u8; 64]));
    tampered.event = serde_json::to_string(&envelope).unwrap();
    let bytes = malicious_packet(&mut w.alice, "bad-signature", &tampered);
    assert_eq!(
        w.bob.e().receive(&bytes, NOW).unwrap().disposition,
        "quarantined"
    );
    w.bob.restart(&w.root);
    let content = w.message("after-bad", "still works", 1, audience);
    let bytes = w
        .alice
        .e()
        .prepare_message("after-bad", GROUP, content, NOW)
        .unwrap();
    assert_eq!(
        w.bob.e().receive(&bytes, NOW).unwrap().disposition,
        "verified"
    );
}
#[test]
fn action_expiry_reuse_and_unapproved_welcome_do_not_change_membership() {
    let mut w = World::new();
    w.pair();
    let kp = w.carol.e().key_package("kp-third", NOW).unwrap();
    let control=w.control("third","group.add",1,vec!["builder".into(),"reviewer".into(),"third".into()],json!({"member":"third","key_id":w.carol.identity.key_id,"key_package_digest":Digest::of(&kp).to_hex()}),Some(kp));
    assert!(w
        .alice
        .e()
        .change_membership("expired", control.clone(), NOW + 301)
        .is_err());
    let packet = w
        .alice
        .e()
        .change_membership("third", control.clone(), NOW)
        .unwrap();
    assert!(w.carol.e().join(GROUP, "reviewer", &packet, NOW).is_err());
    // An unauthorized attempt has not consumed the real Welcome/KeyPackage.
    w.carol.e().join(GROUP, "builder", &packet, NOW).unwrap();
    w.alice
        .e()
        .confirm_publication("third", &packet, "git-fixture-third", NOW)
        .unwrap();
    assert!(w
        .alice
        .e()
        .change_membership("reused-approval", control, NOW)
        .is_err());
}
#[test]
fn rejected_pending_change_keeps_epoch_and_requires_a_new_authorization() {
    let mut w = World::new();
    w.pair();
    let kp = w.carol.e().key_package("kp-third", NOW).unwrap();
    let params = json!({"member":"third","key_id":w.carol.identity.key_id,"key_package_digest":Digest::of(&kp).to_hex()});
    let audience = vec!["builder".into(), "reviewer".into(), "third".into()];
    let control = w.control(
        "lose",
        "group.add",
        1,
        audience.clone(),
        params.clone(),
        Some(kp.clone()),
    );
    let bytes = w
        .alice
        .e()
        .change_membership("lose", control.clone(), NOW)
        .unwrap();
    assert!(w
        .alice
        .e()
        .reject_membership("lose", Digest::of(b"wrong"), "head")
        .is_err());
    w.alice
        .e()
        .reject_membership("lose", Digest::of(&bytes), "verified-rejection-head")
        .unwrap();
    assert!(w.alice.e().ready("lose", NOW).is_err());
    assert!(w
        .alice
        .e()
        .change_membership("retry-old-approval", control, NOW)
        .is_err());
    let fresh = w.control("fresh", "group.add", 1, audience, params, Some(kp));
    let bytes = w.alice.e().change_membership("fresh", fresh, NOW).unwrap();
    w.alice
        .e()
        .confirm_publication("fresh", &bytes, "accepted-head", NOW)
        .unwrap();
    w.carol.e().join(GROUP, "builder", &bytes, NOW).unwrap();
    w.carol.restart(&w.root);
    w.carol.e().join(GROUP, "builder", &bytes, NOW).unwrap();
}
#[test]
fn bootstrap_needs_pinned_head_and_can_replay_expired_historical_registry() {
    let w = World::new();
    let mut fresh = Node::new("new-device", &w.root);
    let mut old = w.registry.clone();
    old["issued_at"] = json!(NOW - 1000);
    old["expires_at"] = json!(NOW - 500);
    let old = signed_json(&w.root, REGISTRY_PAYLOAD_TYPE, &old);
    let mut next = w.registry;
    next["generation"] = json!(2);
    next["previous"] = json!(Envelope::parse(old.as_bytes(), REGISTRY_PAYLOAD_TYPE)
        .unwrap()
        .digest()
        .to_hex());
    let next = signed_json(&w.root, REGISTRY_PAYLOAD_TYPE, &next);
    let head = Envelope::parse(next.as_bytes(), REGISTRY_PAYLOAD_TYPE)
        .unwrap()
        .digest();
    assert!(fresh.e().install_registry(next.as_bytes(), NOW).is_err());
    assert!(fresh
        .e()
        .bootstrap_registry(
            &[old.as_bytes(), next.as_bytes()],
            Digest::of(b"untrusted-head"),
            NOW
        )
        .is_err());
    fresh
        .e()
        .bootstrap_registry(&[old.as_bytes(), next.as_bytes()], head, NOW)
        .unwrap();
}

#[test]
fn both_joiner_and_existing_member_refuse_a_different_package_for_the_same_agent() {
    let mut w = World::new();
    w.pair();
    let approved = w.carol.e().key_package("kp-approved", NOW).unwrap();
    let substituted = w.carol.e().key_package("kp-substituted", NOW).unwrap();
    assert_ne!(approved, substituted);
    let control=w.control("approve-specific-package","group.add",1,vec!["builder".into(),"reviewer".into(),"third".into()],json!({"member":"third","key_id":w.carol.identity.key_id,"key_package_digest":Digest::of(&approved).to_hex()}),Some(approved));
    let attack = w
        .alice
        .e()
        .vault
        .transaction(|db| {
            let signer = AgentSigner::load(db)?;
            let g = group(db, GROUP)?;
            let staged = mls::stage_add(db, &signer, &g.mls_id, &substituted)?;
            let registry: String = storage(db.query_row(
                "SELECT digest FROM yhes_registry ORDER BY generation DESC LIMIT 1",
                [],
                |r| r.get(0),
            ))?;
            let h = Header {
                version: 1,
                project: "fixture".into(),
                operation: "substitution".into(),
                sender: "builder".into(),
                key_id: signer.key_id().to_string(),
                group: GROUP.into(),
                epoch: 1,
                previous: g.previous,
                kind: "commit".into(),
                audience: g.audience,
                next_audience: Some(vec!["builder".into(), "reviewer".into(), "third".into()]),
                registry,
                issued_at: NOW,
                expires_at: NOW + 300,
                ciphertext_digest: Digest::of(&staged.commit).to_hex(),
                welcome_digest: staged.welcome.as_ref().map(|x| Digest::of(x).to_hex()),
                control: Some(control.clone()),
            };
            packet_for(&signer, h, staged.commit, staged.welcome)
        })
        .unwrap();
    assert!(w.bob.e().receive(&attack, NOW).is_err());
    assert!(w.carol.e().join(GROUP, "builder", &attack, NOW).is_err());
    w.alice
        .e()
        .vault
        .transaction(|db| {
            mls::clear_pending(db, &mls_id("fixture", GROUP))?;
            Ok(())
        })
        .unwrap();
    let valid = w
        .alice
        .e()
        .change_membership("specific-package", control, NOW)
        .unwrap();
    w.alice
        .e()
        .confirm_publication("specific-package", &valid, "accepted-head", NOW)
        .unwrap();
    w.bob.e().receive(&valid, NOW).unwrap();
    w.carol.e().join(GROUP, "builder", &valid, NOW).unwrap();
}

fn local_pair(w: &mut World, root: &std::path::Path) -> crate::local::LocalChannel {
    let channel = crate::local::LocalChannel::open(root, "fixture").unwrap();
    let create = w.control(
        "local-create",
        "group.create",
        0,
        vec!["builder".into()],
        json!({}),
        None,
    );
    w.alice
        .e()
        .create_group("local-create", create, NOW)
        .unwrap();
    channel.publish(w.alice.e(), "local-create", NOW).unwrap();
    channel.sync(w.alice.e(), GROUP, "builder", NOW).unwrap();
    let kp = w.bob.e().key_package("local-key-package", NOW).unwrap();
    let add=w.control("local-add","group.add",0,vec!["builder".into(),"reviewer".into()],json!({"member":"reviewer","key_id":w.bob.identity.key_id,"key_package_digest":Digest::of(&kp).to_hex()}),Some(kp));
    w.alice
        .e()
        .change_membership("local-add", add, NOW)
        .unwrap();
    channel.publish(w.alice.e(), "local-add", NOW).unwrap();
    let joined = channel.sync(w.bob.e(), GROUP, "builder", NOW).unwrap();
    assert_eq!(joined.deliveries.len(), 1);
    assert_eq!(joined.deliveries[0].disposition, "joined");
    channel.sync(w.alice.e(), GROUP, "builder", NOW).unwrap();
    channel
}
#[test]
fn local_transport_exchanges_user_messages_and_reconciles_exact_retries() {
    let mut w = World::new();
    let project = tempfile::tempdir().unwrap();
    let channel = local_pair(&mut w, project.path());
    let content = w.message(
        "local-message",
        "LOCAL_PRIVATE_TEXT_62855",
        1,
        vec!["builder".into(), "reviewer".into()],
    );
    let exact = w
        .alice
        .e()
        .prepare_message("local-send", GROUP, content, NOW)
        .unwrap();
    let first = channel.publish(w.alice.e(), "local-send", NOW).unwrap();
    assert!(!first.replayed);
    let second = channel.publish(w.alice.e(), "local-send", NOW).unwrap();
    assert!(second.replayed);
    assert_eq!(first.sequence, second.sequence);
    let incoming = channel.sync(w.bob.e(), GROUP, "builder", NOW).unwrap();
    assert_eq!(incoming.deliveries.len(), 1);
    assert_eq!(
        incoming.deliveries[0].message.as_ref().unwrap().author,
        "builder"
    );
    let grant = w.grant(&w.bob.identity);
    let event = World::event(
        &w.bob.identity,
        "local-answer",
        Body::AgentMessage {
            text: "reply from the second profile".into(),
        },
        vec!["builder".into(), "reviewer".into()],
        1,
        &grant,
    );
    let content = w
        .bob
        .e()
        .sign_event(event, Some(grant), None, None, NOW)
        .unwrap();
    w.bob
        .e()
        .prepare_message("local-answer", GROUP, content, NOW)
        .unwrap();
    channel.publish(w.bob.e(), "local-answer", NOW).unwrap();
    let incoming = channel.sync(w.alice.e(), GROUP, "builder", NOW).unwrap();
    assert_eq!(incoming.deliveries.len(), 1);
    assert_eq!(
        incoming.deliveries[0].message.as_ref().unwrap().author,
        "reviewer"
    );
    w.alice.restart(&w.root);
    assert_eq!(w.alice.e().stored_packet("local-send").unwrap(), exact);
    assert_eq!(
        channel
            .sync(w.alice.e(), GROUP, "builder", NOW)
            .unwrap()
            .processed,
        0
    );
    assert_eq!(
        w.alice
            .e()
            .inbox()
            .unwrap()
            .iter()
            .filter(|r| r.delivery.message.is_some())
            .count(),
        1
    );
    for file in fs::read_dir(project.path().join(".agents/messages/secure/records")).unwrap() {
        let bytes = fs::read(file.unwrap().path()).unwrap();
        assert!(!bytes
            .windows(b"LOCAL_PRIVATE_TEXT_62855".len())
            .any(|b| b == b"LOCAL_PRIVATE_TEXT_62855"));
    }
}
#[test]
fn protected_local_cursor_detects_deleted_or_changed_history() {
    let mut w = World::new();
    let project = tempfile::tempdir().unwrap();
    let channel = local_pair(&mut w, project.path());
    let mut files = fs::read_dir(project.path().join(".agents/messages/secure/records"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect::<Vec<_>>();
    files.sort();
    let last = files.last().unwrap();
    let bytes = fs::read(last).unwrap();
    fs::remove_file(last).unwrap();
    assert!(channel.sync(w.bob.e(), GROUP, "builder", NOW).is_err());
    fs::write(last, &bytes).unwrap();
    assert_eq!(
        channel
            .sync(w.bob.e(), GROUP, "builder", NOW)
            .unwrap()
            .processed,
        0
    );
    let mut changed = bytes;
    changed.push(b' ');
    fs::write(last, changed).unwrap();
    assert!(channel.sync(w.bob.e(), GROUP, "builder", NOW).is_err());
}
#[test]
fn read_views_do_not_advance_checkpoints_and_client_namespace_cannot_replace_pins() {
    let mut w = World::new();
    let revision = w.alice.anchors.0.borrow().as_ref().unwrap().revision;
    w.alice.e().identity().unwrap();
    w.alice.e().outbox().unwrap();
    w.alice.e().groups().unwrap();
    w.alice.e().registry_chain().unwrap();
    assert_eq!(
        w.alice.anchors.0.borrow().as_ref().unwrap().revision,
        revision
    );
    w.alice
        .e()
        .client_put("trust", b"not an authority pin")
        .unwrap();
    assert_eq!(
        w.alice.e().client_get("trust").unwrap().unwrap(),
        b"not an authority pin"
    );
    let head = w.alice.e().registry_head().unwrap().unwrap();
    w.alice.e().install_registry(&head, NOW).unwrap();
    assert!(w.alice.e().client_put("../project", b"wrong").is_err());
    assert!(w
        .alice
        .e()
        .client_put("oversized", &vec![0; (1 << 20) + 1])
        .is_err());
}

#[test]
fn local_capacity_rejection_does_not_poison_history_or_acknowledge_outbox() {
    let mut w = World::new();
    let project = tempfile::tempdir().unwrap();
    let mut channel = local_pair(&mut w, project.path());
    let content = w.message(
        "capacity-first",
        "first",
        1,
        vec!["builder".into(), "reviewer".into()],
    );
    w.alice
        .e()
        .prepare_message("capacity-first", GROUP, content, NOW)
        .unwrap();
    channel.publish(w.alice.e(), "capacity-first", NOW).unwrap();
    let content = w.message(
        "capacity-next",
        "must remain pending",
        1,
        vec!["builder".into(), "reviewer".into()],
    );
    w.alice
        .e()
        .prepare_message("capacity-next", GROUP, content, NOW)
        .unwrap();
    channel.tighten_test_limits(3, 64 * 1024 * 1024);
    assert!(channel.publish(w.alice.e(), "capacity-next", NOW).is_err());
    let paths = fs::read_dir(project.path().join(".agents/messages/secure/records"))
        .unwrap()
        .map(|f| f.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 3);
    let bytes = paths.iter().map(|p| fs::metadata(p).unwrap().len()).sum();
    channel.tighten_test_limits(4096, bytes);
    assert!(channel.publish(w.alice.e(), "capacity-next", NOW).is_err());
    assert_eq!(
        w.alice
            .e()
            .outbox()
            .unwrap()
            .iter()
            .find(|o| o.operation == "capacity-next")
            .unwrap()
            .status,
        "prepared"
    );
    let synced = channel.sync(w.bob.e(), GROUP, "builder", NOW).unwrap();
    assert_eq!(synced.deliveries.len(), 1);
}
#[test]
fn local_readd_to_removed_profile_requires_explicit_recovery_before_cursor_advance() {
    let mut w = World::new();
    let project = tempfile::tempdir().unwrap();
    let channel = local_pair(&mut w, project.path());
    let control = w.control(
        "local-remove",
        "group.remove",
        1,
        vec!["builder".into()],
        json!({"member":"reviewer"}),
        None,
    );
    w.alice
        .e()
        .change_membership("local-remove", control, NOW)
        .unwrap();
    channel.publish(w.alice.e(), "local-remove", NOW).unwrap();
    channel.sync(w.alice.e(), GROUP, "builder", NOW).unwrap();
    channel.sync(w.bob.e(), GROUP, "builder", NOW).unwrap();
    assert!(!w.bob.e().group_status(GROUP).unwrap().unwrap().active);
    let kp = w.bob.e().key_package("readd-package", NOW).unwrap();
    let control=w.control("readd","group.add",2,vec!["builder".into(),"reviewer".into()],json!({"member":"reviewer","key_id":w.bob.identity.key_id,"key_package_digest":Digest::of(&kp).to_hex()}),Some(kp));
    w.alice
        .e()
        .change_membership("readd", control, NOW)
        .unwrap();
    channel.publish(w.alice.e(), "readd", NOW).unwrap();
    let before = w.bob.anchors.0.borrow().as_ref().unwrap().revision;
    assert!(matches!(
        channel.sync(w.bob.e(), GROUP, "builder", NOW),
        Err(Error::Conflict(_))
    ));
    assert_eq!(w.bob.anchors.0.borrow().as_ref().unwrap().revision, before);
    assert!(!w.bob.e().group_status(GROUP).unwrap().unwrap().active);
}

#[test]
fn local_membership_publication_drains_peer_messages_that_arrive_while_staged() {
    let mut w = World::new();
    let project = tempfile::tempdir().unwrap();
    let channel = local_pair(&mut w, project.path());
    let kp = w
        .carol
        .e()
        .key_package("pending-drain-package", NOW)
        .unwrap();
    let control=w.control("pending-drain-add","group.add",1,vec!["builder".into(),"reviewer".into(),"third".into()],json!({"member":"third","key_id":w.carol.identity.key_id,"key_package_digest":Digest::of(&kp).to_hex()}),Some(kp));
    w.alice
        .e()
        .change_membership("pending-drain-add", control, NOW)
        .unwrap();
    let grant = w.grant(&w.bob.identity);
    let event = World::event(
        &w.bob.identity,
        "while-owner-pending",
        Body::AgentMessage {
            text: "must survive the epoch transition".into(),
        },
        vec!["builder".into(), "reviewer".into()],
        1,
        &grant,
    );
    let content = w
        .bob
        .e()
        .sign_event(event, Some(grant), None, None, NOW)
        .unwrap();
    w.bob
        .e()
        .prepare_message("while-owner-pending", GROUP, content, NOW)
        .unwrap();
    channel
        .publish(w.bob.e(), "while-owner-pending", NOW)
        .unwrap();
    channel
        .publish(w.alice.e(), "pending-drain-add", NOW)
        .unwrap();
    assert_eq!(w.alice.e().group_status(GROUP).unwrap().unwrap().epoch, 2);
    let inbox = w.alice.e().inbox().unwrap();
    assert!(inbox.iter().any(|e| e
        .delivery
        .message
        .as_ref()
        .is_some_and(|m| m.event_id == "while-owner-pending")));
    channel.sync(w.alice.e(), GROUP, "builder", NOW).unwrap();
    channel.sync(w.bob.e(), GROUP, "builder", NOW).unwrap();
    channel.sync(w.carol.e(), GROUP, "builder", NOW).unwrap();
}
