//! Test fixtures. All keys are disposable software keys derived from fixed
//! seeds; none of them is, or may be, enrolled anywhere.
#![allow(dead_code)]

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use yhes_wire::*;

pub const NOW: u64 = 1_800_000_000;
pub const PROJECT: &str = "demo";

pub enum Signer {
    Ed(ed25519_dalek::SigningKey),
    P(p256::ecdsa::SigningKey),
}

impl Signer {
    pub fn ed(seed: u8) -> Signer {
        Signer::Ed(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    pub fn p(seed: u8) -> Signer {
        Signer::P(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
    }

    pub fn public(&self) -> PublicKey {
        match self {
            Signer::Ed(k) => {
                PublicKey::new(Algorithm::Ed25519, &k.verifying_key().to_bytes()).unwrap()
            }
            Signer::P(k) => PublicKey::new(
                Algorithm::P256Sha256,
                k.verifying_key().to_encoded_point(false).as_bytes(),
            )
            .unwrap(),
        }
    }

    pub fn id(&self) -> String {
        self.public().key_id().as_str().to_owned()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        match self {
            Signer::Ed(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(message).to_bytes()
            }
            Signer::P(k) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = k.sign(message);
                sig.to_bytes().into()
            }
        }
    }

    pub fn entry(&self, payload_type: &str, payload: &[u8]) -> SignatureEntry {
        SignatureEntry {
            key_id: self.public().key_id(),
            algorithm: self.public().algorithm(),
            signature: self.sign(&pae(payload_type, payload)),
        }
    }
}

/// Signs `payload` with every signer and returns envelope JSON.
pub fn seal(payload_type: &str, payload: &[u8], signers: &[&Signer]) -> Vec<u8> {
    let signatures = signers
        .iter()
        .map(|s| s.entry(payload_type, payload))
        .collect();
    Envelope::new(payload_type, payload.to_vec(), signatures)
        .unwrap()
        .to_json()
}

pub fn seal_event(event: &Value, signer: &Signer) -> Vec<u8> {
    seal(
        EVENT_PAYLOAD_TYPE,
        &serde_json::to_vec(event).unwrap(),
        &[signer],
    )
}

/// Hex digest of the payload carried by an envelope.
pub fn digest_hex(envelope: &[u8]) -> String {
    Envelope::parse(envelope, EVENT_PAYLOAD_TYPE)
        .unwrap()
        .digest()
        .to_hex()
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub struct World {
    pub authority: Signer,
    pub alice: Signer,       // human, P-256 device key
    pub bob: Signer,         // human, Ed25519 device key
    pub alice_agent: Signer, // agent controlled by alice
    pub bob_agent: Signer,   // agent controlled by bob
    pub ci: Signer,          // service
    pub session: Signer,     // alice's session key, never enrolled
    pub anchors: TrustAnchors,
    pub registry_envelope: Vec<u8>,
    pub registry: Registry,
}

fn key_entry(signer: &Signer, participant: &str) -> Value {
    json!({
        "key_id": signer.id(),
        "participant": participant,
        "algorithm": signer.public().algorithm().as_str(),
        "public_key": b64(signer.public().as_bytes()),
        "not_before": NOW - 86_400,
        "not_after": NOW + 86_400,
    })
}

pub fn sort_by_key_id(list: &mut Value) {
    let items = list.as_array_mut().unwrap();
    items.sort_by(|a, b| a["key_id"].as_str().cmp(&b["key_id"].as_str()));
}

impl World {
    pub fn signers() -> (Signer, Signer, Signer, Signer, Signer, Signer, Signer) {
        (
            Signer::ed(1),
            Signer::p(2),
            Signer::ed(3),
            Signer::ed(4),
            Signer::p(5),
            Signer::ed(6),
            Signer::p(7),
        )
    }

    /// The generation-1 registry payload used by most tests.
    pub fn registry_json(
        alice: &Signer,
        bob: &Signer,
        alice_agent: &Signer,
        bob_agent: &Signer,
        ci: &Signer,
    ) -> Value {
        let mut keys = json!([
            key_entry(alice, "alice"),
            key_entry(bob, "bob"),
            key_entry(alice_agent, "alice-agent"),
            key_entry(bob_agent, "bob-agent"),
            key_entry(ci, "ci"),
        ]);
        sort_by_key_id(&mut keys);
        json!({
            "version": 1,
            "project": PROJECT,
            "generation": 1,
            "previous": null,
            "issued_at": NOW - 3600,
            "expires_at": NOW + 86_400,
            "participants": [
                {"id": "alice", "kind": "human", "controller": null,
                 "ghes": {"instance": "ghes.example.com", "user_id": 1001}},
                {"id": "alice-agent", "kind": "agent", "controller": "alice", "ghes": null},
                {"id": "bob", "kind": "human", "controller": null,
                 "ghes": {"instance": "ghes.example.com", "user_id": 1002}},
                {"id": "bob-agent", "kind": "agent", "controller": "bob", "ghes": null},
                {"id": "ci", "kind": "service", "controller": null, "ghes": null},
            ],
            "keys": keys,
            "revocations": [],
        })
    }

    pub fn new() -> World {
        World::with_registry(|_| {})
    }

    /// Builds the world with a modified generation-1 registry.
    pub fn with_registry(change: impl FnOnce(&mut Value)) -> World {
        let (authority, alice, bob, alice_agent, bob_agent, ci, session) = World::signers();
        let mut value = World::registry_json(&alice, &bob, &alice_agent, &bob_agent, &ci);
        change(&mut value);
        let anchors = TrustAnchors::new(PROJECT, vec![authority.public()], 1).unwrap();
        let registry_envelope = seal(
            REGISTRY_PAYLOAD_TYPE,
            &serde_json::to_vec(&value).unwrap(),
            &[&authority],
        );
        let registry =
            Registry::verify(&registry_envelope, &anchors, None, &Policy::default(), NOW).unwrap();
        World {
            authority,
            alice,
            bob,
            alice_agent,
            bob_agent,
            ci,
            session,
            anchors,
            registry_envelope,
            registry,
        }
    }

    pub fn base_registry_json(&self) -> Value {
        World::registry_json(
            &self.alice,
            &self.bob,
            &self.alice_agent,
            &self.bob_agent,
            &self.ci,
        )
    }

    /// Verifies as the participant `me` with no group expected.
    pub fn verify(
        &self,
        envelope: &[u8],
        evidence: Evidence<'_>,
        me: &str,
    ) -> Result<VerifiedEvent, Error> {
        self.verify_at(envelope, evidence, me, None, NOW)
    }

    pub fn verify_at(
        &self,
        envelope: &[u8],
        evidence: Evidence<'_>,
        me: &str,
        group: Option<&str>,
        now: u64,
    ) -> Result<VerifiedEvent, Error> {
        Verifier::new(&self.registry, Policy::default()).verify_event(
            envelope,
            &evidence,
            &Expectation {
                project: PROJECT,
                audience: AudienceCheck::Includes(me),
                group,
            },
            now,
        )
    }

    /// alice's device-signed statement to her agent and bob.
    pub fn statement(&self) -> Value {
        event(
            "human.statement",
            "alice",
            &self.alice,
            json!({"text": "hello team"}),
        )
    }

    /// alice's session grant for `self.session`.
    pub fn session_grant(&self) -> Value {
        let mut g = event(
            "session.grant",
            "alice",
            &self.alice,
            json!({
                "session_key": {
                    "algorithm": self.session.public().algorithm().as_str(),
                    "public_key": b64(self.session.public().as_bytes()),
                },
                "purposes": ["human.statement"],
            }),
        );
        g["id"] = json!("grant-1");
        g["issued_at"] = json!(NOW - 60);
        g["expires_at"] = json!(NOW + 1740);
        g
    }

    /// A statement signed by alice's session key under `grant`.
    pub fn session_statement(&self, grant: &[u8]) -> Value {
        let mut e = event(
            "human.statement",
            "alice",
            &self.session,
            json!({"text": "via session"}),
        );
        e["session"] = json!(digest_hex(grant));
        e
    }

    /// alice's delegation to her agent.
    pub fn delegation(&self, purposes: &[&str]) -> Value {
        let mut d = event(
            "agent.delegation",
            "alice",
            &self.alice,
            json!({
                "agent": "alice-agent",
                "agent_key_id": self.alice_agent.id(),
                "purposes": purposes,
            }),
        );
        d["id"] = json!("delegation-1");
        d["issued_at"] = json!(NOW - 3600);
        d["expires_at"] = json!(NOW + 3600);
        d["audience"] = json!(["alice", "bob", "bob-agent"]);
        d
    }

    /// A message from alice's agent to bob under `delegation`.
    pub fn agent_message(&self, delegation: &[u8]) -> Value {
        let mut e = event(
            "agent.message",
            "alice-agent",
            &self.alice_agent,
            json!({"text": "status"}),
        );
        e["session"] = json!(digest_hex(delegation));
        e["audience"] = json!(["bob"]);
        e
    }

    /// alice-agent relays `original` to bob under `delegation`.
    pub fn relay(&self, original: &[u8], delegation: &[u8]) -> Value {
        let original: Value = serde_json::from_slice(original).unwrap();
        let mut e = event(
            "agent.relay",
            "alice-agent",
            &self.alice_agent,
            json!({"original": original, "note": "forwarding"}),
        );
        e["session"] = json!(digest_hex(delegation));
        e["audience"] = json!(["bob"]);
        e
    }
}

/// An event with default routing: issued just now, to alice-agent and bob.
pub fn event(kind: &str, author: &str, signer: &Signer, body: Value) -> Value {
    json!({
        "version": 1,
        "id": "event-1",
        "project": PROJECT,
        "kind": kind,
        "author": author,
        "key_id": signer.id(),
        "session": null,
        "issued_at": NOW - 10,
        "expires_at": NOW + 600,
        "audience": ["alice-agent", "bob"],
        "group": null,
        "epoch": null,
        "previous": null,
        "body": body,
    })
}

pub fn grant_evidence(grant: &[u8]) -> Evidence<'_> {
    Evidence {
        grant: Some(grant),
        ..Evidence::default()
    }
}

#[macro_export]
macro_rules! assert_err {
    ($result:expr, $pattern:pat) => {
        match $result {
            Err($pattern) => {}
            other => panic!("expected {}, got {:?}", stringify!($pattern), other),
        }
    };
}
