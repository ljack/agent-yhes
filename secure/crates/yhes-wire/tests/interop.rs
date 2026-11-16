//! Verifies envelopes produced outside this crate (the native signer's
//! Python/CryptoKit test vectors) so both sides agree on PAE, key ids,
//! digests and raw P-256 signatures.

mod common;

use common::*;
use serde_json::json;
use yhes_wire::*;

const T: u64 = 2_000_000_000;
const KEY_ID: &str = "k_d7d81e4c7d2741c41372571a108b9ea094cdbb5e50712102211e4cbe48875606";
const DIGEST: &str = "5a3e2176261fdf0fa6df145dda99e9fdb8b04d32b91023b5ff06f52e7f67172b";

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn registry(alice: &PublicKey, bob: &Signer, authority: &Signer) -> Registry {
    let mut keys = json!([
        {"key_id": alice.key_id().as_str(), "participant": "alice", "algorithm": "p256-sha256",
         "public_key": b64(alice.as_bytes()), "not_before": T - 100, "not_after": T + 1000},
        {"key_id": bob.id(), "participant": "bob", "algorithm": "ed25519",
         "public_key": b64(bob.public().as_bytes()), "not_before": T - 100, "not_after": T + 1000},
    ]);
    sort_by_key_id(&mut keys);
    let value = json!({
        "version": 1, "project": "demo", "generation": 1, "previous": null,
        "issued_at": T - 100, "expires_at": T + 1000,
        "participants": [
            {"id": "alice", "kind": "human", "controller": null,
             "ghes": {"instance": "ghes.example.com", "user_id": 1}},
            {"id": "bob", "kind": "human", "controller": null,
             "ghes": {"instance": "ghes.example.com", "user_id": 2}},
        ],
        "keys": keys,
        "revocations": [],
    });
    let anchors = TrustAnchors::new("demo", vec![authority.public()], 1).unwrap();
    let bytes = seal(
        REGISTRY_PAYLOAD_TYPE,
        &serde_json::to_vec(&value).unwrap(),
        &[authority],
    );
    Registry::verify(&bytes, &anchors, None, &Policy::default(), T).unwrap()
}

#[test]
fn native_signer_vectors_verify() {
    let alice = PublicKey::new(
        Algorithm::P256Sha256,
        &unhex(include_str!("fixtures/native-signer/p256-public-key.hex")),
    )
    .unwrap();
    assert_eq!(alice.key_id().as_str(), KEY_ID);

    let registry = registry(&alice, &Signer::ed(3), &Signer::ed(1));
    let verifier = Verifier::new(&registry, Policy::default());
    let expect = Expectation {
        project: "demo",
        audience: AudienceCheck::Includes("bob"),
        group: None,
    };

    let low_s = include_bytes!("fixtures/native-signer/p256-statement-envelope.json");
    let high_s = include_bytes!("fixtures/native-signer/p256-high-s-envelope.json");
    for envelope in [&low_s[..], &high_s[..]] {
        let v = verifier
            .verify_event(envelope, &Evidence::default(), &expect, T)
            .unwrap();
        assert_eq!(v.digest().to_hex(), DIGEST);
        assert_eq!(v.signer(), SignerRole::HumanDevice);
        assert_eq!(v.event().author, "alice");
        assert_eq!(v.event().id, "swift-vector-1");
        assert_eq!(
            v.event().body,
            Body::HumanStatement {
                text: "Hyväksyn tämän täsmällisen viestin. 😀".into()
            }
        );
        // The payload keeps its indentation and final newline.
        assert!(v.payload().ends_with(b"}\n"));
    }

    // The same envelope is refused once expired.
    assert_err!(
        verifier.verify_event(low_s, &Evidence::default(), &expect, T + 301),
        Error::Expired
    );
}

#[test]
fn native_signer_registry_vector_verifies() {
    let key = PublicKey::new(
        Algorithm::P256Sha256,
        &unhex(include_str!("fixtures/native-signer/p256-public-key.hex")),
    )
    .unwrap();
    let anchors = TrustAnchors::new("demo", vec![key.clone()], 1).unwrap();
    let envelope = include_bytes!("fixtures/native-signer/p256-registry-envelope.json");
    let policy = Policy::default();

    let registry = Registry::verify(envelope, &anchors, None, &policy, T).unwrap();
    assert_eq!(registry.project(), "demo");
    assert_eq!(registry.generation(), 1);
    assert_eq!(
        registry.participant("alice").unwrap().kind,
        ParticipantKind::Human
    );
    assert_eq!(
        registry
            .participant("alice-agent")
            .unwrap()
            .controller
            .as_deref(),
        Some("alice")
    );
    assert_eq!(registry.active_key("alice", &key.key_id(), T).unwrap(), key);
    assert_eq!(key.key_id().as_str(), KEY_ID);

    // Outside its validity, for another project, or under other anchors it fails.
    assert_err!(
        Registry::verify(envelope, &anchors, None, &policy, T + 601),
        Error::RegistryExpired
    );
    let other_project = TrustAnchors::new("other", vec![key], 1).unwrap();
    assert_err!(
        Registry::verify(envelope, &other_project, None, &policy, T),
        Error::WrongProject
    );
    let strangers = TrustAnchors::new("demo", vec![Signer::ed(1).public()], 1).unwrap();
    assert_err!(
        Registry::verify(envelope, &strangers, None, &policy, T),
        Error::UntrustedAuthority
    );
    // The registry envelope is not an event.
    let verifier = Verifier::new(&registry, Policy::default());
    let expect = Expectation {
        project: "demo",
        audience: AudienceCheck::AuditOnly,
        group: None,
    };
    assert_err!(
        verifier.verify_event(envelope, &Evidence::default(), &expect, T),
        Error::UnsupportedPayloadType
    );
}
