mod common;

use common::*;
use serde_json::{json, Value};
use yhes_wire::*;

fn none() -> Evidence<'static> {
    Evidence::default()
}

// ---------------------------------------------------------------- envelope

#[test]
fn pae_matches_the_dsse_specification_example() {
    assert_eq!(
        pae("http://example.com/HelloWorld", b"hello world"),
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    );
    // Lengths count bytes, not characters.
    assert_eq!(pae("é", "ä".as_bytes()), "DSSEv1 2 é 2 ä".as_bytes());
}

#[test]
fn key_id_is_the_domain_separated_hash() {
    use sha2::{Digest as _, Sha256};
    for signer in [Signer::ed(9), Signer::p(9)] {
        let key = signer.public();
        let mut h = Sha256::new();
        h.update(b"agent-yhes/key/v1\0");
        h.update(key.algorithm().as_str());
        h.update(b"\0");
        h.update(key.as_bytes());
        let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(key.key_id().as_str(), format!("k_{hex}"));
    }
    // The same bytes under another algorithm name give another id.
    assert_ne!(Signer::ed(9).id(), Signer::p(9).id());
}

#[test]
fn public_keys_are_validated() {
    assert_err!(
        PublicKey::new(Algorithm::Ed25519, &[0u8; 31]),
        Error::InvalidKey
    );
    // Small-order Ed25519 point.
    assert_err!(
        PublicKey::new(Algorithm::Ed25519, &[0u8; 32]),
        Error::InvalidKey
    );
    let p = Signer::p(2).public();
    // Compressed and off-curve P-256 points.
    assert_err!(
        PublicKey::new(Algorithm::P256Sha256, &p.as_bytes()[..33]),
        Error::InvalidKey
    );
    let mut off = p.as_bytes().to_vec();
    off[64] ^= 1;
    assert_err!(
        PublicKey::new(Algorithm::P256Sha256, &off),
        Error::InvalidKey
    );
    assert_err!(Algorithm::parse("rsa"), Error::UnsupportedAlgorithm);
}

#[test]
fn envelope_round_trips_exact_payload_bytes() {
    let w = World::new();
    // Unusual but valid JSON formatting must survive untouched.
    let mut payload = serde_json::to_string_pretty(&w.statement())
        .unwrap()
        .into_bytes();
    payload.extend_from_slice(b"\n\n");
    let bytes = seal(EVENT_PAYLOAD_TYPE, &payload, &[&w.alice]);
    let envelope = Envelope::parse(&bytes, EVENT_PAYLOAD_TYPE).unwrap();
    assert_eq!(envelope.payload(), payload.as_slice());
    assert_eq!(
        Envelope::parse(&envelope.to_json(), EVENT_PAYLOAD_TYPE).unwrap(),
        envelope
    );
    let v = w.verify(&bytes, none(), "bob").unwrap();
    assert_eq!(v.payload(), payload.as_slice());
    assert_eq!(v.digest(), Digest::of(&payload));
}

// ----------------------------------------------------------- malformed input

fn raw_envelope(payload_b64: &str, extra: &str) -> Vec<u8> {
    let sig = b64(&[7u8; 64]);
    let kid = Signer::ed(3).id();
    format!(
        r#"{{"payload_type":"{EVENT_PAYLOAD_TYPE}","payload":"{payload_b64}","signatures":[{{"key_id":"{kid}","algorithm":"ed25519","signature":"{sig}"}}]{extra}}}"#
    )
    .into_bytes()
}

#[test]
fn malformed_envelopes_are_rejected() {
    let parse = |b: &[u8]| Envelope::parse(b, EVENT_PAYLOAD_TYPE);
    assert!(parse(&raw_envelope("e30=", "")).is_ok());

    assert_err!(parse(b""), Error::Malformed(_));
    assert_err!(parse(b"null"), Error::Schema(_));
    assert_err!(parse(b"[]"), Error::Schema(_));
    assert_err!(parse(&[0xff, 0xfe]), Error::Malformed(_));
    assert_err!(parse(b"\xef\xbb\xbf{}"), Error::Malformed(_));

    // Unknown and duplicate fields.
    assert_err!(
        parse(&raw_envelope("e30=", r#","extra":1"#)),
        Error::Schema("unknown field")
    );
    assert_err!(
        parse(&raw_envelope("e30=", r#","payload":"e30=""#)),
        Error::Malformed("duplicate object key")
    );
    // A duplicate hidden behind an escape is still a duplicate.
    assert_err!(
        parse(&raw_envelope("e30=", r#","payload":"e30=""#)),
        Error::Malformed("duplicate object key")
    );

    // Trailing data.
    let mut trailing = raw_envelope("e30=", "");
    trailing.extend_from_slice(b"{}");
    assert_err!(parse(&trailing), Error::Malformed("trailing data"));

    // Base64 must be canonical standard base64.
    assert_err!(parse(&raw_envelope("e30", "")), Error::Malformed(_));
    assert_err!(parse(&raw_envelope("e31=", "")), Error::Malformed(_));
    assert_err!(parse(&raw_envelope("e3 0=", "")), Error::Malformed(_));
    assert_err!(parse(&raw_envelope("e30_", "")), Error::Malformed(_));

    // Wrong payload type, including the registry type on the event path.
    let other = String::from_utf8(raw_envelope("e30=", ""))
        .unwrap()
        .replace("event.v1", "event.v2");
    assert_err!(parse(other.as_bytes()), Error::UnsupportedPayloadType);
    assert_err!(
        Envelope::parse(&raw_envelope("e30=", ""), REGISTRY_PAYLOAD_TYPE),
        Error::UnsupportedPayloadType
    );

    // Signature entries.
    let text = String::from_utf8(raw_envelope("e30=", "")).unwrap();
    assert_err!(
        parse(text.replace("ed25519", "rsa").as_bytes()),
        Error::UnsupportedAlgorithm
    );
    assert_err!(
        parse(text.replace("k_", "K_").as_bytes()),
        Error::InvalidId("key_id")
    );
    assert_err!(
        parse(text.replace(&b64(&[7u8; 64]), &b64(&[7u8; 63])).as_bytes()),
        Error::Malformed("signature is not 64 bytes")
    );
    let empty =
        format!(r#"{{"payload_type":"{EVENT_PAYLOAD_TYPE}","payload":"e30=","signatures":[]}}"#);
    assert_err!(parse(empty.as_bytes()), Error::SignatureCount);
}

#[test]
fn oversized_and_deep_input_is_rejected() {
    let parse = |b: &[u8]| Envelope::parse(b, EVENT_PAYLOAD_TYPE);
    let big = raw_envelope(&"A".repeat(MAX_ENVELOPE_BYTES), "");
    assert_err!(parse(&big), Error::TooLarge);

    let deep = format!(
        r#"{{"payload_type":"{EVENT_PAYLOAD_TYPE}","payload":"e30=","signatures":{}{}}}"#,
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    assert_err!(parse(deep.as_bytes()), Error::Malformed("nesting too deep"));
    // Far beyond any limit: must fail without exhausting the stack.
    let very_deep = "[".repeat(200_000);
    assert_err!(parse(very_deep.as_bytes()), Error::Malformed(_));

    // Too many signatures.
    let w = World::new();
    let payload = serde_json::to_vec(&w.statement()).unwrap();
    let nine: Vec<Signer> = (10..19).map(Signer::ed).collect();
    let entries = nine
        .iter()
        .map(|s| s.entry(EVENT_PAYLOAD_TYPE, &payload))
        .collect();
    assert_err!(
        Envelope::new(EVENT_PAYLOAD_TYPE, payload, entries),
        Error::SignatureCount
    );
}

/// Signs arbitrary payload text with alice's device key.
fn signed_text(w: &World, payload: &str) -> Vec<u8> {
    seal(EVENT_PAYLOAD_TYPE, payload.as_bytes(), &[&w.alice])
}

#[test]
fn malformed_event_payloads_are_rejected_even_when_validly_signed() {
    let w = World::new();
    let good = serde_json::to_string(&w.statement()).unwrap();
    assert!(w.verify(&signed_text(&w, &good), none(), "bob").is_ok());

    let reject = |payload: String| w.verify(&signed_text(&w, &payload), none(), "bob");

    // Duplicate key inside the signed payload.
    let dup = good.replacen('{', r#"{"author":"bob","#, 1);
    assert_err!(reject(dup), Error::Malformed("duplicate object key"));
    // Unknown field, missing field.
    assert_err!(
        reject(good.replacen('{', r#"{"extra":true,"#, 1)),
        Error::Schema("unknown field")
    );
    assert_err!(
        reject(good.replace(r#""previous":null,"#, "")),
        Error::Schema("missing field")
    );
    // Unknown field inside the body.
    assert_err!(
        reject(good.replace(r#""text":"#, r#""html":"x","text":"#)),
        Error::Schema("unknown field")
    );
    // Numbers must be non-negative integers.
    let issued = format!("\"issued_at\":{}", NOW - 10);
    for bad in ["1.5", "-1", "1e3", "1800000000.0", "\"1800000000\""] {
        let result = reject(good.replace(&issued, &format!("\"issued_at\":{bad}")));
        assert!(
            matches!(result, Err(Error::Malformed(_) | Error::Schema(_))),
            "{bad}: {result:?}"
        );
    }
    assert_err!(
        reject(good.replace(&issued, "\"issued_at\":18446744073709551615")),
        Error::Schema("timestamp out of range")
    );
    // Versions other than 1.
    assert_err!(
        reject(good.replace(r#""version":1"#, r#""version":2"#)),
        Error::UnsupportedVersion
    );
    // Unknown kind.
    assert_err!(
        reject(good.replace("human.statement", "human.command")),
        Error::Schema("unknown event kind")
    );
    // Path-unsafe or unbounded identifiers.
    for bad in [
        "../etc",
        "a/b",
        "a\\\\b",
        ".hidden",
        "a..b",
        "",
        "a b",
        "a\\u0000b",
    ] {
        let result = reject(good.replace(r#""id":"event-1""#, &format!(r#""id":"{bad}""#)));
        assert_err!(result, Error::InvalidId("id"));
    }
    let long = "a".repeat(MAX_ID_BYTES + 1);
    assert_err!(
        reject(good.replace(r#""id":"event-1""#, &format!(r#""id":"{long}""#))),
        Error::InvalidId("id")
    );
    // Audience must be sorted, unique and non-empty.
    for bad in [
        r#"["bob","alice-agent"]"#,
        r#"["bob","bob"]"#,
        "[]",
        r#"[1]"#,
    ] {
        let result = reject(good.replace(r#"["alice-agent","bob"]"#, bad));
        assert_err!(result, Error::Schema(_));
    }
    // Epoch needs a group; digests must be 64 lowercase hex characters.
    assert_err!(
        reject(good.replace(r#""epoch":null"#, r#""epoch":3"#)),
        Error::Schema(_)
    );
    assert_err!(
        reject(good.replace(
            r#""previous":null"#,
            &format!(r#""previous":"{}""#, "A".repeat(64))
        )),
        Error::Schema(_)
    );
    // Text limit.
    let huge = "x".repeat(MAX_TEXT_BYTES + 1);
    assert_err!(
        reject(good.replace("hello team", &huge)),
        Error::Schema("text too long")
    );
    // Not JSON at all, and not an object.
    assert_err!(reject("hello".into()), Error::Malformed(_));
    assert_err!(reject("[]".into()), Error::Schema(_));
}

// ------------------------------------------------------- signatures, tamper

#[test]
fn human_statements_verify_with_both_algorithms() {
    let w = World::new();
    let v = w
        .verify(&seal_event(&w.statement(), &w.alice), none(), "bob")
        .unwrap();
    assert_eq!(v.signer(), SignerRole::HumanDevice);
    assert_eq!(v.author_kind(), ParticipantKind::Human);
    assert!(v.is_human_authored());
    assert_eq!(v.ghes().unwrap().user_id, 1001);
    assert_eq!(v.controller(), None);
    assert_eq!(
        v.event().body,
        Body::HumanStatement {
            text: "hello team".into()
        }
    );

    let mut e = event("human.statement", "bob", &w.bob, json!({"text": "hi"}));
    e["audience"] = json!(["alice"]);
    let v = w.verify(&seal_event(&e, &w.bob), none(), "alice").unwrap();
    assert_eq!(v.signer(), SignerRole::HumanDevice);
    assert_eq!(v.ghes().unwrap().user_id, 1002);
}

#[test]
fn tampering_is_detected() {
    let w = World::new();
    for signer_is_p256 in [true, false] {
        let (e, signer) = if signer_is_p256 {
            (w.statement(), &w.alice)
        } else {
            (
                event(
                    "human.statement",
                    "bob",
                    &w.bob,
                    json!({"text": "hello team"}),
                ),
                &w.bob,
            )
        };
        let payload = serde_json::to_vec(&e).unwrap();
        let entry = signer.entry(EVENT_PAYLOAD_TYPE, &payload);

        // Changed payload, original signature.
        let mut edited = e.clone();
        edited["body"]["text"] = json!("hello team!");
        let forged = Envelope::new(
            EVENT_PAYLOAD_TYPE,
            serde_json::to_vec(&edited).unwrap(),
            vec![entry.clone()],
        )
        .unwrap();
        assert_err!(
            w.verify(&forged.to_json(), none(), "bob"),
            Error::BadSignature
        );

        // Semantically equal but re-serialized payload.
        let mut respaced = payload.clone();
        respaced.push(b' ');
        let forged = Envelope::new(EVENT_PAYLOAD_TYPE, respaced, vec![entry.clone()]).unwrap();
        assert_err!(
            w.verify(&forged.to_json(), none(), "bob"),
            Error::BadSignature
        );

        // Every single-bit change of the signature.
        for byte in [0usize, 31, 32, 63] {
            let mut bad = entry.clone();
            bad.signature[byte] ^= 0x01;
            let forged = Envelope::new(EVENT_PAYLOAD_TYPE, payload.clone(), vec![bad]).unwrap();
            assert_err!(
                w.verify(&forged.to_json(), none(), "bob"),
                Error::BadSignature
            );
        }

        // Signature made for another payload type (domain separation).
        let mut cross = entry.clone();
        cross.signature = signer.sign(&pae(REGISTRY_PAYLOAD_TYPE, &payload));
        let forged = Envelope::new(EVENT_PAYLOAD_TYPE, payload.clone(), vec![cross]).unwrap();
        assert_err!(
            w.verify(&forged.to_json(), none(), "bob"),
            Error::BadSignature
        );

        // Signature over the bare payload without PAE.
        let mut bare = entry.clone();
        bare.signature = signer.sign(&payload);
        let forged = Envelope::new(EVENT_PAYLOAD_TYPE, payload.clone(), vec![bare]).unwrap();
        assert_err!(
            w.verify(&forged.to_json(), none(), "bob"),
            Error::BadSignature
        );
    }
}

#[test]
fn signature_must_come_from_the_key_named_in_the_payload() {
    let w = World::new();
    let payload = serde_json::to_vec(&w.statement()).unwrap();

    // Envelope names bob's key, payload names alice's.
    let entry = w.bob.entry(EVENT_PAYLOAD_TYPE, &payload);
    let forged = Envelope::new(EVENT_PAYLOAD_TYPE, payload.clone(), vec![entry]).unwrap();
    assert_err!(
        w.verify(&forged.to_json(), none(), "bob"),
        Error::KeyIdMismatch
    );

    // Envelope names alice's key id but the signature is bob's.
    let mut entry = w.alice.entry(EVENT_PAYLOAD_TYPE, &payload);
    entry.signature = w.bob.sign(&pae(EVENT_PAYLOAD_TYPE, &payload));
    let forged = Envelope::new(EVENT_PAYLOAD_TYPE, payload.clone(), vec![entry]).unwrap();
    assert_err!(
        w.verify(&forged.to_json(), none(), "bob"),
        Error::BadSignature
    );

    // Wrong algorithm label for an enrolled key.
    let mut entry = w.alice.entry(EVENT_PAYLOAD_TYPE, &payload);
    entry.algorithm = Algorithm::Ed25519;
    let forged = Envelope::new(EVENT_PAYLOAD_TYPE, payload.clone(), vec![entry]).unwrap();
    assert_err!(
        w.verify(&forged.to_json(), none(), "bob"),
        Error::AlgorithmMismatch
    );

    // An event carries exactly one signature.
    let two = seal(EVENT_PAYLOAD_TYPE, &payload, &[&w.alice, &w.bob]);
    assert_err!(w.verify(&two, none(), "bob"), Error::SignatureCount);

    // A key nobody enrolled.
    let stranger = Signer::ed(42);
    let e = event("human.statement", "alice", &stranger, json!({"text": "hi"}));
    assert_err!(
        w.verify(&seal_event(&e, &stranger), none(), "bob"),
        Error::UnknownKey
    );
}

// ------------------------------------------------------ forged human labels

#[test]
fn an_agent_cannot_present_itself_as_a_human() {
    let w = World::new();
    let delegation = seal_event(&w.delegation(&["agent.message", "agent.relay"]), &w.alice);

    // Agent key, author field claims alice.
    let e = event(
        "human.statement",
        "alice",
        &w.alice_agent,
        json!({"text": "I am alice"}),
    );
    assert_err!(
        w.verify(&seal_event(&e, &w.alice_agent), none(), "bob"),
        Error::AuthorMismatch
    );

    // Agent key, own author id, human kind; with and without its delegation.
    let mut e = event(
        "human.statement",
        "alice-agent",
        &w.alice_agent,
        json!({"text": "x"}),
    );
    assert_err!(
        w.verify(&seal_event(&e, &w.alice_agent), none(), "bob"),
        Error::KindNotPermitted("human.statement")
    );
    e["session"] = json!(digest_hex(&delegation));
    e["audience"] = json!(["bob"]);
    assert_err!(
        w.verify(
            &seal_event(&e, &w.alice_agent),
            grant_evidence(&delegation),
            "bob"
        ),
        Error::KindNotPermitted("human.statement")
    );

    // A sender-supplied label has no place in the schema.
    let mut e = w.agent_message(&delegation);
    e["author_kind"] = json!("human");
    assert_err!(
        w.verify(
            &seal_event(&e, &w.alice_agent),
            grant_evidence(&delegation),
            "bob"
        ),
        Error::Schema("unknown field")
    );
    let mut e = w.agent_message(&delegation);
    e["body"]["human"] = json!(true);
    assert_err!(
        w.verify(
            &seal_event(&e, &w.alice_agent),
            grant_evidence(&delegation),
            "bob"
        ),
        Error::Schema("unknown field")
    );

    // Quoting a human in an agent message stays agent-authored.
    let mut e = w.agent_message(&delegation);
    e["body"]["text"] = json!("alice says: hello team");
    let v = w
        .verify(
            &seal_event(&e, &w.alice_agent),
            grant_evidence(&delegation),
            "bob",
        )
        .unwrap();
    assert_eq!(v.signer(), SignerRole::Agent);
    assert_eq!(v.author_kind(), ParticipantKind::Agent);
    assert_eq!(v.controller(), Some("alice"));
    assert!(!v.is_human_authored());
    assert!(v.ghes().is_none());
    assert!(v.original().is_none());

    // A service cannot speak as a human or an agent either.
    let e = event("human.statement", "ci", &w.ci, json!({"text": "x"}));
    assert_err!(
        w.verify(&seal_event(&e, &w.ci), none(), "bob"),
        Error::KindNotPermitted(_)
    );
    let e = event("service.notice", "ci", &w.ci, json!({"text": "build done"}));
    let v = w.verify(&seal_event(&e, &w.ci), none(), "bob").unwrap();
    assert_eq!(v.signer(), SignerRole::Service);
    // And a human key cannot issue agent or service kinds.
    let e = event("service.notice", "alice", &w.alice, json!({"text": "x"}));
    assert_err!(
        w.verify(&seal_event(&e, &w.alice), none(), "bob"),
        Error::KindNotPermitted(_)
    );
}

#[test]
fn an_agent_key_cannot_be_turned_into_a_human_session_key() {
    let w = World::new();
    // alice (or someone holding her device key) names the agent's enrolled key
    // as a session key. The grant itself is refused.
    let mut g = w.session_grant();
    g["body"]["session_key"] = json!({
        "algorithm": "ed25519",
        "public_key": b64(w.alice_agent.public().as_bytes()),
    });
    let grant = seal_event(&g, &w.alice);
    assert_err!(w.verify(&grant, none(), "bob"), Error::InvalidGrant(_));

    // Using it: the agent key resolves through the registry as an agent.
    let mut e = event(
        "human.statement",
        "alice",
        &w.alice_agent,
        json!({"text": "x"}),
    );
    e["session"] = json!(digest_hex(&grant));
    assert_err!(
        w.verify(
            &seal_event(&e, &w.alice_agent),
            grant_evidence(&grant),
            "bob"
        ),
        Error::AuthorMismatch
    );
}

// ------------------------------------------- project, audience, group, time

#[test]
fn wrong_project_is_rejected() {
    let w = World::new();
    let mut e = w.statement();
    e["project"] = json!("other");
    assert_err!(
        w.verify(&seal_event(&e, &w.alice), none(), "bob"),
        Error::WrongProject
    );

    let good = seal_event(&w.statement(), &w.alice);
    let verifier = Verifier::new(&w.registry, Policy::default());
    let expect = Expectation {
        project: "other",
        audience: AudienceCheck::Includes("bob"),
        group: None,
    };
    assert_err!(
        verifier.verify_event(&good, &none(), &expect, NOW),
        Error::WrongProject
    );
}

#[test]
fn wrong_audience_and_group_are_rejected() {
    let w = World::new();
    let good = seal_event(&w.statement(), &w.alice);
    assert!(w.verify(&good, none(), "bob").is_ok());
    assert!(w.verify(&good, none(), "alice-agent").is_ok());
    // Not addressed to this recipient.
    assert_err!(w.verify(&good, none(), "bob-agent"), Error::WrongAudience);
    assert_err!(w.verify(&good, none(), "alice"), Error::WrongAudience);

    let verifier = Verifier::new(&w.registry, Policy::default());
    let exact = |ids: &[&str]| {
        let ids: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        let expect = Expectation {
            project: PROJECT,
            audience: AudienceCheck::Exact(&ids),
            group: None,
        };
        verifier.verify_event(&good, &none(), &expect, NOW)
    };
    assert!(exact(&["bob", "alice-agent"]).is_ok());
    assert_err!(exact(&["bob"]), Error::WrongAudience);
    assert_err!(
        exact(&["alice-agent", "bob", "bob-agent"]),
        Error::WrongAudience
    );
    assert_err!(exact(&["bob", "bob", "alice-agent"]), Error::WrongAudience);
    let audit = Expectation {
        project: PROJECT,
        audience: AudienceCheck::AuditOnly,
        group: None,
    };
    assert!(verifier.verify_event(&good, &none(), &audit, NOW).is_ok());

    // Audience members must be registry participants.
    let mut e = w.statement();
    e["audience"] = json!(["bob", "mallory"]);
    assert_err!(
        w.verify(&seal_event(&e, &w.alice), none(), "bob"),
        Error::UnknownParticipant
    );

    // Group binding.
    assert_err!(
        w.verify_at(&good, none(), "bob", Some("g1"), NOW),
        Error::WrongGroup
    );
    let mut e = w.statement();
    e["group"] = json!("g1");
    e["epoch"] = json!(4);
    let grouped = seal_event(&e, &w.alice);
    assert_err!(w.verify(&grouped, none(), "bob"), Error::WrongGroup);
    assert_err!(
        w.verify_at(&grouped, none(), "bob", Some("g2"), NOW),
        Error::WrongGroup
    );
    let v = w
        .verify_at(&grouped, none(), "bob", Some("g1"), NOW)
        .unwrap();
    assert_eq!(v.event().epoch, Some(4));
}

#[test]
fn time_bounds_are_enforced() {
    let w = World::new();
    let good = seal_event(&w.statement(), &w.alice);
    assert!(w.verify_at(&good, none(), "bob", None, NOW + 600).is_ok());
    assert_err!(
        w.verify_at(&good, none(), "bob", None, NOW + 601),
        Error::Expired
    );
    // Issued at NOW-10; tolerated up to the clock skew, not beyond.
    assert!(w.verify_at(&good, none(), "bob", None, NOW - 130).is_ok());
    assert_err!(
        w.verify_at(&good, none(), "bob", None, NOW - 131),
        Error::NotYetValid
    );

    let mut e = w.statement();
    e["expires_at"] = json!(NOW - 11);
    assert_err!(
        w.verify(&seal_event(&e, &w.alice), none(), "bob"),
        Error::InvalidTimeRange
    );
    let mut e = w.statement();
    e["expires_at"] = json!(NOW + 8 * 24 * 3600);
    assert_err!(
        w.verify(&seal_event(&e, &w.alice), none(), "bob"),
        Error::LifetimeTooLong
    );
}

// ------------------------------------------------- expired and revoked keys

#[test]
fn expired_and_not_yet_valid_keys_are_rejected() {
    let alice_id = Signer::p(2).id();
    let set = |field: &'static str, value: u64| {
        let alice_id = alice_id.clone();
        move |r: &mut Value| {
            for k in r["keys"].as_array_mut().unwrap() {
                if k["key_id"] == json!(alice_id) {
                    k[field] = json!(value);
                }
            }
        }
    };
    // Key expired before now, event issued while it was valid.
    let w = World::with_registry(set("not_after", NOW - 5));
    assert_err!(
        w.verify(&seal_event(&w.statement(), &w.alice), none(), "bob"),
        Error::KeyExpired
    );
    // Event issued after the key's validity.
    let w = World::with_registry(set("not_after", NOW + 5));
    let mut e = w.statement();
    e["issued_at"] = json!(NOW + 60);
    assert_err!(
        w.verify(&seal_event(&e, &w.alice), none(), "bob"),
        Error::KeyExpired
    );
    // Event issued before the key became valid.
    let w = World::with_registry(set("not_before", NOW - 5));
    assert_err!(
        w.verify(&seal_event(&w.statement(), &w.alice), none(), "bob"),
        Error::KeyNotYetValid
    );
    // Other keys are unaffected.
    let mut e = event("human.statement", "bob", &w.bob, json!({"text": "hi"}));
    e["audience"] = json!(["alice"]);
    assert!(w.verify(&seal_event(&e, &w.bob), none(), "alice").is_ok());
}

fn revoke(key_id: String) -> impl FnOnce(&mut Value) {
    move |r| r["revocations"] = json!([{"key_id": key_id, "revoked_at": NOW - 100}])
}

#[test]
fn revoked_keys_are_rejected_everywhere() {
    // A revoked human device key: statements, including backdated ones.
    let w = World::with_registry(revoke(Signer::p(2).id()));
    assert_err!(
        w.verify(&seal_event(&w.statement(), &w.alice), none(), "bob"),
        Error::KeyRevoked
    );
    let mut e = w.statement();
    e["issued_at"] = json!(NOW - 5000);
    assert_err!(
        w.verify(&seal_event(&e, &w.alice), none(), "bob"),
        Error::KeyRevoked
    );

    // ...and everything that depends on it: sessions and delegations.
    let grant = seal_event(&w.session_grant(), &w.alice);
    let s = seal_event(&w.session_statement(&grant), &w.session);
    assert_err!(
        w.verify(&s, grant_evidence(&grant), "bob"),
        Error::KeyRevoked
    );
    let delegation = seal_event(&w.delegation(&["agent.message"]), &w.alice);
    let m = seal_event(&w.agent_message(&delegation), &w.alice_agent);
    assert_err!(
        w.verify(&m, grant_evidence(&delegation), "bob"),
        Error::KeyRevoked
    );

    // A revoked agent key, with an otherwise valid delegation.
    let w = World::with_registry(revoke(Signer::ed(4).id()));
    let delegation = seal_event(&w.delegation(&["agent.message"]), &w.alice);
    let m = seal_event(&w.agent_message(&delegation), &w.alice_agent);
    assert_err!(
        w.verify(&m, grant_evidence(&delegation), "bob"),
        Error::KeyRevoked
    );
    assert_err!(w.verify(&delegation, none(), "bob"), Error::KeyRevoked);

    // A revoked key that was removed from the key list is still reported revoked.
    let alice_id = Signer::p(2).id();
    let w = World::with_registry(|r| {
        r["keys"]
            .as_array_mut()
            .unwrap()
            .retain(|k| k["key_id"] != json!(alice_id));
        r["revocations"] = json!([{"key_id": alice_id, "revoked_at": NOW - 100}]);
    });
    assert_err!(
        w.verify(&seal_event(&w.statement(), &w.alice), none(), "bob"),
        Error::KeyRevoked
    );

    // A session key that was revoked cannot be granted again.
    let w = World::with_registry(revoke(Signer::p(7).id()));
    assert_err!(
        w.verify(&seal_event(&w.session_grant(), &w.alice), none(), "bob"),
        Error::InvalidGrant(_)
    );
}

#[test]
fn an_expired_registry_verifies_nothing() {
    let w = World::new();
    let good = seal_event(&w.statement(), &w.alice);
    let mut e = w.statement();
    e["issued_at"] = json!(NOW + 86_400);
    e["expires_at"] = json!(NOW + 86_400 + 600);
    let later = seal_event(&e, &w.alice);
    assert!(w.verify(&good, none(), "bob").is_ok());
    assert_err!(
        w.verify_at(&later, none(), "bob", None, NOW + 86_401),
        Error::RegistryExpired
    );
}

// ------------------------------------------------------------------ registry

fn sealed_registry(value: &Value, signers: &[&Signer]) -> Vec<u8> {
    seal(
        REGISTRY_PAYLOAD_TYPE,
        &serde_json::to_vec(value).unwrap(),
        signers,
    )
}

fn verify_registry(
    w: &World,
    bytes: &[u8],
    prior: Option<&RegistryCheckpoint>,
) -> Result<Registry, Error> {
    Registry::verify(bytes, &w.anchors, prior, &Policy::default(), NOW)
}

#[test]
fn registry_requires_pinned_authority_signatures() {
    let w = World::new();
    let value = w.base_registry_json();
    assert_eq!(w.registry.project(), PROJECT);
    assert_eq!(w.registry.generation(), 1);
    assert_eq!(w.registry.participants().count(), 5);
    assert_eq!(
        w.registry
            .participant("alice-agent")
            .unwrap()
            .controller
            .as_deref(),
        Some("alice")
    );

    // Signed by a participant instead of the authority.
    assert_err!(
        verify_registry(&w, &sealed_registry(&value, &[&w.alice]), None),
        Error::UntrustedAuthority
    );
    // An extra, unpinned co-signature is not ignored.
    assert_err!(
        verify_registry(
            &w,
            &sealed_registry(&value, &[&w.authority, &w.alice]),
            None
        ),
        Error::UntrustedAuthority
    );
    // Authority key id with someone else's signature.
    let payload = serde_json::to_vec(&value).unwrap();
    let mut entry = w.authority.entry(REGISTRY_PAYLOAD_TYPE, &payload);
    entry.signature = Signer::ed(42).sign(&pae(REGISTRY_PAYLOAD_TYPE, &payload));
    let forged = Envelope::new(REGISTRY_PAYLOAD_TYPE, payload.clone(), vec![entry]).unwrap();
    assert_err!(
        verify_registry(&w, &forged.to_json(), None),
        Error::BadSignature
    );
    // Tampered content under the real signature.
    let mut edited = value.clone();
    edited["participants"][1]["controller"] = json!("bob");
    let entry = w.authority.entry(REGISTRY_PAYLOAD_TYPE, &payload);
    let forged = Envelope::new(
        REGISTRY_PAYLOAD_TYPE,
        serde_json::to_vec(&edited).unwrap(),
        vec![entry],
    )
    .unwrap();
    assert_err!(
        verify_registry(&w, &forged.to_json(), None),
        Error::BadSignature
    );
    // An authority-signed event payload is not a registry, and the reverse.
    let as_event = seal(EVENT_PAYLOAD_TYPE, &payload, &[&w.authority]);
    assert_err!(
        verify_registry(&w, &as_event, None),
        Error::UnsupportedPayloadType
    );
    assert_err!(
        w.verify(&w.registry_envelope, none(), "bob"),
        Error::UnsupportedPayloadType
    );

    // Another project's registry, validly signed by the same authority.
    let mut other = value.clone();
    other["project"] = json!("other");
    assert_err!(
        verify_registry(&w, &sealed_registry(&other, &[&w.authority]), None),
        Error::WrongProject
    );

    // Threshold of two authorities.
    let second = Signer::p(8);
    let two = TrustAnchors::new(PROJECT, vec![w.authority.public(), second.public()], 2).unwrap();
    let policy = Policy::default();
    assert_err!(
        Registry::verify(
            &sealed_registry(&value, &[&w.authority]),
            &two,
            None,
            &policy,
            NOW
        ),
        Error::ThresholdNotMet
    );
    assert!(Registry::verify(
        &sealed_registry(&value, &[&second, &w.authority]),
        &two,
        None,
        &policy,
        NOW
    )
    .is_ok());

    // Anchors themselves.
    assert_err!(
        TrustAnchors::new(PROJECT, vec![], 1),
        Error::InvalidAnchors(_)
    );
    assert_err!(
        TrustAnchors::new(PROJECT, vec![w.authority.public()], 0),
        Error::InvalidAnchors(_)
    );
    assert_err!(
        TrustAnchors::new(PROJECT, vec![w.authority.public()], 2),
        Error::InvalidAnchors(_)
    );
    assert_err!(
        TrustAnchors::new(PROJECT, vec![w.authority.public(), w.authority.public()], 1),
        Error::InvalidAnchors(_)
    );
    assert_err!(
        TrustAnchors::new("../x", vec![w.authority.public()], 1),
        Error::InvalidId(_)
    );
}

#[test]
fn registry_generations_are_monotonic_and_chained() {
    let w = World::new();
    let checkpoint = w.registry.checkpoint();
    assert_eq!(checkpoint.generation(), 1);
    assert_eq!(
        checkpoint,
        RegistryCheckpoint::advance(&w.registry_envelope, &w.anchors, None).unwrap()
    );

    let mut gen2 = w.base_registry_json();
    gen2["generation"] = json!(2);
    gen2["previous"] = json!(w.registry.digest().to_hex());
    gen2["revocations"] = json!([{"key_id": w.bob_agent.id(), "revoked_at": NOW - 1}]);
    let gen2_bytes = sealed_registry(&gen2, &[&w.authority]);
    let r2 = verify_registry(&w, &gen2_bytes, Some(&checkpoint)).unwrap();
    assert_eq!(r2.generation(), 2);
    assert!(r2.is_revoked(&w.bob_agent.public().key_id()));
    let cp2 = r2.checkpoint();

    // Same generation again is accepted only when identical.
    assert!(verify_registry(&w, &gen2_bytes, Some(&cp2)).is_ok());
    let mut fork = gen2.clone();
    fork["expires_at"] = json!(NOW + 86_401);
    assert_err!(
        verify_registry(&w, &sealed_registry(&fork, &[&w.authority]), Some(&cp2)),
        Error::RegistryFork
    );

    // Rollback to generation 1.
    assert_err!(
        verify_registry(&w, &w.registry_envelope, Some(&cp2)),
        Error::RegistryRollback
    );

    // Successor naming a different predecessor.
    let mut wrong_prev = gen2.clone();
    wrong_prev["previous"] = json!("0".repeat(64));
    assert_err!(
        verify_registry(
            &w,
            &sealed_registry(&wrong_prev, &[&w.authority]),
            Some(&checkpoint)
        ),
        Error::RegistryChain
    );

    // Skipping a generation.
    let mut gen3 = gen2.clone();
    gen3["generation"] = json!(3);
    gen3["previous"] = json!(r2.digest().to_hex());
    let gen3_bytes = sealed_registry(&gen3, &[&w.authority]);
    assert_err!(
        verify_registry(&w, &gen3_bytes, Some(&checkpoint)),
        Error::RegistryGap
    );
    assert!(verify_registry(&w, &gen3_bytes, Some(&cp2)).is_ok());

    // A successor may not forget a revocation.
    let mut forgetful = gen3.clone();
    forgetful["revocations"] = json!([]);
    assert_err!(
        verify_registry(
            &w,
            &sealed_registry(&forgetful, &[&w.authority]),
            Some(&cp2)
        ),
        Error::RevocationDropped
    );

    // Generation and predecessor must agree structurally.
    let mut g = w.base_registry_json();
    g["generation"] = json!(0);
    assert_err!(
        verify_registry(&w, &sealed_registry(&g, &[&w.authority]), None),
        Error::Schema(_)
    );
    let mut g = w.base_registry_json();
    g["previous"] = json!("0".repeat(64));
    assert_err!(
        verify_registry(&w, &sealed_registry(&g, &[&w.authority]), None),
        Error::Schema(_)
    );
    let mut g = w.base_registry_json();
    g["generation"] = json!(2);
    assert_err!(
        verify_registry(&w, &sealed_registry(&g, &[&w.authority]), None),
        Error::Schema(_)
    );

    // Replaying history without a clock, then the clock still applies to use.
    let cp = RegistryCheckpoint::advance(&gen2_bytes, &w.anchors, Some(&checkpoint)).unwrap();
    assert_eq!(cp, cp2);
    let policy = Policy::default();
    assert_err!(
        Registry::verify(
            &gen2_bytes,
            &w.anchors,
            Some(&checkpoint),
            &policy,
            NOW + 86_401
        ),
        Error::RegistryExpired
    );
    assert_err!(
        Registry::verify(
            &gen2_bytes,
            &w.anchors,
            Some(&checkpoint),
            &policy,
            NOW - 3600 - 121
        ),
        Error::RegistryNotYetValid
    );
}

#[test]
fn registry_schema_is_strict() {
    let w = World::new();
    let check = |change: &dyn Fn(&mut Value)| {
        let mut value = w.base_registry_json();
        change(&mut value);
        verify_registry(&w, &sealed_registry(&value, &[&w.authority]), None)
    };
    assert!(check(&|_| {}).is_ok());
    assert_err!(
        check(&|r| r["version"] = json!(2)),
        Error::UnsupportedVersion
    );
    assert_err!(
        check(&|r| r["note"] = json!("x")),
        Error::Schema("unknown field")
    );
    assert_err!(
        check(&|r| r["participants"][0]["role"] = json!("admin")),
        Error::Schema("unknown field")
    );
    assert_err!(
        check(&|r| r["expires_at"] = json!(NOW - 3601)),
        Error::InvalidTimeRange
    );
    // Classification rules.
    assert_err!(
        check(&|r| r["participants"][0]["kind"] = json!("root")),
        Error::Schema(_)
    );
    // Local human keys may be enrolled without claiming an enterprise account.
    assert!(check(&|r| r["participants"][0]["ghes"] = json!(null)).is_ok());
    assert_err!(
        check(&|r| r["participants"][0]["controller"] = json!("bob")),
        Error::Schema(_)
    );
    assert_err!(
        check(&|r| r["participants"][1]["controller"] = json!(null)),
        Error::Schema(_)
    );
    assert_err!(
        check(&|r| r["participants"][1]["controller"] = json!("bob-agent")),
        Error::Schema(_)
    );
    assert_err!(
        check(&|r| r["participants"][1]["controller"] = json!("nobody")),
        Error::Schema(_)
    );
    assert_err!(
        check(&|r| r["participants"][1]["ghes"] =
            json!({"instance": "ghes.example.com", "user_id": 5})),
        Error::Schema(_)
    );
    assert_err!(
        check(&|r| r["participants"][4]["controller"] = json!("alice-agent")),
        Error::Schema(_)
    );
    // GHES identity: one account, one participant; host and id are checked.
    assert_err!(
        check(&|r| r["participants"][2]["ghes"]["user_id"] = json!(1001)),
        Error::Schema(_)
    );
    assert_err!(
        check(&|r| r["participants"][0]["ghes"]["user_id"] = json!(0)),
        Error::Schema(_)
    );
    assert_err!(
        check(&|r| r["participants"][0]["ghes"]["instance"] = json!("https://ghes.example.com/")),
        Error::Schema(_)
    );
    assert_err!(
        check(&|r| r["participants"][0]["ghes"]["login"] = json!("alice")),
        Error::Schema(_)
    );
    // Ordering and uniqueness.
    assert_err!(
        check(&|r| r["participants"].as_array_mut().unwrap().swap(0, 1)),
        Error::Schema(_)
    );
    assert_err!(
        check(&|r| r["keys"].as_array_mut().unwrap().swap(0, 1)),
        Error::Schema(_)
    );
    assert_err!(
        check(&|r| {
            let first = r["keys"][0].clone();
            r["keys"].as_array_mut().unwrap().insert(0, first);
        }),
        Error::Schema(_)
    );
    // Keys: id must match the key, owner must exist, validity must be ordered.
    assert_err!(
        check(&|r| r["keys"][0]["key_id"] = json!(Signer::ed(42).id())),
        Error::KeyIdMismatch
    );
    assert_err!(
        check(&|r| r["keys"][0]["participant"] = json!("mallory")),
        Error::UnknownParticipant
    );
    assert_err!(
        check(&|r| r["keys"][0]["not_after"] = json!(0)),
        Error::InvalidTimeRange
    );
    assert_err!(
        check(&|r| r["keys"][0]["public_key"] = json!(b64(&[0u8; 32]))),
        Error::InvalidKey
    );
    assert_err!(
        check(&|r| r["keys"][0]["algorithm"] = json!("rsa")),
        Error::UnsupportedAlgorithm
    );

    // Duplicate JSON key inside the signed registry payload.
    let text = serde_json::to_string(&w.base_registry_json()).unwrap();
    let dup = text.replacen('{', r#"{"generation":1,"#, 1);
    let bytes = seal(REGISTRY_PAYLOAD_TYPE, dup.as_bytes(), &[&w.authority]);
    assert_err!(
        verify_registry(&w, &bytes, None),
        Error::Malformed("duplicate object key")
    );
}

// ------------------------------------------------------------ human sessions

#[test]
fn a_session_key_may_sign_statements_within_its_grant() {
    let w = World::new();
    let grant = seal_event(&w.session_grant(), &w.alice);
    // The grant verifies on its own.
    let g = w.verify(&grant, none(), "bob").unwrap();
    assert_eq!(g.signer(), SignerRole::HumanDevice);

    let s = seal_event(&w.session_statement(&grant), &w.session);
    let v = w.verify(&s, grant_evidence(&grant), "bob").unwrap();
    assert_eq!(v.signer(), SignerRole::HumanSession);
    assert_eq!(v.author_kind(), ParticipantKind::Human);
    assert!(v.is_human_authored());
    assert_eq!(v.event().author, "alice");
    assert_eq!(v.grant().unwrap().digest(), g.digest());
    assert_eq!(v.ghes().unwrap().user_id, 1001);

    // Narrowing the audience is allowed.
    let mut e = w.session_statement(&grant);
    e["audience"] = json!(["bob"]);
    assert!(w
        .verify(&seal_event(&e, &w.session), grant_evidence(&grant), "bob")
        .is_ok());

    // Both this session and statement remain current at this point.
    assert!(w
        .verify_at(&s, grant_evidence(&grant), "bob", None, NOW + 590)
        .is_ok());
    // Use an actually expired grant: an old issued_at cannot establish timely
    // use for a newly received statement. Accepted history is the core's job.
    let mut short = w.session_grant();
    short["expires_at"] = json!(NOW + 100);
    let grant = seal_event(&short, &w.alice);
    let s = seal_event(&w.session_statement(&grant), &w.session);
    assert_err!(
        w.verify_at(&s, grant_evidence(&grant), "bob", None, NOW + 590),
        Error::Expired
    );
}

#[test]
fn session_scope_cannot_be_escalated() {
    let w = World::new();
    let grant = seal_event(&w.session_grant(), &w.alice);
    let ev = grant_evidence(&grant);
    let with = |change: &dyn Fn(&mut Value)| {
        let mut e = w.session_statement(&grant);
        change(&mut e);
        w.verify(&seal_event(&e, &w.session), ev, "bob")
    };
    assert!(with(&|_| {}).is_ok());

    // Wider audience than granted.
    assert_err!(
        with(&|e| e["audience"] = json!(["alice-agent", "bob", "bob-agent"])),
        Error::ScopeEscalation("audience")
    );
    // Another group than granted.
    assert_err!(
        w.verify_at(
            &seal_event(
                &{
                    let mut e = w.session_statement(&grant);
                    e["group"] = json!("g1");
                    e
                },
                &w.session
            ),
            ev,
            "bob",
            Some("g1"),
            NOW
        ),
        Error::ScopeEscalation("group")
    );
    // Issued before or after the session window.
    assert_err!(
        with(&|e| e["issued_at"] = json!(NOW - 61)),
        Error::OutsideGrantWindow
    );
    let mut late = w.session_statement(&grant);
    late["issued_at"] = json!(NOW + 1741);
    late["expires_at"] = json!(NOW + 1800);
    assert_err!(
        w.verify_at(&seal_event(&late, &w.session), ev, "bob", None, NOW + 1750),
        Error::OutsideGrantWindow
    );
    // Speaking for someone else.
    assert_err!(with(&|e| e["author"] = json!("bob")), Error::AuthorMismatch);

    // The session key cannot issue grants, delegations or authorizations,
    // nor any non-statement kind.
    let session_ref = digest_hex(&grant);
    let attempts = [
        ("session.grant", w.session_grant()["body"].clone()),
        (
            "agent.delegation",
            w.delegation(&["agent.message"])["body"].clone(),
        ),
        (
            "action.authorization",
            json!({"action": "membership.add", "request_digest": "1".repeat(64), "performer": "alice-agent"}),
        ),
        ("agent.message", json!({"text": "x"})),
        ("service.notice", json!({"text": "x"})),
    ];
    for (kind, body) in attempts {
        let mut e = event(kind, "alice", &w.session, body);
        e["session"] = json!(session_ref);
        e["expires_at"] = json!(NOW + 100);
        let result = w.verify(&seal_event(&e, &w.session), ev, "bob");
        assert_err!(result, Error::KindNotPermitted(_));
        // Without naming the grant the key is simply unknown.
        e["session"] = json!(null);
        assert_err!(
            w.verify(&seal_event(&e, &w.session), none(), "bob"),
            Error::UnknownKey
        );
    }
}

#[test]
fn session_grants_must_be_narrow_and_device_signed() {
    let w = World::new();
    let use_grant = |g: &Value, signer: &Signer| {
        let grant = seal_event(g, signer);
        let s = seal_event(&w.session_statement(&grant), &w.session);
        w.verify(&s, grant_evidence(&grant), "bob")
    };
    assert!(use_grant(&w.session_grant(), &w.alice).is_ok());

    // Longer than the session maximum.
    let mut g = w.session_grant();
    g["expires_at"] = json!(NOW + 1741);
    assert_err!(use_grant(&g, &w.alice), Error::LifetimeTooLong);
    // Purposes beyond human.statement.
    let mut g = w.session_grant();
    g["body"]["purposes"] = json!(["agent.delegation", "human.statement"]);
    assert_err!(use_grant(&g, &w.alice), Error::InvalidGrant(_));
    let mut g = w.session_grant();
    g["body"]["purposes"] = json!(["session.grant"]);
    assert_err!(use_grant(&g, &w.alice), Error::InvalidGrant(_));
    let mut g = w.session_grant();
    g["body"]["purposes"] = json!([]);
    assert_err!(use_grant(&g, &w.alice), Error::Schema(_));

    // Granted by an agent, or by the agent in alice's name.
    let mut g = w.session_grant();
    g["author"] = json!("alice-agent");
    g["key_id"] = json!(w.alice_agent.id());
    assert_err!(
        use_grant(&g, &w.alice_agent),
        Error::KindNotPermitted("session.grant")
    );
    let mut g = w.session_grant();
    g["key_id"] = json!(w.alice_agent.id());
    assert_err!(use_grant(&g, &w.alice_agent), Error::AuthorMismatch);
    // Self-issued by the session key.
    let mut g = w.session_grant();
    g["key_id"] = json!(w.session.id());
    assert_err!(use_grant(&g, &w.session), Error::UnknownKey);
    // Granted by another human for alice's name.
    let mut g = w.session_grant();
    g["author"] = json!("bob");
    g["key_id"] = json!(w.bob.id());
    assert_err!(use_grant(&g, &w.bob), Error::AuthorMismatch);
    // Tampered grant.
    let grant = seal_event(&w.session_grant(), &w.alice);
    let s = seal_event(&w.session_statement(&grant), &w.session);
    let mut edited = w.session_grant();
    edited["audience"] = json!(["alice-agent", "bob", "bob-agent"]);
    let entry = w.alice.entry(
        EVENT_PAYLOAD_TYPE,
        &serde_json::to_vec(&w.session_grant()).unwrap(),
    );
    let forged = Envelope::new(
        EVENT_PAYLOAD_TYPE,
        serde_json::to_vec(&edited).unwrap(),
        vec![entry],
    )
    .unwrap();
    assert_err!(
        w.verify(&s, grant_evidence(&forged.to_json()), "bob"),
        Error::EvidenceMismatch("grant")
    );

    // Evidence handling.
    assert_err!(
        w.verify(&s, none(), "bob"),
        Error::EvidenceRequired("grant")
    );
    let mut other = w.session_grant();
    other["id"] = json!("grant-2");
    let other = seal_event(&other, &w.alice);
    assert_err!(
        w.verify(&s, grant_evidence(&other), "bob"),
        Error::EvidenceMismatch("grant")
    );
    // A grant for a different session key.
    let mut g = w.session_grant();
    g["body"]["session_key"]["public_key"] = json!(b64(Signer::p(77).public().as_bytes()));
    assert_err!(
        use_grant(&g, &w.alice),
        Error::EvidenceMismatch("session key")
    );
    // Unneeded evidence is refused rather than ignored.
    let plain = seal_event(&w.statement(), &w.alice);
    assert_err!(
        w.verify(&plain, grant_evidence(&grant), "bob"),
        Error::UnexpectedEvidence("grant")
    );
    // A device key does not sign under a session reference.
    let mut e = w.statement();
    e["session"] = json!(digest_hex(&grant));
    assert_err!(
        w.verify(&seal_event(&e, &w.alice), grant_evidence(&grant), "bob"),
        Error::SessionNotAllowed
    );
}

// --------------------------------------------------------- agent delegations

#[test]
fn an_agent_acts_only_within_its_delegation() {
    let w = World::new();
    let delegation = seal_event(&w.delegation(&["agent.message"]), &w.alice);
    let ev = grant_evidence(&delegation);
    assert!(w.verify(&delegation, none(), "bob").is_ok());

    let m = seal_event(&w.agent_message(&delegation), &w.alice_agent);
    let v = w.verify(&m, ev, "bob").unwrap();
    assert_eq!(v.signer(), SignerRole::Agent);
    assert_eq!(v.controller(), Some("alice"));
    assert_eq!(v.grant().unwrap().event().author, "alice");

    // No delegation named, or not supplied.
    let mut e = w.agent_message(&delegation);
    e["session"] = json!(null);
    assert_err!(
        w.verify(&seal_event(&e, &w.alice_agent), none(), "bob"),
        Error::EvidenceRequired("delegation")
    );
    assert_err!(
        w.verify(&m, none(), "bob"),
        Error::EvidenceRequired("grant")
    );

    // Purpose not delegated.
    let statement = seal_event(&w.statement(), &w.alice);
    let relay = seal_event(&w.relay(&statement, &delegation), &w.alice_agent);
    assert_err!(
        w.verify(&relay, ev, "bob"),
        Error::ScopeEscalation("purpose")
    );
    // Audience outside the delegation (alice-agent itself is not in it).
    let mut e = w.agent_message(&delegation);
    e["audience"] = json!(["alice-agent", "bob"]);
    assert_err!(
        w.verify(&seal_event(&e, &w.alice_agent), ev, "bob"),
        Error::ScopeEscalation("audience")
    );
    // Group outside the delegation.
    let mut e = w.agent_message(&delegation);
    e["group"] = json!("g1");
    assert_err!(
        w.verify_at(&seal_event(&e, &w.alice_agent), ev, "bob", Some("g1"), NOW),
        Error::ScopeEscalation("group")
    );
    // Issued after the delegation ended.
    let mut e = w.agent_message(&delegation);
    e["issued_at"] = json!(NOW + 3601);
    e["expires_at"] = json!(NOW + 3700);
    assert_err!(
        w.verify_at(&seal_event(&e, &w.alice_agent), ev, "bob", None, NOW + 3650),
        Error::OutsideGrantWindow
    );
    // A session grant is not a delegation.
    let grant = seal_event(&w.session_grant(), &w.alice);
    let mut e = w.agent_message(&delegation);
    e["session"] = json!(digest_hex(&grant));
    assert_err!(
        w.verify(
            &seal_event(&e, &w.alice_agent),
            grant_evidence(&grant),
            "bob"
        ),
        Error::EvidenceMismatch(_)
    );
}

#[test]
fn delegations_cannot_be_forged_or_widened() {
    let w = World::new();
    let attempt = |d: &Value, signer: &Signer| {
        let delegation = seal_event(d, signer);
        let m = seal_event(&w.agent_message(&delegation), &w.alice_agent);
        w.verify(&m, grant_evidence(&delegation), "bob")
    };
    assert!(attempt(&w.delegation(&["agent.message"]), &w.alice).is_ok());

    // The agent delegates to itself.
    let mut d = w.delegation(&["agent.message"]);
    d["author"] = json!("alice-agent");
    d["key_id"] = json!(w.alice_agent.id());
    assert_err!(
        attempt(&d, &w.alice_agent),
        Error::KindNotPermitted("agent.delegation")
    );
    // The agent signs in alice's name.
    let mut d = w.delegation(&["agent.message"]);
    d["key_id"] = json!(w.alice_agent.id());
    assert_err!(attempt(&d, &w.alice_agent), Error::AuthorMismatch);
    // Another human delegates alice's agent.
    let mut d = w.delegation(&["agent.message"]);
    d["author"] = json!("bob");
    d["key_id"] = json!(w.bob.id());
    assert_err!(attempt(&d, &w.bob), Error::InvalidGrant(_));
    // Delegation to a human, or naming a key that is not the agent's.
    let mut d = w.delegation(&["agent.message"]);
    d["body"]["agent"] = json!("bob");
    assert_err!(
        w.verify(&seal_event(&d, &w.alice), none(), "bob"),
        Error::InvalidGrant(_)
    );
    let mut d = w.delegation(&["agent.message"]);
    d["body"]["agent_key_id"] = json!(w.bob_agent.id());
    assert_err!(
        w.verify(&seal_event(&d, &w.alice), none(), "bob"),
        Error::InvalidGrant(_)
    );
    // Human purposes cannot be delegated.
    for purpose in [
        "human.statement",
        "session.grant",
        "agent.delegation",
        "action.authorization",
    ] {
        let d = w.delegation(&[purpose]);
        assert_err!(attempt(&d, &w.alice), Error::InvalidGrant(_));
    }
    // Too long-lived.
    let mut d = w.delegation(&["agent.message"]);
    d["expires_at"] = json!(NOW + 8 * 24 * 3600);
    assert_err!(attempt(&d, &w.alice), Error::LifetimeTooLong);
    // Issued by a human session key.
    let grant = seal_event(&w.session_grant(), &w.alice);
    let mut d = w.delegation(&["agent.message"]);
    d["key_id"] = json!(w.session.id());
    d["session"] = json!(digest_hex(&grant));
    d["issued_at"] = json!(NOW - 30);
    // As evidence it would itself need evidence, which is never supplied...
    assert_err!(attempt(&d, &w.session), Error::EvidenceRequired("grant"));
    // ...and on its own it is not something a session key may issue.
    assert_err!(
        w.verify(&seal_event(&d, &w.session), grant_evidence(&grant), "bob"),
        Error::KindNotPermitted("agent.delegation")
    );

    // bob's agent cannot use alice-agent's delegation.
    let delegation = seal_event(&w.delegation(&["agent.message"]), &w.alice);
    let mut e = event(
        "agent.message",
        "bob-agent",
        &w.bob_agent,
        json!({"text": "x"}),
    );
    e["session"] = json!(digest_hex(&delegation));
    e["audience"] = json!(["bob"]);
    assert_err!(
        w.verify(
            &seal_event(&e, &w.bob_agent),
            grant_evidence(&delegation),
            "bob"
        ),
        Error::EvidenceMismatch(_)
    );
}

// ---------------------------------------------------------------------- relay

#[test]
fn a_relay_preserves_the_verifiable_human_original() {
    let w = World::new();
    let delegation = seal_event(&w.delegation(&["agent.message", "agent.relay"]), &w.alice);
    let statement = seal_event(&w.statement(), &w.alice);
    let original_payload = Envelope::parse(&statement, EVENT_PAYLOAD_TYPE)
        .unwrap()
        .payload()
        .to_vec();

    let relay = seal_event(&w.relay(&statement, &delegation), &w.alice_agent);
    let v = w
        .verify(&relay, grant_evidence(&delegation), "bob")
        .unwrap();
    // The relay is the agent's.
    assert_eq!(v.signer(), SignerRole::Agent);
    assert_eq!(v.author_kind(), ParticipantKind::Agent);
    assert!(!v.is_human_authored());
    // The original is alice's, byte for byte.
    let o = v.original().unwrap();
    assert_eq!(o.signer(), SignerRole::HumanDevice);
    assert_eq!(o.event().author, "alice");
    assert!(o.is_human_authored());
    assert_eq!(o.payload(), original_payload.as_slice());
    assert_eq!(o.digest(), Digest::of(&original_payload));
    assert_eq!(
        o.event().body,
        Body::HumanStatement {
            text: "hello team".into()
        }
    );

    // A session-signed original needs its own grant.
    let grant = seal_event(&w.session_grant(), &w.alice);
    let s = seal_event(&w.session_statement(&grant), &w.session);
    let relay = seal_event(&w.relay(&s, &delegation), &w.alice_agent);
    let ev = Evidence {
        grant: Some(&delegation),
        original_grant: Some(&grant),
        authorization: None,
    };
    let v = w.verify(&relay, ev, "bob").unwrap();
    assert_eq!(v.original().unwrap().signer(), SignerRole::HumanSession);
    assert_err!(
        w.verify(&relay, grant_evidence(&delegation), "bob"),
        Error::EvidenceRequired("grant")
    );
    // original_grant is refused where no relay needs it.
    let m = seal_event(&w.agent_message(&delegation), &w.alice_agent);
    assert_err!(
        w.verify(&m, ev, "bob"),
        Error::UnexpectedEvidence("original_grant")
    );
}

#[test]
fn relay_substitution_is_rejected() {
    let w = World::new();
    let delegation = seal_event(&w.delegation(&["agent.message", "agent.relay"]), &w.alice);
    let ev = grant_evidence(&delegation);
    let statement = seal_event(&w.statement(), &w.alice);
    let relay_of = |original: &[u8]| {
        w.verify(
            &seal_event(&w.relay(original, &delegation), &w.alice_agent),
            ev,
            "bob",
        )
    };
    assert!(relay_of(&statement).is_ok());

    // The agent edits the human's words but keeps her signature.
    let parsed = Envelope::parse(&statement, EVENT_PAYLOAD_TYPE).unwrap();
    let mut edited: Value = serde_json::from_slice(parsed.payload()).unwrap();
    edited["body"]["text"] = json!("hello team, please wire the money");
    let forged = Envelope::new(
        EVENT_PAYLOAD_TYPE,
        serde_json::to_vec(&edited).unwrap(),
        parsed.signatures().to_vec(),
    )
    .unwrap();
    assert_err!(relay_of(&forged.to_json()), Error::BadSignature);

    // The agent re-signs the edited words with its own key under alice's name.
    let mut fake = w.statement();
    fake["key_id"] = json!(w.alice_agent.id());
    fake["body"]["text"] = json!("hello team, please wire the money");
    assert_err!(
        relay_of(&seal_event(&fake, &w.alice_agent)),
        Error::AuthorMismatch
    );
    // ...or names alice's key id while signing with its own.
    let payload = serde_json::to_vec(&edited).unwrap();
    let mut entry = w.alice.entry(EVENT_PAYLOAD_TYPE, &payload);
    entry.signature = w.alice_agent.sign(&pae(EVENT_PAYLOAD_TYPE, &payload));
    let forged = Envelope::new(EVENT_PAYLOAD_TYPE, payload, vec![entry]).unwrap();
    assert_err!(relay_of(&forged.to_json()), Error::BadSignature);

    // The "original" is an agent message, or another relay.
    let m = seal_event(&w.agent_message(&delegation), &w.alice_agent);
    assert_err!(
        relay_of(&m),
        Error::RelayInvalid("original is not a human statement")
    );
    let inner_relay = seal_event(&w.relay(&statement, &delegation), &w.alice_agent);
    assert_err!(
        relay_of(&inner_relay),
        Error::RelayInvalid("original is not a human statement")
    );

    // A genuine alice statement from another project.
    let mut foreign = w.statement();
    foreign["project"] = json!("other");
    assert_err!(
        relay_of(&seal_event(&foreign, &w.alice)),
        Error::WrongProject
    );

    // A genuine statement that has expired.
    let mut old = w.statement();
    old["issued_at"] = json!(NOW - 1000);
    old["expires_at"] = json!(NOW - 1);
    assert_err!(relay_of(&seal_event(&old, &w.alice)), Error::Expired);

    // Relaying to someone the human did not address.
    let mut private = w.statement();
    private["audience"] = json!(["alice-agent"]);
    assert_err!(
        relay_of(&seal_event(&private, &w.alice)),
        Error::RelayInvalid("audience is wider than the original's")
    );

    // An agent that never received the original relays it.
    let mut d = event(
        "agent.delegation",
        "bob",
        &w.bob,
        json!({"agent": "bob-agent", "agent_key_id": w.bob_agent.id(), "purposes": ["agent.relay"]}),
    );
    d["audience"] = json!(["alice", "alice-agent", "bob"]);
    let bob_delegation = seal_event(&d, &w.bob);
    let mut r = w.relay(&statement, &bob_delegation);
    r["author"] = json!("bob-agent");
    r["key_id"] = json!(w.bob_agent.id());
    assert_err!(
        w.verify(
            &seal_event(&r, &w.bob_agent),
            grant_evidence(&bob_delegation),
            "bob"
        ),
        Error::RelayInvalid("relayer was not a recipient of the original")
    );

    // The outer relay itself is tampered: swap in another genuine original
    // after signing.
    let mut second = w.statement();
    second["id"] = json!("event-2");
    second["body"]["text"] = json!("a different message");
    let second = seal_event(&second, &w.alice);
    let relay_value = w.relay(&statement, &delegation);
    let entry = w.alice_agent.entry(
        EVENT_PAYLOAD_TYPE,
        &serde_json::to_vec(&relay_value).unwrap(),
    );
    let swapped = w.relay(&second, &delegation);
    let forged = Envelope::new(
        EVENT_PAYLOAD_TYPE,
        serde_json::to_vec(&swapped).unwrap(),
        vec![entry],
    )
    .unwrap();
    assert_err!(w.verify(&forged.to_json(), ev, "bob"), Error::BadSignature);

    // Unknown fields inside the embedded envelope.
    let mut r = w.relay(&statement, &delegation);
    r["body"]["original"]["comment"] = json!("trust me");
    assert_err!(
        w.verify(&seal_event(&r, &w.alice_agent), ev, "bob"),
        Error::Schema("unknown field")
    );
}

// -------------------------------------------------------------------- actions

struct Action {
    delegation: Vec<u8>,
    authorization: Value,
    request: String,
}

fn action(w: &World) -> Action {
    let request = Digest::of(b"exact reviewed request sidecar").to_hex();
    let mut d = w.delegation(&["action.execute", "agent.message"]);
    d["group"] = json!("g1");
    let mut a = event(
        "action.authorization",
        "alice",
        &w.alice,
        json!({"action": "membership.add", "request_digest": request, "performer": "alice-agent"}),
    );
    a["id"] = json!("authz-1");
    a["issued_at"] = json!(NOW - 30);
    a["expires_at"] = json!(NOW + 270);
    a["audience"] = json!(["alice", "bob"]);
    a["group"] = json!("g1");
    a["epoch"] = json!(4);
    Action {
        delegation: seal_event(&d, &w.alice),
        authorization: a,
        request,
    }
}

fn execute(w: &World, a: &Action, authorization: &[u8]) -> Value {
    let mut e = event(
        "action.execute",
        "alice-agent",
        &w.alice_agent,
        json!({
            "action": "membership.add",
            "request_digest": a.request,
            "authorization": digest_hex(authorization),
        }),
    );
    e["session"] = json!(digest_hex(&a.delegation));
    e["audience"] = json!(["alice", "bob"]);
    e["group"] = json!("g1");
    e["epoch"] = json!(4);
    e
}

fn run(w: &World, a: &Action, authorization: &[u8], e: &Value) -> Result<VerifiedEvent, Error> {
    let ev = Evidence {
        grant: Some(&a.delegation),
        authorization: Some(authorization),
        original_grant: None,
    };
    w.verify_at(&seal_event(e, &w.alice_agent), ev, "bob", Some("g1"), NOW)
}

#[test]
fn an_action_needs_a_matching_fresh_human_authorization() {
    let w = World::new();
    let a = action(&w);
    let authz = seal_event(&a.authorization, &w.alice);
    assert!(w.verify_at(&authz, none(), "bob", Some("g1"), NOW).is_ok());

    let v = run(&w, &a, &authz, &execute(&w, &a, &authz)).unwrap();
    assert_eq!(v.signer(), SignerRole::Agent);
    let approved = v.authorization().unwrap();
    assert_eq!(approved.signer(), SignerRole::HumanDevice);
    assert_eq!(approved.event().author, "alice");
    assert_eq!(approved.digest().to_hex(), digest_hex(&authz));

    // Missing authorization.
    let e = seal_event(&execute(&w, &a, &authz), &w.alice_agent);
    assert_err!(
        w.verify_at(&e, grant_evidence(&a.delegation), "bob", Some("g1"), NOW),
        Error::EvidenceRequired("authorization")
    );
    // A different authorization than the one named.
    let mut other = a.authorization.clone();
    other["id"] = json!("authz-2");
    let other = seal_event(&other, &w.alice);
    assert_err!(
        run(&w, &a, &other, &execute(&w, &a, &authz)),
        Error::EvidenceMismatch("authorization")
    );

    // The executed action differs from what the human approved.
    let mut e = execute(&w, &a, &authz);
    e["body"]["request_digest"] = json!(Digest::of(b"another request sidecar").to_hex());
    assert_err!(
        run(&w, &a, &authz, &e),
        Error::AuthorizationMismatch("request digest")
    );
    let mut e = execute(&w, &a, &authz);
    e["body"]["action"] = json!("membership.remove");
    assert_err!(
        run(&w, &a, &authz, &e),
        Error::AuthorizationMismatch("action")
    );
    let mut e = execute(&w, &a, &authz);
    e["audience"] = json!(["bob"]);
    assert_err!(
        run(&w, &a, &authz, &e),
        Error::AuthorizationMismatch("audience")
    );
    let mut e = execute(&w, &a, &authz);
    e["epoch"] = json!(5);
    assert_err!(
        run(&w, &a, &authz, &e),
        Error::AuthorizationMismatch("group or epoch")
    );

    // Executed after the authorization lapsed.
    let mut e = execute(&w, &a, &authz);
    e["issued_at"] = json!(NOW + 271);
    e["expires_at"] = json!(NOW + 600);
    let ev = Evidence {
        grant: Some(&a.delegation),
        authorization: Some(&authz),
        original_grant: None,
    };
    assert_err!(
        w.verify_at(
            &seal_event(&e, &w.alice_agent),
            ev,
            "bob",
            Some("g1"),
            NOW + 280
        ),
        Error::OutsideGrantWindow
    );

    // The delegation must allow executing actions at all.
    let mut narrow = action(&w);
    let mut d = w.delegation(&["agent.message"]);
    d["group"] = json!("g1");
    narrow.delegation = seal_event(&d, &w.alice);
    assert_err!(
        run(&w, &narrow, &authz, &execute(&w, &narrow, &authz)),
        Error::ScopeEscalation("purpose")
    );

    // Unneeded authorization evidence is refused.
    let mut m = w.agent_message(&a.delegation);
    m["group"] = json!("g1");
    assert_err!(
        run(&w, &a, &authz, &m),
        Error::UnexpectedEvidence("authorization")
    );
}

#[test]
fn authorizations_come_only_from_the_controlling_human_device_key() {
    let w = World::new();
    let a = action(&w);
    let attempt = |authorization: &Value, signer: &Signer| {
        let authz = seal_event(authorization, signer);
        run(&w, &a, &authz, &execute(&w, &a, &authz))
    };
    assert!(attempt(&a.authorization, &w.alice).is_ok());

    // Longer-lived than "fresh".
    let mut z = a.authorization.clone();
    z["expires_at"] = json!(NOW + 271);
    assert_err!(attempt(&z, &w.alice), Error::LifetimeTooLong);
    // Approved for another performer.
    let mut z = a.authorization.clone();
    z["body"]["performer"] = json!("alice");
    assert_err!(
        attempt(&z, &w.alice),
        Error::AuthorizationMismatch("performer")
    );
    // bob approves an action for alice's agent.
    let mut z = a.authorization.clone();
    z["author"] = json!("bob");
    z["key_id"] = json!(w.bob.id());
    assert_err!(attempt(&z, &w.bob), Error::InvalidGrant(_));
    // The agent approves itself, directly or in alice's name.
    let mut z = a.authorization.clone();
    z["author"] = json!("alice-agent");
    z["key_id"] = json!(w.alice_agent.id());
    assert_err!(
        attempt(&z, &w.alice_agent),
        Error::KindNotPermitted("action.authorization")
    );
    let mut z = a.authorization.clone();
    z["key_id"] = json!(w.alice_agent.id());
    assert_err!(attempt(&z, &w.alice_agent), Error::AuthorMismatch);
    // A human session key cannot approve actions.
    let grant = seal_event(&w.session_grant(), &w.alice);
    let mut z = a.authorization.clone();
    z["key_id"] = json!(w.session.id());
    z["session"] = json!(digest_hex(&grant));
    assert_err!(attempt(&z, &w.session), Error::EvidenceRequired("grant"));
    assert_err!(
        w.verify_at(
            &seal_event(&z, &w.session),
            grant_evidence(&grant),
            "bob",
            Some("g1"),
            NOW
        ),
        Error::KindNotPermitted("action.authorization")
    );
    // A delegation is not an authorization.
    let mut e = execute(&w, &a, &a.delegation);
    e["body"]["authorization"] = json!(digest_hex(&a.delegation));
    assert_err!(
        run(&w, &a, &a.delegation, &e),
        Error::OutsideGrantWindow | Error::EvidenceMismatch(_)
    );

    // A human may execute an action approved for themself.
    let mut z = a.authorization.clone();
    z["body"]["performer"] = json!("alice");
    let authz = seal_event(&z, &w.alice);
    let mut e = execute(&w, &a, &authz);
    e["author"] = json!("alice");
    e["key_id"] = json!(w.alice.id());
    e["session"] = json!(null);
    let ev = Evidence {
        authorization: Some(&authz),
        ..Evidence::default()
    };
    let v = w
        .verify_at(&seal_event(&e, &w.alice), ev, "bob", Some("g1"), NOW)
        .unwrap();
    assert_eq!(v.signer(), SignerRole::HumanDevice);
    // ...but not one approved by and for another human.
    e["author"] = json!("bob");
    e["key_id"] = json!(w.bob.id());
    assert_err!(
        w.verify_at(&seal_event(&e, &w.bob), ev, "alice", Some("g1"), NOW),
        Error::AuthorizationMismatch("performer")
    );
    // Services cannot execute actions.
    e["author"] = json!("ci");
    e["key_id"] = json!(w.ci.id());
    assert_err!(
        w.verify_at(&seal_event(&e, &w.ci), ev, "bob", Some("g1"), NOW),
        Error::KindNotPermitted("action.execute")
    );
}

// ------------------------------------------------------------------ builders

#[test]
fn event_builder_round_trips_through_the_strict_parser() {
    let w = World::new();
    let statement = seal_event(&w.statement(), &w.alice);
    let bodies = vec![
        Body::HumanStatement {
            text: "héllo \u{0}\"\\ \n".into(),
        },
        Body::SessionGrant {
            session_key: w.session.public(),
            purposes: vec![Kind::HumanStatement],
        },
        Body::AgentDelegation {
            agent: "alice-agent".into(),
            agent_key_id: w.alice_agent.public().key_id(),
            purposes: vec![Kind::ActionExecute, Kind::AgentMessage],
        },
        Body::AgentRelay {
            original: Envelope::parse(&statement, EVENT_PAYLOAD_TYPE).unwrap(),
            note: None,
        },
        Body::ActionAuthorization {
            action: "membership.add".into(),
            request_digest: Digest::of(b"r"),
            performer: "alice-agent".into(),
        },
        Body::ActionExecute {
            action: "membership.add".into(),
            request_digest: Digest::of(b"r"),
            authorization: Digest::of(b"a"),
        },
        Body::ServiceNotice {
            text: String::new(),
        },
    ];
    for body in bodies {
        let event = Event {
            id: "event-9".into(),
            project: PROJECT.into(),
            author: "alice".into(),
            key_id: w.alice.public().key_id(),
            session: Some(Digest::of(b"s")),
            issued_at: NOW,
            expires_at: NOW + 60,
            audience: vec!["alice-agent".into(), "bob".into()],
            group: Some("g1".into()),
            epoch: Some(u64::MAX),
            previous: Some(Digest::of(b"p")),
            body,
        };
        let payload = event.to_payload().unwrap();
        assert_eq!(Event::parse(&payload).unwrap(), event);
    }

    // The builder refuses what the parser would refuse.
    let mut event = Event::parse(&serde_json::to_vec(&w.statement()).unwrap()).unwrap();
    assert_eq!(event.kind(), Kind::HumanStatement);
    event.audience = vec!["bob".into(), "alice-agent".into()];
    assert_err!(event.to_payload(), Error::Schema(_));
    event.audience = vec!["bob".into()];
    event.id = "../x".into();
    assert_err!(event.to_payload(), Error::InvalidId("id"));

    // A built, signed event verifies.
    let event = Event {
        id: "event-10".into(),
        project: PROJECT.into(),
        author: "bob".into(),
        key_id: w.bob.public().key_id(),
        session: None,
        issued_at: NOW,
        expires_at: NOW + 60,
        audience: vec!["alice".into()],
        group: None,
        epoch: None,
        previous: None,
        body: Body::HumanStatement {
            text: "built".into(),
        },
    };
    let payload = event.to_payload().unwrap();
    let bytes = seal(EVENT_PAYLOAD_TYPE, &payload, &[&w.bob]);
    assert_eq!(w.verify(&bytes, none(), "alice").unwrap().event(), &event);
}

// ------------------------------------------------------------ ticket.action

fn ticket_action(w: &World, delegation: &[u8]) -> Value {
    let mut e = event(
        "ticket.action",
        "alice-agent",
        &w.alice_agent,
        json!({
            "action": "ticket.claim",
            "request_digest": Digest::of(b"exact reviewed request sidecar").to_hex(),
        }),
    );
    e["session"] = json!(digest_hex(delegation));
    e["audience"] = json!(["bob"]);
    e
}

#[test]
fn ticket_actions_are_routine_but_need_an_explicit_delegation() {
    let w = World::new();
    let delegation = seal_event(&w.delegation(&["agent.message", "ticket.action"]), &w.alice);
    let ev = grant_evidence(&delegation);

    // No fresh human authorization is needed, only the delegation.
    let t = seal_event(&ticket_action(&w, &delegation), &w.alice_agent);
    let v = w.verify(&t, ev, "bob").unwrap();
    assert_eq!(v.signer(), SignerRole::Agent);
    assert!(!v.is_human_authored());
    assert_eq!(
        v.event().body,
        Body::TicketAction {
            action: "ticket.claim".into(),
            request_digest: Digest::of(b"exact reviewed request sidecar"),
        }
    );
    assert_eq!(v.grant().unwrap().event().author, "alice");

    // Every routine action is accepted; nothing else is.
    for action in TICKET_ACTIONS {
        let mut e = ticket_action(&w, &delegation);
        e["body"]["action"] = json!(action);
        assert!(
            w.verify(&seal_event(&e, &w.alice_agent), ev, "bob").is_ok(),
            "{action}"
        );
    }
    for action in [
        "ticket.recover",
        "ticket.delete",
        "claim",
        "membership.add",
        "Ticket.Claim",
        "",
    ] {
        let mut e = ticket_action(&w, &delegation);
        e["body"]["action"] = json!(action);
        assert_err!(
            w.verify(&seal_event(&e, &w.alice_agent), ev, "bob"),
            Error::Schema("not a routine ticket action")
        );
    }

    // Not delegated: the purpose must be listed explicitly.
    let narrow = seal_event(
        &w.delegation(&["action.execute", "agent.message"]),
        &w.alice,
    );
    let t2 = seal_event(&ticket_action(&w, &narrow), &w.alice_agent);
    assert_err!(
        w.verify(&t2, grant_evidence(&narrow), "bob"),
        Error::ScopeEscalation("purpose")
    );
    // No delegation at all.
    let mut e = ticket_action(&w, &delegation);
    e["session"] = json!(null);
    assert_err!(
        w.verify(&seal_event(&e, &w.alice_agent), none(), "bob"),
        Error::EvidenceRequired("delegation")
    );
    // Audience and group outside the delegation.
    let mut e = ticket_action(&w, &delegation);
    e["audience"] = json!(["alice-agent", "bob"]);
    assert_err!(
        w.verify(&seal_event(&e, &w.alice_agent), ev, "bob"),
        Error::ScopeEscalation("audience")
    );
    let mut e = ticket_action(&w, &delegation);
    e["group"] = json!("g1");
    assert_err!(
        w.verify_at(&seal_event(&e, &w.alice_agent), ev, "bob", Some("g1"), NOW),
        Error::ScopeEscalation("group")
    );
    // An authorization is not accepted as decoration.
    let a = action(&w);
    let authz = seal_event(&a.authorization, &w.alice);
    let both = Evidence {
        grant: Some(&delegation),
        authorization: Some(&authz),
        original_grant: None,
    };
    assert_err!(
        w.verify(&t, both, "bob"),
        Error::UnexpectedEvidence("authorization")
    );

    // Tampering with the bound request.
    let payload = serde_json::to_vec(&ticket_action(&w, &delegation)).unwrap();
    let entry = w.alice_agent.entry(EVENT_PAYLOAD_TYPE, &payload);
    let mut edited = ticket_action(&w, &delegation);
    edited["body"]["action"] = json!("ticket.cancel");
    let forged = Envelope::new(
        EVENT_PAYLOAD_TYPE,
        serde_json::to_vec(&edited).unwrap(),
        vec![entry],
    )
    .unwrap();
    assert_err!(w.verify(&forged.to_json(), ev, "bob"), Error::BadSignature);

    // Strict body: the removed fields and anything else are unknown.
    for (field, value) in [
        ("request_digest", json!("abc")),
        ("ticket", json!("T-12")),
        ("operation", json!("claim")),
        ("revision", json!(3)),
        ("force", json!(true)),
    ] {
        let mut e = ticket_action(&w, &delegation);
        e["body"][field] = value;
        assert_err!(
            w.verify(&seal_event(&e, &w.alice_agent), ev, "bob"),
            Error::Schema(_)
        );
    }

    // Agents only: not a human device key, a session key or a service; and
    // not another agent on this delegation.
    let mut e = ticket_action(&w, &delegation);
    e["author"] = json!("alice");
    e["key_id"] = json!(w.alice.id());
    e["session"] = json!(null);
    assert_err!(
        w.verify(&seal_event(&e, &w.alice), none(), "bob"),
        Error::KindNotPermitted("ticket.action")
    );
    let grant = seal_event(&w.session_grant(), &w.alice);
    e["key_id"] = json!(w.session.id());
    e["session"] = json!(digest_hex(&grant));
    assert_err!(
        w.verify(&seal_event(&e, &w.session), grant_evidence(&grant), "bob"),
        Error::KindNotPermitted("ticket.action")
    );
    let mut e = ticket_action(&w, &delegation);
    e["author"] = json!("ci");
    e["key_id"] = json!(w.ci.id());
    e["session"] = json!(null);
    assert_err!(
        w.verify(&seal_event(&e, &w.ci), none(), "bob"),
        Error::KindNotPermitted("ticket.action")
    );
    let mut e = ticket_action(&w, &delegation);
    e["author"] = json!("bob-agent");
    e["key_id"] = json!(w.bob_agent.id());
    assert_err!(
        w.verify(&seal_event(&e, &w.bob_agent), ev, "bob"),
        Error::EvidenceMismatch(_)
    );

    // Builder: round trip, and refusal of a non-routine action.
    let mut parsed =
        Event::parse(&serde_json::to_vec(&ticket_action(&w, &delegation)).unwrap()).unwrap();
    assert_eq!(parsed.kind(), Kind::TicketAction);
    assert_eq!(Event::parse(&parsed.to_payload().unwrap()).unwrap(), parsed);
    parsed.body = Body::TicketAction {
        action: "ticket.recover".into(),
        request_digest: Digest::of(b"r"),
    };
    assert_err!(
        parsed.to_payload(),
        Error::Schema("not a routine ticket action")
    );
}

#[test]
fn ticket_recover_is_privileged_and_needs_a_fresh_human_authorization() {
    let w = World::new();
    let mut a = action(&w);
    a.authorization["body"]["action"] = json!("ticket.recover");
    let authz = seal_event(&a.authorization, &w.alice);
    let mut e = execute(&w, &a, &authz);
    e["body"]["action"] = json!("ticket.recover");
    let v = run(&w, &a, &authz, &e).unwrap();
    assert_eq!(v.authorization().unwrap().signer(), SignerRole::HumanDevice);

    // Without the authorization, or with one for another action, it fails.
    let sealed = seal_event(&e, &w.alice_agent);
    assert_err!(
        w.verify_at(
            &sealed,
            grant_evidence(&a.delegation),
            "bob",
            Some("g1"),
            NOW
        ),
        Error::EvidenceRequired("authorization")
    );
    let other = action(&w);
    let other_authz = seal_event(&other.authorization, &w.alice);
    let mut e = execute(&w, &other, &other_authz);
    e["body"]["action"] = json!("ticket.recover");
    assert_err!(
        run(&w, &other, &other_authz, &e),
        Error::AuthorizationMismatch("action")
    );
}

// ------------------------------------------------------------ transport type

#[test]
fn transport_envelopes_parse_but_are_never_events_or_registries() {
    let w = World::new();
    let payload = br#"{"any":"transport record"}"#;
    let bytes = seal(TRANSPORT_PAYLOAD_TYPE, payload, &[&w.alice_agent]);
    let envelope = Envelope::parse(&bytes, TRANSPORT_PAYLOAD_TYPE).unwrap();
    assert_eq!(envelope.payload_type(), TRANSPORT_PAYLOAD_TYPE);
    assert_eq!(envelope.payload(), payload);
    assert_eq!(
        Envelope::parse(&envelope.to_json(), TRANSPORT_PAYLOAD_TYPE).unwrap(),
        envelope
    );
    // The signature is domain-separated from the event type by PAE.
    let sig = &envelope.signatures()[0];
    assert!(w
        .alice_agent
        .public()
        .verify(&envelope.signing_input(), &sig.signature)
        .is_ok());
    assert_err!(
        w.alice_agent
            .public()
            .verify(&pae(EVENT_PAYLOAD_TYPE, payload), &sig.signature),
        Error::BadSignature
    );

    // Callers expecting another type refuse it.
    assert_err!(
        Envelope::parse(&bytes, EVENT_PAYLOAD_TYPE),
        Error::UnsupportedPayloadType
    );
    assert_err!(
        Envelope::parse(&bytes, REGISTRY_PAYLOAD_TYPE),
        Error::UnsupportedPayloadType
    );
    // A valid event payload under the transport type is not an event.
    let event_payload = serde_json::to_vec(&w.statement()).unwrap();
    let as_transport = seal(TRANSPORT_PAYLOAD_TYPE, &event_payload, &[&w.alice]);
    assert_err!(
        w.verify(&as_transport, none(), "bob"),
        Error::UnsupportedPayloadType
    );
    // Nor a registry, even when signed by the authority.
    let registry_payload = serde_json::to_vec(&w.base_registry_json()).unwrap();
    let as_transport = seal(TRANSPORT_PAYLOAD_TYPE, &registry_payload, &[&w.authority]);
    assert_err!(
        verify_registry(&w, &as_transport, None),
        Error::UnsupportedPayloadType
    );
    // Nor evidence, nor a relayed original.
    let delegation = seal_event(&w.delegation(&["agent.message", "agent.relay"]), &w.alice);
    let m = seal_event(&w.agent_message(&delegation), &w.alice_agent);
    let delegation_payload = Envelope::parse(&delegation, EVENT_PAYLOAD_TYPE)
        .unwrap()
        .payload()
        .to_vec();
    let as_transport = seal(TRANSPORT_PAYLOAD_TYPE, &delegation_payload, &[&w.alice]);
    assert_err!(
        w.verify(&m, grant_evidence(&as_transport), "bob"),
        Error::UnsupportedPayloadType
    );
    let mut r = w.relay(&seal_event(&w.statement(), &w.alice), &delegation);
    r["body"]["original"]["payload_type"] = json!(TRANSPORT_PAYLOAD_TYPE);
    assert_err!(
        w.verify(
            &seal_event(&r, &w.alice_agent),
            grant_evidence(&delegation),
            "bob"
        ),
        Error::UnsupportedPayloadType
    );
    // Unknown types are still refused by the envelope layer itself.
    assert_err!(
        Envelope::new(
            "application/vnd.agent-yhes.other.v1+json",
            payload.to_vec(),
            vec![sig.clone()]
        ),
        Error::UnsupportedPayloadType
    );
}

// -------------------------------------------------------------- active_key

#[test]
fn active_key_binds_key_owner_validity_and_revocation() {
    let w = World::new();
    let agent_id = w.alice_agent.public().key_id();
    let key = w
        .registry
        .active_key("alice-agent", &agent_id, NOW)
        .unwrap();
    assert_eq!(key, w.alice_agent.public());
    assert_eq!(
        w.registry
            .active_key("alice", &w.alice.public().key_id(), NOW)
            .unwrap(),
        w.alice.public()
    );

    // Enrolled key, wrong owner (including the agent's own controller).
    assert_err!(
        w.registry.active_key("bob-agent", &agent_id, NOW),
        Error::AuthorMismatch
    );
    assert_err!(
        w.registry.active_key("alice", &agent_id, NOW),
        Error::AuthorMismatch
    );
    // Unknown participant or key; a session key is never an enrolled key.
    assert_err!(
        w.registry.active_key("mallory", &agent_id, NOW),
        Error::UnknownParticipant
    );
    assert_err!(
        w.registry
            .active_key("alice-agent", &Signer::ed(42).public().key_id(), NOW),
        Error::UnknownKey
    );
    assert_err!(
        w.registry
            .active_key("alice", &w.session.public().key_id(), NOW),
        Error::UnknownKey
    );
    // Key validity window (NOW-86400 ..= NOW+86400) and registry expiry.
    assert_err!(
        w.registry
            .active_key("alice-agent", &agent_id, NOW - 86_401),
        Error::KeyNotYetValid
    );
    assert!(w
        .registry
        .active_key("alice-agent", &agent_id, NOW + 86_400)
        .is_ok());
    assert_err!(
        w.registry
            .active_key("alice-agent", &agent_id, NOW + 86_401),
        Error::RegistryExpired
    );
    let short = Signer::ed(4).id();
    let w2 = World::with_registry(move |r| {
        for k in r["keys"].as_array_mut().unwrap() {
            if k["key_id"] == json!(short) {
                k["not_after"] = json!(NOW + 10);
            }
        }
    });
    assert!(w2
        .registry
        .active_key("alice-agent", &agent_id, NOW + 10)
        .is_ok());
    assert_err!(
        w2.registry.active_key("alice-agent", &agent_id, NOW + 11),
        Error::KeyExpired
    );

    // Revoked, whether or not the key is still listed.
    let w3 = World::with_registry(revoke(Signer::ed(4).id()));
    assert_err!(
        w3.registry.active_key("alice-agent", &agent_id, NOW),
        Error::KeyRevoked
    );
    let gone = Signer::ed(4).id();
    let w4 = World::with_registry(move |r| {
        r["keys"]
            .as_array_mut()
            .unwrap()
            .retain(|k| k["key_id"] != json!(gone));
        r["revocations"] = json!([{"key_id": gone, "revoked_at": NOW - 1}]);
    });
    assert_err!(
        w4.registry.active_key("alice-agent", &agent_id, NOW),
        Error::KeyRevoked
    );
}

#[test]
fn backdating_cannot_revive_an_expired_agent_delegation() {
    let w = World::new();
    let mut d = w.delegation(&["agent.message"]);
    d["issued_at"] = json!(NOW - 100);
    d["expires_at"] = json!(NOW - 1);
    let grant = seal_event(&d, &w.alice);
    let mut event = w.agent_message(&grant);
    event["issued_at"] = json!(NOW - 50);
    event["expires_at"] = json!(NOW + 600);
    assert_err!(
        w.verify(
            &seal_event(&event, &w.alice_agent),
            grant_evidence(&grant),
            "bob"
        ),
        Error::Expired
    );
}
