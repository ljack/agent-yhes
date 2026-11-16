use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use yhes_actions::{Action, Error, Parameters, Request};
use yhes_wire::{
    pae, Algorithm, AudienceCheck, Envelope, Evidence, Expectation, Policy, Registry,
    SignatureEntry, SignerRole, TrustAnchors, Verifier, EVENT_PAYLOAD_TYPE, REGISTRY_PAYLOAD_TYPE,
};

const NOW: u64 = 1_800_000_000;
const PROJECT: &str = "demo";

fn signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sign_envelope(payload_type: &str, payload: &[u8], key: &SigningKey) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let public =
        yhes_wire::PublicKey::new(Algorithm::Ed25519, &key.verifying_key().to_bytes()).unwrap();
    let signature = key.sign(&pae(payload_type, payload)).to_bytes();
    Envelope::new(
        payload_type,
        payload.to_vec(),
        vec![SignatureEntry {
            key_id: public.key_id(),
            algorithm: Algorithm::Ed25519,
            signature,
        }],
    )
    .unwrap()
    .to_json()
}

fn registry(alice: &SigningKey, authority: &SigningKey) -> (Registry, TrustAnchors) {
    let alice_public =
        yhes_wire::PublicKey::new(Algorithm::Ed25519, &alice.verifying_key().to_bytes()).unwrap();
    let authority_public =
        yhes_wire::PublicKey::new(Algorithm::Ed25519, &authority.verifying_key().to_bytes())
            .unwrap();
    let payload = json!({
        "version": 1,
        "project": PROJECT,
        "generation": 1,
        "previous": null,
        "issued_at": NOW - 3600,
        "expires_at": NOW + 86_400,
        "participants": [{
            "id": "alice",
            "kind": "human",
            "controller": null,
            "ghes": {"instance": "ghes.example.com", "user_id": 1001}
        }],
        "keys": [{
            "key_id": alice_public.key_id().as_str(),
            "participant": "alice",
            "algorithm": "ed25519",
            "public_key": STANDARD.encode(alice_public.as_bytes()),
            "not_before": NOW - 86_400,
            "not_after": NOW + 86_400
        }],
        "revocations": []
    });
    let payload = serde_json::to_vec(&payload).unwrap();
    let envelope = sign_envelope(REGISTRY_PAYLOAD_TYPE, &payload, authority);
    let anchors = TrustAnchors::new(PROJECT, vec![authority_public], 1).unwrap();
    let registry = Registry::verify(&envelope, &anchors, None, &Policy::default(), NOW).unwrap();
    (registry, anchors)
}

fn registry_with_agent(alice: &SigningKey, agent: &SigningKey, authority: &SigningKey) -> Registry {
    let alice_public =
        yhes_wire::PublicKey::new(Algorithm::Ed25519, &alice.verifying_key().to_bytes()).unwrap();
    let agent_public =
        yhes_wire::PublicKey::new(Algorithm::Ed25519, &agent.verifying_key().to_bytes()).unwrap();
    let authority_public =
        yhes_wire::PublicKey::new(Algorithm::Ed25519, &authority.verifying_key().to_bytes())
            .unwrap();
    let mut keys = vec![
        json!({
            "key_id": alice_public.key_id().as_str(),
            "participant": "alice",
            "algorithm": "ed25519",
            "public_key": STANDARD.encode(alice_public.as_bytes()),
            "not_before": NOW - 86_400,
            "not_after": NOW + 86_400
        }),
        json!({
            "key_id": agent_public.key_id().as_str(),
            "participant": "alice-agent",
            "algorithm": "ed25519",
            "public_key": STANDARD.encode(agent_public.as_bytes()),
            "not_before": NOW - 86_400,
            "not_after": NOW + 86_400
        }),
    ];
    keys.sort_by(|left, right| left["key_id"].as_str().cmp(&right["key_id"].as_str()));
    let payload = json!({
        "version": 1,
        "project": PROJECT,
        "generation": 1,
        "previous": null,
        "issued_at": NOW - 3600,
        "expires_at": NOW + 86_400,
        "participants": [
            {
                "id": "alice",
                "kind": "human",
                "controller": null,
                "ghes": {"instance": "ghes.example.com", "user_id": 1001}
            },
            {
                "id": "alice-agent",
                "kind": "agent",
                "controller": "alice",
                "ghes": null
            }
        ],
        "keys": keys,
        "revocations": []
    });
    let envelope = sign_envelope(
        REGISTRY_PAYLOAD_TYPE,
        &serde_json::to_vec(&payload).unwrap(),
        authority,
    );
    let anchors = TrustAnchors::new(PROJECT, vec![authority_public], 1).unwrap();
    Registry::verify(&envelope, &anchors, None, &Policy::default(), NOW).unwrap()
}

fn event(
    kind: &str,
    key: &SigningKey,
    body: Value,
    audience: Value,
    group: &str,
    epoch: u64,
    id: &str,
) -> Vec<u8> {
    let public =
        yhes_wire::PublicKey::new(Algorithm::Ed25519, &key.verifying_key().to_bytes()).unwrap();
    let payload = json!({
        "version": 1,
        "id": id,
        "project": PROJECT,
        "kind": kind,
        "author": "alice",
        "key_id": public.key_id().as_str(),
        "session": null,
        "issued_at": NOW - 10,
        "expires_at": if kind == "action.authorization" { NOW + 290 } else { NOW + 600 },
        "audience": audience,
        "group": group,
        "epoch": epoch,
        "previous": null,
        "body": body
    });
    sign_envelope(
        EVENT_PAYLOAD_TYPE,
        &serde_json::to_vec(&payload).unwrap(),
        key,
    )
}

fn verified_action_execute(request: &Request, when: u64) -> yhes_wire::VerifiedEvent {
    let alice = signer(2);
    let authority = signer(1);
    let (registry, _anchors) = registry(&alice, &authority);
    let authorization = event(
        "action.authorization",
        &alice,
        json!({
            "action": request.action().as_str(),
            "request_digest": request.digest().to_hex(),
            "performer": request.performer()
        }),
        json!(request.audience()),
        request.group(),
        request.epoch(),
        "auth-1",
    );
    let authorization_digest = yhes_wire::Envelope::parse(&authorization, EVENT_PAYLOAD_TYPE)
        .unwrap()
        .digest();
    let execute = event(
        "action.execute",
        &alice,
        json!({
            "action": request.action().as_str(),
            "request_digest": request.digest().to_hex(),
            "authorization": authorization_digest.to_hex()
        }),
        json!(request.audience()),
        request.group(),
        request.epoch(),
        "exec-1",
    );
    Verifier::new(&registry, Policy::default())
        .verify_event(
            &execute,
            &Evidence {
                authorization: Some(&authorization),
                ..Evidence::default()
            },
            &Expectation {
                project: PROJECT,
                audience: AudienceCheck::Includes(&request.audience()[0]),
                group: Some(request.group()),
            },
            when,
        )
        .unwrap()
}

fn verified_group_create(request: &Request, when: u64) -> yhes_wire::VerifiedEvent {
    verified_action_execute(request, when)
}

fn verified_ticket_claim(request: &Request, when: u64) -> yhes_wire::VerifiedEvent {
    let alice = signer(2);
    let agent = signer(3);
    let authority = signer(1);
    let registry = registry_with_agent(&alice, &agent, &authority);
    let alice_public =
        yhes_wire::PublicKey::new(Algorithm::Ed25519, &alice.verifying_key().to_bytes()).unwrap();
    let agent_public =
        yhes_wire::PublicKey::new(Algorithm::Ed25519, &agent.verifying_key().to_bytes()).unwrap();

    let delegation_payload = json!({
        "version": 1,
        "id": "delegation-1",
        "project": PROJECT,
        "kind": "agent.delegation",
        "author": "alice",
        "key_id": alice_public.key_id().as_str(),
        "session": null,
        "issued_at": NOW - 60,
        "expires_at": NOW + 3600,
        "audience": ["alice-agent"],
        "group": "team",
        "epoch": 2,
        "previous": null,
        "body": {
            "agent": "alice-agent",
            "agent_key_id": agent_public.key_id().as_str(),
            "purposes": ["ticket.action"]
        }
    });
    let delegation = sign_envelope(
        EVENT_PAYLOAD_TYPE,
        &serde_json::to_vec(&delegation_payload).unwrap(),
        &alice,
    );
    let delegation_digest = yhes_wire::Envelope::parse(&delegation, EVENT_PAYLOAD_TYPE)
        .unwrap()
        .digest();
    let ticket_payload = json!({
        "version": 1,
        "id": "ticket-action-1",
        "project": PROJECT,
        "kind": "ticket.action",
        "author": "alice-agent",
        "key_id": agent_public.key_id().as_str(),
        "session": delegation_digest.to_hex(),
        "issued_at": NOW - 10,
        "expires_at": NOW + 600,
        "audience": ["alice-agent"],
        "group": "team",
        "epoch": 2,
        "previous": null,
        "body": {
            "action": "ticket.claim",
            "request_digest": request.digest().to_hex()
        }
    });
    let ticket_event = sign_envelope(
        EVENT_PAYLOAD_TYPE,
        &serde_json::to_vec(&ticket_payload).unwrap(),
        &agent,
    );
    Verifier::new(&registry, Policy::default())
        .verify_event(
            &ticket_event,
            &Evidence {
                grant: Some(&delegation),
                ..Evidence::default()
            },
            &Expectation {
                project: PROJECT,
                audience: AudienceCheck::Includes("alice-agent"),
                group: Some("team"),
            },
            when,
        )
        .unwrap()
}

fn valid_ticket_claim() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "version": 1,
        "project": "demo",
        "action": "ticket.claim",
        "performer": "alice-agent",
        "group": "team",
        "epoch": 2,
        "audience": ["alice-agent"],
        "parameters": {
            "ticket": "ticket-7",
            "expected_revision": 9
        }
    }))
    .unwrap()
}

fn valid_group_create() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "version": 1,
        "project": "demo",
        "action": "group.create",
        "performer": "alice",
        "group": "new-group",
        "epoch": 0,
        "audience": ["alice"],
        "parameters": {}
    }))
    .unwrap()
}

#[test]
fn parses_and_hashes_exact_typed_request_bytes() {
    let bytes = valid_group_create();
    let request = Request::parse(&bytes).unwrap();
    assert_eq!(request.action(), Action::GroupCreate);
    assert_eq!(request.project(), PROJECT);
    assert_eq!(request.performer(), "alice");
    assert_eq!(request.group(), "new-group");
    assert_eq!(request.epoch(), 0);
    assert_eq!(request.audience(), ["alice"]);
    assert_eq!(request.parameters(), &Parameters::GroupCreate {});
    assert_eq!(request.digest(), yhes_wire::Digest::of(&bytes));

    let spaced = format!(" {}\n", String::from_utf8(bytes.clone()).unwrap());
    assert_ne!(
        Request::parse(spaced.as_bytes()).unwrap().digest(),
        request.digest()
    );
}

#[test]
fn rejects_unknown_actions_fields_duplicates_and_oversized_input() {
    let valid = String::from_utf8(valid_group_create()).unwrap();
    for malformed in [
        valid.replace("group.create", "shell.exec"),
        valid.replace("\"parameters\":{}", "\"parameters\":{\"command\":\"id\"}"),
        valid.replace(
            "\"parameters\":{}",
            "\"parameters\":{\"member\":\"one\",\"member\":\"two\"}",
        ),
        valid.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
        valid.replace(
            "\"project\":\"demo\"",
            "\"project\":\"demo\",\"extra\":true",
        ),
    ] {
        assert!(Request::parse(malformed.as_bytes()).is_err());
    }

    let too_large = vec![b' '; yhes_actions::MAX_REQUEST_BYTES + 1];
    assert_eq!(Request::parse(&too_large), Err(Error::TooLarge));
}

#[test]
fn enforces_sorted_audience_and_create_scope() {
    let valid = String::from_utf8(valid_group_create()).unwrap();
    let unsorted = valid.replace("[\"alice\"]", "[\"bob\",\"alice\"]");
    assert!(matches!(
        Request::parse(unsorted.as_bytes()),
        Err(Error::Schema("audience must be sorted and unique"))
    ));

    let wrong_audience = valid.replace("[\"alice\"]", "[\"bob\"]");
    assert!(Request::parse(wrong_audience.as_bytes()).is_err());

    let wrong_epoch = valid.replace("\"epoch\":0", "\"epoch\":1");
    assert!(Request::parse(wrong_epoch.as_bytes()).is_err());
}

#[test]
fn parses_action_specific_ticket_and_membership_parameters() {
    let base = json!({
        "version": 1,
        "project": "demo",
        "performer": "alice",
        "group": "team",
        "epoch": 2,
        "audience": ["alice", "bob"]
    });
    let mut group_add = base.clone();
    group_add["action"] = json!("group.add");
    group_add["parameters"] = json!({
        "member": "new-agent",
        "key_id": format!("k_{}", "a".repeat(64)),
        "key_package_digest": "b".repeat(64)
    });
    assert!(matches!(
        Request::parse(&serde_json::to_vec(&group_add).unwrap())
            .unwrap()
            .parameters(),
        Parameters::GroupAdd { .. }
    ));

    let mut recover = base.clone();
    recover["action"] = json!("ticket.recover");
    recover["parameters"] = json!({
        "ticket": "ticket-7",
        "expected_revision": 0,
        "stop_evidence": "Supervisor confirmed agent process stopped; evidence record stop-7"
    });
    assert!(matches!(
        Request::parse(&serde_json::to_vec(&recover).unwrap())
            .unwrap()
            .parameters(),
        Parameters::TicketRecover {
            expected_revision: 0,
            ..
        }
    ));

    recover["parameters"]["stop_evidence"] = json!("  ");
    assert!(Request::parse(&serde_json::to_vec(&recover).unwrap()).is_err());
    recover["parameters"]["stop_evidence"] = json!("x".repeat(4097));
    assert!(Request::parse(&serde_json::to_vec(&recover).unwrap()).is_err());

    let mut claim = base.clone();
    claim["action"] = json!("ticket.claim");
    claim["parameters"] = json!({"ticket": "ticket-7", "expected_revision": 0});
    assert!(matches!(
        Request::parse(&serde_json::to_vec(&claim).unwrap())
            .unwrap()
            .parameters(),
        Parameters::TicketClaim {
            expected_revision: 0,
            ..
        }
    ));

    let mut create = base.clone();
    create["action"] = json!("ticket.create");
    create["parameters"] = json!({"title": "New task", "description": "Typed request"});
    assert!(matches!(
        Request::parse(&serde_json::to_vec(&create).unwrap())
            .unwrap()
            .parameters(),
        Parameters::TicketCreate { .. }
    ));

    let mut update = base;
    update["action"] = json!("ticket.update");
    update["parameters"] = json!({
        "ticket": "ticket-7",
        "expected_revision": 9,
        "description": "Revised details"
    });
    assert!(matches!(
        Request::parse(&serde_json::to_vec(&update).unwrap())
            .unwrap()
            .parameters(),
        Parameters::TicketUpdate {
            title: None,
            description: Some(_),
            ..
        }
    ));

    update["parameters"] = json!({
        "ticket": "ticket-7",
        "expected_revision": 9,
        "title": null
    });
    assert!(Request::parse(&serde_json::to_vec(&update).unwrap()).is_err());
    update["parameters"] = json!({"ticket": "ticket-7", "expected_revision": 9});
    assert!(Request::parse(&serde_json::to_vec(&update).unwrap()).is_err());
}

#[test]
fn binds_privileged_execution_to_exact_request_and_current_authorization() {
    let bytes = valid_group_create();
    let request = Request::parse(&bytes).unwrap();
    let verified = verified_group_create(&request, NOW);
    assert_eq!(verified.signer(), SignerRole::HumanDevice);
    request.verify_binding(&verified, NOW).unwrap();

    let later = NOW + 291;
    assert_eq!(
        request.verify_binding(&verified, later),
        Err(Error::AuthorizationExpired)
    );

    let different_bytes = format!(" {}\n", String::from_utf8(bytes).unwrap());
    let different_request = Request::parse(different_bytes.as_bytes()).unwrap();
    assert!(matches!(
        different_request.verify_binding(&verified, NOW),
        Err(Error::BindingMismatch("request digest"))
    ));
}

#[test]
fn binds_delegated_ticket_action_to_exact_request_without_human_authorization() {
    let bytes = valid_ticket_claim();
    let request = Request::parse(&bytes).unwrap();
    let verified = verified_ticket_claim(&request, NOW);
    assert_eq!(verified.signer(), SignerRole::Agent);
    request.verify_binding(&verified, NOW).unwrap();

    let different_bytes = format!(" {}\n", String::from_utf8(bytes).unwrap());
    let different_request = Request::parse(different_bytes.as_bytes()).unwrap();
    assert!(matches!(
        different_request.verify_binding(&verified, NOW),
        Err(Error::BindingMismatch("request digest"))
    ));
    let wrong_action_json = String::from_utf8(valid_ticket_claim())
        .unwrap()
        .replace("ticket.claim", "ticket.release");
    let wrong_action = Request::parse(wrong_action_json.as_bytes()).unwrap();
    assert!(matches!(
        wrong_action.verify_binding(&verified, NOW),
        Err(Error::BindingMismatch("action"))
    ));
    for (field, changed, expected) in [
        ("project", "other-project", "project"),
        ("performer", "bob", "performer"),
        ("group", "other-group", "group"),
    ] {
        let changed_json = String::from_utf8(valid_ticket_claim()).unwrap().replace(
            &format!(
                "\"{field}\":\"{}\"",
                match field {
                    "project" => "demo",
                    "performer" => "alice-agent",
                    _ => "team",
                }
            ),
            &format!("\"{field}\":\"{changed}\""),
        );
        let changed_request = Request::parse(changed_json.as_bytes()).unwrap();
        assert!(matches!(
            changed_request.verify_binding(&verified, NOW),
            Err(Error::BindingMismatch(actual)) if actual == expected
        ));
    }
    let changed_audience_json = String::from_utf8(valid_ticket_claim())
        .unwrap()
        .replace("[\"alice-agent\"]", "[\"alice-agent\",\"bob\"]");
    let changed_audience = Request::parse(changed_audience_json.as_bytes()).unwrap();
    assert!(matches!(
        changed_audience.verify_binding(&verified, NOW),
        Err(Error::BindingMismatch("audience"))
    ));
    let changed_epoch_json = String::from_utf8(valid_ticket_claim())
        .unwrap()
        .replace("\"epoch\":2", "\"epoch\":3");
    let changed_epoch = Request::parse(changed_epoch_json.as_bytes()).unwrap();
    assert!(matches!(
        changed_epoch.verify_binding(&verified, NOW),
        Err(Error::BindingMismatch("epoch"))
    ));
    assert_eq!(
        request.verify_binding(&verified, NOW + 601),
        Err(Error::BindingMismatch("event is not current"))
    );
}

#[test]
fn routine_ticket_action_must_use_delegated_ticket_action_event_kind() {
    let human_routine_request = String::from_utf8(valid_ticket_claim())
        .unwrap()
        .replace("alice-agent", "alice");
    let request = Request::parse(human_routine_request.as_bytes()).unwrap();
    let verified = verified_action_execute(&request, NOW);
    assert!(matches!(
        request.verify_binding(&verified, NOW),
        Err(Error::BindingMismatch("event kind"))
    ));
}

#[test]
fn refuses_action_execute_when_request_action_scope_or_authorization_differs() {
    let request = Request::parse(&valid_group_create()).unwrap();
    let verified = verified_group_create(&request, NOW);
    let wrong_project = Request::parse(
        &String::from_utf8(valid_group_create())
            .unwrap()
            .replace("\"project\":\"demo\"", "\"project\":\"other-project\"")
            .into_bytes(),
    )
    .unwrap();
    assert!(matches!(
        wrong_project.verify_binding(&verified, NOW),
        Err(Error::BindingMismatch("project"))
    ));
    let wrong_performer = Request::parse(
        &String::from_utf8(valid_group_create())
            .unwrap()
            .replace("\"performer\":\"alice\"", "\"performer\":\"agent\"")
            .replace("[\"alice\"]", "[\"agent\"]")
            .into_bytes(),
    )
    .unwrap();
    assert!(matches!(
        wrong_performer.verify_binding(&verified, NOW),
        Err(Error::BindingMismatch("performer"))
    ));
    let wrong_action_json = String::from_utf8(valid_group_create())
        .unwrap()
        .replace("group.create", "group.remove")
        .replace("\"parameters\":{}", "\"parameters\":{\"member\":\"bob\"}");
    let wrong_action = Request::parse(wrong_action_json.as_bytes()).unwrap();
    assert!(matches!(
        wrong_action.verify_binding(&verified, NOW),
        Err(Error::BindingMismatch("action"))
    ));
    let wrong_group_json = String::from_utf8(valid_group_create())
        .unwrap()
        .replace("new-group", "other-group");
    let wrong_group = Request::parse(wrong_group_json.as_bytes()).unwrap();
    assert!(matches!(
        wrong_group.verify_binding(&verified, NOW),
        Err(Error::BindingMismatch("group"))
    ));
}

#[test]
fn rejects_deep_json_before_typed_deserialization() {
    let mut bytes = String::from("{\"version\":1,\"project\":\"demo\",\"action\":\"group.create\",\"performer\":\"alice\",\"group\":\"g\",\"epoch\":0,\"audience\":[\"alice\"],\"parameters\":");
    bytes.push_str(&"[".repeat(9));
    bytes.push('0');
    bytes.push_str(&"]".repeat(9));
    bytes.push('}');
    assert_eq!(Request::parse(bytes.as_bytes()), Err(Error::TooLarge));
}
