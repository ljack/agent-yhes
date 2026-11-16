//! Disposable-key evaluation. Basic credentials here are labels, not human identity proof.
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

struct Party {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    package: KeyPackageBundle,
}

fn party(name: &str, suite: Ciphersuite) -> Party {
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let package = KeyPackage::builder()
        .build(suite, &provider, &signer, credential.clone())
        .unwrap();
    Party {
        provider,
        signer,
        credential,
        package,
    }
}

fn input(bytes: &[u8]) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .unwrap()
        .try_into_protocol_message()
        .unwrap()
}

fn read(group: &mut MlsGroup, party: &Party, bytes: &[u8]) -> Vec<u8> {
    match group
        .process_message(&party.provider, input(bytes))
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
        _ => panic!("expected application message"),
    }
}

fn merge(group: &mut MlsGroup, party: &Party, commit: &MlsMessageOut) {
    let bytes = commit.tls_serialize_detached().unwrap();
    match group
        .process_message(&party.provider, input(&bytes))
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            group.merge_staged_commit(&party.provider, *commit).unwrap()
        }
        _ => panic!("expected membership commit"),
    }
}

fn join(
    party: &Party,
    config: &MlsGroupCreateConfig,
    welcome: MlsMessageOut,
    tree: RatchetTreeIn,
) -> MlsGroup {
    let welcome =
        match MlsMessageIn::tls_deserialize_exact(welcome.tls_serialize_detached().unwrap())
            .unwrap()
            .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => panic!("expected welcome"),
        };
    StagedWelcome::new_from_welcome(&party.provider, config.join_config(), welcome, Some(tree))
        .unwrap()
        .into_group(&party.provider)
        .unwrap()
}

fn welcome_failure(suite: Ciphersuite) -> serde_json::Value {
    let a = party("welcome-creator", suite);
    let f = party("welcome-recipient", suite);
    let config = MlsGroupCreateConfig::builder().ciphersuite(suite).build();
    let mut group = MlsGroup::new(&a.provider, &a.signer, &config, a.credential.clone()).unwrap();
    let (_, welcome, _) = group
        .add_members(&a.provider, &a.signer, &[f.package.key_package().clone()])
        .unwrap();
    group.merge_pending_commit(&a.provider).unwrap();
    let original = welcome.tls_serialize_detached().unwrap();
    let decode = |bytes: &[u8]| match MlsMessageIn::tls_deserialize_exact(bytes)
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("expected welcome"),
    };
    let checkpoint = f.provider.storage().values.read().unwrap().clone();
    let mut tampered = original.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let error = StagedWelcome::new_from_welcome(
        &f.provider,
        config.join_config(),
        decode(&tampered),
        Some(group.export_ratchet_tree().into()),
    )
    .expect_err("tampered welcome must fail");
    let retry = StagedWelcome::new_from_welcome(
        &f.provider,
        config.join_config(),
        decode(&original),
        Some(group.export_ratchet_tree().into()),
    );
    let (safe, retry_error) = match retry {
        Ok(staged) => {
            staged.into_group(&f.provider).unwrap();
            (true, None)
        }
        Err(error) => (false, Some(format!("{error:?}"))),
    };
    if !safe {
        *f.provider.storage().values.write().unwrap() = checkpoint;
        StagedWelcome::new_from_welcome(
            &f.provider,
            config.join_config(),
            decode(&original),
            Some(group.export_ratchet_tree().into()),
        )
        .unwrap()
        .into_group(&f.provider)
        .unwrap();
    }
    serde_json::json!({"valid_welcome_after_invalid":safe,"invalid_welcome_error":format!("{error:?}"),
        "valid_retry_error":retry_error,"checkpoint_restore":if safe {"not_needed"} else {"verified"}})
}

fn run(suite: Ciphersuite) {
    let a = party("human-label-only", suite);
    let b = party("agent-b", suite);
    let c = party("agent-c", suite);
    let d = party("late-joiner", suite);
    let e = party("outsider", suite);
    let config = MlsGroupCreateConfig::builder().ciphersuite(suite).build();
    let mut ga = MlsGroup::new(&a.provider, &a.signer, &config, a.credential.clone()).unwrap();
    let (_, welcome, _) = ga
        .add_members(
            &a.provider,
            &a.signer,
            &[
                b.package.key_package().clone(),
                c.package.key_package().clone(),
            ],
        )
        .unwrap();
    ga.merge_pending_commit(&a.provider).unwrap();
    let mut gb = join(
        &b,
        &config,
        welcome.clone(),
        ga.export_ratchet_tree().into(),
    );
    let mut gc = join(&c, &config, welcome, ga.export_ratchet_tree().into());
    let mut ge = MlsGroup::new(&e.provider, &e.signer, &config, e.credential.clone()).unwrap();
    let old = ga
        .create_message(&a.provider, &a.signer, b"first-group-message")
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    assert_eq!(read(&mut gb, &b, &old), b"first-group-message");
    assert_eq!(read(&mut gc, &c, &old), b"first-group-message");
    assert!(ge.process_message(&e.provider, input(&old)).is_err());
    assert!(gb.process_message(&b.provider, input(&old)).is_err());

    let good = ga
        .create_message(&a.provider, &a.signer, b"integrity-check")
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(gb.process_message(&b.provider, input(&bad)).is_err());
    assert_eq!(read(&mut gb, &b, &good), b"integrity-check");

    let early = ga
        .create_message(&a.provider, &a.signer, b"early")
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let late = ga
        .create_message(&a.provider, &a.signer, b"late")
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    assert_eq!(read(&mut gb, &b, &late), b"late");
    assert_eq!(read(&mut gb, &b, &early), b"early");

    let (addition, welcome, _) = ga
        .add_members(&a.provider, &a.signer, &[d.package.key_package().clone()])
        .unwrap();
    ga.merge_pending_commit(&a.provider).unwrap();
    merge(&mut gb, &b, &addition);
    merge(&mut gc, &c, &addition);
    let mut gd = join(&d, &config, welcome, ga.export_ratchet_tree().into());
    assert!(gd.process_message(&d.provider, input(&old)).is_err());

    let removed_index = gc.own_leaf_index();
    let (removal, _, _) = ga
        .remove_members(&a.provider, &a.signer, &[removed_index])
        .unwrap();
    ga.merge_pending_commit(&a.provider).unwrap();
    merge(&mut gb, &b, &removal);
    merge(&mut gd, &d, &removal);
    // The removed member deliberately keeps its old state and ignores removal.
    let future = ga
        .create_message(&a.provider, &a.signer, b"after-removal")
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    assert!(gc.process_message(&c.provider, input(&future)).is_err());
    assert_eq!(read(&mut gb, &b, &future), b"after-removal");
    assert_eq!(read(&mut gd, &d, &future), b"after-removal");

    let id = gb.group_id().clone();
    drop(gb);
    let mut reloaded = MlsGroup::load(b.provider.storage(), &id).unwrap().unwrap();
    let next = ga
        .create_message(&a.provider, &a.signer, b"after-reload")
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    assert_eq!(read(&mut reloaded, &b, &next), b"after-reload");
    let welcome_check = welcome_failure(suite);
    println!(
        "{}",
        serde_json::json!({"implementation":"openmls", "version":"0.9.2", "suite":format!("{suite:?}"),
        "checks":{"multi_recipient":true,"outsider_rejected":true,"duplicate_rejected":true,
        "tamper_rejected_without_poisoning":true,"out_of_order":true,"late_joiner_cannot_read_past":true,
        "removed_member_cannot_read_future":true,"remaining_members_continue":true,"provider_state_reload":true},
        "welcome_observation":welcome_check,
        "identity":"unverified basic credentials; no GHE/Touch ID test"})
    );
}

fn main() {
    run(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    run(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256);
}
