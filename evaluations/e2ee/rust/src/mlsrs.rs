//! Disposable-key evaluation of the RFC group API with the OpenSSL provider.
use mls_rs::{
    client_builder::MlsConfig,
    group::{Group, ReceivedMessage},
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, MlsMessage,
};
use mls_rs_crypto_openssl::OpensslCryptoProvider;

fn client(name: &str, suite: CipherSuite) -> Client<impl MlsConfig> {
    let crypto = OpensslCryptoProvider::default();
    let (private, public) = crypto
        .cipher_suite_provider(suite)
        .unwrap()
        .signature_key_generate()
        .unwrap();
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .signing_identity(
            SigningIdentity::new(
                BasicCredential::new(name.as_bytes().to_vec()).into_credential(),
                public,
            ),
            private,
            suite,
        )
        .build()
}

#[track_caller]
fn read<C: MlsConfig>(group: &mut Group<C>, message: MlsMessage) -> Vec<u8> {
    match group.process_incoming_message(message).unwrap() {
        ReceivedMessage::ApplicationMessage(message) => message.data().to_vec(),
        _ => panic!("expected application message"),
    }
}

fn welcome_failure(suite: CipherSuite) -> serde_json::Value {
    let a = client("welcome-creator", suite);
    let f = client("welcome-recipient", suite);
    let mut group = a.group_builder().unwrap().build().unwrap();
    let kp = f
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let addition = group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();
    let original = addition.welcome_messages[0].clone();
    let mut bytes = original.to_bytes().unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let error = match MlsMessage::from_bytes(&bytes) {
        Ok(tampered) => match f.join_group(None, &tampered, None) {
            Err(error) => format!("{error:?}"),
            Ok(_) => panic!("tampered welcome must fail"),
        },
        Err(error) => format!("{error:?}"),
    };
    let (safe, retry_error) = match f.join_group(None, &original, None) {
        Ok(_) => (true, None),
        Err(error) => (false, Some(format!("{error:?}"))),
    };
    serde_json::json!({"valid_welcome_after_invalid":safe,"invalid_welcome_error":error,"valid_retry_error":retry_error})
}

fn run(suite: CipherSuite) {
    let a = client("human-label-only", suite);
    let b = client("agent-b", suite);
    let c = client("agent-c", suite);
    let d = client("late-joiner", suite);
    let e = client("outsider", suite);
    let mut ga = a.group_builder().unwrap().build().unwrap();
    let kp_b = b
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let kp_c = c
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let addition = ga
        .commit_builder()
        .add_member(kp_b)
        .unwrap()
        .add_member(kp_c)
        .unwrap()
        .build()
        .unwrap();
    ga.apply_pending_commit().unwrap();
    let (mut gb, _) = b
        .join_group(None, &addition.welcome_messages[0], None)
        .unwrap();
    let (mut gc, _) = c
        .join_group(None, &addition.welcome_messages[0], None)
        .unwrap();
    let mut ge = e.group_builder().unwrap().build().unwrap();
    let old = ga
        .encrypt_application_message(b"first-group-message", Default::default())
        .unwrap();
    assert_eq!(read(&mut gb, old.clone()), b"first-group-message");
    assert_eq!(read(&mut gc, old.clone()), b"first-group-message");
    assert!(ge.process_incoming_message(old.clone()).is_err());
    assert!(gb.process_incoming_message(old.clone()).is_err());

    let good = ga
        .encrypt_application_message(b"integrity-check", Default::default())
        .unwrap();
    gb.write_to_storage().unwrap();
    let checkpoint_id = gb.group_id().to_vec();
    let mut bad = good.to_bytes().unwrap();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let invalid_error = match MlsMessage::from_bytes(&bad) {
        Ok(message) => format!(
            "{:?}",
            gb.process_incoming_message(message)
                .expect_err("tampering must fail")
        ),
        Err(error) => format!("{error:?}"),
    };
    let after_invalid = gb.process_incoming_message(good.clone());
    let (state_safe, valid_retry_error) = match after_invalid {
        Ok(ReceivedMessage::ApplicationMessage(message)) => {
            (message.data() == b"integrity-check", None)
        }
        Err(error) => (false, Some(format!("{error:?}"))),
        _ => panic!("unexpected message kind"),
    };
    // Characterize the failure, then test an application-owned checkpoint restore.
    // Do not silently call the direct path a pass when rollback was required.
    gb = b.load_group(&checkpoint_id).unwrap();
    assert_eq!(read(&mut gb, good), b"integrity-check");
    let early = ga
        .encrypt_application_message(b"early", Default::default())
        .unwrap();
    let late = ga
        .encrypt_application_message(b"late", Default::default())
        .unwrap();
    assert_eq!(read(&mut gb, late), b"late");
    assert_eq!(read(&mut gb, early), b"early");

    let kp_d = d
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let add_d = ga
        .commit_builder()
        .add_member(kp_d)
        .unwrap()
        .build()
        .unwrap();
    ga.apply_pending_commit().unwrap();
    gb.process_incoming_message(add_d.commit_message.clone())
        .unwrap();
    gc.process_incoming_message(add_d.commit_message).unwrap();
    let (mut gd, _) = d
        .join_group(None, &add_d.welcome_messages[0], None)
        .unwrap();
    assert!(gd.process_incoming_message(old).is_err());

    let index = ga.member_with_identity(b"agent-c").unwrap().index;
    let removal = ga
        .commit_builder()
        .remove_member(index)
        .unwrap()
        .build()
        .unwrap();
    ga.apply_pending_commit().unwrap();
    gb.process_incoming_message(removal.commit_message.clone())
        .unwrap();
    gd.process_incoming_message(removal.commit_message).unwrap();
    let future = ga
        .encrypt_application_message(b"after-removal", Default::default())
        .unwrap();
    assert!(gc.process_incoming_message(future.clone()).is_err());
    assert_eq!(read(&mut gb, future.clone()), b"after-removal");
    assert_eq!(read(&mut gd, future), b"after-removal");

    gb.write_to_storage().unwrap();
    let id = gb.group_id().to_vec();
    drop(gb);
    let mut reloaded = b.load_group(&id).unwrap();
    let next = ga
        .encrypt_application_message(b"after-reload", Default::default())
        .unwrap();
    assert_eq!(read(&mut reloaded, next), b"after-reload");
    let welcome_check = welcome_failure(suite);
    println!(
        "{}",
        serde_json::json!({"implementation":"mls-rs", "version":"0.57.1", "provider":"OpenSSL 0.22.0", "suite":format!("{suite:?}"),
        "checks":{"multi_recipient":true,"outsider_rejected":true,"duplicate_rejected":true,
        "tamper_rejected_without_poisoning":state_safe,"out_of_order":true,"late_joiner_cannot_read_past":true,
        "removed_member_cannot_read_future":true,"remaining_members_continue":true,"provider_state_reload":true},
        "observations":{"invalid_message_error":invalid_error,"valid_retry_error":valid_retry_error,"application_checkpoint_restore_recovers":true},
        "welcome_observation":welcome_check,
        "identity":"unverified basic credentials; no GHE/Touch ID test"})
    );
}

fn main() {
    run(CipherSuite::CURVE25519_AES128);
    run(CipherSuite::P256_AES128);
}
