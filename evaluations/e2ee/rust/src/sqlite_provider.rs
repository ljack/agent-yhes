//! Native upstream SQLite-provider compatibility check with disposable keys.
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use std::path::Path;

#[derive(Default)]
struct JsonCodec;
impl Codec for JsonCodec {
    type Error = serde_json::Error;
    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }
    fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

struct Provider<'a> {
    crypto: RustCrypto,
    store: SqliteStorageProvider<JsonCodec, &'a Connection>,
}
impl<'a> Provider<'a> {
    fn new(connection: &'a Connection) -> Self {
        Self {
            crypto: RustCrypto::default(),
            store: SqliteStorageProvider::new(connection),
        }
    }
}
impl<'a> OpenMlsProvider for Provider<'a> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, &'a Connection>;
    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
    fn storage(&self) -> &Self::StorageProvider {
        &self.store
    }
}

fn connection(path: &Path) -> Connection {
    let mut connection = Connection::open(path).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .unwrap();
    SqliteStorageProvider::<JsonCodec, _>::new(&mut connection)
        .run_migrations()
        .unwrap();
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS application_outbox (id TEXT PRIMARY KEY, wire BLOB);
        CREATE TABLE IF NOT EXISTS application_inbox (id TEXT PRIMARY KEY, body BLOB);",
        )
        .unwrap();
    connection
}

// This private comparison is never printed. It includes all provider and app rows.
fn snapshot(connection: &Connection) -> Vec<(String, Vec<Vec<String>>)> {
    let mut query = connection.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap();
    let names: Vec<String> = query
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    names
        .into_iter()
        .map(|name| {
            let sql = format!("SELECT * FROM \"{}\"", name.replace('"', "\"\""));
            let mut query = connection.prepare(&sql).unwrap();
            let columns = query.column_count();
            let mut rows: Vec<Vec<String>> = query
                .query_map([], |row| {
                    Ok((0..columns)
                        .map(|i| format!("{:?}", row.get_ref(i).unwrap()))
                        .collect())
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            rows.sort();
            (name, rows)
        })
        .collect()
}

fn credential(name: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    }
}

fn welcome(bytes: &[u8]) -> Welcome {
    match MlsMessageIn::tls_deserialize_exact(bytes)
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("welcome expected"),
    }
}

fn run(root: &Path, suite: Ciphersuite, label: &str) {
    let a_path = root.join(format!("{label}-a.sqlite"));
    let b_path = root.join(format!("{label}-b.sqlite"));
    let a_db = connection(&a_path);
    let b_db = connection(&b_path);
    let a = Provider::new(&a_db);
    let b = Provider::new(&b_db);
    let sa = SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
    let sb = SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
    let package = KeyPackage::builder()
        .build(suite, &b, &sb, credential("bob", &sb))
        .unwrap();
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .use_ratchet_tree_extension(true)
        .build();
    let mut group_a = MlsGroup::new(&a, &sa, &config, credential("alice", &sa)).unwrap();
    let (_, invite, _) = group_a
        .add_members(&a, &sa, &[package.key_package().clone()])
        .unwrap();
    group_a.merge_pending_commit(&a).unwrap();
    let invite = invite.tls_serialize_detached().unwrap();
    let mut bad = invite.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let before = snapshot(&b_db);
    b_db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(
        StagedWelcome::new_from_welcome(&b, config.join_config(), welcome(&bad), None).is_err()
    );
    b_db.execute_batch("ROLLBACK").unwrap();
    assert!(
        snapshot(&b_db) == before,
        "failed join changed durable storage"
    );
    b_db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let group_b = StagedWelcome::new_from_welcome(&b, config.join_config(), welcome(&invite), None)
        .unwrap()
        .into_group(&b)
        .unwrap();
    b_db.execute(
        "INSERT INTO application_inbox VALUES ('joined',?)",
        (b"joined".as_slice(),),
    )
    .unwrap();
    b_db.execute_batch("COMMIT").unwrap();
    let id = group_b.group_id().clone();
    drop(group_b);

    let before = snapshot(&b_db);
    b_db.execute_batch("BEGIN IMMEDIATE").unwrap();
    {
        let mut group = MlsGroup::load(b.storage(), &id).unwrap().unwrap();
        let abandoned = group
            .create_message(&b, &sb, b"never published")
            .unwrap()
            .tls_serialize_detached()
            .unwrap();
        b_db.execute(
            "INSERT INTO application_outbox VALUES ('abandoned',?)",
            (&abandoned,),
        )
        .unwrap();
    }
    b_db.execute_batch("ROLLBACK").unwrap();
    assert!(
        snapshot(&b_db) == before,
        "failed send changed state or outbox"
    );

    b_db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let committed = {
        let mut group = MlsGroup::load(b.storage(), &id).unwrap().unwrap();
        group
            .create_message(&b, &sb, b"native atomic send")
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    };
    b_db.execute(
        "INSERT INTO application_outbox VALUES ('committed',?)",
        (&committed,),
    )
    .unwrap();
    b_db.execute_batch("COMMIT").unwrap();
    drop(b);
    drop(b_db);
    let b_db = connection(&b_path);
    let b = Provider::new(&b_db);
    assert!(MlsGroup::load(b.storage(), &id).unwrap().is_some());
    let restored: Vec<u8> = b_db
        .query_row(
            "SELECT wire FROM application_outbox WHERE id='committed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(restored == committed, "outbox bytes changed on reopen");
    a_db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let message = MlsMessageIn::tls_deserialize_exact(restored)
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let body = match group_a.process_message(&a, message).unwrap().into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
        _ => panic!("application message expected"),
    };
    assert_eq!(body, b"native atomic send");
    a_db.execute(
        "INSERT INTO application_inbox VALUES ('received',?)",
        (&body,),
    )
    .unwrap();
    a_db.execute_batch("COMMIT").unwrap();
    let sqlite_version: String = a_db
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .unwrap();
    println!(
        "{}",
        json!({"suite":label,"provider":"openmls_sqlite_storage 0.3.0","sqlite_version":sqlite_version,
        "checks":{"provider_and_application_share_transaction":true,"invalid_welcome_rolls_back":true,
        "valid_join_after_failed_attempt":true,"sender_state_and_outbox_rollback_together":true,
        "committed_state_and_ciphertext_survive_database_reopen":true,"receiver_state_and_payload_commit_together":true}})
    );
}

fn main() {
    let root_arg = std::env::args()
        .nth(1)
        .expect("disposable directory required");
    let root = Path::new(&root_arg);
    assert!(
        root.join("EXPERIMENT_ONLY").is_file(),
        "disposable fixture marker required"
    );
    run(
        root,
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        "ed25519",
    );
    run(
        root,
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        "p256",
    );
}
