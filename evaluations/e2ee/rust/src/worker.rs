//! Experiment-only private IPC worker. Its stdout contains disposable secret
//! state and MUST be captured by the SQLite adapter, never logged or published.
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};

#[derive(Serialize, Deserialize)]
struct State {
    name: String,
    suite: Ciphersuite,
    signer: SignatureKeyPair,
    group_id: Option<GroupId>,
    storage: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Deserialize)]
struct Request {
    state: Option<State>,
    operation: String,
    payload: Value,
}

fn error<E: std::fmt::Debug>(error: E) -> String {
    format!("{error:?}")
}

fn bytes(payload: &Value, field: &str) -> Result<Vec<u8>, String> {
    serde_json::from_value(payload.get(field).cloned().ok_or("missing bytes")?).map_err(error)
}

fn config(suite: Ciphersuite) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .use_ratchet_tree_extension(true)
        .build()
}

fn loaded(state: &State, provider: &OpenMlsRustCrypto) -> Result<MlsGroup, String> {
    MlsGroup::load(
        provider.storage(),
        state.group_id.as_ref().ok_or("not in a group")?,
    )
    .map_err(error)?
    .ok_or("missing group state".to_string())
}

fn summary(state: &State, provider: &OpenMlsRustCrypto) -> Result<Value, String> {
    if state.group_id.is_none() {
        return Ok(json!({"group_id":null,"epoch":null,"members":[],"pending":false}));
    }
    let group = loaded(state, provider)?;
    let members: Vec<_> = group.members().map(|member| {
        json!({"index":member.index.u32(), "label":String::from_utf8_lossy(member.credential.serialized_content())})
    }).collect();
    // Fixture-only exporter output travels to the parent through private IPC.
    // The parent compares it and publishes only a hash in experiment results.
    let convergence = group
        .export_secret(provider.crypto(), "yhes-experiment", b"convergence", 32)
        .map_err(error)?;
    Ok(
        json!({"group_id":group.group_id().as_slice(),"epoch":group.epoch().as_u64(),
        "members":members,"pending":group.pending_commit().is_some(),"convergence":convergence}),
    )
}

fn execute(request: Request) -> Result<Value, String> {
    let provider = OpenMlsRustCrypto::default();
    let mut state;
    let mut result;
    if request.operation == "init" {
        if request.state.is_some() {
            return Err("already initialized".into());
        }
        let name = request.payload["name"]
            .as_str()
            .ok_or("name required")?
            .to_string();
        let suite = if request.payload["suite"] == "p256" {
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        } else {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        };
        let signer = SignatureKeyPair::new(suite.signature_algorithm()).map_err(error)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let package = KeyPackage::builder()
            .build(suite, &provider, &signer, credential)
            .map_err(error)?;
        result = json!({"kind":"identity_fixture","key_package":package.key_package().tls_serialize_detached().map_err(error)?,
            "signing_key":signer.to_public_vec()});
        state = State {
            name,
            suite,
            signer,
            group_id: None,
            storage: vec![],
        };
    } else {
        state = request.state.ok_or("not initialized")?;
        *provider.storage().values.write().map_err(error)? = state.storage.into_iter().collect();
        state.storage = vec![];
        result = match request.operation.as_str() {
            "create" => {
                if state.group_id.is_some() {
                    return Err("already in a group".into());
                }
                let credential = CredentialWithKey {
                    credential: BasicCredential::new(state.name.as_bytes().to_vec()).into(),
                    signature_key: state.signer.to_public_vec().into(),
                };
                let group =
                    MlsGroup::new(&provider, &state.signer, &config(state.suite), credential)
                        .map_err(error)?;
                state.group_id = Some(group.group_id().clone());
                json!({"kind":"created"})
            }
            "prepare_send" => {
                let mut group = loaded(&state, &provider)?;
                if group.pending_commit().is_some() {
                    return Err("membership confirmation pending".into());
                }
                let payload = bytes(&request.payload, "body")?;
                let epoch = group.epoch().as_u64();
                let packet = group
                    .create_message(&provider, &state.signer, &payload)
                    .map_err(error)?;
                json!({"kind":"application","packet":packet.tls_serialize_detached().map_err(error)?,"base_epoch":epoch})
            }
            "prepare_add" => {
                let mut group = loaded(&state, &provider)?;
                if group.pending_commit().is_some() {
                    return Err("membership confirmation pending".into());
                }
                let package =
                    KeyPackageIn::tls_deserialize_exact(bytes(&request.payload, "key_package")?)
                        .map_err(error)?
                        .validate(provider.crypto(), ProtocolVersion::Mls10)
                        .map_err(error)?;
                let epoch = group.epoch().as_u64();
                let (commit, welcome, _) = group
                    .add_members(&provider, &state.signer, &[package])
                    .map_err(error)?;
                json!({"kind":"membership","packet":commit.tls_serialize_detached().map_err(error)?,
                    "welcome":welcome.tls_serialize_detached().map_err(error)?,"base_epoch":epoch})
            }
            "accept_own" => {
                let mut group = loaded(&state, &provider)?;
                if group.pending_commit().is_none() {
                    return Err("no membership commit pending".into());
                }
                group.merge_pending_commit(&provider).map_err(error)?;
                json!({"kind":"accepted"})
            }
            "discard_pending" => {
                let mut group = loaded(&state, &provider)?;
                group
                    .clear_pending_commit(provider.storage())
                    .map_err(error)?;
                json!({"kind":"discarded"})
            }
            "receive" => {
                let packet = bytes(&request.payload, "packet")?;
                let message = MlsMessageIn::tls_deserialize_exact(packet).map_err(error)?;
                if state.group_id.is_none() {
                    let welcome = match message.extract() {
                        MlsMessageBodyIn::Welcome(welcome) => welcome,
                        _ => return Err("a new participant needs a Welcome".into()),
                    };
                    let group = StagedWelcome::new_from_welcome(
                        &provider,
                        config(state.suite).join_config(),
                        welcome,
                        None,
                    )
                    .map_err(error)?
                    .into_group(&provider)
                    .map_err(error)?;
                    state.group_id = Some(group.group_id().clone());
                    json!({"kind":"joined"})
                } else {
                    let mut group = loaded(&state, &provider)?;
                    if group.pending_commit().is_some() {
                        return Err("resolve pending membership before receiving".into());
                    }
                    match group
                        .process_message(
                            &provider,
                            message.try_into_protocol_message().map_err(error)?,
                        )
                        .map_err(error)?
                        .into_content()
                    {
                        ProcessedMessageContent::ApplicationMessage(message) => {
                            json!({"kind":"application","body":message.into_bytes()})
                        }
                        ProcessedMessageContent::StagedCommitMessage(commit) => {
                            group
                                .merge_staged_commit(&provider, *commit)
                                .map_err(error)?;
                            json!({"kind":"membership"})
                        }
                        _ => return Err("unsupported message kind for this experiment".into()),
                    }
                }
            }
            "status" => json!({"kind":"status"}),
            _ => return Err("unknown operation".into()),
        };
    }
    result["group"] = summary(&state, &provider)?;
    state.storage = provider
        .storage()
        .values
        .read()
        .map_err(error)?
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    state.storage.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(json!({"state":state,"result":result}))
}

fn main() {
    let mut input = String::new();
    std::io::stdin()
        .take(16 * 1024 * 1024)
        .read_to_string(&mut input)
        .unwrap();
    let outcome = serde_json::from_str::<Request>(&input)
        .map_err(error)
        .and_then(execute);
    let response = match outcome {
        Ok(value) => value,
        Err(error) => json!({"error":error}),
    };
    std::io::stdout()
        .write_all(serde_json::to_string(&response).unwrap().as_bytes())
        .unwrap();
}
