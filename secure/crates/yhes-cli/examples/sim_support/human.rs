//! SIMULATION ONLY P-256 identity. No native signer is constructed or contacted.
use super::{
    config::Lab,
    fs::{self, rejected},
    review,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::{
    ecdsa::{signature::Signer as _, Signature, SigningKey},
    elliptic_curve::rand_core::OsRng,
};
use serde::{Deserialize, Serialize};
use yhes_cli::{
    signer::{Descriptor, Mode, Operation, Request, SignerClient},
    Clock, Failure, SystemClock,
};
use yhes_wire::{
    Algorithm, Envelope, PublicKey, SignatureEntry, EVENT_PAYLOAD_TYPE, REGISTRY_PAYLOAD_TYPE,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedKey {
    version: u8,
    simulation: bool,
    lab_root: std::path::PathBuf,
    project_path: std::path::PathBuf,
    role: String,
    project: String,
    author: String,
    secret: String,
}

pub struct Human {
    key: SigningKey,
    pub project: String,
    pub author: String,
    pub agent: String,
}
impl Human {
    pub fn open(lab: &Lab) -> Result<Self, Failure> {
        let path = lab.role_root.join("human.key");
        if !fs::exists(&path)? {
            let key = SigningKey::random(&mut OsRng);
            let mut secret = key.to_bytes();
            let mut saved = SavedKey {
                version: 1,
                simulation: true,
                lab_root: lab.node.lab_root.clone(),
                project_path: lab.node.project.clone(),
                role: lab.node.role.clone(),
                project: lab.node.project_id.clone(),
                author: lab.human.clone(),
                secret: STANDARD.encode(secret),
            };
            secret.fill(0);
            let mut bytes = serde_json::to_vec(&saved).map_err(|_| rejected())?;
            saved.secret.clear();
            let result = fs::add(&path, &bytes);
            bytes.fill(0);
            result?;
        }
        let mut bytes = fs::read(&path, 4096, true)?;
        let saved: SavedKey = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
        bytes.fill(0);
        if saved.version != 1
            || !saved.simulation
            || saved.lab_root != lab.node.lab_root
            || saved.project_path != lab.node.project
            || saved.role != lab.node.role
            || saved.project != lab.node.project_id
            || saved.author != lab.human
        {
            return Err(rejected());
        }
        let mut raw = STANDARD.decode(&saved.secret).map_err(|_| rejected())?;
        let key = SigningKey::from_slice(&raw).map_err(|_| rejected());
        raw.fill(0);
        Ok(Self {
            key: key?,
            project: saved.project,
            author: saved.author,
            agent: lab.agent.clone(),
        })
    }
    pub fn descriptor(&self) -> Result<Descriptor, Failure> {
        let key = PublicKey::new(
            Algorithm::P256Sha256,
            self.key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .map_err(|_| rejected())?;
        Ok(Descriptor {
            algorithm: key.algorithm().as_str().into(),
            key_id: key.key_id().to_string(),
            public_key: STANDARD.encode(key.as_bytes()),
            author: self.author.clone(),
            project: self.project.clone(),
        })
    }
    fn seal(&self, ty: &str, payload: &[u8]) -> Result<Vec<u8>, Failure> {
        let signature: Signature = self.key.sign(&yhes_wire::pae(ty, payload));
        let envelope = Envelope::new(
            ty,
            payload.to_vec(),
            vec![SignatureEntry {
                key_id: self.descriptor()?.key_id()?,
                algorithm: Algorithm::P256Sha256,
                signature: signature.to_bytes().into(),
            }],
        )
        .map_err(|_| rejected())?;
        Ok(envelope.to_json())
    }
}
impl SignerClient for Human {
    fn accepts(&self, algorithm: Algorithm) -> bool {
        algorithm == Algorithm::P256Sha256
    }
    fn probe(&self) -> Result<(), Failure> {
        Ok(())
    }
    fn exchange(&self, request: &Request) -> Result<Vec<u8>, Failure> {
        if request.author != self.author || request.project != self.project {
            return Err(rejected());
        }
        request.encode()?;
        let bytes = match request.operation {
            Operation::Identity | Operation::Enroll
                if request.mode.is_none()
                    && request.payloads.is_empty()
                    && request.request.is_none() =>
            {
                serde_json::to_vec(&self.descriptor()?).map_err(|_| rejected())?
            }
            Operation::Review => {
                let [payload] = request.payloads.as_slice() else {
                    return Err(rejected());
                };
                if payload.len() > 256 * 1024 {
                    return Err(rejected());
                }
                match request.mode {
                    Some(Mode::Event) => {
                        review::event(self, request, payload)?;
                        self.seal(EVENT_PAYLOAD_TYPE, payload)?
                    }
                    Some(Mode::Registry) if request.request.is_none() => {
                        review::registry(self, payload)?;
                        let sealed = self.seal(REGISTRY_PAYLOAD_TYPE, payload)?;
                        let anchors = yhes_wire::TrustAnchors::new(
                            &self.project,
                            vec![self.descriptor()?.key()?],
                            1,
                        )
                        .map_err(|_| rejected())?;
                        yhes_wire::Registry::verify(
                            &sealed,
                            &anchors,
                            None,
                            &yhes_wire::Policy::default(),
                            SystemClock.now(),
                        )
                        .map_err(|_| rejected())?;
                        sealed
                    }
                    _ => return Err(rejected()),
                }
            }
            _ => return Err(rejected()),
        };
        Ok(format!("{}\n", serde_json::json!({"version":1,"id":request.id,"status":"ok","result":STANDARD.encode(bytes),"error":null})).into_bytes())
    }
}
