//! DSSE-style envelope with exact payload bytes.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::error::Error;
use crate::json::{self, Fields, Value};
use crate::keys::{Algorithm, Digest, KeyId};
use crate::{
    EVENT_PAYLOAD_TYPE, MAX_ENVELOPE_BYTES, MAX_SIGNATURES, REGISTRY_PAYLOAD_TYPE,
    TRANSPORT_PAYLOAD_TYPE,
};

/// DSSE v1 pre-authentication encoding: the bytes that are signed.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// One signature over the envelope's signing input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEntry {
    pub key_id: KeyId,
    pub algorithm: Algorithm,
    pub signature: [u8; 64],
}

/// A structurally valid envelope. Parsing establishes no trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    payload_type: String,
    payload: Vec<u8>,
    signatures: Vec<SignatureEntry>,
}

impl Envelope {
    /// Strictly parses envelope JSON and requires `expected_payload_type`.
    pub fn parse(bytes: &[u8], expected_payload_type: &str) -> Result<Envelope, Error> {
        let value = json::parse(bytes, MAX_ENVELOPE_BYTES)?;
        Envelope::from_value(value, expected_payload_type)
    }

    /// Assembles an envelope from payload bytes and signatures made elsewhere.
    pub fn new(
        payload_type: &str,
        payload: Vec<u8>,
        signatures: Vec<SignatureEntry>,
    ) -> Result<Envelope, Error> {
        let envelope = Envelope {
            payload_type: payload_type.to_owned(),
            payload,
            signatures,
        };
        envelope.check()?;
        if envelope.to_json().len() > MAX_ENVELOPE_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(envelope)
    }

    pub(crate) fn from_value(value: Value, expected: &str) -> Result<Envelope, Error> {
        let mut f = Fields::new(value)?;
        let payload_type = f.string("payload_type")?;
        let payload_b64 = f.string("payload")?;
        let entries = f.array("signatures")?;
        f.finish()?;

        if payload_type != expected {
            return Err(Error::UnsupportedPayloadType);
        }
        let payload = STANDARD
            .decode(payload_b64.as_bytes())
            .map_err(|_| Error::Malformed("payload is not canonical base64"))?;

        let mut signatures = Vec::with_capacity(entries.len().min(MAX_SIGNATURES));
        if entries.len() > MAX_SIGNATURES {
            return Err(Error::SignatureCount);
        }
        for entry in entries {
            let mut s = Fields::new(entry)?;
            let key_id = KeyId::parse(&s.string("key_id")?)?;
            let algorithm = Algorithm::parse(&s.string("algorithm")?)?;
            let sig_b64 = s.string("signature")?;
            s.finish()?;
            let sig = STANDARD
                .decode(sig_b64.as_bytes())
                .map_err(|_| Error::Malformed("signature is not canonical base64"))?;
            let signature: [u8; 64] = sig
                .try_into()
                .map_err(|_| Error::Malformed("signature is not 64 bytes"))?;
            signatures.push(SignatureEntry {
                key_id,
                algorithm,
                signature,
            });
        }
        let envelope = Envelope {
            payload_type,
            payload,
            signatures,
        };
        envelope.check()?;
        Ok(envelope)
    }

    fn check(&self) -> Result<(), Error> {
        let known = [
            EVENT_PAYLOAD_TYPE,
            REGISTRY_PAYLOAD_TYPE,
            TRANSPORT_PAYLOAD_TYPE,
        ];
        if !known.contains(&self.payload_type.as_str()) {
            return Err(Error::UnsupportedPayloadType);
        }
        if self.signatures.is_empty() || self.signatures.len() > MAX_SIGNATURES {
            return Err(Error::SignatureCount);
        }
        for (i, a) in self.signatures.iter().enumerate() {
            if self.signatures[..i].iter().any(|b| b.key_id == a.key_id) {
                return Err(Error::Schema("duplicate signature key id"));
            }
        }
        Ok(())
    }

    pub fn payload_type(&self) -> &str {
        &self.payload_type
    }

    /// The exact signed payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn signatures(&self) -> &[SignatureEntry] {
        &self.signatures
    }

    /// The DSSE signing input for this envelope.
    pub fn signing_input(&self) -> Vec<u8> {
        pae(&self.payload_type, &self.payload)
    }

    /// SHA-256 of the exact payload bytes.
    pub fn digest(&self) -> Digest {
        Digest::of(&self.payload)
    }

    /// Envelope JSON. The payload bytes are carried unchanged.
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(&self.to_json_value()).expect("serializing JSON values cannot fail")
    }

    pub(crate) fn to_json_value(&self) -> serde_json::Value {
        let signatures: Vec<serde_json::Value> = self
            .signatures
            .iter()
            .map(|s| {
                serde_json::json!({
                    "key_id": s.key_id.as_str(),
                    "algorithm": s.algorithm.as_str(),
                    "signature": STANDARD.encode(s.signature),
                })
            })
            .collect();
        serde_json::json!({
            "payload_type": self.payload_type,
            "payload": STANDARD.encode(&self.payload),
            "signatures": signatures,
        })
    }
}
