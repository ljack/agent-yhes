//! Public transport bytes. Network acceptance does not confer application trust.
use crate::{trust::wire, Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use yhes_wire::{
    Algorithm, Digest, Envelope, KeyId, ParticipantKind, PublicKey, Registry, SignatureEntry,
};

pub(crate) const TRANSPORT_TYPE: &str = "application/vnd.agent-yhes.transport.v1+json";
pub(crate) const MAX_PACKET: usize = 1 << 20;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedContent {
    /// Exact JSON envelope bytes represented as a UTF-8 string.
    pub event: String,
    pub grant: Option<String>,
    pub authorization: Option<String>,
    pub original_grant: Option<String>,
}
impl SignedContent {
    pub(crate) fn evidence(&self) -> yhes_wire::Evidence<'_> {
        yhes_wire::Evidence {
            grant: self.grant.as_deref().map(str::as_bytes),
            authorization: self.authorization.as_deref().map(str::as_bytes),
            original_grant: self.original_grant.as_deref().map(str::as_bytes),
        }
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| Error::Storage)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub content: SignedContent,
    /// Exact, human-reviewed typed request JSON.
    pub request: String,
    /// Public MLS KeyPackage, only for group.add.
    pub key_package: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    pub version: u8,
    pub project: String,
    pub operation: String,
    pub sender: String,
    pub key_id: String,
    pub group: String,
    /// Base MLS epoch; membership changes advance this by one.
    pub epoch: u64,
    pub previous: Option<String>,
    pub kind: String,
    pub audience: Vec<String>,
    pub next_audience: Option<Vec<String>>,
    pub registry: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub ciphertext_digest: String,
    pub welcome_digest: Option<String>,
    pub control: Option<Control>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedPacket {
    version: u8,
    header: String,
    ciphertext: String,
    welcome: Option<String>,
}

pub(crate) struct Packet {
    pub header: Header,
    pub ciphertext: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
}

pub(crate) fn id(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 128
        || !s.as_bytes()[0].is_ascii_alphanumeric()
        || s.contains("..")
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
    {
        return Err(Error::Invalid("invalid identifier".into()));
    }
    Ok(())
}
fn audience(a: &[String]) -> Result<()> {
    if a.is_empty() || a.len() > 256 || a.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Error::Verification("invalid audience".into()));
    }
    for s in a {
        id(s)?;
    }
    Ok(())
}
impl Header {
    fn validate(&self, project: &str, now: u64) -> Result<()> {
        if self.version != 1
            || self.project != project
            || self.expires_at < now
            || self.issued_at > now.saturating_add(120)
            || self.expires_at < self.issued_at
            || self.expires_at - self.issued_at > 7 * 86400
            || self.epoch > i64::MAX as u64
        {
            return Err(Error::Verification(
                "transport scope or time mismatch".into(),
            ));
        }
        for s in [&self.project, &self.operation, &self.sender, &self.group] {
            id(s)?;
        }
        audience(&self.audience)?;
        if let Some(next) = &self.next_audience {
            audience(next)?;
        }
        Digest::from_hex(&self.registry).map_err(wire)?;
        if let Some(previous) = &self.previous {
            Digest::from_hex(previous).map_err(wire)?;
        }
        let valid = match self.kind.as_str() {
            "application" => {
                self.control.is_none()
                    && self.next_audience.is_none()
                    && self.welcome_digest.is_none()
            }
            "genesis" => {
                self.control.is_some()
                    && self.epoch == 0
                    && self.next_audience.is_none()
                    && self.welcome_digest.is_none()
            }
            "commit" => self.control.is_some() && self.next_audience.is_some(),
            _ => false,
        };
        if !valid {
            return Err(Error::Verification("unsupported transport kind".into()));
        }
        Ok(())
    }
}

/// Structural metadata only. The caller must already hold a protected acceptance
/// record for these exact bytes, or treat every field as untrusted data.
pub(crate) fn unverified_header(bytes: &[u8]) -> Result<Header> {
    if bytes.len() > MAX_PACKET {
        return Err(Error::Invalid("packet too large".into()));
    }
    let p: EncodedPacket = serde_json::from_slice(bytes)
        .map_err(|_| Error::Invalid("malformed sealed packet".into()))?;
    if p.version != 1 {
        return Err(Error::Invalid("unsupported sealed packet version".into()));
    }
    let raw = STANDARD
        .decode(p.header)
        .map_err(|_| Error::Invalid("invalid encoding".into()))?;
    let envelope = Envelope::parse(&raw, TRANSPORT_TYPE).map_err(wire)?;
    serde_json::from_slice(envelope.payload())
        .map_err(|_| Error::Invalid("malformed transport header".into()))
}

pub(crate) fn encode(
    header: Header,
    ciphertext: Vec<u8>,
    welcome: Option<Vec<u8>>,
    public: &PublicKey,
    sign: impl FnOnce(&[u8]) -> Result<[u8; 64]>,
) -> Result<Vec<u8>> {
    if header.key_id != public.key_id().as_str()
        || header.ciphertext_digest != Digest::of(&ciphertext).to_hex()
        || header.welcome_digest != welcome.as_ref().map(|w| Digest::of(w).to_hex())
    {
        return Err(Error::Verification("packet assembly mismatch".into()));
    }
    let payload = serde_json::to_vec(&header).map_err(|_| Error::Storage)?;
    let signature = sign(&payload)?;
    let envelope = Envelope::new(
        TRANSPORT_TYPE,
        payload,
        vec![SignatureEntry {
            key_id: public.key_id(),
            algorithm: public.algorithm(),
            signature,
        }],
    )
    .map_err(wire)?;
    let packet = EncodedPacket {
        version: 1,
        header: STANDARD.encode(envelope.to_json()),
        ciphertext: STANDARD.encode(ciphertext),
        welcome: welcome.map(|w| STANDARD.encode(w)),
    };
    let bytes = serde_json::to_vec(&packet).map_err(|_| Error::Storage)?;
    if bytes.len() > MAX_PACKET {
        return Err(Error::Invalid("packet too large".into()));
    }
    Ok(bytes)
}

pub(crate) fn decode(bytes: &[u8], registry: &Registry, now: u64) -> Result<Packet> {
    if bytes.len() > MAX_PACKET {
        return Err(Error::Invalid("packet too large".into()));
    }
    let p: EncodedPacket = serde_json::from_slice(bytes)
        .map_err(|_| Error::Invalid("malformed sealed packet".into()))?;
    if p.version != 1 {
        return Err(Error::Invalid("unsupported sealed packet version".into()));
    }
    let raw = STANDARD
        .decode(&p.header)
        .map_err(|_| Error::Invalid("invalid encoding".into()))?;
    let envelope = Envelope::parse(&raw, TRANSPORT_TYPE).map_err(wire)?;
    let header: Header = serde_json::from_slice(envelope.payload())
        .map_err(|_| Error::Invalid("malformed transport header".into()))?;
    header.validate(registry.project(), now)?;
    let key_id = KeyId::parse(&header.key_id).map_err(wire)?;
    let key = registry
        .active_key(&header.sender, &key_id, now)
        .map_err(wire)?;
    if registry
        .participant(&header.sender)
        .is_none_or(|p| p.kind != ParticipantKind::Agent)
    {
        return Err(Error::Verification(
            "transport sender must be an enrolled agent".into(),
        ));
    }
    let [sig] = envelope.signatures() else {
        return Err(Error::Verification("transport needs one signature".into()));
    };
    if sig.key_id != key_id
        || sig.algorithm != Algorithm::Ed25519
        || key.algorithm() != sig.algorithm
    {
        return Err(Error::Verification("transport key mismatch".into()));
    }
    key.verify(&envelope.signing_input(), &sig.signature)
        .map_err(wire)?;
    let ciphertext = STANDARD
        .decode(&p.ciphertext)
        .map_err(|_| Error::Invalid("invalid encoding".into()))?;
    let welcome = p
        .welcome
        .map(|w| STANDARD.decode(w))
        .transpose()
        .map_err(|_| Error::Invalid("invalid encoding".into()))?;
    if header.ciphertext_digest != Digest::of(&ciphertext).to_hex()
        || header.welcome_digest != welcome.as_ref().map(|w| Digest::of(w).to_hex())
    {
        return Err(Error::Verification("sealed content digest mismatch".into()));
    }
    Ok(Packet {
        header,
        ciphertext,
        welcome,
    })
}
