//! Local signer protocol v1 (docs/USABLE-PILOT-CONTRACT.md). The transport is
//! a `SignerClient`; every reply is validated here before anything is trusted.
//! No operation signs caller-chosen bytes without native human review.
use crate::Failure;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize};
use yhes_wire::{Algorithm, Envelope, KeyId, PublicKey, EVENT_PAYLOAD_TYPE, REGISTRY_PAYLOAD_TYPE};

/// One line of UTF-8 JSON per connection, in both directions.
pub const MAX_LINE: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Identity,
    Enroll,
    Review,
}
impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Operation::Identity => "identity",
            Operation::Enroll => "enroll",
            Operation::Review => "review",
        }
    }
}

/// The contract also defines `batch`. This CLI sends one statement per review
/// and never builds a batch, so it has no variant for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Event,
    Registry,
}
impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Event => "event",
            Mode::Registry => "registry",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub id: String,
    pub operation: Operation,
    pub author: String,
    pub project: String,
    pub mode: Option<Mode>,
    pub payloads: Vec<Vec<u8>>,
    pub request: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct WireRequest<'a> {
    version: u8,
    id: &'a str,
    operation: &'a str,
    author: &'a str,
    project: &'a str,
    mode: Option<&'a str>,
    payloads: Vec<String>,
    request: Option<String>,
}

impl Request {
    fn new(operation: Operation, author: &str, project: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            operation,
            author: author.to_owned(),
            project: project.to_owned(),
            mode: None,
            payloads: vec![],
            request: None,
        }
    }
    /// The exact line sent to the signer, newline included.
    pub fn encode(&self) -> Result<Vec<u8>, Failure> {
        let mut line = serde_json::to_vec(&WireRequest {
            version: 1,
            id: &self.id,
            operation: self.operation.as_str(),
            author: &self.author,
            project: &self.project,
            mode: self.mode.map(Mode::as_str),
            payloads: self.payloads.iter().map(|p| STANDARD.encode(p)).collect(),
            request: self.request.as_ref().map(|r| STANDARD.encode(r)),
        })
        .map_err(|_| Failure::new("internal", "cannot encode the signer request"))?;
        line.push(b'\n');
        if line.len() > MAX_LINE {
            return Err(Failure::new(
                "too_large",
                "the document is too large for one signer request",
            ));
        }
        Ok(line)
    }
}

/// Carries one request line to the signer and returns its one reply line.
/// The production implementation authenticates the peer process first.
pub trait SignerClient {
    fn exchange(&self, request: &Request) -> Result<Vec<u8>, Failure>;
    /// Reach and authenticate the signer without asking it for anything.
    fn probe(&self) -> Result<(), Failure>;
    /// Start the authenticated companion if necessary, without requesting a key
    /// or approval. Non-native test/adapter implementations may just probe.
    fn prepare(&self) -> Result<(), Failure> {
        self.probe()
    }
    /// Key algorithms this signer profile may present. The native app holds a
    /// Secure Enclave P-256 key, so its transport accepts nothing else.
    fn accepts(&self, algorithm: Algorithm) -> bool;
}

fn required<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    version: u64,
    id: String,
    status: String,
    // `deserialize_with` makes these required: an absent field is an error.
    #[serde(deserialize_with = "required")]
    result: Option<String>,
    #[serde(deserialize_with = "required")]
    error: Option<String>,
}

enum Reply {
    Ok(Vec<u8>),
    Cancelled,
    Error(String),
}

fn malformed() -> Failure {
    Failure::new("signer_reply_invalid", "the signer sent a malformed reply")
        .hint("Update YhesSigner and yhes to the same build, then retry.")
}

fn parse_reply(request: &Request, line: &[u8]) -> Result<Reply, Failure> {
    if line.len() > MAX_LINE {
        return Err(malformed());
    }
    let body = line.strip_suffix(b"\n").unwrap_or(line);
    if body.contains(&b'\n') || body.contains(&b'\r') {
        return Err(malformed());
    }
    let reply: WireResponse = serde_json::from_slice(body).map_err(|_| malformed())?;
    if reply.version != 1 {
        return Err(malformed());
    }
    // The signer answers a frame it could not parse under the all-zero ID.
    if reply.id == "00000000-0000-0000-0000-000000000000"
        && reply.status == "error"
        && reply.result.is_none()
        && reply.error.as_deref() == Some("invalid_request")
    {
        return Ok(Reply::Error("invalid_request".into()));
    }
    // A reply for any other request, including an earlier one, is refused.
    if reply.id != request.id {
        return Err(Failure::new(
            "signer_reply_mismatch",
            "the signer replied to a different request",
        ));
    }
    match (reply.status.as_str(), reply.result, reply.error) {
        ("ok", Some(result), None) => {
            let bytes = STANDARD.decode(&result).map_err(|_| malformed())?;
            if STANDARD.encode(&bytes) != result || std::str::from_utf8(&bytes).is_err() {
                return Err(malformed());
            }
            Ok(Reply::Ok(bytes))
        }
        ("cancelled", None, None) => Ok(Reply::Cancelled),
        // The contract leaves the error code optional only for `ok`.
        ("cancelled", None, Some(code)) | ("error", None, Some(code)) => {
            if code.is_empty()
                || code.len() > 64
                || !code
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(malformed());
            }
            if reply.status == "cancelled" {
                Ok(Reply::Cancelled)
            } else {
                Ok(Reply::Error(code))
            }
        }
        _ => Err(malformed()),
    }
}

fn signer_error(code: &str) -> Failure {
    let (message, hint) = match code {
        "busy" => (
            "the signer is showing another review",
            "Finish or cancel the open review in YhesSigner, then run the command again.",
        ),
        "identity_missing" => (
            "this Mac has no human signing key for this author and project",
            "Run `yhes pilot` to request key setup in YhesSigner.",
        ),
        "identity_mismatch" => (
            "the signer's key belongs to a different author or project",
            "Use the --human ID and project that were enrolled in YhesSigner.",
        ),
        "timeout" => (
            "the review expired before it was approved",
            "Run the command again and approve within 5 minutes.",
        ),
        "unauthorized" => (
            "the signer refused this program",
            "Run the signed `yhes` helper that ships inside YhesSigner.app.",
        ),
        "invalid_document" => (
            "the signer cannot review this document",
            "Check the text for invisible characters and that it is under 32 KiB, then retry.",
        ),
        "identity_exists" => (
            "a signing key already exists and is never overwritten",
            "Resume setup to use the existing key with its original human ID and project.",
        ),
        "approval_failed" => (
            "the approval attempt did not complete",
            "Check YhesSigner for the reason and retry there when offered. Existing keys are preserved; resume setup to check saved progress.",
        ),
        "identity_unavailable" | "unavailable" => (
            "the signer could not use its key or Touch ID",
            "Open YhesSigner; it shows why (Touch ID unavailable, locked, or an unsigned build).",
        ),
        _ => (
            "the signer refused the request",
            "Open YhesSigner for details; `yhes doctor` checks the setup.",
        ),
    };
    let mut failure = Failure::new("signer_refused", message).hint(hint);
    failure.detail = Some(code.to_owned());
    failure
}

fn cancelled() -> Failure {
    Failure::new("cancelled", "the review was cancelled in YhesSigner")
        .hint("No approval was returned. Resume setup in YhesSigner, or retry the command when you are ready.")
}

/// The signer's public descriptor. Public metadata; the CLI pins it locally.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub author: String,
    pub project: String,
}
impl Descriptor {
    pub fn parse(bytes: &[u8]) -> Result<Self, Failure> {
        let d: Descriptor = serde_json::from_slice(bytes).map_err(|_| malformed())?;
        d.key()?;
        Ok(d)
    }
    /// The validated key. Fails if the key ID does not belong to the key.
    pub fn key(&self) -> Result<PublicKey, Failure> {
        let algorithm = Algorithm::parse(&self.algorithm).map_err(|_| malformed())?;
        let raw = STANDARD.decode(&self.public_key).map_err(|_| malformed())?;
        let key = PublicKey::new(algorithm, &raw).map_err(|_| malformed())?;
        if key.key_id().as_str() != self.key_id {
            return Err(malformed());
        }
        Ok(key)
    }
    pub fn key_id(&self) -> Result<KeyId, Failure> {
        Ok(self.key()?.key_id())
    }
}

fn unexpected_algorithm() -> Failure {
    Failure::new(
        "signer_algorithm_rejected",
        "the signer presented a key type this signer profile never uses",
    )
    .hint("Nothing was accepted. Check that the running YhesSigner is the signed release.")
}

fn descriptor(
    client: &dyn SignerClient,
    request: &Request,
    bytes: &[u8],
) -> Result<Descriptor, Failure> {
    let d = Descriptor::parse(bytes)?;
    if !client.accepts(d.key()?.algorithm()) {
        return Err(unexpected_algorithm());
    }
    if d.author != request.author || d.project != request.project {
        return Err(Failure::new(
            "signer_identity_mismatch",
            "the signer returned a key for a different author or project",
        ));
    }
    Ok(d)
}

/// Existing identity, or `None` when the signer has no key for this scope.
/// Never prompts and never creates a key.
pub fn identity(
    client: &dyn SignerClient,
    author: &str,
    project: &str,
) -> Result<Option<Descriptor>, Failure> {
    let request = Request::new(Operation::Identity, author, project);
    match parse_reply(&request, &client.exchange(&request)?)? {
        Reply::Ok(bytes) => Ok(Some(descriptor(client, &request, &bytes)?)),
        Reply::Error(code) if code == "identity_missing" => Ok(None),
        Reply::Error(code) => Err(signer_error(&code)),
        Reply::Cancelled => Err(cancelled()),
    }
}

/// Ask the native app to set up the human key. The human approves there.
pub fn enroll(
    client: &dyn SignerClient,
    author: &str,
    project: &str,
) -> Result<Descriptor, Failure> {
    let request = Request::new(Operation::Enroll, author, project);
    match parse_reply(&request, &client.exchange(&request)?)? {
        Reply::Ok(bytes) => descriptor(client, &request, &bytes),
        Reply::Error(code) => Err(signer_error(&code)),
        Reply::Cancelled => Err(cancelled()),
    }
}

/// Native review of one exact document. Returns the signed envelope only if it
/// carries exactly the submitted bytes under the pinned human key.
pub fn review(
    client: &dyn SignerClient,
    pinned: &Descriptor,
    mode: Mode,
    payload: &[u8],
    sidecar: Option<&[u8]>,
) -> Result<String, Failure> {
    // Checked before the document leaves this process.
    let key = pinned.key()?;
    if !client.accepts(key.algorithm()) {
        return Err(unexpected_algorithm());
    }
    let mut request = Request::new(Operation::Review, &pinned.author, &pinned.project);
    request.mode = Some(mode);
    request.payloads = vec![payload.to_vec()];
    request.request = sidecar.map(<[u8]>::to_vec);
    let bytes = match parse_reply(&request, &client.exchange(&request)?)? {
        Reply::Ok(bytes) => bytes,
        Reply::Error(code) => return Err(signer_error(&code)),
        Reply::Cancelled => return Err(cancelled()),
    };
    let wrong = || {
        Failure::new(
            "signer_result_rejected",
            "the signer's result is not a signature by the pinned key over the reviewed document",
        )
        .hint("Nothing was accepted. Run `yhes doctor`; the enrolled key may have changed.")
    };
    let payload_type = match mode {
        Mode::Event => EVENT_PAYLOAD_TYPE,
        Mode::Registry => REGISTRY_PAYLOAD_TYPE,
    };
    let envelope = Envelope::parse(&bytes, payload_type).map_err(|_| wrong())?;
    let [signature] = envelope.signatures() else {
        return Err(wrong());
    };
    if envelope.payload() != payload
        || signature.key_id != key.key_id()
        || signature.algorithm != key.algorithm()
        || key
            .verify(&envelope.signing_input(), &signature.signature)
            .is_err()
    {
        return Err(wrong());
    }
    String::from_utf8(bytes).map_err(|_| wrong())
}
