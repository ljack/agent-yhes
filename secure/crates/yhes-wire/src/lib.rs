//! Signed-event and registry verifier for the agent-yhes secure profile.
//!
//! The crate verifies; it holds no private keys, performs no I/O and keeps no
//! state. Every check fails closed, and there is no switch that relaxes one.
//! The wire format is described in `spec/secure-events.md`; the public API is
//! summarized in `API.md` next to this crate.

mod envelope;
mod error;
mod event;
mod json;
mod keys;
mod registry;
mod verify;

pub use envelope::{pae, Envelope, SignatureEntry};
pub use error::Error;
pub use event::{Body, Event, Kind, TICKET_ACTIONS};
pub use keys::{Algorithm, Digest, KeyId, PublicKey};
pub use registry::{
    GhesIdentity, Participant, ParticipantKind, Registry, RegistryCheckpoint, TrustAnchors,
};
pub use verify::{
    AudienceCheck, Evidence, Expectation, Policy, SignerRole, VerifiedEvent, Verifier,
};

/// Payload type of signed events.
pub const EVENT_PAYLOAD_TYPE: &str = "application/vnd.agent-yhes.event.v1+json";
/// Payload type of signed registries.
pub const REGISTRY_PAYLOAD_TYPE: &str = "application/vnd.agent-yhes.registry.v1+json";

/// Payload type of signed transport records. The envelope layer carries it;
/// the event and registry verifiers refuse it.
pub const TRANSPORT_PAYLOAD_TYPE: &str = "application/vnd.agent-yhes.transport.v1+json";

/// Largest accepted envelope, and so the largest payload, in bytes.
pub const MAX_ENVELOPE_BYTES: usize = 1 << 20;
/// Deepest accepted nesting of JSON arrays and objects.
pub const MAX_JSON_DEPTH: usize = 8;
/// Longest accepted identifier, in bytes.
pub const MAX_ID_BYTES: usize = 128;
/// Longest accepted message text or relay note, in bytes.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
/// Most audience members in one event.
pub const MAX_AUDIENCE: usize = 256;
/// Most signatures in one envelope, and most pinned authorities.
pub const MAX_SIGNATURES: usize = 8;

/// Largest accepted timestamp: 9999-12-31T23:59:59Z.
pub(crate) const MAX_TIMESTAMP: u64 = 253_402_300_799;
