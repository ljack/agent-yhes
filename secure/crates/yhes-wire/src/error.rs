//! The single error type. Messages name the failed check, never payload content.

/// Why verification or parsing was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("input exceeds the size limit")]
    TooLarge,
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    #[error("schema violation: {0}")]
    Schema(&'static str),
    #[error("invalid identifier: {0}")]
    InvalidId(&'static str),
    #[error("unsupported payload type")]
    UnsupportedPayloadType,
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("unsupported signature algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid public key")]
    InvalidKey,
    #[error("wrong number of signatures")]
    SignatureCount,
    #[error("signature key id differs from the signed key id")]
    KeyIdMismatch,
    #[error("signature algorithm differs from the key's algorithm")]
    AlgorithmMismatch,
    #[error("signature does not verify")]
    BadSignature,
    #[error("signing key is not enrolled")]
    UnknownKey,
    #[error("signing key is revoked")]
    KeyRevoked,
    #[error("signing key is not yet valid")]
    KeyNotYetValid,
    #[error("signing key has expired")]
    KeyExpired,
    #[error("signing key does not belong to the claimed author")]
    AuthorMismatch,
    #[error("participant is not in the registry")]
    UnknownParticipant,
    #[error("event or registry belongs to another project")]
    WrongProject,
    #[error("audience does not match the expectation")]
    WrongAudience,
    #[error("group does not match the expectation")]
    WrongGroup,
    #[error("issued in the future")]
    NotYetValid,
    #[error("expired")]
    Expired,
    #[error("expires_at precedes issued_at")]
    InvalidTimeRange,
    #[error("validity period exceeds policy")]
    LifetimeTooLong,
    #[error("this signer may not issue this kind of event: {0}")]
    KindNotPermitted(&'static str),
    #[error("session reference is not allowed for this signer")]
    SessionNotAllowed,
    #[error("required evidence is missing: {0}")]
    EvidenceRequired(&'static str),
    #[error("evidence was supplied but the event does not reference it: {0}")]
    UnexpectedEvidence(&'static str),
    #[error("evidence does not match the event: {0}")]
    EvidenceMismatch(&'static str),
    #[error("event was issued outside the validity window of its grant")]
    OutsideGrantWindow,
    #[error("event exceeds the scope of its grant: {0}")]
    ScopeEscalation(&'static str),
    #[error("grant is not valid: {0}")]
    InvalidGrant(&'static str),
    #[error("relay is not valid: {0}")]
    RelayInvalid(&'static str),
    #[error("action differs from its authorization: {0}")]
    AuthorizationMismatch(&'static str),
    #[error("invalid trust anchors: {0}")]
    InvalidAnchors(&'static str),
    #[error("registry signature is not from a pinned authority")]
    UntrustedAuthority,
    #[error("too few authority signatures")]
    ThresholdNotMet,
    #[error("registry generation is older than the checkpoint")]
    RegistryRollback,
    #[error("registry differs from the checkpoint at the same generation")]
    RegistryFork,
    #[error("registry skips a generation")]
    RegistryGap,
    #[error("registry does not name the checkpoint as its predecessor")]
    RegistryChain,
    #[error("registry drops an earlier revocation")]
    RevocationDropped,
    #[error("registry is not yet valid")]
    RegistryNotYetValid,
    #[error("registry has expired")]
    RegistryExpired,
}
