# yhes-wire public API

Verifier for agent-yhes secure events and registries. The wire format is in
[`spec/secure-events.md`](../../../spec/secure-events.md). The crate holds no
private keys, performs no I/O, keeps no state and reads no environment
variables or feature flags. Every check fails closed with an `Error`.

Add it to another workspace crate with `yhes-wire = { path = "../yhes-wire" }`.

## Typical use

```rust
use yhes_wire::*;

// 1. Pin the authority keys (out of band) and verify the registry.
let anchors = TrustAnchors::new("demo", vec![authority_public_key], 1)?;
let registry = Registry::verify(&registry_envelope, &anchors, prior_checkpoint.as_ref(), &policy, now)?;
// Persist the exact registry envelope bytes; rebuild the checkpoint from them
// at start-up with RegistryCheckpoint::advance(bytes, &anchors, None).

// 2. Verify an event against it.
let verifier = Verifier::new(&registry, Policy::default());
let verified = verifier.verify_event(
    &event_envelope,
    &Evidence { grant: grant_envelope, authorization: None, original_grant: None },
    &Expectation { project: "demo", audience: AudienceCheck::Includes("alice-agent"), group: None },
    now,
)?;

match verified.signer() {
    SignerRole::HumanDevice | SignerRole::HumanSession => { /* human-authored */ }
    SignerRole::Agent | SignerRole::Service => { /* never human-authored */ }
}
```

`now` is Unix seconds supplied by the caller. Replay and single-use state is
the caller's job: use `verified.digest()`, `verified.event().id` and, for
`action.execute`, the `authorization` digest in the body.

## Constants

| Name | Value |
| --- | --- |
| `EVENT_PAYLOAD_TYPE` | `application/vnd.agent-yhes.event.v1+json` |
| `REGISTRY_PAYLOAD_TYPE` | `application/vnd.agent-yhes.registry.v1+json` |
| `TRANSPORT_PAYLOAD_TYPE` | `application/vnd.agent-yhes.transport.v1+json` |
| `TICKET_ACTIONS` | `ticket.create`, `.claim`, `.release`, `.update`, `.complete`, `.cancel` |
| `MAX_ENVELOPE_BYTES` | 1 048 576 |
| `MAX_JSON_DEPTH` | 8 |
| `MAX_ID_BYTES` | 128 |
| `MAX_TEXT_BYTES` | 65 536 |
| `MAX_AUDIENCE` | 256 |
| `MAX_SIGNATURES` | 8 |

## Keys and digests

```rust
pub enum Algorithm { Ed25519, P256Sha256 }      // as_str(), parse()
pub struct PublicKey;                           // validated raw public key
impl PublicKey {
    pub fn new(algorithm: Algorithm, raw: &[u8]) -> Result<PublicKey, Error>; // 32 bytes / 65-byte SEC1 uncompressed
    pub fn algorithm(&self) -> Algorithm;
    pub fn as_bytes(&self) -> &[u8];
    pub fn key_id(&self) -> KeyId;              // "k_" + sha256("agent-yhes/key/v1\0" + alg + "\0" + raw)
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), Error>;
}
pub struct KeyId;                               // parse(&str), as_str(), Display, Ord
pub struct Digest;                              // of(bytes), from_hex(&str), to_hex(), as_bytes(), Display
```

Ed25519 uses strict verification (no small-order keys, canonical encodings).
P-256 signatures are raw `r||s`; high-S is accepted because Secure Enclave
signatures are not normalized.

## Envelope

```rust
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8>;   // DSSE v1 signing input

pub struct SignatureEntry { pub key_id: KeyId, pub algorithm: Algorithm, pub signature: [u8; 64] }

pub struct Envelope;
impl Envelope {
    pub fn parse(bytes: &[u8], expected_payload_type: &str) -> Result<Envelope, Error>; // strict, unverified
    pub fn new(payload_type: &str, payload: Vec<u8>, signatures: Vec<SignatureEntry>) -> Result<Envelope, Error>;
    pub fn payload_type(&self) -> &str;
    pub fn payload(&self) -> &[u8];             // exact signed bytes
    pub fn signatures(&self) -> &[SignatureEntry];
    pub fn signing_input(&self) -> Vec<u8>;     // pae(payload_type, payload)
    pub fn digest(&self) -> Digest;             // sha256 of exact payload bytes
    pub fn to_json(&self) -> Vec<u8>;           // envelope JSON; payload bytes unchanged
}
```

A producer builds payload bytes, signs `pae(type, payload)` with its own key
store, and assembles the envelope with `Envelope::new`. `Envelope::parse`
checks structure only; nothing is trusted until `Verifier` or `Registry` accepts it.

## Events

```rust
pub enum Kind { HumanStatement, SessionGrant, AgentDelegation, AgentMessage,
                AgentRelay, ActionAuthorization, ActionExecute, ServiceNotice,
                TicketAction }                                                     // as_str(), parse()

pub enum Body {
    HumanStatement { text: String },
    SessionGrant { session_key: PublicKey, purposes: Vec<Kind> },
    AgentDelegation { agent: String, agent_key_id: KeyId, purposes: Vec<Kind> },
    AgentMessage { text: String },
    AgentRelay { original: Envelope, note: Option<String> },
    ActionAuthorization { action: String, request_digest: Digest, performer: String },
    ActionExecute { action: String, request_digest: Digest, authorization: Digest },
    ServiceNotice { text: String },
    TicketAction { action: String, request_digest: Digest },     // action is one of TICKET_ACTIONS
}

pub struct Event {                    // unverified field set; all fields pub
    pub id: String, pub project: String, pub author: String, pub key_id: KeyId,
    pub session: Option<Digest>,      // digest of the session grant or delegation event
    pub issued_at: u64, pub expires_at: u64,
    pub audience: Vec<String>,        // sorted, unique, non-empty
    pub group: Option<String>, pub epoch: Option<u64>, pub previous: Option<Digest>,
    pub body: Body,
}
impl Event {
    pub fn kind(&self) -> Kind;
    pub fn parse(payload: &[u8]) -> Result<Event, Error>;      // strict schema, no trust
    pub fn to_payload(&self) -> Result<Vec<u8>, Error>;        // bytes to sign; self-checked by re-parsing
}
```

## Registry

```rust
pub struct TrustAnchors;
impl TrustAnchors {
    pub fn new(project: &str, authorities: Vec<PublicKey>, threshold: usize) -> Result<TrustAnchors, Error>;
}

pub enum ParticipantKind { Human, Agent, Service }
pub struct GhesIdentity { pub instance: String, pub user_id: u64 }
pub struct Participant { pub id: String, pub kind: ParticipantKind,
                         pub controller: Option<String>, pub ghes: Option<GhesIdentity> }

pub struct Registry;
impl Registry {
    pub fn verify(envelope: &[u8], anchors: &TrustAnchors, prior: Option<&RegistryCheckpoint>,
                  policy: &Policy, now: u64) -> Result<Registry, Error>;
    pub fn project(&self) -> &str;
    pub fn generation(&self) -> u64;
    pub fn digest(&self) -> Digest;
    pub fn issued_at(&self) -> u64;
    pub fn expires_at(&self) -> u64;
    pub fn participant(&self, id: &str) -> Option<&Participant>;
    pub fn participants(&self) -> impl Iterator<Item = &Participant>;
    pub fn is_revoked(&self, key_id: &KeyId) -> bool;
    // The enrolled key of `participant`, usable at `now`. Errors: RegistryExpired,
    // UnknownParticipant, KeyRevoked, UnknownKey, AuthorMismatch (enrolled for
    // someone else), KeyNotYetValid, KeyExpired.
    pub fn active_key(&self, participant: &str, key_id: &KeyId, now: u64) -> Result<PublicKey, Error>;
    pub fn checkpoint(&self) -> RegistryCheckpoint;
}

pub struct RegistryCheckpoint;        // generation + digest + revoked key ids
impl RegistryCheckpoint {
    // Signature and chain checks only (no clock): for replaying older generations.
    pub fn advance(envelope: &[u8], anchors: &TrustAnchors,
                   prior: Option<&RegistryCheckpoint>) -> Result<RegistryCheckpoint, Error>;
    pub fn generation(&self) -> u64;
    pub fn digest(&self) -> Digest;
}
```

With a prior checkpoint, a registry is accepted only when it is the same
generation with the same digest, or exactly the next generation naming the
prior digest and keeping every prior revocation. Without one, any authentic
generation is accepted (first contact).

## Verifier

```rust
pub struct Policy {                           // Default: 120 s, 7 d, 30 min, 7 d, 5 min
    pub max_clock_skew: u64,
    pub max_event_lifetime: u64,
    pub max_session_lifetime: u64,
    pub max_delegation_lifetime: u64,
    pub max_authorization_lifetime: u64,
}

pub struct Evidence<'a> {                     // Default: all None
    pub grant: Option<&'a [u8]>,              // envelope named by the event's `session`
    pub authorization: Option<&'a [u8]>,      // envelope named by action.execute `authorization`
    pub original_grant: Option<&'a [u8]>,     // grant of a session-signed original inside a relay
}

pub enum AudienceCheck<'a> { Includes(&'a str), Exact(&'a [String]), AuditOnly }
pub struct Expectation<'a> { pub project: &'a str, pub audience: AudienceCheck<'a>, pub group: Option<&'a str> }

pub struct Verifier<'a>;
impl<'a> Verifier<'a> {
    pub fn new(registry: &'a Registry, policy: Policy) -> Verifier<'a>;
    pub fn verify_event(&self, envelope: &[u8], evidence: &Evidence<'_>,
                        expect: &Expectation<'_>, now: u64) -> Result<VerifiedEvent, Error>;
}

pub enum SignerRole { HumanDevice, HumanSession, Agent, Service }

pub struct VerifiedEvent;             // only the verifier can construct one
impl VerifiedEvent {
    pub fn event(&self) -> &Event;
    pub fn digest(&self) -> Digest;               // sha256 of exact payload bytes
    pub fn payload(&self) -> &[u8];               // exact signed bytes
    pub fn signer(&self) -> SignerRole;           // derived from registry and grants
    pub fn author_kind(&self) -> ParticipantKind; // derived, never read from the event
    pub fn controller(&self) -> Option<&str>;     // human controlling an agent/service
    pub fn ghes(&self) -> Option<&GhesIdentity>;  // human author's GHES identity
    pub fn grant(&self) -> Option<&VerifiedEvent>;          // verified session grant / delegation
    pub fn authorization(&self) -> Option<&VerifiedEvent>;  // verified action authorization
    pub fn original(&self) -> Option<&VerifiedEvent>;       // verified human original of a relay
    pub fn is_human_authored(&self) -> bool;
}
```

Evidence that is required but missing, supplied but not required, or whose
digest differs from the reference in the event is an error.

### Who may sign what

| Kind | Signer | `session` | Evidence |
| --- | --- | --- | --- |
| `human.statement` | human device key | null | none |
| `human.statement` | human session key | session grant digest | `grant` |
| `session.grant`, `agent.delegation`, `action.authorization` | human device key only | null | none |
| `agent.message`, `agent.relay` | agent key | delegation digest | `grant` (+ `original_grant`) |
| `action.execute` | agent key | delegation digest | `grant`, `authorization` |
| `action.execute` | human device key | null | `authorization` |
| `service.notice` | service key | null | none |
| `ticket.action` | agent key only | delegation digest | `grant` |

`ticket.action` is the routine delegated event: an agent needs a delegation
whose `purposes` list `ticket.action` explicitly, and no fresh human
authorization. Human, session and service keys cannot issue it. `action` must
be one of `TICKET_ACTIONS`. Privileged ticket actions such as `ticket.recover`
go through `action.execute` with a fresh `action.authorization`. Delegable
purposes are `agent.message`, `agent.relay`, `action.execute` and `ticket.action`.

`request_digest`, here and in `action.authorization`/`action.execute`, is the
SHA-256 of the exact reviewed request sidecar, never of MLS Commit bytes.

`Envelope::parse` and `Envelope::new` also accept `TRANSPORT_PAYLOAD_TYPE` for
the transport layer's own records. `Verifier` and `Registry` never accept a
transport envelope, directly, as evidence or as a relayed original.

To bind an MLS KeyPackage signature key to an enrolled agent key, compute the
`KeyId` of the KeyPackage's public key (`PublicKey::new(..)?.key_id()`) and call
`registry.active_key(agent_id, &key_id, now)`; compare the returned key bytes.

### Rules that affect integration

- A revoked key is refused for every event regardless of `issued_at`. Keep
  already accepted history in durable state; do not re-verify it later.
- Grants must cover the dependent event's `issued_at` and remain current now.
  An old sender-supplied timestamp is not proof of timely use. Read previously
  accepted history from the durable core; do not submit it as fresh authority.
- An agent event's audience must lie within its delegation's audience and
  share its `group`. A relay's audience must also lie within the original's.
- `action.execute` must repeat the authorization's `action`, `request_digest`,
  `audience`, `group` and `epoch` exactly. Single use is the caller's job.
- `group` may be set without `epoch`; `epoch` requires `group`.
- The `Policy` limits are plain configuration. Use `Policy::default()` unless
  a reviewed decision changes a limit.

## Tests

`cargo test -p yhes-wire` from `secure/`. `tests/verifier.rs` covers forged
human labels, tampering, wrong project/audience/group, expired and revoked
keys, registry rollback/fork/gap, session and delegation escalation, relay
substitution, action authorization, `ticket.action`, `active_key` and malformed input. `tests/interop.rs`
verifies the native signer's P-256 vectors: a statement (low-S and high-S)
and a registry. All keys are
fixed-seed software keys.

## Errors

`Error` is `#[non_exhaustive]`, implements `std::error::Error`, `Clone`,
`PartialEq`. Variants: `TooLarge`, `Malformed`, `Schema`, `InvalidId`,
`UnsupportedPayloadType`, `UnsupportedVersion`, `UnsupportedAlgorithm`,
`InvalidKey`, `SignatureCount`, `KeyIdMismatch`, `AlgorithmMismatch`,
`BadSignature`, `UnknownKey`, `KeyRevoked`, `KeyNotYetValid`, `KeyExpired`,
`AuthorMismatch`, `UnknownParticipant`, `WrongProject`, `WrongAudience`,
`WrongGroup`, `NotYetValid`, `Expired`, `InvalidTimeRange`, `LifetimeTooLong`,
`KindNotPermitted`, `SessionNotAllowed`, `EvidenceRequired`,
`UnexpectedEvidence`, `EvidenceMismatch`, `OutsideGrantWindow`,
`ScopeEscalation`, `InvalidGrant`, `RelayInvalid`, `AuthorizationMismatch`,
`InvalidAnchors`, `UntrustedAuthority`, `ThresholdNotMet`, `RegistryRollback`,
`RegistryFork`, `RegistryGap`, `RegistryChain`, `RevocationDropped`,
`RegistryNotYetValid`, `RegistryExpired`. Messages never contain payload content.
