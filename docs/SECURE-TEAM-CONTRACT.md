# Secure implementation working contract

This coordinates implementation of the approved plan. It does not authorize
real enrollment, publishing, commits or tags. Existing v0.1/v0.2/v0.3 prototype
files and evaluation evidence must be preserved.

## Ownership

- Root: `secure/Cargo.toml`, `secure/crates/yhes-core/**`, secure Python transport,
  integration tests, overall docs and integration.
- Verifier child: `secure/crates/yhes-wire/**` and `spec/secure-events.md` only.
- macOS child: `native/YhesSigner/**` and `docs/MACOS-SIGNER.md` only.
- Reviewer: read-only unless explicitly assigned a correction later.

## Shared signature format

Use a DSSE-style envelope with exact payload bytes preserved:

```json
{"payload_type":"application/vnd.agent-yhes.event.v1+json","payload":"BASE64_UTF8_JSON","signatures":[{"key_id":"k_SHA256HEX","algorithm":"p256-sha256","signature":"BASE64_RAW64"}]}
```

Signing input is the standard DSSE PAE:
`DSSEv1 <decimal UTF8 payload_type length> <payload_type> <decimal payload byte length> <payload bytes>`.
Lengths count bytes. Preserve original signed bytes on retry and relay. Verification
strictly rejects duplicate JSON object keys, unknown envelope fields, unsupported
versions, oversized/deep input and invalid event schemas. Integer timestamps are
Unix seconds. There is no reserialization before signature verification.

Algorithms: `ed25519` (32-byte raw public key; 64-byte signature) and `p256-sha256`
(65-byte uncompressed SEC1 public key; 64-byte r||s ECDSA signature, SHA-256).
Key IDs are `k_` + lowercase SHA-256 of `b"agent-yhes/key/v1\0" + algorithm ASCII
bytes + b"\0" + raw public key`. Bind the key ID inside the signed event too.

Event payload fields: `version:1`, `id`, `project`, `kind`, `author`, `key_id`,
`session` (nullable), `issued_at`, `expires_at`, `audience` (sorted unique IDs),
`group` (nullable), `epoch` (nullable), `previous` (nullable digest), `body` (typed
by kind). IDs must be bounded and path-safe; never interpret payload paths/URLs
as configuration or commands. Event digest is SHA-256 of exact payload bytes.

Registry is a separately signed payload type
`application/vnd.agent-yhes.registry.v1+json`, verified against explicitly pinned
authority public keys. It binds project, monotonic generation/previous digest,
validity, participant identities, keys, controller relationships and revocations.
Human/agent/service classifications are verifier outputs, not trusted sender labels.

## Human/native boundary

Native human root: Secure Enclave P-256, private-key-use access control with
Touch ID. Keys never enter Python or Rust MLS storage. Native app displays the
actual event/audience and requires intentional user action. No unattended
arbitrary-data human-sign endpoint. Fresh confirmation for enrollment, delegation,
membership/recipient expansion, trust changes and action authorization.

The implemented profile uses a fixed batch of exact reviewed human statements
per fresh authentication context. It grants no timed window for future data.
Agents use their own delegated keys for routine messages. Registry, delegation
and membership reviews remain separate protected actions. Lock, user switch,
exit, expiry or changed review data invalidates the pending approval.
No runtime test flag or unavailable-biometric fallback may produce a human signature.
Native UI/signing can be built/tested without performing real enrollment.

## Verifier boundary

Human device keys can issue narrowly scoped session grants/delegations and fresh
action authorizations. Human-session keys cannot issue them. Agent keys cannot
become humans or widen a delegation. Every signature, project/audience/time bound,
controller and purpose must be checked. Relays preserve a verifiable original
human envelope and add a distinct agent signature; edited/paraphrased content
remains agent-authored. Replay/idempotency state belongs to the durable core.

## Private state and transport

OpenMLS 0.9.2, RustCrypto 0.6.0, upstream SQLite storage 0.3.0. State, immutable
outbox and durable inbox share one transaction. Production must protect the
database/WAL at rest; no private state JSON export. Network and Touch ID calls
occur outside database transactions. Cryptographic failures roll back and discard
the group object. Trusted transport acceptance precedes merging own membership.

Git carries signed/sealed public records only. NATS remains a hint mechanism.
Application verification and authorization precede acting on decrypted messages.
Unsigned legacy records cannot downgrade a secure channel. No project commits,
tags, external messages or production deployment during this implementation.

## Action request sidecar and review bindings

An `action.authorization` must be reviewed with the exact request sidecar whose
SHA-256 is `body.request_digest`. The native signer must show both the validated
request and authorization, and require matching project/action/performer/group/
epoch/audience. Hash-only approval is forbidden.

Request fields (all required, unknown fields rejected): `version:1`, `project`,
`action`, `performer`, `group`, `epoch` (integer), `audience` (sorted unique),
`parameters`. For `group.create`, parameters are `{}` and initial audience is
the performing agent. For `group.add`, parameters are `{member, key_id,
key_package_digest}`. For `group.remove`, parameters are `{member}`. For
`ticket.recover`, parameters are `{ticket, expected_revision, stop_evidence}`.
These are the first privileged actions; no arbitrary shell/deploy action is
implicitly supported. Core binds the exact request bytes and prior epoch before
acting. Rebuilt attempts after an audience change require new authorization.

Routine ticket operations use a distinct `ticket.action` event, signed by an
agent with that explicitly delegated purpose. Body: `{action, request_digest}`,
where action is one of `ticket.create`, `ticket.claim`, `ticket.release`,
`ticket.update`, `ticket.complete`, `ticket.cancel`. Core enforces ticket ownership
and revision rules. This purpose grants no group/trust change, human-signing role
or authority to perform arbitrary work mentioned in a ticket.

Inner signed application bytes cannot include their own enclosing ciphertext
digest (that would be circular). Bind the inner event to its project/audience and
the transport relay to the exact ciphertext digest/group/epoch. Membership grants
bind the pre-encryption action descriptor; the resulting MLS Commit is separately
bound by the publishing agent. Effect replay keys are verified author + event ID
and exact payload digest, never raw signature bytes. P-256 high-S signatures from
CryptoKit may verify; an alternate signature over the same payload must not create
a second action.
