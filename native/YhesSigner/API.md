# Native signer interface

The Swift 6 package in this workspace requires macOS 14+. Products are `YhesSignerCore`
(pure parsing, review policy, DSSE) and `YhesSigner` (AppKit executable). The
authenticated local socket below accepts typed review requests. No generic signing,
URL handler or AppleScript approval bridge exists.


## Local socket v1

Socket `~/Library/Application Support/agent-yhes/signer.sock` is inside a 0700
same-owner directory; socket is 0600. Both ends authenticate the kernel-provided
Darwin `LOCAL_PEERTOKEN` (level 0, option 6) with `SecCodeCopyGuestWithAttributes`
using `kSecGuestAttributeAudit`, then Apple-anchored identifier and certificate
team requirements. Signer accepts only `com.agent-yhes.engine`, team `25C9H9N953`;
engine accepts only `com.agent-yhes.YhesSigner`, same team. Same UID is also required.
A process-wide file lock prevents a second app from removing a live listener.

One UTF-8 JSON line per connection, at most 1 MiB excluding newline. No duplicate
or unknown fields. Exactly these fields, with a UUID correlation `id`:

```json
{"version":1,"id":"UUID","operation":"identity|enroll|review","author":"AUTHOR","project":"PROJECT","mode":null,"payloads":[],"request":null}
```

`identity` and `enroll` use those null/empty fields. Identity reads never create
keys or prompt. Enrollment displays exact author/project and requires the user's
native consent and Touch ID. Existing keys are never overwritten. Review `mode`
is `event`, `registry` or `batch`, `payloads` is base64 exact UTF-8 input bytes
(one for event/registry), and `request` is base64 exact action sidecar only for
`action.authorization`; it is null otherwise. Existing typed bounds, lifetimes,
statement-only batch rules and exact-byte policy apply after decoding. Outer
base64 encoding does not relax the payload parser's 65,536-byte bound.

Responses are one line with exactly `version`, `id`, `status`, `result`, `error`:

```json
{"version":1,"id":"UUID","status":"ok","result":"BASE64_EXACT_OUTPUT_JSON","error":null}
```

`result` is the public identity descriptor or `SignedReview.exportData()` output.
Failures have null result and a fixed code: `invalid_request`, `invalid_document`,
`identity_missing`, `identity_mismatch`, `identity_unavailable`, `identity_exists`,
`busy`, `unauthorized`, `timeout`, `cancelled`, `approval_failed`, or `unavailable`.
Cancellation uses status `cancelled`; all other failures use `error`. A frame
that cannot be parsed has the all-zero UUID response ID. No error echoes input.

Input must finish within 10 seconds; a native review expires after 300 seconds
(or sooner at document expiry). One native request at a time; there is no hidden
queue. Disconnect, extra frames, timeout, screen lock, sleep or user switch cancel
pending consent. Foreground loss resets the one-second visible-review guard for
starting an attempt, but preserves an already frozen authentication attempt.
Completion checks its captured attempt, connection token, request ID, document
revision, identity, time and liveness. A stale completion cannot finish a newer
request. Manual modal panels reject incoming requests as busy; the reviewed
document must equal the captured request document. Reconnection requires a fresh
request and fresh review. Success
returns directly to the waiting CLI and consumes approval; no save dialog/courier
is involved. Manual open/save paths remain available separately. No payloads or
private key material are logged, persisted as drafts or sent through diagnostics.

## Explicit native review modes

1. **Event:** opens one untrusted UTF-8 event and, for action authorization, its
   exact typed request sidecar. Supported kinds are `human.statement`,
   `agent.delegation`, `action.authorization`. All require `session:null`.
2. **Statement batch:** the native multi-file picker loads 1–16 exact
   `human.statement` payloads, at most 256 KiB combined. IDs must be unique;
   project/author/key/audience/group/epoch must be identical. Every complete
   payload is displayed in fixed order. There is no append/replace operation
   after authentication. Other event kinds cannot join a batch.
3. **Registry:** a separate file picker and approval label show an entire
   registry trust change. The strict schema matches `yhes-wire`'s registry
   fields, participants, GHES identities/controllers, keys and revocations.
   Humans may use `ghes:null` for an explicit local identity with no enterprise
   account claim; a present GHES claim remains strictly validated.
   Generation/predecessor, sorted uniqueness, key-ID/public-key binding and
   times are checked. P-256 and Ed25519 participant keys are validated by
   `yhes-wire::PublicKey::new` through a bounded statically linked Rust/C bridge,
   including curve and weak-key rejection. No curve arithmetic is reimplemented.

Opening a file is not approval. The app labels drafts **not approved** and
shows the exact bytes, digest and scope. Approval requires the mode-specific
action button, then a fresh Touch ID context. The unchanged review must first be
visible for one second in the active key window; there is no default Return-key
approval. Registry approval
explicitly names identity/key/revocation bindings. The public authority descriptor
must be pinned independently; the registry cannot authorize its own signing key.
Local parsing does not authenticate GHES evidence or a prior registry checkpoint.
The verifier/core must enforce authority threshold, chain, revocations and freshness.

A backend attempt contains an immutable `FixedSigningPlan` built before
Touch ID. `SecureEnclaveRoot.sign(attempt:)` accepts only its one-use handle,
**no payload argument**. One fresh `LAContext` is used for this fixed plan and
invalidated on completion/error/cancellation. A batch shares this context solely
among its frozen statements. The OS may prompt again; ACLs and reuse settings
are never weakened to force a single prompt. No result from a partially failed
batch is exported. Revision, time and cancellation are checked throughout and
before export; changing mode or bytes invalidates the old review.

This is the low-prompt alternative to a timed signing oracle. No session key,
30-minute authentication cache or future-signing grant exists. Code signing and
Keychain isolation do not distinguish human Send clicks from same-user UI
input automation; future statements therefore require a new fixed review and
fresh authentication.

## Event and action schema

Bodies: `human.statement: {text}`; `agent.delegation: {agent, agent_key_id,
purposes}`; `action.authorization: {action, request_digest, performer}`.
Delegation purposes are sorted/unique, limited to `action.execute`,
`agent.message`, `agent.relay`, `ticket.action`.

Action sidecars follow the team contract: all project/action/performer/group/
epoch/audience fields and the exact request digest must match. Actions are
`group.create`, `group.add`, `group.remove`, `ticket.recover`; parameters are
strictly typed. `stop_evidence` is a nonempty string, `expected_revision` a
nonnegative integer. Creation requires epoch zero and the performer's singleton
audience. Hash-only, shell and deployment requests are refused. The core must
verify that claimed stop evidence and current state justify execution.

The local identity is bound to one author/project. Statement validity is at most
1,800 seconds, action authorization 300 seconds, and an explicitly reviewed agent
delegation seven days. Registry validity is at most seven days. These are document
lifetimes, not authentication caches. All must
be current, with no local clock-skew allowance. Group/epoch are paired for statements/actions. An `agent.delegation` may bind
a group with `epoch:null`, explicitly granting group-wide authority across epochs.
IDs use `[A-Za-z0-9][A-Za-z0-9._-]*`, at most 128 bytes, without `..`.
Audiences contain 1–128 sorted unique IDs. Each input is at most 65,536 bytes /
eight nesting levels; decoded strings at most 32,768 UTF-8 bytes. Invisible
format/control characters (except tab/newline/carriage return), duplicate and
unknown keys, fractional/exponent numbers, negative zero and unknown versions
are refused. Registries allow at most 128 participants, 256 keys, 256 revocations.
These bounds are deliberately stricter than the broader wire parser.

## Outputs

Event and registry outputs are standard DSSE envelopes:

```json
{"payload_type":"application/vnd.agent-yhes.event.v1+json","payload":"BASE64_EXACT_BYTES","signatures":[{"key_id":"k_SHA256HEX","algorithm":"p256-sha256","signature":"BASE64_RAW64"}]}
```

Registry mode uses `application/vnd.agent-yhes.registry.v1+json` instead.
PAE is `DSSEv1 <type byte count> <type> <payload byte count> <payload>`.
Type lengths are 40 (event) and 43 (registry). Raw P-256 ECDSA `r||s` signs
SHA-256 of PAE and is locally verified before export. Payloads are never
reserialized. Both low-S and high-S signatures are accepted. A signature under
one payload-type domain cannot authorize the other.

Batch export is a native **container**, not a new trusted wire kind:

```json
{"format":"yhes.reviewed-batch.v1","batch_digest":"SHA256HEX","envelopes":[{"payload_type":"application/vnd.agent-yhes.event.v1+json","payload":"BASE64_EXACT_BYTES","signatures":[{"key_id":"k_SHA256HEX","algorithm":"p256-sha256","signature":"BASE64_RAW64"}]}]}
```

`envelopes` contains actual DSSE objects. Consumers must extract and
verify every envelope independently and apply ordinary replay rules. The outer
container/digest does not prove atomic delivery, a session grant or remote
biometric attestation. Its digest is SHA-256 of
`agent-yhes/reviewed-statement-batch/v1\0<count> ` followed, in reviewed order,
by `<decimal payload byte count> <exact payload>` for every statement.

Key IDs are `k_` + lowercase SHA-256 of
`agent-yhes/key/v1\0p256-sha256\0` + the 65-byte uncompressed SEC1 key.
Public identity export has exactly `algorithm`, `key_id`, `public_key` (base64
SEC1), `author`, `project`; it is public metadata suitable for independent
pinning, not proof of enrollment. No root/session/storage secrets are exported,
printed or sent to agents/core. Wrapped enclave handles stay in protected Keychain.

## Pure Swift interfaces

```swift
ValidatedEvent.parse(_ payload: Data) throws -> ValidatedEvent
ActionRequest.parse(_ payload: Data) throws -> ActionRequest
ValidatedRegistry.parse(_ payload: Data) throws -> ValidatedRegistry
StatementBatch.init(payloads: [Data]) throws

enum ReviewedDocument {
    case event(ValidatedEvent, ActionRequest?)
    case statementBatch(StatementBatch)
    case registry(ValidatedRegistry)
}
ReviewState.replace(with: ReviewedDocument)
ReviewState.invalidate()
ReviewState.checked(revision: UInt64, identity: SigningIdentity, now: Int64) throws -> ReviewedDocument
FixedSigningPlan.init(document: ReviewedDocument, identity: SigningIdentity, now: Int64) throws
FixedSigningPlan.sign(using: some EventSigning, now: () -> Int64,
                      checkCancellation: () throws -> Void = {}) throws -> SignedReview
OneUseSigningPermit.take() throws -> FixedSigningPlan
OneUseSigningPermit.invalidate()
SignedReview.exportData() throws -> Data

DSSE.pae(payload: Data, kind: DSSEPayloadKind = .event) -> Data
DSSE.envelope(payload: Data, signature: Data, publicKey: Data,
              kind: DSSEPayloadKind = .event) throws -> Data
```

`EventSigning` is a pure-test dependency seam, never a production endpoint or
runtime flag. Test software signers are linked only into the test target. A
revision or permit is not proof of human action; native review plus protected
biometric signing supplies the production boundary. Legacy single-event pure
APIs (`ApprovalState`, `EnvelopeSigning`) remain available.

## Build and public-key bridge

Run `scripts/test.sh` for the pure Rust and Swift suites or `scripts/build-app.sh`
for an inert preview under `build/Preview`. For a usable local build, connect the
Apple Developer account in Xcode Settings > Accounts, run `scripts/provision.py`,
then `scripts/build-app.sh --signed`. Dedicated development profiles are required
authorizing both dedicated app IDs; Xcode's newly created team wildcard is
accepted only for the pinned team. An unrelated product profile is refused, and
the signed code retains exact dedicated IDs and exclusive Keychain groups. Signing is local only: no
notarization, archive upload or key export. The signed helper lives inside
`build/YhesSigner.app/Contents/Helpers/Engine.app`, with the public executable path
`Contents/Helpers/yhes` (symlink to its `Contents/MacOS/yhes`). Engine keychain group
is `25C9H9N953.com.agent-yhes.engine.vault`; signer group is
`25C9H9N953.com.agent-yhes.YhesSigner`. The engine build sets `YHES_SIGNING_TEAM`
only at compilation. Native team and bundle IDs are source constants.

Build and test scripts first run `scripts/prepare-validator.sh`,
which builds the root workspace's `yhes-wire-ffi` static library with `--locked`
into `.build/rust`. For direct `swift build`/`swift test`, run that preparation
script first and again after changes to the verifier/bridge. SwiftPM links the
exact archive path; a missing archive fails the link. There is no weaker fallback
or validator subprocess at runtime. Rust/Cargo and the checked-in workspace
lockfile are build prerequisites. The current scripts target the host architecture.

The C shim accepts only public-key algorithm codes 1 (Ed25519/raw32) and 2
(P-256/uncompressed SEC1-65), exact lengths and nonnull buffers. Swift supplies
scoped `Data` storage. Rust delegates to the verifier and contains panics at the
ABI boundary. This does not make arbitrary invalid C pointers safe; the private
in-process shim must honor its readable-buffer contract. The bridge handles no
private keys, signing, enrollment, Keychain, network or environment inputs.

## Integration status

`TrustedApplication.teamID` is pinned to `25C9H9N953`. Unsigned/ad-hoc preview
builds still fail before the listener, Keychain or biometrics. The signed local
build requires valid provisioning authorization for both dedicated app IDs. The
initial 2026-11-14 `No Accounts` blocker was resolved by user sign-in; explicit
shared schemes/current Mac destination then registered this Mac and successfully
built both provisioning targets. Xcode generated a new team wildcard profile;
exact code-signing identities/groups remain enforced. No unrelated identity was
reused. Provisioning success is not biometric or end-to-end acceptance. See
[`docs/MACOS-SIGNER.md`](../../docs/MACOS-SIGNER.md).

Interoperability fixtures in `Tests/YhesSignerCoreTests/Fixtures` use known TEST
scalar 1. They include exact statement payloads with low/high-S signatures and
an exact P-256-signed registry. No fixture represents enrollment or human action.
