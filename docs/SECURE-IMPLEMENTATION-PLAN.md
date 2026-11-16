# Secure implementation readiness

**Network-pilot update, 2026-11-15:** [the two-person team CLI](TEAM-PILOT.md)
now provides explicit authority/bootstrap pinning, native-reviewed enrollment
proposals, founder-approved membership, secure Git publication and NATS-triggered
receipt after Git confirmation. Disposable independent-client tests exercise
real Git and NATS; hosted GHES and actual two-Mac enrollment remain pending.
The local human enrollment and actual Codex–Claude trial succeeded on 14 November;
see [validation](VALIDATION.md). Source releases are tracked in
[RELEASES.md](RELEASES.md) under `MIT OR Apache-2.0`; the dated notes below
preserve earlier milestone snapshots.

**Usable-pilot update, 2026-11-14:** [the signed local client](LOCAL-PILOT.md) now
connects setup, native approval, encrypted delivery and inbox/status commands.
It includes authenticated local IPC and a sealed local-log adapter. Provisioning,
signed peer authentication and a disposable production Keychain probe were
verified. The first real human enrollment request timed out before approval;
successful human signing and cross-harness use still need manual acceptance.
Secure Git/NATS, secure ticket execution and historical-admission evidence were
recorded as later integration work at that milestone.

**Implementation update, 2026-11-14:** the event/action verifier, private
transactional MLS core, macOS signer prototype and GHES proof adapter are now
implemented. See [the implementation guide](../secure/README.md) for commands,
acceptance evidence and the remaining integration gates. The plan below records
the starting point; its final statement about unchanged runtime code is historical.

The proposed timed human-signing session has been replaced in the first native
profile by a fixed batch of reviewed statements per fresh Touch ID confirmation.
Arbitrary later payloads remain outside that approval. Long-offline membership
acceptance needs independently verifiable timing evidence before transport
integration; sender-controlled timestamps will not substitute for it.

2026-11-13. **The transaction, retry and Git-ordering experiments passed. There
is enough evidence to start the implementation with a concrete adapter contract.**
The result is an implementation path, not a completed security release. The
existing v0.3 runtime still needs authenticated identities, signed actions,
encrypted storage, MLS integration and the native human signer.

## Decisions and constraints

The user has established: GHES **3.21.9** as the enterprise target; humans and
agents as distinct parties; preserved human signatures when an agent relays a
message; Apple Touch ID as the first human signing-device profile; infrequent
routine authentication and fresh confirmation at major security boundaries;
multiple-recipient encryption; Git and realtime participation; and verifiable
traces in the first security-capable version.

The recommended implementation choices are MLS/OpenMLS for group encryption,
a Rust service owning private state, and the existing Python Git/NATS transport
behind an opaque-record boundary. The proposed 30-minute signing window and
five-minute inactivity timeout remain policy defaults to review, not user-fixed
requirements. (Repository licensing has since been set to `MIT OR Apache-2.0`.)

## Experiment results

[Reproduction instructions](../evaluations/e2ee/atomic/README.md) and
[recorded results](../evaluations/e2ee/atomic/results.json) accompany the code.

| Gate | What was observed |
| --- | --- |
| Rejected Welcome | Its key consumption stayed inside the aborted transaction; the later valid join succeeded. |
| Process dies before local commit | Durable state and outbox stayed unchanged. |
| Process dies after local commit | Retrying the operation returned identical stored ciphertext without advancing state again. |
| Git accepts before the sender records acknowledgment | Recovery found the existing record; no second Git commit or re-encryption occurred. |
| Receiver dies after commit, before returning plaintext | The durable inbox supplied the same result on retry; the message was not lost with its consumed receive key. |
| Two membership changes race | Exactly one Git push won. The loser cleared its pending change, consumed the winner and rebuilt a new attempt. |
| Membership convergence | Four databases reached epoch 3 with the same exporter-derived comparison hash. |
| An old-epoch message is still unsent | Publication was refused; the adapter did not silently re-encrypt for a changed audience. |
| An old database loses an accepted own send | The client was quarantined instead of reusing the restored state. |
| Git object contents | Accepted and rejected/unreachable fixture blobs contained ciphertext/public metadata, with no fixture plaintext or private-state fields. |

There were **36 process/Git checks** and **12 native-provider checks**, across
the X25519/Ed25519 and P-256 suites. They passed on macOS with disposable identities.
The native `openmls_sqlite_storage 0.3.0` provider used bundled SQLite 3.50.2.

## Native storage choice

The pinned upstream SQLite provider accepts a borrowed `rusqlite::Connection`.
The native probe demonstrated that provider writes and our own outbox/inbox
inserts participate in the same explicit transaction. This lets us use the
upstream provider instead of carrying the experiment's private JSON snapshots
across a Python subprocess boundary.

Run provider migrations on the connection before normal message transactions.
Within an operation, use a fresh mutable group object loaded from the transaction's
state. If processing aborts, discard that object as well as rolling back SQL;
otherwise its in-memory mutations may survive the database rollback.

References: [pinned SQLite provider](https://docs.rs/openmls_sqlite_storage/0.3.0/openmls_sqlite_storage/),
[SQLite atomic commit](https://www.sqlite.org/atomiccommit.html).
The project’s current main-branch SQLx examples describe a different provider;
implementation should follow the pinned rusqlite API tested here.

## Transaction contract

| Operation | One local transaction must cover |
| --- | --- |
| Prepare send | Advanced sender state, immutable ciphertext, operation ID, private request fingerprint and outbox status. |
| Receive application message | Advanced receiver state plus a durable, protected inbox record. |
| Stage membership change | Pending MLS state and its exact Commit/Welcome bytes. |
| Accept own membership change | Merge of the matching pending state and the recorded remote acceptance. |
| Reject a losing membership attempt | Clearing the pending change and recording that attempt's rejection, without rolling back unrelated state. |

Release ciphertext to transport only after local commit. Release a plaintext
result to the participant only after its inbox record is durable. Git calls,
broker calls and Touch ID prompts occur outside the database transaction.

Retries of an uncertain send use the same operation ID and ciphertext. A changed
request cannot reuse that ID. A membership attempt can be rebuilt only after its
rejection is established; it gets a new attempt identity and a policy recheck.
Never discard pending MLS state merely because a push timed out.

## Git and membership contract

Git orders published records; it does not establish that their authors were
authorized. The secure client must derive accepted state from verified signed
events, not trust an editable `group.json` or the commit's author string.

Membership events need a group ID, base epoch/state binding, authorized action,
operation/attempt identity and signature evidence. Consume accepted membership
changes in order, retaining the last applied checkpoint with local crypto state.
Application messages can tolerate bounded reordering through MLS; membership
changes need their preceding epoch.

Pending membership blocks new outgoing application encryption for that group.
An unsent packet prepared for an older epoch stays immutable. If its audience
changed, publishing it needs an explicit new authorized attempt. A grant bound
to an old roster cannot be silently widened during a rebase.

Rejected Git pushes can leave objects in a mirror or server object store. Their
unreachability is not a confidentiality control. All transport candidates must
already contain only ciphertext and approved public metadata. Removal protects
new-epoch traffic; an in-flight old-epoch message may remain readable to its
original recipients.

## Identity, signatures and input rejection

GHES account identity must include the enterprise instance and immutable user ID.
Enroll device public keys through a protected bootstrap/approval path, and sign
the registry changes, delegations and revocations. An agent's key is distinct
from the human device key. Role, controller and permitted scope are derived
from verified bindings, never from a sender-supplied human/agent label.

Preserve the original human-signed event inside an agent-signed relay. Bind
signatures to the complete event, project, audience, purpose and replay identity.
Enterprise commit signing is an additional transport requirement, separate from
the signature identifying the message author. GHES's persistent Verified badge
does not substitute for current key and authorization checks.

Different failure stages need deliberate behavior:

- Invalid wire/cryptographic input: abort without committing key consumption.
- Unauthorized Welcome or membership change: abort the candidate transition;
  keep the group unchanged or explicitly disputed pending an authorized resolution.
- Authenticated application ciphertext with an invalid inner signature/policy:
  record a protected quarantine/disposition and the appropriate receive-state
  progress; expose no trusted instruction or claimed human provenance.
- Valid message with temporarily unavailable identity evidence: retain it as
  pending verification, with no implicit permission downgrade.

These policy paths are not implemented by the disposable BasicCredential tests.
They become acceptance tests for the verifier before real participants are enrolled.

## Human signing service

The first profile uses a Secure Enclave P-256 key and Touch ID in a trusted native
macOS signer. The human root key never enters MLS provider storage, Python IPC,
an agent environment or a general-purpose signing socket. Routine communication
uses a bounded session grant enforced by the signer; agents continue using their
own delegated keys. New authority, new confidential audiences and other defined
major boundaries require fresh action-bound confirmation.

Show the actual action and audience before signing. Recheck the approved scope
against current state when executing. Lock/user-switch/expiry ends the local
signing session. Authentication failure and unavailable biometrics fail closed;
test signers must be injected in test targets, never enabled through a production
environment bypass.

Peers can verify the enrolled key and signed grant. A claimed biometric assurance
level is evidence from the trusted signer, not generic remote hardware attestation.
The enrollment path and any enterprise attestation requirement must remain explicit.

## Private storage and restore policy

The experiment's databases deliberately use plaintext disposable secrets.
Production must encrypt private MLS state, signing-session material and inbox
payloads at rest, including WAL/journal and backup exposure. Select an encrypted
database/connection or a reviewed private-storage layer that keeps the shared
transaction boundary. A process-global encryption key hidden inside a static
serialization codec is not the intended design.

Private request fingerprints stay private. Publishing a hash of predictable
plaintext arguments can enable guessing, even when the message body is encrypted.
Public traces should reference ciphertext/event digests and approved metadata.

An encrypted database can still be stale. The experiment detected one concrete
rollback case through accepted own operations in Git; it does not detect every
offline rollback. Require a verified external checkpoint/freshness check before
resuming restored state. If consistency cannot be established, quarantine the
old state and enroll a fresh MLS device through an authorized recovery flow.
Checking out an old software tag must never restore an old ratchet database.

## Implementation slices

1. **Freeze the secure event and verifier contract.** Define signed fields,
   canonical encoding/domain separation, enrollment/delegation purposes,
    audience binding, revocation rules and the secure-channel bootstrap. Bind
    ciphersuite selection to signed policy and reject unsupported choices without
    silently falling back. Reject
   unsigned legacy records in the secure profile; import old notes explicitly as
   historical data rather than relabelling them verified.
2. **Build the native Rust state service.** Pin the tested OpenMLS/provider versions,
   add protected storage and a typed local API returning public packages, opaque
   ciphertext handles and verified application results. Port the process-kill and
   ordering tests to its actual database. Private state has no export API to harnesses.
3. **Add GHES identity and the native human signer.** Implement the verified registry,
   signed agent delegations, human originals/agent relays and action-specific grants.
   Test with disposable keys first; real Touch ID enrollment is a separate explicit step.
4. **Integrate Git and NATS.** Verify signatures and logical transitions, publish
   only sealed records, resolve ambiguous outcomes, consume ordered epochs and
   preserve the existing separation of broker transport and application receipts.
5. **Exercise the complete boundary.** Test unauthorized joins, forged human labels,
   relayed-content edits, revoked keys, recipient expansion, restored databases,
   fresh-confirmation failures, and multi-device reconnect. Then run an actual
   human/agent trial before tagging the security-capable release.

The first implementation work can now start with slices 1 and 2. Further experiments
should become acceptance tests for those modules rather than another open-ended
library comparison. No production runtime code, commit or tag was changed here.
