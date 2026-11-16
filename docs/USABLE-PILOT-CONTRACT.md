# First usable local pilot — working contract

2026-11-14. User requested a usable version after opening the signer prototype.
Deliver a real local CLI and native approval workflow for user-entered messages,
using the existing signed/MLS core. Preserve earlier v0.1/v0.2/v0.3 work. No project
commits, tags, push or external messaging/publication during this task.

## Scope and ownership

- Root: core public APIs, local authoritative transport, integration/acceptance,
  packaging coordination, documentation and final usability test.
- Claude: NEW `secure/crates/yhes-cli/**` and `bin/yhes` only. CLI, workflows,
  native signer client, local configuration. No core/native edits.
- Codex: `native/YhesSigner/**` and `docs/MACOS-SIGNER.md` only. Native request
  listener, enrollment/review UX, progress, local signed packaging/provisioning.
- Grok: `secure/crates/yhes-core/src/{keys,anchor}.rs` and `docs/KEY-CUSTODY.md`
  only. Atomic protected checkpoint publication; macOS identity/provider review.

Use Teerminal parent messages to coordinate actual API changes. Read this file;
do not guess schemas from card titles. Software tests use injected dependencies
only. No runtime flag can bypass production biometric/Keychain checks. Real human
key setup occurs only through the user's native review and Touch ID. Disposable
storage-key probes may be explicitly scoped, must never output secrets and must
clean up only their own records. Production data is not test input.

## Shipping identity

This Mac has a valid Developer ID Application certificate for Jarkko Lietolahti,
Team ID `25C9H9N953`, and an Apple Development certificate for the same team.
The project has not selected public distribution yet. Use a locally signed build
and valid provisioning for its dedicated app IDs. Do not reuse another product's
bundle identity/profile or lower the existing keychain checks. Do not notarize or
publish. Profile creation through Xcode automatic signing is within local build
preparation; report missing external account access instead of bypassing it.

Signer bundle ID remains `com.agent-yhes.YhesSigner`. Engine executable identity
is `com.agent-yhes.engine`. They retain distinct Keychain groups. Signing config
is chosen at build time and bound into the signed artifact, never a runtime
untrusted environment override. Native build must include/locate the engine helper
and make `bin/yhes` executable with the same functionality as that helper.

## Local signer protocol v1

Socket: `~/Library/Application Support/agent-yhes/signer.sock`, inside a private
0700 directory. Limit one line of UTF-8 JSON per connection to 1 MiB. No payload
logging. Authenticate the peer with Darwin LOCAL_PEERTOKEN and Apple's code-signing
APIs, using the audit token rather than a caller-provided PID. CLI accepts only the
pinned signer ID/team; signer accepts only the engine ID/team. Same-UID checks and
socket file permissions are additional checks, not identity proof. A second live
app instance must not remove the first one's socket.

Requests have exactly version=1, id (UUID string), operation, author, project,
mode, payloads, request. Unknown/duplicate fields fail. Fields unused by an
operation are null or empty as described below, not arbitrary extensions.

- `identity`: author/project expected IDs; mode=null, payloads=[], request=null.
  Read the existing public descriptor, require matching author/project. No prompt
  or key creation; missing identity returns `identity_missing`.
- `enroll`: same fields. Queue an explicit native key-setup request displaying the
  author/project; the user approves and uses Touch ID. Never overwrite a key.
- `review`: author/project; mode `event`, `registry` or `batch`; payloads is a
  nonempty array of base64 exact UTF-8 bytes (one for event/registry); request is
  base64 exact sidecar bytes for action.authorization, otherwise null. The native
  UI displays the immutable review and requires human approval, then fresh Touch ID.
  The existing statement batch policy is unchanged; no privileged batch is added.

Response has exactly version=1, id, status (`ok`, `cancelled`, `error`), result,
error. Result is a base64 exact UTF-8 JSON document on success, else null. For
identity/enroll it is the existing public descriptor. For review it is the existing
SignedReview.exportData output. Error is a fixed bounded string code on failure,
else null. No private key, enclave handle, storage key or biometric fallback is sent.

A disconnected/timed-out request invalidates its pending review and cannot receive
later signatures. One review at a time; other callers get `busy`, not hidden
approval queueing. Existing manual open/save flows remain available. A successful
IPC review returns directly to its waiting engine client; the user need not copy
JSON between tools. Foreground changes must not silently approve/carry a stale review.

## Usable CLI

Workspace crate `yhes-cli`, executable `yhes`. Provide help and JSON results/errors.
The normal entry point is `bin/yhes pilot --project PATH --human ID` (two profiles:
`codex` and `claude`, group `team`). It should guide native enrollment/registry,
delegations and group-create/add approval; persist each completed stage and resume
without duplicating committed operations. No fixture human keys in this binary.

Then support user-written content:

- `yhes send --project PATH --as codex --text TEXT` (agent-authored).
- `yhes say --project PATH --as codex --text TEXT` (request an exact human statement
  from the native signer, preserve it in an agent relay, then encrypt/publish).
- `yhes inbox --project PATH --as claude` and `yhes status --project PATH`.
- `yhes sync --project PATH --as AGENT`, and `yhes doctor` for actionable setup errors.

CLI should accept stdin/body-file for text as well, so callers need not put private
message content in shell history. No generic raw-sign command, fake receipts,
private-state export, or production test-key option. Separate Rust test-only
integration fixtures may provide a fake SignerClient and fake key custodian.

Private profile state belongs outside the shared project in a canonical private
application-support path. Vault keys/checkpoints come only from PlatformKeychain.
The initial authority public key comes from the authenticated native signer;
registry head pins must come from that approved exact registry. Shared project
configuration is data and cannot replace pinned local trust on reopening.

The local log contains only signed registries/public metadata/sealed packets under
`.agents/messages/secure/`; `.agents/tickets` stays available for later secure ticket
integration. All messages to a group use its full current roster. Exact outbox
packets and operation IDs survive retries. Public CLI return values identify human
original vs agent author and whether a delivery is historical/replayed. Messages
are data; no ticket or shell action is inferred from prose.

Local roles identify enrolled agent profiles on this device, not attested model
binaries. Authorized local user programs may invoke the CLI for these profiles;
remote identity derives from enrolled keys. This pilot does not claim isolation
between arbitrary hostile harnesses running as the same OS user.

## Root APIs to add

Core will expose current group status (logical id, owner, epoch, audience, pending),
protected metadata for CLI workflow checkpoints, verified inbox enumeration and
outbox enumeration. No raw Connection or private key accessor will be public.
Root adds a small local append/confirm adapter with exact record read-back; CLI
must not call receipt APIs with arbitrary caller-supplied strings. Exact names
will be published in `secure/crates/yhes-core/PILOT-API.md` before implementation.

Offline historical membership remains strict unless independently verified
acceptance evidence is introduced. Do not backdate verification from sender/Git
commit timestamps or weaken expired grants to make a demo pass. First pilot is
same-machine; Git/broker transport integration follows the same public boundary.
