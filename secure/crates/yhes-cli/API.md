# yhes-cli interface

The `yhes` command line for the first local pilot: two persistent agent profiles
(`codex`, the group owner, and `claude`) in group `team` on one Mac. It uses the
existing core through [`PILOT-API.md`](../yhes-core/PILOT-API.md) and the native
signer through the socket protocol in
[`USABLE-PILOT-CONTRACT.md`](../../../docs/USABLE-PILOT-CONTRACT.md).

It has no command that signs caller-chosen bytes, exports private state or
asserts a receipt, and no flag, environment variable or file that selects a
software signer or another key provider.

## Layout

| Path | Content |
| --- | --- |
| `src/main.rs` | Production binary. Hard-wires `NativeSigner`, `PlatformCustody` (the core's `PlatformKeychain`) and the system clock. |
| `src/lib.rs` | `run(argv, stdin, stdin_is_terminal, &mut Deps) -> Outcome`, argument parsing, `Failure`, the `Custody` and `Clock` traits. |
| `src/signer.rs` | Protocol v1 request encoding, strict reply validation, `SignerClient` transport trait, `identity` / `enroll` / `review`. |
| `src/native.rs` | macOS transport and peer authentication (`verify_peer`). |
| `src/profile.rs` | Private paths, the local pin file, vault create/open. |
| `src/flow.rs`, `pilot.rs`, `message.rs`, `report.rs` | Workflows. |
| `tests/` | Separate test binaries. `tests/support` holds the only software human key and in-memory custody; neither is linked into `yhes`. |
| `bin/yhes` (repository root) | Launcher. Execs the signed helper in `YhesSigner.app/Contents/Helpers/yhes` (build folder, then `/Applications`). It has no unsigned fallback and reads no environment variable. When the helper is missing it points to `build-app.sh --signed`. |

`Deps` is a Rust interface, the same kind of seam as the core's `KeyProvider`.
`main.rs` passes production values; nothing at run time can pass others.

## Commands

```
yhes pilot  --project PATH --human ID [--project-id ID]
yhes send   --project PATH --as AGENT (--text T | --body-file F | --stdin) [--operation ID]
yhes say    --project PATH --as AGENT (--text T | --body-file F | --stdin) [--operation ID]
yhes sync   --project PATH --as AGENT
yhes inbox  --project PATH --as AGENT [--no-sync]
yhes status --project PATH
yhes doctor [--project PATH] [--start-signer]
yhes help
```

`pilot` and `say` start the companion when its socket is absent or not listening.
The helper locates only its enclosing signer bundle, verifies the pinned disk
signature and hardening before launch, serializes concurrent startup, and waits
up to ten seconds for a verified live peer. No request is sent before live peer
authentication succeeds. Identity/permission failures never trigger a launch or
weaker fallback. Existing signing requests are not automatically replayed if a
connection drops. `doctor --start-signer` exercises startup without asking for a
key or approval; plain `doctor` remains read-only.

Standard output is one JSON object: `{"ok":true,...}` or
`{"ok":false,"error":{"code","message","hint","detail"}}`. Exit status is 0, 1,
or 2 for a usage error. Progress and "waiting for approval" lines go to standard
error. `help` prints plain text.

Text comes from `--text`, `--body-file FILE` (`-` for standard input) or
`--stdin`; with none of them, standard input is read when it is not a terminal.
One trailing newline from a file or pipe is dropped. Text is never written to
progress output or errors, and an unexpected positional argument is rejected
without being echoed. Limits: 65,536 bytes for `send`, 32,768 bytes and no
control characters for `say` (the native review limits).

`--operation` names a send so a retry cannot send twice. The first use records a
digest of the command and text in the vault. The same name with other text, or
with the other command, fails with `operation_conflict`. A retry returns
`"replayed": true` and publishes the stored packet if that had not completed.

### What the result fields mean

| Field | Meaning |
| --- | --- |
| `author` | The agent profile whose enrolled key signed and sent the event. Always an agent on this channel. |
| `kind` | `agent.message` (from `send`) or `agent.relay` (from `say`). |
| `human_original_author` | Set only when the core verified a human device-key statement inside the relay. Otherwise `null`. |
| `human_authored` | The core's flag for the outer event. False for both kinds: a relay is agent-authored and carries a human original. |
| `origin` | `agent` or `human-statement-relayed-by-agent`, derived from the two fields above. |
| `text` / `human_text` | Agent message text, or the human's exact statement. `note` is the agent's relay note (this CLI sends none). |
| `replayed` | In `sync`: the core's flag, true for a stored earlier result. In `inbox`: true unless this same command verified the record just now. A replayed entry reports acceptance at `accepted_at`, not current authority. |
| `new` (inbox) | False once an earlier `inbox` call has listed the entry. A reading aid kept in the vault, not a security property. |
| `receive_before` | The event's expiry. A recipient that has not synced by then cannot admit it. For `say` this is 30 minutes after approval, because the human statement is re-verified on receipt. |
| `key_custody` | `platform-keychain` in the `yhes` binary. The test custodian reports `injected-test`. |
| `ghes` | `null`. The pilot registry claims no GHES account for the human. |

`say` asks for one statement in signer mode `event`. It never uses `batch`, and
no result describes a batch.

## Setup (`pilot`)

Every stage is decided from durable state, so a rerun continues and repeats no
committed operation. `stages` in the result says `completed` or `already-done`
for each.

| Stage | Durable evidence | Human review |
| --- | --- | --- |
| `identity` | `pin.json` in the private folder | Key setup, once, if the signer has no key |
| `vaults` | Vault files; storage key and checkpoint in `Custody` | none |
| `registry` | The vaults' registry chain (`Engine::registry_chain`); `registry-next` checkpoint for an approved envelope not yet installed everywhere | Full registry, generation 1 and each renewal |
| `delegations` | `grant` checkpoint in each agent's vault | One per agent |
| `group_create` | `create` checkpoint (approved control), outbox, group status | `group.create` authorization |
| `group_add` | `add` checkpoint, outbox, group status | `group.add` authorization |
| `join` | `claude` group status | none |

Rules the code follows:

- The signer's descriptor becomes the single registry authority and the human's
  device key. `pin.json` only lets the CLI find it again; the vault's trust
  fingerprint is the enforced pin, and a changed file makes `Engine::open` fail.
  A second `pilot` with another `--human` or `--project-id` is `pin_mismatch`.
- The whole pin is bound to each vault. On first setup a digest of the pin is
  stored as the `pin-binding` checkpoint; every later open requires the same
  digest and fails with `pin_changed` before any output or action. The binding
  is never rewritten, so an edited name cannot be adopted, and `status` prints
  no pin field when a vault refuses it. Renewals do not touch the pin.
- A signer result is accepted only if its payload equals the bytes the CLI sent
  and its one signature verifies under the pinned key. The bootstrap head digest
  is taken from that envelope. Files under the project folder are never read to
  choose a key or a head.
- Registry and delegations last seven days, key entries 30 days. `pilot` renews
  them when less than a day remains: the next registry generation with the same
  participants, and new delegations. Until then `send` fails with
  `delegation_expired` or a verification error. Nothing is extended silently.
- Delegations carry group `team` and no epoch, purposes `action.execute`,
  `agent.message`, `agent.relay`. Statements and authorizations name the exact
  current epoch.
- An approved membership control is stored encrypted before it is used, so a
  crash after approval needs no second Touch ID. If its five-minute approval has
  expired, the stored control is refused by the core and a new approval with new
  event and operation IDs is requested.
- After each membership publication both profiles sync at once, before the next
  review opens. A membership record that was prepared but could not be published
  before its approval expired is reported with a recovery hint; it is not
  re-timestamped.

The human sees six native reviews on first setup: key setup, registry, two
delegations, group creation, member addition.

## Private and shared state

- Private: `~/Library/Application Support/agent-yhes/engine/<first 32 hex of
  SHA-256(canonical project path)>/`, mode 0700, with `pin.json` (0600) and
  `<agent>/vault.db`. The home folder comes from the password database, not
  `$HOME`. Only `pilot` creates directories; other commands change nothing when
  no setup exists.
- Keychain reference: `p<hash>-<agent>`, used for both the vault key and its
  checkpoint.
- Shared: `<project>/.agents/messages/secure/`. Records are written and read
  only by the core's `LocalChannel`. The CLI adds
  `identities/registry-<generation>.json`, the public signed registry.
- CLI checkpoints in the vault (`client_put`): `grant`, `registry-next`,
  `create`, `add`, `op-<operation>`, `inbox-shown`, `pin-binding`.

## Signer peer authentication

Before any request byte is written, `NativeSigner` reads the peer's audit token
with `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`, resolves it with
`SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` and checks, with strict
validation:

```
anchor apple generic and identifier "com.agent-yhes.YhesSigner" and certificate leaf[subject.OU] = "<TEAM>"
```

The requirement alone is not accepted. The same code object must also have the
hardened runtime in its signature and in its live kernel status, be valid, not
ad-hoc or linker-signed, not debugged, and hold none of these entitlements as
true: `get-task-allow`, `cs.disable-library-validation`,
`cs.allow-dyld-environment-variables`, `cs.allow-unsigned-executable-memory`,
`cs.allow-jit`, `cs.disable-executable-page-protection`. `verify_peer` runs both
checks before the signer's descriptor is read or any document is sent.

`<TEAM>` is compiled in by `build.rs` from `YHES_SIGNING_TEAM`. A build without
it reports `signer_unconfigured` for every approval; `send`, `sync`, `inbox` and
`status` do not need the signer. The peer UID, the 0700 folder and the socket
file type are checked as well and are not treated as identity. No PID is used.

The native transport accepts only a `p256-sha256` human key
(`SignerClient::accepts`). A descriptor or pinned key of another algorithm is
refused with `signer_algorithm_rejected` before any review is requested.

Replies are one line of at most 1 MiB with exactly `version`, `id`, `status`,
`result`, `error`. Unknown, duplicate or missing fields, another request's `id`,
non-canonical base64 and free-text error codes are refused. The read timeout is
330 seconds for a review, 15 for `identity`.

## Tests

`cargo test -p yhes-cli` from `secure/`. 23 tests:

- `pilot_flow` (7): an edited pin (same key, other human name) is refused by every command and cannot be rebound; full setup, send, say, inbox and reopening the vaults on
  every command; the same flow with a P-256 human key in the native format
  (65-byte SEC1 public key, raw 64-byte signatures) behind a P-256-only
  transport; a failed review at each of the five setup approvals (cancel, busy,
  malformed reply) followed by a rerun that asks only for what is missing;
  named operations sent once; expiry stops sending until the human renews.
  Real core, vault files and local log; software human key and in-memory custody.
- `signer_boundary` (7): malformed replies, a reply for another request, a
  replayed earlier approval, a signature over other bytes or by another key,
  cancel, busy, and an unexpected key algorithm. Each checks that nothing was
  stored or published.
- `peer_identity` (3): the real macOS check against live processes.
  `/usr/bin/ssh-agent` (Apple-signed, hardened) passes the full check for its
  own identity and fails the signer's. `/usr/bin/nc` (Apple-signed, not
  hardened) passes its requirement and fails the full check. An unsigned
  same-user listener fails.
- `native` unit tests (3): the hardening decision for each flag and each
  forbidden entitlement.
- `cli_surface` (3): usage, input sources, and that signing, export, receipt
  and test-key commands or flags do not exist.

Not covered by software tests: `PlatformKeychain` access and the signer socket
with the signed app. Both need the signed, provisioned build.
