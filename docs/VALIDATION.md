# Validation of this draft

## Source release checks — 2026-11-16

Before grouping the release tags, the secure source passed 166 Rust workspace
tests, two explicitly enabled real NATS/TLS tests, 12 simulator example tests,
strict all-target Clippy, 104 Swift tests and eight GHES fixture tests. The native
script also repeats three Rust bridge tests. The local/Git/broker and simulation
Python suites passed 54 checks across the main run and a separate opt-in simulator
run. These checks add no physical second-Mac or hosted GHES acceptance claim.

## Two-workspace same-Mac simulation — 2026-11-15

The README bootstrap prompt is now 15 words, with the workflow in
[BOOTSTRAP.md](../BOOTSTRAP.md). `bin/yhes-sim` prepares two separate workspace
roles and runs the existing team protocol through a separate Cargo example.
The native signer and production `yhes` entry point/providers are unchanged.
Every simulator result is marked as simulation; human consent and file-based
key custody are explicitly simulated, with no Touch ID or real human keys.

The example passed **12 tests**, strict Clippy and its build. Tests cover
persistent distinct P-256 identities, file custody/checkpoints, exact retry,
scope/role rebinding refusal, checkpoint races and confinement to the fixture
Git remote and loopback broker. Only the fixed realtime wait message is forwarded;
native-approval progress is suppressed to avoid claiming actual Touch ID consent.

The process-level manager suite passed **two tests**. Separate CLI processes
completed Alice/Bob bootstrap through real local Git, preserved distinct keys
and matching membership, observed a verified NATS wake-up, exchanged a reply,
verified a simulated human original inside an agent relay, and reopened history
without duplicates. Role-marker substitution was refused; Git objects contained
no test-message plaintext. A separate regression checks that inherited Git
directory/configuration variables cannot redirect fixture initialization.

```sh
CARGO_BUILD_JOBS=4 cargo test --manifest-path secure/Cargo.toml -p yhes-cli --example yhes_sim --locked
CARGO_BUILD_JOBS=4 cargo clippy --manifest-path secure/Cargo.toml -p yhes-cli --example yhes_sim --locked -- -D warnings
YHES_SIM_NATS_SERVER=/absolute/path/to/nats-server \
  python3 -m unittest discover -s tests -p test_simulation.py -v
```

The user's `yhes-demo1` and `yhes-demo2` workspaces were prepared as Alice and
Bob, with test private state in a separate cache lab and a managed loopback NATS
session. Broker authentication/ping passed. Their actor handshake was deliberately
left for the user's two agent sessions to perform from the short prompt. This
preparation is not evidence that those real harnesses have completed the exchange.
The simulation separates state under one macOS account; it does not establish
OS-user isolation, hardware custody or two real human approvals.

## Two-person Git and NATS pilot — 2026-11-15

The new `team-*` CLI connects independently stored human/agent profiles through
a dedicated Git branch, then uses NATS to wake receivers after Git publication.
The [team runbook](TEAM-PILOT.md) documents the actual commands, required trust
checks and current limits. This is a software network pilot; the hosted GHES
and physical two-Mac trial has not run.

The final workspace run passed **166 Rust tests**, with **two real-broker tests
run explicitly afterward; both passed**. Workspace/all-target Clippy passed with
warnings denied. The legacy helpers passed **21 local and 18 Git tests**, including
the new refusal of plaintext fallback when a secure team profile exists outside
the source worktree. Both agent skills passed their validator. Documentation
links and shell examples were checked without executing enrollment commands.

The network checks include:

- Two distinct P-256 test humans, separate private stores, explicit founder key
  and generation-1 payload-digest pins, a signed enrollment proposal and a
  founder-approved merged registry. Swapped authority/head, human/controller
  bindings and a valid KeyPackage for the wrong agent are refused.
- Real Git fetch/push, independent caches, fast-forward races, exact lost-ACK
  recovery, immutable public artifacts, rollback/rewritten ancestry rejection,
  isolated source indexes, URL credential rejection and bounded subprocesses.
- Explicit SSH commit signing with a disposable agent/key; the resulting Git
  signature was verified. OpenPGP and the fixed macOS HTTPS credential helper
  are implemented but have not been tested against real credentials or GHES.
- A real NATS Server 2.15.3 on loopback with separate client workers: an active
  receiver wakes through the broker, verifies the Git-confirmed encrypted
  message, preserves a human original inside an agent relay, and reopens history
  without duplicates. Valid ciphertext delivered only to NATS does not advance
  the recipient; later publication of those exact bytes through Git succeeds.
- Broker outage after Git publication reports pending notification while the
  recipient can still recover through Git. Server restart and notification retry
  preserve event identity. Untrusted broker bytes never become messages.
- TLS accepts the explicitly trusted test CA, rejects an unknown CA or wrong
  hostname, and refuses an existing stream with widened rollup settings.
  A long already-notified prefix does not exhaust the next flush's work limit;
  Git reconciliation errors are distinguished from broker-only outages.

The native signed app and nested helper were rebuilt and their signatures
verified. The packaged `bin/yhes help` lists the team, broker and explicit Git
signing/authentication options. A live `doctor --start-signer --project local-pilot`
authenticated the rebuilt app and opened both existing production-Keychain
profiles successfully. Their previous inbox counts (Claude 2, Codex 1), matching
epoch and empty pending/quarantine state remained intact. No native human
approval or new human-key enrollment was triggered by these checks.

Codex subagents implemented the Git adapter and team CLI; Grok independently
reviewed Git acceptance and broker boundaries. Fixes include checked public
artifact reads/publications, scoped SSH-agent inheritance, forbidden local hooks,
URL secret rejection, notification batching and strict stream configuration.
An early parallel test run hit a Git deadline; a separate inherited-file-lock
case led to an explicit-unlock guard and an isolated fork regression. Final
checks passed. No expiry rule was relaxed: an own unconfirmed membership packet
found after its approval expires still needs recovery, as does a late first join.

Commands used for final verification:

```sh
CARGO_BUILD_JOBS=4 cargo test --manifest-path secure/Cargo.toml --workspace --locked -- --test-threads=1
YHES_NATS_SERVER=/absolute/path/to/nats-server CARGO_BUILD_JOBS=4 \
  cargo test --manifest-path secure/Cargo.toml -p yhes-cli --test realtime_git --locked -- --ignored --test-threads=1
CARGO_BUILD_JOBS=4 cargo clippy --manifest-path secure/Cargo.toml --workspace --all-targets --locked -- -D warnings
python3 -m unittest discover -s tests -p test_protocol.py -v
python3 -m unittest discover -s tests -p test_remote.py -v
CARGO_BUILD_JOBS=4 native/YhesSigner/scripts/build-app.sh --signed
bin/yhes doctor --start-signer --project local-pilot
```

The NATS binary came from the official release archive; its SHA-256 was checked
before running. Only disposable test remotes, stores, SSH signing keys and TLS
certificates were used for network tests. Only disposable test remotes received
Git writes. No project/enterprise remote was pushed, no production server was
deployed, and no source commit or version tag was created.
The first team CLI remains limited to two people, one agent each and a fresh
online join. Registry renewal, membership recovery, GHES human-account binding,
team distribution and broker-only finality remain separate work.

## Live local acceptance — 2026-11-14

The user completed the guided setup and the native app reported the team ready.
Sequential `status` and `doctor` checks verified the saved `jarkko` identity,
current registry and delegations, and two real platform-Keychain profiles in
the same active `team` channel at epoch 1. Both reported the same membership
commit and audience, with no pending or unpublished work. Running diagnostics
simultaneously first caused mutual vault-lock conflicts; sequential reruns passed.

The user then authorized a real message trial. Root Codex used its `codex`
profile; a separate Teerminal Claude harness read and replied using `claude`.
The question and reply travelled through Yhes, not through copied harness output.

| Check | Observed result |
| --- | --- |
| Codex → Claude question | `message-d9bf6b06d177`, shared sequence 3; Claude received `agent.message`, `origin: agent`, `disposition: verified`, no human original. |
| Identical operation retry | Reusing `acceptance-20261114-codex-01` returned the same event with `replayed:true`, no new publication. |
| Claude → Codex reply | `message-a17434a0caa0`, sequence 4; Codex read the verified agent reply. |
| Human statement via Codex | The user approved the native review. `say` returned `relay-020f8868ddc7`, sequence 5; Claude verified original statement `statement-6208bc5b026b`, original author `jarkko`, relay author `codex`, and `origin: human-statement-relayed-by-agent`. |
| Exact human text | `This is a human-approved test message for the local agent-yhes pilot.` arrived unchanged; the relay had `note:null` and remained `human_authored:false` itself. |
| Durable readback | Separate CLI processes reopened both vaults. Claude retained the question and human relay once each; Codex retained the reply once. Subsequent reads returned `new:false`, `replayed:true`. |
| Shared records | All three application records contained ciphertext with `control:null`. The trial text was absent from decoded transport headers and ciphertext. This inspection supplements, rather than substitutes for, successful recipient verification. |
| Final health | Both profiles retained matching channel state and current grants. `doctor` returned `ok:true`; no pending operations, unpublished messages or quarantined entries. |

This establishes one successful local enrollment, setup approval sequence,
actual Codex–Claude exchange and human-approved encrypted relay on this Mac.
Signatures identify enrolled keys; they do not attest which model binary used a
profile. Network delivery, other machines, long-offline recovery, biometric-set
changes and lock/sleep failure cases were not exercised by this trial. No source
code was changed, and no commit, tag or push was made during acceptance.

## Guided setup and authentication lifecycle — 2026-11-14

After the user reported a cancelled enrollment and confusing setup, the native
window was changed to a compact Identity → Team → Permissions → Channel flow.
Setup runs the bundled, signature-verified helper, retains the selected folder
and IDs, and offers Resume or an explicit retry. Full keys/JSON remain available
in Details; manual file/key tools are in Advanced. The action button and fresh
Touch ID replace the separate checkbox. The helper reports `ready:true` only
after both profiles have the same active channel state and expected membership.

Source inspection found that losing app focus cancelled active authentication.
That is a possible cause of the user's cancellation, not an established diagnosis
of their attempt. Focus transfer now preserves the already frozen one-use attempt;
lock, sleep, user switching, disconnect, expiry and explicit cancellation still
invalidate it. Starting an attempt requires one second with the unchanged review
in the active key window. Completion binds the captured request, connection,
revision, identity and attempt; stale callbacks cannot finish a newer request.
If key persistence finishes before delivery is cancelled, the app adopts the saved
identity and offers resume instead of another key creation.

Verification:

- **104 Swift tests** and the three Rust bridge tests passed, including lifecycle,
  stale-result, arming, modal ownership, bounded output and presentation cases.
- **30 CLI tests** passed, including interrupted/resumed setup and the checked
  `ready` result. CLI Clippy passed with warnings denied.
- A Teerminal Codex subagent implemented the UI; an independent Teerminal Claude
  review found no remaining blocker after the modal, document-ownership and retry
  fixes. This was source review, not hardware acceptance.
- A separate inert UI harness was checked in light/dark appearances and at the
  minimum window size. The real signed app/helper were then rebuilt and verified.
  Its actual setup window was opened with `local-pilot`, `jarkko` and
  `agent-yhes-pilot` selected. `bin/yhes doctor` returned `ok:true` and authenticated
  the running signed app. No setup/approval button was activated by this check.

Human Touch ID enrollment and signing remain unconfirmed. The signed app is ready
for that manual trial; software tests and visual checks do not establish biometric
prompt behavior. No commit, tag or push was made for this change.

## Signer startup fix — 2026-11-14

The reported `signer_unavailable` was reproduced with no YhesSigner process and
no `signer.sock`. The CLI previously required a manually opened app. `pilot` and
`say` now verify and launch their enclosing signed companion when absent, then
wait for authenticated readiness. They do not retry an identity failure or replay
a signing request after a dropped connection. Concurrent startup is serialized.

All **30 CLI tests** and CLI Clippy with warnings denied passed. New regression
cases cover delayed readiness, one-time startup, bounded timeout, launch failure,
untrusted peers, an unsigned on-disk companion, a detached helper and diagnostic
startup without enrollment or approval. The signed app/helper were rebuilt and
their signatures verified.

A live cold-start test began with zero signer processes and ran two simultaneous
`bin/yhes doctor --start-signer` calls. Both returned `ok:true` after verifying
the live peer, and exactly one signer process remained. Plain `doctor` then passed.
No key setup or signing request was sent in this test. The full test suite was
not rerun for this CLI-only change.

## Usable signed local pilot — 2026-11-14

The latest workspace run passed **120 Rust tests**: 47 core/storage/MLS/local-log
tests, 23 CLI tests, 38 wire/interoperability tests, nine action tests and three
bridge tests. The native app passed **82 Swift tests**; its three bridge checks
repeat tests already counted above. GHES fixtures passed eight tests. The changed
legacy helpers passed 20 local and 17 remote Git tests, including refusal to write
plaintext into a secure project. No broker test was rerun for this local pilot.

The CLI's software end-to-end tests cover resumable setup, user-entered messages,
P-256 human statements preserved in agent relays, malformed/substituted signer
responses, expired/replayed approvals, changed local pin metadata, and every
setup-stage interruption. Production code has no software-key/test-mode fallback.

Local transport regression tests cover exact read-back before acknowledgment,
protected cursor rollback detection, full-log refusal before an invalid append,
explicit refusal of an unsupported rejoin, and draining earlier peer application
messages before a pending membership commit advances the owner's epoch. Same-user
programs may invoke approved local agent profiles; model-process attestation is
not claimed.

Live platform evidence:

- Xcode provisioning initially reported no account. After the user signed in,
  selecting the actual Mac destination enabled device registration and successful
  builds for the signer and engine identities. The new Apple-managed same-team
  wildcard profile authorizes the exact dedicated application IDs/groups; the
  packaged entitlements remain exact, not wildcard claims.
- The signer and nested engine were signed, verified against their expected
  identities/team and hardened runtime, and their final entitlements were checked.
  `bin/yhes doctor` successfully authenticated the running native signer through
  the kernel audit token and code-signing checks. No notarization or upload occurred.
- A disposable, separately signed engine probe exercised the production Data
  Protection Keychain provider: key creation/reload, SQLCipher vault reopen,
  checkpoint load/retry and rejection of a conflicting digest. It exited 0 with
  `pass cleaned=6`; its exact six test records were removed by the signed probe.
  The probe never accessed the human signer group or exported private keys.
- The real enrollment request for `jarkko` / `agent-yhes-pilot` reached the native
  UI. It timed out before a completed approval. The CLI received a timeout and
  the app cleared the request. Successful Touch ID enrollment, human signing and
  real-harness messaging remain the next manual acceptance steps.

One earlier parallel workspace run failed the existing correct-key vault-reopen
assertion after its wrong-key/wrong-project checks. Its cause was not established.
The assertion now preserves the error on a future failure; no validation was
relaxed. Subsequent complete runs passed, as did 20 repeated runs of all eight
store tests. Keep this intermittent observation open for further diagnosis if it
recurs; it is not evidence of a resolved storage defect.

Use [LOCAL-PILOT.md](LOCAL-PILOT.md) for the actual user workflow. This snapshot
was uncommitted when tested; its source is now included from v0.3.0 onward.
The earlier implementation/transport results below are retained as dated evidence.

## Secure implementation slice — 2026-11-14

The new Rust workspace passed **88 tests**: 38 core/storage/MLS checks, 38 wire
and native interoperability checks, nine action-sidecar checks and three C-ABI
public-key validation checks. `cargo clippy --workspace --all-targets --locked
-- -D warnings` passed. The native signer passed **66 Swift tests** and built a
release app bundle. The GHES adapter passed **eight tests** with injected HTTP
and disposable SSH/OpenPGP proofs. The native test script also reruns the same
three Rust bridge tests; those are not counted twice here.

Commands, from the repository root:

```sh
cargo test --manifest-path secure/Cargo.toml --workspace --locked
cargo clippy --manifest-path secure/Cargo.toml --workspace --all-targets --locked -- -D warnings
native/YhesSigner/scripts/test.sh
native/YhesSigner/scripts/build-app.sh
python3 -m unittest discover -s secure/identity -v
```

The combined engine checks exercise:

- A human-signed statement carried unchanged inside an agent-signed relay,
  encrypted to another agent, with separate human and agent provenance.
- Exact outbox retry and durable inbox retrieval after reopening the vault.
- Three-recipient messages, membership add/remove, pending-send fencing,
  rejected-attempt recovery and exclusion from new-epoch messages after removal.
- Both an existing member and a joiner rejecting a substituted KeyPackage for
  the same enrolled signing key; the valid approved package still works afterward.
- Forged human roles, tampering, revocation, expired/reused action approvals,
  registry rollback and bootstrap with an independently pinned current head.
- Backdated events cannot revive an expired human-session grant or agent delegation.
- Valid MLS ciphertext with an invalid inner signature or conflicting event ID
  going to durable quarantine, with subsequent valid messages still deliverable.
- SQLCipher database/WAL plaintext-marker checks, wrong-key refusal, clone/restore
  quarantine and authenticated checkpoint repair after an interrupted publication.
- Actual SIGKILL before and after the transaction committing MLS sender state,
  ciphertext outbox and application rows. Restart preserves their shared outcome.

Cross-harness review changed the implementation: Copilot found the missing binding
to the exact added KeyPackage; Claude exposed that value from OpenMLS and the core
now checks it. Grok's store review led to explicit committed-but-unpublished errors,
idempotent joins, authenticated bridge schemas, a post-bridge MAC check and path
binding. Automatic acceptance of an initial database with a missing checkpoint
was rejected because it would also allow restoration of an old initial snapshot.

The README was checked with the `article` tool's English readability analyzer:
no defensive legal-language findings, academic-citation findings or long-sentence
findings. Its path detector flagged the public example command
`python3 examples/demo.py`; that is a documented relative command, not a private path.

No real human keys were enrolled, no Keychain items were created, and no Touch ID
or live GHES trial ran. The native app's shipping identity remains
unconfigured and key operations fail closed. The [secure implementation guide](../secure/README.md)
records the remaining daemon/transport, ticket-execution, historical acceptance,
governance and process-containment gates. These tests establish this implementation
slice, not a deployed secure v0.3. No commit, tag or push was made for this slice.

## v0.3 realtime checks — 2026-11-13

The complete suite passed **48 tests**, with no skips, on macOS using Python
3.14.3, Git 2.53.0, NATS Server 2.15.3 and nats-py 2.16.0. The broker-enabled run
used `uv run --with nats-py==2.16.0 python -m unittest discover -s tests -v`
with `YHES_NATS_SERVER` pointing to the checksum-verified server binary.

Thirteen added checks cover live delivery before the reconciliation interval,
keeping transport and handled receipts separate, broker outage/flush recovery,
publish deduplication, lost publish acknowledgment recovery, unacknowledged replay
after server restart, Git-outage redelivery, missed-notification reconciliation,
invalid hints, credential rejection, TLS certificate verification, connection
policy and JSON-line listener output. The existing 35 local/Git tests still pass.

`examples/realtime_demo.py` passed with real Git clones and an authenticated
loopback NATS server. Both scripted participants received their expected message
after a broker notification, the ticket reached `done`, and its result was kept
in Git. The server and listeners stopped when the example finished.

Both shipped NATS configurations passed `nats-server -t`. Both skills passed
their structure validator. Documentation links and `git diff --check` passed.
The README's article check found zero sentences over 28 words and zero matching
Anti-Legalism patterns.

These tests ran on one physical computer with isolated clones and local TCP.
Native harness wake-up, production hosting, multi-node NATS replication and
Linux/Windows execution remain deployment/integration work. No permanent broker
or live Git coordination branch was created for this run.

## v0.2 remote Git checks — 2026-11-13

On macOS, Python 3.14.3 and Git 2.53.0:
`python3 -m unittest discover -s tests -v` passed **35 tests**: the original
19 local tests and 16 remote integration tests.

Remote tests use actual bare Git remotes and independent source clones. They
cover competing claims from separate processes, concurrent independent messages,
a full agent-to-agent-to-human review, lost push acknowledgments, interruption
after acceptance, offline intents, operation-ID collisions, stale claims,
human recovery, cross-clone session continuation and shared receipts.

They also verify that source HEAD, staged changes, unstaged files and the source
index stay intact; branch rewrites/deletion, rejected server pushes, remote
symlink records, source-branch targeting and use of the v0.1 helper on remote
records fail safely. The human CLI registration path is exercised directly.

`python3 examples/remote_demo.py --tcp` also passed. Three independent clones
exchanged a question and reply, transferred the ticket to a scripted human
reviewer, and observed the completed ticket and durable result through real
Git traffic over loopback TCP. Source worktrees stayed clean and the temporary
server stopped on exit.

Both updated skills passed their structure validator. All documentation file
links resolve, and `git diff --check` passes. The README's `article check --fast`
run found zero sentences over 28 words and zero Anti-Legalism pattern matches.

The transport is tested locally with independent clones. Actual model sessions,
multiple physical machines, hosted HTTPS/SSH authentication, native Windows and
Linux execution remain integration checks for a deployment. The protocol uses
the installed Git client for those remote transports.

## v0.1 baseline — 2026-11-11

Executed on 2026-11-11 on macOS using Python 3.14.3. This is a local reference
implementation check, not a vendor compatibility certification.

## Passed

`python3 -m unittest discover -s tests -v`: **19 tests passed**.

The tests exercise observable protocol behavior:

- Eight independent processes claiming the same revision produce one winner.
- Eight concurrent sends preserve all distinct messages.
- A generated ticket-ID collision cannot replace an existing task.
- A failed publication before rename preserves the previous ticket and history.
- A terminated lock-owning process releases the OS lock; its inode remains.
- Expiry blocks automatic takeover and late renewal; recorded recovery changes
  the generation, and the former owner's token cannot mutate the new claim.
- A live claim cannot be recovered, stale revisions fail and renewal cannot
  shorten an existing lease.
- An expired owner can voluntarily hand off but cannot declare completion.
- Listing and display limits do not consume messages; seen remains pending and
  handled cannot regress to seen.
- A reply saved before an interrupted acknowledgment remains discoverable;
  identical-ID retries are stable and changed content is rejected.
- Explicit session continuation discovers pending session-addressed messages
  and preserves predecessor handled receipts without changing agent identity.
- Live expiry hides activity while preserving the file and durable memory.
- Invalid/unsupported records are reported without hiding valid messages.
- Supersession preserves original memory, dependency gates work, overlapping
  scopes produce a warning and completion requires evidence.
- Path traversal is rejected; imperative message text is stored literally.
- An uninitialized read does not create protocol directories; CLI round trips
  work and conflicts return exit code 3.

`python3 examples/demo.py`: **passed**. The complete claim → question → reply →
durable decision/result → completion flow ran using two simulated identities.
The script leaves an inspectable disposable directory and prints its location.

The sample export contains **14 valid JSON records**, including two tickets,
two sessions, question/reply, intent, decision, result, handoff, task request and
two receipts, plus the project descriptor. Export intentionally omits `.lock`.

Both skills passed the `skill-creator/scripts/quick_validate.py` validator.
The initial system-Python invocation lacked PyYAML; validation succeeded through
`uv run --with pyyaml python .../quick_validate.py <skill-directory>`.
The runtime helper and its tests use only the Python standard library.

Internal Markdown file links were checked for existing targets. The final ZIP
is built from an explicit public-file allowlist and checked for corruption and
unexpected paths; private `.tickets`, machine intake state and caches are absent.

## Not established by these checks

- Real Codex–Claude, Antigravity, Copilot or Cursor execution and idle wake-up.
  [The live trial procedure](../examples/WALKTHROUGH.md) is ready to run.
- A receiving model's resistance to prompt injection. The literal-storage test
  does not test a model's decisions. The skill and spec define the boundary;
  the live trial must exercise it.
- Independent verification of worker shutdown from a recovery caller's text.
- Protection against hostile same-account processes, arbitrary source editors,
  in-flight external side effects, or scope overlap ignored by a participant.
- Linux, native Windows, network filesystems, power loss, disk exhaustion,
  very large project histories or physical cross-machine operation.

These limits are deliberate boundaries of the first experiment. No reference
project was rebuilt or deployed as part of this validation.

## Publication status

Jarkko selected the name **agent-yhes** and authorized publication of this draft
at [ljack/agent-yhes](https://github.com/ljack/agent-yhes). That publication does
not change the validation limits above. License selection remains open.
