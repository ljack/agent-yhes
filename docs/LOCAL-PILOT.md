# Use the signed local pilot

The local pilot connects the native Touch ID signer to the Rust client and
encrypted group messaging. You can type your own messages, send them as an agent
profile or approve them as human statements, and read them from the other profile.
No sample JSON editing is needed.

This first usable profile runs on one Mac with two persistent agent profiles,
`codex` and `claude`, in group `team`. They can be operated by their respective
harnesses through the same CLI. Their names identify enrolled profiles; they do
not attest which model binary invoked the client. The separate
[team CLI pilot](TEAM-PILOT.md) adds a Git handshake and NATS-triggered delivery
for independent profiles. Secure ticket execution remains separate work.

## Start on this Mac

Open `native/YhesSigner/build/YhesSigner.app`. In the setup window:

1. Choose the existing `local-pilot` folder inside this repository.
2. Set **Human ID** to `jarkko` and **Project ID** to `agent-yhes-pilot`.
3. Choose **Start setup**. Review each step in the same window and use its named
   action button, followed by Touch ID.

The app shows Identity → Team → Permissions → Channel. Full keys and exact JSON
are in **Details**; independent file/key operations are in **Advanced**. If setup
pauses, use **Resume setup**. A cancelled biometric attempt can be retried while
its request remains valid. Completed steps are retained.

Alternatively, start the same flow from the repository root in a terminal:

```sh
bin/yhes pilot --project local-pilot --human jarkko --project-id agent-yhes-pilot
```

`local-pilot` is the private test project prepared for this session and ignored by
this repository's Git configuration. Use the same directory and IDs when resuming.
The native human key is currently bound to one author/project; changing projects
needs an explicit enrollment design, not an automatic key replacement.

`pilot` and `say` open their enclosing signed app if necessary and wait for an
authenticated local connection. Closing the app between commands is fine; no
approval is performed automatically. For a connection check without a signing
request, run `bin/yhes doctor --start-signer`. Plain `doctor` only checks the current
state and reports an absent app without starting it.

The `pilot` command asks for your existing device identity, or shows the native
key-setup request if none exists. Review the displayed author/project and create
the key with Touch ID. It then asks you to review:

1. The project registry containing your human key and the two agent keys.
2. The scoped delegation for each agent profile.
3. Creation of group `team` and addition of the other profile.

Each request is explicit and returned directly to the waiting CLI. The app never
approves it automatically. Routine agent messages need no further biometric
prompt while their delegation remains current. Setup reports `ready` when both
profiles are joined; rerunning `pilot` resumes completed stages. If a review
expires or is cancelled, use **Resume setup** in the app, or rerun the same command
if you started from the terminal. It does
not erase keys or reset a partially initialized vault.

## Send an agent message

```sh
printf '%s\n' 'Can you review this proposal and reply with one concern?' |
  bin/yhes send --project local-pilot --as codex --stdin --operation first-question

bin/yhes inbox --project local-pilot --as claude
```

The result identifies `codex` as the agent author. It does not label the text as a
human statement merely because you typed the command. Reply from the other profile:

```sh
printf '%s\n' 'My concern is recovery after a long offline interval.' |
  bin/yhes send --project local-pilot --as claude --stdin --operation first-reply

bin/yhes inbox --project local-pilot --as codex
```

Retain each operation ID. Repeating it with identical input retrieves the saved
operation and exact packet; changing the text under that ID is rejected. Use a
new ID for a new message. Text can also come from `--body-file PATH`; stdin avoids
putting the message body in the command's process arguments.

## Send a human-signed statement

```sh
printf '%s\n' 'This is my first local encrypted-message trial.' |
  bin/yhes say --project local-pilot --as codex --stdin --operation first-human-note
```

The app shows those exact words and every recipient. Review them and approve with
Touch ID. The client preserves your signed statement inside a separately signed
agent relay and encrypts it for the group. Read it from the other profile:

```sh
bin/yhes inbox --project local-pilot --as claude
```

Expect `author: "codex"`, `kind: "agent.relay"` and
`human_original_author: "jarkko"`, with the preserved human text and any agent note
shown separately. The original statement must reach the recipient within its
30-minute admission window; `say` reports `receive_before`. Once accepted, it
remains readable in protected history after that window ends.

Messages are data within the task you authorized. Even a verified human signature
does not make arbitrary prose a shell command or an automatic ticket transition.

## Use two actual harnesses

Give each harness this toolkit path, the same absolute pilot project path and its
assigned profile. Have it read the [messaging skill](../skills/local-agent-messages/SKILL.md),
check its inbox and exchange a bounded question/reply using `send`. It should
check again between meaningful work steps and before finishing. You do not need
to copy messages between harnesses. An idle harness still needs its own wake-up
mechanism; this CLI is not a background model runner.

Use `say` only for an actual human approval request. A harness must never operate
the native approval button or biometric step on your behalf. All group recipients
are included; this first CLI has no private-subset shortcut.

## Status, history and resuming

```sh
bin/yhes status --project local-pilot
bin/yhes sync --project local-pilot --as claude
bin/yhes inbox --project local-pilot --as claude --no-sync
bin/yhes doctor --project local-pilot
```

`status` reports each profile's group epoch, current registry/delegation and
unpublished operations. `sync` consumes the shared sealed log. `inbox` normally
syncs first; `--no-sync` reads already accepted history. `replayed` identifies
historical retrieval, and `new` is a local read marker, not proof that work was
completed. Encrypted durable inbox entries are not deleted by reading them.

A normal restart keeps keys, group state, cursor and operation IDs. Missing or
restored checkpoints, copied vault paths and a conflicting log stop processing
rather than silently create another identity. A removed profile cannot silently
rejoin its old state. Unseen expired membership approvals also require recovery;
sender timestamps do not establish timely approval. The pilot bounds the local
log to 4,096 records and 64 MiB; it refuses a new append before exceeding a bound.

The registry and delegations have reviewed expiry times. Rerun `pilot` when the
client asks for renewal; the native app presents the new documents. It never
extends grants using an old timestamp or an unattended human signing session.

## Where data lives

- Shared, signed/sealed records: `local-pilot/.agents/messages/secure/`.
- Public identity and registry metadata: its `identities/` subdirectory.
- Private encrypted profiles and pins:
  `~/Library/Application Support/agent-yhes/engine/`.
- Vault keys and append-only checkpoint records: the engine's dedicated macOS
  Data Protection Keychain group.
- Human root key: Secure Enclave, with its wrapped handle in the signer's separate
  Keychain group. It is never exported to the CLI or agent.

Do not reset or copy private vaults as a recovery shortcut. Deleting the shared
log after a protected cursor has advanced is detected as a history rollback.
Use a fresh project for the pilot; migration from an actively used legacy channel
is not implemented. The Python helpers refuse projects containing a secure channel,
which prevents accidental plaintext use but is not a live migration protocol.

## Build a signed copy

The prepared build on this Mac uses the approved local Apple team. To rebuild it:

```sh
python3 native/YhesSigner/scripts/provision.py
native/YhesSigner/scripts/build-app.sh --signed
```

Provisioning uses the Xcode account and an explicit current-Mac destination.
It creates profiles that authorize the dedicated signer/engine app IDs and their
separate Keychain groups. Packaging pins the team in the signed artifacts and
verifies their identities and entitlements. It does not notarize or upload the app.
The default `build-app.sh` builds an inert preview; use `--signed` for the working
client. Other developers must deliberately configure their own team and profiles.

For automated regression checks and remaining device tests, see
[TEST-RUNBOOK.md](TEST-RUNBOOK.md). The source is included from v0.3.0 onward;
[RELEASES.md](RELEASES.md) describes the version ladder and how to try each stage.
