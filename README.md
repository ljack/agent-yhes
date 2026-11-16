# agent-yhes

## Start with your agent

Paste this into Codex, Claude, Agy (Antigravity), Grok or Copilot in **each of
two separate Teerminal project directories**:

```text
Use the local agent-yhes repo. Read BOOTSTRAP.md and bootstrap this workspace
for the two-user simulation.
```

[BOOTSTRAP.md](BOOTSTRAP.md) contains the setup steps, roles and checks. Each
workspace gets its own simulated identity and private state; Git and NATS are
shared. The simulation uses disposable keys and does not request Touch ID.

For real human identities and device approval, use the
[team pilot guide](docs/TEAM-PILOT.md).


---

**Agents and people working together, across harnesses and computers.**

*Yhes* is short for the Finnish *yhessä*, a colloquial form of *yhdessä*
("together"): **agents together**. Jarkko chose the name **agent-yhes**.
The project lives at [ljack/agent-yhes](https://github.com/ljack/agent-yhes).

Start with the [getting started guide](GETTING-STARTED.md): setup, what each
approval does, your first messages, troubleshooting, and the proposed path to a
team on separate computers.

An agent should be able to ask another agent for help without making a person
copy messages between them. agent-yhes gives a project two shared directories:

```text
.agents/tickets     durable work, ownership and work history
.agents/messages    project memory and active coordination
```

Version **0.3** adds realtime delivery through **NATS JetStream**. The broker
notifies active participants when the channel changes; they fetch the records
from Git. Replay and periodic reconciliation recover missed notifications.

Version **0.2** shares the records through a remote Git branch. Each participant
works from their own clone; the remote coordinates ownership, messages and memory.
The original **0.1** helper remains available for collaboration on one computer.

The [signed local pilot](docs/LOCAL-PILOT.md) connects the CLI, native Touch ID
approval and encrypted group messages on one Mac. It accepts your own text and
keeps human statements distinct from agent replies. Secure Git/NATS integration
is now available in the separate [two-person team CLI pilot](docs/TEAM-PILOT.md):
an explicitly verified Git handshake, encrypted records and NATS wake-up.
It has passed disposable multi-client tests; the two-Mac/GHES trial is still
pending. The Python remote commands below use the earlier record format.

The agreement belongs to the project. The goal is a shared workflow for agents
using Codex, Claude, Antigravity, Copilot and Cursor. Today an agent can read the
supplied skills and use the same local helper. Native wake-up, hooks and vendor
support are separate work.

**Initiated and directed by Jarkko Lietolahti.** The requirements and product
direction are Jarkko's; this draft, examples and reference helper were prepared
with OpenAI Codex. Jarkko directs the proposal and its licensing decisions.
See [AUTHORS.md](AUTHORS.md).

## Run the signed local pilot

On the development Mac with the locally signed build prepared:

```sh
bin/yhes pilot --project local-pilot --human jarkko --project-id agent-yhes-pilot
```

The command opens the signed app when needed. Review its setup requests, then send
and receive your own messages:

```sh
printf '%s\n' 'Hello from the Codex profile.' |
  bin/yhes send --project local-pilot --as codex --stdin --operation hello-1
bin/yhes inbox --project local-pilot --as claude
```

Use `say` instead of `send` for a statement you review and sign with Touch ID.
The [pilot guide](docs/LOCAL-PILOT.md) covers setup, replies, human provenance,
restart and signing prerequisites for another build.

## Test the secure core

```sh
cargo test --manifest-path secure/Cargo.toml --workspace --locked
native/YhesSigner/scripts/test.sh
python3 -m unittest discover -s secure/identity -v
```

The tests cover signed human messages relayed by agents, three-recipient MLS
encryption, membership changes, revocation, restart and exact message retry.
They use disposable keys. The native signer supports one Touch ID confirmation
for a fixed batch of reviewed statements and fresh confirmation for authority
or recipient changes. Read the [implementation guide](secure/README.md) for the
components, test workflow and remaining release work.

## Share work through a Git remote

- A dedicated `agent-yhes/state` branch carries tickets and messages. Source code
  stays on the project's ordinary branches.
- A claim takes effect after the remote confirms it. Competing claims use Git's
  branch-update rules and ticket revisions to select one owner.
- Saved operation IDs let a participant resolve an interrupted push before
  retrying. Offline requests remain pending until the remote accepts them.
- People can register as human participants, review tasks, answer questions and
  record decisions using the same CLI as agents.
- Durable decisions, handoffs and results live in `messages/memory`. Questions,
  replies and file intentions have an expiry in `messages/live`.
- Shared receipts and explicit session continuation support resuming on another
  computer. Expired claims require a handoff or human-confirmed recovery.

Designed for trusted participants working on one shared project. The helper uses
Python 3.10+, Git and a local Unix filesystem on each computer. Tested on macOS;
Linux validation is pending. Native Windows support is future work.

Choose a repository that all participants can read and push to. Run this once
from the organizer's computer, using an existing project clone:

```sh
python3 /path/agent-yhes/tools/remote.py --root /path/project init
```

Register an agent from its own clone:

```sh
python3 /path/agent-yhes/tools/remote.py --root /path/project session \
  --label implementer --harness codex
```

Or register yourself:

```sh
python3 /path/agent-yhes/tools/remote.py --root /path/project session \
  --label 'Human reviewer' --harness terminal --participant-type human
```

Keep the returned session and participant IDs. Use `sessions`, `tickets` and
`inbox --session SESSION_ID` to discover people, work and messages. Commands
return JSON; remote operation results are under `result`.

The helper uses `origin` and the `agent-yhes/state` branch by default. Choose
another configured remote or channel with `--remote` and `--branch`. Channel
visibility follows the repository, so use a private repository for private
discussion. The [remote walkthrough](examples/REMOTE-WALKTHROUGH.md) covers
claims, questions, human review and recovery.

## Add realtime notifications

Follow the [broker setup and usage guide](docs/BROKER.md) to run NATS, configure
token authentication and TLS, and install the optional Python client. It includes
server configuration files and links to the broker's own protocol documentation.

With the Git channel and broker configured:

```sh
python3 tools/realtime.py --root /path/project broker-init
python3 tools/realtime.py --root /path/project listen \
  --session SESSION_ID --seconds 30
```

Use `realtime.py` in place of `remote.py` for sends, claims and acknowledgments.
It confirms the Git operation, then notifies the broker. If the broker is down,
the Git result remains available and `flush` retries the notification later.
Listeners print fresh inbox snapshots as JSON lines. Message handling and ticket
completion still use their explicit Git commands.

## Try the complete workflow locally

The demo creates three independent clones and a temporary Git server on loopback:

```sh
python3 examples/remote_demo.py --tcp
python3 -m unittest discover -s tests -v
```

Scripted Codex and Claude participants exchange a question and answer through
real Git fetches and pushes. A scripted human reviewer takes over the ticket and
saves the outcome as shared memory. The demo prints its directory for inspection
and stops the server when finished. It runs with Python and Git, using the
standard library and your local machine.

For the original local-file workflow, run `python3 examples/demo.py` and read the
[v0.1 walkthrough](examples/WALKTHROUGH.md). Its sample records are listed in the
[example index](examples/INDEX.md).

With `nats-server` on PATH and the optional client available, try the live broker
workflow with scripted participants:

```sh
uv run --with nats-py==2.16.0 python3 examples/realtime_demo.py
```

It starts an authenticated loopback broker, delivers a question and reply between
independent clones, saves the result in Git, and stops the broker afterward.
Broker integration tests run when the server and client are installed; otherwise
the test runner reports them as skipped.

## Try it with two actual agents

Keep this toolkit at a stable location. In each harness, give the agent the
absolute paths to [the ticket skill](skills/local-agent-tickets/SKILL.md),
[the messaging skill](skills/local-agent-messages/SKILL.md), this toolkit and
their respective project clone and the shared remote/channel. Have each agent
read those files and select the remote workflow.
No harness-specific skill installation is necessary for this first trial.

The user authorizes the small shared task once. Each active agent checks its
inbox at the start of work, between meaningful steps and before stopping.
They exchange records directly, without the user relaying the replies.
Waking an idle agent requires a harness adapter.
The optional integration contract is in [adapters/README.md](adapters/README.md).
Peer messages are attributed data; the agent handles them within the user's
existing permissions. Source changes use the project's usual branches and reviews.

## Read and challenge the proposal

- [v0.2 specification](spec/v0.2.md): remote arbitration, participants and interrupted pushes.
- [v0.3 specification](spec/v0.3.md): broker events, replay, acknowledgments and reconciliation.
- [v0.1 specification](spec/v0.1.md): base records and the local workflow.
- [Design decisions and open questions](docs/DECISIONS.md): proposed choices,
  alternatives, name and project creation.
- [Verified reference observations](docs/REFERENCES.md): Teerminal and No More
  Meat Proxy, with source provenance and limits.
- [Validation](docs/VALIDATION.md): what was actually exercised.
- [Changes](CHANGELOG.md): version history.

The repository is published for review and interoperability feedback.
See the [project decisions](docs/DECISIONS.md#creating-the-project) for what is
settled and what remains open.

**License: undecided.**
