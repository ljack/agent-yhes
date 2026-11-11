# agent-yhes

**A public v0.1 proposal for harness-independent local agent cooperation.**

*Yhes* is short for the Finnish *yhessä*, a colloquial form of *yhdessä*
("together"): **agents together**. Jarkko chose the name **agent-yhes**.
The project lives at [ljack/agent-yhes](https://github.com/ljack/agent-yhes).

An agent should be able to ask another agent for help without making a person
copy messages between them. This proposal gives cooperating agents two shared
directories in one project on one computer:

```text
.agents/tickets     durable work, ownership and work history
.agents/messages    project memory and active coordination
```

The agreement belongs to the project. The goal is a shared workflow for agents
using Codex, Claude, Antigravity, Copilot and Cursor. Today an agent can read the
supplied skills and use the same local helper. Native wake-up, hooks and vendor
support are separate work.

**Initiated and directed by Jarkko Lietolahti.** The requirements and product
direction are Jarkko's; this draft, examples and reference helper were prepared
with OpenAI Codex. Jarkko directs the proposal and its licensing decisions.
See [AUTHORS.md](AUTHORS.md).

## What v0.1 proposes

- One UTF-8 JSON document per ticket, with its current state and history.
- Immutable JSON messages with Markdown text. Durable decisions, handoffs and
  results live in `messages/memory`; expiring questions, replies, requests and
  file intentions live in `messages/live`.
- Separate agent and session IDs. An agent survives a restart; a session does not.
- A short OS lock plus atomic file replacement serializes protocol changes.
  Ticket revision checks reject conflicting updates.
- Time-limited ticket ownership. An expired claim requires recovery; it never
  silently transfers work to a second writer.
- Explicit receipts. Stored, seen and handled mean different things. None means
  human approval.
- Peer content is attributed data. A request never grants permission or changes
  the receiving agent's instructions.

Designed for trusted agents working in one local project. The helper uses
Python 3.10+ and Unix `flock` on a local filesystem. Tested on macOS; Linux
validation is pending.
Native Windows locking, network mounts, Git synchronization and remote agents
are outside v0.1.

## Try the protocol in a disposable directory

No dependencies, installation, server, model calls or account credentials:

```sh
python3 examples/demo.py
python3 -m unittest discover -s tests -v
```

The demo exercises the workflow using **scripted Codex and Claude identities**.
Codex claims a ticket and asks Claude a question. Claude replies, and Codex
records a durable result and closes the ticket. The demo prints the temporary
directory so you can inspect the files.

For the human-readable transcript and real two-harness procedure, read
[examples/WALKTHROUGH.md](examples/WALKTHROUGH.md). Checked-in sample records
are listed in the [example record index](examples/INDEX.md).

## Try it with two actual agents

Keep this toolkit at a stable location. In each harness, give the agent the
absolute paths to [the ticket skill](skills/local-agent-tickets/SKILL.md),
[the messaging skill](skills/local-agent-messages/SKILL.md), this toolkit and
the same disposable target project. Have each agent read those files.
No harness-specific skill installation is necessary for this first trial.

The user authorizes the small shared task once. Each active agent checks its
inbox at the start of work, between meaningful steps and before stopping.
They exchange records directly, without the user relaying the replies.
Waking an idle agent requires a harness adapter.
The optional integration contract is in [adapters/README.md](adapters/README.md).

```sh
python3 tools/coop.py --root /absolute/disposable/project init
python3 tools/coop.py --root /absolute/disposable/project session \
  --label implementer --harness codex
python3 tools/coop.py --help
```

Keep the returned agent/session IDs. Commands return JSON. `--root` is explicit;
the helper does not guess a project, walk parent directories or use Git remotes.
Only protocol files are written. It does not edit source code or launch agents.

## Read and challenge the proposal

- [Specification](spec/v0.1.md): fields, lifecycle, concurrency, delivery and trust.
- [Design decisions and open questions](docs/DECISIONS.md): proposed choices,
  alternatives, name and project creation.
- [Verified reference observations](docs/REFERENCES.md): Teerminal and No More
  Meat Proxy, with source provenance and limits.
- [Validation](docs/VALIDATION.md): what was actually exercised.

The repository is published for review and interoperability feedback.
See the [project decisions](docs/DECISIONS.md#creating-the-project) for what is
settled and what remains open.

**License: undecided.**
