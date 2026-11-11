# Proposed choices and open decisions

## Established by Jarkko's request

Start on one machine in one project. Use `.agents/tickets` for durable work and
`.agents/messages` for both memory and active coordination. Keep the common
agreement independent of the harness. Make a small skill-driven trial possible.
Prepare a public proposal with Jarkko's role visible. Jarkko subsequently chose
**agent-yhes** and authorized publication at **ljack/agent-yhes**. The license
remains open.

The technical choices below are **design proposals**, not additional user
decisions. The project name and publication destination are explicit user choices.

## Why these formats and mechanisms

| Choice | Reason | Tradeoff / rejected first-version alternative |
| --- | --- | --- |
| JSON with Markdown strings | Common parser support, explicit types, one atomic record. | Less pleasant to edit by hand than Markdown with YAML frontmatter; avoids YAML coercion and metadata/body split transactions. A reader UI can improve this later. |
| One snapshot plus history per ticket | A single rename commits status, owner and audit history together. | Rewrites and grows a small document; full event sourcing would add replay, corruption and snapshot rules. |
| One immutable message per file | Concurrent writers never append into the same message. | Directory scans grow; index/sharding is later work. Shared JSONL makes partial trailing writes and concurrent append behavior part of every client. |
| UUIDv4 with type prefix | Available without a central sequence or clock ordering. | Long IDs; short display labels must never become ambiguous addresses. |
| Stable agent / new session | Replies can survive harness restarts while ownership remains specific. | Adapter must retain identity and explicitly record continuity. |
| One short `flock` lock | Straightforward local mutual exclusion and automatic release on process death. | Unix first; every client must cooperate. `mkdir` stale-lock deletion has races and needs a more complex recovery protocol. |
| Revision and claim token | Reject stale writes and old sessions after takeover. | Protects coordination state only, not arbitrary editors or external side effects. |
| Conservative expiry recovery | Prevents time alone from starting two source writers. | Unresponsive workers sometimes need operator help; unattended reclaim requires a real stop-capable adapter. |
| Explicit ID receipts, full scan | Limits and clock/order changes cannot silently advance past unread work. | Intended for small projects; efficient indexing is later work. |
| Separate durable/live folders | Clear retention without confusing permanence with authority. | A result must deliberately promote useful reply content into project memory. |

The minimal helper makes concurrency rules executable. Asking each LLM to write
its own ad hoc JSON/lock sequence would make the first trial less interoperable.
The helper is replaceable; its implementation language is not a protocol rule.

## Creating the project

Jarkko selected **agent-yhes** for the project and
[ljack/agent-yhes](https://github.com/ljack/agent-yhes) for its public repository.
*Yhes* is short for *yhessä*, the colloquial Finnish form of *yhdessä*
("together"): **agents together**.

The existing `agent-yhes` working directory becomes the standalone repository;
no nested project or workspace rename is needed. The initial `main` contains
the public v0.1 proposal, skills, examples, helper and tests. Private Teerminal
tickets, runtime state, caches and local archives are excluded.

Publication invites feedback on the draft; it does not imply vendor adoption,
native harness integration or a finalized protocol. Licensing remains a separate
decision. No license, release tag or global skill installation is implied.

## Open questions before a broader version

1. Code/documentation license and contribution policy.
2. Whether the Unix-first profile is acceptable or Windows must be in v0.1.
3. Whether 15-minute claims and one-hour live messages fit real harness turns.
4. Which trusted adapter can prove a worker and its children stopped for recovery.
5. Should projects require independent review, and who may resolve conflicting
   durable decisions? The base version supplies records, not a governance model.
6. How should active receipts, old sessions, full histories and expired notices
   be archived? Initial version hides expiry but deletes nothing.
7. Should exact path ownership be enforced later? Current scope warnings and
   intentions are advisory, and overlapping source work requires coordination.
8. Native idle wake-up and safe delivery without replacing a person's draft.
9. Later: shared worktrees, cross-machine authentication, transport, replay
   protection, Git synchronization, schema migration and capability negotiation.

The trial should answer whether agents discover work, coordinate and recover
without losing messages, before adding these larger features.
