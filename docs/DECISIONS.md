# Proposed choices and open decisions

## Established by Jarkko's request

The first version starts on one machine in one project. Use `.agents/tickets` for durable work and
`.agents/messages` for both memory and active coordination. Keep the common
agreement independent of the harness. Make a small skill-driven trial possible.
Jarkko chose **agent-yhes**, authorized publication at **ljack/agent-yhes**, and
selected **MIT OR Apache-2.0** dual licensing.

For v0.2, Jarkko requested remote Git collaboration so participants on different
computers, using different harnesses, and humans can share the work. The
[v0.2 specification](../spec/v0.2.md) defines the implemented remote profile.

For v0.3, Jarkko requested a realtime broker layer, including server/specification
references and usage instructions. He delegated the choice of broker. The
implementation uses NATS JetStream as described in [v0.3](../spec/v0.3.md).

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

The repository does not imply vendor adoption or native harness integration.
Version tags are listed in [RELEASES.md](RELEASES.md), and repository source
and documentation are licensed under [MIT](../LICENSE-MIT) OR
[Apache-2.0](../LICENSE-APACHE). No global skill installation is implied.

## Remote profile choices in v0.2

Use one dedicated coordination branch as the serialization point. A successful
remote operation establishes ownership; a local candidate remains pending.
Reapply independent requests after contention, while preserving ticket revision
checks. Save immutable operation receipts so a dropped push acknowledgment can
be resolved without repeating the logical operation. The source checkout and
its index remain separate from this transport.

Human participants use the same commands and can review tasks. Shared receipts
and session continuation let them or agents move to another computer. Expired
claims retain the conservative recovery rule; remote recovery requires a human
to record stop and reconciliation evidence.

Git host permissions control channel access. This v0.2 profile assumes
cooperating repository members. The separate secure implementation added in
v0.3 supplies signed identities and encrypted groups; it does not turn v0.2
records into authenticated secure events.

## Broker profile choices in v0.3

NATS JetStream supplies storage acknowledgments, durable consumers and replay.
The broker carries channel-change hints while Git remains the authority for
records and claims. This keeps one task state and lets existing v0.2 clients
continue participating. Git publication latency remains part of the send path.

The first broker deployment is a single persistent server with token
authentication, and verified TLS for connections between computers. It serves
one trusted group per server/account. Separate groups need NATS account/subject
permissions. Native harness wake-up and broker-first message storage are separate
future extensions.

## Open questions before a broader version

1. External contributor workflow and CLA policy (repository license is `MIT OR Apache-2.0`).
2. Native Windows support and Linux verification for the remote helper.
3. Whether 15-minute claims and one-hour live messages fit real harness turns.
4. Which trusted adapter can prove a worker and its children stopped for recovery.
5. Should projects require independent review, and who may resolve conflicting
   durable decisions? The base version supplies records, not a governance model.
6. How should active receipts, old sessions, full histories and expired notices
   be archived? Initial version hides expiry but deletes nothing.
7. Should exact path ownership be enforced later? Current scope warnings and
   intentions are advisory, and overlapping source work requires coordination.
8. Native idle wake-up and safe delivery without replacing a person's draft.
9. Per-participant server permissions, channel archival, automatic v0.1 migration
   and capability negotiation. Signed identities are implemented in the separate
   v0.3 secure profile.

The trial should answer whether agents discover work, coordinate and recover
without losing messages, before adding these larger features.
