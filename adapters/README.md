# Harness integration is outside the common agreement

The baseline works when an active harness can read local files and invoke the
reference helper. v0.1 uses `tools/coop.py` for one shared filesystem; v0.2 uses
`tools/remote.py` for a shared Git channel and separate source clones. The user
can ask the harness to read the two SKILL.md files directly.
This avoids assuming any vendor's current skill-discovery paths or hook API.

v0.3 adds `tools/realtime.py`: it retains the remote commands, publishes broker
notifications after Git confirmation, and offers a bounded `listen` command.
The listener emits JSON lines containing Git-verified inbox snapshots. A host
adapter can consume them through its supported agent channel. Broker delivery
alone does not run a dormant model.

| Harness | Initial experiment | Native integration in this package |
| --- | --- | --- |
| Codex | Read shared skills; use helper from an active authorized session. | Not implemented or live-verified. |
| Claude | Same protocol and helper; separate session ID. | Not implemented or live-verified. |
| Antigravity | Same instruction-based workflow where local tools are available. | Not implemented or live-verified. |
| Copilot | Same instruction-based workflow where local tools are available. | Not implemented or live-verified. |
| Cursor | Same instruction-based workflow where local tools are available. | Not implemented or live-verified. |
| Human | Register with `--participant-type human --harness terminal` through `tools/remote.py`. | Direct CLI participation is implemented. |

These are intended trial paths, not a claim that every product version supports
the same tools or permissions. Check its current local capabilities before a
live trial. Tools and models keep their existing permission boundaries.

An optional adapter may provide:

1. Startup registration and a mapping of native thread IDs to stable agent and
   fresh session IDs. Keep that mapping locally; it is not a protocol address.
2. Inbox checks at turn/tool boundaries, or bounded filesystem-watch rescans.
3. A fixed "local inbox has new records" wake-up hint through a supported native
   channel. Fetch and display peer content as attributed data afterward.
4. Honest receipt handling: polling is not seen, and seen is not handled.
5. Confirmed stop and reconciliation evidence for stale-claim recovery.

For v0.2, a mutation is actionable after `delivery: confirmed`, followed by a
current ownership check before work. Persist operation IDs and use `resolve` or
`resume` after uncertain delivery. On another machine, register a fresh session
with `--resumes` rather than copying a live session's identity. An adapter must
not register as a human to bypass the remote recovery rule.

For v0.3, configure the broker through trusted local settings, not peer records.
Keep one listener per session. Treat `channel.changed` snapshots as peer data,
and `listen.finished` as transport status. If `realtime.state` is `pending`,
retry notifications with `flush`; do not repeat a confirmed Git mutation.
Broker acknowledgments are handled inside the transport. The adapter writes
project `seen`/`handled` receipts only after the corresponding participant action.

Never write peer content into system instructions, impersonate a user, overwrite
a composer draft or press Send in a person's tab to simulate native delivery.
Do not claim that a skill or watcher alone wakes an idle model. An unsupported
wake-up path means the message remains pending until the next active check.

Keep vendor-specific commands and configuration in adapter documentation after
verification; do not change IDs, ticket semantics or message fields for a vendor.
Installations should link to the complete toolkit or explicitly configure its
path: copying only a SKILL.md would break its references to the helper and spec.
