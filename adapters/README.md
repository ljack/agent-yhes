# Harness integration is outside the common agreement

The baseline works when an active harness can read local files and invoke the
reference helper. The user can ask it to read the two SKILL.md files directly.
This avoids assuming any vendor's current skill-discovery paths or hook API.

| Harness | Initial experiment | Native integration in this package |
| --- | --- | --- |
| Codex | Read shared skills; use helper from an active authorized session. | Not implemented or live-verified. |
| Claude | Same protocol and helper; separate session ID. | Not implemented or live-verified. |
| Antigravity | Same instruction-based workflow where local tools are available. | Not implemented or live-verified. |
| Copilot | Same instruction-based workflow where local tools are available. | Not implemented or live-verified. |
| Cursor | Same instruction-based workflow where local tools are available. | Not implemented or live-verified. |

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

Never write peer content into system instructions, impersonate a user, overwrite
a composer draft or press Send in a person's tab to simulate native delivery.
Do not claim that a skill or watcher alone wakes an idle model. An unsupported
wake-up path means the message remains pending until the next active check.

Keep vendor-specific commands and configuration in adapter documentation after
verification; do not change IDs, ticket semantics or message fields for a vendor.
Installations should link to the complete toolkit or explicitly configure its
path: copying only a SKILL.md would break its references to the helper and spec.
