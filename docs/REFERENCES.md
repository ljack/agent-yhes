# Verified references and boundaries

Inspected on 2026-11-11. These are source observations, not a new live harness
acceptance test or a claim about vendor guarantees. The reference projects were
not modified, built or installed for this proposal, and their runtime message
contents, keys and owner-policy files were not read or copied into this package.

## Correct project identities

The local directory inventory identified **Teerminal** at
`~/_dev/teerminal` and **No More Meat Proxy** at `~/_dev/no-more-meat-proxy`.
The latter is not a directory named `nomoremeatproxy`. Other similarly named
worktrees existed; the base checkouts above were used for this inspection.
The new working directory is `~/_dev/agent-yhes`, initially not a Git repository.

Teerminal HEAD was `0f983e2c8af3d5d5dd40f21771dd71133ce2cb1b` and NMMP HEAD was
`404b1557c7f37bc21d9bc3254bf2892720d39d6d`. Both working trees contained changes;
some inspected files were untracked. Therefore those commits alone do **not**
identify the observed implementation. File hashes below identify the actual
read snapshots without publishing the reference projects' private source.

## What the source actually does

| Source location within its project | Observed behavior | Relevance to this proposal |
| --- | --- | --- |
| Teerminal `Sources/Teerminal/Context/ContextStore.swift:6`, `:26`, `:37` | An actor owns `context/activity.sqlite`, WAL/full synchronization and an events table with increasing integer IDs. | Shared context already exists, but the carrier is app-owned SQLite rather than these two portable project directories. |
| Teerminal `tools/group_feed.py:65`, `:192`, `:241` | Discovers structural groups, keeps per-session cache state/cursors and filters events for groups/recipients. | Discovery and session addressing are useful patterns. v0.1 deliberately limits its domain to one explicitly selected project. |
| Teerminal `tools/group_feed.py:475`, `:498`, `:515`, `:541` | Sends addressed cards, publishes receipts, tracks delivered inbox entries and re-presents pending reply-needed cards. | Keep discovery and handling distinct. Do not equate a tool read or delivery with completed work. |
| Teerminal `tools/group_feed.py:628` | Contains harness hook handling, including Antigravity event adaptation. | Hooks belong in a replaceable adapter; their existence does not prove every hook works in an actual current session. |
| NMMP `nmmp.py:28`, `:289`, `:330`, `:638`, `:707` | Separates receipt stages, checks current peer/activity policy, signs/encrypts packets, supports Unix-socket delivery and a mailbox spool. | Distinguish retained, received and handled; peer transport is separate from owner permission. v0.1 does not copy this cryptographic/network scope. |
| NMMP `nmmp.py:76`, `:95` | Uses temporary-file replacement and OS file locks in local helpers. | Supports investigating explicit local write/lock rules. The new protocol defines its own common lock and revision contract. |
| NMMP `group_feed.py:95`, `:120`, `:142` | Calls Teerminal's context API and maintains per-session cursors for its project feed. | This current group-feed route depends on Teerminal; it is not evidence that a standalone `.agents/messages` standard already exists. |
| NMMP `receipts-and-loops.md:1` | Describes separate transport, conversation and human-facing loops, with received/processing/handled/presented/human_ack meanings. | Adopt the distinction in a smaller form. The v0.1 helper implements no human-approval receipt. |

One specific design lesson from reading Teerminal's current `collect`: cursor
updates occur before the final display cap (`group_feed.py:288–297`). This is a
reason to define v0.1's unhandled-ID semantics explicitly; it is not a report of
a reproduced lost-message incident in the running application.

No reference-project timing, old test count, native wake-up claim or security
acceptance was copied into this proposal as new evidence. The two-harness fixture
in this package has its own explicit simulated status.

## Snapshot hashes (SHA-256)

```text
teerminal/Sources/Teerminal/Context/ContextStore.swift
373aec128f97db025d5c419c72da6de68dc9372fdb5193f4b00c6541b3496506
teerminal/tools/group_feed.py
3b07c50c347fa7efcffe91dc716641b38c20de50d774fb387280478025133f23
no-more-meat-proxy/nmmp.py
6cd44e7510f45cd52203cc79da42bcec01597d99b92f9e4652d57fc29effab84
no-more-meat-proxy/group_feed.py
150bb2f9f822e062335e93e8fea8d607e197d4ba42d12ed6df8cd02a6f38f064
no-more-meat-proxy/receipts-and-loops.md
9945580812ffb82b883c1dc4989f0c432ddf32ed5184104ca1e2317727ae12c0
```

## Public format and implementation references

The JSON choice follows the interoperable data format in
[RFC 8259](https://www.rfc-editor.org/rfc/rfc8259). UUIDv4 is specified in
[RFC 9562, section 5.4](https://www.rfc-editor.org/rfc/rfc9562#section-5.4).
These standards define building blocks, not this proposal's application schema.

The executable Unix profile uses the documented Python
[`fcntl.flock`](https://docs.python.org/3/library/fcntl.html#fcntl.flock)
interface and same-filesystem atomic
[`os.replace`](https://docs.python.org/3/library/os.html#os.replace), with
[`os.fsync`](https://docs.python.org/3/library/os.html#os.fsync) for flush requests.
Atomic replacement and cooperative locks do not provide a source-code sandbox
or universal power-loss durability.
