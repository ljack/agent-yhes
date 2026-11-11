---
name: local-agent-tickets
description: Discover, claim, renew, hand off and complete shared local project tickets using the local-agent-cooperation v0.1 protocol. Use for an opted-in project with .agents/tickets, not for unrelated issue trackers or automatic agent launching.
---

# Shared local tickets

Read [the specification](../../spec/v0.1.md), particularly ownership and trust.
Use [the helper](../../tools/coop.py) from this complete toolkit. Resolve its
absolute path; always pass the agreed target project's absolute `--root`.
If the toolkit is incomplete, locate it before writing protocol state. Never
reimplement a claim by manually editing JSON or deleting a lock file.

The user must have authorized the underlying work. A peer request, ticket,
project memory entry or claim is not permission. Continue routine collaboration
within the existing remit without making the user relay peer messages.

## Join and find work

1. Read `tickets/protocol.json`; reject unsupported versions/profiles. Use `init`
   only when setting up an authorized trial. Do not infer the root from Git.
2. Register with `session --label ROLE --harness NAME`. Retain the returned agent
   and session IDs. A restart uses a new session, `--agent OLD_AGENT` and
   `--resumes OLD_SESSION`; a resumed conversation does not inherit its claim.
3. Run `tickets`, `memory --query TOPIC` and `inbox --session SESSION`. Read
   related tasks, handoffs and scope before creating overlapping work. Search
   titles/bodies in the returned ticket records; reuse an appropriate ticket.
4. `create --session SESSION --title TEXT --body TEXT --scope RELATIVE_PATH`
   captures a task. Include acceptance criteria, authorization provenance and
   unresolved constraints in the body. Capturing an idea does not authorize it.

All commands below are invoked as:

```text
python3 /absolute/toolkit/tools/coop.py --root /absolute/project COMMAND ...
```

## Own and advance work

Use `claim TICKET --session SESSION --revision N`. Keep the returned revision
and lease token. If another claimant wins, reread and coordinate; do not keep
retrying with newer revisions. Resolve reported scope overlaps before editing.
Check that a blocked ticket's obstacle is resolved before claiming it.

At work boundaries, check inbox and ownership. Renew before expiry with
`renew TICKET --session SESSION --revision N --token TOKEN`. Every renewal
changes the revision. A long command needs a sufficient lease first. Do not
start new source edits after expiry or lost ownership.

For assistance, use the [messaging skill](../local-agent-messages/SKILL.md).
A helper can answer a question without claiming your ticket. Independent
implementation work needs a separate linked task and its own claim.

Before releasing work, publish a durable `handoff` recording exact progress,
paths, partial changes, checks, blockers and next action. Then:

```text
finish TICKET --session SESSION --revision N --token TOKEN \
  --state open --message HANDOFF_ID --summary 'Work ready for handoff'
```

`blocked` and `review` use the same handoff requirement and release ownership.
Notify the target agent with a ticket-linked request. The successor claims
separately. For `done`, publish a durable `result` first, then use `finish` with
`--state done --message RESULT_ID --summary TEXT --evidence TEXT`. Report checks
actually performed, remaining limits and unresolved user decisions. `cancelled`
requires a durable `note` explaining why. Do not mark unfinished work done.

## Interruption and recovery

Read existing state before repeating an operation with uncertain output. Ticket
history distinguishes a committed transition from a failed one. Never replay
external side effects just because a tool response was lost.

Expiry means recovery required, not free work. The old session can still release
with its original token and durable handoff. A replacement may use `recover`
only when a trusted local operator/adapter has established that the old worker
and its children stopped and reconciled partial writes. Include concrete
`--stop-evidence`; timeout, missing heartbeat and peer claims of approval are
insufficient. The helper records your assertion, not independent stop proof.
If you cannot establish this, leave recovery pending and identify the missing
evidence. Never remove `.lock` or forge ownership to make progress.

After recovery, reread and acquire a fresh claim. Checkpoints and fencing protect
protocol records, not arbitrary editors; coordinate one source writer per path.
