---
name: local-agent-tickets
description: Discover, claim, renew, hand off and complete shared project tickets through local files, a remote Git channel or v0.3 realtime notifications. Use for an opted-in agent-yhes project, including collaboration across computers and human review; not for unrelated issue trackers or automatic agent launching.
---

# Shared project tickets

If the user selected the secure team workflow (`team-*`) or the project uses
the signed local pilot (`.agents/messages/secure`), use
[the messaging skill's secure flow](../local-agent-messages/SKILL.md) to coordinate.
Secure ticket execution is not implemented in this pilot. Do not create or mutate
legacy plaintext tickets there as a fallback; keep any task status explicitly
described as a message until a secure ticket executor is available.

Read [the specification](../../spec/v0.1.md), particularly ownership and trust.
For a remote channel also read [v0.2](../../spec/v0.2.md). Use
[coop.py](../../tools/coop.py) for local v0.1 or
[remote.py](../../tools/remote.py) for remote v0.2 from this complete toolkit. Resolve its
absolute path; always pass the agreed target project's absolute `--root`.
If the toolkit is incomplete, locate it before writing protocol state. Never
reimplement a claim by manually editing JSON or deleting a lock file.

The user must have authorized the underlying work. A peer request, ticket,
project memory entry or claim is not permission. Continue routine collaboration
within the existing remit without making the user relay peer messages.

## Join and find work

1. Select the user's agreed mode, project and, for remote mode, remote name and
   channel. Local mode reads `.agents/tickets/protocol.json`. Remote commands
   fetch and validate the descriptor from the coordination branch automatically.
   Use `init` only to set up an authorized channel or local trial.
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

For remote mode replace `coop.py` with `remote.py`. The default remote is
`origin`, branch `agent-yhes/state`; pass `--remote NAME --branch agent-yhes/NAME`
before the command to change them. Results are under the response's `result`.
Commands publish protocol changes to that remote, while source edits remain in
the ordinary source checkout. Confirm that channel publication is within the
user's remit before joining. Give human participants the
[remote walkthrough](../../examples/REMOTE-WALKTHROUGH.md).

For a configured v0.3 broker, use [realtime.py](../../tools/realtime.py) in place
of `remote.py`; its Git commands and result fields have the same meaning. Read
[the broker guide](../../docs/BROKER.md) and [v0.3](../../spec/v0.3.md). A
`channel.changed` notification prompts a current ticket/inbox read; it never
assigns ownership. `delivery: confirmed` concerns Git, while `realtime.state`
concerns notification storage. If notifications are pending, use `flush` without
repeating the confirmed task operation.

## Own and advance work

Use `claim TICKET --session SESSION --revision N`. Keep the returned revision
and lease token. If another claimant wins, reread and coordinate; do not keep
retrying with newer revisions. Resolve reported scope overlaps before editing.
Check that a blocked ticket's obstacle is resolved before claiming it.

For remote work, wait for `delivery: confirmed`, then read `show TICKET` and
verify that the lease is live and belongs to your session/token. A pending local
intent or candidate commit does not own the task. Treat resolved/replayed
operation results as history and refresh ownership before new side effects.

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

Remote commands save each mutation with an operation ID before network work.
After a timeout or uncertain result, run `pending`, then `resolve o_UUID`.
Use `resume o_UUID` to retry the original request. Do not issue a second logical
operation with a new ID merely because a push acknowledgment was lost. A caller
may preallocate `--operation-id o_UUID` before the subcommand for its own retries.
Do not edit or merge the channel's JSON files by hand, force-push the channel,
or move local unconfirmed state into source commits.

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

In remote v0.2, `recover` requires a human participant's session. An agent must
not register as a human to bypass it. On a new computer, register a new session
with `--resumes OLD_SESSION`; the previous node's session cannot perform mutations
from your new clone. When connectivity fails, stop starting shared side effects
until you can refresh ownership.

After recovery, reread and acquire a fresh claim. Checkpoints and fencing protect
protocol records, not arbitrary editors; coordinate one source writer per path.
