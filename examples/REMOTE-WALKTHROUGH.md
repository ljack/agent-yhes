# Agents and a person share work through Git

Run `python3 examples/remote_demo.py --tcp` for a complete scripted example. It
creates three independent clones and a temporary Git server bound to loopback.
The participants exchange a question and answer, hand a ticket to a human
reviewer, and save the outcome as shared memory. The script stops the server
afterward and prints the directory containing the bare remote and source clones.

All fetches and pushes are real Git operations. The participant replies and human
actions in this demo are scripted. To try it with actual people or harnesses on
different computers, follow the steps below.

## Set up the shared channel once

Choose a repository that every participant can read and push to. On each
computer, install Python 3.10+, Git and a copy of this toolkit. Clone the project
normally and use the same remote/branch in every coordination command.
The example uses `/path/project`, its `origin` remote and `agent-yhes/state`.

On the organizer's computer:

```sh
python3 /path/agent-yhes/tools/remote.py --root /path/project init
```

This creates an independent coordination branch on that remote. The existing
source branch stays as it is. Use `--remote NAME --branch agent-yhes/CHANNEL`
before the subcommand if your project uses another coordination repository or
channel. In the Git host, allow ordinary collaborator pushes to this channel and
disable force-push/deletion. Private conversations need a private repository.

## Each participant registers from their own clone

Agent on computer A:

```sh
python3 /path/agent-yhes/tools/remote.py --root /path/project session \
  --label implementer --harness codex
```

Agent on computer B:

```sh
python3 /path/agent-yhes/tools/remote.py --root /path/project session \
  --label reviewer --harness claude
```

Person on computer C:

```sh
python3 /path/agent-yhes/tools/remote.py --root /path/project session \
  --label 'Human reviewer' --harness terminal --participant-type human
```

Save `result.id` (session) and `result.agent` (participant) from each response.
`sessions` lets everyone discover the other participants directly. A user sets
the task and authorizes each agent's scope once; messages then travel through
the Git branch without the user forwarding them.

All remaining commands use the same prefix:

```text
python3 /path/agent-yhes/tools/remote.py --root /path/project COMMAND ...
```

## Claim, ask, review and record the outcome

1. The implementer uses `create --session SESSION --title TEXT --body TEXT`
   with acceptance criteria and optional `--scope PATH`. Save `result.id`.
2. It claims the ticket with `claim TICKET --session SESSION --revision 1`.
   Wait for `delivery: confirmed`; retain `result.ticket.revision` and
   `result.ticket.lease.token`. `show TICKET` gives current ownership.
3. It sends `send --session SESSION --kind question --to agent:REVIEWER_ID
   --ticket TICKET --body TEXT`. The reviewer reads `inbox --session SESSION`,
   sends a correlated `send --kind reply --reply-to QUESTION_ID` to the implementer, then
   uses `ack --message QUESTION_ID --session SESSION --stage handled`.
4. The implementer publishes a durable `handoff` to the human reviewer and
   calls `finish TICKET --session SESSION --revision N --token TOKEN
   --state review --message HANDOFF_ID --summary TEXT`. Ownership is released.
5. The person reads their inbox, claims the current ticket revision, and checks
   the work. They save a durable `result` addressed to `project`, then finish
   with `--state done --message RESULT_ID --summary TEXT --evidence TEXT`.
6. Everyone can read `memory --ticket TICKET` from their own computer. The result
   includes the conclusion and evidence so it stands on its own after a reply
   expires. Mark the relevant input messages handled after recording the outcome.

Renew a live claim using its current revision/token before the lease expires.
Use separate tickets for independent implementation work. A question's recipient
can answer without taking the sender's ticket. Source changes travel through the
project's ordinary branches and pull requests, independently of this channel.

## Continue after a dropped connection or another computer

`pending` shows locally saved writes. `resolve o_UUID` checks whether the remote
accepted a write. `resume o_UUID` retries its original request. Reuse its ID and
revision rather than issuing a second claim or repeating external work.

On a replacement computer, register a new session with `--resumes OLD_SESSION`.
Humans also pass `--participant-type human`. Pending session-addressed messages
and handled receipts follow the session chain. The old claim still needs a
handoff or human-confirmed stop/recovery before the new session can take it.

If two agents race to claim, only the successful remote operation owns the work.
The other receives a conflict and should inspect the ticket. An offline intent,
a rejected push or an expired lease is not permission to proceed.
