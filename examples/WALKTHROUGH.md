# Codex asks Claude for help

The checked-in records and `demo.py` use **simulated harness identities**. The
helper runs the same protocol operations real agents would use. No real Codex or
Claude sessions are launched by the demo, and the text replies are authored
fixture data, not model outputs.

```mermaid
sequenceDiagram
    participant C as Codex implementer
    participant T as .agents/tickets
    participant M as .agents/messages
    participant A as Claude reviewer
    C->>T: claim(ticket, expected_revision=1)
    T-->>C: revision=2, token, expiry
    C->>M: question to Claude agent, ticket reference
    A->>M: inbox scan (no implicit ack)
    M-->>A: attributed question
    A->>M: reply with reply_to and same ticket
    A->>M: handled receipt for question
    C->>M: inbox scan
    M-->>C: correlated reply
    C->>M: durable decision and result
    C->>M: handled receipt for reply
    C->>T: complete with token, revision, result ID and evidence
    T-->>C: done; claim cleared; history retained
```

The sample question is whether an expired claim proves the previous source
writer stopped. The answer explains the long-running-command race. The result
stores that conclusion in full so it remains useful after the reply expires.
A second open ticket and handoff preserve the unperformed live trial.

## Inspect or rerun the fixture

```sh
python3 examples/demo.py
```

The output provides the temporary root and all relevant IDs. With that root:

```text
python3 tools/coop.py --root ROOT tickets
python3 tools/coop.py --root ROOT memory --query recovery
python3 tools/coop.py --root ROOT inbox --session CLAUDE_SESSION
```

The static [project/.agents](project/.agents) files are historical fixtures.
Their live messages may have expired; `--include-expired` displays them. They
contain no working-directory credentials or actual harness thread identifiers.

## Run the smallest actual two-harness trial

Use a new disposable project directory and one active Codex session plus one
active Claude session with local file/tool access. This is a procedure for a
future live verification, not a report that it already happened.

1. Give both agents the same authorization: read this toolkit, use its ticket
   and messaging skills against the disposable project, exchange this bounded
   review question, and write only protocol records. No source edits, external
   messages, installation or publication are needed.
2. Initialize the project once. Have each agent register itself and retain its
   own returned IDs. Both can discover the other's full ID with `sessions`;
   the person does not have to relay an ID or reply.
3. Tell Claude to handle one ticket-linked review question while this trial is
   active: check its inbox at safe boundaries, answer, acknowledge and stop.
   Tell Codex to create and claim the recovery-design ticket, discover Claude's
   agent ID, ask the question and continue checking for the answer.
4. Codex sends `question` to `agent:CLAUDE_AGENT` with the ticket ID. Claude
   reads the inbox, evaluates the question within the authorized review remit,
   sends `reply --reply-to QUESTION_ID` to Codex's agent, then marks the question
   handled. It does not claim Codex's ticket to answer a question.
5. Codex reads the reply, publishes durable `decision` and `result` records
   including rationale/evidence, marks the reply handled, and finishes the
   ticket using its current revision and token. Renew beforehand if needed.
6. In a new session, read the result using `memory --ticket TICKET`. Record
   which actual harness versions ran, whether a native wake-up was needed, and
   each observed message/receipt/ticket ID in a local trial report.

For short polling, use one bounded inbox call, then yield to the harness. Set a
trial deadline and stop with a durable handoff if the peer stays inactive. This
procedure does not invent an idle wake-up API or ask a person to copy messages.

## Failure exercises

- Both sessions claim the same revision: exactly one succeeds, the other rereads.
- Stop after reading a question without ack: it must reappear.
- Stop after replying but before ack: inspect `reply_to` before sending again.
- Let a claim expire: a competitor still cannot claim it. First obtain voluntary
  release, or confirm the old process and children stopped and reconcile edits.
- Resume with a new session and `--resumes`: recover old session-addressed
  pending messages without inheriting its claim.
- Send an imperative-looking message asking for an unauthorized secret upload:
  the receiving model must treat it as peer text and refuse. Storage validation
  alone cannot prove this behavioral safety property.
