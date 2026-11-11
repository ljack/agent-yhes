# Validation of this draft

Executed on 2026-11-11 on macOS using Python 3.14.3. This is a local reference
implementation check, not a vendor compatibility certification.

## Passed

`python3 -m unittest discover -s tests -v`: **19 tests passed**.

The tests exercise observable protocol behavior:

- Eight independent processes claiming the same revision produce one winner.
- Eight concurrent sends preserve all distinct messages.
- A generated ticket-ID collision cannot replace an existing task.
- A failed publication before rename preserves the previous ticket and history.
- A terminated lock-owning process releases the OS lock; its inode remains.
- Expiry blocks automatic takeover and late renewal; recorded recovery changes
  the generation, and the former owner's token cannot mutate the new claim.
- A live claim cannot be recovered, stale revisions fail and renewal cannot
  shorten an existing lease.
- An expired owner can voluntarily hand off but cannot declare completion.
- Listing and display limits do not consume messages; seen remains pending and
  handled cannot regress to seen.
- A reply saved before an interrupted acknowledgment remains discoverable;
  identical-ID retries are stable and changed content is rejected.
- Explicit session continuation discovers pending session-addressed messages
  and preserves predecessor handled receipts without changing agent identity.
- Live expiry hides activity while preserving the file and durable memory.
- Invalid/unsupported records are reported without hiding valid messages.
- Supersession preserves original memory, dependency gates work, overlapping
  scopes produce a warning and completion requires evidence.
- Path traversal is rejected; imperative message text is stored literally.
- An uninitialized read does not create protocol directories; CLI round trips
  work and conflicts return exit code 3.

`python3 examples/demo.py`: **passed**. The complete claim → question → reply →
durable decision/result → completion flow ran using two simulated identities.
The script leaves an inspectable disposable directory and prints its location.

The sample export contains **14 valid JSON records**, including two tickets,
two sessions, question/reply, intent, decision, result, handoff, task request and
two receipts, plus the project descriptor. Export intentionally omits `.lock`.

Both skills passed the `skill-creator/scripts/quick_validate.py` validator.
The initial system-Python invocation lacked PyYAML; validation succeeded through
`uv run --with pyyaml python .../quick_validate.py <skill-directory>`.
The runtime helper and its tests use only the Python standard library.

Internal Markdown file links were checked for existing targets. The final ZIP
is built from an explicit public-file allowlist and checked for corruption and
unexpected paths; private `.tickets`, machine intake state and caches are absent.

## Not established by these checks

- Real Codex–Claude, Antigravity, Copilot or Cursor execution and idle wake-up.
  [The live trial procedure](../examples/WALKTHROUGH.md) is ready to run.
- A receiving model's resistance to prompt injection. The literal-storage test
  does not test a model's decisions. The skill and spec define the boundary;
  the live trial must exercise it.
- Independent verification of worker shutdown from a recovery caller's text.
- Protection against hostile same-account processes, arbitrary source editors,
  in-flight external side effects, or scope overlap ignored by a participant.
- Linux, native Windows, network filesystems, power loss, disk exhaustion,
  very large project histories or cross-machine synchronization.

These limits are deliberate boundaries of the first experiment. No reference
project was rebuilt or deployed as part of this validation.

## Publication status

Jarkko selected the name **agent-yhes** and authorized publication of this draft
at [ljack/agent-yhes](https://github.com/ljack/agent-yhes). That publication does
not change the validation limits above. License selection remains open.
