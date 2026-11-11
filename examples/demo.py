#!/usr/bin/env python3
"""Protocol demonstration; simulated harness identities, no model calls."""
from pathlib import Path
import json
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from coop import Store


def run(root):
    store = Store(root)
    store.execute("init")
    codex = store.execute("session", label="implementer (simulated)", harness="codex")
    claude = store.execute("session", label="reviewer (simulated)", harness="claude")
    ticket = store.execute("create", session=codex["id"], title="Choose safe stale-claim behavior",
                           body="Synthetic trial authorized by the demo runner. Explain safe expiry recovery; do not edit application source.",
                           scope=["docs/recovery.md"])
    claim = store.execute("claim", ticket=ticket["id"], session=codex["id"], revision=1)["ticket"]
    store.execute("send", session=codex["id"], kind="intent", ticket=ticket["id"], to=[{"kind": "project"}],
                  body="Reviewing the planned docs/recovery.md scope for this ticket. This synthetic run writes only protocol records; no source editing is underway.", ttl=900)
    question = store.execute("send", session=codex["id"], kind="question", ticket=ticket["id"],
                             to=[{"kind": "agent", "id": claude["agent"]}],
                             body="Can expiry alone prove the old source writer stopped? Please review the recovery rule.")
    inbox = store.execute("inbox", session=claude["id"])
    assert question["id"] in [r["id"] for r in inbox["records"]]
    reply = store.execute("send", session=claude["id"], kind="reply", ticket=ticket["id"], reply_to=question["id"],
                          to=[{"kind": "agent", "id": codex["agent"]}],
                          body="No. A long-running command may still write after expiry. Require voluntary release or confirmed-stop recovery.")
    store.execute("ack", session=claude["id"], message=question["id"], stage="handled")
    assert reply["id"] in [r["id"] for r in store.execute("inbox", session=codex["id"])["records"]]
    decision = store.execute("send", session=codex["id"], kind="decision", ticket=ticket["id"],
                             to=[{"kind": "project"}],
                             body="Proposed trial decision: expiry requires recovery. Claude's simulated review identified a still-running writer as the reason. This records a design proposal, not a new user approval.")
    result = store.execute("send", session=codex["id"], kind="result", ticket=ticket["id"],
                           to=[{"kind": "project"}],
                           body="Synthetic protocol exercise completed: the implementer claimed work, requested a peer review and received the reply. Conclusion: an expiry timestamp does not prove a writer stopped; recovery needs voluntary release or confirmed stop evidence. No real harnesses or application source edits were involved. Decision: " + decision["id"])
    store.execute("ack", session=codex["id"], message=reply["id"], stage="handled")
    done = store.execute("finish", ticket=ticket["id"], session=codex["id"], revision=claim["revision"],
                         token=claim["lease"]["token"], state="done", message=result["id"],
                         summary="Documented safe expiry recovery in durable project memory.",
                         evidence=["Question and correlated reply were observed in separate simulated session inboxes.",
                                   "Durable result contains the conclusion independently of the ephemeral reply."])
    followup = store.execute("create", session=codex["id"], title="Run a real two-harness trial",
                             body="Proposal only: live interoperability remains unverified. Read WALKTHROUGH.md before deciding to run it.",
                             depends_on=[done["id"]])
    handoff = store.execute("send", session=codex["id"], kind="handoff", ticket=followup["id"],
                            to=[{"kind": "agent", "id": claude["agent"]}],
                            body="The deterministic protocol demonstration passed. No live model was launched. Next: an authorized disposable Codex/Claude trial following WALKTHROUGH.md; preserve this distinction in reporting.")
    store.execute("send", session=codex["id"], kind="task_request", ticket=followup["id"],
                  to=[{"kind": "agent", "id": claude["agent"]}],
                  body="Review the proposed live trial when authorized; handoff " + handoff["id"])
    return {"mode": "simulated identities; no models launched", "root": str(root),
            "codex_session": codex["id"], "claude_session": claude["id"],
            "completed_ticket": done["id"], "question": question["id"], "reply": reply["id"],
            "memory_result": result["id"], "followup_ticket": followup["id"]}


if __name__ == "__main__":
    root = Path(tempfile.mkdtemp(prefix="local-agent-demo-"))
    print(json.dumps(run(root), indent=2))
