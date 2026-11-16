#!/usr/bin/env python3
"""Scripted question/reply/result with real Git and authenticated JetStream."""
import asyncio
import contextlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from remote import Remote
from realtime import NatsBroker, Realtime
from broker_support import DemoBroker
from remote_demo import endpoint, git


async def run(root):
    server = DemoBroker(root / "nats").start()
    tasks = []
    try:
        with endpoint(root, tcp=False) as url:
            paths = [root / name for name in ("codex", "claude")]
            for path in paths:
                subprocess.run(["git", "clone", url, str(path)], check=True, capture_output=True)
            a, b = [Remote(path) for path in paths]
            a.execute("init")
            sa = a.execute("session", label="Implementer", harness="codex")["result"]
            sb = b.execute("session", label="Reviewer", harness="claude")["result"]
            ra = Realtime(a, NatsBroker(server.url, server.token))
            rb = Realtime(b, NatsBroker(server.url, server.token))
            await ra.provision()
            ticket = (await ra.execute("create", session=sa["id"], title="Review realtime delivery",
                        body="Scripted example: ask a peer, receive a live reply and retain a result."))["result"]
            claim = (await ra.execute("claim", session=sa["id"], ticket=ticket["id"], revision=1))["result"]["ticket"]
            ready_a, ready_b, got_question, got_reply = [asyncio.Event() for _ in range(4)]
            events = []
            def receive(label, ready, signal, expected_kind):
                def emit(event):
                    events.append({"receiver": label, **event})
                    ready.set()
                    if event["reason"] == "broker" and any(m["kind"] == expected_kind for m in event["inbox"]["records"]):
                        signal.set()
                return emit
            # Distinct connections per listener: a participant can send while
            # its listener waits without sharing a connect/close lifecycle.
            wa = Realtime(Remote(paths[0]), NatsBroker(server.url, server.token))
            wb = Realtime(Remote(paths[1]), NatsBroker(server.url, server.token))
            tasks = [asyncio.create_task(wa.listen(sa["id"], receive("codex", ready_a, got_reply, "reply"), seconds=20)),
                     asyncio.create_task(wb.listen(sb["id"], receive("claude", ready_b, got_question, "question"), seconds=20))]
            await asyncio.wait_for(asyncio.gather(ready_a.wait(), ready_b.wait()), 10)
            question = (await ra.execute("send", session=sa["id"], kind="question", ticket=ticket["id"],
                        to=[{"kind": "agent", "id": sb["agent"]}], body="Does a broker receipt finish the ticket?"))["result"]
            await asyncio.wait_for(got_question.wait(), 10)
            reply = (await rb.execute("send", session=sb["id"], kind="reply", ticket=ticket["id"], reply_to=question["id"],
                        to=[{"kind": "agent", "id": sa["agent"]}], body="Broker receipts confirm notification transport. Ticket completion and handled receipts remain in Git."))["result"]
            await rb.execute("ack", session=sb["id"], message=question["id"], stage="handled")
            await asyncio.wait_for(got_reply.wait(), 10)
            result = (await ra.execute("send", session=sa["id"], kind="result", ticket=ticket["id"],
                        to=[{"kind": "project"}], body="The broker delivered live change hints to both scripted participants. Each fetched the actual messages from Git. Project-level handling and completion were recorded separately."))["result"]
            await ra.execute("ack", session=sa["id"], message=reply["id"], stage="handled")
            await ra.execute("finish", session=sa["id"], ticket=ticket["id"], revision=claim["revision"],
                        token=claim["lease"]["token"], state="done", message=result["id"], summary="Realtime exchange completed",
                        evidence=["Both running listeners observed the expected message after a broker notification."])
            assert b.execute("show", ticket=ticket["id"])["result"]["ticket"]["status"] == "done"
            assert all(git(path, "status", "--porcelain") == "" for path in paths)
            return {"root": str(root), "participants": "scripted Codex and Claude in independent clones",
                    "transport": "real Git and authenticated NATS JetStream over TCP",
                    "broker_snapshots": sum(e["reason"] == "broker" for e in events),
                    "question_received_live": got_question.is_set(), "reply_received_live": got_reply.is_set(),
                    "ticket_status": "done", "server": "stopped on exit"}
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        server.stop()


if __name__ == "__main__":
    root = Path(tempfile.mkdtemp(prefix="agent-yhes-v03-")).resolve()
    print(json.dumps(asyncio.run(run(root)), indent=2))
