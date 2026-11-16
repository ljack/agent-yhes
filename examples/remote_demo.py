#!/usr/bin/env python3
"""Three scripted participants, independent clones, and real remote Git traffic."""
import argparse
import contextlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from remote import Remote


def git(root, *arguments):
    return subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True, text=True).stdout.strip()


@contextlib.contextmanager
def endpoint(root, tcp):
    origin = root / "origin.git"
    subprocess.run(["git", "init", "--bare", "--initial-branch=main", str(origin)], check=True, capture_output=True)
    if not tcp:
        yield str(origin)
        return
    # This unauthenticated demonstration server is accessible only on loopback.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    process = subprocess.Popen(["git", "daemon", "--reuseaddr", "--export-all", "--enable=receive-pack",
                                "--listen=127.0.0.1", f"--port={port}", f"--base-path={root}", str(root)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            if process.poll() is not None:
                raise RuntimeError("local Git demo server exited: " + process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError("local Git demo server did not start")
                time.sleep(0.05)
        yield f"git://127.0.0.1:{port}/origin.git"
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stderr.close()


def run(root, tcp=False):
    with endpoint(root, tcp) as url:
        paths = [root / name for name in ("codex", "claude", "human")]
        for path in paths:
            subprocess.run(["git", "clone", url, str(path)], check=True, capture_output=True)
        # Source code and coordination have separate histories.
        (paths[0] / "example.txt").write_text("Source file remains on main.\n")
        git(paths[0], "add", "example.txt")
        git(paths[0], "-c", "user.name=Demo", "-c", "user.email=demo@localhost", "commit", "-m", "Source seed")
        git(paths[0], "push", "origin", "main")
        for path in paths[1:]:
            git(path, "pull", "--ff-only", "origin", "main")
        a, b, h = [Remote(path) for path in paths]
        a.execute("init")
        sa = a.execute("session", label="Implementer", harness="codex")["result"]
        sb = b.execute("session", label="Peer reviewer", harness="claude")["result"]
        sh = h.execute("session", label="Human reviewer", harness="terminal", participant_type="human")["result"]
        ticket = a.execute("create", session=sa["id"], title="Review the remote collaboration proposal",
                           body="Scripted demo: ask a peer, hand off to a human, and record the conclusion.", scope=["example.txt"])["result"]
        claim = a.execute("claim", session=sa["id"], ticket=ticket["id"], revision=1)["result"]["ticket"]
        question = a.execute("send", session=sa["id"], kind="question", ticket=ticket["id"],
                             to=[{"kind": "agent", "id": sb["agent"]}], body="What makes a remote claim authoritative?")["result"]
        assert question["id"] in [r["id"] for r in b.execute("inbox", session=sb["id"])["result"]["records"]]
        reply = b.execute("send", session=sb["id"], kind="reply", ticket=ticket["id"], reply_to=question["id"],
                          to=[{"kind": "agent", "id": sa["agent"]}],
                          body="The claim is confirmed when its operation is present on the shared remote branch.")["result"]
        b.execute("ack", session=sb["id"], message=question["id"], stage="handled")
        a.execute("ack", session=sa["id"], message=reply["id"], stage="handled")
        handoff = a.execute("send", session=sa["id"], kind="handoff", ticket=ticket["id"],
                            to=[{"kind": "agent", "id": sh["agent"]}],
                            body="Peer answered: successful remote publication confirms ownership. Please review the conclusion.")["result"]
        a.execute("finish", session=sa["id"], ticket=ticket["id"], revision=claim["revision"],
                  token=claim["lease"]["token"], state="review", message=handoff["id"], summary="Ready for human review")
        human_claim = h.execute("claim", session=sh["id"], ticket=ticket["id"], revision=3)["result"]["ticket"]
        result = h.execute("send", session=sh["id"], kind="result", ticket=ticket["id"], to=[{"kind": "project"}],
                           body="Scripted human review complete: begin work after the operation is confirmed remotely. The three independent clones exchanged and retained the conclusion.")["result"]
        h.execute("ack", session=sh["id"], message=handoff["id"], stage="handled")
        h.execute("finish", session=sh["id"], ticket=ticket["id"], revision=human_claim["revision"],
                  token=human_claim["lease"]["token"], state="done", message=result["id"],
                  summary="Remote collaboration exercised", evidence=["Three separate clones used real Git fetch/push."])
        for remote in (a, b, h):
            assert remote.execute("show", ticket=ticket["id"])["result"]["ticket"]["status"] == "done"
            assert result["id"] in [r["id"] for r in remote.execute("memory")["result"]["records"]]
        for path in paths:
            assert git(path, "status", "--porcelain") == ""
        return {"root": str(root), "transport": "Git over loopback TCP" if tcp else "local bare Git remote",
                "participants": "scripted Codex, Claude and human in three independent clones",
                "ticket": ticket["id"], "result_message": result["id"], "status": "done",
                "source_worktrees": "unchanged", "server": "stopped on exit" if tcp else "local file remote"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tcp", action="store_true", help="exercise Git networking through a temporary loopback server")
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="agent-yhes-v02-")).resolve()
    print(json.dumps(run(root, tcp=args.tcp), indent=2))
