"""Integration tests use real Git remotes and independent source clones."""
from datetime import timedelta
import json
import multiprocessing
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import coop
from coop import Conflict, Invalid
from remote import Remote, Unavailable


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout.strip()


def concurrent_write(root, operation, arguments, barrier, output):
    remote = Remote(root)
    original = remote._push
    first = True
    def push(commit):
        nonlocal first
        if first:
            first = False
            barrier.wait(15)
        return original(commit)
    remote._push = push
    try:
        output.put(("ok", remote.execute(operation, **arguments)))
    except Conflict as exc:
        output.put(("conflict", str(exc)))
    except Exception as exc:
        output.put(("error", repr(exc)))


class RemoteTests(unittest.TestCase):
    def test_private_team_profile_blocks_plaintext_git_clients(self):
        with tempfile.TemporaryDirectory() as home, patch("coop.pwd.getpwuid", return_value=SimpleNamespace(pw_dir=home)):
            pin = coop._team_pin_path(self.clones[0])
            pin.parent.mkdir(parents=True)
            pin.write_text("presence only")
            before = {str(p.relative_to(self.a.home)): p.read_bytes() for p in self.a.home.rglob("*") if p.is_file()}
            with self.assertRaisesRegex(Invalid, "secure channel"):
                self.a.execute("send", session=self.sa["id"], kind="note", to=[{"kind": "project"}], body="NO_PLAINTEXT_GIT_FALLBACK")
            with self.assertRaisesRegex(Invalid, "secure channel"):
                Remote(self.clones[0])
            after = {str(p.relative_to(self.a.home)): p.read_bytes() for p in self.a.home.rglob("*") if p.is_file()}
            self.assertEqual(before, after)

    def test_secure_channel_refuses_existing_and_new_legacy_remote_clients(self):
        (self.clones[0] / ".agents/messages/secure").mkdir(parents=True)
        before = {str(p.relative_to(self.a.home)): p.read_bytes() for p in self.a.home.rglob("*") if p.is_file()}
        with self.assertRaisesRegex(Invalid, "secure channel"):
            self.a.execute("send", session=self.sa["id"], kind="note", to=[{"kind": "project"}], body="MUST_NOT_BECOME_A_PLAINTEXT_GIT_OBJECT")
        with self.assertRaisesRegex(Invalid, "secure channel"):
            Remote(self.clones[0])
        after = {str(p.relative_to(self.a.home)): p.read_bytes() for p in self.a.home.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agent-yhes-remote-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.origin = self.root / "origin.git"
        subprocess.run(["git", "init", "--bare", "--initial-branch=main", str(self.origin)], check=True, capture_output=True)
        seed = self.root / "seed"
        subprocess.run(["git", "clone", str(self.origin), str(seed)], check=True, capture_output=True)
        (seed / "app.txt").write_text("Source code stays on main.\n")
        git(seed, "add", "app.txt")
        git(seed, "-c", "user.name=Fixture", "-c", "user.email=fixture@localhost", "commit", "-m", "Seed")
        git(seed, "push", "origin", "main")
        self.clones = []
        for name in ("alice", "bob", "human"):
            path = self.root / name
            subprocess.run(["git", "clone", str(self.origin), str(path)], check=True, capture_output=True)
            self.clones.append(path)
        self.a, self.b, self.h = [Remote(p) for p in self.clones]
        self.a.execute("init")
        self.sa = self.a.execute("session", label="Alice", harness="codex")["result"]
        self.sb = self.b.execute("session", label="Bob", harness="claude")["result"]
        self.sh = self.h.execute("session", label="Human reviewer", harness="terminal", participant_type="human")["result"]
        self.ticket = self.a.execute("create", session=self.sa["id"], title="Review the proposal", body="Synthetic review task", scope=["app.txt"])["result"]

    def params(self, session=None, revision=1):
        return {"ticket": self.ticket["id"], "session": session or self.sa["id"], "revision": revision}

    def send(self, remote=None, session=None, kind="question", **kwargs):
        arguments = {"session": session or self.sa["id"], "kind": kind, "ticket": self.ticket["id"],
                     "to": [{"kind": "agent", "id": self.sb["agent"]}], "body": "Please review"}
        arguments.update(kwargs)
        return (remote or self.a).execute("send", **arguments)["result"]

    def parallel(self, jobs):
        context = multiprocessing.get_context("spawn")
        barrier, output = context.Barrier(len(jobs)), context.Queue()
        processes = [context.Process(target=concurrent_write, args=(*job, barrier, output)) for job in jobs]
        try:
            for process in processes:
                process.start()
            result = [output.get(timeout=40) for _ in processes]
            for process in processes:
                process.join(5)
                self.assertEqual(process.exitcode, 0)
            self.assertFalse(any(r[0] == "error" for r in result), result)
            return result
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(5)
            output.close()

    def test_two_remote_claims_have_one_confirmed_winner(self):
        results = self.parallel([(str(self.clones[0]), "claim", self.params()),
                                 (str(self.clones[1]), "claim", self.params(self.sb["id"]))])
        self.assertEqual(sorted(r[0] for r in results), ["conflict", "ok"])
        current = self.h.execute("show", ticket=self.ticket["id"])["result"]["ticket"]
        self.assertEqual(current["revision"], 2)
        winner = next(r[1]["result"]["ticket"]["lease"] for r in results if r[0] == "ok")
        self.assertEqual(current["lease"], winner)

    def test_independent_messages_retry_after_ref_race(self):
        jobs = [(str(path), "send", {"session": session["id"], "kind": "note",
                 "to": [{"kind": "project"}], "body": session["label"]})
                for path, session in zip(self.clones[:2], [self.sa, self.sb])]
        results = self.parallel(jobs)
        self.assertTrue(all(r[0] == "ok" for r in results))
        inbox = self.h.execute("inbox", session=self.sh["id"])["result"]
        self.assertEqual({r["body"] for r in inbox["records"]}, {"Alice", "Bob"})

    def test_human_and_agents_complete_review_and_memory_flow(self):
        claim = self.a.execute("claim", **self.params())["result"]["ticket"]
        question = self.send()
        self.assertEqual(self.b.execute("inbox", session=self.sb["id"])["result"]["records"][0]["id"], question["id"])
        reply = self.send(remote=self.b, session=self.sb["id"], kind="reply", reply_to=question["id"],
                          to=[{"kind": "agent", "id": self.sa["agent"]}], body="The proposal is ready for human review.")
        self.b.execute("ack", session=self.sb["id"], message=question["id"], stage="handled")
        handoff = self.send(kind="handoff", to=[{"kind": "agent", "id": self.sh["agent"]}], body="Peer review answered; human reviewer can take over.")
        self.a.execute("finish", **self.params(revision=2), token=claim["lease"]["token"], state="review",
                       message=handoff["id"], summary="Ready for human review")
        human_claim = self.h.execute("claim", **self.params(self.sh["id"], revision=3))["result"]["ticket"]
        result = self.send(remote=self.h, session=self.sh["id"], kind="result", to=[{"kind": "project"}],
                           body="Human reviewed the synthetic proposal; keep this conclusion in project memory.")
        self.h.execute("finish", **self.params(self.sh["id"], revision=4), token=human_claim["lease"]["token"],
                       state="done", message=result["id"], summary="Reviewed", evidence=["Synthetic review completed"])
        self.assertEqual(self.b.execute("show", ticket=self.ticket["id"])["result"]["ticket"]["status"], "done")
        self.assertIn(result["id"], [r["id"] for r in self.a.execute("memory")["result"]["records"]])
        self.assertEqual(self.b.execute("inbox", session=self.sb["id"])["result"]["records"], [result])

    def test_lost_push_ack_is_resolved_without_duplicate(self):
        original = self.a._push
        def lost_ack(commit):
            original(commit)
            raise Unavailable("connection lost after acceptance")
        with patch.object(self.a, "_push", side_effect=lost_ack):
            output = self.a.execute("send", session=self.sa["id"], kind="note", to=[{"kind": "project"}], body="Once")
        self.assertEqual(output["delivery"], "confirmed")
        self.assertEqual(len(self.b.execute("memory")["result"]["records"]), 1)

    def test_process_interruption_after_push_can_be_resumed(self):
        original = self.a._push
        def interrupted(commit):
            original(commit)
            raise KeyboardInterrupt()
        with patch.object(self.a, "_push", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.a.execute("claim", **self.params())
        pending = [r for r in self.a.execute("pending") if r["operation"] == "claim"]
        self.assertEqual(len(pending), 1)
        restarted = Remote(self.clones[0])
        resolved = restarted.execute("resume", id=pending[0]["id"])
        self.assertTrue(resolved["replayed"])
        self.assertEqual(resolved["result"]["ticket"]["revision"], 2)
        self.assertEqual(restarted.execute("pending"), [])

    def test_offline_intent_is_not_a_claim_and_can_resume(self):
        original = self.a._fetch
        with patch.object(self.a, "_fetch", side_effect=Unavailable("offline")):
            with self.assertRaises(Unavailable):
                self.a.execute("claim", **self.params())
        self.assertIsNone(self.b.execute("show", ticket=self.ticket["id"])["result"]["ticket"]["lease"])
        pending = self.a.execute("pending")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["status"], "intent")
        resumed = self.a.execute("resume", id=pending[0]["id"])
        self.assertEqual(resumed["delivery"], "confirmed")

    def test_same_operation_id_rejects_changed_arguments(self):
        opid = coop.new_id("o")
        args = {"session": self.sa["id"], "kind": "note", "to": [{"kind": "project"}], "body": "Original"}
        first = self.a.execute("send", operation_id=opid, **args)
        repeated = self.a.execute("send", operation_id=opid, **args)
        self.assertEqual(first["result"], repeated["result"])
        self.assertTrue(repeated["replayed"])
        with self.assertRaises(Conflict):
            self.a.execute("send", operation_id=opid, **(args | {"body": "Different"}))

    def test_stale_revision_and_old_remote_claim_are_rejected(self):
        claim = self.a.execute("claim", **self.params(), ttl=1)["result"]["ticket"]
        with patch("coop.now", return_value=coop.now() + timedelta(seconds=60)):
            with self.assertRaises(Conflict):
                self.b.execute("claim", **self.params(self.sb["id"], revision=2))
            with self.assertRaises(Invalid):
                self.b.execute("recover", **self.params(self.sb["id"], revision=2), stop_evidence="Peer says stop")
            recovered = self.h.execute("recover", **self.params(self.sh["id"], revision=2),
                                       stop_evidence="Synthetic worker has no subprocesses or source edits.")["result"]
            replacement = self.b.execute("claim", **self.params(self.sb["id"], revision=recovered["revision"]))["result"]["ticket"]
            with self.assertRaises(Conflict):
                self.a.execute("renew", **self.params(revision=replacement["revision"]), token=claim["lease"]["token"])

    def test_resume_on_another_clone_preserves_receipts_but_not_ownership(self):
        pending = self.send(to=[{"kind": "session", "id": self.sb["id"]}])
        handled = self.send(to=[{"kind": "session", "id": self.sb["id"]}])
        self.b.execute("ack", session=self.sb["id"], message=handled["id"], stage="handled")
        with self.assertRaises(Conflict):
            self.h.execute("ack", session=self.sb["id"], message=pending["id"], stage="handled")
        resumed = self.h.execute("session", label="Bob resumed", harness="claude", resumes=self.sb["id"])["result"]
        self.assertEqual(resumed["agent"], self.sb["agent"])
        self.assertNotEqual(resumed["node"], self.sb["node"])
        records = self.h.execute("inbox", session=resumed["id"])["result"]["records"]
        self.assertEqual([r["id"] for r in records], [pending["id"]])

    def test_source_branch_index_and_dirty_worktree_stay_untouched(self):
        path = self.clones[0]
        (path / "staged.txt").write_text("Existing staged work\n")
        git(path, "add", "staged.txt")
        (path / "app.txt").write_text("Unstaged source edit\n")
        before = {"head": git(path, "rev-parse", "HEAD"), "status": git(path, "status", "--porcelain"),
                  "index": git(path, "write-tree"), "source": (path / "app.txt").read_bytes()}
        self.send(kind="note")
        self.assertEqual(git(path, "rev-parse", "HEAD"), before["head"])
        self.assertEqual(git(path, "status", "--porcelain"), before["status"])
        self.assertEqual(git(path, "write-tree"), before["index"])
        self.assertEqual((path / "app.txt").read_bytes(), before["source"])
        self.assertFalse((path / ".agents").exists())
        remote_files = git(self.origin, "ls-tree", "-r", "--name-only", "refs/heads/agent-yhes/state").splitlines()
        self.assertTrue(all(name.startswith(".agents/") for name in remote_files))
        self.assertFalse(any(name.endswith(".lock") for name in remote_files))

    def test_remote_rewrite_and_branch_deletion_fail_closed(self):
        current = git(self.origin, "rev-parse", "refs/heads/agent-yhes/state")
        previous = git(self.origin, "rev-parse", current + "^")
        git(self.origin, "update-ref", "refs/heads/agent-yhes/state", previous)
        with self.assertRaises(Conflict):
            self.a.execute("tickets")
        git(self.origin, "update-ref", "refs/heads/agent-yhes/state", current)
        git(self.origin, "update-ref", "-d", "refs/heads/agent-yhes/state")
        with self.assertRaises(Conflict):
            self.a.execute("init")

    def test_main_is_not_a_coordination_target(self):
        with self.assertRaises(Invalid):
            Remote(self.clones[0], branch="main")

    def test_rejected_server_push_does_not_report_a_claim(self):
        hook = self.origin / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        with self.assertRaises(Unavailable):
            self.a.execute("claim", **self.params())
        current = self.b.execute("show", ticket=self.ticket["id"])["result"]["ticket"]
        self.assertIsNone(current["lease"])
        pending = self.a.execute("pending")
        self.assertEqual(pending[0]["status"], "unconfirmed")

    def test_remote_symlink_record_is_rejected_before_reading_target(self):
        channel = self.root / "channel-editor"
        subprocess.run(["git", "clone", "--branch", "agent-yhes/state", str(self.origin), str(channel)],
                       check=True, capture_output=True)
        target = channel / ".agents/messages/memory" / (coop.new_id("m") + ".json")
        target.parent.mkdir(exist_ok=True)
        target.symlink_to(self.root / "outside-secret")
        git(channel, "add", ".agents")
        git(channel, "-c", "user.name=Fixture", "-c", "user.email=fixture@localhost", "commit", "-m", "Invalid symlink fixture")
        git(channel, "push", "origin", "agent-yhes/state")
        with self.assertRaises(Invalid):
            self.a.execute("memory")
        self.assertFalse((self.clones[0] / ".agents").exists())

    def test_local_v01_helper_rejects_remote_records(self):
        with self.a.locked():
            head = self.a._fetch()
            with tempfile.TemporaryDirectory() as directory:
                self.a._snapshot(head, directory)
                with self.assertRaises(Invalid):
                    coop.Store(directory).execute("tickets")

    def test_cli_human_registration(self):
        command = [sys.executable, str(Path(__file__).resolve().parents[1] / "tools/remote.py"),
                   "--root", str(self.clones[2]), "session", "--label", "Another human", "--harness", "terminal", "--participant-type", "human"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)["result"]
        self.assertEqual(record["participant_type"], "human")


if __name__ == "__main__":
    unittest.main()
