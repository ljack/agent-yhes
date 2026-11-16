#!/usr/bin/env python3
"""Real Git arbitration fixture. It publishes only explicit public wire records.

This is not the production transport or an identity/authorization verifier.
All fixture participants are deliberately trusted; only throwaway keys are used.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from adapter import Adapter, Rejected, canonical, digest, pause_at

REF = "refs/heads/mls-experiment"
STATE_PATH = ".agents/tickets/group.json"
RECORD_DIR = ".agents/messages/crypto/"


class GitFixture:
    def __init__(self, root, name):
        self.root = Path(root).resolve()
        if not (self.root / "EXPERIMENT_ONLY").is_file():
            raise Rejected("disposable fixture root required")
        self.origin = self.root / "remote.git"
        self.mirror = self.root / (name + ".git")
        if not self.origin.exists():
            subprocess.run(["git", "init", "--bare", "--initial-branch=main", str(self.origin)], check=True, capture_output=True)
        if not self.mirror.exists():
            subprocess.run(["git", "init", "--bare", "--template=", str(self.mirror)], check=True, capture_output=True)

    def command(self, *args):
        return ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "--git-dir=" + str(self.mirror), *args]

    def git(self, *args, data=None, check=True, env=None):
        return subprocess.run(self.command(*args), input=data, capture_output=True, check=check, env=env)

    def fetch(self):
        if not self.git("ls-remote", str(self.origin), REF).stdout.strip():
            return None, None
        self.git("fetch", "--no-tags", str(self.origin), REF)
        head = self.git("rev-parse", "FETCH_HEAD").stdout.decode().strip()
        state = json.loads(self.git("show", head + ":" + STATE_PATH).stdout)
        return head, state

    def record(self, head, opid):
        result = self.git("show", head + ":" + RECORD_DIR + opid + ".json", check=False)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def commit(self, parent, files):
        with tempfile.TemporaryDirectory(prefix="index-", dir=self.root) as folder:
            env = os.environ.copy()
            env.update(GIT_INDEX_FILE=str(Path(folder) / "index"), GIT_AUTHOR_NAME="MLS experiment",
                       GIT_AUTHOR_EMAIL="experiment@localhost", GIT_COMMITTER_NAME="MLS experiment",
                       GIT_COMMITTER_EMAIL="experiment@localhost")
            self.git("read-tree", parent if parent else "--empty", env=env)
            for path, value in files.items():
                oid = self.git("hash-object", "-w", "--stdin", data=canonical(value).encode()).stdout.decode().strip()
                self.git("update-index", "--add", "--cacheinfo", "100644," + oid + "," + path, env=env)
            tree = self.git("write-tree", env=env).stdout.decode().strip()
            args = ["commit-tree", tree] + (["-p", parent] if parent else [])
            return self.git(*args, data=b"MLS experiment record\n", env=env).stdout.decode().strip()

    def bootstrap(self, group):
        head, _ = self.fetch()
        if head:
            raise Rejected("already bootstrapped")
        commit = self.commit(None, {STATE_PATH: {"group_id": group["group_id"], "epoch": group["epoch"]}})
        self.git("push", str(self.origin), commit + ":" + REF)

    def prepare(self, wire):
        head, state = self.fetch()
        existing = self.record(head, wire["op_id"])
        if existing:
            if existing != wire:
                raise Rejected("remote operation ID collision")
            return {"accepted": True, "head": head}
        if wire["base_epoch"] != state["epoch"] or wire["group_id"] != state["group_id"]:
            raise Rejected("epoch or group changed; do not reuse this attempt in a new audience")
        next_state = dict(state)
        if wire["kind"] == "membership":
            next_state["epoch"] += 1
        commit = self.commit(head, {STATE_PATH: next_state, RECORD_DIR + wire["op_id"] + ".json": wire})
        return {"accepted": False, "head": head, "candidate": commit}

    def decide(self, db, opid):
        adapter = Adapter(db)
        wire = adapter.execute("outbox", op_id=opid)["wire"]
        head, state = self.fetch()
        record = self.record(head, opid)
        if record:
            if record != wire:
                raise Rejected("remote operation differs from durable ciphertext")
            pause_at("after_remote_push")
            adapter.execute("accept", op_id=opid, git_ref=head)
            return {"status": "accepted", "head": head, "wire_hash": digest(wire)}
        if state["epoch"] > wire["base_epoch"]:
            adapter.execute("reject", op_id=opid, git_ref=head)
            return {"status": "rejected", "head": head}
        return {"status": "unconfirmed", "head": head}

    def publish(self, db, opid):
        wire = Adapter(db).execute("outbox", op_id=opid)["wire"]
        prepared = self.prepare(wire)
        if not prepared["accepted"]:
            self.git("push", str(self.origin), prepared["candidate"] + ":" + REF, check=False)
        return self.decide(db, opid)

    def guard_restored_state(self, db):
        """Narrow rollback detector using accepted own operations as an anchor."""
        adapter = Adapter(db)
        local = adapter.execute("status")
        known = {row["id"] for row in local["outbox"]}
        head, _ = self.fetch()
        paths = self.git("ls-tree", "-r", "--name-only", head, RECORD_DIR).stdout.decode().splitlines()
        for path in paths:
            record = json.loads(self.git("show", head + ":" + path).stdout)
            if record["client_id"] == local["client_id"] and record["op_id"] not in known:
                adapter.execute("quarantine")
                return {"recovery_required": True, "missing_accepted_operation": record["op_id"]}
        return {"recovery_required": False}


def main():
    try:
        root, name, db, opid = sys.argv[1:5]
        print(canonical(GitFixture(root, name).publish(db, opid)), flush=True)
    except (Rejected, subprocess.CalledProcessError) as exc:
        print(canonical({"error": str(exc)}), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
