#!/usr/bin/env python3
"""agent-yhes v0.2: publish cooperative state through one remote Git branch.

Source worktrees and indexes stay untouched. Mutations succeed only after the
operation is found on the authoritative remote. Use pending/resolve/resume after
an interruption. Git credentials and branch access come from the selected remote.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

import coop
from coop import Conflict, Invalid, Store, check_id, new_id, stamp, reject_secure_channel

READS = {"sessions", "tickets", "show", "inbox", "memory"}
WRITES = {"init", "session", "create", "claim", "renew", "finish", "recover", "send", "ack"}
MAX_FILES = 5000
MAX_TOTAL = 50 * 1024 * 1024


class Unavailable(Exception):
    """Transport failed; a candidate may or may not have been accepted."""


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")


def read_json(path):
    try:
        raw = path.read_bytes()
        if len(raw) > coop.MAX_BYTES:
            raise Invalid("local transport record exceeds limit")
        return json.loads(raw, object_pairs_hook=coop.pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid("nonfinite number")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Invalid("invalid local transport record") from exc


def save_json(path, value):
    data = encode(value)
    if len(data) > coop.MAX_BYTES:
        raise Invalid("local transport record exceeds limit")
    fd, name = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def record_kind(name):
    """Only these regular-file paths can be imported from the channel."""
    parts = name.split("/")
    if name == ".agents/tickets/protocol.json":
        return "project"
    patterns = [
        (r"\.agents/tickets/(t_[^/]+)\.json", "t", "ticket"),
        (r"\.agents/messages/sessions/(s_[^/]+)\.json", "s", "session"),
        (r"\.agents/messages/(?:memory|live)/(m_[^/]+)\.json", "m", "message"),
        (r"\.agents/messages/operations/(o_[^/]+)\.json", "o", "operation"),
    ]
    for pattern, prefix, kind in patterns:
        match = re.fullmatch(pattern, name)
        if match:
            check_id(match.group(1), prefix)
            return kind
    if len(parts) == 5 and parts[:3] == [".agents", "messages", "receipts"] and parts[4].endswith(".json"):
        check_id(parts[3], "s")
        check_id(parts[4][:-5], "m")
        return "receipt"
    raise Invalid("unexpected file in coordination branch: " + name)


class RemoteRecords(Store):
    version = "0.2"
    profile = "git-ref-v1"

    def __init__(self, root, node):
        super().__init__(root)
        self.node = check_id(node, "n")

    def actor(self, sid):
        session = self.get_session(sid)
        if session["node"] != self.node:
            raise Conflict("session belongs to another local client; register a new session with --resumes")
        return {"agent": session["agent"], "session": sid}

    def _session(self, label, harness, agent=None, resumes=None, participant_type="agent"):
        if resumes:
            previous = self.get_session(resumes)
            agent = agent or previous["agent"]
            if agent != previous["agent"] or participant_type != previous["participant_type"]:
                raise Invalid("resume must preserve participant identity and type")
        obj = {**self.header("session"), "id": new_id("s"), "agent": check_id(agent, "a") if agent else new_id("a"),
               "label": label, "harness": harness, "started_at": stamp(), "resumes": resumes,
               "node": self.node, "participant_type": participant_type}
        self.write(self.messages_dir / "sessions" / (obj["id"] + ".json"), obj, immutable=True)
        return obj

    def receipt_path(self, sid, mid):
        return self.messages_dir / "receipts" / check_id(sid, "s") / (check_id(mid, "m") + ".json")

    def _ack(self, session, message, stage):
        self.actor(session)
        return super()._ack(session, message, stage)

    def _recover(self, ticket, session, revision, stop_evidence):
        if self.get_session(session)["participant_type"] != "human":
            raise Invalid("remote recovery requires a human participant to confirm stop and reconciliation evidence")
        return super()._recover(ticket, session, revision, stop_evidence)


class Remote:
    def __init__(self, root, remote="origin", branch="agent-yhes/state", timeout=30, attempts=3):
        self.root = Path(root).resolve(strict=True)
        reject_secure_channel(self.root)
        self.timeout = timeout
        self.attempts = attempts
        if not 1 <= timeout <= 60 or not 1 <= attempts <= 10:
            raise Invalid("timeout must be 1..60 seconds and attempts 1..10")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", remote):
            raise Invalid("use a configured remote name")
        self.url = ""
        top = Path(self._source("rev-parse", "--show-toplevel").stdout.decode().strip()).resolve()
        if top != self.root:
            raise Invalid("--root must be the Git worktree root")
        if not branch.startswith("agent-yhes/"):
            raise Invalid("coordination branches must start with agent-yhes/; source branches are not allowed")
        self.ref = "refs/heads/" + branch
        self._source("check-ref-format", self.ref)
        fetch = self._source("remote", "get-url", "--all", remote).stdout.decode().splitlines()
        push = self._source("remote", "get-url", "--push", "--all", remote).stdout.decode().splitlines()
        if len(fetch) != 1 or fetch != push:
            raise Invalid("use one remote with the same single fetch and push URL")
        self.url = fetch[0]
        if self.url.startswith("-") or self.url.startswith("ext::"):
            raise Invalid("unsupported transport")
        gitdir = Path(self._source("rev-parse", "--absolute-git-dir").stdout.decode().strip())
        key = hashlib.sha256(encode([self.url, self.ref])).hexdigest()[:24]
        self.home = gitdir / "agent-yhes" / key
        self.home.mkdir(parents=True, exist_ok=True)
        self.cache = self.home / "objects.git"

    def _run(self, args, *, data=None, extra_env=None, check=True):
        env = os.environ.copy()
        for key in ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
            env.pop(key, None)
        env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_EDITOR": "true"})
        env.setdefault("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
        env.update(extra_env or {})
        argv = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never",
                "-c", "core.autocrlf=false", "-c", "core.attributesFile=/dev/null", *args]
        with subprocess.Popen(argv, cwd=self.root, env=env, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as process:
            try:
                stdout, stderr = process.communicate(data, timeout=self.timeout)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise Unavailable("Git timed out; resolve any pending operation before retrying work") from exc
        result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
        if check and result.returncode:
            error = stderr.decode("utf-8", "replace")
            if self.url:
                error = error.replace(self.url, "[remote]")
            error = re.sub(r"https?://\S+", "[remote]", error)
            raise Unavailable("Git command failed: " + error.strip()[:500])
        return result

    def _source(self, *args):
        return self._run(["-C", str(self.root), *args])

    def git(self, *args, **kwargs):
        return self._run(["--git-dir=" + str(self.cache), *args], **kwargs)

    @contextlib.contextmanager
    def locked(self):
        with (self.home / "lock").open("a+b") as lock:
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise Conflict("another command is using this local channel; retry after it finishes")
                    time.sleep(0.02)
            try:
                if not self.cache.exists():
                    self._run(["init", "--bare", "--template=", str(self.cache)])
                (self.home / "pending").mkdir(exist_ok=True)
                nodepath = self.home / "node.json"
                if not nodepath.exists():
                    save_json(nodepath, {"node": new_id("n")})
                self.node = check_id(read_json(nodepath)["node"], "n")
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _fetch(self):
        observed = self.git("ls-remote", "--refs", self.url, self.ref).stdout.decode().splitlines()
        pinpath = self.home / "observed.json"
        pin = read_json(pinpath) if pinpath.exists() else None
        if not observed:
            if pin:
                raise Conflict("coordination branch disappeared; refusing to recreate it")
            return None
        self.git("fetch", "--no-tags", "--no-recurse-submodules", self.url, self.ref)
        head = self.git("rev-parse", "FETCH_HEAD").stdout.decode().strip()
        if pin and self.git("merge-base", "--is-ancestor", pin["commit"], head, check=False).returncode:
            raise Conflict("coordination history was rewritten; reconcile it with the participants")
        self.git("update-ref", "refs/agent-yhes/observed", head)
        return head

    def _snapshot(self, head, directory):
        directory = Path(directory).resolve()
        store = RemoteRecords(directory, self.node)
        if head:
            entries = self.git("ls-tree", "-rlz", head).stdout.split(b"\0")
            entries = [entry for entry in entries if entry]
            if len(entries) > MAX_FILES:
                raise Invalid("coordination branch exceeds the record limit")
            total = 0
            for entry in entries:
                metadata, raw_name = entry.split(b"\t", 1)
                mode, kind, blob, raw_size = metadata.decode().split()
                name = raw_name.decode("utf-8")
                expected = record_kind(name)
                size = int(raw_size)
                total += size
                if mode != "100644" or kind != "blob" or size > coop.MAX_BYTES or total > MAX_TOTAL:
                    raise Invalid("channel contains a non-regular file or exceeds size limits")
                data = self.git("cat-file", "blob", blob).stdout
                target = store.safe(Path(directory) / name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                record = store.read(target, expected)
                if expected == "operation" and record["id"] != target.stem:
                    raise Invalid("operation ID does not match filename")
                if expected == "receipt" and (record["session"] != target.parent.name or record["message"] != target.stem):
                    raise Invalid("receipt identity does not match path")
                if expected == "message" and ("/memory/" in name) != (record["retention"] == "durable"):
                    raise Invalid("message is in the wrong retention folder")
            project = store.read(store.tickets_dir / "protocol.json", "project")
            pinpath = self.home / "observed.json"
            if pinpath.exists() and read_json(pinpath)["project"] != project["id"]:
                raise Conflict("remote project identity changed")
            save_json(pinpath, {"project": project["id"], "commit": head})
        # This lock is private to the disposable snapshot and never sent to Git.
        store.tickets_dir.mkdir(parents=True, exist_ok=True)
        (store.tickets_dir / ".lock").touch()
        return store

    def _candidate(self, directory, parent, operation_id):
        files = sorted(p for p in Path(directory).rglob("*.json") if p.is_file())
        total = 0
        for path in files:
            record_kind(path.relative_to(directory).as_posix())
            total += path.stat().st_size
        if len(files) > MAX_FILES or total > MAX_TOTAL:
            raise Invalid("coordination branch exceeds capacity")
        index = str(Path(directory) / "git-index")
        env = {"GIT_INDEX_FILE": index, "GIT_WORK_TREE": str(directory)}
        self.git("read-tree", "--empty", extra_env=env)
        self.git("add", "--force", "--", *[str(p.relative_to(directory)) for p in files], extra_env=env)
        tree = self.git("write-tree", extra_env=env).stdout.decode().strip()
        author = {"GIT_AUTHOR_NAME": "agent-yhes", "GIT_AUTHOR_EMAIL": "agent-yhes@localhost",
                  "GIT_COMMITTER_NAME": "agent-yhes", "GIT_COMMITTER_EMAIL": "agent-yhes@localhost"}
        args = ["commit-tree", tree] + (["-p", parent] if parent else [])
        commit = self.git(*args, data=("agent-yhes operation " + operation_id + "\n").encode(), extra_env=author).stdout.decode().strip()
        self.git("update-ref", "refs/agent-yhes/candidates/" + operation_id, commit)
        return commit

    def _push(self, commit):
        # Ordinary fast-forward push only. Competing children cannot both win.
        return self.git("push", "--porcelain", self.url, commit + ":" + self.ref, check=False)

    def _receipt(self, store, operation_id, fingerprint=None):
        path = store.messages_dir / "operations" / (operation_id + ".json")
        if not path.exists():
            return None
        record = store.read(path, "operation")
        if fingerprint is not None and record["arguments_hash"] != fingerprint:
            raise Conflict("operation ID was already used with different arguments")
        return record

    def _confirmed(self, pending, receipt, head, replayed):
        pending["status"] = "confirmed"
        pending["observed_commit"] = head
        save_json(self.home / "pending" / (pending["id"] + ".json"), pending)
        return {"delivery": "confirmed", "operation_id": pending["id"], "observed_commit": head,
                "replayed": replayed, "result": receipt["result"]}

    def _mutate(self, pending):
        opid = pending["id"]
        for attempt in range(self.attempts):
            head = self._fetch()
            if head is None and pending["operation"] != "init":
                raise Invalid("channel is not initialized; its organizer must run init")
            with tempfile.TemporaryDirectory(prefix="snapshot-", dir=self.home) as directory:
                store = self._snapshot(head, directory)
                previous = self._receipt(store, opid, pending["arguments_hash"])
                if previous:
                    return self._confirmed(pending, previous, head, replayed=True)
                result = store.execute(pending["operation"], **pending["arguments"])
                receipt = {**store.header("operation"), "id": opid, "operation": pending["operation"],
                           "arguments_hash": pending["arguments_hash"], "created_at": stamp(), "result": result}
                store.write(store.messages_dir / "operations" / (opid + ".json"), receipt, immutable=True)
                candidate = self._candidate(directory, head, opid)
                pending.update(status="unconfirmed", candidate=candidate)
                save_json(self.home / "pending" / (opid + ".json"), pending)
                try:
                    push_result = self._push(candidate)
                except Unavailable:
                    push_result = None
                # A failed/timed-out push may still have reached the server.
                # Resolve the ID from remote state before rebuilding anything.
                observed = self._fetch()
                with tempfile.TemporaryDirectory(prefix="verify-", dir=self.home) as verification:
                    current = self._snapshot(observed, verification)
                    accepted = self._receipt(current, opid, pending["arguments_hash"])
                    if accepted:
                        return self._confirmed(pending, accepted, observed, replayed=False)
                if observed == head:
                    if push_result is not None and push_result.returncode == 0:
                        raise Conflict("server acknowledged push but the operation is absent; reconcile the channel")
                    raise Unavailable("push is unconfirmed; inspect access/connectivity and use resolve or resume with operation " + opid)
                # Another participant advanced the ref. Reapply the same request
                # to that state; never merge JSON or change its expected revision.
        raise Conflict("channel kept changing; operation remains pending, retry with the same ID")

    def execute(self, operation, operation_id=None, **arguments):
        reject_secure_channel(self.root)
        with self.locked():
            reject_secure_channel(self.root)
            if operation == "pending":
                return [{k: row[k] for k in ("id", "operation", "status")}
                        for row in (read_json(p) for p in sorted((self.home / "pending").glob("o_*.json")))
                        if row["status"] != "confirmed"]
            if operation == "resume":
                opid = check_id(arguments["id"], "o")
                pending = read_json(self.home / "pending" / (opid + ".json"))
                return self._mutate(pending)
            if operation == "resolve":
                opid = check_id(arguments["id"], "o")
                path = self.home / "pending" / (opid + ".json")
                pending = read_json(path) if path.exists() else None
                head = self._fetch()
                with tempfile.TemporaryDirectory(prefix="resolve-", dir=self.home) as directory:
                    store = self._snapshot(head, directory)
                    receipt = self._receipt(store, opid, pending["arguments_hash"] if pending else None)
                    if receipt:
                        if pending:
                            return self._confirmed(pending, receipt, head, replayed=True)
                        return {"delivery": "confirmed", "operation_id": opid, "observed_commit": head,
                                "replayed": True, "result": receipt["result"]}
                return {"delivery": "not_found", "operation_id": opid, "observed_commit": head}
            if operation in READS:
                head = self._fetch()
                if head is None:
                    raise Invalid("channel is not initialized")
                with tempfile.TemporaryDirectory(prefix="read-", dir=self.home) as directory:
                    store = self._snapshot(head, directory)
                    return {"observed_commit": head, "observed_at": stamp(), "result": store.execute(operation, **arguments)}
            if operation not in WRITES:
                raise Invalid("unsupported operation")
            opid = check_id(operation_id, "o") if operation_id else new_id("o")
            fingerprint = hashlib.sha256(encode([operation, arguments, self.node])).hexdigest()
            path = self.home / "pending" / (opid + ".json")
            if path.exists():
                pending = read_json(path)
                if pending["arguments_hash"] != fingerprint:
                    raise Conflict("local operation ID already has different arguments")
            else:
                pending = {"id": opid, "operation": operation, "arguments": arguments,
                           "arguments_hash": fingerprint, "status": "intent", "created_at": stamp()}
                save_json(path, pending)
            return self._mutate(pending)


def build_parser(description=__doc__):
    parser, commands = coop.build_parser(description)
    parser.add_argument("--remote", default="origin", help="configured Git remote with one fetch/push URL")
    parser.add_argument("--branch", default="agent-yhes/state", help="dedicated coordination branch under agent-yhes/")
    parser.add_argument("--operation-id", help="o_UUID for retrying the same mutation")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--attempts", type=int, default=3)
    commands.choices["session"].add_argument("--participant-type", choices=["human", "agent"], default="agent")
    commands.add_parser("pending", help="list locally saved operations without contacting the remote")
    for command in ("resolve", "resume"):
        p = commands.add_parser(command)
        p.add_argument("id", help="saved o_UUID; resolve only reads, resume retries the original request")
    return parser, commands


def main():
    parser, _ = build_parser()
    args = vars(parser.parse_args())
    options = {key: args.pop(key) for key in ("root", "remote", "branch", "timeout", "attempts")}
    operation, opid = args.pop("operation"), args.pop("operation_id")
    try:
        result = Remote(**options).execute(operation, operation_id=opid, **args)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (Invalid, Conflict, Unavailable, OSError) as exc:
        print(json.dumps({"error": str(exc), "kind": type(exc).__name__,
                          "next": "Use pending and resolve before retrying an interrupted write."}), file=sys.stderr)
        return 4 if isinstance(exc, Unavailable) else (3 if isinstance(exc, Conflict) else 2)


if __name__ == "__main__":
    sys.exit(main())
