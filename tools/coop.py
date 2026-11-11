#!/usr/bin/env python3
"""Small, cooperative Unix reference for local-agent-cooperation 0.1.

No source editing, agent launch, network, wake-up, authorization or stop verifier.
Use the public execute() entry point so every operation obeys the common lock.
"""
from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import time
import uuid

PROTOCOL = "local-agent-cooperation"
VERSION = "0.1"
MAX_BYTES = 1024 * 1024
DURABLE = {"decision", "handoff", "result", "note"}
LIVE = {"task_request", "question", "reply", "intent", "presence"}
STATES = {"open", "in_progress", "blocked", "review", "done", "cancelled"}


class Invalid(Exception):
    pass


class Conflict(Exception):
    pass


def new_id(prefix):
    return f"{prefix}_{uuid.uuid4()}"


def check_id(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(
        rf"{prefix}_[0-9a-f]{{8}}-[0-9a-f]{{4}}-4[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}", value
    ):
        raise Invalid(f"invalid {prefix} identifier")
    return value


def now():
    return datetime.now(timezone.utc)


def stamp(value=None):
    return (value or now()).isoformat(timespec="microseconds").replace("+00:00", "Z")


def date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", value):
        raise Invalid("expected UTC timestamp ending in Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise Invalid("invalid timestamp") from exc


def nonempty(value, name):
    if not isinstance(value, str) or not value.strip():
        raise Invalid(f"{name} must be nonempty text")
    return value


def seconds(value):
    if type(value) is not int or not 1 <= value <= 86400:
        raise Invalid("ttl must be an integer from 1 to 86400 seconds")
    return value


def relpath(value):
    nonempty(value, "scope path")
    p = PurePosixPath(value)
    if p.is_absolute() or ".." in p.parts or "\\" in value or "\0" in value or str(p) != value or value == ".":
        raise Invalid("scope must be a canonical relative path without traversal")
    return value


def header(kind):
    return {"protocol": PROTOCOL, "version": VERSION, "type": kind}


def pairs(items):
    obj = {}
    for key, value in items:
        if key in obj:
            raise Invalid("duplicate JSON key")
        obj[key] = value
    return obj


def actor_check(value):
    if not isinstance(value, dict):
        raise Invalid("expected actor object")
    check_id(value.get("agent"), "a")
    check_id(value.get("session"), "s")


def validate(obj, kind):
    """Validate core fields on disk; optional extensions are never executed."""
    try:
        if not isinstance(obj, dict) or any(obj.get(k) != v for k, v in header(kind).items()):
            raise Invalid("unsupported protocol, version or record type")
        if kind == "project":
            check_id(obj["id"], "p")
            date(obj["created_at"])
            if obj["locking"] != "unix-flock-v1":
                raise Invalid("unsupported locking profile")
        elif kind == "session":
            check_id(obj["id"], "s")
            check_id(obj["agent"], "a")
            nonempty(obj["label"], "label")
            nonempty(obj["harness"], "harness")
            date(obj["started_at"])
            if obj["resumes"] is not None:
                check_id(obj["resumes"], "s")
        elif kind == "ticket":
            check_id(obj["id"], "t")
            nonempty(obj["title"], "title")
            nonempty(obj["body"], "body")
            actor_check(obj["created_by"])
            date(obj["created_at"])
            date(obj["updated_at"])
            if obj["status"] not in STATES or type(obj["revision"]) is not int or obj["revision"] < 1:
                raise Invalid("invalid ticket state or revision")
            if type(obj["generation"]) is not int or obj["generation"] < 0:
                raise Invalid("invalid generation")
            for key in ("scope", "depends_on", "history"):
                if not isinstance(obj[key], list):
                    raise Invalid(f"{key} must be an array")
            for path in obj["scope"]:
                relpath(path)
            for dependency in obj["depends_on"]:
                check_id(dependency, "t")
            if len(obj["history"]) != obj["revision"]:
                raise Invalid("ticket history/revision mismatch")
            for number, entry in enumerate(obj["history"], 1):
                if entry["revision"] != number:
                    raise Invalid("nonsequential ticket history")
                actor_check(entry["by"])
                date(entry["at"])
                nonempty(entry["action"], "action")
                nonempty(entry["summary"], "summary")
                if not isinstance(entry["messages"], list):
                    raise Invalid("history messages must be an array")
                for mid in entry["messages"]:
                    check_id(mid, "m")
            lease = obj["lease"]
            if lease is not None:
                actor_check(lease)
                check_id(lease["token"], "c")
                date(lease["expires_at"])
                if lease["generation"] != obj["generation"] or obj["status"] not in {"in_progress", "review"}:
                    raise Invalid("invalid lease generation or workflow state")
            if obj["status"] == "in_progress" and lease is None:
                raise Invalid("in-progress ticket has no claim")
            result = obj["result"]
            if obj["status"] == "done":
                nonempty(result["summary"], "result summary")
                check_id(result["memory"], "m")
                if not isinstance(result["evidence"], list) or not result["evidence"]:
                    raise Invalid("result evidence is required")
                for evidence in result["evidence"]:
                    nonempty(evidence, "evidence")
            elif result is not None:
                raise Invalid("result is reserved for completed tickets")
        elif kind == "message":
            check_id(obj["id"], "m")
            actor_check(obj["from"])
            date(obj["created_at"])
            nonempty(obj["body"], "body")
            if obj["kind"] not in DURABLE | LIVE:
                raise Invalid("unsupported message kind")
            durable = obj["kind"] in DURABLE
            if obj["retention"] != ("durable" if durable else "ephemeral"):
                raise Invalid("kind/retention mismatch")
            if durable:
                if obj["expires_at"] is not None:
                    raise Invalid("durable message cannot expire")
            elif not 0 < (date(obj["expires_at"]) - date(obj["created_at"])).total_seconds() <= 86400:
                raise Invalid("invalid message lifetime")
            if not isinstance(obj["to"], list) or not obj["to"]:
                raise Invalid("recipient array required")
            for target in obj["to"]:
                if target["kind"] == "project":
                    if set(target) != {"kind"}:
                        raise Invalid("project recipient has no ID")
                elif target["kind"] in {"agent", "session"}:
                    check_id(target["id"], "a" if target["kind"] == "agent" else "s")
                else:
                    raise Invalid("invalid recipient kind")
            if obj["ticket"] is not None:
                check_id(obj["ticket"], "t")
            if obj["kind"] == "task_request" and obj["ticket"] is None:
                raise Invalid("task_request requires a ticket")
            if obj["reply_to"] is not None:
                check_id(obj["reply_to"], "m")
            if obj["kind"] == "reply" and obj["reply_to"] is None:
                raise Invalid("reply requires reply_to")
            if not isinstance(obj["supersedes"], list) or (not durable and obj["supersedes"]):
                raise Invalid("only durable messages can supersede memory")
            for mid in obj["supersedes"]:
                check_id(mid, "m")
        elif kind == "receipt":
            check_id(obj["message"], "m")
            check_id(obj["session"], "s")
            date(obj["at"])
            if obj["stage"] not in {"seen", "handled"}:
                raise Invalid("invalid receipt stage")
        return obj
    except (KeyError, TypeError, ValueError) as exc:
        raise Invalid(f"malformed {kind} record") from exc


class Store:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise Invalid("project root must be a directory")
        self.base = self.root / ".agents"
        self.tickets_dir = self.base / "tickets"
        self.messages_dir = self.base / "messages"

    def safe(self, path):
        path.relative_to(self.base)
        for part in [path, *path.parents]:
            if part == self.root:
                break
            if part.is_symlink():
                raise Invalid("symlinks inside protocol storage are unsupported")
        return path

    @contextlib.contextmanager
    def locked(self, initialize=False, shared=False):
        self.safe(self.tickets_dir)
        if initialize:
            self.tickets_dir.mkdir(parents=True, exist_ok=True)
        lockfile = self.safe(self.tickets_dir / ".lock")
        if not initialize and not lockfile.is_file():
            raise Invalid("project is not initialized")
        with lockfile.open("a+b") as lock:
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(lock, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise Conflict("protocol lock timeout; do not remove the lock file")
                    time.sleep(0.02)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def read(self, path, kind):
        self.safe(path)
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise Invalid("record exceeds 1 MiB")
            obj = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                             parse_constant=lambda _: (_ for _ in ()).throw(Invalid("nonfinite JSON number")))
            validate(obj, kind)
            if kind in {"ticket", "session", "message"} and path.stem != obj["id"]:
                raise Invalid("record ID does not match filename")
            return obj
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            raise Invalid(f"cannot read {path.relative_to(self.root)}: {exc}") from exc

    def write(self, path, obj, immutable=False):
        self.safe(path)
        validate(obj, obj["type"])
        payload = (json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
        if len(payload) > MAX_BYTES:
            raise Invalid("record exceeds 1 MiB; no history was truncated")
        path.parent.mkdir(parents=True, exist_ok=True)
        if immutable and path.exists():
            if self.read(path, obj["type"]) != obj:
                raise Conflict("immutable ID collision with different content")
            return
        fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                try:
                    os.fsync(directory_fd)
                except OSError as exc:
                    if exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                        raise
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def execute(self, operation, **kwargs):
        operations = {"init", "session", "sessions", "create", "tickets", "show", "claim", "renew", "finish", "recover", "send", "inbox", "memory", "ack"}
        if operation not in operations:
            raise Invalid("unsupported operation")
        with self.locked(initialize=operation == "init", shared=operation in {"sessions", "tickets", "show", "inbox", "memory"}):
            if operation != "init":
                self.read(self.tickets_dir / "protocol.json", "project")
            return getattr(self, "_" + operation)(**kwargs)

    def _init(self):
        path = self.tickets_dir / "protocol.json"
        if path.exists():
            return self.read(path, "project")
        for folder in ("sessions", "memory", "live", "local/receipts"):
            self.safe(self.messages_dir / folder).mkdir(parents=True, exist_ok=True)
        obj = {**header("project"), "id": new_id("p"), "locking": "unix-flock-v1", "created_at": stamp()}
        self.write(path, obj, immutable=True)
        return obj

    def get_session(self, sid):
        return self.read(self.messages_dir / "sessions" / (check_id(sid, "s") + ".json"), "session")

    def actor(self, sid):
        session = self.get_session(sid)
        return {"agent": session["agent"], "session": sid}

    def _session(self, label, harness, agent=None, resumes=None):
        if resumes:
            previous = self.get_session(resumes)
            agent = agent or previous["agent"]
            if agent != previous["agent"]:
                raise Invalid("resumed session must belong to the same agent")
        obj = {**header("session"), "id": new_id("s"), "agent": check_id(agent, "a") if agent else new_id("a"),
               "label": label, "harness": harness, "started_at": stamp(), "resumes": resumes}
        self.write(self.messages_dir / "sessions" / (obj["id"] + ".json"), obj, immutable=True)
        return obj

    def _sessions(self):
        return [self.read(p, "session") for p in sorted((self.messages_dir / "sessions").glob("s_*.json"))]

    def ticket(self, tid):
        return self.read(self.tickets_dir / (check_id(tid, "t") + ".json"), "ticket")

    def add_history(self, ticket, actor, action, summary, messages=None):
        ticket["updated_at"] = stamp()
        ticket["history"].append({"revision": ticket["revision"], "at": ticket["updated_at"],
                                  "by": actor, "action": action, "summary": nonempty(summary, "summary"),
                                  "messages": messages or []})
        self.write(self.tickets_dir / (ticket["id"] + ".json"), ticket, immutable=ticket["revision"] == 1)
        return ticket

    def _create(self, session, title, body, scope=None, depends_on=None):
        actor = self.actor(session)
        for path in scope or []:
            relpath(path)
            if not (self.root / path).resolve().is_relative_to(self.root):
                raise Invalid("scope escapes project through symlink")
        for tid in depends_on or []:
            self.ticket(tid)
        obj = {**header("ticket"), "id": new_id("t"), "revision": 1, "title": title, "body": body,
               "created_at": stamp(), "updated_at": stamp(), "created_by": actor, "status": "open",
               "scope": scope or [], "depends_on": depends_on or [], "generation": 0, "lease": None,
               "history": [], "result": None}
        return self.add_history(obj, actor, "create", "Task captured; capture does not grant execution authority.")

    def _show(self, ticket):
        obj = self.ticket(ticket)
        lease = obj["lease"]
        condition = "unowned" if lease is None else ("live" if date(lease["expires_at"]) > now() else "recovery_required")
        return {"ticket": obj, "ownership": condition}

    def _tickets(self):
        return [self._show(p.stem) for p in sorted(self.tickets_dir.glob("t_*.json"))]

    def revision(self, tid, revision):
        obj = self.ticket(tid)
        if type(revision) is not int or obj["revision"] != revision:
            raise Conflict("ticket revision changed; reread before deciding what to do")
        return obj

    def owned(self, tid, session, revision, token, live=True):
        obj = self.revision(tid, revision)
        actor = self.actor(session)
        claim = obj["lease"]
        check_id(token, "c")
        if not claim or any(claim[k] != v for k, v in actor.items()) or claim["token"] != token or claim["generation"] != obj["generation"]:
            raise Conflict("claim does not belong to this session/token/generation")
        if live and date(claim["expires_at"]) <= now():
            raise Conflict("claim expired; stop new work and recover or hand off")
        return obj, actor

    def _claim(self, ticket, session, revision, ttl=900):
        obj = self.revision(ticket, revision)
        actor = self.actor(session)
        if obj["lease"] is not None:
            raise Conflict("ticket already claimed; expired claims require explicit recovery")
        if obj["status"] not in {"open", "blocked", "review"}:
            raise Conflict("ticket is not claimable")
        if any(self.ticket(tid)["status"] != "done" for tid in obj["depends_on"]):
            raise Conflict("ticket dependencies are not done")
        overlaps = []
        for other in self._tickets():
            t = other["ticket"]
            if t["id"] != ticket and t["lease"] and any(
                a == b or a.startswith(b + "/") or b.startswith(a + "/") for a in obj["scope"] for b in t["scope"]
            ):
                overlaps.append(t["id"])
        obj["generation"] += 1
        obj["revision"] += 1
        obj["lease"] = {**actor, "token": new_id("c"), "generation": obj["generation"],
                        "expires_at": stamp(now() + timedelta(seconds=seconds(ttl)))}
        if obj["status"] != "review":
            obj["status"] = "in_progress"
        self.add_history(obj, actor, "claim", "Claim acquired; source-file scope overlaps still require coordination.")
        return {"ticket": obj, "overlaps": overlaps}

    def _renew(self, ticket, session, revision, token, ttl=900):
        obj, actor = self.owned(ticket, session, revision, token)
        obj["lease"]["expires_at"] = stamp(max(date(obj["lease"]["expires_at"]), now() + timedelta(seconds=seconds(ttl))))
        obj["revision"] += 1
        return self.add_history(obj, actor, "renew", "Claim renewed by its owning session.")

    def _finish(self, ticket, session, revision, token, state, message, summary, evidence=None):
        if state not in {"open", "blocked", "review", "done", "cancelled"}:
            raise Invalid("unsupported finish state")
        obj, actor = self.owned(ticket, session, revision, token, live=state != "open")
        record = self.message(message)
        required_kind = "result" if state == "done" else ("note" if state == "cancelled" else "handoff")
        if record["kind"] != required_kind or record["ticket"] != ticket:
            raise Invalid(f"finish requires a durable {required_kind} linked to this ticket")
        nonempty(summary, "summary")
        if state == "done":
            if not evidence:
                raise Invalid("completion requires evidence")
            for item in evidence:
                nonempty(item, "evidence")
            obj["result"] = {"summary": summary, "evidence": evidence, "memory": message}
        obj["status"], obj["lease"] = state, None
        obj["revision"] += 1
        return self.add_history(obj, actor, "finish:" + state, summary, [message])

    def _recover(self, ticket, session, revision, stop_evidence):
        obj = self.revision(ticket, revision)
        actor = self.actor(session)
        if obj["lease"] is None or date(obj["lease"]["expires_at"]) > now():
            raise Conflict("recovery requires an expired claim")
        nonempty(stop_evidence, "confirmed stop evidence")
        obj["revision"] += 1
        obj["generation"] += 1
        obj["status"], obj["lease"] = "open", None
        return self.add_history(obj, actor, "recover", "Caller asserts worker/children stopped and partial writes reconciled: " + stop_evidence)

    def message(self, mid):
        check_id(mid, "m")
        paths = [self.messages_dir / folder / (mid + ".json") for folder in ("memory", "live")]
        found = [p for p in paths if self.safe(p).exists()]
        if len(found) != 1:
            raise Invalid("message missing or ID appears in both retention folders")
        obj = self.read(found[0], "message")
        if (found[0].parent.name == "memory") != (obj["retention"] == "durable"):
            raise Invalid("message in wrong retention folder")
        return obj

    def _send(self, session, kind, to, body, ticket=None, reply_to=None, supersedes=None, ttl=3600, id=None):
        actor = self.actor(session)
        if kind not in DURABLE | LIVE:
            raise Invalid("unknown message kind")
        if ticket is not None:
            self.ticket(ticket)
        if reply_to and self.message(reply_to)["ticket"] != ticket:
            raise Invalid("reply must preserve ticket context")
        for mid in supersedes or []:
            if self.message(mid)["retention"] != "durable":
                raise Invalid("supersedes must reference durable memory")
        for target in to:
            if target.get("kind") == "session":
                self.get_session(target.get("id"))
            elif target.get("kind") == "agent":
                if not any(s["agent"] == target.get("id") for s in self._sessions()):
                    raise Invalid("recipient agent has no registered session")
        mid = check_id(id, "m") if id else new_id("m")
        existing = any(self.safe(self.messages_dir / folder / (mid + ".json")).exists() for folder in ("memory", "live"))
        created = self.message(mid)["created_at"] if existing else stamp()
        obj = {**header("message"), "id": mid, "created_at": created, "from": actor, "to": to,
               "kind": kind, "retention": "durable" if kind in DURABLE else "ephemeral",
               "expires_at": None if kind in DURABLE else stamp(date(created) + timedelta(seconds=seconds(ttl))),
               "ticket": ticket, "reply_to": reply_to, "supersedes": supersedes or [], "body": body}
        if existing and self.message(mid) != obj:
            raise Conflict("message ID retry has different content")
        folder = "memory" if kind in DURABLE else "live"
        self.write(self.messages_dir / folder / (mid + ".json"), obj, immutable=True)
        return obj

    def lineage(self, sid):
        session = self.get_session(sid)
        chain = {sid}
        previous = session["resumes"]
        while previous:
            if previous in chain:
                raise Invalid("session resume cycle")
            old = self.get_session(previous)
            if old["agent"] != session["agent"]:
                raise Invalid("resume chain changes agent")
            chain.add(previous)
            previous = old["resumes"]
        return session, chain

    @staticmethod
    def addressed(record, session, chain):
        return any(t["kind"] == "project" or
                   (t["kind"] == "agent" and t["id"] == session["agent"]) or
                   (t["kind"] == "session" and t["id"] in chain) for t in record["to"])

    def receipt_path(self, sid, mid):
        return self.messages_dir / "local" / "receipts" / check_id(sid, "s") / (check_id(mid, "m") + ".json")

    def scan_messages(self, memory_only=False):
        records, errors = [], []
        paths = []
        for folder in (("memory",) if memory_only else ("memory", "live")):
            paths.extend(sorted(self.safe(self.messages_dir / folder).glob("m_*.json")))
        for path in paths:
            try:
                records.append(self.message(path.stem))
            except Invalid as exc:
                errors.append({"file": str(path.relative_to(self.root)), "error": str(exc)})
        return sorted(records, key=lambda obj: (obj["created_at"], obj["id"])), errors

    def _inbox(self, session, limit=50, include_expired=False):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise Invalid("limit must be between 1 and 1000")
        who, chain = self.lineage(session)
        records, errors = self.scan_messages()
        pending = []
        for obj in records:
            if not self.addressed(obj, who, chain):
                continue
            if not include_expired and obj["expires_at"] and date(obj["expires_at"]) <= now():
                continue
            handled = False
            for sid in chain:
                path = self.receipt_path(sid, obj["id"])
                if self.safe(path).exists():
                    try:
                        receipt = self.read(path, "receipt")
                        if receipt["session"] != sid or receipt["message"] != obj["id"]:
                            raise Invalid("receipt path/identity mismatch")
                        handled |= receipt["stage"] == "handled"
                    except Invalid as exc:
                        errors.append({"file": str(path.relative_to(self.root)), "error": str(exc)})
            if not handled:
                pending.append(obj)
        return {"records": pending[:limit], "remaining": max(0, len(pending) - limit), "errors": errors}

    def _memory(self, query="", ticket=None):
        if ticket:
            check_id(ticket, "t")
        records, errors = self.scan_messages(memory_only=True)
        return {"records": [r for r in records if (not ticket or r["ticket"] == ticket) and query.casefold() in r["body"].casefold()],
                "errors": errors}

    def _ack(self, session, message, stage):
        who, chain = self.lineage(session)
        record = self.message(message)
        if not self.addressed(record, who, chain):
            raise Invalid("message is not addressed to this consumer")
        if stage not in {"seen", "handled"}:
            raise Invalid("invalid receipt stage")
        path = self.receipt_path(session, message)
        if self.safe(path).exists():
            previous = self.read(path, "receipt")
            if previous["session"] != session or previous["message"] != message:
                raise Invalid("receipt path/identity mismatch")
            if previous["stage"] == "handled" or previous["stage"] == stage:
                return previous
        obj = {**header("receipt"), "message": message, "session": session, "stage": stage, "at": stamp()}
        self.write(path, obj)
        return obj


def recipient(value):
    if value == "project":
        return {"kind": "project"}
    parts = value.split(":", 1)
    if len(parts) != 2 or parts[0] not in {"agent", "session"}:
        raise argparse.ArgumentTypeError("use project, agent:a_UUID or session:s_UUID")
    return {"kind": parts[0], "id": parts[1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="explicit target project directory")
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("init")
    commands.add_parser("sessions")
    commands.add_parser("tickets")
    p = commands.add_parser("session")
    p.add_argument("--label", required=True)
    p.add_argument("--harness", required=True)
    p.add_argument("--agent")
    p.add_argument("--resumes")
    p = commands.add_parser("create")
    p.add_argument("--session", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--body", required=True)
    p.add_argument("--scope", action="append")
    p.add_argument("--depends-on", action="append")
    p = commands.add_parser("show")
    p.add_argument("ticket")
    for operation in ("claim", "renew", "finish", "recover"):
        p = commands.add_parser(operation)
        p.add_argument("ticket")
        p.add_argument("--session", required=True)
        p.add_argument("--revision", required=True, type=int)
        if operation in {"renew", "finish"}:
            p.add_argument("--token", required=True)
        if operation in {"claim", "renew"}:
            p.add_argument("--ttl", type=int, default=900)
        if operation == "finish":
            p.add_argument("--state", choices=sorted(STATES - {"in_progress"}), required=True)
            p.add_argument("--message", required=True)
            p.add_argument("--summary", required=True)
            p.add_argument("--evidence", action="append")
        if operation == "recover":
            p.add_argument("--stop-evidence", required=True, help="trusted caller's confirmed stop and reconciliation evidence, not a timeout")
    p = commands.add_parser("send")
    p.add_argument("--session", required=True)
    p.add_argument("--kind", choices=sorted(DURABLE | LIVE), required=True)
    p.add_argument("--to", type=recipient, action="append", required=True)
    p.add_argument("--body", required=True)
    p.add_argument("--ticket")
    p.add_argument("--reply-to")
    p.add_argument("--supersedes", action="append")
    p.add_argument("--ttl", type=int, default=3600)
    p.add_argument("--id", help="preallocated m_UUID for identical retry")
    p = commands.add_parser("inbox")
    p.add_argument("--session", required=True)
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--include-expired", action="store_true")
    p = commands.add_parser("memory")
    p.add_argument("--query", default="")
    p.add_argument("--ticket")
    p = commands.add_parser("ack")
    p.add_argument("--session", required=True)
    p.add_argument("--message", required=True)
    p.add_argument("--stage", choices=["seen", "handled"], required=True)
    args = vars(parser.parse_args())
    root, operation = args.pop("root"), args.pop("operation")
    try:
        result = Store(root).execute(operation, **args)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (Invalid, Conflict, OSError) as exc:
        print(json.dumps({"error": str(exc), "kind": type(exc).__name__}), file=sys.stderr)
        return 3 if isinstance(exc, Conflict) else 2


if __name__ == "__main__":
    sys.exit(main())
