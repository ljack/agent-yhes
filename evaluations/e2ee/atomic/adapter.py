#!/usr/bin/env python3
"""Experiment-only SQLite adapter for a disposable OpenMLS state snapshot.

The private database is intentionally plaintext test data. It cannot be used
outside a directory marked EXPERIMENT_ONLY, and is never imported by runtime tools.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time

WORKER = Path(__file__).resolve().parents[1] / "rust/target/debug/openmls-worker"


class Rejected(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value).encode()).hexdigest()


def pause_at(stage):
    """A test parent sends SIGKILL after receiving this marker."""
    if os.environ.get("YHES_EXPERIMENT_PAUSE") == stage:
        print(canonical({"paused": stage}), flush=True)
        while True:
            time.sleep(1)


def public_result(result):
    result = json.loads(canonical(result))
    group = result.get("group", {})
    if "convergence" in group:
        group["convergence_hash"] = digest(bytes(group.pop("convergence")))
    if "body" in result:
        result["body_hash"] = digest(bytes(result.pop("body")))
    return result


def worker(state, operation, payload):
    raw = canonical({"state": state, "operation": operation, "payload": payload})
    if len(raw.encode()) > 8 * 1024 * 1024:
        raise Rejected("experiment input limit")
    process = subprocess.run([str(WORKER)], input=raw, text=True, capture_output=True, timeout=15)
    if process.returncode:
        raise Rejected("worker process failed")
    response = json.loads(process.stdout)
    if "error" in response:
        raise Rejected(response["error"])
    return response


class Adapter:
    def __init__(self, path):
        self.path = Path(path).resolve()
        if not (self.path.parent / "EXPERIMENT_ONLY").is_file():
            raise Rejected("only disposable experiment directories are accepted")

    def execute(self, operation, **arguments):
        os.umask(0o077)
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK (id=1), revision INTEGER NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, wire TEXT NOT NULL, status TEXT NOT NULL, receipt TEXT);
                CREATE TABLE IF NOT EXISTS inbox (digest TEXT PRIMARY KEY, result TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT revision, body FROM state WHERE id=1").fetchone()
            revision, state = (row[0], json.loads(row[1])) if row else (0, None)
            meta = {k: json.loads(v) for k, v in connection.execute("SELECT key,value FROM meta")}
            if operation == "status":
                result = worker(state, "status", {})["result"] if state else {"group": None}
                result.update(revision=revision, state_hash=digest(state), client_id=meta.get("client_id"),
                    recovery_required=meta.get("recovery_required", False),
                    outbox=[{"id": oid, "status": status, "wire_hash": digest(json.loads(wire))} for oid, status, wire in connection.execute("SELECT id,status,wire FROM outbox ORDER BY id")],
                    inbox_count=connection.execute("SELECT COUNT(*) FROM inbox").fetchone()[0])
                return public_result(result)
            if operation == "outbox":
                row = connection.execute("SELECT wire,status,receipt FROM outbox WHERE id=?", (arguments["op_id"],)).fetchone()
                if not row:
                    raise Rejected("unknown operation")
                return {"wire": json.loads(row[0]), "status": row[1], "receipt": row[2]}
            if operation == "identity":
                return meta["public_identity"]
            if operation == "quarantine":
                connection.execute("INSERT OR REPLACE INTO meta VALUES ('recovery_required','true')")
                connection.commit()
                return {"recovery_required": True}
            if meta.get("recovery_required"):
                raise Rejected("recovery required; do not reuse restored cryptographic state")

            if operation.startswith("prepare_"):
                opid = arguments.get("op_id", "")
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", opid):
                    raise Rejected("invalid experiment operation ID")
                request_hash = digest([operation, arguments])
                old = connection.execute("SELECT request_hash,wire FROM outbox WHERE id=?", (opid,)).fetchone()
                if old:
                    if old[0] != request_hash:
                        raise Rejected("operation ID already has different arguments")
                    return {"replayed": True, "wire": json.loads(old[1])}
                response = worker(state, operation, arguments)
                result = response["result"]
                wire = {"op_id": opid, "client_id": meta["client_id"], "prepared_revision": revision + 1,
                        "kind": result["kind"], "base_epoch": result["base_epoch"],
                        "group_id": result["group"]["group_id"], "packet": result["packet"]}
                if "welcome" in result:
                    wire["welcome"] = result["welcome"]
                connection.execute("INSERT INTO outbox VALUES (?,?,?,'prepared',NULL)", (opid, request_hash, canonical(wire)))
                if result["kind"] == "membership":
                    connection.execute("INSERT OR REPLACE INTO meta VALUES ('pending_operation',?)", (canonical(opid),))
                output = {"replayed": False, "wire": wire}
            elif operation == "receive":
                wire_digest = digest(bytes(arguments["packet"]))
                old = connection.execute("SELECT result FROM inbox WHERE digest=?", (wire_digest,)).fetchone()
                if old:
                    return {"replayed": True, "result": public_result(json.loads(old[0]))}
                response = worker(state, "receive", arguments)
                # Keep the decrypted fixture payload together with receiver state,
                # so a crash after commit cannot consume the only readable copy.
                connection.execute("INSERT INTO inbox VALUES (?,?)", (wire_digest, canonical(response["result"])))
                output = {"replayed": False, "result": public_result(response["result"])}
            elif operation in {"accept", "reject"}:
                opid = arguments["op_id"]
                row = connection.execute("SELECT wire,status FROM outbox WHERE id=?", (opid,)).fetchone()
                if not row:
                    raise Rejected("unknown operation")
                wire, status = json.loads(row[0]), row[1]
                target = "accepted" if operation == "accept" else "rejected"
                if status == target:
                    return {"replayed": True, "status": target}
                if status != "prepared":
                    raise Rejected("an already decided attempt cannot change outcome")
                if wire["kind"] == "membership":
                    if meta.get("pending_operation") != opid:
                        raise Rejected("this operation does not own the pending MLS state")
                    command = "accept_own" if operation == "accept" else "discard_pending"
                    response = worker(state, command, {})
                    connection.execute("DELETE FROM meta WHERE key='pending_operation'")
                else:
                    response = {"state": state, "result": {}}
                # The experiment's Git coordinator checks this decision before
                # calling the adapter. These local calls are not authorization APIs.
                connection.execute("UPDATE outbox SET status=?,receipt=? WHERE id=?", (target, arguments["git_ref"], opid))
                output = {"replayed": False, "status": target}
            elif operation in {"init", "create"}:
                response = worker(state, operation, arguments)
                output = public_result(response["result"])
                if operation == "init":
                    client_id = digest(bytes(response["result"]["signing_key"]))
                    connection.execute("INSERT INTO meta VALUES ('client_id',?)", (canonical(client_id),))
                    connection.execute("INSERT INTO meta VALUES ('public_identity',?)", (canonical(output),))
            else:
                raise Rejected("unknown adapter operation")

            connection.execute("INSERT OR REPLACE INTO state VALUES (1,?,?)", (revision + 1, canonical(response["state"])))
            pause_at("before_db_commit")
            connection.commit()
            pause_at("after_db_commit")
            return output
        finally:
            connection.close()


def main():
    try:
        path, operation = sys.argv[1:3]
        arguments = json.loads(sys.stdin.read() or "{}")
        result = Adapter(path).execute(operation, **arguments)
        print(canonical(result), flush=True)
    except (Rejected, OSError, sqlite3.Error) as exc:
        print(canonical({"error": str(exc)}), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
