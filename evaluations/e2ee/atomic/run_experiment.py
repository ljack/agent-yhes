#!/usr/bin/env python3
"""Run the next OpenMLS experiment with SQLite, process kills and real Git."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from adapter import Adapter, Rejected, canonical, digest
from git_fixture import GitFixture, REF, RECORD_DIR

HERE = Path(__file__).resolve().parent


def call(db, operation, **arguments):
    result = subprocess.run([sys.executable, str(HERE / "adapter.py"), str(db), operation],
                            input=canonical(arguments), capture_output=True, text=True)
    if result.returncode:
        raise Rejected(json.loads(result.stderr)["error"])
    return json.loads(result.stdout)


def kill_at(argv, stage, payload=None):
    env = os.environ.copy()
    env["YHES_EXPERIMENT_PAUSE"] = stage
    process = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if payload is not None:
            process.stdin.write(canonical(payload).encode())
        process.stdin.close()
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            if not ready.select(timeout=15):
                raise AssertionError("worker did not reach crash boundary")
            line = process.stdout.readline()
        if json.loads(line) != {"paused": stage}:
            raise AssertionError("unexpected output before crash boundary")
        process.kill()
        process.wait(timeout=5)
        assert process.returncode < 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def kill_adapter(db, operation, stage, **arguments):
    kill_at([sys.executable, str(HERE / "adapter.py"), str(db), operation], stage, arguments)


def expect_rejection(function):
    try:
        function()
    except Rejected:
        return
    raise AssertionError("operation should have been rejected")


def copy_database(source, destination):
    src, dst = sqlite3.connect(source), sqlite3.connect(destination)
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()


def run(suite):
    checks = {}
    with tempfile.TemporaryDirectory(prefix="yhes-mls-atomic-") as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        (root / "EXPERIMENT_ONLY").touch()
        nodes = {name: root / (name + ".sqlite") for name in ("alice", "bob", "carol", "dave")}
        identities = {name: call(db, "init", name=name, suite=suite) for name, db in nodes.items()}
        a, b, c, d = [nodes[name] for name in ("alice", "bob", "carol", "dave")]
        pubs = {name: GitFixture(root, name) for name in nodes}
        created = call(a, "create")
        pubs["alice"].bootstrap(created["group"])
        initial = call(a, "prepare_add", op_id="add-bob", key_package=identities["bob"]["key_package"])["wire"]
        assert pubs["alice"].publish(a, "add-bob")["status"] == "accepted"
        bad_welcome = list(initial["welcome"])
        bad_welcome[-1] ^= 1
        before = call(b, "status")
        expect_rejection(lambda: call(b, "receive", packet=bad_welcome))
        assert call(b, "status") == before
        checks["invalid_welcome_preserves_durable_state"] = True

        kill_adapter(b, "receive", "before_db_commit", packet=initial["welcome"])
        assert call(b, "status") == before
        call(b, "receive", packet=initial["welcome"])
        assert call(b, "status")["group"]["epoch"] == 1
        checks["killed_join_rolls_back_key_consumption"] = True

        before = call(a, "status")
        args = {"op_id": "send-before-crash", "body": list(b"CONFIDENTIAL-FIXTURE before commit")}
        kill_adapter(a, "prepare_send", "before_db_commit", **args)
        assert call(a, "status") == before
        call(a, "prepare_send", **args)
        assert pubs["alice"].publish(a, args["op_id"])["status"] == "accepted"
        first = call(a, "outbox", op_id=args["op_id"])["wire"]
        call(b, "receive", packet=first["packet"])
        checks["killed_send_before_commit_has_no_partial_state_or_outbox"] = True

        args = {"op_id": "send-after-crash", "body": list(b"CONFIDENTIAL-FIXTURE after commit")}
        kill_adapter(a, "prepare_send", "after_db_commit", **args)
        saved = call(a, "outbox", op_id=args["op_id"])["wire"]
        state_after = call(a, "status")
        repeated = call(a, "prepare_send", **args)
        assert repeated["replayed"] and repeated["wire"] == saved
        assert call(a, "status") == state_after
        expect_rejection(lambda: call(a, "prepare_send", **(args | {"body": [1, 2, 3]})))
        checks["killed_send_after_commit_reuses_exact_ciphertext"] = True
        checks["changed_request_cannot_reuse_operation_id"] = True

        before = pubs["alice"].fetch()[0]
        kill_at([sys.executable, str(HERE / "git_fixture.py"), str(root), "alice", str(a), args["op_id"]], "after_remote_push")
        accepted_tip = pubs["alice"].fetch()[0]
        assert accepted_tip != before
        assert call(a, "outbox", op_id=args["op_id"])["status"] == "prepared"
        assert pubs["alice"].publish(a, args["op_id"])["status"] == "accepted"
        assert pubs["alice"].fetch()[0] == accepted_tip
        assert call(a, "outbox", op_id=args["op_id"])["wire"] == saved
        checks["lost_git_ack_resolves_without_reencrypt_or_second_commit"] = True

        bad = list(saved["packet"])
        bad[-1] ^= 1
        before = call(b, "status")
        expect_rejection(lambda: call(b, "receive", packet=bad))
        assert call(b, "status") == before
        checks["invalid_ciphertext_preserves_durable_receiver_state"] = True
        kill_adapter(b, "receive", "after_db_commit", packet=saved["packet"])
        received_state = call(b, "status")
        duplicate = call(b, "receive", packet=saved["packet"])
        assert duplicate["replayed"]
        assert duplicate["result"]["body_hash"] == digest(bytes(args["body"]))
        assert call(b, "status") == received_state
        checks["killed_receiver_after_commit_replays_durable_inbox"] = True

        # Keep one unsent application packet to test an intervening epoch change.
        obsolete = call(a, "prepare_send", op_id="old-epoch-message", body=list(b"CONFIDENTIAL-FIXTURE old audience"))["wire"]
        candidates = {}
        wires = {}
        for actor, newcomer in (("alice", "carol"), ("bob", "dave")):
            opid = "add-" + newcomer
            wire = call(nodes[actor], "prepare_add", op_id=opid, key_package=identities[newcomer]["key_package"])["wire"]
            wires[actor] = wire
            candidates[actor] = pubs[actor].prepare(wire)
        assert candidates["alice"]["head"] == candidates["bob"]["head"]
        expect_rejection(lambda: call(a, "prepare_send", op_id="during-pending", body=[1]))
        checks["pending_membership_blocks_new_sends"] = True
        processes = {actor: subprocess.Popen(pubs[actor].command("push", str(pubs[actor].origin), candidate["candidate"] + ":" + REF),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE) for actor, candidate in candidates.items()}
        codes = {}
        try:
            for actor, process in processes.items():
                process.communicate(timeout=15)
                codes[actor] = process.returncode
        finally:
            for process in processes.values():
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        assert sorted(code == 0 for code in codes.values()) == [False, True]
        winner = next(actor for actor, code in codes.items() if code == 0)
        loser = "bob" if winner == "alice" else "alice"
        first_joiner = "carol" if winner == "alice" else "dave"
        second_joiner = "dave" if winner == "alice" else "carol"
        assert pubs[winner].decide(nodes[winner], wires[winner]["op_id"])["status"] == "accepted"
        assert pubs[loser].decide(nodes[loser], wires[loser]["op_id"])["status"] == "rejected"
        call(nodes[loser], "receive", packet=wires[winner]["packet"])
        call(nodes[first_joiner], "receive", packet=wires[winner]["welcome"])
        checks["concurrent_membership_has_one_git_winner"] = True
        checks["loser_discards_pending_and_consumes_winner"] = True

        retry_id = "add-" + second_joiner + "-rebuilt"
        rebuilt = call(nodes[loser], "prepare_add", op_id=retry_id, key_package=identities[second_joiner]["key_package"])["wire"]
        assert rebuilt["base_epoch"] == 2
        assert rebuilt["packet"] != wires[loser]["packet"]
        assert pubs[loser].publish(nodes[loser], retry_id)["status"] == "accepted"
        call(nodes[winner], "receive", packet=rebuilt["packet"])
        call(nodes[first_joiner], "receive", packet=rebuilt["packet"])
        call(nodes[second_joiner], "receive", packet=rebuilt["welcome"])
        statuses = [call(db, "status") for db in nodes.values()]
        assert {s["group"]["epoch"] for s in statuses} == {3}
        assert len({s["group"]["convergence_hash"] for s in statuses}) == 1
        assert all(len(s["group"]["members"]) == 4 for s in statuses)
        checks["rebuilt_membership_converges_four_independent_databases"] = True

        before = call(nodes[winner], "status")
        expect_rejection(lambda: call(nodes[winner], "receive", packet=wires[loser]["packet"]))
        assert call(nodes[winner], "status") == before
        checks["rejected_old_membership_attempt_cannot_replay"] = True
        head = pubs["alice"].fetch()[0]
        expect_rejection(lambda: pubs["alice"].publish(a, obsolete["op_id"]))
        assert pubs["alice"].fetch()[0] == head
        assert call(a, "outbox", op_id=obsolete["op_id"])["wire"] == obsolete
        checks["unsent_old_epoch_ciphertext_requires_new_authorized_attempt"] = True

        future = call(a, "prepare_send", op_id="new-epoch-message", body=list(b"CONFIDENTIAL-FIXTURE four members"))["wire"]
        pubs["alice"].publish(a, future["op_id"])
        for db in (b, c, d):
            result = call(db, "receive", packet=future["packet"])
            assert result["result"]["body_hash"] == digest(b"CONFIDENTIAL-FIXTURE four members")
        checks["messaging_continues_after_membership_race"] = True

        checkpoint = root / "old-backup.sqlite"
        copy_database(a, checkpoint)
        anchor = call(a, "prepare_send", op_id="rollback-anchor", body=list(b"CONFIDENTIAL-FIXTURE rollback"))["wire"]
        pubs["alice"].publish(a, anchor["op_id"])
        # Every adapter is a separate process and has closed its DB connection.
        for suffix in ("-wal", "-shm"):
            Path(str(a) + suffix).unlink(missing_ok=True)
        shutil.copyfile(checkpoint, a)
        detected = pubs["alice"].guard_restored_state(a)
        assert detected["recovery_required"]
        expect_rejection(lambda: call(a, "prepare_send", op_id="after-rollback", body=[1]))
        checks["known_accepted_send_missing_from_restored_db_quarantines_client"] = True

        head, _ = pubs["bob"].fetch()
        paths = pubs["bob"].git("ls-tree", "-r", "--name-only", head).stdout.decode().splitlines()
        contents = b"\n".join(pubs["bob"].git("show", head + ":" + path).stdout for path in paths)
        assert b"CONFIDENTIAL-FIXTURE" not in contents
        assert b'"signer"' not in contents and b'"storage"' not in contents and b'"request_hash"' not in contents
        assert all(path.startswith(".agents/") and path.endswith(".json") for path in paths)
        checks["git_contains_only_ciphertext_and_explicit_public_metadata"] = True
        for mirror in [pubs["alice"].origin, *[p.mirror for p in pubs.values()]]:
            objects = subprocess.check_output(["git", "--git-dir=" + str(mirror), "cat-file",
                "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)"], text=True).splitlines()
            for row in objects:
                oid, kind = row.split()
                if kind != "blob":
                    continue
                blob = subprocess.check_output(["git", "--git-dir=" + str(mirror), "cat-file", "blob", oid])
                assert b"CONFIDENTIAL-FIXTURE" not in blob
                assert b'"signer"' not in blob and b'"storage"' not in blob and b'"request_hash"' not in blob
        checks["rejected_and_unreachable_git_objects_have_no_fixture_plaintext_or_private_state"] = True
        return {"suite": suite, "checks": checks, "git_race_winner": winner, "final_epoch": 3,
                "members_after_rebuild": 4, "process_termination": "SIGKILL at explicit boundaries",
                "storage": "SQLite WAL/FULL with disposable plaintext fixture secrets",
                "scope": "No real identity, Touch ID, hardware power-loss or complete anti-rollback proof"}


def main():
    results = [run(suite) for suite in ("ed25519", "p256")]
    output = {"experiment": "OpenMLS transactional adapter", "version": "0.9.2", "results": results}
    print(json.dumps(output, indent=2))
    (HERE / "results.json").write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
