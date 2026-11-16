"""Process-level lab manager trial. Only disposable stores and loopback NATS."""
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import simulation

TOOLKIT = Path(__file__).resolve().parents[1]
RUNNER = TOOLKIT / "bin/yhes-sim"
SERVER = os.environ.get("YHES_SIM_NATS_SERVER") or shutil.which("nats-server")


class ManagerBoundaryTests(unittest.TestCase):
    def test_fixture_git_ignores_ambient_git_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            outside = root / "unrelated"
            outside.mkdir()
            remote = root / "fixture.git"
            with patch.dict(os.environ, {"GIT_DIR": str(outside / "redirected.git"),
                                         "GIT_OBJECT_DIRECTORY": str(outside / "objects"),
                                         "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.bare",
                                         "GIT_CONFIG_VALUE_0": "false"}):
                simulation.fixture_git(["init", "--bare", "--template=", "--quiet", str(remote)], check=True)
            result = simulation.fixture_git(["--git-dir", str(remote), "rev-parse", "--is-bare-repository"],
                                            stdout=subprocess.PIPE, check=True)
            self.assertEqual(result.stdout.strip(), b"true")
            self.assertEqual(list(outside.iterdir()), [])


@unittest.skipUnless(SERVER, "set YHES_SIM_NATS_SERVER for the disposable simulation trial")
class SimulationTests(unittest.TestCase):
    def test_two_workspace_bootstrap_persistent_identities_and_broker(self):
        with tempfile.TemporaryDirectory(prefix="yhes-sim-process-") as directory:
            root = Path(directory).resolve()
            alice, bob, lab = root / "alice", root / "bob", root / "lab"
            alice.mkdir(mode=0o700)
            (alice / "keep.txt").write_text("Existing project content stays here.")
            prepared = self.call(None, "prepare", "--alice", str(alice), "--bob", str(bob),
                                 "--lab", str(lab), "--nats-server", str(Path(SERVER).resolve()))
            self.assertTrue(prepared["simulation"])
            self.assertEqual((alice / "keep.txt").read_text(), "Existing project content stays here.")
            lab_config = json.loads((lab / "lab.json").read_text())
            port = int(lab_config["broker_url"].rsplit(":", 1)[1])
            with (root / "server.log").open("wb") as log:
                server = subprocess.Popen([str(RUNNER), "serve", "--lab", str(lab)],
                                          cwd=TOOLKIT, stdout=log, stderr=log)
                listener = None
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        self.assertIsNone(server.poll())
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                break
                        except OSError:
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(0.05)
                    self.assertEqual(self.call(alice, "bootstrap", "--wait", "0")["state"], "waiting-for-bob")
                    self.assertEqual(self.call(bob, "bootstrap", "--wait", "0")["state"], "waiting-for-admission")
                    self.assertEqual(self.call(alice, "bootstrap", "--wait", "0")["state"], "waiting-for-key-package")
                    self.assertEqual(self.call(bob, "bootstrap", "--wait", "0")["state"], "waiting-for-invitation")
                    self.assertEqual(self.call(alice, "bootstrap", "--wait", "0")["state"], "ready")
                    self.assertEqual(self.call(bob, "bootstrap", "--wait", "0")["state"], "ready")
                    a, b = self.call(alice, "status"), self.call(bob, "status")
                    self.assertEqual(a["human"], "sim-alice")
                    self.assertEqual(b["human"], "sim-bob")
                    self.assertNotEqual(a["human_key"], b["human_key"])
                    self.assertEqual(a["group"], b["group"])
                    self.assertEqual(a["key_custody"], "simulation-files")
                    self.assertEqual(a["human_authentication"], "simulated-no-touch-id")
                    listener = subprocess.Popen([str(RUNNER), "--project", str(bob), "listen", "--seconds", "15"],
                                                cwd=TOOLKIT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    deadline = time.monotonic() + 20
                    while True:
                        self.assertIsNone(listener.poll(), "listener exited before waiting")
                        if select.select([listener.stderr], [], [], 0.5)[0]:
                            if b"realtime: waiting" in listener.stderr.readline():
                                break
                        self.assertLess(time.monotonic(), deadline)
                    sent = self.call(alice, "send", "--text", "SIMULATION private question", "--operation", "question")
                    stdout, stderr = listener.communicate(timeout=30)
                    self.assertEqual(listener.returncode, 0, stderr.decode())
                    received = json.loads(stdout)
                    self.assertEqual(received["wake"], "broker")
                    self.assertEqual(received["messages"][0]["text"], "SIMULATION private question")
                    self.assertTrue(received["simulation"])
                    retry = self.call(alice, "send", "--text", "SIMULATION private question", "--operation", "question")
                    self.assertEqual(retry["event_id"], sent["event_id"])
                    self.assertTrue(retry["replayed"])
                    self.call(bob, "send", "--text", "SIMULATION reply", "--operation", "reply")
                    self.assertEqual(self.call(alice, "inbox")["messages"][0]["author"], "sim-bob-agent")
                    self.call(alice, "say", "--text", "SIMULATION human original", "--operation", "human")
                    inbox = self.call(bob, "inbox")
                    relay = next(m for m in inbox["messages"] if m["kind"] == "agent.relay")
                    self.assertEqual(relay["human_original_author"], "sim-alice")
                    self.assertEqual(relay["author"], "sim-alice-agent")
                    self.assertEqual(relay["human_text"], "SIMULATION human original")
                    self.assertEqual(self.call(bob, "inbox")["new_messages"], 0)
                    marker = bob / ".agents/yhes-simulation.json"
                    wrong = json.loads(marker.read_text()); wrong["role"] = "alice"
                    marker.write_text(json.dumps(wrong))
                    rejected = self.call(bob, "status", success=False)
                    self.assertFalse(rejected["ok"])
                    self.assertIn("workspace", rejected["error"].lower())
                    # Git blobs contain public metadata and ciphertext only.
                    objects = subprocess.check_output(["git", "--git-dir", str(lab / "shared.git"), "rev-list", "--objects", "--all"], text=True)
                    for line in objects.splitlines():
                        value = subprocess.check_output(["git", "--git-dir", str(lab / "shared.git"), "cat-file", "-p", line.split()[0]])
                        self.assertNotIn(b"SIMULATION private question", value)
                        self.assertNotIn(b"SIMULATION human original", value)
                finally:
                    if listener is not None and listener.poll() is None:
                        listener.terminate(); listener.wait(timeout=10)
                    if listener is not None:
                        listener.stdout.close(); listener.stderr.close()
                    server.terminate(); server.wait(timeout=10)

    def call(self, project, *args, success=True):
        argv = [str(RUNNER)]
        if project is not None:
            argv += ["--project", str(project)]
        result = subprocess.run([*argv, *args], cwd=TOOLKIT, capture_output=True, timeout=180)
        value = json.loads(result.stdout)
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr.decode() + str(value))
        self.assertTrue(value["simulation"])
        return value


if __name__ == "__main__":
    unittest.main()
