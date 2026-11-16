#!/usr/bin/env python3
"""Two local workspaces, disposable identities, real Git and loopback NATS.

The separate Cargo example contains the fixture providers. The production yhes
binary and native signer are never invoked by this runner.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid

TOOLKIT = Path(__file__).resolve().parents[1]
EXAMPLE = TOOLKIT / "secure/target/debug/examples/yhes_sim"
MARKER = Path(".agents/yhes-simulation.json")
BRANCH = "agent-yhes/secure-simulation"


class SimError(Exception):
    pass


def checked_dir(path, create=False):
    path = Path(path).absolute()
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise SimError("Use a real, locally owned directory without group/world write access.")
    return path.resolve(strict=True)


def read_bytes(path, limit=65536):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > limit:
        raise SimError("The simulation descriptor is not a bounded regular local file.")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise SimError("Simulation data exceeds its size bound.")
    return data


def read_json(path):
    return json.loads(read_bytes(path))


def save_new(path, value, raw=False):
    path = Path(path)
    data = value if raw else (json.dumps(value, indent=2) + "\n").encode()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        if read_bytes(path, max(len(data), 65536)) != data:
            raise SimError("Existing simulation data differs; keep it and choose an unused lab.")
        return
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


@contextlib.contextmanager
def locked(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def build():
    command = ["cargo", "build", "--quiet", "--locked", "--manifest-path", str(TOOLKIT / "secure/Cargo.toml"),
               "--target-dir", str(TOOLKIT / "secure/target"), "-p", "yhes-cli", "--example", "yhes_sim"]
    env = os.environ.copy()
    env.setdefault("CARGO_BUILD_JOBS", "4")
    result = subprocess.run(command, cwd=TOOLKIT, env=env, stdout=subprocess.DEVNULL, timeout=180)
    if result.returncode:
        raise SimError("The separate simulation example did not build.")


def fixture_git(arguments, **kwargs):
    # Do not let a caller's GIT_DIR, object directory, SSH agent or Git config
    # redirect this fixture's initialization/inspection into another project.
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1"}
    return subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                           "-c", "credential.helper=", *arguments], env=environment, **kwargs)


def load_lab(path):
    root = checked_dir(path)
    if root.stat().st_mode & 0o077:
        raise SimError("The fixture lab must have mode 0700.")
    lab = read_json(root / "lab.json")
    if lab.get("version") != 1 or lab.get("simulation") is not True or not lab.get("project_id", "").startswith("sim-"):
        raise SimError("This is not an initialized simulation lab.")
    if Path(lab["toolkit"]).resolve() != TOOLKIT:
        raise SimError("Use the toolkit that prepared this simulation.")
    if lab["alice"] == lab["bob"]:
        raise SimError("The two simulated users need different workspace directories.")
    return root, lab


def node_context(project):
    project = checked_dir(project)
    marker = read_json(project / MARKER)
    if marker.get("simulation") is not True or marker.get("role") not in ("alice", "bob"):
        raise SimError("This workspace is not attached to a simulation.")
    root, lab = load_lab(marker["lab_root"])
    role = marker["role"]
    if project != Path(lab[role]).resolve() or marker.get("toolkit") != str(TOOLKIT):
        raise SimError("The workspace does not match this simulation role.")
    return root, lab, role, root / "nodes" / f"{role}.json"


def invoke(node, command, input_bytes=None):
    env = os.environ.copy()
    for key in ("YHES_BROKER_TOKEN", "YHES_BROKER_URL", "YHES_BROKER_CA", "SSH_AUTH_SOCK"):
        env.pop(key, None)
    process = subprocess.run([str(EXAMPLE), "run", "--node", str(node), "--", *command],
                             input=input_bytes, stdout=subprocess.PIPE, env=env, timeout=360)
    try:
        result = json.loads(process.stdout)
    except (ValueError, UnicodeError):
        raise SimError("The simulation runner returned no structured result.") from None
    if result.get("simulation") is not True:
        raise SimError("A result was not labelled as a simulation.")
    if process.returncode or result.get("ok") is False:
        raise SimError(json.dumps(result, ensure_ascii=False))
    return result


def identity(node):
    result = subprocess.run([str(EXAMPLE), "identity", "--node", str(node)], stdout=subprocess.PIPE, timeout=30)
    value = json.loads(result.stdout)
    if result.returncode or value.get("simulation") is not True:
        raise SimError("Simulation identity preparation failed.")
    return {key: value[key] for key in ("algorithm", "key_id", "public_key", "author", "project")}


def prepare(args):
    alice = checked_dir(args.alice, create=True)
    bob = checked_dir(args.bob, create=True)
    if alice == bob or TOOLKIT in (alice, bob) or alice in bob.parents or bob in alice.parents:
        raise SimError("Choose two separate workspaces outside the toolkit.")
    pair = hashlib.sha256(f"{alice}\0{bob}".encode()).hexdigest()[:16]
    root = checked_dir(args.lab or Path.home() / "Library/Caches/agent-yhes/simulations" / pair, create=True)
    if root in (alice, bob) or alice in root.parents or bob in root.parents or root in alice.parents or root in bob.parents:
        raise SimError("Store the simulation lab outside both project directories.")
    if not (root / "lab.json").exists() and any(root.iterdir()):
        raise SimError("The selected lab directory is not empty and has no simulation marker.")
    server = Path(args.nats_server or shutil.which("nats-server") or "")
    if not server.is_absolute() or not server.is_file() or not os.access(server, os.X_OK):
        raise SimError("Supply --nats-server with the installed official nats-server executable.")
    server = server.resolve()
    for project in (alice, bob):
        if (project / MARKER).exists():
            marker = read_json(project / MARKER)
            if marker.get("lab_root") != str(root):
                raise SimError("A workspace already belongs to another simulation; it was not changed.")
    build()
    with locked(root / ".prepare.lock"):
        if (root / "lab.json").exists():
            _, lab = load_lab(root)
            if lab["alice"] != str(alice) or lab["bob"] != str(bob):
                raise SimError("Existing lab has other workspace bindings.")
        else:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            lab = dict(version=1, simulation=True, project_id="sim-" + uuid.uuid4().hex[:16],
                       alice=str(alice), bob=str(bob), broker_url=f"nats://127.0.0.1:{port}", toolkit=str(TOOLKIT))
            save_new(root / "lab.json", lab)
        for directory in (root / "nodes", root / "private"):
            checked_dir(directory, create=True)
        if not (root / "broker.token").exists():
            save_new(root / "broker.token", secrets.token_hex(32).encode(), raw=True)
        port = int(lab["broker_url"].rsplit(":", 1)[1])
        token = read_bytes(root / "broker.token", 128).decode().strip()
        if len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
            raise SimError("The disposable broker token is malformed.")
        # Only a disposable local token lives in this mode-0600 server config.
        config = f'listen: "127.0.0.1:{port}"\nauthorization {{ token: "{token}" }}\njetstream {{ store_dir: {json.dumps(str(root / "broker-data"))} }}\n'
        save_new(root / "nats.conf", config.encode(), raw=True)
        save_new(root / "runtime.json", {"nats_server": str(server)})
        remote = root / "shared.git"
        if not remote.exists():
            fixture_git(["init", "--bare", "--template=", "--quiet", str(remote)], check=True, timeout=30)
        public = {}
        for role, project in (("alice", alice), ("bob", bob)):
            node = root / "nodes" / f"{role}.json"
            save_new(node, dict(version=1, simulation=True, lab_root=str(root), project=str(project),
                                project_id=lab["project_id"], role=role))
            public[role] = identity(node)
            checked_dir(project / ".agents", create=True)
            save_new(project / MARKER, dict(version=1, simulation=True, lab_root=str(root), role=role, toolkit=str(TOOLKIT)))
        save_new(root / "public-identities.json", public)
    return dict(ok=True, simulation=True, lab=str(root), alice=str(alice), bob=str(bob),
                next="Open each workspace as its own Teerminal project and paste the short README bootstrap prompt.")


def port_ready(lab):
    port = int(lab["broker_url"].rsplit(":", 1)[1])
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def server_start(root, lab):
    with locked(root / ".server.lock"):
        if port_ready(lab):
            return
        ctl = Path.home() / ".local/bin/teerminalctl"
        if not ctl.is_file():
            raise SimError(f"Start the simulation server in another terminal: {TOOLKIT}/bin/yhes-sim serve --lab {root}")
        # The native persistent terminal manager owns the server lifecycle.
        subprocess.run([str(ctl), "tmux", "list", "--json"], check=True, stdout=subprocess.DEVNULL, timeout=15)
        launch = subprocess.run([str(ctl), "tmux", "run", "--detach", "--cwd", str(TOOLKIT), "--",
                                 str(TOOLKIT / "bin/yhes-sim"), "serve", "--lab", str(root)],
                                check=True, stdout=subprocess.PIPE, text=True, timeout=15)
        session = launch.stdout.strip()
        try:
            session = str(uuid.UUID(session))
        except ValueError:
            raise SimError("The server session started but did not return a recognizable session ID.") from None
        state = root / "server-session.json"
        if state.exists():
            # Retain old session evidence; never stop a different process to restart.
            old = read_json(state)
            save_new(root / f"server-session-{old['session']}.json", old)
            state.unlink()
        save_new(state, {"session": session, "lab": str(root)})
        deadline = time.monotonic() + 10
        while not port_ready(lab):
            if time.monotonic() >= deadline:
                raise SimError("The managed NATS server did not become ready; inspect its Teerminal tab.")
            time.sleep(0.1)


def serve(args):
    root, lab = load_lab(args.lab)
    if port_ready(lab):
        raise SimError("The simulation port is already in use; no second server started.")
    runtime = read_json(root / "runtime.json")
    server = Path(runtime["nats_server"])
    if not server.is_absolute() or not server.is_file():
        raise SimError("The prepared NATS executable is unavailable.")
    os.execv(str(server), [str(server), "-c", str(root / "nats.conf")])


def artifact_exists(root, name):
    result = fixture_git(["--git-dir", str(root / "shared.git"), "cat-file", "-e",
                             f"refs/heads/{BRANCH}:public/{name}"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=10)
    return result.returncode == 0


def bootstrap_once(root, lab, role, node):
    shared = ["--project", lab[role], "--project-id", lab["project_id"],
              "--human", f"sim-{role}", "--as", f"sim-{role}-agent",
              "--remote", str(root / "shared.git"), "--branch", BRANCH]
    public = read_json(root / "public-identities.json")
    if role == "alice":
        result = invoke(node, ["team-init", *shared])
        save_new(root / "invitation.json", {"authority": result["authority"], "bootstrap_head": result["bootstrap_head"]})
        if not artifact_exists(root, "request-sim-bob-agent.json"):
            return dict(ok=True, simulation=True, role=role, state="waiting-for-bob", next="Start bootstrap in Bob's project.")
        invoke(node, ["team-admit", "--project", lab[role], "--peer", "sim-bob-agent", "--peer-key", public["bob"]["key_id"]])
    else:
        if not (root / "invitation.json").exists():
            return dict(ok=True, simulation=True, role=role, state="waiting-for-alice", next="Start bootstrap in Alice's project.")
        invitation = read_json(root / "invitation.json")
        if invitation["authority"] != public["alice"]["key_id"]:
            raise SimError("Simulation invitation differs from its prepared fixture identity.")
        invoke(node, ["team-request", *shared, "--authority", invitation["authority"], "--bootstrap", invitation["bootstrap_head"]])
    result = invoke(node, ["team-connect", "--project", lab[role]])
    if role == "alice" and result.get("state") == "ready":
        invoke(node, ["team-broker-init", "--project", lab[role], "--broker", lab["broker_url"]])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default=".", help="this simulated user's workspace (default: current directory)")
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("--alice", required=True); prep.add_argument("--bob", required=True)
    prep.add_argument("--lab"); prep.add_argument("--nats-server")
    server = commands.add_parser("serve"); server.add_argument("--lab", required=True)
    start = commands.add_parser("bootstrap"); start.add_argument("--wait", type=int, default=30)
    for name in ("status", "inbox", "flush"):
        commands.add_parser(name)
    listen = commands.add_parser("listen"); listen.add_argument("--seconds", type=int, default=30)
    for name in ("send", "say"):
        sub = commands.add_parser(name)
        source = sub.add_mutually_exclusive_group(required=True)
        source.add_argument("--text"); source.add_argument("--stdin", action="store_true")
        sub.add_argument("--operation", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare(args)
        elif args.command == "serve":
            serve(args); return 0
        else:
            root, lab, role, node = node_context(args.project)
            build()
            if args.command == "bootstrap":
                if not 0 <= args.wait <= 300:
                    raise SimError("--wait must be between 0 and 300 seconds.")
                server_start(root, lab)
                deadline = time.monotonic() + args.wait
                previous = None
                while True:
                    result = bootstrap_once(root, lab, role, node)
                    state = result.get("state")
                    if state != previous:
                        print(f"SIMULATION {role}: {state}", file=sys.stderr); previous = state
                    if state == "ready" or time.monotonic() >= deadline:
                        break
                    time.sleep(2)
            else:
                command = [f"team-{args.command}", "--project", lab[role]]
                if args.command in ("send", "say", "listen", "flush"):
                    command += ["--broker", lab["broker_url"]]
                payload = None
                if args.command in ("send", "say"):
                    command += ["--operation", args.operation]
                    if args.stdin:
                        command += ["--stdin"]; payload = sys.stdin.buffer.read(65540)
                    else:
                        command += ["--text", args.text]
                if args.command == "listen":
                    command += ["--seconds", str(args.seconds)]
                result = invoke(node, command, payload)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (SimError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"ok": False, "simulation": True, "error": str(error)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
