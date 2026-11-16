"""Disposable loopback NATS fixture shared by the demo and integration tests."""
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import time


class DemoBroker:
    def __init__(self, directory, tls=False):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.binary = os.environ.get("YHES_NATS_SERVER") or shutil.which("nats-server")
        if not self.binary:
            raise RuntimeError("Install nats-server or set YHES_NATS_SERVER to its binary path")
        self.token = secrets.token_hex(24)
        self.process = None
        self.tls = tls
        self.ca = None
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        self.url = ("tls" if tls else "nats") + f"://127.0.0.1:{self.port}"
        self.config = self.directory / "nats.conf"
        config = f'listen: "127.0.0.1:{self.port}"\njetstream {{ store_dir: {json.dumps(str(self.directory / "store"))} }}\nauthorization {{ token: {json.dumps(self.token)} }}\n'
        if tls:
            certificate, key = self.directory / "cert.pem", self.directory / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout", str(key), "-out", str(certificate)], check=True, capture_output=True)
            key.chmod(0o600)
            self.ca = str(certificate)
            config += f'tls {{ cert_file: {json.dumps(str(certificate))}, key_file: {json.dumps(str(key))} }}\n'
        self.config.write_text(config)
        self.config.chmod(0o600)

    def start(self):
        self.log = (self.directory / "server.log").open("ab")
        self.process = subprocess.Popen([self.binary, "-c", str(self.config)], stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("temporary NATS server exited; inspect its local server.log")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return self
            except OSError:
                time.sleep(0.02)
        self.stop()
        raise RuntimeError("temporary NATS server did not start")

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process = None
        if hasattr(self, "log"):
            self.log.close()
