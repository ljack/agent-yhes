import datetime as dt
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from dataclasses import replace
from pathlib import Path

from ghes import (
    BindingChallenge,
    BindingProof,
    EvidenceUnavailable,
    GHESIdentityAdapter,
    HTTPResponse,
    IdentityEvidence,
    InvalidEvidence,
    InvalidProof,
    SSHSigningKey,
    UrllibTransport,
    binding_payload,
    verify_binding_proof,
)


HOST = "https://ghes.example.test"
USER_ID = 7421
REPO_ID = 9182
OWNER = "team"
REPOSITORY = "project"
NOW = dt.datetime.now(dt.timezone.utc).isoformat()


class FakeTransport:
    def __init__(self, *, ssh_record=None, gpg_records=None, permission="write"):
        self.ssh_record = ssh_record
        self.gpg_records = [] if gpg_records is None else gpg_records
        self.permission = permission
        self.urls = []
        self.response_url = None

    def __call__(self, request, timeout):
        self.urls.append(request.full_url)
        path = urllib.parse.urlsplit(request.full_url).path
        self.assert_token(request)
        if path == "/api/v3/user":
            value = {"id": USER_ID, "login": "fixture-user"}
        elif path == f"/api/v3/repos/{OWNER}/{REPOSITORY}":
            value = {"id": REPO_ID}
        elif path.endswith("/collaborators/fixture-user/permission"):
            value = {"permission": self.permission, "user": {"id": USER_ID}}
        elif path == "/api/v3/user/ssh_signing_keys":
            value = [] if self.ssh_record is None else [self.ssh_record]
        elif path == "/api/v3/user/gpg_keys":
            value = self.gpg_records
        else:
            raise AssertionError(f"unexpected fake request path: {path}")
        return HTTPResponse(
            status=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(value).encode(),
            url=self.response_url or request.full_url,
        )

    @staticmethod
    def assert_token(request):
        if request.get_header("Authorization") != "Bearer test-token":
            raise AssertionError("adapter did not use the injected test token")


class GHESIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="agent-yhes-ghes-test-")
        cls.root = Path(cls.temp.name)
        cls.ssh_private = cls.root / "ssh_ed25519"
        cls.ssh_public = cls.root / "ssh_ed25519.pub"
        cls.ssh_available = shutil.which("ssh-keygen") is not None
        if cls.ssh_available:
            cls.run_checked(
                [
                    shutil.which("ssh-keygen"),
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(cls.ssh_private),
                ]
            )

        # A shallow path avoids the Unix-domain socket path limit used by gpg-agent.
        cls.gpg_home = cls.root
        cls.gpg_available = all(shutil.which(name) for name in ("gpg", "gpgv", "gpgconf"))
        cls.gpg_raw = None
        cls.gpg_fingerprint = None
        if cls.gpg_available:
            os.chmod(cls.gpg_home, 0o700)
            cls.gpg_env = {
                "PATH": os.environ.get("PATH", os.defpath),
                "LC_ALL": "C",
                "HOME": str(cls.gpg_home),
                "GNUPGHOME": str(cls.gpg_home),
            }
            try:
                cls.run_checked(
                    [
                        shutil.which("gpg"),
                        "--batch",
                        "--no-tty",
                        "--pinentry-mode",
                        "loopback",
                        "--passphrase",
                        "",
                        "--quick-generate-key",
                        "GHES Adapter Fixture <fixture@example.invalid>",
                        "ed25519",
                        "sign",
                        "0",
                    ],
                    env=cls.gpg_env,
                )
                cls.gpg_fingerprint = cls.fingerprint_from_home()
                exported = cls.run_checked(
                    [shutil.which("gpg"), "--armor", "--export", cls.gpg_fingerprint],
                    env=cls.gpg_env,
                )
                cls.gpg_raw = exported.stdout.decode()
            except BaseException:
                subprocess.run(
                    [shutil.which("gpgconf"), "--homedir", str(cls.gpg_home), "--kill", "gpg-agent"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=10,
                    env=cls.gpg_env,
                )
                cls.temp.cleanup()
                raise

    @classmethod
    def tearDownClass(cls):
        if cls.gpg_available:
            subprocess.run(
                [
                    shutil.which("gpgconf"),
                    "--homedir",
                    str(cls.gpg_home),
                    "--kill",
                    "gpg-agent",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
                env=cls.gpg_env,
            )
        cls.temp.cleanup()

    @classmethod
    def run_checked(cls, argv, *, env=None):
        if env is None:
            env = {
                "PATH": os.environ.get("PATH", os.defpath),
                "LC_ALL": "C",
                "HOME": str(cls.root),
            }
        return subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=30,
            env=env,
        )

    @classmethod
    def fingerprint_from_home(cls):
        result = cls.run_checked(
            [shutil.which("gpg"), "--with-colons", "--list-keys"], env=cls.gpg_env
        )
        for line in result.stdout.decode().splitlines():
            fields = line.split(":")
            if fields[0] == "fpr":
                return fields[9].upper()
        raise AssertionError("fixture GPG key has no fingerprint")

    def setUp(self):
        self.challenge = BindingChallenge(
            host=HOST,
            user_id=USER_ID,
            repository_id=REPO_ID,
            nonce="ab" * 32,
            project="project:alpha",
            device_key="ssh-ed25519:Zml4dHVyZS1wdWJsaWMta2V5",
        )

    def adapter(self, transport):
        return GHESIdentityAdapter(HOST, "test-token", transport=transport)

    def read(self, transport):
        return self.adapter(transport).read_identity(
            expected_host=HOST,
            expected_user_id=USER_ID,
            owner=OWNER,
            repository=REPOSITORY,
            expected_repository_id=REPO_ID,
        )

    def ssh_record(self):
        public = self.ssh_public.read_text().strip()
        return {"id": 123, "key": public, "created_at": NOW}

    def test_reads_authenticated_immutable_ids_permission_and_signing_keys(self):
        fake = FakeTransport(ssh_record=self.ssh_record())
        evidence = self.read(fake)
        self.assertEqual((evidence.host, evidence.user_id, evidence.repository_id), (HOST, USER_ID, REPO_ID))
        self.assertEqual(evidence.permission, "write")
        self.assertEqual(evidence.ssh_signing_keys[0].algorithm, "ssh-ed25519")
        self.assertEqual(len(fake.urls), 5)
        self.assertTrue(all("/user/ssh_signing_keys" not in url or "page=1" in url for url in fake.urls))

    def test_identity_fetch_fails_closed_for_wrong_host_ids_permission_and_redirect(self):
        with self.assertRaises(InvalidEvidence):
            self.adapter(FakeTransport()).read_identity(
                expected_host="https://other.example.test",
                expected_user_id=USER_ID,
                owner=OWNER,
                repository=REPOSITORY,
                expected_repository_id=REPO_ID,
            )
        with self.assertRaises(InvalidEvidence):
            self.adapter(FakeTransport()).read_identity(
                expected_host=HOST,
                expected_user_id=USER_ID + 1,
                owner=OWNER,
                repository=REPOSITORY,
                expected_repository_id=REPO_ID,
            )
        with self.assertRaises(InvalidEvidence):
            self.adapter(FakeTransport()).read_identity(
                expected_host=HOST,
                expected_user_id=USER_ID,
                owner=OWNER,
                repository=REPOSITORY,
                expected_repository_id=REPO_ID + 1,
            )
        with self.assertRaises(InvalidEvidence):
            self.read(FakeTransport(permission="read"))
        fake = FakeTransport()
        fake.response_url = "https://redirect.example.test/api/v3/user"
        with self.assertRaises(EvidenceUnavailable):
            self.read(fake)
        fake = FakeTransport()
        fake.response_url = HOST + "/api/v3/another-endpoint"
        with self.assertRaises(EvidenceUnavailable):
            self.read(fake)

    def test_ssh_proof_verifies_exact_payload_and_all_scope_fields(self):
        if not self.ssh_available:
            self.skipTest("ssh-keygen is unavailable")
        evidence = self.read(FakeTransport(ssh_record=self.ssh_record()))
        payload = binding_payload(self.challenge)
        payload_path = self.root / "proof.payload"
        payload_path.write_bytes(payload)
        self.run_checked(
            [
                shutil.which("ssh-keygen"),
                "-q",
                "-Y",
                "sign",
                "-f",
                str(self.ssh_private),
                "-n",
                "agent-yhes-enrollment-v1",
                str(payload_path),
            ]
        )
        signature = Path(str(payload_path) + ".sig").read_bytes()
        proof = BindingProof("ssh-ed25519", "123", payload, signature)
        verify_binding_proof(evidence, self.challenge, proof)

        with self.assertRaises(InvalidProof):
            verify_binding_proof(
                evidence,
                replace(self.challenge, nonce="cd" * 32),
                proof,
            )
        for field, value in (
            ("host", "https://other.example.test"),
            ("user_id", USER_ID + 1),
            ("repository_id", REPO_ID + 1),
        ):
            with self.subTest(field=field), self.assertRaises(InvalidProof):
                verify_binding_proof(evidence, replace(self.challenge, **{field: value}), proof)
        tampered = bytearray(payload)
        tampered[-2] ^= 1
        with self.assertRaises(InvalidProof):
            verify_binding_proof(
                evidence,
                self.challenge,
                BindingProof("ssh-ed25519", "123", bytes(tampered), signature),
            )
        with self.assertRaises(InvalidProof):
            verify_binding_proof(
                evidence,
                self.challenge,
                BindingProof("ssh-rsa", "123", payload, signature),
            )

    def test_ssh_key_profiles_are_restricted_and_malformed_keys_rejected(self):
        unsupported = dict(self.ssh_record(), key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==")
        with self.assertRaises(InvalidEvidence):
            self.read(FakeTransport(ssh_record=unsupported))
        malformed = dict(self.ssh_record(), key="ssh-ed25519 not-base64")
        with self.assertRaises(InvalidEvidence):
            self.read(FakeTransport(ssh_record=malformed))

    def test_gpg_raw_key_fingerprints_and_isolated_signature_verification(self):
        if not self.gpg_available:
            self.skipTest("gpg/gpgv are unavailable")
        record = {
            "key_id": self.gpg_fingerprint[-16:],
            "created_at": NOW,
            "expires_at": None,
            "revoked": False,
            "can_sign": True,
            "raw_key": self.gpg_raw,
            "subkeys": [],
        }
        evidence = self.read(FakeTransport(gpg_records=[record]))
        key = evidence.gpg_signing_keys[0]
        self.assertEqual(key.fingerprints, (self.gpg_fingerprint,))
        self.assertEqual(key.signing_fingerprints, (self.gpg_fingerprint,))

        payload = binding_payload(self.challenge)
        payload_path = self.root / "gpg.payload"
        signature_path = self.root / "gpg.signature"
        payload_path.write_bytes(payload)
        self.run_checked(
            [
                shutil.which("gpg"),
                "--batch",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--local-user",
                self.gpg_fingerprint,
                "--detach-sign",
                "--output",
                str(signature_path),
                str(payload_path),
            ],
            env=self.gpg_env,
        )
        proof = BindingProof(
            "openpgp",
            self.gpg_fingerprint,
            payload,
            signature_path.read_bytes(),
        )
        verify_binding_proof(evidence, self.challenge, proof)

    def test_gpg_expired_revoked_or_mismatched_metadata_is_rejected(self):
        if not self.gpg_available:
            self.skipTest("gpg is unavailable")
        record = {
            "key_id": self.gpg_fingerprint[-16:],
            "created_at": NOW,
            "expires_at": None,
            "revoked": False,
            "can_sign": True,
            "raw_key": self.gpg_raw,
            "subkeys": [],
        }
        expired = dict(record, expires_at="2000-01-01T00:00:00Z")
        with self.assertRaises(InvalidEvidence):
            self.read(FakeTransport(gpg_records=[expired]))
        revoked = dict(record, revoked=True)
        with self.assertRaises(InvalidEvidence):
            self.read(FakeTransport(gpg_records=[revoked]))
        mismatch = dict(record, key_id="0000000000000000")
        with self.assertRaises(InvalidEvidence):
            self.read(FakeTransport(gpg_records=[mismatch]))
        private_material = dict(record, raw_key="-----BEGIN PGP PRIVATE KEY BLOCK-----")
        with self.assertRaises(InvalidEvidence):
            self.read(FakeTransport(gpg_records=[private_material]))

    def test_strict_payload_rejects_duplicate_fields(self):
        evidence = IdentityEvidence(
            HOST, USER_ID, "fixture-user", REPO_ID, OWNER, REPOSITORY, "write",
            (SSHSigningKey(123, "ssh-ed25519 AAAA", "ssh-ed25519", NOW),), (),
        )
        payload = (
            b'{"device_key":"x","host":"' + HOST.encode() + b'","nonce":"' +
            self.challenge.nonce.encode() + b'","project":"project:alpha","purpose":'
            b'"agent-yhes-enrollment-v1","repository_id":9182,"user_id":7421,'
            b'"version":1,"version":1}'
        )
        with self.assertRaises((InvalidEvidence, InvalidProof)):
            verify_binding_proof(
                evidence,
                self.challenge,
                BindingProof("ssh-ed25519", "123", payload, b"not-a-signature"),
            )

    def test_urllib_transport_rejects_redirect_without_following_it(self):
        hits = []

        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/final")
                self.end_headers()

            def log_message(self, _format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        transport = UrllibTransport()
        request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/start")
        try:
            with self.assertRaises(EvidenceUnavailable):
                transport(request, timeout=2)
            self.assertEqual(hits, ["/start"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
