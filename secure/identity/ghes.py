"""Read-only GHES identity evidence and scoped device-binding proof checks."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Protocol


SSH_NAMESPACE = "agent-yhes-enrollment-v1"
PROOF_PURPOSE = "agent-yhes-enrollment-v1"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PROOF_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_PAGES = 20
PAGE_SIZE = 100
COMMAND_TIMEOUT_SECONDS = 10


class IdentityError(Exception):
    """Base class for explicit fail-closed adapter errors."""


class EvidenceUnavailable(IdentityError):
    """Current identity evidence could not be obtained or established."""


class InvalidEvidence(IdentityError):
    """The forge returned malformed, inconsistent, or unsupported evidence."""


class InvalidProof(IdentityError):
    """The supplied scoped device-binding proof did not verify."""


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str


class HTTPTransport(Protocol):
    def __call__(self, request: urllib.request.Request, timeout: float) -> HTTPResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    """urllib transport which never follows redirects."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect())

    def __call__(self, request: urllib.request.Request, timeout: float) -> HTTPResponse:
        try:
            response = self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            error.close()
            if 300 <= error.code < 400:
                raise EvidenceUnavailable("GHES redirected an identity request") from None
            raise EvidenceUnavailable(f"GHES identity request failed with HTTP {error.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise EvidenceUnavailable("GHES identity request failed") from None
        try:
            with response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise EvidenceUnavailable("GHES identity response exceeded the size limit")
                return HTTPResponse(
                    status=response.status,
                    headers=dict(response.headers.items()),
                    body=body,
                    url=response.geturl(),
                )
        except EvidenceUnavailable:
            raise
        except (urllib.error.URLError, TimeoutError, OSError):
            raise EvidenceUnavailable("GHES identity response could not be read") from None


@dataclass(frozen=True)
class SSHSigningKey:
    key_id: int
    public_key: str
    algorithm: str
    created_at: str


@dataclass(frozen=True)
class GPGSigningKey:
    key_id: str
    fingerprints: tuple[str, ...]
    signing_fingerprints: tuple[str, ...]
    raw_key: str
    created_at: str
    expires_at: str | None


@dataclass(frozen=True)
class IdentityEvidence:
    host: str
    user_id: int
    login: str
    repository_id: int
    owner: str
    repository: str
    permission: str
    ssh_signing_keys: tuple[SSHSigningKey, ...]
    gpg_signing_keys: tuple[GPGSigningKey, ...]


@dataclass(frozen=True)
class BindingChallenge:
    host: str
    user_id: int
    repository_id: int
    nonce: str
    project: str
    device_key: str


@dataclass(frozen=True)
class BindingProof:
    profile: str
    key_id: str
    payload: bytes
    signature: bytes


def _normalized_origin(value: str, *, root_only: bool) -> str:
    try:
        if not isinstance(value, str):
            raise ValueError
        parsed = urllib.parse.urlsplit(value)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or (root_only and parsed.query)
            or parsed.fragment
            or (root_only and parsed.path not in ("", "/"))
        ):
            raise ValueError
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        if host.endswith("."):
            raise ValueError
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        if ":" in host:
            host = f"[{host}]"
        if port == 443:
            port = None
        return f"https://{host}" + (f":{port}" if port is not None else "")
    except (UnicodeError, ValueError):
        raise ValueError("GHES host must be a trusted HTTPS origin") from None


def _origin(value: str) -> str:
    return _normalized_origin(value, root_only=True)


def _strict_json(data: bytes, *, source: str) -> object:
    try:
        text = data.decode("utf-8")

        def object_without_duplicates(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        return json.loads(
            text,
            object_pairs_hook=object_without_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise InvalidEvidence(f"{source} was not strict UTF-8 JSON") from None


def _positive_id(value: object, label: str) -> int:
    if type(value) is not int or not 1 <= value <= (2**63 - 1):
        raise InvalidEvidence(f"GHES returned an invalid {label}")
    return value


def _valid_name(value: str, label: str) -> str:
    if (
        not value
        or len(value) > 100
        or value in {".", ".."}
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", value)
    ):
        raise InvalidEvidence(f"GHES returned an invalid {label}")
    return value


def _iso_datetime(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise InvalidEvidence(f"GHES returned an invalid {label}")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(dt.timezone.utc)
    except ValueError:
        raise InvalidEvidence(f"GHES returned an invalid {label}") from None


def _not_expired(value: object, label: str) -> str | None:
    if value is None:
        return None
    expiration = _iso_datetime(value, label)
    if expiration <= dt.datetime.now(dt.timezone.utc):
        raise InvalidEvidence(f"GHES reported an expired {label}")
    return value


def _parse_ssh_key(raw: object) -> tuple[str, str]:
    if not isinstance(raw, str) or len(raw) > 16_384:
        raise InvalidEvidence("GHES returned an invalid SSH signing key")
    fields = raw.strip().split()
    if len(fields) < 2:
        raise InvalidEvidence("GHES returned an invalid SSH signing key")
    algorithm, encoded = fields[:2]
    supported = {"ssh-ed25519", "ecdsa-sha2-nistp256"}
    if algorithm not in supported:
        raise InvalidEvidence("GHES returned an unsupported SSH signing-key profile")
    try:
        blob = base64.b64decode(encoded, validate=True)
        offset = 0

        def read_field() -> bytes:
            nonlocal offset
            if offset + 4 > len(blob):
                raise ValueError
            length = struct.unpack(">I", blob[offset : offset + 4])[0]
            offset += 4
            if length > len(blob) - offset:
                raise ValueError
            value = blob[offset : offset + length]
            offset += length
            return value

        blob_algorithm = read_field().decode("ascii")
        if blob_algorithm != algorithm:
            raise ValueError
        if algorithm == "ssh-ed25519":
            if len(read_field()) != 32:
                raise ValueError
        else:
            if read_field() != b"nistp256" or len(read_field()) != 65:
                raise ValueError
            if blob[offset - 65] != 4:
                raise ValueError
        if offset != len(blob):
            raise ValueError
    except (ValueError, UnicodeDecodeError, struct.error):
        raise InvalidEvidence("GHES returned a malformed SSH signing key") from None
    return algorithm, f"{algorithm} {encoded}"


def _run(
    argv: list[str],
    *,
    input_bytes: bytes | None = None,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
    env: Mapping[str, str] | None = None,
    error: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            argv,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env=dict(env) if env is not None else {"PATH": os.defpath, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise EvidenceUnavailable(error) from None


def _tool(name: str) -> str:
    result = shutil.which(name)
    if result is None:
        raise EvidenceUnavailable(f"Required verifier tool is unavailable: {name}")
    return result


def _gpg_inventory(raw_key: str) -> dict[str, tuple[int, int, str, str]]:
    if (
        not raw_key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        or "-----BEGIN PGP PRIVATE KEY BLOCK-----" in raw_key
        or "-----BEGIN PGP SECRET KEY BLOCK-----" in raw_key
    ):
        raise InvalidEvidence("GHES returned non-public OpenPGP key material")
    gpg = _tool("gpg")
    try:
        with tempfile.TemporaryDirectory(prefix="agent-yhes-ghes-gpg-") as directory:
            os.chmod(directory, 0o700)
            home = os.path.join(directory, "home")
            os.mkdir(home, 0o700)
            key_path = os.path.join(directory, "key.asc")
            with open(key_path, "wb") as file:
                os.chmod(key_path, 0o600)
                file.write(raw_key.encode("utf-8"))
            base = [
                gpg,
                "--batch",
                "--no-options",
                "--no-tty",
                "--no-autostart",
                "--homedir",
                home,
            ]
            imported = _run(
                base + ["--import", key_path],
                error="Could not inspect the GHES OpenPGP public key",
            )
            if imported.returncode != 0:
                raise InvalidEvidence("GHES returned an unusable OpenPGP public key")
            secrets = _run(
                base + ["--with-colons", "--list-secret-keys"],
                error="Could not inspect the GHES OpenPGP public key",
            )
            if secrets.returncode != 0 or any(
                line.split(":", 1)[0].startswith(("sec", "ssb"))
                for line in secrets.stdout.decode("utf-8", "strict").splitlines()
            ):
                raise InvalidEvidence("GHES raw_key contained private OpenPGP material")
            listed = _run(
                base + ["--with-colons", "--fingerprint", "--list-keys"],
                error="Could not inspect the GHES OpenPGP public key",
            )
            if listed.returncode != 0:
                raise InvalidEvidence("GHES returned an unusable OpenPGP public key")
            records: dict[str, tuple[int, int, str, str]] = {}
            pending: tuple[str, int, int, str, str, str] | None = None
            for line in listed.stdout.decode("utf-8", "strict").splitlines():
                fields = line.split(":")
                if fields[0] in {"pub", "sub"}:
                    try:
                        algorithm = int(fields[3])
                        bits = int(fields[2])
                        validity = fields[1]
                        expiration = fields[6]
                        curve = fields[16] if len(fields) > 16 else ""
                    except (IndexError, ValueError):
                        raise InvalidEvidence("GHES returned malformed OpenPGP key metadata") from None
                    pending = (fields[0], algorithm, bits, validity, expiration, curve)
                elif fields[0] == "fpr" and pending is not None:
                    try:
                        fingerprint = fields[9].upper()
                    except IndexError:
                        raise InvalidEvidence("GHES returned malformed OpenPGP fingerprint data") from None
                    if not re.fullmatch(r"[0-9A-F]{40}|[0-9A-F]{64}", fingerprint):
                        raise InvalidEvidence("GHES returned an unsupported OpenPGP fingerprint")
                    if pending[3] in {"r", "e", "d", "i"}:
                        raise InvalidEvidence("GHES returned a revoked, expired, or invalid OpenPGP key")
                    if pending[4]:
                        try:
                            expiration = int(pending[4])
                        except ValueError:
                            raise InvalidEvidence("GHES returned malformed OpenPGP expiration data") from None
                        if expiration <= int(dt.datetime.now(dt.timezone.utc).timestamp()):
                            raise InvalidEvidence("GHES returned an expired OpenPGP key")
                    records[fingerprint] = (pending[1], pending[2], pending[0], pending[5])
                    pending = None
            if not records:
                raise InvalidEvidence("GHES returned an OpenPGP key without fingerprints")
            return records
    except UnicodeDecodeError:
        raise InvalidEvidence("GHES returned malformed OpenPGP metadata") from None


def _parse_gpg_key(value: object) -> GPGSigningKey:
    if not isinstance(value, dict):
        raise InvalidEvidence("GHES returned a malformed OpenPGP key record")
    raw_key = value.get("raw_key")
    created_at = value.get("created_at")
    if not isinstance(raw_key, str) or not isinstance(created_at, str):
        raise InvalidEvidence("GHES did not provide importable OpenPGP public-key evidence")
    if value.get("revoked") is not False:
        raise InvalidEvidence("GHES reported a revoked or unverified OpenPGP key")
    expires_at = _not_expired(value.get("expires_at"), "OpenPGP key expiration")
    _iso_datetime(created_at, "OpenPGP key creation time")
    if "expires_at" not in value:
        raise InvalidEvidence("GHES omitted OpenPGP key expiration evidence")
    subkeys = value.get("subkeys")
    if not isinstance(subkeys, list):
        raise InvalidEvidence("GHES returned malformed OpenPGP subkey metadata")
    metadata = [value]
    for subkey in subkeys:
        if not isinstance(subkey, dict):
            raise InvalidEvidence("GHES returned malformed OpenPGP subkey metadata")
        if subkey.get("revoked") is not False:
            raise InvalidEvidence("GHES reported a revoked or unverified OpenPGP subkey")
        if "expires_at" not in subkey:
            raise InvalidEvidence("GHES omitted OpenPGP subkey expiration evidence")
        _iso_datetime(subkey.get("created_at"), "OpenPGP subkey creation time")
        _not_expired(subkey.get("expires_at"), "OpenPGP subkey expiration")
        metadata.append(subkey)
    records = _gpg_inventory(raw_key)
    by_id: dict[str, str] = {}
    for fingerprint in records:
        suffix = fingerprint[-16:]
        if suffix in by_id:
            raise InvalidEvidence("GHES returned ambiguous OpenPGP key identifiers")
        by_id[suffix] = fingerprint
    expected_ids = []
    for item in metadata:
        item_id = item.get("key_id")
        if not isinstance(item_id, str) or not re.fullmatch(r"[0-9A-Fa-f]{1,16}", item_id):
            raise InvalidEvidence("GHES returned an invalid OpenPGP key identifier")
        full = by_id.get(item_id.upper().zfill(16))
        if full is None:
            raise InvalidEvidence("GHES OpenPGP fingerprint did not match raw_key")
        expected_ids.append(full)
        fingerprint_record = records[full]
        algorithm, bits, _kind, curve = fingerprint_record
        can_sign = item.get("can_sign")
        if type(can_sign) is not bool:
            raise InvalidEvidence("GHES omitted OpenPGP signing capability")
        if can_sign and not (
            (algorithm in {1, 2, 3} and bits >= 3072)
            or (algorithm == 19 and curve in {"nistp256", "nistp384", "nistp521"})
            or (algorithm == 22 and curve == "ed25519" and bits == 255)
        ):
            raise InvalidEvidence("GHES OpenPGP signing key uses a weak or unsupported profile")
    if len(expected_ids) != len(records) or len(set(expected_ids)) != len(expected_ids):
        raise InvalidEvidence("GHES OpenPGP raw_key and subkey inventory did not match")
    if not any(item.get("can_sign") is True for item in metadata):
        raise InvalidEvidence("GHES OpenPGP key has no signing-capable key")
    signing = tuple(
        expected_ids[index]
        for index, item in enumerate(metadata)
        if item.get("can_sign") is True
    )
    return GPGSigningKey(
        key_id=str(value.get("key_id", "")),
        fingerprints=tuple(expected_ids),
        signing_fingerprints=signing,
        raw_key=raw_key,
        created_at=created_at,
        expires_at=expires_at,
    )


class GHESIdentityAdapter:
    """Fetch current evidence from a trusted GHES origin; never enroll or mutate."""

    def __init__(
        self,
        host: str,
        token: str,
        *,
        transport: HTTPTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.host = _origin(host)
        if not isinstance(token, str) or not token or any(ord(char) < 33 for char in token):
            raise ValueError("A non-empty GHES read token is required")
        if not 0 < timeout <= 60:
            raise ValueError("HTTP timeout must be between 0 and 60 seconds")
        self._token = token
        self._transport = transport or UrllibTransport()
        self._timeout = timeout

    def _get(self, path: str) -> tuple[object, HTTPResponse]:
        url = f"{self.host}/api/v3{path}"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "agent-yhes-readonly-identity/1",
            },
            method="GET",
        )
        try:
            response = self._transport(request, self._timeout)
        except IdentityError:
            raise
        except Exception:
            raise EvidenceUnavailable("GHES identity transport failed") from None
        if not isinstance(response, HTTPResponse):
            raise EvidenceUnavailable("GHES identity transport returned an invalid response")
        try:
            response_origin = _normalized_origin(response.url, root_only=False)
        except ValueError:
            raise EvidenceUnavailable("GHES changed host during an identity request") from None
        if response_origin != self.host:
            raise EvidenceUnavailable("GHES changed host during an identity request")
        if response.url != request.full_url:
            raise EvidenceUnavailable("GHES redirected an identity request")
        if response.status != 200:
            raise EvidenceUnavailable(f"GHES identity endpoint returned HTTP {response.status}")
        if not isinstance(response.body, bytes) or len(response.body) > MAX_RESPONSE_BYTES:
            raise EvidenceUnavailable("GHES identity response was unavailable or oversized")
        return _strict_json(response.body, source="GHES response"), response

    def _pages(self, path: str) -> list[object]:
        result: list[object] = []
        for page in range(1, MAX_PAGES + 1):
            separator = "&" if "?" in path else "?"
            value, _response = self._get(
                f"{path}{separator}per_page={PAGE_SIZE}&page={page}"
            )
            if not isinstance(value, list):
                raise InvalidEvidence("GHES returned a malformed signing-key list")
            result.extend(value)
            if len(value) < PAGE_SIZE:
                return result
        raise EvidenceUnavailable("GHES signing-key pagination exceeded the safety limit")

    def read_identity(
        self,
        *,
        expected_host: str,
        expected_user_id: int,
        owner: str,
        repository: str,
        expected_repository_id: int,
    ) -> IdentityEvidence:
        trusted_host = _origin(expected_host)
        if trusted_host != self.host:
            raise InvalidEvidence("Expected GHES host does not match configured trust")
        expected_user_id = _positive_id(expected_user_id, "expected user ID")
        expected_repository_id = _positive_id(expected_repository_id, "expected repository ID")
        owner = _valid_name(owner, "repository owner")
        repository = _valid_name(repository, "repository name")

        user_value, _ = self._get("/user")
        if not isinstance(user_value, dict):
            raise InvalidEvidence("GHES returned a malformed authenticated user")
        user_id = _positive_id(user_value.get("id"), "user ID")
        login = user_value.get("login")
        if not isinstance(login, str):
            raise InvalidEvidence("GHES returned a malformed authenticated login")
        login = _valid_name(login, "authenticated login")
        if user_id != expected_user_id:
            raise InvalidEvidence("Authenticated GHES user ID did not match expectation")

        encoded_owner = urllib.parse.quote(owner, safe="")
        encoded_repository = urllib.parse.quote(repository, safe="")
        base_repo_path = f"/repos/{encoded_owner}/{encoded_repository}"
        repo_value, _ = self._get(base_repo_path)
        if not isinstance(repo_value, dict):
            raise InvalidEvidence("GHES returned a malformed repository")
        repository_id = _positive_id(repo_value.get("id"), "repository ID")
        if repository_id != expected_repository_id:
            raise InvalidEvidence("GHES repository ID did not match expectation")

        encoded_login = urllib.parse.quote(login, safe="")
        permission_value, _ = self._get(
            f"{base_repo_path}/collaborators/{encoded_login}/permission"
        )
        if not isinstance(permission_value, dict):
            raise InvalidEvidence("GHES returned malformed repository permission evidence")
        permission = permission_value.get("permission")
        if not isinstance(permission, str) or permission not in {"write", "maintain", "admin"}:
            raise InvalidEvidence("Authenticated GHES user lacks write, maintain, or admin access")
        permission_user = permission_value.get("user")
        if permission_user is not None:
            if not isinstance(permission_user, dict) or _positive_id(
                permission_user.get("id"), "permission user ID"
            ) != user_id:
                raise InvalidEvidence("Repository permission was returned for a different user")

        ssh_records = self._pages("/user/ssh_signing_keys")
        ssh_keys: list[SSHSigningKey] = []
        seen_ssh_ids: set[int] = set()
        for record in ssh_records:
            if not isinstance(record, dict):
                raise InvalidEvidence("GHES returned a malformed SSH signing-key record")
            key_id = _positive_id(record.get("id"), "SSH signing-key ID")
            if key_id in seen_ssh_ids:
                raise InvalidEvidence("GHES returned duplicate SSH signing-key IDs")
            seen_ssh_ids.add(key_id)
            algorithm, public_key = _parse_ssh_key(record.get("key"))
            created_at = record.get("created_at")
            _iso_datetime(created_at, "SSH signing-key creation time")
            ssh_keys.append(SSHSigningKey(key_id, public_key, algorithm, created_at))

        gpg_records = self._pages("/user/gpg_keys")
        gpg_keys = tuple(_parse_gpg_key(record) for record in gpg_records)
        gpg_ids = [key.key_id.lower() for key in gpg_keys]
        if len(set(gpg_ids)) != len(gpg_ids):
            raise InvalidEvidence("GHES returned duplicate OpenPGP key IDs")

        return IdentityEvidence(
            host=self.host,
            user_id=user_id,
            login=login,
            repository_id=repository_id,
            owner=owner,
            repository=repository,
            permission=permission,
            ssh_signing_keys=tuple(ssh_keys),
            gpg_signing_keys=gpg_keys,
        )


def binding_payload(challenge: BindingChallenge) -> bytes:
    """Create the documented UTF-8 JSON representation for a proof challenge."""
    _validate_challenge(challenge)
    return json.dumps(
        {
            "device_key": challenge.device_key,
            "host": _origin(challenge.host),
            "nonce": challenge.nonce,
            "project": challenge.project,
            "purpose": PROOF_PURPOSE,
            "repository_id": challenge.repository_id,
            "user_id": challenge.user_id,
            "version": 1,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _validate_challenge(challenge: BindingChallenge) -> None:
    if not isinstance(challenge, BindingChallenge):
        raise InvalidProof("A typed device-binding challenge is required")
    _origin(challenge.host)
    _positive_id(challenge.user_id, "expected user ID")
    _positive_id(challenge.repository_id, "expected repository ID")
    if not isinstance(challenge.nonce, str) or not re.fullmatch(
        r"[0-9A-Fa-f]{32,256}", challenge.nonce
    ):
        raise InvalidProof("Challenge nonce must contain at least 128 bits of hex")
    for value, label, maximum in (
        (challenge.project, "project", 512),
        (challenge.device_key, "device key", 8192),
    ):
        if (
            not isinstance(value, str)
            or not value
            or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise InvalidProof(f"Invalid challenge {label}")


def _check_payload(payload: bytes, challenge: BindingChallenge) -> None:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_PROOF_BYTES:
        raise InvalidProof("Proof payload is empty or oversized")
    value = _strict_json(payload, source="proof payload")
    expected = {
        "device_key": challenge.device_key,
        "host": _origin(challenge.host),
        "nonce": challenge.nonce,
        "project": challenge.project,
        "purpose": PROOF_PURPOSE,
        "repository_id": challenge.repository_id,
        "user_id": challenge.user_id,
        "version": 1,
    }
    if not isinstance(value, dict) or value != expected:
        raise InvalidProof("Proof payload does not match the device-binding challenge")


def _ssh_verify(key: SSHSigningKey, proof: BindingProof, identity: IdentityEvidence) -> None:
    ssh_keygen = _tool("ssh-keygen")
    with tempfile.TemporaryDirectory(prefix="agent-yhes-ghes-ssh-") as directory:
        os.chmod(directory, 0o700)
        allowed_signers = os.path.join(directory, "allowed_signers")
        signature_path = os.path.join(directory, "signature")
        principal = f"agent-yhes-{hashlib.sha256(identity.host.encode()).hexdigest()[:16]}-{identity.user_id}"
        with open(allowed_signers, "w", encoding="ascii") as file:
            os.chmod(allowed_signers, 0o600)
            file.write(f"{principal} {key.public_key}\n")
        with open(signature_path, "wb") as file:
            os.chmod(signature_path, 0o600)
            file.write(proof.signature)
        verified = _run(
            [
                ssh_keygen,
                "-Y",
                "verify",
                "-f",
                allowed_signers,
                "-I",
                principal,
                "-n",
                SSH_NAMESPACE,
                "-s",
                signature_path,
            ],
            input_bytes=proof.payload,
            env={"PATH": os.defpath, "LC_ALL": "C", "HOME": directory},
            error="SSH proof verification tool failed",
        )
        if verified.returncode != 0:
            raise InvalidProof("SSH device-binding signature did not verify")


def _gpg_verify(key: GPGSigningKey, proof: BindingProof) -> None:
    gpg = _tool("gpg")
    gpgv = _tool("gpgv")
    try:
        with tempfile.TemporaryDirectory(prefix="agent-yhes-ghes-gpgv-") as directory:
            os.chmod(directory, 0o700)
            home = os.path.join(directory, "home")
            os.mkdir(home, 0o700)
            raw_path = os.path.join(directory, "public.asc")
            payload_path = os.path.join(directory, "payload")
            signature_path = os.path.join(directory, "signature")
            keyring_path = os.path.join(directory, "keyring.gpg")
            for path, data in (
                (raw_path, key.raw_key.encode("utf-8")),
                (payload_path, proof.payload),
                (signature_path, proof.signature),
            ):
                with open(path, "wb") as file:
                    os.chmod(path, 0o600)
                    file.write(data)
            base = [
                gpg,
                "--batch",
                "--no-options",
                "--no-tty",
                "--no-autostart",
                "--homedir",
                home,
            ]
            imported = _run(base + ["--import", raw_path], error="OpenPGP proof verifier failed")
            if imported.returncode != 0:
                raise InvalidProof("OpenPGP public key could not be imported")
            secrets = _run(
                base + ["--with-colons", "--list-secret-keys"],
                error="OpenPGP proof verifier failed",
            )
            if secrets.returncode != 0 or any(
                line.split(":", 1)[0].startswith(("sec", "ssb"))
                for line in secrets.stdout.decode("utf-8", "strict").splitlines()
            ):
                raise InvalidProof("OpenPGP keyring unexpectedly contains private key material")
            exported = _run(
                base + ["--output", keyring_path, "--export"],
                error="OpenPGP proof verifier failed",
            )
            if exported.returncode != 0 or not os.path.exists(keyring_path):
                raise InvalidProof("OpenPGP public key could not be exported to the isolated keyring")
            verified = _run(
                [
                    gpgv,
                    "--homedir",
                    home,
                    "--keyring",
                    keyring_path,
                    "--status-fd",
                    "1",
                    signature_path,
                    payload_path,
                ],
                env={"PATH": os.defpath, "LC_ALL": "C", "HOME": directory},
                error="OpenPGP proof verification tool failed",
            )
            if verified.returncode != 0:
                raise InvalidProof("OpenPGP device-binding signature did not verify")
            status_lines = verified.stdout.decode("utf-8", "replace").splitlines()
            valid = [line.split() for line in status_lines if line.startswith("[GNUPG:] VALIDSIG ")]
            if len(valid) != 1 or len(valid[0]) < 11:
                raise InvalidProof("OpenPGP verifier did not identify one valid signing key")
            fields = valid[0]
            fingerprint = fields[2].upper()
            if fingerprint not in key.signing_fingerprints:
                raise InvalidProof("OpenPGP signature used a key not marked for signing by GHES")
            if fields[9] not in {"8", "9", "10", "11"}:
                raise InvalidProof("OpenPGP signature uses a weak or unsupported digest")
    except UnicodeDecodeError:
        raise InvalidProof("OpenPGP verifier returned malformed status data") from None


def verify_binding_proof(
    evidence: IdentityEvidence,
    challenge: BindingChallenge,
    proof: BindingProof,
) -> None:
    """Verify exact signed bytes and all scope bindings; return only on success.

    A successful forge proof is enrollment evidence only. It does not grant
    authority to update the project registry.
    """
    _validate_challenge(challenge)
    if not isinstance(evidence, IdentityEvidence) or not isinstance(proof, BindingProof):
        raise InvalidProof("Typed identity evidence and proof are required")
    if not isinstance(proof.profile, str) or not isinstance(proof.key_id, str):
        raise InvalidProof("Proof profile and key identifier must be strings")
    if (
        _origin(evidence.host) != _origin(challenge.host)
        or evidence.user_id != challenge.user_id
        or evidence.repository_id != challenge.repository_id
    ):
        raise InvalidProof("Challenge scope does not match fetched GHES identity evidence")
    if evidence.permission not in {"write", "maintain", "admin"}:
        raise InvalidProof("Fetched GHES permission is insufficient")
    if not isinstance(proof.signature, bytes) or not 1 <= len(proof.signature) <= MAX_SIGNATURE_BYTES:
        raise InvalidProof("Proof signature is empty or oversized")
    _check_payload(proof.payload, challenge)

    if proof.profile in {"ssh-ed25519", "ssh-ecdsa-p256"}:
        matching = [key for key in evidence.ssh_signing_keys if str(key.key_id) == proof.key_id]
        if len(matching) != 1 or matching[0].algorithm != proof.profile:
            raise InvalidProof("Proof does not identify a current supported SSH signing key")
        _ssh_verify(matching[0], proof, evidence)
        return
    if proof.profile == "openpgp":
        matching_gpg = [
            key
            for key in evidence.gpg_signing_keys
            if proof.key_id.upper() in key.signing_fingerprints
        ]
        if len(matching_gpg) != 1:
            raise InvalidProof("Proof does not identify a current signing-capable OpenPGP key")
        _gpg_verify(matching_gpg[0], proof)
        return
    raise InvalidProof("Unsupported device-binding proof profile")
