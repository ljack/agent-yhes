# GHES read-only identity evidence

`ghes.py` is a standard-library Python adapter for collecting current,
read-only identity evidence from a trusted GitHub Enterprise Server 3.21.9
origin. It does not enroll a device, edit a registry, sign as the user, or
persist/cache evidence. The caller supplies the HTTPS origin, a read-scoped
token and the expected immutable GHES user and repository IDs.

## Public API

```python
from secure.identity.ghes import (
    BindingChallenge,
    BindingProof,
    GHESIdentityAdapter,
    binding_payload,
    verify_binding_proof,
)

adapter = GHESIdentityAdapter("https://ghes.example.com", token)
evidence = adapter.read_identity(
    expected_host="https://ghes.example.com",
    expected_user_id=1234,
    owner="team",
    repository="project",
    expected_repository_id=5678,
)

challenge = BindingChallenge(
    host=evidence.host,
    user_id=evidence.user_id,
    repository_id=evidence.repository_id,
    nonce="a1" * 16,  # Caller-supplied 128-bit nonce, represented as hex.
    project="project-id",
    device_key="opaque device public-key representation",
)
payload = binding_payload(challenge)
# Obtain a proof out of band. The adapter never signs with a user's key.
proof = BindingProof(profile="ssh-ed25519", key_id="42",
                     payload=payload, signature=signature_bytes)
verify_binding_proof(evidence, challenge, proof)
```

`read_identity` binds evidence to the exact configured HTTPS origin and checks
the authenticated `/user` ID, repository `/id`, and current permission
(`write`, `maintain` or `admin`). It fetches the authenticated account's SSH
**signing** keys and GPG keys; SSH authentication keys are never consulted.
Pagination, redirects, host changes, missing evidence, unexpected permissions,
malformed records, duplicate JSON names, and unsupported key profiles fail
closed. No successful result is cached. An HTTP transport can be injected for
tests; the default urllib transport has redirects disabled. HTTP, signing and
verification failures are surfaced using sanitized messages, not raw transport
or subprocess output.

Supported SSH proof profiles are `ssh-ed25519` and
`ssh-ecdsa-p256`. SSH verification uses `ssh-keygen -Y verify`, the exact
payload bytes on stdin, and namespace `agent-yhes-enrollment-v1`. OpenPGP
proofs are detached signatures checked by `gpgv` against a temporary isolated
keyring imported from GHES `raw_key`; the signed payload includes the same
purpose string. OpenPGP SHA-1/MD5 signatures, unsupported key algorithms,
expired/revoked keys and keys not marked signing-capable by GHES are rejected.
Temporary key material is public-only and cleaned on return.

The GHES SSH signing-key list schema does not expose separate revocation or
expiration flags. This adapter uses the uncached authenticated current-key list
as the registration/revocation check and accepts only non-certificate
Ed25519/P-256 public keys, which do not carry key expiration metadata.

The GPG REST API's `public_key` value is **not an importable GPG key**: GHES
returns an extracted cryptographic key representation. This adapter requires
the API's ASCII-armored `raw_key`, imports it in an isolated temporary GPG
home, and derives full primary/subkey fingerprints from that material. If
`raw_key` is absent, unusable, or inconsistent with the API key IDs, evidence
is rejected.

## Trust boundary and integration notes

The adapter proves only that the expected GHES account currently holds the
listed signing key and has the reported current repository permission, and
that a proof signed by that key binds the expected host, immutable IDs, nonce,
project and device key. The caller must provide a fresh nonce and must recheck
evidence at the appropriate boundary. A valid forge proof is enrollment
evidence, **not authority to update the registry**: project authority still
requires the separately pinned, verified project/registry authority defined in
the secure team contract. Keep registry approval and persistent replay state in
the secure core; do not infer them from GHES permission or this adapter's
success return.

The token is held only by the adapter instance and sent only as an HTTPS
`Authorization: Bearer` header to the configured origin. Use a token with only
the required read scopes and never include it in diagnostics or result data.
This module intentionally has no token discovery, credential prompting,
logging, cache, signing, enrollment, or write endpoints.

## GHES 3.21 REST references

- [Authenticated user](https://docs.github.com/en/enterprise-server@3.21/rest/users/users#get-the-authenticated-user) — `GET /user`, immutable numeric `id`.
- [Repository permissions for a user](https://docs.github.com/en/enterprise-server@3.21/rest/collaborators/collaborators#get-repository-permissions-for-a-user) — `GET /repos/{owner}/{repo}/collaborators/{username}/permission`.
- [SSH signing keys](https://docs.github.com/en/enterprise-server@3.21/rest/users/ssh-signing-keys) — authenticated user's `GET /user/ssh_signing_keys`, distinct from SSH authentication keys.
- [GPG keys](https://docs.github.com/en/enterprise-server@3.21/rest/users/gpg-keys) — authenticated user's `GET /user/gpg_keys`; document explains why `public_key` cannot be imported by GPG and provides `raw_key`.

The `X-GitHub-Api-Version` request header is pinned to `2022-11-28`, an API
version supported by GHES 3.21.9; it is not a request for the moving cloud API
default. The adapter does not support GitHub.com hosts or non-HTTPS origins.

## Tests

Run from this directory:

```sh
python3 -m unittest -v
```

Tests use a fake HTTP transport only. If installed, `ssh-keygen`, `gpg`,
`gpgv`, and `gpgconf` are used with disposable test keys/homes; the test
fixture kills only the GPG agent associated with its own temporary home.
