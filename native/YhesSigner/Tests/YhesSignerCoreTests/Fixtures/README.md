# Disposable interoperability vector

Known TEST scalar 1 on P-256; never an enrolled identity. Generated with Python
cryptography 46.0.6 deterministic ECDSA SHA-256 and independently consumed by
CryptoKit tests. Exact UTF-8 payload has indentation, non-ASCII text and a final
newline. The two envelopes differ only in low-S versus high-S signatures.

Use verifier time 2000000000, project demo, human author alice, audience alice/bob.
Public key is uncompressed SEC1 hex in p256-public-key.hex. No registry trust is
implied. Payload type length is 40 bytes.

Key ID: k_d7d81e4c7d2741c41372571a108b9ea094cdbb5e50712102211e4cbe48875606
Event digest: 5a3e2176261fdf0fa6df145dda99e9fdb8b04d32b91023b5ff06f52e7f67172b

The registry pair uses the same known test key as an externally pinned authority,
project demo, generation 1, no predecessor, verifier time 2000000000. Its DSSE
payload type is application/vnd.agent-yhes.registry.v1+json (43 bytes).
Registry payload digest: f5315fa464d2f00dfcd858697eb8ccb6d5e5af92558ac025a85f881b5a7d8565
