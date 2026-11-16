# Signal and MLS evaluation for agent-yhes

Evaluated on 2026-11-13. **Recommendation: use MLS for project-group encryption,
with OpenMLS as the first candidate for a constrained integration prototype.**
Keep mls-rs as the alternative. Preserve the separate GHES identity, human/agent
delegation, Touch ID approval and signed application-event layer in either case.

This chooses a protocol direction and a next experiment. At the evaluation date
(2026-11-13), the v0.3 runtime had not yet integrated E2EE or cryptographic author
verification; source releases are listed in [RELEASES.md](RELEASES.md).

## Why MLS fits this project

Our conversations have changing groups of humans, agents and devices. Membership
changes need a consistent order, and removed members must lose access to future
messages. MLS gives these changes an explicit epoch and Commit/Welcome lifecycle.
Git's existing branch arbitration can order those membership events, and NATS
can notify receivers after durable publication. MLS is specified for asynchronous
groups with forward secrecy and post-compromise security. Those properties depend
on correct key/state handling in the application. [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)

Signal provides excellent secure messaging building blocks. Its official library
is primarily for Signal's own products and explicitly says external use is
unsupported. Our sender-key probe also requires the application to manage key
distribution and removal. Integrating Signal would still leave us to build the
project membership and authorization layer. [Pinned libsignal README](https://github.com/signalapp/libsignal/blob/v0.107.0/README.md)

| Candidate | Best fit here | Integration cost or unresolved issue |
| --- | --- | --- |
| **OpenMLS 0.9.2** | Group membership lifecycle and a small external `Signer` interface. | Native Swift bridge and authenticated credential policy are ours; rejected Welcome processing needs atomic storage. |
| **mls-rs 0.57.1** | Custom identity policy, X.509 support, storage interfaces and a UniFFI/Swift route. | The tested provider needs state restoration after a rejected application ciphertext; the existing CryptoKit bridge exports raw private-key bytes. |
| **libsignal 0.107.0** | Pairwise messaging and existing Swift/TypeScript APIs. | External use is unsupported; the tested sender-key primitive leaves group membership/rekey policy to the application. |

The checked metadata identifies OpenMLS as MIT, mls-rs as Apache-2.0 OR MIT, and
libsignal as AGPL-3.0-only. At the time of evaluation the repository license was
open; the repository is now dual-licensed under `MIT OR Apache-2.0`.

## What ran

The [reproducible probes](../evaluations/e2ee/README.md) used actual library
implementations on macOS arm64, with Rust 1.92.0, Node 26.13.0 and OpenSSL 3.6.4.
The OpenMLS provider was `openmls_rust_crypto 0.6.0`; the mls-rs provider was
`mls-rs-crypto-openssl 0.22.0`. Both MLS libraries ran suites 1 and 2 independently.
The Signal probe used the official prebuilt Node package.

| Observable check | OpenMLS | mls-rs / OpenSSL | Signal sender-key primitive |
| --- | --- | --- | --- |
| One message decrypts for multiple recipients | Passed, both suites | Passed, both suites | Passed |
| Outsider rejected | Passed | Passed | Passed |
| Duplicate ciphertext rejected | Passed | Passed | Passed |
| Out-of-order application messages | Passed | Passed | Passed |
| A late joiner cannot decrypt the earlier message | Passed | Passed | Passed with a distribution from the current chain position |
| Removed member cannot decrypt future traffic | Passed after MLS removal | Passed after MLS removal | Passed after application-driven replacement/distribution of sender keys |
| Remaining members continue | Passed | Passed | Passed |
| Reload current state through provider storage | Passed | Passed | Passed through serialized sender-key records |
| Tampered application message does not prevent a subsequent valid retry | Passed | **Failed without checkpoint restoration** | Passed |
| Tampered Welcome does not prevent a subsequent valid join | **Failed without checkpoint restoration** | Passed | Not applicable to this probe |

Full observations, versions and error names are in
[results.json](../evaluations/e2ee/results.json). These are behavioral probes, not
proofs of forward secrecy, post-compromise recovery, cryptographic correctness or
cross-implementation interoperability. No real identity enrollment or hardware
signing was exercised.

## Two concrete state-handling findings

**OpenMLS 0.9.2: rejected Welcome consumes the one-time KeyPackage.** In each
tested suite, the tampered packet failed with `GroupSecrets(DecryptionFailed)`.
Retrying the original valid Welcome then failed with `NoMatchingKeyPackage`.
Restoring the provider's pre-attempt storage made the original Welcome work.
This is consistent with the existing upstream report for 0.9.2; the local probe
uses a tampered packet rather than the report's missing-tree example.
[OpenMLS issue 2316](https://github.com/openmls/openmls/issues/2316)

**mls-rs 0.57.1 / OpenSSL 0.22.0: rejected application ciphertext changes receive
state.** In each tested suite, flipping the final ciphertext byte produced an
AEAD error. The original valid ciphertext then failed with `KeyMissing(1)`.
Reloading the group from a checkpoint written before the failed attempt restored
successful decryption. This is a local integration observation; it needs review
against the library's state-mutation contract before wider use.

Both findings make **transactional state handling a release requirement**. Failed
input must not consume one-time join material or advance committed receive state.
The next adapter must prove this with its actual storage backend, rather than
depending on the in-memory recovery used by these probes.

OpenMLS has a public security policy and published advisories; mls-rs's README
states that it has not received a full third-party security audit. This evaluation
does not establish complete audit coverage for either pinned dependency graph.
[OpenMLS security policy](https://github.com/openmls/openmls/security),
[mls-rs security notice](https://github.com/awslabs/mls-rs#security-notice)

## Signal findings in context

The sender-key experiment worked as expected when the application distributed a
fresh key to the remaining recipients. When we changed the hypothetical member
list without changing the sender key, the removed participant could still read
the next message. This demonstrates the boundary of the primitive, not a failure
of Signal's complete group application.

The test passed distribution packets directly in memory. Such packets contain
secret key material and must not be placed in the public-key registry. Real
Signal integration requires authenticated, confidential distribution and device
session management. MLS KeyPackages are public; Welcomes carry protected join
material. Neither approach removes our need to authenticate the key/identity
binding.

Signal's current specifications include PQXDH and post-quantum ratcheting. Those
were not exercised by this group-primitive probe. The MLS profiles tested here
were classical; OpenMLS also exposes draft PQ feature flags, which were not
enabled. A post-quantum requirement needs a separate profile/interoperability
evaluation before freezing the format.
[Signal specifications](https://signal.org/docs/),
[OpenMLS 0.9.2 features](https://docs.rs/crate/openmls/0.9.2/features)

## Touch ID and enterprise identity

Keep the human Secure Enclave key as the protected root that authorizes signing
sessions and major security decisions. The encryption engine's working state
has a different lifetime and access pattern. Successful P-256 encryption/signing
tests do not demonstrate Secure Enclave storage or biometric enforcement.

OpenMLS exposes a `Signer` trait, so a signer can be supplied independently of
the stock signature-key implementation. That is useful for a later native bridge,
but this evaluation used software keys. The preferred architecture remains a
separate human-signing service and scoped delegation to working/session keys.
[Signer interface](https://docs.rs/openmls_traits/0.6.0/openmls_traits/signatures/trait.Signer.html)

mls-rs has a CryptoKit provider in its source tree. Inspection of its Swift
signature bridge showed `P256.Signing.PrivateKey` with raw representations passed
across the bridge, not `SecureEnclave.P256.Signing.PrivateKey` handles. Its current
CryptoKit provider therefore is not our Touch ID signer. That bridge was source
reviewed, not built in these probes.
[Pinned bridge source](https://github.com/awslabs/mls-rs/blob/c894f45e1c30160e8f608934e1f0f1d6b2cbf95d/mls-rs-crypto-cryptokit/cryptokit-bridge/Sources/cryptokit-bridge/sig.swift)

The probes intentionally used basic labels such as `human-label-only`. Production
identity must come from the GHES 3.21.9 account binding, signed device enrollment,
delegation, current authorization and revocation state. An MLS credential label
does not establish that a human approved a message. Preserve human originals,
agent relay signatures and action-specific approvals inside the encrypted payload.

## Integration rules to carry forward

1. **Audience equals encryption membership.** A `to` field selecting two people
   does not hide a message from other members of its MLS group. Use a dedicated
   group for an approved audience; membership expansion is a human security
   boundary. Validate the selected group against the signed audience before sending.
2. **Keep secrets out of Git.** Git carries public enrollment/KeyPackages,
   ciphertext and suitable signed metadata. Ratchet secrets and private keys
   stay in protected per-device storage. Existing plaintext operation results
   and ticket summaries must be addressed before enabling encrypted mode.
3. **Make local state and the outbox atomic.** Persist generated ciphertext,
   operation ID and advanced sender state together, then retry those exact bytes.
   Never reset sender state to regenerate an uncertain send.
4. **Order MLS membership commits through Git.** Apply the local pending MLS
   commit only after its delivery has been accepted. A losing concurrent change
   must consume the winning epoch and be rebuilt through the library's APIs.
   Broker delivery remains a notification, not a second ordering authority.
5. **Define history access explicitly.** New members get future traffic by default.
   Useful past knowledge can be shared as a newly authorized, signed memory bundle.
   No library can erase plaintext a previous recipient already retained.
6. **Keep verifiable evidence above encryption.** MLS sender authentication does
   not by itself supply our human/agent classification or a portable audit record.
   Signed application events and receipts preserve that evidence across transports.

## Next experiment

The follow-up is complete: the transaction/retry/Git-ordering experiment and a
native upstream SQLite-provider probe passed. See the
[implementation readiness plan](SECURE-IMPLEMENTATION-PLAN.md) and
[reproduction instructions](../evaluations/e2ee/atomic/README.md).
The next work is the secure event/verifier contract and protected native state
service, followed by human/agent/relay provenance and Touch ID integration.

The production runtime, existing version artifacts, commits and tags were not
changed by this evaluation. New files are confined to this report and the
reproducible evaluation directory.
