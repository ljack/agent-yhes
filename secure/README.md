# Secure core implementation

The first implementation of the [secure plan](../docs/SECURE-IMPLEMENTATION-PLAN.md)
is here: signed identities and actions, an encrypted transactional MLS core, a
native macOS human signer, and GHES enrollment-proof verification.

The [usable local pilot](../docs/LOCAL-PILOT.md) now connects this core to a signed
CLI and native approval app. It supports two persistent local profiles, your own
agent messages and human-signed relays, a sealed append-only log and restart.
The [team CLI pilot](../docs/TEAM-PILOT.md) adds two-person enrollment through Git
and NATS-triggered delivery of Git-confirmed encrypted messages. Its independent
client tests use disposable identities; hosted GHES and two-Mac acceptance remain
pending. The Python helpers still use the earlier record format. Secure ticket
execution remains separate work; no release has been tagged.

## Try the acceptance tests

Use the [test runbook](../docs/TEST-RUNBOOK.md) for a complete sequence, saved logs,
expected results, focused recovery tests and the native UI preview.

On the development Mac, with Rust/Cargo, Swift and Python installed:

```sh
cargo test --manifest-path secure/Cargo.toml --workspace --locked
native/YhesSigner/scripts/test.sh
python3 -m unittest discover -s secure/identity -v
```

These use disposable software keys and injected identity evidence. They make no
real Keychain or Touch ID calls and do not contact a GHES installation. The
native script builds the Rust public-key validator before linking the Swift tests.

The combined workflow is in
[`engine_tests.rs`](crates/yhes-core/src/engine_tests.rs): two independently
stored agents, controlled by different human identities, join an authorized
group; an agent preserves and relays a signed human decision; a third recipient
joins; messages reach both recipients; removal excludes a member from subsequent
epochs. Restart tests retrieve the exact outbox packet and durable inbox result.
The scripted messages represent protocol fixtures, not conversations between models.

## Components

| Component | Responsibility |
| --- | --- |
| [yhes-wire](crates/yhes-wire/API.md) | Strict DSSE parsing; Ed25519/P-256 signatures; signed registry chains, roles, grants and human originals. No private keys or I/O. |
| [yhes-actions](crates/yhes-actions/API.md) | Exact typed action request, its digest, scope and current human authorization. |
| [yhes-core](crates/yhes-core/API.md) | Private agent key, OpenMLS, SQLCipher, atomic outbox/inbox, replay records and external checkpoints. |
| [yhes-cli](crates/yhes-cli/API.md) | Setup, send, human-signed statements, inbox, sync and status through the signed engine helper. |
| [GHES evidence](identity/README.md) | GHES 3.21.9 immutable IDs, current repository permission and SSH/OpenPGP device-binding proofs. |
| [Native signer](../native/YhesSigner/API.md) | Review exact statements, action requests or registry changes; sign with a Secure Enclave P-256 key after Touch ID. |

Project-authority keys and the initial registry-head digest are approved outside
the repository being authenticated. Bootstrap verifies the complete chain from
generation one, including expired historical generations, and requires the head
to be current and match that approved digest. Later updates cannot drop a
revocation, skip a generation or replace an accepted generation.

The first MLS profile fixes suite 1: X25519, AES-128-GCM, SHA-256 and Ed25519.
Agents have their own enrolled Ed25519 working keys. Human Secure Enclave P-256
keys remain in the signer and do not enter MLS storage. The registry derives
human, agent and service roles; a sender cannot choose a role in message text.
A relay remains agent-authored and exposes the separately verified human original.
Signatures establish provenance and scope; prose does not grant new permissions.

## Human confirmation

A fixed batch of up to 16 exact, reviewed statements can share one fresh Touch ID
confirmation. The list is frozen before authentication. A batch cannot contain
registry edits, delegations or group changes. Those require their own review and
fresh confirmation. Delegated routine agent messages do not prompt the human.
The exact reviewed agent delegation can last up to the wire profile's seven-day
cap; this grants no human-signing authority. New event admission requires its
grant to remain current. A sender's backdated timestamp cannot extend that grant.

The earlier timed human-signing-window proposal is disabled. Same-user UI
automation cannot reliably establish that a later Send click came from the human.
The fixed batch reduces prompts without leaving an open signing endpoint.

The locally signed build uses dedicated app identities and separate Keychain groups.
[Building with `--signed`](../docs/MACOS-SIGNER.md) provisions and verifies those
identities; the default build remains an inert preview. Real enrollment happens
only after the human reviews the native request and uses Touch ID.

## Storage and retry

OpenMLS provider writes, outgoing ciphertext, incoming results, replay IDs and
consumed authorizations share one SQLCipher transaction. Outgoing retries return
the saved ciphertext. A changed request cannot reuse its operation ID. An MLS
cryptographic failure rolls back; valid ciphertext with invalid inner application
policy advances receive state into quarantine and exposes no trusted content.

A MAC covers logical database state and a revision. Its checkpoint lives outside
the database in the protected Data Protection Keychain. One authenticated bridge
repairs a crash between database commit and checkpoint publication. Restored,
cloned or moved vaults and missing checkpoints require recovery. An interruption
before the first checkpoint is published is also quarantined: automatically
accepting that file could resurrect a deleted checkpoint and an old initial state.
`CheckpointPending` means the operation committed locally: reopen the vault and
retry its original identity, rather than assuming it rolled back.

The store checks private modes, ownership, symlinks, hard links and a stable
per-vault lock; its authenticated metadata binds the absolute vault path.
Atomic add-only Keychain revision slots prevent two restored/swapped vault copies
from both publishing a different next checkpoint. Ordinary path checks still do
not isolate arbitrary hostile programs running as the same user. The pilot grants
local user programs access to its approved agent profiles; it does not attest
which harness process authored a request.
The full-state MAC scan is intentionally simple and intended for small trials.

## Gates before a secure v0.3 release

- Complete hosted, two-Mac acceptance of the new Git/NATS team CLI. Its Git
  adapter reads back exact sealed records and checks protected history before
  acknowledgment. NATS wakes receivers after Git publication; broker-only
  acceptance remains unsupported. A PUBACK or Git author string does not
  substitute for verified authoritative acceptance.
- Define and implement independently verifiable acceptance-time evidence for
  historical membership changes. Today a previously unseen change with an expired
  five-minute authorization is refused, including after a long offline interval.
  Sender-controlled commit timestamps cannot fix this. Stored accepted history
  and exact inbox retries remain available.
- Integrate ticket ownership/revision checks and verified recovery evidence in
  the protected transaction. The action verifier exists; it is not a secure ticket
  executor, and message text never runs ticket actions.
- Decide the group-governance extension. This first core restricts membership
  changes to the founding agent, under its human controller's fresh approval.
  Owner handover and owner-key recovery need an explicit protocol.
- Complete process/filesystem containment and platform Keychain/Touch ID tests
  with a signed build; enroll real devices; exercise GHES commit policy and a
  cross-computer trial. Non-macOS key custodians remain future profiles.

These gates are recorded work, not switches that loosen verification. The older
helpers remain useful for trusted-participant experiments while this integration
is completed. Commits, tags and publication remain on hold under the existing plan.
