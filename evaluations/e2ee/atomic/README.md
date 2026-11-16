# OpenMLS transaction and Git-ordering experiment

This follow-up tests the failure boundaries identified by the
[implementation comparison](../../../docs/E2EE-EVALUATION.md).
See [the implementation plan](../../../docs/SECURE-IMPLEMENTATION-PLAN.md) for
the resulting decisions and [results.json](results.json) for the recorded checks.

Run from the repository root:

```sh
python3 evaluations/e2ee/atomic/run_all.py
```

It builds the two pinned Rust experiment binaries, runs the fixtures, and
regenerates results.json with source hashes. Requirements match the earlier
evaluation: Python 3, Git, Rust 1.91+ and the existing Rust package's OpenSSL
dependency. Build concurrency is limited to four jobs.

## What actually runs

- An OpenMLS 0.9.2 worker performs each operation against a private working copy
  of its storage. A Python adapter commits the resulting state together with
  outbox/inbox data using SQLite `BEGIN IMMEDIATE`, WAL and `synchronous=FULL`.
- Independent adapter processes are stopped with **SIGKILL** before SQLite commit,
  after commit, and after a Git push but before its local acknowledgment.
- Separate private Git mirrors race real fast-forward pushes to a disposable
  bare remote. One membership change wins, the other is discarded and rebuilt
  after the winning epoch has been consumed.
- Four independent databases converge to the same epoch, membership count and
  hash of a fixture-only exporter value. Messaging then continues.
- A deliberately restored old database is compared with accepted own operations
  in Git. The detected missing send puts that client into recovery.
- A separate native Rust probe uses `openmls_sqlite_storage 0.3.0` directly.
  It shares one connection/transaction between OpenMLS tables and application
  outbox/inbox tables, including rollback of a rejected Welcome.

Both RFC suite 1 (X25519/Ed25519) and suite 2 (P-256) are exercised. The process/Git
fixture has 18 checks per suite; the native provider has six per suite.

## Boundaries of the experiment

All keys and identities are disposable fixtures. The temporary SQLite databases
contain plaintext fixture secrets and are removed when the run ends. The worker's
private IPC response contains secret state: **run it only through this harness**,
which captures that output. Production must keep private state inside the trusted
native service and protect it at rest.

Git contains ciphertext and explicit public metadata. The fixture checks blob
objects in the remote and local mirrors, including unreachable objects, for its
plaintext marker and private-state fields. Private request hashes stay in the
local database. This is a concrete leakage check, not a general data-flow proof.

The Git coordinator trusts its fixture participants. It does not implement GHES
identity verification, signed membership authorization, a human signing device or
hardware attestation. Those are implementation requirements. Restoring a backup
is tested only in the case where it loses an operation already accepted in Git;
this is not complete offline rollback detection.

The tests cover process termination, not actual power loss, filesystem failure,
secure key erasure or privileged host compromise. The private-state snapshot
adapter and its fault-injection environment variable are experiment code, not
production entry points. No source checkout, existing Git branch, live broker,
real user key, commit or tag is changed by the experiment.
