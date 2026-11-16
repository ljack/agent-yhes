# E2EE implementation probes

These are disposable-key evaluation programs, separate from agent-yhes runtime
code. They exercise library APIs using in-memory participants and emit JSON
observations. They use no real user keys, GHES credentials, Touch ID prompts or
network messaging service. Dependencies are pinned by package manifests and locks.

Read the [evaluation and recommendation](../../docs/E2EE-EVALUATION.md) before
interpreting [results.json](results.json).

The [follow-up transaction experiment](atomic/README.md) adds disk-backed state,
real process termination, Git membership races and the native SQLite provider.

## Reproduce

Rust 1.91+ is required by the pinned OpenMLS crates. The mls-rs probe also needs
OpenSSL development libraries discoverable by `pkg-config`. The recorded run used
Rust 1.92.0, Node 26.13.0, OpenSSL 3.6.4 and macOS arm64.

```sh
CARGO_BUILD_JOBS=4 cargo run --locked --manifest-path evaluations/e2ee/rust/Cargo.toml --bin openmls-probe
CARGO_BUILD_JOBS=4 cargo run --locked --manifest-path evaluations/e2ee/rust/Cargo.toml --bin mlsrs-probe
```

For Signal, use an isolated copy if you want to keep native dependencies outside
the checkout. From `evaluations/e2ee/signal` or a copy of that directory:

```sh
npm ci --ignore-scripts --no-audit --no-fund
node probe.mjs
```

The official npm package includes a native macOS binary. Its API and license
belong to Signal; the package is not bundled in this repository.

## What the results mean

The programs assert basic encryption, outsider rejection, replay rejection,
out-of-order delivery, joining, removal and continued delivery. They separately
record state mutation after failed validation. A successful program exit can
therefore include `false` for a safety property: it means the observation was
recorded, not that the candidate passed every acceptance criterion.

The MLS programs exercise both RFC suites 1 (X25519/Ed25519) and 2 (P-256).
The mls-rs program uses its OpenSSL provider, not its CryptoKit bridge. All MLS
credentials are deliberately unverified basic labels. The group reload tests
reload objects from in-memory provider storage, not an encrypted production
database or a restarted process.

The Signal program exercises the sender-key group primitive. It delivers secret
distribution packets directly in memory as a trusted fixture. Real applications
must deliver those packets through authenticated, confidential pairwise sessions.
This is not a test of PQXDH, Double/Triple Ratchet, Signal's full group service or
the Signal application. The removal test deliberately distinguishes changing an
application membership list from actually replacing and redistributing keys.

No secret state is printed or written into results.json. The checkpoint copies
used to investigate failures exist only in process memory. Restoring an old
checkpoint after successful encryption is not a safe retry strategy: persist
the resulting state and exact ciphertext before transport, then retry that same
ciphertext if delivery is uncertain.
