# Changes

## 0.4.0 — interactive tutorial and GitHub Pages, 2026-11-16

- Add two editable example terminals and animated Connect, Message, Human approval
  and Catch up walkthroughs, with object explanations and optional Why details.
- Add responsive playback, light/dark themes and links to the real setup guides.
- Package only the tutorial assets for Pages; bind documentation links and
  build metadata to the deployed source revision.
- Test and deploy the site with GitHub Actions. Keep v0.1.0–v0.4.0 as separate
  tagged stages; see [the release ladder](docs/RELEASES.md).

## 0.3.0 — secure team pilot and realtime delivery, 2026-11-16

- Publish the broker, security and local-pilot work described below as one source
  release, including identity/MLS experiments and their recorded results.
- Add the secure Git handshake and Git-first NATS path, human and agent provenance,
  scoped membership and encrypted history with retry/restart handling.
- Add two-person onboarding, the new-member agent guide, and the disposable
  same-Mac simulator for separate harness workspaces.
- Preserve the device build requirements: the native signer requires local signing
  and provisioning. Signed binaries, profiles and private runtime state are not
  part of the source release. Hosted GHES/two-Mac acceptance remains pending.

## 0.3 local pilot — runnable implementation, 2026-11-14

- Connect `yhes pilot`, `send`, `say`, `inbox`, `sync`, `status` and `doctor` to
  protected agent profiles, native human approval and encrypted local delivery.
- Authenticate both ends of the local signer connection with kernel audit tokens,
  pinned code identities and hardened-runtime checks; return exact approvals to
  the waiting client without manual JSON copying.
- Add local enrollment without inventing GHES account claims, encrypted setup
  checkpoints and an integrity binding for the complete local pin configuration.
- Use add-only Keychain checkpoint slots and avoid advancing them on unchanged reads.
- Add signed/provisioned local packaging and prevent legacy plaintext helpers from
  operating in a secure project. Secure Git/NATS arrived in the team pilot above;
  secure ticket execution remains open.

## 0.3 security work — implementation in progress, 2026-11-14

- Add strict signed identities, registry chains, scoped delegations, human originals
  in agent relays and exact action-sidecar verification.
- Add the Rust/OpenMLS core with SQLCipher, protected checkpoints, atomic outbox/inbox
  and tested crash/retry behavior.
- Add the macOS Secure Enclave signer prototype: exact native review, fixed statement
  batches, fresh authority-change approval and shared Rust public-key validation.
- Add read-only GHES 3.21.9 enrollment evidence through SSH signing and OpenPGP keys.
- Record the remaining secure transport, daemon, ticket execution, historical
  acceptance and live-device gates in [the implementation guide](secure/README.md).

## 0.3 — realtime broker notifications

- Add an optional NATS JetStream layer over the remote Git protocol.
- Publish channel-change hints after confirmed Git operations, with retryable notifications.
- Add durable per-session consumers, reconnect/replay and periodic Git reconciliation.
- Keep transport acknowledgments separate from project message handling.
- Provide authenticated local/TLS server configurations, setup instructions and broker references.
- Add a real-server demonstration and integration tests for delivery, outages, authentication and TLS.

## 0.2.0 — remote Git collaboration

- Add a dedicated coordination branch with isolated per-clone transport state.
- Confirm claims through remote fast-forward updates and revision checks.
- Save operation IDs and results for resolving interrupted or uncertain pushes.
- Add human participants, node-bound sessions and shared handled receipts.
- Support continuation on another computer through an explicit session chain.
- Add a three-clone demo with optional Git networking over loopback TCP.
- Preserve v0.1 local behavior and its existing examples.

## 0.1.0 — local collaboration proposal

- Define `.agents/tickets` and `.agents/messages`, with JSON records and Markdown bodies.
- Add local locking, revision checks, leases, handoffs and durable project memory.
- Provide two harness-independent skills and a scripted Codex–Claude example.
