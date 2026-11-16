# Test runbook

Use this runbook for the secure implementation slice introduced on 2026-11-14.
For a personal trial with your own messages, start with [LOCAL-PILOT.md](LOCAL-PILOT.md).
This runbook covers developer checks and the inert preview. The signed local
client has passed human acceptance. The new [team CLI](TEAM-PILOT.md) has passed
disposable Git/NATS tests; hosted GHES and physical two-Mac acceptance remain pending.

Run commands from the repository root containing `secure/Cargo.toml` and
`native/YhesSigner/scripts/test.sh`. These files are included from v0.3.0 onward.
The native signer is built locally; signed app bundles are not included in Git.

## 1. Check the environment

The native package targets macOS 14 or newer and Swift 6. The Rust workspace
declares Rust 1.91; the verified toolchain for the current locked dependencies is
Rust/Cargo 1.92.0. Use the recorded toolchain when reproducing this baseline.
Python, Git, `ssh-keygen`, `gpg`, `gpgv` and `gpgconf` are also needed for full
fixture coverage. Neither a GHES token nor a broker is needed for the secure suite.

```sh
sw_vers -productVersion
uname -m
rustc --version
cargo --version
swift --version
xcode-select -p
python3 --version
git --version
command -v ssh-keygen gpg gpgv gpgconf
```

The development Mac currently has Rust/Cargo 1.92.0, Swift 6.4.2, Python 3.14.3
and Git 2.53.0, with all four signing-proof tools available. Dependency downloads
may occur on a first build. Keep `--locked`; do not update dependencies to resolve
a test failure without recording that change.

## 2. Run the complete automated suite

Paste this block from the repository root. It stops at the first failed command
and preserves each command's exit status while saving its output. The printed
temporary directory contains the logs.

```sh
bash <<'SH'
set -euo pipefail
test -f secure/Cargo.toml
test -f native/YhesSigner/scripts/test.sh
yhes_test_logs=$(mktemp -d "${TMPDIR:-/tmp}/agent-yhes-tests.XXXXXX")
printf 'Test logs: %s\n' "$yhes_test_logs"

cargo test --manifest-path secure/Cargo.toml --workspace --locked \
  2>&1 | tee "$yhes_test_logs/rust-tests.log"

cargo clippy --manifest-path secure/Cargo.toml --workspace --all-targets --locked -- -D warnings \
  2>&1 | tee "$yhes_test_logs/clippy.log"

native/YhesSigner/scripts/test.sh \
  2>&1 | tee "$yhes_test_logs/native-tests.log"

python3 -m unittest discover -s secure/identity -v \
  2>&1 | tee "$yhes_test_logs/ghes-tests.log"

native/YhesSigner/scripts/build-app.sh \
  2>&1 | tee "$yhes_test_logs/native-build.log"

printf 'All commands completed. Check test counts and skips in %s\n' "$yhes_test_logs"
SH
```

Expected results for this snapshot:

| Step | Pass condition |
| --- | --- |
| Rust workspace | All workspace test binaries pass, including the CLI and local transport. Current counts are recorded in VALIDATION.md. Zero-test library/doc-test binaries are normal. |
| Clippy | Exit 0 with warnings denied. |
| Native tests | All Swift tests and three Rust bridge tests pass. The bridge tests repeat tests already counted in the Rust workspace. |
| GHES fixtures | Eight tests pass, with no skips. Missing SSH/GPG tools can produce a successful exit with skipped coverage; record that as incomplete. |
| Native preview build | Exit 0, `Info.plist: OK`, and a bundle at `native/YhesSigner/build/Preview/YhesSigner.app`. It does not replace a signed build. |

These tests use disposable software identities, temporary databases and fake HTTP
responses. No real human key is enrolled and no Touch ID or real Keychain operation
is expected. The crash test deliberately kills its own child processes with
SIGKILL; the parent test must still pass. The app build does not launch or install
the app. Temporary database fixtures are cleaned by the tests; build caches and
the app bundle remain under the ignored build directories.

## 3. Inspect the collaboration and failure cases

Run the combined engine scenarios separately:

```sh
cargo test --manifest-path secure/Cargo.toml -p yhes-core --locked --lib engine::tests
```

These use separate vaults and signed fixture messages. They do not launch Codex,
Claude or another model. Each attack case passes when the operation is rejected
and the expected valid work still succeeds.

| Test name under `engine::tests::` | What to look for |
| --- | --- |
| `signed_human_relay_survives_encryption_retry_and_restart` | Agent authorship and the original human author stay distinct; retry returns identical ciphertext; reopening the receiver retrieves its durable result. |
| `membership_add_remove_fences_old_packets_and_removed_member` | Both other members receive a three-party message; pending membership blocks sends; old-audience packets are refused; a removed member cannot receive new-epoch traffic. |
| `tampering_unauthorized_join_scope_and_revocation_are_rejected` | Tampering and forged human roles are rejected; a nonmember cannot receive; revoked senders and registry rollback are refused. |
| `authenticated_forged_inner_content_is_quarantined_and_ratchet_progress_survives` | Valid MLS ciphertext with a bad inner signature or conflicting event ID is quarantined; later valid messages still work. |
| `action_expiry_reuse_and_unapproved_welcome_do_not_change_membership` | Expired approvals and wrong-owner invitations fail; the correct invitation remains usable. |
| `rejected_pending_change_keeps_epoch_and_requires_a_new_authorization` | Definitive rejection clears the pending attempt; reusing its approval fails; a fresh approved attempt succeeds. |
| `bootstrap_needs_pinned_head_and_can_replay_expired_historical_registry` | Bootstrap requires the independently approved current head; expired historical chain entries can lead to a current valid head. |
| `both_joiner_and_existing_member_refuse_a_different_package_for_the_same_agent` | Swapping the approved KeyPackage for another package under the same signing key fails at both receivers. |

To run just one scenario, give its full test path and use `--exact`. For example:

```sh
cargo test --manifest-path secure/Cargo.toml -p yhes-core --locked --lib \
  engine::tests::signed_human_relay_survives_encryption_retry_and_restart -- --exact
```

Expect **one** test to run. A misspelled filter can exit successfully with zero
matching tests; that does not exercise the scenario.

Run the real process-interruption case:

```sh
cargo test --manifest-path secure/Cargo.toml -p yhes-core --locked --lib \
  store::process_tests::real_process_kill_before_and_after_commit -- --exact
```

Expected: one parent test passes. It runs both kill points. Before commit, MLS
sender state, outbox and application changes roll back together. After commit,
they survive together and the checkpoint can be repaired on reopen.

Check that a backdated timestamp cannot revive an expired agent delegation:

```sh
cargo test --manifest-path secure/Cargo.toml -p yhes-wire --locked --test verifier \
  backdating_cannot_revive_an_expired_agent_delegation -- --exact
```

Expected: one test passes by refusing the expired grant. The full wire suite also
covers an expired human-session grant. Previously accepted inbox records remain
available as history; they do not gain renewed authority.

## 4. Preview the native review UI

After the build step, launch the development bundle:

```sh
open -n native/YhesSigner/build/Preview/YhesSigner.app
```

Perform these checks manually and record the result; the automated suite does
not establish live layout, keyboard or VoiceOver behavior.

1. Choose **Open event…** and select
   `native/YhesSigner/Tests/YhesSignerCoreTests/Fixtures/p256-statement-payload.json`.
   Expect an agent-prepared, unapproved draft with the author, project, recipients,
   exact payload and digest visible. Select the payload file, not its signed envelope.
2. Choose **Open registry…** and select
   `native/YhesSigner/Tests/YhesSignerCoreTests/Fixtures/p256-registry-payload.json`.
   Expect the registry review mode, full registry contents and a new unapproved
   request. Its named action becomes available after one second in the active
   review window; Return must not approve it.
3. Check resizing, scrolling, text selection, keyboard navigation and readability.
   Opening another document or changing modes must not preserve an earlier approval.
4. Choose **Load device identity**. In this preview build, expect a refusal
   because its application signature is not trusted. No biometric
   prompt or Keychain access should occur. Approval remains unavailable without
   a loaded identity. This is the expected development-build result.
5. Quit the app with Command-Q.

The fixtures use a known public test key and fixed timestamps. They are for review
and interoperability, not signing with a real identity. Do not adjust the system
clock or remove the signing-identity checks to make them signable.

## 5. Optional: exercise the existing Git and broker transports

These demos use the earlier trusted-participant record format. They exercise real
transport with scripted participants; they do not prove the secure core is wired
to Git or NATS.

```sh
python3 examples/remote_demo.py --tcp
```

Expected: the loopback Git workflow finishes its ticket and reports its temporary
directory. It uses separate clones and stops its temporary Git server on exit.

For the broker demo, provide `nats-server` on PATH or set `YHES_NATS_SERVER` to the
absolute path of an installed server binary. On the development Mac it is currently
not on PATH. See [broker setup](BROKER.md) for the separately tested server profile.

```sh
uv run --with nats-py==2.16.0 python3 examples/realtime_demo.py
```

Expected JSON includes `question_received_live: true`, `reply_received_live: true`,
`ticket_status: "done"` and `server: "stopped on exit"`. Both demos leave their
printed temporary directories for inspection; remove only those directories when
finished. They do not push to the project's real Git remote.

## 6. Live-device and cross-computer acceptance: next stage

The signed local client now has dedicated provisioning, a hardened app/helper,
an authenticated approval socket and an enrollment path. Follow the pilot guide
for its local trial. Cross-computer acceptance still needs secure network transport,
additional process-containment review and the historical-membership timing protocol.
The library's receipt callbacks must be connected to verified authoritative Git
acceptance, not invoked manually to simulate a successful remote operation.

Use dedicated test identities and a test project when that build is ready:

| Trial | Expected result |
| --- | --- |
| Device setup | Human explicitly creates a Touch ID-protected key; only its public descriptor is exported. The native signer and core use distinct keys. |
| One statement | Exact current draft is reviewed; successful Touch ID produces an envelope accepted under the enrolled public key. Cancellation produces none. |
| Fixed statement batch | One frozen reviewed list uses one fresh authentication context; count actual OS prompts. No later payload can join the batch and no partial result is exported on failure. |
| Major boundary | A recipient change or registry edit requires its own exact review and fresh authentication. A previous batch cannot authorize it. |
| Invalidation | Lock, user switching, sleep, changed review data and expiry cancel the pending approval. A focus change resets the guard for starting an attempt but preserves an already frozen attempt. Verify that the OS Touch ID sheet can complete without app-caused cancellation, and that stale results cannot reach another request. |
| GHES 3.21.9 proof | Use the configured HTTPS instance, immutable user/repository IDs, current permission and a fresh device-binding nonce. Correct SSH signing/OpenPGP proof succeeds; changed scope, missing permission or unavailable evidence fails. |
| Real harness exchange | Two harnesses on separate computers claim work, exchange a verified question/reply, preserve human provenance and save the result through the secure transport. |
| Reconnect and removal | Broker outage preserves Git-backed work; exact retries do not duplicate effects; removed recipients cannot read subsequent epochs. |

Historical membership admission remains a release gate: a previously unseen change
whose five-minute authorization expired is currently refused. Do not treat the
sender's issue time or a Git commit timestamp as proof of timely acceptance.

The detailed prerequisites are in [the secure guide](../secure/README.md),
[native signer notes](MACOS-SIGNER.md), [key custody](KEY-CUSTODY.md), and
[GHES adapter API](../secure/identity/README.md).

## 7. Record the outcome

For each run, record the date, checkout commit plus whether it is dirty, toolchain
versions, commands, exit statuses, test counts/skips and log directory. Mark each
manual case **passed**, **failed**, or **not run**, with observed behavior. Include
only test data in any screenshots or exported examples.

If a command fails, retain its first error and log; rerun that command or the exact
failing test after resolving the cause. A missing Rust static archive means the
native validator was not built: use `scripts/test.sh` or `scripts/build-app.sh`,
which build it automatically. Missing SSH/GPG tools mean proof coverage is incomplete.
The inert preview's key-operation refusal is expected and is not a reason to
weaken authentication checks.

Current executed counts, signed-build evidence and live-device status are in
[VALIDATION.md](VALIDATION.md). Automated tests and an authenticated socket are
separate from the human completing real Touch ID enrollment and approval.

## Secure team network checks

For the new two-person flow, follow [TEAM-PILOT.md](TEAM-PILOT.md). The automated
network suite uses disposable human keys and independent private stores; it never
requests Touch ID or writes to a configured real project remote.

```sh
CARGO_BUILD_JOBS=4 cargo test --manifest-path secure/Cargo.toml -p yhes-core --test secure_git --locked -- --test-threads=1
CARGO_BUILD_JOBS=4 cargo test --manifest-path secure/Cargo.toml -p yhes-cli --test team_flow --locked -- --test-threads=1
YHES_NATS_SERVER=/absolute/path/to/nats-server CARGO_BUILD_JOBS=4 \
  cargo test --manifest-path secure/Cargo.toml -p yhes-cli --test realtime_git --locked -- --ignored --test-threads=1
```

Use the tested NATS Server 2.15.3 and have `openssl` available for the disposable
TLS fixture. The two realtime tests are explicitly ignored in the default suite;
the final command must run them to establish broker/TLS coverage. Expect real
Git/NATS question delivery, human-relay provenance, restart/outage recovery,
wrong-CA/hostname rejection, and refusal to admit broker-only ciphertext.
Run Git-heavy suites serially to avoid confusing process-load timeouts with
protocol failures. The [validation record](VALIDATION.md) lists observed results
and the remaining real-device/GHES checks.
