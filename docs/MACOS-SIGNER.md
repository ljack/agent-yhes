# Native macOS human signer

`native/YhesSigner` provides an AppKit review app, a strict Swift validation/DSSE
library and an authenticated local socket for the signed `yhes` CLI. The app
guides setup through Identity, Team, Permissions and Channel, showing one immutable
request at a time. Manual file and key tools are in Advanced; full keys and exact
JSON remain available in Details.
The complete [socket and document API](../native/YhesSigner/API.md) defines the
wire format, fixed errors, bounds and approval rules.

## Run the local pilot

The native team is pinned in source to `25C9H9N953`. The app uses dedicated bundle
ID `com.agent-yhes.YhesSigner`; the engine uses `com.agent-yhes.engine`. Their
Keychain access groups are separate:

- Signer: `25C9H9N953.com.agent-yhes.YhesSigner`.
- Engine storage: `25C9H9N953.com.agent-yhes.engine.vault`.

A certificate alone does not authorize these Keychain groups. Connect the Apple
Developer account for this team in Xcode Settings > Accounts, then from the repo:

```sh
native/YhesSigner/scripts/provision.py
native/YhesSigner/scripts/build-app.sh --signed
open native/YhesSigner/build/YhesSigner.app
```

Choose an existing project folder, check your human and project IDs, and select
**Start setup**. The app runs its bundled, signature-verified helper and brings
each review into the same window. Check the displayed scope, then use the named
action button and Touch ID. There is no separate review checkbox. **Resume setup**
checks completed stages before continuing; an interrupted request needs fresh review.

You can also start from the terminal with
`bin/yhes pilot --project PATH --human YOUR_ID --project-id PROJECT_ID`.
Both routes return approved output directly to the waiting helper. Then use `yhes send`,
`yhes say` and `yhes inbox` for the actual message flow. `yhes doctor` reports
setup problems. See the [pilot contract](USABLE-PILOT-CONTRACT.md).

`provision.py` generates two dedicated Xcode application targets under the native
build directory and asks Xcode automatic signing for local Mac development
profiles. Dedicated shared schemes select the discovered current Mac explicitly,
allowing Xcode to register that development device. Xcode may choose its newly
created Apple-managed team wildcard profile; this authorizes the exact dedicated
application IDs and groups embedded in each signature.
It does not upload, archive, notarize, publish, or export a signing key. It never
reuses another application's profile. `package-signed.py` checks profile team,
application ID authorization, platform, expiry, permitted group and matching local
certificate. A profile must authorize the exact ID/group or the pinned team's
`25C9H9N953.*` namespace; an unrelated product profile is refused. The packaged
code must still have the exact dedicated entitlements, never wildcard entitlements;
it refuses missing or mismatched profiles. It builds the engine with the team
pinned at compilation, signs the nested engine first and the app afterward,
and verifies both signatures with `codesign --verify --strict`.

The engine is a nested `Contents/Helpers/Engine.app` with its own provisioning
profile. `Contents/Helpers/yhes` points to its `Contents/MacOS/yhes` executable.
The completed bundle is `native/YhesSigner/build/YhesSigner.app`. Packaging does
not launch, enroll, install or replace any production Keychain item. Existing
build output is retained as `build/PreviousYhesSigner.app` on successful replacement.

**Local preparation verified (2026-11-14):** the first attempt failed with Xcode
`No Accounts`. After the user signed in, explicit shared schemes and the current
Mac destination resolved device registration. Both provisioning targets built
successfully with a newly created `Mac Team Provisioning Profile: *`, valid until
2027-11-14 for this team and one registered Mac. Both code signatures carried the
exact dedicated application IDs and exclusive Keychain groups, with no debugging
entitlement. The unrelated LookFlow profile was neither reused nor modified.
`package-signed.py --check-profiles` validates preparation without building or
launching the engine/app.

## Review and direct return

The socket is `~/Library/Application Support/agent-yhes/signer.sock`, under a
0700 same-owner directory with a 0600 socket. Both ends authenticate the kernel
Darwin `LOCAL_PEERTOKEN` audit token through Apple's code-signing APIs, checking
an Apple-anchored bundle ID and the compiled team pin. UID/permissions supplement
that identity proof. The signer also requires the engine's hardened runtime,
exact application ID and exclusive vault group, with unsafe entitlements absent.
It never uses a claimed PID or caller-supplied signing identity. A held file lock
prevents another instance from unlinking the active listener.

One bounded JSON line is allowed per connection, at most 1 MiB. Input must finish
within ten seconds. A native request expires after five minutes or at its document
expiry. The listener permits at most eight connections and one native review;
others receive `busy`. Extra frames, disconnect, timeout, screen lock, sleep and
user switching invalidate pending consent. An unchanged review must be visible in
the active key window for one second before its action button is enabled. Moving
focus resets that guard, but does not cancel an already frozen authentication
attempt: the system's Touch ID prompt may take focus. Completion remains bound to
the exact attempt, connection, request, document revision, identity and validity.
No approval is cached. Manual modal panels reject incoming requests as busy.

`identity` reads the existing public descriptor without a prompt or key creation.
`enroll` displays exact author/project and waits for explicit native approval.
`review` accepts only the existing typed event/registry/statement-batch forms.
Success returns directly to the waiting CLI; no manual JSON courier or save
panel is involved. Responses contain public identity metadata or ordinary signed
DSSE output. Failures use fixed bounded codes, never echoed input. The app does
not log message contents, private keys or wrapped enclave handles. Manual open,
review and save remain available for independent use.

A human statement shows its exact decoded words, author, project, complete
recipient list, group/epoch, validity and digest. Agent permissions show the
agent key and purposes; a group-wide delegation explicitly says “all epochs”.
Team changes show typed action parameters, performer and scope. Registry review
lists every participant, key and revocation. A local human has no enterprise
account claim; optional GHES claims require independent verification. Exact
UTF-8 JSON remains selectable in Details alongside full public-key identifiers.

## Typed approval and custody protections

Only `human.statement`, `agent.delegation` and `action.authorization` events are
supported. All have `session:null`. Statement validity is at most 30 minutes;
action authorization five minutes; reviewed delegations and registries seven
days. Those are document lifetimes, never authentication sessions. Statements
and actions bind group and epoch together. A delegation may explicitly grant a
group across epochs without granting human-signing authority.

Action authorization requires the exact typed sidecar and matching digest,
project, action, performer, group, epoch and audience. Supported actions remain
group creation, member add/remove and ticket recovery. Hash-only approval,
arbitrary shell/deploy work and generic byte-signing endpoints are refused.
The receiving core must enforce current authority, membership and stop evidence.

A fixed batch contains 1–16 exact statements, at most 256 KiB combined, with
unique IDs and identical author/key/project/audience/group/epoch. Every statement
is displayed before one fresh authentication context is created. The backend
receives only a one-use immutable-plan handle; bytes cannot be appended or
replaced. A failed, expired or cancelled batch returns no partial result. Each
inner envelope requires independent verification and replay checking. The outer
batch container does not prove atomic delivery or remote biometric attestation.

Registry signatures use a separate DSSE payload type. The pinned authority
public key comes from the independently authenticated signer connection; a
draft registry cannot authorize its own key. Native parsing checks schema,
order, uniqueness, optional GHES structure, key-ID/public-key bindings and times.
The bounded Rust/C bridge delegates Ed25519/P-256 public-key validation to
`yhes-wire::PublicKey::new`. The receiving core still enforces authority threshold,
chain, freshness, replay protection and permanent revocations.

The Secure Enclave key uses `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
`privateKeyUsage` and `biometryCurrentSet`. Every approval uses a new `LAContext`,
zero Touch ID reuse, no fallback button and a Touch ID availability check.
The fixed batch shares that context only across its frozen operations. macOS
may still prompt more than once; ACLs/reuse settings are never weakened to force
fewer prompts. Cancellation, time and document revision are checked through
signing and again before output.

Wrapped enclave representation and public metadata live in the app's fixed
Data Protection Keychain group. Setup refuses overwrites. There is no key import,
replacement, deletion, private-key export or runtime test-key/authentication bypass.
A possession challenge forces biometric private-key use before enrollment is
persisted; it is not a yhes event and is never returned. Code-signing checks
require the expected `.app`, Apple anchor, team, hardened runtime, application
ID and exclusive group; debugging, JIT, injected DYLD environment, unsigned
executable memory and disabled library validation entitlements are refused.

This boundary trusts the OS and the signed publisher. It does not claim that
same-user Accessibility input proves a human click, or that arbitrary hostile
programs under one OS user are isolated from enrolled local agent profiles.
Fresh biometric approval of immutable bytes is required even after earlier work.

## Verification and remaining acceptance

```sh
native/YhesSigner/scripts/test.sh
native/YhesSigner/scripts/build-app.sh --preview
```

Tests use injected software signers only in the test target. The executable
contains no fixture private key. The scripts build the locked Rust public-key
bridge first; direct `swift test` requires that archive to exist. The preview
lives under `build/Preview/YhesSigner.app`, has no trusted signature, and fails
before starting its listener or touching Keychain. It is useful for visual review,
not for production setup.

The combined script passed three Rust bridge tests and 104 Swift tests: existing typed policy/DSSE/one-use
and cancellation coverage, plus strict IPC fields/base64/bounds, exact output,
readable statement text, one pending request, timeout/disconnect/late completion,
local-human registry and group-wide delegation cases, plus focus policy, stale
attempt isolation, action arming, modal ownership and setup presentation. The
native release build passed. A separate inert UI harness was inspected in light
and dark appearances at the minimum window size, including identity, retry,
team, channel, cancellation and complete details. No real enrollment or biometric
approval was triggered during testing.

Dedicated provisioning, signed app/helper execution and live authenticated socket
exchange have passed; see [the dated validation record](VALIDATION.md). The user
has now completed enrollment and setup approvals, followed by a human statement
that Claude received as a verified human original inside a Codex relay. Actual
Codex–Claude agent messaging and durable readback also passed on this Mac.
The focus-cancellation path has been removed while preserving exact-review
binding, and the observed user flow completed. Exact OS prompt count, deliberate
focus/lock/sleep interruptions, biometric-set changes and user switching still
need dedicated hardware checks; one successful trial does not establish those.

Apple references: [Secure Enclave keys](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
[Secure Enclave signing key](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey),
[Touch ID reuse policy](https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration).
