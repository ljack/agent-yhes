# yhes-core integration API

This is an in-process library for the future signed local engine. It has no
listening socket, secret-export command or runtime switch selecting test keys.
The caller is trusted engine code; it supplies a trusted current clock and
approved project configuration. Do not expose these methods directly as agent RPC.

`ProjectTrust::new(project, authority_public_keys, threshold)` establishes the
out-of-band authority pins. `Vault::create/open` takes an absolute private path,
a `StorageKey`, project, account and boxed `AnchorStore`. Production key and anchor
providers are `PlatformKeychain`; test providers live in test targets. See
[key custody](../../../docs/KEY-CUSTODY.md).

`Engine::open(vault, trust, principal)` creates or reloads one agent identity.
An existing vault cannot silently change its principal or authority pins.

| Method | Result / required input |
| --- | --- |
| `identity()` | Public agent identity only. No private key export. |
| `bootstrap_registry(chain, expected_head, now)` | Complete signed chain, independently approved head digest, current final registry. Empty registry only. |
| `install_registry(envelope, now)` | Exact next signed generation, or identical current generation. |
| `sign_event(event, grant, authorization, original_grant, now)` | An agent event only after role, signature-evidence and scope verification. No generic sign-bytes API. |
| `key_package(operation, now)` | Durable public MLS KeyPackage; same operation returns the same bytes. |
| `create_group(operation, control, now)` | Signed genesis packet for the approved singleton group; sending stays blocked pending publication. |
| `change_membership(operation, control, now)` | Exact pending Commit/Welcome packet. Fresh approval binds the resulting audience and exact added KeyPackage. |
| `ready(operation, now)` | Stored bytes after current identity, registry and epoch checks. Old unsent packets stay immutable and are refused after audience changes. |
| `confirm_publication(operation, exact_record, receipt, now)` | Trusted adapter callback after verified authoritative acceptance. Merge own pending membership and store receipt atomically. |
| `reject_membership(operation, exact_digest, authoritative_head)` | Trusted adapter callback after definitive rejection and history check; clear pending state, keep approval consumed. Never call on a timeout. |
| `join(expected_group, expected_owner, accepted_record, now)` | Verify approved request, exact own KeyPackage, inviter and complete roster before joining. Exact retry is idempotent. |
| `prepare_message(operation, group, content, now)` | Verify and encrypt an agent message or preserved human relay; persist ciphertext before returning it. |
| `receive(accepted_record, now)` | Verify outer binding and MLS sender, then inner provenance; persist result before returning. |

`SignedContent` retains the event and evidence envelopes as exact UTF-8 JSON
strings. `Control` additionally contains the exact reviewed action request and,
for an add, the base64 public KeyPackage. The native signer and `yhes-actions`
share the [sidecar schema](../yhes-actions/API.md).

`Delivery` has `disposition` (`verified`, `duplicate`, `quarantined`, `membership`
or `joined`), optional `AcceptedMessage`, and `replayed`. An exact inbox retry
returns the original durable result with `replayed: true`, including after expiry
or later revocation: it reports historical acceptance, not renewed authority.
Consumers use event identity and receipts to avoid applying work twice.
`AcceptedMessage` separates the agent author from `human_original_author` and
retains the original signed content. This API never interprets prose as an action.

All mutations take the exclusive vault lock and share one transaction with the
[native OpenMLS provider](MLS-API.md). Exceptions are network operations and human
review, which belong outside it. `CheckpointPending` means the database committed
but its external checkpoint did not; drop/reopen before retrying the same operation.
Other failures return no ciphertext, no newly trusted plaintext and no raw SQL,
key material or message content in diagnostics.

The current fresh-only membership acceptance and founding-agent governance are
intentional limits of this first integration. See the release gates in
[the secure README](../../README.md). Caller-provided acceptance/rejection strings
are adapter assertions, not standalone cryptographic proofs. There is no exposed
production adapter until that boundary verifies Git history and freshness.
