# Key custody

The vault encryption key and the external freshness checkpoint live in the
macOS Data Protection keychain. They are not environment variables, files, or
login-keychain passwords. The human Secure Enclave key is a different key, in
the signer access group, and is not handled here.

`yhes_core::keys::PlatformKeychain` implements `KeyProvider` and `AnchorStore`.
Unit tests use an in-memory store and never call the platform implementation.
No test in this module mutates the login or Data Protection keychain.

## Who may read the items

Every lookup uses one scope:

| Attribute | Value |
| --- | --- |
| Keychain | Data Protection (`kSecUseDataProtectionKeychain`) |
| Synchronizable | false |
| Protection | `AccessibleWhenUnlockedThisDeviceOnly`, access-control flags 0 |
| Access group | `{TeamID}.com.agent-yhes.engine.vault` |
| Class | generic password |

Vault items use service `com.agent-yhes.vault.v1`. Checkpoint items, including
the non-authoritative head hint, use `com.agent-yhes.anchor.v1`. The signer's
group `{TeamID}.com.agent-yhes.YhesSigner` is never used here.

The caller's reference is 1 to 128 ASCII letters, digits, `_`, or `-`. Vault
keys use that string as the Keychain account. Checkpoint accounts do not:

| Record | Keychain account | Write |
| --- | --- | --- |
| Vault key | `{reference}` | `SecItemAdd` only |
| Genesis checkpoint | `g1:{reference}` | `SecItemAdd` only |
| Later revision | `a1:{reference}:{revision}` | `SecItemAdd` only |
| Head hint | `h1:{reference}` | insert, or update of this account only |

`{revision}` is the canonical decimal form (`0`, `1`, `10`, never `01`).
The access group is accepted only after the running process passes all of
these checks:

- `csops` status includes valid, signed, and hardened runtime.
- Status does not include ad-hoc, linker-signed, get-task-allow, or debugged.
- Static signature flags include hardened runtime and exclude ad-hoc and
  linker-signed.
- Signing identifier is `com.agent-yhes.engine`.
- Team ID is 10 characters from `A-Z` and `0-9`, and the leaf certificate OU
  matches it under `anchor apple generic`.
- `com.apple.application-identifier` is `{TeamID}.com.agent-yhes.engine`.
- `keychain-access-groups` is exactly
  `[{TeamID}.com.agent-yhes.engine.vault]`.
- `com.apple.security.get-task-allow` is absent or boolean false.

Anything else, including an unsigned, ad-hoc, or unentitled process, fails
closed. There is no fallback.

## Writes

`KeyProvider::create` generates 32 bytes and calls `SecItemAdd` only. A
duplicate account is a conflict. Key material is never updated and never
deleted.

`AnchorStore::load` rebuilds the head from the add-only chain. `Ok(None)`
means that chain is absent. A head hint is not a checkpoint: a missing, stale,
or unreadable hint does not change the result.

`AnchorStore::advance` publishes one new record:

- `expected == None` adds the genesis record, or succeeds again when that
  exact genesis record is still the head. The genesis slot is one item per
  logical account, so two first publications conflict even when their
  revision numbers differ.
- `expected == Some` adds `a1:{reference}:{next.revision}` only when the
  stored head equals `expected` and `next.revision` is `expected.revision + 1`.
  The payload binds that predecessor's revision and digest.
- The same `expected` and `next`, once that `next` is the head, is idempotent
  and does not insert another item.
- A different digest for an occupied revision is `conflict: checkpoint mismatch`.
  The bytes already stored stay.
- After the add, load must resolve to `next`. A chain that moved further, or
  a slot that already holds other bytes, is a conflict.

`SecItemAdd` is the publication. The caller's filesystem lock is not. Two
copied or swapped database paths share this keychain account and cannot both
become the head.

The head hint may be inserted or replaced only at `h1:{reference}`, and only
after the add-only record is confirmed. Hint failure still returns success.
Load never reads the hint to choose the head.

A corrupt checkpoint is an error and is not overwritten. A record left by the
previous single-item path, whose account is the bare logical reference, is
unreadable and is not migrated. Errors do not include key bytes or checkpoint
contents.

## History growth and recovery

Each published revision is one Data Protection item. Older items stay. This
module never deletes them and never rewrites an occupied revision. Deleting a
tail would free that revision for a different digest, so an operator cleanup
is not a recovery path this code provides.

The chain grows once per committed revision. No-op reads must not call
`advance`. Root owns that choice; there is no compaction here.

A lost or lying head hint is not data loss. The next load walks the add-only
records.

These items are `ThisDeviceOnly` and not synchronizable. They are not in
iCloud and do not come back from a backup restore or another device. A vault
file copied without this chain stays quarantined. Do not mint a replacement
genesis for an account that already has history, and do not rename the
account to get past a conflict.

Gaps, two payloads for one revision, a successor whose predecessor does not
match, unreadable bytes, and a legacy single-item record all fail `load` and
`advance`. The stored bytes are left as they were. The winning digest of a
race remains the only occupant of that slot.

## Assumptions that remain

These are limits of this module, not permissions to weaken the checks above.

1. **The team pin is self-derived.** The runtime requirement takes the team
   id from the running binary and checks that binary's leaf OU against it.
   It does not pin Team ID `25C9H9N953` or a leaf certificate hash.
   `anchor apple generic` accepts an Apple Development certificate as well as
   Developer ID. A binary signed by another team gets a different access
   group and does not read this chain. A replacement binary from this same
   team, with a profile that authorizes
   `{TeamID}.com.agent-yhes.engine.vault`, passes. Dedicated profiles are not
   in the repo; provisioning is what keeps that group on this identity.

2. **Custody authenticates this process, not the local caller.**
   `csops(getpid())` and `SecCode::for_self` describe the engine. Access
   control flags are 0, so the vault key does not ask for Touch ID. Any
   same-UID program that can run the signed engine can use the key. Copied
   database paths do not change the keychain account; after this change they
   still share one chain, and only one digest can win each revision.

3. **The path lock and the head hint are not freshness.** The vault store
   compares `vault_path` as a string and holds a lock beside that path.
   Neither binds the keychain account. The hint is last-write-wins and is
   ignored by load. Treating the hint, the path string, or the lock as the
   checkpoint brings the fork back.

## Signed engine bundle

The binary that calls `PlatformKeychain` must be signed before those calls can
succeed. The unit tests do not produce that signature.

- Identifier `com.agent-yhes.engine`.
- Hardened runtime (`--options runtime`).
- Developer ID or Apple Development certificate whose OU is the team ID.
  Not ad-hoc (`-`), not linker-signed, and not a private CA.
- `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO`, so the build does not inject
  get-task-allow.
- Entitlements, in dictionary form:
  - `com.apple.application-identifier` = `TEAMID.com.agent-yhes.engine`
  - `keychain-access-groups` = [`TEAMID.com.agent-yhes.engine.vault`]
  - `com.apple.security.get-task-allow` absent or false
- A provisioning profile or Developer ID allowance that authorizes that
  keychain access group for the Data Protection keychain.

The process check uses
`identifier "com.agent-yhes.engine" and anchor apple generic and certificate leaf[subject.OU] = "TEAMID"`.
`TEAMID` in that requirement is the team id read from the binary, not a
second constant. A signed Apple Development bundle that fails only that
requirement is the point to revisit the anchor clause. The entitlement and
code-signing flag checks stay as written.

Opening the SQLCipher file, rejecting symlinks, and taking the vault lock
remain in the store owned outside this module. Those steps do not publish
the checkpoint.
