# yhes-core `mls` module API

Low-level MLS operations for the durable core, in `src/mls.rs`. Everything is
`pub(crate)`: nothing here is reachable from transports or harnesses. `lib.rs`
declares `mod mls;`.

The module owns MLS mechanics only. Root owns registry checks, authority and
action checks, audience policy, the outbox, inbox and checkpoints, and decides
what to do with every returned value.

## Contract with the caller

- Every function takes `&rusqlite::Connection` and expects to run **inside the
  caller's transaction** (`Vault::transaction`). It opens no transaction, makes
  no network or keychain call and reads no clock.
- **Any `Err` means the caller must abort that transaction.** A failed
  operation may already have written provider state (for example a consumed
  ratchet key). The module never asks to commit after an error.
- The MLS group object is loaded fresh from the connection in every call and
  dropped before returning. Nothing is cached between calls.
- Fixed suite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (suite 1). Key
  packages, Welcomes and groups of any other suite are refused. There is no fallback.
- Handshake and application messages are both MLS ciphertexts
  (`PURE_CIPHERTEXT_WIRE_FORMAT_POLICY`). The ratchet tree travels in the Welcome.
- Supported commits carry Add and Remove proposals only. Update, PSK, ReInit,
  ExternalInit, GroupContextExtensions, SelfRemove and custom proposals,
  standalone proposals and external commits are refused. A commit whose update
  path changes the committer's credential or signature key is refused.
- Inputs are limited to 1 MiB.

## Identity

```rust
pub(crate) struct AgentSigner;   // not Clone, no Debug, key zeroized on drop

impl AgentSigner {
    /// Generates the agent's Ed25519 key and stores it in `yhes_identity`.
    /// `Error::Conflict` if an identity already exists.
    pub(crate) fn init(db: &Connection, principal: &str) -> Result<AgentSigner>;
    /// Loads it. `Error::Invalid` if absent; `Error::Verification` if the
    /// stored principal, key id, public key and secret do not agree.
    pub(crate) fn load(db: &Connection) -> Result<AgentSigner>;

    pub(crate) fn project(&self) -> &str;            // from yhes_meta 'project'
    pub(crate) fn principal(&self) -> &str;
    pub(crate) fn key_id(&self) -> &yhes_wire::KeyId;
    pub(crate) fn public(&self) -> &yhes_wire::PublicKey;   // Ed25519, 32 raw bytes
    /// DSSE signature over `pae(payload_type, payload)`. Only the event and
    /// transport payload types are accepted; it never signs raw bytes.
    pub(crate) fn sign(&self, payload_type: &str, payload: &[u8]) -> Result<yhes_wire::SignatureEntry>;
}
```

One Ed25519 key serves MLS and DSSE. The two uses are domain-separated by
construction: MLS signs TLS-encoded `SignContent` beginning with a length byte
and the label `MLS 1.0 …`; DSSE signs bytes beginning with `DSSEv1 `. The MLS
`Signer` implementation is private to the module. The secret never leaves it.

`yhes_identity` row (`id = 1`): `principal`, `key_id`, `secret` (32-byte seed),
`public` (32 bytes). No other table is created or altered by this module;
OpenMLS state lives in the provider's own tables.

## Credential

MLS BasicCredential identity bytes:

```
"agent-yhes/mls/v1" 0x00 project 0x00 principal 0x00 key_id
```

The module accepts a credential only when it parses exactly, `project` equals
the vault's project, `principal` is a valid identifier, and `key_id` equals the
yhes-wire key id of the leaf's Ed25519 signature key. That makes each roster
entry self-consistent. **It does not make it authorized**: root must check every
returned `Member` against the registry, for example
`registry.active_key(&m.principal, &m.key_id, now)` and compare with `m.signature_key`.

## Binding the exact KeyPackage

Two KeyPackages made by the same agent carry the same principal, key id and
signature key, so `Member` cannot tell them apart. The caller binds the
approved package by digest instead: `Change.added_key_package_digests` for an
incoming commit and `Invitation.own_key_package_digest` for a Welcome. Both are
`Digest::of` the package's TLS bytes, the same bytes `key_package` returns and
`inspect_key_package` and `stage_add` accept, and both are available to the
policy callback before anything is merged or stored.

## Types

```rust
pub(crate) struct Member {
    pub principal: String,
    pub key_id: yhes_wire::KeyId,
    pub signature_key: Vec<u8>,     // 32 raw Ed25519 bytes
    pub leaf: Option<u32>,          // None for a member not yet in the tree
}

pub(crate) struct GroupState {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub roster: Vec<Member>,        // by leaf index
    pub pending: bool,              // an own staged commit awaits merge or clear
    pub active: bool,               // false once this client was removed
}

pub(crate) struct Staged {          // own membership change, not yet merged
    pub base_epoch: u64,
    pub commit: Vec<u8>,            // public MLS message bytes
    pub welcome: Option<Vec<u8>>,   // public MLS message bytes, for adds
    pub added: Vec<Member>,
    pub removed: Vec<Member>,
    pub next_roster: Vec<Member>,
}

pub(crate) struct Sealed { pub epoch: u64, pub ciphertext: Vec<u8> }

pub(crate) struct Change {          // an incoming commit, before merge
    pub committer: Member,
    pub base_epoch: u64,
    pub added: Vec<Member>,
    /// SHA-256 of each added KeyPackage's exact TLS bytes, in `added` order:
    /// equal to Digest::of(bytes given to inspect_key_package / stage_add).
    pub added_key_package_digests: Vec<yhes_wire::Digest>,
    pub removed: Vec<Member>,
    pub next_roster: Vec<Member>,
    pub removes_self: bool,
}

pub(crate) struct Invitation {      // a Welcome, before joining
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub inviter: Member,
    pub roster: Vec<Member>,        // includes this client
    /// SHA-256 of the exact TLS bytes of the own KeyPackage the Welcome consumed.
    pub own_key_package_digest: yhes_wire::Digest,
}

pub(crate) enum Received {
    Application { sender: Member, epoch: u64, plaintext: Zeroizing<Vec<u8>> },
    Commit { change: Change, state: GroupState },
}
```

## Functions

```rust
/// New group with this agent as the only member.
pub(crate) fn create(db: &Connection, signer: &AgentSigner, group_id: &[u8]) -> Result<GroupState>;

/// Fresh KeyPackage. Private parts stay in provider storage; returns public bytes.
pub(crate) fn key_package(db: &Connection, signer: &AgentSigner) -> Result<Vec<u8>>;

/// Validates a KeyPackage (signature, suite, credential binding) without
/// touching state, so root can check the candidate before staging.
pub(crate) fn inspect_key_package(project: &str, key_package: &[u8]) -> Result<Member>;

/// Stages an Add commit. Refused while another change is pending.
pub(crate) fn stage_add(db: &Connection, signer: &AgentSigner, group_id: &[u8],
                        key_package: &[u8]) -> Result<Staged>;

/// Stages a Remove commit for the member with this principal and key.
/// Removing oneself is refused.
pub(crate) fn stage_remove(db: &Connection, signer: &AgentSigner, group_id: &[u8],
                           principal: &str, key_id: &yhes_wire::KeyId) -> Result<Staged>;

/// Applies the own staged commit after transport accepted it.
pub(crate) fn merge_pending(db: &Connection, group_id: &[u8]) -> Result<GroupState>;

/// Discards the own staged commit after its rejection is established.
pub(crate) fn clear_pending(db: &Connection, group_id: &[u8]) -> Result<GroupState>;

/// Processes a Welcome. `policy` sees the invitation before any group state
/// is created; the group is stored only if it returns Ok.
pub(crate) fn join(db: &Connection, signer: &AgentSigner, welcome: &[u8],
                   policy: &dyn Fn(&Invitation) -> Result<()>) -> Result<GroupState>;

/// Encrypts one application message. Refused while a change is pending.
pub(crate) fn send(db: &Connection, signer: &AgentSigner, group_id: &[u8],
                   plaintext: &[u8]) -> Result<Sealed>;

/// Processes one incoming MLS message for this group. For a commit, `policy`
/// sees the staged change **before** it is merged; the commit is merged only
/// if it returns Ok. While an own change is pending, applications for the current
/// epoch remain receivable; another Commit is refused until resolution.
pub(crate) fn receive(db: &Connection, group_id: &[u8], message: &[u8],
                      policy: &dyn Fn(&Change) -> Result<()>) -> Result<Received>;

/// Current public state of a stored group.
pub(crate) fn group_info(db: &Connection, group_id: &[u8]) -> Result<GroupState>;
```

## Errors

Uses `crate::Error`, with fixed messages and no payload content:

| Variant | When |
| --- | --- |
| `Invalid` | Malformed or oversized input, bad identifier, unknown group, no identity. |
| `Conflict` | Identity or group already exists, change pending, nothing pending, no longer a member. |
| `Verification` | Credential not bound to its key or project, wrong suite, unsupported proposal, changed committer identity, identity row inconsistent. |
| `Mls` | OpenMLS rejected the operation (bad signature, wrong epoch, undecryptable, consumed key). |
| `Storage` | SQLite or provider storage failure. |
| *policy error* | Whatever the callback returned, unchanged. |

## What is not exported

No exporter secrets, epoch authenticators, ratchet tree, private keys or
provider rows. Plaintext leaves only as the `Received::Application` result of
`receive`, wrapped in `Zeroizing`, to the crate-internal caller, which must
make its inbox record durable in the same transaction before releasing it.

## Tests

`cargo test -p yhes-core mls` from `secure/` runs the 17 unit tests in
`src/mls.rs`. They use `crate::store::tests::fixture()` vaults (SQLCipher, one
per agent) with generated software keys, and cover: identity init/load and
inconsistent rows; DSSE signing limits; create/add/join/send/receive; policy
refusal of a Welcome and of an incoming commit with nothing merged; pending
change blocking; a membership race; removal; tampered, replayed and misdirected
messages; KeyPackages with unbound credentials or another suite; and use of a
group with a foreign identity.

Unsupported messages are produced in the tests by driving OpenMLS directly on
a peer's stored group, standing in for a non-conforming client: a commit with
a GroupContextExtensions proposal; a commit with a PreSharedKey proposal (PSK
present on both sides); a standalone Update proposal and the commit that
references it; a standalone Add proposal; and commits whose update path swaps
in a new signature key under the same name, under another member's name, or
with an unbound credential. Each is refused before the policy callback runs
and leaves the receiver's state unchanged. A path-only self-update with the
same identity is accepted as an empty change, which the caller's policy sees.

Not covered by a test: ReInit, ExternalInit, SelfRemove and custom proposals,
and external commits. They take the same refusal branch as the tested types.
