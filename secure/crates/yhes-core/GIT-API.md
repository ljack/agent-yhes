# Secure Git transport

`GitChannel` is an in-process, trusted adapter. It transports exact persisted
signed/sealed packets, never vaults, private keys, plaintext messages or native
signer requests. A separate private bare repository contains its Git objects;
source worktrees, indexes, refs and remotes are not used.

```rust,ignore
GitChannel::open(private_cache: &Path, remote: &str, branch: &str, project: &str)
    -> Result<GitChannel>;
GitChannel::open_with_options(private_cache: &Path, remote: &str, branch: &str,
    project: &str, options: GitOptions) -> Result<GitChannel>;
channel.publish(engine: &mut Engine, operation: &str, now: u64)
    -> Result<local::Publication>;
channel.sync(engine: &mut Engine, group: &str, owner: &str, now: u64)
    -> Result<local::SyncResult>;
channel.fetch_public() -> Result<PublicSnapshot>;
channel.read_public(name: &str) -> Result<Option<Vec<u8>>>;
channel.publish_public(name: &str, bytes: &[u8]) -> Result<PublicPublication>;
channel.fetch_public_checked(engine: &mut Engine) -> Result<PublicSnapshot>;
channel.read_public_checked(engine: &mut Engine, name: &str)
    -> Result<Option<Vec<u8>>>;
channel.publish_public_checked(engine: &mut Engine, name: &str, bytes: &[u8])
    -> Result<PublicPublication>;
```

`PublicSnapshot` has `head: Option<String>` and
`artifacts: BTreeMap<String, Vec<u8>>`. `PublicPublication` has `name`, `digest`,
`commit` and `replayed`. Public artifact names are single path-safe identifiers.
They are immutable: repeat publication requires byte equality. Public artifacts
are deliberately supplied only by trusted enrollment/registry code; callers must
publish public schema data only and verify signatures, project, independently
pinned authority and registry chain before installation. Fetch alone does not
establish identity or authority. Never expose `publish_public` as arbitrary agent
RPC or pass private files to it.

Once a vault/configuration exists, use the **checked** public methods. They check
the engine's existing protected Git ancestry before returning artifacts or
building a publication, and check it again on publication readback. They do not
advance a newer public head ahead of application sync. Public artifacts seen
after the last application checkpoint therefore remain subject to the caller's
signature/generation checks until `sync` checkpoints their ancestry. The raw
methods are only for pretrust bootstrap with explicit independent pins.

`GitOptions` is `Clone + Debug + Serialize + Deserialize + PartialEq + Eq`, rejects
unknown fields, and has these exact fields:

```rust,ignore
GitOptions {
    author_name: String,
    author_email: String,
    signing: Option<GitSigning>,
    credentials: GitCredentials,
    ssh_agent: bool,
}
GitSigning::Ssh { public_key: PathBuf }
GitSigning::OpenPgp { fingerprint: String }
GitCredentials::{None, OsxKeychain}
```

Defaults preserve unsigned transport commits, no credential helper, no inherited
SSH agent, and `agent-yhes transport <transport@invalid>`. Options bind the private
cache, including the exact SSH public-key-file digest. Changing options cannot
reset the engine's logical channel checkpoint. SSH signing requires one absolute
regular OpenSSH **public** key file, uses `/usr/bin/ssh-keygen`, and optionally
the explicitly enabled agent socket. It never imports or exports private keys.
OpenPGP takes a full 40/64-hex fingerprint with exact-key selection and uses only
`/opt/homebrew/bin/gpg` on macOS (`/usr/bin/gpg` elsewhere), if installed. Only
that explicit signing operation receives the user's ordinary `.gnupg` keyring
location. Both modes use `commit-tree -S`; signing failure prevents publication.
Remote commit-signing acceptance policy is separate from packet authorization.

`OsxKeychain` enables only the fixed installed Apple command-line-tools
`git-credential-osxkeychain` executable, only for HTTPS transport, with
`credential.useHttpPath=true`. No arbitrary helper/program string is accepted.
Tests use neither this helper nor the user's OpenPGP keyring. OpenPGP and
osxkeychain live authentication remain unverified integration paths.

The remote and branch come exclusively from approved local configuration. Open
requires an absolute private cache directory, binds that cache permanently to
the exact remote/branch/project/options, and refuses existing unrelated contents. Only
local absolute paths, HTTPS and SSH transports are supported. Git subprocesses
receive explicit argv, a scrubbed environment, no user/system Git configuration,
no hooks, no templates, only explicitly selected fixed signing/auth helpers,
no shell input from remote content,
and bounded output/runtime. SSH uses batch mode and requires existing host trust.
Authentication/host-key failures fail closed. Hosted authentication is a separate
integration from the disposable local-bare-repository tests.
HTTPS redirects, URL userinfo/passwords, queries and fragments are refused;
ambient credential helpers are not used. SSH usernames remain supported.
`ssh_agent: true` explicitly permits the inherited socket solely for SSH
transport or SSH commit signing. Local/HTTPS fetch/push never inherit it.
Absolute-path remotes must be bare repositories with no executable hooks,
linked hooks, custom `core.hooksPath`, config includes or executable upload-pack
configuration. Regular `*.sample` files are inert and allowed. These checks run
before every local transport operation; no hook is executed as a test/probe.

The branch is a bounded linear chain. Each commit adds exactly one immutable
`records/<20-digit-sequence>_<sha256>.json` or `public/<name>` regular blob.
Records reuse the local adapter's exact entry format and SHA-256 previous-record
chain. Full commit and record histories are checked before receiving or
acknowledging packets. Merges, edits, deletions, symlinks, unexpected paths,
oversize history, operation collisions and rollback are errors. Commit author,
message and timestamps carry no authorization or admission-time meaning.
Bounds are 4,096 packets, 1,024 public artifacts, 2 MiB per blob and 64 MiB total
artifact data. Commands have a 30-second deadline. The cache is checked against
256 MiB and 100,000 files before use, during fetch and after fetch. This is a
client resource check, not a filesystem quota; a hostile server can transfer
data between polling intervals. Optional SSH/OpenPGP commit signatures are
supported, but GHES account assertions and remote signing-policy acceptance are
not established by the adapter. Signed packet and registry verification remain
mandatory independently of Git commit identity.

Publication checks the protected cursor, reconciles any exact existing operation,
drains earlier records, and calls `Engine::ready` before building a candidate.
The candidate extends the fetched head and uses a normal fast-forward push (no
force option). After every push outcome, the adapter fetches and checks history
again. Only the exact operation/sender/packet bytes and digest in verified
authoritative history permit `confirm_publication`. A push ACK alone never does.
An uncertain/failed push with no exact record returns an error with pending state
intact. This first profile does not automatically reject pending membership:
the adapter does not derive a definitive signed rejection from arbitrary Git
failures, so a conflict fails closed and needs explicit reconciliation rather
than discarded approval. `Engine::reject_membership` remains a trusted callback;
passing it an unverified Git error string would not satisfy its contract.

Sync uses the local adapter's ordered membership verifier and stores its cursor
inside the encrypted, rollback-protected engine. Git ancestry is also pinned in
that protected store. Current caller-supplied trusted `now` reaches inspect,
receive and join unchanged. Previously unseen expired membership cannot bootstrap
an offline peer; sender/commit timestamps never backdate acceptance. Only exact
protected historical acceptance can use the engine's historical retry path.
This includes an own prepared membership packet found after its approval has
expired: an exact Git match alone is not independent acceptance-time evidence.
The adapter leaves it pending and fails closed; it never backdates the clock or
relaxes expiry to merge it. Recovery/lifecycle policy belongs to the caller.

Parent-owned integration: export `pub mod git`, expose local `Entry`/`Stored`
within the crate, and provide logical `LocalChannel::sync_transport` and
`check_transport_cursor` entry points. These call the existing local verifier
without creating a filesystem channel; the transport binding includes protocol,
remote, branch and project, independent of cache location.
