# Two-person team workflow

This is separate from the existing local `pilot`. It uses one local agent per
person, independent native human identities and a Git transport. It does not
claim GHES integration. Every local human has `ghes: null`.

```
yhes team-init --project PATH --project-id ID --human HUMAN --as AGENT \
    --remote REMOTE [--branch BRANCH]
yhes team-request --project PATH --project-id EXPECTED_ID --human HUMAN --as AGENT \
    --remote REMOTE --authority EXPECTED_AUTHORITY_KEY_ID \
    --bootstrap EXPECTED_REGISTRY1_DIGEST [--branch BRANCH]
yhes team-admit --project PATH --peer PEER_AGENT --peer-key EXPECTED_PEER_HUMAN_KEY_ID
yhes team-connect --project PATH [--as AGENT]
yhes team-send --project PATH [--as AGENT] --text TEXT [--operation ID]
yhes team-say --project PATH [--as AGENT] --text TEXT [--operation ID]
yhes team-inbox --project PATH [--as AGENT] [--no-sync]
yhes team-status --project PATH [--as AGENT]
```

Send/say also accept `--body-file FILE` or `--stdin`, with the local pilot's
size, newline and human review limits. Agent IDs have at most 32 ASCII letters,
digits, underscores or hyphens, starting with a letter or digit. The default
branch is `agent-yhes/secure-team`; the group is `team`.

Setup optionally accepts explicit Git settings: `--git-author-name NAME`,
`--git-author-email EMAIL`, paired `--git-signing-format ssh|openpgp` and
`--git-signing-key PUBLIC_KEY_PATH|FINGERPRINT`, `--git-credentials osxkeychain`,
and `--git-ssh-agent`. SSH signing selects a public key file; it never reads a
private key into the CLI. These settings select the transport's typed providers;
ambient Git configuration does not choose helpers or signing programs. They are
stored in the immutable pin and must match on setup retries. No signing or
credential provider is enabled by default. Git signatures and account access
are separate from the protocol's human identity and membership checks.

## Required trust checks and order

1. The founder runs `team-init`: native identity enrollment when needed,
   one private agent identity and native review of registry generation 1.
   The exact signed registry and public bootstrap descriptor are published.
   The group is deliberately not created yet.
2. The peer checks the project ID, full authority key fingerprint and
   `bootstrap_head` digest with the founder using another trusted channel,
   then supplies all three explicitly to
   `team-request`. The command rejects a mismatched bootstrap before asking
   for the peer's human identity. It validates generation 1 under that pinned
   authority, records its digest in the protected local pin, and publishes a
   native-reviewed self-signed registry proposal for the peer's human and agent.
   This proposal is enrollment evidence, not authoritative membership.
3. The founder checks the peer's full human key fingerprint independently and
   passes it to `team-admit`. The command verifies the self-signature, project,
   exactly one human and agent, key ownership, controller and free namespace.
   The founder reviews the actual merged registry in native registry mode.
   Only that authority-signed next generation admits the peer.
4. With both people online, the peer runs `team-connect`: installs the verified
   monotonic registry chain, reviews delegation of their own agent to the full
   two-agent audience, and publishes a stable MLS KeyPackage. It returns
   `waiting-for-invitation`.
5. The founder runs `team-connect`: checks the peer's MLS signature, project,
   principal and registered key before asking for approval; delegates their
   own agent, then reviews separate exact `group.create` and `group.add`
   authorizations. The add binds the exact package digest and recipient.
   Both signed membership packets are published through verified Git history.
6. The peer immediately runs `team-connect` again. It verifies the fresh genesis
   and add and joins the invitation for its own saved package. Both profiles
   can now use `team-send`, `team-say` and `team-inbox`.

The authority key and generation-1 registry digest are explicit out-of-band
trust pins. `team-init` prints both. The peer must supply both; the command checks
the exact expected digest as well as the signature and schema before native
enrollment. Both pins are stored immutably. Later registry heads are verified
through the pinned chain; no repository key is automatically promoted to an
authority.
The head digest is the wire profile's SHA-256 of the exact registry payload
(`Envelope::digest`), not a hash of the enclosing JSON signature file.

## Freshness and retries

Membership approvals last five minutes. Genesis is delayed until the admitted
peer's KeyPackage exists, so ordinary enrollment delay does not spend that
window. The create approval, add review and peer's first successful sync must
still fit the window. Keep both people online. Long-offline initial join and
membership recovery are intentionally unsupported and fail closed; no timestamp
is backdated and an unseen expired approval is never accepted. A founder's
`ready` result describes its own profile, not proof that the peer has joined.

Exact native registry envelopes, enrollment proposals, delegations, membership
authorization/execution drafts, operation IDs and controls are checkpointed in
the encrypted vault. Retrying a completed stage reuses exact bytes. Expired
checkpointed membership fails rather than silently obtaining a different
approval or discarding pending MLS state. Registry/key renewal and recovery
after expiry require a later explicit workflow; this slice does not implement
them. `team-connect` can renew a delegation under a still-current registry.

Message operations bind command and text. A changed retry fails with
`operation_conflict`. Human originals are checkpointed before agent relaying;
`human_original_author`, `human_text` and the agent outer author stay separate.
The core persists inbox acceptance; repeated inbox reads report historical
acceptance and `replayed`, not renewed authority. The `new` flag is a local
reading aid. No text is interpreted as an action.

## Storage and integration

`Workspace.private/network/team.json` is an immutable mode-0600 `TeamPin`,
separate from legacy `pin.json`. It contains the project path/ID, remote,
branch, group, owner, local agent principal, local human descriptor, authority
descriptor, peer bootstrap digest and typed Git options. Its complete serialization digest is
stored inside the protected vault and checked before using configuration or
opening the Git channel. Vaults live at `network/AGENT/vault.db`, with separate
`pHASH-network-AGENT` custody accounts. The private Git cache is `network/git`.

Public Git files are immutable exact bytes: `bootstrap.json`,
`registry-N.json`, `request-AGENT.json`, `key-package-AGENT.json` and the core's
sealed membership/application records. No vault, private key, signing request
or plaintext application message is published. Source worktrees are untouched.
After a vault exists, every public fetch/publication uses the transport's
checked API and checks the protected Git ancestry. Ordered sync records the
accepted Git head; later rollback of only public artifacts is refused even if
the registry generation is unchanged. Public inspection alone does not advance
the transport cursor ahead of packet verification.
The only unchecked reads are the founder's pre-vault empty-branch check and the
peer's pre-vault bootstrap fetch, which requires both out-of-band trust pins.

Command functions exported by `team`:

```rust,ignore
init/request/admit/connect/inbox/status(&Args, &mut Deps) -> Result<Value, Failure>;
send(&Args, &mut dyn Read, stdin_is_terminal: bool, &mut Deps, human: bool)
    -> Result<Value, Failure>;
open(&Args, &Deps) -> Result<TeamSession, Failure>;
sync(&mut TeamSession, now: u64) -> Result<SyncResult, Failure>;
prepare_message(&mut TeamSession, &mut Deps, human: bool, text: String,
                operation: &str) -> Result<PreparedMessage, Failure>;
present(&Delivery, replayed: bool) -> Value;
```

`TeamSession` has public `ws`, `pin`, `engine`, `channel`; the local agent field
is `pin.principal`, and the local human ID is `pin.human.author`.
`PreparedMessage` has public `result: Value` and `packet: Vec<u8>`. It persists
the exact packet and does not publish or acknowledge it. Trusted integrations
must sync registry/Git first and use `GitChannel::publish` for authoritative
publication. A broker notification must not call `confirm_publication` or
receive uncommitted bytes. The default `send` workflow publishes Git first.
No generic signing, export, receipt-assertion or runtime test-key endpoint exists.

Tests in `tests/team_flow.rs` use separate private roots, two independent
software P-256 human identities behind the fixed signer seam, in-memory custody,
the real engine/vault and a disposable local bare Git repository. They do not
enroll real keys, invoke Touch ID, contact a real origin or use a live broker.
Software success does not establish native or multi-Mac acceptance.
