# Two people, shared Git and a realtime server

To simulate two users in separate Teerminal project directories on one Mac,
start with [BOOTSTRAP.md](../BOOTSTRAP.md). That flow uses separate disposable
identities and real Git/NATS without the native human signer.

This pilot connects two people, each with one agent and their own private keys.
Git carries the identity handshake, approved membership and encrypted history.
NATS wakes an active receiver when a message is published.

For agent-assisted onboarding, give the new member's harness the
[new-member agent instruction](NEW-MEMBER-AGENT.md). It includes a copyable
starting prompt, the member-side steps and the checks to report back.

**Implementation status, 15 November 2026:** the `team-*` commands are separate
from the working same-Mac `pilot`. The network workflow has been exercised with
independent private stores, two disposable P-256 human identities, a real bare
Git server and a real NATS server on loopback. Actual enrollment on a second
Mac and a hosted GHES trial still need to be performed. This source is included
from v0.3.0 onward.

The server path currently publishes to Git first, then sends the exact encrypted
packet through NATS. The receiver reconciles Git before accepting it. This
removes the wait for the next inbox poll; it still involves a Git write for each
message. Broker-only delivery before Git confirmation is not enabled.

## Before the two-person session

Each person needs a Touch ID Mac and a signed, provisioned Yhes Signer build
prepared for that device. See [native setup](MACOS-SIGNER.md#run-the-local-pilot).
The development app prepared for one Mac is not a general team installer.
Use the same source revision on both machines; `bin/yhes help` must list the
`team-*` commands. The app handles native approvals; its **Start setup** button
still starts the original local pilot. Run the team steps below from Terminal.

Agree on:

- A private Git repository both people can fetch and push, using its full SSH
  or HTTPS URL. An alias such as `origin` is not accepted by this adapter.
- One project ID and one distinct human/agent ID per person. This guide uses
  `alice` / `alice-agent` and `bob` / `bob-agent` as examples.
- Who is the founder. The founder's human key approves the project registry;
  their agent performs the approved membership changes.
- A trusted channel for comparing the initial fingerprints and bootstrap digest.
  This is a one-time identity check; enrollment documents and work messages
  travel through Git.

The native human key currently belongs to one human/project pair. If you already
have one, use its existing IDs. Jarkko's tested key uses human `jarkko` and project
`agent-yhes-pilot`. A new folder does not change that key's scope.

On each Mac, open Terminal in the toolkit checkout and set these values, replacing
the examples:

```sh
export YHES_PROJECT="/absolute/path/to/your/project-clone"
export YHES_PROJECT_ID="your-project-id"
export YHES_REMOTE="ssh://git@ghes.example.com/your-org/your-project.git"
```

The project directory must already exist. Source files, their index and their
branches stay untouched. The adapter uses a separate private Git cache and the
dedicated `agent-yhes/secure-team` branch. Give that branch normal fast-forward
push access; retain force-push/deletion protection and any enterprise signing
policy. See the [Git adapter reference](../secure/crates/yhes-core/GIT-API.md)
for explicit authentication and commit-signing configuration.

### Git authentication and signed commits

The adapter does not inherit arbitrary Git helpers or signing programs. Choose
these options on the first `team-init` or `team-request`; repeat them unchanged
when retrying that setup command. Later commands use the stored configuration.

For an SSH remote using your existing SSH agent, add `--git-ssh-agent`. Prepare
host trust and load the intended key through your normal SSH tools beforehand.
The adapter uses batch mode and does not accept a new host key automatically.

For a repository requiring SSH-signed commits, also add:

```text
--git-author-name "Your Name" --git-author-email "your-verified-work-email@example.com"
--git-signing-format ssh --git-signing-key /absolute/path/to/signing-key.pub
--git-ssh-agent
```

The signing key path must be an OpenSSH public-key file. It is distinct from
your Yhes Secure Enclave identity. Git signing failure stops publication.
OpenPGP is selected with `--git-signing-format openpgp` and
`--git-signing-key FULL_FINGERPRINT`; it uses the fixed Homebrew `gpg` installation
on macOS. For HTTPS credentials stored in the macOS Git credential helper, add
`--git-credentials osxkeychain`. Keep passwords and tokens out of remote URLs.

Disposable SSH commit signing has been tested. Actual enterprise acceptance,
OpenPGP signing and macOS credential-helper authentication still need testing
with the chosen repository and each person's existing credentials. Commit
signatures and message signatures are checked for different purposes; a Git
author name does not establish human message authorship.

## 1. Alice creates the team

Alice runs:

```sh
bin/yhes team-init --project "$YHES_PROJECT" \
  --project-id "$YHES_PROJECT_ID" --human alice --as alice-agent \
  --remote "$YHES_REMOTE"
```

Yhes Signer asks Alice to create her key if needed, then review the first registry
containing her human identity and agent. Alice performs the Touch ID approvals.

**Expect:** `state: "waiting-for-request"`. The result includes `authority`, the
full `k_…` fingerprint, and `bootstrap_head`, the digest of the exact approved
generation-1 registry payload. Share those two values and the project ID with
Bob through the agreed trusted channel. The group is not created yet, so this
preparation does not spend the short membership-approval window.

## 2. Bob requests enrollment through Git

Bob checks Alice's project ID, authority fingerprint and bootstrap digest, then
runs this with those exact values:

```sh
bin/yhes team-request --project "$YHES_PROJECT" \
  --project-id "$YHES_PROJECT_ID" --human bob --as bob-agent \
  --remote "$YHES_REMOTE" \
  --authority k_FULL_FOUNDER_KEY_FINGERPRINT \
  --bootstrap FULL_REGISTRY1_PAYLOAD_DIGEST
```

The client verifies the bootstrap before requesting Bob's human key. Bob then
reviews a proposal containing his own human and agent keys and confirms it with
Touch ID. The signed proposal is published through Git. It is a request to join;
Bob cannot make himself a project authority by publishing it.

**Expect:** a waiting-for-admission result and Bob's `human_key` fingerprint.
Alice compares that fingerprint with Bob through their trusted channel. Both
clients use local human identities with `ghes: null`; this pilot does not yet
bind the human key to a verified GHES account.

## 3. Alice admits Bob

Alice runs:

```sh
bin/yhes team-admit --project "$YHES_PROJECT" \
  --peer bob-agent --peer-key k_FULL_BOB_HUMAN_KEY_FINGERPRINT
```

The client checks Bob's signature, controller relationship and key bindings.
Alice reviews the updated registry in Yhes Signer and approves it with Touch ID.
The new authority-signed generation is published to Git.

**Expect:** Bob is admitted to the registry. Each person still needs to approve
their own agent's permissions, and the encrypted channel still needs its
membership approvals.

## 4. Connect the agents while both people are online

First Bob runs:

```sh
bin/yhes team-connect --project "$YHES_PROJECT"
```

Bob reviews his agent's permissions for the two-agent audience. The client
publishes its public MLS KeyPackage, which supplies the material needed to
invite that exact agent into the encrypted group.

**Expect:** `state: "waiting-for-invitation"`.

Next Alice runs the same command on her Mac:

```sh
bin/yhes team-connect --project "$YHES_PROJECT"
```

Alice reviews her agent's permissions, creation of the channel, and addition of
Bob's agent. The add request binds Bob's exact KeyPackage. Each protected action
has its own native review. The client publishes the approved membership records.

**Expect:** Alice's profile reports `state: "ready"`. That confirms Alice's side;
it is not yet an acknowledgment from Bob.

Bob immediately runs `team-connect` again. **Expect:** Bob also reports `ready`,
after verifying the invitation and joining with his saved package. Finish this
sequence within the five-minute membership-approval window, including Alice's
reviews and Bob's first join. A late first join is refused; the client does not
backdate approval or reset keys to make it pass.

Both people can now check their own state:

```sh
bin/yhes team-status --project "$YHES_PROJECT"
```

**Expect:** the same project, authority, group `team`, epoch, membership commit
and audience containing both agent IDs. Each Mac reports its own human and local
agent identity. Keep the resulting configuration unchanged when resuming.

## 5. Exchange an encrypted message through Git

Alice sends:

```sh
printf '%s\n' 'Please review this change and reply with one concern.' |
  bin/yhes team-send --project "$YHES_PROJECT" --stdin --operation team-question-01
```

Bob reads and replies:

```sh
bin/yhes team-inbox --project "$YHES_PROJECT"
printf '%s\n' 'My concern is recovery after an interrupted connection.' |
  bin/yhes team-send --project "$YHES_PROJECT" --stdin --operation team-reply-01
```

Alice runs `team-inbox` to read the reply. **Expect:** verified `agent.message`
records with the correct agent authors and no human original. The private
outbox retains exact ciphertext; retry the same operation ID with identical text
after an uncertain outcome. A different message needs a new ID.

For a human-signed statement, either person uses `team-say`:

```sh
printf '%s\n' 'This is my reviewed statement for the team.' |
  bin/yhes team-say --project "$YHES_PROJECT" --stdin --operation team-human-01
```

Review the words and full audience in Yhes Signer, then approve with Touch ID.
The other person runs `team-inbox` before `receive_before` (at most 30 minutes
from statement creation). **Expect:** `agent.relay`, the correct agent `author`,
your human ID in `human_original_author`, and the exact statement in `human_text`.
Routine agent replies use the existing delegation and require no biometric prompt.

## 6. Prepare the realtime server

An operator runs NATS Server with JetStream, a private token, persistent storage
and a certificate matching the broker hostname. The existing
[TLS server configuration](../deploy/nats-tls.conf) can serve this pilot:

```sh
# Set YHES_BROKER_TOKEN privately through your credential manager.
export YHES_NATS_STORE="/absolute/private/path/yhes-jetstream"
export YHES_NATS_CERT="/absolute/path/server-cert.pem"
export YHES_NATS_KEY="/absolute/private/path/server-key.pem"
nats-server -t -c deploy/nats-tls.conf
nats-server -c deploy/nats-tls.conf
```

Use [NATS Server 2.15.3](https://github.com/nats-io/nats-server/releases/tag/v2.15.3)
for the tested server version. The operator chooses the host and network access;
these commands do not provision a server or change a firewall. Keep the token
and TLS private key outside Git. A separate broker/account for this small pilot
keeps its access scope clear.

On both Macs:

```sh
export YHES_BROKER_URL="tls://broker.example.com:4222"
# Supply the agreed YHES_BROKER_TOKEN privately in this terminal too.
```

The URL is explicit local configuration. The client accepts plaintext `nats://`
only for literal loopback addresses such as `127.0.0.1` in local tests. It verifies
remote TLS certificates and hostnames. For a private CA, add
`--ca-file /absolute/path/ca.pem` to each broker command. Credentials embedded
in a URL are refused, and discovered server addresses do not redirect clients.

One participant initializes the scoped stream once:

```sh
bin/yhes team-broker-init --project "$YHES_PROJECT" --broker "$YHES_BROKER_URL"
```

**Expect:** the stream and subject names. They are derived from the project,
group and authority fingerprint. The stream stores bounded ciphertext history;
Git remains the durable acceptance record.

## 7. Use the server for immediate wake-up

Bob starts a bounded wait:

```sh
bin/yhes team-listen --project "$YHES_PROJECT" \
  --broker "$YHES_BROKER_URL" --seconds 30
```

Alice sends with the broker option:

```sh
printf '%s\n' 'This message should wake your active listener.' |
  bin/yhes team-send --project "$YHES_PROJECT" --stdin \
    --operation team-live-01 --broker "$YHES_BROKER_URL"
```

**Expect:** Alice sees confirmed Git publication and `realtime.state: "published"`.
Bob's listener returns a verified new message after the server wakes it. Startup
also reconciles Git; messages already waiting there may return with `wake: "startup"`.
Run the listener again for the next message. It releases the vault while waiting,
so the same agent can send from another process between receives.

Both `team-send` and `team-say` accept the broker option. The server never sees
decrypted text. A NATS acknowledgment means transport progress, not approval or
permission to execute a message. Receivers accept only exact records on verified
Git history; early or altered broker packets cannot advance their encryption state.

If the server is down, a send can still succeed in Git and report
`realtime.state: "pending"`. Read with `team-inbox`, then retry notifications:

```sh
bin/yhes team-flush --project "$YHES_PROJECT" --broker "$YHES_BROKER_URL"
```

Flush attempts up to 64 still-unnotified accepted messages per call. Repeat it
if `remaining` is nonzero. `unarchived_operations` need the original send retry;
flush does not turn an unaccepted Git operation into an accepted one. Per-operation
errors remain visible. An integrity/reconciliation error reports
`git_confirmed: false` and needs diagnosis rather than a new operation ID.

An active listener also reconciles Git periodically, at startup and before its
wait ends. Missing notifications do not erase messages. The listener returns
after a new message or its timeout; it does not launch or wake a dormant model.

## 8. Give the workflow to your agents

Give each harness the [messaging skill](../skills/local-agent-messages/SKILL.md),
the absolute `bin/yhes` path, its project folder and its assigned local identity.
Use the `team-*` commands for this network profile. Set the broker URL/token in
the harness environment through your normal credential handling.

Authorize a small task once: one agent asks for a review, the other replies,
and the first records the result in a message. Have each active agent call
`team-listen` or check `team-inbox` between work steps. They should preserve
operation IDs on retry, distinguish human originals from agent prose, and leave
native approvals to their human. Harness names are labels; keys identify the
enrolled profiles, not an attested model binary.

## Check the first real session

The first two-Mac acceptance should establish:

1. Both sides reach the same ready membership after checking fingerprints.
2. Each agent receives the other's verified message without copying it through chat.
3. A human statement arrives unchanged with human and relay authors separated.
4. A listener wakes through NATS; a server outage still permits Git delivery.
5. Reopening the clients preserves history, and an identical send retry produces
   no duplicate event.

This first CLI supports two people, one agent each, one group and an online first
join. Registry and key renewal, missed/expired membership recovery, owner handover
and team removal UI still need explicit workflows. The initial registry is valid
for seven days; this pilot is not an unattended long-running deployment. The GHES
account-proof adapter remains separate, even when Git itself authenticates against
GHES and the repository requires signed commits. Never delete private state or
weaken expiry to recover a blocked join.

For implementation details and repeatable checks, see the
[team API](../secure/crates/yhes-cli/TEAM-API.md),
[Git API](../secure/crates/yhes-core/GIT-API.md) and
[validation record](VALIDATION.md).
