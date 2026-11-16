# Run the realtime broker

v0.3 uses **NATS JetStream** to notify participants when their Git channel changes.
Git remains the durable project record. Start with one broker for one trusted
project group; the adapter supports token authentication and verified TLS.

## Install the server and optional client

Install **NATS Server 2.15.3** from the
[official release](https://github.com/nats-io/nats-server/releases/tag/v2.15.3),
following the [server instructions](https://github.com/nats-io/nats-server#readme).
Put `nats-server` on PATH, or set `YHES_NATS_SERVER` to its absolute path for the
demo and tests. Verify it with `nats-server --version`.

In your Python environment:

```sh
python3 -m pip install -r requirements-broker.txt
```

Alternatively, prefix the Python commands below with
`uv run --with nats-py==2.16.0`. The dependency is optional for v0.1/v0.2.

## Run a local broker

Generate a private token and choose a persistent directory outside the project:

```sh
export YHES_BROKER_TOKEN="$(openssl rand -hex 32)"
export YHES_NATS_STORE="/absolute/private/path/yhes-jetstream"
nats-server -t -c deploy/nats-local.conf
nats-server -c deploy/nats-local.conf
```

The [local configuration](../deploy/nats-local.conf) binds to `127.0.0.1:4222`.
Keep the token in your existing credential manager and supply it to authorized
clients through their environment. It should never appear in a Git message or
committed configuration. The store directory must persist across server restarts.

On a client using the same machine:

```sh
export YHES_BROKER_URL="nats://127.0.0.1:4222"
# Set YHES_BROKER_TOKEN to the broker's token in this shell too.
```

## Connect computers through TLS

Use [nats-tls.conf](../deploy/nats-tls.conf) on the server. Set the token and store
directory as above, plus paths to the server certificate and private key:

```sh
export YHES_NATS_CERT="/absolute/path/server-cert.pem"
export YHES_NATS_KEY="/absolute/private/path/server-key.pem"
nats-server -t -c deploy/nats-tls.conf
nats-server -c deploy/nats-tls.conf
```

On each participant's computer:

```sh
export YHES_BROKER_URL="tls://broker.example.com:4222"
# Supply YHES_BROKER_TOKEN privately.
# For a private CA, also set:
export YHES_BROKER_CA="/absolute/path/ca.pem"
```

Use the hostname covered by the certificate. Public-CA certificates can use the
system trust store without `YHES_BROKER_CA`. The client checks the certificate
and hostname; it has no skip-verification option. For server lifecycle,
replication and access management, follow NATS's own operating instructions.

## Initialize the channel and start using it

Set up the [v0.2 Git channel](../examples/REMOTE-WALKTHROUGH.md) first. The
organizer then creates the channel's JetStream stream:

```sh
python3 tools/realtime.py --root /path/project broker-init
```

The response gives the stream and subject names. This is an explicit operator
action; normal sends do not create or reconfigure a stream.

Register a participant using the realtime helper:

```sh
python3 tools/realtime.py --root /path/project session \
  --label reviewer --harness claude
```

Humans add `--participant-type human --harness terminal`. Save `result.id` for
the session and `result.agent` for its address. Existing v0.2 sessions work too.
Every client uses the same Git remote/branch and the same broker group.

Listen in an active agent, terminal or authorized adapter:

```sh
python3 tools/realtime.py --root /path/project listen \
  --session SESSION_ID --seconds 30
```

In another participant's terminal:

```sh
python3 tools/realtime.py --root /path/project send \
  --session SENDER_SESSION --kind question --ticket TICKET_ID \
  --to agent:RECIPIENT_ID --body 'Can you review this change?'
```

The writer confirms the Git operation, then publishes a notification. The
listener wakes, fetches the inbox through Git and prints the new snapshot as
JSON. It does not start a model, execute a message body or mark messages handled.
An active harness reads those records and replies using its existing permissions.

All ticket, message and acknowledgment commands from v0.2 are also available
through `realtime.py`. Their original `result` and `delivery` fields keep their
meaning. A confirmed write with `realtime.state: pending` is safely recorded in
Git and waiting for its notification retry.

## Recover after interruption

```sh
# Retry notifications for Git operations already confirmed by this clone:
python3 tools/realtime.py --root /path/project flush

# Resolve an uncertain Git operation before retrying the work itself:
python3 tools/realtime.py --root /path/project pending
python3 tools/realtime.py --root /path/project resolve OPERATION_ID
python3 tools/realtime.py --root /path/project resume OPERATION_ID
```

A listener reconnects and resumes its durable consumer. It also checks Git at
startup and every 30 seconds by default, so missed or expired notifications are
covered. `--reconcile-every` adjusts that interval. A new computer uses a new
session with `--resumes`; its initial Git read finds pending messages.

JetStream has its own transport acknowledgments. Use `ack --stage handled`
explicitly after the participant records its reply or disposition in Git.

## Run the end-to-end example and tests

```sh
uv run --with nats-py==2.16.0 python3 examples/realtime_demo.py
uv run --with nats-py==2.16.0 python3 -m unittest discover -s tests -v
```

The demo starts an authenticated NATS server on a random loopback port, uses
independent Git clones, and verifies that the scripted question and reply arrive
through broker-triggered reads. It saves a durable result and stops its server
and listeners on exit. It prints its temporary directory for inspection.

The broker integration tests require `nats-server` or `YHES_NATS_SERVER` and
the optional client package. They are explicitly skipped when those prerequisites
are absent; the v0.1/v0.2 suite and pure hint-validation test still run.
The TLS integration test also uses `openssl` to create a disposable certificate.

## Server, protocol and client references

- [NATS Server source and installation](https://github.com/nats-io/nats-server)
- [JetStream concepts and delivery semantics](https://docs.nats.io/concepts/jetstream)
- [NATS wire protocol](https://docs.nats.io/reference/protocols/client)
- [JetStream headers](https://github.com/nats-io/nats.docs/blob/master/nats-concepts/jetstream/headers.md)
- [Authentication](https://docs.nats.io/learn/security/authentication-basics)
- [TLS configuration](https://docs.nats.io/learn/security/encryption)
- [Python client, pinned version](https://github.com/nats-io/nats.py/tree/v2.16.0)
- [agent-yhes v0.3 envelope and delivery contract](../spec/v0.3.md)

The server and client remain separate projects with their own licenses. See
[reference observations](REFERENCES.md#realtime-broker-reference-2026-11-13)
for the local Branchline comparison used while designing this layer.
