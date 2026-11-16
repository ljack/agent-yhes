# Secure events, version 1

Wire format and verification rules of the agent-yhes secure profile. The
reference verifier is the Rust crate `secure/crates/yhes-wire`
([API](../secure/crates/yhes-wire/API.md)). This document describes what that
crate accepts; anything not described here is rejected.

Status: implemented and tested with disposable software keys. No real
participant, key or authority is enrolled.

## 1. Envelope

Every signed object is a DSSE-style envelope, a JSON object with exactly three fields:

```json
{"payload_type":"application/vnd.agent-yhes.event.v1+json",
 "payload":"BASE64",
 "signatures":[{"key_id":"k_<64 hex>","algorithm":"p256-sha256","signature":"BASE64"}]}
```

- `payload_type` is `application/vnd.agent-yhes.event.v1+json` (events),
  `application/vnd.agent-yhes.registry.v1+json` (registries) or
  `application/vnd.agent-yhes.transport.v1+json` (transport records). The
  caller states which one it expects; the others are refused. The transport
  type shares only the envelope and PAE rules: its payload is defined by the
  transport layer, and the event and registry verifiers never accept it.
- `payload` is standard, padded, canonical base64 of the payload bytes.
- `signatures` holds 1 to 8 entries with distinct `key_id`s. An event carries
  exactly one. Each `signature` is base64 of 64 raw bytes.

The signed bytes are the DSSE v1 pre-authentication encoding. Lengths are
decimal byte counts:

```
"DSSEv1" SP len(payload_type) SP payload_type SP len(payload) SP payload
```

The payload is never re-serialized. Retries and relays carry the same bytes.
The **event digest** is SHA-256 of the exact payload bytes, in lowercase hex.

### Algorithms and key identifiers

| `algorithm` | Public key | Signature |
| --- | --- | --- |
| `ed25519` | 32 raw bytes | 64 bytes; strict verification, small-order keys refused |
| `p256-sha256` | 65-byte uncompressed SEC1 point | 64 bytes `r‖s`, ECDSA over SHA-256; high-S accepted |

`key_id` = `k_` + lowercase hex of
SHA-256(`"agent-yhes/key/v1" 0x00` ‖ algorithm name ‖ `0x00` ‖ raw public key).

### Strict JSON

These rules apply to the envelope and to every payload:

- At most 1 048 576 bytes; arrays and objects nest at most 8 deep.
- UTF-8 without a byte-order mark, one document, no trailing data.
- No duplicate object keys, including keys that differ only by escaping.
- Numbers are non-negative integers. Floats, exponents and negatives are refused.
- Every object has a fixed field set: a missing or unknown field is an error.
  Nullable fields are written as `null`, never omitted.
- Identifiers match `[A-Za-z0-9][A-Za-z0-9._-]*`, are at most 128 bytes and
  contain no `..`. They are names only; nothing in a payload is treated as a
  path, URL, configuration or command.
- Timestamps are Unix seconds, at most 253402300799.

## 2. Event payload

```json
{"version":1,"id":"event-1","project":"demo","kind":"human.statement",
 "author":"alice","key_id":"k_…","session":null,
 "issued_at":1800000000,"expires_at":1800000600,
 "audience":["alice-agent","bob"],"group":null,"epoch":null,"previous":null,
 "body":{"text":"hello team"}}
```

| Field | Meaning |
| --- | --- |
| `version` | `1`. |
| `id` | Identifier chosen by the author; the durable core uses it and the digest against replay. |
| `project` | Must equal the registry's project. |
| `kind` | One of the kinds below; decides the shape of `body`. |
| `author` | Participant id. The signing key must belong to it. |
| `key_id` | The signing key; must equal the envelope signature's `key_id`. |
| `session` | Digest of the session grant or delegation the key signs under, else `null`. |
| `issued_at`, `expires_at` | Validity. `expires_at` ≥ `issued_at`. |
| `audience` | 1 to 256 participant ids, sorted by bytes, unique, all in the registry. |
| `group`, `epoch` | Group id and epoch, or `null`. `epoch` needs `group`. |
| `previous` | Digest of a preceding event, or `null`. Carried, not interpreted. |
| `body` | Object typed by `kind`. |

There is no field in which a sender can state that it is a human, an agent or
a service. That classification is derived by the verifier.

### Kinds and bodies

| Kind | Body |
| --- | --- |
| `human.statement` | `{"text"}` |
| `session.grant` | `{"session_key":{"algorithm","public_key"},"purposes":["human.statement"]}` |
| `agent.delegation` | `{"agent","agent_key_id","purposes":[…]}` |
| `agent.message` | `{"text"}` |
| `agent.relay` | `{"original":<envelope object>,"note":<string or null>}` |
| `action.authorization` | `{"action","request_digest","performer"}` |
| `action.execute` | `{"action","request_digest","authorization"}` |
| `service.notice` | `{"text"}` |
| `ticket.action` | `{"action","request_digest"}` |

`text` and `note` are at most 65 536 bytes. `purposes` lists are sorted, unique
and non-empty.

In `action.authorization` and `action.execute`, `action` is an identifier. In
`ticket.action` it is one of `ticket.create`, `ticket.claim`, `ticket.release`,
`ticket.update`, `ticket.complete`, `ticket.cancel`.

`request_digest` MUST be the SHA-256 of the exact reviewed request sidecar: the
bytes that were shown for review and that the action will be carried out from.
It is never the digest of MLS Commit bytes or of any other derived artifact.
The verifier treats it as opaque and binds it exactly.

## 3. Registry

A registry is a payload of type `application/vnd.agent-yhes.registry.v1+json`:

```json
{"version":1,"project":"demo","generation":2,"previous":"<digest of generation 1>",
 "issued_at":1800000000,"expires_at":1800086400,
 "participants":[
   {"id":"alice","kind":"human","controller":null,
    "ghes":{"instance":"ghes.example.com","user_id":1001}},
   {"id":"alice-agent","kind":"agent","controller":"alice","ghes":null},
   {"id":"ci","kind":"service","controller":null,"ghes":null}],
 "keys":[
   {"key_id":"k_…","participant":"alice","algorithm":"p256-sha256",
    "public_key":"BASE64","not_before":1800000000,"not_after":1830000000}],
 "revocations":[{"key_id":"k_…","revoked_at":1800000500}]}
```

Rules:

- **Authority.** The verifier is given pinned authority public keys, a project
  and a threshold. Every signature on the envelope must come from a distinct
  pinned authority and verify, and there must be at least `threshold` of them.
  An extra signature from an unpinned key makes the registry invalid.
- **Chain.** `generation` starts at 1 with `previous: null`; later generations
  name the digest of their predecessor. Against the last accepted generation
  (the checkpoint) a registry is accepted only if it is the same generation
  with the same digest, or the next generation naming that digest. Older
  generations are rollback, a different payload at the same generation is a
  fork, and a skipped generation is a gap; all three are refused.
- **Revocation is permanent.** A successor must list every key the checkpoint
  listed as revoked. A revoked key is refused for every event, whatever the
  event's `issued_at`; `revoked_at` is informational.
- **Validity.** A registry is usable from `issued_at` (with clock skew) to
  `expires_at`. After that nothing verifies until a successor is accepted.
- **Participants.** Sorted by `id`. A human has no controller and either an
  enrolled GHES identity (lowercase instance host and non-zero immutable user id)
  or `ghes:null` for an explicitly local human-key identity. Null makes no
  enterprise-account claim; never substitute a fictional host or user ID. An agent has
  a human controller and no GHES identity. A service may have a human
  controller and a GHES identity. One GHES account belongs to one participant.
- **Keys.** Sorted by `key_id`, which must match the public key. Each key
  belongs to one participant and is valid from `not_before` to `not_after`.

**Active key.** A participant's key is active at a time when the registry is
unexpired, the key is listed for that participant, is not revoked, and the
time lies within `not_before`..`not_after`. Other layers (for example MLS
KeyPackage enrollment) bind to enrolled keys through this rule.

A human's registry keys are **device keys**. Session keys never appear in the registry.

## 4. Verification

An event is verified against one accepted registry, the current time, the
caller's expectation (project, audience, group) and the evidence the event
refers to. All of the following must hold.

1. The envelope and payload are well formed (sections 1 and 2) with exactly one signature.
2. `project` equals the registry's and the caller's project.
3. The signature's `key_id` equals the payload's, its algorithm equals the
   key's, and the signature verifies over the PAE bytes.
4. `issued_at` ≤ now + skew, now ≤ `expires_at`, and the lifetime is within
   policy for the kind.
5. The key is not revoked and resolves to a signer role (below).
6. The role may issue the kind (table below).
7. Every audience member is a registry participant.
8. The event stays inside the scope of its grant, and kind-specific rules hold.
9. The audience satisfies the caller: it contains the local participant, or
   equals a given set. `group` equals the expected group.

### Signer roles

| Role | How the key is resolved |
| --- | --- |
| human device | Registry key of a human participant equal to `author`. |
| agent | Registry key of an agent participant equal to `author`. |
| service | Registry key of a service participant equal to `author`. |
| human session | Not in the registry. `session` names a valid `session.grant` by the same `author` whose `session_key` is this key. |

Registry keys must be valid at `issued_at` and still valid now.

| Kind | Allowed role | `session` |
| --- | --- | --- |
| `human.statement` | human device | `null` |
| `human.statement` | human session | session grant digest |
| `session.grant`, `agent.delegation`, `action.authorization` | human device | `null` |
| `agent.message`, `agent.relay` | agent | delegation digest |
| `action.execute` | agent | delegation digest |
| `action.execute` | human device | `null` |
| `service.notice` | service | `null` |
| `ticket.action` | agent | delegation digest |

`ticket.action` is routine: an agent needs a delegation that lists
`ticket.action` explicitly and no fresh human authorization. No other signer
may issue it. Any other ticket action, such as `ticket.recover`, is privileged:
it is an `action.execute` with a fresh human `action.authorization`. So a human session key cannot grant, delegate or authorize; an agent cannot
issue a human kind, sign for its controller or delegate; and a device key does
not sign under a session reference.

### Grants

A grant is itself a signed event. The dependent event names it by digest, and
the verifier receives its envelope as evidence and verifies it in full. The
dependent's `issued_at` must lie inside the grant's validity. The grant itself
must remain current now, and its issuer key must be valid and unrevoked. An old
sender-supplied timestamp cannot establish timely use of an expired grant.
Previously accepted history belongs to the durable core. Evidence that is missing,
not needed, or does not match the named digest is an error.

**Session grant** (`session.grant`, default maximum 30 minutes). Issued by a
human device key. `purposes` is exactly `["human.statement"]`. The session key
must not be an enrolled or revoked key. An event under it must have the grant's
author, an audience within the grant's audience and the grant's `group`.

**Delegation** (`agent.delegation`, default maximum 7 days). Issued by the
device key of the agent's controller. Names the agent and one of its enrolled
keys. `purposes` is a subset of `agent.message`, `agent.relay`,
`action.execute`, `ticket.action`. An event under it must come from that agent and key, be of a
delegated kind, and have an audience within the delegation's audience and the
delegation's `group`.

**Action authorization** (`action.authorization`, default maximum 5 minutes).
Issued by a human device key. `performer` is the issuer or an agent the issuer
controls. An `action.execute` under it must come from the performer and have
the same `action`, `request_digest`, `audience`, `group` and `epoch`.
Single use is enforced by the durable core through the authorization digest.

### Relay

`agent.relay` carries the original human envelope unchanged in
`body.original`. The verifier:

- verifies the original as an event in its own right (signature, registry,
  time, and its session grant if it was session-signed);
- requires it to be a `human.statement` of the same project;
- requires the relay's audience to be within the original's audience;
- requires the relaying agent to be in the original's audience, or to be
  controlled by the original's author.

The result exposes the original separately with its exact bytes and human
signer. The relay itself, including `note`, is agent-authored. Text that an
agent quotes, edits or paraphrases is only ever agent-authored.

### Time policy

| Limit | Default |
| --- | --- |
| Clock skew for `issued_at` | 120 s |
| Event lifetime | 7 days |
| Session grant lifetime | 30 minutes |
| Delegation lifetime | 7 days |
| Action authorization lifetime | 5 minutes |

These are the proposed defaults of the working contract and remain open for review.

## 5. Outside this format

- **Replay and single use.** The verifier is stateless. The durable core
  records accepted event digests and ids, and consumed authorization digests.
- **Backdating.** A stolen but unrevoked key can sign with an old `issued_at`.
  The core should compare `issued_at` with trusted transport order where it has
  one. Revocation, once in the registry, refuses the key outright.
- **Idle timeout and screen lock.** The native signer currently uses fixed reviewed
  batches, invalidates review on lock and issues no timed session grants. A future
  timed-session profile needs a demonstrated trusted input boundary; an idle timeout
  cannot be verified from these wire records.
- **Biometric assurance.** A human device signature proves use of the enrolled
  key. Whether Touch ID guarded that use is the signer's property.
- **Unsigned legacy records.** They have no envelope and cannot be verified.
  They may be imported as historical data, never relabelled as verified.
- **Confidentiality.** Envelopes are signed, not encrypted. Sealing is the MLS layer's job.
