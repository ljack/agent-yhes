# `yhes-actions` API

This crate parses secure action request sidecars with a closed, typed schema.
It preserves the digest of the exact supplied bytes; it does not normalize or
reserialize a request before hashing.

```rust
use yhes_actions::Request;
use yhes_wire::VerifiedEvent;

let exact_request: &[u8] = obtain_request_bytes();
let request = Request::parse(exact_request)?;
let digest = request.digest();

// Verify the signed event and its evidence first with yhes-wire.
let verified: VerifiedEvent = verify_event_with_wire()?;
request.verify_binding(&verified, trusted_now)?;
```

`Request` exposes `project()`, `action()`, `performer()`, `group()`,
`epoch()`, `audience()`, `parameters()` and `digest()`. Parameters are one of
the public `Parameters` variants; arbitrary JSON or shell/deployment actions
are not accepted.

## Exact request schema

Every request has exactly these fields:

```json
{
  "version": 1,
  "project": "demo",
  "action": "group.add",
  "performer": "builder-agent",
  "group": "engineering",
  "epoch": 4,
  "audience": ["builder-agent", "reviewer"],
  "parameters": {
    "member": "new-agent",
    "key_id": "k_<64 lowercase hex>",
    "key_package_digest": "<64 lowercase hex>"
  }
}
```

The object uses UTF-8 JSON, has a 64 KiB size limit and an eight-level nesting
limit. Duplicate fields, unknown fields, unsupported versions, floats,
negative integers, invalid identifiers, unsorted/duplicate audiences, and
unknown actions are rejected. The exact input bytes are SHA-256 hashed for
`digest()`.

| Action | Exact `parameters` fields |
| --- | --- |
| `group.create` | `{}`; epoch must be `0`; audience must be only the performer |
| `group.add` | `member`, `key_id`, `key_package_digest` |
| `group.remove` | `member` |
| `ticket.recover` | `ticket`, non-negative `expected_revision`, non-empty bounded `stop_evidence` string |
| `ticket.create` | `title`, `description` |
| `ticket.claim`, `ticket.release`, `ticket.complete`, `ticket.cancel` | `ticket`, non-negative `expected_revision` |
| `ticket.update` | `ticket`, non-negative `expected_revision`, and at least one of `title` or `description` |

`ticket.update` permits changing either field or both. A ticket title must be
non-empty; text lengths are bounded. `stop_evidence` is a short human-readable
reference or explanation for the verified stop evidence, not a digest. The
parser checks shape and identifiers,
not ticket ownership or whether the revision is current. The core must enforce
ownership, revision, stop evidence and all other state-dependent policy.

## Event binding and privilege

`verify_binding(&VerifiedEvent, now)` accepts only a verifier-constructed
`action.execute` or `ticket.action`, checks that event expiry has not passed,
and matches project, exact action, performer, group, epoch, audience and
the exact request digest. Privileged `group.create`, `group.add`,
`group.remove`, and `ticket.recover` additionally require the event's verified
human device authorization to still be current at the supplied `now`.
The verifier must verify signature, registry, delegation, authorization and
event validity before this API is called.

`ticket.recover` uses `action.execute` and requires fresh authorization; other
ticket operations use the distinct `ticket.action` kind. Ticket ownership,
revision freshness, stop-evidence semantics and generated ticket identifiers
remain core responsibilities.

No action sidecar authorizes behavior by itself. In particular, successful
parsing/binding does not replace pinned project authority, registry checks,
authorization single-use/replay tracking, or separate signed transport
binding of the resulting MLS Commit/ciphertext.

## Tests

From `secure/`, run `cargo test -p yhes-actions`. All signing keys in its
integration fixtures are disposable deterministic software keys.
