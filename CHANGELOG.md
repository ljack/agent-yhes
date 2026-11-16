# Changes

## 0.2.0 — remote Git collaboration

- Add a dedicated coordination branch with isolated per-clone transport state.
- Confirm claims through remote fast-forward updates and revision checks.
- Save operation IDs and results for resolving interrupted or uncertain pushes.
- Add human participants, node-bound sessions and shared handled receipts.
- Support continuation on another computer through an explicit session chain.
- Add a three-clone demo with optional Git networking over loopback TCP.
- Preserve v0.1 local behavior and its existing examples.

## 0.1.0 — local collaboration proposal

- Define `.agents/tickets` and `.agents/messages`, with JSON records and Markdown bodies.
- Add local locking, revision checks, leases, handoffs and durable project memory.
- Provide two harness-independent skills and a scripted Codex–Claude example.
