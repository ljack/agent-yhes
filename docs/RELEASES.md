# Try the version ladder

Each tagged stage is a separate commit boundary.

| Tag | What to try | Entry point |
| --- | --- | --- |
| `v0.1.0` | Local tickets and messages in one shared project | `examples/demo.py`, `spec/v0.1.md` |
| `v0.2.0` | Remote Git coordination across separate clones | `examples/remote_demo.py`, `examples/REMOTE-WALKTHROUGH.md` |
| `v0.3.0` | Realtime notices, signed identities, encrypted groups and team/simulation tooling | `docs/TEAM-PILOT.md`, `BOOTSTRAP.md` |

Clone with `git clone --branch v0.3.0 https://github.com/ljack/agent-yhes.git`.
Use a fresh directory and the selected tag's README for each experiment.
The earlier file/Git helpers use plaintext records; do not reuse secure project
state with them. The native signer needs a locally signed and provisioned build.
This release contains source, not a distributable signed app.
