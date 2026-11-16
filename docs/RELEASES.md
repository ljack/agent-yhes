# Try the version ladder

Each tagged stage is a separate commit boundary. Protocol version numbers remain
independent of the tutorial/package version: v0.4.1 still explains the v0.3 secure
pilot.

| Tag | What to try | Entry point |
| --- | --- | --- |
| `v0.1.0` | Local tickets and messages in one shared project | `examples/demo.py`, `spec/v0.1.md` |
| `v0.2.0` | Remote Git coordination across separate clones | `examples/remote_demo.py`, `examples/REMOTE-WALKTHROUGH.md` |
| `v0.3.0` | Realtime notices, signed identities, encrypted groups and team/simulation tooling | `docs/TEAM-PILOT.md`, `BOOTSTRAP.md` |
| `v0.4.0` | Interactive explanation and a GitHub Pages build | `tutorial/README.md` |
| `v0.4.1` | Refined interactive tutorial, corridor-routed flows, direct documentation and MIT OR Apache-2.0 licensing | `tutorial/README.md`, `LICENSE-MIT`, `LICENSE-APACHE` |

Use a fresh directory for each experiment so its runtime state stays with its
matching version. For example:

```sh
git clone --branch v0.4.1 https://github.com/ljack/agent-yhes.git agent-yhes-v0.4.1
cd agent-yhes-v0.4.1
python3 tools/tutorial_server.py
```

The clone starts at the tag in detached-HEAD mode. Create a branch if you plan to
edit it. Substitute an earlier tag to inspect that stage and use its README.
The v0.1/v0.2 helpers store plaintext records; use the secure pilot for verified
human authors and encrypted messages. Do not reuse a secure project's state with
an earlier helper. The native human signer requires a locally signed and
provisioned build.

The live [GitHub Pages tutorial](https://ljack.github.io/agent-yhes/) follows
the tested `main` build. Its `build.json` records the exact source revision and
package version. Guide links point to that revision. Release tags stay fixed;
checking out a tag locally lets you replay its version.

The first source publication was on 11 November 2026. The v0.1.0 tag includes the
README wording and Mermaid rendering fixes already on main. Later stages were
developed locally and grouped for publication on 16 November 2026.
